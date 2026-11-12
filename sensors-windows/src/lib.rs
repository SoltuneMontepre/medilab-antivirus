//! Windows sensors: USN journal, ETW, AMSI, Authenticode checks.
#![cfg(windows)]

use std::collections::HashMap;
use std::ffi::{c_void, OsString};
use std::fs::{File, OpenOptions};
use std::io::{self, Seek, SeekFrom};
use std::iter::once;
use std::mem::{offset_of, size_of};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;
use std::path::Path;
use std::ptr::{null, null_mut};

use av_core::{FileKey, Platform, TrustConfig};
use windows_sys::core::PCWSTR;
use windows_sys::Win32::Foundation::{ERROR_NO_MORE_FILES, HANDLE, TRUST_E_NOSIGNATURE, TRUST_E_SUBJECT_FORM_UNKNOWN};
use windows_sys::Win32::Security::Cryptography::Catalog::{
    CryptCATAdminAcquireContext2, CryptCATAdminCalcHashFromFileHandle2, CryptCATAdminEnumCatalogFromHash,
    CryptCATAdminReleaseCatalogContext, CryptCATAdminReleaseContext, CryptCATCatalogInfoFromContext, CATALOG_INFO,
};
use windows_sys::Win32::Security::Cryptography::{
    CertGetNameStringW, BCRYPT_SHA1_ALGORITHM, BCRYPT_SHA256_ALGORITHM, CERT_NAME_SIMPLE_DISPLAY_TYPE,
};
use windows_sys::Win32::Security::WinTrust::{
    WTHelperGetProvSignerFromChain, WTHelperProvDataFromStateData, WinVerifyTrust, WINTRUST_ACTION_GENERIC_VERIFY_V2,
    WINTRUST_CATALOG_INFO, WINTRUST_DATA, WINTRUST_DATA_0, WINTRUST_FILE_INFO, WTD_CACHE_ONLY_URL_RETRIEVAL,
    WTD_CHOICE_CATALOG, WTD_CHOICE_FILE, WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE,
};
use windows_sys::Win32::Storage::FileSystem::{
    FileBasicInfo, FileIdExtdDirectoryInfo, FileIdExtdDirectoryRestartInfo, FileIdInfo, GetFileInformationByHandleEx,
    FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_BASIC_INFO, FILE_FLAG_BACKUP_SEMANTICS,
    FILE_ID_EXTD_DIR_INFO, FILE_ID_INFO, FILE_INFO_BY_HANDLE_CLASS, FILE_LIST_DIRECTORY, FILE_SHARE_DELETE,
    FILE_SHARE_READ, FILE_SHARE_WRITE, SYNCHRONIZE,
};

pub struct WindowsPlatform {
    publishers: Vec<String>,
}

impl WindowsPlatform {
    pub fn new(trust: &TrustConfig) -> Self {
        Self { publishers: trust.publishers.clone() }
    }
}

impl Platform for WindowsPlatform {
    // ponytail: ChangeTime catches SetFileTime backdating of LastWriteTime, but NtSetInformationFile can set
    // ChangeTime too; the USN journal (M3) is the unspoofable marker.
    fn file_key(&self, file: &File) -> io::Result<FileKey> {
        // SAFETY: each class is paired with its documented output struct.
        let (id, basic) =
            unsafe { (query::<FILE_ID_INFO>(file, FileIdInfo)?, query::<FILE_BASIC_INFO>(file, FileBasicInfo)?) };
        Ok(FileKey {
            volume: id.VolumeSerialNumber,
            file: u128::from_le_bytes(id.FileId.Identifier),
            size: file.metadata()?.len(),
            marker: (basic.LastWriteTime as u64 as u128) << 64 | basic.ChangeTime as u64 as u128,
        })
    }

    fn is_trusted(&self, path: &Path, file: &File, _sha256: &[u8; 32]) -> bool {
        signer(path, file).is_some_and(|s| self.publishers.contains(&s))
    }

    fn dir_keys(&self, dir: &Path) -> Option<HashMap<OsString, FileKey>> {
        const LEN: usize = 64 * 1024;
        const NAME: usize = offset_of!(FILE_ID_EXTD_DIR_INFO, FileName);
        let handle = OpenOptions::new()
            .access_mode(FILE_LIST_DIRECTORY | SYNCHRONIZE)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(dir)
            .ok()?;
        // SAFETY: FileIdInfo writes a FILE_ID_INFO.
        let volume = unsafe { query::<FILE_ID_INFO>(&handle, FileIdInfo) }.ok()?.VolumeSerialNumber;
        // u64s for 8-byte alignment. Two spare words past LEN so reading a whole header struct (which is padded
        // past FileName) stays inside the allocation for an entry that ends near LEN.
        let mut buf = vec![0u64; LEN / 8 + 2];
        let mut keys = HashMap::new();
        let mut class = FileIdExtdDirectoryRestartInfo;
        loop {
            // SAFETY: the buffer is at least LEN bytes and the class writes FILE_ID_EXTD_DIR_INFO records.
            let ok = unsafe {
                GetFileInformationByHandleEx(handle.as_raw_handle(), class, buf.as_mut_ptr().cast(), LEN as u32)
            };
            if ok == 0 {
                // Also hit on FAT/exFAT or shares that don't support the class: caller falls back to per-file opens.
                return (io::Error::last_os_error().raw_os_error() == Some(ERROR_NO_MORE_FILES as i32)).then_some(keys);
            }
            class = FileIdExtdDirectoryInfo;
            let base = buf.as_ptr().cast::<u8>();
            let mut off = 0;
            loop {
                if off % 8 != 0 || off + NAME > LEN {
                    return None;
                }
                // SAFETY: off is aligned and off + size_of::<FILE_ID_EXTD_DIR_INFO>() <= LEN + 16 (buffer slack).
                let e = unsafe { std::ptr::read(base.add(off).cast::<FILE_ID_EXTD_DIR_INFO>()) };
                let name_len = e.FileNameLength as usize;
                if off + NAME + name_len > LEN {
                    return None;
                }
                if e.FileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT) == 0 {
                    // SAFETY: bounds checked above; FileName is 2-byte aligned (off is 8-aligned, NAME is even).
                    let name = unsafe { std::slice::from_raw_parts(base.add(off + NAME).cast::<u16>(), name_len / 2) };
                    keys.insert(
                        OsString::from_wide(name),
                        FileKey {
                            volume,
                            file: u128::from_le_bytes(e.FileId.Identifier),
                            size: e.EndOfFile as u64,
                            marker: (e.LastWriteTime as u64 as u128) << 64 | e.ChangeTime as u64 as u128,
                        },
                    );
                }
                if e.NextEntryOffset == 0 {
                    break;
                }
                off += e.NextEntryOffset as usize;
            }
        }
    }
}

/// `GetFileInformationByHandleEx` into a `T`.
/// SAFETY: `T` must be the plain-data struct the API writes for `class`.
unsafe fn query<T>(file: &File, class: FILE_INFO_BY_HANDLE_CLASS) -> io::Result<T> {
    // SAFETY: T is plain data (all-zero is valid) and the buffer is exactly size_of::<T>() bytes.
    unsafe {
        let mut info: T = std::mem::zeroed();
        let ok = GetFileInformationByHandleEx(
            file.as_raw_handle(),
            class,
            (&mut info as *mut T).cast(),
            size_of::<T>() as u32,
        );
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(info)
    }
}

/// Display name of the file's verified Authenticode signer: the embedded signature, or the system catalog
/// when there is none. `None` on any failure. Revocation is not checked and nothing is fetched from the network.
/// Restores the file position afterwards.
fn signer(path: &Path, file: &File) -> Option<String> {
    let mut f = file;
    let pos = f.stream_position().ok()?;
    let path: Vec<u16> = path.as_os_str().encode_wide().chain(once(0)).collect();
    let handle = file.as_raw_handle();
    // The APIs read through the handle; start them at offset 0 whatever the caller did.
    let mut rewind = || f.seek(SeekFrom::Start(0)).is_ok();

    let mut info = WINTRUST_FILE_INFO {
        cbStruct: size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: path.as_ptr(),
        hFile: handle,
        pgKnownSubject: null_mut(),
    };
    let result = if !rewind() {
        None
    } else {
        // SAFETY: `info` and the buffers it points to outlive the call.
        match unsafe { verify(WTD_CHOICE_FILE, (&mut info as *mut WINTRUST_FILE_INFO).cast()) } {
            (TRUST_E_NOSIGNATURE | TRUST_E_SUBJECT_FORM_UNKNOWN, _) => {
                // Older catalogs only have SHA1 entries.
                [BCRYPT_SHA256_ALGORITHM, BCRYPT_SHA1_ALGORITHM]
                    .into_iter()
                    .find_map(|alg| if rewind() { catalog_signer(alg, &path, handle) } else { Some(None) })
                    .flatten()
            }
            (_, signer) => signer,
        }
    };
    let _ = f.seek(SeekFrom::Start(pos));
    result
}

/// `None`: no catalog has this file's hash. `Some(signer)`: the first catalog that does, verified.
/// ponytail: only the first matching catalog is tried; enumerate further ones if a file in several catalogs is
/// signed by an allowlisted publisher only in a later one.
fn catalog_signer(alg: PCWSTR, path: &[u16], handle: HANDLE) -> Option<Option<String>> {
    let mut admin = 0;
    // SAFETY: out-pointer is valid; null subsystem = all catalog databases; released below.
    if unsafe { CryptCATAdminAcquireContext2(&mut admin, null(), alg, null(), 0) } == 0 {
        return None;
    }
    let mut hash = [0u8; 64];
    let mut len = hash.len() as u32;
    let mut result = None;
    // SAFETY: `hash` holds `len` bytes; `admin` is live until the release at the end.
    unsafe {
        if CryptCATAdminCalcHashFromFileHandle2(admin, handle, &mut len, hash.as_mut_ptr(), 0) != 0 {
            let cat = CryptCATAdminEnumCatalogFromHash(admin, hash.as_ptr(), len, 0, null_mut());
            if cat != 0 {
                let mut cat_info = CATALOG_INFO { cbStruct: size_of::<CATALOG_INFO>() as u32, ..Default::default() };
                result = Some(None);
                if CryptCATCatalogInfoFromContext(cat, &mut cat_info, 0) != 0 {
                    let tag: Vec<u16> = hash[..len as usize]
                        .iter()
                        .map(|b| format!("{b:02X}"))
                        .collect::<String>()
                        .encode_utf16()
                        .chain(once(0))
                        .collect();
                    let mut info = WINTRUST_CATALOG_INFO {
                        cbStruct: size_of::<WINTRUST_CATALOG_INFO>() as u32,
                        pcwszCatalogFilePath: cat_info.wszCatalogFile.as_ptr(),
                        pcwszMemberTag: tag.as_ptr(),
                        pcwszMemberFilePath: path.as_ptr(),
                        hMemberFile: handle,
                        pbCalculatedFileHash: hash.as_mut_ptr(),
                        cbCalculatedFileHash: len,
                        hCatAdmin: admin,
                        ..Default::default()
                    };
                    result = Some(verify(WTD_CHOICE_CATALOG, (&mut info as *mut WINTRUST_CATALOG_INFO).cast()).1);
                }
                CryptCATAdminReleaseCatalogContext(admin, cat, 0);
            }
        }
        CryptCATAdminReleaseContext(admin, 0);
    }
    result
}

/// WinVerifyTrust (generic verify v2, no UI, no revocation, no network). Returns the status and, when it is
/// success, the signer's display name. Always closes the trust state.
/// SAFETY: `info` must point to the struct matching `choice`, valid for the call.
unsafe fn verify(choice: u32, info: *mut c_void) -> (i32, Option<String>) {
    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    let mut data = WINTRUST_DATA {
        cbStruct: size_of::<WINTRUST_DATA>() as u32,
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_NONE,
        dwUnionChoice: choice,
        Anonymous: WINTRUST_DATA_0 { pFile: info.cast() },
        dwStateAction: WTD_STATEACTION_VERIFY,
        dwProvFlags: WTD_CACHE_ONLY_URL_RETRIEVAL,
        ..Default::default()
    };
    // SAFETY: `data` is fully initialized; the state it returns is read before WTD_STATEACTION_CLOSE frees it.
    unsafe {
        let status = WinVerifyTrust(null_mut(), &mut action, (&mut data as *mut WINTRUST_DATA).cast());
        let signer = if status == 0 { signer_name(data.hWVTStateData) } else { None };
        data.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(null_mut(), &mut action, (&mut data as *mut WINTRUST_DATA).cast());
        (status, signer)
    }
}

/// Simple display name (usually the subject CN) of the leaf signer certificate.
/// SAFETY: `state` must be a live WinVerifyTrust state handle.
unsafe fn signer_name(state: HANDLE) -> Option<String> {
    // SAFETY: every pointer is null-checked before use; all are owned by `state`, which outlives this call.
    unsafe {
        let prov = WTHelperProvDataFromStateData(state);
        if prov.is_null() {
            return None;
        }
        let sgnr = WTHelperGetProvSignerFromChain(prov, 0, 0, 0);
        if sgnr.is_null() || (*sgnr).csCertChain == 0 || (*sgnr).pasCertChain.is_null() {
            return None;
        }
        let cert = (*(*sgnr).pasCertChain).pCert;
        if cert.is_null() {
            return None;
        }
        // Length includes the terminating NUL; 1 means empty.
        let len = CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, null(), null_mut(), 0);
        if len <= 1 {
            return None;
        }
        let mut buf = vec![0u16; len as usize];
        let len = CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, null(), buf.as_mut_ptr(), len);
        buf.truncate(len.saturating_sub(1) as usize);
        String::from_utf16(&buf).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::path::PathBuf;
    use std::time::Instant;

    const NOTEPAD: &str = r"C:\Windows\System32\notepad.exe";
    const GIT: &str = r"C:\Program Files\Git\cmd\git.exe";

    fn platform(publishers: &[&str]) -> WindowsPlatform {
        WindowsPlatform::new(&TrustConfig { enabled: true, publishers: publishers.iter().map(|&s| s.into()).collect() })
    }

    fn trusted(p: &WindowsPlatform, path: &Path) -> bool {
        p.is_trusted(path, &File::open(path).unwrap(), &[0; 32])
    }

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("av-sensors-windows-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Copies `src` into `dir`, checks the copy is still trusted, flips one byte at 0x200 (PE headers, inside the
    /// Authenticode hash), checks it no longer is.
    fn assert_flip_breaks_trust(p: &WindowsPlatform, src: &str, dir: &Path) {
        let copy = dir.join(Path::new(src).file_name().unwrap());
        std::fs::copy(src, &copy).unwrap();
        assert!(trusted(p, &copy), "unmodified copy of {src}");
        let mut data = std::fs::read(&copy).unwrap();
        data[0x200] ^= 0xFF;
        std::fs::write(&copy, &data).unwrap();
        assert!(!trusted(p, &copy), "flipped copy of {src}");
    }

    #[test]
    fn notepad_is_catalog_signed_by_microsoft_windows() {
        let file = File::open(NOTEPAD).unwrap();
        let name = signer(Path::new(NOTEPAD), &file);
        println!("notepad signer: {name:?}");
        assert_eq!(name.as_deref(), Some("Microsoft Windows"));
        assert!(trusted(&platform(&["Microsoft Windows"]), Path::new(NOTEPAD)));
        assert!(!trusted(&platform(&["Microsoft Corporation"]), Path::new(NOTEPAD)));
    }

    #[test]
    fn position_is_ignored_and_restored() {
        let mut file = File::open(NOTEPAD).unwrap();
        file.read_to_end(&mut Vec::new()).unwrap();
        let end = file.stream_position().unwrap();
        assert!(platform(&["Microsoft Windows"]).is_trusted(Path::new(NOTEPAD), &file, &[0; 32]));
        assert_eq!(file.stream_position().unwrap(), end);
    }

    #[test]
    fn unsigned_exe_not_trusted() {
        let exe = std::env::current_exe().unwrap();
        assert_eq!(signer(&exe, &File::open(&exe).unwrap()), None);
        assert!(!trusted(&platform(&["Microsoft Windows", "Microsoft Corporation"]), &exe));
    }

    #[test]
    fn embedded_signer_must_be_listed() {
        if !Path::new(GIT).exists() {
            println!("skipped: {GIT} not found");
            return;
        }
        let name = signer(Path::new(GIT), &File::open(GIT).unwrap()).expect("git.exe has a valid signature");
        println!("git signer: {name:?}");
        assert!(!trusted(&platform(&["Microsoft Windows", "Microsoft Corporation"]), Path::new(GIT)));
        assert!(trusted(&platform(&[&name]), Path::new(GIT)));
    }

    #[test]
    fn flipped_byte_not_trusted() {
        let dir = temp_dir("flip");
        assert_flip_breaks_trust(&platform(&["Microsoft Windows"]), NOTEPAD, &dir);
        if Path::new(GIT).exists() {
            let name = signer(Path::new(GIT), &File::open(GIT).unwrap()).unwrap();
            assert_flip_breaks_trust(&platform(&[&name]), GIT, &dir);
        } else {
            println!("skipped embedded case: {GIT} not found");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn file_key_tracks_identity_and_changes() {
        let dir = temp_dir("key");
        let (a, b) = (dir.join("a"), dir.join("b"));
        std::fs::write(&a, b"one").unwrap();
        std::fs::write(&b, b"one").unwrap();
        let p = platform(&[]);
        let key = |path: &Path| p.file_key(&File::open(path).unwrap()).unwrap();

        let first = key(&a);
        assert_eq!(first, key(&a));
        assert_eq!(first.size, 3);
        assert_ne!(first.file, key(&b).file);

        std::thread::sleep(std::time::Duration::from_millis(20)); // NTFS timestamps are 100 ns but may be coarser
        std::fs::OpenOptions::new().write(true).open(&a).unwrap().write_all(b"two").unwrap();
        let second = key(&a);
        assert_eq!((second.volume, second.file, second.size), (first.volume, first.file, first.size));
        assert_ne!(second.marker, first.marker);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn dir_keys_match_file_key() {
        let dir = temp_dir("dirkeys");
        std::fs::create_dir(dir.join("sub")).unwrap();
        std::fs::write(dir.join("sub/inner"), b"x").unwrap();
        for (name, data) in [("a.txt", &b"one"[..]), ("b.bin", &[0u8; 5000][..]), ("ünï cödé", &b""[..])] {
            std::fs::write(dir.join(name), data).unwrap();
        }
        let p = platform(&[]);
        let keys = p.dir_keys(&dir).unwrap();
        assert_eq!(keys.len(), 3, "{keys:?}");
        for (name, key) in &keys {
            assert_eq!(*key, p.file_key(&File::open(dir.join(name)).unwrap()).unwrap(), "{name:?}");
        }
        assert!(!keys.contains_key(std::ffi::OsStr::new("sub")));
        assert!(p.dir_keys(&dir.join("missing")).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// NTFS copies size/times into the directory entry lazily; check what the listing shows while a writer
    /// still holds the file open and after it closes.
    #[test]
    fn dir_keys_see_writes() {
        let dir = temp_dir("dirkeys-write");
        let path = dir.join("f");
        std::fs::write(&path, b"abc").unwrap();
        let p = platform(&[]);
        let name = std::ffi::OsStr::new("f");
        let before = p.dir_keys(&dir).unwrap()[name];
        std::thread::sleep(std::time::Duration::from_millis(20));

        let mut writer = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        writer.write_all(b"xyz").unwrap(); // same size: only the marker can show the change
        let listed = p.dir_keys(&dir).unwrap()[name];
        let actual = p.file_key(&File::open(&path).unwrap()).unwrap();
        println!(
            "writer open, same size: listing current = {}, listing marker changed = {}",
            listed == actual,
            listed.marker != before.marker
        );
        writer.write_all(b"grow").unwrap();
        let listed = p.dir_keys(&dir).unwrap()[name];
        let actual = p.file_key(&File::open(&path).unwrap()).unwrap();
        println!(
            "writer open, grown: listing size {} vs {}, write time current = {}, change time current = {}",
            listed.size,
            actual.size,
            listed.marker >> 64 == actual.marker >> 64,
            listed.marker as u64 == actual.marker as u64
        );
        drop(writer);

        let listed = p.dir_keys(&dir).unwrap()[name];
        assert_eq!(listed, p.file_key(&File::open(&path).unwrap()).unwrap());
        assert_ne!(listed.marker, before.marker);

        std::fs::write(&path, b"longer").unwrap();
        let listed = p.dir_keys(&dir).unwrap()[name];
        assert_eq!(listed, p.file_key(&File::open(&path).unwrap()).unwrap());
        assert_eq!(listed.size, 6);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `AVD_TREE=<dir from gen_tree> cargo test -p sensors-windows -- --ignored --nocapture dir_keys_timing`
    #[test]
    #[ignore = "benchmark; needs AVD_TREE"]
    fn dir_keys_timing() {
        let root = std::path::PathBuf::from(std::env::var_os("AVD_TREE").expect("set AVD_TREE"));
        let mut dirs = vec![root];
        let mut i = 0;
        while i < dirs.len() {
            for entry in std::fs::read_dir(&dirs[i]).unwrap() {
                let entry = entry.unwrap();
                if entry.file_type().unwrap().is_dir() {
                    dirs.push(entry.path());
                }
            }
            i += 1;
        }
        let p = platform(&[]);
        for run in 0..3 {
            let start = Instant::now();
            let files: usize = dirs.iter().map(|d| p.dir_keys(d).unwrap().len()).sum();
            println!("run {run}: {} dirs, {files} files, {:?}", dirs.len(), start.elapsed());
        }
    }

    /// `cargo test -p sensors-windows --release -- --ignored --nocapture timings`
    #[test]
    #[ignore]
    fn timings() {
        let p = platform(&["Microsoft Windows", "Microsoft Corporation"]);
        let exe = std::env::current_exe().unwrap();
        let edge = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe";
        let ntdll = r"C:\Windows\System32\ntdll.dll";
        for path in [Path::new(NOTEPAD), Path::new(ntdll), Path::new(GIT), Path::new(edge), &exe] {
            if !path.exists() {
                continue;
            }
            let file = File::open(path).unwrap();
            let n = 20;
            let start = Instant::now();
            for _ in 0..n {
                std::hint::black_box(p.is_trusted(path, &file, &[0; 32]));
            }
            let size = file.metadata().unwrap().len();
            let who = signer(path, &file);
            println!("{}: {size} bytes, signer {who:?}, {:?} per call", path.display(), start.elapsed() / n);
        }
    }
}
