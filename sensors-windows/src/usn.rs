//! Real-time file monitoring through the NTFS USN change journal.
//!
//! One blocking reader thread per NTFS volume that holds a watched root: zero CPU while idle, no lost events on
//! bursts, and changes made while the daemon was down are replayed from a saved [`Cursor`].
//!
//! Limitations:
//! - Needs admin (opening a volume handle); the service runs as LocalSystem.
//! - NTFS only: FAT/exFAT sticks, ReFS and network shares are not covered.
//! - Detection only: a record arrives after the write is closed, so a dropped file can run before its scan
//!   finishes. Blocking needs a kernel minifilter.

use std::collections::HashMap;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::iter::once;
use std::mem::{offset_of, size_of, size_of_val};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread;
use std::time::Duration;

use av_core::watch::Pipeline;
use windows_sys::Win32::Foundation::{ERROR_JOURNAL_NOT_ACTIVE, INVALID_HANDLE_VALUE, MAX_PATH};
use windows_sys::Win32::Storage::FileSystem::{
    FileIdType, GetFinalPathNameByHandleW, GetVolumeNameForVolumeMountPointW, GetVolumePathNameW, OpenFileById,
    FILE_ATTRIBUTE_DIRECTORY, FILE_FLAG_BACKUP_SEMANTICS, FILE_ID_DESCRIPTOR, FILE_ID_DESCRIPTOR_0,
    FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, VOLUME_NAME_DOS,
};
use windows_sys::Win32::System::Ioctl::{
    CREATE_USN_JOURNAL_DATA, FSCTL_CREATE_USN_JOURNAL, FSCTL_QUERY_USN_JOURNAL, FSCTL_READ_USN_JOURNAL,
    READ_USN_JOURNAL_DATA_V0, USN_JOURNAL_DATA_V0, USN_REASON_CLOSE, USN_REASON_DATA_EXTEND, USN_REASON_DATA_OVERWRITE,
    USN_REASON_DATA_TRUNCATION, USN_REASON_FILE_CREATE, USN_REASON_RENAME_NEW_NAME, USN_RECORD_V2,
};
use windows_sys::Win32::System::IO::DeviceIoControl;

/// Where a volume's reader is (or resumes): the next USN to read in journal `journal_id`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cursor {
    /// Volume GUID path without the trailing backslash, like `\\?\Volume{...}`.
    pub volume: String,
    pub journal_id: u64,
    pub usn: i64,
}

/// Starts one blocking reader thread per NTFS volume that holds a watched root. Each reader resumes from its saved
/// cursor when valid; when there is none, the journal ID changed, or the saved USN was purged, it logs and calls
/// `pipeline.rescan()` then starts at the journal's end. Read errors (journal wrapped past us, deleted or
/// recreated) do the same. Returns live cursors, updated by each reader after it has pushed a batch's paths.
/// Errors only if no volume could be opened at all (e.g. not admin); per-volume failures are logged.
pub fn watch(roots: &[PathBuf], saved: &[Cursor], pipeline: Arc<Pipeline>) -> io::Result<Vec<Arc<Mutex<Cursor>>>> {
    let mut seen = Vec::new();
    let mut cursors = Vec::new();
    let mut failure = None;
    for root in roots {
        let name = match volume_name(root) {
            Ok(name) => name,
            Err(e) => {
                log::warn!("{}: no volume: {e}; not watched", root.display());
                failure = Some(e);
                continue;
            }
        };
        if seen.contains(&name) {
            continue;
        }
        seen.push(name.clone());
        match start(name.clone(), saved.iter().find(|c| c.volume == name), pipeline.clone()) {
            Ok(cursor) => cursors.push(cursor),
            Err(e) => {
                log::warn!("{name} ({}): USN journal: {e}; not watched", root.display());
                failure = Some(e);
            }
        }
    }
    match failure {
        Some(e) if cursors.is_empty() => Err(e),
        _ => Ok(cursors),
    }
}

/// Text file, one `volume\tjournal_id\tusn` per line. Missing or corrupt → empty (logged).
pub fn load_cursors(path: &Path) -> Vec<Cursor> {
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) => {
            log::info!("{}: {e}; no saved USN cursors", path.display());
            return Vec::new();
        }
    };
    let parsed: Option<Vec<Cursor>> = text
        .lines()
        .filter(|line| !line.is_empty())
        .map(|line| {
            let mut f = line.split('\t');
            let c =
                Cursor { volume: f.next()?.into(), journal_id: f.next()?.parse().ok()?, usn: f.next()?.parse().ok()? };
            f.next().is_none().then_some(c)
        })
        .collect();
    parsed.unwrap_or_else(|| {
        log::warn!("{}: corrupt; ignoring saved USN cursors", path.display());
        Vec::new()
    })
}

/// Atomic: writes `<path>.tmp` then renames it over `path`.
pub fn save_cursors(path: &Path, cursors: &[Cursor]) -> io::Result<()> {
    let text: String = cursors.iter().map(|c| format!("{}\t{}\t{}\n", c.volume, c.journal_id, c.usn)).collect();
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    fs::write(&tmp, text)?;
    fs::rename(&tmp, path)
}

const BUF_LEN: usize = 64 * 1024;
/// Content changes we scan for; a record must also carry USN_REASON_CLOSE.
const WANTED: u32 = USN_REASON_DATA_OVERWRITE
    | USN_REASON_DATA_EXTEND
    | USN_REASON_DATA_TRUNCATION
    | USN_REASON_FILE_CREATE
    | USN_REASON_RENAME_NEW_NAME;
const MAX_PARENTS: usize = 10_000;
const RETRY: Duration = Duration::from_secs(10);

fn start(name: String, saved: Option<&Cursor>, pipeline: Arc<Pipeline>) -> io::Result<Arc<Mutex<Cursor>>> {
    let (mut volume, data) = Volume::open(name.clone())?;
    let why = match saved {
        None => "no saved cursor",
        Some(c) if c.journal_id != data.UsnJournalID => "journal ID changed",
        Some(c) if !(data.FirstUsn..=data.NextUsn).contains(&c.usn) => "saved USN no longer in the journal",
        Some(c) => {
            volume.next = c.usn;
            ""
        }
    };
    if !why.is_empty() {
        // Starts at the journal's end, so the walk covers everything before it.
        log::info!("{name}: {why}; rescanning watched paths");
        pipeline.rescan();
    }
    let cursor = Arc::new(Mutex::new(volume.cursor()));
    let live = cursor.clone();
    thread::Builder::new().name(format!("usn {name}")).spawn(move || run(volume, live, pipeline))?;
    Ok(cursor)
}

fn run(mut volume: Volume, cursor: Arc<Mutex<Cursor>>, pipeline: Arc<Pipeline>) {
    let mut buf = vec![0u64; BUF_LEN / 8];
    let mut failed = false;
    loop {
        match volume.read(&mut buf) {
            Ok(paths) => {
                failed = false;
                paths.into_iter().for_each(|p| pipeline.push(p, None)); // USN records carry no pid
            }
            Err(e) => {
                log::warn!("{}: reading the USN journal: {e}; rescanning watched paths", volume.name);
                if failed {
                    thread::sleep(RETRY); // failing right after a reopen: don't spin on rescans
                }
                failed = true;
                let name = volume.name.clone();
                volume = loop {
                    match Volume::open(name.clone()) {
                        Ok((v, _)) => break v,
                        Err(e) => {
                            log::warn!("{name}: reopening the USN journal: {e}; retrying in {RETRY:?}");
                            thread::sleep(RETRY);
                        }
                    }
                };
                pipeline.rescan();
            }
        }
        *cursor.lock().unwrap_or_else(PoisonError::into_inner) = volume.cursor();
    }
}

struct Volume {
    name: String,
    file: File,
    journal: u64,
    next: i64,
    /// Parent directory FRN → its path.
    parents: HashMap<u64, PathBuf>,
}

impl Volume {
    /// Opens the volume and its journal (created when not active), positioned at the journal's end.
    fn open(name: String) -> io::Result<(Volume, USN_JOURNAL_DATA_V0)> {
        let file = OpenOptions::new().read(true).share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE).open(&name)?;
        let mut data = USN_JOURNAL_DATA_V0::default();
        // SAFETY: no input; a V0-sized buffer gets a USN_JOURNAL_DATA_V0.
        let query = |data: &mut USN_JOURNAL_DATA_V0| unsafe { ioctl(&file, FSCTL_QUERY_USN_JOURNAL, &(), data) };
        match query(&mut data) {
            Err(e) if e.raw_os_error() == Some(ERROR_JOURNAL_NOT_ACTIVE as i32) => {
                log::info!("{name}: creating the USN journal");
                let create = CREATE_USN_JOURNAL_DATA { MaximumSize: 32 << 20, AllocationDelta: 8 << 20 };
                // SAFETY: CREATE_USN_JOURNAL_DATA in, nothing out.
                unsafe { ioctl(&file, FSCTL_CREATE_USN_JOURNAL, &create, &mut ())? };
                query(&mut data)?;
            }
            r => {
                r?;
            }
        }
        let volume = Volume { name, file, journal: data.UsnJournalID, next: data.NextUsn, parents: HashMap::new() };
        Ok((volume, data))
    }

    fn cursor(&self) -> Cursor {
        Cursor { volume: self.name.clone(), journal_id: self.journal, usn: self.next }
    }

    /// Blocks until there are records past `next`, advances `next` past them and returns the paths to scan.
    fn read(&mut self, buf: &mut [u64]) -> io::Result<Vec<PathBuf>> {
        let input = READ_USN_JOURNAL_DATA_V0 {
            StartUsn: self.next,
            ReasonMask: USN_REASON_CLOSE | WANTED,
            ReturnOnlyOnClose: 1,
            Timeout: 0,
            BytesToWaitFor: 1,
            UsnJournalID: self.journal,
        };
        // SAFETY: READ_USN_JOURNAL_DATA_V0 in; the output is bytes, at most size_of_val(buf) of them.
        let n = unsafe { ioctl(&self.file, FSCTL_READ_USN_JOURNAL, &input, buf)? };
        // SAFETY: the call wrote n <= size_of_val(buf) bytes into buf.
        let bytes = unsafe { std::slice::from_raw_parts(buf.as_ptr().cast::<u8>(), n.min(size_of_val(buf))) };
        let (next, records) =
            parse(bytes).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "malformed USN records"))?;
        let mut paths = Vec::new();
        for r in records {
            if r.reason & USN_REASON_CLOSE == 0 || r.reason & WANTED == 0 {
                continue;
            }
            if r.attributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
                // A directory moved in: the pipeline walks it. Cached paths below it are stale now.
                if r.reason & USN_REASON_RENAME_NEW_NAME == 0 {
                    continue;
                }
                self.parents.clear();
            }
            // Unresolvable parent: deleted since; nothing left to scan.
            if let Some(dir) = self.parent(r.parent) {
                paths.push(dir.join(r.name));
            }
        }
        self.next = next;
        Ok(paths)
    }

    fn parent(&mut self, frn: u64) -> Option<PathBuf> {
        if let Some(path) = self.parents.get(&frn) {
            return Some(path.clone());
        }
        let id = FILE_ID_DESCRIPTOR {
            dwSize: size_of::<FILE_ID_DESCRIPTOR>() as u32,
            Type: FileIdType,
            Anonymous: FILE_ID_DESCRIPTOR_0 { FileId: frn as i64 },
        };
        // SAFETY: `id` is a valid descriptor for the call; the handle is owned by the File below.
        let handle = unsafe {
            OpenFileById(
                self.file.as_raw_handle(),
                &id,
                FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                null(),
                FILE_FLAG_BACKUP_SEMANTICS,
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return None;
        }
        // SAFETY: a fresh handle we own.
        let dir = unsafe { File::from_raw_handle(handle) };
        let path = final_path(&dir)?;
        if self.parents.len() >= MAX_PARENTS {
            self.parents.clear();
        }
        self.parents.insert(frn, path.clone());
        Some(path)
    }
}

/// DOS path of an open file, without the `\\?\` prefix.
fn final_path(file: &File) -> Option<PathBuf> {
    let mut buf = vec![0u16; MAX_PATH as usize];
    loop {
        // SAFETY: buf holds buf.len() u16s.
        let n = unsafe {
            GetFinalPathNameByHandleW(file.as_raw_handle(), buf.as_mut_ptr(), buf.len() as u32, VOLUME_NAME_DOS)
        } as usize;
        match n {
            0 => return None,
            n if n < buf.len() => break buf.truncate(n),
            n => buf.resize(n, 0), // too small: n is the size needed, NUL included
        }
    }
    let verbatim: Vec<u16> = r"\\?\".encode_utf16().collect();
    Some(OsString::from_wide(buf.strip_prefix(&verbatim[..]).unwrap_or(&buf)).into())
}

/// `\\?\Volume{...}` (no trailing backslash) of the volume holding `path`.
fn volume_name(path: &Path) -> io::Result<String> {
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(once(0)).collect();
    let mut mount = vec![0u16; wide.len() + MAX_PATH as usize];
    let mut name = [0u16; 64];
    // SAFETY: each buffer holds the length passed with it; `mount` is NUL-terminated on success.
    let ok = unsafe {
        GetVolumePathNameW(wide.as_ptr(), mount.as_mut_ptr(), mount.len() as u32) != 0
            && GetVolumeNameForVolumeMountPointW(mount.as_ptr(), name.as_mut_ptr(), name.len() as u32) != 0
    };
    if !ok {
        return Err(io::Error::last_os_error());
    }
    let len = name.iter().position(|&c| c == 0).unwrap_or(name.len());
    Ok(String::from_utf16_lossy(&name[..len]).trim_end_matches('\\').into())
}

/// `DeviceIoControl` without overlapped I/O; returns the bytes written to `out`.
/// SAFETY: `input` and `out` must be the buffers `code` expects (`()` for none).
unsafe fn ioctl<I, O: ?Sized>(file: &File, code: u32, input: &I, out: &mut O) -> io::Result<usize> {
    let mut n = 0;
    // SAFETY: both buffers are valid for their sizes for the duration of the call.
    let ok = unsafe {
        DeviceIoControl(
            file.as_raw_handle(),
            code,
            (input as *const I).cast(),
            size_of_val(input) as u32,
            (out as *mut O).cast(),
            size_of_val(out) as u32,
            &mut n,
            null_mut(),
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(n as usize)
}

#[derive(Debug, PartialEq)]
struct Record {
    parent: u64,
    reason: u32,
    attributes: u32,
    name: OsString,
}

/// Splits FSCTL_READ_USN_JOURNAL output: the next USN, then USN_RECORD_V2 records (other versions skipped).
/// `None` if any record does not fit.
fn parse(buf: &[u8]) -> Option<(i64, Vec<Record>)> {
    const NAME: usize = offset_of!(USN_RECORD_V2, FileName);
    fn at<const N: usize>(b: &[u8], off: usize) -> [u8; N] {
        b[off..off + N].try_into().unwrap()
    }
    let next = i64::from_le_bytes(buf.get(..8)?.try_into().ok()?);
    let mut records = Vec::new();
    let mut off = 8;
    while off < buf.len() {
        let len = u32::from_le_bytes(buf.get(off..off + 4)?.try_into().ok()?) as usize;
        if len < NAME {
            return None;
        }
        let r = buf.get(off..off + len)?; // every header field is in bounds from here on
        if u16::from_le_bytes(at(r, offset_of!(USN_RECORD_V2, MajorVersion))) == 2 {
            let name_off = u16::from_le_bytes(at(r, offset_of!(USN_RECORD_V2, FileNameOffset))) as usize;
            let name_len = u16::from_le_bytes(at(r, offset_of!(USN_RECORD_V2, FileNameLength))) as usize;
            let name: Vec<u16> = r
                .get(name_off..name_off + name_len)?
                .as_chunks::<2>()
                .0
                .iter()
                .map(|&c| u16::from_le_bytes(c))
                .collect();
            records.push(Record {
                parent: u64::from_le_bytes(at(r, offset_of!(USN_RECORD_V2, ParentFileReferenceNumber))),
                reason: u32::from_le_bytes(at(r, offset_of!(USN_RECORD_V2, Reason))),
                attributes: u32::from_le_bytes(at(r, offset_of!(USN_RECORD_V2, FileAttributes))),
                name: OsString::from_wide(&name),
            });
        }
        off += len;
    }
    Some((next, records))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A USN_RECORD_V2 as NTFS lays it out: header, name, padded to 8 bytes.
    fn record(version: u16, parent: u64, reason: u32, attributes: u32, name: &str) -> Vec<u8> {
        const NAME: usize = offset_of!(USN_RECORD_V2, FileName);
        let name: Vec<u8> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let len = (NAME + name.len()).next_multiple_of(8);
        let mut r = vec![0u8; len];
        let mut put = |off: usize, bytes: &[u8]| r[off..off + bytes.len()].copy_from_slice(bytes);
        put(offset_of!(USN_RECORD_V2, RecordLength), &(len as u32).to_le_bytes());
        put(offset_of!(USN_RECORD_V2, MajorVersion), &version.to_le_bytes());
        put(offset_of!(USN_RECORD_V2, ParentFileReferenceNumber), &parent.to_le_bytes());
        put(offset_of!(USN_RECORD_V2, Reason), &reason.to_le_bytes());
        put(offset_of!(USN_RECORD_V2, FileAttributes), &attributes.to_le_bytes());
        put(offset_of!(USN_RECORD_V2, FileNameLength), &(name.len() as u16).to_le_bytes());
        put(offset_of!(USN_RECORD_V2, FileNameOffset), &(NAME as u16).to_le_bytes());
        put(NAME, &name);
        r
    }

    #[test]
    fn parse_records() {
        let mut buf = 1234i64.to_le_bytes().to_vec();
        buf.extend(record(2, 7, USN_REASON_CLOSE | USN_REASON_FILE_CREATE, 0x20, "ünï.exe"));
        buf.extend(record(3, 8, 0, 0, "v3 skipped"));
        buf.extend(record(2, 9, USN_REASON_CLOSE, FILE_ATTRIBUTE_DIRECTORY, "d"));
        let (next, records) = parse(&buf).unwrap();
        assert_eq!(next, 1234);
        assert_eq!(
            records,
            [
                Record {
                    parent: 7,
                    reason: USN_REASON_CLOSE | USN_REASON_FILE_CREATE,
                    attributes: 0x20,
                    name: "ünï.exe".into()
                },
                Record { parent: 9, reason: USN_REASON_CLOSE, attributes: FILE_ATTRIBUTE_DIRECTORY, name: "d".into() },
            ]
        );
        assert_eq!(parse(&buf[..8]).unwrap(), (1234, vec![]));

        assert_eq!(parse(&buf[..buf.len() - 1]), None, "truncated record");
        assert_eq!(parse(&buf[..4]), None, "truncated next USN");
        let mut bad = buf.clone();
        bad[8 + offset_of!(USN_RECORD_V2, FileNameLength)] = 200;
        assert_eq!(parse(&bad), None, "name past the record");
        let mut bad = buf.clone();
        bad[8..12].copy_from_slice(&0u32.to_le_bytes());
        assert_eq!(parse(&bad), None, "zero RecordLength");
    }

    #[test]
    fn cursors_roundtrip() {
        let path = std::env::temp_dir().join(format!("av-usn-cursors-{}", std::process::id()));
        let cursors = vec![
            Cursor { volume: r"\\?\Volume{00000000-1111-2222-3333-444444444444}".into(), journal_id: u64::MAX, usn: 0 },
            Cursor { volume: r"\\?\Volume{55555555-1111-2222-3333-444444444444}".into(), journal_id: 1, usn: i64::MAX },
        ];
        save_cursors(&path, &cursors).unwrap();
        assert_eq!(load_cursors(&path), cursors);
        save_cursors(&path, &cursors[..1]).unwrap(); // replaces
        assert_eq!(load_cursors(&path), &cursors[..1]);
        fs::write(&path, "vol\t1\n").unwrap();
        assert_eq!(load_cursors(&path), []);
        fs::remove_file(&path).unwrap();
        assert_eq!(load_cursors(&path), []);
    }

    /// Admin only (opens the volume): a file created in a temp dir comes back with its full path.
    #[test]
    fn reader_resolves_new_file() {
        let dir = std::env::temp_dir().join(format!("av-usn-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let name = volume_name(&dir).unwrap();
        assert!(name.starts_with(r"\\?\Volume{") && name.ends_with('}'), "{name}");
        let mut volume = match Volume::open(name) {
            Ok((volume, _)) => volume,
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                println!("skipped: needs admin");
                return;
            }
            Err(e) => panic!("{e}"),
        };
        let file = dir.join("new file.txt");
        fs::write(&file, b"x").unwrap();
        let expected = fs::canonicalize(&file).unwrap();
        let mut buf = vec![0u64; BUF_LEN / 8];
        // Other activity on the volume shows up too; the record is there, so this ends.
        while !volume.read(&mut buf).unwrap().iter().any(|p| fs::canonicalize(p).ok().as_ref() == Some(&expected)) {}
        let _ = fs::remove_dir_all(&dir);
    }
}
