//! Linux sensors: fanotify, eBPF, RPM trust checks.
#![cfg(target_os = "linux")]

use std::collections::HashMap;
use std::ffi::OsStr;
use std::fs::File;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime};

use av_core::{FileKey, Platform, ProcessOp, TrustConfig};

pub mod fanotify;
pub mod response;

pub use response::notify;

/// Self-protection: owner-only access (0700) to avd's data directory.
pub fn lock_down(dir: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
}

/// True if someone other than root may change `path`: not owned by root, or group/world writable.
pub fn user_writable(path: &Path) -> io::Result<bool> {
    let m = std::fs::metadata(path)?;
    Ok(m.uid() != 0 || m.mode() & 0o022 != 0)
}

/// How often `is_trusted` looks at the rpmdb mtime to see whether packages changed.
const RPMDB_RECHECK: Duration = Duration::from_secs(30);
/// Current Fedora/RHEL first; older releases keep the rpmdb in /var/lib/rpm.
const RPMDB_DIRS: [&str; 2] = ["/usr/lib/sysimage/rpm", "/var/lib/rpm"];
/// One line per package file. `%{=TAG}` repeats the package-level digest algorithm on every line.
const RPM_QUERY: &str = "[%{FILENAMES}\t%{FILEDIGESTS}\t%{FILEFLAGS}\t%{=FILEDIGESTALGO}\n]";
const RPMFILE_CONFIG: u32 = 1;
const PGPHASHALGO_SHA256: u32 = 8;

pub struct LinuxPlatform {
    trust_enabled: bool,
    rpm: Mutex<RpmFiles>,
}

#[derive(Default)]
struct RpmFiles {
    /// Package file path → SHA-256 recorded in the rpmdb. `None` = never trusted
    /// (a %config file, or two packages recording different digests for the path).
    digests: HashMap<PathBuf, Option<[u8; 32]>>,
    db_mtime: Option<SystemTime>,
    /// `None` until the first load.
    checked: Option<Instant>,
}

impl LinuxPlatform {
    /// The rpmdb is loaded on the first `is_trusted` call, not here.
    pub fn new(trust: &TrustConfig) -> Self {
        Self { trust_enabled: trust.enabled, rpm: Mutex::default() }
    }
}

impl Platform for LinuxPlatform {
    fn file_key(&self, file: &File) -> io::Result<FileKey> {
        let m = file.metadata()?; // fstat on the handle being read
        let ns = |secs: i64, nsec: i64| (secs as i128 * 1_000_000_000 + nsec as i128) as u64 as u128;
        Ok(FileKey {
            volume: m.dev(),
            file: m.ino().into(),
            size: m.size(),
            marker: ns(m.mtime(), m.mtime_nsec()) << 64 | ns(m.ctime(), m.ctime_nsec()),
        })
    }

    /// Trusted only when an installed RPM owns the path, it is not %config, and the package's
    /// SHA-256 for it equals `sha256`.
    fn is_trusted(&self, path: &Path, _file: &File, sha256: &[u8; 32]) -> bool {
        if !self.trust_enabled {
            return false;
        }
        let mut rpm = self.rpm.lock().unwrap_or_else(|e| e.into_inner());
        if rpm.checked.is_none_or(|t| t.elapsed() >= RPMDB_RECHECK) {
            let mtime = rpmdb_mtime();
            if rpm.checked.is_none() || mtime != rpm.db_mtime {
                rpm.digests = load_rpm_digests();
                rpm.db_mtime = mtime;
            }
            rpm.checked = Some(Instant::now());
        }
        // rpm records absolute, resolved paths; a relative or symlinked path is tried resolved.
        let recorded = match rpm.digests.get(path) {
            Some(digest) => *digest,
            None => std::fs::canonicalize(path).ok().and_then(|p| rpm.digests.get(&p).copied().flatten()),
        };
        recorded == Some(*sha256)
    }

    fn process(&self, pid: u32, op: ProcessOp) -> io::Result<()> {
        response::process(pid, op)
    }
}

/// Raises niceness to 10 if it is lower, and sets the I/O class to idle. Both are per-thread on Linux:
/// call before spawning threads so they inherit it.
pub fn lower_priority() -> io::Result<()> {
    const IOPRIO_WHO_PROCESS: libc::c_int = 1;
    const IOPRIO_CLASS_IDLE: libc::c_int = 3;
    const IOPRIO_CLASS_SHIFT: libc::c_int = 13;
    // SAFETY: plain syscalls; errno is cleared first because getpriority can legitimately return -1.
    unsafe {
        *libc::__errno_location() = 0;
        let nice = libc::getpriority(libc::PRIO_PROCESS, 0);
        if nice == -1 && *libc::__errno_location() != 0 {
            return Err(io::Error::last_os_error());
        }
        if nice < 10 && libc::setpriority(libc::PRIO_PROCESS, 0, 10) != 0 {
            return Err(io::Error::last_os_error());
        }
        if libc::syscall(libc::SYS_ioprio_set, IOPRIO_WHO_PROCESS, 0, IOPRIO_CLASS_IDLE << IOPRIO_CLASS_SHIFT) != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Blocks SIGTERM and SIGINT in the calling thread and spawns a thread that waits for one, then runs `f`
/// once. Call from main before spawning any thread, so every thread inherits the mask.
pub fn on_terminate(f: impl FnOnce() + Send + 'static) {
    // SAFETY: sigset_t is plain data, initialised by sigemptyset before use.
    let set = unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, libc::SIGTERM);
        libc::sigaddset(&mut set, libc::SIGINT);
        libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut());
        set
    };
    let spawned = std::thread::Builder::new().name("signals".into()).spawn(move || {
        let mut sig = 0;
        // SAFETY: valid set and out pointer.
        unsafe { libc::sigwait(&set, &mut sig) };
        log::info!("signal {sig} received, shutting down");
        f();
    });
    if let Err(e) = spawned {
        log::error!("cannot spawn signal thread: {e}");
    }
}

/// Newest mtime of the rpmdb directory and its files (sqlite writes in place, so the directory alone can miss a change).
fn rpmdb_mtime() -> Option<SystemTime> {
    let dir = Path::new(RPMDB_DIRS.into_iter().find(|d| Path::new(d).is_dir())?);
    let files = std::fs::read_dir(dir).ok()?.flatten().filter_map(|e| e.metadata().ok()?.modified().ok());
    files.chain(dir.metadata().ok()?.modified().ok()).max()
}

/// No rpm, or rpm fails → empty map: nothing is trusted, everything is scanned.
fn load_rpm_digests() -> HashMap<PathBuf, Option<[u8; 32]>> {
    let start = Instant::now();
    let stdout = match Command::new("rpm").args(["-qa", "--qf", RPM_QUERY]).output() {
        Ok(out) if out.status.success() => out.stdout,
        Ok(out) => {
            let err = String::from_utf8_lossy(&out.stderr);
            log::warn!("rpm -qa failed ({}): {}; no package files are trusted", out.status, err.trim());
            return HashMap::new();
        }
        Err(e) => {
            log::warn!("rpm: {e}; no package files are trusted");
            return HashMap::new();
        }
    };
    let mut digests = HashMap::new();
    for line in stdout.split(|&b| b == b'\n') {
        // rsplitn: a tab inside the path stays in the path.
        let mut fields = line.rsplitn(4, |&b| b == b'\t');
        let (Some(algo), Some(flags), Some(digest), Some(path)) =
            (fields.next(), fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        let number = |s: &[u8]| std::str::from_utf8(s).ok()?.parse::<u32>().ok();
        let (Some(flags), Some(algo)) = (number(flags), number(algo)) else { continue };
        if !path.starts_with(b"/") {
            continue;
        }
        let digest = if flags & RPMFILE_CONFIG != 0 {
            None
        } else if algo == PGPHASHALGO_SHA256 {
            // Directories, symlinks and %ghost files have no digest.
            let Some(digest) = parse_sha256(digest) else { continue };
            Some(digest)
        } else {
            continue;
        };
        digests
            .entry(PathBuf::from(OsStr::from_bytes(path)))
            .and_modify(|d| {
                if *d != digest {
                    *d = None;
                }
            })
            .or_insert(digest);
    }
    digests.shrink_to_fit();
    log::info!("rpmdb: {} package files loaded in {:?}", digests.len(), start.elapsed());
    digests
}

fn parse_sha256(hex: &[u8]) -> Option<[u8; 32]> {
    if hex.len() != 64 || !hex.iter().all(u8::is_ascii_hexdigit) {
        return None;
    }
    let mut out = [0u8; 32];
    for (byte, pair) in out.iter_mut().zip(hex.chunks(2)) {
        *byte = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    fn platform() -> LinuxPlatform {
        LinuxPlatform::new(&TrustConfig::default())
    }

    fn sha256(data: &[u8]) -> [u8; 32] {
        Sha256::digest(data).into()
    }

    /// Ubuntu CI has an `rpm` binary but no rpm-owned files: trust tests skip unless rpm owns /usr/bin/ls.
    fn have_rpm() -> bool {
        let ok = Command::new("rpm").args(["-qf", "/usr/bin/ls"]).output().is_ok_and(|o| o.status.success());
        if !ok {
            eprintln!("no rpm-managed system, skipping");
        }
        ok
    }

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("sensors-linux-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn check(p: &LinuxPlatform, path: &Path, digest: &[u8; 32]) -> bool {
        p.is_trusted(path, &File::open(path).unwrap(), digest)
    }

    #[test]
    fn package_binary_trusted_copy_and_modified_not() {
        if !have_rpm() {
            return;
        }
        let p = platform();
        let ls = Path::new("/usr/bin/ls");
        let data = std::fs::read(ls).unwrap();

        let start = Instant::now();
        assert!(check(&p, ls, &sha256(&data)));
        eprintln!("rpmdb load: {:?}, {} entries", start.elapsed(), p.rpm.lock().unwrap().digests.len());
        // usrmerge: /bin is a symlink to /usr/bin; the resolved path is what rpm records.
        assert!(check(&p, Path::new("/bin/ls"), &sha256(&data)));

        let dir = temp_dir("copy");
        let copy = dir.join("ls");
        std::fs::write(&copy, &data).unwrap();
        let copy_trusted = check(&p, &copy, &sha256(&data));

        // Flipping a byte in /usr/bin/ls needs root; the digest of the modified bytes at the
        // original path is what the check would see.
        let mut modified = data;
        modified[100] ^= 1;
        let modified_trusted = check(&p, ls, &sha256(&modified));
        let _ = std::fs::remove_dir_all(&dir);
        assert!(!copy_trusted);
        assert!(!modified_trusted);
    }

    #[test]
    fn config_file_not_trusted_even_when_unmodified() {
        if !have_rpm() {
            return;
        }
        // A %config file of the `setup` package whose on-disk content still matches the rpmdb.
        let out = Command::new("rpm").args(["-q", "--qf", RPM_QUERY, "setup"]).output().unwrap();
        let config = String::from_utf8(out.stdout).unwrap().lines().find_map(|line| {
            let [path, digest, flags, _] = line.split('\t').collect::<Vec<_>>()[..] else { return None };
            let data = std::fs::read(path).ok()?;
            let is_config = flags.parse::<u32>().ok()? & RPMFILE_CONFIG != 0;
            (is_config && parse_sha256(digest.as_bytes()) == Some(sha256(&data))).then(|| (path.to_owned(), data))
        });
        let (path, data) = config.expect("an unmodified %config file from the setup package");
        assert!(!check(&platform(), Path::new(&path), &sha256(&data)), "{path}");
    }

    #[test]
    fn file_key_tracks_identity_and_changes() {
        let p = platform();
        let dir = temp_dir("key");
        let (a, b) = (dir.join("a"), dir.join("b"));
        std::fs::write(&a, b"one").unwrap();
        std::fs::write(&b, b"one").unwrap();
        let key = |path: &Path| p.file_key(&File::open(path).unwrap()).unwrap();

        let first = key(&a);
        assert_eq!(first, key(&a));
        let other = key(&b);
        assert_ne!((first.volume, first.file), (other.volume, other.file));

        // Kernel timestamps are coarse (a jiffy); wait so the write lands on a new tick.
        std::thread::sleep(Duration::from_millis(50));
        std::fs::write(&a, b"two").unwrap(); // same size: only the marker can tell
        let after = key(&a);
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!((first.file, first.size), (after.file, after.size));
        assert_ne!(first.marker, after.marker);
    }
}
