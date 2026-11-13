//! fanotify sensors: scan-on-write (`FAN_CLOSE_WRITE`) and exec blocking (`FAN_OPEN_EXEC_PERM`).
//!
//! Needs `CAP_SYS_ADMIN` and kernel >= 5.0 (`FAN_OPEN_EXEC_PERM`); perm events also need
//! `CONFIG_FANOTIFY_ACCESS_PERMISSIONS`. Both groups mark whole mounts (`FAN_MARK_MOUNT`), so events
//! arrive for the entire mount covering each root; the pipeline / `quick` filter by path.

use std::ffi::CString;
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

use av_core::watch::Pipeline;

const META_LEN: usize = std::mem::size_of::<libc::fanotify_event_metadata>();
const PSEUDO_FS: &[&[u8]] = &[
    b"proc",
    b"sysfs",
    b"devtmpfs",
    b"devpts",
    b"cgroup",
    b"cgroup2",
    b"securityfs",
    b"debugfs",
    b"tracefs",
    b"pstore",
    b"bpf",
    b"configfs",
    b"fusectl",
    b"mqueue",
    b"hugetlbfs",
    b"autofs",
    b"binfmt_misc",
    b"efivarfs",
    b"selinuxfs",
    b"nsfs",
    b"rpc_pipefs",
];

/// Scan-on-write: a `FAN_CLASS_NOTIF` group marking `FAN_CLOSE_WRITE` on the mounts covering `roots`.
/// A reader thread pushes each written file's path into `pipeline` (skipping our own writes), and calls
/// `pipeline.rescan()` once at start (changes made while we were down are unknown) and on queue overflow.
pub fn watch_writes(roots: &[PathBuf], pipeline: Arc<Pipeline>) -> io::Result<()> {
    let mut group = File::from(init(libc::FAN_CLASS_NOTIF)?);
    mark(&group, roots, libc::FAN_CLOSE_WRITE)?;
    let me = std::process::id() as i32;
    std::thread::Builder::new().name("fanotify-write".into()).spawn(move || {
        pipeline.rescan();
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let res = read_events(&mut group, &mut buf, |meta, file| {
                if meta.mask & libc::FAN_Q_OVERFLOW != 0 {
                    log::warn!("fanotify queue overflow; rescanning watched roots");
                    pipeline.rescan();
                }
                // ponytail: the write path is path-based (the scan reopens by path, racing a rename or
                // replace); exec checks scan the event fd. Holding fds in the debouncer would exhaust them.
                if let Some(file) = file.filter(|_| meta.pid != me) {
                    match fd_path(&file) {
                        Ok(path) => pipeline.push(path),
                        Err(e) => log::warn!("fanotify: cannot resolve event path: {e}"),
                    }
                }
            });
            if let Err(e) = res {
                log::error!("fanotify write watch stopped: {e}");
                return;
            }
        }
    })?;
    Ok(())
}

/// One exec-permission request handed to the daemon. Dropping it without answering ALLOWs (also on panic).
pub struct ExecJob {
    pub path: PathBuf,
    /// The fd the kernel opened for the event: scan this, not the path.
    pub file: File,
    answer: Arc<Answer>,
}

impl ExecJob {
    pub fn answer(self, allow: bool) {
        self.answer.send(allow);
    }
}

impl Drop for ExecJob {
    // Runs before `file` closes, so the event fd number can't be reused while the answer is written.
    fn drop(&mut self) {
        self.answer.send(true);
    }
}

/// Shared between the reader thread (deadline) and the `ExecJob`; whoever flips `done` first answers.
struct Answer {
    group: Arc<File>,
    fd: RawFd,
    done: AtomicBool,
}

impl Answer {
    /// Returns whether this call was the one that answered.
    fn send(&self, allow: bool) -> bool {
        if self.done.swap(true, Ordering::AcqRel) {
            return false;
        }
        let response =
            libc::fanotify_response { fd: self.fd, response: if allow { libc::FAN_ALLOW } else { libc::FAN_DENY } };
        // SAFETY: fanotify_response is two plain integers with no padding.
        let bytes = unsafe {
            std::slice::from_raw_parts(
                (&response as *const libc::fanotify_response).cast::<u8>(),
                std::mem::size_of::<libc::fanotify_response>(),
            )
        };
        // ENOENT: the kernel no longer has this event pending (already answered); nothing to do.
        if let Err(e) = (&*self.group).write_all(bytes) {
            if e.raw_os_error() != Some(libc::ENOENT) {
                log::warn!("fanotify: answering exec event failed: {e}");
            }
        }
        true
    }
}

/// Exec blocking: a `FAN_CLASS_CONTENT` group marking `FAN_OPEN_EXEC_PERM` on the mounts covering `roots`.
/// A reader thread answers every event: our own pid → ALLOW; `quick(path, &file)` (cache lookup + path
/// filter; must be fast) returning `Some(allow)` → answered now; `None` → an [`ExecJob`] is sent on the
/// returned channel. A job not answered within `deadline` is ALLOWed by the reader, which then calls
/// `on_timeout(path)` so the daemon can queue a full scan.
///
/// If the daemon dies, the kernel ALLOWs every pending event when the group fd closes.
///
/// The reader never execs and never blocks on the daemon (the channel is unbounded). The daemon's
/// scanner may exec (e.g. `rpm` for trust checks); that child is another pid, so its exec event can wait
/// on the very scanner that waits for it — that costs one `deadline`, never a deadlock.
pub fn guard_exec(
    roots: &[PathBuf],
    deadline: Duration,
    quick: impl Fn(&Path, &File) -> Option<bool> + Send + 'static,
    on_timeout: impl Fn(PathBuf) + Send + 'static,
) -> io::Result<mpsc::Receiver<ExecJob>> {
    let group = Arc::new(File::from(init(libc::FAN_CLASS_CONTENT)?));
    mark(&group, roots, libc::FAN_OPEN_EXEC_PERM)?;
    let (tx, rx) = mpsc::channel();
    let me = std::process::id() as i32;
    std::thread::Builder::new().name("fanotify-exec".into()).spawn(move || {
        let mut pending: Vec<(Instant, PathBuf, Arc<Answer>)> = Vec::new();
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let now = Instant::now();
            pending.retain(|(due, path, answer)| {
                if answer.done.load(Ordering::Acquire) {
                    return false;
                }
                if *due > now {
                    return true;
                }
                if answer.send(true) {
                    log::warn!("exec check of {} timed out; allowed", path.display());
                    on_timeout(path.clone());
                }
                false
            });
            let timeout = pending.iter().map(|p| p.0).min().map_or(-1, |due| {
                due.saturating_duration_since(now).as_micros().div_ceil(1000).min(i32::MAX as u128) as i32
            });
            let mut pfd = libc::pollfd { fd: group.as_raw_fd(), events: libc::POLLIN, revents: 0 };
            // SAFETY: one valid pollfd.
            if unsafe { libc::poll(&mut pfd, 1, timeout) } <= 0 {
                continue; // timeout or EINTR; poll on a valid fd has no other failure worth stopping for
            }
            let res = read_events(&mut &*group, &mut buf, |meta, file| {
                let Some(file) = file else { return };
                let answer = Arc::new(Answer { group: group.clone(), fd: file.as_raw_fd(), done: false.into() });
                if meta.pid == me {
                    answer.send(true);
                    return;
                }
                let path = match fd_path(&file) {
                    Ok(path) => path,
                    Err(e) => {
                        log::warn!("fanotify: cannot resolve exec path ({e}); allowed");
                        answer.send(true);
                        return;
                    }
                };
                match quick(&path, &file) {
                    Some(allow) => {
                        answer.send(allow);
                    }
                    None => {
                        pending.push((Instant::now() + deadline, path.clone(), answer.clone()));
                        // Receiver gone → the job drops here → ALLOW.
                        let _ = tx.send(ExecJob { path, file, answer });
                    }
                }
            });
            if let Err(e) = res {
                // Returning drops the group fd once the jobs are gone; the kernel then allows what's pending.
                log::error!("fanotify exec guard stopped: {e}");
                return;
            }
        }
    })?;
    Ok(rx)
}

fn init(class: libc::c_uint) -> io::Result<OwnedFd> {
    let flags = (libc::O_RDONLY | libc::O_LARGEFILE | libc::O_CLOEXEC) as libc::c_uint;
    // SAFETY: plain syscall; a non-negative return is a new fd we own.
    let fd = unsafe { libc::fanotify_init(class | libc::FAN_CLOEXEC, flags) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: see above.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Marks the mount of each root plus every non-pseudo mount strictly under it. Missing roots are skipped.
fn mark(group: &File, roots: &[PathBuf], mask: u64) -> io::Result<()> {
    let mounts = std::fs::read("/proc/self/mounts")?;
    let mut targets = Vec::new();
    for root in roots {
        let root = match std::fs::canonicalize(root) {
            Ok(root) => root,
            Err(e) => {
                log::warn!("watched path {}: {e}; skipped", root.display());
                continue;
            }
        };
        for line in mounts.split(|&b| b == b'\n') {
            let mut fields = line.split(|&b| b == b' ').skip(1);
            let (Some(dir), Some(fstype)) = (fields.next(), fields.next()) else { continue };
            let dir = unescape(dir);
            if !PSEUDO_FS.contains(&fstype) && dir != root && dir.starts_with(&root) {
                targets.push((dir, false));
            }
        }
        targets.push((root, true));
    }
    targets.sort();
    targets.dedup_by(|a, b| {
        a.0 == b.0 && {
            b.1 |= a.1;
            true
        }
    });
    for (path, is_root) in targets {
        let c_path = CString::new(path.as_os_str().as_bytes())?;
        // SAFETY: valid group fd and NUL-terminated path.
        let rc = unsafe {
            libc::fanotify_mark(
                group.as_raw_fd(),
                libc::FAN_MARK_ADD | libc::FAN_MARK_MOUNT,
                mask,
                libc::AT_FDCWD,
                c_path.as_ptr(),
            )
        };
        if rc != 0 {
            let e = io::Error::last_os_error();
            if is_root {
                return Err(io::Error::new(e.kind(), format!("fanotify_mark {}: {e}", path.display())));
            }
            // e.g. a FUSE mount root can't stat.
            log::warn!("fanotify_mark {}: {e}; mount not watched", path.display());
        }
    }
    Ok(())
}

/// Undoes the `\040`-style octal escapes of /proc/self/mounts.
fn unescape(s: &[u8]) -> PathBuf {
    let mut out = Vec::with_capacity(s.len());
    let mut rest = s;
    while let Some((&c, tail)) = rest.split_first() {
        let octal = tail.get(..3).and_then(|o| u8::from_str_radix(std::str::from_utf8(o).ok()?, 8).ok());
        match octal {
            Some(byte) if c == b'\\' => {
                out.push(byte);
                rest = &tail[3..];
            }
            _ => {
                out.push(c);
                rest = tail;
            }
        }
    }
    PathBuf::from(std::ffi::OsString::from_vec(out))
}

fn fd_path(file: &File) -> io::Result<PathBuf> {
    std::fs::read_link(format!("/proc/self/fd/{}", file.as_raw_fd()))
}

/// One read() of the group; calls `each` per event with its fd already owned (closed when dropped).
fn read_events(
    group: &mut impl Read,
    buf: &mut [u8],
    mut each: impl FnMut(&libc::fanotify_event_metadata, Option<File>),
) -> io::Result<()> {
    let n = match group.read(buf) {
        Ok(n) => n,
        Err(e) if e.kind() == io::ErrorKind::Interrupted => return Ok(()),
        Err(e) => return Err(e),
    };
    let mut off = 0;
    while off + META_LEN <= n {
        // SAFETY: META_LEN bytes are in bounds; read_unaligned has no alignment requirement.
        let meta: libc::fanotify_event_metadata = unsafe { std::ptr::read_unaligned(buf[off..].as_ptr().cast()) };
        if meta.vers != libc::FANOTIFY_METADATA_VERSION {
            return Err(io::Error::new(io::ErrorKind::InvalidData, format!("fanotify metadata version {}", meta.vers)));
        }
        let len = meta.event_len as usize;
        // SAFETY: the kernel handed us this fd; nobody else owns it.
        let file = (meta.fd >= 0).then(|| unsafe { File::from_raw_fd(meta.fd) });
        if len < META_LEN || off + len > n {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "truncated fanotify event"));
        }
        off += len;
        each(&meta, file);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::process::Command;

    #[test]
    fn unescape_mount_paths() {
        assert_eq!(unescape(br"/mnt/my\040disk\134x"), PathBuf::from(r"/mnt/my disk\x"));
    }

    /// fanotify needs CAP_SYS_ADMIN: run as root (e.g. `docker run --privileged`), skipped otherwise.
    fn root_temp_dir(name: &str) -> Option<PathBuf> {
        // SAFETY: plain getter.
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("not root, skipping fanotify test");
            return None;
        }
        let dir = std::env::temp_dir().join(format!("sensors-linux-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Some(std::fs::canonicalize(dir).unwrap())
    }

    #[test]
    fn write_by_another_process_is_scanned() {
        use av_core::watch::{Filter, WatchConfig};
        use sha2::{Digest, Sha256};
        let Some(dir) = root_temp_dir("write") else { return };
        // A harmless file on a private hash list, so its scan is a detection. Kept outside the watched root.
        let (own, watched) = (dir.join("own"), dir.join("watched"));
        std::fs::create_dir_all(&own).unwrap();
        std::fs::create_dir_all(&watched).unwrap();
        let data = b"harmless, but listed";
        std::fs::write(own.join("source"), data).unwrap();
        let hex: String = Sha256::digest(data).iter().map(|b| format!("{b:02x}")).collect();
        std::fs::write(own.join("hashes.txt"), format!("{hex} Test-Marked\n")).unwrap();
        let rules_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../signatures/rules");
        let config = av_core::Config { hash_list: own.join("hashes.txt"), rules_dir, ..Default::default() };
        let shared = av_core::Shared::load(&config).unwrap();
        let watch = WatchConfig { paths: vec![watched.clone()], debounce_ms: 50, ..WatchConfig::default() };
        let pipeline = Pipeline::new(&watch, Arc::new(Filter::new(&watch, &[]).unwrap()));

        let (found_tx, found) = mpsc::channel();
        let worker = pipeline.clone();
        std::thread::spawn(move || {
            worker.work(&mut av_core::Engine::new(shared), &|d| {
                let _ = found_tx.send(d.path);
            })
        });
        watch_writes(std::slice::from_ref(&watched), pipeline.clone()).unwrap();
        while !pipeline.is_idle() {
            std::thread::sleep(Duration::from_millis(10)); // the startup rescan
        }
        // Our own writes are ignored, so another process writes it.
        let target = watched.join("dropped.bin");
        assert!(Command::new("cp").arg(own.join("source")).arg(&target).status().unwrap().success());
        let result = found.recv_timeout(Duration::from_secs(5));
        pipeline.stop();
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(result.unwrap(), target);
    }

    #[test]
    fn exec_denied_by_quick_or_job_and_allowed_on_drop() {
        let Some(dir) = root_temp_dir("exec") else { return };
        let script = |name: &str| {
            let path = dir.join(name);
            std::fs::write(&path, "#!/bin/sh\nexit 0\n").unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
            path
        };
        let (quick_deny, job_deny, allowed) = (script("quick-deny.sh"), script("job-deny.sh"), script("allowed.sh"));

        let jobs = guard_exec(
            std::slice::from_ref(&dir),
            Duration::from_secs(5),
            |path, _| path.ends_with("quick-deny.sh").then_some(false),
            |path| eprintln!("timed out: {}", path.display()),
        )
        .unwrap();
        // The daemon side: deny job-deny.sh, drop everything else (/bin/sh too) unanswered → ALLOW.
        std::thread::spawn(move || {
            for job in jobs {
                if job.path.ends_with("job-deny.sh") {
                    job.answer(false);
                }
            }
        });

        let run = |path: &Path| Command::new(path).status().map(|s| s.success());
        let results = (run(&quick_deny), run(&job_deny), run(&allowed));
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(results.0.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(results.1.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
        assert!(results.2.unwrap());
    }
}
