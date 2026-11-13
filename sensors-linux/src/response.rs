//! Acting on detections: process stop/continue/kill through a pidfd, and desktop notifications.

use std::collections::HashMap;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::process::Command;

use av_core::ProcessOp;

/// `PF_KTHREAD` in /proc/<pid>/stat flags.
const PF_KTHREAD: u64 = 0x0020_0000;

/// Signals through a pidfd, so a pid recycled after `pidfd_open` can't be hit. Refuses pid 0/1, kernel threads
/// and avd itself.
pub fn process(pid: u32, op: ProcessOp) -> io::Result<()> {
    if pid <= 1 || pid == std::process::id() {
        return Err(refused(pid));
    }
    // SAFETY: plain syscall; a non-negative result is a new fd we own.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: see above.
    let pidfd = unsafe { OwnedFd::from_raw_fd(fd as i32) };
    // Read after the pidfd exists: if the pid was reused since, the signal below fails with ESRCH anyway.
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let flags = stat.rsplit_once(')').and_then(|(_, rest)| rest.split_whitespace().nth(6)?.parse::<u64>().ok());
    if flags.is_none_or(|f| f & PF_KTHREAD != 0) {
        return Err(refused(pid));
    }
    let signal = match op {
        ProcessOp::Suspend => libc::SIGSTOP,
        ProcessOp::Resume => libc::SIGCONT,
        ProcessOp::Kill => libc::SIGKILL,
    };
    // SAFETY: valid pidfd; null siginfo = like kill().
    let rc = unsafe {
        libc::syscall(libc::SYS_pidfd_send_signal, pidfd.as_raw_fd(), signal, std::ptr::null::<libc::siginfo_t>(), 0)
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn refused(pid: u32) -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!("action refused: pid {pid} is init, a kernel thread or avd"),
    )
}

/// `notify-send` in every active graphical session, as that session's user. Never through a shell, and with `--`
/// before the text: file names are attacker-controlled. No session or no notify-send → logged only.
pub fn notify(title: &str, text: &str) {
    // The body may be read as markup by the notification server.
    let body = text.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;");
    let sessions = match Command::new("loginctl").args(["list-sessions", "--no-legend"]).output() {
        Ok(out) => String::from_utf8_lossy(&out.stdout).into_owned(),
        Err(e) => {
            log::warn!("notification not shown: loginctl: {e}");
            return;
        }
    };
    for id in sessions.lines().filter_map(|l| l.split_whitespace().next()) {
        let Ok(out) =
            Command::new("loginctl").args(["show-session", id, "-p", "Type", "-p", "State", "-p", "User"]).output()
        else {
            continue;
        };
        let text = String::from_utf8_lossy(&out.stdout);
        let props: HashMap<&str, &str> = text.lines().filter_map(|l| l.split_once('=')).collect();
        let graphical = matches!(props.get("Type"), Some(&"x11" | &"wayland"));
        let active = matches!(props.get("State"), Some(&"active" | &"online"));
        let Some(uid) = props.get("User").and_then(|u| u.parse::<u32>().ok()) else { continue };
        if !graphical || !active {
            continue;
        }
        let Some(gid) = primary_gid(uid) else { continue };
        let status = Command::new("notify-send")
            .uid(uid)
            .gid(gid)
            .env_clear()
            .env("PATH", "/usr/local/bin:/usr/bin:/bin")
            .env("DBUS_SESSION_BUS_ADDRESS", format!("unix:path=/run/user/{uid}/bus"))
            .args(["--app-name=avd", "--urgency=critical", "--", title, &body])
            .status();
        match status {
            Ok(s) if s.success() => {}
            Ok(s) => log::warn!("notify-send for uid {uid}: {s}"),
            Err(e) => log::warn!("notify-send for uid {uid}: {e}"),
        }
    }
}

fn primary_gid(uid: u32) -> Option<u32> {
    // SAFETY: passwd is plain data; getpwuid_r fills it with pointers into `buf`, which outlives the read.
    unsafe {
        let mut pw: libc::passwd = std::mem::zeroed();
        let mut buf = vec![0 as libc::c_char; 16 * 1024];
        let mut found = std::ptr::null_mut();
        let rc = libc::getpwuid_r(uid, &mut pw, buf.as_mut_ptr(), buf.len(), &mut found);
        (rc == 0 && !found.is_null()).then_some(pw.pw_gid)
    }
}
