//! Acting on detections: process suspend/resume/kill, delete-at-reboot, desktop message boxes, Ctrl+C.

use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{FromRawHandle, OwnedHandle};
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};
use std::sync::Mutex;

use av_core::ProcessOp;
use windows_sys::core::BOOL;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Storage::FileSystem::{MoveFileExW, MOVEFILE_DELAY_UNTIL_REBOOT};
use windows_sys::Win32::System::Console::SetConsoleCtrlHandler;
use windows_sys::Win32::System::RemoteDesktop::{
    WTSActive, WTSEnumerateSessionsW, WTSFreeMemory, WTSSendMessageW, WTS_CURRENT_SERVER_HANDLE, WTS_SESSION_INFOW,
};
use windows_sys::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, TerminateProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
    PROCESS_SUSPEND_RESUME, PROCESS_TERMINATE,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{MB_ICONWARNING, MB_SETFOREGROUND, MB_TOPMOST};

// Undocumented but stable since XP; what Process Explorer and Sysinternals pssuspend use.
#[link(name = "ntdll", kind = "raw-dylib")]
extern "system" {
    fn NtSuspendProcess(process: HANDLE) -> i32;
    fn NtResumeProcess(process: HANDLE) -> i32;
}

/// Killing or freezing one of these takes the whole system down. Matched by full path, so a lookalike elsewhere
/// is not protected.
const CRITICAL: [&str; 6] = ["csrss.exe", "wininit.exe", "smss.exe", "services.exe", "lsass.exe", "winlogon.exe"];

pub fn process(pid: u32, op: ProcessOp) -> io::Result<()> {
    if matches!(pid, 0 | 4) || pid == std::process::id() {
        return Err(refused(pid));
    }
    // SAFETY: plain call; a non-null result is a handle we own.
    let raw =
        unsafe { OpenProcess(PROCESS_SUSPEND_RESUME | PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if raw.is_null() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: see above; closed on drop.
    let handle = unsafe { OwnedHandle::from_raw_handle(raw) };
    let image = image_path(raw)?;
    let system32 =
        PathBuf::from(std::env::var_os("SystemRoot").unwrap_or_else(|| r"C:\Windows".into())).join("System32");
    let image_lower = image.to_string_lossy().to_lowercase();
    if CRITICAL.iter().any(|name| system32.join(name).to_string_lossy().to_lowercase() == image_lower) {
        return Err(refused(pid));
    }
    // SAFETY: `raw` stays open (owned by `handle`) for these calls.
    let status = unsafe {
        match op {
            ProcessOp::Suspend => NtSuspendProcess(raw),
            ProcessOp::Resume => NtResumeProcess(raw),
            ProcessOp::Kill => {
                if TerminateProcess(raw, 1) == 0 {
                    return Err(io::Error::last_os_error());
                }
                0
            }
        }
    };
    drop(handle);
    if status < 0 {
        return Err(io::Error::other(format!("NTSTATUS {status:#010x}")));
    }
    Ok(())
}

fn refused(pid: u32) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, format!("action refused: pid {pid} is a critical process or avd"))
}

fn image_path(process: HANDLE) -> io::Result<PathBuf> {
    let mut buf = vec![0u16; 32 * 1024];
    let mut len = buf.len() as u32;
    // SAFETY: `buf` holds `len` u16s.
    if unsafe { QueryFullProcessImageNameW(process, PROCESS_NAME_WIN32, buf.as_mut_ptr(), &mut len) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(String::from_utf16_lossy(&buf[..len as usize]).into())
}

/// Needs admin (the request goes into the registry's PendingFileRenameOperations).
pub fn delete_on_reboot(path: &Path) -> io::Result<()> {
    let wide = wide(path.as_os_str());
    // SAFETY: NUL-terminated path; null target = delete.
    if unsafe { MoveFileExW(wide.as_ptr(), null(), MOVEFILE_DELAY_UNTIL_REBOOT) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// A message box on every active user session's desktop, without waiting for it to be closed. Works from the
/// service (session 0) and from a console. Failures are logged, never fatal.
pub fn notify(title: &str, text: &str) {
    let (title, text): (Vec<u16>, Vec<u16>) = (title.encode_utf16().collect(), text.encode_utf16().collect());
    let mut sessions: *mut WTS_SESSION_INFOW = null_mut();
    let mut count = 0;
    // SAFETY: out-pointers are valid; the list is freed below.
    if unsafe { WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &mut sessions, &mut count) } == 0 {
        log::warn!("notification not shown: WTSEnumerateSessions: {}", io::Error::last_os_error());
        return;
    }
    // SAFETY: the API returned `count` entries at `sessions`.
    for s in unsafe { std::slice::from_raw_parts(sessions, count as usize) }.iter().filter(|s| s.State == WTSActive) {
        let mut response = 0;
        // SAFETY: lengths are in bytes; bWait = FALSE returns at once.
        let ok = unsafe {
            WTSSendMessageW(
                WTS_CURRENT_SERVER_HANDLE,
                s.SessionId,
                title.as_ptr(),
                (title.len() * 2) as u32,
                text.as_ptr(),
                (text.len() * 2) as u32,
                MB_ICONWARNING | MB_SETFOREGROUND | MB_TOPMOST,
                0,
                &mut response,
                0,
            )
        };
        if ok == 0 {
            log::warn!("notification to session {}: {}", s.SessionId, io::Error::last_os_error());
        }
    }
    // SAFETY: allocated by WTSEnumerateSessionsW.
    unsafe { WTSFreeMemory(sessions.cast()) };
}

static ON_STOP: Mutex<Option<Box<dyn FnOnce() + Send>>> = Mutex::new(None);

/// Runs `f` once on Ctrl+C, Ctrl+Break or console close, so `avd run` stops cleanly.
pub fn on_terminate(f: impl FnOnce() + Send + 'static) {
    unsafe extern "system" fn handler(_ctrl: u32) -> BOOL {
        if let Some(f) = av_core::lock(&ON_STOP).take() {
            log::info!("console stop received, shutting down");
            f();
        }
        1
    }
    *av_core::lock(&ON_STOP) = Some(Box::new(f));
    // SAFETY: `handler` is a valid 'static function.
    if unsafe { SetConsoleCtrlHandler(Some(handler), 1) } == 0 {
        log::warn!("Ctrl+C handler: {}", io::Error::last_os_error());
    }
}

pub(crate) fn wide(s: &std::ffi::OsStr) -> Vec<u16> {
    s.encode_wide().chain(std::iter::once(0)).collect()
}
