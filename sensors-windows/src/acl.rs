//! Self-protection: lock avd's data directory to admins, and spot config/rules ordinary users could change.

use std::io;
use std::path::Path;
use std::ptr::null_mut;

use windows_sys::core::PWSTR;
use windows_sys::Win32::Foundation::{CloseHandle, LocalFree, HANDLE};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, GetNamedSecurityInfoW,
    SetNamedSecurityInfoW, SDDL_REVISION_1, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    GetAce, GetSecurityDescriptorDacl, GetTokenInformation, TokenUser, ACCESS_ALLOWED_ACE, ACE_HEADER, ACL,
    DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, TOKEN_QUERY,
    TOKEN_USER,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use crate::response::wide;

/// SYSTEM, Administrators, TrustedInstaller.
const ADMIN_SIDS: [&str; 3] =
    ["S-1-5-18", "S-1-5-32-544", "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"];
/// Rights that change a file or its permissions: write/append data, delete child, DELETE, WRITE_DAC, WRITE_OWNER,
/// GENERIC_ALL, GENERIC_WRITE.
const WRITE: u32 = 0x2 | 0x4 | 0x40 | 0x1_0000 | 0x4_0000 | 0x8_0000 | 0x1000_0000 | 0x4000_0000;

/// Replaces `dir`'s permissions (inherited by everything inside) with full control for SYSTEM, Administrators and
/// the account running avd (SYSTEM for the service), and read-only for the owner — otherwise a non-admin who
/// created the directory first could re-grant themselves access.
pub fn lock_down(dir: &Path) -> io::Result<()> {
    let me = current_user_sid()?;
    let sddl = wide(format!("D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{me})(A;OICI;FR;;;OW)").as_ref());
    let mut sd: PSECURITY_DESCRIPTOR = null_mut();
    // SAFETY: NUL-terminated SDDL; `sd` is freed below.
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.as_ptr(), SDDL_REVISION_1, &mut sd, null_mut())
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let (mut present, mut dacl, mut defaulted) = (0, null_mut::<ACL>(), 0);
    let path = wide(dir.as_os_str());
    // SAFETY: `sd` is a valid descriptor; `dacl` points into it and is used before it is freed.
    let status = unsafe {
        let status = if GetSecurityDescriptorDacl(sd, &mut present, &mut dacl, &mut defaulted) == 0 {
            io::Error::last_os_error().raw_os_error().unwrap_or(1) as u32
        } else {
            SetNamedSecurityInfoW(
                path.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                dacl,
                null_mut(),
            )
        };
        LocalFree(sd);
        status
    };
    match status {
        0 => Ok(()),
        e => Err(io::Error::from_raw_os_error(e as i32)),
    }
}

/// True if an account other than SYSTEM, Administrators or TrustedInstaller may change `path` (its data, or its
/// permissions). A missing DACL counts as writable.
// ponytail: the owner's implicit WRITE_DAC is not checked (an admin's own account owns what it copies, which would
// warn on every normal install); a non-admin owner usually also holds an explicit ACE, which is caught.
pub fn user_writable(path: &Path) -> io::Result<bool> {
    let wide_path = wide(path.as_os_str());
    let (mut dacl, mut sd) = (null_mut::<ACL>(), null_mut());
    // SAFETY: out-pointers valid; `sd` owns `dacl` and is freed below.
    let status = unsafe {
        GetNamedSecurityInfoW(
            wide_path.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            &mut dacl,
            null_mut(),
            &mut sd,
        )
    };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    // SAFETY: `dacl` (when non-null) is a valid ACL inside `sd`; each ACE pointer comes from GetAce.
    let writable = unsafe {
        if dacl.is_null() {
            Ok(true)
        } else {
            (0..(*dacl).AceCount as u32).try_fold(false, |found, i| {
                if found {
                    return Ok(true);
                }
                let mut ace = null_mut();
                if GetAce(dacl, i, &mut ace) == 0 {
                    return Err(io::Error::last_os_error());
                }
                let header = &*(ace as *const ACE_HEADER);
                // 0 = ACCESS_ALLOWED_ACE_TYPE; 0x08 = INHERIT_ONLY_ACE (applies to children, not this object).
                if header.AceType != 0 || header.AceFlags & 0x08 != 0 {
                    return Ok(false);
                }
                let allowed = &*(ace as *const ACCESS_ALLOWED_ACE);
                if allowed.Mask & WRITE == 0 {
                    return Ok(false);
                }
                let sid = sid_string(&allowed.SidStart as *const u32 as PSID)?;
                Ok(!ADMIN_SIDS.contains(&sid.as_str()))
            })
        }
    };
    // SAFETY: allocated by GetNamedSecurityInfoW.
    unsafe { LocalFree(sd) };
    writable
}

fn current_user_sid() -> io::Result<String> {
    let mut token: HANDLE = null_mut();
    // SAFETY: pseudo-handle for this process; `token` closed below.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // TOKEN_USER plus the SID it points to; u64s for alignment.
    let mut buf = vec![0u64; 64];
    let mut len = 0;
    // SAFETY: buffer of the stated size; TokenUser writes a TOKEN_USER followed by its SID.
    unsafe {
        let ok = GetTokenInformation(token, TokenUser, buf.as_mut_ptr().cast(), (buf.len() * 8) as u32, &mut len);
        CloseHandle(token);
        if ok == 0 {
            Err(io::Error::last_os_error())
        } else {
            sid_string((*(buf.as_ptr() as *const TOKEN_USER)).User.Sid)
        }
    }
}

/// SAFETY: `sid` must point to a valid SID.
unsafe fn sid_string(sid: PSID) -> io::Result<String> {
    let mut out: PWSTR = null_mut();
    // SAFETY: `sid` is valid per the caller; `out` is a LocalAlloc'd NUL-terminated string, freed below.
    unsafe {
        if ConvertSidToStringSidW(sid, &mut out) == 0 {
            return Err(io::Error::last_os_error());
        }
        let len = (0..).take_while(|&i| *out.add(i) != 0).count();
        let s = String::from_utf16_lossy(std::slice::from_raw_parts(out, len));
        LocalFree(out.cast());
        Ok(s)
    }
}
