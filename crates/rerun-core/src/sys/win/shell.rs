//! The only calls to `SHGetKnownFolderPath` and `GetSystemWindowsDirectoryW` (ADR 0009).
//!
//! - `SHGetKnownFolderPath` always runs with `KF_FLAG_DONT_VERIFY |
//!   KF_FLAG_NO_PACKAGE_REDIRECTION`: no existence check, no network access for a redirected
//!   folder, nothing is created, and the real folder even if Rerun is ever packaged. The
//!   returned string is freed with `CoTaskMemFree` whether the call succeeds or not (the API
//!   documents that the caller frees it in both cases).
//! - It gets the **process token** (`TOKEN_QUERY | TOKEN_IMPERSONATE`), not `NULL`. With
//!   `NULL` the shell expands `%USERPROFILE%` of `User Shell Folders` from the process
//!   environment, so `LocalAppData` and `RoamingAppData` followed a `USERPROFILE` set by the
//!   parent process; with a token it expands from that user's own environment block (found
//!   on real Windows 11, 2026-11-04, by `known_folders_ignore_the_environment`). The process
//!   token, not the thread token: an impersonating thread does not change whose folders
//!   Rerun protects.
//! - `GetSystemWindowsDirectoryW` (not `GetWindowsDirectoryW`, which is per session on a
//!   terminal server) with a growing buffer.
//!
//! `FOLDERID_ProgramData` and `FOLDERID_UserProfiles` expand `%SystemDrive%` from the process
//! environment even with a token, so `known_folders` never asks the shell for them. Both
//! functions here are `clippy.toml` bans everywhere else.

#![allow(
    unsafe_code,
    reason = "FFI to shell32/kernel32/combase known-folder APIs (ADR 0009); every block has a \
              SAFETY comment"
)]

use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::ptr;

use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Security::{TOKEN_IMPERSONATE, TOKEN_QUERY};
use windows_sys::Win32::System::Com::CoTaskMemFree;
use windows_sys::Win32::System::SystemInformation::GetSystemWindowsDirectoryW;
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows_sys::Win32::UI::Shell::{
    KF_FLAG_DONT_VERIFY, KF_FLAG_NO_PACKAGE_REDIRECTION, SHGetKnownFolderPath,
};
use windows_sys::core::{GUID, HRESULT, PWSTR};

/// The flags of every `SHGetKnownFolderPath` call (ADR 0009). Never `KF_FLAG_CREATE`, never
/// `KF_FLAG_DEFAULT_PATH`.
const FLAGS: u32 = (KF_FLAG_DONT_VERIFY | KF_FLAG_NO_PACKAGE_REDIRECTION).cast_unsigned();
/// winerror.h `E_POINTER`: reported if the API claims success but returns no string.
const E_POINTER: HRESULT = 0x8000_4003_u32.cast_signed();
/// winerror.h `E_FAIL`.
const E_FAIL: HRESULT = 0x8000_4005_u32.cast_signed();
/// winerror.h `ERROR_INSUFFICIENT_BUFFER`: the Windows directory did not settle on a size.
const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
/// Longest path in UTF-16 units, without the terminating NUL.
const MAX_PATH_UNITS: usize = 32_767;

/// A string allocated by `SHGetKnownFolderPath`, freed with `CoTaskMemFree` on drop.
struct CoTaskStr(PWSTR);

impl Drop for CoTaskStr {
    fn drop(&mut self) {
        // SAFETY: the pointer is null or was allocated by SHGetKnownFolderPath with the COM task
        // allocator; this wrapper is its only owner and frees it exactly once. CoTaskMemFree
        // accepts null.
        unsafe { CoTaskMemFree(self.0.cast_const().cast()) };
    }
}

impl CoTaskStr {
    /// The UTF-16 units before the terminating NUL; `None` if null or no NUL within the path
    /// limit.
    fn units(&self) -> Option<&[u16]> {
        if self.0.is_null() {
            return None;
        }
        let mut len = 0;
        loop {
            if len > MAX_PATH_UNITS {
                return None;
            }
            let unit = self.0.wrapping_add(len);
            // SAFETY: the pointer is non-null and points to the NUL-terminated string that
            // SHGetKnownFolderPath returned; the loop stops at the first NUL, so `len` never
            // passes the terminator and `unit` is inside the allocation and aligned.
            if unsafe { unit.read() } == 0 {
                break;
            }
            len += 1;
        }
        // SAFETY: the `len` units before the NUL were just read one by one, so they are
        // initialized and inside the allocation; the slice borrows `self`, which keeps the
        // allocation alive.
        Some(unsafe { std::slice::from_raw_parts(self.0, len) })
    }
}

/// winerror.h `HRESULT_FROM_WIN32`; `E_FAIL` if the failed call left no error code.
fn hresult_from_win32(code: u32) -> HRESULT {
    if code == 0 {
        E_FAIL
    } else {
        ((code & 0xFFFF) | 0x8007_0000).cast_signed()
    }
}

/// The process token with the rights `SHGetKnownFolderPath` needs.
fn process_token() -> Result<OwnedHandle, HRESULT> {
    let mut raw: HANDLE = ptr::null_mut();
    // SAFETY: GetCurrentProcess returns a pseudo handle that needs no closing and is always
    // valid in this process.
    let process = unsafe { GetCurrentProcess() };
    // SAFETY: `process` is the current-process pseudo handle; `raw` is valid for a write.
    let ok = unsafe { OpenProcessToken(process, TOKEN_QUERY | TOKEN_IMPERSONATE, &mut raw) };
    if ok == 0 || raw.is_null() {
        return Err(hresult_from_win32(last_error()));
    }
    // SAFETY: `raw` was just returned by a successful OpenProcessToken; this function owns it
    // and nothing else closes it.
    Ok(unsafe { OwnedHandle::from_raw_handle(raw) })
}

/// `SHGetKnownFolderPath(id, FLAGS, <process token>)`: the path as the system reports it, or
/// the failing `HRESULT`.
pub(super) fn known_folder_path(id: &GUID) -> Result<OsString, HRESULT> {
    let token = process_token()?;
    let mut raw: PWSTR = ptr::null_mut();
    #[expect(
        clippy::disallowed_methods,
        reason = "the one SHGetKnownFolderPath call site (ADR 0009)"
    )]
    // SAFETY: `id` is a valid GUID reference for the duration of the call; `token` is a live
    // token handle with TOKEN_QUERY | TOKEN_IMPERSONATE that this function keeps open until
    // after the call; `raw` is valid for a write and receives a pointer the caller frees with
    // CoTaskMemFree (done by `CoTaskStr`, also on failure).
    let hr = unsafe { SHGetKnownFolderPath(id, FLAGS, token.as_raw_handle(), &mut raw) };
    let owned = CoTaskStr(raw);
    if hr < 0 {
        return Err(hr);
    }
    owned.units().map(OsString::from_wide).ok_or(E_POINTER)
}

/// `GetSystemWindowsDirectoryW`: the shared Windows directory, or the Win32 error code.
pub(super) fn system_windows_directory() -> Result<OsString, u32> {
    // MAX_PATH first; the API reports the size it needs (with the NUL) if that is too small.
    let mut cap: usize = 260;
    for _ in 0..4 {
        let mut buf = vec![0u16; cap];
        let size = u32::try_from(cap).unwrap_or(u32::MAX);
        #[expect(
            clippy::disallowed_methods,
            reason = "the one GetSystemWindowsDirectoryW call site (ADR 0009)"
        )]
        // SAFETY: `buf` is a writable buffer of exactly `size` UTF-16 units that outlives the
        // call; the API writes at most `size` units including the NUL.
        let n = unsafe { GetSystemWindowsDirectoryW(buf.as_mut_ptr(), size) };
        let n = usize::try_from(n).unwrap_or(usize::MAX);
        if n == 0 {
            return Err(last_error());
        }
        if n < cap {
            buf.truncate(n);
            return Ok(OsString::from_wide(&buf));
        }
        // Too small: `n` is the size needed including the NUL.
        if n > MAX_PATH_UNITS + 1 {
            return Err(ERROR_INSUFFICIENT_BUFFER);
        }
        cap = n;
    }
    Err(ERROR_INSUFFICIENT_BUFFER)
}

/// The last Win32 error of this thread (read right after a failed call).
fn last_error() -> u32 {
    std::io::Error::last_os_error()
        .raw_os_error()
        .map_or(0, i32::cast_unsigned)
}

#[cfg(test)]
mod tests {
    use super::hresult_from_win32;

    #[test]
    fn hresult_from_win32_matches_winerror_h() {
        assert_eq!(hresult_from_win32(2), 0x8007_0002_u32.cast_signed());
        assert_eq!(hresult_from_win32(5), 0x8007_0005_u32.cast_signed());
        assert_eq!(hresult_from_win32(0), 0x8000_4005_u32.cast_signed());
    }
}
