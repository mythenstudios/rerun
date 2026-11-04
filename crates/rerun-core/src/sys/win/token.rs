//! `RootInfo::user_writable`: can the current, non-elevated user change the directory itself?
//!
//! The answer comes from `AccessCheck(MAXIMUM_ALLOWED)` against the directory's own security
//! descriptor (owner, group, DACL and mandatory label, read with `GetSecurityInfo` on the open
//! handle, never by path), not from trying a write. Writable means any right that lets the
//! user change the directory or its entries, or grant itself such a right, is granted:
//! `FILE_ADD_FILE`, `FILE_ADD_SUBDIRECTORY`, `FILE_DELETE_CHILD`, `DELETE`, `WRITE_DAC`,
//! `WRITE_OWNER`, `FILE_WRITE_ATTRIBUTES`, `FILE_WRITE_EA` ([`WRITE_RIGHTS`]). The owner
//! therefore always counts as able to write (implicit `WRITE_DAC`). It describes the directory
//! itself only: entries below it may have their own DACLs.
//!
//! The token is the user's non-elevated one:
//! - in a fully elevated process (`TokenElevationTypeFull`) the linked token, i.e. the
//!   filtered token of the same logon. Under over-the-shoulder elevation that is the
//!   **administrator's** filtered token, not the interactive user's. In the elevated helper
//!   `user_writable` is therefore informational only and never a security decision; the
//!   helper's own security-descriptor check (ADR 0007, "Elevation") is the boundary;
//! - otherwise a duplicate of the process token at `SecurityIdentification` level.
//!
//! With UAC off or for the built-in Administrator (`TokenElevationTypeDefault` while being an
//! administrator) there is no non-elevated token; the own token is used, so `user_writable`
//! answers for the administrator. This only makes more roots count as user-writable, which
//! is the stricter case for the elevated helper.

#![allow(
    unsafe_code,
    reason = "FFI to advapi32 security APIs (ADR 0008); every block has a SAFETY comment"
)]

use std::ffi::c_void;
use std::os::windows::io::{AsRawHandle, BorrowedHandle, FromRawHandle, OwnedHandle};
use std::ptr;

use windows_sys::Win32::Foundation::{HANDLE, LocalFree};
use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
use windows_sys::Win32::Security::{
    AccessCheck, DACL_SECURITY_INFORMATION, DuplicateToken, GENERIC_MAPPING,
    GROUP_SECURITY_INFORMATION, GetTokenInformation, LABEL_SECURITY_INFORMATION,
    OWNER_SECURITY_INFORMATION, PRIVILEGE_SET, PSECURITY_DESCRIPTOR, SecurityIdentification,
    TOKEN_DUPLICATE, TOKEN_ELEVATION_TYPE, TOKEN_LINKED_TOKEN, TOKEN_QUERY, TokenElevationType,
    TokenElevationTypeFull, TokenLinkedToken,
};
use windows_sys::Win32::Storage::FileSystem::{
    DELETE, FILE_ADD_FILE, FILE_ADD_SUBDIRECTORY, FILE_ALL_ACCESS, FILE_DELETE_CHILD,
    FILE_GENERIC_EXECUTE, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_WRITE_ATTRIBUTES,
    FILE_WRITE_EA, WRITE_DAC, WRITE_OWNER,
};

/// Rights that make a directory count as writable: any of them lets the user change the
/// directory or its entries, or give itself the right to.
pub(super) const WRITE_RIGHTS: u32 = FILE_ADD_FILE
    | FILE_ADD_SUBDIRECTORY
    | FILE_DELETE_CHILD
    | DELETE
    | WRITE_DAC
    | WRITE_OWNER
    | FILE_WRITE_ATTRIBUTES
    | FILE_WRITE_EA;
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

/// winnt.h `MAXIMUM_ALLOWED` (avoids the large `Win32_System_SystemServices` feature).
const MAXIMUM_ALLOWED: u32 = 0x0200_0000;
/// winerror.h `ERROR_INSUFFICIENT_BUFFER`.
const ERROR_INSUFFICIENT_BUFFER: u32 = 122;

/// Size of `T` as a buffer length for the token APIs (all such `T` are a few bytes).
fn len32<T>() -> u32 {
    u32::try_from(size_of::<T>()).unwrap_or(0)
}

/// The last Win32 error of this thread (read right after a failed call).
fn last_error() -> u32 {
    std::io::Error::last_os_error()
        .raw_os_error()
        .map_or(0, i32::cast_unsigned)
}

/// A security descriptor allocated by `GetSecurityInfo`, freed with `LocalFree`.
struct LocalSd(PSECURITY_DESCRIPTOR);

impl Drop for LocalSd {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the pointer was allocated by GetSecurityInfo with LocalAlloc, is owned
            // only by this wrapper and is freed exactly once here.
            unsafe { LocalFree(self.0) };
        }
    }
}

/// Takes ownership of a handle a successful API call wrote into `raw`.
fn own(raw: HANDLE) -> Option<OwnedHandle> {
    (!raw.is_null()).then(|| {
        // SAFETY: `raw` was just returned by a successful OpenProcessToken, DuplicateToken or
        // GetTokenInformation(TokenLinkedToken); the caller owns it and nothing else closes it.
        unsafe { OwnedHandle::from_raw_handle(raw) }
    })
}

fn process_token() -> Result<OwnedHandle, u32> {
    let mut raw: HANDLE = ptr::null_mut();
    // SAFETY: GetCurrentProcess returns a pseudo handle that needs no closing and is always
    // valid in this process.
    let process = unsafe { GetCurrentProcess() };
    // SAFETY: `process` is the current-process pseudo handle; `raw` is valid for a write.
    let ok = unsafe { OpenProcessToken(process, TOKEN_QUERY | TOKEN_DUPLICATE, &mut raw) };
    if ok == 0 {
        return Err(last_error());
    }
    own(raw).ok_or(ERROR_INSUFFICIENT_BUFFER)
}

fn elevation_type(token: BorrowedHandle<'_>) -> Result<TOKEN_ELEVATION_TYPE, u32> {
    let mut ty: TOKEN_ELEVATION_TYPE = 0;
    let mut returned: u32 = 0;
    // SAFETY: `token` is a live token handle with TOKEN_QUERY; `ty` is a valid, correctly
    // sized output buffer for TokenElevationType (a 4-byte enum); `returned` is valid for a
    // write.
    let ok = unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenElevationType,
            ptr::from_mut(&mut ty).cast::<c_void>(),
            len32::<TOKEN_ELEVATION_TYPE>(),
            &mut returned,
        )
    };
    if ok == 0 {
        return Err(last_error());
    }
    Ok(ty)
}

fn linked_token(token: BorrowedHandle<'_>) -> Result<OwnedHandle, u32> {
    let mut linked = TOKEN_LINKED_TOKEN {
        LinkedToken: ptr::null_mut(),
    };
    let mut returned: u32 = 0;
    // SAFETY: `token` is a live token handle with TOKEN_QUERY; `linked` is a valid, correctly
    // sized output buffer for TokenLinkedToken; `returned` is valid for a write. On success
    // the API writes a new handle that the caller owns.
    let ok = unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenLinkedToken,
            ptr::from_mut(&mut linked).cast::<c_void>(),
            len32::<TOKEN_LINKED_TOKEN>(),
            &mut returned,
        )
    };
    if ok == 0 {
        return Err(last_error());
    }
    own(linked.LinkedToken).ok_or(ERROR_INSUFFICIENT_BUFFER)
}

fn identification_token(token: BorrowedHandle<'_>) -> Result<OwnedHandle, u32> {
    let mut raw: HANDLE = ptr::null_mut();
    // SAFETY: `token` is a live primary token with TOKEN_DUPLICATE; `raw` is valid for a
    // write and receives a new impersonation token the caller owns.
    let ok = unsafe { DuplicateToken(token.as_raw_handle(), SecurityIdentification, &mut raw) };
    if ok == 0 {
        return Err(last_error());
    }
    own(raw).ok_or(ERROR_INSUFFICIENT_BUFFER)
}

/// The impersonation token of the non-elevated user (see module docs).
fn user_token() -> Result<OwnedHandle, u32> {
    use std::os::windows::io::AsHandle;
    let process = process_token()?;
    if elevation_type(process.as_handle())? == TokenElevationTypeFull {
        linked_token(process.as_handle())
    } else {
        identification_token(process.as_handle())
    }
}

fn security_descriptor(dir: BorrowedHandle<'_>) -> Result<LocalSd, u32> {
    let mut sd: PSECURITY_DESCRIPTOR = ptr::null_mut();
    // SAFETY: `dir` is a live handle opened with READ_CONTROL; the owner, group, DACL and
    // SACL outputs are optional (null) because the whole descriptor is requested; `sd` is
    // valid for a write and receives a LocalAlloc'd buffer that LocalSd frees.
    let rc = unsafe {
        GetSecurityInfo(
            dir.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION
                | GROUP_SECURITY_INFORMATION
                | DACL_SECURITY_INFORMATION
                | LABEL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            &mut sd,
        )
    };
    let sd = LocalSd(sd);
    if rc != 0 {
        return Err(rc);
    }
    if sd.0.is_null() {
        return Err(ERROR_INSUFFICIENT_BUFFER);
    }
    Ok(sd)
}

/// The non-elevated user may change the directory `dir` itself: any of [`WRITE_RIGHTS`]
/// granted by `AccessCheck(MAXIMUM_ALLOWED)`. `dir` needs `READ_CONTROL`. Win32 error on
/// failure.
pub(super) fn user_writable(dir: BorrowedHandle<'_>) -> Result<bool, u32> {
    let sd = security_descriptor(dir)?;
    let token = user_token()?;
    let mapping = GENERIC_MAPPING {
        GenericRead: FILE_GENERIC_READ,
        GenericWrite: FILE_GENERIC_WRITE,
        GenericExecute: FILE_GENERIC_EXECUTE,
        GenericAll: FILE_ALL_ACCESS,
    };
    // PRIVILEGE_SET with room for a few privileges, 8-byte aligned.
    let mut privileges = vec![0u64; 32];
    let mut granted: u32 = 0;
    let mut status: i32 = 0;
    loop {
        let mut len = u32::try_from(privileges.len() * 8).map_err(|_| ERROR_INSUFFICIENT_BUFFER)?;
        // SAFETY: `sd` is a valid self-relative security descriptor kept alive by LocalSd;
        // `token` is a live impersonation token (identification level or higher) with
        // TOKEN_QUERY; `mapping` is valid for reads; `privileges` is valid for writes of
        // `len` bytes and aligned for PRIVILEGE_SET; `len`, `granted` and `status` are valid
        // for writes.
        let ok = unsafe {
            AccessCheck(
                sd.0,
                token.as_raw_handle(),
                MAXIMUM_ALLOWED,
                &mapping,
                privileges.as_mut_ptr().cast::<PRIVILEGE_SET>(),
                &mut len,
                &mut granted,
                &mut status,
            )
        };
        if ok != 0 {
            break;
        }
        let err = last_error();
        let needed = (len as usize).div_ceil(8);
        if err == ERROR_INSUFFICIENT_BUFFER && needed > privileges.len() && needed <= 4096 {
            privileges.resize(needed, 0);
            continue;
        }
        return Err(err);
    }
    Ok(status != 0 && granted & WRITE_RIGHTS != 0)
}
