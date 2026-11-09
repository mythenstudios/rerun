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
    TOKEN_DUPLICATE, TOKEN_ELEVATION, TOKEN_ELEVATION_TYPE, TOKEN_LINKED_TOKEN, TOKEN_QUERY,
    TokenElevation, TokenElevationType, TokenElevationTypeFull, TokenLinkedToken,
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

/// The process token is elevated (`TokenElevation`): an administrator's full token, also with
/// UAC off. The registry write side refuses then (ADR 0018, S2).
pub(super) fn process_elevated() -> Result<bool, u32> {
    let token = process_token()?;
    let mut e = TOKEN_ELEVATION { TokenIsElevated: 0 };
    let mut returned: u32 = 0;
    // SAFETY: `token` is a live token handle with TOKEN_QUERY, kept alive until after the call;
    // `e` is a valid, correctly sized output buffer for TokenElevation (one u32); `returned` is
    // valid for a write.
    let ok = unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenElevation,
            ptr::from_mut(&mut e).cast::<c_void>(),
            len32::<TOKEN_ELEVATION>(),
            &mut returned,
        )
    };
    if ok == 0 {
        return Err(last_error());
    }
    Ok(e.TokenIsElevated != 0)
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

/// wdm.h `SE_CHANGE_NOTIFY_PRIVILEGE`: the well-known LUID (`{ LowPart: 23, HighPart: 0 }`) of
/// `SeChangeNotifyPrivilege`, the one privilege the elevated helper keeps (ADR 0023 §3 step 2:
/// traverse checking; every process has it, removing it would only break path walks).
const SE_CHANGE_NOTIFY_PRIVILEGE: u32 = 23;
/// winerror.h `ERROR_NOT_ALL_ASSIGNED`: `AdjustTokenPrivileges` succeeded only in part. Also
/// the error when a privilege is still in the token after the removal.
const ERROR_NOT_ALL_ASSIGNED: u32 = 1300;
/// Bound of the `TokenPrivileges` buffer: a token holds at most about 36 privileges (12 bytes
/// each); anything near this is not a token Windows made.
const MAX_PRIVILEGES_BYTES: u32 = 64 << 10;

/// One `LUID_AND_ATTRIBUTES` of a `TOKEN_PRIVILEGES` buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Privilege {
    /// `Luid.LowPart`.
    pub low: u32,
    /// `Luid.HighPart`.
    pub high: i32,
    /// `Attributes` (`SE_PRIVILEGE_*`).
    pub attributes: u32,
}

impl Privilege {
    fn is_change_notify(self) -> bool {
        self.low == SE_CHANGE_NOTIFY_PRIVILEGE && self.high == 0
    }
}

/// Decodes a `TOKEN_PRIVILEGES` buffer as `GetTokenInformation(TokenPrivileges)` fills it
/// (`winnt.h`, 4-byte packing): `PrivilegeCount` (u32), then that many 12-byte
/// `LUID_AND_ATTRIBUTES` (`LowPart` u32, `HighPart` i32, `Attributes` u32). `None` if the
/// buffer is shorter than the count says. Pure; the layout is pinned by a test against
/// `windows-sys`.
pub(super) fn decode_privileges(b: &[u8]) -> Option<Vec<Privilege>> {
    let u32_at = |at: usize| -> Option<u32> {
        let bytes: [u8; 4] = b.get(at..at.checked_add(4)?)?.try_into().ok()?;
        Some(u32::from_ne_bytes(bytes))
    };
    let count = usize::try_from(u32_at(0)?).ok()?;
    let end = count.checked_mul(12)?.checked_add(4)?;
    if end > b.len() {
        return None;
    }
    (0..count)
        .map(|i| {
            let at = 4 + 12 * i;
            Some(Privilege {
                low: u32_at(at)?,
                high: u32_at(at + 4)?.cast_signed(),
                attributes: u32_at(at + 8)?,
            })
        })
        .collect()
}

/// The `TOKEN_PRIVILEGES` buffer (as `u32` words, so it is 4-aligned) that removes every
/// privilege of `privileges` except `SeChangeNotifyPrivilege` (`SE_PRIVILEGE_REMOVED`); `None`
/// if there is nothing to remove. Pure.
pub(super) fn removal(privileges: &[Privilege]) -> Option<Vec<u32>> {
    use windows_sys::Win32::Security::SE_PRIVILEGE_REMOVED;
    let gone: Vec<&Privilege> = privileges
        .iter()
        .filter(|p| !p.is_change_notify())
        .collect();
    if gone.is_empty() {
        return None;
    }
    let mut words = Vec::with_capacity(1 + 3 * gone.len());
    words.push(u32::try_from(gone.len()).ok()?);
    for p in gone {
        words.extend([p.low, p.high.cast_unsigned(), SE_PRIVILEGE_REMOVED]);
    }
    Some(words)
}

/// The process token with `TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES`.
fn adjustable_process_token() -> Result<OwnedHandle, u32> {
    use windows_sys::Win32::Security::TOKEN_ADJUST_PRIVILEGES;
    let mut raw: HANDLE = ptr::null_mut();
    // SAFETY: GetCurrentProcess returns a pseudo handle that needs no closing and is always
    // valid in this process.
    let process = unsafe { GetCurrentProcess() };
    // SAFETY: `process` is the current-process pseudo handle; `raw` is valid for a write.
    let ok = unsafe { OpenProcessToken(process, TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &mut raw) };
    if ok == 0 {
        return Err(last_error());
    }
    own(raw).ok_or(ERROR_INSUFFICIENT_BUFFER)
}

/// The privileges of `token` (`TokenPrivileges`), size query first, at most
/// [`MAX_PRIVILEGES_BYTES`].
fn privileges(token: BorrowedHandle<'_>) -> Result<Vec<Privilege>, u32> {
    use windows_sys::Win32::Security::TokenPrivileges;
    let mut needed: u32 = 0;
    // SAFETY: `token` is a live token handle with TOKEN_QUERY; a null buffer of length 0 is the
    // documented size query; `needed` is valid for a write.
    let ok = unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenPrivileges,
            ptr::null_mut(),
            0,
            &mut needed,
        )
    };
    if ok != 0 {
        // A size query cannot succeed: the buffer holds at least the count.
        return Err(ERROR_INSUFFICIENT_BUFFER);
    }
    let err = last_error();
    if err != ERROR_INSUFFICIENT_BUFFER || needed == 0 || needed > MAX_PRIVILEGES_BYTES {
        return Err(err);
    }
    // u32 words: 4-byte alignment, as TOKEN_PRIVILEGES needs.
    let mut words = vec![0u32; (needed as usize).div_ceil(4)];
    let len = u32::try_from(words.len() * 4).map_err(|_| ERROR_INSUFFICIENT_BUFFER)?;
    let mut returned: u32 = 0;
    // SAFETY: `token` is a live token handle with TOKEN_QUERY; `words` is valid for writes of
    // `len` bytes and 4-aligned; `returned` is valid for a write.
    let ok = unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenPrivileges,
            words.as_mut_ptr().cast::<c_void>(),
            len,
            &mut returned,
        )
    };
    if ok == 0 {
        return Err(last_error());
    }
    let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_ne_bytes()).collect();
    let filled = bytes
        .get(..returned as usize)
        .ok_or(ERROR_INSUFFICIENT_BUFFER)?;
    decode_privileges(filled).ok_or(ERROR_INSUFFICIENT_BUFFER)
}

/// Removes every privilege of the process token except `SeChangeNotifyPrivilege` and reads
/// the token back (ADR 0023 §3 step 2). Process-wide and irreversible: only the elevated
/// helper calls it, as its first step after `restrict_dll_search` (never a test process,
/// which would lose privileges other tests need). Win32 error on failure;
/// `ERROR_NOT_ALL_ASSIGNED` if a privilege is still there afterwards.
pub(super) fn drop_privileges() -> Result<(), u32> {
    use std::os::windows::io::AsHandle;
    use windows_sys::Win32::Security::{AdjustTokenPrivileges, TOKEN_PRIVILEGES};
    let token = adjustable_process_token()?;
    if let Some(words) = removal(&privileges(token.as_handle())?) {
        #[expect(
            clippy::disallowed_methods,
            reason = "the product AdjustTokenPrivileges call site (the other one is test-only, in \
                      testfx): the elevated helper removes its privileges (ADR 0023 §3 step 2)"
        )]
        // SAFETY: `token` is a live token handle with TOKEN_ADJUST_PRIVILEGES, kept alive until
        // after the call; `words` is a 4-aligned TOKEN_PRIVILEGES built by `removal`: its count
        // is exactly the number of LUID_AND_ATTRIBUTES that follow, so the API reads only inside
        // `words`, which stays alive across the call (the new state has no length parameter).
        // No previous state is requested: PreviousState and ReturnLength are null, and
        // BufferLength, the size of the PreviousState buffer, is 0.
        let ok = unsafe {
            AdjustTokenPrivileges(
                token.as_raw_handle(),
                0,
                words.as_ptr().cast::<TOKEN_PRIVILEGES>(),
                0,
                ptr::null_mut(),
                ptr::null_mut(),
            )
        };
        // Success can still mean "not all": the last error tells (documented).
        let err = last_error();
        if ok == 0 || err == ERROR_NOT_ALL_ASSIGNED {
            return Err(err);
        }
    }
    if privileges(token.as_handle())?
        .iter()
        .all(|p| p.is_change_notify())
    {
        Ok(())
    } else {
        Err(ERROR_NOT_ALL_ASSIGNED)
    }
}

#[cfg(test)]
mod privilege_tests {
    use std::mem::{offset_of, size_of};

    use windows_sys::Win32::Security::{
        LUID_AND_ATTRIBUTES, SE_PRIVILEGE_REMOVED, TOKEN_PRIVILEGES,
    };

    use super::{Privilege, decode_privileges, removal};

    /// The 12-byte entries after a 4-byte count that `decode_privileges` and `removal` assume.
    #[test]
    fn token_privileges_layout_is_pinned() {
        assert_eq!(size_of::<LUID_AND_ATTRIBUTES>(), 12);
        assert_eq!(offset_of!(TOKEN_PRIVILEGES, Privileges), 4);
        assert_eq!(offset_of!(LUID_AND_ATTRIBUTES, Attributes), 8);
    }

    fn bytes(words: &[u32]) -> Vec<u8> {
        words.iter().flat_map(|w| w.to_ne_bytes()).collect()
    }

    #[test]
    fn privileges_decode_and_every_one_but_change_notify_is_removed() {
        // SeShutdown (19, disabled), SeChangeNotify (23, enabled by default), SeBackup (17),
        // and a LUID with a high part.
        let buf = bytes(&[4, 19, 0, 0, 23, 0, 3, 17, 0, 0, 23, 1, 0]);
        let p = decode_privileges(&buf).unwrap();
        assert_eq!(p.len(), 4);
        assert_eq!(
            p[1],
            Privilege {
                low: 23,
                high: 0,
                attributes: 3
            }
        );
        // The high part counts: {23, 1} is not SeChangeNotify.
        let words = removal(&p).unwrap();
        let r = SE_PRIVILEGE_REMOVED;
        assert_eq!(words, [3, 19, 0, r, 17, 0, r, 23, 1, r]);
        assert_eq!(decode_privileges(&bytes(&words)).unwrap().len(), 3);
        // Only SeChangeNotify left, or nothing: nothing to remove.
        assert_eq!(removal(&p[1..2]), None);
        assert_eq!(removal(&[]), None);
    }

    #[test]
    fn a_short_or_lying_buffer_is_refused() {
        assert_eq!(decode_privileges(&[]), None);
        assert_eq!(decode_privileges(&[1, 0]), None);
        // The count says two, the buffer holds one.
        assert_eq!(decode_privileges(&bytes(&[2, 19, 0, 0])), None);
        assert_eq!(decode_privileges(&bytes(&[u32::MAX])), None);
        assert_eq!(decode_privileges(&bytes(&[0])), Some(vec![]));
    }
}
