//! `WinOs`: the real [`Os`] of the shim. The command line, the token check (M1) and the
//! profile read (D2) live here; process, job and shell calls in [`launch`] (the one wrapper
//! module of the banned setters, ADR 0010 and ADR 0022); the topology in `cpu` (64-bit only).

#![allow(
    unsafe_code,
    reason = "FFI to kernel32/advapi32/shell32/combase (ADR 0022); every block has a SAFETY \
              comment"
)]

#[cfg(target_pointer_width = "64")]
mod cpu;
pub(crate) mod launch;

use std::ffi::{OsString, c_void};
use std::io::Read;
use std::os::windows::ffi::OsStringExt;
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::PathBuf;
use std::ptr;

use rerun_proto::cpu::CpuTopology;
use rerun_proto::profile::{MAX_PROFILE_BYTES, ProfileId};
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Security::{
    CheckTokenMembership, GetTokenInformation, TOKEN_ELEVATION, TOKEN_ELEVATION_TYPE,
    TOKEN_IMPERSONATE, TOKEN_QUERY, TokenElevation, TokenElevationType, TokenElevationTypeDefault,
};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE, FILE_SHARE_READ,
};
use windows_sys::Win32::System::Com::CoTaskMemFree;
use windows_sys::Win32::System::Environment::GetCommandLineW;
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows_sys::Win32::UI::Shell::{
    FOLDERID_LocalAppData, KF_FLAG_DONT_VERIFY, KF_FLAG_NO_PACKAGE_REDIRECTION,
    SHGetKnownFolderPath,
};
use windows_sys::core::PWSTR;

use crate::os::{GroupAffinity, Os, OsError, ReadBack, Spawn};

/// Longest command line or path in UTF-16 units, without the NUL.
const MAX_UNITS: usize = 32_767;

/// The last Win32 error of this thread (read right after a failed call).
pub(crate) fn last_error() -> u32 {
    std::io::Error::last_os_error()
        .raw_os_error()
        .map_or(0, i32::cast_unsigned)
}

/// The units of a NUL-terminated UTF-16 string, at most [`MAX_UNITS`]; `None` for null or no
/// NUL within the limit.
///
/// # Safety
/// `p` is null or points to a NUL-terminated UTF-16 string that stays alive and unchanged for
/// `'a`.
unsafe fn wide_units<'a>(p: *const u16) -> Option<&'a [u16]> {
    if p.is_null() {
        return None;
    }
    let mut len = 0;
    loop {
        if len > MAX_UNITS {
            return None;
        }
        let unit = p.wrapping_add(len);
        // SAFETY: by the contract `p` points to a NUL-terminated string; the loop stops at the
        // first NUL, so `unit` is inside the string and aligned.
        if unsafe { unit.read() } == 0 {
            break;
        }
        len += 1;
    }
    // SAFETY: the `len` units before the NUL were just read, so they are initialized and
    // inside the allocation, which lives for `'a` by the contract.
    Some(unsafe { std::slice::from_raw_parts(p, len) })
}

/// The process token with the given rights.
fn process_token(access: u32) -> Result<OwnedHandle, u32> {
    let mut raw: HANDLE = ptr::null_mut();
    // SAFETY: GetCurrentProcess returns a pseudo handle that needs no closing and is always
    // valid in this process.
    let process = unsafe { GetCurrentProcess() };
    // SAFETY: `process` is the current-process pseudo handle; `raw` is valid for a write.
    let ok = unsafe { OpenProcessToken(process, access, &mut raw) };
    if ok == 0 || raw.is_null() {
        return Err(last_error());
    }
    // SAFETY: `raw` was just returned by a successful OpenProcessToken; this function owns it
    // and nothing else closes it.
    Ok(unsafe { OwnedHandle::from_raw_handle(raw) })
}

/// `GetTokenInformation` for a fixed-size `T`.
fn token_info<T: Default>(token: &OwnedHandle, class: i32) -> Result<T, u32> {
    let mut value = T::default();
    let mut returned: u32 = 0;
    let len = u32::try_from(size_of::<T>()).map_err(|_| 0u32)?;
    // SAFETY: `token` is a live token handle with TOKEN_QUERY, kept alive until after the call;
    // `value` is a valid, writable buffer of exactly `len` bytes for the fixed-size class the
    // caller names (TOKEN_ELEVATION or TOKEN_ELEVATION_TYPE); `returned` is valid for a write.
    let ok = unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            class,
            ptr::from_mut(&mut value).cast::<c_void>(),
            len,
            &mut returned,
        )
    };
    if ok == 0 {
        return Err(last_error());
    }
    Ok(value)
}

/// The well-known SID of BUILTIN\Administrators, `S-1-5-32-544` (winnt.h `SID` layout:
/// revision 1, two sub-authorities, authority `SECURITY_NT_AUTHORITY` {0,0,0,0,0,5},
/// `SECURITY_BUILTIN_DOMAIN_RID` 32, `DOMAIN_ALIAS_RID_ADMINS` 544).
#[repr(C)]
struct AdminsSid {
    revision: u8,
    sub_authority_count: u8,
    authority: [u8; 6],
    sub_authority: [u32; 2],
}

const ADMINS: AdminsSid = AdminsSid {
    revision: 1,
    sub_authority_count: 2,
    authority: [0, 0, 0, 0, 0, 5],
    sub_authority: [32, 544],
};

/// M1, as `rerun-core`'s `token::process_elevated` plus UAC off: elevated, or
/// `TokenElevationTypeDefault` with Administrators enabled in the token.
fn elevated() -> Result<bool, u32> {
    let token = process_token(TOKEN_QUERY)?;
    let e: TOKEN_ELEVATION = token_info(&token, TokenElevation)?;
    if e.TokenIsElevated != 0 {
        return Ok(true);
    }
    let ty: TOKEN_ELEVATION_TYPE = token_info(&token, TokenElevationType)?;
    if ty != TokenElevationTypeDefault {
        return Ok(false);
    }
    let sid = ADMINS;
    let mut member: i32 = 0;
    // SAFETY: a null token handle makes the API use the calling thread's (impersonation or
    // duplicated primary) token; `sid` is a valid SID (revision 1, two sub-authorities,
    // 4-aligned by `repr(C)` with `u32` fields) that lives until after the call; `member` is
    // valid for a write.
    let ok = unsafe {
        CheckTokenMembership(
            ptr::null_mut(),
            ptr::from_ref(&sid).cast_mut().cast(),
            &mut member,
        )
    };
    if ok == 0 {
        return Err(last_error());
    }
    Ok(member != 0)
}

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

/// `LocalAppData` as `rerun-core`'s `sys::win::shell` asks for it (ADR 0009): never from the
/// environment; `KF_FLAG_DONT_VERIFY | KF_FLAG_NO_PACKAGE_REDIRECTION`; the process token.
fn local_app_data() -> Result<OsString, OsError> {
    let token = process_token(TOKEN_QUERY | TOKEN_IMPERSONATE).map_err(OsError::Win32)?;
    let flags = (KF_FLAG_DONT_VERIFY | KF_FLAG_NO_PACKAGE_REDIRECTION).cast_unsigned();
    let mut raw: PWSTR = ptr::null_mut();
    #[expect(
        clippy::disallowed_methods,
        reason = "rerun-launch's one SHGetKnownFolderPath call site (ADR 0022, D2)"
    )]
    // SAFETY: the GUID is a static; `token` is a live token handle with TOKEN_QUERY |
    // TOKEN_IMPERSONATE kept open until after the call; `raw` is valid for a write and receives
    // a pointer that `CoTaskStr` frees, also on failure.
    let hr = unsafe {
        SHGetKnownFolderPath(
            &FOLDERID_LocalAppData,
            flags,
            token.as_raw_handle(),
            &mut raw,
        )
    };
    let owned = CoTaskStr(raw);
    if hr < 0 {
        return Err(OsError::HResult(hr));
    }
    // SAFETY: on success `raw` is a NUL-terminated string owned by `owned`, alive and
    // unchanged until `owned` drops at the end of this function, after the copy.
    let units = unsafe { wide_units(owned.0) }.ok_or(OsError::HResult(E_POINTER))?;
    Ok(OsString::from_wide(units))
}

/// winerror.h `E_POINTER`: success without a string.
const E_POINTER: i32 = 0x8000_4003_u32.cast_signed();

/// The real system layer.
pub(crate) struct WinOs;

impl Os for WinOs {
    type Child = launch::Child;

    fn command_line(&self) -> Vec<u16> {
        // SAFETY: no arguments; the returned pointer is the process's command line, valid for
        // the life of the process.
        let p = unsafe { GetCommandLineW() };
        // SAFETY: `p` is null or the NUL-terminated command line, which the process never
        // frees or changes (the shim does not write to it).
        unsafe { wide_units(p) }
            .map(<[u16]>::to_vec)
            .unwrap_or_default()
    }

    fn elevated(&self) -> bool {
        // Fail closed (M1): an unanswerable question counts as elevated.
        elevated().unwrap_or(true)
    }

    fn read_profile(&self, id: &ProfileId) -> Result<Vec<u8>, OsError> {
        let mut path = PathBuf::from(local_app_data()?);
        path.push("Rerun");
        path.push("profiles");
        path.push(format!("{id}.profile"));
        #[expect(
            clippy::disallowed_methods,
            reason = "rerun-launch reads its profile by path below the LocalAppData known \
                      folder (ADR 0022, D2); the file itself is opened as a reparse point and \
                      refused if it is one"
        )]
        let file = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_DELETE)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&path)
            .map_err(io_error)?;
        let meta = file.metadata().map_err(io_error)?;
        if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(OsError::ReparsePoint);
        }
        if !meta.is_file() {
            return Err(OsError::NotAFile);
        }
        let mut bytes = Vec::new();
        let limit = u64::try_from(MAX_PROFILE_BYTES + 1).unwrap_or(u64::MAX);
        file.take(limit).read_to_end(&mut bytes).map_err(io_error)?;
        Ok(bytes)
    }

    fn topology(&self) -> Result<CpuTopology, OsError> {
        #[cfg(target_pointer_width = "64")]
        {
            cpu::topology()
        }
        #[cfg(not(target_pointer_width = "64"))]
        {
            Err(OsError::Unsupported)
        }
    }

    fn spawn(
        &self,
        app: &[u16],
        command_line: &[u16],
        spawn: &Spawn,
    ) -> Result<launch::Child, u32> {
        launch::spawn(app, command_line, spawn)
    }

    fn limit_job(&self, child: &launch::Child, affinity: GroupAffinity) -> Result<(), u32> {
        launch::limit_job(child, affinity)
    }

    fn read_back(&self, child: &launch::Child) -> Result<ReadBack, u32> {
        launch::read_back(child)
    }

    fn set_cpu_sets(&self, child: &launch::Child, ids: &[u32]) -> Result<(), u32> {
        launch::set_cpu_sets(child, ids)
    }

    fn resume(&self, child: &launch::Child) -> Result<(), u32> {
        launch::resume(child)
    }

    fn terminate(&self, child: launch::Child) {
        launch::terminate(child);
    }

    fn shell_execute(
        &self,
        file: &[u16],
        parameters: Option<&[u16]>,
    ) -> Result<Option<launch::Child>, u32> {
        launch::shell_execute(file, parameters)
    }

    fn wait(&self, child: launch::Child) -> Result<u32, u32> {
        launch::wait(child)
    }
}

fn io_error(e: std::io::Error) -> OsError {
    OsError::Win32(e.raw_os_error().map_or(0, i32::cast_unsigned))
}

#[cfg(test)]
mod tests;
