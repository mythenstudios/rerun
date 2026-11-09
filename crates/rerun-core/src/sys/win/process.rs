//! Processes for the elevated helper (ADR 0023 §3, A4 S8): the helper's own image, its instance
//! lock, and the CLI's check whether a helper process still runs. Nothing here changes another
//! process.
//!
//! - [`own_image`]: `QueryFullProcessImageNameW(PROCESS_NAME_NATIVE)` on the current-process
//!   pseudo handle (through `elevation::image_of`, the one call site of that function).
//! - [`instance_mutex`]: rerun-core's one `CreateMutexW` (`clippy.toml`): the named mutex
//!   [`INSTANCE_MUTEX`] in the global namespace, created by the helper after its elevation check.
//!   An existing one (`ERROR_ALREADY_EXISTS`) means another helper runs: `Busy`. The handle is
//!   owned and closed on drop; the kernel destroys the object with its last handle, also when a
//!   helper crashes. A same-user process can create the name first and so keep every helper
//!   from running (a denial of service, never more: the helper only refuses).
//! - [`running`]: one `CreateToolhelp32Snapshot` (rerun-core's one call site), every process whose
//!   `szExeFile` equals the file name (ASCII case ignored) opened with
//!   `PROCESS_QUERY_LIMITED_INFORMATION` (rerun-core's one `OpenProcess`, never inheritable) and
//!   its native image compared folded with the expected NT name. A candidate that cannot be
//!   opened or asked counts as running (fail closed).

#![allow(
    unsafe_code,
    reason = "FFI to kernel32 for the helper's instance lock and the process check (ADR 0023, \
              A4 S8); every block has a SAFETY comment"
)]

use std::os::windows::io::{AsHandle, AsRawHandle, BorrowedHandle, FromRawHandle, OwnedHandle};
use std::ptr;

use windows_sys::Win32::Foundation::{
    ERROR_ALREADY_EXISTS, ERROR_NO_MORE_FILES, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::Threading::{
    CreateMutexW, GetCurrentProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
};

use super::elevation::image_of;
use crate::fold::fold;

/// The helper's instance mutex (A4 S8), in the global namespace so that a helper of another
/// session (over-the-shoulder elevation) counts too.
pub(super) const INSTANCE_MUTEX: &str = r"Global\Rerun.ElevatedHelper";

/// Most processes one snapshot may list (a real machine has a few hundred).
const MAX_PROCESSES: usize = 65_536;

/// The last Win32 error of this thread (read right after a failed call).
fn last_error() -> u32 {
    std::io::Error::last_os_error()
        .raw_os_error()
        .map_or(0, i32::cast_unsigned)
}

/// Takes ownership of `raw` unless it is null or `INVALID_HANDLE_VALUE`.
///
/// # Safety
/// `raw` was just returned by a call that hands a new handle to the caller, and nothing else
/// owns or closes it.
unsafe fn own(raw: HANDLE) -> Option<OwnedHandle> {
    (!raw.is_null() && raw != INVALID_HANDLE_VALUE).then(|| {
        // SAFETY: a new handle owned by the caller and closed by nothing else (the contract).
        unsafe { OwnedHandle::from_raw_handle(raw) }
    })
}

/// This process, as a borrowed pseudo handle.
fn current_process() -> BorrowedHandle<'static> {
    // SAFETY: no arguments; returns the current-process pseudo handle.
    let raw = unsafe { GetCurrentProcess() };
    // SAFETY: the pseudo handle (-1) is valid for the whole life of the process and needs no
    // closing; `BorrowedHandle` allows -1 ("sometimes a valid handle value").
    unsafe { BorrowedHandle::borrow_raw(raw) }
}

/// The NT name of this process's image (module docs).
pub(super) fn own_image() -> Result<String, u32> {
    image_of(current_process())
}

/// The held instance mutex: its handle, closed on drop.
#[derive(Debug)]
pub(super) struct InstanceMutex(#[allow(dead_code, reason = "held for its drop only")] OwnedHandle);

/// Creates [`INSTANCE_MUTEX`] (module docs): `Err(ERROR_ALREADY_EXISTS)` while another helper
/// holds it (the handle to the existing object is closed again at once), else the Win32 error.
pub(super) fn instance_mutex() -> Result<InstanceMutex, u32> {
    named_mutex(INSTANCE_MUTEX)
}

/// [`instance_mutex`] under `name` (tests use their own name).
pub(super) fn named_mutex(name: &str) -> Result<InstanceMutex, u32> {
    let name: Vec<u16> = name.encode_utf16().chain([0]).collect();
    #[expect(
        clippy::disallowed_methods,
        reason = "rerun-core's one CreateMutexW call site: the elevated helper's instance lock \
                  (ADR 0023, A4 S8)"
    )]
    // SAFETY: default security (null attributes); not initially owned (the object's existence is
    // the lock); `name` is a NUL-terminated buffer alive for the call.
    let raw = unsafe { CreateMutexW(ptr::null(), 0, name.as_ptr()) };
    let code = last_error();
    // SAFETY: `raw` was just returned by CreateMutexW (null on failure); nothing else owns it.
    let handle = unsafe { own(raw) }.ok_or(code)?;
    if code == ERROR_ALREADY_EXISTS {
        drop(handle);
        return Err(ERROR_ALREADY_EXISTS);
    }
    Ok(InstanceMutex(handle))
}

/// `szExeFile` up to its NUL.
fn exe_name(entry: &PROCESSENTRY32W) -> String {
    let name = &entry.szExeFile;
    let len = name.iter().position(|&u| u == 0).unwrap_or(name.len());
    String::from_utf16_lossy(name.get(..len).unwrap_or_default())
}

/// The PIDs of every process whose `szExeFile` equals `file_name` (ASCII case ignored).
fn candidates(file_name: &str) -> Result<Vec<u32>, u32> {
    #[expect(
        clippy::disallowed_methods,
        reason = "rerun-core's one CreateToolhelp32Snapshot call site: the helper process check \
                  (ADR 0023, A4 S8)"
    )]
    // SAFETY: documented flags; the process ID is ignored for TH32CS_SNAPPROCESS; no pointers.
    let raw = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if raw == INVALID_HANDLE_VALUE {
        return Err(last_error());
    }
    // SAFETY: `raw` is a new snapshot handle (checked above; null is refused by `own`); nothing
    // else owns it.
    let snap = unsafe { own(raw) }.ok_or_else(last_error)?;
    let mut entry = PROCESSENTRY32W {
        dwSize: u32::try_from(size_of::<PROCESSENTRY32W>()).unwrap_or(0),
        ..PROCESSENTRY32W::default()
    };
    let mut pids = Vec::new();
    let mut seen = 0usize;
    // SAFETY: `snap` is a live snapshot handle; `entry` is a writable PROCESSENTRY32W whose
    // `dwSize` is its size.
    let mut ok = unsafe { Process32FirstW(snap.as_raw_handle(), &mut entry) };
    while ok != 0 {
        seen += 1;
        if seen > MAX_PROCESSES {
            return Err(windows_sys::Win32::Foundation::ERROR_BUFFER_OVERFLOW);
        }
        if exe_name(&entry).eq_ignore_ascii_case(file_name) {
            pids.push(entry.th32ProcessID);
        }
        // SAFETY: as for Process32FirstW.
        ok = unsafe { Process32NextW(snap.as_raw_handle(), &mut entry) };
    }
    let code = last_error();
    if code != ERROR_NO_MORE_FILES {
        return Err(code);
    }
    Ok(pids)
}

/// The native image of process `pid`, or `None` if it cannot be opened or asked.
fn image_of_pid(pid: u32) -> Option<String> {
    #[expect(
        clippy::disallowed_methods,
        reason = "rerun-core's one OpenProcess call site: the helper process check (ADR 0023, \
                  A4 S8), query rights only"
    )]
    // SAFETY: no pointers; `bInheritHandle` FALSE; the call returns a new handle or null.
    let raw = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    // SAFETY: `raw` was just returned by OpenProcess (null on failure); nothing else owns it.
    let process = unsafe { own(raw) }?;
    image_of(process.as_handle()).ok()
}

/// Whether a process of the image `nt_name` runs now (module docs). The file name is the last
/// segment of `nt_name`.
pub(super) fn running(nt_name: &str) -> Result<bool, u32> {
    let file_name = nt_name.rsplit('\\').next().unwrap_or(nt_name);
    let want = fold(nt_name);
    let own_pid = std::process::id();
    for pid in candidates(file_name)? {
        if pid == own_pid {
            // This process is never the helper it waits for; its own image is asked directly.
            if own_image().is_ok_and(|i| fold(&i) == want) {
                return Ok(true);
            }
            continue;
        }
        match image_of_pid(pid) {
            Some(image) if fold(&image) != want => {}
            // The same image, or one that cannot be told apart.
            _ => return Ok(true),
        }
    }
    Ok(false)
}
