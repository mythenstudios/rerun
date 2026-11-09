//! [`WinElevation`]: the CLI's one start of the elevated helper (ADR 0023 §2, §7; A4 S2, N3)
//! and the token kind (§10). The only calls in `rerun-core` to `ShellExecuteExW` and
//! `QueryFullProcessImageNameW`, and one of its two `CoInitializeEx` sites (the other is
//! `com::Apartment`, the firewall read; `clippy.toml`; `rerun-launch` has its own reviewed
//! `ShellExecuteExW`).
//!
//! The start:
//! 1. `HKLM\SOFTWARE\Classes\exefile`, opened read-only in the native view through `reg`, is
//!    passed as `hkeyClass` with `SEE_MASK_CLASSKEY`: the verb is looked up in that key only,
//!    so a user-writable `HKCU\Software\Classes\exefile\shell\runas\command` (the `sdclt`
//!    redirection) is not consulted (verified in `sys::win::tests::elevation`, ADR 0023 §7).
//! 2. COM initialised (apartment-threaded, `COINIT_DISABLE_OLE1DDE`) around the call, as
//!    `ShellExecuteExW` asks (the CLI's named `CoInitializeEx` exception, ADR 0008, A4 N3).
//! 3. `ShellExecuteExW`, verb `runas`, `lpFile` = the pre-checked image, `lpDirectory` = its
//!    folder (N3), `SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC | SEE_MASK_FLAG_NO_UI |
//!    SEE_MASK_CLASSKEY`, the console window as the owner. `ERROR_CANCELLED` (1223) is
//!    [`HelperRun::Declined`].
//! 4. On `hProcess`, right after the start and before the wait: `QueryFullProcessImageNameW`
//!    in the native form (`\Device\…`; the Win32 form fails once the process has exited, and a
//!    scaffold helper exits at once) and `TokenElevation` through
//!    `OpenProcessToken(TOKEN_QUERY)`; a failed read is `None` in [`HelperProc`], never a guess
//!    (`elevate::judge` then says `Unknown`).
//! 5. Wait without a timeout (the prompt waits for the user), then `GetExitCodeProcess`.
//!
//! Every handle is owned (`OwnedHandle`, `OwnedKey`) and closed on every path.

#![allow(
    unsafe_code,
    reason = "FFI to shell32/combase/kernel32 for the one helper start (ADR 0023); every block \
              has a SAFETY comment"
)]

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsHandle, AsRawHandle, BorrowedHandle, FromRawHandle, OwnedHandle};
use std::path::Path;
use std::ptr;

use windows_sys::Win32::Foundation::{HANDLE, WAIT_OBJECT_0};
use windows_sys::Win32::System::Com::{
    COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE, CoInitializeEx, CoUninitialize,
};
use windows_sys::Win32::System::Console::GetConsoleWindow;
use windows_sys::Win32::System::Threading::{
    GetExitCodeProcess, INFINITE, PROCESS_NAME_NATIVE, QueryFullProcessImageNameW,
    WaitForSingleObject,
};
use windows_sys::Win32::UI::Shell::{
    SEE_MASK_CLASSKEY, SEE_MASK_FLAG_NO_UI, SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS,
    SHELLEXECUTEINFOW, ShellExecuteExW,
};

use super::reg::{self, OwnedKey, ReadAccess, Root, View};
use super::status::kind_of_win32;
use super::token;
use crate::path::RootPath;
use crate::sys::elevation::{Elevation, HelperProc, HelperRun, TokenKind, parameters};
use crate::sys::{SysError, SysErrorKind, SysResult};

/// winerror.h `ERROR_CANCELLED`: the user declined the UAC prompt.
pub(super) const ERROR_CANCELLED: u32 = 1223;
/// winuser.h `SW_HIDE` (avoids the `Win32_UI_WindowsAndMessaging` feature): the helper has no
/// window anyway.
const SW_HIDE: i32 = 0;
/// Longest Win32 path in UTF-16 units including the NUL (`QueryFullProcessImageNameW`).
const MAX_IMAGE: u32 = 32_768;
/// The class key of every start (A4 S2).
pub(super) const EXEFILE_CLASS: &str = r"SOFTWARE\Classes\exefile";

/// The real [`Elevation`].
#[derive(Debug, Clone, Copy, Default)]
pub struct WinElevation;

/// The last Win32 error of this thread (read right after a failed call).
fn last_error() -> u32 {
    std::io::Error::last_os_error()
        .raw_os_error()
        .map_or(0, i32::cast_unsigned)
}

fn sys_err(op: &str, code: u32) -> SysError {
    SysError::new(kind_of_win32(code), op).with_win32(code)
}

fn wide(s: &OsStr) -> Vec<u16> {
    s.encode_wide().chain([0]).collect()
}

/// `HKLM\SOFTWARE\Classes\exefile`, read-only (`KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE`),
/// native view.
pub(super) fn exefile_class() -> Result<OwnedKey, u32> {
    reg::open(
        &Root::LocalMachine,
        EXEFILE_CLASS,
        ReadAccess::Enumerate,
        View::Native,
    )
}

/// COM for the one `ShellExecuteExW` call: uninitialised on drop if initialisation succeeded.
struct Com(bool);

impl Com {
    fn init() -> Self {
        let flags = (COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE).cast_unsigned();
        #[expect(
            clippy::disallowed_methods,
            reason = "rerun-core's first CoInitializeEx call site (com::Apartment is the \
                      second), for the helper's ShellExecuteExW (ADR 0023 §2, ADR 0008, A4 N3)"
        )]
        // SAFETY: the reserved pointer must be null; the flags are documented COINIT values.
        let hr = unsafe { CoInitializeEx(ptr::null(), flags) };
        Self(hr >= 0)
    }
}

impl Drop for Com {
    fn drop(&mut self) {
        if self.0 {
            // SAFETY: balances the successful CoInitializeEx of this thread, exactly once.
            unsafe { CoUninitialize() };
        }
    }
}

/// One `ShellExecuteExW` with `SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC |
/// SEE_MASK_FLAG_NO_UI | SEE_MASK_CLASSKEY` and `hkeyClass` = `class`: `verb` on `file` with
/// `params` in `dir`, owner the console window, `SW_HIDE`. The started process's handle, or the
/// Win32 error; a successful call without a process (`hProcess` null) is `ERROR_INVALID_HANDLE`.
/// Product code passes `runas` only ([`WinElevation::run_helper`]); tests pass other verbs to
/// measure the class key without a prompt.
pub(super) fn start(
    verb: &str,
    file: &Path,
    params: &str,
    dir: &Path,
    class: &OwnedKey,
) -> Result<OwnedHandle, u32> {
    let verb = wide(OsStr::new(verb));
    let file = wide(file.as_os_str());
    let params = wide(OsStr::new(params));
    let dir = wide(dir.as_os_str());
    // SAFETY: GetConsoleWindow takes no arguments; a null result (no console) is allowed as the
    // owner.
    let owner = unsafe { GetConsoleWindow() };
    let mut info = SHELLEXECUTEINFOW {
        cbSize: u32::try_from(size_of::<SHELLEXECUTEINFOW>()).unwrap_or(0),
        fMask: SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC | SEE_MASK_FLAG_NO_UI | SEE_MASK_CLASSKEY,
        hwnd: owner,
        lpVerb: verb.as_ptr(),
        lpFile: file.as_ptr(),
        lpParameters: params.as_ptr(),
        lpDirectory: dir.as_ptr(),
        nShow: SW_HIDE,
        hkeyClass: class.raw(),
        ..SHELLEXECUTEINFOW::default()
    };
    let com = Com::init();
    #[expect(
        clippy::disallowed_methods,
        reason = "rerun-core's one ShellExecuteExW call site: the elevated helper's start \
                  (ADR 0023 §2, §7)"
    )]
    // SAFETY: `info` is a SHELLEXECUTEINFOW with a matching `cbSize`; `lpVerb`, `lpFile`,
    // `lpParameters` and `lpDirectory` point to NUL-terminated buffers owned by this function
    // and alive for the call; `hkeyClass` is the open key `class` borrows for the call;
    // `hwnd` is the console window or null.
    let ok = unsafe { ShellExecuteExW(&mut info) };
    let code = if ok == 0 { last_error() } else { 0 };
    drop(com);
    if ok == 0 {
        return Err(code);
    }
    let raw: HANDLE = info.hProcess;
    if raw.is_null() {
        return Err(6); // ERROR_INVALID_HANDLE: no process to check or wait for.
    }
    // SAFETY: with SEE_MASK_NOCLOSEPROCESS a successful call hands `hProcess` to the caller;
    // nothing else closes it.
    Ok(unsafe { OwnedHandle::from_raw_handle(raw) })
}

/// `QueryFullProcessImageNameW(PROCESS_NAME_NATIVE)` of `process`: the NT name
/// (`\Device\HarddiskVolumeN\…`). The native form, because it stays readable after the process
/// has exited; the Win32 form then fails with `ERROR_GEN_FAILURE` (31), measured on Windows 11
/// build 26300 by `image_and_token_are_readable_on_the_handle_also_after_exit`.
pub(super) fn image_of(process: BorrowedHandle<'_>) -> Result<String, u32> {
    let mut buf = vec![0u16; MAX_IMAGE as usize];
    let mut len = MAX_IMAGE;
    #[expect(
        clippy::disallowed_methods,
        reason = "the one QueryFullProcessImageNameW call site: the started helper's image \
                  (ADR 0023 §7, A4 S2)"
    )]
    // SAFETY: `process` is a live process handle borrowed for the call; `buf` is valid for
    // writes of `len` UTF-16 units; `len` is valid for reads and writes.
    let ok = unsafe {
        QueryFullProcessImageNameW(
            process.as_raw_handle(),
            PROCESS_NAME_NATIVE,
            buf.as_mut_ptr(),
            &mut len,
        )
    };
    if ok == 0 {
        return Err(last_error());
    }
    buf.truncate(len as usize);
    String::from_utf16(&buf).map_err(|_| 1113) // ERROR_NO_UNICODE_TRANSLATION
}

/// What is read on `process` before the wait (§7): each fact `None` if it cannot be read.
pub(super) fn facts(process: BorrowedHandle<'_>) -> HelperProc {
    HelperProc {
        image: image_of(process).ok(),
        elevated: token::elevated_of(process).ok(),
    }
}

/// Waits for `process` without a timeout, then its exit code.
pub(super) fn wait(process: BorrowedHandle<'_>) -> Result<u32, u32> {
    // SAFETY: `process` is a live process handle (with SYNCHRONIZE from ShellExecuteExW)
    // borrowed for the call.
    let r = unsafe { WaitForSingleObject(process.as_raw_handle(), INFINITE) };
    if r != WAIT_OBJECT_0 {
        return Err(last_error());
    }
    let mut code: u32 = 0;
    // SAFETY: as above (PROCESS_QUERY_LIMITED_INFORMATION included); `code` is valid for a
    // write.
    let ok = unsafe { GetExitCodeProcess(process.as_raw_handle(), &mut code) };
    if ok == 0 {
        return Err(last_error());
    }
    Ok(code)
}

impl Elevation for WinElevation {
    fn token_kind(&self) -> SysResult<TokenKind> {
        let (elevated, ty) =
            token::process_elevation().map_err(|c| sys_err("elevation of the process token", c))?;
        Ok(if elevated {
            TokenKind::Elevated
        } else if ty == token::LIMITED {
            TokenKind::Filtered
        } else {
            TokenKind::Standard
        })
    }

    fn run_helper(&self, image: &RootPath, args: &[&str]) -> SysResult<HelperRun> {
        let params = parameters(args)?;
        let shown = image.to_string();
        let dir = image
            .path()
            .parent()
            .ok_or_else(|| SysError::new(SysErrorKind::InvalidPath, &shown))?;
        let class = exefile_class().map_err(|c| sys_err(r"HKLM\SOFTWARE\Classes\exefile", c))?;
        let process = match start("runas", image.path(), &params, dir, &class) {
            Ok(p) => p,
            Err(ERROR_CANCELLED) => return Ok(HelperRun::Declined),
            Err(c) => return Err(sys_err(&shown, c)),
        };
        let proc = facts(process.as_handle());
        let code = wait(process.as_handle()).map_err(|c| sys_err(&shown, c))?;
        Ok(HelperRun::Exited { code, proc })
    }
}
