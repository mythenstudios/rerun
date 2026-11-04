//! The only calls that change the DLL search path (ADR 0008, H2).
//!
//! [`restrict_dll_search`] is the first statement of `rerun.exe`'s `main`:
//! `SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32)` removes the application directory,
//! the current directory and `PATH` from every later `LoadLibrary*` of the process, including
//! the ones Windows makes on Rerun's behalf. Together with the link flag
//! `/DEPENDENTLOADFLAG:0x800` (static imports from System32 only, set by the `build.rs` of
//! every shipped executable) no DLL is ever taken from a user-writable install folder.
//! `rerun-launch` has its own copy of the one call (it does not depend on `rerun-core`).
//!
//! `SetDefaultDllDirectories`, `SetDllDirectoryW`/`A`, `AddDllDirectory` and
//! `RemoveDllDirectory` are `clippy.toml` bans everywhere else.

#![allow(
    unsafe_code,
    reason = "FFI to SetDefaultDllDirectories (ADR 0008, H2); every block has a SAFETY comment"
)]

use windows_sys::Win32::System::LibraryLoader::{
    LOAD_LIBRARY_SEARCH_SYSTEM32, SetDefaultDllDirectories,
};

use super::status::kind_of_win32;
use crate::sys::{SysError, SysResult};

/// Restricts the DLL search path of this process to System32 (ADR 0008, H2). Call it first
/// thing in `main`, before anything can load a DLL; a shipped executable that cannot restrict
/// its search path must not run (fail closed).
///
/// # Errors
/// The Win32 error of `SetDefaultDllDirectories`.
pub fn restrict_dll_search() -> SysResult<()> {
    #[expect(
        clippy::disallowed_methods,
        reason = "the one SetDefaultDllDirectories call site (ADR 0008, H2)"
    )]
    // SAFETY: the call takes a flag value only, no pointer; LOAD_LIBRARY_SEARCH_SYSTEM32 is one
    // of the documented flags. It changes process state only (the default search path).
    let ok = unsafe { SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32) };
    if ok == 0 {
        let code = last_error();
        return Err(
            SysError::new(kind_of_win32(code), "SetDefaultDllDirectories").with_win32(code),
        );
    }
    Ok(())
}

/// The last Win32 error of this thread (read right after a failed call).
fn last_error() -> u32 {
    std::io::Error::last_os_error()
        .raw_os_error()
        .map_or(0, i32::cast_unsigned)
}
