//! The only calls that change the DLL search path or load a DLL at run time (ADR 0008, H2).
//!
//! [`restrict_dll_search`] is the first statement of `rerun.exe`'s `main`:
//! `SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32)` removes the application directory,
//! the current directory and `PATH` from every later `LoadLibrary*` of the process, including
//! the ones Windows makes on Rerun's behalf. Together with the link flag
//! `/DEPENDENTLOADFLAG:0x800` (static imports from System32 only, set by the `build.rs` of
//! every shipped executable) no DLL is ever taken from a user-writable install folder.
//! `rerun-launch` has its own copy of the one call (it does not depend on `rerun-core`).
//!
//! [`load_system32`] is the only `LoadLibraryExW`: a bare ASCII DLL name, searched in System32
//! only (`LOAD_LIBRARY_SEARCH_SYSTEM32`), whatever the process's default search path. The
//! module is never freed, so a [`SystemDll`] and every symbol from it stay valid for the life
//! of the process; [`SystemDll::symbol`] is the only `GetProcAddress`. Today the only caller is
//! `dxgi` (`dxgi.dll`, `CreateDXGIFactory1`). Accepted limit: if a module of the same base name
//! is already loaded in the process, the loader returns that one (a test checks that
//! `dxgi.dll` comes from `<Windows>\System32`).
//!
//! `SetDefaultDllDirectories`, `SetDllDirectoryW`/`A`, `AddDllDirectory` and
//! `RemoveDllDirectory` are `clippy.toml` bans everywhere else, as are `LoadLibrary*`,
//! `LoadPackagedLibrary` and `GetProcAddress` outside this module.

#![allow(
    unsafe_code,
    reason = "FFI to SetDefaultDllDirectories, LoadLibraryExW and GetProcAddress (ADR 0008, \
              H2); every block has a SAFETY comment"
)]

use std::ffi::CStr;
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};

use windows_sys::Win32::Foundation::{ERROR_INVALID_PARAMETER, HMODULE};
use windows_sys::Win32::System::LibraryLoader::{
    GetProcAddress, LOAD_LIBRARY_SEARCH_SYSTEM32, LoadLibraryExW, SetDefaultDllDirectories,
};

use super::status::kind_of_win32;
use crate::sys::{SysError, SysResult};

/// Set once [`restrict_dll_search`] succeeded; never cleared (the restriction cannot be undone
/// without the banned `SetDllDirectoryW`/`AddDllDirectory`).
static RESTRICTED: AtomicBool = AtomicBool::new(false);

/// Whether this process restricted its DLL search path with [`restrict_dll_search`]. Code that
/// loads non-KnownDLLs (`dxgi`) refuses to run otherwise.
pub(super) fn dll_search_restricted() -> bool {
    RESTRICTED.load(Ordering::Acquire)
}

/// Restricts the DLL search path of this process to System32 (ADR 0008, H2). Call it first
/// thing in `main`, before anything can load a DLL; a shipped executable that cannot restrict
/// its search path must not run (fail closed). Process-wide; calling it again is harmless.
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
    RESTRICTED.store(true, Ordering::Release);
    Ok(())
}

/// An export as `GetProcAddress` returns it; the caller transmutes it to the export's real
/// function type.
pub(super) type Export = unsafe extern "system" fn() -> isize;

/// A DLL loaded from System32 by [`load_system32`]. Never freed (no `Drop`): the module and
/// every symbol taken from it stay valid until the process exits.
#[derive(Debug)]
pub(super) struct SystemDll(HMODULE);

/// Loads `name` (a bare ASCII file name such as `dxgi.dll`) from System32 only. A name with a
/// path separator, a drive colon or a non-ASCII character is refused with
/// `ERROR_INVALID_PARAMETER` before any call; else the Win32 error of `LoadLibraryExW`
/// (`ERROR_MOD_NOT_FOUND` for a DLL System32 does not have).
pub(super) fn load_system32(name: &'static str) -> Result<SystemDll, u32> {
    if name.is_empty() || !name.is_ascii() || name.contains(['\\', '/', ':']) {
        return Err(ERROR_INVALID_PARAMETER);
    }
    let wide: Vec<u16> = name.encode_utf16().chain([0]).collect();
    #[expect(
        clippy::disallowed_methods,
        reason = "the one LoadLibraryExW call site (ADR 0008): System32 only, bare name"
    )]
    // SAFETY: `wide` is a NUL-terminated UTF-16 string that lives across the call; `hFile` must
    // be null; LOAD_LIBRARY_SEARCH_SYSTEM32 is a documented flag that limits the search for the
    // DLL and its dependencies to System32.
    let module =
        unsafe { LoadLibraryExW(wide.as_ptr(), ptr::null_mut(), LOAD_LIBRARY_SEARCH_SYSTEM32) };
    if module.is_null() {
        return Err(last_error());
    }
    Ok(SystemDll(module))
}

impl SystemDll {
    /// The export `name` (the `FARPROC`); the Win32 error (`ERROR_PROC_NOT_FOUND`) if the DLL
    /// has no such export. The caller must know the export's signature.
    pub(super) fn symbol(&self, name: &'static CStr) -> Result<Export, u32> {
        #[expect(
            clippy::disallowed_methods,
            reason = "the one GetProcAddress call site (ADR 0008)"
        )]
        // SAFETY: `self.0` is a module handle from LoadLibraryExW that is never freed; `name` is
        // a NUL-terminated string with static lifetime (an export name, not an ordinal).
        let f = unsafe { GetProcAddress(self.0, name.as_ptr().cast()) };
        f.ok_or_else(last_error)
    }

    /// The module handle, for tests that ask Windows where the DLL came from.
    #[cfg(test)]
    pub(super) fn handle(&self) -> HMODULE {
        self.0
    }
}

/// The last Win32 error of this thread (read right after a failed call).
fn last_error() -> u32 {
    std::io::Error::last_os_error()
        .raw_os_error()
        .map_or(0, i32::cast_unsigned)
}

#[cfg(test)]
mod tests {
    use windows_sys::Win32::Foundation::{ERROR_MOD_NOT_FOUND, ERROR_PROC_NOT_FOUND};

    use super::*;

    #[test]
    fn the_restriction_is_recorded() {
        restrict_dll_search().unwrap();
        assert!(dll_search_restricted());
        // Again: harmless, still recorded.
        restrict_dll_search().unwrap();
        assert!(dll_search_restricted());
    }

    #[test]
    fn load_system32_takes_bare_ascii_names_only() {
        for bad in [
            "",
            r"..\dxgi.dll",
            r"C:\Windows\System32\dxgi.dll",
            "sub/dxgi.dll",
            "c:dxgi.dll",
            "dxgi.dll:stream",
            "dxgi\u{e9}.dll",
        ] {
            assert_eq!(
                load_system32(bad).unwrap_err(),
                ERROR_INVALID_PARAMETER,
                "{bad}"
            );
        }
    }

    /// Read-only: a name System32 does not have is not found, a missing export is reported.
    #[test]
    fn load_system32_reports_missing_dlls_and_exports() {
        assert_eq!(
            load_system32("rerun-no-such-dll.dll").unwrap_err(),
            ERROR_MOD_NOT_FOUND
        );
        let dxgi = load_system32("dxgi.dll").unwrap();
        assert!(dxgi.symbol(c"CreateDXGIFactory1").is_ok());
        assert_eq!(
            dxgi.symbol(c"RerunNoSuchExport").unwrap_err(),
            ERROR_PROC_NOT_FOUND
        );
    }
}
