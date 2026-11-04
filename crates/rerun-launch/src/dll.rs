//! `rerun-launch`'s own copy of `rerun_core::sys::win::restrict_dll_search` (ADR 0008, H2): the
//! shim does not depend on `rerun-core` (ADR 0006), so it makes the one call itself.

#![allow(
    unsafe_code,
    reason = "FFI to SetDefaultDllDirectories (ADR 0008, H2); the block has a SAFETY comment"
)]

use windows_sys::Win32::System::LibraryLoader::{
    LOAD_LIBRARY_SEARCH_SYSTEM32, SetDefaultDllDirectories,
};

/// Restricts the DLL search path of this process to System32. Call it first thing in `main`;
/// on failure the Win32 error code, and the shim must not run (fail closed).
pub(crate) fn restrict_search() -> Result<(), u32> {
    #[expect(
        clippy::disallowed_methods,
        reason = "rerun-launch's one SetDefaultDllDirectories call site (ADR 0008, H2)"
    )]
    // SAFETY: the call takes a flag value only, no pointer; LOAD_LIBRARY_SEARCH_SYSTEM32 is one
    // of the documented flags. It changes process state only (the default search path).
    let ok = unsafe { SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32) };
    if ok == 0 {
        return Err(std::io::Error::last_os_error()
            .raw_os_error()
            .map_or(0, i32::cast_unsigned));
    }
    Ok(())
}
