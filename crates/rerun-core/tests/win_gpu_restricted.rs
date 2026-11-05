//! `WinSystem` and its GPU under the DLL hardening of the shipped executables (ADR 0008, H2).
//!
//! - With the DLL search path restricted to System32 (as `rerun.exe` does first thing), DXGI
//!   still loads, the drivers' user-mode parts still answer, and the Basic Render Driver is
//!   listed.
//! - This test binary links `WinSystem` with every part (file system, registry, known folders,
//!   topology, GPU), i.e. everything a later shipped binary gets from `rerun-core` today. Its
//!   static imports must stay within [`CORE_IMPORTS`] (no `dxgi.dll`, no `d3d*`, no dynamic
//!   CRT), so a GPU or other import that slipped past the source rule and the bans shows here.
//!
//! Its own test binary, because the restriction is process-wide. Read-only.

#![cfg(windows)]
#![expect(clippy::disallowed_methods, reason = "test reads its own binary")]

use rerun_core::sys::win::{WinSystem, restrict_dll_search};
use rerun_core::sys::{KnownFolder, System};

#[path = "../../../tests/support/pe_min.rs"]
mod pe_min;

/// The static imports of a binary that uses `WinSystem` and the GPU, plus the test harness
/// (exact, case-insensitive). Found on 2026-11-05. A new one fails the test: review it, then
/// extend this list and ADR 0008 (amendment 2026-11-05).
/// `bcryptprimitives.dll` and `userenv.dll` come from `std`, the others from `windows-sys`.
const CORE_IMPORTS: &[&str] = &[
    "kernel32.dll",
    "ntdll.dll",
    "api-ms-win-core-synch-l1-2-0.dll",
    "advapi32.dll",
    "combase.dll",
    "shell32.dll",
    "bcryptprimitives.dll",
    "userenv.dll",
];

#[test]
fn win_system_gpu_with_the_dll_search_path_restricted_to_system32() {
    restrict_dll_search().unwrap();
    let sys = WinSystem::new().unwrap();
    let adapters = sys.gpu().adapters().unwrap();
    assert!(
        adapters.iter().any(|a| a.vendor_id == 0x1414 && a.software),
        "{adapters:#?}"
    );
    for a in &adapters {
        eprintln!(
            "restricted: {:?} vendor {:#06x} software {} umd {:?}",
            a.name, a.vendor_id, a.software, a.umd_version
        );
    }
    // Every other part once, so the linker keeps their imports too.
    for f in KnownFolder::ALL {
        sys.known_folders().get(f).unwrap();
    }
    sys.topology().read().unwrap();
    let windows = sys.known_folders().get(KnownFolder::Windows).unwrap();
    // Fs::open_dir is the one absolute operation (ADR 0007); a listing of the Windows folder
    // only reads.
    let dir = sys.fs().open_dir(&windows).unwrap();
    assert!(!dir.read_dir(None).unwrap().is_empty());
    let exe = std::env::current_exe().unwrap();
    let image = std::fs::read(&exe).unwrap();
    let pe = pe_min::Pe::parse(&image).unwrap_or_else(|e| panic!("{e}"));
    let imports = pe.imports().unwrap_or_else(|e| panic!("{e}"));
    eprintln!("imports: {}", imports.join(", "));
    pe_min::check_imports(&imports, CORE_IMPORTS).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(pe.delay_imports(), Ok(vec![]));
}
