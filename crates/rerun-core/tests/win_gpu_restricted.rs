//! `WinSystem` and its GPU under the DLL hardening of the shipped executables (ADR 0008, H2).
//!
//! - Before `restrict_dll_search` the GPU is `Unsupported` (L2 of the step 10 review).
//! - With the DLL search path restricted to System32 (as `rerun.exe` does first thing), DXGI
//!   still loads, the drivers' user-mode parts still answer, and the Basic Render Driver is
//!   listed.
//! - This test binary links `WinSystem` with every part (file system, registry, known folders,
//!   topology, GPU), as `rerun.exe` does from step 16. Its static imports must stay within
//!   `hardening::CLI_IMPORTS`, the list of `rerun.exe` (no `dxgi.dll`, no `d3d*`, no dynamic
//!   CRT), so a GPU or other import that slipped past the source rule and the bans shows here.
//! - It is also the control of the elevated helper's acceptance (ADR 0023 §14, B9): the
//!   helper's content check (no `dxgi.dll`, no `CreateDXGIFactory1`) and its import allowlist
//!   must both fail on this binary.
//!
//! Its own test binary, because the restriction is process-wide. Read-only.

#![cfg(windows)]
#![expect(clippy::disallowed_methods, reason = "test reads its own binary")]

use rerun_core::sys::win::{WinSystem, restrict_dll_search};
use rerun_core::sys::{KnownFolder, SysErrorKind, System};

#[path = "../../../tests/support/hardening.rs"]
mod hardening;

#[test]
fn win_system_gpu_with_the_dll_search_path_restricted_to_system32() {
    let sys = WinSystem::new().unwrap();
    // Without the restriction the GPU refuses to load DXGI.
    let e = sys.gpu().adapters().unwrap_err();
    assert_eq!(e.kind, SysErrorKind::Unsupported, "{e}");
    restrict_dll_search().unwrap();
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
    let (imports, delayed) = hardening::imports_of(&exe).unwrap_or_else(|e| panic!("{e}"));
    eprintln!("imports: {}", hardening::joined(&imports));
    hardening::check_imports(&imports, hardening::CLI_IMPORTS).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(delayed, vec![]);
    // The control of the helper's acceptance (ADR 0023 §14, B9): this binary uses `WinGpu`, so
    // the helper's content check and import allowlist must both fail on it.
    let image = std::fs::read(&exe).unwrap();
    let dxgi = hardening::dxgi_references(&image);
    assert!(
        dxgi.contains(&"dxgi.dll (ASCII)") && dxgi.contains(&"CreateDXGIFactory1"),
        "{dxgi:?}"
    );
    let e = hardening::check_helper_content(&image).unwrap_err();
    assert!(e.contains("names DXGI"), "{e}");
    let e = hardening::check_imports(&imports, hardening::HELPER_IMPORTS).unwrap_err();
    assert!(e.contains("not in the allowlist"), "{e}");
}
