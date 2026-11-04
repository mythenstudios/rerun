//! `WinGpu` under the DLL hardening of the shipped executables (ADR 0008, H2): with the DLL
//! search path restricted to System32 (as `rerun.exe` does first thing), DXGI still loads, the
//! drivers' user-mode parts still answer, and the Basic Render Driver is listed. Its own test
//! binary, because the restriction is process-wide. Read-only.

#![cfg(windows)]

use rerun_core::sys::Gpu;
use rerun_core::sys::win::{WinGpu, restrict_dll_search};

#[test]
fn gpu_enumerates_with_the_dll_search_path_restricted_to_system32() {
    restrict_dll_search().unwrap();
    let adapters = WinGpu::new().adapters().unwrap();
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
}
