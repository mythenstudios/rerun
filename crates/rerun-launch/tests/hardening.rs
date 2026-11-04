//! DLL hardening of `rerun-launch.exe` (ADR 0008, H2): linked with `/DEPENDENTLOADFLAG:0x800`,
//! no static import of a graphics DLL or the dynamic CRT, no delay-load import; and the shim
//! gets past its DLL search path restriction (its first statement).

#![cfg(windows)]
#![expect(
    clippy::disallowed_methods,
    reason = "test reads and runs its own built binary"
)]

use std::process::Command;

#[path = "../../../tests/support/pe_min.rs"]
mod pe_min;

#[test]
fn rerun_launch_exe_loads_dependencies_from_system32_only() {
    let exe = env!("CARGO_BIN_EXE_rerun-launch");
    let image = std::fs::read(exe).unwrap_or_else(|e| panic!("{exe}: {e}"));
    let imports = pe_min::check_hardened(&image).unwrap_or_else(|e| panic!("{exe}: {e}"));
    eprintln!("rerun-launch.exe imports: {}", imports.join(", "));
}

#[test]
fn rerun_launch_exe_runs_with_the_restricted_search_path() {
    let out = Command::new(env!("CARGO_BIN_EXE_rerun-launch"))
        .output()
        .unwrap();
    // Phase 0: the shim reports "not implemented yet" after the restriction succeeded.
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("not implemented yet"), "{stderr}");
    assert!(!stderr.contains("DLL search path"), "{stderr}");
}
