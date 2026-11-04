//! DLL hardening of `rerun.exe` (ADR 0008, H2): linked with `/DEPENDENTLOADFLAG:0x800`, no
//! static import of a graphics DLL or the dynamic CRT, no delay-load import; and the binary
//! gets past `restrict_dll_search` (its first statement).

#![cfg(windows)]
#![expect(
    clippy::disallowed_methods,
    reason = "test reads and runs its own built binary"
)]

use std::process::Command;

#[path = "../../../tests/support/pe_min.rs"]
mod pe_min;

#[test]
fn rerun_exe_loads_dependencies_from_system32_only() {
    let exe = env!("CARGO_BIN_EXE_rerun");
    let image = std::fs::read(exe).unwrap_or_else(|e| panic!("{exe}: {e}"));
    let imports = pe_min::check_hardened(&image).unwrap_or_else(|e| panic!("{exe}: {e}"));
    eprintln!("rerun.exe imports: {}", imports.join(", "));
}

#[test]
fn rerun_exe_runs_with_the_restricted_search_path() {
    let out = Command::new(env!("CARGO_BIN_EXE_rerun"))
        .arg("--version")
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!stderr.contains("DLL search path"), "{stderr}");
}
