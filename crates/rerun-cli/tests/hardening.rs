//! DLL hardening of `rerun.exe` (ADR 0008, H2): linked with `/DEPENDENTLOADFLAG:0x800`, no
//! static import of a graphics DLL or the dynamic CRT, no delay-load import; and the binary
//! gets past `restrict_dll_search` (its first statement).

#![cfg(windows)]
#![expect(
    clippy::disallowed_methods,
    reason = "test reads and runs its own built binary"
)]

use std::path::Path;
use std::process::Command;

#[path = "../../../tests/support/hardening.rs"]
mod hardening;

#[test]
fn rerun_exe_loads_dependencies_from_system32_only() {
    let exe = env!("CARGO_BIN_EXE_rerun");
    let imports =
        hardening::check_hardened_file(Path::new(exe)).unwrap_or_else(|e| panic!("{exe}: {e}"));
    eprintln!("rerun.exe imports: {}", hardening::joined(&imports));
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
