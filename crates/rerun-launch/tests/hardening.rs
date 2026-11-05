//! DLL hardening of `rerun-launch.exe` (ADR 0008, H2): linked with `/DEPENDENTLOADFLAG:0x800`,
//! no static import of a graphics DLL or the dynamic CRT, no delay-load import; and the shim
//! gets past its DLL search path restriction (its first statement).

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
fn rerun_launch_exe_loads_dependencies_from_system32_only() {
    let exe = env!("CARGO_BIN_EXE_rerun-launch");
    let imports = hardening::check_hardened_file(Path::new(exe), hardening::LAUNCH_IMPORTS)
        .unwrap_or_else(|e| panic!("{exe}: {e}"));
    eprintln!("rerun-launch.exe imports: {}", hardening::joined(&imports));
}

/// The release shim as CI ships it (`cargo build -p rerun-launch --release`, without
/// dev-dependencies): the test-profile binary above is linked with the features of the test
/// build, so CI checks the release binary too. Its path comes from
/// `RERUN_RELEASE_LAUNCH_EXE` (set in `.github/workflows/ci.yml`); unset, the check is skipped
/// locally and fails on a GitHub-hosted runner.
#[test]
fn release_rerun_launch_exe_loads_dependencies_from_system32_only() {
    let Some(exe) = std::env::var_os("RERUN_RELEASE_LAUNCH_EXE") else {
        assert!(
            !hardening::on_github_hosted_runner(),
            "RERUN_RELEASE_LAUNCH_EXE is not set on a GitHub-hosted runner (ci.yml)"
        );
        eprintln!("RERUN_RELEASE_LAUNCH_EXE not set: release binary not checked");
        return;
    };
    let exe = Path::new(&exe);
    let imports = hardening::check_hardened_file(exe, hardening::LAUNCH_IMPORTS)
        .unwrap_or_else(|e| panic!("{}: {e}", exe.display()));
    eprintln!(
        "release rerun-launch.exe imports: {}",
        hardening::joined(&imports)
    );
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
