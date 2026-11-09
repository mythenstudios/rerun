//! DLL hardening of `rerun.exe` (ADR 0008, H2): linked with `/DEPENDENTLOADFLAG:0x800`, no
//! static import of a graphics DLL or the dynamic CRT, every import in `CLI_IMPORTS`, no
//! delay-load import; and the binary gets past `restrict_dll_search` (its first statement).
//! The console is left as found (ADR 0016): no console state API is named in the binary.

#![cfg(windows)]
#![expect(
    clippy::disallowed_methods,
    reason = "test reads and runs its own built binary"
)]

use std::os::windows::process::CommandExt;
use std::path::Path;
use std::process::Command;

#[path = "../../../tests/support/hardening.rs"]
mod hardening;

#[test]
fn rerun_exe_loads_dependencies_from_system32_only() {
    let exe = env!("CARGO_BIN_EXE_rerun");
    let imports = hardening::check_hardened_file(Path::new(exe), hardening::CLI_IMPORTS)
        .unwrap_or_else(|e| panic!("{exe}: {e}"));
    eprintln!("rerun.exe imports: {}", hardening::joined(&imports));
    let image = std::fs::read(exe).unwrap();
    assert_eq!(hardening::console_state_apis(&image), Vec::<&str>::new());
}

/// The release `rerun.exe` as it ships (`cargo build -p rerun-cli --release`, without
/// dev-dependencies, so without `rerun-core/fake`): the test-profile binary above is linked with
/// the features of the test build, so CI checks the release binary too. Its path comes from
/// `RERUN_RELEASE_CLI_EXE` (set in `.github/workflows/ci.yml`); unset, the check is skipped
/// locally and fails on a GitHub-hosted runner.
#[test]
fn release_rerun_exe_loads_dependencies_from_system32_only() {
    let Some(exe) = std::env::var_os("RERUN_RELEASE_CLI_EXE") else {
        assert!(
            !hardening::on_github_hosted_runner(),
            "RERUN_RELEASE_CLI_EXE is not set on a GitHub-hosted runner (ci.yml)"
        );
        eprintln!("RERUN_RELEASE_CLI_EXE not set: release binary not checked");
        return;
    };
    let exe = Path::new(&exe);
    let imports = hardening::check_hardened_file(exe, hardening::CLI_IMPORTS)
        .unwrap_or_else(|e| panic!("{}: {e}", exe.display()));
    eprintln!("release rerun.exe imports: {}", hardening::joined(&imports));
    let image = std::fs::read(exe).unwrap();
    assert_eq!(hardening::console_state_apis(&image), Vec::<&str>::new());
}

#[test]
fn rerun_exe_runs_with_the_restricted_search_path() {
    let out = Command::new(env!("CARGO_BIN_EXE_rerun"))
        .arg("--version")
        // `CREATE_NO_WINDOW` (winbase.h): no console window from a test.
        .creation_flags(0x0800_0000)
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!stderr.contains("DLL search path"), "{stderr}");
}

/// Whether `image` holds the published test key of the signed index (ADR 0024): its seed as
/// hex text or its public key bytes.
fn holds_test_key(image: &[u8]) -> bool {
    use rerun_core::catalog::key::test_key;
    let seed = test_key::SEED_HEX.as_bytes();
    let public = test_key::public();
    let found = |needle: &[u8]| image.windows(needle.len()).any(|w| w == needle);
    found(seed) || found(public.bytes())
}

/// ADR 0024: the test key is trusted only with the feature `test-key`, which only
/// dev-dependencies enable. The test-profile binary has it (the check bites), the release binary
/// must not (`RERUN_RELEASE_CLI_EXE`, as above).
#[test]
fn only_the_test_build_trusts_the_test_key() {
    let image = std::fs::read(env!("CARGO_BIN_EXE_rerun")).unwrap();
    assert!(
        holds_test_key(&image),
        "the test build should hold the test key: the check would not bite"
    );
    let Some(exe) = std::env::var_os("RERUN_RELEASE_CLI_EXE") else {
        assert!(
            !hardening::on_github_hosted_runner(),
            "RERUN_RELEASE_CLI_EXE is not set on a GitHub-hosted runner (ci.yml)"
        );
        eprintln!("RERUN_RELEASE_CLI_EXE not set: release binary not checked");
        return;
    };
    let image = std::fs::read(&exe).unwrap();
    assert!(
        !holds_test_key(&image),
        "the release rerun.exe holds the index test key"
    );
}
