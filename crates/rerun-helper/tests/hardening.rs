//! Hardening of `rerun-helper.exe` (ADR 0023 §2, §13, §14; docs/08 "Acceptance (helper)"):
//! linked with `/DEPENDENTLOADFLAG:0x800`, every static import in `HELPER_IMPORTS`, no
//! delay-load import, nothing that names DXGI (`dxgi.dll` as ASCII or UTF-16LE,
//! `CreateDXGIFactory1`), no run-time loader beyond `std`'s own, the Windows subsystem and an
//! `asInvoker` manifest; started, it gets past its DLL search restriction and refuses
//! (`Refused(NotElevated)` from a standard process, `Refused(ImageFolder)` from an elevated
//! one). The control for the content and import checks is the `WinGpu` test binary of
//! `crates/rerun-core/tests/win_gpu_restricted.rs`, which must fail both (B9).

#![cfg(windows)]
#![expect(
    clippy::disallowed_methods,
    reason = "test reads and runs its own built binary"
)]
#![allow(
    clippy::unwrap_used,
    reason = "test code: a failure should abort the test"
)]

use std::os::windows::process::CommandExt;
use std::path::Path;
use std::process::Command;

use rerun_core::detect::pe::{Limits, Pe};
use rerun_core::elevate::{HelperExit, Reason};
use rerun_core::sys::HelperToken;
use rerun_core::sys::win::WinHelperToken;

#[path = "../../../tests/support/hardening.rs"]
mod hardening;

#[path = "../../../tests/support/test_key.rs"]
mod test_key;

/// `IMAGE_SUBSYSTEM_WINDOWS_GUI`: no console window (§2).
const SUBSYSTEM_WINDOWS_GUI: u16 = 2;

/// Every check of the built helper at `exe`; the imported DLLs for the output.
fn check_helper(exe: &Path) -> String {
    let imports = hardening::check_hardened_file(exe, hardening::HELPER_IMPORTS)
        .unwrap_or_else(|e| panic!("{}: {e}", exe.display()));
    let image = std::fs::read(exe).unwrap();
    hardening::check_helper_content(&image).unwrap_or_else(|e| panic!("{}: {e}", exe.display()));
    let pe = Pe::parse(std::fs::File::open(exe).unwrap(), &Limits::DEFAULT).unwrap();
    assert_eq!(pe.headers().subsystem, SUBSYSTEM_WINDOWS_GUI);
    // The manifest link.exe embeds for /MANIFESTUAC (build.rs), and no other level.
    let has = |s: &[u8]| image.windows(s.len()).any(|w| w == s);
    assert!(
        has(b"level='asInvoker'"),
        "{}: no asInvoker manifest",
        exe.display()
    );
    for other in [
        &b"requireAdministrator"[..],
        b"highestAvailable",
        b"uiAccess='true'",
    ] {
        assert!(
            !has(other),
            "{}: {}",
            exe.display(),
            String::from_utf8_lossy(other)
        );
    }
    hardening::joined(&imports)
}

#[test]
fn rerun_helper_exe_is_hardened_and_never_names_dxgi() {
    let exe = env!("CARGO_BIN_EXE_rerun-helper");
    eprintln!("rerun-helper.exe imports: {}", check_helper(Path::new(exe)));
}

/// The release helper as CI ships it (`cargo build -p rerun-helper --release`, without
/// dev-dependencies): the same checks, and it does not hold the index test key (A4 S3). Its
/// path comes from `RERUN_RELEASE_HELPER_EXE` (set in `.github/workflows/ci.yml`); unset, the
/// check is skipped locally and fails on a GitHub-hosted runner.
#[test]
fn release_rerun_helper_exe_is_hardened_and_holds_no_test_key() {
    let Some(exe) = std::env::var_os("RERUN_RELEASE_HELPER_EXE") else {
        assert!(
            !hardening::on_github_hosted_runner(),
            "RERUN_RELEASE_HELPER_EXE is not set on a GitHub-hosted runner (ci.yml)"
        );
        eprintln!("RERUN_RELEASE_HELPER_EXE not set: release binary not checked");
        return;
    };
    let exe = Path::new(&exe);
    eprintln!("release rerun-helper.exe imports: {}", check_helper(exe));
    let image = std::fs::read(exe).unwrap();
    assert!(
        !test_key::holds_test_key(&image),
        "the release rerun-helper.exe holds the index test key"
    );
    // N5 (P4-2c security review): the CLI's own runtime check agrees on the shipped binary.
    assert!(!rerun_core::policy::root::holds_test_key(&image));
}

/// N5 on built binaries: the runtime check a release CLI runs before it starts the installed
/// helper (`policy::root::holds_test_key`, the seed or the public key, masked in the CLI) finds
/// the test key in this test build of the helper, which has the feature through the
/// dev-dependency (the same build as `rerun-cli`'s `only_the_test_build_trusts_the_test_key`),
/// and agrees with the release byte check of `tests/support/test_key.rs`.
#[test]
fn the_cli_s_runtime_check_finds_the_test_key_in_a_test_key_helper() {
    let image = std::fs::read(env!("CARGO_BIN_EXE_rerun-helper")).unwrap();
    assert!(
        test_key::holds_test_key(&image),
        "the test build should hold the test key: the check would not bite"
    );
    assert!(rerun_core::policy::root::holds_test_key(&image));
}

/// Started from this test (no `runas`), the helper gets past `restrict_dll_search` and drops
/// its privileges (else `Refused(Internal)`), then refuses: `NotElevated` from a standard
/// process (the developer machine), `ImageFolder` from an elevated one (the CI runner, whose
/// processes are elevated): it runs from `target\`, not from the admin-only
/// `Program Files\Rerun` (ADR 0023 §3 step 4, P4-2c). Its privileges are its own: this test
/// process keeps its own.
#[test]
fn rerun_helper_exe_refuses_outside_its_folder() {
    let elevated = WinHelperToken.is_elevated().unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_rerun-helper"))
        .args(["--volume", "x"])
        // `CREATE_NO_WINDOW` (winbase.h); the helper has no console anyway.
        .creation_flags(0x0800_0000)
        .output()
        .unwrap();
    assert!(out.stdout.is_empty() && out.stderr.is_empty(), "{out:?}");
    let code = out.status.code().unwrap().cast_unsigned();
    let want = if elevated {
        Reason::ImageFolder
    } else {
        Reason::NotElevated
    };
    assert_eq!(
        HelperExit::from_code(code, 1),
        Some(HelperExit::refused(want)),
        "{code:#010x}"
    );
}
