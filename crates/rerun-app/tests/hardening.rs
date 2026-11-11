//! Hardening of `rerun-app.exe` (ADR 0008 H2, ADR 0026, ADR 0027): linked with
//! `/DEPENDENTLOADFLAG:0x800`, every static import in `APP_IMPORTS`, no graphics DLL and no
//! dynamic CRT imported statically, no delay-load import, the Windows subsystem and an
//! `asInvoker` manifest (never `requireAdministrator`, `highestAvailable` or
//! `uiAccess='true'`) with per-monitor DPI awareness V2; the release binary holds neither the
//! index test key nor the test-key build's index folder or banner.
//!
//! The release binary is the one CI builds (`cargo build -p rerun-app --release`, without
//! dev-dependencies): its path comes from `RERUN_RELEASE_APP_EXE`; unset, the check is skipped
//! locally and fails on a GitHub-hosted runner.

#![cfg(windows)]
#![expect(clippy::disallowed_methods, reason = "test reads its own built binary")]
#![allow(
    clippy::unwrap_used,
    reason = "test code: a failure should abort the test"
)]

use std::path::Path;

use rerun_core::detect::pe::{Limits, Pe};

#[path = "../../../tests/support/hardening.rs"]
mod hardening;

#[path = "../../../tests/support/test_key.rs"]
mod test_key;

/// `IMAGE_SUBSYSTEM_WINDOWS_GUI`: no console window.
const SUBSYSTEM_WINDOWS_GUI: u16 = 2;

/// Whether `image` holds `text` as ASCII or as UTF-16LE.
fn holds_text(image: &[u8], text: &str) -> bool {
    let ascii = text.as_bytes();
    let wide: Vec<u8> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let found = |needle: &[u8]| image.windows(needle.len()).any(|w| w == needle);
    found(ascii) || found(&wide)
}

/// Every check of the built app at `exe`; the imported DLLs for the output.
fn check_app(exe: &Path) -> String {
    let imports = hardening::check_hardened_file(exe, hardening::APP_IMPORTS)
        .unwrap_or_else(|e| panic!("{}: {e}", exe.display()));
    let image = std::fs::read(exe).unwrap();
    let pe = Pe::parse(std::fs::File::open(exe).unwrap(), &Limits::DEFAULT).unwrap();
    assert_eq!(pe.headers().subsystem, SUBSYSTEM_WINDOWS_GUI);
    let has = |s: &[u8]| image.windows(s.len()).any(|w| w == s);
    // link.exe merges `/MANIFESTUAC` into `rerun-app.manifest` and writes double quotes then.
    assert!(
        has(br#"level="asInvoker""#) || has(b"level='asInvoker'"),
        "{}: no asInvoker manifest",
        exe.display()
    );
    assert!(
        has(b"PerMonitorV2"),
        "{}: no per-monitor DPI awareness",
        exe.display()
    );
    for other in [
        &b"requireAdministrator"[..],
        b"highestAvailable",
        b"uiAccess='true'",
        br#"uiAccess="true""#,
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
fn rerun_app_exe_is_hardened() {
    let exe = env!("CARGO_BIN_EXE_rerun-app");
    eprintln!("rerun-app.exe imports: {}", check_app(Path::new(exe)));
}

#[test]
fn release_rerun_app_exe_is_hardened_and_holds_no_test_key() {
    let Some(exe) = std::env::var_os("RERUN_RELEASE_APP_EXE") else {
        assert!(
            !hardening::on_github_hosted_runner(),
            "RERUN_RELEASE_APP_EXE is not set on a GitHub-hosted runner (ci.yml)"
        );
        eprintln!("RERUN_RELEASE_APP_EXE not set: release binary not checked");
        return;
    };
    let exe = Path::new(&exe);
    eprintln!("release rerun-app.exe imports: {}", check_app(exe));
    let image = std::fs::read(exe).unwrap();
    assert!(
        !test_key::holds_test_key(&image),
        "the release rerun-app.exe holds the index test key"
    );
    assert!(
        !holds_text(&image, "index-test"),
        "the release rerun-app.exe names the test-key index folder"
    );
}

/// The test-profile binary trusts the test key (rerun-core/test-key through the dev-dependency),
/// so the release checks above bite.
#[test]
fn the_test_build_holds_the_test_key() {
    let image = std::fs::read(env!("CARGO_BIN_EXE_rerun-app")).unwrap();
    assert!(test_key::holds_test_key(&image));
    assert!(holds_text(&image, "index-test"));
}
