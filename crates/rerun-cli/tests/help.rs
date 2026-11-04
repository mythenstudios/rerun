//! Phase 0 acceptance: `rerun --help` and `rerun --version` work.

#![allow(clippy::disallowed_methods, reason = "test launches its own binary")]
#![allow(
    clippy::unwrap_used,
    reason = "test code: a failure should abort the test"
)]

use std::process::{Command, Output};

fn rerun(arg: &str) -> Output {
    Command::new(env!("CARGO_BIN_EXE_rerun"))
        .arg(arg)
        .output()
        .unwrap()
}

#[test]
fn help_exits_zero_and_names_the_tool() {
    let out = rerun("--help");
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("rerun"), "{stdout}");
    assert!(stdout.contains("Usage"), "{stdout}");
}

#[test]
fn version_matches_package_version() {
    let out = rerun("--version");
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert_eq!(
        stdout.trim(),
        format!("rerun {}", env!("CARGO_PKG_VERSION"))
    );
}
