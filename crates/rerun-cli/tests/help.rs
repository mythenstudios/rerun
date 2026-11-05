//! Phase 0 acceptance (`rerun --help`, `rerun --version`) and the command line of phase 1
//! (ADR 0016): help, usage errors (exit 2).

#![allow(clippy::disallowed_methods, reason = "test launches its own binary")]
#![allow(
    clippy::unwrap_used,
    reason = "test code: a failure should abort the test"
)]

use std::process::{Command, Output};

fn rerun(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_rerun"))
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn help_exits_zero_and_names_the_tool_and_its_commands() {
    let out = rerun(&["--help"]);
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("rerun"), "{stdout}");
    assert!(stdout.contains("Usage"), "{stdout}");
    assert!(stdout.contains("\n  system "), "{stdout}");
    // No colour: clap is built without `color` (ADR 0016).
    assert!(!stdout.contains('\u{1b}'), "{stdout}");
}

#[test]
fn scan_help_names_the_hashes_flag() {
    let out = rerun(&["scan", "--help"]);
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("--hashes"), "{stdout}");
    assert!(stdout.contains("[APP_IDS]..."), "{stdout}");
}

#[test]
fn version_matches_package_version() {
    let out = rerun(&["--version"]);
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert_eq!(
        stdout.trim(),
        format!("rerun {}", env!("CARGO_PKG_VERSION"))
    );
}

#[test]
fn usage_errors_exit_2_without_a_report() {
    for args in [
        &[][..],
        &["--no-such-flag"],
        &["no-such-command"],
        &["system", "extra"],
        &["scan", "not-an-app-id"],
        &["scan", "-1"],
        &["scan", "4294967296"],
        &["scan", "--nope"],
    ] {
        let out = rerun(args);
        assert_eq!(out.status.code(), Some(2), "{args:?}: {out:?}");
        assert!(out.stdout.is_empty(), "{args:?}: {out:?}");
        let stderr = String::from_utf8(out.stderr).unwrap();
        // Without a command clap shows the help on stderr; otherwise an error line.
        assert!(
            stderr.starts_with("error: ")
                || stderr.contains(
                    "
Usage: rerun <COMMAND>"
                ),
            "{args:?}: {stderr}"
        );
        assert!(!stderr.contains('\u{1b}'), "{stderr}");
    }
}
