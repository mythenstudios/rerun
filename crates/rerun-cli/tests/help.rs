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
fn help_lists_the_phase_2_commands_and_their_flags() {
    let out = rerun(&["--help"]);
    let stdout = String::from_utf8(out.stdout).unwrap();
    for c in ["plan", "apply", "revert", "status", "forget"] {
        assert!(stdout.contains(&format!("\n  {c} ")), "{c}: {stdout}");
    }
    for (c, flags) in [
        ("plan", &["--dry-run"][..]),
        ("apply", &["--dry-run", "--yes"]),
        ("revert", &["--dry-run", "--yes"]),
        ("status", &["--all"]),
        ("forget", &["--yes"]),
    ] {
        let out = rerun(&[c, "--help"]);
        assert!(out.status.success(), "{c}");
        let help = String::from_utf8(out.stdout).unwrap();
        for f in flags {
            assert!(help.contains(f), "{c} {f}: {help}");
        }
    }
}

/// Never a well-formed plan hash or transaction here: this binary runs on the real machine
/// (the project rule: never a writing command against the developer machine), so every
/// argument fails clap's parse.
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
        &["plan"],
        &["apply"],
        &["apply", "abc", "--yes"],
        &["apply", "ABCDEF", "--dry-run"],
        &["revert", "abc", "--yes"],
        &["revert", "1-2", "--dry-run"],
        &["forget", "abc", "--yes"],
        &["forget"],
        &["status", "--nope"],
        // Review N5: a value or command with ESC and U+202E reaches stderr escaped.
        &["scan", "\u{1b}[2J\u{202e}x"],
        &["apply", "\u{1b}]0;title\u{7}"],
        &["no\u{1b}[31mcommand"],
        &["status", "--\u{1b}x"],
    ] {
        let out = rerun(args);
        assert_eq!(out.status.code(), Some(2), "{args:?}: {out:?}");
        assert!(out.stdout.is_empty(), "{args:?}: {out:?}");
        let stderr = String::from_utf8(out.stderr).unwrap();
        assert!(
            !stderr.contains('\u{1b}') && !stderr.contains('\u{202e}') && !stderr.contains('\u{7}'),
            "{args:?}: {stderr}"
        );
        // Without a command clap shows the help on stderr; otherwise Rerun's own error line.
        assert!(
            stderr.starts_with("rerun: ")
                || stderr.contains(
                    "
Usage: rerun <COMMAND>"
                ),
            "{args:?}: {stderr}"
        );
        assert!(!stderr.contains('\u{1b}'), "{stderr}");
    }
}
