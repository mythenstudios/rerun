//! `rerun scan` on the real machine (ADR 0016, `docs/09-testing.md`, "CLI"): a local opt-in
//! only, `#[ignore]` and `RERUN_SMOKE_REAL=1`. Read-only; it prints aggregate counts only
//! (libraries, games, issues), never names, paths or SteamIDs, and writes no file. On failure
//! it shows the exit code and the stderr line count, never the output itself.
//!
//! `RERUN_SMOKE_REAL=1 cargo test -p rerun-cli --test scan -- --ignored --nocapture`

#![cfg(windows)]
#![allow(
    clippy::disallowed_methods,
    reason = "test launches its own binary and reads its opt-in gate"
)]
#![allow(
    clippy::unwrap_used,
    reason = "test code: a failure should abort the test"
)]

use std::process::Command;

#[test]
#[ignore = "reads the real Steam installation; opt-in with RERUN_SMOKE_REAL=1"]
fn rerun_scan_on_this_machine_counts_only() {
    if std::env::var("RERUN_SMOKE_REAL").as_deref() != Ok("1") {
        eprintln!("RERUN_SMOKE_REAL is not 1: skipped");
        return;
    }
    let out = Command::new(env!("CARGO_BIN_EXE_rerun"))
        .arg("scan")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr_lines = String::from_utf8_lossy(&out.stderr).lines().count();
    assert_eq!(
        out.status.code(),
        Some(0),
        "exit code (stderr: {stderr_lines} lines)"
    );
    let count = |prefix: &str| stdout.lines().filter(|l| l.starts_with(prefix)).count();
    let control = stdout
        .chars()
        .filter(|c| c.is_control() && *c != '\n')
        .count();
    eprintln!(
        "libraries {}, apps {}, installed {}, one main {}, ties {}, none {}, steam issues {}, \
         game issues {}, escaped lines {}, control characters {control}, stderr lines \
         {stderr_lines}",
        count("library "),
        count("  app "),
        stdout
            .lines()
            .filter(|l| l.starts_with("  app ") && l.contains(" (installed): "))
            .count(),
        count("    main executable: ")
            - count("    main executable: a tie")
            - count("    main executable: none"),
        count("    main executable: a tie"),
        count("    main executable: none"),
        count("  issue: "),
        count("    issue: "),
        stdout.lines().filter(|l| l.contains(r"\u{")).count(),
    );
    assert_eq!(control, 0, "control characters in the output");
    assert!(
        stdout.ends_with("Roles and APIs are hints from names and imports, not verdicts.\n"),
        "no summary"
    );
}
