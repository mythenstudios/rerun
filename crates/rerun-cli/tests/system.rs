//! `rerun system` on the real machine (ADR 0016, `docs/09-testing.md`, "CLI"): read-only, in
//! the normal suite and in CI (where the GPU block says "no hardware adapter").

#![cfg(windows)]
#![allow(clippy::disallowed_methods, reason = "test launches its own binary")]
#![allow(
    clippy::unwrap_used,
    reason = "test code: a failure should abort the test"
)]

mod support;

use std::os::windows::process::CommandExt;
use std::process::Command;

#[test]
fn rerun_system_on_this_machine() {
    let out = Command::new(env!("CARGO_BIN_EXE_rerun"))
        .arg("system")
        // `CREATE_NO_WINDOW` (winbase.h): no console window from a test.
        .creation_flags(0x0800_0000)
        .output()
        .unwrap();
    let stdout = String::from_utf8(out.stdout).unwrap();
    let stderr = support::without_banner(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "{stdout}\n{stderr}");
    assert!(stderr.is_empty(), "{stderr}");
    let headings: Vec<&str> = stdout
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with(' '))
        .collect();
    assert_eq!(
        headings,
        [
            "GPU",
            "CPU",
            "OS",
            "Conditions (the facts Topo `when` keys are evaluated against)"
        ],
        "{stdout}"
    );
    // No control character but the line feeds, no carriage return.
    assert!(
        !stdout.chars().any(|c| c.is_control() && c != '\n'),
        "{stdout:?}"
    );
    for key in [
        "gpu.vendor",
        "gpu.arch",
        "gpu.integrated",
        "gpu.hybrid",
        "cpu.threads",
        "cpu.hybrid",
        "os.build",
    ] {
        assert!(stdout.contains(&format!("\n  {key}: ")), "{key}: {stdout}");
    }
    // The topology is read: the summary line has the form "<n> L<k> group(s) ...".
    let cpu = stdout.split("CPU\n").nth(1).unwrap();
    assert!(!cpu.starts_with("  could not read"), "{stdout}");
    // Only counts, no names, in the test output.
    eprintln!(
        "rerun system: {} lines, {} GPU lines",
        stdout.lines().count(),
        stdout.split("\n\n").next().unwrap_or("").lines().count()
    );
}
