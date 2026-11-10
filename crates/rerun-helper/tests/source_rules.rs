//! Source rule of the elevated helper (ADR 0023 §11, §14; docs/08 "Acceptance (helper)"): the
//! helper's sources (`crates/rerun-helper/src`) and its one entry into `rerun-core`
//! (`crates/rerun-core/src/elevate`, without its `tests.rs` files) never name `WinSystem` or
//! `WinGpu` (the helper builds its own system without GPU, P4-2c), DXGI, the system profile
//! (`hw::`), the journal, `exec`, `pkg`, the network (`WinHttp`, `http::`, ADR 0025), the Steam
//! detection or `topo::when`. Comment lines are not code and are skipped; the scan has teeth.

#![allow(
    clippy::disallowed_methods,
    reason = "test reads the helper's own sources"
)]
#![allow(
    clippy::unwrap_used,
    reason = "test code: a failure should abort the test"
)]

use std::path::{Path, PathBuf};

/// What the helper's code must never name.
const FORBIDDEN: &[&str] = &[
    "WinSystem",
    "WinGpu",
    "dxgi",
    "hw::",
    "journal::",
    "exec::",
    "pkg::",
    "WinHttp",
    "http::",
    "detect::steam",
    "topo::when",
];

/// The forbidden names in one source text: `(line number, name)`. Lines that are comments
/// (`//`, `//!`, `///` after indentation) are skipped.
fn violations(src: &str) -> Vec<(usize, &'static str)> {
    let mut found = Vec::new();
    for (i, line) in src.lines().enumerate() {
        if line.trim_start().starts_with("//") {
            continue;
        }
        let code = line.split("//").next().unwrap_or(line);
        for name in FORBIDDEN {
            if code.contains(name) {
                found.push((i + 1, *name));
            }
        }
    }
    found
}

fn sources(dir: &Path, out: &mut Vec<PathBuf>) {
    for e in std::fs::read_dir(dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display())) {
        let p = e.unwrap().path();
        if p.is_dir() {
            sources(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs")
            && p.file_name().is_some_and(|n| n != "tests.rs")
        {
            out.push(p);
        }
    }
}

#[test]
fn the_helper_never_names_the_full_system_or_the_gpu() {
    let crate_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    sources(&crate_dir.join("src"), &mut files);
    sources(&crate_dir.join("../rerun-core/src/elevate"), &mut files);
    assert!(
        files.iter().any(|f| f.ends_with("main.rs"))
            && files.iter().any(|f| f.ends_with("exit.rs")),
        "{files:?}"
    );
    let mut bad = Vec::new();
    for f in &files {
        for (n, name) in violations(&std::fs::read_to_string(f).unwrap()) {
            bad.push(format!("{}:{n}: {name}", f.display()));
        }
    }
    assert!(
        bad.is_empty(),
        "the helper names what it must not (ADR 0023 §11):\n{}",
        bad.join("\n")
    );
}

#[test]
fn the_rule_has_teeth() {
    for (src, name) in [
        (
            "    use rerun_core::sys::win::{WinSystem, restrict_dll_search};",
            "WinSystem",
        ),
        ("let g = WinGpu::new();", "WinGpu"),
        ("let p = rerun_core::hw::profile(sys);", "hw::"),
        ("use crate::journal::TxnWriter;", "journal::"),
        ("crate::exec::standard_user(sys)?;", "exec::"),
        ("let s = detect::steam::scan(sys, fr);", "detect::steam"),
        ("topo::when::eval(&w)", "topo::when"),
        ("load_system32(\"dxgi.dll\")", "dxgi"),
        (
            "let x = 1; // fine so far, but WinGpu here is a comment",
            "?",
        ),
    ] {
        let v = violations(src);
        if name == "?" {
            assert!(v.is_empty(), "{src}: {v:?}");
        } else {
            assert_eq!(
                v.iter().map(|(_, n)| *n).collect::<Vec<_>>(),
                [name],
                "{src}"
            );
        }
    }
    // Comment lines are not code.
    assert!(violations("//! `WinSystem` and `exec::standard_user` are for the CLI").is_empty());
    assert!(violations("    /// never `WinGpu`").is_empty());
    assert_eq!(violations("a\nb\nWinGpu"), [(3, "WinGpu")]);
}
