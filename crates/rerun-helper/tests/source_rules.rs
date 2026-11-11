//! Source rule of the elevated helper (ADR 0023 §11, §14; docs/08 "Acceptance (helper)"): the
//! helper's sources (`crates/rerun-helper/src`) and its one entry into `rerun-core`
//! (`crates/rerun-core/src/elevate`, without its `tests.rs` files) never name `WinSystem` or
//! `WinGpu` (the helper builds its own system without GPU, P4-2c), DXGI, the system profile
//! (`hw::`), the journal, `exec`, `pkg`, the network (`WinHttp`, `http::`, ADR 0025), the Steam
//! detection, `topo::when` or `flow` (ADR 0027); a module also as a whole word after
//! `rerun_core` or `crate::` (braces, an alias, a `use` over several lines). Comment lines are
//! not code and are skipped; the scan has teeth.

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
    "flow::",
];

/// Modules of `rerun-core` the helper must not name, as a whole word after `rerun_core` or
/// `crate::` (also through braces or an alias: `use rerun_core::{flow, sys}`,
/// `use rerun_core::flow as f;`, a `use` over several lines), with the name reported.
const MODULES: &[(&str, &str)] = &[
    ("flow", "flow::"),
    ("exec", "exec::"),
    ("hw", "hw::"),
    ("journal", "journal::"),
    ("pkg", "pkg::"),
    ("http", "http::"),
];

/// The identifiers of `code` after its first `rerun_core` or `crate::` (every identifier of a
/// line inside a `use` that started on an earlier line).
fn path_words(code: &str, in_use: bool) -> Vec<&str> {
    let rest = if in_use {
        Some(code)
    } else {
        ["rerun_core", "crate::"]
            .iter()
            .find_map(|p| code.find(p).map(|i| &code[i..]))
    };
    rest.map_or_else(Vec::new, |r| {
        r.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .filter(|w| !w.is_empty())
            .collect()
    })
}

/// The forbidden names in one source text: `(line number, name)`. Lines that are comments
/// (`//`, `//!`, `///` after indentation) are skipped.
fn violations(src: &str) -> Vec<(usize, &'static str)> {
    let mut found = Vec::new();
    let mut in_use = false;
    for (i, line) in src.lines().enumerate() {
        if line.trim_start().starts_with("//") {
            continue;
        }
        let code = line.split("//").next().unwrap_or(line);
        let mut names: Vec<&'static str> = Vec::new();
        for name in FORBIDDEN {
            if code.contains(name) {
                names.push(name);
            }
        }
        let words = path_words(code, in_use);
        for (module, name) in MODULES {
            if words.contains(module) && !names.contains(name) {
                names.push(name);
            }
        }
        let t = code.trim_start();
        let opens = (t.starts_with("use ") || t.starts_with("pub use "))
            && (code.contains("rerun_core") || code.contains("crate::"));
        in_use = (in_use || opens) && !code.contains(';');
        found.extend(names.into_iter().map(|n| (i + 1, n)));
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
        ("let g = rerun_core::flow::guard(env)?;", "flow::"),
        ("use rerun_core::flow as f;", "flow::"),
        ("use rerun_core::{flow, sys::System};", "flow::"),
        ("use crate::{exec, policy};", "exec::"),
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
    // A `use` over several lines.
    assert_eq!(
        violations("use rerun_core::{\n    sys::System,\n    hw,\n};\nlet hw = 1;"),
        [(3, "hw::")]
    );
    // A word that only contains a module name is no module.
    assert!(violations("use rerun_core::sys::{HelperSystem, Https};").is_empty());
}
