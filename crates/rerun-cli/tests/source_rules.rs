//! Source rules of `rerun-cli` (ADR 0016): raw text reaches output only escaped. The product
//! sources (`src/`, without the `tests.rs` files) never call `RawText::as_raw_str` (raw text is
//! shown through `RawText::escaped`) and never use a `{:?}` format (a `Debug` form is no
//! display form; `RawText`'s shows only its length, others may show raw content).

#![allow(
    clippy::disallowed_methods,
    reason = "test reads the crate's own sources"
)]
#![allow(
    clippy::unwrap_used,
    reason = "test code: a failure should abort the test"
)]

use std::path::{Path, PathBuf};

/// The rule violations in one source text: `(line number, line)`.
fn violations(src: &str) -> Vec<(usize, String)> {
    src.lines()
        .enumerate()
        .filter(|(_, l)| {
            let code = l.trim_start();
            !code.starts_with("//")
                && (l.contains("as_raw_str") || l.contains(":?}") || l.contains(":#?}"))
        })
        .map(|(i, l)| (i + 1, l.to_owned()))
        .collect()
}

fn sources(dir: &Path, out: &mut Vec<PathBuf>) {
    for e in std::fs::read_dir(dir).unwrap() {
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
fn no_raw_text_and_no_debug_format_in_the_product_sources() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    sources(&src, &mut files);
    assert!(files.iter().any(|f| f.ends_with("scan.rs")), "{files:?}");
    let mut bad = Vec::new();
    for f in &files {
        for (n, line) in violations(&std::fs::read_to_string(f).unwrap()) {
            bad.push(format!("{}:{n}: {line}", f.display()));
        }
    }
    assert!(bad.is_empty(), "{bad:#?}");
}

#[test]
fn the_rule_has_teeth() {
    for bad in [
        "    let s = app.name.as_raw_str();",
        r#"    write!(f, "{name:?}")"#,
        r#"    write!(f, "{:?}", label)"#,
        r#"    format!("{x:#?}")"#,
    ] {
        assert_eq!(violations(bad).len(), 1, "{bad}");
    }
    for ok in [
        "    let s = app.name.escaped();",
        r#"    write!(f, "{name}")"#,
        "    // as_raw_str is never called here",
    ] {
        assert!(violations(ok).is_empty(), "{ok}");
    }
}
