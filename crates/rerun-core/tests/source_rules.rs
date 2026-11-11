//! Source rule (ADR 0008 amendment, security review of step 10): no hand-written FFI imports.
//!
//! Every Win32 import comes from `windows-sys`, whose bans in `clippy.toml` fence it. A
//! hand-written `extern "…" { … }` block, a `#[link(…)]` attribute or a `raw-dylib` import
//! would bypass those bans (and could import `dxgi.dll` statically), so every `.rs` file of the
//! workspace (`crates/`, `tests/`) is scanned for them. Function pointer
//! types (`unsafe extern "system" fn(…)`) and exported functions (`extern "system" fn f()`) are
//! fine: they import nothing. Exceptions go into [`ALLOWED`] with a reviewed reason; there are
//! none today.

#![expect(
    clippy::disallowed_methods,
    reason = "test reads the workspace sources by path"
)]

use std::path::{Path, PathBuf};

/// Files (workspace-relative, `/`-separated) that may contain an FFI import block. Empty.
const ALLOWED: &[&str] = &[];

/// This file: it holds the patterns as test data and is not scanned.
const SELF: &str = "crates/rerun-core/tests/source_rules.rs";

/// Source roots below the workspace root.
const ROOTS: &[&str] = &["crates", "tests"];

fn workspace() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap_or_else(|e| panic!("workspace root: {e}"))
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries {
        let e = e.unwrap_or_else(|e| panic!("{}: {e}", dir.display()));
        let path = e.path();
        let kind = e
            .file_type()
            .unwrap_or_else(|err| panic!("{}: {err}", e.path().display()));
        if kind.is_dir() {
            let name = e.file_name();
            if name != "target" && name != "node_modules" {
                rust_files(&path, out);
            }
        } else if kind.is_file() && path.extension().is_some_and(|x| x == "rs") {
            out.push(path);
        }
    }
}

/// The FFI import constructs in `src` (with all whitespace removed, so line breaks and spacing
/// do not matter), as short descriptions.
fn ffi_imports(src: &str) -> Vec<String> {
    let s: String = src.chars().filter(|c| !c.is_whitespace()).collect();
    let mut found = Vec::new();
    // `extern {` and `extern "abi" {` (with or without `unsafe` in front, edition 2024).
    let mut rest = s.as_str();
    while let Some(i) = rest.find("extern") {
        let after = &rest[i + "extern".len()..];
        let block = if let Some(abi) = after.strip_prefix('"') {
            abi.find('"')
                .map(|end| (&abi[..end], &abi[end + 1..]))
                .filter(|(_, tail)| tail.starts_with('{'))
                .map(|(abi, _)| abi.to_owned())
        } else {
            after.starts_with('{').then(String::new)
        };
        if let Some(abi) = block {
            found.push(format!("extern \"{abi}\" block"));
        }
        rest = after;
    }
    // `#[link(…)]`, also inside `cfg_attr(…, link(…))`, and `raw-dylib` anywhere.
    let link = concat!("li", "nk(");
    for prefix in ['[', ','] {
        if s.contains(&format!("{prefix}{link}")) {
            found.push(format!("{link}…) attribute"));
        }
    }
    let raw = concat!("raw", "-dylib");
    if s.contains(raw) {
        found.push(raw.to_owned());
    }
    found
}

#[test]
fn no_hand_written_ffi_imports() {
    let root = workspace();
    let mut files = Vec::new();
    for r in ROOTS {
        rust_files(&root.join(r), &mut files);
    }
    assert!(files.len() > 50, "found only {} .rs files", files.len());
    let mut bad = Vec::new();
    for f in files {
        let rel = f
            .strip_prefix(&root)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        if rel == SELF || ALLOWED.contains(&rel.as_str()) {
            continue;
        }
        let src = std::fs::read_to_string(&f).unwrap();
        for what in ffi_imports(&src) {
            bad.push(format!("{rel}: {what}"));
        }
    }
    assert!(
        bad.is_empty(),
        "hand-written FFI imports bypass the windows-sys bans (ADR 0008); use windows-sys or add a \
         reviewed entry to ALLOWED:\n{}",
        bad.join("\n")
    );
}

/// The scanner has teeth.
#[test]
fn the_scanner_finds_every_import_form() {
    let q = '"';
    let block = |abi: &str| format!("unsafe extern {q}{abi}{q}\n{{ fn F(); }}");
    assert_eq!(ffi_imports(&block("system")).len(), 1);
    assert_eq!(ffi_imports(&block("C")).len(), 1);
    assert_eq!(ffi_imports(&block("stdcall")).len(), 1);
    assert_eq!(ffi_imports("extern { fn f(); }").len(), 1);
    let attr = format!("#[{}name = {q}dxgi{q})]", concat!("li", "nk("));
    assert_eq!(ffi_imports(&attr).len(), 1);
    let cfg = format!(
        "#[cfg_attr(windows, {}name = {q}dxgi{q}))]",
        concat!("li", "nk(")
    );
    assert_eq!(ffi_imports(&cfg).len(), 1);
    assert_eq!(ffi_imports(concat!("kind = \"raw", "-dylib\"")).len(), 1);
    // Not imports: function pointer types, exported functions, `extern crate`, link_name.
    let fine = format!(
        "type F = unsafe extern {q}system{q} fn(u32) -> i32;\n\
         pub extern {q}system{q} fn DllMain() {{}}\n\
         extern crate alloc;\n\
         #[{}_name = {q}x{q}]",
        concat!("li", "nk")
    );
    assert_eq!(ffi_imports(&fine), Vec::<String>::new());
}

/// What would switch off TLS certificate validation (ADR 0025): WinHTTP's security flags option
/// and its `SECURITY_FLAG_IGNORE_*` values, WinINet's `INTERNET_FLAG_IGNORE_CERT_*`.
const TLS_OFF: &[&str] = &[
    "WINHTTP_OPTION_SECURITY_FLAGS",
    "SECURITY_FLAG_IGNORE_",
    "INTERNET_FLAG_IGNORE_CERT_",
];

/// The lines of `src` (comments skipped) that name one of [`TLS_OFF`].
fn tls_off(src: &str) -> Vec<&'static str> {
    let mut found = Vec::new();
    for line in src.lines() {
        if line.trim_start().starts_with("//") {
            continue;
        }
        let code = line.split("//").next().unwrap_or(line);
        found.extend(TLS_OFF.iter().copied().filter(|p| code.contains(p)));
    }
    found
}

#[test]
fn certificate_validation_is_never_switched_off() {
    let root = workspace();
    let mut files = Vec::new();
    for r in ROOTS {
        rust_files(&root.join(r), &mut files);
    }
    assert!(files.len() > 50, "found only {} .rs files", files.len());
    let mut bad = Vec::new();
    for f in files {
        let rel = f
            .strip_prefix(&root)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        if rel == SELF {
            continue;
        }
        let src = std::fs::read_to_string(&f).unwrap();
        for what in tls_off(&src) {
            bad.push(format!("{rel}: {what}"));
        }
    }
    assert!(
        bad.is_empty(),
        "TLS certificate validation must stay on (ADR 0025):\n{}",
        bad.join("\n")
    );
    // The scanner has teeth.
    assert_eq!(
        tls_off("set(h, WINHTTP_OPTION_SECURITY_FLAGS, SECURITY_FLAG_IGNORE_UNKNOWN_CA);"),
        ["WINHTTP_OPTION_SECURITY_FLAGS", "SECURITY_FLAG_IGNORE_"]
    );
    assert!(tls_off("// WINHTTP_OPTION_SECURITY_FLAGS in a comment").is_empty());
}
