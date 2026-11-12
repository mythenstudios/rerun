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

/// The source folders and files of the types whose `Debug` form `flow::revert` hashes to compare
/// a preview with what is observed under the lock (ADR 0027 amendment P5-2b): the journal view,
/// the observation, the head's preview and the values in them.
const DIGESTED: &[&str] = &[
    "crates/rerun-core/src/exec",
    "crates/rerun-core/src/plan",
    "crates/rerun-core/src/journal",
    "crates/rerun-core/src/escape.rs",
    "crates/rerun-core/src/escape",
    "crates/rerun-core/src/path.rs",
];

/// Hand-written `Debug` impls there of types that are never part of a digest (a context and a
/// lock guard).
const DEBUG_ALLOWED: &[&str] = &["ExecCtx", "LockHold"];

/// The types with a hand-written `Debug` impl in `src` (comments aside).
fn manual_debug(src: &str) -> Vec<String> {
    let mut found = Vec::new();
    for line in src.lines() {
        let code = line.split("//").next().unwrap_or_default();
        let s: String = code.split_whitespace().collect::<Vec<_>>().join(" ");
        let Some(at) = s.find("Debug for ") else {
            continue;
        };
        if !s.trim_start().starts_with("impl") {
            continue;
        }
        let ty: String = s[at + "Debug for ".len()..]
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        found.push(ty);
    }
    found
}

/// The digest of a preview is taken over the derived `Debug` form, which holds every field; a
/// hand-written impl could leave a field out and let a change pass as "the same" (P5-2b).
#[test]
fn digested_types_derive_debug() {
    let root = workspace();
    let mut files = Vec::new();
    for d in DIGESTED {
        let p = root.join(d);
        if p.is_file() {
            files.push(p);
        } else {
            rust_files(&p, &mut files);
        }
    }
    assert!(files.len() > 10, "found only {} .rs files", files.len());
    let mut bad = Vec::new();
    for f in files {
        let src = std::fs::read_to_string(&f).unwrap();
        for ty in manual_debug(&src) {
            if !DEBUG_ALLOWED.contains(&ty.as_str()) {
                bad.push(format!("{}: {ty}", f.display()));
            }
        }
    }
    assert!(
        bad.is_empty(),
        "flow::revert compares the Debug form of these types: derive Debug, never a manual impl:\n{}",
        bad.join("\n")
    );
    // The scanner has teeth.
    assert_eq!(
        manual_debug("impl fmt::Debug for TxnStatus {"),
        ["TxnStatus"]
    );
    assert_eq!(
        manual_debug("impl std::fmt::Debug for Verified {"),
        ["Verified"]
    );
    assert_eq!(manual_debug("impl Debug for Halt {"), ["Halt"]);
    assert_eq!(
        manual_debug("impl<'a>  fmt::Debug  for Preview<'a> {"),
        ["Preview"]
    );
    assert!(manual_debug("#[derive(Debug)]\n// impl Debug for X").is_empty());
}

/// The lines of `src` (comments skipped) that name a window handle type (`HWND` as a word).
fn window_handles(src: &str) -> usize {
    src.lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .map(|l| l.split("//").next().unwrap_or(l))
        .filter(|code| {
            code.match_indices("HWND").any(|(i, _)| {
                let ident = |c: char| c.is_ascii_alphanumeric() || c == '_';
                !code[..i].chars().next_back().is_some_and(ident)
                    && !code[i + 4..].chars().next().is_some_and(ident)
            })
        })
        .count()
}

/// ADR 0023 amendment P5-5c: the owner of the UAC dialog crosses the core as an opaque
/// `PromptOwner` value; only `sys::win` turns it into a window handle. (In `rerun-app` the
/// handle stays in `ui::chrome`, its own source rule.)
#[test]
fn a_window_handle_type_only_in_sys_win() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let win = src.join("sys").join("win");
    let mut files = Vec::new();
    rust_files(&src, &mut files);
    assert!(files.len() > 50, "{}", files.len());
    let bad: Vec<String> = files
        .iter()
        .filter(|f| !f.starts_with(&win))
        .filter(|f| window_handles(&std::fs::read_to_string(f).unwrap_or_default()) > 0)
        .map(|f| f.display().to_string())
        .collect();
    assert!(bad.is_empty(), "{bad:#?}");
    // The rule bites, and skips comments and longer names.
    assert_eq!(window_handles("let h: HWND = x;"), 1);
    assert_eq!(window_handles("// HWND\nlet h = HWNDS;"), 0);
}
