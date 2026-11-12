//! Source rules of `rerun-app` (ADR 0026, ADR 0027 and its amendment P5-1), over the product
//! sources (`src/`, without the test modules: `tests.rs` and the files below a `tests/` folder) and `ui/*.slint`; comments do not count:
//! - only `ui` (`src/ui.rs`, `src/ui/`) names Slint; `worker`, `vm`, `text` and `theme` stay
//!   framework-free;
//! - `unsafe`, `windows_sys` and `raw_window_handle` only in `src/ui/chrome.rs`;
//! - raw text reaches the window only escaped: no `as_raw_str`, no `Debug` format spec, no
//!   `dbg!` (as in `rerun-cli`, ADR 0016);
//! - a `Guarded` comes only from `flow::guard`: `rerun-app` names neither
//!   `flow::forbidden_roots`/`flow::open_app` (the CLI's elevated read commands, E3) nor
//!   `ForbiddenRoots::resolve`/`AppDir::open`;
//! - no colour literal in a `.slint` file (every colour comes from the global `Theme`), no
//!   Slint translation (`@tr`);
//! - no URL or markup path (security review S2 of P5-3): Slint links `open-url`, `Platform`,
//!   `StyledText` and `@markdown`, and none of them is named in a `.slint` file; `StyledText` is
//!   not named in Rust either;
//! - the three window buttons stay the last elements of the title bar, minimise, maximise,
//!   close (`ui::chrome` hit-tests the second from the right).

#![allow(
    clippy::disallowed_methods,
    reason = "test reads the crate's own sources"
)]
#![allow(
    clippy::unwrap_used,
    reason = "test code: a failure should abort the test"
)]

use std::path::{Path, PathBuf};

/// The code of one line: `None` for a comment line, else the line without a trailing `//`
/// comment (a `//` inside a string literal ends the line early, which only hides code from a
/// rule in a string, never adds a false hit).
fn code(line: &str) -> Option<&str> {
    let t = line.trim_start();
    if t.starts_with("//") {
        return None;
    }
    Some(match line.find("//") {
        Some(i) => &line[..i],
        None => line,
    })
}

/// Whether `text` holds `word` as a whole identifier.
fn has_word(text: &str, word: &str) -> bool {
    let ident = |c: char| c.is_ascii_alphanumeric() || c == '_';
    text.match_indices(word).any(|(i, _)| {
        let before = text[..i].chars().next_back();
        let after = text[i + word.len()..].chars().next();
        !before.is_some_and(ident) && !after.is_some_and(ident)
    })
}

/// A `Debug` format spec in `line` (as in `rerun-cli`'s rule).
fn has_debug_format(line: &str) -> bool {
    let spec = |c: char| c.is_ascii_alphanumeric() || "_#<>^+-.$*".contains(c);
    line.match_indices("?}").any(|(end, _)| {
        let head = &line[..end];
        let Some(open) = head.rfind('{') else {
            return false;
        };
        let inner = &head[open + 1..];
        inner.contains(':') && inner.chars().all(|c| c == ':' || spec(c))
    })
}

/// Where a file sits for the rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Place {
    /// `src/ui.rs` or `src/ui/` other than `chrome.rs`.
    Ui,
    /// `src/ui/chrome.rs`.
    Chrome,
    /// Everything else in `src/`.
    Other,
}

/// The rule violations of one Rust source text at `place`.
fn violations(src: &str, place: Place) -> Vec<String> {
    let mut bad = Vec::new();
    for (n, line) in src.lines().enumerate() {
        let Some(c) = code(line) else {
            continue;
        };
        let mut hit = |what: &str| bad.push(format!("{}: {what}: {}", n + 1, line.trim()));
        if place == Place::Other && has_word(c, "slint") {
            hit("Slint outside ui");
        }
        if place != Place::Chrome {
            for w in ["unsafe", "windows_sys", "raw_window_handle"] {
                if has_word(c, w) {
                    hit(&format!("{w} outside ui::chrome"));
                }
            }
        }
        for w in [
            "as_raw_str",
            "forbidden_roots",
            "open_app",
            "dbg",
            "guard_read",
        ] {
            if has_word(c, w) {
                hit(w);
            }
        }
        let squeezed: String = c.chars().filter(|ch| !ch.is_whitespace()).collect();
        for p in ["ForbiddenRoots::resolve", "AppDir::open"] {
            if squeezed.contains(p) {
                hit(p);
            }
        }
        if has_debug_format(c) {
            hit("Debug format");
        }
        if has_word(c, "StyledText") {
            hit("StyledText");
        }
    }
    bad
}

/// The rule violations of one `.slint` text: colour literals and Slint translation.
fn slint_violations(src: &str) -> Vec<String> {
    let mut bad = Vec::new();
    for (n, line) in src.lines().enumerate() {
        let Some(c) = code(line) else {
            continue;
        };
        let colour = c.match_indices('#').any(|(i, _)| {
            let hex = c[i + 1..]
                .chars()
                .take_while(char::is_ascii_hexdigit)
                .count();
            matches!(hex, 3 | 4 | 6 | 8)
        });
        if colour || c.contains("rgb(") || c.contains("rgba(") || c.contains("hsv(") {
            bad.push(format!("{}: colour literal: {}", n + 1, line.trim()));
        }
        if c.contains("@tr(") {
            bad.push(format!("{}: Slint translation: {}", n + 1, line.trim()));
        }
        for p in ["open-url", "Platform.", "StyledText", "@markdown"] {
            if c.contains(p) {
                bad.push(format!("{}: {p}: {}", n + 1, line.trim()));
            }
        }
    }
    bad
}

fn sources(dir: &Path, ext: &str, out: &mut Vec<PathBuf>) {
    for e in std::fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            // A `tests/` folder below `src` holds test modules, like `tests.rs`.
            if p.file_name().is_some_and(|n| n != "tests") {
                sources(&p, ext, out);
            }
        } else if p.extension().is_some_and(|x| x == ext)
            && p.file_name().is_some_and(|n| n != "tests.rs")
        {
            out.push(p);
        }
    }
}

fn place_of(rel: &Path) -> Place {
    let r = rel.to_string_lossy().replace('\\', "/");
    if r == "ui/chrome.rs" {
        Place::Chrome
    } else if r == "ui.rs" || r.starts_with("ui/") {
        Place::Ui
    } else {
        Place::Other
    }
}

#[test]
fn the_product_sources_keep_the_rules() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let src = root.join("src");
    let mut files = Vec::new();
    sources(&src, "rs", &mut files);
    let places: Vec<Place> = files
        .iter()
        .map(|f| place_of(f.strip_prefix(&src).unwrap()))
        .collect();
    // The scan sees every kind of file (otherwise a rule would have nothing to bite on).
    assert!(places.contains(&Place::Chrome), "{files:?}");
    assert!(places.contains(&Place::Ui), "{files:?}");
    assert!(files.iter().any(|f| f.ends_with("worker.rs")), "{files:?}");
    assert!(files.iter().any(|f| f.ends_with("vm.rs")), "{files:?}");
    let mut bad = Vec::new();
    for (f, place) in files.iter().zip(places) {
        for v in violations(&std::fs::read_to_string(f).unwrap(), place) {
            bad.push(format!("{}:{v}", f.display()));
        }
    }
    let mut slint = Vec::new();
    sources(&root.join("ui"), "slint", &mut slint);
    assert!(!slint.is_empty());
    for f in &slint {
        for v in slint_violations(&std::fs::read_to_string(f).unwrap()) {
            bad.push(format!("{}:{v}", f.display()));
        }
    }
    assert!(bad.is_empty(), "{bad:#?}");
}

/// The labels of the window buttons in the order they appear in `src`.
fn caption_order(src: &str) -> Vec<&'static str> {
    let mut out = Vec::new();
    let mut in_button = false;
    for line in src.lines() {
        let t = line.trim();
        if t.starts_with("CaptionButton {") {
            in_button = true;
        } else if in_button {
            for (label, name) in [
                ("label: Str.minimize;", "minimize"),
                (
                    "label: root.maximized ? Str.restore : Str.maximize;",
                    "maximize",
                ),
                ("label: Str.close;", "close"),
            ] {
                if t == label {
                    out.push(name);
                    in_button = false;
                }
            }
        }
    }
    out
}

#[test]
fn the_caption_buttons_keep_their_order() {
    let src = std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("ui/app.slint"))
        .unwrap();
    assert_eq!(caption_order(&src), ["minimize", "maximize", "close"]);
    // Nothing follows the close button in the title bar but its closing braces and the
    // hairline below the bar.
    let after = &src[src.find("label: Str.close;").unwrap()..];
    let next = after.find("Hairline {").unwrap();
    let elements: Vec<&str> = after[..next]
        .lines()
        .map(str::trim)
        .filter(|l| l.ends_with('{') && *l != "activated => {")
        .collect();
    assert!(elements.is_empty(), "{elements:?}");
    // Teeth: a swapped order is found.
    let swapped = "CaptionButton {\nlabel: Str.close;\n}\nCaptionButton {\nlabel: Str.minimize;\n}";
    assert_eq!(caption_order(swapped), ["close", "minimize"]);
}

#[test]
fn the_rules_have_teeth() {
    let other = |s: &str| !violations(s, Place::Other).is_empty();
    for bad in [
        "use slint::ComponentHandle;",
        "    slint::invoke_from_event_loop(f);",
        "    let x = unsafe { f() };",
        "use windows_sys::Win32::Foundation::HWND;",
        "use raw_window_handle::HasWindowHandle;",
        "    let s = app.name.as_raw_str();",
        "use rerun_core::flow::{forbidden_roots, guard};",
        "    let app = flow::open_app(sys)?;",
        "    let fr = ForbiddenRoots::resolve(sys, dir)?;",
        "    let fr = ForbiddenRoots :: resolve(sys, dir)?;",
        "    let a = AppDir::open(sys, Create::Never)?;",
        "    let g = flow::guard_read(env);",
        r#"    format!("{x:?}")"#,
        "    dbg!(x);",
        "    let t = slint::StyledText::default();",
    ] {
        assert!(other(bad), "{bad}");
    }
    assert!(!violations("    StyledText::from(x)", Place::Ui).is_empty());
    // The same in ui: Slint is fine there, the rest is not; chrome may hold unsafe.
    assert!(violations("use slint::Model;", Place::Ui).is_empty());
    assert!(!violations("    unsafe { f() };", Place::Ui).is_empty());
    assert!(violations("    unsafe { f() };", Place::Chrome).is_empty());
    assert!(!violations("let a = AppDir::open(s, c);", Place::Chrome).is_empty());
    // Not hits: comments, other identifiers, prose.
    for ok in [
        "// slint is named only in ui; AppDir::open never",
        "    let slinter = 1; // unsafe_ok",
        "    let shown = name.escaped();",
        "    let unsafe_word = \"x\";",
        "    flow::guard(env)?;",
    ] {
        assert!(!other(ok), "{ok}");
    }
    // .slint: colour literals and @tr.
    for bad in [
        "    background: #0b0b0b;",
        "    color: #fff;",
        "    color: rgb(1, 2, 3);",
        "    text: @tr(\"Library\");",
        "        Platform.open-url(url);",
        "    open-url(\"https://example.com\");",
        "    in property <StyledText> body;",
        "    text: @markdown(\"**x**\");",
    ] {
        assert!(!slint_violations(bad).is_empty(), "{bad}");
    }
    for ok in [
        "    background: Theme.bg;",
        "    // #0b0b0b in a comment",
        "    text: \"\\u{E921}\";",
    ] {
        assert!(slint_violations(ok).is_empty(), "{ok}");
    }
}
