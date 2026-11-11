//! The bundled brand fonts (`assets/fonts`, user decision 2026-11-12, `docs/05-sources-policy.md`):
//! every `.ttf` is listed in `FONTS.md` with the SHA-256 of the file as shipped upstream, every
//! font folder holds its `OFL.txt`, and `ui/app.slint` imports every file (none unused, none
//! missing). A changed or swapped font file fails here.

#![allow(
    clippy::disallowed_methods,
    reason = "test reads the crate's own assets"
)]
#![allow(
    clippy::unwrap_used,
    reason = "test code: a failure should abort the test"
)]

use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

fn fonts_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("assets/fonts")
}

/// The `(relative path, sha256)` pairs of the `FONTS.md` table rows.
fn listed() -> Vec<(String, String)> {
    let md = std::fs::read_to_string(fonts_dir().join("FONTS.md")).unwrap();
    let mut out = Vec::new();
    for line in md.lines().filter(|l| l.starts_with("| `")) {
        let cells: Vec<&str> = line.split('|').map(str::trim).collect();
        let strip = |c: &str| c.trim_matches('`').to_owned();
        let path = strip(cells[1]);
        let hash = strip(cells[cells.len() - 2]);
        assert!(
            path.ends_with(".ttf") && hash.len() == 64,
            "malformed row: {line}"
        );
        out.push((path, hash));
    }
    out
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// Every `.ttf` below `assets/fonts`, as a path relative to it with `/`.
fn on_disk() -> Vec<String> {
    let mut out = Vec::new();
    for dir in std::fs::read_dir(fonts_dir()).unwrap() {
        let dir = dir.unwrap().path();
        if !dir.is_dir() {
            continue;
        }
        for f in std::fs::read_dir(&dir).unwrap() {
            let f = f.unwrap().path();
            if f.extension().is_some_and(|e| e.eq_ignore_ascii_case("ttf")) {
                out.push(format!(
                    "{}/{}",
                    dir.file_name().unwrap().to_str().unwrap(),
                    f.file_name().unwrap().to_str().unwrap()
                ));
            }
        }
    }
    out.sort();
    out
}

#[test]
fn every_font_file_matches_its_recorded_sha256() {
    let rows = listed();
    assert!(!rows.is_empty(), "FONTS.md lists no font");
    for (path, want) in &rows {
        let bytes = std::fs::read(fonts_dir().join(path)).unwrap();
        assert_eq!(
            &hex(&Sha256::digest(&bytes)),
            want,
            "{path} differs from FONTS.md"
        );
    }
}

#[test]
fn the_listed_fonts_are_exactly_the_files_on_disk() {
    let mut listed: Vec<String> = listed().into_iter().map(|(p, _)| p).collect();
    listed.sort();
    assert_eq!(listed, on_disk());
}

#[test]
fn every_font_folder_has_its_ofl_text() {
    let mut folders = 0;
    for dir in std::fs::read_dir(fonts_dir()).unwrap() {
        let dir = dir.unwrap().path();
        if !dir.is_dir() {
            continue;
        }
        folders += 1;
        let ofl = std::fs::read_to_string(dir.join("OFL.txt"))
            .unwrap_or_else(|_| panic!("{} has no OFL.txt", dir.display()));
        assert!(
            ofl.contains("SIL OPEN FONT LICENSE Version 1.1"),
            "{} is not the OFL 1.1",
            dir.display()
        );
    }
    assert!(folders >= 3);
}

#[test]
fn the_window_imports_every_bundled_font() {
    let slint = std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("ui/app.slint"))
        .unwrap();
    for path in on_disk() {
        let import = format!("import \"../assets/fonts/{path}\";");
        assert!(slint.contains(&import), "app.slint lacks {import}");
    }
}
