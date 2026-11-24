//! The third-party notices (P5-10e, plan decision E5 a; `docs/05-sources-policy.md`): the
//! generator of `assets/THIRD-PARTY-NOTICES.txt` and the check that the committed file is the
//! one it generates (NT1, NT2 in `docs/09-testing.md`). `rerun-app` embeds the file and shows it
//! under Settings > About Rerun > Third-party licences.
//!
//! What is listed: every crate linked into a shipped binary, that is the normal dependencies
//! (no build or dev dependency, no proc macro: none of them ends up in a binary) of
//! `rerun-app`, `rerun-cli`, `rerun-launch`, `rerun-helper` and `rerun-cpu`, each resolved alone
//! as its release build is (`cargo tree -p`, feature resolution of that package only) for the
//! Windows targets x86_64 and i686 together. `cargo metadata` then gives each crate's licence
//! expression and its package folder, whose licence files (`LICENSE*`, `LICENCE*`, `COPYING*`,
//! `COPYRIGHT*`, `NOTICE*`, `UNLICENSE*` and the files of a `LICENSES` folder) are copied with
//! the line ends and controls normalised. A crate that ships none gets the SPDX standard text of
//! every licence its expression names, from `assets/licences/<id>.txt` (SPDX License List 3.28.0;
//! a missing text fails here, so a new licence is added on purpose). Rerun itself (`LICENSE`) and
//! the bundled fonts (`assets/fonts/*/OFL.txt`, families and versions from `FONTS.md`) come
//! first. Each text is one entry under every crate that ships it (texts that differ only in
//! white space count as one).
//!
//! Both cargo commands run through the cargo that runs the tests (`$CARGO`) with `--locked`, and
//! `--offline` outside GitHub Actions. A nested cargo does not inherit a `--config` of the outer
//! one: where it cannot run, the check is skipped with a message, except on GitHub Actions,
//! where it is binding. `RERUN_BLESS=1` writes the file anew.

#![allow(
    clippy::disallowed_methods,
    reason = "test reads the crate's own assets, the package folders cargo names and the environment"
)]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code: a failure should abort the test"
)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

/// The packages of the shipped binaries.
const ROOTS: &[&str] = &[
    "rerun-app",
    "rerun-cli",
    "rerun-launch",
    "rerun-helper",
    "rerun-cpu",
];

/// The targets they are built for (`rerun-cpu` for both, the rest for x86_64).
const TARGETS: &[&str] = &["x86_64-pc-windows-msvc", "i686-pc-windows-msvc"];

/// The line before an entry and the line between its heading and its texts (the app splits the
/// file at them, `rerun-app::notices`).
const ENTRY: &str =
    "================================================================================";
const BODY: &str =
    "--------------------------------------------------------------------------------";

/// The note of an entry for crates that ship no licence file.
const SPDX_NOTE: &str =
    "(These packages ship no licence file: this is the SPDX standard text of a licence they name.)";

const PREAMBLE: &str = "\
THIRD-PARTY NOTICES

Rerun by Mythen Studios is free software under the GNU General Public License, version 3 or
(at your option) any later version; rerun-app.exe links Slint under GPL-3.0-only and is
therefore distributed under version 3 only. It comes with no warranty, to the extent permitted
by applicable law. Its source code is at https://github.com/mythenstudios/rerun.

Below: Rerun's licence, the licences of the bundled fonts and of every crate linked into
rerun-app.exe, rerun.exe, rerun-launch.exe, rerun-helper.exe and rerun-cpu.asi. Each entry is
one licence text as the packages ship it, under the crates that ship it (name, version and
licence expression). A crate that ships no licence file is listed under the SPDX standard text
of each licence it names.

Generated from Cargo.lock by crates/rerun-app/tests/notices.rs; do not edit by hand.";

fn app_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn workspace_dir() -> PathBuf {
    app_dir().join("../..")
}

fn notices_path() -> PathBuf {
    app_dir().join("assets/THIRD-PARTY-NOTICES.txt")
}

/// The file as compared: LF line ends.
fn lf(s: &str) -> String {
    s.replace("\r\n", "\n")
}

fn on_github_actions() -> bool {
    std::env::var("GITHUB_ACTIONS").is_ok_and(|v| v == "true")
}

/// Runs the cargo that runs the tests in the workspace; `Err` with its message if it cannot.
fn cargo(args: &[&str]) -> Result<String, String> {
    let exe = std::env::var_os("CARGO").unwrap_or_else(|| env!("CARGO").into());
    let mut cmd = Command::new(exe);
    cmd.args(args).arg("--locked").current_dir(workspace_dir());
    if !on_github_actions() {
        cmd.arg("--offline");
    }
    let out = cmd
        .output()
        .map_err(|e| format!("cargo did not start: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "cargo {} failed: {}",
            args.first().unwrap_or(&""),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    String::from_utf8(out.stdout).map_err(|e| format!("cargo wrote no UTF-8: {e}"))
}

/// `(name, version)` of every crate a shipped binary links, workspace members included.
fn linked() -> Result<BTreeSet<(String, String)>, String> {
    let mut set = BTreeSet::new();
    for root in ROOTS {
        let mut args = vec![
            "tree",
            "-p",
            root,
            "-e",
            "normal,no-proc-macro",
            "--prefix",
            "none",
            "--format",
            "{p}",
        ];
        for t in TARGETS {
            args.extend(["--target", t]);
        }
        for line in cargo(&args)?.lines() {
            let mut it = line.split_whitespace();
            let (Some(name), Some(version)) = (it.next(), it.next()) else {
                continue;
            };
            let Some(version) = version.strip_prefix('v') else {
                return Err(format!("cargo tree line not understood: {line}"));
            };
            set.insert((name.to_owned(), version.to_owned()));
        }
    }
    Ok(set)
}

/// One crate as listed.
struct Crate {
    name: String,
    version: String,
    licence: String,
    texts: Vec<String>,
    spdx: bool,
    authors: Vec<String>,
}

impl Crate {
    /// The crate's line in an entry's heading: name, version, licence expression, and for a
    /// crate without a licence file the authors its manifest names (the SPDX text has no
    /// copyright line).
    fn line(&self) -> String {
        let mut l = format!("{} {} ({})", self.name, self.version, self.licence);
        if self.spdx && !self.authors.is_empty() {
            l.push_str("; authors: ");
            l.push_str(&self.authors.join(", "));
        }
        l
    }
}

/// An author of a manifest without the e-mail address (`Name <mail>` → `Name`).
fn author_name(a: &str) -> String {
    a.split('<').next().unwrap_or(a).trim().to_owned()
}

/// Licence text as written: LF line ends, no trailing spaces, no control but the tab, no blank
/// lines at either end.
fn normalise(raw: &str, what: &str) -> String {
    assert!(
        !raw.contains('\u{FFFD}'),
        "{what}: not UTF-8 (or holds U+FFFD)"
    );
    let t = raw
        .trim_start_matches('\u{FEFF}')
        .replace("\r\n", "\n")
        .replace('\r', "\n");
    let lines: Vec<String> = t
        .lines()
        .map(|l| {
            l.chars()
                .filter(|c| *c == '\t' || !c.is_control())
                .collect::<String>()
                .trim_end()
                .to_owned()
        })
        .collect();
    lines.join("\n").trim_matches('\n').to_owned()
}

fn read_text(p: &Path) -> String {
    let bytes = std::fs::read(p).unwrap_or_else(|e| panic!("{}: {e}", p.display()));
    normalise(&String::from_utf8_lossy(&bytes), &p.display().to_string())
}

/// Whether a file name is a licence file.
fn licence_name(name: &str) -> bool {
    let u = name.to_ascii_uppercase();
    [
        "LICENSE",
        "LICENCE",
        "COPYING",
        "COPYRIGHT",
        "NOTICE",
        "UNLICENSE",
    ]
    .iter()
    .any(|p| u.starts_with(p))
}

/// The licence files of a package folder, sorted by name.
fn licence_files(dir: &Path, licence_file: Option<&str>) -> Vec<PathBuf> {
    let mut out = BTreeMap::new();
    let mut add = |p: PathBuf| {
        let key = p
            .strip_prefix(dir)
            .unwrap_or(&p)
            .to_string_lossy()
            .replace('\\', "/")
            .to_ascii_lowercase();
        out.insert(key, p);
    };
    for e in std::fs::read_dir(dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display())) {
        let p = e.unwrap().path();
        let name = p.file_name().unwrap().to_string_lossy().into_owned();
        if p.is_dir() {
            if name.eq_ignore_ascii_case("LICENSES") {
                for f in std::fs::read_dir(&p).unwrap() {
                    let f = f.unwrap().path();
                    if f.is_file() {
                        add(f);
                    }
                }
            }
        } else if licence_name(&name) {
            add(p);
        }
    }
    if let Some(f) = licence_file {
        let p = dir.join(f);
        assert!(p.is_file(), "license-file {} missing", p.display());
        add(p);
    }
    out.into_values().collect()
}

/// The SPDX identifiers an expression names (`MIT/Apache-2.0`, the legacy form, too).
fn spdx_ids(expr: &str) -> Vec<String> {
    let mut ids = Vec::new();
    for tok in expr.split(|c: char| c.is_whitespace() || "()/".contains(c)) {
        if tok.is_empty() || ["AND", "OR", "WITH"].contains(&tok) {
            continue;
        }
        let id = tok.trim_end_matches('+').to_owned();
        if !ids.contains(&id) {
            ids.push(id);
        }
    }
    ids
}

/// The SPDX standard text of `id`, or a failure that says to add it.
fn spdx_text(id: &str, who: &str) -> String {
    let p = app_dir().join("assets/licences").join(format!("{id}.txt"));
    assert!(
        p.is_file(),
        "{who} ships no licence file and names {id}: add its SPDX standard text as {} \
         (from the SPDX License List, never written by hand)",
        p.display()
    );
    read_text(&p)
}

/// The third-party crates, from cargo.
fn crates() -> Result<Vec<Crate>, String> {
    let linked = linked()?;
    let mut args = vec!["metadata", "--format-version", "1"];
    for t in TARGETS {
        args.extend(["--filter-platform", t]);
    }
    let meta: Value =
        serde_json::from_str(&cargo(&args)?).map_err(|e| format!("cargo metadata: {e}"))?;
    let members: BTreeSet<&str> = meta["workspace_members"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    let mut out = Vec::new();
    let mut found = BTreeSet::new();
    for p in meta["packages"].as_array().unwrap() {
        let name = p["name"].as_str().unwrap();
        let version = p["version"].as_str().unwrap();
        let key = (name.to_owned(), version.to_owned());
        if !linked.contains(&key) {
            continue;
        }
        found.insert(key);
        if members.contains(p["id"].as_str().unwrap()) {
            continue;
        }
        let who = format!("{name} {version}");
        let manifest = PathBuf::from(p["manifest_path"].as_str().unwrap());
        let dir = manifest.parent().unwrap();
        let licence = p["license"].as_str().map(str::to_owned);
        let files = licence_files(dir, p["license_file"].as_str());
        let (texts, spdx) = if files.is_empty() {
            let expr = licence
                .as_deref()
                .unwrap_or_else(|| panic!("{who}: neither a licence nor a licence file"));
            (
                spdx_ids(expr)
                    .iter()
                    .map(|id| spdx_text(id, &who))
                    .collect(),
                true,
            )
        } else {
            (files.iter().map(|f| read_text(f)).collect(), false)
        };
        out.push(Crate {
            name: name.to_owned(),
            version: version.to_owned(),
            licence: licence.unwrap_or_else(|| "see the licence file".to_owned()),
            texts,
            spdx,
            authors: p["authors"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(author_name))
                        .collect()
                })
                .unwrap_or_default(),
        });
    }
    let missing: Vec<_> = linked.difference(&found).collect();
    assert!(
        missing.is_empty(),
        "cargo tree names crates cargo metadata does not: {missing:?}"
    );
    out.sort_by(|a, b| (&a.name, &a.version).cmp(&(&b.name, &b.version)));
    Ok(out)
}

/// `(family, version)` of the bundled fonts per folder, from `FONTS.md`.
fn fonts() -> BTreeMap<String, (String, String)> {
    let md = std::fs::read_to_string(app_dir().join("assets/fonts/FONTS.md")).unwrap();
    let mut out = BTreeMap::new();
    for line in md.lines().filter(|l| l.starts_with("| `")) {
        let cells: Vec<&str> = line.split('|').map(str::trim).collect();
        let path = cells[1].trim_matches('`');
        let folder = path.split('/').next().unwrap().to_owned();
        out.insert(folder, (cells[2].to_owned(), cells[4].to_owned()));
    }
    assert!(!out.is_empty(), "FONTS.md lists no font");
    out
}

/// The whole file.
fn generate(crates: &[Crate]) -> String {
    let mut entries: Vec<(Vec<String>, String)> = Vec::new();
    entries.push((
        vec!["Rerun (GPL-3.0-or-later; rerun-app.exe: GPL-3.0-only)".to_owned()],
        read_text(&workspace_dir().join("LICENSE")),
    ));
    for (folder, (family, version)) in fonts() {
        entries.push((
            vec![format!("Font {family} {version} (OFL-1.1)")],
            read_text(&app_dir().join("assets/fonts").join(folder).join("OFL.txt")),
        ));
    }
    // One entry per text, listing every crate that ships it (texts that differ only in white
    // space count as one; the first crate's wins), in the order of their first crate.
    let mut groups: Vec<(bool, String, String, Vec<String>)> = Vec::new();
    for c in crates {
        let line = c.line();
        for text in &c.texts {
            let key: String = text.split_whitespace().collect::<Vec<_>>().join(" ");
            match groups
                .iter_mut()
                .find(|(spdx, k, _, _)| *spdx == c.spdx && *k == key)
            {
                Some(g) => {
                    if !g.3.contains(&line) {
                        g.3.push(line.clone());
                    }
                }
                None => groups.push((c.spdx, key, text.clone(), vec![line.clone()])),
            }
        }
    }
    for (spdx, _, text, mut heading) in groups {
        if spdx {
            heading.push(SPDX_NOTE.to_owned());
        }
        entries.push((heading, text));
    }
    let mut out = PREAMBLE.to_owned();
    for (heading, body) in entries {
        assert!(
            !body.lines().any(|l| l == ENTRY || l == BODY),
            "a licence text holds a separator line: {}",
            heading[0]
        );
        out.push('\n');
        out.push_str(ENTRY);
        out.push('\n');
        out.push_str(&heading.join("\n"));
        out.push('\n');
        out.push_str(BODY);
        out.push('\n');
        out.push_str(&body);
    }
    out.push('\n');
    out
}

/// The entries of a notices text: `(heading lines, body)`.
fn entries(text: &str) -> Vec<(Vec<String>, String)> {
    text.split(&format!("\n{ENTRY}\n"))
        .skip(1)
        .map(|e| {
            let (h, b) = e
                .split_once(&format!("\n{BODY}\n"))
                .expect("an entry without its heading line");
            (h.lines().map(str::to_owned).collect(), b.to_owned())
        })
        .collect()
}

/// Characters that could reorder or hide text in the window: never in the file.
fn deceptive(c: char) -> bool {
    matches!(c, '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2060}'..='\u{2069}' | '\u{FEFF}')
}

/// NT1 + NT2: the committed file is the generated one, and it lists every linked crate with
/// name, version, licence expression and a text.
#[test]
fn third_party_notices_are_fresh_and_complete() {
    let crates = match crates() {
        Ok(c) => c,
        Err(e) => {
            assert!(
                !on_github_actions(),
                "the notices check is binding on GitHub Actions: {e}"
            );
            eprintln!("third-party notices not checked (cargo could not list the crates): {e}");
            return;
        }
    };
    assert!(crates.len() > 50, "only {} crates listed", crates.len());
    let text = generate(&crates);
    let es = entries(&text);
    for c in &crates {
        let line = c.line();
        let e = es.iter().find(|(h, _)| h.contains(&line));
        assert!(
            e.is_some_and(|(_, b)| !b.trim().is_empty()),
            "{line}: no entry with a text"
        );
    }
    if std::env::var("RERUN_BLESS").is_ok_and(|v| v == "1") {
        std::fs::write(notices_path(), &text).unwrap();
        eprintln!(
            "wrote {} ({} bytes, {} crates, {} entries)",
            notices_path().display(),
            text.len(),
            crates.len(),
            es.len()
        );
        return;
    }
    let committed = std::fs::read_to_string(notices_path()).unwrap_or_default();
    assert!(
        lf(&committed) == text,
        "assets/THIRD-PARTY-NOTICES.txt is stale (Cargo.lock, a licence file or FONTS.md \
         changed): run `RERUN_BLESS=1 cargo test -p rerun-app --test notices` and commit it"
    );
}

/// NT2 on the committed file, without cargo: Rerun's GPL and every font's OFL are in it, each
/// entry has a heading and a text, and nothing in it could reorder the text in the window.
#[test]
fn committed_notices_hold_rerun_and_the_fonts() {
    let text = lf(&std::fs::read_to_string(notices_path()).unwrap());
    assert!(text.starts_with(PREAMBLE), "the preamble changed");
    let es = entries(&text);
    let (h, b) = &es[0];
    assert!(h[0].starts_with("Rerun (GPL-3.0-or-later"));
    assert!(b.contains("GNU GENERAL PUBLIC LICENSE") && b.contains("Version 3, 29 June 2007"));
    for (family, version) in fonts().values() {
        let head = format!("Font {family} {version} (OFL-1.1)");
        let e = es.iter().find(|(h, _)| h[0] == head);
        assert!(
            e.is_some_and(|(_, b)| b.contains("SIL OPEN FONT LICENSE Version 1.1")),
            "{head}: missing or not the OFL"
        );
    }
    assert!(es.len() > 10, "only {} entries", es.len());
    for (h, b) in &es {
        assert!(!h.is_empty() && !h[0].is_empty() && !b.trim().is_empty());
    }
    assert!(
        !text.chars().any(deceptive),
        "a bidi or invisible character"
    );
    assert!(
        !text
            .chars()
            .any(|c| c != '\n' && c != '\t' && c.is_control()),
        "a control character"
    );
}

/// The SPDX expression reader of the fallback.
#[test]
fn spdx_ids_reads_expressions() {
    assert_eq!(spdx_ids("MIT OR Apache-2.0"), ["MIT", "Apache-2.0"]);
    assert_eq!(spdx_ids("MIT/Apache-2.0"), ["MIT", "Apache-2.0"]);
    assert_eq!(
        spdx_ids("(MIT OR Apache-2.0) AND Unicode-3.0"),
        ["MIT", "Apache-2.0", "Unicode-3.0"]
    );
    assert_eq!(spdx_ids("BSL-1.0"), ["BSL-1.0"]);
}
