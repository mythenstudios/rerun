//! Parity of the typed loader (`rerun_core::catalog`) with the schemas (ADR 0005): the same
//! valid and invalid fixtures of `tests/fixtures/schema`, and every file of `topos/` and
//! `packages/`, go through serde (`deny_unknown_fields`, `RelPath`, hashes) and the form rules
//! of `catalog::check` with `Rules::Source`. A valid fixture must load, an invalid one must be
//! refused (by serde or by a rule). The schema side of the same fixtures is `tests/schema.rs`.

#![expect(
    clippy::disallowed_methods,
    reason = "reads repository fixtures (topos, packages, schema fixtures), never game folders"
)]
#![allow(
    clippy::unwrap_used,
    reason = "test code: a failure should abort the test"
)]

use std::fs;
use std::path::{Path, PathBuf};

use rerun_core::catalog::check::{self, Rules};
use rerun_core::catalog::{Package, Topo};
use serde_json::Value;

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// The loader's YAML rules (ADR 0005, phase 4): strict booleans, no merge keys, no duplicate
/// keys, no anchors or aliases.
fn load_yaml(p: &Path) -> Result<Value, String> {
    yaml_text(&fs::read_to_string(p).unwrap())
}

fn yaml_text(text: &str) -> Result<Value, String> {
    let options = serde_saphyr::options! {
        strict_booleans: true,
        merge_keys: serde_saphyr::MergeKeyPolicy::Error,
        duplicate_keys: serde_saphyr::DuplicateKeyPolicy::Error,
        budget: serde_saphyr::budget! { max_anchors: 0, max_aliases: 0 },
    };
    serde_saphyr::from_str_with_options(text, options).map_err(|e| e.to_string())
}

fn files(rel: &str, prefix: &str) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = fs::read_dir(repo().join(rel))
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| {
            p.extension().is_some_and(|x| x == "yaml")
                && p.file_name().unwrap().to_string_lossy().starts_with(prefix)
        })
        .collect();
    v.sort();
    assert!(!v.is_empty(), "no {prefix}*.yaml in {rel}");
    v
}

fn load_topo(p: &Path) -> Result<Topo, String> {
    let t: Topo = serde_json::from_value(load_yaml(p)?).map_err(|e| e.to_string())?;
    check::topo(&t, Rules::Source).map_err(|e| e.to_string())?;
    Ok(t)
}

fn load_package(p: &Path) -> Result<Package, String> {
    let t: Package = serde_json::from_value(load_yaml(p)?).map_err(|e| e.to_string())?;
    check::package(&t, Rules::Source).map_err(|e| e.to_string())?;
    Ok(t)
}

#[test]
fn valid_fixtures_and_the_repository_load() {
    let mut failed = Vec::new();
    let topos = files("tests/fixtures/schema/valid", "topo-")
        .into_iter()
        .chain(files("topos", ""));
    for f in topos {
        if let Err(e) = load_topo(&f) {
            failed.push(format!("{}: {e}", f.display()));
        }
    }
    let packages = files("tests/fixtures/schema/valid", "package-")
        .into_iter()
        .chain(files("packages", ""));
    for f in packages {
        if let Err(e) = load_package(&f) {
            failed.push(format!("{}: {e}", f.display()));
        }
    }
    assert!(failed.is_empty(), "refused:\n{}", failed.join("\n"));
}

#[test]
fn invalid_fixtures_are_refused() {
    let mut accepted = Vec::new();
    for f in files("tests/fixtures/schema/invalid", "topo-") {
        if load_topo(&f).is_ok() {
            accepted.push(f.display().to_string());
        }
    }
    for f in files("tests/fixtures/schema/invalid", "package-") {
        if load_package(&f).is_ok() {
            accepted.push(f.display().to_string());
        }
    }
    assert!(
        accepted.is_empty(),
        "accepted by the typed loader:\n{}",
        accepted.join("\n")
    );
}

/// Serialising a loaded entry and loading it again gives the same entry (the bundle form is
/// lossless), and serialising twice gives the same bytes.
#[test]
fn typed_entries_round_trip_through_their_json() {
    for f in files("tests/fixtures/schema/valid", "topo-") {
        let t = load_topo(&f).unwrap();
        let a = serde_json::to_vec(&t).unwrap();
        let back: Topo = serde_json::from_slice(&a).unwrap();
        assert_eq!(back, t, "{}", f.display());
        assert_eq!(serde_json::to_vec(&back).unwrap(), a, "{}", f.display());
    }
    for f in files("tests/fixtures/schema/valid", "package-") {
        let p = load_package(&f).unwrap();
        let a = serde_json::to_vec(&p).unwrap();
        let back: Package = serde_json::from_slice(&a).unwrap();
        assert_eq!(back, p, "{}", f.display());
        assert_eq!(serde_json::to_vec(&back).unwrap(), a, "{}", f.display());
    }
}

/// "TODO anywhere ⇒ draft" (docs/02) is a loader rule too, and a release entry has neither.
#[test]
fn todo_needs_draft_and_release_refuses_both() {
    let f = repo().join("tests/fixtures/schema/valid/package-assets.yaml");
    let mut p = load_package(&f).unwrap();
    assert!(
        check::package(&p, Rules::Release).is_err(),
        "draft released"
    );
    p.status = rerun_core::catalog::model::Status::Active;
    let e = check::package(&p, Rules::Source).unwrap_err();
    assert!(e.to_string().contains("TODO"), "{e}");
    let f = repo().join("tests/fixtures/schema/valid/topo-minimal.yaml");
    let mut t = load_topo(&f).unwrap();
    t.status = rerun_core::catalog::model::Status::Active;
    if check::topo(&t, Rules::Source).is_ok() {
        check::topo(&t, Rules::Release).unwrap();
    }
}

/// Review follow-up 4: a release download is exactly `<repo>/releases/download/<tag>/<file>`,
/// and a page on the forge's host never admits another repository's release.
#[test]
fn release_downloads_have_one_form_and_belong_to_their_repository() {
    use rerun_core::catalog::check::release_download;
    for good in [
        "https://github.com/owner/repo/releases/download/v1.0/tool.zip",
        "https://github.com/owner/repo/releases/download/v2.4+1/dxvk-2.4.tar.gz",
        "https://example.org/files/tool.zip",
    ] {
        assert!(release_download(good), "{good}");
    }
    for bad in [
        "https://github.com/owner/repo/releases/download/../../../other/repo/releases/download/x",
        "https://github.com/owner/repo/releases/download/%2e%2e/tool.zip",
        "https://github.com/owner/repo/releases/download/v1/tool.zip?x=1",
        "https://github.com/owner/repo/releases/download/v1/tool.zip#x",
        "https://github.com/owner/repo/releases/download/v1/sub/tool.zip",
        "https://github.com/owner/repo/releases/download/v1/..",
        "https://github.com/owner/repo/releases/download/./tool.zip",
        "https://github.com/owner/repo/releases/download/v1",
        "https://example.org/releases/download/v1/tool.zip",
    ] {
        assert!(!release_download(bad), "{bad}");
    }

    let other_repo = r#"format: 1
id: schema-fixture
name: "Fixture"
status: draft
tier: established
source:
  repo: "https://github.com/owner/repo"
  page: "https://github.com/owner/repo/wiki"
  release: "https://github.com/evil/repo/releases/download/v1/tool.zip"
version: "1.0"
sha256: "0000000000000000000000000000000000000000000000000000000000000000"
license: "MIT"
arch: [x86, x64]
"#;
    let p: Package = serde_json::from_value(yaml_text(other_repo).unwrap()).unwrap();
    let e = check::package(&p, Rules::Source).unwrap_err().to_string();
    assert!(e.contains("not from the original source"), "{e}");
}

/// The parity category of the signed index (ADR 0024 amendment "Forward compatibility"): the
/// fixtures of `tests/fixtures/index/newer` hold entries of a newer entry format; the typed
/// loader sets them aside (and what needs them) as "needs newer" and keeps the index. The schema
/// side (`tests/schema.rs`) accepts their heads.
#[test]
fn index_fixtures_with_newer_entries_are_set_aside() {
    let dir = repo().join("tests/fixtures/index/newer");
    let mut files: Vec<PathBuf> = fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .collect();
    files.sort();
    assert!(!files.is_empty());
    for f in files {
        let aside = rerun_core::catalog::check_bundle(&fs::read(&f).unwrap())
            .unwrap_or_else(|e| panic!("{}: {e}", f.display()));
        assert!(!aside.is_empty(), "{}", f.display());
        assert!(
            aside.iter().all(|a| a.why.needs_newer()),
            "{}: {aside:?}",
            f.display()
        );
    }
}
