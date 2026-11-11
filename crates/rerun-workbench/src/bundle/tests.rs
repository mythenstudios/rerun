//! `index build` (ADR 0024): reproducible bytes, drafts left out, the bundle valid against the
//! schemas of `schema/`, and readable by the client (`rerun_core::catalog`).

use std::fs;
use std::path::{Path, PathBuf};

use rerun_core::catalog::key::test_key;
use rerun_core::catalog::{Catalog, verify};
use serde_json::Value;

use super::{SourceFile, build};

const ISSUED: &str = "2026-11-09T12:00:00Z";

const PACKAGE: &str = r#"format: 1
id: fix-pack
name: "Fix pack"
status: active
tier: established
source:
  repo: "https://github.com/owner/fix-pack"
  release: "https://github.com/owner/fix-pack/releases/download/v1.0/fix-pack.zip"
version: "1.0"
sha256: "ABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABAB"
license: "MIT"
arch: [x86]
slots: [d3d9.dll]
files:
  - { from: "d3d9.dll", to: "d3d9.dll", sha256: "CDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCD" }
options:
  skip: { ini: { file: "d3d9.ini", section: "Main", key: "Skip" }, default: true }
"#;

const TOPO: &str = r#"format: 1
id: a-game
title: "A game"
status: active
rev: 2
match:
  steam_appid: 440
  exes:
    - { path: "bin/game.exe", sha256: "1111111111111111111111111111111111111111111111111111111111111111", api: d3d9 }
launch:
  chain: [steam]
  method: direct
  start: "bin/game.exe"
  cpu: { max_threads: 8, smt: false }
issues:
  - id: stutter
    title: "Stutter"
    when: { gpu.vendor: amd, cpu.threads: { gt: 16 } }
    variants:
      - id: fix-pack
        status: reported
        kind: fix
        steps: [{ package: fix-pack }, { ini_set: { file: "game.ini", values: [{ section: Display, key: Width, value: "1920" }] } }]
        sources:
          - { type: pcgw, url: "https://www.pcgamingwiki.com/wiki/A_Game" }
"#;

fn f(name: &str, text: &str) -> SourceFile {
    SourceFile {
        name: name.into(),
        text: text.into(),
    }
}

fn draft(text: &str, id: &str) -> String {
    text.replacen("status: active", "status: draft", 1)
        .replacen("id: a-game", &format!("id: {id}"), 1)
        .replacen("id: fix-pack\nname", &format!("id: {id}\nname"), 1)
}

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn repo_sources(dir: &str) -> Vec<SourceFile> {
    let mut v: Vec<SourceFile> = fs::read_dir(repo().join(dir))
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "yaml"))
        .map(|p| {
            f(
                &p.file_name().unwrap().to_string_lossy(),
                &fs::read_to_string(&p).unwrap(),
            )
        })
        .collect();
    v.sort_by(|a, b| a.name.cmp(&b.name));
    v
}

#[test]
fn the_same_input_gives_the_same_bytes() {
    let a = build(
        &[f("a-game.yaml", TOPO)],
        &[f("fix-pack.yaml", PACKAGE)],
        7,
        ISSUED,
    )
    .unwrap();
    let b = build(
        &[f("a-game.yaml", TOPO)],
        &[f("fix-pack.yaml", PACKAGE)],
        7,
        ISSUED,
    )
    .unwrap();
    assert_eq!(a.bytes, b.bytes);
    // Order of the files and YAML spelling do not matter, only content.
    let respelled = TOPO.replace("rev: 2", "rev:   2   # comment");
    let extra = draft(TOPO, "b-game");
    let c = build(
        &[f("b-game.yaml", &extra), f("a-game.yaml", &respelled)],
        &[f("fix-pack.yaml", PACKAGE)],
        7,
        ISSUED,
    )
    .unwrap();
    assert_eq!(a.bytes, c.bytes);
    assert!(a.bytes.ends_with(b"}\n"));
    // seq and issued are part of the bytes.
    let d = build(
        &[f("a-game.yaml", TOPO)],
        &[f("fix-pack.yaml", PACKAGE)],
        8,
        ISSUED,
    )
    .unwrap();
    assert_ne!(a.bytes, d.bytes);
}

#[test]
fn the_repository_builds_reproducibly_and_releases_no_draft() {
    let (t, p) = (repo_sources("topos"), repo_sources("packages"));
    let a = build(&t, &p, 1, ISSUED).unwrap();
    let b = build(&t, &p, 1, ISSUED).unwrap();
    assert_eq!(a.bytes, b.bytes);
    for x in &a.index.topos {
        assert_ne!(
            x.status,
            rerun_core::catalog::model::Status::Draft,
            "{}",
            x.id
        );
    }
    for x in &a.index.packages {
        assert_ne!(
            x.status,
            rerun_core::catalog::model::Status::Draft,
            "{}",
            x.id
        );
    }
    // Every file is either released (never a draft, above) or left out as a draft.
    assert_eq!(
        a.index.topos.len() + a.index.packages.len() + a.excluded.len(),
        t.len() + p.len(),
        "{:?}",
        a.excluded
    );
}

#[test]
fn drafts_are_left_out_and_nothing_released_needs_one() {
    let b = build(
        &[
            f("a-game.yaml", TOPO),
            f("b-game.yaml", &draft(TOPO, "b-game")),
        ],
        &[f("fix-pack.yaml", PACKAGE)],
        1,
        ISSUED,
    )
    .unwrap();
    assert_eq!(b.index.topos.len(), 1);
    assert_eq!(b.excluded, vec!["topo b-game".to_owned()]);
    assert!(!String::from_utf8(b.bytes).unwrap().contains("b-game"));

    // A released Topo that needs a draft package fails the build.
    let e = build(
        &[f("a-game.yaml", TOPO)],
        &[f("fix-pack.yaml", &draft(PACKAGE, "fix-pack"))],
        1,
        ISSUED,
    )
    .unwrap_err();
    assert!(e.contains("fix-pack"), "{e}");

    // TODO in a released entry is a source error (TODO needs draft).
    let todo = PACKAGE.replacen("version: \"1.0\"", "version: \"TODO\"", 1);
    let e = build(&[], &[f("fix-pack.yaml", &todo)], 1, ISSUED).unwrap_err();
    assert!(e.contains("TODO"), "{e}");

    // File name = ID.
    let e = build(
        &[f("other.yaml", TOPO)],
        &[f("fix-pack.yaml", PACKAGE)],
        1,
        ISSUED,
    )
    .unwrap_err();
    assert!(e.contains("file name"), "{e}");

    // Anchors are refused like at runtime.
    let anchors = TOPO.replacen("chain: [steam]", "chain: &c [steam]", 1);
    assert!(
        build(
            &[f("a-game.yaml", &anchors)],
            &[f("fix-pack.yaml", PACKAGE)],
            1,
            ISSUED
        )
        .is_err()
    );
}

#[test]
fn issued_and_seq_are_checked() {
    assert!(build(&[], &[], 0, ISSUED).is_err());
    assert!(build(&[], &[], 1, "2026-11-09").is_err());
    assert!(
        build(&[], &[], 1, ISSUED).is_ok(),
        "an empty index is valid"
    );
}

fn schema(name: &str) -> jsonschema::Validator {
    let v: Value =
        serde_json::from_str(&fs::read_to_string(repo().join("schema").join(name)).unwrap())
            .unwrap();
    jsonschema::validator_for(&v).unwrap()
}

fn errors(v: &jsonschema::Validator, doc: &Value) -> Vec<String> {
    v.iter_errors(doc)
        .map(|e| format!("{e} at {}", e.instance_path()))
        .collect()
}

/// The bundle's Topos and packages are in the language of the schemas (ADR 0005): every entry
/// validates against `topo.schema.json` or `package.schema.json`, the whole against
/// `index.schema.json`.
#[test]
fn the_bundle_validates_against_the_schemas() {
    let b = build(
        &[f("a-game.yaml", TOPO)],
        &[f("fix-pack.yaml", PACKAGE)],
        3,
        ISSUED,
    )
    .unwrap();
    let doc: Value = serde_json::from_slice(&b.bytes).unwrap();
    let errs = errors(&schema("index.schema.json"), &doc);
    assert!(errs.is_empty(), "{errs:?}");
    let (topo, package) = (schema("topo.schema.json"), schema("package.schema.json"));
    for t in doc["topos"].as_array().unwrap() {
        let errs = errors(&topo, t);
        assert!(errs.is_empty(), "{errs:?}");
    }
    for p in doc["packages"].as_array().unwrap() {
        let errs = errors(&package, p);
        assert!(errs.is_empty(), "{errs:?}");
    }
    // And the schema refuses what the client refuses at the top level.
    let mut bad = doc.clone();
    bad["seq"] = Value::from(0);
    assert!(!errors(&schema("index.schema.json"), &bad).is_empty());
}

/// Built, signed with the test key, read by the client: the same entries.
#[test]
fn the_client_reads_what_the_workbench_builds() {
    let b = build(
        &[f("a-game.yaml", TOPO)],
        &[f("fix-pack.yaml", PACKAGE)],
        3,
        ISSUED,
    )
    .unwrap();
    let sig = test_key::sign(&b.bytes);
    let v = verify(&b.bytes, &sig, &[test_key::public()]).unwrap();
    let c = Catalog::from_verified(&v).unwrap();
    assert_eq!(c.index(), &b.index);
    assert_eq!(c.topo("a-game").unwrap().rev, 2);
}
