//! Schema v1: metaschema, inventory (`topos/`, `packages/`), valid and invalid fixtures,
//! package references, TODO rule and parity `RelPath` ↔ `$defs/relPath`.
//!
//! See ADR 0005. From phase 4, typed serde structs take over runtime validation;
//! these fixtures then run against both.

#![expect(
    clippy::disallowed_methods,
    reason = "reads repository fixtures (schemas, topos, packages), never game folders"
)]
#![allow(
    clippy::unwrap_used,
    reason = "test code: a failure should abort the test"
)]
#![allow(
    clippy::expect_used,
    reason = "test code: a failure should abort the test"
)]

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use rerun_core::policy::path::RelPath;
use serde_json::Value;

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn load_json(rel: &str) -> Value {
    let p = repo().join(rel);
    serde_json::from_str(&fs::read_to_string(&p).unwrap())
        .unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

/// YAML 1.2 semantics (ADR 0005): only `true`/`false` as booleans (no `off`/`yes`),
/// no merge keys, duplicate keys are an error.
fn load_yaml(p: &Path) -> Value {
    let text = fs::read_to_string(p).unwrap();
    let options = serde_saphyr::options! {
        strict_booleans: true,
        merge_keys: serde_saphyr::MergeKeyPolicy::Error,
        duplicate_keys: serde_saphyr::DuplicateKeyPolicy::Error,
    };
    serde_saphyr::from_str_with_options(&text, options)
        .unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

fn yaml_files(rel: &str) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = fs::read_dir(repo().join(rel))
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "yaml"))
        .collect();
    files.sort();
    assert!(!files.is_empty(), "no yaml files in {rel}");
    files
}

fn validator(schema: &Value) -> jsonschema::Validator {
    jsonschema::validator_for(schema).unwrap()
}

fn errors(v: &jsonschema::Validator, instance: &Value) -> Vec<String> {
    v.iter_errors(instance)
        .map(|e| format!("{} at {}", e, e.instance_path()))
        .collect()
}

fn topo_schema() -> Value {
    load_json("schema/topo.schema.json")
}

fn package_schema() -> Value {
    load_json("schema/package.schema.json")
}

/// Which schema applies to a fixture? By file name prefix.
fn schema_for(p: &Path) -> Value {
    let name = p.file_name().unwrap().to_string_lossy();
    if name.starts_with("topo-") {
        topo_schema()
    } else if name.starts_with("package-") {
        package_schema()
    } else {
        panic!("fixture name must start with topo- or package-: {name}")
    }
}

/// All string values in the document (recursive).
fn strings(v: &Value, out: &mut Vec<String>) {
    match v {
        Value::String(s) => out.push(s.clone()),
        Value::Array(a) => a.iter().for_each(|x| strings(x, out)),
        Value::Object(o) => o.values().for_each(|x| strings(x, out)),
        _ => {}
    }
}

// ---------- Schemas themselves ----------

#[test]
fn schemas_are_valid_against_metaschema() {
    for s in [topo_schema(), package_schema()] {
        jsonschema::meta::validate(&s).unwrap();
        assert_eq!(s["$schema"], "https://json-schema.org/draft/2020-12/schema");
    }
}

#[test]
fn shared_definitions_are_identical() {
    let (t, p) = (topo_schema(), package_schema());
    for def in [
        "id",
        "packageId",
        "status",
        "sha1",
        "sha256",
        "sha1OrTodo",
        "sha256OrTodo",
        "httpsUrl",
        "repoUrl",
        "relPath",
        "dllName",
        "api",
        "arch",
    ] {
        assert_eq!(
            t["$defs"][def], p["$defs"][def],
            "$defs/{def} differs between schemas"
        );
        assert!(!t["$defs"][def].is_null(), "$defs/{def} missing");
    }
}

// ---------- Inventory ----------

#[test]
fn all_topos_are_valid() {
    let v = validator(&topo_schema());
    for f in yaml_files("topos") {
        let doc = load_yaml(&f);
        let errs = errors(&v, &doc);
        assert!(errs.is_empty(), "{}:\n{}", f.display(), errs.join("\n"));
    }
}

#[test]
fn all_packages_are_valid() {
    let v = validator(&package_schema());
    for f in yaml_files("packages") {
        let doc = load_yaml(&f);
        let errs = errors(&v, &doc);
        assert!(errs.is_empty(), "{}:\n{}", f.display(), errs.join("\n"));
    }
}

#[test]
fn file_name_matches_id() {
    for f in yaml_files("topos")
        .into_iter()
        .chain(yaml_files("packages"))
    {
        let doc = load_yaml(&f);
        let stem = f.file_stem().unwrap().to_string_lossy();
        assert_eq!(doc["id"].as_str(), Some(stem.as_ref()), "{}", f.display());
    }
}

#[test]
fn package_references_resolve() {
    let known: BTreeSet<String> = yaml_files("packages")
        .iter()
        .map(|f| f.file_stem().unwrap().to_string_lossy().into_owned())
        .collect();
    let mut missing = Vec::new();
    for f in yaml_files("topos") {
        let doc = load_yaml(&f);
        for issue in doc["issues"].as_array().unwrap() {
            for variant in issue["variants"].as_array().unwrap() {
                for step in variant["steps"].as_array().unwrap() {
                    if let Some(id) = step["package"].as_str()
                        && !known.contains(id)
                    {
                        missing.push(format!("{}: package {id}", f.display()));
                    }
                }
            }
        }
    }
    for f in yaml_files("packages") {
        let doc = load_yaml(&f);
        for id in doc["requires"].as_array().into_iter().flatten() {
            let id = id.as_str().unwrap();
            if !known.contains(id) {
                missing.push(format!("{}: requires {id}", f.display()));
            }
        }
    }
    assert!(
        missing.is_empty(),
        "unknown packages:\n{}",
        missing.join("\n")
    );
}

/// Origin of downloads (docs/05: "no mirrors, original release"). The schema only checks
/// the form of the URL; this checks that `source.release` and `assets[].url` belong to the
/// original: to the releases of `source.repo` or to the host of `source.page`.
/// In phase 4 the runtime loader checks the same again with a URL parser.
#[test]
fn download_urls_belong_to_the_source() {
    let mut wrong = Vec::new();
    for f in yaml_files("packages")
        .into_iter()
        .chain(yaml_files("tests/fixtures/schema/valid"))
        .filter(|f| {
            !f.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("topo-")
        })
    {
        let doc = load_yaml(&f);
        let mut urls: Vec<&str> = doc["source"]["release"].as_str().into_iter().collect();
        for a in doc["assets"].as_array().into_iter().flatten() {
            urls.extend(a["url"].as_str());
        }
        let repo = doc["source"]["repo"].as_str();
        let page_host = doc["source"]["page"]
            .as_str()
            .and_then(|p| p.strip_prefix("https://"))
            .and_then(|p| p.split('/').next());
        for url in urls.into_iter().filter(|u| *u != "TODO") {
            let from_repo = repo.is_some_and(|r| {
                url.starts_with(&format!("{}/releases/download/", r.trim_end_matches('/')))
            });
            let from_page = page_host.is_some_and(|h| url.starts_with(&format!("https://{h}/")));
            if !(from_repo || from_page) {
                wrong.push(format!("{}: {url}", f.display()));
            }
        }
    }
    assert!(
        wrong.is_empty(),
        "downloads not from the original source:\n{}",
        wrong.join("\n")
    );
}

/// "Unknown → TODO and status draft" (docs/02-topo-format.md).
#[test]
fn todo_implies_draft() {
    for f in yaml_files("topos")
        .into_iter()
        .chain(yaml_files("packages"))
    {
        let doc = load_yaml(&f);
        let mut all = Vec::new();
        strings(&doc, &mut all);
        if all.iter().any(|s| s == "TODO") {
            assert_eq!(
                doc["status"],
                "draft",
                "{} contains TODO but is not draft",
                f.display()
            );
        }
    }
}

// ---------- Fixtures ----------

#[test]
fn valid_fixtures_pass() {
    for f in yaml_files("tests/fixtures/schema/valid") {
        let v = validator(&schema_for(&f));
        let errs = errors(&v, &load_yaml(&f));
        assert!(errs.is_empty(), "{}:\n{}", f.display(), errs.join("\n"));
    }
}

#[test]
fn invalid_fixtures_fail() {
    let mut accepted = Vec::new();
    for f in yaml_files("tests/fixtures/schema/invalid") {
        let v = validator(&schema_for(&f));
        let errs = errors(&v, &load_yaml(&f));
        if errs.is_empty() {
            accepted.push(f.display().to_string());
        }
        // To check whether a fixture fails for the right reason:
        // RERUN_SHOW_SCHEMA_ERRORS=1 cargo test --test schema -- --nocapture
        #[expect(
            clippy::disallowed_methods,
            reason = "debug switch for fixture authors, not a path source"
        )]
        let show = std::env::var_os("RERUN_SHOW_SCHEMA_ERRORS").is_some();
        if show {
            println!(
                "{}:\n  {}",
                f.file_name().unwrap().to_string_lossy(),
                errs.join("\n  ")
            );
        }
    }
    assert!(
        accepted.is_empty(),
        "invalid fixtures accepted:\n{}",
        accepted.join("\n")
    );
}

// ---------- Parity RelPath ↔ schema ----------

#[test]
fn rel_path_parity_with_schema() {
    let cases = load_json("tests/fixtures/paths.json");
    let rel_schema = topo_schema()["$defs"]["relPath"].clone();
    let v = validator(&rel_schema);

    let mut valid: Vec<String> = cases["valid"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s.as_str().unwrap().to_owned())
        .collect();
    let mut invalid: Vec<String> = cases["invalid"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s.as_str().unwrap().to_owned())
        .collect();
    // Length limit (in characters, not bytes).
    valid.push("ü".repeat(RelPath::MAX_LEN));
    invalid.push("ü".repeat(RelPath::MAX_LEN + 1));

    let mut mismatches = Vec::new();
    for (expected, list) in [(true, &valid), (false, &invalid)] {
        for s in list {
            let rust = RelPath::parse(s).is_ok();
            let schema = v.is_valid(&Value::String(s.clone()));
            if rust != expected || schema != expected {
                mismatches.push(format!(
                    "{s:?}: expected valid={expected}, RelPath={rust}, schema={schema}"
                ));
            }
        }
    }
    assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
}
