//! Schema v1: metaschema, inventory (`topos/`, `packages/`, `data/gpu-arch.yaml`), valid and
//! invalid fixtures, package references, TODO rule, parity `RelPath` ↔ `$defs/relPath` and
//! `GraphicsApi` ↔ `$defs/api` (ADR 0014), GPU architecture identifiers (ADR 0015).
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

use rerun_core::hw::arch::{
    ArchDecl, ArchEntry, ArchId, DeviceRange, Dx9Path, GpuArchTable, TableErrorKind, VkVersion,
};
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

/// The GPU architecture table and its fixtures (ADR 0015): the strict options of [`load_yaml`]
/// plus a budget without anchors and aliases.
fn try_load_gpu_arch_yaml(text: &str) -> Result<Value, String> {
    let options = serde_saphyr::options! {
        strict_booleans: true,
        merge_keys: serde_saphyr::MergeKeyPolicy::Error,
        duplicate_keys: serde_saphyr::DuplicateKeyPolicy::Error,
        budget: serde_saphyr::budget! { max_anchors: 0, max_aliases: 0 },
    };
    serde_saphyr::from_str_with_options(text, options).map_err(|e| e.to_string())
}

/// Loads a fixture or data file with the loader that belongs to it.
fn load_doc(p: &Path) -> Value {
    if is_gpu_arch(p) {
        try_load_gpu_arch_yaml(&fs::read_to_string(p).unwrap())
            .unwrap_or_else(|e| panic!("{}: {e}", p.display()))
    } else {
        load_yaml(p)
    }
}

fn is_gpu_arch(p: &Path) -> bool {
    p.file_name()
        .unwrap()
        .to_string_lossy()
        .starts_with("gpu-arch")
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

fn gpu_arch_schema() -> Value {
    load_json("schema/gpu-arch.schema.json")
}

fn gpu_arch_data() -> Value {
    load_doc(&repo().join("data/gpu-arch.yaml"))
}

/// Which schema applies to a fixture? By file name prefix.
fn schema_for(p: &Path) -> Value {
    let name = p.file_name().unwrap().to_string_lossy();
    if name.starts_with("topo-") {
        topo_schema()
    } else if name.starts_with("package-") {
        package_schema()
    } else if name.starts_with("gpu-arch-") {
        gpu_arch_schema()
    } else {
        panic!("fixture name must start with topo-, package- or gpu-arch-: {name}")
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
    for s in [
        topo_schema(),
        package_schema(),
        gpu_arch_schema(),
        load_json("schema/index.schema.json"),
    ] {
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
    // ADR 0015: one identifier rule for `when.gpu.arch` and the table.
    let g = gpu_arch_schema();
    assert_eq!(
        t["$defs"]["archId"], g["$defs"]["archId"],
        "$defs/archId differs between the topo and gpu-arch schemas"
    );
    assert!(!t["$defs"]["archId"].is_null(), "$defs/archId missing");
    assert_eq!(
        t["$defs"]["when"]["properties"]["gpu.arch"]["items"]["$ref"],
        "#/$defs/archId"
    );
    for at in [
        "/$defs/archDecl/properties/id",
        "/$defs/entry/properties/arch",
    ] {
        assert_eq!(g.pointer(at).unwrap()["$ref"], "#/$defs/archId", "{at}");
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
fn gpu_arch_table_is_valid() {
    let v = validator(&gpu_arch_schema());
    let doc = gpu_arch_data();
    let errs = errors(&v, &doc);
    assert!(errs.is_empty(), "data/gpu-arch.yaml:\n{}", errs.join("\n"));
}

/// The declared identifiers of `data/gpu-arch.yaml`.
fn declared_archs() -> BTreeSet<String> {
    gpu_arch_data()["archs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["id"].as_str().unwrap().to_owned())
        .collect()
}

/// Every `when.gpu.arch` of the topos and the valid topo fixtures names a declared identifier
/// (from phase 4 the loader refuses an undeclared one, ADR 0015).
#[test]
fn topo_gpu_archs_are_declared() {
    let declared = declared_archs();
    let mut seen = 0;
    let mut undeclared = Vec::new();
    let topo_fixtures = yaml_files("tests/fixtures/schema/valid")
        .into_iter()
        .filter(|f| {
            f.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("topo-")
        });
    for f in yaml_files("topos").into_iter().chain(topo_fixtures) {
        let doc = load_yaml(&f);
        for issue in doc["issues"].as_array().unwrap() {
            for id in issue["when"]["gpu.arch"].as_array().into_iter().flatten() {
                seen += 1;
                let id = id.as_str().unwrap();
                if !declared.contains(id) {
                    undeclared.push(format!("{}: {id}", f.display()));
                }
            }
        }
    }
    assert!(
        seen > 0,
        "no when.gpu.arch found: the check has nothing to bite on"
    );
    assert!(
        undeclared.is_empty(),
        "undeclared gpu.arch:\n{}",
        undeclared.join("\n")
    );
}

/// The shipped table declares the identifiers of `docs/03b-gpu-display.md` with their vendor,
/// and the one shipped entry of step 15.
#[test]
fn gpu_arch_table_declares_the_documented_identifiers() {
    let doc = gpu_arch_data();
    let declared: Vec<(String, u64)> = doc["archs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| {
            (
                a["id"].as_str().unwrap().to_owned(),
                a["vendor"].as_u64().unwrap(),
            )
        })
        .collect();
    let amd = [
        "terascale",
        "gcn1",
        "gcn2",
        "gcn3",
        "gcn4",
        "vega",
        "rdna1",
        "rdna2",
        "rdna3",
        "rdna3_5",
        "rdna4",
        "rdna5",
    ];
    let nvidia = [
        "tesla",
        "fermi",
        "kepler",
        "maxwell",
        "pascal",
        "volta",
        "turing",
        "ampere",
        "ada",
        "blackwell",
        "rubin",
    ];
    let intel = [
        "gen9", "gen11", "xe_lp", "xe_hpg", "xe2", "xe3", "xe3p", "xe4",
    ];
    let expected: Vec<(String, u64)> = [(0x1002, &amd[..]), (0x10DE, &nvidia), (0x8086, &intel)]
        .into_iter()
        .flat_map(|(v, ids)| ids.iter().map(move |id| ((*id).to_owned(), v)))
        .collect();
    assert_eq!(declared, expected);

    let entries = doc["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 1, "step 15 ships one entry");
    let e = &entries[0];
    assert_eq!(e["vendor"], 0x1002);
    assert_eq!(e["arch"], "rdna4");
    assert_eq!(e["integrated"], false);
    assert_eq!(e["vulkan"], "1.4");
    assert_eq!(e["dx9"], "native");
    assert_eq!(e["device_ids"], serde_json::json!([0x7550]));
    assert!(e.get("device_ranges").is_none());
    assert_eq!(e["source"], "developer machine dump, 2026-11-05 (ADR 0008)");
}

/// The identifier rule in a topo: `_` and a leading letter (03b), never `unknown`.
#[test]
fn topo_gpu_arch_identifier_rule() {
    let v = validator(&topo_schema());
    let base = load_yaml(&repo().join("tests/fixtures/schema/valid/topo-full.yaml"));
    let with = |archs: &Value| {
        let mut doc = base.clone();
        doc["issues"][0]["when"]["gpu.arch"] = archs.clone();
        v.is_valid(&doc)
    };
    for good in [
        serde_json::json!(["rdna2"]),
        serde_json::json!(["rdna3_5"]),
        serde_json::json!(["rdna3_5", "xe_lp", "xe_hpg"]),
        serde_json::json!(["a234567890123456789012345678901_"]),
    ] {
        assert!(with(&good), "{good} refused");
    }
    for bad in [
        serde_json::json!(["unknown"]),
        serde_json::json!(["rdna4", "unknown"]),
        serde_json::json!(["Rdna4"]),
        serde_json::json!(["4rdna"]),
        serde_json::json!(["_rdna"]),
        serde_json::json!(["rdna-4"]),
        serde_json::json!(["a2345678901234567890123456789012x"]),
        serde_json::json!([""]),
        serde_json::json!([4]),
        serde_json::json!([]),
        serde_json::json!(["rdna4", "rdna4"]),
    ] {
        assert!(!with(&bad), "{bad} accepted");
    }
}

/// No anchors or aliases in the table (ADR 0015): the budget refuses them. Hex IDs are
/// integers (YAML 1.2 core schema).
#[test]
fn gpu_arch_loader_refuses_anchors_and_aliases() {
    assert!(try_load_gpu_arch_yaml("format: 1\narchs: []\nentries: []\n").is_ok());
    let anchor = "format: 1\narchs: &a []\nentries: []\n";
    let alias = "format: 1\narchs: &a []\nentries: *a\n";
    assert!(try_load_gpu_arch_yaml(anchor).is_err(), "anchor accepted");
    assert!(try_load_gpu_arch_yaml(alias).is_err(), "alias accepted");
    let hex = try_load_gpu_arch_yaml("v: 0x7550\n").unwrap();
    assert_eq!(hex["v"], 0x7550);
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
    let package_fixtures = yaml_files("tests/fixtures/schema/valid")
        .into_iter()
        .filter(|f| {
            f.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("package-")
        });
    for f in yaml_files("packages").into_iter().chain(package_fixtures) {
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
        let errs = errors(&v, &load_doc(&f));
        assert!(errs.is_empty(), "{}:\n{}", f.display(), errs.join("\n"));
    }
}

#[test]
fn invalid_fixtures_fail() {
    let mut accepted = Vec::new();
    for f in yaml_files("tests/fixtures/schema/invalid") {
        let name = f.file_name().unwrap().to_string_lossy().into_owned();
        if GPU_ARCH_NEW_ONLY.iter().any(|(n, _)| *n == name)
            || GPU_ARCH_CONVERSION_ONLY.contains(&name.as_str())
        {
            continue; // schema-valid by design, see gpu_arch_fixture_parity
        }
        let v = validator(&schema_for(&f));
        let errs = errors(&v, &load_doc(&f));
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

// ---------- Parity GraphicsApi ↔ schema ----------

/// `GraphicsApi::topo_name` gives exactly the values of `$defs/api` in both schemas, in order;
/// the other APIs (`d3d12`, `vulkan`, `glide`) are reserved, not in the schemas yet (ADR 0014,
/// user decision 1).
#[test]
fn graphics_api_parity_with_schema() {
    use rerun_core::detect::exe::GraphicsApi;

    let topo: Vec<String> = GraphicsApi::ALL
        .iter()
        .filter_map(|a| a.topo_name())
        .map(str::to_owned)
        .collect();
    for (name, schema) in [("topo", topo_schema()), ("package", package_schema())] {
        let listed: Vec<String> = schema["$defs"]["api"]["enum"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s.as_str().unwrap().to_owned())
            .collect();
        assert_eq!(listed, topo, "$defs/api of the {name} schema");
        for reserved in GraphicsApi::ALL.iter().filter(|a| a.topo_name().is_none()) {
            assert!(
                !listed.iter().any(|l| l == reserved.as_str()),
                "{reserved} is in the {name} schema: give it a topo_name"
            );
        }
    }
}

// ---------- GPU architecture table ↔ GpuArchTable::new (ADR 0015) ----------

/// Does `new` report the expected kind?
type KindCheck = fn(TableErrorKind) -> bool;

/// Invalid fixtures that only `GpuArchTable::new` can refuse (the schema cannot express the
/// rule), with the kind `new` must report. They must be schema-valid, so this list cannot
/// hide a schema gap.
const GPU_ARCH_NEW_ONLY: &[(&str, KindCheck)] = &[
    ("gpu-arch-overlap.yaml", |k| {
        matches!(k, TableErrorKind::Overlap { .. })
    }),
    ("gpu-arch-undeclared-arch.yaml", |k| {
        k == TableErrorKind::UndeclaredArch
    }),
    ("gpu-arch-vendor-conflict.yaml", |k| {
        matches!(k, TableErrorKind::ArchVendorMismatch { .. })
    }),
    ("gpu-arch-range-reversed.yaml", |k| {
        k == TableErrorKind::RangeReversed
    }),
    ("gpu-arch-duplicate-arch.yaml", |k| {
        matches!(k, TableErrorKind::DuplicateArch { .. })
    }),
];

/// Invalid fixtures the schema accepts but a strict typed conversion refuses: JSON Schema
/// 2020-12 counts `30032.0` as an integer, a typed `u32` must not (ADR 0015, open point on the
/// phase 4 integer visitor).
const GPU_ARCH_CONVERSION_ONLY: &[&str] = &["gpu-arch-device-float.yaml"];

/// A strict test-only conversion of a parsed table document into the input of
/// `GpuArchTable::new`, standing in for the phase 4 loader: exactly the keys of the schema,
/// typed values only. `Err` names what failed.
fn table_input(doc: &Value) -> Result<(Vec<ArchDecl>, Vec<ArchEntry>), String> {
    fn object<'a>(
        v: &'a Value,
        required: &[&str],
        optional: &[&str],
    ) -> Result<&'a serde_json::Map<String, Value>, String> {
        let o = v.as_object().ok_or("not an object")?;
        if let Some(k) = o
            .keys()
            .find(|k| !required.contains(&k.as_str()) && !optional.contains(&k.as_str()))
        {
            return Err(format!("unknown key {k}"));
        }
        if let Some(k) = required.iter().find(|k| !o.contains_key(**k)) {
            return Err(format!("missing key {k}"));
        }
        Ok(o)
    }
    fn int(v: &Value) -> Result<u32, String> {
        let n = v.as_u64().ok_or("not an unsigned integer")?;
        u32::try_from(n).map_err(|e| e.to_string())
    }
    fn arch_id(v: &Value) -> Result<ArchId, String> {
        ArchId::new(v.as_str().ok_or("arch id not a string")?).map_err(|e| e.to_string())
    }
    fn list(v: Option<&Value>) -> Result<&[Value], String> {
        v.map_or(Ok(&[][..]), |v| {
            v.as_array().map(Vec::as_slice).ok_or("not a list".into())
        })
    }

    let top = object(doc, &["format", "archs", "entries"], &[])?;
    if top["format"] != 1 {
        return Err("format is not 1".into());
    }
    let archs = list(top.get("archs"))?
        .iter()
        .map(|a| {
            let a = object(a, &["id", "vendor"], &[])?;
            Ok(ArchDecl {
                id: arch_id(&a["id"])?,
                vendor: int(&a["vendor"])?,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let entries = list(top.get("entries"))?
        .iter()
        .map(|e| {
            let e = object(
                e,
                &["vendor", "arch", "integrated", "vulkan", "dx9", "source"],
                &["device_ids", "device_ranges"],
            )?;
            let vulkan = match e["vulkan"].as_str().ok_or("vulkan not a string")? {
                "none" => None,
                v => {
                    let minor = v.strip_prefix("1.").ok_or("vulkan not 1.<minor>")?;
                    if minor.len() > 1 && minor.starts_with('0') {
                        return Err("vulkan minor with a leading zero".into());
                    }
                    // The range (at most 99) is checked by `new`.
                    let minor: u8 = minor.parse().map_err(|_| "vulkan minor")?;
                    Some(VkVersion { minor })
                }
            };
            let dx9 = match e["dx9"].as_str() {
                Some("native") => Dx9Path::Native,
                Some("d3d9on12") => Dx9Path::D3d9On12,
                _ => return Err("dx9".into()),
            };
            let device_ranges = list(e.get("device_ranges"))?
                .iter()
                .map(|r| {
                    let r = object(r, &["from", "to"], &[])?;
                    Ok(DeviceRange {
                        from: int(&r["from"])?,
                        to: int(&r["to"])?,
                    })
                })
                .collect::<Result<Vec<_>, String>>()?;
            Ok(ArchEntry {
                vendor: int(&e["vendor"])?,
                arch: arch_id(&e["arch"])?,
                integrated: e["integrated"].as_bool().ok_or("integrated not a bool")?,
                vulkan,
                dx9,
                device_ids: list(e.get("device_ids"))?
                    .iter()
                    .map(int)
                    .collect::<Result<_, _>>()?,
                device_ranges,
                source: e["source"]
                    .as_str()
                    .ok_or("source not a string")?
                    .to_owned(),
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    Ok((archs, entries))
}

/// `GpuArchTable::new` on a parsed document; `Err` from the conversion or from `new`.
fn rust_table(doc: &Value) -> Result<GpuArchTable, String> {
    let (archs, entries) = table_input(doc)?;
    GpuArchTable::new(archs, entries).map_err(|e| e.to_string())
}

/// The YAML is the single source (ADR 0015): it is schema-valid, passes `GpuArchTable::new`
/// and equals the built-in mirror field by field.
#[test]
fn gpu_arch_data_equals_builtin() {
    let doc = gpu_arch_data();
    let errs = errors(&validator(&gpu_arch_schema()), &doc);
    assert!(errs.is_empty(), "{}", errs.join("\n"));
    let from_yaml = rust_table(&doc).unwrap();
    let builtin = GpuArchTable::builtin().unwrap();
    assert_eq!(from_yaml.archs(), builtin.archs(), "archs differ");
    assert_eq!(from_yaml.entries(), builtin.entries(), "entries differ");
    assert_eq!(&from_yaml, builtin);
}

/// Two stages, like the phase 4 loader: what the schema accepts, `new` accepts too, except the
/// named `GPU_ARCH_NEW_ONLY` fixtures, which `new` refuses with their kind; what the schema
/// refuses, the conversion or `new` refuses as well.
#[test]
fn gpu_arch_fixture_parity() {
    let schema = validator(&gpu_arch_schema());
    let gpu_arch = |dir: &str| {
        yaml_files(dir)
            .into_iter()
            .filter(|f| is_gpu_arch(f))
            .collect::<Vec<_>>()
    };
    let mut wrong = Vec::new();
    let valid = gpu_arch("tests/fixtures/schema/valid");
    assert!(valid.len() >= 2);
    for f in valid {
        if let Err(e) = rust_table(&load_doc(&f)) {
            wrong.push(format!("{}: valid fixture refused: {e}", f.display()));
        }
    }
    let (mut new_only_seen, mut conversion_only_seen) = (0, 0);
    for f in gpu_arch("tests/fixtures/schema/invalid") {
        let name = f.file_name().unwrap().to_string_lossy().into_owned();
        let doc = load_doc(&f);
        let schema_ok = schema.is_valid(&doc);
        let rust = table_input(&doc)
            .map_err(|_| None)
            .and_then(|(a, e)| GpuArchTable::new(a, e).map_err(|e| Some(e.kind)));
        if GPU_ARCH_CONVERSION_ONLY.contains(&name.as_str()) {
            conversion_only_seen += 1;
            if !schema_ok {
                wrong.push(format!(
                    "{name}: on the conversion-only list but schema-invalid"
                ));
            }
            if table_input(&doc).is_ok() {
                wrong.push(format!("{name}: the conversion accepts it"));
            }
            continue;
        }
        match GPU_ARCH_NEW_ONLY.iter().find(|(n, _)| *n == name) {
            Some((_, expected)) => {
                new_only_seen += 1;
                if !schema_ok {
                    wrong.push(format!("{name}: on the new-only list but schema-invalid"));
                }
                match rust {
                    Err(Some(kind)) if expected(kind) => {}
                    other => wrong.push(format!("{name}: new gave {other:?}")),
                }
            }
            None => {
                if schema_ok {
                    wrong.push(format!("{name}: schema accepts an invalid fixture"));
                }
                if rust.is_ok() {
                    wrong.push(format!("{name}: refused by the schema, accepted by new"));
                }
            }
        }
    }
    assert_eq!(
        new_only_seen,
        GPU_ARCH_NEW_ONLY.len(),
        "new-only fixture missing"
    );
    assert_eq!(
        conversion_only_seen,
        GPU_ARCH_CONVERSION_ONLY.len(),
        "conversion-only fixture missing"
    );
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// `ArchId::new` and `$defs/archId` decide every case the same way.
#[test]
fn arch_id_parity_with_schema() {
    let v = validator(&gpu_arch_schema()["$defs"]["archId"]);
    let valid = [
        "a",
        "rdna4",
        "rdna3_5",
        "xe_lp",
        "xe_hpg",
        "gen11",
        "unknown_",
        "unknownx",
        "a_",
        "a234567890123456789012345678901_",
    ];
    let invalid = [
        "",
        "unknown",
        "Unknown",
        "UNKNOWN",
        "Rdna4",
        "rDna4",
        "4rdna",
        "_rdna",
        "rdna-4",
        "rdna.4",
        "rdna 4",
        " rdna4",
        "rdna4 ",
        "rdna4\n",
        "\nrdna4",
        "ärdna",
        "rdnä",
        "rdna\u{0130}",
        "rdna\u{212A}",
        "rdna\u{202E}",
        "rdna\u{FF41}",
        "a2345678901234567890123456789012x",
    ];
    let mut mismatches = Vec::new();
    for (expected, list) in [(true, &valid[..]), (false, &invalid[..])] {
        for s in list {
            let rust = ArchId::new(s).is_ok();
            let schema = v.is_valid(&Value::String((*s).to_owned()));
            if rust != expected || schema != expected {
                mismatches.push(format!(
                    "{s:?}: expected valid={expected}, ArchId={rust}, schema={schema}"
                ));
            }
        }
    }
    assert!(
        !v.is_valid(&serde_json::json!(4)),
        "a number is no identifier"
    );
    assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
}

// ---------- The signed index (ADR 0024 amendment "Forward compatibility") ----------

fn json_files(rel: &str) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = fs::read_dir(repo().join(rel))
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .collect();
    v.sort();
    assert!(!v.is_empty(), "no *.json in {rel}");
    v
}

/// The index schema describes the frozen heads: it accepts an index whose entries are of a
/// newer entry format (the typed side, `catalog_parity.rs`, sets them aside), the frozen
/// format-1 bundle, and refuses a head the client refuses as a whole.
#[test]
fn index_fixtures_validate_against_the_index_schema() {
    let v = validator(&load_json("schema/index.schema.json"));
    let mut files = json_files("tests/fixtures/index/newer");
    files.push(repo().join("tests/fixtures/index/format-1.json"));
    for f in &files {
        let doc: Value = serde_json::from_str(&fs::read_to_string(f).unwrap()).unwrap();
        let errs = errors(&v, &doc);
        assert!(errs.is_empty(), "{}:\n{}", f.display(), errs.join("\n"));
    }
    let doc: Value =
        serde_json::from_str(&fs::read_to_string(&files[files.len() - 1]).unwrap()).unwrap();
    let broken: [fn(&mut Value); 4] = [
        |d| d["topos"][0]["match"]["steam_appid"] = Value::from(0),
        |d| d["topos"][0]["format"] = Value::from(0),
        |d| d["packages"][0]["id"] = Value::from("Not An Id"),
        |d| {
            d["packages"][0].as_object_mut().unwrap().remove("format");
        },
    ];
    for (i, b) in broken.iter().enumerate() {
        let mut d = doc.clone();
        b(&mut d);
        assert!(!errors(&v, &d).is_empty(), "case {i}");
    }
}
