//! `index build`: the YAML of `topos/` and `packages/` into the canonical bundle `index.json`
//! (ADR 0024).
//!
//! Every file is loaded like the runtime loader would (strict YAML without anchors, then the
//! typed `rerun_core::catalog` structs and `check` with `Rules::Source`; file name = ID). A
//! draft is left out of the bundle (a file with `TODO` is a draft, `Rules::Source` makes sure);
//! a released Topo that needs a package left out fails the build, as does any entry the client
//! would set aside (ADR 0024 amendment "Forward compatibility" §6). The bytes are a function of
//! the files, `seq` and `issued` only: sorted by ID, every map a `BTreeMap`, fields in
//! declaration order, pretty JSON with a final newline.

use rerun_core::catalog::check::{self, Rules};
use rerun_core::catalog::model::{Index, Status};
use rerun_core::catalog::{INDEX_FORMAT, MAX_INDEX_BYTES, Package, Topo, check_bundle};
use serde_json::Value;

/// One source file: its name (`<id>.yaml`) and text.
#[derive(Debug, Clone)]
pub struct SourceFile {
    /// The file name.
    pub name: String,
    /// The YAML.
    pub text: String,
}

/// What `build` made.
#[derive(Debug)]
pub struct Bundle {
    /// The bytes of `index.json`.
    pub bytes: Vec<u8>,
    /// The index they encode.
    pub index: Index,
    /// The drafts left out, as `topo <id>` / `package <id>`.
    pub excluded: Vec<String>,
}

/// The loader's YAML rules (ADR 0005, phase 4).
pub fn load_yaml(text: &str) -> Result<Value, String> {
    let options = serde_saphyr::options! {
        strict_booleans: true,
        merge_keys: serde_saphyr::MergeKeyPolicy::Error,
        duplicate_keys: serde_saphyr::DuplicateKeyPolicy::Error,
        budget: serde_saphyr::budget! { max_anchors: 0, max_aliases: 0 },
    };
    serde_saphyr::from_str_with_options(text, options).map_err(|e| e.to_string())
}

fn stem(name: &str) -> Result<&str, String> {
    name.strip_suffix(".yaml")
        .ok_or_else(|| format!("{name}: not a .yaml file"))
}

fn load<T: serde::de::DeserializeOwned>(
    f: &SourceFile,
    check: impl Fn(&T) -> Result<(), check::RuleError>,
    id: impl Fn(&T) -> &str,
) -> Result<T, String> {
    let v = load_yaml(&f.text).map_err(|e| format!("{}: {e}", f.name))?;
    let t: T = serde_json::from_value(v).map_err(|e| format!("{}: {e}", f.name))?;
    check(&t).map_err(|e| format!("{}: {e}", f.name))?;
    let s = stem(&f.name)?;
    if id(&t) != s {
        return Err(format!(
            "{}: the ID is {}, the file name says {s}",
            f.name,
            id(&t)
        ));
    }
    Ok(t)
}

/// Builds the bundle (module docs).
pub fn build(
    topos: &[SourceFile],
    packages: &[SourceFile],
    seq: u64,
    issued: &str,
) -> Result<Bundle, String> {
    let mut all_topos = topos
        .iter()
        .map(|f| load::<Topo>(f, |t| check::topo(t, Rules::Source), |t| t.id.as_str()))
        .collect::<Result<Vec<_>, _>>()?;
    let mut all_packages = packages
        .iter()
        .map(|f| load::<Package>(f, |p| check::package(p, Rules::Source), |p| p.id.as_str()))
        .collect::<Result<Vec<_>, _>>()?;
    all_topos.sort_by(|a, b| a.id.cmp(&b.id));
    all_packages.sort_by(|a, b| a.id.cmp(&b.id));

    let mut excluded = Vec::new();
    let (released_topos, drafts): (Vec<Topo>, Vec<Topo>) = all_topos
        .into_iter()
        .partition(|t| t.status != Status::Draft);
    excluded.extend(drafts.iter().map(|t| format!("topo {}", t.id)));
    let (released_packages, drafts): (Vec<Package>, Vec<Package>) = all_packages
        .into_iter()
        .partition(|p| p.status != Status::Draft);
    excluded.extend(drafts.iter().map(|p| format!("package {}", p.id)));

    let index = Index {
        format: INDEX_FORMAT,
        seq,
        issued: issued.to_owned(),
        topos: released_topos,
        packages: released_packages,
    };
    let mut bytes = serde_json::to_vec_pretty(&index).map_err(|e| e.to_string())?;
    bytes.push(b'\n');
    if bytes.len() > MAX_INDEX_BYTES {
        return Err(format!(
            "the bundle has {} bytes, more than the limit of {MAX_INDEX_BYTES}",
            bytes.len()
        ));
    }
    // The client's classification of these bytes sets nothing aside (ADR 0024 amendment
    // "Forward compatibility" §6): what a client would only show is never built.
    refuse_aside(&bytes)?;
    // The bytes must read back as exactly this index (what the client will parse).
    let back: Index = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    if back != index {
        return Err("the bundle does not read back as the same index".into());
    }
    Ok(Bundle {
        bytes,
        index,
        excluded,
    })
}

/// The client's rules on `bytes` (`rerun_core::catalog::check_bundle`): the envelope, the
/// heads and every entry; any entry the client would set aside fails (`build`, `sign`,
/// `sign-test`).
pub fn refuse_aside(bytes: &[u8]) -> Result<(), String> {
    let aside = check_bundle(bytes).map_err(|e| e.to_string())?;
    if aside.is_empty() {
        return Ok(());
    }
    let list: Vec<String> = aside.iter().map(ToString::to_string).collect();
    Err(format!(
        "the client would set aside {} entr{} of this bundle: {}",
        aside.len(),
        if aside.len() == 1 { "y" } else { "ies" },
        list.join("; ")
    ))
}

#[cfg(test)]
mod tests;
