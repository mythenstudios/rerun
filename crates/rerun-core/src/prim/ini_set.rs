//! `ini_set` (P2-12; ADR 0020 amendment P2-12, ADR 0021): keys of an existing INI file of the
//! game folder.
//!
//! The step `{"ini_set":{"file":"cfg\\game.ini","values":[{"section":"Display","key":"Width",
//! "value":"1920"}]}}` (`deny_unknown_fields`): `file` a `RelPath` with the extension `.ini`
//! (folded; not `desktop.ini`, review S4), naming a plain file of the game folder below plain
//! folders, in the plan in the stored spelling of every segment (A2-B1); 1 to 8 `values`, each a
//! section and key name (`IniName`) and a value (`IniText` and the rule in force now,
//! `IniText::check_new`), unique by folded section and key.
//!
//! The planner reads the file once, bounded (at most 1 MiB), through the game folder's read
//! handle and scans it with `policy::ini` (ADR 0021): a value equal to the file's is left out
//! (all equal: no op); another value is an edit with that old value; a missing key in an
//! existing section an edit `NoKey`; a missing section an edit `NoSection` (refused in a file
//! without any header, review S4). One `IniValue` per file with the edits in canonical order
//! and the new content's hash and length from `policy::ini::edit` (its R/H/S are the old ones).
//!
//! Refused: the file missing (user decision E4 a: start the game once, or ship the file in a
//! package), a folder, a link or other reparse point (a cloud placeholder included) on the way
//! or as the file, restricted, hard-linked, with the system attribute (review S4), larger than
//! 1 MiB, in a case-sensitive folder; a file `policy::ini` refuses (UTF-16, NUL, a lone CR, a
//! `[` line without `]`), an ambiguous section or key, an unusual old value; two `ini_set` steps
//! for one file, an `ini_set` and a `file_install` of the same file in one plan (checked by
//! `prim::plan`), a plan without the game's main executable (user decision E5 a).

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{Builder, PlanCtx, folded};
use crate::path::RelPath;
use crate::plan::{FileHash, FileState, Op, PlanError, RootIx};
use crate::policy::ini::{
    self, Found, IniEdit, IniError, IniName, IniText, MAX_EDITS, MAX_INI_BYTES, Old,
};
use crate::policy::root::GameDir;
use crate::sys::SysErrorKind;
use crate::sys::fs::{EntryKind, Metadata};

/// The `ini_set` step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IniSetSpec {
    /// The INI file, relative to the game folder.
    pub file: RelPath,
    /// The keys, 1 to 8.
    pub values: Vec<IniSetValue>,
}

/// One key of an [`IniSetSpec`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IniSetValue {
    /// The section.
    pub section: String,
    /// The key.
    pub key: String,
    /// The value.
    pub value: String,
}

fn refuse(what: impl Into<String>) -> PlanError {
    PlanError::Step(what.into())
}

/// A path or untrusted text for messages (ADR 0016).
fn shown(s: &str) -> String {
    crate::escape::path(s).to_string()
}

/// The values of the step: names and values in their form, the value rule in force now,
/// unique by folded section and key.
fn values(spec: &IniSetSpec) -> Result<Vec<(IniName, IniName, IniText)>, PlanError> {
    if spec.values.is_empty() || spec.values.len() > MAX_EDITS {
        return Err(refuse("ini_set: 1 to 8 values"));
    }
    let mut out: Vec<(IniName, IniName, IniText)> = Vec::with_capacity(spec.values.len());
    for v in &spec.values {
        let name =
            |s: &str| IniName::parse(s).map_err(|e| refuse(format!("ini_set: {}: {e}", shown(s))));
        let section = name(&v.section)?;
        let key = name(&v.key)?;
        let value = IniText::parse(&v.value)
            .map_err(|e| refuse(format!("ini_set: {}: {e}", shown(&v.value))))?;
        if value.as_str().is_empty() {
            return Err(refuse(format!(
                "ini_set: [{section}] {key}: an empty value cannot be set"
            )));
        }
        value
            .check_new()
            .map_err(|e| refuse(format!("ini_set: [{section}] {key}: {e}")))?;
        if out
            .iter()
            .any(|(s, k, _)| s.folded() == section.folded() && k.folded() == key.folded())
        {
            return Err(refuse(format!("ini_set: [{section}] {key} twice")));
        }
        out.push((section, key, value));
    }
    Ok(out)
}

/// `file` in the stored spelling of every segment and its metadata, if it is a plain file of
/// the game folder below plain folders (module docs).
fn stored_file(game: &GameDir<'_>, file: &RelPath) -> Result<(RelPath, Metadata), PlanError> {
    let bad = |why: &str| refuse(format!("ini_set: {}: {why}", shown(file.as_str())));
    let segs: Vec<&str> = file.segments().collect();
    let mut asked: Option<RelPath> = None;
    let mut stored: Option<RelPath> = None;
    let mut last_meta = None;
    for (i, seg) in segs.iter().enumerate() {
        let next = match &asked {
            None => RelPath::from_segment(seg),
            Some(p) => p.child(seg),
        }
        .map_err(|e| bad(&e.to_string()))?;
        let last = i + 1 == segs.len();
        let meta = match game.dir().metadata(&next) {
            Ok(Some(m)) => m,
            Ok(None) => {
                return Err(bad(
                    "missing; start the game once so it writes the file, or ship the file \
                     in a package",
                ));
            }
            Err(e) if e.kind == SysErrorKind::ReparsePoint => {
                return Err(bad("a link or other reparse point on the way"));
            }
            Err(e) => return Err(e.into()),
        };
        let want = if last {
            EntryKind::File
        } else {
            EntryKind::Dir
        };
        if meta.kind != want || meta.reparse.is_some() || meta.restricted {
            return Err(bad(if last {
                "not a plain file (a folder, a link, a cloud placeholder or not readable)"
            } else {
                "a folder on the way is not a plain folder"
            }));
        }
        if !last
            && game
                .dir()
                .open_dir(&next)
                .and_then(|d| d.info())
                .map_err(|e| bad(&e.to_string()))?
                .case_sensitive
        {
            return Err(bad("a case-sensitive folder on the way"));
        }
        let name = game
            .dir()
            .stored_name(&next)
            .map_err(|e| bad(&e.to_string()))?
            .ok_or_else(|| bad("changed while it was planned"))?;
        stored = Some(
            match &stored {
                None => RelPath::from_segment(&name),
                Some(p) => p.child(&name),
            }
            .map_err(|e| bad(&e.to_string()))?,
        );
        asked = Some(next);
        if last {
            last_meta = Some(meta);
        }
    }
    let meta = last_meta.ok_or_else(|| bad("empty"))?;
    if !meta.is_single_link() {
        return Err(bad("hard-linked (managed by a mod manager)"));
    }
    if meta.attrs.system {
        return Err(bad("a system file"));
    }
    if meta.len > u64::try_from(MAX_INI_BYTES).unwrap_or(u64::MAX) {
        return Err(bad("larger than 1 MiB"));
    }
    Ok((stored.ok_or_else(|| bad("empty"))?, meta))
}

/// Why the file or a value is refused, for a message.
fn ini_refusal(file: &RelPath, vals: &[(IniName, IniName, IniText)], e: IniError) -> PlanError {
    let at = |edit: u8| {
        vals.get(usize::from(edit))
            .map(|(s, k, _)| format!("[{s}] {k}: "))
            .unwrap_or_default()
    };
    let what = match e {
        IniError::Ambiguous { edit } | IniError::Unusual { edit } | IniError::NotOld { edit } => {
            format!("{}{e}", at(edit))
        }
        _ => e.to_string(),
    };
    refuse(format!("ini_set: {}: {what}", shown(file.as_str())))
}

/// Plans `spec` into `b` (module docs).
pub(crate) fn plan_into(
    spec: &IniSetSpec,
    ctx: &PlanCtx<'_>,
    b: &mut Builder,
) -> Result<(), PlanError> {
    let game = ctx.game;
    if !ini::path_ok(&spec.file) {
        return Err(refuse(format!(
            "ini_set: {} is no .ini file (or is desktop.ini)",
            shown(spec.file.as_str())
        )));
    }
    let vals = values(spec)?;
    let f = folded(&spec.file);
    if b.ini_files.contains(&f) {
        return Err(refuse(format!(
            "ini_set: two steps for {}; put the values into one step",
            shown(spec.file.as_str())
        )));
    }
    b.ini_files.push(f);
    if game.info().case_sensitive {
        return Err(refuse("ini_set: the game folder is case-sensitive"));
    }
    let (path, meta) = stored_file(game, &spec.file)?;
    let max = u64::try_from(MAX_INI_BYTES).unwrap_or(u64::MAX);
    let bytes = match game.dir().read_limited(&path, max) {
        Ok(b) => b,
        Err(e) if e.kind == SysErrorKind::TooLarge => {
            return Err(refuse(format!(
                "ini_set: {}: larger than 1 MiB",
                shown(spec.file.as_str())
            )));
        }
        Err(e) => return Err(e.into()),
    };
    let doc = ini::scan(&bytes).map_err(|e| ini_refusal(&spec.file, &vals, e))?;
    let mut edits = Vec::with_capacity(vals.len());
    for (i, (section, key, value)) in vals.iter().enumerate() {
        let ix = u8::try_from(i).unwrap_or(u8::MAX);
        let old = match doc
            .get(ix, section, key)
            .map_err(|e| ini_refusal(&spec.file, &vals, e))?
        {
            Found::Value(v) if v == value.as_str() => continue,
            Found::Value(v) => {
                Old::Value(IniText::parse(v).map_err(|e| ini_refusal(&spec.file, &vals, e))?)
            }
            Found::NoKey => Old::NoKey,
            Found::NoSection => Old::NoSection,
        };
        edits.push(IniEdit {
            section: section.clone(),
            key: key.clone(),
            old,
            new: value.clone(),
        });
    }
    if edits.is_empty() {
        return Ok(());
    }
    // The canonical order (the plan hash does not depend on the order of the step's values).
    edits.sort_by_key(|e| (e.section.folded(), e.key.folded()));
    let new = ini::edit(&bytes, &edits).map_err(|e| match e {
        IniError::NoHeader => refuse(format!(
            "ini_set: {}: a new section in a file without any section header",
            shown(spec.file.as_str())
        )),
        IniError::Edits(why) => refuse(format!("ini_set: {why}")),
        e => ini_refusal(&spec.file, &vals, e),
    })?;
    let hash = |b: &[u8]| -> ([u8; 32], u64) {
        (
            Sha256::digest(b).into(),
            u64::try_from(b.len()).unwrap_or(u64::MAX),
        )
    };
    let (old_sha, old_len) = hash(&bytes);
    let (new_sha, new_len) = hash(&new);
    b.ops.push(Op::IniValue {
        root: RootIx(0),
        path,
        old: FileState {
            sha256: old_sha,
            len: old_len,
            attrs: meta.attrs,
        },
        new: FileHash {
            sha256: new_sha,
            len: new_len,
        },
        edits,
    });
    Ok(())
}
