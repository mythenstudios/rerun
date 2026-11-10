//! `file_install` (ADR 0020, user decision D11): files of a local package into the game
//! folder.
//!
//! Sources are files below `<AppDir>\packages\<id>\<version>\` (`id` and `version` by the
//! rules of `docs/02-topo-format.md`), reached handle-relative through `AppDir` (a reparse
//! point anywhere on the way is refused), each a plain file of at most 2 GiB whose SHA-256,
//! streamed here, equals the step's. `pkg::extract` puts them there (P4-7); before that only
//! test fixtures did.
//!
//! Per target `to` (relative to the game folder): every missing ancestor gets its own
//! `CreateDir`, top-down and once; a missing target a `CreateFile`; an existing plain file
//! with the same content is omitted whatever its attributes (senior-dev B1: a replace needs
//! two different hashes, ADR 0017 A2), any other content a `ReplaceFile` with the old hash,
//! length and attributes. New files get no read-only, hidden or system attribute.
//! Every existing segment of a target goes into the plan in its stored spelling (audit A2-B1),
//! a created one in the spelling of the first step that creates it.
//!
//! Refused: a package or version name outside the rules or not present; a source missing, not
//! a plain file, a reparse point or restricted, with another hash or over 2 GiB; a target
//! twice (folded) or an ancestor of another target; on the way to a target a file, a reparse
//! point, a restricted or case-sensitive folder; a target that is a folder, a reparse point,
//! restricted, a cloud placeholder (reading it would download it), hard-linked (managed by a
//! mod manager, ADR 0017 D1) or over 2 GiB. The plan's bounds (128 ops, 8 KiB per op, 4 GiB
//! of backups) are checked by `plan::Plan::encode`.

use std::io::Read;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{Builder, PlanCtx, folded};
use crate::path::RelPath;
use crate::plan::{
    ContentRef, FileState, MAX_FILE_LEN, Op, PlanError, RootIx, package_id_ok, package_version_ok,
};
use crate::policy::root::AppSub;
use crate::sys::fs::{Attrs, EntryKind, Metadata, tag};
use crate::sys::{Dir, SysError, SysErrorKind};

/// The `file_install` step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileInstallSpec {
    /// Package ID.
    pub package: String,
    /// Package version.
    pub version: String,
    /// The files.
    pub files: Vec<FileEntry>,
}

/// One file of a [`FileInstallSpec`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileEntry {
    /// Below the package version folder.
    pub from: RelPath,
    /// Below the game folder.
    pub to: RelPath,
    /// SHA-256 of the file.
    #[serde(with = "crate::wire::hex32")]
    pub sha256: [u8; 32],
    /// A configuration file the user may edit (`docs/02-topo-format.md`).
    #[serde(default)]
    pub config: bool,
}

/// A path for a message (ADR 0016: untrusted text only through `escape`).
fn shown(p: &RelPath) -> String {
    crate::escape::path(p.as_str()).to_string()
}

fn refuse(what: impl Into<String>) -> PlanError {
    PlanError::Step(what.into())
}

/// SHA-256 and length of a file read through `dir`, at most [`MAX_FILE_LEN`] bytes.
pub(crate) fn hash_file(dir: &dyn Dir, p: &RelPath) -> Result<([u8; 32], u64), PlanError> {
    let mut r = dir.open_read(p)?.take(MAX_FILE_LEN.saturating_add(1));
    let mut h = Sha256::new();
    let mut len = 0u64;
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = match r.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(SysError::io(&e, p.as_str()).into()),
        };
        h.update(buf.get(..n).unwrap_or_default());
        len = len.saturating_add(u64::try_from(n).unwrap_or(u64::MAX));
    }
    if len > MAX_FILE_LEN {
        return Err(refuse(format!("{} is larger than 2 GiB", shown(p))));
    }
    Ok((h.finalize().into(), len))
}

/// `<id>\<version>` as a relative path below `packages`.
pub(crate) fn package_rel(id: &str, version: &str) -> Result<RelPath, PlanError> {
    RelPath::from_segment(id)
        .and_then(|p| p.child(version))
        .map_err(|_| refuse("not a valid package ID and version"))
}

/// Opens `<id>\<version>` below `packages`, read-only and handle-relative (a reparse point on
/// the way is `ReparsePoint`, never followed).
pub(crate) fn open_package<'d>(
    packages: &'d dyn Dir,
    id: &str,
    version: &str,
) -> Result<Box<dyn Dir + 'd>, PlanError> {
    match packages.open_dir(&package_rel(id, version)?) {
        Ok(d) => Ok(d),
        Err(e) if e.kind == SysErrorKind::NotFound => Err(missing(id, version)),
        Err(e) => Err(e.into()),
    }
}

fn missing(id: &str, version: &str) -> PlanError {
    refuse(format!(
        "package {} {} is not in Rerun's packages folder (rerun package fetch {}@{} downloads          and unpacks a package of the signed index)",
        crate::escape::text(id),
        crate::escape::text(version),
        crate::escape::text(id),
        crate::escape::text(version)
    ))
}

/// A plain file that may be read: not restricted, no reparse tag (an allowlisted data tag
/// other than a cloud placeholder is a plain file, ADR 0007).
fn readable_file(m: &Metadata) -> Result<(), &'static str> {
    if m.restricted {
        return Err("cannot be opened by the current user");
    }
    match m.kind {
        EntryKind::File => {}
        EntryKind::Dir => return Err("is a folder"),
        EntryKind::Reparse => return Err("is a link or reparse point"),
    }
    if let Some(r) = &m.reparse
        && (r.tag & 0xFFFF_0FFF == tag::CLOUD || !tag::is_allowed_data_tag(r.tag))
    {
        return Err("is a cloud placeholder or carries a reparse tag");
    }
    if m.len > MAX_FILE_LEN {
        return Err("is larger than 2 GiB");
    }
    Ok(())
}

/// Plans `spec` into `b` (module docs).
pub(crate) fn plan_into(
    spec: &FileInstallSpec,
    ctx: &PlanCtx<'_>,
    b: &mut Builder,
) -> Result<(), PlanError> {
    if !package_id_ok(&spec.package) || !package_version_ok(&spec.version) {
        return Err(refuse("not a valid package ID and version"));
    }
    // Targets first (no I/O): none twice, none an ancestor of another, also across steps.
    for (i, f) in spec.files.iter().enumerate() {
        let t = folded(&f.to);
        let clash = |o: &str| o == t || is_below(o, &t) || is_below(&t, o);
        if spec.files[..i].iter().any(|g| clash(&folded(&g.to)))
            || b.targets.iter().any(|o| clash(o))
        {
            return Err(refuse(format!(
                "{} is a target twice or an ancestor of another",
                shown(&f.to)
            )));
        }
    }
    if spec.files.is_empty() {
        return Ok(());
    }
    // Without Rerun's folder (`plan --dry-run` before the first plan) there are no local
    // packages either (review S6).
    let Some(app) = ctx.app else {
        return Err(missing(&spec.package, &spec.version));
    };
    let packages = app
        .sub(AppSub::Packages)?
        .ok_or_else(|| missing(&spec.package, &spec.version))?;
    let src = open_package(&*packages, &spec.package, &spec.version)?;
    let game = ctx.game.dir();
    if ctx.game.info().case_sensitive {
        return Err(refuse("the game folder is case-sensitive"));
    }
    for f in &spec.files {
        // The source.
        let bad_src = |why: &str| refuse(format!("source {}: {why}", shown(&f.from)));
        let meta = src
            .metadata(&f.from)
            .map_err(|e| bad_src(&e.to_string()))?
            .ok_or_else(|| bad_src("missing"))?;
        readable_file(&meta).map_err(bad_src)?;
        let (sha, len) = hash_file(&*src, &f.from)?;
        if sha != f.sha256 {
            return Err(bad_src("does not have the SHA-256 of the step"));
        }
        // The way to the target, top-down. Every segment that exists is written into the
        // plan in its stored spelling (A2-B1): the plan names the objects as they are, a
        // recovery renames back onto exactly that name, and `exec` refuses a name whose
        // spelling changed since the preview. A segment the plan creates keeps the spelling
        // of the step that creates it first.
        let bad_to = |why: &str| refuse(format!("target {}: {why}", shown(&f.to)));
        let segs: Vec<&str> = f.to.segments().collect();
        let Some((last, ancestors)) = segs.split_last() else {
            return Err(bad_to("empty"));
        };
        let join = |prefix: &Option<RelPath>, seg: &str| {
            match prefix {
                None => RelPath::from_segment(seg),
                Some(p) => p.child(seg),
            }
            .map_err(|e| bad_to(&e.to_string()))
        };
        // The stored spelling of the existing `asked` below `prefix`.
        let stored = |prefix: &Option<RelPath>, asked: &RelPath| -> Result<RelPath, PlanError> {
            let name = game
                .stored_name(asked)
                .map_err(|e| bad_to(&e.to_string()))?
                .ok_or_else(|| bad_to("changed while it was planned"))?;
            join(prefix, &name)
        };
        let mut prefix: Option<RelPath> = None;
        let mut creating = false;
        for seg in ancestors {
            let asked = join(&prefix, seg)?;
            let key = folded(&asked);
            let p = if b.creates(&key) {
                // Created by an earlier target of this plan: so is everything below it.
                creating = true;
                b.created_path(&key)
                    .ok_or_else(|| bad_to("a created folder without its op (internal)"))?
            } else {
                if !creating {
                    match game.metadata(&asked).map_err(|e| bad_to(&e.to_string()))? {
                        None => creating = true,
                        Some(m) => {
                            if m.restricted || m.kind != EntryKind::Dir {
                                return Err(bad_to(&format!(
                                    "{} is not a plain folder",
                                    shown(&asked)
                                )));
                            }
                            let d = game.open_dir(&asked).map_err(|e| bad_to(&e.to_string()))?;
                            if d.info()?.case_sensitive {
                                return Err(bad_to(&format!(
                                    "{} is case-sensitive",
                                    shown(&asked)
                                )));
                            }
                        }
                    }
                }
                if creating {
                    b.created.push(key);
                    b.ops.push(Op::CreateDir {
                        root: RootIx(0),
                        path: asked.clone(),
                    });
                    asked
                } else {
                    stored(&prefix, &asked)?
                }
            };
            prefix = Some(p);
        }
        let asked = join(&prefix, last)?;
        b.targets.push(folded(&f.to));
        let content = ContentRef::Package {
            id: spec.package.clone(),
            version: spec.version.clone(),
            file: f.from.clone(),
            sha256: sha,
            len,
            config: f.config,
        };
        let existing = if creating {
            None
        } else {
            game.metadata(&asked).map_err(|e| bad_to(&e.to_string()))?
        };
        match existing {
            None => b.ops.push(Op::CreateFile {
                root: RootIx(0),
                path: asked,
                content,
                attrs: Attrs::default(),
            }),
            Some(m) => {
                readable_file(&m).map_err(bad_to)?;
                if !m.is_single_link() {
                    return Err(bad_to("is hard-linked (managed by a mod manager)"));
                }
                let to = stored(&prefix, &asked)?;
                let (old_sha, old_len) = hash_file(game, &to)?;
                if old_sha == sha {
                    // B1: the same content is no op, whatever the attributes.
                    continue;
                }
                b.ops.push(Op::ReplaceFile {
                    root: RootIx(0),
                    path: to,
                    old: FileState {
                        sha256: old_sha,
                        len: old_len,
                        attrs: m.attrs,
                    },
                    content,
                    attrs: Attrs::default(),
                });
            }
        }
    }
    Ok(())
}

/// `p` lies strictly below the folded directory path `dir`.
fn is_below(dir: &str, p: &str) -> bool {
    p.strip_prefix(dir).is_some_and(|r| r.starts_with('\\'))
}
