//! Plans (ADR 0020 and its P2-8 amendment): the ops a primitive's planner emits, serialised
//! once, bound to the preview by [`PlanHash`], stored below `<AppDir>\plans` and, as the
//! transaction's `head.json`, read again by `exec`.
//!
//! Wire format 1 (`serde_json`, `deny_unknown_fields`, no maps): `{"format":1,"roots":[…],
//! "ops":[…]}`; enums are externally tagged in `snake_case` (`{"create_file":{…}}`, a unit
//! variant as its name, `"manual"`); every SHA-256 is 64 lower-case hex digits, a [`RootId`]
//! `<16 hex>-<32 hex>`, paths are strings with `\`. [`Plan::encode`] is the one serialisation:
//! its bytes are what the preview shows, what is stored and what `exec` applies, and
//! [`PlanHash`] is SHA-256 over exactly these bytes. [`decode`] treats bytes as untrusted:
//! the format first, then a strict parse, then the one-form check (re-encoding the result
//! gives the same bytes: no whitespace, field order, `/`, lower-case drive letter or other
//! spelling), then the same bounds as `encode` ([`MAX_OPS`], [`MAX_OP_BYTES`],
//! [`MAX_PLAN_BYTES`], root indices, package names, one op per object).
//!
//! Phase 2 has the file op kinds `CreateDir`, `CreateFile`, `ReplaceFile`; registry and INI
//! op kinds are added as further variants with their primitives (format 1 stays unstable until
//! the first release, ADR 0019 amendment E1).

mod preview;
mod store;

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub use preview::{NOT_RESTORED, Preview, PreviewOp, PreviewRoot, preview};
pub(crate) use store::load;
pub use store::store;

use crate::fold::fold;
use crate::path::{RelPath, RootPath};
use crate::policy::root::{RootError, RootId};
use crate::sys::SysError;
use crate::sys::fs::Attrs;

/// The one plan format.
pub const FORMAT: u32 = 1;
/// Most ops of a plan (ADR 0019, condition S1).
pub const MAX_OPS: usize = 128;
/// Most bytes of one serialised op.
pub const MAX_OP_BYTES: usize = 8 << 10;
/// Most bytes of a serialised plan (`head.json`).
pub const MAX_PLAN_BYTES: usize = 1 << 20;
/// Most roots of a plan.
pub const MAX_ROOTS: usize = 16;
/// Largest file a plan installs or replaces (the hash limit of ADR 0014, a backup's limit).
pub const MAX_FILE_LEN: u64 = 2 << 30;
/// Most bytes of all backups of one plan (the journal's limit per transaction).
pub const MAX_BACKUP_BYTES: u64 = 4 << 30;

/// A plan (ADR 0020).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    /// [`FORMAT`].
    pub format: u32,
    /// The roots the ops write into.
    pub roots: Vec<PlanRoot>,
    /// The ops, applied in this order and reverted newest first.
    pub ops: Vec<Op>,
}

/// A root of a plan: reopened through `policy::root` and checked by identity before every
/// apply and revert.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanRoot {
    /// The kind of root.
    pub kind: RootKind,
    /// Canonical path as of planning.
    pub path: RootPath,
    /// Identity as of planning.
    pub id: RootId,
    /// How it is reopened.
    pub origin: PlanOrigin,
    /// The game's main executable (relative to the root), asked by `users()` before apply
    /// and revert (user decision D4).
    pub main_exe: Option<RelPath>,
}

/// Kind of a plan root (`UserData` is reserved for phase 4, D6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RootKind {
    /// A game folder.
    Game,
}

/// Where a plan root came from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum PlanOrigin {
    /// `steamapps\common\<installdir>` of a Steam library.
    Steam {
        /// Canonical path of the library.
        store: RootPath,
        /// Identity of the library.
        store_id: RootId,
        /// The app whose state is checked.
        app_id: u32,
        /// The install folder name.
        installdir: RelPath,
    },
    /// A folder added by the user, reopened by absolute path.
    Manual,
}

/// Index into [`Plan::roots`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RootIx(pub u16);

/// One op (ADR 0020). There is no delete op: deleting is only ever a revert.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Op {
    /// Creates one directory.
    CreateDir {
        /// Root.
        root: RootIx,
        /// Path below the root.
        path: RelPath,
    },
    /// Creates a file that does not exist.
    CreateFile {
        /// Root.
        root: RootIx,
        /// Path below the root.
        path: RelPath,
        /// Its content.
        content: ContentRef,
        /// Read-only, hidden, system of the new file.
        attrs: Attrs,
    },
    /// Replaces an existing file whose state was `old` when planned.
    ReplaceFile {
        /// Root.
        root: RootIx,
        /// Path below the root.
        path: RelPath,
        /// The old state, re-observed on the guard before the change.
        old: FileState,
        /// The new content.
        content: ContentRef,
        /// Read-only, hidden, system of the new file.
        attrs: Attrs,
    },
}

/// What an op targets (audit A2 should-item 3): the generic paths of `plan` and `exec`
/// (objects and "one op per object", records, flushes, the game-closed check) go through
/// this, never through an op kind, so a new kind of target (registry keys and values,
/// P2-10b) is one more variant whose every use the compiler names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target<'a> {
    /// A file or directory below a root.
    File {
        /// Root.
        root: RootIx,
        /// Path below the root.
        path: &'a RelPath,
        /// The op creates a directory.
        dir: bool,
    },
}

impl Op {
    /// What the op targets.
    pub fn target(&self) -> Target<'_> {
        match self {
            Self::CreateDir { root, path } => Target::File {
                root: *root,
                path,
                dir: true,
            },
            Self::CreateFile { root, path, .. } | Self::ReplaceFile { root, path, .. } => {
                Target::File {
                    root: *root,
                    path,
                    dir: false,
                }
            }
        }
    }

    /// The content of a file op.
    pub fn content(&self) -> Option<&ContentRef> {
        match self {
            Self::CreateDir { .. } => None,
            Self::CreateFile { content, .. } | Self::ReplaceFile { content, .. } => Some(content),
        }
    }
}

/// The state of a file: what a guard observes and a revert restores (ADR 0017, "exact").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileState {
    /// SHA-256 of the content.
    #[serde(with = "crate::wire::hex32")]
    pub sha256: [u8; 32],
    /// Length in bytes.
    pub len: u64,
    /// Read-only, hidden, system.
    pub attrs: Attrs,
}

/// Where the content of a file op comes from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ContentRef {
    /// A file below `<AppDir>\packages\<id>\<version>\` (ADR 0020, D11).
    Package {
        /// Package ID (`docs/02-topo-format.md`).
        id: String,
        /// Package version.
        version: String,
        /// The file below the version folder.
        file: RelPath,
        /// SHA-256 of the file, checked while it is streamed.
        #[serde(with = "crate::wire::hex32")]
        sha256: [u8; 32],
        /// Length in bytes.
        len: u64,
        /// A configuration file the user may edit: a revert then finds it `Foreign` and
        /// leaves it (ADR 0020); the preview says so.
        config: bool,
    },
}

impl ContentRef {
    /// SHA-256 of the content.
    pub fn sha256(&self) -> &[u8; 32] {
        match self {
            Self::Package { sha256, .. } => sha256,
        }
    }

    /// Length of the content.
    pub fn len(&self) -> u64 {
        match self {
            Self::Package { len, .. } => *len,
        }
    }

    /// The content is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// SHA-256 over the serialised plan bytes ([`PlanBytes`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PlanHash(pub [u8; 32]);

impl fmt::Display for PlanHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&crate::wire::hex32::to_string(&self.0))
    }
}

impl FromStr for PlanHash {
    type Err = PlanError;

    /// Exactly 64 lower-case hex digits.
    fn from_str(s: &str) -> Result<Self, PlanError> {
        crate::wire::hex32::from_str(s)
            .map(Self)
            .ok_or(PlanError::BadHash)
    }
}

/// The one serialisation of a plan and its hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanBytes {
    bytes: Vec<u8>,
    hash: PlanHash,
}

impl PlanBytes {
    /// Bytes read back (stored plan, `head.json`); the hash is computed here.
    pub(crate) fn from_bytes(bytes: Vec<u8>) -> Self {
        let hash = PlanHash(Sha256::digest(&bytes).into());
        Self { bytes, hash }
    }

    /// The bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Their hash.
    pub fn hash(&self) -> PlanHash {
        self.hash
    }
}

/// Bounds of a plan (crate-internal so tests can shrink them).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Limits {
    pub(crate) ops: usize,
    pub(crate) op_bytes: usize,
    pub(crate) plan_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            ops: MAX_OPS,
            op_bytes: MAX_OP_BYTES,
            plan_bytes: MAX_PLAN_BYTES,
        }
    }
}

/// An error of planning, of the plan format, or of plan storage.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PlanError {
    /// Another plan format.
    #[error("plan format {0} is not supported")]
    Format(u32),
    /// Not a plan of format 1.
    #[error("the plan cannot be parsed")]
    Unparsable,
    /// Parsed, but not in the one written form.
    #[error("the plan is not in its one written form")]
    NotOneForm,
    /// More bytes than [`MAX_PLAN_BYTES`].
    #[error("the plan is larger than {limit} bytes")]
    TooLarge {
        /// The limit.
        limit: usize,
    },
    /// More ops than [`MAX_OPS`].
    #[error("the plan has {n} ops, at most {limit} are allowed")]
    TooManyOps {
        /// Ops of the plan.
        n: usize,
        /// The limit.
        limit: usize,
    },
    /// One op larger than [`MAX_OP_BYTES`] serialised.
    #[error("op {op} is larger than {limit} bytes")]
    OpTooLarge {
        /// Op index.
        op: usize,
        /// The limit.
        limit: usize,
    },
    /// A rule of the plan format is broken (`op` is `None` for the plan itself).
    #[error("{}{why}", op.map(|o| format!("op {o}: ")).unwrap_or_default())]
    Invalid {
        /// Op index.
        op: Option<usize>,
        /// The rule.
        why: &'static str,
    },
    /// Not 64 lower-case hex digits.
    #[error("not a plan hash (64 lower-case hex digits)")]
    BadHash,
    /// No stored plan with this hash.
    #[error("no stored plan {0}; run plan again")]
    NotFound(PlanHash),
    /// The stored bytes do not hash to the name they are stored under.
    #[error("the stored plan {0} was changed; run plan again")]
    HashMismatch(PlanHash),
    /// A step the planner refuses (`file_install`).
    #[error("{0}")]
    Step(String),
    /// The game folder cannot be written by the current user; phase 3 sends such a plan to
    /// the elevated helper.
    #[error("the game folder needs administrator rights (not supported yet)")]
    NeedsHelper,
    /// Serialising failed.
    #[error("the plan is not serialisable: {0}")]
    Encode(String),
    /// Opening Rerun's folder or a root.
    #[error(transparent)]
    Root(Box<RootError>),
    /// The system layer.
    #[error(transparent)]
    Sys(#[from] SysError),
}

impl From<RootError> for PlanError {
    fn from(e: RootError) -> Self {
        Self::Root(Box::new(e))
    }
}

fn invalid(op: Option<usize>, why: &'static str) -> PlanError {
    PlanError::Invalid { op, why }
}

/// A package ID of `docs/02-topo-format.md`: lower-case letters, digits and hyphens, 1 to
/// 64 characters, and a valid path segment.
pub(crate) fn package_id_ok(s: &str) -> bool {
    (1..=64).contains(&s.len())
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        && RelPath::from_segment(s).is_ok()
}

/// A package version of `docs/02-topo-format.md`: `^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$`,
/// without `..`, and a valid path segment.
pub(crate) fn package_version_ok(s: &str) -> bool {
    let mut chars = s.chars();
    chars.next().is_some_and(|c| c.is_ascii_alphanumeric())
        && s.len() <= 64
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '+' | '-'))
        && !s.contains("..")
        && RelPath::from_segment(s).is_ok()
}

impl Plan {
    /// The one serialisation and its hash; refuses a plan outside the bounds of the format.
    pub fn encode(&self) -> Result<PlanBytes, PlanError> {
        self.encode_with(&Limits::default())
    }

    pub(crate) fn encode_with(&self, lim: &Limits) -> Result<PlanBytes, PlanError> {
        let bytes = serde_json::to_vec(self).map_err(|e| PlanError::Encode(e.to_string()))?;
        check(self, bytes.len(), lim)?;
        Ok(PlanBytes::from_bytes(bytes))
    }
}

/// Parses plan bytes as untrusted input (module docs).
pub(crate) fn decode(b: &[u8]) -> Result<Plan, PlanError> {
    decode_with(b, &Limits::default())
}

pub(crate) fn decode_with(b: &[u8], lim: &Limits) -> Result<Plan, PlanError> {
    if b.len() > lim.plan_bytes {
        return Err(PlanError::TooLarge {
            limit: lim.plan_bytes,
        });
    }
    #[derive(Deserialize)]
    struct Probe {
        format: u32,
    }
    let probe: Probe = serde_json::from_slice(b).map_err(|_| PlanError::Unparsable)?;
    if probe.format != FORMAT {
        return Err(PlanError::Format(probe.format));
    }
    let plan: Plan = serde_json::from_slice(b).map_err(|_| PlanError::Unparsable)?;
    if serde_json::to_vec(&plan).ok().as_deref() != Some(b) {
        return Err(PlanError::NotOneForm);
    }
    check(&plan, b.len(), lim)?;
    Ok(plan)
}

/// The bounds and rules shared by [`Plan::encode`] and [`decode`].
fn check(plan: &Plan, len: usize, lim: &Limits) -> Result<(), PlanError> {
    if plan.format != FORMAT {
        return Err(PlanError::Format(plan.format));
    }
    if len > lim.plan_bytes {
        return Err(PlanError::TooLarge {
            limit: lim.plan_bytes,
        });
    }
    if plan.ops.len() > lim.ops {
        return Err(PlanError::TooManyOps {
            n: plan.ops.len(),
            limit: lim.ops,
        });
    }
    if plan.roots.len() > MAX_ROOTS {
        return Err(invalid(None, "more roots than allowed"));
    }
    for (i, r) in plan.roots.iter().enumerate() {
        if plan.roots[..i].iter().any(|o| o.id == r.id) {
            return Err(invalid(None, "a root is listed twice"));
        }
        if let PlanOrigin::Steam { app_id, .. } = r.origin
            && app_id == 0
        {
            return Err(invalid(None, "a Steam root without an app ID"));
        }
    }
    let mut seen: Vec<(RootIx, String)> = Vec::with_capacity(plan.ops.len());
    let mut backups = 0u64;
    for (k, op) in plan.ops.iter().enumerate() {
        let size = serde_json::to_vec(op)
            .map_err(|e| PlanError::Encode(e.to_string()))?
            .len();
        if size > lim.op_bytes {
            return Err(PlanError::OpTooLarge {
                op: k,
                limit: lim.op_bytes,
            });
        }
        match op.target() {
            Target::File { root, path, .. } => {
                if usize::from(root.0) >= plan.roots.len() {
                    return Err(invalid(Some(k), "root index outside the plan's roots"));
                }
                let key = (root, fold(path.as_str()));
                if seen.contains(&key) {
                    return Err(invalid(Some(k), "a second op on the same object"));
                }
                seen.push(key);
            }
        }
        if let Some(ContentRef::Package {
            id, version, len, ..
        }) = op.content()
        {
            if !package_id_ok(id) || !package_version_ok(version) {
                return Err(invalid(Some(k), "not a valid package ID and version"));
            }
            if *len > MAX_FILE_LEN {
                return Err(invalid(Some(k), "content larger than 2 GiB"));
            }
        }
        if let Op::ReplaceFile { old, content, .. } = op {
            if old.sha256 == *content.sha256() {
                return Err(invalid(Some(k), "a replace with the content it replaces"));
            }
            if old.len > MAX_FILE_LEN {
                return Err(invalid(Some(k), "old content larger than 2 GiB"));
            }
            backups = backups.saturating_add(old.len);
        }
    }
    if backups > MAX_BACKUP_BYTES {
        return Err(invalid(None, "the backups exceed 4 GiB"));
    }
    Ok(())
}

/// An object a plan's op touches, for stacking (ADR 0019, B-2), by [`Target`]: a file or
/// directory as root identity and folded path. Two objects overlap if they are the same, or
/// if one is a directory an op creates and the other lies below it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Object {
    /// A file or directory.
    File {
        /// Identity of the root.
        root: RootId,
        /// Canonical path of the root as planned: roots of which one lies inside the other
        /// overlap as a whole (fail closed, review S2).
        root_path: RootPath,
        /// Folded path below the root.
        path: String,
        /// A directory the op creates.
        dir: bool,
    },
}

impl Object {
    /// The objects of `plan` (an op whose root index is outside the plan has none; `decode`
    /// refuses such a plan anyway).
    pub(crate) fn of(plan: &Plan) -> Vec<Self> {
        plan.ops
            .iter()
            .filter_map(|op| match op.target() {
                Target::File { root, path, dir } => {
                    let r = plan.roots.get(usize::from(root.0))?;
                    Some(Self::File {
                        root: r.id,
                        root_path: r.path.clone(),
                        path: fold(path.as_str()),
                        dir,
                    })
                }
            })
            .collect()
    }

    /// Same object, or one a created directory with the other below it; any two objects of
    /// two different roots of which one lies inside the other (a manual root inside a Steam
    /// install folder): no rebasing of paths, fail closed.
    pub(crate) fn overlaps(&self, other: &Self) -> bool {
        match (self, other) {
            (
                Self::File {
                    root: ra,
                    root_path: pa,
                    path: a,
                    dir: da,
                },
                Self::File {
                    root: rb,
                    root_path: pb,
                    path: b,
                    dir: db,
                },
            ) => {
                if ra != rb {
                    return pa.contains(pb) || pb.contains(pa);
                }
                let below = |dir: &str, p: &str| {
                    p.strip_prefix(dir)
                        .is_some_and(|rest| rest.starts_with('\\'))
                };
                a == b || (*da && below(a, b)) || (*db && below(b, a))
            }
        }
    }
}

/// Any object of `a` overlaps any of `b`.
pub(crate) fn overlap(a: &[Object], b: &[Object]) -> bool {
    a.iter().any(|x| b.iter().any(|y| x.overlaps(y)))
}

#[cfg(test)]
pub(crate) mod tests;
