//! The file op kinds: apply, observe and revert (ADR 0020 "Observing and reverting", ADR 0017
//! A3, the P2-8 amendment with user decision D1 and senior-dev conditions B2 and 4).
//!
//! Every hash is taken on a guard; a link count other than 1, other R/H/S, a restricted entry
//! or a reparse point is "other", and so is the target of a replace stored in another
//! spelling than the plan's (A2-B1 review S1). `h0` is the old state of a replace (`old`), `h1` the new one
//! (content and the op's attributes). Actions happen only after the op's `RevertIntent`; a
//! foreign op deletes nothing but Rerun's own temp names by the rule of A3 ("`<tmp>` goes if
//! and only if the target does not hold the new content").
//!
//! - `CreateDir`: missing → `Before`; an empty directory with the file ID of `Done` → `After`
//!   (removed by that ID); without `Done`, the in-process rollback uses the call's result
//!   (`create_dir` returned an ID: that ID; `AlreadyExists`: foreign, never removed), the
//!   recovery removes an empty directory by its current ID (D1; a foreign empty directory of
//!   the same name created in the window between the intent and the crash is the accepted
//!   rest risk, `docs/06-security.md`); anything else `Foreign`. In a root a `Rebind` bound to
//!   another folder (P2-14), the file ID its record names for the op is the proof (none: only a
//!   missing folder is `Before`, anything else `Foreign`; user decision E-R2 a).
//! - `CreateFile` (`X` its temp name): target missing → `Before`, `X` deleted; target `h1` →
//!   `After`, deleted (expected `h1`), `X` left; anything else `Foreign`, `X` deleted unless the
//!   target holds `h1`. `AlreadyExists` from `create_new` in the same run is foreign.
//! - `ReplaceFile`: the apply sequence `S0` (`X`, `h0` → `h1`) and one restore sequence `Si`
//!   (`Yi`, `h1` → `h0`) per `RevertIntent` with a temp name. The newest `Si` whose `Yi` or
//!   `Yi.old` exists decides (else `S0`), by the table of A3 for its direction (B2). `After` is
//!   restored from the backup with the backup's SHA-256 and length as the expected ones and the
//!   old R/H/S. `X.old` holding `h0` next to a decided state is the pending cleanup of `Done`'s
//!   `old_left` and deleted with `h0` expected, after a restore only once it succeeded.
//!
//! The table of B2 is generic over the sequences of an op ([`phases`], P2-12): `S0` from its
//! start to its end state, and each `Si` from its recorded `from` to its `to` when its
//! `RevertIntent` names them (a semantic rewrite, `IniValue` only, `exec::ini`), else back from
//! `h1` to `h0`. A `.old` is compared with the start state of its own sequence, so every
//! action on a `.old` expects a known hash (A2, S1).

use std::collections::BTreeMap;

use super::bind::Proof;
use super::{Acted, ExecCtx, ExecError, Hint, roots};
use crate::fold::fold;
use crate::journal::{Before, BeforeArg, Digest, Observed, OpLog, Reverting, Semantic, TxnWriter};
use crate::path::RelPath;
use crate::plan::{ContentRef, Op, Plan, Target};
use crate::policy::root::AppSub;
use crate::prim::file_install::open_package;
use crate::sys::fs::{Attrs, EntryKind, NewFile, TmpName};
use crate::sys::{DirWrite, SysError, SysErrorKind, SysResult};

/// The root index and path of a file op (the dispatch of `exec` hands only file ops here).
fn file_target(k: u16, op: &Op) -> Result<(u16, &RelPath), ExecError> {
    match op.target() {
        Target::File { root, path, .. } => Ok((root.0, path)),
        Target::Key { .. } | Target::Value { .. } => Err(not_a_file_op(k)),
    }
}

/// A registry op handed to the file domain (a caller's error).
fn not_a_file_op(k: u16) -> ExecError {
    ExecError::Op {
        op: k,
        source: SysError::new(SysErrorKind::Other, "not a file op"),
    }
}

/// Who observes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Mode {
    /// The rollback of an apply in the same process (with [`Hint`]s; no D1).
    Rollback,
    /// A revert or recovery from the records (D1).
    Recovery,
    /// Read only (`verify`, and `After` right after an apply), newest op first: a created
    /// directory may hold the targets of the plan's later ops that will be gone (S3).
    Verify,
}

/// The write handles of the folders a plan touches, opened handle-relative from their roots
/// and cached; the folders written into are flushed before `Applied` and before every
/// `RevertDone`.
pub(super) struct Dirs<'g> {
    roots: &'g roots::Roots<'g>,
    open: Vec<(u16, RelPath, Box<dyn DirWrite + 'g>)>,
    touched: Vec<(u16, Option<RelPath>)>,
}

impl<'g> Dirs<'g> {
    pub(super) fn new(roots: &'g roots::Roots<'g>) -> Self {
        Self {
            roots,
            open: Vec::new(),
            touched: Vec::new(),
        }
    }

    /// How the created folders of `root` are proven (P2-14).
    fn proof(&self, root: u16) -> &'g Proof {
        self.roots.proof(root)
    }

    /// The write handle of `root`; the revert halted before any file op of a root that
    /// cannot run file ops, so an error here is a caller's.
    fn base(&self, root: u16) -> SysResult<&'g dyn DirWrite> {
        let g = self
            .roots
            .for_files(usize::from(root))
            .map_err(|_| SysError::new(SysErrorKind::NotFound, "root of the plan"))?;
        roots::write_handle(g)
    }

    /// The folder `dir` (`None`: the root) of `root`; `Ok(None)` if it is missing.
    fn dir(&mut self, root: u16, dir: Option<&RelPath>) -> SysResult<Option<&dyn DirWrite>> {
        let base = self.base(root)?;
        let Some(d) = dir else {
            return Ok(Some(base));
        };
        if let Some(i) = self.open.iter().position(|(r, p, _)| *r == root && p == d) {
            return Ok(self.open.get(i).map(|(_, _, h)| &**h as &dyn DirWrite));
        }
        match base.open_dir_write(d) {
            Ok(h) => {
                self.open.push((root, d.clone(), h));
                Ok(self.open.last().map(|(_, _, h)| &**h as &dyn DirWrite))
            }
            Err(e) if e.kind == SysErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// The parent folder of `path` and its last segment; `Ok(None)` if the parent is
    /// missing. `write`: the parent is flushed later.
    pub(super) fn parent(
        &mut self,
        root: u16,
        path: &RelPath,
        write: bool,
    ) -> SysResult<Option<(&dyn DirWrite, RelPath)>> {
        let name = RelPath::from_segment(path.file_name())
            .map_err(|_| SysError::new(SysErrorKind::InvalidPath, path.as_str()))?;
        let parent = path.parent();
        if write && !self.touched.iter().any(|(r, p)| *r == root && *p == parent) {
            self.touched.push((root, parent.clone()));
        }
        Ok(self.dir(root, parent.as_ref())?.map(|d| (d, name)))
    }

    /// Before `path` is removed: drops the handles on it and below it.
    fn evict(&mut self, root: u16, path: &RelPath) {
        let dir = fold(path.as_str());
        let gone = |r: u16, p: &RelPath| {
            let f = fold(p.as_str());
            r == root
                && (f == dir
                    || f.strip_prefix(&dir)
                        .is_some_and(|rest| rest.starts_with('\\')))
        };
        self.open.retain(|(r, p, _)| !gone(*r, p));
        self.touched
            .retain(|(r, p)| p.as_ref().is_none_or(|p| !gone(*r, p)));
    }

    /// Flushes every folder written into (ADR 0019): the ordered log of each volume up to its
    /// last change. Called only when no guard is held (a POSIX delete through a guard reaches
    /// the log when the guard closes).
    pub(super) fn flush(&mut self) -> SysResult<()> {
        let keys = self.touched.clone();
        for (r, p) in keys {
            if let Some(d) = self.dir(r, p.as_ref())? {
                d.flush()?;
            }
        }
        Ok(())
    }
}

fn op_err(op: u16) -> impl Fn(SysError) -> ExecError {
    move |source| ExecError::Op { op, source }
}

/// Applies op `k` (ADR 0019 write order): `CreateDir` intent → create → done; `CreateFile`
/// intent (with `X`) → `create_new` → done; `ReplaceFile` guard → old state and `users()` on
/// the guard → backup → intent (with `X` and the backup) → replace → done.
pub(super) fn apply_op(
    cx: &ExecCtx<'_>,
    w: &mut TxnWriter<'_>,
    dirs: &mut Dirs<'_>,
    k: u16,
    op: &Op,
    hints: &mut BTreeMap<u16, Hint>,
) -> Result<(), ExecError> {
    let e = op_err(k);
    let (root, path) = file_target(k, op)?;
    let Some((parent, name)) = dirs.parent(root, path, true).map_err(&e)? else {
        return Err(e(SysError::new(
            SysErrorKind::NotFound,
            format!("the folder of {path}"),
        )));
    };
    let packages = match op {
        Op::CreateDir { .. } => None,
        _ => cx
            .app
            .sub(AppSub::Packages)
            .map_err(|x| ExecError::Refused(super::Refusal::from(x)))?,
    };
    let source = |c: &ContentRef| -> Result<_, ExecError> {
        let ContentRef::Package { id, version, .. } = c;
        let pk = packages
            .as_deref()
            .ok_or_else(|| e(SysError::new(SysErrorKind::NotFound, "packages")))?;
        open_package(pk, id, version).map_err(|_| {
            e(SysError::new(
                SysErrorKind::NotFound,
                format!("package {id} {version}"),
            ))
        })
    };
    match op {
        Op::CreateDir { .. } => {
            w.intent(k, None, None)?;
            match parent.create_dir(&name) {
                Ok(id) => {
                    hints.insert(k, Hint::Dir(id));
                    w.done(k, Some(id), false)?;
                    Ok(())
                }
                Err(x) => {
                    if x.kind == SysErrorKind::AlreadyExists {
                        hints.insert(k, Hint::Foreign);
                    }
                    Err(e(x))
                }
            }
        }
        Op::CreateFile { content, attrs, .. } => {
            let ContentRef::Package {
                file, sha256, len, ..
            } = content;
            let pkg = source(content)?;
            let mut src = pkg.open_read(file).map_err(&e)?;
            let x = w.tmp();
            w.intent(k, Some(x.clone()), None)?;
            let new = NewFile {
                tmp: x,
                attrs: *attrs,
                sha256: *sha256,
                max_len: *len,
            };
            match parent.create_new(&name, &mut src, &new) {
                Ok(wr) => Ok(w.done(k, Some(wr.file_id), false)?),
                Err(x) => {
                    // `Busy` here is a collision at the final rename: someone else's file.
                    if matches!(x.kind, SysErrorKind::AlreadyExists | SysErrorKind::Busy) {
                        hints.insert(k, Hint::Foreign);
                    }
                    Err(e(x))
                }
            }
        }
        Op::ReplaceFile {
            old,
            content,
            attrs,
            ..
        } => {
            let ContentRef::Package {
                file, sha256, len, ..
            } = content;
            let mut g = parent.guard(&name).map_err(&e)?;
            // Condition 5: the guard holds exactly the old state before backup and intent,
            // under exactly the planned spelling (A2-B1: a recovery renames back onto it).
            if !g.name().same_spelling(&name) || !roots::same_state(&mut *g, old).map_err(&e)? {
                return Err(e(SysError::new(
                    SysErrorKind::Mismatch,
                    format!("{path}: changed since the preview"),
                )));
            }
            // D4 again, on the guard itself (condition 8).
            if !g.users().map_err(&e)?.is_empty() {
                return Err(e(SysError::new(
                    SysErrorKind::Busy,
                    format!("{path} is in use"),
                )));
            }
            let pkg = source(content)?;
            let mut src = pkg.open_read(file).map_err(&e)?;
            let b = w.backup(&mut *g)?;
            let x = w.tmp();
            w.intent(k, Some(x.clone()), Some(BeforeArg::Backup(b)))?;
            let new = NewFile {
                tmp: x,
                attrs: *attrs,
                sha256: *sha256,
                max_len: *len,
            };
            let r = g.replace(&old.sha256, &mut src, &new).map_err(&e)?;
            w.done(k, Some(r.new.file_id), r.old_left.is_some())?;
            Ok(())
        }
        Op::CreateKey { .. } | Op::SetValue { .. } | Op::TokenList { .. } | Op::IniValue { .. } => {
            Err(not_a_file_op(k))
        }
    }
}

/// What a file looks like to a guard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum FileSeen {
    Absent,
    File {
        sha: [u8; 32],
        len: u64,
        attrs: Attrs,
        /// The guard found it under exactly the asked spelling (A2-B1 review S1).
        exact: bool,
    },
    /// A folder, link, reparse point, restricted entry or a file with more than one link.
    Other,
}

impl FileSeen {
    /// Exactly this content, length and R/H/S.
    fn is(&self, sha: &[u8; 32], len: u64, attrs: &Attrs) -> bool {
        matches!(self, Self::File { sha: s, len: l, attrs: a, .. } if s == sha && *l == len && a == attrs)
    }

    /// This content (whatever the attributes).
    fn holds(&self, sha: &[u8; 32]) -> bool {
        matches!(self, Self::File { sha: s, .. } if s == sha)
    }

    /// A file stored in another spelling than the one asked for.
    pub(super) fn respelled(&self) -> bool {
        matches!(self, Self::File { exact: false, .. })
    }
}

/// Observes the file `name` of `parent` (absent if the parent is missing) on a guard.
pub(super) fn see_file(parent: Option<&dyn DirWrite>, name: &RelPath) -> SysResult<FileSeen> {
    let Some(d) = parent else {
        return Ok(FileSeen::Absent);
    };
    let Some(m) = d.metadata(name)? else {
        return Ok(FileSeen::Absent);
    };
    // A cloud placeholder is never opened for data (it would be downloaded): "other".
    if m.kind != EntryKind::File || m.restricted || roots::is_placeholder(&m) {
        return Ok(FileSeen::Other);
    }
    match d.guard(name) {
        Ok(mut g) => {
            let gm = g.metadata()?;
            let sha = g.sha256()?;
            Ok(FileSeen::File {
                sha,
                len: gm.len,
                attrs: gm.attrs,
                exact: g.name().same_spelling(name),
            })
        }
        Err(e) if e.kind == SysErrorKind::NotFound => Ok(FileSeen::Absent),
        Err(e)
            if matches!(
                e.kind,
                SysErrorKind::Linked | SysErrorKind::ReparsePoint | SysErrorKind::AccessDenied
            ) =>
        {
            Ok(FileSeen::Other)
        }
        Err(e) => Err(e),
    }
}

pub(super) fn exists(parent: Option<&dyn DirWrite>, name: &RelPath) -> SysResult<bool> {
    match parent {
        None => Ok(false),
        Some(d) => Ok(d.metadata(name)?.is_some()),
    }
}

/// What a directory looks like.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DirSeen {
    Absent,
    /// A plain directory: its file ID, and whether it is empty (or, for [`Mode::Verify`],
    /// holds only targets of later ops of the plan).
    Dir {
        id: u128,
        empty: bool,
    },
    Other,
}

fn see_dir(
    parent: Option<&dyn DirWrite>,
    name: &RelPath,
    allowed: &[String],
) -> SysResult<DirSeen> {
    let Some(d) = parent else {
        return Ok(DirSeen::Absent);
    };
    let Some(m) = d.metadata(name)? else {
        return Ok(DirSeen::Absent);
    };
    if m.kind != EntryKind::Dir || m.restricted || m.reparse.is_some() {
        return Ok(DirSeen::Other);
    }
    let max = allowed.len();
    let empty = match d.read_dir_limited(Some(name), max) {
        Ok(entries) => entries.iter().all(|e| allowed.contains(&fold(&e.name))),
        Err(e) if e.kind == SysErrorKind::TooLarge => false,
        Err(e) => return Err(e),
    };
    Ok(DirSeen::Dir {
        id: m.file_id,
        empty,
    })
}

/// An action of a revert, after its `RevertIntent`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Action {
    /// Remove the created directory by this file ID.
    RemoveDir(u128),
    /// Delete the target, expected hash.
    DeleteTarget([u8; 32]),
    /// Delete one of Rerun's temp names (whatever its content: ours by the journal).
    DeleteTmp(RelPath),
    /// Delete a `.old` if it holds the expected hash (else leave it); `Busy` is a pending
    /// cleanup.
    DeleteOld(RelPath, [u8; 32]),
    /// Rename a `.old` holding the expected hash back onto the target name (phase B): the
    /// name as the plan spells it, which is the stored spelling the planner saw and the apply
    /// checked on its guard (A2-B1).
    RenameBack(RelPath, [u8; 32]),
}

/// What an op observes and what its revert does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Seen {
    pub(super) observed: Observed,
    /// A restore from the backup follows the actions (a `RevertIntent` with a temp name).
    pub(super) restore: bool,
    /// A semantic rewrite follows the actions (`IniValue`, P2-12): the content observed and the
    /// content written, recorded in the `RevertIntent` with a temp name.
    pub(super) rewrite: Option<Semantic>,
    /// What a revert observed beyond the state (`IniValue`: its keys).
    pub(super) detail: Option<super::Detail>,
    pub(super) actions: Vec<Action>,
    /// Temp names that are not Rerun's any more (left and reported).
    pub(super) left: Vec<RelPath>,
}

impl Seen {
    pub(super) fn new(observed: Observed) -> Self {
        Self {
            observed,
            restore: false,
            rewrite: None,
            detail: None,
            actions: Vec::new(),
            left: Vec::new(),
        }
    }

    fn act(mut self, a: Action) -> Self {
        self.actions.push(a);
        self
    }

    fn act_if(self, on: bool, a: Action) -> Self {
        if on { self.act(a) } else { self }
    }

    fn leave_if(mut self, on: bool, name: RelPath) -> Self {
        if on {
            self.left.push(name);
        }
        self
    }
}

/// The records of a file op fit its kind (condition 5; record form of P2-10a): a `CreateDir`
/// has neither temp name nor old state, a `CreateFile` a temp name and no old state, a
/// `ReplaceFile` a temp name and the backup (`Before::Bin`) of exactly its old state; no
/// revert of a non-replace names a temp file; every `Done` has a file ID; no revert names
/// `from`/`to` (no file op reverts semantically).
pub(super) fn records_fit(op: &Op, log: &OpLog) -> bool {
    let i = &log.intent;
    let no_restore = log.reverts.iter().all(|r| r.tmp.is_none());
    let not_semantic = log
        .reverts
        .iter()
        .all(|r| r.from.is_none() && r.to.is_none());
    let file_id = log.done.is_none_or(|d| d.file_id.is_some());
    not_semantic
        && file_id
        && match op {
            Op::CreateDir { .. } => i.tmp.is_none() && i.before.is_none() && no_restore,
            Op::CreateFile { .. } => i.tmp.is_some() && i.before.is_none() && no_restore,
            Op::ReplaceFile { old, .. } => {
                i.tmp.is_some()
                    && i.before
                        == Some(Before::Bin(Digest {
                            sha256: old.sha256,
                            len: old.len,
                        }))
            }
            Op::CreateKey { .. }
            | Op::SetValue { .. }
            | Op::TokenList { .. }
            | Op::IniValue { .. } => false,
        }
}

/// The folded names in `dir` that later file ops of `plan` (after `k`, in the same root) put
/// there and that will be gone when the revert reaches `k`, by what they observed in `later`
/// (reviews S3, S-a): the target of an op observed `After` (the revert removes it) or
/// `Before` (not there), and every temp name a later op deletes (`DeleteTmp`). A later op not
/// observed, or a target left `Foreign`, stays.
fn later_children(
    plan: &Plan,
    k: u16,
    root: u16,
    dir: &RelPath,
    later: &BTreeMap<u16, super::Seen>,
) -> Vec<String> {
    let mut names = Vec::new();
    for (j, o) in plan.ops.iter().enumerate().skip(usize::from(k) + 1) {
        let Some(super::Seen::File(s)) = later.get(&super::op_ix(j)) else {
            continue;
        };
        let Target::File { root: r, path, .. } = o.target() else {
            continue;
        };
        if r.0 != root || path.parent().as_ref() != Some(dir) {
            continue;
        }
        if matches!(s.observed, Observed::After | Observed::Before) {
            names.push(fold(path.file_name()));
        }
        for a in &s.actions {
            if let Action::DeleteTmp(n) = a {
                names.push(fold(n.as_str()));
            }
        }
    }
    names
}

/// Observes op `k` (module docs; read only: guards are opened and dropped, nothing changes).
/// `later`: what the later ops observed and will do ([`Mode::Verify`] only).
#[expect(
    clippy::too_many_arguments,
    reason = "the observation of every file op kind"
)]
pub(super) fn observe(
    plan: &Plan,
    dirs: &mut Dirs<'_>,
    k: u16,
    op: &Op,
    log: &OpLog,
    mode: Mode,
    hint: Option<Hint>,
    later: &BTreeMap<u16, super::Seen>,
) -> Result<Seen, ExecError> {
    if super::trusting_records() {
        return Ok(trusted(op, log));
    }
    let e = op_err(k);
    let (root, path) = file_target(k, op)?;
    let found = dirs.parent(root, path, false).map_err(&e)?;
    let (parent, name) = match &found {
        Some((d, n)) => (Some(*d), n.clone()),
        None => (
            None,
            RelPath::from_segment(path.file_name())
                .map_err(|_| e(SysError::new(SysErrorKind::InvalidPath, path.as_str())))?,
        ),
    };
    match op {
        Op::CreateDir { .. } => {
            let allowed = if mode == Mode::Verify {
                later_children(plan, k, root, path, later)
            } else {
                Vec::new()
            };
            let seen = see_dir(parent, &name, &allowed).map_err(&e)?;
            let done = log.done.and_then(|d| d.file_id).or(match hint {
                Some(Hint::Dir(id)) => Some(id),
                _ => None,
            });
            // P2-14 (E-R2 a): in a rebound root the file ID of the `Rebind` record is the proof
            // (none: only a missing folder fits).
            let (proven, find) = match dirs.proof(root) {
                Proof::Done => (done, mode != Mode::Rollback),
                Proof::Rebound(ids) => (ids.get(&k).copied(), false),
            };
            Ok(match seen {
                DirSeen::Absent => Seen::new(Observed::Before),
                DirSeen::Dir { .. } if hint == Some(Hint::Foreign) => Seen::new(Observed::Foreign),
                DirSeen::Dir { id, empty } => {
                    // D1: without proof, the recovery takes the directory it finds.
                    let want = proven.or(find.then_some(id));
                    if want == Some(id) && empty {
                        Seen::new(Observed::After).act(Action::RemoveDir(id))
                    } else {
                        Seen::new(Observed::Foreign)
                    }
                }
                DirSeen::Other => Seen::new(Observed::Foreign),
            })
        }
        Op::CreateFile { content, attrs, .. } => {
            let x = log.intent.tmp.as_ref().map(TmpName::to_rel);
            let t = see_file(parent, &name).map_err(&e)?;
            let xs = match &x {
                Some(x) => exists(parent, x).map_err(&e)?,
                None => false,
            };
            let h1 = content.sha256();
            let holds = t.holds(h1);
            let del_x = |s: Seen| match &x {
                Some(x) => s.act_if(xs && !holds, Action::DeleteTmp(x.clone())),
                None => s,
            };
            let left_x = |s: Seen| match &x {
                Some(x) => s.leave_if(xs && holds, x.clone()),
                None => s,
            };
            Ok(
                if t.is(h1, content.len(), attrs) && hint != Some(Hint::Foreign) {
                    left_x(Seen::new(Observed::After).act(Action::DeleteTarget(*h1)))
                } else if t == FileSeen::Absent {
                    del_x(Seen::new(Observed::Before))
                } else {
                    left_x(del_x(Seen::new(Observed::Foreign)))
                },
            )
        }
        Op::ReplaceFile {
            old,
            content,
            attrs,
            ..
        } => {
            let Some(x) = log.intent.tmp.clone() else {
                return Ok(Seen::new(Observed::Foreign));
            };
            replace_seen(parent, &name, log, &x, old, content, attrs).map_err(&e)
        }
        Op::CreateKey { .. } | Op::SetValue { .. } | Op::TokenList { .. } | Op::IniValue { .. } => {
            Err(not_a_file_op(k))
        }
    }
}

/// K1: what an observation would be if it trusted the records (`Done` means `After`).
pub(super) fn trusted(op: &Op, log: &OpLog) -> Seen {
    let Some(done) = log.done else {
        return Seen::new(Observed::Before);
    };
    let s = Seen::new(Observed::After);
    match op {
        Op::CreateDir { .. } => match done.file_id {
            Some(id) => s.act(Action::RemoveDir(id)),
            None => Seen::new(Observed::Foreign),
        },
        Op::CreateFile { content, .. } => s.act(Action::DeleteTarget(*content.sha256())),
        Op::ReplaceFile { .. } | Op::IniValue { .. } => Seen { restore: true, ..s },
        Op::CreateKey { .. } | Op::SetValue { .. } | Op::TokenList { .. } => {
            Seen::new(Observed::Foreign)
        }
    }
}

/// How a target or a `.old` compares with the two states of a replace sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Is {
    Absent,
    /// The state the sequence starts from.
    From,
    /// The state the sequence ends in.
    To,
    Other,
}

/// A state a replace sequence starts from or ends in (ADR 0017 B2): content and length, and
/// for an exact state its R/H/S (`None`: whatever the attributes; the content a semantic revert
/// writes keeps the current ones, P2-12).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct State {
    pub(super) sha256: [u8; 32],
    pub(super) len: u64,
    pub(super) attrs: Option<Attrs>,
}

impl State {
    /// `s` is exactly this state.
    pub(super) fn seen_in(&self, s: &FileSeen) -> bool {
        matches!(s, FileSeen::File { sha, len, attrs, .. }
            if *sha == self.sha256 && *len == self.len && self.attrs.is_none_or(|a| a == *attrs))
    }
}

/// One replace sequence of an op (ADR 0017 B2, P2-12): its temp name and the states it goes
/// from and to. `S0` is the apply (`X`, `h0` → `h1`); each `RevertIntent` with a temp name is
/// one `Si` (`Yi`): a restore (`h1` → `h0`) or, with `from`/`to` recorded, a semantic rewrite.
#[derive(Debug, Clone)]
pub(super) struct Seq {
    pub(super) kind: SeqKind,
    pub(super) tmp: TmpName,
    pub(super) from: State,
    pub(super) to: State,
}

/// What a sequence is (senior-dev nit: explicit, not derived from the attributes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SeqKind {
    /// `S0`, the apply.
    Apply,
    /// A restore from the backup.
    Restore,
    /// A semantic rewrite with recorded `from`/`to`.
    Rewrite,
}

/// Where the deciding sequence stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Stood {
    /// At its start: phase A, or phase B once the rename back is done.
    Start,
    /// At its end: phase C (its `.old` deleted) or D.
    End,
    /// Neither: something else is there.
    Other,
}

/// What the table of B2 decides for one target, read only.
#[derive(Debug, Clone)]
pub(super) struct Settled {
    /// The deciding sequence: `None` is `S0`, `Some(i)` the `i`-th of `si`.
    pub(super) seq: Option<usize>,
    /// Where it stands.
    pub(super) stood: Stood,
    /// Its temp name exists.
    pub(super) tmp_exists: bool,
    /// Its `.old` compared with its start state.
    pub(super) old: Is,
    /// The actions, in order: a rename back, its temp name deleted, its `.old` and the `.old`
    /// of every earlier sequence holding its known start state deleted (cleanup).
    pub(super) actions: Vec<Action>,
    /// Temp names that are not Rerun's any more.
    pub(super) left: Vec<RelPath>,
}

impl Settled {
    fn act_if(&mut self, on: bool, a: Action) {
        if on {
            self.actions.push(a);
        }
    }
}

/// The sequences `Si` of an op from its records: one per `RevertIntent` with a temp name, a
/// semantic one with its recorded `from` and `to` (any R/H/S), else `to0` → `from0`.
pub(super) fn sequences(log: &OpLog, from0: State, to0: State) -> Vec<Seq> {
    log.reverts
        .iter()
        .filter_map(|r| {
            let tmp = r.tmp.clone()?;
            Some(match (r.from, r.to) {
                (Some(f), Some(t)) => Seq {
                    kind: SeqKind::Rewrite,
                    tmp,
                    from: State {
                        sha256: f.sha256,
                        len: f.len,
                        attrs: None,
                    },
                    to: State {
                        sha256: t.sha256,
                        len: t.len,
                        attrs: None,
                    },
                },
                _ => Seq {
                    kind: SeqKind::Restore,
                    tmp,
                    from: to0,
                    to: from0,
                },
            })
        })
        .collect()
}

/// The table of B2 over `S0` and the sequences `si` (module docs): the newest `Si` whose `Yi`
/// or `Yi.old` exists decides, else `S0`. `t` is the target as seen. `restored_once`: a restore
/// was started or `Done` left the `.old` of `S0` (its leftover next to the old state is then
/// cleaned up).
pub(super) fn phases(
    parent: Option<&dyn DirWrite>,
    t: &FileSeen,
    s0: &Seq,
    si: &[Seq],
    restored_once: bool,
) -> SysResult<Settled> {
    let class = |s: &Seq| {
        if *t == FileSeen::Absent {
            Is::Absent
        } else if t.respelled() {
            // S1 (review of A2-B1): a target renamed to another spelling is not the planned
            // object any more (a phase-B rename back would give it the planned spelling).
            Is::Other
        } else if s.from.seen_in(t) {
            Is::From
        } else if s.to.seen_in(t) {
            Is::To
        } else {
            Is::Other
        }
    };
    // A `.old` by hash only: it is the renamed guard of its sequence.
    let dot_old = |n: &RelPath, from: &[u8; 32]| -> SysResult<Is> {
        Ok(match see_file(parent, n)? {
            FileSeen::Absent => Is::Absent,
            s if s.holds(from) => Is::From,
            _ => Is::Other,
        })
    };
    let mut decided: Option<(usize, bool, Is)> = None;
    for (i, y) in si.iter().enumerate().rev() {
        let ys = exists(parent, &y.tmp.to_rel())?;
        let yo = dot_old(&y.tmp.old(), &y.from.sha256)?;
        if ys || yo != Is::Absent {
            decided = Some((i, ys, yo));
            break;
        }
    }
    let (seq, s, tmp_exists, old) = match decided {
        Some((i, ys, yo)) => (Some(i), &si[i], ys, yo),
        None => {
            let xs = exists(parent, &s0.tmp.to_rel())?;
            let xo = dot_old(&s0.tmp.old(), &s0.from.sha256)?;
            (None, s0, xs, xo)
        }
    };
    let mut out = Settled {
        seq,
        stood: Stood::Other,
        tmp_exists,
        old,
        actions: Vec::new(),
        left: Vec::new(),
    };
    let tmp = s.tmp.to_rel();
    let old_name = s.tmp.old();
    let f = s.from.sha256;
    match (class(s), old) {
        (Is::From, Is::Absent) => {
            out.stood = Stood::Start;
            out.act_if(tmp_exists, Action::DeleteTmp(tmp));
        }
        (Is::Absent, Is::From) => {
            out.stood = Stood::Start;
            out.actions.push(Action::RenameBack(old_name, f));
            out.act_if(tmp_exists, Action::DeleteTmp(tmp));
        }
        (Is::To, Is::From) => {
            out.stood = Stood::End;
            out.actions.push(Action::DeleteOld(old_name, f));
            if tmp_exists {
                out.left.push(tmp);
            }
        }
        (Is::To, Is::Absent) => {
            out.stood = Stood::End;
            if tmp_exists {
                out.left.push(tmp);
            }
        }
        // B2: the leftover `.old` of a completed `S0` next to the old state.
        (Is::From, Is::From) if seq.is_none() && restored_once => {
            out.stood = Stood::Start;
            out.actions.push(Action::DeleteOld(old_name, f));
            out.act_if(tmp_exists, Action::DeleteTmp(tmp));
        }
        _ => {
            // A3: the temp name goes if and only if the target does not hold the content the
            // sequence writes.
            let holds = t.holds(&s.to.sha256);
            out.act_if(tmp_exists && !holds, Action::DeleteTmp(tmp.clone()));
            if tmp_exists && holds {
                out.left.push(tmp);
            }
            return Ok(out);
        }
    }
    // Every earlier sequence completed (the ordered log of the volume put this one after
    // them), so `X` and older `Yj` are no temp files of Rerun any more; their `.old` holding
    // their known start state is cleaned up.
    if let Some(i) = seq {
        out.actions.extend(cleanup(parent, s0, &si[..i])?);
    }
    Ok(out)
}

/// The `.old` of `S0` and of every sequence in `older` that holds its known start state: the
/// cleanup once a later sequence decides.
pub(super) fn cleanup(
    parent: Option<&dyn DirWrite>,
    s0: &Seq,
    older: &[Seq],
) -> SysResult<Vec<Action>> {
    let mut v = Vec::new();
    for s in std::iter::once(s0).chain(older) {
        if see_file(parent, &s.tmp.old())?.holds(&s.from.sha256) {
            v.push(Action::DeleteOld(s.tmp.old(), s.from.sha256));
        }
    }
    Ok(v)
}

/// The replace observation (module docs, B2): `S0` from `h0` to `h1`, every `Si` a restore.
fn replace_seen(
    parent: Option<&dyn DirWrite>,
    name: &RelPath,
    log: &OpLog,
    x: &TmpName,
    old: &crate::plan::FileState,
    content: &ContentRef,
    attrs: &Attrs,
) -> SysResult<Seen> {
    let h0 = State {
        sha256: old.sha256,
        len: old.len,
        attrs: Some(old.attrs),
    };
    let h1 = State {
        sha256: *content.sha256(),
        len: content.len(),
        attrs: Some(*attrs),
    };
    let s0 = Seq {
        kind: SeqKind::Apply,
        tmp: x.clone(),
        from: h0,
        to: h1,
    };
    let si = sequences(log, h0, h1);
    let restored_once = !si.is_empty() || log.done.is_some_and(|d| d.old_left);
    let t = see_file(parent, name)?;
    let s = phases(parent, &t, &s0, &si, restored_once)?;
    // `S0` at its start is the old state, at its end the new one; a restore the other way.
    let (observed, restore) = match (s.seq, s.stood) {
        (_, Stood::Other) => (Observed::Foreign, false),
        (None, Stood::Start) | (Some(_), Stood::End) => (Observed::Before, false),
        (None, Stood::End) | (Some(_), Stood::Start) => (Observed::After, true),
    };
    Ok(Seen {
        restore,
        actions: s.actions,
        left: s.left,
        ..Seen::new(observed)
    })
}

/// Carries out one action of a revert.
pub(super) fn run_action(
    dirs: &mut Dirs<'_>,
    root: u16,
    path: &RelPath,
    a: &Action,
    done: &mut Acted,
    e: &impl Fn(SysError) -> ExecError,
) -> Result<(), ExecError> {
    if let Action::RemoveDir(_) = a {
        dirs.evict(root, path);
    }
    let Some((parent, name)) = dirs.parent(root, path, true).map_err(e)? else {
        return Ok(());
    };
    match a {
        Action::RemoveDir(id) => parent.remove_dir(&name, *id).map_err(e)?,
        Action::DeleteTarget(h) => parent.guard(&name).and_then(|g| g.delete(h)).map_err(e)?,
        Action::DeleteTmp(n) => match parent.guard(n) {
            Ok(mut g) => {
                let h = g.sha256().map_err(e)?;
                g.delete(&h).map_err(e)?;
            }
            Err(x) if x.kind == SysErrorKind::NotFound => {}
            Err(x)
                if matches!(
                    x.kind,
                    SysErrorKind::Linked | SysErrorKind::ReparsePoint | SysErrorKind::AccessDenied
                ) =>
            {
                done.left.push(n.clone());
            }
            Err(x) => return Err(e(x)),
        },
        Action::DeleteOld(n, h) => match parent.guard(n) {
            Ok(mut g) => {
                if g.sha256().map_err(e)? != *h {
                    done.left.push(n.clone());
                } else {
                    match g.delete(h) {
                        Ok(()) => {}
                        Err(x) if x.kind == SysErrorKind::Busy => {
                            done.old_left = true;
                            done.left.push(n.clone());
                        }
                        Err(x) => return Err(e(x)),
                    }
                }
            }
            Err(x) if x.kind == SysErrorKind::NotFound => {}
            Err(x) => return Err(e(x)),
        },
        Action::RenameBack(n, h) => {
            let mut g = parent.guard(n).map_err(e)?;
            if g.sha256().map_err(e)? != *h {
                return Err(e(SysError::new(
                    SysErrorKind::Mismatch,
                    format!("{n}: not the expected content"),
                )));
            }
            g.rename_to(&name).map_err(e)?;
        }
    }
    Ok(())
}

/// Carries out the actions of `seen` and, if it says so, the restore with temp name `y`.
pub(super) fn act<W: Reverting>(
    w: &W,
    dirs: &mut Dirs<'_>,
    k: u16,
    op: &Op,
    seen: &Seen,
    y: Option<TmpName>,
) -> Result<Acted, ExecError> {
    let e = op_err(k);
    let (root, path) = file_target(k, op)?;
    let mut done = Acted {
        old_left: false,
        left: seen.left.clone(),
    };
    // S1 (review): with a restore, the `.old` holding `h0` goes only after the restore
    // succeeded; a damaged backup must not cost the last copy of the old content. The same
    // for a rewrite (P2-12): every `.old` goes once it succeeded.
    let writes = seen.restore || seen.rewrite.is_some();
    let deferred = |a: &&Action| writes && matches!(a, Action::DeleteOld(..));
    for a in seen.actions.iter().filter(|a| !deferred(a)) {
        run_action(dirs, root, path, a, &mut done, &e)?;
    }
    if let Some(sem) = &seen.rewrite {
        super::ini::rewrite(dirs, k, op, sem, y.clone(), &mut done)?;
    }
    if seen.restore {
        // The old R/H/S and the new content expected at the target.
        let (old_attrs, expected) = match op {
            Op::ReplaceFile { old, content, .. } => (old.attrs, *content.sha256()),
            Op::IniValue { old, new, .. } => (old.attrs, new.sha256),
            _ => {
                return Err(e(SysError::new(
                    SysErrorKind::Other,
                    "a restore of no replace",
                )));
            }
        };
        let b = w
            .ops()
            .get(&k)
            .and_then(|l| l.intent.bin())
            .ok_or_else(|| e(SysError::new(SysErrorKind::NotFound, "the backup")))?;
        let y = y.ok_or_else(|| {
            e(SysError::new(
                SysErrorKind::Other,
                "a restore without its temp name",
            ))
        })?;
        let Some((parent, name)) = dirs.parent(root, path, true).map_err(&e)? else {
            return Err(e(SysError::new(SysErrorKind::NotFound, path.as_str())));
        };
        let g = parent.guard(&name).map_err(&e)?;
        // The planned spelling, as observed (S1): another one since is a change.
        if !g.name().same_spelling(&name) {
            return Err(e(SysError::new(
                SysErrorKind::Mismatch,
                format!("{path}: renamed since it was observed"),
            )));
        }
        // D4 on the guard before the restore (symmetric to the apply).
        if !g.users().map_err(&e)?.is_empty() {
            return Err(e(SysError::new(
                SysErrorKind::Busy,
                format!("{path} is in use"),
            )));
        }
        let attrs = if super::restoring_without_attrs() {
            Attrs::default()
        } else {
            old_attrs
        };
        let mut src = w.backup_reader(k)?;
        // The backup's hash and length are the expected ones: what is written is checked
        // while it is written, nothing earlier (TOCTOU).
        let new = NewFile {
            tmp: y,
            attrs,
            sha256: b.sha256,
            max_len: b.len,
        };
        let r = g.replace(&expected, &mut src, &new).map_err(&e)?;
        drop(src);
        if let Some(t) = r.old_left {
            // Step 8 failed: one more try on a fresh guard (expected `h1`); still `Busy` (the
            // file is mapped) leaves it as a pending cleanup the report names.
            let again = parent.guard(&t.old()).and_then(|mut g| match g.sha256() {
                Ok(h) if h == expected => g.delete(&h),
                Ok(_) => Err(SysError::new(SysErrorKind::Mismatch, t.as_str())),
                Err(x) => Err(x),
            });
            if again.is_err() {
                done.old_left = true;
                done.left.push(t.old());
            }
        }
    }
    for a in seen.actions.iter().filter(|a| deferred(a)) {
        run_action(dirs, root, path, a, &mut done, &e)?;
    }
    Ok(done)
}
