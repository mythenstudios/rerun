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
//!   rest risk, `docs/06-security.md`); anything else `Foreign`.
//! - `CreateFile` (`X` its temp name): target missing → `Before`, `X` deleted; target `h1` →
//!   `After`, deleted (expected `h1`), `X` left; anything else `Foreign`, `X` deleted unless the
//!   target holds `h1`. `AlreadyExists` from `create_new` in the same run is foreign.
//! - `ReplaceFile`: the apply sequence `S0` (`X`, `h0` → `h1`) and one restore sequence `Si`
//!   (`Yi`, `h1` → `h0`) per `RevertIntent` with a temp name. The newest `Si` whose `Yi` or
//!   `Yi.old` exists decides (else `S0`), by the table of A3 for its direction (B2). `After` is
//!   restored from the backup with the backup's SHA-256 and length as the expected ones and the
//!   old R/H/S. `X.old` holding `h0` next to a decided state is the pending cleanup of `Done`'s
//!   `old_left` and deleted with `h0` expected, after a restore only once it succeeded.

use std::collections::BTreeMap;

use super::{Acted, ExecCtx, ExecError, Hint, roots};
use crate::fold::fold;
use crate::journal::{BackupRef, Observed, OpLog, Reverting, TxnWriter};
use crate::path::RelPath;
use crate::plan::{ContentRef, Op, Plan, Target};
use crate::policy::root::{AppSub, GameDir};
use crate::prim::file_install::open_package;
use crate::sys::fs::{Attrs, EntryKind, NewFile, TmpName};
use crate::sys::{DirWrite, SysError, SysErrorKind, SysResult};

/// The root index and path of a file op (the dispatch of `exec` hands only file ops here).
fn file_target(op: &Op) -> (u16, &RelPath) {
    match op.target() {
        Target::File { root, path, .. } => (root.0, path),
    }
}

/// Who observes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Mode {
    /// The rollback of an apply in the same process (with [`Hint`]s; no D1).
    Rollback,
    /// A revert or recovery from the records (D1).
    Recovery,
    /// Read only (`verify`, and `After` right after an apply): a created directory may hold
    /// the targets of the plan's later ops.
    Verify,
}

/// The write handles of the folders a plan touches, opened handle-relative from their roots
/// and cached; the folders written into are flushed before `Applied` and before every
/// `RevertDone`.
pub(super) struct Dirs<'g> {
    games: &'g [GameDir<'g>],
    open: Vec<(u16, RelPath, Box<dyn DirWrite + 'g>)>,
    touched: Vec<(u16, Option<RelPath>)>,
}

impl<'g> Dirs<'g> {
    pub(super) fn new(games: &'g [GameDir<'g>]) -> Self {
        Self {
            games,
            open: Vec::new(),
            touched: Vec::new(),
        }
    }

    fn base(&self, root: u16) -> SysResult<&'g dyn DirWrite> {
        let g = self
            .games
            .get(usize::from(root))
            .ok_or_else(|| SysError::new(SysErrorKind::NotFound, "root of the plan"))?;
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
    let (root, path) = file_target(op);
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
                    w.done(k, id, false)?;
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
                Ok(wr) => Ok(w.done(k, wr.file_id, false)?),
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
            w.intent(k, Some(x.clone()), Some(b))?;
            let new = NewFile {
                tmp: x,
                attrs: *attrs,
                sha256: *sha256,
                max_len: *len,
            };
            let r = g.replace(&old.sha256, &mut src, &new).map_err(&e)?;
            w.done(k, r.new.file_id, r.old_left.is_some())?;
            Ok(())
        }
    }
}

/// What a file looks like to a guard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FileSeen {
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
    fn respelled(&self) -> bool {
        matches!(self, Self::File { exact: false, .. })
    }
}

/// Observes the file `name` of `parent` (absent if the parent is missing) on a guard.
fn see_file(parent: Option<&dyn DirWrite>, name: &RelPath) -> SysResult<FileSeen> {
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

fn exists(parent: Option<&dyn DirWrite>, name: &RelPath) -> SysResult<bool> {
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
enum Action {
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
    actions: Vec<Action>,
    /// Temp names that are not Rerun's any more (left and reported).
    left: Vec<RelPath>,
}

impl Seen {
    fn new(observed: Observed) -> Self {
        Self {
            observed,
            restore: false,
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

/// The records of a file op fit its kind (condition 5): a `CreateDir` has neither temp name
/// nor backup, a `CreateFile` a temp name and no backup, a `ReplaceFile` a temp name and the
/// backup of exactly its old state; no revert of a non-replace names a temp file.
pub(super) fn records_fit(op: &Op, log: &OpLog) -> bool {
    let i = &log.intent;
    let no_restore = log.reverts.iter().all(Option::is_none);
    match op {
        Op::CreateDir { .. } => i.tmp.is_none() && i.backup.is_none() && no_restore,
        Op::CreateFile { .. } => i.tmp.is_some() && i.backup.is_none() && no_restore,
        Op::ReplaceFile { old, .. } => {
            i.tmp.is_some()
                && i.backup
                    == Some(BackupRef {
                        sha256: old.sha256,
                        len: old.len,
                    })
        }
    }
}

/// The folded names of the direct children of `dir` that later file ops of `plan` (after
/// `k`, in the same root) create.
fn later_children(plan: &Plan, k: u16, root: u16, dir: &RelPath) -> Vec<String> {
    plan.ops
        .iter()
        .skip(usize::from(k) + 1)
        .filter_map(|o| match o.target() {
            Target::File { root: r, path, .. }
                if r.0 == root && path.parent().as_ref() == Some(dir) =>
            {
                Some(fold(path.file_name()))
            }
            Target::File { .. } => None,
        })
        .collect()
}

/// Observes op `k` (module docs; read only: guards are opened and dropped, nothing changes).
pub(super) fn observe(
    plan: &Plan,
    dirs: &mut Dirs<'_>,
    k: u16,
    op: &Op,
    log: &OpLog,
    mode: Mode,
    hint: Option<Hint>,
) -> Result<Seen, ExecError> {
    if super::trusting_records() {
        return Ok(trusted(op, log));
    }
    let e = op_err(k);
    let (root, path) = file_target(op);
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
                later_children(plan, k, root, path)
            } else {
                Vec::new()
            };
            let seen = see_dir(parent, &name, &allowed).map_err(&e)?;
            let proven = log.done.map(|d| d.file_id).or(match hint {
                Some(Hint::Dir(id)) => Some(id),
                _ => None,
            });
            Ok(match seen {
                DirSeen::Absent => Seen::new(Observed::Before),
                DirSeen::Dir { .. } if hint == Some(Hint::Foreign) => Seen::new(Observed::Foreign),
                DirSeen::Dir { id, empty } => {
                    // D1: without proof, the recovery takes the directory it finds.
                    let want = proven.or((mode != Mode::Rollback).then_some(id));
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
    }
}

/// K1: what an observation would be if it trusted the records (`Done` means `After`).
fn trusted(op: &Op, log: &OpLog) -> Seen {
    let Some(done) = log.done else {
        return Seen::new(Observed::Before);
    };
    let s = Seen::new(Observed::After);
    match op {
        Op::CreateDir { .. } => s.act(Action::RemoveDir(done.file_id)),
        Op::CreateFile { content, .. } => s.act(Action::DeleteTarget(*content.sha256())),
        Op::ReplaceFile { .. } => Seen { restore: true, ..s },
    }
}

/// How a target or a `.old` compares with the two states of a replace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Is {
    Absent,
    /// The state the sequence starts from.
    From,
    /// The state the sequence ends in.
    To,
    Other,
}

/// The replace observation (module docs, B2).
fn replace_seen(
    parent: Option<&dyn DirWrite>,
    name: &RelPath,
    log: &OpLog,
    x: &TmpName,
    old: &crate::plan::FileState,
    content: &ContentRef,
    attrs: &Attrs,
) -> SysResult<Seen> {
    let h0 = old.sha256;
    let h1 = *content.sha256();
    let t = see_file(parent, name)?;
    // S1 (review of A2-B1): a target someone renamed to another spelling is not the planned
    // object any more (a phase-B rename back would give it the planned spelling): "other",
    // so `Foreign`, in `S0` and in every `Si`.
    let target = if t == FileSeen::Absent {
        Is::Absent
    } else if t.respelled() {
        Is::Other
    } else if t.is(&h0, old.len, &old.attrs) {
        Is::From
    } else if t.is(&h1, content.len(), attrs) {
        Is::To
    } else {
        Is::Other
    };
    // A `.old` by hash only: it is the renamed guard of its sequence.
    let dot_old = |n: &RelPath, from: &[u8; 32]| -> SysResult<Is> {
        Ok(match see_file(parent, n)? {
            FileSeen::Absent => Is::Absent,
            s if s.holds(from) => Is::From,
            _ => Is::Other,
        })
    };
    let x_old = dot_old(&x.old(), &h0)?;
    let x_rel = x.to_rel();
    let x_exists = exists(parent, &x_rel)?;
    // The restores, newest first; the first one with a trace decides (B2).
    let restores: Vec<&TmpName> = log.reverts.iter().flatten().collect();
    let mut decided: Option<(usize, bool, Is)> = None;
    for (i, y) in restores.iter().enumerate().rev() {
        let ys = exists(parent, &y.to_rel())?;
        let yo = dot_old(&y.old(), &h1)?;
        if ys || yo != Is::Absent {
            decided = Some((i, ys, yo));
            break;
        }
    }
    let Some((i, ys, yo)) = decided else {
        // S0: h0 → h1 with X.
        let del_x = |s: Seen, on: bool| s.act_if(x_exists && on, Action::DeleteTmp(x_rel.clone()));
        let restored_once = !restores.is_empty() || log.done.is_some_and(|d| d.old_left);
        return Ok(match (target, x_old) {
            (Is::From, Is::Absent) => del_x(Seen::new(Observed::Before), true),
            (Is::Absent, Is::From) => del_x(
                Seen::new(Observed::Before).act(Action::RenameBack(x.old(), h0)),
                true,
            ),
            (Is::To, Is::From) => Seen {
                restore: true,
                ..Seen::new(Observed::After).act(Action::DeleteOld(x.old(), h0))
            }
            .leave_if(x_exists, x_rel.clone()),
            (Is::To, Is::Absent) => Seen {
                restore: true,
                ..Seen::new(Observed::After)
            }
            .leave_if(x_exists, x_rel.clone()),
            // B2: the leftover `.old` of a completed sequence next to the old state.
            (Is::From, Is::From) if restored_once => del_x(
                Seen::new(Observed::Before).act(Action::DeleteOld(x.old(), h0)),
                true,
            ),
            _ => {
                let holds = t.holds(&h1);
                del_x(Seen::new(Observed::Foreign), !holds)
                    .leave_if(x_exists && holds, x_rel.clone())
            }
        });
    };
    // Si: h1 → h0 with Yi. Every earlier sequence completed (the ordered log of the volume
    // put Yi after them), so X and older Yj are no temp files of Rerun any more.
    let y = restores[i];
    let y_rel = y.to_rel();
    let y_old = y.old();
    let cleanup = |mut s: Seen| -> SysResult<Seen> {
        if x_old == Is::From {
            s = s.act(Action::DeleteOld(x.old(), h0));
        }
        for older in &restores[..i] {
            if dot_old(&older.old(), &h1)? == Is::From {
                s = s.act(Action::DeleteOld(older.old(), h1));
            }
        }
        Ok(s)
    };
    // In Si, "from" is h1 and "to" is h0.
    let target_i = match target {
        Is::From => Is::To,
        Is::To => Is::From,
        o => o,
    };
    Ok(match (target_i, yo) {
        (Is::From, Is::Absent) => cleanup(Seen {
            restore: true,
            ..Seen::new(Observed::After).act_if(ys, Action::DeleteTmp(y_rel.clone()))
        })?,
        (Is::Absent, Is::From) => cleanup(Seen {
            restore: true,
            ..Seen::new(Observed::After)
                .act(Action::RenameBack(y_old, h1))
                .act_if(ys, Action::DeleteTmp(y_rel.clone()))
        })?,
        (Is::To, Is::From) => cleanup(
            Seen::new(Observed::Before)
                .act(Action::DeleteOld(y_old, h1))
                .leave_if(ys, y_rel.clone()),
        )?,
        (Is::To, Is::Absent) => cleanup(Seen::new(Observed::Before).leave_if(ys, y_rel.clone()))?,
        _ => {
            let holds = t.holds(&h0);
            Seen::new(Observed::Foreign)
                .act_if(ys && !holds, Action::DeleteTmp(y_rel.clone()))
                .leave_if(ys && holds, y_rel.clone())
        }
    })
}

/// Carries out one action of a revert.
fn run_action(
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
    let (root, path) = file_target(op);
    let mut done = Acted {
        old_left: false,
        left: seen.left.clone(),
    };
    // S1 (review): with a restore, the `.old` holding `h0` goes only after the restore
    // succeeded; a damaged backup must not cost the last copy of the old content.
    let deferred = |a: &&Action| seen.restore && matches!(a, Action::DeleteOld(..));
    for a in seen.actions.iter().filter(|a| !deferred(a)) {
        run_action(dirs, root, path, a, &mut done, &e)?;
    }
    if seen.restore {
        let Op::ReplaceFile { old, content, .. } = op else {
            return Err(e(SysError::new(
                SysErrorKind::Other,
                "a restore of no replace",
            )));
        };
        let b = w
            .ops()
            .get(&k)
            .and_then(|l| l.intent.backup)
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
            old.attrs
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
        let r = g.replace(content.sha256(), &mut src, &new).map_err(&e)?;
        drop(src);
        if let Some(t) = r.old_left {
            // Step 8 failed: one more try on a fresh guard (expected `h1`); still `Busy` (the
            // file is mapped) leaves it as a pending cleanup the report names.
            let again = parent.guard(&t.old()).and_then(|mut g| match g.sha256() {
                Ok(h) if h == *content.sha256() => g.delete(&h),
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
