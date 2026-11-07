//! `IniValue` (P2-12; ADR 0020 amendment P2-12, ADR 0021, ADR 0017 and ADR 0019 amendments
//! P2-12; user decisions 6c, E1 b, E2 a, E5 a; senior-dev conditions M1, S2, S6): apply,
//! observe and revert the keys of an INI file.
//!
//! - **Apply** (as `ReplaceFile`): the guard holds exactly the old state in the planned
//!   spelling and nobody uses the file; its bytes are read from the guard (bounded),
//!   `policy::ini::edit` must give exactly the planned new content (`Mismatch` before the
//!   intent otherwise); then the backup, the intent with `X`, and the replace sequence with the
//!   edited bytes as the source and the old R/H/S (`NewFile { X, old.attrs, new }`). A `Mismatch`
//!   of the replace is hint `NotWritten`. `exec` never forms INI text: every byte written comes
//!   from `policy::ini::edit`, `policy::ini::unedit` or the hashed backup.
//! - **Records:** `Intent { tmp: X, before: Bin(old) }`, `Done` with a file ID; a `RevertIntent`
//!   names `from`/`to` only for a rewrite, then always with a temp name, `from != to`, both at
//!   most 1 MiB ([`records_fit`]). Before a revert ([`binds`], P2-11 S-1 carried over): the
//!   backup (hashed against the intent) edited with the head's edits must give exactly the
//!   head's new content, else `Blocked`; a tampered head cannot make a revert of a drifted file
//!   write other old values than the backup proves. The path is not bound (`docs/06`, row 14).
//! - **Observation, stage 1** (`file::phases`, ADR 0017 amendment P2-12): `S0` (`X`, old →
//!   new, exact), one `Si` per `RevertIntent` with a temp name (a restore new → old, exact; a
//!   rewrite `from` → `to`, content only). Stage 1 settles traces: phase B renames back, C/D
//!   clean up. Besides the table of A3: (M1) a target other than old and new next to `X.old`
//!   holding the old content, with `X` gone and `Done` recorded, is a completed apply the game
//!   rewrote since: `X.old` is deleted (expected the old hash) and stage 2 follows; with `X`
//!   still there (phase B, the game made a new file) or without `Done` it is `Foreign`. (S2) Only
//!   Rerun's own temp name and no `.old` next to another target: the temp name is deleted and
//!   stage 2 follows. Any other `.old`, a link, folder, reparse point or another spelling at the
//!   target is `Foreign` (S6: a `.old` holding the file as it was before a step of Rerun is
//!   named in the report as the file before that step, `Detail::Ini::before_step`; only
//!   before the apply is it the user's file as Rerun found it, which the backup holds anyway).
//! - **Stage 2** (`st` the content at the target after stage 1; first matching row):
//!
//! | # | `st` | Observed / act |
//! |---|---|---|
//! | 2 | the `to` of a rewrite (its phase C/D) | `Drifted` (cleanup only) |
//! | 3 | exactly `new` (content, length, old R/H/S), no `NotWritten` | `After` / restore the backup |
//! | 4 | exactly `old` | `Before` |
//! | 5 | anything else with `NotWritten` | `Foreign` |
//! | 6 | missing, no trace (E2 a) | `Drifted`, nothing written |
//! | 7 | `unedit` refuses it (encoding, NUL, CR, over 1 MiB, ambiguous at a target) | `Foreign` |
//! | 8 | some key `New` | `Drifted` / rewrite `Semantic { from: st, to: unedit(st) }` |
//! | 9 | no key `New` | `Drifted`, nothing written |
//!
//!   A rewrite at its start (phase A, or B after the rename back) goes through rows 3 to 9 again
//!   with `st = from` (a fresh temp name; `to` is deterministic). Only row 3 gives the state
//!   before the first change; row 8 gives "the current file minus Rerun's keys" (D10, E1 b:
//!   a key someone changed stays, `Changed`), and the preview says so (`INI_NOTE`).
//! - **Rewrite** ([`rewrite`]): on a guard of the target in the planned spelling, nobody using
//!   it, the bytes read must hash to `from`, `unedit` of them to `to` (else `Mismatch`, the op
//!   stays open); then the replace sequence with `Yi` and the current R/H/S, expected `from`; a
//!   left `.old` gets one more delete, expected `from`.

use std::collections::BTreeMap;
use std::io::Read;

use sha2::{Digest as _, Sha256};

use super::file::{self, Action, Dirs, FileSeen, Is, Seq, SeqKind, State, Stood};
use super::{Acted, BeforeStep, Detail, ExecError, Hint, IniKey, RerunStep, roots};
use crate::journal::{
    Before, BeforeArg, Digest, JournalError, Observed, OpLog, Semantic, TxnWriter,
};
use crate::path::RelPath;
use crate::plan::{Op, Plan};
use crate::policy::ini::{self, IniEdit, KeyState, MAX_INI_BYTES};
use crate::sys::fs::FileGuard;
use crate::sys::fs::{EntryKind, NewFile, TmpName};
use crate::sys::{DirWrite, SysError, SysErrorKind, SysResult};

/// K-I1 (tests): the `RevertIntent` of a rewrite without `from`/`to`.
pub(super) fn unrecorded() -> bool {
    #[cfg(test)]
    return knob::is_unrecorded();
    #[cfg(not(test))]
    false
}

fn op_err(k: u16) -> impl Fn(SysError) -> ExecError {
    move |source| ExecError::Op { op: k, source }
}

fn not_ini(k: u16) -> ExecError {
    ExecError::Op {
        op: k,
        source: SysError::new(SysErrorKind::Other, "not an INI op"),
    }
}

fn mismatch(k: u16, what: String) -> ExecError {
    ExecError::Op {
        op: k,
        source: SysError::new(SysErrorKind::Mismatch, what),
    }
}

/// The digest of `b`.
fn digest(b: &[u8]) -> Digest {
    Digest {
        sha256: Sha256::digest(b).into(),
        len: u64::try_from(b.len()).unwrap_or(u64::MAX),
    }
}

/// At most `max` bytes of the guarded file from offset 0; more is `TooLarge`.
fn read_guard(g: &mut dyn FileGuard, max: u64) -> SysResult<Vec<u8>> {
    let name = g.name().as_str().to_owned();
    let mut buf = Vec::new();
    g.reader()?
        .take(max.saturating_add(1))
        .read_to_end(&mut buf)
        .map_err(|e| SysError::io(&e, &name))?;
    if u64::try_from(buf.len()).map_or(true, |n| n > max) {
        return Err(SysError::too_large(&name, max));
    }
    Ok(buf)
}

fn max_ini() -> u64 {
    u64::try_from(MAX_INI_BYTES).unwrap_or(u64::MAX)
}

/// Applies `IniValue` op `k` (module docs).
pub(super) fn apply_op(
    w: &mut TxnWriter<'_>,
    dirs: &mut Dirs<'_>,
    k: u16,
    op: &Op,
    hints: &mut BTreeMap<u16, Hint>,
) -> Result<(), ExecError> {
    let e = op_err(k);
    let Op::IniValue {
        root,
        path,
        old,
        new,
        edits,
    } = op
    else {
        return Err(not_ini(k));
    };
    let Some((parent, name)) = dirs.parent(root.0, path, true).map_err(&e)? else {
        return Err(e(SysError::new(
            SysErrorKind::NotFound,
            format!("the folder of {path}"),
        )));
    };
    let mut g = parent.guard(&name).map_err(&e)?;
    // Condition 5 and A2-B1, as for a replace.
    if !g.name().same_spelling(&name) || !roots::same_state(&mut *g, old).map_err(&e)? {
        return Err(mismatch(k, format!("{path}: changed since the preview")));
    }
    if !g.users().map_err(&e)?.is_empty() {
        return Err(e(SysError::new(
            SysErrorKind::Busy,
            format!("{path} is in use"),
        )));
    }
    let bytes = read_guard(&mut *g, old.len).map_err(&e)?;
    if digest(&bytes)
        != (Digest {
            sha256: old.sha256,
            len: old.len,
        })
    {
        return Err(mismatch(k, format!("{path}: changed while it was read")));
    }
    let out = ini::edit(&bytes, edits)
        .map_err(|x| mismatch(k, format!("{path}: the INI editor refuses it: {x}")))?;
    if digest(&out)
        != (Digest {
            sha256: new.sha256,
            len: new.len,
        })
    {
        return Err(mismatch(
            k,
            format!("{path}: edits to another content than planned"),
        ));
    }
    let b = w.backup(&mut *g)?;
    let x = w.tmp();
    w.intent(k, Some(x.clone()), Some(BeforeArg::Backup(b)))?;
    let nf = NewFile {
        tmp: x,
        attrs: old.attrs,
        sha256: new.sha256,
        max_len: new.len,
    };
    match g.replace(&old.sha256, &mut &out[..], &nf) {
        Ok(r) => Ok(w.done(k, Some(r.new.file_id), r.old_left.is_some())?),
        Err(x) => {
            // `Mismatch`: nothing was written in this run.
            if x.kind == SysErrorKind::Mismatch {
                hints.insert(k, Hint::NotWritten);
            }
            Err(e(x))
        }
    }
}

/// A rewrite's digests are what [`records_fit`] allows (security review S-1): both at most
/// 1 MiB and different. `unedit` bounds its result, so this holds for every rewrite stage 2
/// decides; the revert loop checks it again before the `RevertIntent` is written.
pub(super) fn semantic_fits(s: &Semantic) -> bool {
    let max = max_ini();
    s.from != s.to && s.from.len <= max && s.to.len <= max
}

/// The records of an `IniValue` fit it (module docs).
pub(super) fn records_fit(op: &Op, log: &OpLog) -> bool {
    let Op::IniValue { old, .. } = op else {
        return false;
    };
    let i = &log.intent;
    i.tmp.is_some()
        && i.before
            == Some(Before::Bin(Digest {
                sha256: old.sha256,
                len: old.len,
            }))
        && log.done.is_none_or(|d| d.file_id.is_some())
        && log.reverts.iter().all(|r| match (r.from, r.to) {
            (None, None) => true,
            (Some(f), Some(t)) => r.tmp.is_some() && semantic_fits(&Semantic { from: f, to: t }),
            _ => false,
        })
}

/// Reads the checked backup of an op: its index, the digest of its intent, a bound.
pub(super) type BeforeBytes<'a> = dyn Fn(u16, &Digest, u64) -> Result<Vec<u8>, JournalError> + 'a;

/// The binding of a recorded head to its backups (module docs): every `IniValue` with an intent
/// edits its backup (`before`, hashed against the intent) to exactly its recorded new content.
/// `Ok(false)`: the head does not fit, nothing may be reverted from it.
pub(super) fn binds(
    plan: &Plan,
    ops: &BTreeMap<u16, OpLog>,
    before: &BeforeBytes<'_>,
) -> Result<bool, JournalError> {
    if knob::is_unbound() {
        return Ok(true);
    }
    for (k, log) in ops {
        let Some(Op::IniValue { new, edits, .. }) = plan.ops.get(usize::from(*k)) else {
            continue;
        };
        let Some(Before::Bin(d)) = &log.intent.before else {
            return Ok(false);
        };
        let b = before(*k, d, max_ini())?;
        match ini::edit(&b, edits) {
            Ok(out)
                if digest(&out)
                    == (Digest {
                        sha256: new.sha256,
                        len: new.len,
                    }) => {}
            _ => return Ok(false),
        }
    }
    Ok(true)
}

/// What a guard sees of an INI file: the file and, if it is at most 1 MiB, its bytes (hashed:
/// the state is the hash of these bytes).
fn see_ini(
    parent: Option<&dyn DirWrite>,
    name: &RelPath,
) -> SysResult<(FileSeen, Option<Vec<u8>>)> {
    let Some(d) = parent else {
        return Ok((FileSeen::Absent, None));
    };
    let Some(m) = d.metadata(name)? else {
        return Ok((FileSeen::Absent, None));
    };
    if m.kind != EntryKind::File || m.restricted || roots::is_placeholder(&m) {
        return Ok((FileSeen::Other, None));
    }
    match d.guard(name) {
        Ok(mut g) => {
            let gm = g.metadata()?;
            let exact = g.name().same_spelling(name);
            // Over 1 MiB no state of the op can match (every one is at most 1 MiB) and stage
            // 2 refuses it: "other", never hashed (security review nit 2).
            let bytes = match read_guard(&mut *g, max_ini()) {
                Ok(b) => b,
                Err(e) if e.kind == SysErrorKind::TooLarge => return Ok((FileSeen::Other, None)),
                Err(e) => return Err(e),
            };
            let dg = digest(&bytes);
            let (sha, len, bytes) = (dg.sha256, dg.len, Some(bytes));
            Ok((
                FileSeen::File {
                    sha,
                    len,
                    attrs: gm.attrs,
                    exact,
                },
                bytes,
            ))
        }
        Err(e) if e.kind == SysErrorKind::NotFound => Ok((FileSeen::Absent, None)),
        Err(e)
            if matches!(
                e.kind,
                SysErrorKind::Linked | SysErrorKind::ReparsePoint | SysErrorKind::AccessDenied
            ) =>
        {
            Ok((FileSeen::Other, None))
        }
        Err(e) => Err(e),
    }
}

/// The content stage 2 decides on (module docs): `None` if the target is missing.
struct St {
    seen: FileSeen,
    bytes: Option<Vec<u8>>,
}

/// The detail of an op from the key states (in the order of its edits).
fn detail(edits: &[IniEdit], keys: &[KeyState], before_step: Option<BeforeStep>) -> Option<Detail> {
    Some(Detail::Ini {
        keys: edits
            .iter()
            .zip(keys)
            .map(|(e, s)| IniKey {
                section: e.section.clone(),
                key: e.key.clone(),
                state: *s,
            })
            .collect(),
        before_step,
    })
}

/// Stage 2 (module docs, rows 3 to 9) on `st`, after the actions `pre`.
fn stage2(op: &Op, st: &St, hint: Option<Hint>, pre: file::Seen) -> file::Seen {
    let Op::IniValue {
        old, new, edits, ..
    } = op
    else {
        return file::Seen::new(Observed::Foreign);
    };
    let n = edits.len();
    let with = |mut s: file::Seen, observed: Observed| {
        s.observed = observed;
        s
    };
    let exact_new = State {
        sha256: new.sha256,
        len: new.len,
        attrs: Some(old.attrs),
    };
    let exact_old = State {
        sha256: old.sha256,
        len: old.len,
        attrs: Some(old.attrs),
    };
    let written = hint != Some(Hint::NotWritten);
    if exact_new.seen_in(&st.seen) && written {
        let mut s = with(pre, Observed::After);
        s.restore = true;
        s.detail = detail(edits, &vec![KeyState::New; n], None);
        return s;
    }
    if exact_old.seen_in(&st.seen) {
        let mut s = with(pre, Observed::Before);
        s.detail = detail(edits, &vec![KeyState::Old; n], None);
        return s;
    }
    if !written {
        return with(pre, Observed::Foreign);
    }
    if st.seen == FileSeen::Absent {
        // E2 a: the game or the user removed the file; nothing of Rerun's is left.
        return with(pre, Observed::Drifted);
    }
    let Some(bytes) = &st.bytes else {
        return with(pre, Observed::Foreign);
    };
    let Ok(u) = ini::unedit(bytes, edits) else {
        return with(pre, Observed::Foreign);
    };
    if knob::is_changed_foreign() && u.keys.contains(&KeyState::Changed) {
        return with(pre, Observed::Foreign);
    }
    let mut s = with(pre, Observed::Drifted);
    s.detail = detail(edits, &u.keys, None);
    if u.writes() {
        s.rewrite = Some(Semantic {
            from: digest(bytes),
            to: digest(&u.bytes),
        });
    }
    s
}

/// Observes `IniValue` op `k` (module docs; read only).
pub(super) fn observe(
    dirs: &mut Dirs<'_>,
    k: u16,
    op: &Op,
    log: &OpLog,
    hint: Option<Hint>,
) -> Result<file::Seen, ExecError> {
    let e = op_err(k);
    let Op::IniValue {
        root,
        path,
        old,
        new,
        edits,
    } = op
    else {
        return Err(not_ini(k));
    };
    if super::trusting_records() {
        return Ok(file::trusted(op, log));
    }
    let Some(x) = log.intent.tmp.clone() else {
        return Ok(file::Seen::new(Observed::Foreign));
    };
    let found = dirs.parent(root.0, path, false).map_err(&e)?;
    let (parent, name) = match &found {
        Some((d, n)) => (Some(*d), n.clone()),
        None => (
            None,
            RelPath::from_segment(path.file_name())
                .map_err(|_| e(SysError::new(SysErrorKind::InvalidPath, path.as_str())))?,
        ),
    };
    let h0 = State {
        sha256: old.sha256,
        len: old.len,
        attrs: Some(old.attrs),
    };
    let h1 = State {
        sha256: new.sha256,
        len: new.len,
        attrs: Some(old.attrs),
    };
    let s0 = Seq {
        kind: SeqKind::Apply,
        ix: 0,
        tmp: x,
        from: h0,
        to: h1,
    };
    let si = file::sequences(log, h0, h1);
    let restored_once = !si.is_empty() || log.done.is_some_and(|d| d.old_left);
    let (t, bytes) = see_ini(parent, &name).map_err(&e)?;
    let s = file::phases(parent, &t, &s0, &si, restored_once).map_err(&e)?;
    let mut pre = file::Seen::new(Observed::Foreign);
    pre.actions.clone_from(&s.actions);
    pre.left.clone_from(&s.left);
    let semantic = |i: usize| si.get(i).is_some_and(|q| q.kind == SeqKind::Rewrite);
    let target = St { seen: t, bytes };
    Ok(match (s.seq, s.stood) {
        (_, Stood::Start | Stood::End) => {
            let seq = s.seq.and_then(|i| si.get(i)).unwrap_or(&s0);
            match (s.seq, s.stood) {
                // A rewrite at its end: row 2.
                (Some(i), Stood::End) if semantic(i) => {
                    let mut out = pre;
                    out.observed = Observed::Drifted;
                    if let Some(b) = &target.bytes
                        && let Ok(u) = ini::unedit(b, edits)
                    {
                        out.detail = detail(edits, &u.keys, None);
                    }
                    out
                }
                // A rewrite at its start: rows 3 to 9 on `from` (in phase B the `.old`).
                (Some(_), Stood::Start) if seq.kind == SeqKind::Rewrite => {
                    let st = if target.seen == FileSeen::Absent {
                        let (seen, bytes) = see_ini(parent, &seq.tmp.old()).map_err(&e)?;
                        St { seen, bytes }
                    } else {
                        target
                    };
                    stage2(op, &st, hint, pre)
                }
                // `S0` at its start or a restore at its end: the old state (row 4); `S0` at its
                // end or a restore at its start: the new one (row 3), unless refused in this run.
                (None, Stood::Start) | (Some(_), Stood::End) => {
                    let mut out = pre;
                    out.observed = Observed::Before;
                    out.detail = detail(edits, &vec![KeyState::Old; edits.len()], None);
                    out
                }
                _ if hint == Some(Hint::NotWritten) => pre,
                _ => {
                    let mut out = pre;
                    out.observed = Observed::After;
                    out.restore = true;
                    out.detail = detail(edits, &vec![KeyState::New; edits.len()], None);
                    out
                }
            }
        }
        (seq, Stood::Other) => {
            let deciding = seq.and_then(|i| si.get(i)).unwrap_or(&s0);
            let anomaly = matches!(target.seen, FileSeen::Other) || target.seen.respelled();
            let m1 = seq.is_none()
                && s.old == Is::From
                && matches!(target.seen, FileSeen::File { .. })
                && (knob::is_loose_m1() || (!s.tmp_exists && log.done.is_some()));
            if anomaly {
                pre
            } else if m1 {
                // M1: the cleanup of a completed apply the game rewrote since.
                // If stage 2 then finds `Foreign`, `X.old` is gone all the same: it held the old
                // content, which the backup keeps (security review nit 8).
                let mut p = pre;
                p.actions = vec![Action::DeleteOld(s0.tmp.old(), s0.from.sha256, 0)];
                stage2(op, &target, hint, p)
            } else if s.old != Is::Absent {
                // A `.old` next to something else: never touched (S6: named if it holds the
                // file as it was before a step of Rerun).
                let mut p = pre;
                if s.old == Is::From {
                    let file = deciding.tmp.old();
                    p.left.push(file.clone());
                    let step = match deciding.kind {
                        SeqKind::Apply => RerunStep::Apply,
                        SeqKind::Restore => RerunStep::Restore,
                        SeqKind::Rewrite => RerunStep::Rewrite,
                    };
                    p.detail = detail(edits, &[], Some(BeforeStep { step, file }));
                }
                p
            } else {
                // S2 (or no trace at all): Rerun's own temp name is deleted (by the rule of A3,
                // in the actions), the target decides.
                let mut p = pre;
                if let Some(i) = seq {
                    p.actions.extend(
                        file::cleanup(parent, &s0, si.get(..i).unwrap_or_default()).map_err(&e)?,
                    );
                }
                stage2(op, &target, hint, p)
            }
        }
    })
}

/// The rewrite of op `k` after its `RevertIntent` with `y` and `sem` (module docs).
pub(super) fn rewrite(
    dirs: &mut Dirs<'_>,
    k: u16,
    op: &Op,
    sem: &Semantic,
    y: Option<TmpName>,
    ix: u16,
    done: &mut Acted,
) -> Result<(), ExecError> {
    let e = op_err(k);
    let Op::IniValue {
        root, path, edits, ..
    } = op
    else {
        return Err(not_ini(k));
    };
    let y = y.ok_or_else(|| {
        e(SysError::new(
            SysErrorKind::Other,
            "a rewrite without its temp name",
        ))
    })?;
    let Some((parent, name)) = dirs.parent(root.0, path, true).map_err(&e)? else {
        return Err(e(SysError::new(SysErrorKind::NotFound, path.as_str())));
    };
    let mut g = parent.guard(&name).map_err(&e)?;
    let gm = g.metadata().map_err(&e)?;
    if !g.name().same_spelling(&name) || roots::is_placeholder(&gm) {
        return Err(mismatch(
            k,
            format!("{path}: renamed since it was observed"),
        ));
    }
    if !g.users().map_err(&e)?.is_empty() {
        return Err(e(SysError::new(
            SysErrorKind::Busy,
            format!("{path} is in use"),
        )));
    }
    let bytes = read_guard(&mut *g, sem.from.len).map_err(&e)?;
    if digest(&bytes) != sem.from {
        return Err(mismatch(
            k,
            format!("{path}: changed since it was observed"),
        ));
    }
    let u = ini::unedit(&bytes, edits)
        .map_err(|x| mismatch(k, format!("{path}: the INI editor refuses it: {x}")))?;
    if digest(&u.bytes) != sem.to {
        return Err(mismatch(
            k,
            format!("{path}: reverts to another content than recorded"),
        ));
    }
    let nf = NewFile {
        tmp: y,
        attrs: gm.attrs,
        sha256: sem.to.sha256,
        max_len: sem.to.len,
    };
    let r = g
        .replace(&sem.from.sha256, &mut &u.bytes[..], &nf)
        .map_err(&e)?;
    if let Some(t) = r.old_left {
        // As after a restore: one more try on a fresh guard, else a pending cleanup of this
        // run's sequence `ix`.
        file::retry_old(parent, &t, &sem.from.sha256, ix, done);
    }
    Ok(())
}
#[cfg(test)]
pub(crate) mod knob {
    //! Test knobs of this thread: the controls K-I1 (a rewrite recorded without `from`/`to`),
    //! K-I3 (a key someone changed makes the op `Foreign`), K-I4 (no binding of head and
    //! backup) and K-I5 (the leftover `X.old` deleted without M1's conditions).

    use std::cell::Cell;

    thread_local! {
        static UNRECORDED: Cell<bool> = const { Cell::new(false) };
        static CHANGED_FOREIGN: Cell<bool> = const { Cell::new(false) };
        static UNBOUND: Cell<bool> = const { Cell::new(false) };
        static LOOSE_M1: Cell<bool> = const { Cell::new(false) };
    }

    pub(crate) fn unrecorded(on: bool) {
        UNRECORDED.with(|c| c.set(on));
    }
    pub(crate) fn is_unrecorded() -> bool {
        UNRECORDED.with(Cell::get)
    }
    pub(crate) fn changed_foreign(on: bool) {
        CHANGED_FOREIGN.with(|c| c.set(on));
    }
    pub(super) fn is_changed_foreign() -> bool {
        CHANGED_FOREIGN.with(Cell::get)
    }
    pub(crate) fn unbound(on: bool) {
        UNBOUND.with(|c| c.set(on));
    }
    pub(super) fn is_unbound() -> bool {
        UNBOUND.with(Cell::get)
    }
    pub(crate) fn loose_m1(on: bool) {
        LOOSE_M1.with(|c| c.set(on));
    }
    pub(super) fn is_loose_m1() -> bool {
        LOOSE_M1.with(Cell::get)
    }
}

#[cfg(not(test))]
mod knob {
    pub(super) fn is_changed_foreign() -> bool {
        false
    }
    pub(super) fn is_unbound() -> bool {
        false
    }
    pub(super) fn is_loose_m1() -> bool {
        false
    }
}
