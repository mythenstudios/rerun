//! `rerun status [--all]`, `rerun revert <txn> [--dry-run] [--yes]` and
//! `rerun forget <txn> [--yes]` (P2-13).
//!
//! - `status` reads the journal only (no lock, no game folder, nothing observed): every
//!   transaction that is not settled as a block (state, roots, ops with their recorded state,
//!   backups, pending cleanups, the next step), forgotten ones with their backups (review S8),
//!   closed and empty ones counted (listed with `--all`), and any `.old` a closed one left.
//! - `revert` shows the transaction, then what a revert does now (`exec::verify`, newest op
//!   first, with each INI key and where it would halt), asks, reverts, and reports per op.
//!   Exit 0 closed or nothing to do, 3 refused (nothing written in the run), 5 open.
//! - `forget` shows the transaction with every backup and pending cleanup, what is on disk now
//!   and every `.old` that holds a file as it was before a step of Rerun, says what forget does
//!   not do, asks, forgets. Exit 0 forgotten, 3 refused.

use std::io::Write;

use rerun_core::escape;
use rerun_core::exec::{
    self, Backup, Detail, ExecCtx, ExecError, OpState, OpStatus, Refusal, RerunStep, RevertReport,
    TxnLine, TxnStatus, Verified,
};
use rerun_core::journal::{Closing, InstanceTag, JournalError, Observed, TxnId};
use rerun_core::plan::Preview;
use rerun_core::policy::root::{AppDir, Create, RootError};
use rerun_core::sys::System;

use crate::cli::Exit;
use crate::host::{
    Host, after_change, before_change, confirm, existing_app, exit_for_exec, fail, forbidden, note,
    shown, standard_user,
};
use crate::messages::{Message, OpText, StepText, TxnMsg, TxnText};
use crate::out::{Out, failed as failed_out};
use crate::preview::{op_at, roots};

fn m(t: TxnMsg<'_>) -> Message<'_> {
    Message::Txn(t)
}

/// The preview of a transaction's head, if it could be built.
fn head(st: &TxnStatus) -> Option<&Preview> {
    st.preview.as_ref().and_then(|p| p.as_ref().ok())
}

fn op_text(s: OpState) -> OpText {
    match s {
        OpState::Interrupted => OpText::Interrupted,
        OpState::Applied => OpText::Applied,
        OpState::RevertInterrupted => OpText::RevertInterrupted,
        OpState::Reverted(o) => OpText::Reverted(o),
    }
}

/// The state line of a transaction.
fn txn_text(st: &TxnStatus) -> TxnText<'_> {
    if st.is_forgotten() {
        return TxnText::Closed(Closing::Forgotten);
    }
    match &st.state {
        TxnLine::Empty => TxnText::Empty,
        TxnLine::Open => TxnText::Open,
        TxnLine::Applied if st.ops.iter().any(|o| o.state == OpState::RevertInterrupted) => {
            TxnText::Reverting
        }
        TxnLine::Applied => TxnText::Applied,
        TxnLine::Closed(c) => TxnText::Closed(*c),
        TxnLine::Damaged(d) => TxnText::Damaged(shown(d)),
        TxnLine::Unreadable(why) => TxnText::Unreadable(why.clone()),
    }
}

/// The backup line of an op, if it has one.
fn backup(b: Option<&Backup>) -> Option<Message<'_>> {
    match b {
        Some(Backup::Bin { path, len }) => Some(m(TxnMsg::BackupFile {
            path: path.clone(),
            len: *len,
        })),
        Some(Backup::Inline) => Some(m(TxnMsg::BackupInline)),
        None => None,
    }
}

/// The value name of registry op `k`, if the head names one.
fn value_line(st: &TxnStatus, k: u16) -> Option<Message<'_>> {
    let name = head(st)?.ops.get(usize::from(k))?.name.clone()?;
    Some(m(TxnMsg::OpValue { name }))
}

/// An op with its recorded state, backup and pending cleanups.
fn op_lines<'a>(st: &'a TxnStatus, o: &'a OpStatus, with_backup: bool) -> Vec<Message<'a>> {
    let mut out = vec![m(TxnMsg::TxnOp {
        op: o.op,
        state: op_text(o.state),
        at: op_at(head(st), o.op),
    })];
    out.extend(value_line(st, o.op));
    if with_backup {
        out.extend(backup(o.backup.as_ref()));
    }
    for c in &o.cleanup {
        out.push(m(TxnMsg::Cleanup { path: c.clone() }));
    }
    out
}

/// The roots of the transaction's head, or why it cannot be shown.
fn head_lines(st: &TxnStatus) -> Vec<Message<'_>> {
    match &st.preview {
        Some(Ok(p)) => roots(p),
        Some(Err(why)) => vec![m(TxnMsg::HeadUnreadable { why: why.clone() })],
        None => Vec::new(),
    }
}

/// Damaged, unreadable or with a head that cannot be read: only forget closes it.
fn blocked(st: &TxnStatus) -> bool {
    matches!(st.state, TxnLine::Damaged(_) | TxnLine::Unreadable(_))
        || matches!(st.preview, Some(Err(_)))
}

fn left_foreign(st: &TxnStatus) -> bool {
    st.ops
        .iter()
        .any(|o| o.state == OpState::Reverted(Observed::Foreign))
}

/// The `status` report of `s` (pure).
pub fn render_status(s: &exec::Status, all: bool) -> Vec<Message<'_>> {
    let mut out = Vec::new();
    let (mut open, mut closed, mut forgotten) = (0, 0, 0);
    for st in &s.txns {
        let txn = st.id;
        let cleanups = st.ops.iter().any(|o| !o.cleanup.is_empty());
        if st.is_forgotten() {
            // Review S8: a forgotten transaction always shows where its backups stay.
            forgotten += 1;
            out.push(m(TxnMsg::Txn {
                txn,
                state: txn_text(st),
            }));
            for o in st
                .ops
                .iter()
                .filter(|o| o.backup.is_some() || !o.cleanup.is_empty())
            {
                out.extend(op_lines(st, o, true));
            }
            out.push(m(TxnMsg::BackupsIn {
                folder: st.folder.clone(),
            }));
            out.push(Message::Blank);
        } else if st.is_settled() {
            closed += 1;
            if all || cleanups {
                out.push(m(TxnMsg::Txn {
                    txn,
                    state: txn_text(st),
                }));
                for o in st.ops.iter().filter(|o| !o.cleanup.is_empty()) {
                    out.extend(op_lines(st, o, false));
                }
            }
        } else {
            open += 1;
            out.push(m(TxnMsg::Txn {
                txn,
                state: txn_text(st),
            }));
            out.extend(head_lines(st));
            for o in &st.ops {
                out.extend(op_lines(st, o, true));
            }
            out.push(if blocked(st) {
                m(TxnMsg::HintForgetOnly { txn })
            } else if left_foreign(st) {
                m(TxnMsg::HintForgetForeign { txn })
            } else {
                m(TxnMsg::HintRevert { txn })
            });
            out.push(Message::Blank);
        }
    }
    if s.foreign_entries > 0 {
        out.push(m(TxnMsg::ForeignEntries {
            n: s.foreign_entries,
        }));
    }
    if s.txns.is_empty() {
        out.push(m(TxnMsg::NoTransactions));
        return out;
    }
    out.push(m(TxnMsg::StatusCounts {
        open,
        closed,
        forgotten,
        all,
    }));
    if open > 0 {
        out.push(m(TxnMsg::StatusNote));
    }
    out
}

/// `rerun status` (module docs). Runs elevated too (it only reads the journal).
pub fn status<W: Write, E: Write>(
    sys: &dyn System,
    all: bool,
    out: &mut Out<W>,
    err: &mut Out<E>,
) -> Exit {
    let app = match AppDir::open(sys, Create::Never) {
        Ok(Some(a)) => a,
        Ok(None) => {
            return match out.line(&m(TxnMsg::NoTransactions)) {
                Ok(()) => Exit::Report,
                Err(e) => failed_out(err, e),
            };
        }
        Err(e) => return fail(err, TxnMsg::AppDir { error: shown(&e) }, Exit::Fatal),
    };
    let s = match exec::status(&app) {
        Ok(s) => s,
        Err(e) => {
            return fail(
                err,
                TxnMsg::JournalUnreadable { error: shown(&e) },
                Exit::Fatal,
            );
        }
    };
    match out
        .lines(&render_status(&s, all))
        .and_then(|()| out.flush())
    {
        Ok(()) => Exit::Report,
        Err(e) => failed_out(err, e),
    }
}

/// The transaction `txn` from the journal; not found is a refusal (exit 3), an unreadable
/// journal fatal.
fn load<E: Write>(app: &AppDir<'_>, txn: &TxnId, err: &mut Out<E>) -> Result<TxnStatus, Exit> {
    exec::txn_status(app, txn).map_err(|e| match e {
        JournalError::NotFound(_) => fail(err, TxnMsg::Error { error: shown(&e) }, Exit::Refused),
        e => fail(
            err,
            TxnMsg::JournalUnreadable { error: shown(&e) },
            Exit::Fatal,
        ),
    })
}

/// A refusal on stderr, with the hint for a root that is another folder now (user decision
/// E5 a: no rebind yet).
fn refusal<E: Write>(r: &Refusal, txn: TxnId, err: &mut Out<E>) -> Exit {
    note(err, TxnMsg::Error { error: shown(r) });
    if let Refusal::Root(e) = r
        && matches!(**e, RootError::IdentityMismatch { .. })
    {
        note(err, TxnMsg::IdentityHint { txn });
    }
    Exit::Refused
}

/// What a revert does now, newest op first (`verify`), with the INI keys, the backup of an op
/// left as found, a `.old` that holds a file before a step of Rerun, and the halt.
fn now_lines<'a>(st: &'a TxnStatus, v: &'a Verified) -> Vec<Message<'a>> {
    let mut out = vec![m(TxnMsg::NowHeading)];
    for (k, observed) in v.ops.iter().rev() {
        out.push(m(TxnMsg::Will {
            op: *k,
            observed: *observed,
            at: op_at(head(st), *k),
        }));
        out.extend(value_line(st, *k));
        out.extend(detail_lines(v.details.get(k)));
        if *observed == Observed::Foreign {
            let b = st
                .ops
                .iter()
                .find(|o| o.op == *k)
                .and_then(|o| o.backup.as_ref());
            out.extend(backup(b));
        }
    }
    if let Some(h) = &v.halted {
        out.push(m(TxnMsg::Halted {
            op: h.op,
            why: shown(&h.why),
        }));
    }
    out
}

/// The keys of an INI op and the `.old` before a step of Rerun (P2-12 open point: shown
/// before forget, never called the original).
fn detail_lines(d: Option<&Detail>) -> Vec<Message<'_>> {
    let mut out = Vec::new();
    if let Some(Detail::Ini { keys, before_step }) = d {
        for k in keys {
            out.push(m(TxnMsg::KeyState {
                state: k.state,
                section: escape::text(k.section.as_str()),
                key: escape::text(k.key.as_str()),
            }));
        }
        if let Some(b) = before_step {
            out.push(m(TxnMsg::BeforeStep {
                step: match b.step {
                    RerunStep::Apply => StepText::Apply,
                    RerunStep::Restore => StepText::Restore,
                    RerunStep::Rewrite => StepText::Rewrite,
                },
                file: escape::path(b.file.as_str()),
            }));
        }
    }
    out
}

/// The report of a revert.
fn report_lines<'a>(rep: &'a RevertReport, v: &Verified) -> Vec<Message<'a>> {
    let mut out = Vec::new();
    for o in &rep.ops {
        let seen = v.ops.iter().find(|(k, _)| *k == o.op).map(|(_, s)| *s);
        out.push(m(TxnMsg::Did {
            op: o.op,
            observed: o.observed,
            changed: seen != Some(o.observed),
        }));
        out.extend(detail_lines(o.detail.as_ref()));
        out.extend(backup(o.backup.as_ref()));
        for l in &o.left {
            out.push(m(TxnMsg::Left {
                path: escape::path(l.as_str()),
            }));
        }
    }
    if let Some(h) = &rep.halted {
        out.push(m(TxnMsg::Halted {
            op: h.op,
            why: shown(&h.why),
        }));
    }
    out
}

/// `rerun revert` (module docs).
pub fn revert<W: Write, E: Write>(
    host: &mut Host<'_>,
    txn: &TxnId,
    dry_run: bool,
    yes: bool,
    out: &mut Out<W>,
    err: &mut Out<E>,
) -> Exit {
    match run_revert(host, *txn, dry_run, yes, out, err) {
        Ok(e) | Err(e) => e,
    }
}

fn run_revert<W: Write, E: Write>(
    host: &mut Host<'_>,
    txn: TxnId,
    dry_run: bool,
    yes: bool,
    out: &mut Out<W>,
    err: &mut Out<E>,
) -> Result<Exit, Exit> {
    let sys = host.sys;
    standard_user(sys, err)?;
    let fr = forbidden(host, err)?;
    let app = existing_app(sys, err)?;
    let st = load(&app, &txn, err)?;
    if st.is_forgotten() {
        return Err(refusal(&Refusal::Forgotten { txn }, txn, err));
    }
    match st.state {
        TxnLine::Closed(how) => {
            let _ = out.line(&m(TxnMsg::AlreadyClosed { txn, how }));
            return Ok(Exit::Report);
        }
        // Review nit: an empty transaction without a readable head changed nothing.
        TxnLine::Empty if head(&st).is_none() => {
            let _ = out.line(&m(TxnMsg::NothingToRevert { txn }));
            return Ok(Exit::Report);
        }
        _ if blocked(&st) => return Err(fail(err, TxnMsg::Damaged { txn }, Exit::Refused)),
        _ => {}
    }
    let cx = ExecCtx {
        sys,
        fr: &fr,
        app: &app,
        tag: InstanceTag::new(),
    };
    let v = match exec::verify(&cx, &txn) {
        Ok(v) => v,
        Err(ExecError::Refused(r)) => return Err(refusal(&r, txn, err)),
        Err(e) => return Err(fail(err, TxnMsg::Error { error: shown(&e) }, Exit::Refused)),
    };
    let mut lines = vec![m(TxnMsg::Txn {
        txn,
        state: txn_text(&st),
    })];
    lines.extend(head_lines(&st));
    lines.extend(now_lines(&st, &v));
    lines.push(Message::Blank);
    out.lines(&lines)
        .and_then(|()| out.flush())
        .map_err(|e| before_change(err, e))?;
    if dry_run {
        return Ok(out
            .line(&m(TxnMsg::DryRunDone))
            .map_or_else(|e| before_change(err, e), |()| Exit::Report));
    }
    confirm(host, yes, TxnMsg::AskRevert { ops: v.ops.len() }, err)?;
    let rep = match exec::revert(&cx, &txn) {
        Ok(rep) => rep,
        Err(ExecError::Refused(r)) => return Err(refusal(&r, txn, err)),
        Err(e) => {
            note(err, TxnMsg::Error { error: shown(&e) });
            note(err, TxnMsg::RevertFailed { txn });
            return Err(exit_for_exec(&e));
        }
    };
    let (exit, last) = if rep.closed.is_some() {
        (Exit::Report, TxnMsg::Reverted { txn })
    } else if rep.halted.is_some() {
        (Exit::Open, TxnMsg::StaysOpenHalted { txn })
    } else {
        (Exit::Open, TxnMsg::StaysOpenForeign { txn })
    };
    let mut lines = report_lines(&rep, &v);
    lines.push(m(last));
    Ok(out
        .lines(&lines)
        .and_then(|()| out.flush())
        .map_or_else(|e| after_change(err, e, exit), |()| exit))
}

/// `rerun forget` (module docs).
pub fn forget<W: Write, E: Write>(
    host: &mut Host<'_>,
    txn: &TxnId,
    yes: bool,
    out: &mut Out<W>,
    err: &mut Out<E>,
) -> Exit {
    match run_forget(host, *txn, yes, out, err) {
        Ok(e) | Err(e) => e,
    }
}

fn run_forget<W: Write, E: Write>(
    host: &mut Host<'_>,
    txn: TxnId,
    yes: bool,
    out: &mut Out<W>,
    err: &mut Out<E>,
) -> Result<Exit, Exit> {
    let sys = host.sys;
    standard_user(sys, err)?;
    let fr = forbidden(host, err)?;
    let app = existing_app(sys, err)?;
    let st = load(&app, &txn, err)?;
    if st.is_forgotten() {
        let _ = out.line(&m(TxnMsg::AlreadyForgotten { txn }));
        return Ok(Exit::Report);
    }
    if let TxnLine::Closed(how) = st.state {
        return Err(fail(
            err,
            TxnMsg::NothingToForget { txn, how },
            Exit::Refused,
        ));
    }
    let mut lines = vec![m(TxnMsg::Txn {
        txn,
        state: txn_text(&st),
    })];
    lines.extend(head_lines(&st));
    for o in &st.ops {
        lines.extend(op_lines(&st, o, true));
    }
    // What is on disk now, if the head can be read (`verify` writes nothing).
    let cx = ExecCtx {
        sys,
        fr: &fr,
        app: &app,
        tag: InstanceTag::new(),
    };
    let verified = head(&st).map(|_| exec::verify(&cx, &txn));
    match &verified {
        Some(Ok(v)) => lines.extend(now_lines(&st, v)),
        Some(Err(e)) => lines.push(m(TxnMsg::CannotObserve { error: shown(e) })),
        None => {}
    }
    lines.push(m(TxnMsg::ForgetChangesNothing));
    lines.push(m(TxnMsg::ForgetStays));
    lines.push(m(TxnMsg::ForgetKeeps));
    if st.state == TxnLine::Applied && st.ops.iter().all(|o| o.state == OpState::Applied) {
        lines.push(m(TxnMsg::AllStay { ops: st.ops.len() }));
    }
    // Review S7: nothing is foreign and nothing halts: a revert finishes it cleanly.
    if let Some(Ok(v)) = &verified
        && v.halted.is_none()
        && v.ops.iter().all(|(_, o)| *o != Observed::Foreign)
        && !left_foreign(&st)
    {
        lines.push(m(TxnMsg::RevertIsClean { txn }));
    }
    lines.push(Message::Blank);
    out.lines(&lines)
        .and_then(|()| out.flush())
        .map_err(|e| before_change(err, e))?;
    confirm(host, yes, TxnMsg::AskForget { txn }, err)?;
    if let Err(e) = exec::forget(&cx, &txn) {
        // Forget writes one record or one marker or nothing.
        return Err(fail(err, TxnMsg::Error { error: shown(&e) }, Exit::Refused));
    }
    Ok(out
        .line(&m(TxnMsg::Forgot { txn }))
        .and_then(|()| out.flush())
        .map_or_else(|e| after_change(err, e, Exit::Report), |()| Exit::Report))
}

#[cfg(test)]
mod tests;
