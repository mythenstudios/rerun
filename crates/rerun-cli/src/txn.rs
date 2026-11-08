//! `rerun status [--all]`, `rerun revert <txn> [--dry-run] [--yes]` and
//! `rerun forget <txn> [--yes]` (P2-13).
//!
//! - `status` reads the journal and the launch results only (no lock, no game folder, nothing
//!   observed; P3-2: after the journal, the last start of each launch profile): every
//!   transaction that is not settled as a block (state, roots, ops with their recorded state,
//!   backups, pending cleanups, the next step), forgotten ones with their backups (review S8),
//!   closed and empty ones counted (listed with `--all`), and any `.old` a closed one left.
//! - `revert` shows the transaction, then what a revert does now (`exec::verify`, newest op
//!   first, with each INI key and where it would halt), asks, reverts, and reports per op.
//!   Exit 0 closed or nothing to do, 3 refused (nothing written in the run), 5 open.
//! - `revert --rebind` (P2-14b, ADR 0016 amendment P2-14): `exec::rebind_check` as the preview
//!   (the folder bound now and why it does not open, the folder Steam lists now, the folders the
//!   plan created there, what the revert does there, where the registry changes are reverted,
//!   that the binding is permanent), the question at a console only (never `--yes`, user
//!   decision E-R5), `exec::revert_rebound`. A transaction bound already reverts as it is.
//! - `forget` shows the transaction with every backup and pending cleanup, what is on disk now
//!   and every `.old` that holds a file as it was before a step of Rerun, says what forget does
//!   not do, asks, forgets. Exit 0 forgotten, 3 refused.
//! - Pending cleanup (P2-15, ADR 0016 amendment P2-15): a transaction whose ops are all reverted
//!   but whose journal still names a `.old` of Rerun's is "everything reverted, only cleanup
//!   pending"; `revert --dry-run` lists what the revert deletes (Rerun's copy, by its known
//!   SHA-256) and what stays; the revert asks before it deletes, reports each file, and exits 5
//!   while one is still in use (or kept next to a file that changed).

use std::io::Write;

use rerun_core::detect::steam::AppState;
use rerun_core::escape;
use rerun_core::exec::launch_result::Outcome;
use rerun_core::exec::{
    self, Backup, Detail, ExecCtx, ExecError, Halt, LaunchResults, OldSeen, OpState, OpStatus,
    PendingOld, RebindPreview, RebindRefusal, Refusal, RerunStep, RevertReport, TxnLine, TxnStatus,
    Verified,
};
use rerun_core::journal::{Closing, InstanceTag, JournalError, Observed, TxnId};
use rerun_core::plan::Preview;
use rerun_core::policy::root::{AppDir, Create, RootError};
use rerun_core::sys::System;

use crate::cli::Exit;
use crate::confirm::Answer;
use crate::host::{
    Host, after_change, before_change, confirm, existing_app, exit_for_exec, fail, forbidden, note,
    shown, standard_user,
};
use crate::messages::{LaunchMsg, Message, OpText, StepText, TxnMsg, TxnText, Utc};
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
        TxnLine::Applied if st.ops.iter().any(|o| o.state != OpState::Applied) => {
            TxnText::Reverting
        }
        TxnLine::Applied => TxnText::Applied,
        TxnLine::CleanupPending => TxnText::CleanupPending,
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
        let path = c.clone();
        // P2-15: a forgotten transaction's `.old` comes from its records only.
        out.push(m(if st.is_forgotten() {
            TxnMsg::MayRemain { path }
        } else {
            TxnMsg::Cleanup { path }
        }));
    }
    out
}

/// The SHA-256 of Rerun's content, hex.
fn hex(sha: &[u8; 32]) -> String {
    sha.iter().map(|b| format!("{b:02x}")).collect()
}

/// The pending `.old` files as a preview shows them (P2-15, rule 5): what a revert deletes and
/// what stays; a file already gone is not shown.
pub(crate) fn cleanup_lines(items: &[PendingOld]) -> Vec<Message<'_>> {
    items
        .iter()
        .filter_map(|p| {
            let path = escape::path(p.path.as_str());
            Some(m(match p.seen {
                OldSeen::Gone => return None,
                OldSeen::Ours => TxnMsg::WillDelete {
                    sha256: hex(&p.sha256),
                    path,
                },
                OldSeen::Deleted => TxnMsg::OldDeleted { path },
                OldSeen::InUse => TxnMsg::OldInUse { path },
                OldSeen::Kept => TxnMsg::OldKept { path },
                OldSeen::Foreign => TxnMsg::OldForeign { path },
            }))
        })
        .collect()
}

/// The `.old` files of `items` that keep the transaction open, by what keeps it.
pub(crate) fn holding(items: &[PendingOld]) -> (usize, usize) {
    let n = |s: OldSeen| items.iter().filter(|p| p.seen == s).count();
    (n(OldSeen::InUse), n(OldSeen::Kept))
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
            out.extend(rebind_lines(st));
            for o in &st.ops {
                out.extend(op_lines(st, o, true));
            }
            out.push(if blocked(st) {
                m(TxnMsg::HintForgetOnly { txn })
            } else if left_foreign(st) {
                m(TxnMsg::HintForgetForeign { txn })
            } else if st.state == TxnLine::CleanupPending {
                m(TxnMsg::HintCleanup { txn })
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

/// The launch results after the journal (P3-2, ADR 0022 amendment P3-2): the last start per
/// profile with its time, a file that cannot be read as one line, never an abort. Nothing if
/// the folder `launch` does not exist or holds nothing.
pub fn launch_lines(r: &Result<Option<LaunchResults>, RootError>) -> Vec<Message<'_>> {
    let l = |m| Message::Launch(m);
    let r = match r {
        Ok(None) => return Vec::new(),
        Ok(Some(r)) if r.entries.is_empty() && r.other == 0 => return Vec::new(),
        Ok(Some(r)) => r,
        Err(e) => {
            return vec![
                Message::Blank,
                l(LaunchMsg::FolderUnreadable { error: shown(e) }),
            ];
        }
    };
    let mut out = vec![Message::Blank, l(LaunchMsg::Heading)];
    for e in &r.entries {
        out.push(l(match &e.result {
            Err(why) => LaunchMsg::Unreadable {
                id: e.id,
                why: why.clone(),
            },
            Ok(res) => {
                let at = Utc(res.unix_s);
                match &res.outcome {
                    Outcome::Applied {
                        cpu,
                        priority,
                        check,
                    } => LaunchMsg::Applied {
                        id: e.id,
                        at,
                        cpu: *cpu,
                        priority: *priority,
                        check: *check,
                    },
                    Outcome::Skipped {
                        reason,
                        start,
                        ended,
                    } => LaunchMsg::Skipped {
                        id: e.id,
                        at,
                        reason: *reason,
                        start: *start,
                        ended: *ended,
                    },
                }
            }
        }));
    }
    if r.other > 0 {
        out.push(l(LaunchMsg::Other { n: r.other }));
    }
    out
}

/// `rerun status` (module docs). Runs elevated too (it only reads the journal and the launch
/// results).
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
    let launch = exec::launch_results(&app);
    let mut lines = render_status(&s, all);
    lines.extend(launch_lines(&launch));
    match out.lines(&lines).and_then(|()| out.flush()) {
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
    // P2-15 (N1): no room for another `RevertIntent`; forget always fits.
    if let Refusal::Journal(e) = r
        && matches!(
            **e,
            JournalError::TooLarge {
                what: "the records of a transaction",
                ..
            }
        )
    {
        note(err, TxnMsg::JournalFull { txn });
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
    out.extend(cleanup_lines(&v.cleanup));
    if let Some(h) = &v.halted {
        out.push(m(TxnMsg::Halted {
            op: h.op,
            why: shown(&h.why),
        }));
        out.extend(halt_hint(st, h));
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
fn report_lines<'a>(st: &TxnStatus, rep: &'a RevertReport, v: &Verified) -> Vec<Message<'a>> {
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
        // A `.old` the cleanup pass reports below is not repeated here (P2-15).
        let reported = |l: &rerun_core::path::RelPath| {
            rep.cleanup
                .iter()
                .any(|p| p.op == o.op && p.path.file_name() == l.as_str())
        };
        for l in o.left.iter().filter(|l| !reported(l)) {
            out.push(m(TxnMsg::Left {
                path: escape::path(l.as_str()),
            }));
        }
    }
    out.extend(cleanup_lines(&rep.cleanup));
    if let Some(h) = &rep.halted {
        out.push(m(TxnMsg::Halted {
            op: h.op,
            why: shown(&h.why),
        }));
        out.extend(halt_hint(st, h));
    }
    out
}

/// `rerun revert` (module docs).
pub fn revert<W: Write, E: Write>(
    host: &mut Host<'_>,
    txn: &TxnId,
    dry_run: bool,
    yes: bool,
    rebind: bool,
    out: &mut Out<W>,
    err: &mut Out<E>,
) -> Exit {
    match run_revert(host, *txn, dry_run, yes, rebind, out, err) {
        Ok(e) | Err(e) => e,
    }
}

fn run_revert<W: Write, E: Write>(
    host: &mut Host<'_>,
    txn: TxnId,
    dry_run: bool,
    yes: bool,
    rebind: bool,
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
        // Only forget closes these; one text with the core (`Refusal::Blocked`).
        TxnLine::Damaged(_) | TxnLine::Unreadable(_) => {
            return Err(refusal(&Refusal::Blocked { txn }, txn, err));
        }
        _ => {}
    }
    let cx = ExecCtx {
        sys,
        fr: &fr,
        app: &app,
        tag: InstanceTag::new(),
    };
    if rebind {
        match exec::rebind_check(&cx, &txn) {
            Ok(p) => return rebind_run(host, &cx, &st, &p, dry_run, out, err),
            // Bound already: the revert goes on there as it is (a binding is permanent).
            Err(Refusal::Rebind(RebindRefusal::AlreadyBound { path, .. })) => {
                out.line(&m(TxnMsg::AlreadyBound { path }))
                    .map_err(|e| before_change(err, e))?;
            }
            Err(r) => return Err(refusal(&r, txn, err)),
        }
    }
    // Senior-dev S-a: every check of the revert first, so neither the preview nor the question
    // offers a revert that is refused anyway.
    if let Err(r) = exec::revert_check(&cx, &txn) {
        return Err(refusal(&r, txn, err));
    }
    let v = match exec::verify(&cx, &txn) {
        Ok(v) => v,
        Err(ExecError::Refused(r)) => return Err(refusal(&r, txn, err)),
        Err(e) => return Err(fail(err, TxnMsg::Error { error: shown(&e) }, Exit::Refused)),
    };
    let empty = st.state == TxnLine::Empty;
    let mut lines = vec![m(TxnMsg::Txn {
        txn,
        state: txn_text(&st),
    })];
    lines.extend(head_lines(&st));
    if empty {
        lines.push(m(TxnMsg::EmptyCloses { txn }));
    } else {
        lines.extend(now_lines(&st, &v));
    }
    lines.push(Message::Blank);
    out.lines(&lines)
        .and_then(|()| out.flush())
        .map_err(|e| before_change(err, e))?;
    if dry_run {
        return Ok(out
            .line(&m(TxnMsg::DryRunDone))
            .map_or_else(|e| before_change(err, e), |()| Exit::Report));
    }
    // An empty transaction changed nothing: closing it is nothing to ask about.
    // P2-15: a revert that only cleans up asks before it deletes (nothing to delete: no
    // question). A copy `verify` sees in use may still be deleted (a process holding it with
    // delete sharing, review S1): it counts too.
    let ours = v.cleanup.iter().filter(|p| p.seen == OldSeen::Ours).count();
    let in_use = v
        .cleanup
        .iter()
        .filter(|p| p.seen == OldSeen::InUse)
        .count();
    if st.state == TxnLine::CleanupPending {
        if ours + in_use > 0 {
            let q = TxnMsg::AskCleanup {
                n: ours + in_use,
                in_use,
            };
            confirm(host, yes, q, err)?;
        }
    } else if !empty {
        confirm(host, yes, TxnMsg::AskRevert { ops: v.ops.len() }, err)?;
    }
    let rep = match exec::revert(&cx, &txn) {
        Ok(rep) => rep,
        Err(ExecError::Refused(r)) => return Err(refusal(&r, txn, err)),
        Err(e @ ExecError::Unconfirmed(_)) => {
            note(err, TxnMsg::Error { error: shown(&e) });
            note(err, TxnMsg::MayHaveClosed { txn });
            return Err(exit_for_exec(&e));
        }
        Err(e) => {
            note(err, TxnMsg::Error { error: shown(&e) });
            note(err, TxnMsg::RevertFailed { txn });
            return Err(exit_for_exec(&e));
        }
    };
    let (exit, last) = closing_line(&rep);
    let mut lines = report_lines(&st, &rep, &v);
    lines.push(m(last));
    Ok(out
        .lines(&lines)
        .and_then(|()| out.flush())
        .map_or_else(|e| after_change(err, e, exit), |()| exit))
}

/// The last line of a revert's report and its exit code: closed 0; halted, foreign, or a file of
/// Rerun's still left (P2-15) 5.
fn closing_line(rep: &RevertReport) -> (Exit, TxnMsg<'static>) {
    let txn = rep.txn;
    let (in_use, kept) = holding(&rep.cleanup);
    if rep.closed.is_some() {
        (Exit::Report, TxnMsg::Reverted { txn })
    } else if rep.halted.is_some() {
        (Exit::Open, TxnMsg::StaysOpenHalted { txn })
    } else if in_use > 0 {
        (Exit::Open, TxnMsg::StaysOpenInUse { txn, n: in_use })
    } else if kept > 0 {
        (Exit::Open, TxnMsg::StaysOpenKept { txn })
    } else {
        (Exit::Open, TxnMsg::StaysOpenForeign { txn })
    }
}

/// The rebinds of a transaction (`status`, P2-14b): the folder each root is bound to now.
fn rebind_lines(st: &TxnStatus) -> Vec<Message<'_>> {
    st.rebinds
        .iter()
        .map(|r| {
            m(TxnMsg::StatusRebind {
                root: r.root,
                id: r.id,
                path: r.folder.clone().unwrap_or_else(|| r.library.clone()),
            })
        })
        .collect()
}

/// After a halt at a Steam root that is gone: a rebind may bind it (P2-14b).
fn halt_hint<'a>(st: &TxnStatus, h: &Halt) -> Option<Message<'a>> {
    let steam = head(st)
        .and_then(|p| p.roots.get(usize::from(h.root)))
        .is_some_and(|r| r.steam.is_some());
    let gone = match &*h.why {
        // Installed in another folder of its library: no rebind binds that (E-R1).
        Refusal::SteamGone {
            gone: exec::SteamGone::OtherFolder,
            ..
        } => false,
        Refusal::SteamGone { .. }
        | Refusal::Steam {
            state: AppState::NotInstalled,
            ..
        } => true,
        Refusal::Root(e) => matches!(&**e, RootError::Sys(s)
            if s.kind == rerun_core::sys::SysErrorKind::NotFound),
        _ => false,
    };
    (steam && gone).then(|| m(TxnMsg::HaltRebindHint { txn: st.id }))
}

/// The preview of a rebind (rule 5): the transaction, the folder bound now and why it does not
/// open, the folder Steam lists now, the folders the plan created there, what the revert does
/// there, and the two notes.
fn rebind_lines_of<'a>(st: &'a TxnStatus, p: &'a RebindPreview) -> Vec<Message<'a>> {
    let path = |r: &rerun_core::path::RootPath| escape::path(&r.to_string()).into_owned();
    let mut out = vec![m(TxnMsg::Txn {
        txn: st.id,
        state: txn_text(st),
    })];
    out.extend(head_lines(st));
    out.extend(rebind_lines(st));
    out.push(m(TxnMsg::RebindHeading { root: p.to.root }));
    out.push(m(TxnMsg::RebindNow {
        id: p.to.from.id,
        path: path(&p.to.from.path),
    }));
    out.push(m(TxnMsg::RebindLibrary {
        library: path(&p.to.from.store),
    }));
    out.push(m(TxnMsg::RebindWhy { why: shown(&p.why) }));
    out.push(m(TxnMsg::RebindTo {
        id: p.to.id,
        path: path(&p.path),
    }));
    out.push(m(TxnMsg::RebindLibrary {
        library: path(&p.to.store),
    }));
    for d in &p.created {
        out.push(m(if d.found {
            TxnMsg::CreatedFound {
                path: d.path.clone(),
            }
        } else {
            TxnMsg::CreatedMissing {
                path: d.path.clone(),
            }
        }));
    }
    out.push(m(TxnMsg::RebindNowHeading));
    out.push(m(TxnMsg::RebindRootIs {
        root: p.to.root,
        path: path(&p.path),
    }));
    out.extend(now_lines(st, &p.verified).into_iter().skip(1));
    // Only where the head has registry ops (a registry op has no root in the preview).
    if head(st).is_some_and(|h| h.ops.iter().any(|o| o.root.is_none())) {
        out.push(m(TxnMsg::RebindRegistryNote));
    }
    out.push(m(TxnMsg::RebindScopeNote));
    out.push(m(TxnMsg::RebindPermanentNote));
    out.push(Message::Blank);
    out
}

/// `rerun revert <txn> --rebind` after its checks: the preview, the question (at a console
/// only, user decision E-R5), the rebind and the revert, the report.
fn rebind_run<W: Write, E: Write>(
    host: &mut Host<'_>,
    cx: &ExecCtx<'_>,
    st: &TxnStatus,
    p: &RebindPreview,
    dry_run: bool,
    out: &mut Out<W>,
    err: &mut Out<E>,
) -> Result<Exit, Exit> {
    let txn = st.id;
    out.lines(&rebind_lines_of(st, p))
        .and_then(|()| out.flush())
        .map_err(|e| before_change(err, e))?;
    if dry_run {
        return Ok(out
            .line(&m(TxnMsg::DryRunDone))
            .map_or_else(|e| before_change(err, e), |()| Exit::Report));
    }
    let q = TxnMsg::AskRebind {
        txn,
        ops: p.verified.ops.len(),
    };
    match host.confirm.ask(&Message::Txn(q)) {
        Answer::Yes => {}
        Answer::No => return Err(fail(err, TxnMsg::NothingDone, Exit::Refused)),
        Answer::NoConsole => return Err(fail(err, TxnMsg::RebindNeedsConsole, Exit::Usage)),
    }
    let rep = match exec::revert_rebound(cx, &txn, &p.to) {
        Ok(rep) => rep,
        Err(ExecError::Refused(r)) => return Err(refusal(&r, txn, err)),
        // The record may not be on disk, and the journal could not be read again.
        Err(e @ ExecError::RebindUnconfirmed(_)) => {
            note(err, TxnMsg::Error { error: shown(&e) });
            note(err, TxnMsg::MayBeBound { txn });
            return Err(exit_for_exec(&e));
        }
        // Every other error comes after the record (review N3): bound now.
        Err(e @ ExecError::Unconfirmed(_)) => {
            note(err, TxnMsg::Error { error: shown(&e) });
            note(err, TxnMsg::BoundMayHaveClosed { txn });
            return Err(exit_for_exec(&e));
        }
        Err(e) => {
            note(err, TxnMsg::Error { error: shown(&e) });
            note(err, TxnMsg::BoundNow { txn });
            return Err(exit_for_exec(&e));
        }
    };
    let (exit, last) = closing_line(&rep);
    let mut lines = report_lines(st, &rep, &p.verified);
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
    // P2-15 (senior-dev S3): with only the cleanup pending, no change of Rerun's stays.
    lines.push(m(if st.state == TxnLine::CleanupPending {
        TxnMsg::ForgetOnlyCleanup
    } else {
        TxnMsg::ForgetStays
    }));
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
        lines.push(m(match holding(&v.cleanup) {
            (0, 0) => TxnMsg::RevertIsClean { txn },
            (0, _) => TxnMsg::FinishKept { txn },
            _ => TxnMsg::FinishCleanup { txn },
        }));
    }
    lines.push(Message::Blank);
    out.lines(&lines)
        .and_then(|()| out.flush())
        .map_err(|e| before_change(err, e))?;
    confirm(host, yes, TxnMsg::AskForget { txn }, err)?;
    match exec::forget(&cx, &txn) {
        Ok(()) => {}
        // Nothing written.
        Err(ExecError::Refused(r)) => return Err(refusal(&r, txn, err)),
        // The record or marker may be on disk (security review N1).
        Err(e) => {
            note(err, TxnMsg::Error { error: shown(&e) });
            note(err, TxnMsg::MayHaveClosed { txn });
            return Err(Exit::Open);
        }
    }
    Ok(out
        .line(&m(TxnMsg::Forgot { txn }))
        .and_then(|()| out.flush())
        .map_or_else(|e| after_change(err, e, Exit::Report), |()| Exit::Report))
}

#[cfg(test)]
mod launch_tests;
#[cfg(test)]
mod tests;
