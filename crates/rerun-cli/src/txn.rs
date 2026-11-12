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
//!
//! Since P5-2b (ADR 0027 amendment P5-2b) the gates, the checks before the preview, the X12
//! fates, the question and how a revert ended are `rerun_core::flow`'s (`revert_preview`/`revert`,
//! `rebind_preview`/`rebind`, `forget_preview`/`forget`); the operation compares what it observes
//! under the lock with the preview and refuses with nothing written when it changed (exit 3). This
//! module renders, asks and maps the exit codes.

use std::io::Write;

use rerun_core::detect::steam::AppState;
use rerun_core::escape;
use rerun_core::exec::launch_result::Outcome;
use rerun_core::exec::{
    self, Backup, Detail, ExecError, Halt, LaunchResults, OldSeen, OpState, OpStatus, PendingOld,
    RebindPreview, RebindRefusal, Refusal, RerunStep, RevertReport, TxnLine, TxnStatus, Verified,
};
use rerun_core::journal::{Closing, JournalError, Observed, TxnId};
use rerun_core::policy::root::RootError;
use rerun_core::sys::System;

use crate::cli::Exit;
use crate::confirm::Answer;
use crate::host::{
    Host, after_change, before_change, confirm, exit_for_exec, fail, gate, note, shown,
};
use crate::messages::{LaunchMsg, Message, OpText, ProfileMsg, StepText, TxnMsg, TxnText, Utc};
use crate::out::{Out, failed as failed_out};
use crate::preview::{op_at, roots, x12_lines};
use rerun_core::exec::ProfilesMoved;
use rerun_core::exec::launch_result::SkipReason;
use rerun_core::flow::{
    self, ActError, Env, Holder, LaunchOption, RebindShown, RebindView, RevertAsk, RevertEnd,
    RevertGate, RevertWould, head,
};
use rerun_core::plan::RootKind;
use rerun_core::prim::launch_method::ProfileMethod as Method;

fn m(t: TxnMsg<'_>) -> Message<'_> {
    Message::Txn(t)
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

pub(crate) use rerun_core::flow::holding;

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
            out.extend(share_lines(st, false));
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
pub fn launch_lines<'a>(
    r: &'a Result<Option<LaunchResults>, RootError>,
    holders: &'a [Holder],
) -> Vec<Message<'a>> {
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
        let missing = matches!(
            &e.result,
            Ok(res) if matches!(res.outcome, Outcome::Skipped { reason: SkipReason::ProfileMissing, .. })
        );
        let holder = holders.iter().find(|h| h.id == e.id);
        // The method for the wording is the result file's own (`method=`, senior-dev decision 1
        // of the review of P3-4b/c): a head may be newer than the result. Without the line the
        // shared words stay; the head gives a path only, and only when it agrees.
        let method = e.result.as_ref().ok().and_then(|r| r.method);
        let watch = method == Some(Method::Watch);
        let mut restore_failed = None;
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
                        watch,
                    },
                    Outcome::Skipped {
                        reason,
                        start,
                        ended,
                        priority_restore,
                    } => {
                        restore_failed = *priority_restore;
                        LaunchMsg::Skipped {
                            id: e.id,
                            at,
                            reason: *reason,
                            start: *start,
                            ended: *ended,
                            restore: *priority_restore,
                            // Only `watch` writes these reasons and a restore line (N1).
                            watch: watch || reason.watch_only() || priority_restore.is_some(),
                        }
                    }
                }
            }
        }));
        // A4: the priority class could not be put back after a failed CPU step.
        if let Some(code) = restore_failed {
            out.push(l(LaunchMsg::PriorityNotRestored { code }));
        }
        // A7: after a revert or forget the option still starts the game through the shim.
        if missing {
            out.push(l(match holder {
                Some(h) if h.forgotten => LaunchMsg::OptionStillSetForgotten { id: e.id },
                h => LaunchMsg::OptionStillSet {
                    id: e.id,
                    held: h.map(|h| h.txn),
                },
            }));
        } else if let (
            Some(Holder {
                launcher: Some(start),
                ..
            }),
            Ok(res),
        ) = (holder, &e.result)
            && method == Some(Method::Direct)
            && matches!(res.outcome, Outcome::Applied { .. })
        {
            // A6: the check covered the launcher Steam starts, not the game.
            out.push(l(LaunchMsg::CheckedLauncher {
                start: start.clone(),
            }));
        } else if let Some(target) = holder.and_then(|h| h.watch.as_ref())
            && watch
        {
            // P3-4c: the rule and the check concern the game process found after the start.
            out.push(l(LaunchMsg::Watched {
                target: target.clone(),
            }));
        }
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
    let app = match flow::open_app(sys) {
        Ok(Some(a)) => a,
        Ok(None) => {
            return match out.line(&m(TxnMsg::NoTransactions)) {
                Ok(()) => Exit::Report,
                Err(e) => failed_out(err, e),
            };
        }
        Err(g) => return gate(err, g),
    };
    let v = match flow::status(sys, &app) {
        Ok(v) => v,
        Err(e) => {
            return fail(
                err,
                TxnMsg::JournalUnreadable { error: shown(&e) },
                Exit::Fatal,
            );
        }
    };
    let mut lines = render_status(&v.status, all);
    lines.extend(launch_lines(&v.launch, &v.holders));
    // P4-2d (ADR 0023 §6, A4 N6): Rerun rules no transaction of this account owns.
    lines.extend(orphan_lines(&v.orphans));
    match out.lines(&lines).and_then(|()| out.flush()) {
        Ok(()) => Exit::Report,
        Err(e) => failed_out(err, e),
    }
}

/// The `status` lines of the Rerun firewall rules no transaction of this account owns (A4 N6):
/// nothing when there are none; an unreadable firewall is one line, never an error of `status`.
pub(crate) fn orphan_lines(
    r: &Result<Vec<exec::OrphanRule>, exec::OrphansError>,
) -> Vec<Message<'_>> {
    use crate::messages::HelperMsg;
    match r {
        Ok(v) if v.is_empty() => Vec::new(),
        Ok(v) => {
            let mut out = vec![Message::Blank, Message::Helper(HelperMsg::OrphansHeading)];
            out.extend(v.iter().map(|o| {
                Message::Helper(HelperMsg::Orphan {
                    program: o.program.clone(),
                    name: o.name.clone(),
                })
            }));
            out.push(Message::Helper(HelperMsg::OrphansHint));
            out
        }
        Err(e @ exec::OrphansError::Journal(_)) => {
            vec![Message::Helper(HelperMsg::OrphansNoJournal {
                error: shown(e),
            })]
        }
        Err(e) => vec![Message::Helper(HelperMsg::OrphansUnreadable {
            error: shown(e),
        })],
    }
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
        out.extend(detail_lines(v.details.get(k), true));
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
    out.extend(moved_lines(v.profiles_moved.as_ref()));
    out.extend(crate::preview::shadow_lines(&v.virtual_store));
    if let Some(h) = &v.halted {
        out.push(m(TxnMsg::Halted {
            op: h.op,
            why: shown(&h.why),
        }));
        out.extend(halt_hint(st, h));
        out.extend(profiles_halt(st, h));
    }
    out
}

/// S3 of P3-3a: Rerun's profiles folder at another path than the head names (A1).
fn moved_lines(m: Option<&ProfilesMoved>) -> Vec<Message<'_>> {
    m.map(|m| {
        vec![
            Message::Profile(ProfileMsg::ProfilesMovedFrom {
                planned: m.planned.clone(),
            }),
            Message::Profile(ProfileMsg::ProfilesMovedTo { now: m.now.clone() }),
        ]
    })
    .unwrap_or_default()
}

/// A halt at the profiles root: its folder is missing (also the tolerated halt of a rebind).
fn profiles_halt<'a>(st: &TxnStatus, h: &Halt) -> Option<Message<'a>> {
    head(st)
        .and_then(|p| p.roots.get(usize::from(h.root)))
        .is_some_and(|r| r.kind == RootKind::Profiles)
        .then_some(Message::Profile(ProfileMsg::ProfilesHalt))
}

/// X12 before a revert (review M1/B1): what the revert `verify` describes will leave.
fn x12_before(
    install: &Result<std::path::PathBuf, String>,
    st: &TxnStatus,
    v: &Verified,
) -> Vec<Message<'static>> {
    x12(install, flow::fate_before(st, v), true)
}

/// X12 after a revert: what its report says became of the profile.
#[cfg(test)]
fn x12_after(
    install: &Result<std::path::PathBuf, String>,
    st: &TxnStatus,
    rep: &RevertReport,
) -> Vec<Message<'static>> {
    x12(install, flow::fate_after(st, rep), false)
}

/// X12 before `forget`: the profile as it is now (forget changes nothing).
#[cfg(test)]
fn x12_forget(
    install: &Result<std::path::PathBuf, String>,
    st: &TxnStatus,
    v: Option<&Verified>,
) -> Vec<Message<'static>> {
    x12(install, flow::fate_forget(st, v), false)
}

/// The X12 lines of a launch profile's fate (`after_revert`: said before a revert).
fn x12(
    install: &Result<std::path::PathBuf, String>,
    lo: Option<LaunchOption>,
    after_revert: bool,
) -> Vec<Message<'static>> {
    lo.map(|lo| x12_lines(install, lo.id, lo.fate, after_revert))
        .unwrap_or_default()
}

/// The keys of an INI op and the `.old` before a step of Rerun (P2-12 open point: shown
/// before forget, never called the original).
fn detail_lines(d: Option<&Detail>, will: bool) -> Vec<Message<'_>> {
    let mut out = Vec::new();
    // P4-8b (E6): kept for later transactions, or inherited from earlier ones.
    match d {
        Some(Detail::Kept { by }) => {
            let by: Vec<String> = by.iter().map(ToString::to_string).collect();
            out.push(m(TxnMsg::KeptFor { by: by.join(", ") }));
        }
        Some(Detail::Inherited(items)) => {
            for i in items {
                out.push(m(TxnMsg::Inherited {
                    will,
                    from: i.from,
                    outcome: i.outcome,
                    dir: i.dir,
                    path: i.path.clone(),
                }));
            }
        }
        _ => {}
    }
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

/// The shared files and folders of `st` (P4-8b): in `status`, or what `forget` means for them.
fn share_lines(st: &TxnStatus, forget: bool) -> Vec<Message<'_>> {
    let mut out: Vec<Message<'_>> = st
        .shares
        .iter()
        .map(|s| {
            m(TxnMsg::Share {
                forget,
                kind: s.kind,
                dir: s.dir,
                path: s.path.clone(),
            })
        })
        .collect();
    // Review follow-up (senior N-6): never swallowed.
    if let Some(e) = &st.shares_error {
        out.push(m(TxnMsg::SharesUnread { error: e.clone() }));
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
            held: op_at(head(st), o.op).is_some_and(|r| r.action == rerun_core::plan::HOLD_ACTION),
        }));
        out.extend(detail_lines(o.detail.as_ref(), false));
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
    out.extend(moved_lines(rep.profiles_moved.as_ref()));
    if let Some(h) = &rep.halted {
        out.push(m(TxnMsg::Halted {
            op: h.op,
            why: shown(&h.why),
        }));
        out.extend(halt_hint(st, h));
        out.extend(profiles_halt(st, h));
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

/// A gate of `flow` before a revert, a rebind or a forget, on stdout or stderr, and its exit
/// code: closed or empty 0, not found, forgotten, damaged or refused 3, an unreadable journal 1.
fn revert_gate<W: Write, E: Write>(
    g: RevertGate,
    txn: TxnId,
    out: &mut Out<W>,
    err: &mut Out<E>,
) -> Exit {
    match g {
        RevertGate::NoAppDir => fail(err, TxnMsg::NoAppDir, Exit::Refused),
        RevertGate::NotFound(e) => fail(err, TxnMsg::Error { error: shown(&e) }, Exit::Refused),
        RevertGate::Journal(e) => fail(
            err,
            TxnMsg::JournalUnreadable { error: shown(&e) },
            Exit::Fatal,
        ),
        RevertGate::Forgotten => refusal(&Refusal::Forgotten { txn }, txn, err),
        RevertGate::Closed(how) => {
            let _ = out.line(&m(TxnMsg::AlreadyClosed { txn, how }));
            Exit::Report
        }
        RevertGate::Empty => {
            let _ = out.line(&m(TxnMsg::NothingToRevert { txn }));
            Exit::Report
        }
        RevertGate::Blocked => refusal(&Refusal::Blocked { txn }, txn, err),
        RevertGate::Refused(r) => refusal(&r, txn, err),
        RevertGate::Failed(e) => fail(err, TxnMsg::Error { error: shown(&e) }, Exit::Refused),
    }
}

/// A failed revert (also one after a rebind's record) on stderr, and its exit code; `after` is
/// the note for an error after the run's first record.
fn failed_revert<E: Write>(e: ActError, txn: TxnId, after: TxnMsg<'_>, err: &mut Out<E>) -> Exit {
    match e {
        // P5-2b: the transaction or what is on disk changed since the preview; nothing written.
        ActError::Changed => refusal(&Refusal::Changed { txn }, txn, err),
        ActError::Exec(ExecError::Refused(r)) => refusal(&r, txn, err),
        ActError::Exec(e) => {
            note(err, TxnMsg::Error { error: shown(&e) });
            note(err, after);
            exit_for_exec(&e)
        }
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
    // The guards borrow a copy of the install folder: the question needs the host mutably.
    let install = host.install.clone();
    let env = Env {
        sys: host.sys,
        http: host.http,
        install: &install,
    };
    let g = flow::guard(env).map_err(|x| gate(err, x))?;
    if rebind {
        match flow::rebind_preview(&g, &txn) {
            Ok((v, s)) => return rebind_run(host, &g, &v, s, dry_run, out, err),
            // Bound already: the revert goes on there as it is (a binding is permanent).
            Err(RevertGate::Refused(Refusal::Rebind(RebindRefusal::AlreadyBound {
                path, ..
            }))) => {
                out.line(&m(TxnMsg::AlreadyBound { path }))
                    .map_err(|e| before_change(err, e))?;
            }
            Err(x) => return Err(revert_gate(x, txn, out, err)),
        }
    }
    // Senior-dev S-a: every check of the revert runs before the preview (in `flow`), so neither
    // the preview nor the question offers a revert that is refused anyway.
    let (pv, s) = flow::revert_preview(&g, &txn).map_err(|x| revert_gate(x, txn, out, err))?;
    let (st, v) = (&pv.status, &pv.verified);
    let mut lines = vec![m(TxnMsg::Txn {
        txn,
        state: txn_text(st),
    })];
    lines.extend(head_lines(st));
    if pv.empty {
        lines.push(m(TxnMsg::EmptyCloses { txn }));
    } else {
        lines.extend(now_lines(st, v));
    }
    // X12 (B7, C-LM3): the launch option Rerun does not change, said before the question.
    lines.extend(x12(&install, pv.launch_option, true));
    // P4-2d: a firewall rule still there brings the administrator prompt (ADR 0023 §10).
    if let Some(p) = &pv.prompt {
        lines.extend(crate::preview::prompt_lines_of(p));
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
    // An empty transaction changed nothing: closing it is nothing to ask about. P2-15: a revert
    // that only cleans up asks before it deletes (nothing to delete: no question).
    match pv.ask {
        RevertAsk::Nothing => {}
        RevertAsk::Cleanup(c) => {
            let q = TxnMsg::AskCleanup {
                n: c.n,
                in_use: c.in_use,
            };
            confirm(host, yes, q, err)?;
        }
        RevertAsk::Revert { ops } => confirm(host, yes, TxnMsg::AskRevert { ops }, err)?,
    }
    let o = match flow::revert(&g, s) {
        Ok(o) => o,
        Err(e @ ActError::Exec(ExecError::Unconfirmed(_))) => {
            return Err(failed_revert(e, txn, TxnMsg::MayHaveClosed { txn }, err));
        }
        Err(e) => return Err(failed_revert(e, txn, TxnMsg::RevertFailed { txn }, err)),
    };
    let (exit, last) = closing_line(txn, o.end);
    let mut lines = report_lines(st, &o.report, v);
    lines.push(m(last));
    lines.extend(x12(&install, o.launch_option, false));
    Ok(out
        .lines(&lines)
        .and_then(|()| out.flush())
        .map_or_else(|e| after_change(err, e, exit), |()| exit))
}

/// The last line of a revert's report and its exit code: closed 0; halted, foreign, or a file of
/// Rerun's still left (P2-15) 5.
fn closing_line(txn: TxnId, end: RevertEnd) -> (Exit, TxnMsg<'static>) {
    match end {
        RevertEnd::Closed => (Exit::Report, TxnMsg::Reverted { txn }),
        RevertEnd::Halted => (Exit::Open, TxnMsg::StaysOpenHalted { txn }),
        RevertEnd::InUse(n) => (Exit::Open, TxnMsg::StaysOpenInUse { txn, n }),
        RevertEnd::Kept => (Exit::Open, TxnMsg::StaysOpenKept { txn }),
        RevertEnd::Foreign => (Exit::Open, TxnMsg::StaysOpenForeign { txn }),
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
fn rebind_lines_of<'a>(
    install: &Result<std::path::PathBuf, String>,
    st: &'a TxnStatus,
    p: &'a RebindPreview,
) -> Vec<Message<'a>> {
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
    // X12 in the rebind preview too (review of P3-3d): what the revert there leaves.
    out.extend(x12_before(install, st, &p.verified));
    out.push(Message::Blank);
    out
}

/// `rerun revert <txn> --rebind` after its checks: the preview, the question (at a console
/// only, user decision E-R5), the rebind and the revert, the report.
fn rebind_run<W: Write, E: Write>(
    host: &mut Host<'_>,
    g: &flow::Guarded<'_>,
    view: &RebindView,
    s: RebindShown,
    dry_run: bool,
    out: &mut Out<W>,
    err: &mut Out<E>,
) -> Result<Exit, Exit> {
    let (st, p) = (&view.status, &view.rebind);
    let txn = st.id;
    out.lines(&rebind_lines_of(&host.install, st, p))
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
    let o = match flow::rebind(g, s) {
        Ok(o) => o,
        // The record may not be on disk, and the journal could not be read again.
        Err(e @ ActError::Exec(ExecError::RebindUnconfirmed(_))) => {
            return Err(failed_revert(e, txn, TxnMsg::MayBeBound { txn }, err));
        }
        // Every other error comes after the record (review N3): bound now.
        Err(e @ ActError::Exec(ExecError::Unconfirmed(_))) => {
            return Err(failed_revert(
                e,
                txn,
                TxnMsg::BoundMayHaveClosed { txn },
                err,
            ));
        }
        Err(e) => return Err(failed_revert(e, txn, TxnMsg::BoundNow { txn }, err)),
    };
    let (exit, last) = closing_line(txn, o.end);
    let mut lines = report_lines(st, &o.report, &p.verified);
    lines.push(m(last));
    lines.extend(x12(&host.install, o.launch_option, false));
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
    let install = host.install.clone();
    let env = Env {
        sys: host.sys,
        http: host.http,
        install: &install,
    };
    let g = flow::guard(env).map_err(|x| gate(err, x))?;
    let (pv, s) = match flow::forget_preview(&g, &txn) {
        Ok(x) => x,
        Err(RevertGate::Forgotten) => {
            let _ = out.line(&m(TxnMsg::AlreadyForgotten { txn }));
            return Ok(Exit::Report);
        }
        Err(RevertGate::Closed(how)) => {
            return Err(fail(
                err,
                TxnMsg::NothingToForget { txn, how },
                Exit::Refused,
            ));
        }
        Err(x) => return Err(revert_gate(x, txn, out, err)),
    };
    let st = &pv.status;
    let mut lines = vec![m(TxnMsg::Txn {
        txn,
        state: txn_text(st),
    })];
    lines.extend(head_lines(st));
    for o in &st.ops {
        lines.extend(op_lines(st, o, true));
    }
    // What is on disk now, if the head can be read (`verify` writes nothing).
    match &pv.verified {
        Some(Ok(v)) => lines.extend(now_lines(st, v)),
        Some(Err(e)) => lines.push(m(TxnMsg::CannotObserve { error: shown(e) })),
        None => {}
    }
    // P4-8b (S3, default 2): what forget means for the files it shares.
    lines.extend(share_lines(st, true));
    lines.push(m(TxnMsg::ForgetChangesNothing));
    // P2-15 (senior-dev S3): with only the cleanup pending, no change of Rerun's stays.
    lines.push(m(if st.state == TxnLine::CleanupPending {
        TxnMsg::ForgetOnlyCleanup
    } else {
        TxnMsg::ForgetStays
    }));
    lines.push(m(TxnMsg::ForgetKeeps));
    // C-LM4 (A3, X12): what forget leaves of the profile, as it is now.
    lines.extend(x12(&install, pv.launch_option, false));
    if st.state == TxnLine::Applied && st.ops.iter().all(|o| o.state == OpState::Applied) {
        lines.push(m(TxnMsg::AllStay { ops: st.ops.len() }));
    }
    // Review S7: nothing is foreign and nothing halts: a revert finishes it cleanly.
    if let Some(w) = pv.revert_would {
        lines.push(m(match w {
            RevertWould::BeClean => TxnMsg::RevertIsClean { txn },
            RevertWould::KeepCopy => TxnMsg::FinishKept { txn },
            RevertWould::CleanUp => TxnMsg::FinishCleanup { txn },
        }));
    }
    lines.push(Message::Blank);
    out.lines(&lines)
        .and_then(|()| out.flush())
        .map_err(|e| before_change(err, e))?;
    confirm(host, yes, TxnMsg::AskForget { txn }, err)?;
    match flow::forget(&g, s) {
        Ok(()) => {}
        // Nothing written (P5-2b: changed since the preview, or refused).
        Err(ActError::Changed) => return Err(refusal(&Refusal::Changed { txn }, txn, err)),
        Err(ActError::Exec(ExecError::Refused(r))) => return Err(refusal(&r, txn, err)),
        // The record or marker may be on disk (security review N1).
        Err(ActError::Exec(e)) => {
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
