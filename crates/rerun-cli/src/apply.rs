//! `rerun apply <hash> [--dry-run] [--yes]` (P2-13): shows the stored plan again from exactly
//! the bytes that are applied, runs every check of the apply without writing (`exec::check`),
//! asks (user decision E1 a), then applies (`exec::apply` loads the same bytes by hash and runs
//! every check again under the lock).
//!
//! Nothing is asked for a plan that is refused anyway. `--dry-run` stops after the checks: no
//! journal folder, no lock file, no record (user decision E2 a). Exit codes: 0 applied or
//! nothing to do, 3 refused or declined, 4 rolled back, 5 left open (ADR 0016 amendment).

use std::io::Write;

use rerun_core::exec::{self, ApplyError, ExecCtx, ExecError, Outcome};
use rerun_core::journal::InstanceTag;
use rerun_core::plan::{self, PlanHash};

use crate::cli::Exit;
use crate::host::{
    Host, after_change, before_change, confirm, existing_app, exit_for_apply, fail, forbidden,
    note, shown, standard_user,
};
use crate::messages::{Message, TxnMsg};
use crate::out::Out;
use crate::preview;

/// Applies and prints (module docs).
pub fn apply<W: Write, E: Write>(
    host: &mut Host<'_>,
    hash: &PlanHash,
    dry_run: bool,
    yes: bool,
    out: &mut Out<W>,
    err: &mut Out<E>,
) -> Exit {
    match run(host, hash, dry_run, yes, out, err) {
        Ok(e) | Err(e) => e,
    }
}

fn run<W: Write, E: Write>(
    host: &mut Host<'_>,
    hash: &PlanHash,
    dry_run: bool,
    yes: bool,
    out: &mut Out<W>,
    err: &mut Out<E>,
) -> Result<Exit, Exit> {
    let sys = host.sys;
    standard_user(sys, err)?;
    let fr = forbidden(host, err)?;
    let app = existing_app(sys, err)?;
    let refused = |err: &mut Out<E>, e: &dyn std::fmt::Display| {
        fail(err, TxnMsg::Error { error: shown(&e) }, Exit::Refused)
    };
    let bytes = plan::load(&app, hash).map_err(|e| refused(err, &e))?;
    let view = plan::preview_stored(&bytes).map_err(|e| refused(err, &e))?;
    let ops = view.ops.len();
    let mut lines = vec![Message::Txn(TxnMsg::PlanHead { hash: *hash, ops })];
    lines.extend(preview::render(&view));
    lines.push(Message::Blank);
    out.lines(&lines)
        .and_then(|()| out.flush())
        .map_err(|e| before_change(err, e))?;
    let cx = ExecCtx {
        sys,
        fr: &fr,
        app: &app,
        tag: InstanceTag::new(),
    };
    match exec::check(&cx, hash) {
        Err(r) => return Err(refused(err, &r)),
        Ok(0) => {
            let _ = out.line(&Message::Txn(TxnMsg::NothingToDo));
            return Ok(Exit::Report);
        }
        Ok(_) => {}
    }
    if dry_run {
        return Ok(out
            .line(&Message::Txn(TxnMsg::ChecksPassed))
            .map_or_else(|e| before_change(err, e), |()| Exit::Report));
    }
    confirm(host, yes, TxnMsg::AskApply { ops }, err)?;
    match exec::apply(&cx, hash) {
        Ok(Outcome::Nothing) => {
            let _ = out.line(&Message::Txn(TxnMsg::NothingToDo));
            Ok(Exit::Report)
        }
        Ok(Outcome::Applied(txn)) => {
            let done = [
                Message::Txn(TxnMsg::Applied { txn }),
                Message::Txn(TxnMsg::RevertWith { txn }),
            ];
            Ok(out
                .lines(&done)
                .and_then(|()| out.flush())
                .map_or_else(|e| after_change(err, e, Exit::Report), |()| Exit::Report))
        }
        Err(e) => Ok(failed_apply(&e, err)),
    }
}

/// The lines of a failed apply on stderr, and its exit code.
pub fn failed_apply<E: Write>(e: &ApplyError, err: &mut Out<E>) -> Exit {
    match e {
        ApplyError::Refused(r) => note(err, TxnMsg::Error { error: shown(r) }),
        ApplyError::RolledBack { txn, cause, .. } => {
            note(err, TxnMsg::RolledBack { txn: *txn });
            note(
                err,
                TxnMsg::Cause {
                    error: shown(cause),
                },
            );
        }
        ApplyError::LeftOpen {
            txn,
            cause,
            rollback,
        } => {
            note(err, TxnMsg::LeftOpen { txn: *txn });
            note(
                err,
                TxnMsg::Cause {
                    error: shown(cause),
                },
            );
            note(
                err,
                TxnMsg::RollbackCause {
                    error: shown(rollback),
                },
            );
            // Review S7: a rollback that met changes someone else made ends with forget.
            if matches!(**rollback, ExecError::Foreign { .. }) {
                note(err, TxnMsg::FinishWithForget { txn: *txn });
            } else {
                note(err, TxnMsg::FinishWithRevert { txn: *txn });
            }
        }
        other => note(
            err,
            TxnMsg::Error {
                error: shown(other),
            },
        ),
    }
    exit_for_apply(e)
}
