//! `rerun apply <hash> [--dry-run] [--yes]` (P2-13): shows the stored plan again from exactly
//! the bytes that are applied, runs every check of the apply without writing (`exec::check`),
//! asks (user decision E1 a), then applies (`exec::apply` loads the same bytes by hash and runs
//! every check again under the lock).
//!
//! Nothing is asked for a plan that is refused anyway. `--dry-run` stops after the checks: no
//! journal folder, no lock file, no record (user decision E2 a). Exit codes: 0 applied or
//! nothing to do, 3 refused or declined, 4 rolled back, 5 left open, also rolled back with a
//! file Rerun replaced still in use (P2-15; ADR 0016 amendments).

use std::io::Write;

use rerun_core::exec::{self, ApplyError, ExecCtx, ExecError, Outcome};
use rerun_core::journal::InstanceTag;
use rerun_core::plan::{self, PlanHash};
use rerun_core::policy::root::shadows_stored;

use crate::cli::Exit;
use crate::host::{
    Host, after_change, before_change, confirm, existing_app, exit_for_apply, fail, forbidden,
    note, shown, standard_user,
};
use crate::messages::{Message, ProfileMsg, TxnMsg};
use crate::out::Out;
use crate::preview;
use crate::txn::{cleanup_lines, holding};

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
    // P3-7: a VirtualStore copy of a managed file (read only; decoded above already).
    let shadows = shadows_stored(sys, &bytes).unwrap_or_default();
    lines.extend(preview::shadow_lines(&shadows));
    // P3-3d: the launch profile's selection here, hints and the launch option.
    let lv = preview::launch_view(sys, &host.install, &view);
    if let Some(lv) = &lv {
        lines.extend(preview::launch_lines(&view, lv));
    }
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
            let mut done = vec![
                Message::Txn(TxnMsg::Applied { txn }),
                Message::Txn(TxnMsg::RevertWith { txn }),
            ];
            // C-LM5: the launch option is the user's step now.
            // Review L3: only an option that can be pasted, with the shim there.
            if let Some(lv) = &lv {
                done.push(Message::Profile(if lv.ready() {
                    ProfileMsg::PasteNow
                } else {
                    ProfileMsg::PasteNotYet
                }));
            }
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
        ApplyError::RolledBack {
            txn,
            cause,
            cleanup,
        } => {
            note(err, TxnMsg::RolledBack { txn: *txn });
            note(
                err,
                TxnMsg::Cause {
                    error: shown(cause),
                },
            );
            // P2-15 (E-C4, review S1): what the cleanup deleted or found not Rerun's.
            for l in cleanup_lines(cleanup) {
                let _ = err.line(&l);
            }
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
        ApplyError::CleanupPending {
            txn,
            cause,
            cleanup,
        } => {
            note(err, TxnMsg::RolledBackCleanup { txn: *txn });
            note(
                err,
                TxnMsg::Cause {
                    error: shown(cause),
                },
            );
            for l in cleanup_lines(cleanup) {
                let _ = err.line(&l);
            }
            note(
                err,
                match holding(cleanup) {
                    (0, _) => TxnMsg::FinishKept { txn: *txn },
                    _ => TxnMsg::FinishCleanup { txn: *txn },
                },
            );
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
