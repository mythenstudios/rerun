//! `rerun uninstall-check` (P5-13b, ADR 0030): whether Rerun can be removed now, for
//! `uninstall.ps1`. Reads only (`flow::uninstall_check`), creates nothing, refuses elevated
//! (exit 3, user decision E3).
//!
//! - Exit 0: no change is open. Warnings may follow (games Steam may still start through
//!   `rerun-launch.exe`, forgotten transactions, Rerun's firewall rules no transaction owns).
//! - Exit 5: transactions are still open; they are listed as `rerun status` lists them, then the
//!   verdict line.
//! - Exit 3: refused (elevated, or that cannot be determined); exit 1: the journal or Rerun's
//!   folder cannot be read.
//!
//! Rerun's folder is named last (the uninstaller shows it with its size).

use std::io::Write;

use rerun_core::escape;
use rerun_core::flow::{self, UninstallVerdict, UninstallView};
use rerun_core::prim::SHIM;

use crate::cli::Exit;
use crate::host::{Host, fail, gate, shown};
use crate::messages::{Message, TxnMsg, UninstallMsg, Utc};
use crate::out::{Out, failed as failed_out};
use crate::txn::{orphan_lines, render_status};

fn u(m: UninstallMsg<'_>) -> Message<'_> {
    Message::Uninstall(m)
}

/// The lines of the check (module docs).
fn lines<'a>(v: &'a UninstallView, host: &Host<'_>) -> Vec<Message<'a>> {
    let mut out = Vec::new();
    let open = v.open().len();
    match (&v.status, v.verdict()) {
        (Some(s), UninstallVerdict::OpenChanges) => {
            out.extend(render_status(s, false));
            out.push(Message::Blank);
            out.push(u(UninstallMsg::Open { n: open }));
        }
        _ => out.push(u(UninstallMsg::Clean)),
    }
    let forgotten = v.forgotten();
    if forgotten > 0 {
        out.push(u(UninstallMsg::Forgotten { n: forgotten }));
    }
    if !v.launch_options.is_empty() {
        let shim = host
            .install
            .as_ref()
            .ok()
            .map(|dir| escape::path(&dir.join(SHIM).display().to_string()).into_owned());
        out.push(Message::Blank);
        out.push(u(UninstallMsg::LaunchHeading { shim }));
        for l in &v.launch_options {
            out.push(u(UninstallMsg::LaunchLeft {
                id: l.id,
                app: l.app_id,
            }));
            if let Some((txn, forgotten)) = l.held {
                out.push(u(UninstallMsg::LaunchHeld { txn, forgotten }));
            }
            match &l.last_start {
                Some(Ok(t)) => out.push(u(UninstallMsg::LaunchStarted { at: Utc(*t) })),
                Some(Err(why)) => {
                    out.push(u(UninstallMsg::LaunchResultUnreadable { why: why.clone() }))
                }
                None => {}
            }
        }
        out.push(u(UninstallMsg::LaunchHint));
    }
    if let Some(e) = &v.launch_unreadable {
        out.push(Message::Blank);
        out.push(u(UninstallMsg::LaunchUnreadable { error: shown(e) }));
    }
    if let Some(o) = &v.orphans {
        out.extend(orphan_lines(o));
    }
    out.push(Message::Blank);
    out.push(u(match &v.data {
        Ok(d) => UninstallMsg::DataFolder {
            exists: d.exists,
            path: escape::path(&d.path.to_string()).into_owned(),
        },
        Err(e) => UninstallMsg::DataUnknown { error: shown(e) },
    }));
    out
}

/// `rerun uninstall-check` (module docs).
pub fn check<W: Write, E: Write>(host: &Host<'_>, out: &mut Out<W>, err: &mut Out<E>) -> Exit {
    let g = match flow::guard(host.env()) {
        Ok(g) => g,
        Err(g) => return gate(err, g),
    };
    let v = match flow::uninstall_check(&g) {
        Ok(v) => v,
        Err(e) => {
            return fail(
                err,
                TxnMsg::JournalUnreadable { error: shown(&e) },
                Exit::Fatal,
            );
        }
    };
    let exit = match v.verdict() {
        UninstallVerdict::Clean => Exit::Report,
        UninstallVerdict::OpenChanges => Exit::Open,
    };
    match out.lines(&lines(&v, host)).and_then(|()| out.flush()) {
        Ok(()) => exit,
        Err(e) => match failed_out(err, e) {
            // A closed pipe after the report: the verdict stands (nothing was changed).
            Exit::Report => exit,
            other => other,
        },
    }
}
