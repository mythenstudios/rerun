//! What the phase 2 commands share (P2-13): the host (system, install folder) and the guards
//! that run before anything is read for a change (ADR 0016 amendment "phase 2 commands").

use std::fmt::Display;
use std::io::Write;
use std::path::PathBuf;

use rerun_core::escape::{self, Shown};
use rerun_core::exec;
use rerun_core::policy::root::ForbiddenRoots;
use rerun_core::sys::System;

use crate::cli::Exit;
use crate::messages::{Message, TxnMsg};
use crate::out::{Out, OutError, failed};

/// What a command runs against.
pub struct Host<'a> {
    /// The system.
    pub sys: &'a dyn System,
    /// Rerun's install folder (the folder of `rerun.exe`), or why it is unknown.
    pub install: Result<PathBuf, String>,
}

/// An error's text through the text rule (it may name a file).
pub fn shown(e: &impl Display) -> Shown<'static> {
    escape::text(&e.to_string()).into_owned()
}

/// Writes `m` to stderr; nothing more to do if stderr is gone.
pub fn note<E: Write>(err: &mut Out<E>, m: TxnMsg<'_>) {
    let _ = err.line(&Message::Txn(m));
}

/// A line on stderr and `exit`.
pub fn fail<E: Write>(err: &mut Out<E>, m: TxnMsg<'_>, exit: Exit) -> Exit {
    note(err, m);
    exit
}

/// User decision E3: elevated (or undeterminable), only `system`, `scan` and `status` run.
pub fn standard_user<E: Write>(sys: &dyn System, err: &mut Out<E>) -> Result<(), Exit> {
    exec::standard_user(sys)
        .map_err(|r| fail(err, TxnMsg::Error { error: shown(&r) }, Exit::Refused))
}

/// The forbidden roots from Rerun's install folder; unknown or unresolvable is fatal (exit 1).
pub fn forbidden<E: Write>(host: &Host<'_>, err: &mut Out<E>) -> Result<ForbiddenRoots, Exit> {
    let dir = host.install.as_ref().map_err(|e| {
        let _ = err.line(&Message::CurrentExe {
            error: escape::text(e).into_owned(),
        });
        Exit::Fatal
    })?;
    ForbiddenRoots::resolve(host.sys, dir).map_err(|e| {
        let _ = err.line(&Message::ForbiddenRoots { error: shown(&e) });
        Exit::Fatal
    })
}

/// A write of the preview failed, before anything changed: a closed pipe is "nothing done"
/// (rule 5: a preview that did not arrive does not count), any other error fatal.
pub fn before_change<E: Write>(err: &mut Out<E>, e: OutError) -> Exit {
    match e {
        OutError::Closed => Exit::Refused,
        OutError::Io(_) => failed(err, e),
    }
}

/// A write of the report failed after the change: the change stands, so does its exit code;
/// a write error other than a closed pipe is named on stderr.
pub fn after_change<E: Write>(err: &mut Out<E>, e: OutError, exit: Exit) -> Exit {
    if let OutError::Io(kind) = e {
        let _ = err.line(&Message::WriteFailed { kind });
    }
    exit
}
