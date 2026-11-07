//! C12: the exit codes of `exec`'s errors (ADR 0016 amendment "phase 2 commands"), one row of
//! the table each.

use rerun_core::exec::{ApplyError, ExecError, Refusal};
use rerun_core::journal::{JournalError, TxnId};
use rerun_core::sys::{SysError, SysErrorKind};

use super::{exit_for_apply, exit_for_exec};
use crate::cli::Exit;

fn txn() -> TxnId {
    "00000001-00000000000000ab".parse().unwrap()
}

fn op_error() -> ExecError {
    ExecError::Op {
        op: 0,
        source: SysError::new(SysErrorKind::AccessDenied, "x"),
    }
}

#[test]
fn c12_every_row_of_the_exit_table() {
    // 3: refused, whatever the reason.
    for r in [
        Refusal::JournalBusy,
        Refusal::Elevated,
        Refusal::NeedsHelper,
        Refusal::Mismatch { op: 1 },
        Refusal::Blocked { txn: txn() },
        Refusal::Interrupted { txn: txn() },
        Refusal::Later { txn: txn() },
        Refusal::Forgotten { txn: txn() },
    ] {
        let text = r.to_string();
        assert_eq!(
            exit_for_apply(&ApplyError::Refused(r)),
            Exit::Refused,
            "{text}"
        );
    }
    assert_eq!(
        exit_for_exec(&ExecError::Refused(Refusal::JournalBusy)),
        Exit::Refused
    );
    // 4: rolled back.
    assert_eq!(
        exit_for_apply(&ApplyError::RolledBack {
            txn: txn(),
            cause: Box::new(op_error()),
            cleanup: Vec::new(),
        }),
        Exit::RolledBack
    );
    // 5: left open; and every revert error after its first record.
    assert_eq!(
        exit_for_apply(&ApplyError::LeftOpen {
            txn: txn(),
            cause: Box::new(op_error()),
            rollback: Box::new(ExecError::Foreign { ops: vec![2] }),
        }),
        Exit::Open
    );
    for e in [
        op_error(),
        ExecError::Journal(JournalError::Busy),
        ExecError::Foreign { ops: vec![0] },
        ExecError::Sys(SysError::new(SysErrorKind::Other, "flush")),
    ] {
        let text = e.to_string();
        assert_eq!(exit_for_exec(&e), Exit::Open, "{text}");
    }
    // The numbers are an interface: only additive changes.
    let codes = [
        Exit::Report,
        Exit::Fatal,
        Exit::Usage,
        Exit::Refused,
        Exit::RolledBack,
        Exit::Open,
    ]
    .map(|e| e as u8);
    assert_eq!(codes, [0, 1, 2, 3, 4, 5]);
}
