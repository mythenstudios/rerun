//! Stacking and LIFO on the listing under the lock (ADR 0019, B-2; P2-7 amendment E2;
//! senior-dev conditions 3 and 6). Only the listing sees a duplicate `seq`, so every decision
//! starts from it; the head of a transaction that matters is then loaded once, and its state
//! and head come from that one load, whose head hash must equal the listing's.
//!
//! Pending cleanup (P2-15, user decision E-C1 A): a transaction whose every op is reverted but
//! whose journal still names a `.old` of Rerun's is open too, with its own refusal
//! (`Refusal::CleanupPending`) for an apply on its objects and for the revert of an earlier
//! transaction on them (LIFO).
//!
//! Rebinds (P2-14, user decisions E-R3 and E-R6): a transaction with a `Rebind` counts as open
//! (a revert has begun), its objects lie at the head's roots and at the bound folders until it
//! is closed, and rebinds that do not fit the head make it `Blocked` (`Bindings::of`).

use super::Refusal;
use super::bind::Bindings;
use crate::journal::{Journal, Listed, Listing, TxnId, TxnState, VerifyBackups};
use crate::plan::{Object, overlap};

/// What a listed transaction means for stacking.
enum Class {
    /// Closed, empty or forgotten: blocks nothing.
    Ignore,
    /// Unreadable, damaged without a usable head, a head that changed or cannot be parsed:
    /// blocks every apply and the revert of every earlier transaction (fail closed).
    Blocked,
    /// Applied and not reverting: later applies may stack on it.
    Active(Vec<Object>),
    /// Open, or applied with a revert begun (condition 3) or a rebind recorded (P2-14).
    Open(Vec<Object>),
    /// Every op reverted, but a `.old` of Rerun's is left (P2-15): open, with its own text.
    Cleanup(Vec<Object>),
    /// Damaged with a usable head (P2-13 review S-A/S-d): only forget closes it, so it blocks
    /// every apply and every earlier revert on its objects as `Blocked` (one text for all of
    /// them); applies on other objects go on.
    Damaged(Vec<Object>),
}

fn classify(j: &Journal<'_>, l: &Listed) -> Class {
    if l.forgotten {
        return Class::Ignore;
    }
    let Ok(v) = &l.view else {
        return Class::Blocked;
    };
    let damaged = match &v.state {
        TxnState::Closed(_) | TxnState::Empty => return Class::Ignore,
        TxnState::Damaged(_) if !v.head_usable() => return Class::Blocked,
        TxnState::Damaged(_) => true,
        TxnState::Open | TxnState::Applied => false,
    };
    let Ok(full) = j.load(&l.id, VerifyBackups::Length) else {
        return Class::Blocked;
    };
    if full.head_sha256 != v.head_sha256 {
        return Class::Blocked;
    }
    let Some(head) = full.head.as_deref() else {
        return Class::Blocked;
    };
    // E4: the recorded rules, so a tightened rule never blocks every later apply.
    let Ok(p) = super::decode_head(head) else {
        return Class::Blocked;
    };
    let Some(b) = Bindings::of(&p, &full.rebinds) else {
        return Class::Blocked;
    };
    let Ok(objs) = b.objects(&p) else {
        return Class::Blocked;
    };
    match &full.state {
        TxnState::Damaged(_) if !full.head_usable() => Class::Blocked,
        _ if damaged => Class::Damaged(objs),
        TxnState::Damaged(_) => Class::Damaged(objs),
        TxnState::Open | TxnState::Applied if super::status::cleanup_pending(&full.ops) => {
            Class::Cleanup(objs)
        }
        TxnState::Open => Class::Open(objs),
        TxnState::Applied
            if full.ops.values().any(|o| !o.reverts.is_empty()) || !full.rebinds.is_empty() =>
        {
            Class::Open(objs)
        }
        TxnState::Applied => Class::Active(objs),
        TxnState::Closed(_) | TxnState::Empty => Class::Ignore,
    }
}

/// Apply: no blocked transaction at all, no open one on an object of `mine`.
pub(super) fn for_apply(j: &Journal<'_>, l: &Listing, mine: &[Object]) -> Result<(), Refusal> {
    for t in &l.txns {
        match classify(j, t) {
            Class::Blocked => return Err(Refusal::Blocked { txn: t.id }),
            Class::Damaged(o) if overlap(&o, mine) => return Err(Refusal::Blocked { txn: t.id }),
            Class::Open(o) if overlap(&o, mine) => return Err(Refusal::Interrupted { txn: t.id }),
            Class::Cleanup(o) if overlap(&o, mine) => {
                return Err(Refusal::CleanupPending { txn: t.id });
            }
            Class::Ignore
            | Class::Active(_)
            | Class::Open(_)
            | Class::Cleanup(_)
            | Class::Damaged(_) => {}
        }
    }
    Ok(())
}

/// Revert of `own`: no later transaction blocked, none active or open on an object of `mine`.
pub(super) fn for_revert(
    j: &Journal<'_>,
    l: &Listing,
    own: &TxnId,
    mine: &[Object],
) -> Result<(), Refusal> {
    for t in l.txns.iter().filter(|t| t.id > *own) {
        match classify(j, t) {
            Class::Blocked => return Err(Refusal::Blocked { txn: t.id }),
            Class::Damaged(o) if overlap(&o, mine) => return Err(Refusal::Blocked { txn: t.id }),
            Class::Open(o) | Class::Active(o) if overlap(&o, mine) => {
                return Err(Refusal::Later { txn: t.id });
            }
            Class::Cleanup(o) if overlap(&o, mine) => {
                return Err(Refusal::CleanupPending { txn: t.id });
            }
            Class::Ignore
            | Class::Active(_)
            | Class::Open(_)
            | Class::Cleanup(_)
            | Class::Damaged(_) => {}
        }
    }
    Ok(())
}
