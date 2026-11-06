//! Stacking and LIFO on the listing under the lock (ADR 0019, B-2; P2-7 amendment E2;
//! senior-dev conditions 3 and 6). Only the listing sees a duplicate `seq`, so every decision
//! starts from it; the head of a transaction that matters is then loaded once, and its state
//! and head come from that one load, whose head hash must equal the listing's.

use super::Refusal;
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
    /// Open, applied with a revert begun (condition 3), or damaged with a usable head.
    Open(Vec<Object>),
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
    let Ok(objs) = Object::of(&p) else {
        return Class::Blocked;
    };
    match &full.state {
        TxnState::Damaged(_) if !full.head_usable() => Class::Blocked,
        _ if damaged => Class::Open(objs),
        TxnState::Damaged(_) | TxnState::Open => Class::Open(objs),
        TxnState::Applied if full.ops.values().any(|o| !o.reverts.is_empty()) => Class::Open(objs),
        TxnState::Applied => Class::Active(objs),
        TxnState::Closed(_) | TxnState::Empty => Class::Ignore,
    }
}

/// Apply: no blocked transaction at all, no open one on an object of `mine`.
pub(super) fn for_apply(j: &Journal<'_>, l: &Listing, mine: &[Object]) -> Result<(), Refusal> {
    for t in &l.txns {
        match classify(j, t) {
            Class::Blocked => return Err(Refusal::Blocked { txn: t.id }),
            Class::Open(o) if overlap(&o, mine) => return Err(Refusal::Interrupted { txn: t.id }),
            Class::Ignore | Class::Active(_) | Class::Open(_) => {}
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
            Class::Open(o) | Class::Active(o) if overlap(&o, mine) => {
                return Err(Refusal::Later { txn: t.id });
            }
            Class::Ignore | Class::Active(_) | Class::Open(_) => {}
        }
    }
    Ok(())
}
