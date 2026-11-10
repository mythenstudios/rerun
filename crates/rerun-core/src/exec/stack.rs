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
//!
//! Holds and slots (P4-8, P4-8b): a later transaction that meets the revert's objects only
//! through relying ops (`share::relies`: a hold of a created file, a file or folder below a
//! created folder) takes them over (E6): `for_revert` returns them as keeps instead of refusing.
//! Any other overlap stays newest first; one through a `Hold` (a file this one replaced) has its
//! own text (`Refusal::Held`). An apply that would change a held file is `Refusal::HeldChange`
//! (S2). An apply whose package
//! DLL (a slot) lies where a live transaction has a DLL of another package is refused
//! (`Refusal::SlotTaken`): Rerun does not chainload DLLs.

use super::Refusal;
use super::bind::Bindings;
use super::share::{self, Keeps, Relier};
use crate::escape::Shown;
use crate::journal::{Journal, Listed, Listing, TxnId, TxnState, VerifyBackups};
use crate::plan::{Object, Op, Plan, Target, overlap};

/// The objects of a head, each with whether its op is a `Hold` (P4-8).
struct Objs(Vec<(Object, bool)>);

impl Objs {
    fn of(p: &Plan, objs: Vec<(usize, Object)>) -> Self {
        Self(
            objs.into_iter()
                .map(|(k, o)| (o, matches!(p.ops.get(k), Some(Op::Hold { .. }))))
                .collect(),
        )
    }

    /// A held object of these overlaps an object of `mine` whose op changes it (`changes`,
    /// aligned with `mine`).
    fn holds_changed(&self, mine: &[Object], changes: &[bool]) -> bool {
        self.0
            .iter()
            .filter(|(_, held)| *held)
            .any(|(o, _)| mine.iter().zip(changes).any(|(m, ch)| *ch && m.overlaps(o)))
    }

    /// Whether these objects overlap `mine`, and if so whether a `Hold` is among them.
    fn meets(&self, mine: &[Object]) -> Meets {
        let mut seen = Meets::No;
        for (o, held) in &self.0 {
            if mine.iter().any(|m| m.overlaps(o)) {
                if *held {
                    return Meets::Held;
                }
                seen = Meets::Changed;
            }
        }
        seen
    }
}

/// How a later transaction meets the objects of a revert.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Meets {
    No,
    /// It holds one of them (a shared package file, P4-8): it relies on the earlier one.
    Held,
    /// It changed one of them, or a file in a folder the earlier one created.
    Changed,
}

/// What a listed transaction means for stacking.
enum Class {
    /// Closed, empty or forgotten: blocks nothing.
    Ignore,
    /// Unreadable, damaged without a usable head, a head that changed or cannot be parsed:
    /// blocks every apply and the revert of every earlier transaction (fail closed).
    Blocked,
    /// Applied and not reverting: later applies may stack on it.
    Active(Objs),
    /// Open, or applied with a revert begun (condition 3) or a rebind recorded (P2-14).
    Open(Objs),
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
    let Ok(by_op) = b.objects_by_op(&p) else {
        return Class::Blocked;
    };
    let objs: Vec<Object> = by_op.iter().map(|(_, o)| o.clone()).collect();
    match &full.state {
        TxnState::Damaged(_) if !full.head_usable() => Class::Blocked,
        _ if damaged => Class::Damaged(objs),
        TxnState::Damaged(_) => Class::Damaged(objs),
        TxnState::Open | TxnState::Applied if super::status::cleanup_pending(&full.ops) => {
            Class::Cleanup(objs)
        }
        TxnState::Open => Class::Open(Objs::of(&p, by_op.clone())),
        TxnState::Applied
            if full.ops.values().any(|o| !o.reverts.is_empty()) || !full.rebinds.is_empty() =>
        {
            Class::Open(Objs::of(&p, by_op.clone()))
        }
        TxnState::Applied => Class::Active(Objs::of(&p, by_op)),
        TxnState::Closed(_) | TxnState::Empty => Class::Ignore,
    }
}

/// Apply: no blocked transaction at all, no open one on an object of `mine`.
pub(super) fn for_apply(
    j: &Journal<'_>,
    l: &Listing,
    mine: &[Object],
    changes: &[bool],
) -> Result<(), Refusal> {
    for t in &l.txns {
        match classify(j, t) {
            Class::Blocked => return Err(Refusal::Blocked { txn: t.id }),
            Class::Damaged(o) if overlap(&o, mine) => return Err(Refusal::Blocked { txn: t.id }),
            Class::Open(o) if o.meets(mine) != Meets::No => {
                return Err(Refusal::Interrupted { txn: t.id });
            }
            // P4-8b (S2): a file a live `Hold` holds is not changed under it (a replace or an INI
            // edit); the holder relies on its content.
            Class::Active(o) if o.holds_changed(mine, changes) => {
                return Err(Refusal::HeldChange { txn: t.id });
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

/// A DLL slot of `mine` taken by a live transaction (P4-8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SlotTaken {
    /// The transaction.
    pub(crate) txn: TxnId,
    /// The op of `mine`.
    pub(crate) op: u16,
    /// The DLL, as `mine` names it.
    pub(crate) path: Shown<'static>,
    /// The package of the transaction there (escaped: a head is untrusted).
    pub(crate) package: Shown<'static>,
}

/// The first DLL of a package that `mine` puts or holds where a live transaction (open,
/// applied, damaged with a usable head; not closed, empty or forgotten) has a DLL of another
/// package that it has not reverted yet (P4-8, from the heads: `ContentRef::Package` and the
/// object). A transaction whose head cannot be read is left to stacking (`Blocked`). Rerun does
/// not chainload DLLs, so two packages never share a DLL slot.
pub(crate) fn slot_taken(j: &Journal<'_>, l: &Listing, mine: &Plan) -> Option<SlotTaken> {
    let my_objs = Object::of(mine).ok()?;
    let slots: Vec<(usize, &str, &Object)> = mine
        .ops
        .iter()
        .zip(&my_objs)
        .enumerate()
        .filter_map(|(k, (op, o))| {
            let (id, _) = op.package_file()?;
            let Target::File { path, .. } = op.target() else {
                return None;
            };
            crate::catalog::check::is_dll(path).then_some((k, id, o))
        })
        .collect();
    if slots.is_empty() {
        return None;
    }
    for t in &l.txns {
        if t.forgotten {
            continue;
        }
        let Ok(v) = &t.view else { continue };
        if matches!(v.state, TxnState::Closed(_) | TxnState::Empty) {
            continue;
        }
        let Ok(full) = j.load(&t.id, VerifyBackups::Length) else {
            continue;
        };
        let Some(p) = full
            .head
            .as_deref()
            .and_then(|h| super::decode_head(h).ok())
        else {
            continue;
        };
        let Some(b) = Bindings::of(&p, &full.rebinds) else {
            continue;
        };
        let Ok(objs) = b.objects_by_op(&p) else {
            continue;
        };
        for (k, o) in &objs {
            let k = *k;
            let Some((theirs, _)) = p.ops.get(k).and_then(Op::package_file) else {
                continue;
            };
            let reverted = full
                .ops
                .get(&super::op_ix(k))
                .is_some_and(|x| x.reverted.is_some());
            if reverted {
                continue;
            }
            if let Some((mk, _, _)) = slots
                .iter()
                .find(|(_, id, mo)| *id != theirs && mo.overlaps(o))
            {
                let path = match mine.ops.get(*mk).map(Op::target) {
                    Some(Target::File { path, .. }) => crate::escape::path(path.as_str()),
                    _ => continue,
                };
                return Some(SlotTaken {
                    txn: t.id,
                    op: super::op_ix(*mk),
                    path: path.into_owned(),
                    package: crate::escape::text(theirs).into_owned(),
                });
            }
        }
    }
    None
}

/// Revert of `own`: no later transaction blocked, none active or open on an object of `mine`.
pub(super) fn for_revert(
    j: &Journal<'_>,
    l: &Listing,
    own: &TxnId,
    mine: &[Object],
    me: Option<&Me<'_>>,
) -> Result<Keeps, Refusal> {
    let mut keeps = Keeps::new();
    for t in l.txns.iter().filter(|t| t.id > *own) {
        match classify(j, t) {
            Class::Blocked => return Err(Refusal::Blocked { txn: t.id }),
            Class::Damaged(o) if overlap(&o, mine) => return Err(Refusal::Blocked { txn: t.id }),
            Class::Open(o) | Class::Active(o) => {
                let m = o.meets(mine);
                if m == Meets::No {
                    continue;
                }
                // P4-8b (E6): a later transaction that meets this one only through relying ops
                // takes the objects over; anything else stays newest first.
                if let Some(me) = me.filter(|m| !m.rebound)
                    && let Some(other) = share::load(j, t)
                    && other.applied
                    && !other.damaged
                    && let Some(rel) = relying_pairs(&other, me)
                {
                    for (k, r) in rel {
                        keeps.entry(k).or_default().push(r);
                    }
                    continue;
                }
                return Err(match m {
                    Meets::Held => Refusal::Held { txn: t.id },
                    Meets::Changed | Meets::No => Refusal::Later { txn: t.id },
                });
            }
            Class::Cleanup(o) if overlap(&o, mine) => {
                return Err(Refusal::CleanupPending { txn: t.id });
            }
            Class::Ignore | Class::Cleanup(_) | Class::Damaged(_) => {}
        }
    }
    Ok(keeps)
}

/// The reverting transaction as [`for_revert`] compares it with later ones (P4-8b); without it
/// the plain LIFO holds (a rebind's check).
pub(super) struct Me<'a> {
    /// Its head.
    pub(super) plan: &'a Plan,
    /// Its objects with their ops (as stacking sees them).
    pub(super) objs: &'a [(usize, Object)],
    /// It recorded a `Rebind`: no hand-over (X14).
    pub(super) rebound: bool,
}

/// Every pair of an object of `other` and one of `me` that overlap is a relying op of `other`
/// (applied: `Done`, no revert begun) on a created object of `me`: the reliers by op of `me`;
/// `None` if any pair is not.
fn relying_pairs(other: &share::Other, me: &Me<'_>) -> Option<Vec<(u16, Relier)>> {
    let mut out = Vec::new();
    for (k2, o2) in other.objs.iter().enumerate() {
        let k2 = super::op_ix(k2);
        for (k, mo) in me.objs {
            if !mo.overlaps(o2) {
                continue;
            }
            let later = other.plan.ops.get(usize::from(k2))?;
            let mine = me.plan.ops.get(*k)?;
            let log = other.ops.get(&k2)?;
            // Two holds of one file: neither changed anything, no order between them (P4-8b §2).
            if matches!(mine, Op::Hold { .. })
                && matches!(later, Op::Hold { .. })
                && share::same_file(mo, o2)
            {
                continue;
            }
            let name = share::relies(later, o2, mine, mo)?;
            let done = log.done?;
            if !log.reverts.is_empty() || log.reverted.is_some() {
                return None;
            }
            out.push((
                super::op_ix(*k),
                Relier {
                    txn: other.id,
                    op: k2,
                    held_id: matches!(later, Op::Hold { .. })
                        .then_some(done.file_id)
                        .flatten(),
                    name,
                },
            ));
        }
    }
    Some(out)
}
