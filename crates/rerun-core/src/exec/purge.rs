//! Which settled transactions may be purged (P5-6d, ADR 0019 amendment P5-6d): the rules that
//! need the other transactions or the head, enforced here and not in a front end (S1); the
//! journal itself refuses anything that is not settled or not Rerun's
//! (`JournalLock::purge`).
//!
//! - **Not settled** (`Open`, `Applied`, a cleanup pending, `Damaged` without a marker) and
//!   **unreadable** folders (with or without a marker) are never purged.
//! - **Forgotten** ones (a `Closed { Forgotten }` record or a marker) are not purged in this
//!   step (user decision E3: only with a preview of the backups lost, P5-6d-2); one whose launch
//!   profile op is applied holds the profile and is never purged (`HoldsProfile`).
//! - **A hand-over (B1, fail closed):** a closed transaction with a `Kept` op stays while any
//!   newer transaction that is not forgotten is not settled (`Open`, `Applied`, a cleanup
//!   pending, `Damaged`) or cannot be read: such a transaction may rely on what was kept, and
//!   the records that prove it are read from the creator (ADR 0019 amendment P4-8b). Who
//!   relies on what is deliberately not asked: an unreadable heir cannot say.
//! - **Foreign content** (a planted tail after `Closed`, an unknown entry) and **too many
//!   entries** are refused as such.

use crate::journal::{
    Closing, Damage, Journal, JournalError, Listed, Listing, Observed, PurgeStop, TxnId, TxnState,
    VerifyBackups,
};
use crate::plan::{Op, RootKind};
use crate::sys::SysErrorKind;

use super::{ExecCtx, ExecError, Refusal, decode_head, standard_user};

/// Why a transaction stays.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Keep {
    /// Not settled: open, applied, a cleanup pending, or damaged (and not forgotten).
    NotSettled,
    /// Its folder cannot be read.
    Unreadable,
    /// Forgotten, and its launch profile op is applied: it holds the profile.
    HoldsProfile,
    /// It handed a file or folder over (`Kept`) and a newer transaction may still rely on it.
    HandedOver,
    /// Its folder holds something Rerun did not write there.
    Foreign,
    /// Its folder has too many entries.
    TooManyEntries,
    /// Forgotten (its backups are not purged without their own preview, P5-6d-2).
    Forgotten,
    /// A file of it is in use; its purge is finished by a later run.
    InUse,
}

/// What [`purge_seen`] did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PurgeReport {
    /// Purged.
    pub removed: Vec<TxnId>,
    /// Asked for, and not in the journal (any more): purged already, which counts as done.
    pub gone: Vec<TxnId>,
    /// Asked for, and kept.
    pub refused: Vec<(TxnId, Keep)>,
    /// Launch results deleted (P5-6d-1b; none yet).
    pub results: usize,
}

/// The rules of this module for one listed transaction: `None` if it may be purged.
fn keep(j: &Journal<'_>, l: &Listing, t: &Listed) -> Option<Keep> {
    let Ok(v) = &t.view else {
        return Some(Keep::Unreadable);
    };
    if t.forgotten || v.state == TxnState::Closed(Closing::Forgotten) {
        return Some(if holds_profile(j, &t.id) {
            Keep::HoldsProfile
        } else {
            Keep::Forgotten
        });
    }
    match &v.state {
        TxnState::Damaged(Damage::TooManyEntries) => return Some(Keep::TooManyEntries),
        TxnState::Damaged(Damage::UnknownEntry) => return Some(Keep::Foreign),
        TxnState::Open | TxnState::Applied | TxnState::Damaged(_) => {
            return Some(Keep::NotSettled);
        }
        TxnState::Closed(_) if v.anomaly.is_some() => return Some(Keep::Foreign),
        TxnState::Closed(_) | TxnState::Empty => {}
    }
    let kept = v.ops.values().any(|o| {
        o.reverted
            .as_ref()
            .is_some_and(|r| r.observed == Observed::Kept)
    });
    (kept && l.txns.iter().any(|o| o.id > t.id && unsettled_heir(o))).then_some(Keep::HandedOver)
}

/// A newer transaction that may rely on what an older one kept (B1, fail closed): not
/// forgotten, and unreadable or not closed and not empty.
fn unsettled_heir(o: &Listed) -> bool {
    !o.forgotten
        && match &o.view {
            Err(_) => true,
            Ok(v) => matches!(
                v.state,
                TxnState::Open | TxnState::Applied | TxnState::Damaged(_)
            ),
        }
}

/// A forgotten transaction whose launch profile op (a file op on the profiles root) has its
/// `Done` and no `RevertDone`: it holds the profile. A head that cannot be read or decoded
/// says nothing (the transaction stays as forgotten anyway).
fn holds_profile(j: &Journal<'_>, id: &TxnId) -> bool {
    let Ok(v) = j.load(id, VerifyBackups::Length) else {
        return false;
    };
    let Some(plan) = v.head.as_deref().and_then(|h| decode_head(h).ok()) else {
        return false;
    };
    plan.ops.iter().enumerate().any(|(k, op)| {
        let root = match op {
            Op::CreateFile { root, .. } | Op::ReplaceFile { root, .. } => root,
            _ => return false,
        };
        let profiles = plan
            .roots
            .get(usize::from(root.0))
            .is_some_and(|r| r.kind == RootKind::Profiles);
        let applied = u16::try_from(k)
            .ok()
            .and_then(|k| v.ops.get(&k))
            .is_some_and(|o| o.done.is_some() && o.reverted.is_none());
        profiles && applied
    })
}

/// How [`purge_seen`] treats an ID that is not removable (review S-2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "flow::history uses both from P5-6d-1b on")
)]
pub(crate) enum PurgeMode {
    /// "Clear history": the user confirmed exactly these IDs. If any of them is not removable
    /// any more (a [`Keep`] applies now) or has another head, nothing is written and the
    /// result is `Refusal::Changed`.
    Exact,
    /// The automatic cap: what is not removable is reported in [`PurgeReport::refused`] and the
    /// rest goes.
    Lenient,
}

/// Purges the transactions `ids` (each with the hash of its head as the caller saw it, `None`
/// without one) under the journal lock, by the rules of this module. Every ID (each once, the
/// first occurrence) is classified on one listing before anything is written: a head other
/// than the one seen is `Refusal::Changed` with nothing written, in both modes; in
/// [`PurgeMode::Exact`] so is an ID a [`Keep`] applies to. An ID not listed counts as gone
/// (done) in both. Then it finishes what earlier purges left (`JournalLock::finish_purges`, best
/// effort) and purges. A file in use stops only its own transaction ([`Keep::InUse`]: its
/// tombstone stays, a later run finishes it); an access error of one transaction reports it
/// ([`Keep::Foreign`]) and the run goes on.
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "flow::history calls it from P5-6d-1b on")
)]
pub(crate) fn purge_seen(
    cx: &ExecCtx<'_>,
    ids: &[(TxnId, Option<[u8; 32]>)],
    mode: PurgeMode,
) -> Result<PurgeReport, ExecError> {
    standard_user(cx.sys)?;
    let j = Journal::new(cx.app, cx.tag);
    let lock = j.lock().map_err(Refusal::from)?;
    let listing = j.list().map_err(Refusal::from)?;
    let mut report = PurgeReport::default();
    let mut todo = Vec::new();
    let mut asked: Vec<TxnId> = Vec::new();
    for (id, seen) in ids {
        if asked.contains(id) {
            continue;
        }
        asked.push(*id);
        let Some(t) = listing.txns.iter().find(|t| t.id == *id) else {
            report.gone.push(*id);
            continue;
        };
        if let Ok(v) = &t.view
            && v.head_sha256 != *seen
        {
            return Err(Refusal::Changed { txn: *id }.into());
        }
        match (keep(&j, &listing, t), mode) {
            (None, _) => todo.push((*id, *seen)),
            (Some(_), PurgeMode::Exact) => return Err(Refusal::Changed { txn: *id }.into()),
            (Some(k), PurgeMode::Lenient) => report.refused.push((*id, k)),
        }
    }
    lock.finish_purges()?;
    for (id, head) in todo {
        match lock.purge(&id, head.as_ref()) {
            Ok(_) => report.removed.push(id),
            Err(JournalError::NotFound(_)) => report.gone.push(id),
            Err(JournalError::Purge { why, .. }) => report.refused.push((id, keep_of(why))),
            Err(JournalError::Root(_)) => report.refused.push((id, Keep::Unreadable)),
            Err(JournalError::Sys(e)) if e.kind == SysErrorKind::AccessDenied => {
                report.refused.push((id, Keep::Foreign));
            }
            Err(e) => return Err(e.into()),
        }
    }
    Ok(report)
}

/// The journal's reason as a [`Keep`].
fn keep_of(why: PurgeStop) -> Keep {
    match why {
        PurgeStop::InUse => Keep::InUse,
        PurgeStop::TooManyEntries => Keep::TooManyEntries,
        PurgeStop::NotSettled => Keep::NotSettled,
        // Under the lock the listing cannot change, so another head or a tombstone for another
        // head is something planted.
        PurgeStop::HeadChanged | PurgeStop::TombstoneInTheWay | PurgeStop::Foreign => Keep::Foreign,
    }
}
