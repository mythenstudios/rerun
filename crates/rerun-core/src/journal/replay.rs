//! The grammar of a transaction's records (ADR 0019 amendment, P2-7), pure.
//!
//! [`Machine`] is the one implementation: the reader replays every record through it (a
//! refused record makes the transaction [`Damage::Grammar`](super::Damage::Grammar)), and the
//! writer checks every record with it before writing, so Rerun never writes a sequence it
//! would read as damaged.
//!
//! - `Intent(k)` only before `Applied` and before any `RevertIntent`, with `k` the number of
//!   intents so far (the first is 0) and every earlier intent done.
//! - `Done(k)` directly after `Intent(k)`.
//! - `Applied { ops }` once, before any `RevertIntent`, with `ops` ≥ 1 equal to the number of
//!   intents and every intent done.
//! - `RevertIntent(k)` for the highest intended op without `RevertDone` (descending, the op
//!   whose intent came last first); repeatable (after a crash) until `RevertDone(k)`.
//! - `RevertDone(k)` directly after `RevertIntent(k)`; its `old_left` strictly ascending, each
//!   index a sequence of `k` with a temp name (0: the intent's; `i`: the `i`-th `RevertIntent`
//!   of `k` with one, P2-15).
//! - Record contents (P2-10a): an inline old state at most [`INLINE_MAX`] bytes; a
//!   `RevertIntent` names both `from` and `to` or neither.
//! - `Closed { RolledBack }` only without `Applied`, `Closed { Reverted }` only after it; both
//!   only when every intended op has its `RevertDone` and none observed `Foreign` (ADR 0020,
//!   D10). `Closed { Forgotten }` at any time.
//! - `Rebind` (P2-14) only after `Applied`: a root index below 16, at most 128 directory
//!   proofs, by op strictly ascending, each naming an intended op. Repeatable (the last one of a
//!   root holds). Which root and op kinds it may name, and that no op of its root has a
//!   `RevertIntent` before it, is `exec`'s business (the journal does not parse the head). It
//!   ends a pending `RevertIntent`'s claim to the next record, so `RevertDone` cannot follow it
//!   directly.
//! - Nothing after `Closed`.
//!
//! The helper batch (ADR 0023 §9, P4-2d; additive to format 1):
//! - `HelperBatch { first, last }` in place of the intents of ops `first..=last`: once, before
//!   `Applied` and before any revert record, with `first` the number of intents so far, every
//!   earlier intent done, 1 to [`MAX_BATCH`] ops. No intent after it: the batch is the last
//!   ops of a plan.
//! - `Done(k)` of a batch op without a file ID and without `old_left`: `Done(first)` directly
//!   after `HelperBatch`, `Done(k)` directly after `Done(k - 1)`.
//! - A batch op has no `RevertIntent`; `RevertBatch { first, last }` takes its place: `first`
//!   the batch's, `last` the op whose revert comes next (so every op above the batch has its
//!   `RevertDone`, and a revert interrupted inside the batch writes a new `RevertBatch` for the
//!   ops left). Repeatable.
//! - `RevertDone(k)` of a batch op without `old_left`: directly after a `RevertBatch` whose
//!   `last` is `k`, or directly after `RevertDone(k + 1)` of the batch.

use std::collections::BTreeMap;

use super::record::{Before, Closing, INLINE_MAX, MAX_DIRS, Observed, Record};
use super::{DoneRec, IntentRec, OpLog, RebindRec, RevertDoneRec, RevertRec, TxnState};

/// Most roots of a head (`plan::MAX_ROOTS`; the journal does not parse the head).
const MAX_ROOTS: u16 = 16;

/// Most ops of one helper batch (`elevate::MAX_BATCH_OPS`; the journal does not depend on it).
pub(crate) const MAX_BATCH: u16 = 8;

/// The record before the next one, as far as the grammar needs it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Last {
    Intent(u16),
    RevertIntent(u16),
    /// `HelperBatch`.
    Batch,
    /// `Done(k)`.
    Done(u16),
    /// `RevertBatch` with this `last`.
    RevertBatch(u16),
    /// `RevertDone(k)`.
    RevertDone(u16),
    Other,
}

/// Replay state of one transaction.
#[derive(Debug, Clone, Default)]
pub(crate) struct Machine {
    ops: BTreeMap<u16, OpLog>,
    applied: bool,
    reverting: bool,
    foreign: bool,
    closed: Option<Closing>,
    last: Option<Last>,
    records: u16,
    rebinds: Vec<RebindRec>,
    /// The helper batch: its first and last op (P4-2d).
    batch: Option<(u16, u16)>,
}

impl Machine {
    /// The helper batch, its first and last op (P4-2d).
    pub(crate) fn batch(&self) -> Option<(u16, u16)> {
        self.batch
    }

    /// `op` is an op of the helper batch.
    fn in_batch(&self, op: u16) -> bool {
        self.batch.is_some_and(|(f, l)| (f..=l).contains(&op))
    }

    /// Number of intents so far: the op number of the next intent.
    pub(crate) fn intents(&self) -> u16 {
        u16::try_from(self.ops.len()).unwrap_or(u16::MAX)
    }

    /// Number of records replayed.
    pub(crate) fn records(&self) -> u16 {
        self.records
    }

    /// The ops with an intent.
    pub(crate) fn ops(&self) -> &BTreeMap<u16, OpLog> {
        &self.ops
    }

    /// How the transaction was closed, if it was.
    pub(crate) fn closed(&self) -> Option<Closing> {
        self.closed
    }

    /// The `Rebind` records, in order (P2-14).
    pub(crate) fn rebinds(&self) -> &[RebindRec] {
        &self.rebinds
    }

    /// The lowest op with a `RevertIntent` so far: every op from it upwards has one (a revert
    /// goes newest first).
    fn reverting_from(&self) -> Option<u16> {
        self.ops
            .iter()
            .find(|(_, o)| !o.reverts.is_empty())
            .map(|(k, _)| *k)
    }

    /// `Applied` was recorded.
    pub(crate) fn applied(&self) -> bool {
        self.applied
    }

    /// The op whose revert comes next: the highest intended op without `RevertDone`.
    pub(crate) fn next_revert(&self) -> Option<u16> {
        self.ops
            .iter()
            .rev()
            .find(|(_, o)| o.reverted.is_none())
            .map(|(k, _)| *k)
    }

    /// The state after the records so far.
    pub(crate) fn state(&self) -> TxnState {
        match (self.closed, self.applied, self.records) {
            (Some(how), _, _) => TxnState::Closed(how),
            (None, true, _) => TxnState::Applied,
            (None, false, 0) => TxnState::Empty,
            (None, false, _) => TxnState::Open,
        }
    }

    /// Whether `r` may come next; `Err` names the broken rule.
    pub(crate) fn check(&self, r: &Record) -> Result<(), &'static str> {
        if self.closed.is_some() {
            return Err("a record after Closed");
        }
        let all_done = self.ops.values().all(|o| o.done.is_some());
        match *r {
            Record::Intent {
                before: Some(Before::Inline(ref v)),
                ..
            } if v.len() > INLINE_MAX => {
                return Err("an inline old state larger than 16 KiB");
            }
            Record::RevertIntent { from, to, .. } if from.is_some() != to.is_some() => {
                return Err("a revert intent with only one of from and to");
            }
            _ => {}
        }
        match *r {
            Record::Intent { op, .. } => {
                if self.applied {
                    return Err("an intent after Applied");
                }
                if self.reverting {
                    return Err("an intent after a revert started");
                }
                if self.batch.is_some() {
                    return Err("an intent after the helper batch");
                }
                if op != self.intents() {
                    return Err("an intent out of order");
                }
                if !all_done {
                    return Err("an intent before the previous op is done");
                }
            }
            Record::HelperBatch { first, last, .. } => {
                if self.applied {
                    return Err("a helper batch after Applied");
                }
                if self.reverting {
                    return Err("a helper batch after a revert started");
                }
                if self.batch.is_some() {
                    return Err("a second helper batch");
                }
                if first != self.intents() {
                    return Err("a helper batch out of order");
                }
                if last < first || last - first >= MAX_BATCH {
                    return Err("a helper batch of other than 1 to 8 ops");
                }
                if !all_done {
                    return Err("a helper batch before the previous op is done");
                }
            }
            Record::Done {
                op,
                file_id,
                old_left,
            } if self.in_batch(op) => {
                let after = match self.batch {
                    Some((first, _)) if op == first => Last::Batch,
                    _ => Last::Done(op.wrapping_sub(1)),
                };
                if self.last != Some(after) {
                    return Err("a batch op's done not in batch order");
                }
                if file_id.is_some() || old_left {
                    return Err("a batch op's done with a file ID or a .old");
                }
            }
            Record::Done { op, .. } => {
                if self.last != Some(Last::Intent(op)) {
                    return Err("done not directly after its intent");
                }
            }
            Record::Applied { ops } => {
                if self.applied {
                    return Err("a second Applied");
                }
                if self.reverting {
                    return Err("Applied after a revert started");
                }
                if ops == 0 || ops != self.intents() {
                    return Err("Applied does not count every intent");
                }
                if !all_done {
                    return Err("Applied before every op is done");
                }
            }
            Record::RevertIntent { op, .. } => {
                if self.next_revert() != Some(op) {
                    return Err("a revert intent out of order");
                }
                if self.in_batch(op) {
                    return Err("a revert intent for a batch op");
                }
            }
            Record::RevertBatch { first, last, .. } => {
                if self.batch.map(|(f, _)| f) != Some(first) || !self.in_batch(last) {
                    return Err("a revert batch that is not the helper batch");
                }
                if self.next_revert() != Some(last) {
                    return Err("a revert batch out of order");
                }
            }
            Record::RevertDone {
                op, ref old_left, ..
            } if self.in_batch(op) => {
                let ok = self.last == Some(Last::RevertBatch(op))
                    || (op.checked_add(1).is_some_and(|n| self.in_batch(n))
                        && self.last == Some(Last::RevertDone(op + 1)));
                if !ok {
                    return Err("a batch op's revert done not in batch order");
                }
                if !old_left.is_empty() {
                    return Err("a batch op's revert done with a .old");
                }
            }
            Record::RevertDone {
                op, ref old_left, ..
            } => {
                if self.last != Some(Last::RevertIntent(op)) {
                    return Err("revert done not directly after its revert intent");
                }
                if old_left.windows(2).any(|w| w[0] >= w[1]) {
                    return Err("a revert done's .old files out of order");
                }
                let named = |i: &u16| self.ops.get(&op).is_some_and(|o| o.seq_tmp(*i).is_some());
                if !old_left.iter().all(named) {
                    return Err("a revert done names a .old the op has no temp name for");
                }
            }
            Record::Rebind { root, ref dirs, .. } => {
                if !self.applied {
                    return Err("a rebind before Applied");
                }
                if root >= MAX_ROOTS {
                    return Err("a rebind of a root outside a head");
                }
                if dirs.len() > MAX_DIRS {
                    return Err("a rebind with too many directories");
                }
                if dirs.windows(2).any(|w| w[0].op >= w[1].op) {
                    return Err("a rebind's directories out of order");
                }
                if dirs.iter().any(|d| !self.ops.contains_key(&d.op)) {
                    return Err("a rebind names an op without intent");
                }
            }
            Record::Closed { how } => match how {
                Closing::Forgotten => {}
                Closing::RolledBack | Closing::Reverted => {
                    if how == Closing::RolledBack && self.applied {
                        return Err("RolledBack after Applied");
                    }
                    if how == Closing::Reverted && !self.applied {
                        return Err("Reverted without Applied");
                    }
                    if self.next_revert().is_some() {
                        return Err("closed before every op is reverted");
                    }
                    if self.foreign {
                        return Err("closed as reverted although an op was Foreign");
                    }
                }
            },
        }
        Ok(())
    }

    /// Checks `r` and replays it.
    pub(crate) fn step(&mut self, r: &Record) -> Result<(), &'static str> {
        self.check(r)?;
        self.last = Some(Last::Other);
        match r {
            Record::Intent { op, tmp, before } => {
                self.ops
                    .insert(*op, OpLog::new(tmp.clone(), before.clone()));
                self.last = Some(Last::Intent(*op));
            }
            Record::HelperBatch { first, last, .. } => {
                for k in *first..=*last {
                    let mut log = OpLog::new(None, None);
                    log.intent.batch = true;
                    self.ops.insert(k, log);
                }
                self.batch = Some((*first, *last));
                self.last = Some(Last::Batch);
            }
            Record::Done {
                op,
                file_id,
                old_left,
            } => {
                if let Some(o) = self.ops.get_mut(op) {
                    o.done = Some(DoneRec {
                        file_id: *file_id,
                        old_left: *old_left,
                    });
                }
                self.last = Some(Last::Done(*op));
            }
            Record::Applied { .. } => self.applied = true,
            Record::RevertIntent { op, tmp, from, to } => {
                self.reverting = true;
                if let Some(o) = self.ops.get_mut(op) {
                    o.reverts.push(RevertRec {
                        tmp: tmp.clone(),
                        from: *from,
                        to: *to,
                    });
                }
                self.last = Some(Last::RevertIntent(*op));
            }
            Record::RevertBatch { first, last, .. } => {
                self.reverting = true;
                for k in *first..=*last {
                    if let Some(o) = self.ops.get_mut(&k) {
                        o.reverts.push(RevertRec {
                            tmp: None,
                            from: None,
                            to: None,
                        });
                    }
                }
                self.last = Some(Last::RevertBatch(*last));
            }
            Record::RevertDone {
                op,
                observed,
                old_left,
            } => {
                self.foreign |= *observed == Observed::Foreign;
                if let Some(o) = self.ops.get_mut(op) {
                    o.reverted = Some(RevertDoneRec {
                        observed: *observed,
                        old_left: old_left.clone(),
                    });
                }
                self.last = Some(Last::RevertDone(*op));
            }
            Record::Rebind {
                root,
                old,
                store,
                store_id,
                id,
                dirs,
            } => {
                let reverting = self.reverting_from();
                self.rebinds.push(RebindRec {
                    root: *root,
                    old: *old,
                    store: store.clone(),
                    store_id: *store_id,
                    id: *id,
                    dirs: dirs.clone(),
                    reverting,
                });
            }
            Record::Closed { how } => self.closed = Some(*how),
        }
        self.records = self.records.saturating_add(1);
        Ok(())
    }
}

impl OpLog {
    fn new(tmp: Option<crate::sys::fs::TmpName>, before: Option<Before>) -> Self {
        Self {
            intent: IntentRec {
                tmp,
                before,
                batch: false,
            },
            done: None,
            reverts: Vec::new(),
            reverted: None,
        }
    }
}

#[cfg(test)]
mod tests;
