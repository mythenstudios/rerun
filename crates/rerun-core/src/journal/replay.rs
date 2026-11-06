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
//! - `RevertDone(k)` directly after `RevertIntent(k)`.
//! - `Closed { RolledBack }` only without `Applied`, `Closed { Reverted }` only after it; both
//!   only when every intended op has its `RevertDone` and none observed `Foreign` (ADR 0020,
//!   D10). `Closed { Forgotten }` at any time.
//! - Nothing after `Closed`.

use std::collections::BTreeMap;

use super::record::{BackupRef, Closing, Observed, Record};
use super::{DoneRec, IntentRec, OpLog, RevertDoneRec, TxnState};
use crate::sys::fs::TmpName;

/// The record before the next one, as far as the grammar needs it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Last {
    Intent(u16),
    RevertIntent(u16),
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
}

impl Machine {
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
            Record::Intent { op, .. } => {
                if self.applied {
                    return Err("an intent after Applied");
                }
                if self.reverting {
                    return Err("an intent after a revert started");
                }
                if op != self.intents() {
                    return Err("an intent out of order");
                }
                if !all_done {
                    return Err("an intent before the previous op is done");
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
            }
            Record::RevertDone { op, .. } => {
                if self.last != Some(Last::RevertIntent(op)) {
                    return Err("revert done not directly after its revert intent");
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
            Record::Intent { op, tmp, backup } => {
                self.ops.insert(*op, OpLog::new(tmp.clone(), *backup));
                self.last = Some(Last::Intent(*op));
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
            }
            Record::Applied { .. } => self.applied = true,
            Record::RevertIntent { op, tmp } => {
                self.reverting = true;
                if let Some(o) = self.ops.get_mut(op) {
                    o.reverts.push(tmp.clone());
                }
                self.last = Some(Last::RevertIntent(*op));
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
                        old_left: *old_left,
                    });
                }
            }
            Record::Closed { how } => self.closed = Some(*how),
        }
        self.records = self.records.saturating_add(1);
        Ok(())
    }
}

impl OpLog {
    fn new(tmp: Option<TmpName>, backup: Option<BackupRef>) -> Self {
        Self {
            intent: IntentRec { tmp, backup },
            done: None,
            reverts: Vec::new(),
            reverted: None,
        }
    }
}

#[cfg(test)]
mod tests;
