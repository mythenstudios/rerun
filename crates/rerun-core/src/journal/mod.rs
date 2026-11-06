//! The journal (ADR 0019 and its P2-7 amendment): one folder per transaction below
//! `<AppDir>\journal`, with `head.json` (the plan bytes, opaque here) and immutable numbered
//! records, each written once with `create_new`.
//!
//! - [`names`]: [`TxnId`] (`<seq>-<tag>`), [`InstanceTag`], the names in a transaction folder.
//! - `record`: wire format 1 of a record (crate-internal), [`Observed`], [`Closing`],
//!   [`BackupRef`].
//! - `replay`: the grammar, pure; the reader and the writer share it.
//!
//! The journal is op-agnostic: records refer to ops by their index in the head; which op
//! kinds exist and what they change is `exec`'s business (ADR 0020).

pub mod names;
mod record;
mod replay;

use std::fmt;

pub use names::{InstanceTag, TxnId};
pub use record::{BackupRef, Closing, FORMAT, Observed};

use crate::sys::fs::TmpName;

/// State of a transaction after replaying its records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TxnState {
    /// Only the head (or nothing): nothing was changed, it blocks nothing.
    Empty,
    /// At least one record, neither `Applied` nor `Closed`: in progress or interrupted.
    Open,
    /// `Applied`, not closed: active.
    Applied,
    /// Closed.
    Closed(Closing),
    /// Not a valid journal; never acted on automatically, only `forget` closes it.
    Damaged(Damage),
}

/// Why a transaction is damaged (or, after a valid prefix that ends in `Closed`, the anomaly
/// of a closed one).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Damage {
    /// Records without `head.json`.
    #[error("head.json is missing")]
    HeadMissing,
    /// `head.json` is larger than the head limit.
    #[error("head.json is too large")]
    HeadTooLarge,
    /// Record `at` is missing while a later one exists.
    #[error("record {at} is missing")]
    Gap {
        /// The missing number.
        at: u16,
    },
    /// Record `n` is larger than the record limit.
    #[error("record {n} is too large")]
    TooLarge {
        /// Record number.
        n: u16,
    },
    /// Record `n` is not a record of format 1 in its one written form.
    #[error("record {n} cannot be parsed")]
    Unparsable {
        /// Record number.
        n: u16,
    },
    /// Record `n` has another `format`.
    #[error("record {n} has an unknown format")]
    Format {
        /// Record number.
        n: u16,
    },
    /// Record `n` carries another number than its file name.
    #[error("record {n} carries another number")]
    Numbering {
        /// Record number.
        n: u16,
    },
    /// Record `n` names another head than `head.json`.
    #[error("record {n} belongs to another head")]
    HeadHash {
        /// Record number.
        n: u16,
    },
    /// Record `n` breaks the grammar.
    #[error("record {n}: {why}")]
    Grammar {
        /// Record number.
        n: u16,
        /// The rule.
        why: &'static str,
    },
    /// An entry that is no part of a transaction folder (or a part of the wrong kind).
    #[error("an unknown entry in the transaction folder")]
    UnknownEntry,
    /// The transaction folder has more entries than the listing limit.
    #[error("too many entries in the transaction folder")]
    TooManyEntries,
    /// The backup of op `op` does not match its intent.
    #[error("the backup of op {op} is {why}")]
    Backup {
        /// Op index.
        op: u16,
        /// What is wrong.
        why: BackupFault,
    },
    /// Another transaction folder has the same sequence number.
    #[error("another transaction has the same sequence number")]
    DuplicateSeq,
}

impl Damage {
    /// The head cannot be trusted (ADR 0019 amendment, E2): such a transaction blocks every
    /// apply until it is forgotten. With any other damage the head is readable and
    /// hash-consistent, and its objects count as open.
    pub fn head_unusable(&self) -> bool {
        matches!(
            self,
            Self::HeadMissing | Self::HeadTooLarge | Self::HeadHash { .. }
        )
    }
}

/// What is wrong with a backup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackupFault {
    /// `op-NNNN.bin` is missing or not a plain file.
    Missing,
    /// Another length than the intent's.
    Length,
    /// Another hash than the intent's.
    Hash,
}

impl fmt::Display for BackupFault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Missing => "missing",
            Self::Length => "of another length",
            Self::Hash => "of another content",
        })
    }
}

/// The records of one op.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpLog {
    /// Its intent.
    pub intent: IntentRec,
    /// Its `Done`, if recorded.
    pub done: Option<DoneRec>,
    /// The temp name of each `RevertIntent`, in order.
    pub reverts: Vec<Option<TmpName>>,
    /// Its `RevertDone`, if recorded.
    pub reverted: Option<RevertDoneRec>,
}

/// An `Intent` record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntentRec {
    /// Temp name next to the target.
    pub tmp: Option<TmpName>,
    /// Backup of the old content.
    pub backup: Option<BackupRef>,
}

/// A `Done` record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DoneRec {
    /// File ID of what the op created.
    pub file_id: u128,
    /// `<tmp>.old` was left behind.
    pub old_left: bool,
}

/// A `RevertDone` record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RevertDoneRec {
    /// What the revert observed.
    pub observed: Observed,
    /// `<tmp>.old` was left behind.
    pub old_left: bool,
}
