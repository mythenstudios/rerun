//! The journal (ADR 0019 and its P2-7 amendment): one folder per transaction below
//! `<AppDir>\journal`, with `head.json` (the plan bytes, opaque here) and immutable numbered
//! records, each written once with `create_new`.
//!
//! - [`names`]: [`TxnId`] (`<seq>-<tag>`), [`InstanceTag`], the names in a transaction folder.
//! - `record`: wire format 1 of a record (crate-internal), [`Observed`], [`Closing`],
//!   [`Before`], [`Digest`].
//! - `replay`: the grammar, pure; the reader and the writer share it.
//! - `read`: [`Journal::list`] and [`Journal::load`], without the lock. The journal is
//!   untrusted input: bounded reads, one written form, `Damaged` instead of guessing.
//! - `write`: [`JournalLock`] (`journal\lock`, held by apply, revert and forget) with `begin`
//!   (a new transaction) and `resume` (revert only, condition S4), and the writers.
//!
//! The journal is op-agnostic: records refer to ops by their index in the head; which op
//! kinds exist and what they change is `exec`'s business (ADR 0020).
//!
//! Write order per op (ADR 0019): guard; `backup` (streamed from the guard into
//! `op-NNNN.bin` with `create_new`, then read back and compared, which proves the content,
//! not its durability); `intent` (`create_new` of the record, then the transaction folder is
//! flushed: the ordered volume log makes the folder, `head.json`, the backup and every
//! earlier record durable with it); the change; `done` (not flushed; the next flush covers
//! it). The caller flushes the changed folders before `applied` and before `close`, which
//! flush the transaction folder, as does every `revert_intent`.

pub mod names;
mod read;
mod record;
mod replay;
mod write;

use std::collections::BTreeMap;
use std::fmt;
use std::sync::OnceLock;
use std::sync::atomic::AtomicU64;

use names::LOCK;
pub use names::{InstanceTag, TxnId};
pub use record::{
    Before, Closing, Digest, DirProof, FORMAT, INLINE_MAX, MAX_DIRS, Observed, Semantic,
};
pub use write::JournalLock;
#[cfg_attr(
    not(test),
    expect(unused_imports, reason = "P2-14: exec uses it from the next commit on")
)]
pub(crate) use write::RebindArgs;
pub(crate) use write::{BeforeArg, Reverting, TxnWriter};
#[cfg(test)]
pub(crate) use write::{FlushSite, knob};

use crate::path::{RelPath, RootPath};
use crate::policy::root::{AppDir, AppSub, Create, RootError, RootId};
use crate::sys::fs::{ReadSeek, TmpName};
use crate::sys::{DirWrite, SysError, SysErrorKind};

/// Budgets of the journal (ADR 0019, condition S1). Crate-internal so tests can shrink them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Limits {
    /// `head.json`, bytes.
    pub(crate) head: u64,
    /// One record, bytes.
    pub(crate) record: u64,
    /// Records per transaction.
    pub(crate) records: u16,
    /// One backup, bytes.
    pub(crate) backup: u64,
    /// All backups of a transaction, bytes.
    pub(crate) backups: u64,
    /// Entries of a transaction folder.
    pub(crate) txn_entries: usize,
    /// Entries of `journal\`.
    pub(crate) journal_entries: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            head: 1 << 20,
            record: 64 << 10,
            records: 1024,
            backup: 2 << 30,
            backups: 4 << 30,
            txn_entries: 2 * 1024 + 128,
            journal_entries: 65_536,
        }
    }
}

/// An error of the journal itself (a damaged transaction is a [`TxnState`], not an error).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum JournalError {
    /// The lock is held: another Rerun is applying, reverting or forgetting.
    #[error("another Rerun is applying or reverting; try again when it has finished")]
    Busy,
    /// No such transaction.
    #[error("transaction {0} not found")]
    NotFound(TxnId),
    /// The transaction cannot be resumed in its state (closed or damaged).
    #[error("transaction {id} cannot be resumed: {state:?}")]
    NotResumable {
        /// The transaction.
        id: TxnId,
        /// Its state.
        state: TxnState,
    },
    /// A budget of the journal is exceeded; nothing was written for it.
    #[error("{what} exceeds the journal limit of {limit}")]
    TooLarge {
        /// What.
        what: &'static str,
        /// The limit.
        limit: u64,
    },
    /// An entry with the highest transaction name exists; `begin` cannot go on.
    #[error("journal entry {highest} has the highest sequence number; forget or remove it")]
    SeqExhausted {
        /// The entry.
        highest: TxnId,
    },
    /// A forget marker for another head is in the way (user decision D2).
    #[error("{path} names another head; remove it and forget again")]
    MarkerInTheWay {
        /// The marker, escaped for display.
        path: String,
    },
    /// The record would break the grammar (a caller error); nothing was written.
    #[error("journal record refused: {0}")]
    Order(&'static str),
    /// The backup read back differs from what the guard streamed; no intent was written.
    #[error("the backup of op {0} reads back differently")]
    BackupMismatch(u16),
    /// A record could not be serialised.
    #[error("journal record not serialisable: {0}")]
    Encode(String),
    /// Opening `AppDir\journal` or a transaction folder (a reparse point is refused).
    #[error(transparent)]
    Root(Box<RootError>),
    /// The system layer (with its Win32 or NTSTATUS code).
    #[error(transparent)]
    Sys(#[from] SysError),
}

impl From<RootError> for JournalError {
    fn from(e: RootError) -> Self {
        Self::Root(Box::new(e))
    }
}

/// How [`Journal::load`] checks the backups of a transaction that is not closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyBackups {
    /// Existence and length from the listing (`status`, user decision E3: "backup not
    /// verified"); a revert checks the hash on the guard when it restores.
    Length,
    /// Also stream and hash every backup.
    Hash,
}

/// One transaction as read from disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxnView {
    /// The transaction.
    pub id: TxnId,
    /// `head.json`, if present and within its limit (opaque plan bytes). Only
    /// [`Journal::load`] keeps the bytes; [`Journal::list`] keeps [`Self::head_sha256`]
    /// only, so a listing holds no head in memory (a budget per listing is not needed).
    pub head: Option<Vec<u8>>,
    /// SHA-256 of `head.json`, if it was read.
    pub head_sha256: Option<[u8; 32]>,
    /// The state.
    pub state: TxnState,
    /// The anomaly of a transaction whose valid prefix ends in `Closed` (user decision E2):
    /// it counts as closed and blocks nothing.
    pub anomaly: Option<Damage>,
    /// The records of each op with an intent (of the valid prefix).
    pub ops: BTreeMap<u16, OpLog>,
    /// The `Rebind` records of the valid prefix, in order (P2-14).
    pub rebinds: Vec<RebindRec>,
    /// The records of the valid prefix, in order.
    pub(crate) log: Vec<record::Record>,
    /// The folder holds at least one record file.
    pub(crate) has_records: bool,
}

impl TxnView {
    /// The head can be trusted for stacking (ADR 0019 amendment, E2): it was read, no damage
    /// concerns it, and at least one record confirmed its hash (or there are no records at
    /// all). Otherwise the transaction blocks every apply until it is forgotten; so does a
    /// [`Listed`] entry whose view is an error.
    pub fn head_usable(&self) -> bool {
        let head_damage = matches!(&self.state, TxnState::Damaged(d) if d.head_unusable());
        self.head_sha256.is_some() && !head_damage && (!self.log.is_empty() || !self.has_records)
    }
}

/// One entry of [`Listing`].
#[derive(Debug)]
pub struct Listed {
    /// The transaction name.
    pub id: TxnId,
    /// What was read (an error for a folder that cannot be opened, e.g. a reparse point).
    pub view: Result<TxnView, JournalError>,
    /// `journal\<txn>.forgotten` applies to it (user decision D2): a damaged transaction, or
    /// one whose view is an error, that `forget` closed without a record. It blocks nothing
    /// and is never acted on; its backups stay.
    pub forgotten: bool,
}

/// Every transaction in `journal\`, ordered by [`TxnId`].
#[derive(Debug, Default)]
pub struct Listing {
    /// The transactions.
    pub txns: Vec<Listed>,
    /// Entries of `journal\` that are neither `lock`, nor a transaction name, nor a Rerun
    /// temp name.
    pub foreign: usize,
}

/// An existing `journal\lock` held read side by a check ([`Journal::hold`]); released when it
/// drops. Empty when there was no lock file.
pub(crate) struct LockHold<'a>(Option<Box<dyn ReadSeek + 'a>>);

impl fmt::Debug for LockHold<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("LockHold").field(&self.0.is_some()).finish()
    }
}

/// The journal of an [`AppDir`].
#[derive(Debug)]
pub struct Journal<'a> {
    app: &'a AppDir<'a>,
    tag: InstanceTag,
    tmp_n: AtomicU64,
    lim: Limits,
    /// `journal\` with the write capability, opened (and created) by the first [`Self::lock`].
    dir: OnceLock<Box<dyn DirWrite + 'a>>,
}

impl<'a> Journal<'a> {
    /// The journal below `app`; opens nothing yet.
    pub fn new(app: &'a AppDir<'a>, tag: InstanceTag) -> Self {
        Self::with_limits(app, tag, Limits::default())
    }

    /// With other budgets (tests).
    pub(crate) fn with_limits(app: &'a AppDir<'a>, tag: InstanceTag, lim: Limits) -> Self {
        Self {
            app,
            tag,
            tmp_n: AtomicU64::new(0),
            lim,
            dir: OnceLock::new(),
        }
    }

    /// `journal\` with the write capability, created if missing.
    fn dir_write(&self) -> Result<&dyn DirWrite, JournalError> {
        if let Some(d) = self.dir.get() {
            return Ok(&**d);
        }
        let opened = self
            .app
            .sub_write(AppSub::Journal, Create::IfMissing)?
            .ok_or_else(|| SysError::new(SysErrorKind::NotFound, "journal"))?;
        // Another thread may have been first; either handle is `journal\`.
        Ok(&**self.dir.get_or_init(|| opened))
    }

    /// Takes `journal\lock` for the whole run of apply, revert or forget. `Busy` if another
    /// Rerun holds it; the kernel releases it when the process ends.
    pub fn lock(&self) -> Result<JournalLock<'_>, JournalError> {
        JournalLock::take(self.dir_write()?, self)
    }

    /// Holds an existing `journal\lock` for a check that writes nothing (`exec::check`, the
    /// `verify` before a revert or forget; P2-13 review S2): opened read side, never created,
    /// sharing read only. Held, it keeps any writer out ([`Self::lock`] opens with share 0,
    /// so it is `Busy` meanwhile), and a writer that holds it makes this `Busy`; two checks
    /// do not block each other. No `journal\` or no `lock` yet: nothing to hold; a writer that
    /// starts meanwhile creates the lock and checks everything again under it.
    pub(crate) fn hold(&self) -> Result<LockHold<'a>, JournalError> {
        let p = match RelPath::parse(&format!(r"journal\{LOCK}")) {
            Ok(p) => p,
            Err(e) => unreachable!("journal\\lock is a fixed valid path: {e}"),
        };
        match self.app.dir().open_read(&p) {
            Ok(r) => Ok(LockHold(Some(r))),
            Err(e) if e.kind == SysErrorKind::NotFound => Ok(LockHold(None)),
            Err(e) if e.kind == SysErrorKind::Busy => Err(JournalError::Busy),
            Err(e) if e.kind == SysErrorKind::ReparsePoint => Err(RootError::Reparse {
                store: self.app.path().clone(),
                at: p,
            }
            .into()),
            Err(e) => Err(e.into()),
        }
    }

    /// Every transaction, without the lock (`status`).
    pub fn list(&self) -> Result<Listing, JournalError> {
        match self.app.sub(AppSub::Journal)? {
            None => Ok(Listing::default()),
            Some(d) => read::list(&*d, &self.lim, self.app.path()),
        }
    }

    /// One transaction, without the lock.
    pub fn load(&self, id: &TxnId, v: VerifyBackups) -> Result<TxnView, JournalError> {
        match self.app.sub(AppSub::Journal)? {
            None => Err(JournalError::NotFound(*id)),
            Some(d) => read::load(&*d, id, v, &self.lim, self.app.path()),
        }
    }

    /// The backup `op-NNNN.bin` of transaction `id` read whole, without the lock (`verify`, the
    /// binding of a recorded INI head, P2-12), by [`read_backup`] (security review nit 3: one
    /// reader with the writer's `before_bytes`; the writer's `backup_bytes` writes one).
    pub(crate) fn read_backup(
        &self,
        id: &TxnId,
        op: u16,
        digest: &Digest,
        max: u64,
    ) -> Result<Vec<u8>, JournalError> {
        let j = self
            .app
            .sub(AppSub::Journal)?
            .ok_or(JournalError::NotFound(*id))?;
        let rel = id.rel();
        let d = j.open_dir(&rel).map_err(|e| match e.kind {
            SysErrorKind::NotFound => JournalError::NotFound(*id),
            SysErrorKind::ReparsePoint => reparse(self.app.path(), &rel),
            _ => JournalError::Sys(e),
        })?;
        read_backup(&*d, op, digest, max)
    }
}

/// `op-NNNN.bin` of `op` in the transaction folder `dir`, read whole: at most `max` (else
/// `TooLarge`) and the digest's length, checked against `digest`; missing, longer or another
/// content is `BackupMismatch`. The bytes returned are the bytes checked (no TOCTOU).
pub(crate) fn read_backup(
    dir: &dyn crate::sys::Dir,
    op: u16,
    digest: &Digest,
    max: u64,
) -> Result<Vec<u8>, JournalError> {
    if digest.len > max {
        return Err(JournalError::TooLarge {
            what: "an old state",
            limit: max,
        });
    }
    let bytes = match dir.read_limited(&names::backup_name(op), digest.len) {
        Ok(b) => b,
        Err(e) if matches!(e.kind, SysErrorKind::TooLarge | SysErrorKind::NotFound) => {
            return Err(JournalError::BackupMismatch(op));
        }
        Err(e) => return Err(e.into()),
    };
    let sha: [u8; 32] =
        sha2::Digest::finalize(<sha2::Sha256 as sha2::Digest>::new_with_prefix(&bytes)).into();
    if sha != digest.sha256 || u64::try_from(bytes.len()).ok() != Some(digest.len) {
        return Err(JournalError::BackupMismatch(op));
    }
    Ok(bytes)
}

/// `RootError::Reparse` for `journal\<rel>` below `app`.
fn reparse(app: &RootPath, rel: &RelPath) -> JournalError {
    RootError::Reparse {
        store: app.clone(),
        at: RelPath::parse(&format!(r"journal\{rel}")).unwrap_or_else(|_| rel.clone()),
    }
    .into()
}

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
    /// This damage concerns the head itself. Whether a head can be trusted is decided by
    /// [`TxnView::head_usable`], which also requires a record that confirmed its hash.
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
    /// Each `RevertIntent`, in order.
    pub reverts: Vec<RevertRec>,
    /// Its `RevertDone`, if recorded.
    pub reverted: Option<RevertDoneRec>,
}

/// An `Intent` record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntentRec {
    /// Temp name next to the target.
    pub tmp: Option<TmpName>,
    /// The old state its revert needs.
    pub before: Option<Before>,
}

impl IntentRec {
    /// The digest of the backup `op-NNNN.bin` this intent names, if any.
    pub fn bin(&self) -> Option<Digest> {
        match &self.before {
            Some(Before::Bin(d)) => Some(*d),
            Some(Before::Inline(_)) | None => None,
        }
    }
}

/// A `RevertIntent` record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevertRec {
    /// Temp name of a restore.
    pub tmp: Option<TmpName>,
    /// A semantic revert's start (P2-12, [`Semantic`]).
    pub from: Option<Digest>,
    /// A semantic revert's end (P2-12).
    pub to: Option<Digest>,
}

/// A `Rebind` record (P2-14): root `root` of the head is bound to the install folder of the
/// head in the Steam library `store` from here on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RebindRec {
    /// Root index in the head.
    pub root: u16,
    /// The identity of the game folder as bound before.
    pub old: RootId,
    /// The Steam library.
    pub store: RootPath,
    /// Identity of the library.
    pub store_id: RootId,
    /// Identity of the game folder.
    pub id: RootId,
    /// The folders the plan created, by their file ID in that folder.
    pub dirs: Vec<DirProof>,
    /// Not on the wire: the lowest op that had a `RevertIntent` when the record was replayed
    /// (every op from it upwards had one); `exec` refuses a rebind after a `RevertIntent` of an
    /// op of its root (user decision E-R3).
    pub reverting: Option<u16>,
}

/// A `Done` record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DoneRec {
    /// File ID of what a file op created or wrote (`None` for keys and values).
    pub file_id: Option<u128>,
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

#[cfg(test)]
mod crash_tests;
#[cfg(test)]
pub(crate) mod tests;
