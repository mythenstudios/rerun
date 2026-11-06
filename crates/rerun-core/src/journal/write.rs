//! Writing the journal (ADR 0019, "Write order and durability"; P2-7 amendment).
//!
//! Everything is written under [`JournalLock`]. [`JournalLock::begin`] starts a transaction
//! and hands out a [`TxnWriter`] (apply, with its rollback); [`JournalLock::resume`] reopens an
//! `Empty`, `Open` or `Applied` one as a [`RevertWriter`], which by its type can only revert
//! and close (condition S4). Every record is checked against the grammar before it is
//! written ([`Machine`]), written with `create_new` (temp name, flush, rename without
//! replace), and, for `intent`, `applied`, `revert_intent` and `close`, followed by a flush
//! of the transaction folder.

#![cfg_attr(
    not(test),
    expect(dead_code, reason = "the writers' first caller is exec (P2-8)")
)]

use std::collections::BTreeMap;
use std::io::Read;
use std::sync::atomic::{AtomicU64, Ordering};

use sha2::{Digest, Sha256};

use super::names::{self, HEAD, LOCK, MAX_SEQ};
use super::read;
use super::record::{self, BackupRef, Closing, Observed, Record};
use super::replay::Machine;
use super::{Journal, JournalError, Limits, OpLog, TxnId, TxnState, VerifyBackups, reparse};
use crate::path::RootPath;
use crate::sys::fs::{Attrs, FileGuard, FileLock, NewFile, TmpName};
use crate::sys::{DirWrite, SysError, SysErrorKind};

/// The held `journal\lock` (ADR 0019, "Lock").
#[derive(Debug)]
pub struct JournalLock<'j> {
    dir: &'j dyn DirWrite,
    _lock: Box<dyn FileLock + 'j>,
    tag: u64,
    tmp_n: &'j AtomicU64,
    lim: Limits,
    app: &'j RootPath,
}

impl<'j> JournalLock<'j> {
    /// Takes the lock in `dir` (`journal\`) for `j`.
    pub(super) fn take(dir: &'j dyn DirWrite, j: &'j Journal<'_>) -> Result<Self, JournalError> {
        let name = names::fixed(LOCK);
        let lock = dir.lock(&name).map_err(|e| match e.kind {
            SysErrorKind::Busy => JournalError::Busy,
            SysErrorKind::ReparsePoint => reparse(j.app.path(), &name),
            _ => JournalError::Sys(e),
        })?;
        Ok(Self {
            dir,
            _lock: lock,
            tag: j.tag.get(),
            tmp_n: &j.tmp_n,
            lim: j.lim,
            app: j.app.path(),
        })
    }

    /// A fresh temp name of this instance.
    fn tmp(&self) -> TmpName {
        TmpName::new(self.tag, self.tmp_n.fetch_add(1, Ordering::Relaxed))
    }

    /// Begins a transaction with the plan bytes `head`: `seq` one more than the highest
    /// transaction name in `journal\`, its folder created and reopened (a different file ID
    /// is `Busy`), `head.json` written with `create_new`. Nothing is flushed yet: the first
    /// intent's flush covers the folder and the head.
    pub(crate) fn begin(&self, head: &[u8]) -> Result<TxnWriter<'_>, JournalError> {
        let len = u64::try_from(head.len()).unwrap_or(u64::MAX);
        if len > self.lim.head {
            return Err(JournalError::TooLarge {
                what: "head.json",
                limit: self.lim.head,
            });
        }
        let (ids, _) = read::scan(self.dir, &self.lim)?;
        let seq = ids
            .iter()
            .map(|(id, _)| id.seq())
            .max()
            .unwrap_or(0)
            .checked_add(1)
            .filter(|s| *s <= MAX_SEQ);
        let Some(id) = seq.and_then(|s| TxnId::new(s, self.tag)) else {
            return Err(JournalError::TooLarge {
                what: "the transaction sequence number",
                limit: u64::from(MAX_SEQ),
            });
        };
        let rel = id.rel();
        let file_id = self.dir.create_dir(&rel)?;
        let dir = self.dir.open_dir_write(&rel).map_err(|e| match e.kind {
            SysErrorKind::ReparsePoint => reparse(self.app, &rel),
            _ => JournalError::Sys(e),
        })?;
        if dir.info()?.file_id != file_id {
            return Err(SysError::new(
                SysErrorKind::Busy,
                format!("journal\\{rel} changed while it was created"),
            )
            .into());
        }
        let sha: [u8; 32] = Sha256::digest(head).into();
        let new = NewFile {
            tmp: self.tmp(),
            attrs: Attrs::default(),
            sha256: sha,
            max_len: len,
        };
        dir.create_new(&names::fixed(HEAD), &mut &head[..], &new)?;
        Ok(TxnWriter {
            t: Txn::new(self, id, dir, sha, Machine::default()),
        })
    }

    /// Reopens transaction `id` to revert it (after a crash, or a revert of an applied one).
    /// `Empty`, `Open` and `Applied` only; never a damaged or closed one.
    pub(crate) fn resume(&self, id: &TxnId) -> Result<RevertWriter<'_>, JournalError> {
        let rel = id.rel();
        let dir = self.dir.open_dir_write(&rel).map_err(|e| match e.kind {
            SysErrorKind::NotFound => JournalError::NotFound(*id),
            SysErrorKind::ReparsePoint => reparse(self.app, &rel),
            _ => JournalError::Sys(e),
        })?;
        let (view, m) = read::read_txn(&*dir, *id, VerifyBackups::Length, &self.lim)?;
        let resumable = matches!(
            view.state,
            TxnState::Empty | TxnState::Open | TxnState::Applied
        );
        let head = view.head.as_deref().filter(|_| resumable);
        let Some(head) = head else {
            return Err(JournalError::NotResumable {
                id: *id,
                state: view.state,
            });
        };
        let sha: [u8; 32] = Sha256::digest(head).into();
        Ok(RevertWriter {
            t: Txn::new(self, *id, dir, sha, m),
        })
    }
}

/// Where a writer flushes the transaction folder (J6 switches one off at a time).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FlushSite {
    Intent,
    Applied,
    RevertIntent,
    Close,
}

/// The token of a backup taken by [`TxnWriter::backup`]; only its intent consumes it.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Backup {
    op: u16,
    sha256: [u8; 32],
    len: u64,
}

/// One open transaction.
#[derive(Debug)]
struct Txn<'l> {
    lock: &'l JournalLock<'l>,
    id: TxnId,
    dir: Box<dyn DirWrite + 'l>,
    head: [u8; 32],
    m: Machine,
    backed_up: u64,
    /// Op of the backup taken and not yet named by an intent.
    pending: Option<u16>,
}

impl<'l> Txn<'l> {
    fn new(
        lock: &'l JournalLock<'l>,
        id: TxnId,
        dir: Box<dyn DirWrite + 'l>,
        head: [u8; 32],
        m: Machine,
    ) -> Self {
        Self {
            lock,
            id,
            dir,
            head,
            m,
            backed_up: 0,
            pending: None,
        }
    }

    fn flush(&self, site: FlushSite) -> Result<(), JournalError> {
        let _ = site;
        Ok(self.dir.flush()?)
    }

    /// Checks `rec`, writes it as the next record, replays it, flushes at `site`.
    fn write(&mut self, rec: &Record, site: Option<FlushSite>) -> Result<(), JournalError> {
        self.m.check(rec).map_err(JournalError::Order)?;
        let lim = &self.lock.lim;
        let n = self.m.records().saturating_add(1);
        if n > lim.records {
            return Err(JournalError::TooLarge {
                what: "the records of a transaction",
                limit: u64::from(lim.records),
            });
        }
        let bytes =
            record::encode(n, &self.head, rec).map_err(|e| JournalError::Encode(e.to_string()))?;
        let len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        if len > lim.record {
            return Err(JournalError::TooLarge {
                what: "a record",
                limit: lim.record,
            });
        }
        let new = NewFile {
            tmp: self.lock.tmp(),
            attrs: Attrs::default(),
            sha256: Sha256::digest(&bytes).into(),
            max_len: len,
        };
        self.dir
            .create_new(&names::record_name(n), &mut &bytes[..], &new)?;
        // On disk now: replay it before the flush, so a failed flush leaves the writer in
        // step with the folder (the caller rolls back with the records that follow).
        self.m.step(rec).map_err(JournalError::Order)?;
        match site {
            Some(s) => self.flush(s),
            None => Ok(()),
        }
    }

    fn backup(&mut self, g: &mut dyn FileGuard) -> Result<Backup, JournalError> {
        let op = self.m.intents();
        let probe = Record::Intent {
            op,
            tmp: None,
            backup: None,
        };
        self.m.check(&probe).map_err(JournalError::Order)?;
        if self.pending.is_some() {
            return Err(JournalError::Order("a second backup before its intent"));
        }
        let lim = &self.lock.lim;
        let len = g.metadata()?.len;
        if len > lim.backup {
            return Err(JournalError::TooLarge {
                what: "a backup",
                limit: lim.backup,
            });
        }
        // The budget is checked before anything is streamed.
        if self.backed_up.saturating_add(len) > lim.backups {
            return Err(JournalError::TooLarge {
                what: "the backups of a transaction",
                limit: lim.backups,
            });
        }
        let sha256 = g.sha256()?;
        let name = names::backup_name(op);
        let new = NewFile {
            tmp: self.lock.tmp(),
            attrs: Attrs::default(),
            sha256,
            max_len: len,
        };
        {
            let mut src = g.reader()?;
            self.dir.create_new(&name, &mut *src, &new)?;
        }
        self.pending = Some(op);
        // Read back: proves the content, not its durability (the intent's flush does that).
        let reader = self.dir.open_read(&name)?;
        let back = read::stream_hash(reader.take(len.saturating_add(1)), &name)?;
        if back != (sha256, len) {
            return Err(JournalError::BackupMismatch(op));
        }
        self.backed_up = self.backed_up.saturating_add(len);
        Ok(Backup { op, sha256, len })
    }

    fn intent(
        &mut self,
        op: u16,
        tmp: Option<TmpName>,
        b: Option<Backup>,
    ) -> Result<(), JournalError> {
        match (&b, self.pending) {
            (Some(b), _) if b.op != op => {
                return Err(JournalError::Order("the backup belongs to another op"));
            }
            (None, Some(_)) => {
                return Err(JournalError::Order("an intent without its backup"));
            }
            _ => {}
        }
        let backup = b.map(|b| BackupRef {
            sha256: b.sha256,
            len: b.len,
        });
        self.write(&Record::Intent { op, tmp, backup }, Some(FlushSite::Intent))?;
        self.pending = None;
        Ok(())
    }

    fn revert_intent(&mut self, op: u16, tmp: Option<TmpName>) -> Result<(), JournalError> {
        if self.pending.is_some() {
            // The orphan backup of an op that never got its intent stays allowed (B1).
            self.pending = None;
        }
        self.write(
            &Record::RevertIntent { op, tmp },
            Some(FlushSite::RevertIntent),
        )
    }
}

/// Writes an apply (and its rollback). Crate-internal: only `exec` writes.
#[derive(Debug)]
pub(crate) struct TxnWriter<'l> {
    t: Txn<'l>,
}

/// Writes the revert of a resumed transaction: no intent, done or applied (condition S4).
#[derive(Debug)]
pub(crate) struct RevertWriter<'l> {
    t: Txn<'l>,
}

macro_rules! common {
    ($ty:ident) => {
        impl $ty<'_> {
            /// The transaction.
            pub(crate) fn id(&self) -> &TxnId {
                &self.t.id
            }

            /// A fresh temp name of this instance (also for a `<tmp>` in a game folder).
            pub(crate) fn tmp(&self) -> TmpName {
                self.t.lock.tmp()
            }

            /// The records so far, per op.
            pub(crate) fn ops(&self) -> &BTreeMap<u16, OpLog> {
                self.t.m.ops()
            }

            /// The op whose revert comes next (highest intended op without `RevertDone`).
            pub(crate) fn next_revert(&self) -> Option<u16> {
                self.t.m.next_revert()
            }

            /// `Applied` is recorded.
            pub(crate) fn is_applied(&self) -> bool {
                self.t.m.applied()
            }

            /// Before the revert of `op` changes anything; flushed. Repeatable until
            /// [`Self::revert_done`].
            pub(crate) fn revert_intent(
                &mut self,
                op: u16,
                tmp: Option<TmpName>,
            ) -> Result<(), JournalError> {
                self.t.revert_intent(op, tmp)
            }

            /// The revert of `op` is done (not flushed; the next flush covers it).
            pub(crate) fn revert_done(
                &mut self,
                op: u16,
                observed: Observed,
                old_left: bool,
            ) -> Result<(), JournalError> {
                let rec = Record::RevertDone {
                    op,
                    observed,
                    old_left,
                };
                self.t.write(&rec, None)
            }

            /// Closes the transaction; flushed. The caller flushes the folders the revert
            /// changed first.
            pub(crate) fn close(mut self, how: Closing) -> Result<(), JournalError> {
                self.t
                    .write(&Record::Closed { how }, Some(FlushSite::Close))
            }
        }
    };
}

common!(TxnWriter);
common!(RevertWriter);

impl TxnWriter<'_> {
    /// Streams the guarded file into `op-NNNN.bin` of the next op (at most 2 GiB, at most
    /// 4 GiB per transaction, checked before streaming), reads it back and compares hash and
    /// length. The token goes into that op's [`Self::intent`].
    pub(crate) fn backup(&mut self, g: &mut dyn FileGuard) -> Result<Backup, JournalError> {
        self.t.backup(g)
    }

    /// Before op `op` changes anything: its temp name and backup; flushed.
    pub(crate) fn intent(
        &mut self,
        op: u16,
        tmp: Option<TmpName>,
        backup: Option<Backup>,
    ) -> Result<(), JournalError> {
        self.t.intent(op, tmp, backup)
    }

    /// Op `op` is done (not flushed; the next flush covers it).
    pub(crate) fn done(
        &mut self,
        op: u16,
        file_id: u128,
        old_left: bool,
    ) -> Result<(), JournalError> {
        let rec = Record::Done {
            op,
            file_id,
            old_left,
        };
        self.t.write(&rec, None)
    }

    /// Every op is done; flushed. The caller flushes every changed folder first.
    pub(crate) fn applied(&mut self, ops: u16) -> Result<(), JournalError> {
        self.t
            .write(&Record::Applied { ops }, Some(FlushSite::Applied))
    }
}
