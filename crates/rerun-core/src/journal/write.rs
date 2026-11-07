//! Writing the journal (ADR 0019, "Write order and durability"; P2-7 amendment).
//!
//! Everything is written under [`JournalLock`]. [`JournalLock::begin`] starts a transaction
//! and hands out a [`TxnWriter`] (apply, with its rollback); [`JournalLock::resume`] reopens an
//! `Empty`, `Open` or `Applied` one as a [`RevertWriter`], which by its type can only revert
//! and close (condition S4). Every record is checked against the grammar before it is
//! written ([`Machine`]), written with `create_new` (temp name, flush, rename without
//! replace), and, for `intent`, `applied`, `revert_intent`, `rebind` and `close`, followed by a flush
//! of the transaction folder.

use std::collections::BTreeMap;
use std::io::Read;
use std::sync::atomic::{AtomicU64, Ordering};

use sha2::{Digest as _, Sha256};

use super::names::{self, HEAD, LOCK, MAX_SEQ};
use super::read;
use super::record::{self, Before, Closing, Digest, DirProof, Observed, Record, Semantic};
use super::replay::Machine;
use super::{
    Journal, JournalError, Limits, OpLog, RebindRec, TxnId, TxnState, VerifyBackups, reparse,
};
use crate::path::RootPath;
use crate::policy::root::RootId;
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
        let ids = read::scan(self.dir, &self.lim)?.txns;
        let highest = ids.iter().map(|(id, _)| *id).max_by_key(TxnId::seq);
        let seq = highest
            .map_or(0, |h| h.seq())
            .checked_add(1)
            .filter(|s| *s <= MAX_SEQ);
        let Some(id) = seq.and_then(|s| TxnId::new(s, self.tag)) else {
            return Err(match highest {
                Some(highest) => JournalError::SeqExhausted { highest },
                None => JournalError::Order("no sequence number"),
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

    /// `forget` of a damaged transaction, or of one whose folder cannot be read (user
    /// decision D2): `journal\<txn>.forgotten` with `create_new`, holding the hex SHA-256 of
    /// the head as listed (empty without one), then `journal\` flushed. Nothing in the
    /// transaction folder changes and its backups stay. A marker already there is `Ok`.
    pub(crate) fn forget_marker(
        &self,
        id: &TxnId,
        head: Option<&[u8; 32]>,
    ) -> Result<(), JournalError> {
        let content = head.map(crate::wire::hex32::to_string).unwrap_or_default();
        let new = NewFile {
            tmp: self.tmp(),
            attrs: Attrs::default(),
            sha256: Sha256::digest(content.as_bytes()).into(),
            max_len: u64::try_from(content.len()).unwrap_or(u64::MAX),
        };
        match self
            .dir
            .create_new(&names::marker_name(id), &mut content.as_bytes(), &new)
        {
            Ok(_) => {}
            Err(e) if e.kind == SysErrorKind::AlreadyExists => {
                let have = self.dir.read_limited(&names::marker_name(id), 64)?;
                if have != content.as_bytes() {
                    return Err(JournalError::MarkerInTheWay {
                        path: crate::escape::path(&format!(
                            r"{}\journal\{}",
                            self.app,
                            names::marker_name(id)
                        ))
                        .to_string(),
                    });
                }
            }
            Err(e) => return Err(e.into()),
        }
        Ok(self.dir.flush()?)
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
        let head = head.to_vec();
        Ok(RevertWriter {
            t: Txn::new(self, *id, dir, sha, m),
            head,
        })
    }
}

/// Where a writer flushes the transaction folder (J6 switches one off at a time).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FlushSite {
    Intent,
    Applied,
    RevertIntent,
    /// P2-14: a confirmed rebind survives every cut once its call returned `Ok`.
    Rebind,
    Close,
}

#[cfg(test)]
pub(crate) mod knob {
    //! J6: a flush site of this thread's writers that does nothing.

    use std::cell::Cell;

    use super::FlushSite;

    thread_local! {
        static SKIP: Cell<Option<FlushSite>> = const { Cell::new(None) };
    }

    /// From now on, the flush at `site` does nothing (on this thread).
    pub(crate) fn skip(site: Option<FlushSite>) {
        SKIP.with(|s| s.set(site));
    }

    pub(super) fn skipped(site: FlushSite) -> bool {
        SKIP.with(|s| s.get() == Some(site))
    }
}

/// The token of a backup taken by [`TxnWriter::backup`] or [`TxnWriter::backup_bytes`]; only
/// its intent consumes it.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Backup {
    op: u16,
    sha256: [u8; 32],
    len: u64,
}

/// The old state an intent keeps ([`Before`]): a backup taken for it, or the bytes inline
/// (at most [`record::INLINE_MAX`]; the grammar refuses more).
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum BeforeArg {
    /// The backup `op-NNNN.bin` of the op.
    Backup(Backup),
    /// The bytes, in the record.
    Inline(Vec<u8>),
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
        #[cfg(test)]
        if knob::skipped(site) {
            return Ok(());
        }
        #[cfg(not(test))]
        let _ = site;
        Ok(self.dir.flush()?)
    }

    /// Checks `rec`, writes it as the next record, replays it, flushes at `site`.
    fn write(&mut self, rec: &Record, site: Option<FlushSite>) -> Result<(), JournalError> {
        self.m.check(rec).map_err(JournalError::Order)?;
        let lim = &self.lock.lim;
        let n = self.m.records().saturating_add(1);
        // The last slot is kept for `Closed`, so `forget` can always close (rule 2); an intent
        // also needs room for the rest of a full revert ([`Self::room_for_intent`]).
        let cap = if matches!(rec, Record::Closed { .. }) {
            lim.records
        } else {
            lim.records.saturating_sub(1)
        };
        if n > cap || (matches!(rec, Record::Intent { .. }) && !self.room_for_intent()) {
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

    /// Room for one more intent: its intent and done, a revert intent and done for every op
    /// including it, `Applied` and `Closed`.
    fn room_for_intent(&self) -> bool {
        let ops = u32::from(self.m.intents()) + 1;
        let need = u32::from(self.m.records()) + 2 + 2 * ops + 2;
        need <= u32::from(self.lock.lim.records)
    }

    /// The checks of a backup of `len` bytes for the next op, before anything is written:
    /// the grammar allows its intent, no other backup waits for its intent, the record budget
    /// holds the intent and a full revert, the per-file and per-transaction budgets hold it.
    fn backup_allowed(&self, len: u64) -> Result<u16, JournalError> {
        let op = self.m.intents();
        let probe = Record::Intent {
            op,
            tmp: None,
            before: None,
        };
        self.m.check(&probe).map_err(JournalError::Order)?;
        if self.pending.is_some() {
            return Err(JournalError::Order("a second backup before its intent"));
        }
        if !self.room_for_intent() {
            return Err(JournalError::TooLarge {
                what: "the records of a transaction",
                limit: u64::from(self.lock.lim.records),
            });
        }
        let lim = &self.lock.lim;
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
        Ok(op)
    }

    /// Writes `op-NNNN.bin` of `op` from `src` with `create_new` (`sha256` and `len` the
    /// expected ones), then reads it back and compares: proves the content, not its
    /// durability (the intent's flush does that).
    fn backup_from(
        &mut self,
        op: u16,
        src: &mut dyn Read,
        sha256: [u8; 32],
        len: u64,
    ) -> Result<Backup, JournalError> {
        let name = names::backup_name(op);
        let new = NewFile {
            tmp: self.lock.tmp(),
            attrs: Attrs::default(),
            sha256,
            max_len: len,
        };
        self.dir.create_new(&name, src, &new)?;
        self.pending = Some(op);
        let reader = self.dir.open_read(&name)?;
        let back = read::stream_hash(reader.take(len.saturating_add(1)), &name)?;
        if back != (sha256, len) {
            return Err(JournalError::BackupMismatch(op));
        }
        self.backed_up = self.backed_up.saturating_add(len);
        Ok(Backup { op, sha256, len })
    }

    fn backup(&mut self, g: &mut dyn FileGuard) -> Result<Backup, JournalError> {
        let len = g.metadata()?.len;
        let op = self.backup_allowed(len)?;
        let sha256 = g.sha256()?;
        let mut src = g.reader()?;
        self.backup_from(op, &mut *src, sha256, len)
    }
    fn backup_bytes(&mut self, data: &[u8]) -> Result<Backup, JournalError> {
        let len = u64::try_from(data.len()).unwrap_or(u64::MAX);
        let op = self.backup_allowed(len)?;
        let sha256: [u8; 32] = Sha256::digest(data).into();
        self.backup_from(op, &mut &data[..], sha256, len)
    }

    fn intent(
        &mut self,
        op: u16,
        tmp: Option<TmpName>,
        before: Option<BeforeArg>,
    ) -> Result<(), JournalError> {
        match (&before, self.pending) {
            (Some(BeforeArg::Backup(b)), pending) if b.op != op || pending != Some(b.op) => {
                return Err(JournalError::Order(
                    "the backup belongs to another op or transaction",
                ));
            }
            (None | Some(BeforeArg::Inline(_)), Some(_)) => {
                return Err(JournalError::Order("an intent without its backup"));
            }
            _ => {}
        }
        let before = before.map(|b| match b {
            BeforeArg::Backup(b) => Before::Bin(Digest {
                sha256: b.sha256,
                len: b.len,
            }),
            BeforeArg::Inline(v) => Before::Inline(v),
        });
        self.write(&Record::Intent { op, tmp, before }, Some(FlushSite::Intent))?;
        self.pending = None;
        Ok(())
    }

    fn revert_intent(
        &mut self,
        op: u16,
        tmp: Option<TmpName>,
        sem: Option<Semantic>,
    ) -> Result<(), JournalError> {
        if self.pending.is_some() {
            // The orphan backup of an op that never got its intent stays allowed (B1).
            self.pending = None;
        }
        // The writer refuses what `exec` would refuse on reading (J1): a semantic revert names
        // its temp name, and `from` differs from `to` (security review S-1).
        if sem.is_some_and(|s| tmp.is_none() || s.from == s.to) {
            return Err(JournalError::Order(
                "a semantic revert without its temp name or with from equal to to",
            ));
        }
        // `from`/`to`: a semantic revert (P2-12, `IniValue` only; `exec` checks the op kind).
        let rec = Record::RevertIntent {
            op,
            tmp,
            from: sem.map(|s| s.from),
            to: sem.map(|s| s.to),
        };
        self.write(&rec, Some(FlushSite::RevertIntent))
    }

    /// The old state of `op` as bytes, at most `max`: inline from its intent, or
    /// `op-NNNN.bin` read whole (bounded) and checked against the intent's digest (else
    /// `BackupMismatch`), so what is used is what was checked (no TOCTOU).
    fn before_bytes(&self, op: u16, max: u64) -> Result<Vec<u8>, JournalError> {
        let too_large = || JournalError::TooLarge {
            what: "an old state",
            limit: max,
        };
        match self.m.ops().get(&op).and_then(|o| o.intent.before.as_ref()) {
            None => Err(JournalError::Order("an op without an old state")),
            Some(Before::Inline(v)) => {
                if u64::try_from(v.len()).unwrap_or(u64::MAX) > max {
                    return Err(too_large());
                }
                Ok(v.clone())
            }
            Some(Before::Bin(d)) => super::read_backup(&*self.dir, op, d, max),
        }
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
    /// The bytes of `head.json` whose hash the records carry: `exec` parses exactly these.
    head: Vec<u8>,
}

impl RevertWriter<'_> {
    /// The head bytes read under the lock and hashed (`exec` parses these, never a re-read).
    pub(crate) fn head(&self) -> &[u8] {
        &self.head
    }

    /// The `Rebind` records so far, in order (P2-14).
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "P2-14: exec writes and reads rebinds from the next commit on"
        )
    )]
    pub(crate) fn rebinds(&self) -> &[RebindRec] {
        self.t.m.rebinds()
    }

    /// Binds root `root` to the head's install folder in the library `store` from here on
    /// (P2-14): the grammar, the record budget, and room for the rest of the revert (a
    /// `RevertIntent` and `RevertDone` for every op not reverted yet, and `Closed`), checked
    /// before anything is written; then the record, and the transaction folder flushed, so a
    /// rebind whose call returned `Ok` survives every cut.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "P2-14: exec writes and reads rebinds from the next commit on"
        )
    )]
    pub(crate) fn rebind(&mut self, r: &RebindArgs<'_>) -> Result<(), JournalError> {
        let open = self
            .t
            .m
            .ops()
            .values()
            .filter(|o| o.reverted.is_none())
            .count();
        let open = u32::try_from(open).unwrap_or(u32::MAX);
        let need = u32::from(self.t.m.records())
            .saturating_add(1)
            .saturating_add(open.saturating_mul(2))
            .saturating_add(1);
        if need > u32::from(self.t.lock.lim.records) {
            return Err(JournalError::TooLarge {
                what: "the records of a transaction",
                limit: u64::from(self.t.lock.lim.records),
            });
        }
        let rec = Record::Rebind {
            root: r.root,
            old: r.old,
            store: r.store.clone(),
            store_id: r.store_id,
            id: r.id,
            dirs: r.dirs.to_vec(),
        };
        self.t.write(&rec, Some(FlushSite::Rebind))
    }
}

/// What [`RevertWriter::rebind`] records.
#[derive(Debug, Clone, Copy)]
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "P2-14: exec writes and reads rebinds from the next commit on"
    )
)]
pub(crate) struct RebindArgs<'a> {
    /// Root index in the head.
    pub(crate) root: u16,
    /// The identity of the game folder as bound before.
    pub(crate) old: RootId,
    /// The Steam library.
    pub(crate) store: &'a RootPath,
    /// Identity of the library.
    pub(crate) store_id: RootId,
    /// Identity of the game folder.
    pub(crate) id: RootId,
    /// The folders the plan created, by their file ID there, by op ascending.
    pub(crate) dirs: &'a [DirProof],
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
            /// [`Self::revert_done`]. `sem`: a semantic revert, the content it starts from and
            /// the content it writes (P2-12), durable with the record before the first change.
            pub(crate) fn revert_intent(
                &mut self,
                op: u16,
                tmp: Option<TmpName>,
                sem: Option<Semantic>,
            ) -> Result<(), JournalError> {
                self.t.revert_intent(op, tmp, sem)
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

            /// The backup `op-NNNN.bin` of `op`, from offset 0, for a restore. Its hash is
            /// not checked here: the restore streams it into `<tmp>` with the intent's
            /// SHA-256 and length as the expected ones (`NewFile`), so what is checked is
            /// what is written (no earlier check, TOCTOU).
            pub(crate) fn backup_reader(
                &self,
                op: u16,
            ) -> Result<Box<dyn Read + '_>, JournalError> {
                Ok(Box::new(self.t.dir.open_read(&names::backup_name(op))?))
            }

            /// The old state of `op` as bytes, at most `max` (old registry values): inline,
            /// or `op-NNNN.bin` read whole and checked against the intent (else
            /// `BackupMismatch`); the bytes returned are the bytes checked.
            pub(crate) fn before_bytes(&self, op: u16, max: u64) -> Result<Vec<u8>, JournalError> {
                self.t.before_bytes(op, max)
            }
        }

        impl Reverting for $ty<'_> {
            fn id(&self) -> &TxnId {
                $ty::id(self)
            }
            fn tmp(&self) -> TmpName {
                $ty::tmp(self)
            }
            fn ops(&self) -> &BTreeMap<u16, OpLog> {
                $ty::ops(self)
            }
            fn next_revert(&self) -> Option<u16> {
                $ty::next_revert(self)
            }
            fn is_applied(&self) -> bool {
                $ty::is_applied(self)
            }
            fn revert_intent(
                &mut self,
                op: u16,
                tmp: Option<TmpName>,
                sem: Option<Semantic>,
            ) -> Result<(), JournalError> {
                $ty::revert_intent(self, op, tmp, sem)
            }
            fn revert_done(
                &mut self,
                op: u16,
                observed: Observed,
                old_left: bool,
            ) -> Result<(), JournalError> {
                $ty::revert_done(self, op, observed, old_left)
            }
            fn backup_reader(&self, op: u16) -> Result<Box<dyn Read + '_>, JournalError> {
                $ty::backup_reader(self, op)
            }
            fn before_bytes(&self, op: u16, max: u64) -> Result<Vec<u8>, JournalError> {
                $ty::before_bytes(self, op, max)
            }
            fn close(self, how: Closing) -> Result<(), JournalError> {
                $ty::close(self, how)
            }
        }
    };
}

/// What a revert needs of a writer: the rollback of an apply ([`TxnWriter`]) and the revert
/// or recovery of a resumed transaction ([`RevertWriter`]) run the same code (`exec`).
pub(crate) trait Reverting {
    /// The transaction.
    fn id(&self) -> &TxnId;
    /// A fresh temp name of this instance.
    fn tmp(&self) -> TmpName;
    /// The records so far, per op.
    fn ops(&self) -> &BTreeMap<u16, OpLog>;
    /// The op whose revert comes next.
    fn next_revert(&self) -> Option<u16>;
    /// `Applied` is recorded.
    fn is_applied(&self) -> bool;
    /// `RevertIntent` (with `sem` for a semantic revert); flushed.
    fn revert_intent(
        &mut self,
        op: u16,
        tmp: Option<TmpName>,
        sem: Option<Semantic>,
    ) -> Result<(), JournalError>;
    /// `RevertDone`.
    fn revert_done(
        &mut self,
        op: u16,
        observed: Observed,
        old_left: bool,
    ) -> Result<(), JournalError>;
    /// The backup of `op`.
    fn backup_reader(&self, op: u16) -> Result<Box<dyn Read + '_>, JournalError>;
    /// The old state of `op` as checked bytes, at most `max`.
    fn before_bytes(&self, op: u16, max: u64) -> Result<Vec<u8>, JournalError>;
    /// `Closed`; flushed.
    fn close(self, how: Closing) -> Result<(), JournalError>
    where
        Self: Sized;
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

    /// Writes `data` as `op-NNNN.bin` of the next op (an old registry value above
    /// [`record::INLINE_MAX`]), with the budgets of [`Self::backup`], reads it back and
    /// compares hash and length. The token goes into that op's [`Self::intent`].
    pub(crate) fn backup_bytes(&mut self, data: &[u8]) -> Result<Backup, JournalError> {
        self.t.backup_bytes(data)
    }

    /// Before op `op` changes anything: its temp name and old state; flushed.
    pub(crate) fn intent(
        &mut self,
        op: u16,
        tmp: Option<TmpName>,
        before: Option<BeforeArg>,
    ) -> Result<(), JournalError> {
        self.t.intent(op, tmp, before)
    }

    /// Op `op` is done (not flushed; the next flush covers it). `file_id` for a file op.
    pub(crate) fn done(
        &mut self,
        op: u16,
        file_id: Option<u128>,
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
