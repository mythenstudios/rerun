//! Purging settled transactions (P5-6d, ADR 0019 amendment P5-6d), under `journal\lock`.
//!
//! [`JournalLock::purge`] removes `journal\<txn>\` and `journal\<txn>.forgotten` of a
//! transaction that is `Closed`, `Empty` or forgotten by a marker that applies, and nothing
//! else: never another folder of `AppDir`, a profile, the lock, a game folder, the registry or
//! the firewall. Whether a settled transaction may go (a hand-over, a profile it holds) is
//! `exec`'s rule (`exec::purge_seen`); this module only refuses what is not settled or not
//! Rerun's.
//!
//! Order (S2): the checks write nothing; then the tombstone `journal\<txn>.purge` (content
//! the lower-case hex SHA-256 of the head, empty without one; `create_new`) and a flush of
//! `journal\`. The tombstone and every deletion are changes of the one volume of `journal\`,
//! whose log is ordered, so no deletion is durable without the tombstone even without that
//! flush (no cut of the fake's model can tell the flush is there, JP4); it is belt and braces,
//! as `create_new` flushes everywhere else in Rerun. Then the backups, Rerun's temp leftovers, the records newest first with the record
//! holding `Closed` last, and `head.json` last of all. A reader that misses the tombstone sees a
//! closed, empty or damaged transaction, never an open or applied one, and every reader reads
//! the tombstone after its `load` anyway (`read::see`). Each file goes by its file ID from the
//! listing of the same folder handle (`DirWrite::remove_file`), never by hash: they are
//! Rerun's own files, and a backup can be gigabytes.
//!
//! Then the folder: if no transaction name in `journal\` has a higher `seq`, the empty folder
//! and the tombstone stay as the anchor of `seq` (`begin` counts the folder name, so a number
//! is never handed out twice); else the folder is removed by its file ID, the forget marker
//! deleted, `journal\` flushed, the tombstone deleted and `journal\` flushed again. An anchor
//! goes the same way once a newer transaction exists ([`JournalLock::finish_purges`]).
//!
//! A purge that stopped (a crash, a power loss, a file in use) is finished by a later run only
//! if its tombstone applies by the reader's rule (its hash names the head, or there is no head
//! any more); a tombstone for another head stays and nothing is deleted. Tombstones and markers
//! without a folder are removed.

use std::collections::BTreeSet;
use std::fmt;

use sha2::{Digest as _, Sha256};

use super::names::{self, TxnEntry};
use super::read;
use super::write::JournalLock;
use super::{JournalError, Limits, TxnId, TxnState, VerifyBackups, reparse};
use crate::path::RelPath;
use crate::sys::fs::{Attrs, DirEntry, EntryKind, NewFile};
use crate::sys::{Dir, SysErrorKind, SysResult};

/// What [`JournalLock::purge`] left.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Purged {
    /// The transaction had the highest `seq`: its empty folder and its tombstone stay as the
    /// anchor of `seq` (invisible to every reader) until a newer transaction exists.
    pub(crate) anchor: bool,
}

/// Why a purge did not go on ([`JournalError::Purge`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PurgeStop {
    /// Not `Closed`, not `Empty` and not forgotten by a marker that applies; nothing written.
    NotSettled,
    /// The head is not the one the caller saw; nothing written.
    HeadChanged,
    /// A tombstone for another head is in the way; nothing written, nothing deleted.
    TombstoneInTheWay,
    /// The folder holds something Rerun did not write there (an unknown name, a folder, a link,
    /// a reparse point, a restricted entry, a planted tail after `Closed`), or a file changed
    /// its identity on the way. Checked before the tombstone: nothing written then; met while
    /// deleting: the tombstone stays and nothing more of the transaction is deleted.
    Foreign,
    /// The folder has more entries than the listing limit; nothing written.
    TooManyEntries,
    /// Another program holds a file without sharing its deletion (a scanner, a backup tool):
    /// the tombstone stays and a later run finishes the purge.
    InUse,
}

impl fmt::Display for PurgeStop {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotSettled => "it is not settled",
            Self::HeadChanged => "its head changed",
            Self::TombstoneInTheWay => "a purge marker for another head is in the way",
            Self::Foreign => "its folder holds something Rerun did not write",
            Self::TooManyEntries => "its folder has too many entries",
            Self::InUse => "a file of it is in use",
        })
    }
}

/// The outcome of one deletion: gone (also when it was gone already), or why the purge stops.
fn removed(r: SysResult<()>) -> Result<Option<PurgeStop>, JournalError> {
    match r {
        Ok(()) => Ok(None),
        Err(e) => match e.kind {
            SysErrorKind::NotFound => Ok(None),
            SysErrorKind::Busy => Ok(Some(PurgeStop::InUse)),
            SysErrorKind::Linked
            | SysErrorKind::Mismatch
            | SysErrorKind::ReparsePoint
            | SysErrorKind::InvalidPath
            | SysErrorKind::NotEmpty => Ok(Some(PurgeStop::Foreign)),
            _ => Err(e.into()),
        },
    }
}

/// A file as Rerun writes one into `journal\`: plain, readable, one link, no read-only, hidden
/// or system attribute (`create_new` with `Attrs::default()`); anything else is not Rerun's.
fn plain(e: &DirEntry) -> bool {
    e.meta.kind == EntryKind::File
        && !e.meta.restricted
        && e.meta.is_single_link()
        && e.meta.attrs == Attrs::default()
}

/// The files of a transaction folder in the order of deletion, each with its file ID from this
/// listing: backups, temp leftovers, records newest first with the newest (`Closed` of a closed
/// one) last, `head.json`. Anything else stops the purge before it writes.
fn doomed(
    dir: &dyn Dir,
    lim: &Limits,
) -> Result<Result<Vec<(RelPath, u128)>, PurgeStop>, JournalError> {
    let listing = match dir.read_dir_limited(None, lim.txn_entries) {
        Ok(l) => l,
        Err(e) if e.kind == SysErrorKind::TooLarge => return Ok(Err(PurgeStop::TooManyEntries)),
        Err(e) => return Err(e.into()),
    };
    let (mut bins, mut tmps, mut recs, mut head) = (Vec::new(), Vec::new(), Vec::new(), None);
    for e in listing {
        let class = names::classify(&e.name, lim.records);
        let name = match RelPath::from_segment(&e.name) {
            Ok(n) if plain(&e) && class != TxnEntry::Unknown => n,
            _ => return Ok(Err(PurgeStop::Foreign)),
        };
        let item = (name, e.meta.file_id);
        match class {
            TxnEntry::Backup(op) => bins.push((op, item)),
            TxnEntry::Tmp => tmps.push(item),
            TxnEntry::Record(n) => recs.push((n, item)),
            TxnEntry::Head => head = Some(item),
            TxnEntry::Unknown => return Ok(Err(PurgeStop::Foreign)),
        }
    }
    bins.sort_by_key(|(op, _)| *op);
    recs.sort_by_key(|(n, _)| std::cmp::Reverse(*n));
    let mut out: Vec<(RelPath, u128)> = bins.into_iter().map(|(_, i)| i).collect();
    out.extend(tmps);
    let mut recs = recs.into_iter().map(|(_, i)| i);
    let newest = recs.next();
    out.extend(recs);
    out.extend(newest);
    out.extend(head);
    Ok(Ok(out))
}

impl JournalLock<'_> {
    /// Purges transaction `id` (module docs). `head`: the hash of its head as the caller saw
    /// it (`None` without one); another head is [`PurgeStop::HeadChanged`]. A purge begun
    /// before (its tombstone applies) is finished whatever `head` says. Refusals before the
    /// tombstone write nothing; [`PurgeStop::InUse`] and [`PurgeStop::Foreign`] met while
    /// deleting leave the tombstone, so the transaction stays hidden and a later run finishes
    /// (or keeps refusing) it.
    pub(crate) fn purge(
        &self,
        id: &TxnId,
        head: Option<&[u8; 32]>,
    ) -> Result<Purged, JournalError> {
        let stop = |why| JournalError::Purge { id: *id, why };
        let rel = id.rel();
        let dir = self.dir.open_dir_write(&rel).map_err(|e| match e.kind {
            SysErrorKind::NotFound => JournalError::NotFound(*id),
            SysErrorKind::ReparsePoint => reparse(self.app, &rel),
            _ => JournalError::Sys(e),
        })?;
        let (view, _) = read::read_txn(&*dir, *id, VerifyBackups::Length, &self.lim)?;
        // A tombstone that cannot be read as a plain file (a folder planted under its name) is in
        // the way like one for another head: refused, nothing written.
        let resume = match read::tombstone(self.dir, id, view.head_sha256.as_ref()) {
            Ok(Some(true)) => true,
            Ok(Some(false)) => return Err(stop(PurgeStop::TombstoneInTheWay)),
            Err(JournalError::Sys(e))
                if matches!(
                    e.kind,
                    SysErrorKind::AccessDenied
                        | SysErrorKind::ReparsePoint
                        | SysErrorKind::InvalidPath
                        | SysErrorKind::Linked
                ) =>
            {
                return Err(stop(PurgeStop::TombstoneInTheWay));
            }
            Ok(None) => false,
            Err(e) => return Err(e),
        };
        // Rerun writes a tombstone only for a settled transaction, and its order never makes a
        // closed one read as open or applied: such a view with a tombstone was not left by a
        // purge unless a forget marker covers it (review nit 4, defense in depth).
        if resume
            && matches!(view.state, TxnState::Open | TxnState::Applied)
            && !read::marker_applies(self.dir, id, view.head_sha256.as_ref())?
        {
            return Err(stop(PurgeStop::NotSettled));
        }
        if !resume {
            if view.head_sha256.as_ref() != head {
                return Err(stop(PurgeStop::HeadChanged));
            }
            let settled = match &view.state {
                TxnState::Closed(_) if view.anomaly.is_some() => {
                    return Err(stop(PurgeStop::Foreign));
                }
                TxnState::Closed(_) | TxnState::Empty => true,
                TxnState::Open | TxnState::Applied | TxnState::Damaged(_) => {
                    read::marker_applies(self.dir, id, head)?
                }
            };
            if !settled {
                return Err(stop(PurgeStop::NotSettled));
            }
        }
        let files = doomed(&*dir, &self.lim)?.map_err(stop)?;
        let dir_id = dir.info()?.file_id;
        if !resume {
            self.put_tombstone(id, head)?;
        }
        for (name, file_id) in &files {
            if let Some(why) = removed(dir.remove_file(name, *file_id))? {
                return Err(stop(why));
            }
        }
        drop(dir);
        self.finish_folder(id, dir_id)
    }

    /// `journal\<txn>.purge` with `create_new`, then `journal\` flushed. One already there with
    /// the same content is `Ok` (a race with nobody: we hold the lock); another content is
    /// [`PurgeStop::TombstoneInTheWay`].
    fn put_tombstone(&self, id: &TxnId, head: Option<&[u8; 32]>) -> Result<(), JournalError> {
        let name = names::tombstone_name(id);
        let content = head.map(crate::wire::hex32::to_string).unwrap_or_default();
        let new = NewFile {
            tmp: self.tmp(),
            attrs: Attrs::default(),
            sha256: Sha256::digest(content.as_bytes()).into(),
            max_len: u64::try_from(content.len()).unwrap_or(u64::MAX),
        };
        match self.dir.create_new(&name, &mut content.as_bytes(), &new) {
            Ok(_) => {}
            Err(e) if e.kind == SysErrorKind::AlreadyExists => {
                if self.dir.read_limited(&name, 64)? != content.as_bytes() {
                    return Err(JournalError::Purge {
                        id: *id,
                        why: PurgeStop::TombstoneInTheWay,
                    });
                }
            }
            Err(e) => return Err(e.into()),
        }
        Ok(self.dir.flush()?)
    }

    /// After the files of `id` are gone: the anchor of `seq`, or the folder (by `dir_id`), the
    /// forget marker and the tombstone, with `journal\` flushed before and after the tombstone.
    fn finish_folder(&self, id: &TxnId, dir_id: u128) -> Result<Purged, JournalError> {
        let stop = |why| JournalError::Purge { id: *id, why };
        let entries = self.dir.read_dir_limited(None, self.lim.journal_entries)?;
        let newer = entries
            .iter()
            .any(|e| e.name.parse::<TxnId>().is_ok_and(|t| t.seq() > id.seq()));
        if newer && let Some(why) = removed(self.dir.remove_dir(&id.rel(), dir_id))? {
            return Err(stop(why));
        }
        let marker = names::marker_name(id);
        if let Some(e) = entries.iter().find(|e| e.name == marker.as_str())
            && plain(e)
            && removed(self.dir.remove_file(&marker, e.meta.file_id))? == Some(PurgeStop::InUse)
        {
            // A marker that is not Rerun's any more stays: without its folder it hides nothing.
            return Err(stop(PurgeStop::InUse));
        }
        self.dir.flush()?;
        if !newer {
            return Ok(Purged { anchor: true });
        }
        let tomb = names::tombstone_name(id);
        if let Some(e) = entries.iter().find(|e| e.name == tomb.as_str()) {
            match removed(self.dir.remove_file(&tomb, e.meta.file_id))? {
                None => {}
                Some(why) => return Err(stop(why)),
            }
        }
        self.dir.flush()?;
        Ok(Purged { anchor: false })
    }

    /// Finishes what earlier purges left (S5): every transaction folder whose tombstone applies
    /// is purged on (an anchor goes once a newer transaction exists), a tombstone for another
    /// head stays untouched, and markers and tombstones without a folder are deleted (markers
    /// first). Best effort per entry (review S1): whatever stops one transaction or one orphan
    /// (in use, foreign, unreadable, any error of its own) leaves it for a later run; only an
    /// error of listing or flushing `journal\` itself is returned.
    pub(crate) fn finish_purges(&self) -> Result<(), JournalError> {
        let entries = self.dir.read_dir_limited(None, self.lim.journal_entries)?;
        let named: BTreeSet<TxnId> = entries.iter().filter_map(|e| e.name.parse().ok()).collect();
        let mut touched = false;
        for pass in [
            names::marker_of as fn(&str) -> Option<TxnId>,
            names::tombstone_of,
        ] {
            for e in entries.iter().filter(|e| plain(e)) {
                let Some(id) = pass(&e.name) else { continue };
                if named.contains(&id) {
                    continue;
                }
                let Ok(name) = RelPath::from_segment(&e.name) else {
                    continue;
                };
                // An orphan that does not go now goes next time.
                touched |= self.dir.remove_file(&name, e.meta.file_id).is_ok();
            }
        }
        for e in entries.iter().filter(|e| plain(e)) {
            let Some(id) = names::tombstone_of(&e.name) else {
                continue;
            };
            if named.contains(&id) {
                // Whatever stops this one leaves it for a later run.
                let _later = self.purge(&id, None);
                touched = true;
            }
        }
        if touched {
            // Makes what was deleted durable, and reports a `journal\` that cannot be flushed.
            self.dir.flush()?;
        }
        Ok(())
    }
}
