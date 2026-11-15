//! Reading the journal (ADR 0019, "The journal is untrusted input"; P2-7 amendment).
//!
//! Every read is bounded before anything is parsed: the listing of `journal\` and of a
//! transaction folder (`read_dir_limited`), `head.json` and each record (`read_limited`), a
//! backup when it is hashed (at most its intent's length plus one byte). Nothing found is
//! repaired or followed: a reparse point is an error, an unexpected entry or record is a
//! [`Damage`].

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;

use sha2::{Digest as _, Sha256};

use super::names::{self, HEAD, TxnEntry};
use super::record::{self, Digest};
use super::replay::Machine;
use super::{
    BackupFault, Damage, JournalError, Limits, Listed, Listing, TxnId, TxnState, TxnView,
    VerifyBackups, reparse,
};
use crate::path::{RelPath, RootPath};
use crate::sys::fs::{EntryKind, TmpName};
use crate::sys::{Dir, SysErrorKind};

/// What [`scan`] finds in `journal\`.
pub(super) struct Scan {
    /// Every entry with a transaction name (whatever its kind), ordered.
    pub(super) txns: Vec<(TxnId, EntryKind)>,
    /// Plain files `<txn>.forgotten` (user decision D2): their transactions.
    pub(super) forgotten: Vec<TxnId>,
    /// Plain files `<txn>.purge` (P5-6d): their transactions. Only orphans are counted from
    /// here; whether a tombstone hides a transaction is read after its `load`, independently.
    pub(super) purges: Vec<TxnId>,
    /// Entries that are none of these, nor `lock`, nor a temp name.
    pub(super) foreign: usize,
}

/// The entries of `journal\`: transaction names (every one counts for `seq`), forget markers
/// and the rest.
pub(super) fn scan(jdir: &dyn Dir, lim: &Limits) -> Result<Scan, JournalError> {
    let entries = jdir.read_dir_limited(None, lim.journal_entries)?;
    let mut s = Scan {
        txns: Vec::new(),
        forgotten: Vec::new(),
        purges: Vec::new(),
        foreign: 0,
    };
    for e in entries {
        if let Ok(id) = e.name.parse::<TxnId>() {
            s.txns.push((id, e.meta.kind));
        } else if let Some(id) = names::marker_of(&e.name)
            && e.meta.kind == EntryKind::File
            && !e.meta.restricted
        {
            s.forgotten.push(id);
        } else if let Some(id) = names::tombstone_of(&e.name)
            && e.meta.kind == EntryKind::File
            && !e.meta.restricted
        {
            s.purges.push(id);
        } else if e.name != names::LOCK && TmpName::parse(&e.name).is_none() {
            s.foreign += 1;
        }
    }
    s.txns.sort_by_key(|(id, _)| *id);
    Ok(s)
}

/// A forget marker applies to the transaction as it is now: its content names the head
/// hash that was forgotten (or nothing, for a transaction without a readable head), so a
/// head swapped in afterwards is not covered.
pub(super) fn marker_applies(
    jdir: &dyn Dir,
    id: &TxnId,
    head: Option<&[u8; 32]>,
) -> Result<bool, JournalError> {
    let content = match jdir.read_limited(&names::marker_name(id), 64) {
        Ok(c) => c,
        Err(e) if matches!(e.kind, SysErrorKind::NotFound | SysErrorKind::TooLarge) => {
            return Ok(false);
        }
        Err(e) => return Err(e.into()),
    };
    Ok(head_named(&content, head))
}

/// The tombstone `<txn>.purge` (P5-6d) as it is now: `None` without one; else whether it
/// applies to the transaction as loaded, by the rule of the forget marker: its content names
/// the head that was purged, or there is no head (any more). A tombstone that cannot be read
/// as a plain file of at most 64 bytes does not apply.
pub(super) fn tombstone(
    jdir: &dyn Dir,
    id: &TxnId,
    head: Option<&[u8; 32]>,
) -> Result<Option<bool>, JournalError> {
    let content = match jdir.read_limited(&names::tombstone_name(id), 64) {
        Ok(c) => c,
        Err(e) if e.kind == SysErrorKind::NotFound => return Ok(None),
        Err(e) if e.kind == SysErrorKind::TooLarge => return Ok(Some(false)),
        Err(e) => return Err(e.into()),
    };
    Ok(Some(head_named(&content, head)))
}

/// The content of a marker or tombstone names `head` (or there is no head).
pub(super) fn head_named(content: &[u8], head: Option<&[u8; 32]>) -> bool {
    match head {
        Some(h) => content == crate::wire::hex32::to_string(h).as_bytes(),
        None => true,
    }
}

/// What a reader makes of a transaction after its `load` (P5-6d, S2): the tombstone is read
/// after every `load`, never taken from the scan. A tombstone that applies hides it; a folder
/// gone by now hides it (the purge finished, its tombstone may be gone too); everything else
/// is shown as loaded.
enum Seen {
    Shown(Result<TxnView, JournalError>),
    /// Hidden by a tombstone; `bare`: an empty folder (the anchor of `seq`).
    Purging {
        bare: bool,
    },
    Gone,
}

fn see(jdir: &dyn Dir, id: &TxnId, v: VerifyBackups, lim: &Limits, app: &RootPath) -> Seen {
    let view = load_raw(jdir, id, v, lim, app);
    if matches!(view, Err(JournalError::NotFound(_))) {
        return Seen::Gone;
    }
    // Only a folder that was read can be hidden: the head (or its absence) is known then. An
    // unreadable one is shown whatever tombstone there is (fail closed, review S-1: otherwise a
    // tombstone with any content would hide an unreadable heir from the hand-over rule). A
    // tombstone that cannot be read leaves the transaction as loaded too.
    if let Ok(v) = &view
        && let Ok(Some(true)) = tombstone(jdir, id, v.head_sha256.as_ref())
    {
        return Seen::Purging { bare: v.bare };
    }
    // The purge removes the folder before its tombstone: a view caught mid-purge whose
    // tombstone is gone by now belongs to a folder that is gone as well. Only a view that is
    // not settled is worth the second look.
    let settled = view
        .as_ref()
        .is_ok_and(|v| matches!(v.state, TxnState::Closed(_) | TxnState::Empty));
    if !settled && matches!(jdir.metadata(&id.rel()), Ok(None)) {
        return Seen::Gone;
    }
    Seen::Shown(view)
}

/// Every transaction of `journal\`, without head bytes (only their hashes). S5: every entry
/// with a transaction name counts for its `seq`; two with one `seq` make an open or applied
/// one damaged, a closed one gets the anomaly, a damaged one keeps its first cause. A
/// transaction with a forget marker that applies to it is [`Listed::forgotten`]. P5-6d: a
/// transaction a tombstone hides, or whose folder vanished after the scan, is not listed;
/// [`Listing::purging`] counts the purges begun (hidden folders that are not bare, and
/// tombstones without a folder), never the anchor of `seq`.
pub(super) fn list(jdir: &dyn Dir, lim: &Limits, app: &RootPath) -> Result<Listing, JournalError> {
    let Scan {
        txns: ids,
        forgotten,
        purges,
        foreign,
    } = scan(jdir, lim)?;
    let mut per_seq: BTreeMap<u32, usize> = BTreeMap::new();
    for (id, _) in &ids {
        *per_seq.entry(id.seq()).or_default() += 1;
    }
    let mut purging = purges
        .iter()
        .filter(|p| !ids.iter().any(|(id, _)| id == *p))
        .count();
    let mut txns = Vec::with_capacity(ids.len());
    for (id, _) in ids {
        let mut view = match see(jdir, &id, VerifyBackups::Length, lim, app) {
            Seen::Shown(v) => v,
            Seen::Purging { bare } => {
                purging += usize::from(!bare);
                continue;
            }
            Seen::Gone => continue,
        };
        if let Ok(v) = &mut view {
            v.head = None;
            if per_seq.get(&id.seq()).copied().unwrap_or(0) > 1 {
                match v.state {
                    TxnState::Damaged(_) => {}
                    TxnState::Closed(_) => {
                        v.anomaly.get_or_insert(Damage::DuplicateSeq);
                    }
                    _ => v.state = TxnState::Damaged(Damage::DuplicateSeq),
                }
            }
        }
        let forgotten = forgotten.contains(&id)
            && marker_applies(
                jdir,
                &id,
                view.as_ref().ok().and_then(|v| v.head_sha256.as_ref()),
            )?;
        txns.push(Listed {
            id,
            view,
            forgotten,
        });
    }
    Ok(Listing {
        txns,
        foreign,
        purging,
    })
}

/// What a transaction folder holds, by name.
#[derive(Default)]
struct Entries {
    head: bool,
    records: BTreeSet<u16>,
    /// Backup op → length from the listing.
    backups: BTreeMap<u16, u64>,
    unknown: bool,
    /// Entries listed, of any kind.
    count: usize,
}

fn entries(dir: &dyn Dir, lim: &Limits) -> Result<Option<Entries>, JournalError> {
    let listing = match dir.read_dir_limited(None, lim.txn_entries) {
        Ok(l) => l,
        Err(e) if e.kind == SysErrorKind::TooLarge => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let mut found = Entries {
        count: listing.len(),
        ..Entries::default()
    };
    for e in listing {
        let class = names::classify(&e.name, lim.records);
        let plain = e.meta.kind == EntryKind::File && !e.meta.restricted;
        match class {
            TxnEntry::Tmp => {}
            _ if !plain => found.unknown = true,
            TxnEntry::Head => found.head = true,
            TxnEntry::Record(n) => {
                found.records.insert(n);
            }
            TxnEntry::Backup(op) => {
                found.backups.insert(op, e.meta.len);
            }
            TxnEntry::Unknown => found.unknown = true,
        }
    }
    Ok(Some(found))
}

/// Reads one transaction (P2-7 amendment, "States") as a reader sees it: one that a tombstone
/// hides, or whose folder is gone, is `NotFound` (P5-6d).
pub(super) fn load(
    jdir: &dyn Dir,
    id: &TxnId,
    v: VerifyBackups,
    lim: &Limits,
    app: &RootPath,
) -> Result<TxnView, JournalError> {
    match see(jdir, id, v, lim, app) {
        Seen::Shown(view) => view,
        Seen::Purging { .. } | Seen::Gone => Err(JournalError::NotFound(*id)),
    }
}

/// Reads one transaction folder, whatever tombstone there is.
pub(super) fn load_raw(
    jdir: &dyn Dir,
    id: &TxnId,
    v: VerifyBackups,
    lim: &Limits,
    app: &RootPath,
) -> Result<TxnView, JournalError> {
    let rel = id.rel();
    let dir = jdir.open_dir(&rel).map_err(|e| match e.kind {
        SysErrorKind::NotFound => JournalError::NotFound(*id),
        SysErrorKind::ReparsePoint => reparse(app, &rel),
        _ => JournalError::Sys(e),
    })?;
    read_txn(&*dir, *id, v, lim).map(|(view, _)| view)
}

/// Reads an opened transaction folder; also returns the replay machine (for `resume`).
pub(super) fn read_txn(
    dir: &dyn Dir,
    id: TxnId,
    v: VerifyBackups,
    lim: &Limits,
) -> Result<(TxnView, Machine), JournalError> {
    let mut view = TxnView {
        id,
        head: None,
        head_sha256: None,
        state: TxnState::Empty,
        anomaly: None,
        ops: BTreeMap::new(),
        rebinds: Vec::new(),
        log: Vec::new(),
        has_records: false,
        bare: false,
    };
    let mut m = Machine::default();
    let damaged = |mut view: TxnView, m: Machine, d: Damage| {
        view.state = TxnState::Damaged(d);
        Ok((view, m))
    };
    let Some(found) = entries(dir, lim)? else {
        return damaged(view, m, Damage::TooManyEntries);
    };
    view.has_records = !found.records.is_empty();
    view.bare = found.count == 0;
    if found.records.is_empty() && !found.head {
        // B2: a folder without head and records changed nothing (a crash right after
        // `begin` created it); it still counts for `seq`.
        return if found.unknown {
            damaged(view, m, Damage::UnknownEntry)
        } else {
            Ok((view, m))
        };
    }
    if !found.head {
        return damaged(view, m, Damage::HeadMissing);
    }
    let head = match dir.read_limited(&names::fixed(HEAD), lim.head) {
        Ok(h) => h,
        Err(e) if e.kind == SysErrorKind::TooLarge => {
            return damaged(view, m, Damage::HeadTooLarge);
        }
        Err(e) => return Err(e.into()),
    };
    let head_sha: [u8; 32] = Sha256::digest(&head).into();
    view.head = Some(head);
    view.head_sha256 = Some(head_sha);

    let last = found.records.last().copied().unwrap_or(0);
    let mut damage = None;
    for n in 1..=last {
        if !found.records.contains(&n) {
            damage = Some(Damage::Gap { at: n });
            break;
        }
        let bytes = match dir.read_limited(&names::record_name(n), lim.record) {
            Ok(b) => b,
            Err(e) if e.kind == SysErrorKind::TooLarge => {
                damage = Some(Damage::TooLarge { n });
                break;
            }
            Err(e) if e.kind == SysErrorKind::NotFound => {
                damage = Some(Damage::Gap { at: n });
                break;
            }
            Err(e) => return Err(e.into()),
        };
        let rec = match record::decode(&bytes, n, &head_sha) {
            Ok(r) => r,
            Err(d) => {
                damage = Some(d);
                break;
            }
        };
        if let Err(why) = m.step(&rec) {
            damage = Some(Damage::Grammar { n, why });
            break;
        }
        view.log.push(rec);
    }
    if damage.is_none() && found.unknown {
        damage = Some(Damage::UnknownEntry);
    }
    if damage.is_none() && m.closed().is_none() {
        damage = check_backups(dir, &m, &found.backups, v)?;
    }
    view.ops = m.ops().clone();
    view.rebinds = m.rebinds().to_vec();
    view.state = m.state();
    if let Some(d) = damage {
        if m.closed().is_some() {
            // E2: a valid prefix up to `Closed` with a planted tail.
            view.anomaly = Some(d);
        } else {
            view.state = TxnState::Damaged(d);
        }
    }
    Ok((view, m))
}

/// B1: every `op-NNNN.bin` is named by its intent or is the orphan of the next op; every
/// backup an intent names exists with its length (and hash, if asked).
fn check_backups(
    dir: &dyn Dir,
    m: &Machine,
    bins: &BTreeMap<u16, u64>,
    v: VerifyBackups,
) -> Result<Option<Damage>, JournalError> {
    let ops = m.ops();
    for op in bins.keys() {
        let named = ops.get(op).is_some_and(|o| o.intent.bin().is_some());
        let orphan = !ops.contains_key(op) && *op == m.intents();
        if !named && !orphan {
            return Ok(Some(Damage::UnknownEntry));
        }
    }
    for (op, b) in ops.iter().filter_map(|(k, o)| Some((*k, o.intent.bin()?))) {
        let Some(len) = bins.get(&op) else {
            return Ok(Some(Damage::Backup {
                op,
                why: BackupFault::Missing,
            }));
        };
        if *len != b.len {
            return Ok(Some(Damage::Backup {
                op,
                why: BackupFault::Length,
            }));
        }
        if v == VerifyBackups::Hash && !hash_matches(dir, &names::backup_name(op), &b)? {
            return Ok(Some(Damage::Backup {
                op,
                why: BackupFault::Hash,
            }));
        }
    }
    Ok(None)
}

/// Streams at most `b.len + 1` bytes of `name` and compares hash and length.
fn hash_matches(dir: &dyn Dir, name: &RelPath, b: &Digest) -> Result<bool, JournalError> {
    let reader = match dir.open_read(name) {
        Ok(r) => r,
        Err(e) if e.kind == SysErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e.into()),
    };
    let (sha, len) = stream_hash(reader.take(b.len.saturating_add(1)), name)?;
    Ok(sha == b.sha256 && len == b.len)
}

/// SHA-256 and length of everything `r` yields.
pub(super) fn stream_hash(
    mut r: impl Read,
    name: &RelPath,
) -> Result<([u8; 32], u64), JournalError> {
    let mut h = Sha256::new();
    let mut len = 0u64;
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = match r.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(crate::sys::SysError::io(&e, name.as_str()).into()),
        };
        h.update(buf.get(..n).unwrap_or_default());
        len = len.saturating_add(u64::try_from(n).unwrap_or(u64::MAX));
    }
    Ok((h.finalize().into(), len))
}
