//! Reading the journal (ADR 0019, "The journal is untrusted input"; P2-7 amendment).
//!
//! Every read is bounded before anything is parsed: the listing of `journal\` and of a
//! transaction folder (`read_dir_limited`), `head.json` and each record (`read_limited`), a
//! backup when it is hashed (at most its intent's length plus one byte). Nothing found is
//! repaired or followed: a reparse point is an error, an unexpected entry or record is a
//! [`Damage`].

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;

use sha2::{Digest, Sha256};

use super::names::{self, HEAD, TxnEntry};
use super::record::{self, BackupRef};
use super::replay::Machine;
use super::{
    BackupFault, Damage, JournalError, Limits, Listed, Listing, TxnId, TxnState, TxnView,
    VerifyBackups, reparse,
};
use crate::path::{RelPath, RootPath};
use crate::sys::fs::{EntryKind, TmpName};
use crate::sys::{Dir, SysErrorKind};

/// The highest `seq` of any entry of `journal\` that has a transaction name (whatever its
/// kind), and the entries that are neither such a name, nor `lock`, nor a temp name.
pub(super) fn scan(
    jdir: &dyn Dir,
    lim: &Limits,
) -> Result<(Vec<(TxnId, EntryKind)>, usize), JournalError> {
    let entries = jdir.read_dir_limited(None, lim.journal_entries)?;
    let mut txns = Vec::new();
    let mut foreign = 0;
    for e in entries {
        if let Ok(id) = e.name.parse::<TxnId>() {
            txns.push((id, e.meta.kind));
        } else if e.name != names::LOCK && TmpName::parse(&e.name).is_none() {
            foreign += 1;
        }
    }
    txns.sort_by_key(|(id, _)| *id);
    Ok((txns, foreign))
}

/// Every transaction of `journal\` (S5: two folders with one `seq` are both damaged).
pub(super) fn list(jdir: &dyn Dir, lim: &Limits, app: &RootPath) -> Result<Listing, JournalError> {
    let (ids, foreign) = scan(jdir, lim)?;
    let mut per_seq: BTreeMap<u32, usize> = BTreeMap::new();
    for (id, _) in &ids {
        *per_seq.entry(id.seq()).or_default() += 1;
    }
    let txns = ids
        .into_iter()
        .map(|(id, _)| {
            let mut view = load(jdir, &id, VerifyBackups::Length, lim, app);
            if per_seq.get(&id.seq()).copied().unwrap_or(0) > 1
                && let Ok(v) = &mut view
            {
                v.state = TxnState::Damaged(Damage::DuplicateSeq);
            }
            Listed { id, view }
        })
        .collect();
    Ok(Listing { txns, foreign })
}

/// What a transaction folder holds, by name.
#[derive(Default)]
struct Entries {
    head: bool,
    records: BTreeSet<u16>,
    /// Backup op → length from the listing.
    backups: BTreeMap<u16, u64>,
    unknown: bool,
}

fn entries(dir: &dyn Dir, lim: &Limits) -> Result<Option<Entries>, JournalError> {
    let listing = match dir.read_dir_limited(None, lim.txn_entries) {
        Ok(l) => l,
        Err(e) if e.kind == SysErrorKind::TooLarge => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let mut found = Entries::default();
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

/// Reads one transaction (P2-7 amendment, "States").
pub(super) fn load(
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
        state: TxnState::Empty,
        anomaly: None,
        ops: BTreeMap::new(),
        log: Vec::new(),
    };
    let mut m = Machine::default();
    let damaged = |mut view: TxnView, m: Machine, d: Damage| {
        view.state = TxnState::Damaged(d);
        Ok((view, m))
    };
    let Some(found) = entries(dir, lim)? else {
        return damaged(view, m, Damage::TooManyEntries);
    };
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
        let named = ops.get(op).is_some_and(|o| o.intent.backup.is_some());
        let orphan = !ops.contains_key(op) && *op == m.intents();
        if !named && !orphan {
            return Ok(Some(Damage::UnknownEntry));
        }
    }
    for (op, b) in ops.iter().filter_map(|(k, o)| Some((*k, o.intent.backup?))) {
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
fn hash_matches(dir: &dyn Dir, name: &RelPath, b: &BackupRef) -> Result<bool, JournalError> {
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
