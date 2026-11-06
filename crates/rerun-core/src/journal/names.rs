//! Names in the journal (ADR 0019, "Names"): transaction folders, records, backups and the
//! instance tag. Every name has one written form, and parsing accepts only that form.

use std::fmt;
use std::hash::{BuildHasher, Hasher};
use std::str::FromStr;

use crate::path::RelPath;
use crate::sys::fs::TmpName;

/// Highest sequence number: the folder name has exactly 8 decimal digits.
pub const MAX_SEQ: u32 = 99_999_999;

/// `head.json`: the plan bytes.
pub(crate) const HEAD: &str = "head.json";
/// `lock` in `journal`.
pub(crate) const LOCK: &str = "lock";

/// A transaction: `<seq>-<tag>`, 8 decimal digits and 16 lower-case hex digits. Ordered by
/// `seq` (then `tag`), which totally orders transactions for LIFO (ADR 0019).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TxnId {
    seq: u32,
    tag: u64,
}

impl TxnId {
    /// `None` if `seq` has more than 8 digits.
    pub(crate) fn new(seq: u32, tag: u64) -> Option<Self> {
        (seq <= MAX_SEQ).then_some(Self { seq, tag })
    }

    /// The sequence number.
    pub fn seq(&self) -> u32 {
        self.seq
    }

    /// The instance tag of the run that began it.
    pub fn tag(&self) -> u64 {
        self.tag
    }

    /// The folder name as a single segment.
    pub(crate) fn rel(&self) -> RelPath {
        segment(&self.to_string())
    }
}

impl fmt::Display for TxnId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:08}-{:016x}", self.seq, self.tag)
    }
}

/// A string that is not a transaction name.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("not a transaction name (8 digits, '-', 16 lower-case hex digits)")]
pub struct BadTxnId;

impl FromStr for TxnId {
    type Err = BadTxnId;

    fn from_str(s: &str) -> Result<Self, BadTxnId> {
        let (seq, tag) = s.split_once('-').ok_or(BadTxnId)?;
        let hex = |c: char| c.is_ascii_digit() || ('a'..='f').contains(&c);
        if seq.len() != 8 || !seq.chars().all(|c| c.is_ascii_digit()) {
            return Err(BadTxnId);
        }
        if tag.len() != 16 || !tag.chars().all(hex) {
            return Err(BadTxnId);
        }
        let seq = seq.parse().map_err(|_| BadTxnId)?;
        let tag = u64::from_str_radix(tag, 16).map_err(|_| BadTxnId)?;
        Self::new(seq, tag).ok_or(BadTxnId)
    }
}

/// The instance tag (ADR 0019): 64 bits, different per run, in every temp name and in the
/// name of every transaction the run begins. Not a secret; `create_new` catches collisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InstanceTag(u64);

impl InstanceTag {
    /// A fresh tag: `std::hash::RandomState` (keys from the OS random generator) over the
    /// process ID and the current time.
    pub fn new() -> Self {
        let mut h = std::hash::RandomState::new().build_hasher();
        h.write_u32(std::process::id());
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        h.write_u128(now);
        Self(h.finish())
    }

    /// A fixed tag, for tests.
    pub fn fixed(tag: u64) -> Self {
        Self(tag)
    }

    /// The value.
    pub fn get(self) -> u64 {
        self.0
    }
}

impl Default for InstanceTag {
    fn default() -> Self {
        Self::new()
    }
}

/// What a name in a transaction folder is (ADR 0019 amendment, P2-7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TxnEntry {
    /// `head.json`.
    Head,
    /// `NNNN.json`, 1 to the record limit.
    Record(u16),
    /// `op-NNNN.bin`: the backup of op `NNNN` (named by op, not by record, B1).
    Backup(u16),
    /// A temp name of Rerun (`.rerun-<tag>-<n>.tmp`): a crash remnant, never read.
    Tmp,
    /// Anything else.
    Unknown,
}

/// Exactly 4 decimal digits.
fn four_digits(s: &str) -> Option<u16> {
    (s.len() == 4 && s.chars().all(|c| c.is_ascii_digit()))
        .then(|| s.parse().ok())
        .flatten()
}

/// Classifies a raw name of a transaction folder. Names are compared exactly (they are
/// written by Rerun in this form; another spelling is someone else's).
pub(crate) fn classify(name: &str, max_records: u16) -> TxnEntry {
    if name == HEAD {
        return TxnEntry::Head;
    }
    if let Some(n) = name.strip_suffix(".json").and_then(four_digits)
        && (1..=max_records).contains(&n)
    {
        return TxnEntry::Record(n);
    }
    if let Some(op) = name
        .strip_prefix("op-")
        .and_then(|s| s.strip_suffix(".bin"))
        .and_then(four_digits)
    {
        return TxnEntry::Backup(op);
    }
    if TmpName::parse(name).is_some() {
        return TxnEntry::Tmp;
    }
    TxnEntry::Unknown
}

/// `NNNN.json`.
pub(crate) fn record_name(n: u16) -> RelPath {
    segment(&format!("{n:04}.json"))
}

/// `op-NNNN.bin`.
pub(crate) fn backup_name(op: u16) -> RelPath {
    segment(&format!("op-{op:04}.bin"))
}

/// Suffix of a forget marker `<txn>.forgotten` in `journal\` (user decision D2).
const MARKER_SUFFIX: &str = ".forgotten";

/// `<txn>.forgotten`.
pub(crate) fn marker_name(id: &TxnId) -> RelPath {
    segment(&format!("{id}{MARKER_SUFFIX}"))
}

/// The transaction of a forget marker name, exactly in the written form.
pub(crate) fn marker_of(name: &str) -> Option<TxnId> {
    name.strip_suffix(MARKER_SUFFIX)?.parse().ok()
}

/// A fixed name (`head.json`, `lock`) as a segment.
pub(crate) fn fixed(name: &str) -> RelPath {
    segment(name)
}

/// Names built here are ASCII digits, letters, `-` and `.` without a trailing dot: always a
/// valid single segment.
fn segment(s: &str) -> RelPath {
    match RelPath::from_segment(s) {
        Ok(p) => p,
        Err(e) => unreachable!("{s:?} is a journal name and a segment: {e}"),
    }
}

#[cfg(test)]
mod tests {
    use super::{InstanceTag, MAX_SEQ, TxnEntry, TxnId, backup_name, classify, record_name};

    #[test]
    fn j8_txn_ids_are_a_bijection_and_ordered_by_seq() {
        for (seq, tag) in [
            (0, 0),
            (1, 0xab),
            (MAX_SEQ, u64::MAX),
            (42, 0x0123_4567_89ab_cdef),
        ] {
            let id = TxnId::new(seq, tag).unwrap();
            let s = id.to_string();
            assert_eq!(s.len(), 25, "{s}");
            assert_eq!(s.parse::<TxnId>(), Ok(id), "{s}");
            assert_eq!(id.rel().as_str(), s);
            assert_eq!((id.seq(), id.tag()), (seq, tag));
        }
        assert_eq!(
            TxnId::new(7, 0xab).unwrap().to_string(),
            "00000007-00000000000000ab"
        );
        assert!(TxnId::new(MAX_SEQ + 1, 0).is_none());
        for bad in [
            "",
            "00000001",
            "00000001-",
            "0000001-00000000000000ab",
            "000000001-00000000000000ab",
            "00000001-0000000000000ab",
            "00000001-000000000000000ab",
            "00000001-00000000000000AB",
            "+0000001-00000000000000ab",
            "0000000a-00000000000000ab",
            "00000001_00000000000000ab",
            "00000001-00000000000000ab-",
            "00000001-+0000000000000ab",
            "00000001-00000000000000ab.json",
        ] {
            assert!(bad.parse::<TxnId>().is_err(), "{bad}");
        }
        // Ordered by seq first, whatever the tag.
        let a = TxnId::new(2, u64::MAX).unwrap();
        let b = TxnId::new(10, 0).unwrap();
        assert!(a < b);
        assert!(a.to_string() < b.to_string(), "the names sort the same way");
    }

    #[test]
    fn j8_entries_have_one_form() {
        assert_eq!(classify("head.json", 1024), TxnEntry::Head);
        assert_eq!(classify("0001.json", 1024), TxnEntry::Record(1));
        assert_eq!(classify("1024.json", 1024), TxnEntry::Record(1024));
        assert_eq!(classify("op-0000.bin", 1024), TxnEntry::Backup(0));
        assert_eq!(classify("op-0127.bin", 1024), TxnEntry::Backup(127));
        assert_eq!(
            classify(".rerun-00000000000000ab-3.tmp", 1024),
            TxnEntry::Tmp
        );
        assert_eq!(record_name(7).as_str(), "0007.json");
        assert_eq!(backup_name(7).as_str(), "op-0007.bin");
        for bad in [
            "HEAD.JSON",
            "head.json.tmp",
            "0000.json",
            "1025.json",
            "001.json",
            "00001.json",
            "0001.JSON",
            "+001.json",
            "op-001.bin",
            "op-00001.bin",
            "OP-0001.bin",
            "0001.bin",
            ".rerun-ab-3.tmp",
            "lock",
            "desktop.ini",
        ] {
            assert_eq!(classify(bad, 1024), TxnEntry::Unknown, "{bad}");
        }
        assert_eq!(
            classify("0005.json", 4),
            TxnEntry::Unknown,
            "beyond the limit"
        );
    }

    #[test]
    fn instance_tags_differ_between_instances() {
        let tags: std::collections::BTreeSet<u64> =
            (0..16).map(|_| InstanceTag::new().get()).collect();
        assert_eq!(tags.len(), 16);
        assert_eq!(InstanceTag::fixed(9).get(), 9);
    }
}
