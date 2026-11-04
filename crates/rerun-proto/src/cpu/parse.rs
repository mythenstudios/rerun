//! Parser for the two Windows topology buffers (ADR 0010). Pure, safe, no dependencies.
//!
//! [`CpuTopology::from_windows`] takes the bytes returned by `GetSystemCpuSetInformation`
//! (system-wide, `Process = NULL`) and by `GetLogicalProcessorInformationEx(RelationAll)`, in
//! the layout a **64-bit** process receives (`KAFFINITY` is 8 bytes; offsets in [`layout`]).
//! Fields are read by offset from the byte slice: no casts, no alignment needs. Every record
//! header must fit, `Size` must be non-zero, at least the minimum of its type (including its
//! variable part) and fit in the buffer. Unknown record types are skipped by `Size`.
//!
//! Authority:
//! - CPU Sets: `cpu_set_id`, the set of `(group, index)`, the flags.
//! - GLPI: core membership, LLC membership (per logical processor the highest-level unified or
//!   data cache whose group masks contain it), LLC level and size, the active groups.
//!   Membership is taken on the active logical processors; mask bits of inactive ones are
//!   ignored.
//!
//! The two must agree ([`Check`]); any mismatch is an error, never a best-effort topology.
//! CPU Sets with `RealTime` or `Allocated` are then left out, and `core`/`llc` are numbered
//! densely in first-appearance order over the remaining processors sorted by
//! `(group, index)`. `Parked`, `SchedulingClass`, `AllocationTag` and `NumaNodeIndex` are
//! ignored.

use std::collections::BTreeMap;
use std::fmt;

use super::{CpuTopology, GROUP_SIZE, Llc, LogicalCpu, MAX_LOGICAL_CPUS, TopologyError};

/// Byte offsets of the Windows structures, relative to the start of a record, in the layout of
/// a 64-bit process. A layout test in `rerun-core` compares them with `offset_of!` on the
/// `windows-sys` structures.
pub mod layout {
    /// `SYSTEM_CPU_SET_INFORMATION.Size` (u32).
    pub const CPU_SET_SIZE: usize = 0;
    /// `SYSTEM_CPU_SET_INFORMATION.Type` (u32; `CpuSetInformation` = 0).
    pub const CPU_SET_TYPE: usize = 4;
    /// `CpuSet.Id` (u32).
    pub const CPU_SET_ID: usize = 8;
    /// `CpuSet.Group` (u16).
    pub const CPU_SET_GROUP: usize = 12;
    /// `CpuSet.LogicalProcessorIndex` (u8).
    pub const CPU_SET_LOGICAL_PROCESSOR_INDEX: usize = 14;
    /// `CpuSet.CoreIndex` (u8, group-relative).
    pub const CPU_SET_CORE_INDEX: usize = 15;
    /// `CpuSet.LastLevelCacheIndex` (u8, group-relative).
    pub const CPU_SET_LAST_LEVEL_CACHE_INDEX: usize = 16;
    /// `CpuSet.EfficiencyClass` (u8).
    pub const CPU_SET_EFFICIENCY_CLASS: usize = 18;
    /// `CpuSet.AllFlags` (u8).
    pub const CPU_SET_ALL_FLAGS: usize = 19;
    /// Smallest CPU Set record the parser accepts: every field it reads.
    pub const CPU_SET_MIN_SIZE: usize = 20;
    /// Size of `SYSTEM_CPU_SET_INFORMATION` (Windows 10 and 11).
    pub const CPU_SET_STRUCT_SIZE: usize = 32;

    /// `SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX.Relationship` (u32).
    pub const INFO_RELATIONSHIP: usize = 0;
    /// `SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX.Size` (u32).
    pub const INFO_SIZE: usize = 4;
    /// Start of the relationship union.
    pub const INFO_BODY: usize = 8;

    /// `Processor.EfficiencyClass` (u8).
    pub const PROCESSOR_EFFICIENCY_CLASS: usize = 9;
    /// `Processor.GroupCount` (u16).
    pub const PROCESSOR_GROUP_COUNT: usize = 30;
    /// `Processor.GroupMask[0]`.
    pub const PROCESSOR_GROUP_MASK: usize = 32;

    /// `Cache.Level` (u8).
    pub const CACHE_LEVEL: usize = 8;
    /// `Cache.CacheSize` (u32).
    pub const CACHE_SIZE: usize = 12;
    /// `Cache.Type` (u32).
    pub const CACHE_TYPE: usize = 16;
    /// `Cache.GroupCount` (u16; reserved and 0 before Windows 11, counts as 1).
    pub const CACHE_GROUP_COUNT: usize = 38;
    /// `Cache.GroupMask` / `GroupMasks[0]`.
    pub const CACHE_GROUP_MASK: usize = 40;

    /// `Group.ActiveGroupCount` (u16).
    pub const GROUP_ACTIVE_GROUP_COUNT: usize = 10;
    /// `Group.GroupInfo[0]`.
    pub const GROUP_INFO: usize = 32;
    /// Size of `PROCESSOR_GROUP_INFO`.
    pub const GROUP_INFO_SIZE: usize = 48;
    /// `PROCESSOR_GROUP_INFO.ActiveProcessorCount` (u8).
    pub const GROUP_INFO_ACTIVE_PROCESSOR_COUNT: usize = 1;
    /// `PROCESSOR_GROUP_INFO.ActiveProcessorMask` (`KAFFINITY`, 8 bytes).
    pub const GROUP_INFO_ACTIVE_PROCESSOR_MASK: usize = 40;

    /// Size of `GROUP_AFFINITY`.
    pub const GROUP_AFFINITY_SIZE: usize = 16;
    /// `GROUP_AFFINITY.Mask` (`KAFFINITY`, 8 bytes).
    pub const GROUP_AFFINITY_MASK: usize = 0;
    /// `GROUP_AFFINITY.Group` (u16).
    pub const GROUP_AFFINITY_GROUP: usize = 8;
}

use layout as l;

/// `CPU_SET_INFORMATION_TYPE::CpuSetInformation`.
pub const CPU_SET_INFORMATION: u32 = 0;
/// `LOGICAL_PROCESSOR_RELATIONSHIP::RelationProcessorCore`.
pub const RELATION_PROCESSOR_CORE: u32 = 0;
/// `LOGICAL_PROCESSOR_RELATIONSHIP::RelationCache`.
pub const RELATION_CACHE: u32 = 2;
/// `LOGICAL_PROCESSOR_RELATIONSHIP::RelationGroup`.
pub const RELATION_GROUP: u32 = 4;
/// `PROCESSOR_CACHE_TYPE::CacheUnified`.
pub const CACHE_UNIFIED: u32 = 0;
/// `PROCESSOR_CACHE_TYPE::CacheData`.
pub const CACHE_DATA: u32 = 2;
/// `SYSTEM_CPU_SET_INFORMATION_ALLOCATED`.
pub const FLAG_ALLOCATED: u8 = 0x2;
/// `SYSTEM_CPU_SET_INFORMATION_REALTIME`.
pub const FLAG_REALTIME: u8 = 0x8;

/// Which Windows buffer a [`TopologyError`] refers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Source {
    /// `GetSystemCpuSetInformation`.
    CpuSets,
    /// `GetLogicalProcessorInformationEx(RelationAll)`.
    ProcessorInfo,
}

impl fmt::Display for Source {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::CpuSets => "cpu sets",
            Self::ProcessorInfo => "processor information",
        })
    }
}

/// A consistency check of [`CpuTopology::from_windows`] (ADR 0010, fail closed).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Check {
    /// Exactly one `RelationGroup` record.
    GroupRecord,
    /// The CPU Set IDs are unique.
    CpuSetIdsUnique,
    /// No `(group, index)` appears twice in the CPU Sets.
    CpuSetsUnique,
    /// The CPU Sets' `(group, index)` equal the active masks of `RelationGroup`.
    CpuSetsMatchGroups,
    /// Every active logical processor is in exactly one `RelationProcessorCore`.
    CoreMembership,
    /// The partition by `(Group, CoreIndex)` equals the one by `RelationProcessorCore`.
    CorePartition,
    /// Every active logical processor has exactly one highest-level unified or data cache.
    LlcMembership,
    /// The partition by `(Group, LastLevelCacheIndex)` equals the GLPI LLC partition
    /// intersected with each group.
    LlcPartition,
    /// Every thread's efficiency class equals its core's.
    EfficiencyClass,
}

impl Check {
    /// Stable name for messages and tests.
    pub fn name(self) -> &'static str {
        match self {
            Self::GroupRecord => "one group record",
            Self::CpuSetIdsUnique => "unique cpu set ids",
            Self::CpuSetsUnique => "unique cpu set (group, index)",
            Self::CpuSetsMatchGroups => "cpu sets match the active groups",
            Self::CoreMembership => "one core per logical processor",
            Self::CorePartition => "core partition",
            Self::LlcMembership => "one last-level cache per logical processor",
            Self::LlcPartition => "last-level cache partition",
            Self::EfficiencyClass => "efficiency class",
        }
    }
}

/// `(group, index)` of a logical processor.
type Lp = (u16, u8);

/// One CPU Set record, raw.
#[derive(Debug, Clone, Copy)]
struct RawCpuSet {
    id: u32,
    group: u16,
    index: u8,
    core_index: u8,
    llc_index: u8,
    efficiency_class: u8,
    flags: u8,
}

/// A core or cache from GLPI: its logical processors (all masks) and its data.
#[derive(Debug, Clone)]
struct Unit {
    lps: Vec<Lp>,
    efficiency_class: u8,
    level: u8,
    size: u32,
}

/// The parsed GLPI buffer.
#[derive(Debug, Default)]
struct Info {
    cores: Vec<Unit>,
    /// Unified and data caches only.
    caches: Vec<Unit>,
    /// Active logical processors, sorted.
    active: Vec<Lp>,
    groups_seen: usize,
}

/// Little-endian reads from a record that is known to be long enough (callers check the
/// record size first); out-of-range reads cannot happen and would yield 0, never panic.
struct Rec<'a>(&'a [u8]);

impl Rec<'_> {
    fn u8(&self, at: usize) -> u8 {
        self.0.get(at).copied().unwrap_or(0)
    }

    fn u16(&self, at: usize) -> u16 {
        u16::from_le_bytes(self.array(at))
    }

    fn u32(&self, at: usize) -> u32 {
        u32::from_le_bytes(self.array(at))
    }

    fn u64(&self, at: usize) -> u64 {
        u64::from_le_bytes(self.array(at))
    }

    fn array<const N: usize>(&self, at: usize) -> [u8; N] {
        let mut out = [0; N];
        if let Some(s) = at.checked_add(N).and_then(|end| self.0.get(at..end)) {
            out.copy_from_slice(s);
        }
        out
    }
}

/// A record: its byte offset in the buffer, its type and its bytes (exactly `Size` long).
type Record<'a> = (usize, u32, &'a [u8]);

/// Splits `buf` into records `(offset, type, bytes)`; the size field is at `size_at`, the type
/// at `type_at`. Checks that every header fits, `Size != 0` and the record fits.
fn records(
    buf: &[u8],
    source: Source,
    type_at: usize,
    size_at: usize,
) -> Result<Vec<Record<'_>>, TopologyError> {
    let mut out = Vec::new();
    let mut offset = 0;
    while offset < buf.len() {
        let rest = &buf[offset..];
        if rest.len() < 8 {
            return Err(TopologyError::Truncated { source, offset });
        }
        let head = Rec(rest);
        let size = usize::try_from(head.u32(size_at)).unwrap_or(usize::MAX);
        if size == 0 {
            return Err(TopologyError::ZeroSize { source, offset });
        }
        let Some(bytes) = rest.get(..size) else {
            return Err(TopologyError::Truncated { source, offset });
        };
        out.push((offset, head.u32(type_at), bytes));
        offset += size;
    }
    Ok(out)
}

fn need(source: Source, offset: usize, rec: &[u8], min: usize) -> Result<(), TopologyError> {
    if rec.len() < min {
        Err(TopologyError::RecordTooSmall {
            source,
            offset,
            size: rec.len(),
            min,
        })
    } else {
        Ok(())
    }
}

fn parse_cpu_sets(buf: &[u8]) -> Result<Vec<RawCpuSet>, TopologyError> {
    let source = Source::CpuSets;
    let mut out = Vec::new();
    for (offset, kind, bytes) in records(buf, source, l::CPU_SET_TYPE, l::CPU_SET_SIZE)? {
        if kind != CPU_SET_INFORMATION {
            continue;
        }
        need(source, offset, bytes, l::CPU_SET_MIN_SIZE)?;
        if out.len() == MAX_LOGICAL_CPUS {
            return Err(TopologyError::TooManyCpus { source });
        }
        let r = Rec(bytes);
        let set = RawCpuSet {
            id: r.u32(l::CPU_SET_ID),
            group: r.u16(l::CPU_SET_GROUP),
            index: r.u8(l::CPU_SET_LOGICAL_PROCESSOR_INDEX),
            core_index: r.u8(l::CPU_SET_CORE_INDEX),
            llc_index: r.u8(l::CPU_SET_LAST_LEVEL_CACHE_INDEX),
            efficiency_class: r.u8(l::CPU_SET_EFFICIENCY_CLASS),
            flags: r.u8(l::CPU_SET_ALL_FLAGS),
        };
        if set.index >= GROUP_SIZE {
            return Err(TopologyError::BadField {
                source,
                offset,
                field: "LogicalProcessorIndex",
            });
        }
        out.push(set);
    }
    Ok(out)
}

/// Reads `count` `GROUP_AFFINITY` masks starting at `at` into logical processors.
fn masks(r: &Rec<'_>, at: usize, count: usize) -> Vec<Lp> {
    let mut lps = Vec::new();
    for k in 0..count {
        let base = at + k * l::GROUP_AFFINITY_SIZE;
        let group = r.u16(base + l::GROUP_AFFINITY_GROUP);
        let mask = r.u64(base + l::GROUP_AFFINITY_MASK);
        lps.extend(bits(mask).map(|i| (group, i)));
    }
    lps
}

fn bits(mask: u64) -> impl Iterator<Item = u8> {
    (0..GROUP_SIZE).filter(move |i| mask & (1 << i) != 0)
}

fn parse_info(buf: &[u8]) -> Result<Info, TopologyError> {
    let source = Source::ProcessorInfo;
    let mut info = Info::default();
    for (offset, kind, bytes) in records(buf, source, l::INFO_RELATIONSHIP, l::INFO_SIZE)? {
        let r = Rec(bytes);
        let bad = |field| TopologyError::BadField {
            source,
            offset,
            field,
        };
        match kind {
            RELATION_PROCESSOR_CORE => {
                need(source, offset, bytes, l::PROCESSOR_GROUP_COUNT + 2)?;
                let count = usize::from(r.u16(l::PROCESSOR_GROUP_COUNT));
                if count == 0 {
                    return Err(bad("Processor.GroupCount"));
                }
                need(
                    source,
                    offset,
                    bytes,
                    l::PROCESSOR_GROUP_MASK + count * l::GROUP_AFFINITY_SIZE,
                )?;
                info.cores.push(Unit {
                    lps: masks(&r, l::PROCESSOR_GROUP_MASK, count),
                    efficiency_class: r.u8(l::PROCESSOR_EFFICIENCY_CLASS),
                    level: 0,
                    size: 0,
                });
            }
            RELATION_CACHE => {
                need(source, offset, bytes, l::CACHE_GROUP_COUNT + 2)?;
                let count = usize::from(r.u16(l::CACHE_GROUP_COUNT)).max(1);
                need(
                    source,
                    offset,
                    bytes,
                    l::CACHE_GROUP_MASK + count * l::GROUP_AFFINITY_SIZE,
                )?;
                let kind = r.u32(l::CACHE_TYPE);
                if kind != CACHE_UNIFIED && kind != CACHE_DATA {
                    continue;
                }
                let level = r.u8(l::CACHE_LEVEL);
                if level == 0 {
                    return Err(bad("Cache.Level"));
                }
                info.caches.push(Unit {
                    lps: masks(&r, l::CACHE_GROUP_MASK, count),
                    efficiency_class: 0,
                    level,
                    size: r.u32(l::CACHE_SIZE),
                });
            }
            RELATION_GROUP => {
                info.groups_seen += 1;
                if info.groups_seen > 1 {
                    return Err(TopologyError::Inconsistent(Check::GroupRecord));
                }
                need(source, offset, bytes, l::GROUP_ACTIVE_GROUP_COUNT + 2)?;
                let count = usize::from(r.u16(l::GROUP_ACTIVE_GROUP_COUNT));
                if count == 0 {
                    return Err(bad("Group.ActiveGroupCount"));
                }
                need(
                    source,
                    offset,
                    bytes,
                    l::GROUP_INFO + count * l::GROUP_INFO_SIZE,
                )?;
                for g in 0..count {
                    let base = l::GROUP_INFO + g * l::GROUP_INFO_SIZE;
                    let mask = r.u64(base + l::GROUP_INFO_ACTIVE_PROCESSOR_MASK);
                    let active = r.u8(base + l::GROUP_INFO_ACTIVE_PROCESSOR_COUNT);
                    if u32::from(active) != mask.count_ones() {
                        return Err(bad("ActiveProcessorCount"));
                    }
                    // `count` came from a u16, so every group number fits.
                    let group = u16::try_from(g).map_err(|_| bad("Group.ActiveGroupCount"))?;
                    if info.active.len() + usize::from(active) > MAX_LOGICAL_CPUS {
                        return Err(TopologyError::TooManyCpus { source });
                    }
                    info.active.extend(bits(mask).map(|i| (group, i)));
                }
            }
            // Die, module, NUMA, package and anything newer: skipped by `Size`.
            _ => {}
        }
    }
    if info.groups_seen == 0 {
        return Err(TopologyError::Inconsistent(Check::GroupRecord));
    }
    Ok(info)
}

/// For every active logical processor (by position in `active`) the unit that contains it.
/// `pick` decides between two units containing the same processor: `Some(true)` = take the
/// new one, `Some(false)` = keep, `None` = ambiguous.
fn assign(
    active: &[Lp],
    units: &[Unit],
    check: Check,
    pick: impl Fn(&Unit, &Unit) -> Option<bool>,
) -> Result<Vec<usize>, TopologyError> {
    let mut of: Vec<Option<usize>> = vec![None; active.len()];
    for (u, unit) in units.iter().enumerate() {
        for lp in &unit.lps {
            // Bits of inactive processors are ignored.
            let Ok(pos) = active.binary_search(lp) else {
                continue;
            };
            of[pos] = match of[pos] {
                None => Some(u),
                Some(old) if old == u => Some(u),
                Some(old) => match pick(&units[old], unit) {
                    Some(true) => Some(u),
                    Some(false) => Some(old),
                    None => return Err(TopologyError::Inconsistent(check)),
                },
            };
        }
    }
    of.into_iter()
        .map(|u| u.ok_or(TopologyError::Inconsistent(check)))
        .collect()
}

/// `true` if `pairs` (key → value) is a function in both directions, i.e. the two
/// partitions they describe are equal.
fn bijective<A: Ord + Copy, B: Ord + Copy>(pairs: impl Iterator<Item = (A, B)>) -> bool {
    let mut fwd = BTreeMap::new();
    let mut back = BTreeMap::new();
    for (a, b) in pairs {
        if *fwd.entry(a).or_insert(b) != b || *back.entry(b).or_insert(a) != a {
            return false;
        }
    }
    true
}

impl CpuTopology {
    /// Parses the bytes of `GetSystemCpuSetInformation(Process = NULL)` and
    /// `GetLogicalProcessorInformationEx(RelationAll)` (64-bit layout, only the returned
    /// length) into a validated topology. See the module documentation for the rules; any
    /// malformed record, failed [`Check`] or violated invariant is an error.
    pub fn from_windows(cpu_sets: &[u8], processor_info: &[u8]) -> Result<Self, TopologyError> {
        let mut sets = parse_cpu_sets(cpu_sets)?;
        let info = parse_info(processor_info)?;
        let inconsistent = |c| Err(TopologyError::Inconsistent(c));

        sets.sort_by_key(|s| (s.group, s.index));
        if sets
            .windows(2)
            .any(|w| (w[0].group, w[0].index) == (w[1].group, w[1].index))
        {
            return inconsistent(Check::CpuSetsUnique);
        }
        let mut ids: Vec<u32> = sets.iter().map(|s| s.id).collect();
        ids.sort_unstable();
        if ids.windows(2).any(|w| w[0] == w[1]) {
            return inconsistent(Check::CpuSetIdsUnique);
        }
        let mut active = info.active;
        active.sort_unstable();
        if !sets
            .iter()
            .map(|s| (s.group, s.index))
            .eq(active.iter().copied())
        {
            return inconsistent(Check::CpuSetsMatchGroups);
        }

        let core_of = assign(&active, &info.cores, Check::CoreMembership, |_, _| None)?;
        let llc_of = assign(
            &active,
            &info.caches,
            Check::LlcMembership,
            |old, new| match new.level.cmp(&old.level) {
                std::cmp::Ordering::Greater => Some(true),
                std::cmp::Ordering::Less => Some(false),
                std::cmp::Ordering::Equal => None,
            },
        )?;

        // `sets` and `active` are the same sorted list, so position `p` is the same processor.
        if !bijective(
            sets.iter()
                .zip(&core_of)
                .map(|(s, &c)| ((s.group, s.core_index), c)),
        ) {
            return inconsistent(Check::CorePartition);
        }
        if !bijective(
            sets.iter()
                .zip(&llc_of)
                .map(|(s, &c)| ((s.group, s.llc_index), (c, s.group))),
        ) {
            return inconsistent(Check::LlcPartition);
        }
        if sets
            .iter()
            .zip(&core_of)
            .any(|(s, &c)| s.efficiency_class != info.cores[c].efficiency_class)
        {
            return inconsistent(Check::EfficiencyClass);
        }

        let mut cores: BTreeMap<usize, u32> = BTreeMap::new();
        let mut llcs: BTreeMap<usize, u32> = BTreeMap::new();
        let mut topology = Self {
            cpus: Vec::new(),
            llcs: Vec::new(),
        };
        for ((s, &c), &cache) in sets.iter().zip(&core_of).zip(&llc_of) {
            if s.flags & (FLAG_REALTIME | FLAG_ALLOCATED) != 0 {
                continue;
            }
            // At most MAX_LOGICAL_CPUS entries, so the counters fit in u32.
            let next = u32::try_from(cores.len()).unwrap_or(u32::MAX);
            let core = *cores.entry(c).or_insert(next);
            let next = u32::try_from(llcs.len()).unwrap_or(u32::MAX);
            let llc = *llcs.entry(cache).or_insert_with(|| {
                let unit = &info.caches[cache];
                topology.llcs.push(Llc {
                    level: unit.level,
                    size: u64::from(unit.size),
                });
                next
            });
            topology.cpus.push(LogicalCpu {
                cpu_set_id: s.id,
                group: s.group,
                index: s.index,
                core,
                llc,
                efficiency_class: info.cores[c].efficiency_class,
            });
        }
        topology.validate()?;
        Ok(topology)
    }
}

#[cfg(test)]
mod tests;
