//! Parser edge cases on synthetic byte records (ADR 0010; the byte-builder exception of
//! `docs/09-testing.md`). [`Machine::new`] encodes a shape the way Windows 11 does: CPU Set IDs
//! `0x100 + n`, group-relative `CoreIndex`/`LastLevelCacheIndex` (first logical processor of
//! the core or cache in that group), per core a `RelationProcessorCore` with its L1 data and
//! instruction caches, one `RelationCache` per last-level cache with one mask per group, and one
//! `RelationGroup` at the end.

use super::super::{Invariant, MAX_LOGICAL_CPUS};
use super::*;

/// A logical processor of a synthetic shape: `core` and `llc` are keys of the builder.
#[derive(Debug, Clone, Copy)]
struct P {
    group: u16,
    index: u8,
    core: usize,
    llc: usize,
    eff: u8,
}

fn p(group: u16, index: u8, core: usize, llc: usize) -> P {
    P {
        group,
        index,
        core,
        llc,
        eff: 0,
    }
}

fn put16(r: &mut [u8], at: usize, v: u16) {
    r[at..at + 2].copy_from_slice(&v.to_le_bytes());
}

fn put32(r: &mut [u8], at: usize, v: u32) {
    r[at..at + 4].copy_from_slice(&v.to_le_bytes());
}

fn put64(r: &mut [u8], at: usize, v: u64) {
    r[at..at + 8].copy_from_slice(&v.to_le_bytes());
}

fn size_of(len: usize) -> u32 {
    u32::try_from(len).unwrap()
}

fn cpu_set_rec(id: u32, group: u16, index: u8, core: u8, llc: u8, eff: u8, flags: u8) -> Vec<u8> {
    let mut r = vec![0; l::CPU_SET_STRUCT_SIZE];
    put32(&mut r, l::CPU_SET_SIZE, size_of(l::CPU_SET_STRUCT_SIZE));
    put32(&mut r, l::CPU_SET_TYPE, CPU_SET_INFORMATION);
    put32(&mut r, l::CPU_SET_ID, id);
    put16(&mut r, l::CPU_SET_GROUP, group);
    r[l::CPU_SET_LOGICAL_PROCESSOR_INDEX] = index;
    r[l::CPU_SET_CORE_INDEX] = core;
    r[l::CPU_SET_LAST_LEVEL_CACHE_INDEX] = llc;
    r[l::CPU_SET_EFFICIENCY_CLASS] = eff;
    r[l::CPU_SET_ALL_FLAGS] = flags;
    // SchedulingClass and AllocationTag: noise the parser must ignore.
    r[20] = 0x0c;
    put64(&mut r, 24, 0xDEAD_BEEF);
    r
}

fn info_rec(relationship: u32, len: usize) -> Vec<u8> {
    let mut r = vec![0; len];
    put32(&mut r, l::INFO_RELATIONSHIP, relationship);
    put32(&mut r, l::INFO_SIZE, size_of(len));
    r
}

fn put_masks(r: &mut [u8], at: usize, masks: &[(u16, u64)]) {
    for (k, &(group, mask)) in masks.iter().enumerate() {
        let base = at + k * l::GROUP_AFFINITY_SIZE;
        put64(r, base + l::GROUP_AFFINITY_MASK, mask);
        put16(r, base + l::GROUP_AFFINITY_GROUP, group);
    }
}

fn core_rec(eff: u8, masks: &[(u16, u64)]) -> Vec<u8> {
    let mut r = info_rec(
        RELATION_PROCESSOR_CORE,
        l::PROCESSOR_GROUP_MASK + masks.len() * l::GROUP_AFFINITY_SIZE,
    );
    let threads: u32 = masks.iter().map(|m| m.1.count_ones()).sum();
    r[l::INFO_BODY] = u8::from(threads > 1); // LTP_PC_SMT
    r[l::PROCESSOR_EFFICIENCY_CLASS] = eff;
    put16(
        &mut r,
        l::PROCESSOR_GROUP_COUNT,
        u16::try_from(masks.len()).unwrap(),
    );
    put_masks(&mut r, l::PROCESSOR_GROUP_MASK, masks);
    r
}

fn cache_rec(level: u8, kind: u32, size: u32, group_count: u16, masks: &[(u16, u64)]) -> Vec<u8> {
    let slots = masks.len().max(1);
    let mut r = info_rec(
        RELATION_CACHE,
        l::CACHE_GROUP_MASK + slots * l::GROUP_AFFINITY_SIZE,
    );
    r[l::CACHE_LEVEL] = level;
    r[l::CACHE_LEVEL + 1] = 8; // Associativity
    put16(&mut r, l::CACHE_LEVEL + 2, 64); // LineSize
    put32(&mut r, l::CACHE_SIZE, size);
    put32(&mut r, l::CACHE_TYPE, kind);
    put16(&mut r, l::CACHE_GROUP_COUNT, group_count);
    put_masks(&mut r, l::CACHE_GROUP_MASK, masks);
    r
}

fn group_rec(masks: &[u64]) -> Vec<u8> {
    let mut r = info_rec(
        RELATION_GROUP,
        l::GROUP_INFO + masks.len() * l::GROUP_INFO_SIZE,
    );
    let n = u16::try_from(masks.len()).unwrap();
    put16(&mut r, l::INFO_BODY, n); // MaximumGroupCount
    put16(&mut r, l::GROUP_ACTIVE_GROUP_COUNT, n);
    for (g, &mask) in masks.iter().enumerate() {
        let base = l::GROUP_INFO + g * l::GROUP_INFO_SIZE;
        let count = u8::try_from(mask.count_ones()).unwrap();
        r[base] = count; // MaximumProcessorCount
        r[base + l::GROUP_INFO_ACTIVE_PROCESSOR_COUNT] = count;
        put64(&mut r, base + l::GROUP_INFO_ACTIVE_PROCESSOR_MASK, mask);
    }
    r
}

/// Masks per group of the processors selected by `f`, in group order.
fn masks_of(lps: &[P], f: impl Fn(&P) -> bool) -> Vec<(u16, u64)> {
    let mut by_group: BTreeMap<u16, u64> = BTreeMap::new();
    for q in lps.iter().filter(|q| f(q)) {
        *by_group.entry(q.group).or_default() |= 1 << q.index;
    }
    by_group.into_iter().collect()
}

/// Both buffers as lists of records, so tests can corrupt single records.
#[derive(Debug, Clone)]
struct Machine {
    sets: Vec<Vec<u8>>,
    info: Vec<Vec<u8>>,
}

impl Machine {
    /// `lps` sorted by `(group, index)`; `llcs[k]` = (level, size) of LLC key `k`.
    fn new(lps: &[P], llcs: &[(u8, u32)]) -> Self {
        let first = |g: u16, f: &dyn Fn(&P) -> bool| {
            lps.iter()
                .filter(|q| q.group == g && f(q))
                .map(|q| q.index)
                .min()
                .unwrap()
        };
        let sets = lps
            .iter()
            .enumerate()
            .map(|(n, q)| {
                cpu_set_rec(
                    0x100 + u32::try_from(n).unwrap(),
                    q.group,
                    q.index,
                    first(q.group, &|o| o.core == q.core),
                    first(q.group, &|o| o.llc == q.llc),
                    q.eff,
                    0,
                )
            })
            .collect();
        let mut info = Vec::new();
        let mut cores: Vec<usize> = lps.iter().map(|q| q.core).collect();
        cores.dedup();
        for c in cores {
            let masks = masks_of(lps, |q| q.core == c);
            let eff = lps.iter().find(|q| q.core == c).unwrap().eff;
            info.push(core_rec(eff, &masks));
            info.push(cache_rec(1, CACHE_DATA, 48 << 10, 1, &masks));
            info.push(cache_rec(1, 1, 32 << 10, 1, &masks)); // CacheInstruction
        }
        for (k, &(level, size)) in llcs.iter().enumerate() {
            let masks = masks_of(lps, |q| q.llc == k);
            let n = u16::try_from(masks.len()).unwrap();
            info.push(cache_rec(level, CACHE_UNIFIED, size, n, &masks));
        }
        let groups = masks_of(lps, |_| true);
        let mut active = vec![0; usize::from(groups.last().unwrap().0) + 1];
        for (g, m) in groups {
            active[usize::from(g)] = m;
        }
        info.push(group_rec(&active));
        Self { sets, info }
    }

    fn sets(&self) -> Vec<u8> {
        self.sets.concat()
    }

    fn info(&self) -> Vec<u8> {
        self.info.concat()
    }

    fn parse(&self) -> Result<CpuTopology, TopologyError> {
        CpuTopology::from_windows(&self.sets(), &self.info())
    }

    /// Index of the first GLPI record with this relationship.
    fn find(&self, relationship: u32) -> usize {
        self.info
            .iter()
            .position(|r| Rec(r).u32(l::INFO_RELATIONSHIP) == relationship)
            .unwrap()
    }

    /// Index of the GLPI record of the last-level cache with key `k` (after all cores).
    fn llc(&self, k: usize) -> usize {
        let caches: Vec<usize> = (0..self.info.len())
            .filter(|&i| {
                Rec(&self.info[i]).u32(l::INFO_RELATIONSHIP) == RELATION_CACHE
                    && Rec(&self.info[i]).u8(l::CACHE_LEVEL) > 1
            })
            .collect();
        caches[k]
    }
}

/// `(cpu_set_id, group, index, core, llc, efficiency_class)` of every processor.
fn rows(t: &CpuTopology) -> Vec<(u32, u16, u8, u32, u32, u8)> {
    t.cpus
        .iter()
        .map(|c| {
            (
                c.cpu_set_id,
                c.group,
                c.index,
                c.core,
                c.llc,
                c.efficiency_class,
            )
        })
        .collect()
}

const L3: u32 = 32 << 20;

/// 2 LLCs × 2 cores × 2 threads in group 0 (a small 5950X).
fn smt() -> Machine {
    let lps: Vec<P> = (0..8u8)
        .map(|i| p(0, i, usize::from(i / 2), usize::from(i / 4)))
        .collect();
    Machine::new(&lps, &[(3, L3), (3, L3)])
}

fn inconsistent(m: &Machine) -> Check {
    match m.parse() {
        Err(TopologyError::Inconsistent(c)) => c,
        other => panic!("expected an inconsistency, got {other:?}"),
    }
}

// ---------- Shapes ----------

#[test]
fn smt_siblings_share_a_dense_core() {
    let t = smt().parse().unwrap();
    assert_eq!(
        rows(&t),
        [
            (0x100, 0, 0, 0, 0, 0),
            (0x101, 0, 1, 0, 0, 0),
            (0x102, 0, 2, 1, 0, 0),
            (0x103, 0, 3, 1, 0, 0),
            (0x104, 0, 4, 2, 1, 0),
            (0x105, 0, 5, 2, 1, 0),
            (0x106, 0, 6, 3, 1, 0),
            (0x107, 0, 7, 3, 1, 0),
        ]
    );
    let l3 = Llc {
        level: 3,
        size: u64::from(L3),
    };
    assert_eq!(t.llcs, [l3, l3]);
    assert_eq!((t.core_count(), t.llc_count()), (4, 2));
    assert!(t.has_smt() && !t.is_hybrid());
}

#[test]
fn without_smt_every_thread_is_a_core() {
    let lps: Vec<P> = (0..4u8).map(|i| p(0, i, usize::from(i), 0)).collect();
    let t = Machine::new(&lps, &[(3, 6 << 20)]).parse().unwrap();
    assert_eq!(
        rows(&t),
        [
            (0x100, 0, 0, 0, 0, 0),
            (0x101, 0, 1, 1, 0, 0),
            (0x102, 0, 2, 2, 0, 0),
            (0x103, 0, 3, 3, 0, 0),
        ]
    );
    assert_eq!(
        t.llcs,
        [Llc {
            level: 3,
            size: 6 << 20
        }]
    );
    assert!(!t.has_smt());
}

#[test]
fn hybrid_with_lp_e_cores_on_their_own_l2() {
    // Core Ultra 7 155H-like: 2 P-cores with SMT (class 2), 4 E-cores (class 1) on the L3,
    // 2 LP E-cores (class 0) whose last level is their L2.
    let mut lps = Vec::new();
    for i in 0..4u8 {
        lps.push(P {
            eff: 2,
            ..p(0, i, usize::from(i / 2), 0)
        });
    }
    for i in 4..8u8 {
        lps.push(P {
            eff: 1,
            ..p(0, i, usize::from(i), 0)
        });
    }
    for i in 8..10u8 {
        lps.push(P {
            eff: 0,
            ..p(0, i, usize::from(i), 1)
        });
    }
    let m = Machine::new(&lps, &[(3, 24 << 20), (2, 2 << 20)]);
    let t = m.parse().unwrap();
    assert_eq!(
        t.llcs,
        [
            Llc {
                level: 3,
                size: 24 << 20
            },
            Llc {
                level: 2,
                size: 2 << 20
            }
        ]
    );
    assert_eq!(
        rows(&t)[..],
        [
            (0x100, 0, 0, 0, 0, 2),
            (0x101, 0, 1, 0, 0, 2),
            (0x102, 0, 2, 1, 0, 2),
            (0x103, 0, 3, 1, 0, 2),
            (0x104, 0, 4, 2, 0, 1),
            (0x105, 0, 5, 3, 0, 1),
            (0x106, 0, 6, 4, 0, 1),
            (0x107, 0, 7, 5, 0, 1),
            (0x108, 0, 8, 6, 1, 0),
            (0x109, 0, 9, 7, 1, 0),
        ]
    );
    assert!(t.is_hybrid());
}

#[test]
fn an_l2_below_the_l3_is_not_the_last_level() {
    // E-core module: 4 cores share an L2 (level 2), the L3 above it is the last level.
    let lps: Vec<P> = (0..4u8).map(|i| p(0, i, usize::from(i), 0)).collect();
    let mut m = Machine::new(&lps, &[(3, 8 << 20)]);
    let at = m.find(RELATION_GROUP);
    m.info
        .insert(at, cache_rec(2, CACHE_UNIFIED, 2 << 20, 1, &[(0, 0xF)]));
    let t = m.parse().unwrap();
    assert_eq!(
        t.llcs,
        [Llc {
            level: 3,
            size: 8 << 20
        }]
    );
}

#[test]
fn several_groups_restart_the_index_and_keep_numbering_dense() {
    let mut lps = Vec::new();
    for g in 0..2u16 {
        for i in 0..4u8 {
            lps.push(p(
                g,
                i,
                usize::from(g) * 2 + usize::from(i / 2),
                usize::from(g),
            ));
        }
    }
    let t = Machine::new(&lps, &[(3, L3), (3, L3)]).parse().unwrap();
    assert_eq!(
        rows(&t),
        [
            (0x100, 0, 0, 0, 0, 0),
            (0x101, 0, 1, 0, 0, 0),
            (0x102, 0, 2, 1, 0, 0),
            (0x103, 0, 3, 1, 0, 0),
            (0x104, 1, 0, 2, 1, 0),
            (0x105, 1, 1, 2, 1, 0),
            (0x106, 1, 2, 3, 1, 0),
            (0x107, 1, 3, 3, 1, 0),
        ]
    );
}

#[test]
fn an_llc_across_two_groups_is_one_llc() {
    // A large single-L3 part split into two groups: raw LastLevelCacheIndex is 0 in both
    // groups, the GLPI record carries two group masks.
    let mut lps = Vec::new();
    for g in 0..2u16 {
        for i in 0..2u8 {
            lps.push(p(g, i, usize::from(g) * 2 + usize::from(i), 0));
        }
    }
    let m = Machine::new(&lps, &[(3, 96 << 20)]);
    assert_eq!(Rec(&m.info[m.llc(0)]).u16(l::CACHE_GROUP_COUNT), 2);
    let t = m.parse().unwrap();
    assert_eq!(
        t.llcs,
        [Llc {
            level: 3,
            size: 96 << 20
        }]
    );
    assert!(t.cpus.iter().all(|c| c.llc == 0));
    assert_eq!(t.core_count(), 4);
}

#[test]
fn cache_group_count_zero_counts_as_one() {
    // Before Windows 11 the field is reserved and 0; the single mask is still there.
    let mut m = smt();
    for k in 0..2 {
        let at = m.llc(k);
        put16(&mut m.info[at], l::CACHE_GROUP_COUNT, 0);
    }
    assert_eq!(m.parse().unwrap(), smt().parse().unwrap());
}

#[test]
fn unknown_relationships_and_cpu_set_types_are_skipped_by_size() {
    let mut m = smt();
    // Package (3), die (5), module (7), NUMA (1) and something new of an odd size.
    for (rel, len) in [(3, 48), (5, 48), (7, 48), (1, 48), (99, 12)] {
        let mut r = info_rec(rel, len);
        // Garbage in the body must not matter.
        r[8..].fill(0xFF);
        m.info.insert(0, r);
    }
    let mut odd = vec![0xAB; 12];
    put32(&mut odd, l::CPU_SET_SIZE, 12);
    put32(&mut odd, l::CPU_SET_TYPE, 1);
    m.sets.insert(3, odd);
    assert_eq!(m.parse().unwrap(), smt().parse().unwrap());
}

#[test]
fn record_order_does_not_matter() {
    let mut m = smt();
    m.sets.reverse();
    m.info.reverse();
    assert_eq!(m.parse().unwrap(), smt().parse().unwrap());
}

#[test]
fn parked_scheduling_class_and_allocation_tag_are_ignored() {
    let mut m = smt();
    for (n, r) in m.sets.iter_mut().enumerate() {
        r[l::CPU_SET_ALL_FLAGS] = 0x1 | 0x4; // Parked, AllocatedToTargetProcess
        r[20] = u8::try_from(n).unwrap();
        put64(r, 24, u64::try_from(n).unwrap());
    }
    assert_eq!(m.parse().unwrap(), smt().parse().unwrap());
}

// ---------- Flags ----------

#[test]
fn realtime_and_allocated_cpu_sets_are_dropped_and_numbering_restarts() {
    let mut m = smt();
    // The whole first core and the first thread of the third.
    m.sets[0][l::CPU_SET_ALL_FLAGS] = FLAG_REALTIME;
    m.sets[1][l::CPU_SET_ALL_FLAGS] = FLAG_ALLOCATED;
    m.sets[4][l::CPU_SET_ALL_FLAGS] = FLAG_ALLOCATED | 0x1;
    let t = m.parse().unwrap();
    assert_eq!(
        rows(&t),
        [
            (0x102, 0, 2, 0, 0, 0),
            (0x103, 0, 3, 0, 0, 0),
            (0x105, 0, 5, 1, 1, 0),
            (0x106, 0, 6, 2, 1, 0),
            (0x107, 0, 7, 2, 1, 0),
        ]
    );
}

#[test]
fn a_dropped_llc_leaves_no_entry() {
    let mut m = smt();
    for r in &mut m.sets[..4] {
        r[l::CPU_SET_ALL_FLAGS] = FLAG_REALTIME;
    }
    let t = m.parse().unwrap();
    assert_eq!(t.llcs.len(), 1);
    assert!(t.cpus.iter().all(|c| c.llc == 0 && c.core < 2));
}

#[test]
fn all_dropped_is_empty() {
    let mut m = smt();
    for r in &mut m.sets {
        r[l::CPU_SET_ALL_FLAGS] = FLAG_ALLOCATED;
    }
    assert_eq!(m.parse(), Err(TopologyError::Invalid(Invariant::Empty)));
}

// ---------- Malformed buffers ----------

#[test]
fn truncated_headers_and_bodies_are_errors() {
    let m = smt();
    let (sets, info) = (m.sets(), m.info());
    for cut in [1, 7, 31, 33, 100] {
        assert!(
            matches!(
                CpuTopology::from_windows(&sets[..cut], &info),
                Err(TopologyError::Truncated {
                    source: Source::CpuSets,
                    ..
                })
            ),
            "cpu sets cut at {cut}"
        );
    }
    for cut in [1, 7, 47, 50, info.len() - 1] {
        assert!(
            matches!(
                CpuTopology::from_windows(&sets, &info[..cut]),
                Err(TopologyError::Truncated {
                    source: Source::ProcessorInfo,
                    ..
                })
            ),
            "processor info cut at {cut}"
        );
    }
}

#[test]
fn a_size_beyond_the_buffer_is_truncated() {
    let mut m = smt();
    let last = m.sets.len() - 1;
    put32(&mut m.sets[last], l::CPU_SET_SIZE, 33);
    assert_eq!(
        m.parse(),
        Err(TopologyError::Truncated {
            source: Source::CpuSets,
            offset: 7 * 32
        })
    );
    let mut m = smt();
    let at = m.find(RELATION_GROUP);
    put32(&mut m.info[at], l::INFO_SIZE, u32::MAX);
    assert!(matches!(
        m.parse(),
        Err(TopologyError::Truncated {
            source: Source::ProcessorInfo,
            ..
        })
    ));
}

#[test]
fn size_zero_is_an_error() {
    let mut m = smt();
    put32(&mut m.sets[2], l::CPU_SET_SIZE, 0);
    assert_eq!(
        m.parse(),
        Err(TopologyError::ZeroSize {
            source: Source::CpuSets,
            offset: 64
        })
    );
    let mut m = smt();
    put32(&mut m.info[0], l::INFO_SIZE, 0);
    assert_eq!(
        m.parse(),
        Err(TopologyError::ZeroSize {
            source: Source::ProcessorInfo,
            offset: 0
        })
    );
}

#[test]
fn records_too_small_for_their_type_are_errors() {
    let small = |m: &Machine| matches!(m.parse(), Err(TopologyError::RecordTooSmall { .. }));
    // CPU Set shorter than the fields read.
    let mut m = smt();
    m.sets[0].truncate(l::CPU_SET_MIN_SIZE - 1);
    put32(
        &mut m.sets[0],
        l::CPU_SET_SIZE,
        size_of(l::CPU_SET_MIN_SIZE - 1),
    );
    assert!(small(&m));
    // Exactly the minimum is enough.
    let mut m = smt();
    for r in &mut m.sets {
        r.truncate(l::CPU_SET_MIN_SIZE);
        put32(r, l::CPU_SET_SIZE, size_of(l::CPU_SET_MIN_SIZE));
    }
    assert_eq!(m.parse().unwrap(), smt().parse().unwrap());
    // Core without room for its GroupCount, and with GroupCount 2 but one mask.
    for (rel, count_at, len) in [
        (RELATION_PROCESSOR_CORE, l::PROCESSOR_GROUP_COUNT, 30),
        (RELATION_CACHE, l::CACHE_GROUP_COUNT, 38),
        (RELATION_GROUP, l::GROUP_ACTIVE_GROUP_COUNT, 10),
    ] {
        let mut m = smt();
        let at = m.find(rel);
        m.info[at].truncate(len);
        put32(&mut m.info[at], l::INFO_SIZE, size_of(len));
        assert!(small(&m), "relationship {rel} of {len} bytes");
        let mut m = smt();
        let at = m.find(rel);
        put16(&mut m.info[at], count_at, 2);
        assert!(small(&m), "relationship {rel} with a count of 2");
    }
}

#[test]
fn more_than_4096_cpu_sets_is_too_many() {
    let one = cpu_set_rec(1, 0, 0, 0, 0, 0, 0);
    let sets = one.repeat(MAX_LOGICAL_CPUS + 1);
    assert_eq!(
        CpuTopology::from_windows(&sets, &smt().info()),
        Err(TopologyError::TooManyCpus {
            source: Source::CpuSets
        })
    );
}

#[test]
fn more_than_4096_active_processors_is_too_many() {
    let mut m = smt();
    let at = m.find(RELATION_GROUP);
    m.info[at] = group_rec(&[u64::MAX; MAX_LOGICAL_CPUS / 64 + 1]);
    assert_eq!(
        m.parse(),
        Err(TopologyError::TooManyCpus {
            source: Source::ProcessorInfo
        })
    );
}

#[test]
fn exactly_4096_processors_parse() {
    let lps: Vec<P> = (0..u16::try_from(MAX_LOGICAL_CPUS / 64).unwrap())
        .flat_map(|g| {
            (0..64u8).map(move |i| {
                p(
                    g,
                    i,
                    usize::from(g) * 32 + usize::from(i / 2),
                    usize::from(g),
                )
            })
        })
        .collect();
    let llcs = vec![(3, L3); MAX_LOGICAL_CPUS / 64];
    let t = Machine::new(&lps, &llcs).parse().unwrap();
    assert_eq!(t.logical_count(), MAX_LOGICAL_CPUS);
    assert_eq!(t.llc_count(), 64);
}

#[test]
fn empty_buffers_are_errors() {
    let m = smt();
    assert_eq!(
        CpuTopology::from_windows(&m.sets(), &[]),
        Err(TopologyError::Inconsistent(Check::GroupRecord))
    );
    assert_eq!(
        CpuTopology::from_windows(&[], &m.info()),
        Err(TopologyError::Inconsistent(Check::CpuSetsMatchGroups))
    );
}

// ---------- Bad fields ----------

fn bad_field(m: &Machine) -> &'static str {
    match m.parse() {
        Err(TopologyError::BadField { field, .. }) => field,
        other => panic!("expected a bad field, got {other:?}"),
    }
}

#[test]
fn fields_windows_never_reports_are_errors() {
    let mut m = smt();
    m.sets[0][l::CPU_SET_LOGICAL_PROCESSOR_INDEX] = 64;
    assert_eq!(bad_field(&m), "LogicalProcessorIndex");

    let mut m = smt();
    let at = m.find(RELATION_PROCESSOR_CORE);
    put16(&mut m.info[at], l::PROCESSOR_GROUP_COUNT, 0);
    assert_eq!(bad_field(&m), "Processor.GroupCount");

    let mut m = smt();
    let at = m.llc(0);
    m.info[at][l::CACHE_LEVEL] = 0;
    assert_eq!(bad_field(&m), "Cache.Level");

    let mut m = smt();
    let at = m.find(RELATION_GROUP);
    put16(&mut m.info[at], l::GROUP_ACTIVE_GROUP_COUNT, 0);
    assert_eq!(bad_field(&m), "Group.ActiveGroupCount");

    let mut m = smt();
    let at = m.find(RELATION_GROUP);
    m.info[at][l::GROUP_INFO + l::GROUP_INFO_ACTIVE_PROCESSOR_COUNT] = 7;
    assert_eq!(bad_field(&m), "ActiveProcessorCount");
}

// ---------- Consistency ----------

#[test]
fn group_record_missing_or_twice() {
    let mut m = smt();
    let at = m.find(RELATION_GROUP);
    let group = m.info.remove(at);
    assert_eq!(inconsistent(&m), Check::GroupRecord);
    m.info.push(group.clone());
    m.info.push(group);
    assert_eq!(inconsistent(&m), Check::GroupRecord);
}

#[test]
fn duplicate_cpu_set_ids() {
    let mut m = smt();
    put32(&mut m.sets[5], l::CPU_SET_ID, 0x100);
    assert_eq!(inconsistent(&m), Check::CpuSetIdsUnique);
}

#[test]
fn duplicate_cpu_set_processor() {
    let mut m = smt();
    let copy = m.sets[0].clone();
    m.sets.push(copy);
    put32(m.sets.last_mut().unwrap(), l::CPU_SET_ID, 0x200);
    assert_eq!(inconsistent(&m), Check::CpuSetsUnique);
}

#[test]
fn cpu_sets_and_groups_differ() {
    // A CPU Set for a processor the group mask does not have.
    let mut m = smt();
    m.sets.push(cpu_set_rec(0x200, 0, 8, 8, 4, 0, 0));
    assert_eq!(inconsistent(&m), Check::CpuSetsMatchGroups);
    // An active processor without a CPU Set.
    let mut m = smt();
    m.sets.pop();
    assert_eq!(inconsistent(&m), Check::CpuSetsMatchGroups);
    // Same count, other group.
    let mut m = smt();
    put16(&mut m.sets[7], l::CPU_SET_GROUP, 1);
    assert_eq!(inconsistent(&m), Check::CpuSetsMatchGroups);
}

#[test]
fn a_processor_in_two_cores_or_none() {
    let mut m = smt();
    let at = m.find(RELATION_PROCESSOR_CORE);
    m.info.insert(at, core_rec(0, &[(0, 0b10)]));
    assert_eq!(inconsistent(&m), Check::CoreMembership);
    let mut m = smt();
    let at = m.find(RELATION_PROCESSOR_CORE);
    m.info.remove(at);
    assert_eq!(inconsistent(&m), Check::CoreMembership);
}

#[test]
fn core_masks_of_inactive_processors_are_ignored() {
    let mut m = smt();
    let at = m.find(RELATION_PROCESSOR_CORE);
    put64(
        &mut m.info[at],
        l::PROCESSOR_GROUP_MASK + l::GROUP_AFFINITY_MASK,
        0b11 | 1 << 40,
    );
    assert_eq!(m.parse().unwrap(), smt().parse().unwrap());
}

#[test]
fn core_index_disagrees_with_the_core_records() {
    // Thread 1 claims to be its own core.
    let mut m = smt();
    m.sets[1][l::CPU_SET_CORE_INDEX] = 1;
    assert_eq!(inconsistent(&m), Check::CorePartition);
    // Two cores claim the same CoreIndex.
    let mut m = smt();
    m.sets[2][l::CPU_SET_CORE_INDEX] = 0;
    m.sets[3][l::CPU_SET_CORE_INDEX] = 0;
    assert_eq!(inconsistent(&m), Check::CorePartition);
}

#[test]
fn a_processor_without_or_with_two_last_level_caches() {
    let mut m = smt();
    let at = m.llc(1);
    m.info.remove(at);
    // Processors 4..8 now end at their per-core L1 data caches: two caches where the CPU
    // Sets report one LastLevelCacheIndex.
    assert_eq!(inconsistent(&m), Check::LlcPartition);
    // Remove every cache: no LLC at all.
    let mut m = smt();
    m.info
        .retain(|r| Rec(r).u32(l::INFO_RELATIONSHIP) != RELATION_CACHE);
    assert_eq!(inconsistent(&m), Check::LlcMembership);
    // Two L3 records covering the same processor.
    let mut m = smt();
    let at = m.llc(0);
    m.info
        .insert(at, cache_rec(3, CACHE_UNIFIED, L3, 1, &[(0, 0b1)]));
    assert_eq!(inconsistent(&m), Check::LlcMembership);
}

#[test]
fn instruction_and_trace_caches_are_never_the_llc() {
    let mut m = smt();
    let at = m.find(RELATION_GROUP);
    m.info.insert(at, cache_rec(4, 1, 1 << 20, 1, &[(0, 0xFF)]));
    m.info.insert(at, cache_rec(4, 3, 1 << 20, 1, &[(0, 0xFF)]));
    assert_eq!(m.parse().unwrap(), smt().parse().unwrap());
}

#[test]
fn llc_index_disagrees_with_the_cache_records() {
    // Processor 3 claims the second LLC.
    let mut m = smt();
    m.sets[3][l::CPU_SET_LAST_LEVEL_CACHE_INDEX] = 4;
    assert_eq!(inconsistent(&m), Check::LlcPartition);
    // Both LLCs claim index 0.
    let mut m = smt();
    for r in &mut m.sets {
        r[l::CPU_SET_LAST_LEVEL_CACHE_INDEX] = 0;
    }
    assert_eq!(inconsistent(&m), Check::LlcPartition);
}

#[test]
fn efficiency_class_disagrees_with_the_core() {
    let mut m = smt();
    m.sets[1][l::CPU_SET_EFFICIENCY_CLASS] = 1;
    assert_eq!(inconsistent(&m), Check::EfficiencyClass);
}

#[test]
fn smt_siblings_in_two_llcs_are_invalid() {
    // Consistent between the sources, but physically impossible.
    let mut lps: Vec<P> = (0..4u8).map(|i| p(0, i, usize::from(i / 2), 0)).collect();
    lps[1].llc = 1;
    let m = Machine::new(&lps, &[(3, L3), (3, L3)]);
    assert_eq!(m.parse(), Err(TopologyError::Invalid(Invariant::CoreSplit)));
}

#[test]
fn a_cache_size_of_zero_is_invalid() {
    let mut m = smt();
    let at = m.llc(1);
    put32(&mut m.info[at], l::CACHE_SIZE, 0);
    assert_eq!(m.parse(), Err(TopologyError::Invalid(Invariant::LlcSize)));
}

#[test]
fn errors_name_their_check() {
    assert_eq!(
        TopologyError::Inconsistent(Check::CorePartition).to_string(),
        "inconsistent topology: check core partition failed"
    );
    assert_eq!(
        TopologyError::RecordTooSmall {
            source: Source::ProcessorInfo,
            offset: 48,
            size: 30,
            min: 32
        }
        .to_string(),
        "processor information: record at offset 48 has size 30, needs 32"
    );
}

// ---------- Robustness ----------

/// xorshift64*, so the loop is the same on every machine.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: usize) -> usize {
        usize::try_from(self.next() % u64::try_from(n).unwrap()).unwrap()
    }

    fn byte(&mut self) -> u8 {
        self.next().to_le_bytes()[0]
    }
}

#[test]
fn mutated_buffers_never_panic() {
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    let base = smt();
    let (sets, info) = (base.sets(), base.info());
    let mut parsed = 0;
    for _ in 0..20_000 {
        let (mut s, mut i) = (sets.clone(), info.clone());
        for _ in 0..=rng.below(4) {
            let buf = if rng.below(2) == 0 { &mut s } else { &mut i };
            match rng.below(4) {
                0 => {
                    let at = rng.below(buf.len());
                    buf[at] = rng.byte();
                }
                1 => {
                    // Small values in size and count fields are the interesting ones.
                    let at = rng.below(buf.len());
                    buf[at] = u8::try_from(rng.below(4)).unwrap();
                }
                2 => {
                    let at = rng.below(buf.len() + 1);
                    buf.truncate(at);
                }
                _ => {
                    let at = rng.below(buf.len() + 1);
                    buf.insert(at, rng.byte());
                }
            }
            if buf.is_empty() {
                break;
            }
        }
        if let Ok(t) = CpuTopology::from_windows(&s, &i) {
            assert_eq!(t.validate(), Ok(()));
            parsed += 1;
        }
    }
    // Some mutations hit only ignored bytes; the loop must exercise both outcomes.
    assert!(parsed > 0 && parsed < 20_000, "parsed {parsed}");
}

#[test]
fn random_bytes_never_panic() {
    let mut rng = Rng(0x2545_F491_4F6C_DD1D);
    for _ in 0..20_000 {
        let a: Vec<u8> = (0..rng.below(300)).map(|_| rng.byte()).collect();
        let b: Vec<u8> = (0..rng.below(300)).map(|_| rng.byte()).collect();
        let _ = CpuTopology::from_windows(&a, &b);
    }
}
