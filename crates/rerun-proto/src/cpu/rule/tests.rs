#![allow(
    clippy::unwrap_used,
    reason = "test code: a failure should abort the test"
)]

use std::collections::{BTreeMap, BTreeSet};

use super::*;
use crate::cpu::{Invariant, Llc};

const MIB: u64 = 1 << 20;

/// Builds valid topologies block by block: each block is one LLC in one group.
#[derive(Default)]
struct Builder {
    cpus: Vec<LogicalCpu>,
    llcs: Vec<Llc>,
    next_index: BTreeMap<u16, u8>,
    core: u32,
}

impl Builder {
    /// Adds an LLC in `group` with `cores` cores of `smt` threads each.
    fn llc(mut self, group: u16, level: u8, size: u64, class: u8, cores: u32, smt: u8) -> Self {
        let llc = u32::try_from(self.llcs.len()).unwrap();
        self.llcs.push(Llc { level, size });
        for _ in 0..cores {
            for _ in 0..smt {
                let index = self.next_index.entry(group).or_default();
                let id = 0x100 + u32::try_from(self.cpus.len()).unwrap();
                self.cpus.push(LogicalCpu {
                    cpu_set_id: id,
                    group,
                    index: *index,
                    core: self.core,
                    llc,
                    efficiency_class: class,
                });
                *index += 1;
            }
            self.core += 1;
        }
        self
    }

    fn build(self) -> CpuTopology {
        let t = CpuTopology {
            cpus: self.cpus,
            llcs: self.llcs,
        };
        t.validate().unwrap();
        t
    }
}

fn rule() -> CpuRule {
    CpuRule {
        max_threads: None,
        prefer: Prefer::Any,
        single_l3: false,
        prefer_l3: None,
        smt: true,
        mode: Mode::Hard,
    }
}

fn r5950x() -> CpuTopology {
    Builder::default()
        .llc(0, 3, 32 * MIB, 0, 8, 2)
        .llc(0, 3, 32 * MIB, 0, 8, 2)
        .build()
}

/// Lunar Lake (Core Ultra 200V): 4 P-cores on an L3, 4 LP E-cores with their own L2.
fn lunar_lake() -> CpuTopology {
    Builder::default()
        .llc(0, 3, 12 * MIB, 1, 4, 1)
        .llc(0, 2, 4 * MIB, 0, 4, 1)
        .build()
}

fn mask(indices: impl IntoIterator<Item = u8>) -> u64 {
    indices.into_iter().fold(0, |m, i| m | (1 << i))
}

fn sel(t: &CpuTopology, r: &CpuRule, b: Bitness) -> Selection {
    select(t, r, b).unwrap()
}

#[test]
fn the_5950x_single_l3_max_8_is_8_cores_of_ccd_0() {
    let t = r5950x();
    let first_threads = mask((0..16).step_by(2));
    for smt in [false, true] {
        let r = CpuRule {
            max_threads: Some(8),
            single_l3: true,
            smt,
            ..rule()
        };
        let s = sel(&t, &r, Bitness::X64);
        // B5: cores before SMT siblings, so `smt: true` gives the same 8 cores x 1 thread.
        assert_eq!(s.mask, first_threads, "smt {smt}");
        assert_eq!((s.group, s.threads, s.of), (0, 8, 32));
        assert_eq!(
            s.cpu_set_ids,
            (0..8).map(|n| 0x100 + 2 * n).collect::<Vec<_>>()
        );
    }
    // 16 threads with SMT: all of CCD 0.
    let r = CpuRule {
        max_threads: Some(16),
        single_l3: true,
        ..rule()
    };
    assert_eq!(sel(&t, &r, Bitness::X64).mask, 0xFFFF);
    // No rule at all: every processor.
    assert_eq!(sel(&t, &rule(), Bitness::X64).mask, 0xFFFF_FFFF);
}

#[test]
fn max_threads_takes_first_threads_of_all_cores_before_siblings() {
    let t = Builder::default().llc(0, 3, 8 * MIB, 0, 4, 2).build();
    let r = CpuRule {
        max_threads: Some(6),
        ..rule()
    };
    // Cores 0..4 have threads (0,1) (2,3) (4,5) (6,7): first 0 2 4 6, then 1 3.
    assert_eq!(sel(&t, &r, Bitness::X64).mask, mask([0, 1, 2, 3, 4, 6]));
}

#[test]
fn lp_e_cores_are_never_selected_on_lunar_lake() {
    let t = lunar_lake();
    let lp_e = mask(4..8);
    for r in all_rules(&[None, Some(1), Some(4), Some(8), Some(64)]) {
        for b in [Bitness::X86, Bitness::X64] {
            let s = sel(&t, &r, b);
            assert_eq!(s.mask & lp_e, 0, "{r:?} {b:?}");
            assert!(s.threads >= 1 && s.threads <= 4);
        }
    }
}

#[test]
fn an_l2_only_machine_keeps_all_its_llcs() {
    // Core 2 Quad: two L2 caches are the last level; nothing is below the top level.
    let t = Builder::default()
        .llc(0, 2, 4 * MIB, 0, 2, 1)
        .llc(0, 2, 4 * MIB, 0, 2, 1)
        .build();
    assert_eq!(sel(&t, &rule(), Bitness::X64).mask, 0xF);
}

#[test]
fn the_largest_group_wins_and_ties_go_to_the_lowest_number() {
    let t = Builder::default()
        .llc(0, 3, 32 * MIB, 0, 4, 2)
        .llc(1, 3, 32 * MIB, 0, 8, 2)
        .build();
    let s = sel(&t, &rule(), Bitness::X64);
    assert_eq!((s.group, s.mask, s.of), (1, 0xFFFF, 24));
    let t = Builder::default()
        .llc(0, 3, 32 * MIB, 0, 8, 2)
        .llc(1, 3, 32 * MIB, 0, 8, 2)
        .build();
    let s = sel(&t, &rule(), Bitness::X64);
    assert_eq!((s.group, s.mask), (0, 0xFFFF));
}

#[test]
fn a_32_bit_game_gets_indices_below_32_only() {
    // One group of 64: 4 LLCs x 8 cores x 2 threads.
    let mut b = Builder::default();
    for _ in 0..4 {
        b = b.llc(0, 3, 32 * MIB, 0, 8, 2);
    }
    let t = b.build();
    let s = sel(&t, &rule(), Bitness::X86);
    assert_eq!((s.mask, s.threads), (0xFFFF_FFFF, 32));
    let s = sel(&t, &rule(), Bitness::X64);
    assert_eq!((s.mask, s.threads), (u64::MAX, 64));
    // The LLC choice sees only what a 32-bit game can reach: the largest LLC at 32..48 is out.
    let t = Builder::default()
        .llc(0, 3, 32 * MIB, 0, 16, 2)
        .llc(0, 3, 96 * MIB, 0, 8, 2)
        .build();
    let r = CpuRule {
        prefer_l3: Some(PreferL3::Largest),
        ..rule()
    };
    assert_eq!(sel(&t, &r, Bitness::X86).mask, 0xFFFF_FFFF);
    assert_eq!(sel(&t, &r, Bitness::X64).mask, 0xFFFF << 32);
}

#[test]
fn a_32_bit_game_on_a_group_with_nothing_below_32_is_empty_after_bitness() {
    // Indices 0..32 are LP E-cores (level 2), the L3 cores sit at 32..48.
    let t = Builder::default()
        .llc(0, 2, 2 * MIB, 0, 32, 1)
        .llc(0, 3, 32 * MIB, 1, 16, 1)
        .build();
    assert_eq!(
        select(&t, &rule(), Bitness::X86),
        Err(SelectError::Empty {
            after: SelectStep::Bitness
        })
    );
    assert_eq!(sel(&t, &rule(), Bitness::X64).mask, 0xFFFF << 32);
}

#[test]
fn performance_keeps_the_highest_class() {
    // i9-14900K shape: 8 P-cores with SMT (class 1), 16 E-cores (class 0), one L3.
    let t = Builder::default().llc(0, 3, 36 * MIB, 1, 8, 2).build();
    let t = CpuTopology {
        cpus: t
            .cpus
            .iter()
            .copied()
            .chain((0..16u8).map(|n| LogicalCpu {
                cpu_set_id: 0x110 + u32::from(n),
                group: 0,
                index: 16 + n,
                core: 8 + u32::from(n),
                llc: 0,
                efficiency_class: 0,
            }))
            .collect(),
        llcs: t.llcs,
    };
    t.validate().unwrap();
    let r = CpuRule {
        prefer: Prefer::Performance,
        ..rule()
    };
    assert_eq!(sel(&t, &r, Bitness::X64).mask, 0xFFFF);
    assert_eq!(sel(&t, &rule(), Bitness::X64).mask, 0xFFFF_FFFF);
}

#[test]
fn llc_ties_never_spread_a_game() {
    // Equal sizes (9950X3D2): `prefer_l3: largest` falls back to the most candidates, then
    // the lowest LLC number.
    let t = Builder::default()
        .llc(0, 3, 96 * MIB, 0, 8, 2)
        .llc(0, 3, 96 * MIB, 0, 8, 2)
        .build();
    for r in [
        CpuRule {
            prefer_l3: Some(PreferL3::Largest),
            ..rule()
        },
        CpuRule {
            single_l3: true,
            ..rule()
        },
    ] {
        assert_eq!(sel(&t, &r, Bitness::X64).mask, 0xFFFF, "{r:?}");
    }
    // More candidates win a size tie.
    let t = Builder::default()
        .llc(0, 3, 32 * MIB, 0, 4, 2)
        .llc(0, 3, 32 * MIB, 0, 8, 2)
        .build();
    let r = CpuRule {
        prefer_l3: Some(PreferL3::Largest),
        ..rule()
    };
    assert_eq!(sel(&t, &r, Bitness::X64).mask, 0xFFFF << 8);
    // `single_l3`: most candidates first, then the larger cache (7950X3D: equal counts).
    let t = Builder::default()
        .llc(0, 3, 32 * MIB, 0, 8, 2)
        .llc(0, 3, 96 * MIB, 0, 8, 2)
        .build();
    let r = CpuRule {
        single_l3: true,
        ..rule()
    };
    assert_eq!(sel(&t, &r, Bitness::X64).mask, 0xFFFF << 16);
    // ... but a bigger LLC with fewer candidates loses to `single_l3`, wins `prefer_l3`.
    let t = Builder::default()
        .llc(0, 3, 16 * MIB, 0, 8, 2)
        .llc(0, 3, 96 * MIB, 0, 4, 2)
        .build();
    assert_eq!(sel(&t, &r, Bitness::X64).mask, 0xFFFF);
    let r = CpuRule {
        prefer_l3: Some(PreferL3::Largest),
        ..rule()
    };
    assert_eq!(sel(&t, &r, Bitness::X64).mask, 0xFF << 16);
}

#[test]
fn without_single_l3_or_prefer_l3_every_llc_stays() {
    let t = r5950x();
    let s = sel(
        &t,
        &CpuRule {
            smt: false,
            ..rule()
        },
        Bitness::X64,
    );
    assert_eq!(s.mask, mask((0..32).step_by(2)));
}

#[test]
fn max_threads_0_is_empty_after_max_threads() {
    let r = CpuRule {
        max_threads: Some(0),
        ..rule()
    };
    assert_eq!(
        select(&r5950x(), &r, Bitness::X64),
        Err(SelectError::Empty {
            after: SelectStep::MaxThreads
        })
    );
}

#[test]
fn an_invalid_topology_is_refused() {
    let mut t = r5950x();
    t.cpus[1].index = 0;
    assert_eq!(
        select(&t, &rule(), Bitness::X64),
        Err(SelectError::Invalid(TopologyError::Invalid(
            Invariant::NotSorted
        )))
    );
}

#[test]
fn errors_name_the_step() {
    assert_eq!(
        SelectError::Empty {
            after: SelectStep::Bitness
        }
        .to_string(),
        "the CPU rule selects no processor on this machine (empty after step bitness)"
    );
}

/// Every combination of the rule fields with the given `max_threads` values.
fn all_rules(maxes: &[Option<u16>]) -> Vec<CpuRule> {
    let mut out = Vec::new();
    for &max_threads in maxes {
        for prefer in [Prefer::Any, Prefer::Performance] {
            for single_l3 in [false, true] {
                for prefer_l3 in [None, Some(PreferL3::Largest)] {
                    for smt in [false, true] {
                        for mode in [Mode::Hard, Mode::Soft] {
                            out.push(CpuRule {
                                max_threads,
                                prefer,
                                single_l3,
                                prefer_l3,
                                smt,
                                mode,
                            });
                        }
                    }
                }
            }
        }
    }
    out
}

/// xorshift64*, so the loop is the same on every machine (no proptest dependency).
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }

    fn pick<T: Copy>(&mut self, of: &[T]) -> T {
        of[usize::try_from(self.below(of.len() as u64)).unwrap()]
    }
}

/// A random valid topology: 1 to 3 groups, each with 1 to 4 LLCs.
fn random_topology(rng: &mut Rng) -> CpuTopology {
    let mut b = Builder::default();
    for group in 0..=u16::try_from(rng.below(3)).unwrap() {
        let mut room: u32 = 64;
        for _ in 0..=rng.below(4) {
            let smt = u8::try_from(1 + rng.below(2)).unwrap();
            let cores = u32::try_from(1 + rng.below(8)).unwrap();
            if cores * u32::from(smt) > room {
                break;
            }
            room -= cores * u32::from(smt);
            let level = rng.pick(&[2, 3, 3, 3]);
            let size = rng.pick(&[2, 4, 16, 32, 96]) * MIB;
            let class = rng.pick(&[0, 0, 1, 2]);
            b = b.llc(group, level, size, class, cores, smt);
        }
    }
    b.build()
}

/// Checks the properties of docs/03 on one result, against the steps recomputed naively.
fn check_properties(t: &CpuTopology, r: &CpuRule, b: Bitness) {
    let res = select(t, r, b);
    assert_eq!(res, select(t, r, b), "deterministic");
    let level = |c: &LogicalCpu| t.llcs[usize::try_from(c.llc).unwrap()].level;
    let size = |c: &LogicalCpu| t.llcs[usize::try_from(c.llc).unwrap()].size;

    let mut per_group: BTreeMap<u16, usize> = BTreeMap::new();
    for c in &t.cpus {
        *per_group.entry(c.group).or_default() += 1;
    }
    let most = per_group.values().copied().max().unwrap();
    let group = *per_group.iter().find(|(_, n)| **n == most).unwrap().0;
    let in_group: Vec<&LogicalCpu> = t.cpus.iter().filter(|c| c.group == group).collect();
    let top = in_group.iter().map(|c| level(c)).max().unwrap();
    let reachable: Vec<&LogicalCpu> = in_group
        .iter()
        .copied()
        .filter(|c| level(c) == top)
        .filter(|c| b == Bitness::X64 || c.index < X86_INDEX_LIMIT)
        .collect();

    let s = match res {
        Err(SelectError::Empty { after }) => {
            match after {
                SelectStep::Bitness => assert!(reachable.is_empty() && b == Bitness::X86),
                SelectStep::MaxThreads => assert_eq!(r.max_threads, Some(0)),
                other => panic!("{other:?} can never empty the candidates"),
            }
            return;
        }
        Err(e) => panic!("{e}"),
        Ok(s) => s,
    };
    let chosen: Vec<&LogicalCpu> = t
        .cpus
        .iter()
        .filter(|c| c.group == s.group && s.mask & (1 << c.index) != 0)
        .collect();
    // One group, the largest (lowest on a tie); mask, IDs and counts agree.
    assert_eq!(s.group, group);
    assert_eq!(chosen.len(), usize::from(s.threads));
    assert_eq!(s.mask.count_ones(), u32::from(s.threads));
    assert!(s.threads >= 1);
    assert_eq!(usize::from(s.of), t.logical_count());
    assert_eq!(
        s.cpu_set_ids,
        chosen.iter().map(|c| c.cpu_set_id).collect::<Vec<_>>()
    );
    // Within the candidates: never below the top LLC level, 32-bit below index 32.
    for c in &chosen {
        assert_eq!(level(c), top, "LP E-cores selected");
        if b == Bitness::X86 {
            assert!(c.index < X86_INDEX_LIMIT);
        }
    }
    if b == Bitness::X86 {
        assert!(s.threads <= 32);
    }
    // Performance: the highest class among the reachable ones.
    if r.prefer == Prefer::Performance {
        let best = reachable.iter().map(|c| c.efficiency_class).max().unwrap();
        assert!(chosen.iter().all(|c| c.efficiency_class == best));
    }
    // One LLC with single_l3/prefer_l3 (never spread across tied LLCs); the largest with
    // prefer_l3 among those the class step left.
    let llcs: BTreeSet<u32> = chosen.iter().map(|c| c.llc).collect();
    if r.single_l3 || r.prefer_l3.is_some() {
        assert_eq!(llcs.len(), 1, "spread across LLCs: {r:?}");
        if r.prefer_l3 == Some(PreferL3::Largest) {
            let best = if r.prefer == Prefer::Performance {
                reachable.iter().map(|c| c.efficiency_class).max().unwrap()
            } else {
                0
            };
            let max = reachable
                .iter()
                .filter(|c| r.prefer == Prefer::Any || c.efficiency_class == best)
                .map(|c| size(c))
                .max()
                .unwrap();
            assert_eq!(size(chosen[0]), max);
        }
    }
    // SMT off: one thread per core.
    let cores: BTreeSet<u32> = chosen.iter().map(|c| c.core).collect();
    if !r.smt {
        assert_eq!(cores.len(), chosen.len());
    }
    // max_threads holds, and is a prefix: the selection without it is a superset.
    if let Some(max) = r.max_threads {
        assert!(s.threads <= max);
        let wide = select(
            t,
            &CpuRule {
                max_threads: None,
                ..*r
            },
            b,
        )
        .unwrap();
        assert_eq!(s.mask & !wide.mask, 0);
        assert_eq!(s.threads, max.min(wide.threads));
        // Cores before siblings: no core contributes a second thread while a core of the
        // wide selection has none.
        let wide_cores: BTreeSet<u32> = t
            .cpus
            .iter()
            .filter(|c| c.group == wide.group && wide.mask & (1 << c.index) != 0)
            .map(|c| c.core)
            .collect();
        if cores.len() < chosen.len() {
            assert_eq!(cores, wide_cores, "a sibling before a core");
        }
    }
}

#[test]
fn random_topologies_keep_every_property() {
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    let rules = all_rules(&[
        None,
        Some(0),
        Some(1),
        Some(3),
        Some(8),
        Some(33),
        Some(100),
    ]);
    for _ in 0..400 {
        let t = random_topology(&mut rng);
        for r in &rules {
            for b in [Bitness::X86, Bitness::X64] {
                check_properties(&t, r, b);
            }
        }
    }
}

#[test]
fn the_named_shapes_keep_every_property() {
    let rules = all_rules(&[None, Some(0), Some(1), Some(8), Some(64)]);
    for t in [r5950x(), lunar_lake()] {
        for r in &rules {
            for b in [Bitness::X86, Bitness::X64] {
                check_properties(&t, r, b);
            }
        }
    }
}
