use super::*;

fn cpu(index: u8, core: u32, llc: u32) -> LogicalCpu {
    LogicalCpu {
        cpu_set_id: 0x100 + u32::from(index),
        group: 0,
        index,
        core,
        llc,
        efficiency_class: 0,
    }
}

const L3: Llc = Llc {
    level: 3,
    size: 32 << 20,
};

/// 2 LLCs × 1 core × 2 threads.
fn valid() -> CpuTopology {
    CpuTopology {
        cpus: vec![cpu(0, 0, 0), cpu(1, 0, 0), cpu(2, 1, 1), cpu(3, 1, 1)],
        llcs: vec![L3, L3],
    }
}

fn invalid(t: &CpuTopology) -> Invariant {
    match t.validate() {
        Err(TopologyError::Invalid(inv)) => inv,
        other => panic!("expected an invariant violation, got {other:?}"),
    }
}

#[test]
fn counts_smt_siblings_as_one_core() {
    let t = valid();
    assert_eq!(t.validate(), Ok(()));
    assert_eq!(t.logical_count(), 4);
    assert_eq!(t.core_count(), 2);
    assert_eq!(t.llc_count(), 2);
    assert!(t.has_smt());
    assert!(!t.is_hybrid());
}

#[test]
fn cores_in_other_groups_continue_the_numbering() {
    let mut other = cpu(0, 1, 1);
    other.group = 1;
    other.cpu_set_id = 0x200;
    let t = CpuTopology {
        cpus: vec![cpu(0, 0, 0), other],
        llcs: vec![L3, L3],
    };
    assert_eq!(t.validate(), Ok(()));
    assert_eq!(t.core_count(), 2);
    assert!(!t.has_smt());
}

#[test]
fn empty_is_invalid() {
    let t = CpuTopology {
        cpus: vec![],
        llcs: vec![],
    };
    assert_eq!(invalid(&t), Invariant::Empty);
}

#[test]
fn more_than_4096_is_invalid() {
    let cpus: Vec<LogicalCpu> = (0..=MAX_LOGICAL_CPUS)
        .map(|n| {
            let n32 = u32::try_from(n).unwrap();
            LogicalCpu {
                cpu_set_id: n32,
                group: u16::try_from(n / 64).unwrap(),
                index: u8::try_from(n % 64).unwrap(),
                core: n32,
                llc: 0,
                efficiency_class: 0,
            }
        })
        .collect();
    let t = CpuTopology {
        cpus,
        llcs: vec![L3],
    };
    assert_eq!(invalid(&t), Invariant::TooManyCpus);
}

#[test]
fn unsorted_or_duplicate_processors_are_invalid() {
    let mut t = valid();
    t.cpus.swap(0, 1);
    t.cpus[0].core = 0;
    assert_eq!(invalid(&t), Invariant::NotSorted);
    let mut t = valid();
    t.cpus[1].index = 0;
    assert_eq!(invalid(&t), Invariant::NotSorted);
    let mut t = valid();
    t.cpus[0].group = 1;
    assert_eq!(invalid(&t), Invariant::NotSorted);
}

#[test]
fn index_64_is_invalid() {
    let mut t = valid();
    t.cpus[3].index = 64;
    assert_eq!(invalid(&t), Invariant::IndexOutOfRange);
}

#[test]
fn duplicate_cpu_set_ids_are_invalid() {
    let mut t = valid();
    t.cpus[3].cpu_set_id = t.cpus[0].cpu_set_id;
    assert_eq!(invalid(&t), Invariant::DuplicateCpuSetId);
}

#[test]
fn raw_windows_numbering_is_invalid() {
    // CoreIndex/LastLevelCacheIndex as Windows reports them: first index of the core/cache.
    let t = CpuTopology {
        cpus: vec![cpu(0, 0, 0), cpu(1, 0, 0), cpu(2, 2, 2), cpu(3, 2, 2)],
        llcs: vec![L3, L3],
    };
    assert_eq!(invalid(&t), Invariant::CoreNotDense);
    let mut t = valid();
    t.cpus[0].core = 1;
    t.cpus[1].core = 1;
    t.cpus[2].core = 0;
    t.cpus[3].core = 0;
    assert_eq!(invalid(&t), Invariant::CoreNotDense);
    let mut t = valid();
    t.cpus[2].llc = 2;
    t.cpus[3].llc = 2;
    assert_eq!(invalid(&t), Invariant::LlcNotDense);
}

#[test]
fn threads_of_a_core_must_agree() {
    let mut t = valid();
    t.cpus[1].efficiency_class = 1;
    assert_eq!(invalid(&t), Invariant::CoreSplit);
    let mut t = valid();
    t.cpus[1].llc = 1;
    assert_eq!(invalid(&t), Invariant::CoreSplit);
    // A core that spans two groups.
    let mut split = cpu(0, 0, 0);
    split.group = 1;
    split.cpu_set_id = 0x300;
    let t = CpuTopology {
        cpus: vec![cpu(0, 0, 0), split],
        llcs: vec![L3],
    };
    assert_eq!(invalid(&t), Invariant::CoreSplit);
}

#[test]
fn llcs_must_match_the_llc_numbers() {
    let mut t = valid();
    t.llcs.pop();
    assert_eq!(invalid(&t), Invariant::LlcCount);
    let mut t = valid();
    t.llcs.push(L3);
    assert_eq!(invalid(&t), Invariant::LlcCount);
    let mut t = valid();
    t.llcs[1].size = 0;
    assert_eq!(invalid(&t), Invariant::LlcSize);
    for level in [0, 5] {
        let mut t = valid();
        t.llcs[0].level = level;
        assert_eq!(invalid(&t), Invariant::LlcLevel);
    }
}

#[test]
fn invariant_names_appear_in_the_error() {
    assert_eq!(
        TopologyError::Invalid(Invariant::CoreNotDense).to_string(),
        "invalid topology: dense core numbering violated"
    );
}
