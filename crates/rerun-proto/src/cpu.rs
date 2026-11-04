//! CPU topology as plain data (see `docs/03-cpu-topology.md`).
//!
//! On the real system the values come from `GetSystemCpuSetInformation` and
//! `GetLogicalProcessorInformationEx`, in tests from fixtures under `tests/fixtures/cpu/`.

use std::collections::{BTreeMap, BTreeSet};

/// A logical processor (hardware thread).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(deny_unknown_fields))]
pub struct LogicalCpu {
    /// Processor group (Windows puts at most 64 logical processors in one group).
    pub group: u16,
    /// Index within the group.
    pub index: u8,
    /// Physical core. SMT siblings share the same value.
    pub core: u32,
    /// Efficiency class; higher = more powerful (P-cores > E-cores).
    pub efficiency_class: u8,
    /// Last-level cache group (≈ CCD/CCX on AMD).
    pub llc: u32,
    /// NUMA node.
    pub numa: u32,
}

/// The complete CPU topology of a system.
///
/// Named `CpuTopology` rather than `Topology` so it does not clash with the trait
/// `rerun_core::sys::Topology`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(deny_unknown_fields))]
pub struct CpuTopology {
    /// All logical processors.
    pub cpus: Vec<LogicalCpu>,
    /// Size of each LLC group in bytes. `BTreeMap` for deterministic output.
    pub llc_sizes: BTreeMap<u32, u64>,
}

impl CpuTopology {
    /// Number of logical processors.
    pub fn logical_count(&self) -> usize {
        self.cpus.len()
    }

    /// Number of physical cores (across all groups).
    pub fn core_count(&self) -> usize {
        self.cpus
            .iter()
            .map(|c| (c.group, c.core))
            .collect::<BTreeSet<_>>()
            .len()
    }

    /// Number of distinct LLC groups.
    pub fn llc_count(&self) -> usize {
        self.cpus
            .iter()
            .map(|c| c.llc)
            .collect::<BTreeSet<_>>()
            .len()
    }

    /// `true` if at least one core has more than one hardware thread.
    pub fn has_smt(&self) -> bool {
        self.logical_count() > self.core_count()
    }

    /// `true` if there are several efficiency classes (Intel P/E-cores).
    pub fn is_hybrid(&self) -> bool {
        self.cpus
            .iter()
            .map(|c| c.efficiency_class)
            .collect::<BTreeSet<_>>()
            .len()
            > 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cpu(core: u32, index: u8, llc: u32) -> LogicalCpu {
        LogicalCpu {
            group: 0,
            index,
            core,
            efficiency_class: 0,
            llc,
            numa: 0,
        }
    }

    #[test]
    fn counts_smt_siblings_as_one_core() {
        let t = CpuTopology {
            cpus: vec![cpu(0, 0, 0), cpu(0, 1, 0), cpu(1, 2, 1), cpu(1, 3, 1)],
            llc_sizes: BTreeMap::from([(0, 32 << 20), (1, 32 << 20)]),
        };
        assert_eq!(t.logical_count(), 4);
        assert_eq!(t.core_count(), 2);
        assert_eq!(t.llc_count(), 2);
        assert!(t.has_smt());
        assert!(!t.is_hybrid());
    }

    #[test]
    fn same_core_index_in_other_group_is_another_core() {
        let mut other = cpu(0, 0, 1);
        other.group = 1;
        let t = CpuTopology {
            cpus: vec![cpu(0, 0, 0), other],
            llc_sizes: BTreeMap::new(),
        };
        assert_eq!(t.core_count(), 2);
        assert!(!t.has_smt());
    }
}
