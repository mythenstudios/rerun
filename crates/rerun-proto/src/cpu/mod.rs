//! CPU topology as plain data (see `docs/03-cpu-topology.md`, ADR 0010).
//!
//! On the real system the values come from `GetSystemCpuSetInformation` and
//! `GetLogicalProcessorInformationEx`, parsed by [`CpuTopology::from_windows`]; in tests from
//! fixtures under `tests/fixtures/cpu/`. Raw Windows indices never leave the parser: `core` and
//! `llc` are dense numbers in first-appearance order, so two machines of the same shape give
//! the same topology apart from `cpu_set_id`. Every topology that Rerun hands on has passed
//! [`CpuTopology::validate`].

use std::collections::BTreeSet;
use std::fmt;

pub mod parse;
pub mod rule;

pub use parse::{Check, Source};

/// Most logical processors Rerun accepts (the parser and [`CpuTopology::validate`]).
pub const MAX_LOGICAL_CPUS: usize = 4096;

/// Logical processors per processor group (one `KAFFINITY` mask).
pub const GROUP_SIZE: u8 = 64;

/// A logical processor (hardware thread).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(deny_unknown_fields))]
pub struct LogicalCpu {
    /// CPU Set ID (`SYSTEM_CPU_SET_INFORMATION.CpuSet.Id`), for `SetProcessDefaultCpuSets`.
    /// A runtime value: read it at launch, never store it.
    pub cpu_set_id: u32,
    /// Processor group (Windows puts at most 64 logical processors in one group).
    pub group: u16,
    /// Index within the group, `< 64`; the bit of the group's affinity mask.
    pub index: u8,
    /// Dense physical core number. SMT siblings share it.
    pub core: u32,
    /// Dense last-level cache number (≈ CCD/CCX on AMD), index into [`CpuTopology::llcs`].
    pub llc: u32,
    /// Efficiency class; higher = more powerful (P-cores > E-cores).
    pub efficiency_class: u8,
}

/// A last-level cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(deny_unknown_fields))]
pub struct Llc {
    /// Cache level, `1..=4` (3 for an L3; 2 where the L2 is the last level, LP E-cores).
    pub level: u8,
    /// Size in bytes, `> 0`.
    pub size: u64,
}

/// The complete CPU topology of a system.
///
/// Named `CpuTopology` rather than `Topology` so it does not clash with the trait
/// `rerun_core::sys::Topology`. Not a persisted format (no journal, no topo field).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(deny_unknown_fields))]
pub struct CpuTopology {
    /// All logical processors available to a game, sorted by `(group, index)`.
    pub cpus: Vec<LogicalCpu>,
    /// The last-level caches, indexed by [`LogicalCpu::llc`].
    pub llcs: Vec<Llc>,
}

/// An invariant of [`CpuTopology::validate`] that does not hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Invariant {
    /// `cpus` is empty.
    Empty,
    /// More than [`MAX_LOGICAL_CPUS`] logical processors.
    TooManyCpus,
    /// `cpus` is not strictly sorted by `(group, index)`.
    NotSorted,
    /// An `index` is 64 or more.
    IndexOutOfRange,
    /// Two logical processors have the same `cpu_set_id`.
    DuplicateCpuSetId,
    /// `core` is not numbered `0, 1, …` in first-appearance order.
    CoreNotDense,
    /// `llc` is not numbered `0, 1, …` in first-appearance order.
    LlcNotDense,
    /// The threads of one core differ in group, LLC or efficiency class.
    CoreSplit,
    /// `llcs.len()` is not the number of LLCs.
    LlcCount,
    /// An LLC has size 0.
    LlcSize,
    /// An LLC level is outside `1..=4`.
    LlcLevel,
}

impl Invariant {
    /// Stable name for messages and tests.
    pub fn name(self) -> &'static str {
        match self {
            Self::Empty => "non-empty",
            Self::TooManyCpus => "at most 4096 logical processors",
            Self::NotSorted => "strictly sorted by (group, index)",
            Self::IndexOutOfRange => "index < 64",
            Self::DuplicateCpuSetId => "unique cpu_set_id",
            Self::CoreNotDense => "dense core numbering",
            Self::LlcNotDense => "dense llc numbering",
            Self::CoreSplit => "threads of a core share group, llc and efficiency class",
            Self::LlcCount => "one llcs entry per llc",
            Self::LlcSize => "llc size > 0",
            Self::LlcLevel => "llc level in 1..=4",
        }
    }
}

/// Why a topology was rejected: a malformed Windows buffer, a failed consistency check
/// between the two Windows sources, or a violated invariant.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum TopologyError {
    /// A record header or body does not fit the returned length.
    Truncated {
        /// Buffer.
        source: Source,
        /// Byte offset of the record.
        offset: usize,
    },
    /// A record has `Size == 0`.
    ZeroSize {
        /// Buffer.
        source: Source,
        /// Byte offset of the record.
        offset: usize,
    },
    /// A record is smaller than its type (including its variable part) requires.
    RecordTooSmall {
        /// Buffer.
        source: Source,
        /// Byte offset of the record.
        offset: usize,
        /// `Size` of the record.
        size: usize,
        /// Bytes the record needs.
        min: usize,
    },
    /// More than [`MAX_LOGICAL_CPUS`] logical processors.
    TooManyCpus {
        /// Buffer.
        source: Source,
    },
    /// A buffer is larger than [`parse::MAX_BUFFER`].
    TooLarge {
        /// Buffer.
        source: Source,
        /// Its length in bytes.
        len: usize,
    },
    /// A field has a value Windows never reports (index ≥ 64, no active group, a core
    /// without a group mask, a cache level of 0, …).
    BadField {
        /// Buffer.
        source: Source,
        /// Byte offset of the record.
        offset: usize,
        /// Field name as in the Windows headers.
        field: &'static str,
    },
    /// The two sources disagree or one of them is not a partition (ADR 0010, fail closed).
    Inconsistent(Check),
    /// The result violates an invariant.
    Invalid(Invariant),
}

impl fmt::Display for TopologyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated { source, offset } => {
                write!(f, "{source}: record at offset {offset} is truncated")
            }
            Self::ZeroSize { source, offset } => {
                write!(f, "{source}: record at offset {offset} has size 0")
            }
            Self::RecordTooSmall {
                source,
                offset,
                size,
                min,
            } => write!(
                f,
                "{source}: record at offset {offset} has size {size}, needs {min}"
            ),
            Self::TooManyCpus { source } => write!(
                f,
                "{source}: more than {MAX_LOGICAL_CPUS} logical processors"
            ),
            Self::TooLarge { source, len } => {
                write!(f, "{source}: {len} bytes, more than {}", parse::MAX_BUFFER)
            }
            Self::BadField {
                source,
                offset,
                field,
            } => write!(
                f,
                "{source}: record at offset {offset} has an invalid {field}"
            ),
            Self::Inconsistent(check) => {
                write!(f, "inconsistent topology: check {} failed", check.name())
            }
            Self::Invalid(inv) => write!(f, "invalid topology: {} violated", inv.name()),
        }
    }
}

impl std::error::Error for TopologyError {}

impl CpuTopology {
    /// Checks the invariants of ADR 0010: non-empty (at most [`MAX_LOGICAL_CPUS`]); strictly
    /// sorted by `(group, index)`; `index < 64`; unique `cpu_set_id`; `core` and `llc` dense
    /// in first-appearance order; the threads of one core share group, LLC and efficiency
    /// class; one [`Llc`] per LLC, each with `size > 0` and `level` in `1..=4`.
    pub fn validate(&self) -> Result<(), TopologyError> {
        let fail = |inv| Err(TopologyError::Invalid(inv));
        if self.cpus.is_empty() {
            return fail(Invariant::Empty);
        }
        if self.cpus.len() > MAX_LOGICAL_CPUS {
            return fail(Invariant::TooManyCpus);
        }
        if self
            .cpus
            .windows(2)
            .any(|w| (w[0].group, w[0].index) >= (w[1].group, w[1].index))
        {
            return fail(Invariant::NotSorted);
        }
        if self.cpus.iter().any(|c| c.index >= GROUP_SIZE) {
            return fail(Invariant::IndexOutOfRange);
        }
        let mut ids = BTreeSet::new();
        if !self.cpus.iter().all(|c| ids.insert(c.cpu_set_id)) {
            return fail(Invariant::DuplicateCpuSetId);
        }
        // The first thread of each core, by dense number.
        let mut cores: Vec<&LogicalCpu> = Vec::new();
        let mut llcs: u32 = 0;
        for c in &self.cpus {
            match usize::try_from(c.core).ok() {
                Some(n) if n < cores.len() => {
                    let first = cores[n];
                    if (first.group, first.llc, first.efficiency_class)
                        != (c.group, c.llc, c.efficiency_class)
                    {
                        return fail(Invariant::CoreSplit);
                    }
                }
                Some(n) if n == cores.len() => cores.push(c),
                _ => return fail(Invariant::CoreNotDense),
            }
            if c.llc == llcs {
                llcs += 1;
            } else if c.llc > llcs {
                return fail(Invariant::LlcNotDense);
            }
        }
        if usize::try_from(llcs).ok() != Some(self.llcs.len()) {
            return fail(Invariant::LlcCount);
        }
        if self.llcs.iter().any(|l| l.size == 0) {
            return fail(Invariant::LlcSize);
        }
        if self.llcs.iter().any(|l| !(1..=4).contains(&l.level)) {
            return fail(Invariant::LlcLevel);
        }
        Ok(())
    }

    /// Number of logical processors.
    pub fn logical_count(&self) -> usize {
        self.cpus.len()
    }

    /// Number of physical cores (across all groups).
    pub fn core_count(&self) -> usize {
        self.cpus
            .iter()
            .map(|c| c.core)
            .collect::<BTreeSet<_>>()
            .len()
    }

    /// Number of distinct last-level caches.
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

    /// `true` if Windows reports more than one efficiency class. Not the same as "Intel
    /// P/E-cores": any CPU whose cores report different classes counts, one with a single
    /// class does not (ADR 0015).
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
mod tests;
