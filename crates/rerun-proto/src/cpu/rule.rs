//! CPU rule selection (`docs/03-cpu-topology.md`, "Selection algorithm"; ADR 0022).
//!
//! [`select`] turns a [`CpuRule`] into the logical processors of one processor group, on the
//! live [`CpuTopology`] of the machine at hand. It is pure: `rerun-launch` runs it at every
//! start (CPU Set IDs are runtime values), `rerun-core` runs it for the preview. The steps, in
//! order:
//!
//! 1. **Group:** the group with the most logical processors, on a tie the lowest number. In it,
//!    LLCs whose `level` is below the highest `level` in the group drop out (LP E-cores with
//!    their own L2 as last level, never for games).
//! 2. **Bitness:** for a 32-bit game only indices `< 32` stay (ADR 0022, B6).
//! 3. **Performance:** `prefer: performance` keeps the highest efficiency class.
//! 4. **L3:** `prefer_l3: largest` keeps the LLC with the largest size, then the most
//!    candidates, then the lowest number; `single_l3` alone keeps the LLC with the most
//!    candidates, then the largest size, then the lowest number. Either way exactly one LLC.
//! 5. **SMT:** `smt: false` keeps the first thread of each core.
//! 6. **Max threads:** the first `N` in the order "first threads of all cores, then second
//!    threads, …", each by `index` (cores before SMT siblings).
//!
//! An empty result is an error naming the step that emptied it, never a silent fallback.

use std::collections::BTreeMap;
use std::fmt;

use super::{CpuTopology, LogicalCpu, TopologyError};

/// A 32-bit (WOW64) process sees affinity masks as 32-bit values: only indices below this
/// are selectable for [`Bitness::X86`] (ADR 0022, B6).
pub const X86_INDEX_LIMIT: u8 = 32;

/// Which efficiency classes a rule may use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Prefer {
    /// Only the highest efficiency class (P-cores on Intel hybrid parts).
    Performance,
    /// Every class that is left after step 1 (LP E-cores are gone already).
    Any,
}

/// Which last-level cache a rule prefers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PreferL3 {
    /// The LLC with the largest size (the V-Cache CCD on X3D parts).
    Largest,
}

/// How the selection is applied by `rerun-launch`. [`select`] does not depend on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Mode {
    /// Affinity (Job Object group affinity): the game cannot leave it.
    Hard,
    /// Default CPU Sets (`SetProcessDefaultCpuSets`): a preference for the launched process.
    Soft,
}

/// Bitness of the game's executable (PE machine).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Bitness {
    /// 32-bit (`IMAGE_FILE_MACHINE_I386`), runs under WOW64.
    X86,
    /// 64-bit (`IMAGE_FILE_MACHINE_AMD64`).
    X64,
}

/// A CPU rule as a Topo states it (`docs/02-topo-format.md`, `cpu` step).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CpuRule {
    /// At most this many logical processors (`0` selects nothing: an error).
    pub max_threads: Option<u16>,
    /// Efficiency classes.
    pub prefer: Prefer,
    /// All threads from one LLC.
    pub single_l3: bool,
    /// Prefer an LLC by size; implies one LLC.
    pub prefer_l3: Option<PreferL3>,
    /// `false`: one thread per core.
    pub smt: bool,
    /// Hard or soft.
    pub mode: Mode,
}

/// The logical processors a rule selected, all in one group.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Selection {
    /// The processor group.
    pub group: u16,
    /// Affinity mask within the group (bit = `index`), never 0.
    pub mask: u64,
    /// CPU Set IDs of the selected processors, in `index` order.
    pub cpu_set_ids: Vec<u32>,
    /// Number of selected logical processors (bits in `mask`).
    pub threads: u16,
    /// Logical processors of the whole machine (for "8 of 32").
    pub of: u16,
}

/// A step of [`select`], in order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SelectStep {
    /// Step 1: group and LP E-cores.
    Group,
    /// Step 2: 32-bit limit.
    Bitness,
    /// Step 3: `prefer: performance`.
    Performance,
    /// Step 4: `single_l3` / `prefer_l3`.
    L3,
    /// Step 5: `smt: false`.
    Smt,
    /// Step 6: `max_threads`.
    MaxThreads,
}

impl SelectStep {
    /// Stable name for messages and tests.
    pub fn name(self) -> &'static str {
        match self {
            Self::Group => "group",
            Self::Bitness => "bitness",
            Self::Performance => "performance",
            Self::L3 => "l3",
            Self::Smt => "smt",
            Self::MaxThreads => "max_threads",
        }
    }
}

/// Why [`select`] has no result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SelectError {
    /// The rule is too strict for this machine: `after` left no processor.
    Empty {
        /// The step that emptied the candidates.
        after: SelectStep,
    },
    /// The topology violates an invariant (never select on an unchecked topology).
    Invalid(TopologyError),
}

impl fmt::Display for SelectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty { after } => write!(
                f,
                "the CPU rule selects no processor on this machine (empty after step {})",
                after.name()
            ),
            Self::Invalid(e) => write!(f, "cannot select: {e}"),
        }
    }
}

impl std::error::Error for SelectError {}

/// Selects the logical processors for `rule` on `topology` for a game of `bitness`.
///
/// Validates the topology first. The result lies in one group, is non-empty and follows the
/// steps of the module documentation.
pub fn select(
    topology: &CpuTopology,
    rule: &CpuRule,
    bitness: Bitness,
) -> Result<Selection, SelectError> {
    topology.validate().map_err(SelectError::Invalid)?;
    let llc = |c: &LogicalCpu| {
        usize::try_from(c.llc)
            .ok()
            .and_then(|i| topology.llcs.get(i))
            .map_or((0, 0), |l| (l.level, l.size))
    };

    // Step 1: the largest group, on a tie the lowest number; then no LLC below the top level.
    let mut per_group: BTreeMap<u16, usize> = BTreeMap::new();
    for c in &topology.cpus {
        *per_group.entry(c.group).or_default() += 1;
    }
    let group = per_group
        .iter()
        .max_by(|a, b| a.1.cmp(b.1).then(b.0.cmp(a.0)))
        .map(|(g, _)| *g)
        .ok_or(SelectError::Empty {
            after: SelectStep::Group,
        })?;
    let mut cand: Vec<&LogicalCpu> = topology.cpus.iter().filter(|c| c.group == group).collect();
    let top = cand.iter().map(|c| llc(c).0).max().unwrap_or(0);
    cand.retain(|c| llc(c).0 == top);
    nonempty(&cand, SelectStep::Group)?;

    // Step 2: a 32-bit game addresses indices 0..32 only.
    if bitness == Bitness::X86 {
        cand.retain(|c| c.index < X86_INDEX_LIMIT);
        nonempty(&cand, SelectStep::Bitness)?;
    }

    // Step 3: the highest efficiency class.
    if rule.prefer == Prefer::Performance {
        let best = cand.iter().map(|c| c.efficiency_class).max().unwrap_or(0);
        cand.retain(|c| c.efficiency_class == best);
        nonempty(&cand, SelectStep::Performance)?;
    }

    // Step 4: exactly one LLC.
    if rule.single_l3 || rule.prefer_l3.is_some() {
        let mut per_llc: BTreeMap<u32, (usize, u64)> = BTreeMap::new();
        for c in &cand {
            let e = per_llc.entry(c.llc).or_insert((0, llc(c).1));
            e.0 += 1;
        }
        let largest = rule.prefer_l3 == Some(PreferL3::Largest);
        let chosen = per_llc
            .iter()
            .max_by(|(la, (na, sa)), (lb, (nb, sb))| {
                let primary = if largest {
                    sa.cmp(sb).then(na.cmp(nb))
                } else {
                    na.cmp(nb).then(sa.cmp(sb))
                };
                primary.then(lb.cmp(la))
            })
            .map(|(l, _)| *l);
        cand.retain(|c| Some(c.llc) == chosen);
        nonempty(&cand, SelectStep::L3)?;
    }

    // Step 5: the first thread of each core (`cand` is sorted by index within the group).
    if !rule.smt {
        let mut seen = std::collections::BTreeSet::new();
        cand.retain(|c| seen.insert(c.core));
        nonempty(&cand, SelectStep::Smt)?;
    }

    // Step 6: cores before SMT siblings.
    if let Some(max) = rule.max_threads {
        let mut rank: BTreeMap<u32, usize> = BTreeMap::new();
        let mut order: Vec<(usize, u8, &LogicalCpu)> = cand
            .iter()
            .map(|c| {
                let r = rank.entry(c.core).or_default();
                let this = *r;
                *r += 1;
                (this, c.index, *c)
            })
            .collect();
        order.sort_by_key(|(r, i, _)| (*r, *i));
        order.truncate(usize::from(max));
        cand = order.into_iter().map(|(_, _, c)| c).collect();
        cand.sort_by_key(|c| c.index);
        nonempty(&cand, SelectStep::MaxThreads)?;
    }

    let mask = cand.iter().fold(0u64, |m, c| m | (1u64 << c.index));
    Ok(Selection {
        group,
        mask,
        cpu_set_ids: cand.iter().map(|c| c.cpu_set_id).collect(),
        threads: u16::try_from(cand.len()).unwrap_or(u16::MAX),
        of: u16::try_from(topology.logical_count()).unwrap_or(u16::MAX),
    })
}

fn nonempty(cand: &[&LogicalCpu], after: SelectStep) -> Result<(), SelectError> {
    if cand.is_empty() {
        Err(SelectError::Empty { after })
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests;
