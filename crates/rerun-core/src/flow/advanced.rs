//! The data of the game page's "Advanced" section (ADR 0029, plan P5-OE "UI"): what the user may
//! set themselves for the game in front of them, and what the rule they would set selects on
//! this PC. Read only and presentational: nothing here plans or applies, and the rules (the form
//! check [`crate::plan::Manual::check`], the launcher case [`crate::prim::allowed`], the engine's
//! refusals) stay where they are. The front end draws these values and sends a
//! [`crate::plan::Manual`] with the picks; the engine checks it again.
//!
//! - [`AdvancedView`]: the Topo's launch as it bears on the form (Steam's launch entry, the
//!   default method, the main executable and its bitness), the anti-cheat rule, the add
//!   allowlist of compatibility flags, the own settings a live transaction applied, and what is
//!   known of the processor (logical processors, the steps a thread limit may take, a
//!   performance class).
//! - [`cpu_topology`] and [`rule_view`]: the live readout. The topology is read once by the
//!   caller (a session), the selection is pure and made again for every change of a field.

use rerun_proto::cpu::CpuTopology;
/// The bitness of a program, as the rule selection takes it (re-exported for the front ends).
pub use rerun_proto::cpu::rule::Bitness;

use crate::catalog::model::Arch;
use crate::exec::{LiveError, LiveManual, LiveState};
use crate::fold::fold;
use crate::journal::TxnId;
use crate::path::RelPath;
use crate::plan::ManualMethod;
use crate::policy::registry::layers::LAYER_TOKENS;
use crate::prim::{CpuRuleSpec, MachineView, MethodSpec, rule_on_this_machine};
use crate::topo::{GameFacts, LaunchProblem, method_without_start};

use super::Guarded;
use super::game::OwnedReport;

/// Steam's launch entry as the Advanced section meets it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdvancedStart {
    /// The Topo names it: the user's own settings cannot change it.
    Topo(RelPath),
    /// The Topo names no method or no start: the user may choose the program Steam starts among
    /// the executables of the game that matched (each lies in a folder the anti-cheat scan
    /// covers).
    Choose(Vec<RelPath>),
    /// The Topo's launch method is for a later phase: no own launch settings.
    Unavailable(LaunchProblem),
}

/// What the Advanced section of one game page shows (module docs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdvancedView {
    /// The executable that identifies the game (the flags go on it unless a kept `run` chose
    /// another one).
    pub main_exe: Option<RelPath>,
    /// Its bitness (a 32-bit program sees processors 0 to 31 of a group, ADR 0022 B6).
    pub bitness: Bitness,
    /// Steam's launch entry.
    pub start: AdvancedStart,
    /// The method without the user's choice: the Topo's.
    pub default_method: ManualMethod,
    /// The anti-cheat rule applies (`watch` and flags are refused, `direct` is warned).
    pub anti_cheat: bool,
    /// The live profile holds a `run` (an option value starts another program): `watch` is
    /// refused, and the started program is the effective main executable.
    pub kept_run: bool,
    /// The live change whose launch profile holds a CPU rule or a priority (an own rule or a
    /// fix): an own launch part replaces it (`Warning::ReplacesRule`).
    pub rule_txn: Option<TxnId>,
    /// The compatibility flags Rerun sets (`policy::registry::layers::LAYER_TOKENS`).
    pub tokens: &'static [&'static str],
    /// The own settings a live transaction applied.
    pub live: Option<LiveManual>,
    /// Logical processors of this PC (`None`: the topology is unknown).
    pub logical: Option<u16>,
    /// The values a thread limit steps through on this PC, ascending, each below the number of
    /// logical processors.
    pub steps: Vec<u16>,
    /// The PC has more than one efficiency class: `prefer: performance` selects less.
    pub hybrid: bool,
}

impl AdvancedView {
    /// `exe` is the main executable (folded, as the engine compares): a fix's flags for it and
    /// the user's own flags would be two `compat_layer` steps for one executable.
    pub fn is_main(&self, exe: &RelPath) -> bool {
        self.main_exe
            .as_ref()
            .is_some_and(|m| fold(m.as_str()) == fold(exe.as_str()))
    }

    /// The program the shim starts under `direct` is the main executable: the chosen `start`
    /// (or the Topo's), compared folded as the planner does; a kept `run` is the effective main
    /// executable itself.
    pub fn started_is_main(&self, chosen: Option<&RelPath>) -> bool {
        if self.kept_run {
            return true;
        }
        let start = match (&self.start, chosen) {
            (AdvancedStart::Topo(s), _) => Some(s),
            (AdvancedStart::Choose(_), Some(c)) => Some(c),
            _ => None,
        };
        match (start, &self.main_exe) {
            (Some(s), Some(m)) => fold(s.as_str()) == fold(m.as_str()),
            _ => false,
        }
    }
}

/// The steps of a thread limit on a PC of `logical` logical processors with `cores` physical
/// cores: 1 to 4, then every even number to 16, every multiple of 4 above it, the core count and
/// one processor less than the PC has (the usual "leave one for the system"), each below
/// `logical`, ascending.
pub fn thread_steps(logical: u16, cores: u16) -> Vec<u16> {
    (1..logical)
        .filter(|n| {
            *n <= 4 || (*n <= 16 && n % 2 == 0) || n % 4 == 0 || *n == cores || *n + 1 == logical
        })
        .collect()
}

/// The steps for a PC whose topology is unknown: the usual small numbers.
const UNKNOWN_STEPS: &[u16] = &[1, 2, 4, 6, 8, 12, 16, 24];

fn topology_facts(cpu: Option<&CpuTopology>) -> (Option<u16>, Vec<u16>, bool) {
    let Some(t) = cpu else {
        return (None, UNKNOWN_STEPS.to_vec(), false);
    };
    let logical = u16::try_from(t.cpus.len()).unwrap_or(u16::MAX);
    let mut cores: Vec<u32> = t.cpus.iter().map(|c| c.core).collect();
    cores.sort_unstable();
    cores.dedup();
    let cores = u16::try_from(cores.len()).unwrap_or(u16::MAX);
    let hybrid = t
        .cpus
        .iter()
        .any(|c| c.efficiency_class != t.cpus[0].efficiency_class);
    (Some(logical), thread_steps(logical, cores), hybrid)
}

/// The Advanced section's view of a matched game (crate-internal behind [`super::game`]).
pub(crate) fn advanced(
    report: &OwnedReport,
    game: &GameFacts,
    cpu: Option<&CpuTopology>,
    live: &Result<LiveState, LiveError>,
) -> AdvancedView {
    let manual_method = |m: MethodSpec| match m {
        MethodSpec::Watch => ManualMethod::Watch,
        _ => ManualMethod::Direct,
    };
    let (start, default_method) = match &report.launch {
        Ok(lp) => (
            AdvancedStart::Topo(lp.start.clone()),
            manual_method(lp.method),
        ),
        Err(p @ LaunchProblem::NotYet(_)) => (AdvancedStart::Unavailable(*p), ManualMethod::Direct),
        Err(LaunchProblem::NoMethod | LaunchProblem::NoStart) => {
            let mut exes: Vec<RelPath> = Vec::new();
            for e in game.matched_exes() {
                if !exes.contains(&e.path) {
                    exes.push(e.path.clone());
                }
            }
            (
                AdvancedStart::Choose(exes),
                manual_method(method_without_start(&report.topo)),
            )
        }
    };
    let state = live.as_ref().ok();
    let (logical, steps, hybrid) = topology_facts(cpu);
    AdvancedView {
        main_exe: report.main_exe.clone(),
        bitness: match game.main_arch() {
            Some(Arch::X86) => Bitness::X86,
            _ => Bitness::X64,
        },
        start,
        default_method,
        anti_cheat: report.anti_cheat.enforced(),
        kept_run: state
            .and_then(|s| s.profile.as_ref())
            .is_some_and(|p| p.profile.run.is_some()),
        rule_txn: state
            .and_then(|s| s.profile.as_ref())
            .filter(|p| p.profile.cpu.is_some() || p.profile.priority.is_some())
            .map(|p| p.txn),
        tokens: LAYER_TOKENS,
        live: state.and_then(|s| s.manual.clone()),
        logical,
        steps,
        hybrid,
    }
}

/// The CPU topology of this PC, read for the live readout; the reason (raw text) when it cannot
/// be read. The caller reads it once per session.
pub fn cpu_topology(g: &Guarded<'_>) -> Result<CpuTopology, String> {
    g.env().sys.topology().read().map_err(|e| e.to_string())
}

/// What the rule `rule` selects on this PC for a program of `bitness` (the readout, never part
/// of the plan): `topo` as [`cpu_topology`] read it.
pub fn rule_view(
    topo: &Result<CpuTopology, String>,
    rule: &CpuRuleSpec,
    bitness: Bitness,
) -> MachineView {
    rule_on_this_machine(topo.as_ref().map_err(String::as_str), rule, bitness)
}
