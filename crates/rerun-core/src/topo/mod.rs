//! The Topo engine (P4-4, ADR 0020 amendment P4-4): from a Topo of the signed index, the
//! system profile and the game folder to a report, and with picked variants to a plan of the
//! existing primitives.
//!
//! - [`read_game`] (reads only, handle-relative): every `match.exes` entry is opened, parsed
//!   and hashed on the very handle that was parsed (`detect::exe::inspect_exe`); a Topo matches
//!   when at least one of them is there with every hash it names (SHA-256 and SHA-1). The main
//!   executable is the first that matches, in the Topo's order. Anti-cheat markers are looked
//!   for in the game folder and the folders of those executables and of `launch.start`.
//! - [`report`] (pure): per issue the `when` result ([`when::eval`]), per variant whether it
//!   can be planned here and what the anti-cheat rule ([`policy`]) says. A report preselects
//!   nothing.
//! - [`plan`] (reads through the planners only): the picked variants, at most one per issue.
//!   `when = no` is refused, `unknown` is planned with a warning; the anti-cheat rule refuses or
//!   warns per step kind. A `package` step (P4-7) becomes the `file_install` step of the
//!   package's files for the main executable's architecture (read from its PE header) and the
//!   Topo's API for it ([`prim::package`]); a package's `requires` must be planned in the same
//!   plan (a file another transaction installed with the same content is held, P4-8); a package
//!   with `supports_exe_sha1` only for a listed build, `requires_gpu` a warning, no two packages
//!   with a DLL at one place (no chainloading, P4-8). The `firewall_rule` steps (P4-2d) become
//!   `FirewallRule` ops after every other op, built only from the anchors of
//!   `elevate::check_plan` (the helper's own derivation on the game folder as read, A4 S7). A `cpu` step becomes the one `launch_method` step: the Topo's method (`auto` is `direct` when the chain is exactly `[steam]`, else
//!   `watch`, L10), its `launch.start`, and its `launch.priority`. The steps go to
//!   [`prim::plan`] unchanged, so the plan has the bytes of a step file with the same steps,
//!   plus [`Plan::source`] (the index's SHA-256, the Topo and the picks).
//!
//! `appinfo.vdf` is not read (L9): `launch.start` comes only from the Topo. `when` is never
//! authorisation; the plan's checks are those of the planners.

pub mod policy;
pub mod when;

use std::fmt;

pub use policy::{ANTI_CHEAT_RULES, AcRule, StepKind, anti_cheat_rule};
pub use when::Tri;

use crate::catalog::Catalog;
use crate::catalog::model::{
    Api, Arch, Chain, Exe, GpuRequirement, Issue, Method, Package, Sha1, Status, Topo, TopoStep,
    Variant, When,
};
use crate::detect::exe::anti_cheat;
use crate::detect::exe::{
    AntiCheat, AntiCheatScan, ExeError, HashLimits, HashOutcome, inspect_exe,
};
use crate::detect::pe::{self, Machine, PeReadError};
use crate::hw::{Fact, GpuArchTable, SacState, SystemProfile};
use crate::path::RelPath;
use crate::plan::{MAX_PICKS, Op, Pick, Plan, PlanError, PlanSource, RootIx};
use crate::policy::root::GameDir;
use crate::prim::{self, GameBuild, LaunchMethodSpec, MethodSpec, PackageRefusal, PlanCtx, Step};
use crate::sys::SysErrorKind;

/// The Topos of the index that name this Steam app, sorted by ID.
pub fn topos_for(catalog: &Catalog, app_id: u32) -> Vec<&Topo> {
    catalog
        .topos()
        .iter()
        .filter(|t| t.matches.steam_appid == Some(app_id))
        .collect()
}

// ---------- The game folder ----------

/// What one executable of `match.exes` is in the game folder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExeState {
    /// There, with every hash the Topo names.
    Match,
    /// There, with another content.
    Mismatch,
    /// Not there.
    Missing,
    /// Could not be opened, parsed or hashed (Rerun's text, may name the file).
    Unreadable(String),
}

/// One executable of `match.exes` checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExeCheck {
    /// The path of the Topo.
    pub path: RelPath,
    /// What it is.
    pub state: ExeState,
    /// Its architecture from the PE header when it matched (`None`: no match, or neither x86
    /// nor x64).
    pub arch: Option<Arch>,
    /// The `api` of this very `match.exes` entry when it matched (`None` otherwise): two
    /// entries may name one path with different builds, so the path alone never says it.
    pub api: Option<Api>,
    /// Its SHA-1, hashed on the handle it was parsed on, when it matched (`None` otherwise; P4-8:
    /// a package's `supports_exe_sha1`). For a file a live transaction patched, the Topo's SHA-1
    /// of the build it was patched from.
    pub sha1: Option<Sha1>,
    /// The file matched as the build a live transaction patched with `laa_patch` (P4-10, R5): the
    /// transaction. `None` for a file that matched by its own hashes.
    pub patched_by: Option<crate::journal::TxnId>,
}

/// What the engine read from the game folder for one Topo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GameFacts {
    /// Every executable of `match.exes`, in the Topo's order.
    pub exes: Vec<ExeCheck>,
    /// Anti-cheat markers.
    pub anti_cheat: AntiCheatScan,
}

impl GameFacts {
    /// At least one executable matches.
    pub fn matched(&self) -> bool {
        self.main_exe().is_some()
    }

    /// The first executable that matches.
    pub fn main_exe(&self) -> Option<&RelPath> {
        self.main().map(|e| &e.path)
    }

    /// The architecture of [`Self::main_exe`].
    pub fn main_arch(&self) -> Option<Arch> {
        self.main().and_then(|e| e.arch)
    }

    /// The Topo's `api` of the entry that matched as [`Self::main_exe`].
    pub fn main_api(&self) -> Option<Api> {
        self.main().and_then(|e| e.api)
    }

    /// The SHA-1 of [`Self::main_exe`].
    pub fn main_sha1(&self) -> Option<&Sha1> {
        self.main().and_then(|e| e.sha1.as_ref())
    }

    fn main(&self) -> Option<&ExeCheck> {
        self.exes.iter().find(|e| e.state == ExeState::Match)
    }
}

/// Reads what the engine needs of the game folder (module docs).
pub fn read_game(game: &GameDir<'_>, topo: &Topo) -> GameFacts {
    read_game_with(game, topo, &[])
}

/// [`read_game`], where a file that one of `patched` (the executables live transactions of this
/// game folder patched, `exec::patched_now`) left matches as the build it was patched from: a
/// `match.exes` entry with a `sha256` equal to the patch's base, at the same path (folded), and
/// the file's SHA-256 the patch's result (P4-10, P4 lead condition R5). Such an entry carries
/// [`ExeCheck::patched_by`]; the elevated helper's derivation never takes it as an anchor.
pub fn read_game_with(
    game: &GameDir<'_>,
    topo: &Topo,
    patched: &[crate::exec::PatchedExe],
) -> GameFacts {
    let exes = topo
        .matches
        .exes
        .iter()
        .map(|e| {
            let (state, arch, sha1, patched_by) = check_exe(game, e, patched);
            let api = (state == ExeState::Match).then_some(e.api);
            ExeCheck {
                path: e.path.clone(),
                state,
                arch,
                api,
                sha1,
                patched_by,
            }
        })
        .collect();
    GameFacts {
        exes,
        anti_cheat: anti_cheat::find(game, &anti_cheat_dirs(topo)),
    }
}

/// The folders the anti-cheat markers are looked for in besides the game folder: those of the
/// executables of `match.exes` and of `launch.start` (also the elevated helper's re-check,
/// ADR 0023 §5 step 6).
pub fn anti_cheat_dirs(topo: &Topo) -> Vec<RelPath> {
    let mut dirs: Vec<RelPath> = topo
        .matches
        .exes
        .iter()
        .filter_map(|e| e.path.parent())
        .collect();
    if let Some(s) = topo
        .launch
        .as_ref()
        .and_then(|l| l.start.as_ref())
        .and_then(RelPath::parent)
    {
        dirs.push(s);
    }
    dirs
}

fn check_exe(
    game: &GameDir<'_>,
    e: &Exe,
    patched: &[crate::exec::PatchedExe],
) -> (
    ExeState,
    Option<Arch>,
    Option<Sha1>,
    Option<crate::journal::TxnId>,
) {
    let r = inspect_exe(
        game,
        &e.path,
        &pe::Limits::DEFAULT,
        Some(&HashLimits::DEFAULT),
    );
    let arch = match &r {
        Ok(f) => match f.info.headers.machine {
            Machine::X86 => Some(Arch::X86),
            Machine::X64 => Some(Arch::X64),
            _ => None,
        },
        Err(_) => None,
    };
    let mut matched_sha1 = None;
    let mut patched_by = None;
    let state = match r {
        Err(ExeError::Pe(PeReadError::Open { source, .. }))
            if source.kind == SysErrorKind::NotFound =>
        {
            ExeState::Missing
        }
        Err(err) => ExeState::Unreadable(err.to_string()),
        Ok(f) => match f.hashes {
            HashOutcome::Done(h) => {
                // Every hash given must agree (a `TODO` never does); the loader requires one.
                let sha256 = e.sha256.as_ref().map(|x| x.to_string() == h.sha256);
                let sha1 = e.sha1.as_ref().map(|x| x.to_string() == h.sha1);
                let any = sha256.is_some() || sha1.is_some();
                // R5: the result of a live patch of the Topo's build counts as that build.
                let derived = e.sha256.as_ref().and_then(|x| x.bytes()).and_then(|base| {
                    let at = crate::fold::fold(e.path.as_str());
                    patched.iter().find(|p| {
                        p.path == at
                            && p.base == *base
                            && crate::wire::hex32::to_string(&p.sha256)
                                .eq_ignore_ascii_case(&h.sha256)
                    })
                });
                if any && sha256 != Some(false) && sha1 != Some(false) {
                    matched_sha1 = Sha1::parse(&h.sha1);
                    ExeState::Match
                } else if let Some(p) = derived {
                    matched_sha1 = e.sha1.clone().filter(|x| !x.is_todo());
                    patched_by = Some(p.txn);
                    ExeState::Match
                } else {
                    ExeState::Mismatch
                }
            }
            other => ExeState::Unreadable(other.to_string()),
        },
    };
    let arch = if state == ExeState::Match { arch } else { None };
    (state, arch, matched_sha1, patched_by)
}

// ---------- Anti-cheat and launch ----------

/// How the anti-cheat rule applies to the game.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AntiCheatState {
    /// No marker found.
    Clear,
    /// The rule applies: the systems found that the Topo does not release, and whether a
    /// marker could not be checked.
    Enforced {
        /// Systems found.
        systems: Vec<AntiCheat>,
        /// A marker could not be checked (counted as found).
        unreadable: bool,
    },
    /// Every system found is released as dead by the Topo (`anti_cheat.dead`).
    Released {
        /// Systems found.
        systems: Vec<AntiCheat>,
    },
}

impl AntiCheatState {
    /// The rule applies.
    pub fn enforced(&self) -> bool {
        matches!(self, Self::Enforced { .. })
    }
}

/// The anti-cheat state of `topo` with what was found.
pub fn anti_cheat_state(topo: &Topo, scan: &AntiCheatScan) -> AntiCheatState {
    if scan.is_clear() {
        return AntiCheatState::Clear;
    }
    let dead = topo.anti_cheat.as_ref().map_or(&[][..], |a| &a.dead[..]);
    let found = scan.systems();
    let live: Vec<AntiCheat> = found
        .iter()
        .copied()
        .filter(|s| !dead.contains(s))
        .collect();
    if live.is_empty() && scan.unreadable.is_empty() {
        AntiCheatState::Released { systems: found }
    } else {
        AntiCheatState::Enforced {
            systems: live,
            unreadable: !scan.unreadable.is_empty(),
        }
    }
}

/// The launch method of a Topo, resolved (L10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchPlan {
    /// `direct` or `watch`.
    pub method: MethodSpec,
    /// Steam's launch entry.
    pub start: RelPath,
    /// It was `auto`.
    pub auto: bool,
}

/// Why a Topo's launch cannot carry a CPU rule here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaunchProblem {
    /// No `launch.method`.
    NoMethod,
    /// `hold`, `ifeo` or `inproc` (later phases).
    NotYet(&'static str),
    /// `launch.start` is missing or `TODO` (a release index has neither).
    NoStart,
}

impl fmt::Display for LaunchProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoMethod => f.write_str("the Topo names no launch method"),
            Self::NotYet(m) => write!(f, "the launch method {m} comes in a later phase"),
            Self::NoStart => f.write_str("the Topo does not name Steam's launch entry"),
        }
    }
}

/// `launch` resolved: `auto` is `direct` when the chain is exactly `[steam]`, else `watch`.
pub fn resolve_launch(topo: &Topo) -> Result<LaunchPlan, LaunchProblem> {
    let l = topo.launch.as_ref().ok_or(LaunchProblem::NoMethod)?;
    let m = l.method.ok_or(LaunchProblem::NoMethod)?;
    let (method, auto) = match m {
        Method::Auto if l.chain == [Chain::Steam] => (MethodSpec::Direct, true),
        Method::Auto => (MethodSpec::Watch, true),
        Method::Direct => (MethodSpec::Direct, false),
        Method::Watch => (MethodSpec::Watch, false),
        Method::Hold => return Err(LaunchProblem::NotYet("hold")),
        Method::Ifeo => return Err(LaunchProblem::NotYet("ifeo")),
        Method::Inproc => return Err(LaunchProblem::NotYet("inproc")),
    };
    let start = l
        .start
        .clone()
        .filter(|s| s.as_str() != crate::catalog::model::TODO)
        .ok_or(LaunchProblem::NoStart)?;
    Ok(LaunchPlan {
        method,
        start,
        auto,
    })
}

/// The kind of a step with the launch as resolved.
fn step_kind(s: &TopoStep, launch: &Result<LaunchPlan, LaunchProblem>) -> StepKind {
    match s {
        TopoStep::Package(_) => StepKind::Package,
        TopoStep::SteamInput(_) => StepKind::SteamInput,
        TopoStep::Cpu(_) => match launch {
            Ok(LaunchPlan {
                method: MethodSpec::Watch,
                ..
            }) => StepKind::LaunchWatch,
            Err(LaunchProblem::NotYet("hold")) => StepKind::LaunchHold,
            Err(LaunchProblem::NotYet("ifeo")) => StepKind::LaunchIfeo,
            Err(LaunchProblem::NotYet(_)) => StepKind::LaunchInproc,
            _ => StepKind::LaunchDirect,
        },
        TopoStep::RegistrySet(_) => StepKind::RegistrySet,
        TopoStep::CompatLayer(_) => StepKind::CompatLayer,
        TopoStep::IniSet(_) => StepKind::IniSet,
        TopoStep::FirewallRule(_) => StepKind::FirewallRule,
        TopoStep::LaaPatch(_) => StepKind::LaaPatch,
        TopoStep::GpuPreference(_) => StepKind::GpuPreference,
    }
}

/// The kind of a step of a step file (E4 holds for every plan source, review follow-up 1).
pub fn prim_step_kind(s: &Step) -> StepKind {
    match s {
        Step::FileInstall(_) => StepKind::Package,
        Step::RegistrySet(_) => StepKind::RegistrySet,
        Step::CompatLayer(_) => StepKind::CompatLayer,
        Step::IniSet(_) => StepKind::IniSet,
        Step::LaaPatch(_) => StepKind::LaaPatch,
        Step::GpuPreference(_) => StepKind::GpuPreference,
        Step::LaunchMethod(l) => match l.method {
            MethodSpec::Watch => StepKind::LaunchWatch,
            // `auto` is refused by the planner; counted as the stricter of its results.
            MethodSpec::Auto => StepKind::LaunchWatch,
            MethodSpec::Direct => StepKind::LaunchDirect,
        },
    }
}

/// The folders a step file's anti-cheat check looks in besides the game folder: those of the
/// main executable and of a `launch_method` start.
pub fn step_file_dirs(steps: &[Step], main_exe: &RelPath) -> Vec<RelPath> {
    let mut dirs: Vec<RelPath> = main_exe.parent().into_iter().collect();
    dirs.extend(steps.iter().filter_map(|s| match s {
        Step::LaunchMethod(l) => l.start.parent(),
        _ => None,
    }));
    dirs
}

/// The anti-cheat rule on the steps of a step file: nothing when `scan` is clear; else the
/// first refused kind as `Err`, or the warned kinds (each once, in step order). A step file
/// has no Topo, so nothing is released as dead.
pub fn anti_cheat_steps(steps: &[Step], scan: &AntiCheatScan) -> Result<Vec<StepKind>, Refusal> {
    let mut warned = Vec::new();
    if scan.is_clear() {
        return Ok(warned);
    }
    for s in steps {
        let k = prim_step_kind(s);
        match anti_cheat_rule(k) {
            AcRule::Refuse => return Err(Refusal::AntiCheat(k)),
            AcRule::Warn if !warned.contains(&k) => warned.push(k),
            _ => {}
        }
    }
    Ok(warned)
}

/// Which Topo of the app is meant (review follow-up 4): retired Topos aside, exactly one that
/// matches.
#[derive(Debug)]
pub enum Selection<'t> {
    /// Exactly one Topo that is not retired matches.
    One(&'t Topo, GameFacts),
    /// None matches; every Topo that is not retired with what was read.
    NoMatch(Vec<(&'t Topo, GameFacts)>),
    /// Several match (the index refuses overlapping Topos, so a damaged or foreign index).
    Several(Vec<&'t Topo>),
}

/// Splits `read` (every Topo of the app with what was read for it) into the retired ones and
/// the [`Selection`] among the others.
pub fn select<'t>(read: Vec<(&'t Topo, GameFacts)>) -> (Vec<&'t Topo>, Selection<'t>) {
    let (retired, live): (Vec<_>, Vec<_>) = read
        .into_iter()
        .partition(|(t, _)| t.status == Status::Retired);
    let retired = retired.into_iter().map(|(t, _)| t).collect();
    let matched = live.iter().filter(|(_, g)| g.matched()).count();
    let sel = match matched {
        0 => Selection::NoMatch(live),
        1 => match live.into_iter().find(|(_, g)| g.matched()) {
            Some((t, g)) => Selection::One(t, g),
            None => Selection::NoMatch(Vec::new()),
        },
        _ => Selection::Several(
            live.into_iter()
                .filter(|(_, g)| g.matched())
                .map(|(t, _)| t)
                .collect(),
        ),
    };
    (retired, sel)
}

// ---------- Report ----------

/// Why a variant cannot be planned here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The anti-cheat rule refuses a step of this kind.
    AntiCheat(StepKind),
    /// A `cpu` step, but the Topo's launch cannot carry it.
    Launch(LaunchProblem),
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AntiCheat(k) => write!(
                f,
                "refused: anti-cheat found, no {} for this game",
                k.as_str()
            ),
            Self::Launch(p) => write!(f, "refused: {p}"),
        }
    }
}

/// What the engine says about one variant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VariantReport<'t> {
    /// The variant.
    pub variant: &'t Variant,
    /// Why it cannot be planned here (the first refused step).
    pub refused: Option<Refusal>,
    /// Step kinds the anti-cheat rule warns about.
    pub warned: Vec<StepKind>,
}

/// What the engine says about one issue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssueReport<'t> {
    /// The issue.
    pub issue: &'t Issue,
    /// Its `when` on this system.
    pub when: Tri,
    /// Its variants.
    pub variants: Vec<VariantReport<'t>>,
}

/// The engine's report of one Topo for one game (preselects nothing).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report<'t> {
    /// The Topo.
    pub topo: &'t Topo,
    /// The executable that identifies the game (the first that matches).
    pub main_exe: Option<RelPath>,
    /// The launch, resolved.
    pub launch: Result<LaunchPlan, LaunchProblem>,
    /// The anti-cheat rule.
    pub anti_cheat: AntiCheatState,
    /// Every issue.
    pub issues: Vec<IssueReport<'t>>,
    /// The system has several hardware adapters and an issue has a GPU condition: the report
    /// says that GPU conditions are unknown where the adapters differ (P4-11, E-G2 d).
    pub several_gpus: bool,
}

/// What the engine works with.
#[derive(Debug, Clone, Copy)]
pub struct Facts<'a> {
    /// The system profile (`hw::read` with `table`).
    pub profile: &'a SystemProfile,
    /// The architecture table the profile was read with (ADR 0015 pairing).
    pub table: Option<&'a GpuArchTable>,
    /// The game folder.
    pub game: &'a GameFacts,
    /// The packages of the signed index the Topo comes from (sorted by ID).
    pub packages: &'a [Package],
}

fn assess(
    v: &Variant,
    launch: &Result<LaunchPlan, LaunchProblem>,
    ac: &AntiCheatState,
) -> (Option<Refusal>, Vec<StepKind>) {
    let mut refused = None;
    let mut warned = Vec::new();
    for s in &v.steps {
        let k = step_kind(s, launch);
        let r = if ac.enforced() {
            anti_cheat_rule(k)
        } else {
            AcRule::None
        };
        let why = match (r, k, s) {
            (AcRule::Refuse, ..) => Some(Refusal::AntiCheat(k)),
            // P4-13: Smart App Control no longer refuses `laa_patch`; the plan warns
            // (`Warning::SmartAppControl`).
            (_, _, TopoStep::Cpu(_)) => launch.as_ref().err().map(|p| Refusal::Launch(*p)),
            _ => None,
        };
        if refused.is_none() {
            refused = why;
        }
        if r == AcRule::Warn && !warned.contains(&k) {
            warned.push(k);
        }
    }
    (refused, warned)
}

/// Why the engine refuses a Topo or a pick.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum EngineError {
    /// A `gpu.arch` the paired table does not declare (ADR 0015).
    #[error("Topo {topo}: gpu.arch names {arch}, which the architecture table does not declare")]
    UndeclaredArch {
        /// The Topo.
        topo: String,
        /// The identifier.
        arch: String,
    },
    /// No executable of `match.exes` is there with its hashes.
    #[error("Topo {0}: no executable of the game folder matches its hashes")]
    NoMatch(String),
    /// The Topo is retired.
    #[error("Topo {0} is retired and offers no fixes")]
    Retired(String),
    /// No variant picked, or too many.
    #[error("pick 1 to {MAX_PICKS} variants as <issue>/<variant>")]
    Picks,
    /// No such issue.
    #[error("the Topo has no issue {0}")]
    UnknownIssue(String),
    /// No such variant.
    #[error("issue {issue} has no variant {variant}")]
    UnknownVariant {
        /// The issue.
        issue: String,
        /// The variant.
        variant: String,
    },
    /// Two variants of one issue.
    #[error("issue {0} is picked twice: one variant per issue")]
    TwoVariants(String),
    /// `when` is no on this system.
    #[error("issue {0} does not apply to this system (its conditions are not met)")]
    WhenNo(String),
    /// The variant cannot be planned here.
    #[error("{issue}/{variant}: {why}")]
    Refused {
        /// The issue.
        issue: String,
        /// The variant.
        variant: String,
        /// Why.
        why: Refusal,
    },
    /// Two picked variants each bring a CPU rule (one launch profile per game).
    #[error("two picked variants bring a CPU rule; pick one of them")]
    TwoCpuRules,
    /// The planners refused.
    #[error(transparent)]
    Plan(#[from] PlanError),
    /// The firewall rules of the picked variants cannot be planned here (A4 S7, P4-2d).
    #[error(transparent)]
    Firewall(Box<crate::elevate::PlanRefusal>),
    /// A `laa_patch` step cannot be planned for this game (P4-10).
    #[error("laa_patch of {exe}: {why}")]
    LaaPatch {
        /// The executable (escaped).
        exe: String,
        /// Why.
        why: &'static str,
    },
    /// A package step cannot be planned for this game (P4-7).
    #[error("package {id}: {why}")]
    Package {
        /// The package ID.
        id: String,
        /// Why.
        why: String,
    },
    /// A picked step sets a file in the Topo's user data folder (P4-12), but the folder the
    /// caller opened is not that folder (or none): the caller opens it with
    /// [`needs_user_data`] and the Topo's `user_data`.
    #[error("the picked variants need the Topo's user data folder, opened as the Topo names it")]
    UserData,
}

/// A picked variant of `topo` sets a file in its user data folder (P4-12): the caller opens
/// `topo.user_data` (`policy::root::UserDataDir`) for [`plan`] then, and only then (review N5:
/// after the picks resolve; picks that do not resolve need nothing, `plan` refuses them, and an
/// issue whose `when` is no on `profile` needs nothing either).
pub fn needs_user_data(topo: &Topo, picks: &[Pick], profile: &SystemProfile) -> bool {
    let Ok(resolved) = resolve_picks(topo, picks) else {
        return false;
    };
    resolved.iter().any(|(issue, v)| {
        when::eval(issue.when.as_ref(), profile) != Tri::No
            && v.steps.iter().any(|s| s.root() == prim::StepRoot::UserData)
    })
}

/// Every `gpu.arch` of the Topo is declared by `table` (none to check without a table).
fn check_archs(topo: &Topo, table: Option<&GpuArchTable>) -> Result<(), EngineError> {
    let Some(table) = table else {
        return Ok(());
    };
    let archs = topo
        .issues
        .iter()
        .filter_map(|i| i.when.as_ref())
        .filter_map(|w: &When| w.gpu_arch.as_ref())
        .flatten();
    for a in archs {
        if !table.declares(a.id()) {
            return Err(EngineError::UndeclaredArch {
                topo: topo.id.to_string(),
                arch: a.id().as_str().to_owned(),
            });
        }
    }
    Ok(())
}

/// The report of `topo` for this game and system (module docs).
pub fn report<'t>(topo: &'t Topo, facts: &Facts<'_>) -> Result<Report<'t>, EngineError> {
    check_archs(topo, facts.table)?;
    let launch = resolve_launch(topo);
    let ac = anti_cheat_state(topo, &facts.game.anti_cheat);
    let issues = topo
        .issues
        .iter()
        .map(|issue| IssueReport {
            issue,
            when: when::eval(issue.when.as_ref(), facts.profile),
            variants: issue
                .variants
                .iter()
                .map(|variant| {
                    let (refused, warned) = assess(variant, &launch, &ac);
                    VariantReport {
                        variant,
                        refused,
                        warned,
                    }
                })
                .collect(),
        })
        .collect();
    let several_gpus = facts.profile.gpu_hybrid() == Fact::Known(true)
        && topo
            .issues
            .iter()
            .filter_map(|i| i.when.as_ref())
            .any(when::has_gpu_block);
    Ok(Report {
        topo,
        main_exe: facts.game.main_exe().cloned(),
        launch,
        anti_cheat: ac,
        issues,
        several_gpus,
    })
}

// ---------- Plan ----------

/// Something the user should know about a planned Topo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Warning {
    /// The Topo is to be tested again.
    NeedsRetest,
    /// A picked issue's `when` is unknown on this system.
    WhenUnknown {
        /// The issue.
        issue: String,
    },
    /// The anti-cheat rule warns about a step.
    AntiCheat {
        /// The issue.
        issue: String,
        /// The variant.
        variant: String,
        /// The step kind.
        step: StepKind,
    },
    /// `steam_input: enable`: a hint, Rerun changes nothing.
    SteamInput {
        /// The issue.
        issue: String,
    },
    /// `laa_patch` while Smart App Control is not off (P4-13, which replaced the refusal of
    /// P4-10): it decides per file whether the patched executable may run; if it blocks it, the
    /// revert restores the original file bit for bit. Once per plan.
    SmartAppControl {
        /// The state read (`Enforce`, `Evaluation` or `Unknown`).
        state: SacState,
    },
    /// `laa_patch` of an executable whose DOS stub carries a Valve header while Smart App
    /// Control is not off (P4-13): Steam likely built it for this user, so the patched copy is
    /// unknown to Smart App Control and likely to be blocked sooner or later.
    SteamPerUserExe {
        /// The executable.
        exe: RelPath,
    },
    /// `laa_patch` of an executable with an Authenticode signature (P4-10): the patch makes the
    /// signature invalid.
    SignedExe {
        /// The executable.
        exe: RelPath,
    },
    /// A `gpu_preference` step plans nothing: the executable's preference is High performance
    /// already (P4-11, N2), set by the open Rerun transaction `by` if one did.
    GpuPreferenceSet {
        /// The executable.
        exe: RelPath,
        /// The open transaction that set it.
        by: Option<crate::journal::TxnId>,
    },
    /// A planned package needs a GPU feature Rerun does not check (`requires_gpu`, P4-8): v1
    /// `vulkan`, a Vulkan driver for the game's adapter.
    RequiresGpu {
        /// The package.
        package: String,
        /// What it needs.
        needs: GpuRequirement,
    },
}

/// A plan of a Topo with what the user should know.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TopoPlan {
    /// The plan, with [`Plan::source`].
    pub plan: Plan,
    /// The steps given to the planners (the same as in a step file).
    pub steps: Vec<Step>,
    /// The launch, if a `cpu` step was planned.
    pub launch: Option<LaunchPlan>,
    /// Warnings, in pick order.
    pub warnings: Vec<Warning>,
}

/// The picked variants of `topo` with their issues, in pick order, by the engine's pure rules:
/// 1 to [`MAX_PICKS`] picks, each issue once, every issue and variant present. `when` is not
/// evaluated here (the elevated helper re-derives with this and nothing of the system profile,
/// ADR 0023 §5 step 3).
///
/// # Errors
/// [`EngineError::Picks`], [`EngineError::TwoVariants`], [`EngineError::UnknownIssue`],
/// [`EngineError::UnknownVariant`].
pub fn resolve_picks<'t>(
    topo: &'t Topo,
    picks: &[Pick],
) -> Result<Vec<(&'t Issue, &'t Variant)>, EngineError> {
    if picks.is_empty() || picks.len() > MAX_PICKS {
        return Err(EngineError::Picks);
    }
    let mut out = Vec::with_capacity(picks.len());
    for (i, p) in picks.iter().enumerate() {
        if picks[..i].iter().any(|q| q.issue == p.issue) {
            return Err(EngineError::TwoVariants(p.issue.clone()));
        }
        let issue = topo
            .issues
            .iter()
            .find(|x| x.id.as_str() == p.issue)
            .ok_or_else(|| EngineError::UnknownIssue(p.issue.clone()))?;
        let variant = issue
            .variants
            .iter()
            .find(|v| v.id.as_str() == p.variant)
            .ok_or_else(|| EngineError::UnknownVariant {
                issue: p.issue.clone(),
                variant: p.variant.clone(),
            })?;
        out.push((issue, variant));
    }
    Ok(out)
}

/// Plans the picked variants of `topo` (module docs). `index` is the SHA-256 of the signed
/// index the Topo comes from; `ctx` is the planners' context without a main executable (the
/// engine names the one that matched).
pub fn plan(
    index: &[u8; 32],
    topo: &Topo,
    facts: &Facts<'_>,
    picks: &[Pick],
    ctx: &PlanCtx<'_>,
) -> Result<TopoPlan, EngineError> {
    check_archs(topo, facts.table)?;
    if topo.status == Status::Retired {
        return Err(EngineError::Retired(topo.id.to_string()));
    }
    let Some(main_exe) = facts.game.main_exe() else {
        return Err(EngineError::NoMatch(topo.id.to_string()));
    };
    let resolved = resolve_picks(topo, picks)?;
    let mut warnings = Vec::new();
    if topo.status == Status::NeedsRetest {
        warnings.push(Warning::NeedsRetest);
    }
    let launch = resolve_launch(topo);
    let ac = anti_cheat_state(topo, &facts.game.anti_cheat);
    let mut steps = Vec::new();
    let mut planned_launch = None;
    let mut rules = false;
    let mut rule_exes: Vec<String> = Vec::new();
    let mut planned_packages: Vec<&Package> = Vec::new();
    for (p, (issue, variant)) in picks.iter().zip(resolved) {
        match when::eval(issue.when.as_ref(), facts.profile) {
            Tri::No => return Err(EngineError::WhenNo(p.issue.clone())),
            Tri::Unknown => warnings.push(Warning::WhenUnknown {
                issue: p.issue.clone(),
            }),
            Tri::Yes => {}
        }
        let (refused, warned) = assess(variant, &launch, &ac);
        if let Some(why) = refused {
            return Err(EngineError::Refused {
                issue: p.issue.clone(),
                variant: p.variant.clone(),
                why,
            });
        }
        warnings.extend(warned.into_iter().map(|step| Warning::AntiCheat {
            issue: p.issue.clone(),
            variant: p.variant.clone(),
            step,
        }));
        for s in &variant.steps {
            match s {
                TopoStep::Package(id) => {
                    let (pkg, spec) = package_step(facts, id.as_str())?;
                    if !planned_packages.iter().any(|q| q.id == pkg.id) {
                        planned_packages.push(pkg);
                        steps.push(Step::FileInstall(spec));
                    }
                }
                // Planned below from `elevate::check_plan` (the helper's own derivation).
                TopoStep::FirewallRule(f) => {
                    rules = true;
                    rule_exes.push(crate::fold::fold(f.exe.as_str()));
                }
                TopoStep::SteamInput(_) => warnings.push(Warning::SteamInput {
                    issue: p.issue.clone(),
                }),
                TopoStep::Cpu(cpu) => {
                    let Ok(lp) = &launch else { continue };
                    if planned_launch.is_some() {
                        return Err(EngineError::TwoCpuRules);
                    }
                    planned_launch = Some(lp.clone());
                    steps.push(Step::LaunchMethod(LaunchMethodSpec {
                        method: lp.method,
                        start: lp.start.clone(),
                        cpu: Some(*cpu),
                        priority: topo.launch.as_ref().and_then(|l| l.priority),
                    }));
                }
                TopoStep::RegistrySet(r) => steps.push(Step::RegistrySet(r.clone())),
                TopoStep::CompatLayer(c) => steps.push(Step::CompatLayer(c.clone())),
                TopoStep::IniSet(x) => steps.push(Step::IniSet(x.clone())),
                // Two picks for one executable: the planner refuses the second step.
                TopoStep::GpuPreference(g) => steps.push(Step::GpuPreference(g.clone())),
                TopoStep::LaaPatch(l) => {
                    let spec = laa_step(topo, facts, l)?;
                    // P4-13: warned, never refused (the user's decision of 2026-11-11).
                    let sac = facts.profile.sac;
                    if sac != SacState::Off
                        && !warnings
                            .iter()
                            .any(|w| matches!(w, Warning::SmartAppControl { .. }))
                    {
                        warnings.push(Warning::SmartAppControl { state: sac });
                    }
                    // Once per executable (two picks may patch the same one).
                    if !steps
                        .iter()
                        .any(|s| matches!(s, Step::LaaPatch(x) if x.exe == spec.exe))
                    {
                        // The planner checks everything again; a refusal here is its refusal
                        // there.
                        if let Ok(f) = prim::laa_patch::inspect(ctx.game, &spec.exe) {
                            if f.valve_stub && sac != SacState::Off {
                                warnings.push(Warning::SteamPerUserExe {
                                    exe: spec.exe.clone(),
                                });
                            }
                            if f.signed {
                                warnings.push(Warning::SignedExe {
                                    exe: spec.exe.clone(),
                                });
                            }
                        }
                        steps.push(Step::LaaPatch(spec));
                    }
                }
            }
        }
    }
    // A package's shared dependencies come with it in this plan; a file another transaction
    // installed with the same content becomes a `Hold` of this plan (P4-8, `prim::file_install`).
    for p in &planned_packages {
        if let Some(r) = p
            .requires
            .iter()
            .find(|r| !planned_packages.iter().any(|q| q.id == **r))
        {
            return Err(EngineError::Package {
                id: p.id.to_string(),
                why: format!(
                    "it needs package {r}; pick a variant that installs it in the same plan"
                ),
            });
        }
        for needs in &p.requires_gpu {
            warnings.push(Warning::RequiresGpu {
                package: p.id.to_string(),
                needs: *needs,
            });
        }
    }
    // P4-10 review: a rule for the executable a patch changes in the same plan would fail the
    // helper's hash check after the prompt. The rule binds the executable by its path and only
    // its add hashes it, so the rule first (its own plan), then the patch, works.
    for s in &steps {
        if let Step::LaaPatch(x) = s
            && rule_exes.contains(&crate::fold::fold(x.exe.as_str()))
        {
            return Err(EngineError::LaaPatch {
                exe: crate::escape::path(x.exe.as_str()).into_owned().to_string(),
                why: "a picked firewall_rule blocks the same executable; plan and apply the \
                      firewall rule on its own first, then laa_patch in a second plan",
            });
        }
    }
    slots_free(&steps, &planned_packages)?;
    // P4-12: the user data folder the caller opened is the Topo's (base and folder as named).
    if prim::needs_user_data(&steps) {
        let same = match (&topo.user_data, ctx.user_data) {
            (Some(spec), Some(u)) => u.base() == spec.base() && u.sub() == spec.sub(),
            _ => false,
        };
        if !same {
            return Err(EngineError::UserData);
        }
    }
    let ctx = PlanCtx {
        main_exe: Some(main_exe),
        ..*ctx
    };
    let mut plan = prim::plan(&steps, &ctx)?;
    // N2 (P4-11): a preference that is set already plans no op; the user is told, and by which
    // open transaction if Rerun's.
    for a in prim::gpu_preference::already_set(&steps, &plan, &ctx) {
        warnings.push(Warning::GpuPreferenceSet {
            exe: a.exe,
            by: a.by,
        });
    }
    // P4-2d (ADR 0023 §9, A4 S7): the firewall rules last, built only from the anchors of the
    // derivation the helper repeats, on the game folder as read here.
    if rules {
        let anchors = crate::elevate::check_plan(topo, picks, ctx.game.info(), facts.game)
            .map_err(|e| EngineError::Firewall(Box::new(e)))?;
        plan.ops
            .extend(anchors.into_iter().map(|a| Op::FirewallRule {
                root: RootIx(0),
                program: a.exe,
                direction: a.direction,
            }));
    }
    plan.source = Some(PlanSource {
        index: *index,
        topo: topo.id.to_string(),
        rev: topo.rev,
        picks: picks.to_vec(),
    });
    // The bounds and the source's form, as when stored and applied.
    plan.encode()?;
    Ok(TopoPlan {
        plan,
        steps,
        launch: planned_launch,
        warnings,
    })
}

/// A `laa_patch` step (P4-10): the executable is the `match.exes` entry in exactly the step's
/// spelling (the loader's rule, ADR 0024), it matched here, and its `sha256` is what the planner
/// checks the file against; the path and hash come from the entry, never from the step.
fn laa_step(
    topo: &Topo,
    facts: &Facts<'_>,
    l: &crate::catalog::model::LaaPatchStep,
) -> Result<prim::LaaPatchSpec, EngineError> {
    let refused = |why: &'static str| EngineError::LaaPatch {
        exe: crate::escape::path(l.exe.as_str()).into_owned().to_string(),
        why,
    };
    // Two builds may share the path (review S2): the entry of exactly this spelling that matched.
    let mut same = topo
        .matches
        .exes
        .iter()
        .zip(&facts.game.exes)
        .filter(|(e, _)| e.path.same_spelling(&l.exe))
        .peekable();
    if same.peek().is_none() {
        return Err(refused("it is no executable of the Topo's match.exes"));
    }
    let (entry, check) = same
        .find(|(_, c)| c.state == ExeState::Match)
        .ok_or_else(|| {
            refused("it is not a build the Topo names in this game folder (its hashes differ)")
        })?;
    if check.patched_by.is_some() {
        return Err(refused(
            "a Rerun transaction has patched it already; revert that one first",
        ));
    }
    let sha256 = entry
        .sha256
        .as_ref()
        .and_then(|h| h.bytes())
        .ok_or_else(|| refused("its match.exes entry names no sha256"))?;
    Ok(prim::LaaPatchSpec {
        exe: entry.path.clone(),
        sha256: *sha256,
    })
}

/// A `package` step: the package of the index and its `file_install` step for this game.
fn package_step<'p>(
    facts: &Facts<'p>,
    id: &str,
) -> Result<(&'p Package, prim::FileInstallSpec), EngineError> {
    let refused = |why: String| EngineError::Package {
        id: id.to_owned(),
        why,
    };
    let p = facts
        .packages
        .iter()
        .find(|p| p.id.as_str() == id)
        .ok_or_else(|| refused("not in the signed index".to_owned()))?;
    let api = facts
        .game
        .main_api()
        .ok_or_else(|| refused("the main executable has no API (internal)".to_owned()))?;
    let build = GameBuild {
        arch: facts.game.main_arch(),
        api,
    };
    // P4-8: a package that names the builds it supports is planned only for one of them.
    if !p.supports_exe_sha1.is_empty()
        && facts
            .game
            .main_sha1()
            .is_none_or(|h| !p.supports_exe_sha1.contains(h))
    {
        return Err(refused(
            "it does not list this build of the game (its SHA-1) in supports_exe_sha1".to_owned(),
        ));
    }
    let spec = prim::package::file_install(p, &build)
        .map_err(|e: PackageRefusal| refused(e.to_string()))?;
    Ok((p, spec))
}

/// Slot conflicts inside one plan (P4-8): no two packages of the plan put a DLL (a slot, bound
/// by the loader) at the same place of the game folder. Rerun has no chainloading: one DLL of a
/// name per folder is loaded, so two packages that both need it are refused, whichever comes
/// first. Conflicts with open transactions are the planner's (`prim::file_install`, from their
/// heads), and `exec` checks them again before an apply.
fn slots_free(steps: &[Step], packages: &[&Package]) -> Result<(), EngineError> {
    let mut taken: Vec<(String, &str)> = Vec::new();
    for s in steps {
        let Step::FileInstall(spec) = s else { continue };
        let Some(p) = packages.iter().find(|p| p.id.as_str() == spec.package) else {
            continue;
        };
        for f in spec
            .files
            .iter()
            .filter(|f| crate::catalog::check::is_dll(&f.to))
        {
            let at = crate::fold::fold(f.to.as_str());
            if let Some((_, other)) = taken.iter().find(|(t, o)| *t == at && *o != p.id.as_str()) {
                return Err(EngineError::Package {
                    id: p.id.to_string(),
                    why: format!(
                        "its DLL {} is the slot of package {other} too; one of them only \
                         (Rerun does not chainload DLLs)",
                        crate::escape::path(f.to.as_str())
                    ),
                });
            }
            taken.push((at, p.id.as_str()));
        }
    }
    Ok(())
}

#[cfg(test)]
mod gpu_tests;
#[cfg(test)]
mod laa_tests;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod user_data_tests;
