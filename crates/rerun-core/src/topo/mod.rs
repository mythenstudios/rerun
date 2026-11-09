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
//!   warns per step kind; `package` waits for P4-7. A `cpu` step becomes the one `launch_method`
//!   step: the Topo's method (`auto` is `direct` when the chain is exactly `[steam]`, else
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
use crate::catalog::model::{Chain, Exe, Issue, Method, Status, Topo, TopoStep, Variant, When};
use crate::detect::exe::anti_cheat;
use crate::detect::exe::{
    AntiCheat, AntiCheatScan, ExeError, HashLimits, HashOutcome, inspect_exe,
};
use crate::detect::pe::{self, PeReadError};
use crate::hw::{GpuArchTable, SystemProfile};
use crate::path::RelPath;
use crate::plan::{MAX_PICKS, Pick, Plan, PlanError, PlanSource};
use crate::policy::root::GameDir;
use crate::prim::{self, LaunchMethodSpec, MethodSpec, PlanCtx, Step};
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
        self.exes
            .iter()
            .find(|e| e.state == ExeState::Match)
            .map(|e| &e.path)
    }
}

/// Reads what the engine needs of the game folder (module docs).
pub fn read_game(game: &GameDir<'_>, topo: &Topo) -> GameFacts {
    let exes = topo
        .matches
        .exes
        .iter()
        .map(|e| ExeCheck {
            path: e.path.clone(),
            state: check_exe(game, e),
        })
        .collect();
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
    GameFacts {
        exes,
        anti_cheat: anti_cheat::find(game, &dirs),
    }
}

fn check_exe(game: &GameDir<'_>, e: &Exe) -> ExeState {
    match inspect_exe(
        game,
        &e.path,
        &pe::Limits::DEFAULT,
        Some(&HashLimits::DEFAULT),
    ) {
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
                if any && sha256 != Some(false) && sha1 != Some(false) {
                    ExeState::Match
                } else {
                    ExeState::Mismatch
                }
            }
            other => ExeState::Unreadable(other.to_string()),
        },
    }
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
            _ => StepKind::LaunchDirect,
        },
        TopoStep::RegistrySet(_) => StepKind::RegistrySet,
        TopoStep::CompatLayer(_) => StepKind::CompatLayer,
        TopoStep::IniSet(_) => StepKind::IniSet,
    }
}

// ---------- Report ----------

/// Why a variant cannot be planned here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The anti-cheat rule refuses a step of this kind.
    AntiCheat(StepKind),
    /// A step kind the engine cannot plan yet (`package`: P4-7).
    NotYet(StepKind),
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
            Self::NotYet(k) => write!(f, "not yet: {} steps come in a later step", k.as_str()),
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
            (_, StepKind::Package, _) => Some(Refusal::NotYet(k)),
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
    Ok(Report {
        topo,
        main_exe: facts.game.main_exe().cloned(),
        launch,
        anti_cheat: ac,
        issues,
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
    if picks.is_empty() || picks.len() > MAX_PICKS {
        return Err(EngineError::Picks);
    }
    let mut warnings = Vec::new();
    if topo.status == Status::NeedsRetest {
        warnings.push(Warning::NeedsRetest);
    }
    let launch = resolve_launch(topo);
    let ac = anti_cheat_state(topo, &facts.game.anti_cheat);
    let mut steps = Vec::new();
    let mut planned_launch = None;
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
                // Refused by `assess` above.
                TopoStep::Package(_) => {}
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
            }
        }
    }
    let ctx = PlanCtx {
        main_exe: Some(main_exe),
        ..*ctx
    };
    let mut plan = prim::plan(&steps, &ctx)?;
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

#[cfg(test)]
mod tests;
