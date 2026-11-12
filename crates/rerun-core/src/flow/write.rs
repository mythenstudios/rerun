//! The write side of a plan (ADR 0027 amendment P5-2a): plan → the caller shows the preview →
//! [`shown`] → [`store`] → [`check`] → [`apply`]; for a plan stored earlier (`rerun apply
//! <hash>`) [`load_stored`] takes the place of the planning.
//!
//! - [`plan`] (a Topo and the picked variants) and [`plan_steps`] (a step file) read only: the
//!   planners, the one encoding, and the preview and the VirtualStore lookup decoded from exactly
//!   those bytes. Nothing is stored, nothing created.
//! - [`Planned`] holds the bytes privately with the preview built from them; only [`shown`] turns
//!   it into a [`Previewed`], which owns the bytes. The proof types are a naming convention, not
//!   a guarantee (`shown` is free to call): they make "preview, then exactly these bytes" the
//!   convenient and the only path through this API; `apply` takes no plan hash.
//! - [`store`] creates Rerun's folder only now (review S6 of P2-13) and refuses a plan made with
//!   another path of it (`<LocalAppData>` moved meanwhile: a launch profile names that folder by
//!   path, plan §9 of P3-3c). A plan without ops is never stored.
//! - [`check`] and [`apply`] run `exec` on the stored plan of the `Previewed`'s hash: `exec` loads
//!   the bytes by that hash (and accepts them only if they hash to it), so what is applied is
//!   what was shown. `exec` checks everything again under the journal lock.

use crate::catalog::Topo;
use crate::detect::exe::anti_cheat;
use crate::exec::{self, ApplyError, ExecCtx, Outcome, Refusal};
use crate::journal::InstanceTag;
use crate::path::RootPath;
use crate::plan::{self, Pick, PlanBytes, PlanError, PlanHash, Preview};
use crate::policy::registry::RegPolicy;
use crate::policy::root::{AppDir, Create, RootError, Shadow, UserDataDir, preview_with_shadows};
use crate::prim::{self, PlanCtx, StepFile};
use crate::sys::System;
use crate::topo::{self, EngineError, StepKind, Warning};

use super::{GameOpen, GameRefusal, Guarded, Lookup, with_game, with_topo};

/// A plan as encoded, with the preview decoded from exactly its bytes. Stores nothing. Only
/// this module builds one ([`plan`], [`plan_steps`], [`load_stored`]).
#[derive(Debug)]
pub struct Planned {
    bytes: PlanBytes,
    /// The path of Rerun's folder the planners were given (`None`: unknown, or a stored plan).
    app_path: Option<RootPath>,
    /// The preview of the bytes (private: a caller cannot swap it for another plan's).
    preview: Preview,
    /// VirtualStore copies of managed files (P3-7), looked up from the same decode.
    shadows: Vec<Shadow>,
    /// The engine's warnings (a Topo plan; empty otherwise).
    warnings: Vec<Warning>,
}

impl Planned {
    /// The hash of the bytes (the name the plan is stored by).
    pub fn hash(&self) -> PlanHash {
        self.bytes.hash()
    }

    /// The number of ops.
    pub fn ops(&self) -> usize {
        self.preview.ops.len()
    }

    /// The preview, decoded from exactly the bytes.
    pub fn preview(&self) -> &Preview {
        &self.preview
    }

    /// VirtualStore copies of managed files (P3-7), looked up from the same decode.
    pub fn shadows(&self) -> &[Shadow] {
        &self.shadows
    }

    /// The engine's warnings (a Topo plan; empty otherwise).
    pub fn warnings(&self) -> &[Warning] {
        &self.warnings
    }

    fn of(
        sys: &dyn System,
        bytes: PlanBytes,
        app_path: Option<RootPath>,
        warnings: Vec<Warning>,
    ) -> Result<Self, PlanError> {
        // P3-7: the VirtualStore lookup (read only) from the same decode as the preview.
        let (preview, shadows) = preview_with_shadows(sys, &bytes)?;
        Ok(Self {
            bytes,
            app_path,
            preview,
            shadows,
            warnings,
        })
    }
}

/// The bytes whose preview the caller showed (a naming convention, module docs). Owns the
/// bytes, so what is stored and applied is exactly what was shown.
///
/// Only [`shown`] builds one:
///
/// ```compile_fail
/// # fn f(bytes: rerun_core::plan::PlanBytes) {
/// // The fields are private.
/// let p = rerun_core::flow::Previewed { bytes, app_path: None, ops: 1 };
/// # }
/// ```
#[derive(Debug)]
pub struct Previewed {
    bytes: PlanBytes,
    app_path: Option<RootPath>,
    ops: usize,
}

impl Previewed {
    /// The hash of the bytes.
    pub fn hash(&self) -> PlanHash {
        self.bytes.hash()
    }

    /// The number of ops.
    pub fn ops(&self) -> usize {
        self.ops
    }
}

/// The caller rendered `p.preview` (and the shadows and warnings): its bytes may now be stored
/// and applied.
pub fn shown(p: Planned) -> Previewed {
    let ops = p.ops();
    Previewed {
        bytes: p.bytes,
        app_path: p.app_path,
        ops,
    }
}

// ---------- Planning ----------

/// Why the engine or a planner refused the picks of the one Topo that matched.
#[derive(Debug, thiserror::Error)]
pub enum PlanRefusal {
    /// The Topo's folder below the user's `Documents` (P4-12) did not open.
    #[error(transparent)]
    UserData(Box<RootError>),
    /// The engine refused.
    #[error(transparent)]
    Engine(Box<EngineError>),
    /// The plan cannot be encoded or decoded for its preview.
    #[error(transparent)]
    Plan(Box<PlanError>),
}

/// What the picks gave on the one Topo that matched.
#[derive(Debug)]
pub struct Picked {
    /// The Topo.
    pub topo: Topo,
    /// The SHA-256 of the signed index it comes from.
    pub index: [u8; 32],
    /// The plan, or why not.
    pub planned: Result<Planned, PlanRefusal>,
}

/// Plans the variants `picks` of the Topo of `app_id` (`rerun plan <app-id> --pick …`): the
/// lookup of [`super::game`], then on the one Topo that matches the game's folder below
/// `Documents` only if a picked step sets a file there (P4-12), the engine
/// ([`topo::plan`]), the encoding and the preview of the encoded bytes. Stores nothing,
/// creates nothing.
pub fn plan(g: &Guarded<'_>, app_id: u32, picks: &[Pick]) -> Result<Lookup<Picked>, GameRefusal> {
    let sys = g.env().sys;
    with_topo(g, app_id, None, |m| {
        let t = m.topo;
        let index = *m.catalog.sha256();
        let planned = (|| {
            let facts = m.facts();
            let user_data = match &t.user_data {
                Some(u) if topo::needs_user_data(t, picks, m.profile) => Some(
                    UserDataDir::open(sys, g.fr(), u.base(), u.sub())
                        .map_err(|e| PlanRefusal::UserData(Box::new(e)))?,
                ),
                _ => None,
            };
            let ctx = PlanCtx {
                game: m.game,
                app: g.app(),
                steam_app: m.steam_app,
                main_exe: None,
                reg: RegPolicy.reader(sys),
                app_path: m.app_path,
                user_data: user_data.as_ref(),
            };
            let tp = topo::plan(&index, t, &facts, picks, &ctx)
                .map_err(|e| PlanRefusal::Engine(Box::new(e)))?;
            let bytes = tp
                .plan
                .encode()
                .map_err(|e| PlanRefusal::Plan(Box::new(e)))?;
            Planned::of(sys, bytes, m.app_path.cloned(), tp.warnings)
                .map_err(|e| PlanRefusal::Plan(Box::new(e)))
        })();
        Picked {
            topo: t.clone(),
            index,
            planned,
        }
    })
}

/// Why a step file was not planned.
#[derive(Debug)]
pub enum StepsRefusal {
    /// The game folder did not open.
    Game(GameOpen),
    /// The anti-cheat rule, the user data folder or a planner refused.
    Plan(PlanError),
}

/// Plans a step file (`rerun plan <steps.json>`, P2-13; read by the caller): the game folder it
/// names, the anti-cheat rule for every step (user decision E4 of P4-4: a step file has no Topo,
/// so nothing is released as dead), the game's folder below `Documents` only if a step needs it
/// (P4-12), the planners, the encoding and the preview of the encoded bytes. Also returns the
/// step kinds the anti-cheat rule warns about. Stores nothing, creates nothing.
pub fn plan_steps(
    g: &Guarded<'_>,
    sf: &StepFile,
) -> Result<(Planned, Vec<StepKind>), StepsRefusal> {
    let sys = g.env().sys;
    // P3-3c: the path of Rerun's folder without creating it (a launch profile names its
    // profiles root by path); unknown only fails a `launch_method` step.
    let app_path = AppDir::path_of(sys).ok();
    with_game(sys, g.fr(), &sf.game, |game, steam_app| {
        let scan = anti_cheat::find(game, &topo::step_file_dirs(&sf.steps, &sf.main_exe));
        let warned =
            topo::anti_cheat_steps(&sf.steps, &scan).map_err(|r| PlanError::Step(r.to_string()))?;
        // P4-12: the user data folder only if a step needs it (nothing below Documents is
        // touched otherwise); without `user_data` such a step is the planner's refusal.
        let user_data = match &sf.user_data {
            Some(u) if prim::needs_user_data(&sf.steps) => {
                Some(UserDataDir::open(sys, g.fr(), u.base(), u.sub())?)
            }
            _ => None,
        };
        let ctx = PlanCtx {
            game,
            app: g.app(),
            steam_app,
            main_exe: Some(&sf.main_exe),
            reg: RegPolicy.reader(sys),
            app_path: app_path.as_ref(),
            user_data: user_data.as_ref(),
        };
        let bytes = prim::plan(&sf.steps, &ctx)?.encode()?;
        Ok((
            Planned::of(sys, bytes, app_path.clone(), Vec::new())?,
            warned,
        ))
    })
    .map_err(StepsRefusal::Game)?
    .map_err(StepsRefusal::Plan)
}

// ---------- Storing ----------

/// Why a plan was not stored.
#[derive(Debug)]
pub enum StoreRefusal {
    /// The plan has no ops: nothing to store.
    Empty,
    /// Rerun's folder was neither found nor created.
    NoAppDir,
    /// Rerun's folder cannot be opened or created.
    AppDir(Box<RootError>),
    /// Rerun's folder is at another path than the plan was made with.
    AppDirMoved,
    /// The plan cannot be stored.
    Store(PlanError),
}

/// Stores the bytes of `p` as `<AppDir>\plans\<hash>.json` (module docs): Rerun's folder is
/// created only now and kept in `g` for [`check`] and [`apply`]. The same bytes stored already
/// are no change.
pub fn store(g: &mut Guarded<'_>, p: &Previewed) -> Result<PlanHash, StoreRefusal> {
    if p.ops == 0 {
        return Err(StoreRefusal::Empty);
    }
    let sys = g.env().sys;
    // Review S6: Rerun's folder is created only now, right before the plan is stored.
    let app = match g.app.take() {
        Some(a) => a,
        None => match AppDir::open(sys, Create::IfMissing) {
            Ok(Some(a)) => a,
            Ok(None) => return Err(StoreRefusal::NoAppDir),
            Err(e) => return Err(StoreRefusal::AppDir(Box::new(e))),
        },
    };
    let app = g.app.insert(app);
    // Plan §9 (review of P3-3c): a launch profile names Rerun's folder by the path planned
    // with; one that is another now (LocalAppData moved meanwhile) is not stored.
    if p.app_path.as_ref().is_some_and(|x| x != app.path()) {
        return Err(StoreRefusal::AppDirMoved);
    }
    plan::store(app, &p.bytes).map_err(StoreRefusal::Store)
}

/// Why a stored plan was not loaded.
#[derive(Debug)]
pub enum LoadRefusal {
    /// Rerun's folder does not exist: no plan is stored.
    NoAppDir,
    /// The plan is not there, does not hash to its name, or cannot be decoded.
    Plan(PlanError),
}

/// The stored plan `h` (`rerun apply <hash>`) with the preview of exactly its bytes, decoded
/// with the rules in force now as the apply decodes them. Creates nothing.
pub fn load_stored(g: &Guarded<'_>, h: &PlanHash) -> Result<Planned, LoadRefusal> {
    let app = g.app().ok_or(LoadRefusal::NoAppDir)?;
    let bytes = plan::load(app, h).map_err(LoadRefusal::Plan)?;
    Planned::of(g.env().sys, bytes, None, Vec::new()).map_err(LoadRefusal::Plan)
}

// ---------- Applying ----------

/// The stored plan of `p` is missing (Rerun's folder does not exist).
fn not_stored(p: &Previewed) -> Refusal {
    Refusal::Plan(PlanError::NotFound(p.hash()))
}

/// Every check of the apply without writing ([`exec::check`]) on the stored plan of `p`
/// ([`store`] or [`load_stored`] first). `Ok(0)`: nothing to do.
pub fn check(g: &Guarded<'_>, p: &Previewed) -> Result<usize, Refusal> {
    let app = g.app().ok_or_else(|| not_stored(p))?;
    let cx = ExecCtx {
        sys: g.env().sys,
        fr: g.fr(),
        app,
        tag: InstanceTag::new(),
    };
    exec::check(&cx, &p.hash())
}

/// Applies the stored plan of `p` ([`exec::apply`]; [`store`] or [`load_stored`] first). Takes
/// the [`Previewed`], never a plan hash:
///
/// ```compile_fail
/// # fn f(g: &rerun_core::flow::Guarded<'_>, h: rerun_core::plan::PlanHash) {
/// let _ = rerun_core::flow::apply(g, h);
/// # }
/// ```
///
/// The path through the API:
///
/// ```no_run
/// # fn f(mut g: rerun_core::flow::Guarded<'_>, planned: rerun_core::flow::Planned) {
/// // … the caller renders `planned.preview()` …
/// let p = rerun_core::flow::shown(planned);
/// if rerun_core::flow::store(&mut g, &p).is_ok() && rerun_core::flow::check(&g, &p).is_ok() {
///     let _ = rerun_core::flow::apply(&g, p);
/// }
/// # }
/// ```
pub fn apply(g: &Guarded<'_>, p: Previewed) -> Result<Outcome, ApplyError> {
    let app = g.app().ok_or_else(|| not_stored(&p))?;
    let cx = ExecCtx {
        sys: g.env().sys,
        fr: g.fr(),
        app,
        tag: InstanceTag::new(),
    };
    exec::apply(&cx, &p.hash())
}

/// Whether a plan or revert that needs the elevated helper could start it now, and the UAC
/// prompt state the user meets ([`exec::helper_ready`]: the pre-check of the installed helper,
/// then whether Windows allows an elevation). Read only; never a prompt. The app locks a fix or
/// an undo that would be refused anyway and shows the prompt state in the preview (ADR 0023
/// amendment P5-5c); `exec` checks again in the run.
///
/// # Errors
/// The refusal the run would meet before any prompt (`HelperUnsafe`, `NoElevation`, `Elevated`).
pub fn helper(g: &Guarded<'_>) -> Result<crate::elevate::PromptState, Refusal> {
    exec::helper_ready(g.env().sys)
}

#[cfg(test)]
#[path = "write_tests.rs"]
mod tests;
