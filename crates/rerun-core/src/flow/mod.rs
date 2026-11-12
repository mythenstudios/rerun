//! Typed flows shared by the CLI and the app (ADR 0027): the order of the existing calls
//! (`exec`, `plan`, `topo`, `catalog`, `detect`) as the CLI runs them, with typed results. No
//! user-facing text, never a question: the CLI renders these values through its `messages`,
//! the app through its view models. `flow` decides nothing the core does not already decide.
//!
//! Read side (P5-1):
//! - the guards: [`guard`] (elevation, then the forbidden roots, then Rerun's folder opened if
//!   it exists, never created), and its parts [`forbidden_roots`] and [`open_app`] for the
//!   CLI's read commands, which run elevated and need only one of them;
//! - [`index_state`]: the current signed index, none, or why it is refused;
//! - [`library`]: the Steam libraries and every listed app, streamed row by row;
//! - [`game`]: one app's Topo, the engine's report and its fixes grouped by variant ID
//!   ([`Fix`]); [`with_topo`] is the same lookup with a closure (behind [`plan`] since P5-2a);
//! - [`status`]: the journal, the launch results, the profile holders and the orphaned firewall
//!   rules.
//!
//! Write side (P5-2a, [`write`]): [`plan`] (a Topo and the picked variants) and [`plan_steps`]
//! (a step file) read only and give a [`Planned`]; the caller shows its preview and calls
//! [`shown`]; [`store`] creates Rerun's folder only then; [`load_stored`] reads a stored plan
//! back; [`check`] and [`apply`] run `exec` on the stored bytes of the [`Previewed`]; [`helper`]
//! says before the click whether a run that needs the elevated helper could start it, with the
//! UAC prompt state (P5-5c).
//!
//! Revert, rebind and forget (P5-2b, `flow/revert.rs`): [`revert_preview`],
//! [`rebind_preview`] and [`forget_preview`] run every check read only and give what the caller
//! shows with a token ([`RevertShown`], [`RebindShown`], [`ForgetShown`]) that carries digests of
//! it; [`revert`], [`rebind`] and [`forget`] take only the token, observe again under the journal
//! lock and write nothing when it differs ([`ActError::Changed`]).
//!
//! Packages (P5-5b, `flow/packages.rs`): [`need`] says what a fix's package is (the list a user
//! consents to) and whether it is unpacked; [`fetch`] downloads, verifies and unpacks it with
//! progress and cancellation, only for the list that was shown.
//!
//! A [`Guarded`] is built per job, never kept for a session: Rerun's folder can appear or vanish
//! between two jobs.

use std::path::PathBuf;

use crate::detect::steam::{self, AppState};
use crate::exec::{self, Refusal};
use crate::policy::root::{AppDir, Create, ForbiddenRoots, GameDir, RootError};
use crate::prim::GameRef;
use crate::sys::{Http, System};

mod game;
mod launch;
mod library;
mod packages;
mod revert;
mod status;
mod write;

pub(crate) use game::with_topo;
pub use game::{
    Fix, Found, GameCache, GameRefusal, GameView, IssueView, Lookup, MatchView, Matched,
    OwnedReport, Solved, VariantView, fixes, game, game_cached,
};
pub use launch::{LaunchView, OptionText, launch_view, option_text};
pub use library::{LibraryCounts, LibraryEvent, LibraryFacts, RowScan, failed_games, library};
pub use packages::{
    DownloadNeed, FetchError, FetchKind, Fetched, NeedState, PackageNeed, Progress, fetch, need,
    redirect_hosts,
};
pub use revert::{
    ActError, CleanupAsk, ForgetPreview, ForgetShown, LaunchOption, ProfileFate, RebindShown,
    RebindView, RevertAsk, RevertEnd, RevertGate, RevertOutcome, RevertPreview, RevertShown,
    RevertWould, forget, forget_preview, holding, left_foreign, rebind, rebind_preview, revert,
    revert_preview,
};
pub use status::{Holder, StatusView, head, profile_id_of, profile_of, profile_op, status};
pub use write::{
    LoadRefusal, Picked, PlanRefusal, Planned, Previewed, StepsRefusal, StoreRefusal, apply, check,
    helper, load_stored, plan, plan_steps, shown, store,
};

/// What a job runs against.
#[derive(Clone, Copy)]
pub struct Env<'a> {
    /// The system.
    pub sys: &'a dyn System,
    /// HTTPS, for package downloads only (ADR 0025).
    pub http: &'a dyn Http,
    /// Rerun's install folder (the folder of `rerun.exe`), or why it is unknown.
    pub install: &'a Result<PathBuf, String>,
}

/// Why a guard stops a job before anything else is read.
#[derive(Debug)]
pub enum Gate {
    /// The process runs elevated, or that cannot be determined (user decision E3).
    Elevated(Refusal),
    /// Rerun's install folder is unknown (the text says why).
    InstallUnknown(String),
    /// The forbidden roots cannot be resolved (fail closed).
    Forbidden(Box<RootError>),
    /// Rerun's folder exists but cannot be opened.
    AppDir(Box<RootError>),
}

/// A job past its guards: the forbidden roots, and Rerun's folder if it exists. Only
/// [`guard`] builds one (private fields), so a `Guarded` always went through elevation first.
pub struct Guarded<'a> {
    env: Env<'a>,
    fr: ForbiddenRoots,
    app: Option<AppDir<'a>>,
}

impl<'a> Guarded<'a> {
    /// What the job runs against.
    pub fn env(&self) -> Env<'a> {
        self.env
    }

    /// The forbidden roots, resolved for this job.
    pub fn fr(&self) -> &ForbiddenRoots {
        &self.fr
    }

    /// Rerun's folder, opened if it exists (never created by a guard, review S6 of P2-13).
    pub fn app(&self) -> Option<&AppDir<'a>> {
        self.app.as_ref()
    }
}

/// The guards of every job that may lead to a change, in the CLI's order: elevation first (an
/// elevated process reads nothing else), then the forbidden roots, then Rerun's folder.
pub fn guard(env: Env<'_>) -> Result<Guarded<'_>, Gate> {
    exec::standard_user(env.sys).map_err(Gate::Elevated)?;
    let fr = forbidden_roots(env.sys, env.install)?;
    let app = open_app(env.sys)?;
    Ok(Guarded { env, fr, app })
}

/// The forbidden roots from Rerun's install folder; an unknown folder or roots that do not
/// resolve stop the job (fail closed). A read-only part of [`guard`] that skips the elevation
/// check (E3): only for the CLI's read commands that run elevated (`rerun scan`); a job that
/// may lead to a change takes [`guard`].
pub fn forbidden_roots(
    sys: &dyn System,
    install: &Result<PathBuf, String>,
) -> Result<ForbiddenRoots, Gate> {
    let dir = install
        .as_ref()
        .map_err(|e| Gate::InstallUnknown(e.clone()))?;
    ForbiddenRoots::resolve(sys, dir).map_err(|e| Gate::Forbidden(Box::new(e)))
}

/// Rerun's folder if it exists, never created. A read-only part of [`guard`] that skips the
/// elevation check (E3): only for the CLI's read commands that run elevated (`rerun status`,
/// `rerun index show`); a job that may lead to a change takes [`guard`].
pub fn open_app(sys: &dyn System) -> Result<Option<AppDir<'_>>, Gate> {
    AppDir::open(sys, Create::Never).map_err(|e| Gate::AppDir(Box::new(e)))
}

// ---------- The index ----------

/// The current signed index.
#[derive(Debug)]
pub enum IndexState {
    /// None accepted yet (or Rerun's folder does not exist).
    None,
    /// The current index, its signature and form checked again.
    Current(Box<crate::catalog::Catalog>),
    /// The stored index is refused.
    Refused(crate::catalog::store::StoreError),
}

/// The current index of Rerun's folder `app` (`None`: the folder does not exist).
pub fn index_state(app: Option<&AppDir<'_>>) -> IndexState {
    let Some(app) = app else {
        return IndexState::None;
    };
    match crate::catalog::store::current(app, &crate::catalog::trusted_keys()) {
        Ok(None) => IndexState::None,
        Ok(Some(c)) => IndexState::Current(Box::new(c)),
        Err(e) => IndexState::Refused(e),
    }
}

// ---------- The game folder ----------

/// What is wrong with the Steam app of a plan source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SteamWhy {
    /// Steam was not found.
    NoSteam,
    /// No library lists it.
    NotListed,
    /// More than one library lists it.
    Twice,
    /// Steam is updating it.
    Updating,
    /// Not installed.
    NotInstalled,
}

/// Why the game folder of a plan source was not opened.
#[derive(Debug)]
pub enum GameOpen {
    /// The Steam app cannot be used.
    Steam {
        /// The app.
        app_id: u32,
        /// Why.
        why: SteamWhy,
    },
    /// The folder did not open.
    Folder(Box<RootError>),
}

/// Opens the game folder `game` names and runs `f` on it (with the Steam app ID for a Steam
/// game). A Steam app must be listed by exactly one library and installed; nothing is guessed.
pub(crate) fn with_game<R>(
    sys: &dyn System,
    fr: &ForbiddenRoots,
    game: &GameRef,
    f: impl FnOnce(&GameDir<'_>, Option<u32>) -> R,
) -> Result<R, GameOpen> {
    match game {
        GameRef::Folder(p) => {
            let g = GameDir::open_manual(sys, fr, p.path())
                .map_err(|e| GameOpen::Folder(Box::new(e)))?;
            Ok(f(&g, None))
        }
        GameRef::Steam(app_id) => {
            let app_id = *app_id;
            let why = |why| GameOpen::Steam { app_id, why };
            let s = steam::scan(sys, fr);
            if s.root.is_none() {
                return Err(why(SteamWhy::NoSteam));
            }
            // Every entry counts: a library may list an app twice (ADR 0012), nothing is
            // guessed.
            let mut found = s.libraries.iter().flat_map(|lib| {
                lib.apps()
                    .iter()
                    .filter(move |a| a.app_id == app_id)
                    .map(move |a| (lib, a.state()))
            });
            let (lib, state) = match (found.next(), found.next()) {
                (None, _) => return Err(why(SteamWhy::NotListed)),
                (Some(_), Some(_)) => return Err(why(SteamWhy::Twice)),
                (Some(x), None) => x,
            };
            match state {
                AppState::Installed => {}
                AppState::UpdatePending => return Err(why(SteamWhy::Updating)),
                AppState::NotInstalled => return Err(why(SteamWhy::NotInstalled)),
            }
            let g = lib
                .open_game(fr, app_id)
                .map_err(|e| GameOpen::Folder(Box::new(e)))?;
            Ok(f(&g, Some(app_id)))
        }
    }
}

#[cfg(test)]
mod tests;
