//! The worker (ADR 0027): one thread for the session owns the system, runs one job at a time
//! and hands view models back as events. The UI thread never touches the system.
//!
//! P5-3 is read-only: [`Job::Library`], [`Job::Game`], [`Job::Status`] and [`Job::System`].
//! Every job builds its own `Guarded` through `flow::guard` (elevation first, then the
//! forbidden roots, then Rerun's folder opened if it exists, never created): an elevated process
//! reads nothing, and the window shows the blocking page (rule 6). Nothing is written, no
//! folder created, nothing cached on disk.
//!
//! Session (P5-3b): the worker keeps, in memory and for the session only, what it already
//! read ([`Session`]): per game the executables' hashes (`flow::GameCache`, valid while the
//! files keep their identity), the applied page and the system page. A library scan (the
//! rescan) clears all of it. Nothing of it is ever written.
//!
//! Order (ADR 0027 amendment P5-3b): jobs run one at a time in the order sent, except that a
//! library scan, which takes seconds, lets the jobs that wait run between two games (a click on
//! a game or a page never waits for the scan); a second library job during a scan restarts it.
//!
//! Rule 1: the thread lives as long as the window. Dropping the [`Worker`] closes the job
//! channel; the thread ends after the job it runs (read-only, so the process may also end
//! while it runs).

use std::ops::ControlFlow;
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, Sender};

use rerun_core::catalog::Catalog;
use rerun_core::catalog::model::Status;
use rerun_core::detect::steam;
use rerun_core::escape::Shown;
use rerun_core::flow::{self, Env, GameCache, Guarded, IndexState, LibraryEvent};
use rerun_core::hw::{self, GpuArchTable};
use rerun_core::sys::{Http, System};
use rerun_core::topo;

use crate::text::{Lang, Msg, t};
use crate::vm::{
    self, AppliedVm, BlockedVm, DetailVm, GameVm, LibraryVm, Notice, RowVm, SteamVm, SystemVm,
    TopoKnown,
};

/// A job for the worker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Job {
    /// Scan the Steam libraries; rows are streamed.
    Library,
    /// One game's page.
    Game {
        /// The Steam app.
        app_id: u32,
        /// Its name as the library listed it (escaped), for the title.
        name: Option<Shown<'static>>,
    },
    /// The journal, for the applied page.
    Status,
    /// The system profile.
    System,
}

impl Job {
    /// The job's name for the timing trace.
    fn name(&self) -> String {
        match self {
            Self::Library => "library".to_owned(),
            Self::Game { app_id, .. } => format!("game {app_id}"),
            Self::Status => "status".to_owned(),
            Self::System => "system".to_owned(),
        }
    }
}

/// What the worker hands back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// A guard stopped the job; nothing was read.
    Blocked(BlockedVm),
    /// A library scan begins: the rows of an earlier scan are void.
    LibraryStarted,
    /// One game of the library.
    Row(RowVm),
    /// The library scan is done.
    LibraryDone(LibraryVm),
    /// A game page.
    Game(GameVm),
    /// The applied page.
    Applied(AppliedVm),
    /// The system page.
    System(SystemVm),
}

/// How the framework learns that an event is waiting (ADR 0027).
pub trait Wake: Send + 'static {
    /// Called on the worker thread after each event; the UI thread then calls
    /// [`Worker::poll`].
    fn wake(&self);
}

/// What the worker runs against, built on its own thread.
pub struct World {
    /// The system.
    pub sys: Box<dyn System>,
    /// HTTPS (unused while the app is read-only; `flow::Env` carries it).
    pub http: Box<dyn Http>,
    /// Rerun's install folder (the folder of `rerun-app.exe`), or why it is unknown.
    pub install: Result<PathBuf, String>,
}

/// The worker thread's handle.
pub struct Worker {
    jobs: Sender<Job>,
    events: Receiver<Event>,
}

impl Worker {
    /// Starts the thread. `make` builds the world on it (a `WinSystem` is created and used on
    /// one thread only); if it fails, every job is answered with [`Event::Blocked`].
    pub fn start<F>(lang: Lang, make: F, wake: Box<dyn Wake>) -> std::io::Result<Self>
    where
        F: FnOnce() -> Result<World, Shown<'static>> + Send + 'static,
    {
        let (jobs, job_rx) = mpsc::channel::<Job>();
        let (event_tx, events) = mpsc::channel::<Event>();
        std::thread::Builder::new()
            .name("rerun-worker".to_owned())
            .spawn(move || {
                let world = make();
                let mut emit = |e: Event| {
                    // The window is gone when the receiver is: nothing left to tell.
                    if event_tx.send(e).is_ok() {
                        wake.wake();
                    }
                };
                let mut session = Session::default();
                // A library job that stopped a running scan: it runs next.
                let mut next: Option<Job> = None;
                while let Some(job) = next.take().or_else(|| job_rx.recv().ok()) {
                    match &world {
                        Ok(w) => {
                            let env = Env {
                                sys: &*w.sys,
                                http: &*w.http,
                                install: &w.install,
                            };
                            next = run_in(
                                env,
                                &job,
                                lang,
                                &mut session,
                                &mut || job_rx.try_recv().ok(),
                                &mut emit,
                            );
                        }
                        Err(detail) => emit(Event::Blocked(no_system(detail.clone(), lang))),
                    }
                }
            })?;
        Ok(Self { jobs, events })
    }

    /// Queues a job (ignored once the thread has ended).
    pub fn send(&self, job: Job) {
        let _ = self.jobs.send(job);
    }

    /// The next waiting event.
    pub fn poll(&self) -> Option<Event> {
        self.events.try_recv().ok()
    }
}

/// The blocking page when the system layer could not be created.
fn no_system(detail: Shown<'static>, lang: Lang) -> BlockedVm {
    BlockedVm {
        elevated: false,
        notice: Notice {
            title: t(lang, Msg::GuardTitle).into_owned(),
            body: t(lang, Msg::GuardBody).into_owned(),
            details: vec![DetailVm::of(detail)],
        },
    }
}

/// What the worker has read in this session (module docs). Memory only.
#[derive(Debug, Default)]
pub struct Session {
    /// The executables read per game.
    pub games: GameCache,
    applied: Option<AppliedVm>,
    system: Option<SystemVm>,
}

impl Session {
    /// A rescan: forget everything read so far.
    fn rescan(&mut self) {
        self.games.clear();
        self.applied = None;
        self.system = None;
    }

    /// The journal changed (the hook for P5-6: an apply, a revert or a forget calls this): the
    /// applied page is read again at its next visit.
    #[cfg(test)]
    pub fn journal_changed(&mut self) {
        self.applied = None;
    }
}

/// Runs one job against `env` with a fresh [`Session`]: the guards first, then the job; every
/// outcome goes to `emit`.
#[cfg(test)]
pub fn run(env: Env<'_>, job: &Job, lang: Lang, emit: &mut dyn FnMut(Event)) {
    let mut session = Session::default();
    let _ = run_in(env, job, lang, &mut session, &mut || None, emit);
}

/// [`run`] in `session`. `waiting` hands out the next job that is already queued, without
/// waiting for one: a library scan runs those between two games; if it hands out another
/// library job, the scan stops and that job is returned to be run next.
pub fn run_in(
    env: Env<'_>,
    job: &Job,
    lang: Lang,
    session: &mut Session,
    waiting: &mut dyn FnMut() -> Option<Job>,
    emit: &mut dyn FnMut(Event),
) -> Option<Job> {
    let began = std::time::Instant::now();
    let g = match flow::guard(env) {
        Ok(g) => g,
        Err(gate) => {
            emit(Event::Blocked(vm::blocked(&gate, lang)));
            return None;
        }
    };
    let mut preempted = None;
    match job {
        Job::Library => preempted = library(&g, lang, session, waiting, emit),
        Job::Game { app_id, name } => {
            let page = match flow::game_cached(&g, *app_id, Some(&mut session.games)) {
                Ok(v) => vm::game(&v, name.as_ref(), lang),
                Err(e) => vm::game_refused(*app_id, name.as_ref(), &e, lang),
            };
            emit(Event::Game(page));
        }
        Job::Status => {
            let page = session.applied.take().unwrap_or_else(|| match g.app() {
                None => vm::applied(None, lang),
                Some(app) => {
                    // The journal only (review of P5-3): the orphaned firewall rules are read
                    // when the applied page shows them (P5-6).
                    let s = rerun_core::exec::status(app);
                    vm::applied(Some(s.as_ref()), lang)
                }
            });
            session.applied = Some(page.clone());
            emit(Event::Applied(page));
        }
        Job::System => {
            let page = session.system.take().unwrap_or_else(|| {
                let sys = g.env().sys;
                let profile = hw::read(sys, GpuArchTable::builtin().ok());
                let s = steam::scan(sys, g.fr());
                let libraries = s.root.is_some().then_some(s.libraries.len());
                vm::system(&profile, libraries, lang)
            });
            session.system = Some(page.clone());
            emit(Event::System(page));
        }
    }
    crate::trace::log(|| {
        format!(
            "worker: {} took {:.1} ms (jobs run in between included)",
            job.name(),
            began.elapsed().as_secs_f64() * 1000.0
        )
    });
    preempted
}

/// Whether the index names a Topo (not retired) for `app_id`.
fn topo_known(catalog: Option<&Catalog>, app_id: u32) -> TopoKnown {
    match catalog {
        None => TopoKnown::NoIndex,
        Some(c) => {
            let live = topo::topos_for(c, app_id)
                .iter()
                .any(|t| t.status != Status::Retired);
            if live { TopoKnown::Yes } else { TopoKnown::No }
        }
    }
}

/// The library: the index, then the scan streamed row by row (without hashes: matching a
/// Topo is the game page's job), then the summary. Between two games the jobs that wait run
/// (module docs). Returns the library job that stopped the scan, if one did.
fn library(
    g: &Guarded<'_>,
    lang: Lang,
    session: &mut Session,
    waiting: &mut dyn FnMut() -> Option<Job>,
    emit: &mut dyn FnMut(Event),
) -> Option<Job> {
    session.rescan();
    emit(Event::LibraryStarted);
    let state = flow::index_state(g.app());
    let catalog = match &state {
        IndexState::Current(c) => Some(&**c),
        IndexState::None | IndexState::Refused(_) => None,
    };
    let mut steam_vm = SteamVm {
        found: false,
        problems: Vec::new(),
    };
    let mut problems: Vec<DetailVm> = Vec::new();
    let mut preempted: Option<Job> = None;
    let env = g.env();
    let scanned = flow::library::<()>(env.sys, g.fr(), &[], false, &mut |ev| {
        match ev {
            LibraryEvent::Steam(s) => {
                steam_vm = vm::steam(s);
                problems.extend(steam_vm.problems.iter().cloned());
            }
            LibraryEvent::Library { .. } => {}
            LibraryEvent::Row { app, scan } => {
                problems.extend(vm::row_problems(app, scan));
                let known = topo_known(catalog, app.app_id);
                emit(Event::Row(vm::row(app, scan, known, lang)));
                // The game folder is closed: a click that waits goes first.
                while let Some(next) = waiting() {
                    if next == Job::Library {
                        preempted = Some(next);
                        return ControlFlow::Break(());
                    }
                    let _ = run_in(env, &next, lang, session, &mut || None, emit);
                }
            }
        }
        ControlFlow::Continue(())
    });
    let Ok(facts) = scanned else {
        // Stopped by a newer scan: no summary of this one.
        return preempted;
    };
    let index = vm::index(&state, lang);
    emit(Event::LibraryDone(vm::library_done(
        &facts, &steam_vm, &problems, index, lang,
    )));
    None
}

#[cfg(test)]
mod tests;
