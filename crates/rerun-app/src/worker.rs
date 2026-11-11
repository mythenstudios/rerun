//! The worker (ADR 0027): one thread for the session owns the system, runs one job at a time
//! in the order sent and hands view models back as events. The UI thread never touches the
//! system.
//!
//! P5-3 is read-only: [`Job::Library`], [`Job::Game`], [`Job::Status`] and [`Job::System`].
//! Every job builds its own `Guarded` through `flow::guard` (elevation first, then the
//! forbidden roots, then Rerun's folder opened if it exists, never created): an elevated process
//! reads nothing, and the window shows the blocking page (rule 6). Nothing is written, no
//! folder created, nothing cached on disk.
//!
//! Rule 1: the thread lives as long as the window. Dropping the [`Worker`] closes the job
//! channel; the thread ends after the job it runs (read-only, so the process may also end
//! while it runs).

use std::convert::Infallible;
use std::ops::ControlFlow;
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, Sender};

use rerun_core::catalog::Catalog;
use rerun_core::catalog::model::Status;
use rerun_core::detect::steam;
use rerun_core::escape::Shown;
use rerun_core::flow::{self, Env, Guarded, IndexState, LibraryEvent};
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

/// What the worker hands back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// A guard stopped the job; nothing was read.
    Blocked(BlockedVm),
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
                while let Ok(job) = job_rx.recv() {
                    match &world {
                        Ok(w) => {
                            let env = Env {
                                sys: &*w.sys,
                                http: &*w.http,
                                install: &w.install,
                            };
                            run(env, &job, lang, &mut emit);
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

/// Runs one job against `env`: the guards first, then the job; every outcome goes to `emit`.
pub fn run(env: Env<'_>, job: &Job, lang: Lang, emit: &mut dyn FnMut(Event)) {
    let g = match flow::guard(env) {
        Ok(g) => g,
        Err(gate) => {
            emit(Event::Blocked(vm::blocked(&gate, lang)));
            return;
        }
    };
    match job {
        Job::Library => library(&g, lang, emit),
        Job::Game { app_id, name } => {
            let page = match flow::game(&g, *app_id) {
                Ok(v) => vm::game(&v, name.as_ref(), lang),
                Err(e) => vm::game_refused(*app_id, name.as_ref(), &e, lang),
            };
            emit(Event::Game(page));
        }
        Job::Status => {
            let page = match g.app() {
                None => vm::applied(None, lang),
                Some(app) => {
                    // The journal only (review of P5-3): the orphaned firewall rules are read
                    // when the applied page shows them (P5-6).
                    let s = rerun_core::exec::status(app);
                    vm::applied(Some(s.as_ref()), lang)
                }
            };
            emit(Event::Applied(page));
        }
        Job::System => {
            let sys = g.env().sys;
            let profile = hw::read(sys, GpuArchTable::builtin().ok());
            let s = steam::scan(sys, g.fr());
            let libraries = s.root.is_some().then_some(s.libraries.len());
            emit(Event::System(vm::system(&profile, libraries, lang)));
        }
    }
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
/// Topo is the game page's job), then the summary.
fn library(g: &Guarded<'_>, lang: Lang, emit: &mut dyn FnMut(Event)) {
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
    let scanned = flow::library::<Infallible>(g.env().sys, g.fr(), &[], false, &mut |ev| {
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
            }
        }
        ControlFlow::Continue(())
    });
    let facts = match scanned {
        Ok(f) => f,
        Err(never) => match never {},
    };
    let index = vm::index(&state, lang);
    emit(Event::LibraryDone(vm::library_done(
        &facts, &steam_vm, &problems, index, lang,
    )));
}

#[cfg(test)]
mod tests;
