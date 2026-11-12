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
//! files keep their identity) and the system page; the applied page is read each visit. A library scan (the
//! rescan) clears all of it. Nothing of it is ever written.
//!
//! Order (ADR 0027 amendment P5-3b): jobs run one at a time in the order sent, except that a
//! library scan, which takes seconds, lets the jobs that wait run between two games (a click on
//! a game or a page never waits for the scan); a second library job during a scan restarts it.
//!
//! Rule 1: the thread lives as long as the window. Dropping the [`Worker`] closes the job
//! channel; the thread ends after the job it runs (read-only, so the process may also end
//! while it runs).

use std::collections::HashMap;
use std::ops::ControlFlow;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};

use rerun_core::catalog::Catalog;
use rerun_core::catalog::model::Status;
use rerun_core::detect::steam;
use rerun_core::escape::Shown;
use rerun_core::exec;
use rerun_core::flow::{
    self, ActError, Env, ForgetShown, Found, GameCache, Guarded, IndexState, LibraryEvent, Lookup,
    Planned, Previewed, RevertShown,
};
use rerun_core::hw::{self, GpuArchTable};
use rerun_core::journal::TxnId;
use rerun_core::plan::Pick;
use rerun_core::sys::{Http, System};
use rerun_core::topo;

use crate::text::{Lang, Msg, t};
use crate::vm::{
    self, AppliedVm, BlockedVm, DetailVm, DialogVm, GameVm, LibraryVm, Names, Notice, Offer,
    PreviewVm, ResultVm, RowVm, SteamVm, SystemVm, TopoKnown,
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
    /// Plans the picked fixes of a game (reads only, stores nothing). No picks: clears the
    /// preview.
    Plan {
        /// The Steam app.
        app_id: u32,
        /// The fixes' picks, one per selected fix.
        picks: Vec<Pick>,
    },
    /// The window rendered the preview with this plan hash: only now may it be applied
    /// (`flow::shown`, ADR 0027 rule 5).
    PreviewShown {
        /// The plan hash (hex).
        hash: String,
    },
    /// Applies the shown plan with this hash: store, check, apply. The core checks the hash
    /// again.
    Apply {
        /// The plan hash (hex) the Apply button carries.
        hash: String,
    },
    /// The preview of the undo of a transaction.
    RevertPreview {
        /// The transaction.
        txn: TxnId,
    },
    /// Undoes the transaction whose preview was shown.
    Revert {
        /// The transaction.
        txn: TxnId,
    },
    /// The preview of closing a transaction without undoing it.
    ForgetPreview {
        /// The transaction.
        txn: TxnId,
    },
    /// Closes the transaction whose preview was shown.
    Forget {
        /// The transaction.
        txn: TxnId,
    },
}

impl Job {
    /// The job's name for the timing trace.
    fn name(&self) -> String {
        match self {
            Self::Library => "library".to_owned(),
            Self::Game { app_id, .. } => format!("game {app_id}"),
            Self::Status => "status".to_owned(),
            Self::System => "system".to_owned(),
            Self::Plan { app_id, .. } => format!("plan {app_id}"),
            Self::PreviewShown { .. } => "preview shown".to_owned(),
            Self::Apply { .. } => "apply".to_owned(),
            Self::RevertPreview { .. } => "undo preview".to_owned(),
            Self::Revert { .. } => "undo".to_owned(),
            Self::ForgetPreview { .. } => "forget preview".to_owned(),
            Self::Forget { .. } => "forget".to_owned(),
        }
    }

    /// The job may change the system: the window cannot close while it is queued or runs
    /// (rule 1, ADR 0027).
    pub fn writes(&self) -> bool {
        matches!(
            self,
            Self::Apply { .. } | Self::Revert { .. } | Self::Forget { .. }
        )
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
    /// The preview of the picked fixes (rule 5).
    Preview {
        /// The game it is for.
        app_id: u32,
        /// The preview.
        vm: Box<PreviewVm>,
    },
    /// Nothing is picked: the preview is cleared.
    PreviewNone {
        /// The game.
        app_id: u32,
    },
    /// No preview could be made.
    PreviewRefused {
        /// The game.
        app_id: u32,
        /// Why.
        result: ResultVm,
    },
    /// The preview with this plan hash is shown: Apply may be offered.
    PreviewReady {
        /// The plan hash (hex).
        hash: String,
    },
    /// An undo or forget dialog.
    Dialog(Box<DialogVm>),
    /// What a job that may have written (or was refused) came to.
    Result(ResultVm),
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
    /// Write jobs queued or running: the window does not close while it is above zero.
    writes: Arc<AtomicUsize>,
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
        let writes = Arc::new(AtomicUsize::new(0));
        let thread_writes = writes.clone();
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
                let mut session = Session {
                    writes: thread_writes,
                    ..Session::default()
                };
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
        Ok(Self {
            jobs,
            events,
            writes,
        })
    }

    /// Queues a job (ignored once the thread has ended). A write job counts as running from
    /// here on, so the window cannot close between the click and the worker picking it up.
    pub fn send(&self, job: Job) {
        let writes = job.writes();
        if writes {
            self.writes.fetch_add(1, Ordering::SeqCst);
        }
        if self.jobs.send(job).is_err() && writes {
            self.writes.fetch_sub(1, Ordering::SeqCst);
        }
    }

    /// A write job is queued or running (rule 1: closing the window is refused meanwhile).
    pub fn busy_writing(&self) -> bool {
        self.writes.load(Ordering::SeqCst) > 0
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
    pub(crate) games: GameCache,
    system: Option<SystemVm>,
    /// The names of the games the library listed (escaped), for the applied cards.
    names: Names,
    /// The fixes of the page last handed to the window, per game: a plan that finds the game
    /// read differently now hands the window the fresh page instead of a preview (ADR 0027
    /// amendment P5-5a).
    pages: HashMap<u32, Vec<(String, Offer)>>,
    /// What the window was shown and may confirm (module docs).
    pending: Pending,
    /// Write jobs queued or running (shared with [`Worker::busy_writing`]).
    writes: Arc<AtomicUsize>,
}

/// The proof tokens of the flows the window may confirm: the bytes whose preview was handed
/// over, and the observation an undo or forget preview showed. Memory only; one of each at a
/// time (a new preview replaces the old).
#[derive(Debug, Default)]
struct Pending {
    /// A plan whose preview was handed to the window, not yet reported rendered.
    plan: Option<(u32, Planned)>,
    /// A plan whose preview the window rendered: "Apply" may use it.
    shown: Option<(u32, Previewed)>,
    /// An undo preview, with the game its transaction is about.
    revert: Option<(RevertShown, Option<u32>)>,
    /// A forget preview, with the game its transaction is about.
    forget: Option<(ForgetShown, Option<u32>)>,
}

impl Session {
    /// A rescan: forget everything read so far.
    fn rescan(&mut self) {
        self.games.clear();
        self.system = None;
        self.pages.clear();
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
    let preempted = run_job(env, job, lang, session, waiting, emit);
    if job.writes() {
        // The write is over (done, refused or never started): the window may close.
        let _ = session
            .writes
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
                Some(n.saturating_sub(1))
            });
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

fn run_job(
    env: Env<'_>,
    job: &Job,
    lang: Lang,
    session: &mut Session,
    waiting: &mut dyn FnMut() -> Option<Job>,
    emit: &mut dyn FnMut(Event),
) -> Option<Job> {
    let mut g = match flow::guard(env) {
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
            if let Some(n) = name {
                session.names.insert(*app_id, n.clone());
            }
            let page = game_page(&g, *app_id, name.as_ref(), lang, session);
            emit(Event::Game(page));
        }
        Job::Status => {
            // Never kept: another process may apply or revert while the window is open (the
            // window only skips setting an unchanged page).
            emit(Event::Applied(applied_page(&g, lang, session)));
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
        Job::Plan { app_id, picks } => plan(&g, *app_id, picks, lang, session, emit),
        Job::PreviewShown { hash } => {
            // The window handed the preview over to be drawn: only now is the plan the
            // user's to apply (rule 5, `flow::shown`).
            // Only the plan the window drew: a report for an older preview leaves the newer
            // plan where it is.
            if session
                .pending
                .plan
                .as_ref()
                .is_some_and(|(_, p)| p.hash().to_string() == *hash)
                && let Some((app, p)) = session.pending.plan.take()
            {
                session.pending.shown = Some((app, flow::shown(p)));
                emit(Event::PreviewReady { hash: hash.clone() });
            }
        }
        Job::Apply { hash } => apply(&mut g, hash, lang, session, emit),
        Job::RevertPreview { txn } => revert_preview(&g, txn, false, lang, session, emit),
        Job::Revert { txn } => revert(&g, txn, lang, session, emit),
        Job::ForgetPreview { txn } => forget_preview(&g, txn, false, lang, session, emit),
        Job::Forget { txn } => forget(&g, txn, lang, session, emit),
    }
    preempted
}

/// A game's page: the lookup, and the transactions applied to it.
fn game_page(
    g: &Guarded<'_>,
    app_id: u32,
    name: Option<&Shown<'static>>,
    lang: Lang,
    session: &mut Session,
) -> GameVm {
    let mut page = match flow::game_cached(g, app_id, Some(&mut session.games)) {
        Ok(v) => vm::game(&v, name, lang),
        Err(e) => vm::game_refused(app_id, name, &e, lang),
    };
    if let Some(Ok(s)) = g.app().map(exec::status) {
        page.applied = vm::cards(&s, &session.names, lang)
            .into_iter()
            .filter(|c| c.app_id == Some(app_id))
            .collect();
    }
    session.pages.insert(app_id, fix_key(&page));
    page
}

/// What decides whether a page the window holds is still the page of the files: the fixes and
/// whether each can be applied.
fn fix_key(page: &GameVm) -> Vec<(String, Offer)> {
    page.fixes
        .iter()
        .map(|f| (f.key.clone(), f.offer))
        .collect()
}

/// The applied page from the journal (never kept).
fn applied_page(g: &Guarded<'_>, lang: Lang, session: &Session) -> AppliedVm {
    match g.app() {
        None => vm::applied(None, &session.names, lang),
        Some(app) => {
            // The journal only (review of P5-3): the orphaned firewall rules are read when the
            // applied page shows them (P5-6).
            let s = exec::status(app);
            vm::applied(Some(s.as_ref()), &session.names, lang)
        }
    }
}

/// After a write: the applied page, and the game page of the app it was about (its cached
/// executables dropped: the files may have changed).
fn refresh(
    g: &Guarded<'_>,
    app_id: Option<u32>,
    lang: Lang,
    session: &mut Session,
    emit: &mut dyn FnMut(Event),
) {
    emit(Event::Applied(applied_page(g, lang, session)));
    if let Some(app) = app_id {
        session.games.forget(app);
        let name = session.names.get(&app).cloned();
        let page = game_page(g, app, name.as_ref(), lang, session);
        emit(Event::Game(page));
    }
}

/// The preview of the picked fixes. Reads only and stores nothing (S6: looking at fixes never
/// creates Rerun's folder).
///
/// The executables are read again first (the session's entry of the game is dropped): `flow::plan`
/// reads them fresh anyway, and a display from the cache must not lead to a plan the page
/// does not show (ADR 0027 amendment P5-5a). If the fresh page offers other fixes than the page
/// the window holds, the window gets the fresh page and a calm note instead of a preview.
fn plan(
    g: &Guarded<'_>,
    app_id: u32,
    picks: &[Pick],
    lang: Lang,
    session: &mut Session,
    emit: &mut dyn FnMut(Event),
) {
    session.pending.plan = None;
    session.pending.shown = None;
    if picks.is_empty() {
        emit(Event::PreviewNone { app_id });
        return;
    }
    let before = session.pages.get(&app_id).cloned();
    session.games.forget(app_id);
    let name = session.names.get(&app_id).cloned();
    let page = game_page(g, app_id, name.as_ref(), lang, session);
    if before.as_ref().is_some_and(|b| *b != fix_key(&page)) {
        emit(Event::Game(page));
        emit(Event::PreviewRefused {
            app_id,
            result: vm::stale(lang),
        });
        return;
    }
    let refused = |result| Event::PreviewRefused { app_id, result };
    match flow::plan(g, app_id, picks) {
        Err(e) => emit(refused(vm::game_refusal(&e, lang))),
        Ok(Lookup::Read {
            found: Found::One(picked),
            ..
        }) => match picked.planned {
            Err(e) => emit(refused(vm::plan_refusal(&e, lang))),
            Ok(planned) => {
                let env = g.env();
                let launch = flow::launch_view(env.sys, env.install, planned.preview());
                let vm = vm::preview_vm(&planned, launch.as_ref(), lang);
                session.pending.plan = Some((app_id, planned));
                emit(Event::Preview {
                    app_id,
                    vm: Box::new(vm),
                });
            }
        },
        // The game reads differently now (another build, no Topo): the page is the answer.
        Ok(_) => {
            emit(Event::Game(page));
            emit(refused(vm::stale(lang)));
        }
    }
}

/// Applies the plan the window rendered: store, check, apply. Nothing is applied that was not
/// shown (the preview of exactly those bytes) and whose hash the click does not carry; the core
/// checks everything again under the journal lock.
fn apply(
    g: &mut Guarded<'_>,
    hash: &str,
    lang: Lang,
    session: &mut Session,
    emit: &mut dyn FnMut(Event),
) {
    // Only a plan whose preview was shown, under exactly the hash the click carries; another
    // hash leaves the shown plan where it is.
    let wanted = session
        .pending
        .shown
        .as_ref()
        .is_some_and(|(_, p)| p.hash().to_string() == hash);
    let Some((app_id, p)) = wanted.then(|| session.pending.shown.take()).flatten() else {
        emit(Event::Result(vm::no_preview(lang)));
        return;
    };
    if let Err(e) = flow::store(g, &p) {
        let r = vm::store_refusal(&e, lang);
        let refresh_page = r.refresh;
        emit(Event::Result(r));
        if refresh_page {
            refresh(g, Some(app_id), lang, session, emit);
        }
        return;
    }
    let mut again = false;
    let result = match flow::check(g, &p) {
        Err(r) => {
            let r = vm::refusal(&r, lang);
            if !r.refresh {
                // A refusal that may pass later (the game runs, another Rerun holds the lock):
                // the same preview stays, "Apply" can be tried again.
                session.pending.shown = Some((app_id, p));
                again = true;
            }
            r
        }
        Ok(0) => vm::apply_result(Ok(exec::Outcome::Nothing), lang),
        Ok(_) => vm::apply_result(flow::apply(g, p), lang),
    };
    let refresh_page = result.refresh;
    emit(Event::Result(result));
    if again {
        emit(Event::PreviewReady {
            hash: hash.to_owned(),
        });
    }
    if refresh_page {
        refresh(g, Some(app_id), lang, session, emit);
    }
}

fn revert_preview(
    g: &Guarded<'_>,
    txn: &TxnId,
    changed: bool,
    lang: Lang,
    session: &mut Session,
    emit: &mut dyn FnMut(Event),
) {
    session.pending.revert = None;
    match flow::revert_preview(g, txn) {
        Ok((p, shown)) => {
            let app = vm::app_of(&p.status);
            let dialog = vm::revert_vm(&p, g.env().install, changed, lang);
            session.pending.revert = Some((shown, app));
            emit(Event::Dialog(Box::new(dialog)));
        }
        Err(gate) => emit(Event::Result(vm::gate(&gate, lang))),
    }
}

fn revert(
    g: &Guarded<'_>,
    txn: &TxnId,
    lang: Lang,
    session: &mut Session,
    emit: &mut dyn FnMut(Event),
) {
    let Some((shown, app)) = session
        .pending
        .revert
        .take()
        .filter(|(s, _)| s.txn() == *txn)
    else {
        // No preview of this transaction was shown: show it first.
        revert_preview(g, txn, false, lang, session, emit);
        return;
    };
    match flow::revert(g, shown) {
        Ok(o) => {
            let mut r = vm::revert_result(&o, lang);
            if let Some(l) = o.launch_option {
                vm::add_launch_option(&mut r, &l, g.env().install, lang);
            }
            emit(Event::Result(r));
            refresh(g, app, lang, session, emit);
        }
        // What is there now differs from the preview: nothing was written; show it again.
        Err(ActError::Changed) => revert_preview(g, txn, true, lang, session, emit),
        Err(e) => {
            emit(Event::Result(vm::act_error(&e, lang)));
            refresh(g, app, lang, session, emit);
        }
    }
}

fn forget_preview(
    g: &Guarded<'_>,
    txn: &TxnId,
    changed: bool,
    lang: Lang,
    session: &mut Session,
    emit: &mut dyn FnMut(Event),
) {
    session.pending.forget = None;
    match flow::forget_preview(g, txn) {
        Ok((p, shown)) => {
            let app = vm::app_of(&p.status);
            let dialog = vm::forget_vm(&p, g.env().install, changed, lang);
            session.pending.forget = Some((shown, app));
            emit(Event::Dialog(Box::new(dialog)));
        }
        Err(gate) => emit(Event::Result(vm::gate(&gate, lang))),
    }
}

fn forget(
    g: &Guarded<'_>,
    txn: &TxnId,
    lang: Lang,
    session: &mut Session,
    emit: &mut dyn FnMut(Event),
) {
    let Some((shown, app)) = session
        .pending
        .forget
        .take()
        .filter(|(s, _)| s.txn() == *txn)
    else {
        forget_preview(g, txn, false, lang, session, emit);
        return;
    };
    match flow::forget(g, shown) {
        Ok(()) => {
            emit(Event::Result(vm::forget_result(lang)));
            refresh(g, app, lang, session, emit);
        }
        Err(ActError::Changed) => forget_preview(g, txn, true, lang, session, emit),
        Err(e) => {
            emit(Event::Result(vm::act_error(&e, lang)));
            refresh(g, app, lang, session, emit);
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
                session
                    .names
                    .insert(app.app_id, app.name.escaped().into_owned());
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
