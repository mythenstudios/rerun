//! The worker (ADR 0027): one thread for the session owns the system, runs one job at a time
//! and hands view models back as events. The UI thread never touches the system.
//!
//! Read jobs: [`Job::Library`], [`Job::Game`], [`Job::Status`], [`Job::History`] (P5-6a), [`Job::System`] and the preview jobs
//! ([`Job::Plan`], [`Job::RevertPreview`], [`Job::ForgetPreview`]); write jobs (P5-5a): [`Job::Apply`],
//! [`Job::Revert`] and [`Job::Forget`], which write only through `flow` with a token the window
//! was shown.
//! Package downloads (P5-5b): [`Job::DownloadAsk`] answers the consent dialog (what would be
//! downloaded, read only) and keeps the list it showed under a nonce; [`Job::Download`] downloads
//! only for the list whose nonce the click carries, through `flow::fetch` (which checks the index
//! against that list again), reports progress, and ends in [`Event::DownloadEnded`]. A cancel is
//! a flag ([`Worker::cancel_download`]) the fetch checks before every request and read: it takes
//! effect at the next read, up to WinHTTP's 30 s receive timeout, and a cancelled or failed body
//! leaves nothing in the cache.
//!
//! Opening (P5-10a): [`Job::OpenSource`] names a source of the fix card by reference, the core
//! looks its URL up in the current signed index; [`Job::ReportAsk`] answers with the report
//! dialog (exactly the issue's text) and keeps the report under the dialog's nonce,
//! [`Job::ReportOpen`] opens exactly its URL once; [`Job::DataFolder`] and
//! [`Job::OpenDataFolder`] are Settings > Data, [`Job::OpenOwn`] the links of Settings > About
//! Rerun (P5-10e). All through the world's `Shell` (never in
//! `flow::Env`), none a write job; [`Event::Opened`] or a calm result answers.
//!
//! Settings (P5-10b): [`Job::SaveSettings`] writes the settings the window now has, only if they
//! differ from what the session read or last wrote (`settings::Memo`, which [`Worker::start`] is
//! handed from `main`). It is not a write job: it never holds the window's close (the file is
//! written with a temp file and renames under compare-and-swap, so a process that ends in the
//! middle leaves the old or the new file, or none, which is the defaults). No event answers it:
//! a failed write is silent and the settings hold for the session.
//!
//! Every job builds its own `Guarded` through `flow::guard` (elevation first, then the
//! forbidden roots, then Rerun's folder opened if it exists, never created): an elevated process
//! reads nothing, and the window shows the blocking page (rule 6). Reading and previewing
//! write nothing and create no folder; nothing is cached on disk.
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
//! The elevated helper (P5-5c, ADR 0023 amendment P5-5c): a fix or an undo that needs it is
//! offered only when `flow::helper` says it could run now (installed safely, Windows allows an
//! elevation), and the preview names the UAC prompt. The system is built at once with a
//! [`PromptOwnerSlot`] the window fills with its handle when its native window exists
//! ([`Worker::set_owner`]); every helper start reads it then, so a late owner is never lost (a
//! start before it would have no owner; the window exists long before any click). Before the
//! core call that may start the
//! helper, the worker sends [`Event::WaitingForUac`] (only when Windows shows a dialog); the
//! thread then blocks in `run_helper` until the user answers, and the result follows. The window
//! cannot close meanwhile (a write job runs).
//!
//! Rule 1: the thread lives as long as the window. Dropping the [`Worker`] closes the job
//! channel; the thread ends after the job it runs. A write job counts as running from `send` to its
//! end ([`Worker::busy_writing`]): the window does not close meanwhile.

use std::collections::HashMap;
use std::ops::ControlFlow;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};

use rerun_core::catalog::Catalog;
use rerun_core::catalog::model::Status;
use rerun_core::detect::steam;
use rerun_core::elevate::PromptState;
use rerun_core::escape::Shown;
use rerun_core::exec::{self, ExecError, RebindRefusal, Refusal};
use rerun_core::flow::{
    self, ActError, ClearShown, Env, FetchError, ForgetShown, Found, GameCache, GameView, Guarded,
    Heads, IndexState, LibraryEvent, Lookup, NeedState, PackageNeed, Planned, Previewed, Progress,
    RebindShown, RemoveShown, RevertGate, RevertShown,
};
use rerun_core::hw::{self, GpuArchTable};
use rerun_core::journal::TxnId;
use rerun_core::plan::Pick;
use rerun_core::policy::open::{OpenUrl, OwnLink};
use rerun_core::sys::{Http, NoShell, PromptOwner, PromptOwnerSlot, Shell, System};
use rerun_core::topo;

use crate::settings::{Memo, Settings};
use crate::text::{Lang, Msg, t};
use crate::vm::{
    self, AppliedVm, BlockedVm, DataVm, DetailVm, DialogVm, DownloadVm, GameVm, HelperState,
    HistoryVm, LibraryVm, Names, Notice, Offer, OrphansVm, PackageState, PreviewVm, ResultVm,
    RowVm, SteamVm, StoreVm, SystemVm, TopoKnown, UacVm,
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
    /// The journal with every transaction's head and the launch results, for the history page
    /// (P5-6a). Reads only; never kept.
    History,
    /// The system profile.
    System,
    /// The Rerun firewall rules no change of this account owns (P5-6b). Reads the firewall, so
    /// the window sends it only when the System page opens; never kept.
    Orphans,
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
    /// Undoes the transaction whose preview was shown: only if `nonce` is the one of the
    /// dialog the user confirmed (a confirm of an older dialog writes nothing).
    Revert {
        /// The transaction.
        txn: TxnId,
        /// The nonce of the shown preview (`DialogVm::nonce`).
        nonce: u64,
    },
    /// The preview of binding a transaction to the game folder Steam lists now (P5-6c). Reads
    /// only; offered from an undo dialog whose game folder has changed.
    RebindPreview {
        /// The transaction.
        txn: TxnId,
    },
    /// Binds the transaction to the new folder and undoes it there: only if `nonce` is the one
    /// of the rebind dialog the user confirmed (P5-6c, the rule of [`Job::Revert`]).
    Rebind {
        /// The transaction.
        txn: TxnId,
        /// The nonce of the shown rebind preview.
        nonce: u64,
    },
    /// The preview of closing a transaction without undoing it.
    ForgetPreview {
        /// The transaction.
        txn: TxnId,
    },
    /// Closes the transaction whose preview was shown (nonce as for [`Job::Revert`]).
    Forget {
        /// The transaction.
        txn: TxnId,
        /// The nonce of the shown preview.
        nonce: u64,
    },
    /// The preview of clearing the history (P5-6d-1b): what goes and what stays. Reads only.
    ClearPreview,
    /// Clears the history the preview showed: only if `nonce` is the one of the clear dialog the
    /// user confirmed (the rule of [`Job::Revert`]); the core removes exactly what was shown.
    Clear {
        /// The nonce of the shown preview.
        nonce: u64,
    },
    /// Rerun's package store for Settings > Packages (P5-8b-3). Reads only; never kept.
    Store,
    /// The preview of removing one package or every unused one: what goes with its files and
    /// what stays. Reads only.
    RemovePreview {
        /// Which packages.
        pick: flow::Pick,
    },
    /// Removes the packages the preview showed: only if `nonce` is the one of the removal dialog
    /// the user confirmed (the rule of [`Job::Revert`]); the core removes exactly what was shown.
    RemovePackages {
        /// The nonce of the shown preview.
        nonce: u64,
    },
    /// What a fix would download: answers the consent dialog. Reads only.
    DownloadAsk {
        /// The Steam app.
        app_id: u32,
        /// The fix (its variant ID).
        variant: String,
    },
    /// Downloads, verifies and unpacks the packages of the consent dialog whose nonce this is
    /// (also "Try again" of the failure dialog). Nothing is downloaded for another nonce.
    Download {
        /// The nonce of the dialog the user confirmed (`DownloadVm::nonce`).
        nonce: u64,
    },
    /// Opens a source link of a fix in the browser (P5-10a): the core looks the URL up in the
    /// current signed index by this reference; the window never hands over a URL.
    OpenSource(flow::LinkRef),
    /// "Report a problem": the dialog with exactly the text of the issue (reads only, opens
    /// nothing); the worker keeps the report under the dialog's nonce.
    ReportAsk {
        /// The game the page is about.
        app_id: u32,
    },
    /// Opens the issue of the report dialog whose nonce this is in the browser; another nonce
    /// opens nothing.
    ReportOpen {
        /// The nonce of the shown dialog.
        nonce: u64,
    },
    /// Where Rerun's folder is and whether it exists, for Settings > Data (reads only, creates
    /// nothing).
    DataFolder,
    /// Shows Rerun's folder in Explorer, only if it exists.
    OpenDataFolder,
    /// Opens one of Rerun's own links in the browser (Settings > About Rerun, P5-10e): the
    /// source code of this build or the repository. The URL is the core's constant.
    OpenOwn(OwnLink),
    /// Writes the settings the window now has, if they changed (P5-10b).
    SaveSettings(Settings),
}

impl Job {
    /// The job's name for the timing trace.
    fn name(&self) -> String {
        match self {
            Self::Library => "library".to_owned(),
            Self::Game { app_id, .. } => format!("game {app_id}"),
            Self::Status => "status".to_owned(),
            Self::History => "history".to_owned(),
            Self::System => "system".to_owned(),
            Self::Orphans => "orphans".to_owned(),
            Self::Plan { app_id, .. } => format!("plan {app_id}"),
            Self::PreviewShown { .. } => "preview shown".to_owned(),
            Self::Apply { .. } => "apply".to_owned(),
            Self::RevertPreview { .. } => "undo preview".to_owned(),
            Self::Revert { .. } => "undo".to_owned(),
            Self::RebindPreview { .. } => "rebind preview".to_owned(),
            Self::Rebind { .. } => "rebind".to_owned(),
            Self::ForgetPreview { .. } => "forget preview".to_owned(),
            Self::Forget { .. } => "forget".to_owned(),
            Self::ClearPreview => "clear preview".to_owned(),
            Self::Clear { .. } => "clear".to_owned(),
            Self::Store => "store".to_owned(),
            Self::RemovePreview { .. } => "remove preview".to_owned(),
            Self::RemovePackages { .. } => "remove packages".to_owned(),
            Self::DownloadAsk { app_id, .. } => format!("download ask {app_id}"),
            Self::Download { .. } => "download".to_owned(),
            Self::OpenSource(_) => "open source".to_owned(),
            Self::ReportAsk { app_id } => format!("report ask {app_id}"),
            Self::ReportOpen { .. } => "report open".to_owned(),
            Self::DataFolder => "data folder".to_owned(),
            Self::OpenDataFolder => "open data folder".to_owned(),
            Self::OpenOwn(_) => "open own link".to_owned(),
            Self::SaveSettings(_) => "save settings".to_owned(),
        }
    }

    /// The job may change the system: the window cannot close while it is queued or runs
    /// (rule 1, ADR 0027).
    pub fn writes(&self) -> bool {
        matches!(
            self,
            Self::Apply { .. }
                | Self::Revert { .. }
                | Self::Rebind { .. }
                | Self::Forget { .. }
                | Self::Clear { .. }
                | Self::RemovePackages { .. }
        )
    }

    /// The job downloads: the window cancels it and waits for it before it closes (rule 1).
    pub fn downloads(&self) -> bool {
        matches!(self, Self::Download { .. })
    }
}

/// How a [`Job::Download`] ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DownloadOutcome {
    /// Every package is in place; the fix can be selected.
    Done,
    /// The user cancelled; nothing of the running download was kept.
    Cancelled,
    /// It failed; the failure dialog was sent.
    Failed,
    /// The click carried no list that was shown: nothing was downloaded.
    Refused,
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
    /// The history page (P5-6a).
    History(Box<HistoryVm>),
    /// The packages group of the settings (P5-8b-3).
    Store(Box<StoreVm>),
    /// The system page.
    System(SystemVm),
    /// The orphaned firewall rules for the system page (P5-6b).
    Orphans(Box<OrphansVm>),
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
    /// The consent, progress or failure dialog of a package download (P5-5b).
    Download(Box<DownloadVm>),
    /// A [`Job::Download`] has ended (always the last event of it, after the fresh page).
    DownloadEnded(DownloadOutcome),
    /// The shell took a link or Rerun's folder (P5-10a): a report dialog closes.
    Opened,
    /// Settings > Data: where Rerun's folder is (P5-10a).
    DataFolder(Box<DataVm>),
    /// The next core call may start the elevated helper and Windows shows its UAC dialog: the
    /// worker blocks until the user answers it. Always followed by [`Event::Result`] (or, for an
    /// undo whose state changed meanwhile, [`Event::Dialog`]).
    WaitingForUac(Box<UacVm>),
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
    /// The user's shell: links and Rerun's folder (P5-10a). Outside `flow::Env`, which the
    /// CLI shares; only the app has one.
    pub shell: Arc<dyn Shell>,
    /// Rerun's install folder (the folder of `rerun-app.exe`), or why it is unknown.
    pub install: Result<PathBuf, String>,
}

/// The worker thread's handle.
pub struct Worker {
    jobs: Sender<Job>,
    /// The owner of the UAC dialog: the system reads it at every helper start.
    owner: PromptOwnerSlot,
    events: Receiver<Event>,
    /// Write jobs queued or running: the window does not close while it is above zero.
    writes: Arc<AtomicUsize>,
    /// Downloads queued or running: the window cancels them and waits before it closes.
    downloads: Arc<AtomicUsize>,
    /// The cancel flag of the download (shared with the session).
    cancel: Arc<AtomicBool>,
    /// The language the next job speaks (P5-10d): the window changes it at once, without a restart.
    german: Arc<AtomicBool>,
}

impl Worker {
    /// Starts the thread. `make` builds the world on it (a `WinSystem` is created and used on
    /// one thread only) with the slot of the UAC dialog's owner, which the window fills later
    /// ([`Self::set_owner`]); if it fails, every job is answered with [`Event::Blocked`].
    /// `settings`: what `main` read before the window (what [`Job::SaveSettings`] compares with).
    pub fn start<F>(
        lang: Lang,
        settings: Memo,
        make: F,
        wake: Box<dyn Wake>,
    ) -> std::io::Result<Self>
    where
        F: FnOnce(PromptOwnerSlot) -> Result<World, Shown<'static>> + Send + 'static,
    {
        let (jobs, job_rx) = mpsc::channel::<Job>();
        let owner = PromptOwnerSlot::new();
        let thread_owner = owner.clone();
        let (event_tx, events) = mpsc::channel::<Event>();
        let writes = Arc::new(AtomicUsize::new(0));
        let downloads = Arc::new(AtomicUsize::new(0));
        let cancel = Arc::new(AtomicBool::new(false));
        let thread_writes = writes.clone();
        let thread_downloads = downloads.clone();
        let thread_cancel = cancel.clone();
        let german = Arc::new(AtomicBool::new(lang == Lang::De));
        let thread_german = german.clone();
        std::thread::Builder::new()
            .name("rerun-worker".to_owned())
            .spawn(move || {
                let world = make(thread_owner);
                let mut emit = |e: Event| {
                    // The window is gone when the receiver is: nothing left to tell.
                    if event_tx.send(e).is_ok() {
                        wake.wake();
                    }
                };
                let mut session = Session {
                    writes: thread_writes,
                    downloads: thread_downloads,
                    cancel: thread_cancel,
                    settings,
                    ..Session::default()
                };
                if let Ok(w) = &world {
                    session.shell = ShellRef(w.shell.clone());
                }
                // A library job that stopped a running scan: it runs next.
                let mut next: Option<Job> = None;
                let mut spoken = lang;
                while let Some(job) = next.take().or_else(|| job_rx.recv().ok()) {
                    // The language of this job (P5-10d); what the session kept in the old one
                    // (the system page) is read again.
                    let lang = if thread_german.load(Ordering::SeqCst) {
                        Lang::De
                    } else {
                        Lang::En
                    };
                    if lang != spoken {
                        session.system = None;
                        spoken = lang;
                    }
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
                        Err(detail) => {
                            let _guard = WriteGuard::new(&session, &job);
                            emit(Event::Blocked(no_system(detail.clone(), lang)));
                            if job.downloads() {
                                emit(Event::DownloadEnded(DownloadOutcome::Refused));
                            }
                        }
                    }
                }
            })?;
        Ok(Self {
            jobs,
            owner,
            events,
            writes,
            downloads,
            cancel,
            german,
        })
    }

    /// The language of every job queued from now on (P5-10d). The window sends the jobs that
    /// read its pages again after it.
    pub fn set_lang(&self, lang: Lang) {
        self.german.store(lang == Lang::De, Ordering::SeqCst);
    }

    /// Hands the system the window that owns the UAC dialog; it is used from the next helper
    /// start on. Only the first owner counts (`false` for a later one); `None` (the window has no
    /// native handle) leaves the dialog without an owner of the app's.
    pub fn set_owner(&self, owner: Option<PromptOwner>) -> bool {
        owner.is_some_and(|o| self.owner.set(o))
    }

    /// Queues a job (ignored once the thread has ended). A write job counts as running from
    /// here on, so the window cannot close between the click and the worker picking it up.
    pub fn send(&self, job: Job) {
        let writes = job.writes();
        let downloads = job.downloads();
        if writes {
            self.writes.fetch_add(1, Ordering::SeqCst);
        }
        if downloads {
            // A new download starts uncancelled; a cancel after this call reaches it.
            self.cancel.store(false, Ordering::SeqCst);
            self.downloads.fetch_add(1, Ordering::SeqCst);
        }
        if self.jobs.send(job).is_err() {
            if writes {
                self.writes.fetch_sub(1, Ordering::SeqCst);
            }
            if downloads {
                self.downloads.fetch_sub(1, Ordering::SeqCst);
            }
        }
    }

    /// A download is queued or running (rule 1: the window cancels it and closes when it has
    /// stopped).
    pub fn downloading(&self) -> bool {
        self.downloads.load(Ordering::SeqCst) > 0
    }

    /// Asks the running download to stop. Takes effect at the next read (up to WinHTTP's 30 s
    /// receive timeout); the worker answers with [`Event::DownloadEnded`].
    pub fn cancel_download(&self) {
        self.cancel.store(true, Ordering::SeqCst);
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
    /// The last dialog nonce handed out (a confirm must carry the one of the shown dialog).
    nonce: u64,
    /// Write jobs queued or running (shared with [`Worker::busy_writing`]).
    writes: Arc<AtomicUsize>,
    /// Downloads queued or running (shared with [`Worker::downloading`]).
    downloads: Arc<AtomicUsize>,
    /// The download's cancel flag (shared with [`Worker::cancel_download`]).
    pub(crate) cancel: Arc<AtomicBool>,
    /// The time the pages say "ago" against, seconds since 1970-01-01 UTC: `None` reads the
    /// clock (tests set it).
    pub(crate) now: Option<u64>,
    /// The user's shell (the world's; none until the thread has its world, and in tests that
    /// set none).
    pub(crate) shell: ShellRef,
    /// The settings file as read at the start or last written (P5-10b).
    pub(crate) settings: Memo,
}

/// The shell a session opens links and Rerun's folder with.
#[derive(Clone)]
pub struct ShellRef(pub Arc<dyn Shell>);

impl Default for ShellRef {
    fn default() -> Self {
        Self(Arc::new(NoShell))
    }
}

impl std::fmt::Debug for ShellRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ShellRef")
    }
}

impl Session {
    /// Now, seconds since 1970-01-01 UTC (reading the clock changes nothing).
    fn now_s(&self) -> u64 {
        self.now.unwrap_or_else(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs())
        })
    }
}

/// The proof tokens of the flows the window may confirm: the bytes whose preview was handed
/// over, and the observation an undo or forget preview showed. Memory only; one of each at a
/// time (a new preview replaces the old).
#[derive(Debug, Default)]
struct Pending {
    /// A plan whose preview was handed to the window, not yet reported rendered, with the UAC
    /// prompt its preview named (a plan with firewall rules).
    plan: Option<(u32, Planned, Option<PromptState>)>,
    /// A plan whose preview the window rendered: "Apply" may use it.
    shown: Option<(u32, Previewed, Option<PromptState>)>,
    /// An undo preview, with the game its transaction is about, its nonce and the UAC prompt
    /// the dialog named (an undo that removes a firewall rule).
    revert: Option<(RevertShown, Option<u32>, u64, Option<PromptState>)>,
    /// A rebind preview, with the game its transaction is about and its nonce (P5-6c; no
    /// prompt: a change with a firewall rule keeps no token).
    rebind: Option<(RebindShown, Option<u32>, u64)>,
    /// A forget preview, with the game its transaction is about.
    forget: Option<(ForgetShown, Option<u32>, u64)>,
    /// A clear preview with its nonce (P5-6d-1b): the entries and launch results the dialog
    /// listed, each with the hash it was read with.
    clear: Option<(ClearShown, u64)>,
    /// A package removal preview with its nonce (P5-8b-3): the packages, archives and leftovers
    /// the dialog listed, each with the file ID it was read with.
    store: Option<(RemoveShown, u64)>,
    /// Which packages the last removal preview was for: a dialog that changed is shown again
    /// for the same ones.
    store_pick: Option<flow::Pick>,
    /// The list the consent (or failure) dialog showed: a download is made only for it.
    consent: Option<Consent>,
    /// The report the report dialog showed, under its nonce: only its URL is opened.
    report: Option<(u64, flow::Report)>,
}

/// What a download dialog showed, kept under its nonce (the consent is bound to this list).
#[derive(Debug)]
struct Consent {
    nonce: u64,
    app_id: u32,
    variant: String,
    /// The packages the fix still needs (not unpacked yet), as shown.
    needs: Vec<PackageNeed>,
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
/// Counts a write job as finished when dropped (done, refused, never started, or a panic).
struct WriteGuard(Option<Arc<AtomicUsize>>);

impl WriteGuard {
    /// Counts `job` in the counter of its kind (writes or downloads), if it has one.
    fn new(session: &Session, job: &Job) -> Self {
        Self(if job.writes() {
            Some(session.writes.clone())
        } else if job.downloads() {
            Some(session.downloads.clone())
        } else {
            None
        })
    }
}

impl Drop for WriteGuard {
    fn drop(&mut self) {
        if let Some(w) = &self.0 {
            let _ = w.try_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
                Some(n.saturating_sub(1))
            });
        }
    }
}

pub fn run_in(
    env: Env<'_>,
    job: &Job,
    lang: Lang,
    session: &mut Session,
    waiting: &mut dyn FnMut() -> Option<Job>,
    emit: &mut dyn FnMut(Event),
) -> Option<Job> {
    let began = std::time::Instant::now();
    // Dropped at the end of the job, also on a panic: the window may close then.
    let _guard = WriteGuard::new(session, job);
    let preempted = run_job(env, job, lang, session, waiting, emit);
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
            // A download's dialog must not outlive a stopped job.
            if job.downloads() {
                emit(Event::DownloadEnded(DownloadOutcome::Refused));
            }
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
        Job::History => emit(Event::History(Box::new(history_page(&g, lang, session)))),
        Job::Orphans => {
            let r = g.app().map(|app| flow::orphans(g.env().sys, app));
            emit(Event::Orphans(Box::new(vm::orphans(r.as_ref(), lang))));
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
                .is_some_and(|(_, p, _)| p.hash().to_string() == *hash)
                && let Some((app, p, prompt)) = session.pending.plan.take()
            {
                session.pending.shown = Some((app, flow::shown(p), prompt));
                emit(Event::PreviewReady { hash: hash.clone() });
            }
        }
        Job::Apply { hash } => apply(&mut g, hash, lang, session, emit),
        Job::RevertPreview { txn } => revert_preview(&g, txn, false, lang, session, emit),
        Job::Revert { txn, nonce } => revert(&g, txn, *nonce, lang, session, emit),
        Job::RebindPreview { txn } => rebind_preview(&g, txn, false, lang, session, emit),
        Job::Rebind { txn, nonce } => rebind(&g, txn, *nonce, lang, session, emit),
        Job::ForgetPreview { txn } => forget_preview(&g, txn, false, lang, session, emit),
        Job::Forget { txn, nonce } => forget(&g, txn, *nonce, lang, session, emit),
        Job::ClearPreview => clear_preview(&g, false, lang, session, emit),
        Job::Clear { nonce } => clear(&g, *nonce, lang, session, emit),
        Job::Store => emit(Event::Store(Box::new(store_page(&g, lang, session)))),
        Job::RemovePreview { pick } => {
            session.pending.store_pick = Some(pick.clone());
            remove_preview(&g, pick, false, lang, session, emit);
        }
        Job::RemovePackages { nonce } => remove_packages(&g, *nonce, lang, session, emit),
        Job::DownloadAsk { app_id, variant } => {
            download_ask(&g, *app_id, variant, lang, session, emit);
        }
        Job::Download { nonce } => download(&g, *nonce, lang, session, emit),
        Job::OpenSource(r) => {
            let r = flow::source_url(&g, r)
                .map_err(flow::OpenError::Refused)
                .and_then(|u| flow::open_url(&*session.shell.0, &u));
            opened(r, lang, emit);
        }
        Job::ReportAsk { app_id } => match flow::report(&g, *app_id) {
            Ok(report) => {
                session.nonce += 1;
                let nonce = session.nonce;
                emit(Event::Dialog(Box::new(vm::report_dialog(
                    &report, nonce, lang,
                ))));
                session.pending.report = Some((nonce, report));
            }
            Err(e) => opened(Err(flow::OpenError::Refused(e)), lang, emit),
        },
        Job::ReportOpen { nonce } => {
            // Only the report of the dialog the user confirmed; the dialog closes either way.
            match session.pending.report.take() {
                Some((n, report)) if n == *nonce => {
                    opened(flow::open_url(&*session.shell.0, report.url()), lang, emit);
                }
                _ => emit(Event::Result(vm::open_stale(lang))),
            }
        }
        Job::DataFolder => {
            emit(Event::DataFolder(Box::new(vm::data_folder(
                &flow::data_folder(&g),
                lang,
            ))));
        }
        Job::OpenDataFolder => opened(flow::open_data_folder(&g, &*session.shell.0), lang, emit),
        Job::OpenOwn(l) => opened(
            flow::open_url(&*session.shell.0, &OpenUrl::own(*l)),
            lang,
            emit,
        ),
        Job::SaveSettings(new) => {
            let saved = session.settings.save(&mut g, new);
            crate::trace::log(|| format!("worker: settings {}", saved.word()));
        }
    }
    preempted
}

/// What an open came to: [`Event::Opened`], or a calm result that says nothing was opened.
fn opened(r: Result<(), flow::OpenError>, lang: Lang, emit: &mut dyn FnMut(Event)) {
    match r {
        Ok(()) => emit(Event::Opened),
        Err(e) => emit(Event::Result(vm::open_failed(&e, lang))),
    }
}

/// A game's page: the lookup, and the transactions applied to it.
fn game_page(
    g: &Guarded<'_>,
    app_id: u32,
    name: Option<&Shown<'static>>,
    lang: Lang,
    session: &mut Session,
) -> GameVm {
    game_page_view(g, app_id, name, lang, session).0
}

/// [`game_page`], with the flow's view it was made from (`None` when the lookup was refused).
fn game_page_view(
    g: &Guarded<'_>,
    app_id: u32,
    name: Option<&Shown<'static>>,
    lang: Lang,
    session: &mut Session,
) -> (GameVm, Option<GameView>) {
    let (mut page, view) = match flow::game_cached(g, app_id, Some(&mut session.games)) {
        Ok(v) => {
            // The helper is asked only when a fix needs it (a few reads in Program Files).
            let helper = needs_helper(&v).then(|| vm::helper_state(&flow::helper(g)));
            (vm::game(&v, name, helper.as_ref(), lang), Some(v))
        }
        Err(e) => (vm::game_refused(app_id, name, &e, lang), None),
    };
    if let Some(Ok(j)) = g.app().map(|app| flow::journal(app, Heads::Open)) {
        page.applied = vm::cards(&j.status, &session.names, lang)
            .into_iter()
            .filter(|c| c.app_id == Some(app_id))
            .collect();
        // The last start of this game (P5-6a): a fact, and the notes that go with it.
        if let Ok(Some(r)) = &j.launch
            && let lines = flow::launch_lines(r, &j.holders)
            && let Some(l) = flow::launch_of(&lines, app_id)
            && let Some((fact, notes)) = vm::last_launch(l, session.now_s(), lang)
        {
            page.facts.push(fact);
            page.notes.extend(notes);
        }
    }
    session.pages.insert(app_id, fix_key(&page));
    (page, view)
}

/// Whether a fix of the view needs the elevated helper.
fn needs_helper(v: &GameView) -> bool {
    match &v.lookup {
        Lookup::Read {
            found: Found::One(m),
            ..
        } => m.fixes.iter().any(|f| f.needs_helper),
        _ => false,
    }
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
            // The journal only (review of P5-3): the orphaned firewall rules are read by their
            // own job when the System page opens (`Job::Orphans`, P5-6b).
            let s = exec::status(app);
            vm::applied(Some(s.as_ref()), &session.names, lang)
        }
    }
}

/// The history page from the journal, every head read (P5-6a; never kept).
fn history_page(g: &Guarded<'_>, lang: Lang, session: &Session) -> HistoryVm {
    let now = session.now_s();
    match g.app() {
        None => vm::history(None, &session.names, now, lang),
        Some(app) => {
            let j = flow::journal(app, Heads::All);
            vm::history(Some(j.as_ref()), &session.names, now, lang)
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
    // No page before (a rescan cleared them) counts as a difference: the window may hold a
    // page the session cannot vouch for. The note comes first, then the page, so the window
    // clears its selection before it takes the fresh page.
    if before.as_ref().is_none_or(|b| *b != fix_key(&page)) {
        emit(Event::Result(vm::stale(lang)));
        emit(Event::Game(page));
        return;
    }
    let refused = |result| Event::PreviewRefused { app_id, result };
    // Only fixes the app can apply here (not a download the user has not agreed to, not the
    // helper when it cannot run): the lock holds in the worker too, whatever a caller sends.
    if !picks.iter().all(|p| {
        page.fixes
            .iter()
            .any(|f| f.key == p.variant && f.offer == Offer::Selectable)
    }) {
        emit(refused(vm::not_available(lang)));
        return;
    }
    match flow::plan(g, app_id, picks) {
        Err(e) => emit(refused(vm::game_refusal(&e, lang))),
        Ok(Lookup::Read {
            found: Found::One(picked),
            ..
        }) => match picked.planned {
            Err(e) => emit(refused(vm::plan_refusal(&e, lang))),
            Ok(planned) => {
                // A plan with firewall rules needs the helper now, and its preview names the
                // prompt Windows will show (ADR 0023 §10).
                let prompt = match helper_prompt(g, planned.preview()) {
                    Ok(p) => p,
                    Err(r) => {
                        emit(refused(vm::refusal(&r, lang)));
                        return;
                    }
                };
                let env = g.env();
                let launch = flow::launch_view(env.sys, env.install, planned.preview());
                let vm = vm::preview_vm(&planned, launch.as_ref(), prompt.as_ref(), lang);
                session.pending.plan = Some((app_id, planned, prompt));
                emit(Event::Preview {
                    app_id,
                    vm: Box::new(vm),
                });
            }
        },
        // The game reads differently now (another build, no Topo): the page is the answer.
        Ok(_) => {
            emit(Event::Result(vm::stale(lang)));
            emit(Event::Game(page));
        }
    }
}

/// Whether an undo preview keeps its token: an undo that needs the administrator prompt only
/// when the helper could run now (P5-5c); otherwise no confirm can reach `flow::revert`.
pub(crate) fn token_kept(prompt: Option<&PromptState>, helper: Option<&HelperState>) -> bool {
    prompt.is_none() || matches!(helper, Some(HelperState::Ready(_)))
}

/// The UAC prompt a plan's apply would meet: `None` for a plan without firewall rules (no
/// helper), else the state of `flow::helper`, or the refusal the apply would meet before any
/// prompt (the helper not installed safely, Windows granting no elevation). Package files need
/// nothing here since P5-5b: the planner reads them from Rerun's packages folder and hashes them
/// against the Topo's pinned values.
pub(crate) fn helper_prompt(
    g: &Guarded<'_>,
    pv: &rerun_core::plan::Preview,
) -> Result<Option<PromptState>, rerun_core::exec::Refusal> {
    if pv.firewall.is_none() {
        return Ok(None);
    }
    flow::helper(g).map(Some)
}

/// Tells the window that the next core call may start the helper and Windows shows its dialog:
/// the modal "waiting for Windows" until the result (P5-5c).
fn waiting_for_uac(prompt: Option<&PromptState>, lang: Lang, emit: &mut dyn FnMut(Event)) {
    if let Some(s) = prompt.filter(|s| s.has_dialog()) {
        emit(Event::WaitingForUac(Box::new(vm::uac_wait(s, lang))));
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
        .is_some_and(|(_, p, _)| p.hash().to_string() == hash);
    let Some((app_id, p, prompt)) = wanted.then(|| session.pending.shown.take()).flatten() else {
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
                session.pending.shown = Some((app_id, p, prompt));
                again = true;
            }
            r
        }
        Ok(0) => vm::apply_result(Ok(exec::Outcome::Nothing), lang),
        Ok(_) => {
            // Every check passed: the helper starts at the end of this apply (its batch is the
            // plan's last ops), and the thread blocks until the user answers Windows.
            waiting_for_uac(prompt.as_ref(), lang, emit);
            let done = flow::apply(g, p);
            if let Ok(a) = &done {
                log_tidy(&a.tidied);
            }
            vm::applied_result(done, lang)
        }
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
    session.pending.rebind = None;
    match flow::revert_preview(g, txn) {
        Ok((p, shown)) => {
            let app = vm::app_of(&p.status);
            session.nonce += 1;
            let nonce = session.nonce;
            // An undo that removes a firewall rule needs the helper: asked now, so a dialog that
            // can be confirmed never ends in a refusal the user could have been told about.
            let helper = p
                .prompt
                .is_some()
                .then(|| vm::helper_state(&flow::helper(g)));
            // A halt at a Steam folder that is gone: a rebind may help (P5-6c). Only offered; the
            // rebind preview is the authority.
            let rebind = p
                .verified
                .halted
                .as_ref()
                .is_some_and(|h| flow::rebind_may_help(flow::RebindCue::Halted(&p.status, h)));
            let dialog = vm::revert_vm(
                &p,
                g.env().install,
                changed,
                nonce,
                helper.as_ref(),
                rebind,
                lang,
            );
            // Without a ready helper no token is kept, so no confirm can reach `flow::revert`.
            if token_kept(p.prompt.as_ref(), helper.as_ref()) {
                let prompt = match helper {
                    Some(HelperState::Ready(s)) => Some(s),
                    _ => None,
                };
                session.pending.revert = Some((shown, app, nonce, prompt));
            }
            emit(Event::Dialog(Box::new(dialog)));
        }
        // The game folder is another folder now: nothing to undo yet, but a rebind may help.
        Err(RevertGate::Refused(r)) if flow::rebind_may_help(flow::RebindCue::Refused(&r)) => {
            session.nonce += 1;
            let nonce = session.nonce;
            let dialog = vm::revert_refused_vm(*txn, &r, nonce, changed, lang);
            emit(Event::Dialog(Box::new(dialog)));
        }
        Err(gate) => emit(Event::Result(vm::gate(&gate, lang))),
    }
}

/// What an undo or a rebind came to: the result with the report per change and the launch option,
/// then the pages read again.
fn finish_revert(
    g: &Guarded<'_>,
    o: flow::RevertOutcome,
    app: Option<u32>,
    lang: Lang,
    session: &mut Session,
    emit: &mut dyn FnMut(Event),
) {
    log_tidy(&o.tidied);
    // The head names what each change was (read only; the journal is as the undo left it).
    let ops = g
        .app()
        .and_then(|app| flow::transaction(app, &o.report.txn))
        .map(|st| vm::head_ops(&st, lang))
        .unwrap_or_default();
    let mut r = vm::revert_result(&o, &ops, lang);
    if let Some(l) = o.launch_option {
        vm::add_launch_option(&mut r, &l, g.env().install, lang);
    }
    emit(Event::Result(r));
    refresh(g, app, lang, session, emit);
}

/// Undoes the transaction of the dialog the user confirmed (`nonce`). A confirm of any other
/// dialog (an older one, or a second click queued behind a preview that was refreshed) writes
/// nothing: the current preview is shown again and the user confirms that one.
fn revert(
    g: &Guarded<'_>,
    txn: &TxnId,
    nonce: u64,
    lang: Lang,
    session: &mut Session,
    emit: &mut dyn FnMut(Event),
) {
    let ok = session
        .pending
        .revert
        .as_ref()
        .is_some_and(|(s, _, n, _)| s.txn() == *txn && *n == nonce);
    let Some((shown, app, _, prompt)) = ok.then(|| session.pending.revert.take()).flatten() else {
        revert_preview(g, txn, true, lang, session, emit);
        return;
    };
    // The helper's batch is reverted first (LIFO), so the dialog of Windows comes right away.
    waiting_for_uac(prompt.as_ref(), lang, emit);
    match flow::revert(g, shown) {
        Ok(o) => finish_revert(g, o, app, lang, session, emit),
        // What is there now differs from the preview: nothing was written; show it again.
        Err(ActError::Changed) => revert_preview(g, txn, true, lang, session, emit),
        Err(e) => {
            emit(Event::Result(vm::act_error(&e, lang)));
            refresh(g, app, lang, session, emit);
        }
    }
}

/// The preview of binding a transaction to the folder Steam lists now (P5-6c). Reads only. A
/// transaction that is bound already goes straight to the undo preview; every other refusal is
/// said in its own words.
fn rebind_preview(
    g: &Guarded<'_>,
    txn: &TxnId,
    changed: bool,
    lang: Lang,
    session: &mut Session,
    emit: &mut dyn FnMut(Event),
) {
    session.pending.revert = None;
    session.pending.rebind = None;
    match flow::rebind_preview(g, txn) {
        Ok((view, shown)) => {
            let app = vm::app_of(&view.status);
            session.nonce += 1;
            let nonce = session.nonce;
            let dialog = vm::rebind_vm(&view, g.env().install, changed, nonce, lang);
            // A change with a firewall rule cannot be confirmed here: no token, so no confirm
            // reaches the core (the dialog says why).
            if dialog.can_confirm {
                session.pending.rebind = Some((shown, app, nonce));
            }
            emit(Event::Dialog(Box::new(dialog)));
        }
        // Bound already: undo it as it is.
        Err(RevertGate::Refused(Refusal::Rebind(RebindRefusal::AlreadyBound { .. }))) => {
            revert_preview(g, txn, false, lang, session, emit);
        }
        Err(gate) => emit(Event::Result(vm::gate(&gate, lang))),
    }
}

/// Binds and undoes the transaction of the rebind dialog the user confirmed (`nonce`). A confirm
/// of any other dialog writes nothing: the current rebind preview is shown again (H1 of P5-5a).
fn rebind(
    g: &Guarded<'_>,
    txn: &TxnId,
    nonce: u64,
    lang: Lang,
    session: &mut Session,
    emit: &mut dyn FnMut(Event),
) {
    let ok = session
        .pending
        .rebind
        .as_ref()
        .is_some_and(|(s, _, n)| s.txn() == *txn && *n == nonce);
    let Some((shown, app, _)) = ok.then(|| session.pending.rebind.take()).flatten() else {
        rebind_preview(g, txn, true, lang, session, emit);
        return;
    };
    match flow::rebind(g, shown) {
        Ok(o) => finish_revert(g, o, app, lang, session, emit),
        // What is on disk now differs from the preview: nothing was written; show it again.
        Err(ActError::Changed)
        | Err(ActError::Exec(ExecError::Refused(Refusal::Rebind(RebindRefusal::Changed)))) => {
            rebind_preview(g, txn, true, lang, session, emit);
        }
        Err(e) => {
            emit(Event::Result(vm::rebind_failed(&e, lang)));
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
            session.nonce += 1;
            let nonce = session.nonce;
            let dialog = vm::forget_vm(&p, g.env().install, changed, nonce, lang);
            session.pending.forget = Some((shown, app, nonce));
            emit(Event::Dialog(Box::new(dialog)));
        }
        Err(gate) => emit(Event::Result(vm::gate(&gate, lang))),
    }
}

fn forget(
    g: &Guarded<'_>,
    txn: &TxnId,
    nonce: u64,
    lang: Lang,
    session: &mut Session,
    emit: &mut dyn FnMut(Event),
) {
    let ok = session
        .pending
        .forget
        .as_ref()
        .is_some_and(|(s, _, n)| s.txn() == *txn && *n == nonce);
    let Some((shown, app, _)) = ok.then(|| session.pending.forget.take()).flatten() else {
        forget_preview(g, txn, true, lang, session, emit);
        return;
    };
    match flow::forget(g, shown) {
        Ok(done) => {
            log_tidy(&done.tidied);
            emit(Event::Result(vm::forget_result(&done.tidied, lang)));
            refresh(g, app, lang, session, emit);
        }
        Err(ActError::Changed) => forget_preview(g, txn, true, lang, session, emit),
        Err(e) => {
            emit(Event::Result(vm::act_error(&e, lang)));
            refresh(g, app, lang, session, emit);
        }
    }
}

/// The history's upkeep after a write that ran into trouble: logged and never shown (the write it
/// followed went through, P5-6d-1b).
fn log_tidy(t: &flow::Tidy) {
    match t {
        Ok(_) => {}
        Err(flow::TidyNote::Journal(e)) => crate::trace::log(|| {
            format!(
                "worker: history upkeep removed nothing (journal): {}",
                vm::shown_error(e).as_str()
            )
        }),
        Err(flow::TidyNote::Exec(e)) => crate::trace::log(|| {
            format!(
                "worker: history upkeep removed nothing (purge): {}",
                vm::shown_error(e).as_str()
            )
        }),
    }
}

/// The preview of clearing the history (P5-6d-1b, rule 5): the list of what goes and what stays.
/// Reads only. `changed`: shown again because the history changed since the dialog the user
/// confirmed.
fn clear_preview(
    g: &Guarded<'_>,
    changed: bool,
    lang: Lang,
    session: &mut Session,
    emit: &mut dyn FnMut(Event),
) {
    session.pending.clear = None;
    match flow::clear_preview(g) {
        Ok((p, shown)) => {
            session.nonce += 1;
            let nonce = session.nonce;
            let dialog = vm::clear_vm(&p, &session.names, changed, nonce, lang);
            // Nothing to remove: no token, so no confirm reaches the core (the dialog has none).
            if !shown.is_empty() {
                session.pending.clear = Some((shown, nonce));
            }
            emit(Event::Dialog(Box::new(dialog)));
        }
        Err(gate) => emit(Event::Result(vm::clear_gate(&gate, lang))),
    }
}

/// Clears the history of the dialog the user confirmed (`nonce`). A confirm of any other dialog
/// writes nothing: the current preview is shown again. The core removes exactly what was shown
/// and says `Changed` when something else is there now (nothing written, the preview again).
fn clear(
    g: &Guarded<'_>,
    nonce: u64,
    lang: Lang,
    session: &mut Session,
    emit: &mut dyn FnMut(Event),
) {
    let ok = session
        .pending
        .clear
        .as_ref()
        .is_some_and(|(_, n)| *n == nonce);
    let Some((shown, _)) = ok.then(|| session.pending.clear.take()).flatten() else {
        clear_preview(g, true, lang, session, emit);
        return;
    };
    match flow::clear(g, shown) {
        Ok(report) => {
            emit(Event::Result(vm::clear_done(&report, lang)));
            emit(Event::History(Box::new(history_page(g, lang, session))));
        }
        Err(ActError::Changed) => clear_preview(g, true, lang, session, emit),
        Err(e) => {
            emit(Event::Result(vm::act_error(&e, lang)));
            emit(Event::History(Box::new(history_page(g, lang, session))));
        }
    }
}

/// The packages group of the settings from the store as it is now (P5-8b-3; never kept).
fn store_page(g: &Guarded<'_>, lang: Lang, session: &Session) -> StoreVm {
    match flow::package_store(g) {
        Ok(v) => vm::store(&v, &session.names, lang),
        Err(gate) => vm::store_unavailable(&gate, lang),
    }
}

/// The preview of removing packages (P5-8b-3, rule 5): what goes with every file, and what stays
/// with its reason. Reads only. `changed`: shown again because the store, or the use of a
/// package, changed since the dialog the user confirmed.
fn remove_preview(
    g: &Guarded<'_>,
    pick: &flow::Pick,
    changed: bool,
    lang: Lang,
    session: &mut Session,
    emit: &mut dyn FnMut(Event),
) {
    session.pending.store = None;
    match flow::remove_preview(g, pick) {
        Ok((p, shown)) => {
            session.nonce += 1;
            let nonce = session.nonce;
            let dialog = vm::store_dialog(&p, &session.names, changed, nonce, lang);
            // Nothing to remove: no token, so no confirm reaches the core (the dialog has none).
            if !shown.is_empty() {
                session.pending.store = Some((shown, nonce));
            }
            emit(Event::Dialog(Box::new(dialog)));
        }
        Err(flow::StoreGate::NotFound) => {
            // Gone since the list: say so and show the list as it is.
            emit(Event::Result(vm::store_gate(
                &flow::StoreGate::NotFound,
                lang,
            )));
            emit(Event::Store(Box::new(store_page(g, lang, session))));
        }
        Err(gate) => emit(Event::Result(vm::store_gate(&gate, lang))),
    }
}

/// Removes the packages of the dialog the user confirmed (`nonce`). A confirm of any other
/// dialog writes nothing: the current preview is shown again. The core removes exactly what was
/// shown and says `Changed` when the store or the use of a package is not what it showed
/// (nothing removed, the preview again). After a removal the session forgets what it read of the
/// games, so a fix card that needed a package offers the download again.
fn remove_packages(
    g: &Guarded<'_>,
    nonce: u64,
    lang: Lang,
    session: &mut Session,
    emit: &mut dyn FnMut(Event),
) {
    let ok = session
        .pending
        .store
        .as_ref()
        .is_some_and(|(_, n)| *n == nonce);
    let Some((shown, _)) = ok.then(|| session.pending.store.take()).flatten() else {
        let pick = session
            .pending
            .store_pick
            .clone()
            .unwrap_or(flow::Pick::Unused);
        remove_preview(g, &pick, true, lang, session, emit);
        return;
    };
    match flow::remove(g, shown) {
        Ok(removed) => {
            session.games.clear();
            session.pages.clear();
            // A preview that names a package which may be gone is void: it is planned again, so
            // an apply never goes through the stale path (the core checks the package anyway).
            session.pending.plan = None;
            session.pending.shown = None;
            emit(Event::Result(vm::store_done(&removed, lang)));
            emit(Event::Store(Box::new(store_page(g, lang, session))));
        }
        Err(ActError::Changed) => {
            let pick = session
                .pending
                .store_pick
                .clone()
                .unwrap_or(flow::Pick::Unused);
            remove_preview(g, &pick, true, lang, session, emit);
        }
        Err(e) => {
            emit(Event::Result(vm::act_error(&e, lang)));
            emit(Event::Store(Box::new(store_page(g, lang, session))));
        }
    }
}

/// The fix `variant` of a game view.
fn fix_of<'v>(view: &'v GameView, variant: &str) -> Option<&'v flow::Fix> {
    match &view.lookup {
        Lookup::Read {
            found: Found::One(m),
            ..
        } => m.fixes.iter().find(|f| f.variant == variant),
        _ => None,
    }
}

/// The consent dialog for a fix that needs packages: what would be downloaded, read only
/// (nothing is requested, nothing is created). The game is read again first, as a plan does: a
/// window that holds a page the files no longer match gets the fresh page instead.
fn download_ask(
    g: &Guarded<'_>,
    app_id: u32,
    variant: &str,
    lang: Lang,
    session: &mut Session,
    emit: &mut dyn FnMut(Event),
) {
    session.pending.consent = None;
    let before = session.pages.get(&app_id).cloned();
    session.games.forget(app_id);
    let name = session.names.get(&app_id).cloned();
    let (page, view) = game_page_view(g, app_id, name.as_ref(), lang, session);
    if before.as_ref().is_none_or(|b| *b != fix_key(&page)) {
        emit(Event::Result(vm::stale(lang)));
        emit(Event::Game(page));
        return;
    }
    // Only a fix the page offers with a download: nothing else is asked for.
    let offered = page
        .fixes
        .iter()
        .any(|f| f.key == variant && f.offer == Offer::NeedsDownload);
    let needs: Vec<PackageNeed> = view
        .as_ref()
        .and_then(|v| fix_of(v, variant))
        .map(|f| {
            f.packages
                .iter()
                .filter(|p| p.state == NeedState::Missing)
                .cloned()
                .collect()
        })
        .unwrap_or_default();
    if !offered || needs.is_empty() {
        emit(Event::Result(vm::not_available(lang)));
        return;
    }
    session.nonce += 1;
    let nonce = session.nonce;
    let dialog = vm::consent(app_id, variant, &needs, nonce, lang);
    session.pending.consent = Some(Consent {
        nonce,
        app_id,
        variant: variant.to_owned(),
        needs,
    });
    emit(Event::Download(Box::new(dialog)));
}

/// How often progress reaches the window (every report in tests, so they see each state).
const PROGRESS_EVERY: std::time::Duration = if cfg!(test) {
    std::time::Duration::ZERO
} else {
    std::time::Duration::from_millis(100)
};

/// Downloads the packages of the dialog the user confirmed (`nonce`), one after the other, through
/// `flow::fetch` with the session's cancel flag. Only a list that was shown is downloaded: a
/// confirm that matches none writes nothing and asks nobody. The core checks the index against
/// the shown list again for every package.
fn download(
    g: &Guarded<'_>,
    nonce: u64,
    lang: Lang,
    session: &mut Session,
    emit: &mut dyn FnMut(Event),
) {
    let shown = session
        .pending
        .consent
        .as_ref()
        .is_some_and(|c| c.nonce == nonce);
    let Some(c) = shown.then(|| session.pending.consent.take()).flatten() else {
        emit(Event::Result(vm::no_consent(lang)));
        emit(Event::DownloadEnded(DownloadOutcome::Refused));
        return;
    };
    let cancel = session.cancel.clone();
    let mut states = vec![PackageState::Waiting; c.needs.len()];
    let progress = |states: &[PackageState]| {
        Event::Download(Box::new(vm::progress(
            c.app_id,
            &c.variant,
            &c.needs,
            states,
            nonce,
            cancel.load(Ordering::SeqCst),
            lang,
        )))
    };
    emit(progress(&states));
    let mut last = std::time::Instant::now();
    for i in 0..c.needs.len() {
        let result = {
            let mut on = |p: Progress| {
                states[i] = match p {
                    Progress::Download {
                        read, announced, ..
                    } => PackageState::Reading { read, announced },
                    Progress::Cached { .. } => PackageState::Cached,
                    Progress::Unpacking => PackageState::Unpacking,
                };
                // Throttled: the core reports every 64 KiB, the window needs a few a second.
                if last.elapsed() >= PROGRESS_EVERY || matches!(p, Progress::Unpacking) {
                    last = std::time::Instant::now();
                    emit(progress(&states));
                }
            };
            flow::fetch(g, &c.needs[i], &mut on, &cancel)
        };
        match result {
            Ok(_) => {
                states[i] = PackageState::Done;
                emit(progress(&states));
            }
            Err(FetchError::Cancelled) => {
                // What finished before stays unpacked; the page shows where things stand.
                emit(Event::Result(vm::cancelled(lang)));
                refresh_page(g, c.app_id, lang, session, emit);
                emit(Event::DownloadEnded(DownloadOutcome::Cancelled));
                return;
            }
            Err(e) => {
                states[i] = PackageState::Failed;
                for s in &mut states[i + 1..] {
                    *s = PackageState::NotStarted;
                }
                session.nonce += 1;
                let again = session.nonce;
                emit(Event::Download(Box::new(vm::failed(
                    c.app_id, &c.variant, &c.needs, &states, &e, again, lang,
                ))));
                let app_id = c.app_id;
                // The list is kept for "Try again" only when trying again can help (the
                // dialog offers it only then).
                if e.transient() {
                    session.pending.consent = Some(Consent { nonce: again, ..c });
                }
                if e.kind() == flow::FetchKind::Changed {
                    // The index changed: the page may offer other fixes now.
                    refresh_page(g, app_id, lang, session, emit);
                }
                emit(Event::DownloadEnded(DownloadOutcome::Failed));
                return;
            }
        }
    }
    // Every package is in place: the window selects the fix when it takes the fresh page.
    session.games.forget(c.app_id);
    refresh_page(g, c.app_id, lang, session, emit);
    emit(Event::DownloadEnded(DownloadOutcome::Done));
}

/// The game page again (its cached executables dropped), after the packages changed.
fn refresh_page(
    g: &Guarded<'_>,
    app_id: u32,
    lang: Lang,
    session: &mut Session,
    emit: &mut dyn FnMut(Event),
) {
    session.games.forget(app_id);
    let name = session.names.get(&app_id).cloned();
    let page = game_page(g, app_id, name.as_ref(), lang, session);
    emit(Event::Game(page));
}

/// Whether the index names a Topo (not retired) for `app_id`, or only Topos this version sets
/// aside (ADR 0024 amendment "Forward compatibility" §10).
fn topo_known(catalog: Option<&Catalog>, app_id: u32) -> TopoKnown {
    match catalog {
        None => TopoKnown::NoIndex,
        Some(c) => {
            let live = topo::topos_for(c, app_id)
                .iter()
                .any(|t| t.status != Status::Retired);
            let mut aside = c.aside_for(app_id).peekable();
            if live {
                TopoKnown::Yes
            } else if aside.peek().is_some() {
                TopoKnown::Aside {
                    newer: aside.any(|a| a.why.needs_newer()),
                }
            } else {
                TopoKnown::No
            }
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
