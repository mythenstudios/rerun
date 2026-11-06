//! Apply, verify, revert and forget plans (ADR 0020 and its P2-8 amendment), with the journal
//! (ADR 0019).
//!
//! - [`apply`]: checks without writing anything (stored plan and its hash, the lock, stacking
//!   on the listing, every root reopened by identity, the Steam app state, the game closed,
//!   the old state of every op and every source re-observed), then the transaction: op by op
//!   intent, change, done; every op observed `After`; the changed game folders flushed;
//!   `Applied`. Any error after `begin` rolls back at once on the same writer (the revert
//!   loop, which flushes the game folders an op changed before its `RevertDone`), then the
//!   transaction is closed `RolledBack`; if the rollback fails or meets a foreign state, it
//!   stays open.
//! - [`revert`]: the one path for a revert, the recovery of an interrupted apply and (through
//!   the same loop) the rollback: the head parsed from the bytes the writer read under the
//!   lock, LIFO against later transactions, each root on its own (`roots`, E3: open, absent,
//!   or undecided, which refuses), Steam and `users()` of the open roots again, then newest op
//!   first: observe, `RevertIntent`, act, flush, `RevertDone`. A foreign op is recorded
//!   `Foreign` and left; the lower ops are still reverted (user decision D3, R1), and only
//!   `forget` closes. A file op whose root cannot run file ops halts the revert without a
//!   record (6b-d, [`Halt`]): the transaction stays open and resumable.
//! - [`verify`]: what each op of a transaction observes now, read only, without the lock,
//!   newest first and halting where the revert would; also the preview before a revert
//!   (rule 5).
//! - [`forget`]: closes an empty, open or applied transaction with `Closed { Forgotten }`, a
//!   damaged or unreadable one with the marker `journal\<txn>.forgotten` (user decision D2).
//!
//! Observing never trusts a record alone (`file`): every hash is taken on a guard, a link
//! count other than 1 or other R/H/S is "other".
//!
//! Dispatch (audit A2 should-item 3): apply, observe, act, the record check, the flushes and
//! the game-closed check match on [`Op::target`] and hand the op to the module of its domain
//! (`file` for files and directories); the revert loop is one for every domain. A new domain
//! (registry keys and values, P2-10b) adds a [`Target`] variant, a variant of [`Seen`] (and
//! of [`Hint`] where it needs one) and its part of [`Touched`].

mod file;
mod roots;
mod stack;

use std::collections::BTreeMap;

use file::Mode;

use crate::detect::steam::AppState;
use crate::escape::Shown;
use crate::journal::{
    Closing, InstanceTag, Journal, JournalError, Observed, OpLog, Reverting, TxnId, TxnState,
    TxnWriter,
};
use crate::path::RelPath;
use crate::plan::{self, Object, Op, Plan, PlanError, PlanHash, Target};
use crate::policy::root::{AppDir, ForbiddenRoots, RootError};
use crate::sys::fs::TmpName;
use crate::sys::{SysError, SysResult, System};

/// What `exec` works with.
#[derive(Clone, Copy)]
pub struct ExecCtx<'a> {
    /// The system.
    pub sys: &'a dyn System,
    /// The forbidden roots (every root is reopened through `policy::root`).
    pub fr: &'a ForbiddenRoots,
    /// Rerun's folder (journal, plans, packages).
    pub app: &'a AppDir<'a>,
    /// The instance tag of this run (transaction names, temp names). Fresh per run
    /// (`InstanceTag::new`): a journal numbers its temp names from 0, so a tag used twice
    /// could meet a temp name of an earlier run.
    pub tag: InstanceTag,
}

impl std::fmt::Debug for ExecCtx<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExecCtx")
            .field("app", &self.app.path())
            .finish_non_exhaustive()
    }
}

/// Result of a successful [`apply`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The plan has no ops: nothing to do, no transaction (ADR 0020).
    Nothing,
    /// Applied as this transaction.
    Applied(TxnId),
}

/// Why nothing was done: refused before anything was written (no transaction folder, or
/// only an empty one that blocks nothing).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Refusal {
    /// A file of the game is in use (user decision D4).
    #[error("{0} is in use; close the game and try again later")]
    Busy(Shown<'static>),
    /// Another Rerun holds the journal lock.
    #[error("another Rerun is applying or reverting; try again when it has finished")]
    JournalBusy,
    /// A transaction is damaged, unreadable or has a head that cannot be parsed: nothing is
    /// applied (and no earlier one reverted) until it is forgotten (fail closed, E2).
    #[error("transaction {txn} is damaged or unreadable; forget it first")]
    Blocked {
        /// The transaction.
        txn: TxnId,
    },
    /// An interrupted transaction touches an object of this plan.
    #[error("transaction {txn} is interrupted; revert it first")]
    Interrupted {
        /// The transaction.
        txn: TxnId,
    },
    /// A later transaction touches an object of the one to revert (LIFO).
    #[error("transaction {txn} changed the same files later; revert it first")]
    Later {
        /// The transaction.
        txn: TxnId,
    },
    /// Whether a file of the game is in use cannot be checked (access denied): fail closed.
    #[error("{0} cannot be checked for use (access denied)")]
    Unchecked(Shown<'static>),
    /// The Steam app is not installed or is updating (ADR 0012).
    #[error("Steam app {app_id} is {}; try again when Steam has finished", steam_state(*state))]
    Steam {
        /// The app.
        app_id: u32,
        /// Its state.
        state: AppState,
    },
    /// The Steam app has no manifest in its library, or is installed in another folder.
    #[error("Steam app {app_id} {}", steam_gone(*gone))]
    SteamGone {
        /// The app.
        app_id: u32,
        /// Why it is gone.
        gone: SteamGone,
    },
    /// The Steam manifest of the app cannot be read now (Steam may be writing it).
    #[error("the Steam manifest of app {app_id} cannot be read now; try again later")]
    SteamManifest {
        /// The app.
        app_id: u32,
    },
    /// The transaction was forgotten: there is nothing to revert.
    #[error("transaction {txn} was forgotten; there is nothing to revert")]
    Forgotten {
        /// The transaction.
        txn: TxnId,
    },
    /// A root cannot be reopened or is another folder now.
    #[error(transparent)]
    Root(Box<RootError>),
    /// The old state of op `op` (or its source) changed since the preview.
    #[error("op {op} changed since the preview; plan again")]
    Mismatch {
        /// Op index.
        op: u16,
    },
    /// A root the current user cannot write (phase 3: the elevated helper).
    #[error("the game folder needs administrator rights (not supported yet)")]
    NeedsHelper,
    /// The main executable of a root is missing or no plain file (audit A2 should-item 8):
    /// the game-closed check would ask nothing about it.
    #[error("the main executable {0} is missing or not a file; plan again")]
    MainExe(Shown<'static>),
    /// The stored plan is missing, changed or invalid.
    #[error(transparent)]
    Plan(PlanError),
    /// The journal could not be read or the transaction not begun.
    #[error(transparent)]
    Journal(Box<JournalError>),
}

/// Why a Steam app counts as gone for its root (E3 "absent").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SteamGone {
    /// No `appmanifest_<id>.acf` in the library.
    NoManifest,
    /// The manifest names another install folder.
    OtherFolder,
    /// The manifest says not installed.
    NotInstalled,
}

/// A [`SteamGone`] for a message.
fn steam_gone(g: SteamGone) -> &'static str {
    match g {
        SteamGone::NoManifest => "has no manifest in its library (uninstalled)",
        SteamGone::OtherFolder => "is installed in another folder now",
        SteamGone::NotInstalled => "is not installed",
    }
}

/// An app state for a message.
fn steam_state(s: AppState) -> &'static str {
    match s {
        AppState::Installed => "installed",
        AppState::UpdatePending => "updating",
        AppState::NotInstalled => "not installed",
    }
}

impl From<RootError> for Refusal {
    fn from(e: RootError) -> Self {
        Self::Root(Box::new(e))
    }
}

impl From<JournalError> for Refusal {
    fn from(e: JournalError) -> Self {
        match e {
            JournalError::Busy => Self::JournalBusy,
            e => Self::Journal(Box::new(e)),
        }
    }
}

impl From<SysError> for Refusal {
    fn from(e: SysError) -> Self {
        Self::Root(Box::new(RootError::Sys(e)))
    }
}

/// An error of `exec` after its checks.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ExecError {
    /// Refused before anything was written.
    #[error(transparent)]
    Refused(Refusal),
    /// The journal.
    #[error(transparent)]
    Journal(#[from] JournalError),
    /// Op `op` failed in the system layer.
    #[error("op {op}: {source}")]
    Op {
        /// Op index.
        op: u16,
        /// The error, with its Win32 or NTSTATUS code.
        source: SysError,
    },
    /// An op did not observe `After` right after it was applied.
    #[error("op {op} is {observed:?} right after it was applied")]
    Verify {
        /// Op index.
        op: u16,
        /// What it observed.
        observed: Observed,
    },
    /// These ops met a state Rerun did not leave: left as they are, their backups kept; only
    /// `forget` closes the transaction (ADR 0020, D10).
    #[error(
        "ops {ops:?} were changed by someone else and are left as they are; forget closes the transaction"
    )]
    Foreign {
        /// Op indices.
        ops: Vec<u16>,
    },
    /// The system layer outside an op (a flush of a game folder).
    #[error(transparent)]
    Sys(#[from] SysError),
}

impl From<Refusal> for ExecError {
    fn from(r: Refusal) -> Self {
        Self::Refused(r)
    }
}

/// An error of [`apply`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ApplyError {
    /// Nothing was written (or only an empty transaction that blocks nothing).
    #[error(transparent)]
    Refused(Refusal),
    /// Failed and rolled back completely: `Closed { RolledBack }`.
    #[error("apply failed and was rolled back ({txn}): {cause}")]
    RolledBack {
        /// The transaction.
        txn: TxnId,
        /// The failure.
        cause: Box<ExecError>,
    },
    /// Failed, and the rollback failed too or met a foreign state: the transaction stays
    /// open; `revert` finishes it later (or `forget` closes it).
    #[error("apply failed ({txn}): {cause}; the rollback did not finish: {rollback}")]
    LeftOpen {
        /// The transaction.
        txn: TxnId,
        /// The failure.
        cause: Box<ExecError>,
        /// Why the rollback did not finish.
        rollback: Box<ExecError>,
    },
}

impl From<Refusal> for ApplyError {
    fn from(r: Refusal) -> Self {
        Self::Refused(r)
    }
}

/// One op of a [`RevertReport`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpReport {
    /// Op index.
    pub op: u16,
    /// What it observed before the revert acted.
    pub observed: Observed,
    /// Names Rerun left in the op's folder: a `.old` still mapped (pending cleanup), a temp
    /// name that is not Rerun's any more.
    pub left: Vec<RelPath>,
    /// Where the backup of a foreign op stays (`journal\<txn>\op-NNNN.bin` below `AppDir`).
    pub backup: Option<String>,
}

/// Where a revert stopped (6b-d): at file op `op`, whose root `root` cannot run file ops now
/// (gone, or not writable). Nothing was recorded for it; the transaction stays open and a
/// later revert goes on from there once the folder itself is back or the update finished. A
/// reinstall makes a new folder with a new identity: `IdentityMismatch`, refused until a
/// rebind (D5).
#[derive(Debug)]
pub struct Halt {
    /// Op index.
    pub op: u16,
    /// Root index.
    pub root: u16,
    /// Why.
    pub why: Box<Refusal>,
}

/// What [`revert`] did.
#[derive(Debug)]
pub struct RevertReport {
    /// The transaction.
    pub txn: TxnId,
    /// How it was closed; `None` if an op was foreign (it stays open, `forget` closes it) or
    /// the revert halted.
    pub closed: Option<Closing>,
    /// The ops reverted in this run, newest first.
    pub ops: Vec<OpReport>,
    /// Where the revert halted, if it did (review N4: also at its first op, an `Ok`).
    pub halted: Option<Halt>,
}

/// What [`verify`] observed.
#[derive(Debug)]
pub struct Verified {
    /// The intended ops by index (ascending): observed now, or `Foreign` as recorded for an
    /// op left foreign on a root that cannot run file ops. Missing: the ops below a halt and
    /// the cleanly reverted ops of such a root.
    pub ops: Vec<(u16, Observed)>,
    /// Where a revert would halt now.
    pub halted: Option<Halt>,
}

#[cfg(test)]
pub(crate) mod knob {
    //! Test knobs of this thread: J6 switches off a flush of `exec`; the controls K1 and K3
    //! break the revert on purpose, and the check functions of T6 and T1 must report it.

    use std::cell::Cell;

    use super::Flush;

    thread_local! {
        static SKIP: Cell<Option<Flush>> = const { Cell::new(None) };
        static TRUST_RECORDS: Cell<bool> = const { Cell::new(false) };
        static RESTORE_WITHOUT_ATTRS: Cell<bool> = const { Cell::new(false) };
        static EAGER_ROOTS: Cell<bool> = const { Cell::new(false) };
    }

    pub(crate) fn skip(f: Option<Flush>) {
        SKIP.with(|s| s.set(f));
    }
    pub(crate) fn skipped(f: Flush) -> bool {
        SKIP.with(|s| s.get() == Some(f))
    }
    /// K1: observe from the records instead of the disk.
    pub(crate) fn trust_records(on: bool) {
        TRUST_RECORDS.with(|s| s.set(on));
    }
    pub(crate) fn trusting_records() -> bool {
        TRUST_RECORDS.with(Cell::get)
    }
    /// K3: restore without the old R/H/S.
    pub(crate) fn restore_without_attrs(on: bool) {
        RESTORE_WITHOUT_ATTRS.with(|s| s.set(on));
    }
    pub(crate) fn restoring_without_attrs() -> bool {
        RESTORE_WITHOUT_ATTRS.with(Cell::get)
    }
    /// K-R9: a revert needs every root open for file ops (as before P2-10a).
    pub(crate) fn open_eagerly(on: bool) {
        EAGER_ROOTS.with(|s| s.set(on));
    }
    pub(crate) fn opening_eagerly() -> bool {
        EAGER_ROOTS.with(Cell::get)
    }
}

/// K1 (tests): observe from the records.
fn trusting_records() -> bool {
    #[cfg(test)]
    return knob::trusting_records();
    #[cfg(not(test))]
    false
}

/// K3 (tests): restore without the old R/H/S.
fn restoring_without_attrs() -> bool {
    #[cfg(test)]
    return knob::restoring_without_attrs();
    #[cfg(not(test))]
    false
}

/// A flush of `exec` (ADR 0019 amendments P2-7 S2 and P2-8), named by domain and place; J6
/// switches each off in turn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Flush {
    /// The game folders an apply wrote into, before `Applied`.
    GameBeforeApplied,
    /// The game folder of an op, before its `RevertDone` (and so before `Closed`).
    GameBeforeRevertDone,
}

/// J6 (tests): this flush is switched off.
fn flush_skipped(
    #[cfg_attr(not(test), expect(unused_variables, reason = "test knob"))] at: Flush,
) -> bool {
    #[cfg(test)]
    return knob::skipped(at);
    #[cfg(not(test))]
    false
}

/// The in-process result of a call of the apply, for its rollback (senior-dev condition 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Hint {
    /// `create_dir` created the directory with this file ID.
    Dir(u128),
    /// `create_dir` or `create_new` found the name taken: someone else's.
    Foreign,
}

/// What an op observes and what its revert does, by the domain of its target.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Seen {
    /// A file or directory.
    File(file::Seen),
}

impl Seen {
    /// What the op observed.
    fn observed(&self) -> Observed {
        match self {
            Self::File(s) => s.observed,
        }
    }

    /// A restore follows its actions (a `RevertIntent` with a temp name).
    fn restore(&self) -> bool {
        match self {
            Self::File(s) => s.restore,
        }
    }
}

/// What the act of a revert left behind.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Acted {
    /// A `<tmp>.old` was left (mapped as an image).
    old_left: bool,
    /// Names Rerun left in the op's folder: a `.old` still mapped, a temp name that is not
    /// Rerun's any more.
    left: Vec<RelPath>,
}

/// What a run touches, per domain, for the flushes (ADR 0019): the game folders written into.
struct Touched<'g> {
    dirs: file::Dirs<'g>,
}

impl<'g> Touched<'g> {
    fn new(roots: &'g roots::Roots<'g>) -> Self {
        Self {
            dirs: file::Dirs::new(roots),
        }
    }

    /// Before `Applied`: every domain the apply changed (the game folders, after every guard
    /// is dropped: a POSIX delete through a guard reaches the volume log when it closes).
    fn flush_all(&mut self) -> SysResult<()> {
        if !flush_skipped(Flush::GameBeforeApplied) {
            self.dirs.flush()?;
        }
        Ok(())
    }

    /// Before the `RevertDone` of op `k`: the domain of its target, always, also when the
    /// revert changed nothing (a `sys::seq` sequence that failed in the apply undid itself
    /// without a flush, and the `RevertDone` must not outlive that undo; review M1).
    fn flush_for(&mut self, k: u16, t: Target<'_>) -> Result<(), ExecError> {
        match t {
            Target::File { root, path, .. } => {
                if !flush_skipped(Flush::GameBeforeRevertDone) {
                    self.dirs
                        .parent(root.0, path, true)
                        .map_err(|source| ExecError::Op { op: k, source })?;
                    self.dirs.flush()?;
                }
            }
            Target::Key { .. } | Target::Value { .. } => {}
        }
        Ok(())
    }
}

/// A registry op before `exec` runs registry ops.
fn no_registry_yet(k: u16) -> ExecError {
    ExecError::Op {
        op: k,
        source: SysError::new(crate::sys::SysErrorKind::Unsupported, "a registry op"),
    }
}

/// Applies op `k` in its domain.
fn apply_op(
    cx: &ExecCtx<'_>,
    w: &mut TxnWriter<'_>,
    t: &mut Touched<'_>,
    k: u16,
    op: &Op,
    hints: &mut BTreeMap<u16, Hint>,
) -> Result<(), ExecError> {
    match op.target() {
        Target::File { .. } => file::apply_op(cx, w, &mut t.dirs, k, op, hints),
        Target::Key { .. } | Target::Value { .. } => Err(no_registry_yet(k)),
    }
}

/// Observes op `k` in its domain (read only). `later`: what the later ops observed and will
/// do ([`Mode::Verify`], newest first: review S3).
#[expect(
    clippy::too_many_arguments,
    reason = "the one dispatch of an observation"
)]
fn observe(
    plan: &Plan,
    t: &mut Touched<'_>,
    k: u16,
    op: &Op,
    log: &OpLog,
    mode: Mode,
    hint: Option<Hint>,
    later: &BTreeMap<u16, Seen>,
) -> Result<Seen, ExecError> {
    match op.target() {
        Target::File { .. } => {
            file::observe(plan, &mut t.dirs, k, op, log, mode, hint, later).map(Seen::File)
        }
        Target::Key { .. } | Target::Value { .. } => Err(no_registry_yet(k)),
    }
}

/// The halt of a revert at op `k` (6b-d): a file op whose root cannot run file ops.
fn halt(roots: &roots::Roots<'_>, k: u16, op: &Op) -> Option<Halt> {
    match op.target() {
        Target::File { root, .. } => roots.for_files(usize::from(root.0)).err().map(|n| Halt {
            op: k,
            root: root.0,
            why: Box::new(n.refusal()),
        }),
        // Registry ops never halt: they need no root (6b-d).
        Target::Key { .. } | Target::Value { .. } => None,
    }
}

/// Observes the intended ops `ops` newest first, as `verify` (review S3: a created directory
/// counts only what the later ops will remove or never made: a target observed `Before` or
/// `After`, a temp name a later op deletes), halting where a revert would. An op whose root
/// cannot run file ops is skipped if it was reverted cleanly, shown `Foreign` as recorded if
/// its revert left it foreign.
fn verify_ops(
    plan: &Plan,
    t: &mut Touched<'_>,
    roots: &roots::Roots<'_>,
    ops: &BTreeMap<u16, OpLog>,
) -> Result<Verified, ExecError> {
    let mut seen = BTreeMap::new();
    let mut out = BTreeMap::new();
    let mut halted = None;
    for (k, log) in ops.iter().rev() {
        let op = op_of(plan, *k)?;
        if let Some(h) = halt(roots, *k, op) {
            match log.reverted {
                // Reverted cleanly: the revert never comes back to it.
                Some(r) if r.observed != Observed::Foreign => continue,
                // Left foreign: shown as recorded (its root cannot be read for file ops),
                // so the user sees why the transaction stays open (security N-5).
                Some(_) => {
                    out.insert(*k, Observed::Foreign);
                    continue;
                }
                None => {
                    halted = Some(h);
                    break;
                }
            }
        }
        let s = observe(plan, t, *k, op, log, Mode::Verify, None, &seen)?;
        out.insert(*k, s.observed());
        seen.insert(*k, s);
    }
    Ok(Verified {
        ops: out.into_iter().collect(),
        halted,
    })
}

/// Carries out what `seen` says for op `k`, after its `RevertIntent`.
fn act<W: Reverting>(
    w: &W,
    t: &mut Touched<'_>,
    k: u16,
    op: &Op,
    seen: &Seen,
    y: Option<TmpName>,
) -> Result<Acted, ExecError> {
    match seen {
        Seen::File(s) => file::act(w, &mut t.dirs, k, op, s, y),
    }
}

/// The records fit the head (ADR 0019: the journal is op-agnostic; condition 5): every
/// intended op exists, and its records have the form of its kind.
fn records_fit(plan: &Plan, ops: &BTreeMap<u16, OpLog>) -> bool {
    ops.iter()
        .all(|(k, log)| match plan.ops.get(usize::from(*k)) {
            None => false,
            Some(op) => match op.target() {
                Target::File { .. } => file::records_fit(op, log),
                Target::Key { .. } | Target::Value { .. } => false,
            },
        })
}

/// Applies the stored plan `h` (module docs).
pub fn apply(cx: &ExecCtx<'_>, h: &PlanHash) -> Result<Outcome, ApplyError> {
    let bytes = plan::load(cx.app, h).map_err(Refusal::Plan)?;
    let plan = plan::decode(bytes.bytes()).map_err(Refusal::Plan)?;
    if plan.ops.is_empty() {
        return Ok(Outcome::Nothing);
    }
    if plan.ops.iter().any(|o| o.target().is_registry()) {
        return Err(Refusal::Plan(PlanError::Invalid {
            op: None,
            why: "registry ops are not executed yet",
        })
        .into());
    }
    let j = Journal::new(cx.app, cx.tag);
    let lock = j.lock().map_err(Refusal::from)?;
    let listing = j.list().map_err(Refusal::from)?;
    let objects = Object::of(&plan).map_err(Refusal::Plan)?;
    stack::for_apply(&j, &listing, &objects)?;
    let stores = roots::open_stores(cx, &plan);
    let roots = roots::Roots::all(cx, &plan, &stores)?;
    let all: Vec<u16> = (0..plan.ops.len()).map(op_ix).collect();
    roots::main_exe_present(&plan, &roots)?;
    roots::game_closed(&plan, &roots, &all)?;
    roots::old_state(cx, &plan, &roots)?;
    let mut w = lock.begin(bytes.bytes()).map_err(Refusal::from)?;
    let txn = *w.id();
    let mut touched = Touched::new(&roots);
    let mut hints = BTreeMap::new();
    let cause = match run(cx, &plan, &mut w, &mut touched, &roots, &mut hints) {
        Ok(()) => return Ok(Outcome::Applied(txn)),
        Err(e) => e,
    };
    match rollback(cx, &plan, w, &mut touched, &roots, &hints) {
        Ok(()) => Err(ApplyError::RolledBack {
            txn,
            cause: Box::new(cause),
        }),
        Err(rollback) => Err(ApplyError::LeftOpen {
            txn,
            cause: Box::new(cause),
            rollback: Box::new(rollback),
        }),
    }
}

/// `k` as an op index of the journal (a plan has at most 128 ops).
fn op_ix(k: usize) -> u16 {
    u16::try_from(k).unwrap_or(u16::MAX)
}

/// The ops, `After` for each, the flushes, `Applied`.
fn run(
    cx: &ExecCtx<'_>,
    plan: &Plan,
    w: &mut TxnWriter<'_>,
    t: &mut Touched<'_>,
    roots: &roots::Roots<'_>,
    hints: &mut BTreeMap<u16, Hint>,
) -> Result<(), ExecError> {
    for (k, op) in plan.ops.iter().enumerate() {
        apply_op(cx, w, t, op_ix(k), op, hints)?;
    }
    let ops = w.ops().clone();
    let v = verify_ops(plan, t, roots, &ops)?;
    for (k, observed) in v.ops {
        if observed != Observed::After {
            return Err(ExecError::Verify { op: k, observed });
        }
    }
    if let Some(h) = v.halted {
        return Err(ExecError::Refused(*h.why));
    }
    t.flush_all()?;
    w.applied(op_ix(plan.ops.len()))?;
    Ok(())
}

fn op_of(plan: &Plan, k: u16) -> Result<&Op, ExecError> {
    plan.ops.get(usize::from(k)).ok_or(ExecError::Verify {
        op: k,
        observed: Observed::Foreign,
    })
}

/// The rollback of a failed apply: the revert loop on the apply's own writer, with the
/// in-process results of the calls (`hints`, senior-dev condition 4).
fn rollback(
    cx: &ExecCtx<'_>,
    plan: &Plan,
    mut w: TxnWriter<'_>,
    t: &mut Touched<'_>,
    roots: &roots::Roots<'_>,
    hints: &BTreeMap<u16, Hint>,
) -> Result<(), ExecError> {
    // Every root opened for the apply, so the rollback never halts; if it did, it is open.
    let (_, halted) = revert_loop(cx, plan, &mut w, t, roots, Mode::Rollback, hints)?;
    if let Some(h) = halted {
        return Err(ExecError::Refused(*h.why));
    }
    let foreign = foreign_ops(&w);
    if !foreign.is_empty() {
        return Err(ExecError::Foreign { ops: foreign });
    }
    close(w)
}

/// The ops whose `RevertDone` recorded `Foreign`, in this run or an earlier one: the
/// transaction cannot be closed as reverted (ADR 0019 grammar, S3), only forgotten.
fn foreign_ops<W: Reverting>(w: &W) -> Vec<u16> {
    w.ops()
        .iter()
        .filter(|(_, o)| o.reverted.is_some_and(|r| r.observed == Observed::Foreign))
        .map(|(k, _)| *k)
        .collect()
}

/// `Closed` by how far the transaction got. Every change of the revert was flushed before its
/// `RevertDone` (in [`revert_loop`]), so the game folders need no flush here.
fn close<W: Reverting>(w: W) -> Result<(), ExecError> {
    let how = if w.is_applied() {
        Closing::Reverted
    } else {
        Closing::RolledBack
    };
    w.close(how)?;
    Ok(())
}

/// Newest op first while one is left: observe, `RevertIntent` (with a temp name only when a
/// restore starts, B2), act, flush the domain of the op (always), `RevertDone`. A foreign
/// op gets its records and is left (R1). A file op whose root cannot run file ops ends the
/// loop before any record of it ([`Halt`], 6b-d).
///
/// The flush before `RevertDone` (found by T4): `RevertDone` is not flushed itself, but the
/// flush of its own temp file makes the journal's volume log durable up to just before its
/// rename, so a power loss can keep `RevertDone` while the change on the game's volume is
/// lost; a recovery that then skips the op (the grammar allows no second revert of it) would
/// trust the record alone. With the flush, a durable `RevertDone` has a durable change; it
/// also covers `Closed`, which therefore needs no flush of its own. It runs for every op, also
/// one whose act changed nothing (T3 under power loss, review M1).
fn revert_loop<W: Reverting>(
    cx: &ExecCtx<'_>,
    plan: &Plan,
    w: &mut W,
    t: &mut Touched<'_>,
    roots: &roots::Roots<'_>,
    mode: Mode,
    hints: &BTreeMap<u16, Hint>,
) -> Result<(Vec<OpReport>, Option<Halt>), ExecError> {
    let mut reports = Vec::new();
    while let Some(k) = w.next_revert() {
        let log: OpLog = w
            .ops()
            .get(&k)
            .cloned()
            .ok_or(JournalError::Order("an op to revert without its intent"))?;
        let op = op_of(plan, k)?;
        if let Some(h) = halt(roots, k, op) {
            return Ok((reports, Some(h)));
        }
        let none = BTreeMap::new();
        let seen = observe(plan, t, k, op, &log, mode, hints.get(&k).copied(), &none)?;
        let observed = seen.observed();
        let y = seen.restore().then(|| w.tmp());
        w.revert_intent(k, y.clone())?;
        let done = act(w, t, k, op, &seen, y)?;
        // Always, also when the act changed nothing (`Touched::flush_for`).
        t.flush_for(k, op.target())?;
        w.revert_done(k, observed, done.old_left)?;
        reports.push(OpReport {
            op: k,
            observed,
            left: done.left,
            backup: (observed == Observed::Foreign && log.intent.bin().is_some()).then(|| {
                let p = format!(r"{}\journal\{}\op-{k:04}.bin", cx.app.path(), w.id());
                crate::escape::path(&p).to_string()
            }),
        });
    }
    Ok((reports, None))
}

/// Reverts transaction `t` (module docs): also the recovery of an interrupted apply.
pub fn revert(cx: &ExecCtx<'_>, t: &TxnId) -> Result<RevertReport, ExecError> {
    let j = Journal::new(cx.app, cx.tag);
    let lock = j.lock().map_err(Refusal::from)?;
    let listing = j.list().map_err(Refusal::from)?;
    let own = listing
        .txns
        .iter()
        .find(|l| l.id == *t)
        .ok_or(JournalError::NotFound(*t))?;
    if own.forgotten {
        return Err(Refusal::Forgotten { txn: *t }.into());
    }
    let damaged = own
        .view
        .as_ref()
        .map_or(true, |v| matches!(v.state, TxnState::Damaged(_)));
    if damaged {
        return Err(Refusal::Blocked { txn: *t }.into());
    }
    let mut w = lock.resume(t)?;
    let plan = plan::decode(w.head()).map_err(|_| Refusal::Blocked { txn: *t })?;
    if !records_fit(&plan, w.ops()) {
        return Err(Refusal::Blocked { txn: *t }.into());
    }
    let objects = Object::of(&plan).map_err(|_| Refusal::Blocked { txn: *t })?;
    stack::for_revert(&j, &listing, t, &objects)?;
    let stores = roots::open_stores(cx, &plan);
    let roots = roots::Roots::each(cx, &plan, &stores)?;
    let intended: Vec<u16> = w.ops().keys().copied().collect();
    roots::game_closed(&plan, &roots, &intended)?;
    let mut touched = Touched::new(&roots);
    let (ops, halted) = revert_loop(
        cx,
        &plan,
        &mut w,
        &mut touched,
        &roots,
        Mode::Recovery,
        &BTreeMap::new(),
    )?;
    if halted.is_some() || !foreign_ops(&w).is_empty() {
        return Ok(RevertReport {
            txn: *t,
            closed: None,
            ops,
            halted,
        });
    }
    let how = if w.is_applied() {
        Closing::Reverted
    } else {
        Closing::RolledBack
    };
    close(w)?;
    Ok(RevertReport {
        txn: *t,
        closed: Some(how),
        ops,
        halted: None,
    })
}

/// What each intended op of `t` observes now, newest first and halting where a revert would
/// (read only, no lock).
pub fn verify(cx: &ExecCtx<'_>, t: &TxnId) -> Result<Verified, ExecError> {
    let j = Journal::new(cx.app, cx.tag);
    let v = j.load(t, crate::journal::VerifyBackups::Length)?;
    let blocked = || ExecError::Refused(Refusal::Blocked { txn: *t });
    if !v.head_usable() {
        return Err(blocked());
    }
    let plan = plan::decode(v.head.as_deref().unwrap_or_default()).map_err(|_| blocked())?;
    if !records_fit(&plan, &v.ops) {
        return Err(blocked());
    }
    let stores = roots::open_stores(cx, &plan);
    let roots = roots::Roots::each(cx, &plan, &stores)?;
    let mut touched = Touched::new(&roots);
    verify_ops(&plan, &mut touched, &roots, &v.ops)
}

/// Forgets transaction `t` (module docs). Backups stay.
pub fn forget(cx: &ExecCtx<'_>, t: &TxnId) -> Result<(), ExecError> {
    let j = Journal::new(cx.app, cx.tag);
    let lock = j.lock().map_err(Refusal::from)?;
    let listing = j.list()?;
    let l = listing
        .txns
        .iter()
        .find(|l| l.id == *t)
        .ok_or(JournalError::NotFound(*t))?;
    if l.forgotten {
        return Ok(());
    }
    let head = match &l.view {
        Ok(v) => match v.state {
            TxnState::Closed(_) => {
                return Err(JournalError::NotResumable {
                    id: *t,
                    state: v.state.clone(),
                }
                .into());
            }
            TxnState::Empty | TxnState::Open | TxnState::Applied => {
                match lock.resume(t) {
                    Ok(w) => return Ok(w.close(Closing::Forgotten)?),
                    // Damaged since the listing: the marker below.
                    Err(JournalError::NotResumable { .. }) => v.head_sha256,
                    Err(e) => return Err(e.into()),
                }
            }
            TxnState::Damaged(_) => v.head_sha256,
        },
        Err(_) => None,
    };
    lock.forget_marker(t, head.as_ref())?;
    Ok(())
}

#[cfg(test)]
mod crash_tests;
#[cfg(test)]
mod halt_tests;
#[cfg(test)]
pub(crate) mod tests;
