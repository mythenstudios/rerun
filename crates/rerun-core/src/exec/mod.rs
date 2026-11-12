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
//! - [`verify`]: what each op of a transaction observes now, read only (an existing lock file
//!   held read side, never taken), newest first and halting where the revert would; also the
//!   preview before a revert (rule 5).
//! - [`forget`]: closes an empty, open or applied transaction with `Closed { Forgotten }`, a
//!   damaged or unreadable one with the marker `journal\<txn>.forgotten` (user decision D2).
//!
//! Observing never trusts a record alone (`file`): every hash is taken on a guard, a link
//! count other than 1 or other R/H/S is "other".
//!
//! Dispatch (audit A2 should-item 3): apply, observe, act, the record check, the flushes and
//! the game-closed check match on [`Op::target`] and hand the op to the module of its domain
//! (`file` for files and directories, `reg` for registry keys and values, P2-10b); the revert
//! loop is one for every domain. A new domain adds a [`Target`] variant, a variant of [`Seen`]
//! (and of [`Hint`] where it needs one) and its part of [`Touched`].
//!
//! Front end (P2-13): [`check`] runs every check of an apply without writing (`preflight` is
//! the one chain both use); [`status`] and [`txn_status`] show the journal without observing
//! anything. [`standard_user`] (user decision E3) is the first call of `apply`, `check`,
//! `revert` and `forget`: an elevated process, or one whose elevation cannot be determined,
//! changes nothing, whatever the plan (`Refusal::Elevated`). A revert reports every error
//! before its first record of the run as a refusal (review S4).
//!
//! Registry ops (P2-10b): the old state of
//! every key and value is re-observed with the files (`Mismatch`, `Refusal::Registry`); `HKCU`
//! is flushed before `Applied` (after the game folders) and before the `RevertDone` of every
//! registry op. Registry ops need no root: they never halt a revert, and `plan::check` puts them
//! after every file op, so a halt comes after every registry op is reverted (6b-d).
//!
//! INI ops (P2-12): an `IniValue` is a file op (its target, flushes, halts and stacking are a
//! file's), but apply, observe and the record check go to `ini` (`policy::ini` edits the bytes;
//! the revert of a file the game rewrote is a semantic rewrite with `from`/`to` in its
//! `RevertIntent`). Before a revert and `verify`, a recorded head is bound to its backups
//! (`ini::binds`: `Blocked` otherwise). `verify` and the report carry the state of each of
//! Rerun's keys ([`Detail`]).
//!
//! Rebinds (P2-14): a recorded head is never rewritten; the `Rebind` records of a transaction
//! bind its roots (`bind`), checked against the head on every revert, `verify` and stacking
//! (`Blocked` otherwise). A binding acts only where a root is opened: the file ops, D4 and the
//! file objects of stacking; registry locations come from the head.
//!
//! Pending cleanup (P2-15, user decisions E-C1 to E-C4): a `.old` a process still maps when a
//! step ends stays, and the journal names it by sequence (`RevertDone.old_left`). After the
//! revert loop of a revert or a rollback, the cleanup pass ([`cleanup_pass`]) observes every
//! `.old` the journal says is left: gone is done; Rerun's own content is deleted with its known
//! hash when the target still holds the reverted state; a mapped one stays ([`OldSeen::InUse`]),
//! and so does one next to a target that changed since ([`OldSeen::Kept`]); anything else at the
//! name is not Rerun's and is never touched ([`OldSeen::Foreign`], reported). The game folders
//! are flushed before `Closed` (the tenth flush site), and a transaction is closed only when
//! nothing of Rerun's is left, so `Closed { Reverted | RolledBack }` means Rerun's changes are
//! undone exactly. Otherwise it stays open (stacking: `Refusal::CleanupPending`), and only a
//! later `revert` of the same transaction cleans up: nothing in the background, at start or on
//! reboot.
//!
//! Launch profiles (P3-3, ADR 0020 amendment P3-3): a profile op is a plain file op on the
//! profiles root (`roots`: opened through `AppDir`, created by the apply, never by a revert)
//! with inline content (`file`); its records, observation and revert are those of every
//! `CreateFile` and `ReplaceFile`, and there is no new record kind or flush site.
//!
//! Shared files and folders (P4-8b, user decision E6, `share`): a revert keeps a file or folder
//! it created that a later applied transaction relies on (`RevertDone { Kept }`, nothing
//! deleted), and the last revert that relies on such an object removes it if it is still exactly
//! the creator's (its file ID, content and R/H/S; a folder empty), after its own flushed intent
//! of the op that carries it. Everything is derived under the lock before the first record from
//! the listing and the other transactions' heads and records; the disk is checked when acting.

mod bind;
mod file;
mod helper;
mod ini;
mod launch;
mod rebind;
mod reg;
mod roots;
mod share;
mod stack;
mod status;

use std::collections::{BTreeMap, BTreeSet};

pub use launch::{LaunchEntry, LaunchResults, MAX_LAUNCH_ENTRIES, launch_results};
/// The launch result types (`rerun_proto::launch`, ADR 0022 amendment P3-2).
pub mod launch_result {
    pub use super::launch::{
        AppliedCpu, Check, Ended, LaunchResult, Mode, Outcome, Priority, ProfileId, SkipReason,
        Start,
    };
}
pub use helper::{HelperFailure, reason_words};
pub(crate) use rebind::revert_rebound_seen;
pub use rebind::{
    CreatedDir, RebindFrom, RebindPreview, RebindRefusal, RebindTo, rebind_check, revert_rebound,
};
pub use stack::PatchedExe;
pub use status::{
    OpState, OpStatus, OrphanRule, OrphansError, RebindLine, ShareKind, ShareLine, Status, TxnLine,
    TxnStatus, firewall_orphans, status, txn_status,
};

use bind::Bindings;
use file::Mode;

use crate::detect::steam::AppState;
use crate::escape::Shown;
use crate::journal::{
    Before, Closing, InstanceTag, IntentRec, Journal, JournalError, Listing, Observed, OpLog,
    RebindRec, Reverting, Semantic, TxnId, TxnState, TxnWriter,
};
use crate::path::RelPath;
use crate::plan::{self, Object, Op, Plan, PlanError, PlanHash, Target};
use crate::policy::ini::{IniName, KeyState};
use crate::policy::registry::{RegPolicy, RegWriter};
use crate::policy::root::{AppDir, ForbiddenRoots, RootError, StoreDir};
use crate::sys::fs::TmpName;
use crate::sys::registry::Hive;
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
    /// applied (and no earlier one reverted) until it is forgotten (fail closed, E2). P4-8b: also
    /// the revert of a transaction that may inherit a shared file or folder from it (its records
    /// cannot be read, it is damaged, or it handed something over or relies on something and its
    /// head cannot be used) while that file (with the ID the reverting transaction recorded) or a
    /// folder above one of its relying ops that it did not create is still there.
    #[error(
        "transaction {txn} is damaged; rerun status shows what it left; only rerun forget {txn} \
         closes it"
    )]
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
    /// A later transaction relies on a file of the one to revert that cannot be handed over
    /// (P4-8, P4-8b): a file this one replaced (its old content would need this one's backup), or
    /// one whose identity changed since (rewritten with the same content); newest first.
    #[error(
        "transaction {txn} relies on a shared file this transaction replaced, or one that is \
         no longer the file it installed, so it cannot be handed over; revert {txn} first, then \
         this one (newest first)"
    )]
    Held {
        /// The later transaction.
        txn: TxnId,
    },
    /// The plan would replace or edit a file a live transaction holds (P4-8b, S2).
    #[error(
        "transaction {txn} relies on a shared file this plan would change; revert {txn} first, \
         then plan again"
    )]
    HeldChange {
        /// The transaction that holds it.
        txn: TxnId,
    },
    /// More transactions than one revert reads for the hand-over of shared files (P4-8b, S4).
    #[error(
        "more than {limit} transactions of Rerun would have to be read to hand over shared \
         files; nothing was changed. Closed transactions that handed files over are kept until \
         Rerun prunes its journal (a later version); forgetting transactions that are not \
         closed and that you no longer need lowers the count"
    )]
    TooManyTransactions {
        /// The bound.
        limit: usize,
    },
    /// A DLL of a package of the plan lies where a live transaction has a DLL of another
    /// package (P4-8): one DLL of a name per folder is loaded, and Rerun does not chainload.
    #[error(
        "op {op}: {path} is the DLL slot of package {package} from transaction {txn}; two \
         packages cannot share a DLL (Rerun does not chainload): revert {txn} first, or keep \
         that fix instead"
    )]
    SlotTaken {
        /// The transaction.
        txn: TxnId,
        /// Op index of the plan.
        op: u16,
        /// The DLL.
        path: Shown<'static>,
        /// The package of the transaction there.
        package: Shown<'static>,
    },
    /// A transaction on an object of this plan is reverted, but its journal still names a file
    /// Rerun left (in use, or kept next to a file that changed: the journal does not say which),
    /// so it stays open until a revert deletes that file (P2-15): it blocks applies on its
    /// objects and, newest first, the revert of earlier transactions on them.
    #[error(
        "transaction {txn} is reverted, but a file Rerun left is still there; run rerun revert \
         {txn}, it deletes the file or says why it stays (close the game and any window showing \
         its folder first)"
    )]
    CleanupPending {
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
    /// What a revert, rebind or forget observes under the lock differs from what its preview
    /// showed (ADR 0027 amendment P5-2b): nothing was written; show the preview again.
    #[error(
        "transaction {txn} changed since its preview; nothing was done; look at it again before \
         you go on"
    )]
    Changed {
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
    /// Rerun's profiles folder is at another path than the plan names (`<LocalAppData>` moved
    /// since planning): an apply writes nothing then (P3-3, senior-dev condition A1).
    #[error("Rerun's profiles folder is {} now, the plan names {}; plan again", .0.now, .0.planned)]
    ProfilesMoved(ProfilesMoved),
    /// A user data folder (P4-12) resolves to another path than the plan names: the user's
    /// `Documents` was moved or redirected since. Apply and revert refuse (no rebind, no revert
    /// at the new place): move it back, or `forget` the transaction (its backup stays).
    #[error(
        "the game's folder in your Documents is {now} now, the plan names {planned}; move \
         Documents back, or plan again (a transaction: forget it, its backup stays in the journal)"
    )]
    UserDataMoved {
        /// The path the plan names.
        planned: Shown<'static>,
        /// The path now.
        now: Shown<'static>,
    },
    /// The main executable of a root is missing or no plain file (audit A2 should-item 8):
    /// the game-closed check would ask nothing about it.
    #[error("the main executable {0} is missing or not a file; plan again")]
    MainExe(Shown<'static>),
    /// The main executable has another content than the Topo engine matched when the plan was
    /// made (P5-2a, ADR 0020 amendment P5-2a): a game update, or another fix (an earlier
    /// `laa_patch`, or the revert of one) changed it since.
    #[error(
        "the main executable {0} changed since the plan (a game update, or another fix changed \
         it); plan again"
    )]
    GameChanged(Shown<'static>),
    /// A key or value of op `op` cannot be checked: a symbolic-link or volatile key on the way,
    /// a key deleted while it was opened, a value too large to read.
    #[error("op {op}: the registry cannot be checked: {source}")]
    Registry {
        /// Op index.
        op: u16,
        /// The error, with its Win32 or NTSTATUS code.
        source: SysError,
    },
    /// Rerun runs elevated, or whether it does cannot be determined (fail closed): it changes
    /// nothing then, whatever the plan (ADR 0018, S2; P2-13, user decision E3).
    #[error(
        "Rerun runs as administrator, or whether it does cannot be determined, and changes \
         nothing then; run it as a standard user (with UAC turned off, an administrator \
         account always runs elevated)"
    )]
    Elevated,
    /// Op `op` of a revert cannot be observed now: the system layer failed before the revert
    /// wrote anything (P2-13, review S4).
    #[error("op {op} cannot be checked now: {source}")]
    Observe {
        /// Op index.
        op: u16,
        /// The error, with its Win32 or NTSTATUS code.
        source: SysError,
    },
    /// The stored plan is missing, changed or invalid.
    #[error(transparent)]
    Plan(PlanError),
    /// A rebind is refused (P2-14).
    #[error(transparent)]
    Rebind(RebindRefusal),
    /// The installed helper fails the pre-check (ADR 0023 §2, P4-2d): no prompt is shown.
    #[error("the helper is not installed safely: {0}")]
    HelperUnsafe(Box<RootError>),
    /// Windows allows no elevation here (ADR 0023 §10): standard users are denied it, or UAC
    /// is off.
    #[error("{}", no_elevation(*.0))]
    NoElevation(crate::elevate::PromptKind),
    /// The firewall rules of the plan are no longer what the signed Topo and the game folder
    /// authorise (A4 S7 before `begin`).
    #[error("the firewall rules of this plan no longer hold: {0}; plan again")]
    HelperPlan(Box<crate::elevate::PlanRefusal>),
    /// The helper batch of a revert did not finish (ADR 0023 §9; a [`Halt`]'s reason) or a
    /// helper of an earlier run may still be running (A4 S8).
    #[error("{0}")]
    Helper(HelperFailure),
    /// The journal could not be read or the transaction not begun.
    #[error(transparent)]
    Journal(Box<JournalError>),
}

/// The profiles root at another path than the plan or head names (P3-3, A1): an apply refuses
/// ([`Refusal::ProfilesMoved`]); a revert and `verify` work at the folder now (every profile op
/// is decided by its hashes) and report it ([`RevertReport::profiles_moved`],
/// [`Verified::profiles_moved`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfilesMoved {
    /// The path the plan names.
    pub planned: Shown<'static>,
    /// The path of `<LocalAppData>\Rerun\profiles` now.
    pub now: Shown<'static>,
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

/// A [`Refusal::NoElevation`] for a message.
fn no_elevation(k: crate::elevate::PromptKind) -> &'static str {
    match k {
        crate::elevate::PromptKind::UacOff => {
            "User Account Control is off on this PC: Rerun cannot ask for administrator rights \
             for its firewall rules"
        }
        _ => {
            "Windows denies administrator rights to standard users on this PC: Rerun cannot \
             add or remove its firewall rules here"
        }
    }
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
    /// Closing (a revert's `Closed`, forget's record or marker) failed after the closing entry
    /// reached the journal (its flush failed): the transaction may count as closed now; `status`
    /// shows what the journal holds (P2-13, security review N1). After a rebind the transaction
    /// is bound in any case; only its closing is uncertain.
    #[error("the transaction may have been closed, but its closing entry may not be durable: {0}")]
    Unconfirmed(JournalError),
    /// A `Rebind` whose call failed while the journal cannot be read again to tell whether it is
    /// on disk (P2-14 reviews N3 and S3): the transaction may be bound now; `status` shows it.
    #[error("the rebind may have been written, but whether it is on disk cannot be read: {0}")]
    RebindUnconfirmed(JournalError),
    /// The helper batch of an apply did not end with every rule added (ADR 0023 §9, P4-2d).
    #[error(transparent)]
    Helper(HelperFailure),
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
        /// What the cleanup pass observed (P2-15): only what was deleted, gone, or is not
        /// Rerun's (`OldSeen::Foreign`, reported and never touched).
        cleanup: Vec<PendingOld>,
    },
    /// Failed and rolled back, but a file Rerun replaced is still in use (or kept next to a
    /// target that changed since), so the transaction stays open until a later revert deletes
    /// it (P2-15, senior-dev B1): not `Closed`.
    #[error(
        "apply failed and was rolled back ({txn}): {cause}; a file Rerun left is still there, \
         the transaction stays open until rerun revert {txn} deletes it"
    )]
    CleanupPending {
        /// The transaction.
        txn: TxnId,
        /// The failure.
        cause: Box<ExecError>,
        /// What the cleanup pass observed; at least one item holds the transaction open.
        cleanup: Vec<PendingOld>,
    },
    /// The helper batch ended in a state the apply cannot roll back without a second
    /// administrator prompt (ADR 0023 §9, R3: `LeftOpen`, an unknown result, a disagreement
    /// with the observed firewall): nothing more was changed, the transaction stays open, and
    /// `rerun revert <txn>` finishes it with one prompt.
    #[error(
        "apply failed ({txn}): {cause}; nothing more was changed; rerun revert {txn} finishes it \
         (with one administrator prompt if a rule is there)"
    )]
    HelperOpen {
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
    /// Where the old state of a foreign op stays (`journal\<txn>\op-NNNN.bin` below `AppDir`,
    /// or the record itself for a small old value).
    pub backup: Option<Backup>,
    /// What the op observed beyond its state (an `IniValue`: its keys).
    pub detail: Option<Detail>,
}

/// Where the old state of an op is kept (P2-13; audit A2, P2-12 open point: a front end names
/// it before `forget`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Backup {
    /// The backup file `<AppDir>\journal\<txn>\op-NNNN.bin` (escaped for display) and its
    /// length.
    Bin {
        /// The file.
        path: Shown<'static>,
        /// Its length in bytes.
        len: u64,
    },
    /// In the op's journal record (a small old value; its content is never shown).
    Inline,
}

impl Backup {
    /// The backup of op `k` of transaction `t` by its intent, if the op has an old state.
    pub(crate) fn of(app: &AppDir<'_>, t: &TxnId, k: u16, intent: &IntentRec) -> Option<Self> {
        match &intent.before {
            Some(Before::Bin(d)) => Some(Self::Bin {
                path: crate::escape::path(&format!(
                    r"{}\journal\{t}\{}",
                    app.path(),
                    crate::journal::names::backup_name(k)
                ))
                .into_owned(),
                len: d.len,
            }),
            Some(Before::Inline(_)) => Some(Self::Inline),
            None => None,
        }
    }
}

/// What an op observed beyond its [`Observed`] state, for `verify` and the report (P2-12; review
/// nit: per op, not a field per op kind).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Detail {
    /// An `IniValue`: the state of each of Rerun's keys, in the op's order (user decision E1 b:
    /// a key someone changed stays and is named); and, for an op left `Foreign` next to a `.old`
    /// that holds the file as it was before a step of Rerun, that file (review S6: kept and
    /// named, never deleted).
    Ini {
        /// The keys.
        keys: Vec<IniKey>,
        /// The `.rerun-….tmp.old` holding the file as it was before a step of Rerun.
        before_step: Option<BeforeStep>,
    },
    /// P4-8b (E6): a file or folder the op created, kept for the later transactions that rely
    /// on it (the last revert that relies on it removes it).
    Kept {
        /// The transactions that rely on it.
        by: Vec<TxnId>,
    },
    /// P4-8b (E6): files and folders an earlier transaction created and handed over, that this
    /// op relies on: what the revert does with them.
    Inherited(Vec<Inherited>),
}

/// One file or folder handed over to a transaction (P4-8b, E6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inherited {
    /// The transaction that created it.
    pub from: TxnId,
    /// The path below the root (escaped).
    pub path: Shown<'static>,
    /// A folder.
    pub dir: bool,
    /// What the revert does (`verify`) or did with it.
    pub outcome: InheritedOutcome,
}

/// What a revert does with a file or folder handed over to it (P4-8b).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InheritedOutcome {
    /// Removed: the last revert that relied on it, and it was exactly the creator's.
    Removed,
    /// Another transaction still relies on it: it stays for that one.
    StillRelied(TxnId),
    /// Not there any more: nothing to do.
    Gone,
    /// Left as it is, not the creator's any more (X14).
    Left(LeftWhy),
}

/// Why a handed-over file or folder is left (X14).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeftWhy {
    /// Another content, R/H/S, a link or another kind of entry.
    Changed,
    /// The same content with another file ID (rewritten or a copy).
    OtherFileId,
    /// A folder that holds something else.
    NotEmpty,
}

/// A file as it was before a step of Rerun, left in a `.old` next to a foreign file (review S6,
/// senior-dev S3). Only before the apply is it the user's file as Rerun found it; before a
/// restore it is Rerun's edited file, before a rewrite the file the game had written. The
/// state before the first change is always the backup (`OpReport::backup`); a front end shows
/// both before `forget`, and never calls this file the original.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BeforeStep {
    /// The step it was before.
    pub step: RerunStep,
    /// The `.old`, in the INI file's folder.
    pub file: RelPath,
}

/// A step of Rerun on a file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RerunStep {
    /// The apply.
    Apply,
    /// A restore from the backup.
    Restore,
    /// A rewrite of a file the game rewrote.
    Rewrite,
}

/// One of Rerun's keys in an INI file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IniKey {
    /// The section.
    pub section: IniName,
    /// The key.
    pub key: IniName,
    /// Its state.
    pub state: KeyState,
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
    /// How it was closed; `None` if an op was foreign (it stays open, `forget` closes it), the
    /// revert halted, or a `.old` of Rerun's is still left ([`Self::cleanup`], P2-15).
    pub closed: Option<Closing>,
    /// The ops reverted in this run, newest first.
    pub ops: Vec<OpReport>,
    /// Where the revert halted, if it did (review N4: also at its first op, an `Ok`).
    pub halted: Option<Halt>,
    /// What the cleanup pass observed of every `.old` the journal names (P2-15), by op
    /// ascending; one that holds the transaction open ([`OldSeen::holds_open`]) means
    /// `closed == None`.
    pub cleanup: Vec<PendingOld>,
    /// The profiles root was reverted at another path than the head names (P3-3, A1).
    pub profiles_moved: Option<ProfilesMoved>,
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
    /// What the observed ops saw beyond their state, by op index.
    pub details: BTreeMap<u16, Detail>,
    /// The `.old` files the journal names for the ops reverted already, as a revert's cleanup
    /// pass would find them now (P2-15, rule 5: `OldSeen::Ours` is what it deletes).
    pub cleanup: Vec<PendingOld>,
    /// The profiles root was observed at another path than the head names (P3-3, A1).
    pub profiles_moved: Option<ProfilesMoved>,
    /// UAC VirtualStore copies of the managed files at the bound roots (P3-7; only `verify`
    /// looks, a rebind's check leaves it empty).
    pub virtual_store: Vec<crate::policy::root::Shadow>,
}

/// A `.old` the journal says a step of Rerun left (P2-15), as observed now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingOld {
    /// Op index.
    pub op: u16,
    /// Root index of the op.
    pub root: u16,
    /// The file, relative to the root (the target's folder and the `.old` name).
    pub path: RelPath,
    /// The content Rerun put there (the start state of its sequence): deleted only with it.
    pub sha256: [u8; 32],
    /// What is there now.
    pub seen: OldSeen,
}

/// What is at the name of a pending `.old` (P2-15).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OldSeen {
    /// Nothing (the user deleted it, or a run before): done.
    Gone,
    /// Rerun's content, and the target holds the reverted state: a revert deletes it
    /// (`verify` only).
    Ours,
    /// Deleted by this run, with its known hash expected.
    Deleted,
    /// Rerun's content, but deleting it is refused (a process maps it as an image): it stays,
    /// and so does the transaction.
    InUse,
    /// Rerun's content, but the target is not in the reverted state any more (it changed
    /// since the revert): kept, as it may be the last copy on disk of a state, and the
    /// transaction stays open (senior-dev S2); deleting it by hand or `forget` ends it.
    Kept,
    /// Another content, a link, a folder or a reparse point: not Rerun's, never touched, only
    /// reported (user decision E-C4).
    Foreign,
}

impl OldSeen {
    /// It keeps the transaction open (E-C1: `Closed` only when nothing of Rerun's is left).
    pub fn holds_open(self) -> bool {
        matches!(self, Self::InUse | Self::Kept)
    }
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
        static CURRENT_FOR_RECORDED: Cell<bool> = const { Cell::new(false) };
        static OBJECTS_FROM_HEAD: Cell<bool> = const { Cell::new(false) };
        static DIR_PROOF_FROM_DONE: Cell<bool> = const { Cell::new(false) };
        static REWRITE_HEAD: Cell<bool> = const { Cell::new(false) };
        static OBJECTS_FROM_BINDING_ONLY: Cell<bool> = const { Cell::new(false) };
        static DIR_FOUND_AFTER_RECORD: Cell<bool> = const { Cell::new(false) };
        static CLOSE_DESPITE_CLEANUP: Cell<bool> = const { Cell::new(false) };
        static CLEANUP_WITHOUT_HASH: Cell<bool> = const { Cell::new(false) };
        static FLUSH_ONLY_AFTER_DELETE: Cell<bool> = const { Cell::new(false) };
        static IGNORE_TARGET: Cell<bool> = const { Cell::new(false) };
        static FLUSH_ONCE_PER_FOLDER: Cell<bool> = const { Cell::new(false) };
        static RENAME_BACK_UPCASED: Cell<bool> = const { Cell::new(false) };
        static PARENT_NOT_MARKED: Cell<bool> = const { Cell::new(false) };
        static PROFILES_PATHS_UNCHECKED: Cell<bool> = const { Cell::new(false) };
        static HANDOVER: Cell<u8> = const { Cell::new(0) };
    }

    /// K-HO1 to K-HO5 (P4-8b, `handover_tests`): one control of the hand-over switched on (0:
    /// none). 1 the file-ID chain off (content only); 2 condition (d) off (a duty also while
    /// another transaction relies); 3 a forgotten creator honoured; 4 the parent of a removed
    /// inherited folder not marked for the flush; 5 an inherited act before the carrying op's
    /// `RevertIntent`.
    pub(crate) fn handover(n: u8) {
        HANDOVER.with(|s| s.set(n));
    }
    pub(crate) fn handover_is(n: u8) -> bool {
        HANDOVER.with(Cell::get) == n
    }

    /// K-LM2 (P3-3): the path of the profiles root is not compared with the plan's.
    pub(crate) fn uncheck_profiles_paths(on: bool) {
        PROFILES_PATHS_UNCHECKED.with(|s| s.set(on));
    }
    pub(crate) fn profiles_paths_unchecked() -> bool {
        PROFILES_PATHS_UNCHECKED.with(Cell::get)
    }

    /// K-CM1 (audit A2/A3, `combo_tests`): a folder is flushed once per run, not before every
    /// `RevertDone` of an op in it.
    pub(crate) fn flush_once_per_folder(on: bool) {
        FLUSH_ONCE_PER_FOLDER.with(|s| s.set(on));
    }
    pub(crate) fn flushing_once_per_folder() -> bool {
        FLUSH_ONCE_PER_FOLDER.with(Cell::get)
    }

    /// K-CM2 (A2-B1, `combo_tests`): a `.old` is renamed back onto the target name in upper
    /// case instead of the stored spelling.
    pub(crate) fn rename_back_upcased(on: bool) {
        RENAME_BACK_UPCASED.with(|s| s.set(on));
    }
    pub(crate) fn renaming_back_upcased() -> bool {
        RENAME_BACK_UPCASED.with(Cell::get)
    }

    /// K-CM3 (review M1 of P2-8, `combo_tests`): the parent folder of an op's target is not
    /// marked for the flush before its `RevertDone`.
    pub(crate) fn parent_not_marked(on: bool) {
        PARENT_NOT_MARKED.with(|s| s.set(on));
    }
    pub(crate) fn leaving_parent_unmarked() -> bool {
        PARENT_NOT_MARKED.with(Cell::get)
    }

    /// K-CL4 (P2-15 review M1): the cleanup pass ignores the target (deletes Rerun's copy also
    /// next to a file that changed since the revert).
    pub(crate) fn ignore_target(on: bool) {
        IGNORE_TARGET.with(|s| s.set(on));
    }
    pub(crate) fn ignoring_target() -> bool {
        IGNORE_TARGET.with(Cell::get)
    }

    /// K-CL2b (P2-15, senior-dev S1): the cleanup pass flushes only after a deletion of its own.
    pub(crate) fn flush_only_after_delete(on: bool) {
        FLUSH_ONLY_AFTER_DELETE.with(|s| s.set(on));
    }
    pub(crate) fn flushing_only_after_delete() -> bool {
        FLUSH_ONLY_AFTER_DELETE.with(Cell::get)
    }

    /// K-CL1 (P2-15): a transaction is closed although a `.old` of Rerun's is left.
    pub(crate) fn close_despite_cleanup(on: bool) {
        CLOSE_DESPITE_CLEANUP.with(|s| s.set(on));
    }
    pub(crate) fn closing_despite_cleanup() -> bool {
        CLOSE_DESPITE_CLEANUP.with(Cell::get)
    }
    /// K-CL3 (P2-15): the cleanup deletes whatever is at the name, without its known hash.
    pub(crate) fn cleanup_without_hash(on: bool) {
        CLEANUP_WITHOUT_HASH.with(|s| s.set(on));
    }
    pub(crate) fn cleaning_without_hash() -> bool {
        CLEANUP_WITHOUT_HASH.with(Cell::get)
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
    /// K-L3: a recorded head is decoded with the rules in force now (as before P2-11).
    pub(crate) fn current_for_recorded(on: bool) {
        CURRENT_FOR_RECORDED.with(|s| s.set(on));
    }
    pub(crate) fn decoding_recorded_as_current() -> bool {
        CURRENT_FOR_RECORDED.with(Cell::get)
    }
    /// K-RB3 (P2-14): stacking takes the objects of a rebound transaction from the head only.
    pub(crate) fn objects_from_head(on: bool) {
        OBJECTS_FROM_HEAD.with(|s| s.set(on));
    }
    pub(crate) fn taking_objects_from_head() -> bool {
        OBJECTS_FROM_HEAD.with(Cell::get)
    }
    /// K-RB2 (P2-14): a created folder of a rebound root is proven by `Done.file_id` only.
    pub(crate) fn dir_proof_from_done(on: bool) {
        DIR_PROOF_FROM_DONE.with(|s| s.set(on));
    }
    pub(crate) fn proving_dirs_from_done() -> bool {
        DIR_PROOF_FROM_DONE.with(Cell::get)
    }
    /// K-RB1 (P2-14, senior-dev B2): the revert rewrites the head's roots with the bindings, so
    /// the registry locations are built from the bound folder.
    pub(crate) fn rewrite_head(on: bool) {
        REWRITE_HEAD.with(|s| s.set(on));
    }
    pub(crate) fn rewriting_head() -> bool {
        REWRITE_HEAD.with(Cell::get)
    }
    /// K-RB4 (P2-14 review): the objects at the old identity of a rebound transaction dropped.
    pub(crate) fn objects_from_binding_only(on: bool) {
        OBJECTS_FROM_BINDING_ONLY.with(|s| s.set(on));
    }
    pub(crate) fn taking_objects_from_binding_only() -> bool {
        OBJECTS_FROM_BINDING_ONLY.with(Cell::get)
    }
    /// K-RB2b (P2-14 review S2): after the record, a created folder of a rebound root proven by
    /// the folder found (as before the record), not by the recorded file ID.
    pub(crate) fn dir_found_after_record(on: bool) {
        DIR_FOUND_AFTER_RECORD.with(|s| s.set(on));
    }
    pub(crate) fn finding_dirs_after_record() -> bool {
        DIR_FOUND_AFTER_RECORD.with(Cell::get)
    }
}

/// A recorded head (revert, `verify`, stacking) with `plan::Rules::Recorded` (E4: a rule
/// tightened since the apply does not block the revert); K-L3 (tests) uses the current rules.
pub(crate) fn decode_head(b: &[u8]) -> Result<Plan, PlanError> {
    #[cfg(test)]
    if knob::decoding_recorded_as_current() {
        return plan::decode(b);
    }
    plan::decode_recorded(b)
}

/// K1 (tests): observe from the records.
fn trusting_records() -> bool {
    #[cfg(test)]
    return knob::trusting_records();
    #[cfg(not(test))]
    false
}

/// K-RB3 (tests): the objects of a rebound transaction from the head only.
fn knob_objects_from_head() -> bool {
    #[cfg(test)]
    return knob::taking_objects_from_head();
    #[cfg(not(test))]
    false
}

/// K-RB4 (tests): the objects at the old identity of a rebound transaction dropped.
fn knob_objects_from_binding_only() -> bool {
    #[cfg(test)]
    return knob::taking_objects_from_binding_only();
    #[cfg(not(test))]
    false
}

/// K-RB2b (tests): after the record, a created folder proven by the folder found.
fn knob_dir_found_after_record() -> bool {
    #[cfg(test)]
    return knob::finding_dirs_after_record();
    #[cfg(not(test))]
    false
}

/// K-CL1 (tests): closed although a `.old` of Rerun's is left.
fn knob_close_despite_cleanup() -> bool {
    #[cfg(test)]
    return knob::closing_despite_cleanup();
    #[cfg(not(test))]
    false
}

/// K-CL2b (tests): the cleanup pass flushes only after a deletion of its own.
fn knob_flush_only_after_delete() -> bool {
    #[cfg(test)]
    return knob::flushing_only_after_delete();
    #[cfg(not(test))]
    false
}

/// K-HO1 to K-HO5 (tests, P4-8b): control `n` of the hand-over is on.
pub(super) fn knob_ho(
    #[cfg_attr(not(test), expect(unused_variables, reason = "test knob"))] n: u8,
) -> bool {
    #[cfg(test)]
    return knob::handover_is(n);
    #[cfg(not(test))]
    false
}

/// K-CM3 (tests): the parent folder of an op's target is not marked for the flush.
fn knob_parent_not_marked() -> bool {
    #[cfg(test)]
    return knob::leaving_parent_unmarked();
    #[cfg(not(test))]
    false
}

/// K-CL4 (tests): the cleanup pass ignores the target.
fn knob_ignore_target() -> bool {
    #[cfg(test)]
    return knob::ignoring_target();
    #[cfg(not(test))]
    false
}

/// K-CL3 (tests): the cleanup deletes whatever is at the name.
fn knob_cleanup_without_hash() -> bool {
    #[cfg(test)]
    return knob::cleaning_without_hash();
    #[cfg(not(test))]
    false
}

/// K-RB2 (tests): a created folder of a rebound root proven by `Done.file_id` only.
fn knob_dir_proof_from_done() -> bool {
    #[cfg(test)]
    return knob::proving_dirs_from_done();
    #[cfg(not(test))]
    false
}

/// K-RB1 (tests): the head's roots rewritten with the bindings for the revert loop (what E-R4 a
/// forbids: the registry locations would follow the bound folder).
fn knob_rewrite_head(
    #[cfg_attr(not(test), expect(unused_variables, reason = "test knob"))] plan: &Plan,
    #[cfg_attr(not(test), expect(unused_variables, reason = "test knob"))] b: &Bindings,
) -> Option<Plan> {
    #[cfg(test)]
    if knob::rewriting_head() {
        let mut p = plan.clone();
        for (r, x) in p.roots.iter_mut().zip(b.iter()) {
            r.path = x.path.clone();
            r.id = x.id;
            r.origin = x.origin.clone();
        }
        return Some(p);
    }
    None
}

/// K3 (tests): restore without the old R/H/S.
fn restoring_without_attrs() -> bool {
    #[cfg(test)]
    return knob::restoring_without_attrs();
    #[cfg(not(test))]
    false
}

/// A flush of `exec` (ADR 0019 amendments P2-7 S2, P2-8 and P2-10b), named by domain and
/// place; J6 switches each off in turn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Flush {
    /// The game folders an apply wrote into, before `Applied`.
    GameBeforeApplied,
    /// The hives an apply wrote into (`RegFlushKey`), before `Applied`.
    HiveBeforeApplied,
    /// The game folder of an op, before its `RevertDone` (and so before `Closed`).
    GameBeforeRevertDone,
    /// `HKCU`, before the `RevertDone` of a registry op.
    HiveBeforeRevertDone,
    /// The game folders of the `.old` files the cleanup pass looked at, before `Closed`
    /// (P2-15, senior-dev S1: always, also when every one was gone, so a deletion of an earlier
    /// run that crashed before its flush is durable before `Closed`).
    GameBeforeClosed,
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
    /// The result of `create_key` (6a).
    Key(reg::KeyHint),
    /// `set` refused the value (`Mismatch` or the policy): nothing was written in this run, so
    /// the new value there is not Rerun's.
    NotWritten,
}

/// What an op observes and what its revert does, by the domain of its target.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Seen {
    /// A file or directory.
    File(file::Seen),
    /// A registry key or value.
    Reg(reg::Seen),
    /// A firewall rule of the helper batch (P4-2d): observed only (`verify`); its revert is the
    /// batch's ([`helper::revert_batch`]).
    Rule(Observed),
}

impl Seen {
    /// What the op observed.
    fn observed(&self) -> Observed {
        match self {
            Self::File(s) => s.observed,
            Self::Reg(s) => s.observed,
            Self::Rule(o) => *o,
        }
    }

    /// A restore follows its actions (a `RevertIntent` with a temp name).
    fn restore(&self) -> bool {
        match self {
            Self::File(s) => s.restore,
            Self::Reg(_) | Self::Rule(_) => false,
        }
    }

    /// A semantic rewrite follows its actions (`IniValue`).
    fn rewrite(&self) -> Option<Semantic> {
        match self {
            Self::File(s) => s.rewrite,
            Self::Reg(_) | Self::Rule(_) => None,
        }
    }

    /// What it observed beyond its state.
    fn detail(&self) -> Option<Detail> {
        match self {
            Self::File(s) => s.detail.clone(),
            Self::Reg(_) | Self::Rule(_) => None,
        }
    }
}

/// What the act of a revert left behind.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Acted {
    /// The sequences whose `<tmp>.old` was left (mapped as an image), by index (P2-15).
    old_left: Vec<u16>,
    /// Names Rerun left in the op's folder: a `.old` still mapped, a temp name that is not
    /// Rerun's any more.
    left: Vec<RelPath>,
}

/// What a run touches, per domain, for the flushes (ADR 0019): the game folders and the hives
/// written into; and the registry writer and system the registry ops use.
struct Touched<'g> {
    dirs: file::Dirs<'g>,
    hives: BTreeSet<Hive>,
    reg: RegWriter<'g>,
    sys: &'g dyn System,
    /// The transaction, for the names of its firewall rules (P4-2d; `None` before `begin`).
    txn: Option<TxnId>,
    /// The firewall rules of the plan as observed in one enumeration (A4 S11), by op.
    rules: Option<BTreeMap<u16, Observed>>,
    /// What this revert hands over and inherits (P4-8b; empty for an apply and a rollback).
    shares: Shares,
}

/// What a revert hands over to later transactions and inherits from earlier ones (P4-8b, E6;
/// `share`).
#[derive(Debug, Default)]
struct Shares {
    /// Ops whose object later transactions rely on: kept, not removed.
    keeps: share::Keeps,
    /// Objects handed over to this transaction.
    inherit: share::Inherit,
}

impl<'g> Touched<'g> {
    fn new(sys: &'g dyn System, roots: &'g roots::Roots<'g>) -> Self {
        Self {
            dirs: file::Dirs::new(roots),
            hives: BTreeSet::new(),
            reg: RegPolicy.writer(sys),
            sys,
            txn: None,
            rules: None,
            shares: Shares::default(),
        }
    }

    /// For transaction `t` (its firewall rules' names).
    fn of(mut self, t: TxnId) -> Self {
        self.txn = Some(t);
        self
    }

    /// What the firewall holds for the rule of op `k`: every rule of the plan observed once.
    fn rule_seen(&mut self, plan: &Plan, k: u16) -> Result<Observed, ExecError> {
        if self.rules.is_none() {
            let txn = self.txn.ok_or(ExecError::Journal(JournalError::Order(
                "a firewall rule observed without its transaction",
            )))?;
            self.rules = Some(
                helper::observe_rules(self.sys, plan, &txn)?
                    .into_iter()
                    .collect(),
            );
        }
        self.rules
            .as_ref()
            .and_then(|m| m.get(&k).copied())
            .ok_or(ExecError::Verify {
                op: k,
                observed: Observed::Foreign,
            })
    }

    /// Before `Applied`: every domain the apply changed (the game folders, after every guard
    /// is dropped: a POSIX delete through a guard reaches the volume log when it closes; then
    /// the hives: `RegFlushKey` flushes a whole hive).
    fn flush_all(&mut self) -> SysResult<()> {
        if !flush_skipped(Flush::GameBeforeApplied) {
            self.dirs.flush()?;
        }
        if !self.hives.is_empty() && !flush_skipped(Flush::HiveBeforeApplied) {
            self.reg.flush()?;
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
                        .parent(root.0, path, !knob_parent_not_marked())
                        .map_err(|source| ExecError::Op { op: k, source })?;
                    self.dirs.flush()?;
                }
            }
            Target::Key { .. } | Target::Value { .. } => {
                if !flush_skipped(Flush::HiveBeforeRevertDone) {
                    self.reg
                        .flush()
                        .map_err(|source| ExecError::Op { op: k, source })?;
                }
            }
            // The firewall persists its rules itself (ADR 0023 §6); the batch has no flush here.
            Target::Rule { .. } => {}
        }
        Ok(())
    }
}

/// Applies op `k` in its domain.
fn apply_op(
    cx: &ExecCtx<'_>,
    plan: &Plan,
    w: &mut TxnWriter<'_>,
    t: &mut Touched<'_>,
    k: u16,
    op: &Op,
    hints: &mut BTreeMap<u16, Hint>,
) -> Result<(), ExecError> {
    match op.target() {
        Target::File { .. } if matches!(op, Op::IniValue { .. }) => {
            ini::apply_op(w, &mut t.dirs, k, op, hints)
        }
        Target::File { .. } => file::apply_op(cx, w, &mut t.dirs, k, op, hints),
        Target::Key { .. } | Target::Value { .. } => {
            t.hives.insert(Hive::CurrentUser);
            reg::apply_op(w, &t.reg, plan, k, op, hints)
        }
        // The helper batch is applied as a whole (`helper::run_batch`).
        Target::Rule { .. } => Err(helper_only(k)),
    }
}

/// An op of the helper batch reached a path of a single op.
fn helper_only(k: u16) -> ExecError {
    ExecError::Op {
        op: k,
        source: SysError::new(
            crate::sys::SysErrorKind::Other,
            "a firewall rule op is changed only by the helper batch",
        ),
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
        Target::File { .. } if matches!(op, Op::IniValue { .. }) => {
            ini::observe(&mut t.dirs, k, op, log, hint).map(Seen::File)
        }
        Target::File { .. } => {
            file::observe(plan, &mut t.dirs, k, op, log, mode, hint, later).map(Seen::File)
        }
        Target::Key { .. } | Target::Value { .. } => {
            reg::observe(&t.reg, t.sys, plan, k, op, log, mode, hint, later).map(Seen::Reg)
        }
        Target::Rule { .. } => t.rule_seen(plan, k).map(Seen::Rule),
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
        // Registry ops never halt: they need no root (6b-d). Nor does a firewall rule: its
        // program is the head's path, the root need not be there (ADR 0023 §9).
        Target::Key { .. } | Target::Value { .. } | Target::Rule { .. } => None,
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
    verify_seen(plan, t, roots, ops).map(|(v, _)| v)
}

/// [`verify_ops`] with what each observed op saw and will do (a rebind takes the file IDs of the
/// created folders from it, P2-14).
fn verify_seen(
    plan: &Plan,
    t: &mut Touched<'_>,
    roots: &roots::Roots<'_>,
    ops: &BTreeMap<u16, OpLog>,
) -> Result<(Verified, BTreeMap<u16, Seen>), ExecError> {
    let mut seen = BTreeMap::new();
    let mut out = BTreeMap::new();
    let mut details = BTreeMap::new();
    let mut halted = None;
    for (k, log) in ops.iter().rev() {
        let op = op_of(plan, *k)?;
        if let Some(h) = halt(roots, *k, op) {
            match &log.reverted {
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
        // P4-8b: a kept op, as the revert would keep it (a chain that does not hold shows the
        // plain observation; the revert refuses it before its first record).
        let s = match keep_of(plan, t, *k, op, log, Mode::Verify, &seen) {
            Ok(Some(s)) => s,
            Ok(None) | Err(ExecError::Refused(_)) => {
                observe(plan, t, *k, op, log, Mode::Verify, None, &seen)?
            }
            Err(e) => return Err(e),
        };
        out.insert(*k, s.observed());
        let mut with = seen.clone();
        with.insert(*k, s.clone());
        let inherited = inherit_of(t, *k, false, &gone_below(plan, &with))?;
        if let Some(d) = s
            .detail()
            .or_else(|| (!inherited.is_empty()).then_some(Detail::Inherited(inherited)))
        {
            details.insert(*k, d);
        }
        seen.insert(*k, s);
    }
    Ok((
        Verified {
            ops: out.into_iter().collect(),
            halted,
            details,
            cleanup: Vec::new(),
            profiles_moved: roots.profiles_moved().cloned(),
            virtual_store: Vec::new(),
        },
        seen,
    ))
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
        Seen::Reg(s) => reg::act(w, &t.reg, k, op, s),
        Seen::Rule(_) => Err(helper_only(k)),
    }
}

/// The records fit the head (ADR 0019: the journal is op-agnostic; condition 5): every
/// intended op exists, and its records have the form of its kind.
fn records_fit(plan: &Plan, ops: &BTreeMap<u16, OpLog>) -> bool {
    // P4-2d review follow-up (ADR 0023 §9): a logged batch is exactly the head's rule ops, which
    // end at the head's last op (a `HelperBatch` cut short of them does not fit).
    let logged: Vec<u16> = ops
        .iter()
        .filter(|(_, l)| l.intent.batch)
        .map(|(k, _)| *k)
        .collect();
    if !logged.is_empty() {
        let whole = helper::batch_of(plan).is_some_and(|(f, l)| {
            logged.iter().copied().eq(f..=l) && usize::from(l) + 1 == plan.ops.len()
        });
        if !whole {
            return false;
        }
    }
    ops.iter()
        .all(|(k, log)| match plan.ops.get(usize::from(*k)) {
            None => false,
            // P4-2d: an op of the helper batch exactly when the head says it is a firewall rule.
            Some(op) if log.intent.batch != op.target().is_helper() => false,
            // P4-8b (B1): only a created file or folder is ever kept for a later transaction.
            Some(op)
                if log
                    .reverted
                    .as_ref()
                    .is_some_and(|r| r.observed == Observed::Kept)
                    && !matches!(op, Op::CreateFile { .. } | Op::CreateDir { .. }) =>
            {
                false
            }
            Some(op) => match op.target() {
                Target::File { .. } if matches!(op, Op::IniValue { .. }) => {
                    ini::records_fit(op, log)
                }
                Target::File { .. } => file::records_fit(op, log),
                Target::Key { .. } | Target::Value { .. } => reg::records_fit(op, log),
                Target::Rule { .. } => rule_records_fit(log),
            },
        })
}

/// The records of a firewall rule op (ADR 0023 §9): no temp name, no old state, no file ID, no
/// `.old`, no semantic revert (the grammar refuses most of it already; the head decides the kind).
fn rule_records_fit(log: &OpLog) -> bool {
    log.intent.tmp.is_none()
        && log.intent.before.is_none()
        && log.done.is_none_or(|d| d.file_id.is_none() && !d.old_left)
        && log
            .reverts
            .iter()
            .all(|r| r.tmp.is_none() && r.from.is_none() && r.to.is_none())
        && log.reverted.as_ref().is_none_or(|r| r.old_left.is_empty())
}

/// The front-end and core guard of every write (P2-13, user decision E3): Rerun runs as a
/// standard user. Elevated, or undeterminable (fail closed): `Refusal::Elevated`. `apply`,
/// `revert` and `forget` ask it first, for every plan; a front end also asks it before it
/// stores a plan and before a dry run, so an elevated process neither writes nor checks as an
/// administrator (`user_writable` is the linked token's, ADR 0007; the journal and the plans
/// would land in the administrator's profile).
pub fn standard_user(sys: &dyn System) -> Result<(), Refusal> {
    RegPolicy
        .writer(sys)
        .writable()
        .map_err(|_| Refusal::Elevated)
}

/// Every check of [`apply`] before its transaction begins, read only (P2-13, user decision
/// E2 a; review S1, S2): the stored plan and its hash, then (if it has ops) the stacking on the
/// listing, every root reopened by identity, the main executables, the game closed and the old
/// state of every op, by the same `preflight` as `apply`. No `journal\` and no lock file is
/// created and no record written; an existing `journal\lock` is held read side meanwhile, so
/// an apply that holds it makes this `JournalBusy`, as it would the apply. The game files are
/// read under guards, as by the apply. `Ok(0)`: nothing to do.
pub fn check(cx: &ExecCtx<'_>, h: &PlanHash) -> Result<usize, Refusal> {
    standard_user(cx.sys)?;
    let bytes = plan::load(cx.app, h).map_err(Refusal::Plan)?;
    let plan = plan::decode(bytes.bytes()).map_err(Refusal::Plan)?;
    if plan.ops.is_empty() {
        return Ok(0);
    }
    // P4-2d: the helper's pre-check and the prompt state, before anything else (ADR 0023 §2).
    helper::ready(cx.sys, &plan)?;
    let j = Journal::new(cx.app, cx.tag);
    let hold = j.hold().map_err(Refusal::from)?;
    let listing = j.list().map_err(Refusal::from)?;
    let stores = roots::open_stores(cx, &Bindings::head(&plan));
    let roots = preflight(cx, &plan, &j, &listing, &stores, roots::Preflight::Check)?;
    drop(roots);
    drop(hold);
    Ok(plan.ops.len())
}

/// The checks of an apply before `begin`, in this order (review S1: one chain for [`apply`]
/// under the lock and [`check`] without it): stacking on the listing, every root reopened by
/// identity (writable where it has file ops), the main executable of every root a file, the
/// game closed, the old state of every op and source, the old registry state. The roots stay
/// open for the apply. `run`: the apply creates a missing profiles root (P3-3), `check`
/// creates nothing.
fn preflight<'g>(
    cx: &ExecCtx<'g>,
    plan: &Plan,
    j: &Journal<'_>,
    listing: &Listing,
    stores: &'g [Option<Result<StoreDir<'g>, RootError>>],
    run: roots::Preflight,
) -> Result<roots::Roots<'g>, Refusal> {
    let objects = Object::of(plan).map_err(Refusal::Plan)?;
    let changes: Vec<bool> = plan
        .ops
        .iter()
        .map(|o| matches!(o, Op::ReplaceFile { .. } | Op::IniValue { .. }))
        .collect();
    stack::for_apply(j, listing, &objects, &changes)?;
    // P4-8: no DLL slot of another package's live transaction.
    if let Some(s) = stack::slot_taken(j, listing, plan) {
        return Err(Refusal::SlotTaken {
            txn: s.txn,
            op: s.op,
            path: s.path,
            package: s.package,
        });
    }
    let roots = roots::Roots::all(cx, plan, &Bindings::head(plan), stores, run)?;
    let all: Vec<u16> = (0..plan.ops.len()).map(op_ix).collect();
    roots::main_exe_present(plan, &roots)?;
    roots::game_closed(plan, &roots, &all)?;
    // P5-2a: the build the plan was made for (after D4: a running game is refused without
    // hashing up to 2 GiB).
    roots::main_exe_same(plan, &roots)?;
    roots::old_state(cx, plan, &roots)?;
    reg::old_state(&RegPolicy.writer(cx.sys), plan)?;
    // A4 S7: the firewall rules are still what the signed Topo authorises here.
    helper::recheck(cx, plan, &roots)?;
    Ok(roots)
}

/// The executables of game folder `root` that live transactions patched (P4-10, R5): the Topo
/// engine counts such a file as its base build (`topo::read_game_with`), so a game patched by
/// `laa_patch` is still found until the revert. Read without the lock (like the plan's slot check);
/// a journal that cannot be read gives none.
pub fn patched_now(app: &AppDir<'_>, root: crate::policy::root::RootId) -> Vec<PatchedExe> {
    let j = Journal::new(app, crate::journal::InstanceTag::new());
    match j.list() {
        Ok(l) => stack::patched(&j, &l, root),
        Err(_) => Vec::new(),
    }
}

/// The DLL slot check of an apply (P4-8), for the planner, so a plan names a taken slot before
/// its preview: the journal read without the lock (anything unreadable is "nothing found"; the
/// apply checks again under the lock).
pub(crate) fn slot_taken_now(app: &AppDir<'_>, plan: &Plan) -> Option<Refusal> {
    let j = Journal::new(app, crate::journal::InstanceTag::new());
    let l = j.list().ok()?;
    stack::slot_taken(&j, &l, plan).map(|s| Refusal::SlotTaken {
        txn: s.txn,
        op: s.op,
        path: s.path,
        package: s.package,
    })
}

/// Applies the stored plan `h` (module docs).
pub fn apply(cx: &ExecCtx<'_>, h: &PlanHash) -> Result<Outcome, ApplyError> {
    standard_user(cx.sys)?;
    let bytes = plan::load(cx.app, h).map_err(Refusal::Plan)?;
    let plan = plan::decode(bytes.bytes()).map_err(Refusal::Plan)?;
    if plan.ops.is_empty() {
        return Ok(Outcome::Nothing);
    }
    // P4-2d: the helper's pre-check and the prompt state before the lock (ADR 0023 §2, §10).
    let ready = helper::ready(cx.sys, &plan)?;
    let j = Journal::new(cx.app, cx.tag);
    let lock = j.lock().map_err(Refusal::from)?;
    let listing = j.list().map_err(Refusal::from)?;
    let stores = roots::open_stores(cx, &Bindings::head(&plan));
    let roots = preflight(cx, &plan, &j, &listing, &stores, roots::Preflight::Apply)?;
    let mut w = lock.begin(bytes.bytes()).map_err(Refusal::from)?;
    let txn = *w.id();
    let mut touched = Touched::new(cx.sys, &roots).of(txn);
    let mut hints = BTreeMap::new();
    let cause = match run(
        cx,
        &plan,
        &mut w,
        &mut touched,
        &roots,
        &mut hints,
        ready.as_ref(),
    ) {
        Ok(()) => return Ok(Outcome::Applied(txn)),
        Err(e) => e,
    };
    // R3: a helper result the rollback cannot undo without a second prompt stays open.
    if let ExecError::Helper(f) = &cause
        && !f.rolls_back()
    {
        return Err(ApplyError::HelperOpen {
            txn,
            cause: Box::new(cause),
        });
    }
    match rollback(cx, &plan, w, &mut touched, &roots, &hints) {
        Ok(cleanup) if cleanup.iter().any(|p| p.seen.holds_open()) => {
            Err(ApplyError::CleanupPending {
                txn,
                cause: Box::new(cause),
                cleanup,
            })
        }
        Ok(cleanup) => Err(ApplyError::RolledBack {
            txn,
            cause: Box::new(cause),
            cleanup,
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

/// The ops, `After` for each, the flushes, `Applied`. The helper batch (P4-2d, ADR 0023 §9)
/// comes after the flushes of every other op, so only `Done` records and `Applied` follow it.
fn run(
    cx: &ExecCtx<'_>,
    plan: &Plan,
    w: &mut TxnWriter<'_>,
    t: &mut Touched<'_>,
    roots: &roots::Roots<'_>,
    hints: &mut BTreeMap<u16, Hint>,
    ready: Option<&helper::Ready>,
) -> Result<(), ExecError> {
    let batch = helper::batch_of(plan);
    let plain = batch.map_or(plan.ops.len(), |(first, _)| usize::from(first));
    for (k, op) in plan.ops.iter().enumerate().take(plain) {
        apply_op(cx, plan, w, t, op_ix(k), op, hints)?;
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
    if batch.is_some() {
        let ready = ready.ok_or(ExecError::Journal(JournalError::Order(
            "a helper batch without the helper's pre-check",
        )))?;
        helper::run_batch(cx, plan, w, roots, ready)?;
    }
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
/// in-process results of the calls (`hints`, senior-dev condition 4), then the cleanup pass
/// (P2-15, senior-dev B1: a rollback closes only when nothing of Rerun's is left, as a revert).
/// `Ok`: what the cleanup pass observed; closed `RolledBack` unless one item holds it open.
fn rollback(
    cx: &ExecCtx<'_>,
    plan: &Plan,
    mut w: TxnWriter<'_>,
    t: &mut Touched<'_>,
    roots: &roots::Roots<'_>,
    hints: &BTreeMap<u16, Hint>,
) -> Result<Vec<PendingOld>, ExecError> {
    // Every root opened for the apply, so the rollback never halts; if it did, it is open.
    let (_, halted) = revert_loop(cx, plan, &mut w, t, roots, Mode::Rollback, hints)?;
    if let Some(h) = halted {
        return Err(ExecError::Refused(*h.why));
    }
    let foreign = foreign_ops(&w);
    if !foreign.is_empty() {
        return Err(ExecError::Foreign { ops: foreign });
    }
    let mut deleted = false;
    let ops = w.ops().clone();
    let (cleanup, halted) = cleanup_pass(plan, t, roots, &ops, Mode::Recovery, &mut deleted)?;
    if let Some(h) = halted {
        return Err(ExecError::Refused(*h.why));
    }
    if cleanup.iter().any(|p| p.seen.holds_open()) && !knob_close_despite_cleanup() {
        return Ok(cleanup);
    }
    close(w)?;
    Ok(cleanup)
}

/// The cleanup pass (P2-15; module docs): every `.old` the journal names for the ops `ops`
/// whose `RevertDone` is not `Foreign` (`OpLog::pending_old`), by op ascending, through
/// `file::cleanup_op`; `Mode::Verify` reads only. An op whose root cannot run file ops halts
/// the pass before anything of it is touched (no record is written by the pass at all). After
/// a pass that looked at a `.old`, every game folder it looked in is flushed (the tenth flush
/// site, always: senior-dev S1). `deleted`: a deletion happened (a change, never "nothing
/// changed", senior-dev B2), also when the pass then fails.
fn cleanup_pass(
    plan: &Plan,
    t: &mut Touched<'_>,
    roots: &roots::Roots<'_>,
    ops: &BTreeMap<u16, OpLog>,
    mode: Mode,
    deleted: &mut bool,
) -> Result<(Vec<PendingOld>, Option<Halt>), ExecError> {
    let act = mode != Mode::Verify;
    let mut out = Vec::new();
    let mut looked = false;
    for (k, log) in ops {
        let reverted = log
            .reverted
            .as_ref()
            .is_some_and(|r| r.observed != Observed::Foreign);
        if !reverted || log.pending_old().is_empty() {
            continue;
        }
        let op = op_of(plan, *k)?;
        if let Some(h) = halt(roots, *k, op) {
            return Ok((out, Some(h)));
        }
        looked = true;
        out.extend(file::cleanup_op(&mut t.dirs, *k, op, log, act, deleted)?);
    }
    let flush = !knob_flush_only_after_delete() || *deleted;
    if act && looked && flush && !flush_skipped(Flush::GameBeforeClosed) {
        t.dirs.flush()?;
    }
    Ok((out, None))
}

/// The ops whose `RevertDone` recorded `Foreign`, in this run or an earlier one: the
/// transaction cannot be closed as reverted (ADR 0019 grammar, S3), only forgotten.
fn foreign_ops<W: Reverting>(w: &W) -> Vec<u16> {
    w.ops()
        .iter()
        .filter(|(_, o)| {
            o.reverted
                .as_ref()
                .is_some_and(|r| r.observed == Observed::Foreign)
        })
        .map(|(k, _)| *k)
        .collect()
}

/// `Closed` by how far the transaction got. Every change of the revert was flushed before its
/// `RevertDone` (in [`revert_loop`]), and every deletion of the cleanup pass by its own flush
/// ([`cleanup_pass`]), so the game folders need no flush here.
fn close<W: Reverting>(w: W) -> Result<(), ExecError> {
    let how = if w.is_applied() {
        Closing::Reverted
    } else {
        Closing::RolledBack
    };
    w.close(how)?;
    Ok(())
}

/// The creator side of the hand-over for op `k` (P4-8b): `Some` when the op is kept for later
/// transactions (`file::keep_seen`).
fn keep_of(
    plan: &Plan,
    t: &mut Touched<'_>,
    k: u16,
    op: &Op,
    log: &OpLog,
    mode: Mode,
    later: &BTreeMap<u16, Seen>,
) -> Result<Option<Seen>, ExecError> {
    if mode == Mode::Rollback {
        return Ok(None);
    }
    let Some(reliers) = t.shares.keeps.get(&k).cloned() else {
        return Ok(None);
    };
    file::keep_seen(plan, &mut t.dirs, k, op, log, mode, &reliers, later).map(|s| s.map(Seen::File))
}

/// The inheritor side of the hand-over for op `k` (P4-8b): its duties carried out (`act`) or
/// predicted, and the objects another transaction still relies on.
fn inherit_of(
    t: &mut Touched<'_>,
    k: u16,
    act: bool,
    gone: &BTreeMap<String, Vec<String>>,
) -> Result<Vec<Inherited>, ExecError> {
    let duties = t.shares.inherit.duties.get(&k).cloned().unwrap_or_default();
    let still = t.shares.inherit.still.get(&k).cloned().unwrap_or_default();
    if duties.is_empty() && still.is_empty() {
        return Ok(Vec::new());
    }
    file::inherit(&mut t.dirs, k, &duties, &still, act, gone)
}

/// For `verify` (N5): the folded names below each folder (folded path) that the observed ops of
/// `seen` remove (`After`) or never made (`Before`).
fn gone_below(plan: &Plan, seen: &BTreeMap<u16, Seen>) -> BTreeMap<String, Vec<String>> {
    let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (k, s) in seen {
        if !matches!(s.observed(), Observed::After | Observed::Before) {
            continue;
        }
        // Review follow-up (senior S-1): a hold never removes its file (an inherited file duty
        // records its own removal).
        if matches!(plan.ops.get(usize::from(*k)), Some(Op::Hold { .. })) {
            continue;
        }
        let Some(Target::File { path, .. }) = plan.ops.get(usize::from(*k)).map(Op::target) else {
            continue;
        };
        let segs: Vec<String> = path.segments().map(crate::fold::fold).collect();
        for i in 1..segs.len() {
            out.entry(segs[..i].join("\\"))
                .or_default()
                .push(segs[i].clone());
        }
    }
    out
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
        // P4-2d: the helper batch as a whole (newest first, so before every other op); a
        // rollback never starts the helper (R3).
        if log.intent.batch {
            let (done, halted) = helper::revert_batch(cx, plan, w, mode != Mode::Rollback)?;
            reports.extend(done);
            if halted.is_some() {
                return Ok((reports, halted));
            }
            continue;
        }
        let op = op_of(plan, k)?;
        if let Some(h) = halt(roots, k, op) {
            return Ok((reports, Some(h)));
        }
        let none = BTreeMap::new();
        let seen = match keep_of(plan, t, k, op, &log, mode, &none) {
            Ok(Some(s)) => s,
            Ok(None) => observe(plan, t, k, op, &log, mode, hints.get(&k).copied(), &none)?,
            // Review follow-up (security 4): the ID chain broke after the check before the first
            // record: a halt (open, resumable newest first), never an error after records.
            Err(ExecError::Refused(r @ Refusal::Held { .. })) => {
                let root = match op.target() {
                    Target::File { root, .. } => root.0,
                    _ => 0,
                };
                return Ok((
                    reports,
                    Some(Halt {
                        op: k,
                        root,
                        why: Box::new(r),
                    }),
                ));
            }
            Err(e) => return Err(e),
        };
        let observed = seen.observed();
        // K-HO5 (tests): the inherited act before this op's `RevertIntent` (what S1 forbids).
        let early_inherited = if knob_ho(5) {
            inherit_of(t, k, true, &BTreeMap::new())?
        } else {
            Vec::new()
        };
        let sem = seen.rewrite();
        let y = (seen.restore() || sem.is_some()).then(|| w.tmp());
        // P2-12: a rewrite records where it starts and ends, before its first change (K-I1
        // switches that off).
        if sem.is_some_and(|s| !ini::semantic_fits(&s)) {
            // Never written: the reader would refuse the record (security review S-1).
            return Err(ExecError::Op {
                op: k,
                source: crate::sys::SysError::new(
                    crate::sys::SysErrorKind::TooLarge,
                    "a rewrite outside the bounds of its record",
                ),
            });
        }
        w.revert_intent(k, y.clone(), sem.filter(|_| !ini::unrecorded()))?;
        let done = act(w, t, k, op, &seen, y)?;
        // P4-8b (S1): what this op inherited, after its own act and its flushed intent.
        let mut inherited = early_inherited;
        if !knob_ho(5) {
            inherited = inherit_of(t, k, true, &BTreeMap::new())?;
        }
        // Always, also when the act changed nothing (`Touched::flush_for`).
        t.flush_for(k, op.target())?;
        w.revert_done(k, observed, &done.old_left)?;
        reports.push(OpReport {
            op: k,
            observed,
            left: done.left,
            backup: (observed == Observed::Foreign)
                .then(|| Backup::of(cx.app, w.id(), k, &log.intent))
                .flatten(),
            detail: seen
                .detail()
                .or_else(|| (!inherited.is_empty()).then_some(Detail::Inherited(inherited))),
        });
    }
    Ok((reports, None))
}

/// An error of a revert before it wrote anything in this run, as the refusal it is (P2-13,
/// review S4): a front end can then say "nothing changed" for every error of this kind.
fn refused_early(e: ExecError) -> Refusal {
    match e {
        ExecError::Refused(r) => r,
        ExecError::Journal(e) => e.into(),
        ExecError::Sys(e) => e.into(),
        ExecError::Op { op, source } => Refusal::Observe { op, source },
        ExecError::Verify { op, .. } => Refusal::Observe {
            op,
            source: SysError::new(
                crate::sys::SysErrorKind::Other,
                "the op is in another state than its records say",
            ),
        },
        _ => Refusal::Journal(Box::new(JournalError::Order(
            "an error before the first record of the revert",
        ))),
    }
}

/// The revert records of `ops` (`RevertIntent` and `RevertDone`): whether this run wrote one.
fn revert_records(ops: &BTreeMap<u16, OpLog>) -> usize {
    ops.values()
        .map(|o| o.reverts.len() + usize::from(o.reverted.is_some()))
        .sum()
}

/// The listing part of a revert's checks: `t` exists, is not forgotten, not damaged.
fn revert_listed(listing: &Listing, t: &TxnId) -> Result<(), Refusal> {
    let own = listing
        .txns
        .iter()
        .find(|l| l.id == *t)
        .ok_or_else(|| Refusal::from(JournalError::NotFound(*t)))?;
    if own.forgotten {
        return Err(Refusal::Forgotten { txn: *t });
    }
    let damaged = own
        .view
        .as_ref()
        .map_or(true, |v| matches!(v.state, TxnState::Damaged(_)));
    if damaged {
        return Err(Refusal::Blocked { txn: *t });
    }
    Ok(())
}

/// The head part of a revert's checks: the recorded head decodes (recorded rules), the records
/// fit it, every recorded `IniValue` binds to its backup, and the rebinds fit the head (P2-14).
fn revert_plan(
    t: &TxnId,
    head: &[u8],
    ops: &BTreeMap<u16, OpLog>,
    rebinds: &[RebindRec],
    before: &ini::BeforeBytes<'_>,
) -> Result<(Plan, Bindings), Refusal> {
    let blocked = || Refusal::Blocked { txn: *t };
    let plan = decode_head(head).map_err(|_| blocked())?;
    if !records_fit(&plan, ops) {
        return Err(blocked());
    }
    // P2-12: a recorded `IniValue` edits its backup to exactly its new content.
    if !ini::binds(&plan, ops, before).map_err(Refusal::from)? {
        return Err(blocked());
    }
    let b = Bindings::of(&plan, rebinds).ok_or_else(blocked)?;
    Ok((plan, b))
}

/// The rest of a revert's checks before its first record: LIFO against later transactions,
/// each root on its own, the game closed. The roots stay open for the revert.
#[expect(
    clippy::too_many_arguments,
    reason = "the one chain of a revert's checks"
)]
fn revert_roots<'g>(
    cx: &ExecCtx<'g>,
    plan: &Plan,
    b: &Bindings,
    j: &Journal<'_>,
    listing: &Listing,
    t: &TxnId,
    ops: &BTreeMap<u16, OpLog>,
    stores: &'g [Option<Result<StoreDir<'g>, RootError>>],
    rebound: bool,
) -> Result<(roots::Roots<'g>, Shares), Refusal> {
    let by_op = b
        .objects_by_op(plan)
        .map_err(|_| Refusal::Blocked { txn: *t })?;
    let objects: Vec<Object> = by_op.iter().map(|(_, o)| o.clone()).collect();
    let me = stack::Me {
        plan,
        objs: &by_op,
        rebound,
    };
    let keeps = stack::for_revert(j, listing, t, &objects, Some(&me))?;
    let roots = roots::Roots::each(cx, b, stores)?;
    let intended: Vec<u16> = ops.keys().copied().collect();
    roots::game_closed(plan, &roots, &intended)?;
    // Review follow-up (security 1): also an interrupted apply carries what it inherits (it
    // counted as relying); the in-process rollback of an apply never does (`Mode::Rollback`).
    let (inherit, blocked) = if !rebound && share::may_inherit(plan, ops) {
        let others = share::read(j, listing, Some(t), true)?;
        (share::duties(&others, t, plan, ops)?, others.blocked)
    } else {
        (share::Inherit::default(), Vec::new())
    };
    let shares = Shares { keeps, inherit };
    shares_hold(t, plan, ops, &roots, &shares, &blocked)?;
    Ok((roots, shares))
}

/// The disk checks of a hand-over before the first record, read only (P4-8b): S5, a file a
/// later transaction relies on that holds the op's content with another file ID than the op
/// recorded (or a relying `Hold` that recorded another one) cannot be handed over
/// (`Refusal::Held`, nothing written); fail closed (HO8), a duty whose object still exists with
/// its creator's file ID while an entry of the listing cannot be read is `Blocked`.
fn shares_hold(
    own: &TxnId,
    plan: &Plan,
    ops: &BTreeMap<u16, OpLog>,
    roots: &roots::Roots<'_>,
    shares: &Shares,
    blocked: &[TxnId],
) -> Result<(), Refusal> {
    let mut dirs = file::Dirs::new(roots);
    for (k, reliers) in &shares.keeps {
        let Some(Op::CreateFile {
            root,
            path,
            content,
            attrs,
        }) = plan.ops.get(usize::from(*k))
        else {
            continue;
        };
        if ops.get(k).is_some_and(|l| l.reverted.is_some()) {
            continue;
        }
        let done = ops.get(k).and_then(|l| l.done).and_then(|d| d.file_id);
        let found = file::find(&mut dirs, root.0, path)
            .map_err(|source| Refusal::Observe { op: *k, source })?;
        if let file::Found::File {
            sha,
            len,
            attrs: a,
            id,
            exact,
        } = found
            && sha == *content.sha256()
            && len == content.len()
            && a == *attrs
            && exact
        {
            let chain = Some(id) == done
                && reliers
                    .iter()
                    .all(|r| r.held_id.is_none() || r.held_id == done);
            if !chain
                && !knob_ho(1)
                && let Some(r) = reliers.first()
            {
                return Err(Refusal::Held { txn: r.txn });
            }
        }
    }
    // An entry that cannot be used (`share::read`: its records unknown, damaged, or a creator or
    // holder whose head cannot be used) may have handed over, or rely on, an object this
    // transaction relies on: while a held file still has the ID this transaction recorded, or a
    // folder above one of its relying ops that it did not create is there, the revert is
    // refused (fail closed; `forget` of that entry ends it). This covers every duty object.
    let Some(earlier) = blocked.iter().find(|b| **b != *own) else {
        return Ok(());
    };
    let created: Vec<String> = plan
        .ops
        .iter()
        .filter_map(|o| match o {
            Op::CreateDir { path, .. } => Some(crate::fold::fold(path.as_str())),
            _ => None,
        })
        .collect();
    for (k, op) in plan.ops.iter().enumerate() {
        let k16 = op_ix(k);
        let Some(log) = ops.get(&k16).filter(|l| l.reverted.is_none()) else {
            continue;
        };
        let Target::File { root, path, .. } = op.target() else {
            continue;
        };
        if !matches!(
            op,
            Op::CreateFile { .. } | Op::CreateDir { .. } | Op::Hold { .. }
        ) {
            continue;
        }
        let refuse = |found: file::Found, want: Option<u128>| match (found, want) {
            (file::Found::File { id, .. }, Some(w)) => id == w,
            (file::Found::Dir { .. }, None) => true,
            _ => false,
        };
        if matches!(op, Op::Hold { .. }) {
            let want = log.done.and_then(|d| d.file_id);
            let found = file::find(&mut dirs, root.0, path)
                .map_err(|source| Refusal::Observe { op: k16, source })?;
            if want.is_some() && refuse(found, want) {
                return Err(Refusal::Blocked { txn: *earlier });
            }
        }
        let segs: Vec<&str> = path.segments().collect();
        for i in 1..segs.len() {
            let Ok(dir) = crate::path::RelPath::parse(&segs[..i].join("\\")) else {
                continue;
            };
            if created.contains(&crate::fold::fold(dir.as_str())) {
                continue;
            }
            let found = file::find(&mut dirs, root.0, &dir)
                .map_err(|source| Refusal::Observe { op: k16, source })?;
            if refuse(found, None) {
                return Err(Refusal::Blocked { txn: *earlier });
            }
        }
    }
    Ok(())
}

/// Every check of [`revert`] before its first record, read only (P2-13, senior-dev S-a): the
/// same chain (`revert_listed`, `revert_plan`, `revert_roots`), on the transaction as read
/// without the lock, holding an existing lock file read side (review S2). A front end runs it
/// before its preview and its question, so neither offers a revert that is refused anyway.
pub fn revert_check(cx: &ExecCtx<'_>, t: &TxnId) -> Result<(), Refusal> {
    standard_user(cx.sys)?;
    let j = Journal::new(cx.app, cx.tag);
    let hold = j.hold()?;
    let listing = j.list()?;
    revert_listed(&listing, t)?;
    let (v, head) = load_resumable(&j, t)?;
    let before = |k: u16, d: &crate::journal::Digest, max: u64| j.read_backup(t, k, d, max);
    let (plan, b) = revert_plan(t, &head, &v.ops, &v.rebinds, &before)?;
    let stores = roots::open_stores(cx, &b);
    let (roots, _) = revert_roots(
        cx,
        &plan,
        &b,
        &j,
        &listing,
        t,
        &v.ops,
        &stores,
        !v.rebinds.is_empty(),
    )?;
    drop(roots);
    drop(hold);
    Ok(())
}

/// Transaction `t` read without the lock, as `JournalLock::resume` would accept it: `Empty`,
/// `Open` or `Applied`, with a head (its bytes).
fn load_resumable(
    j: &Journal<'_>,
    t: &TxnId,
) -> Result<(crate::journal::TxnView, Vec<u8>), Refusal> {
    let mut v = j.load(t, crate::journal::VerifyBackups::Length)?;
    let resumable = matches!(
        v.state,
        TxnState::Empty | TxnState::Open | TxnState::Applied
    );
    match v.head.take().filter(|_| resumable) {
        Some(head) => Ok((v, head)),
        None => Err(JournalError::NotResumable {
            id: *t,
            state: v.state.clone(),
        }
        .into()),
    }
}

/// Whether `t` counts as closed in the journal now (a `Closed` record or a forget marker); a
/// journal that cannot be read counts as "maybe" (true): never claim "nothing changed" then.
fn closed_now(j: &Journal<'_>, t: &TxnId) -> bool {
    j.list().map_or(true, |l| {
        l.txns.iter().find(|x| x.id == *t).is_none_or(|x| {
            x.forgotten
                || x.view
                    .as_ref()
                    .map_or(true, |v| matches!(v.state, TxnState::Closed(_)))
        })
    })
}

/// A failed closing entry (security review N1): on disk now (its flush failed) is
/// [`ExecError::Unconfirmed`]; not on disk, nothing was written: a refusal.
fn closing_failed(j: &Journal<'_>, t: &TxnId, e: JournalError) -> ExecError {
    if closed_now(j, t) {
        ExecError::Unconfirmed(e)
    } else {
        Refusal::from(e).into()
    }
}

/// Reverts transaction `t` (module docs): also the recovery of an interrupted apply. Every
/// error before this run's first record is an [`ExecError::Refused`] (review S4: nothing
/// changed); a `Closed` that may be on disk is [`ExecError::Unconfirmed`]; any other error
/// came after a record of this run.
pub fn revert(cx: &ExecCtx<'_>, t: &TxnId) -> Result<RevertReport, ExecError> {
    revert_seen(cx, t, &|_| true)
}

/// What a front end's preview is compared with under the lock (ADR 0027 amendment P5-2b): right
/// after the lock is taken, and for a rebind also the observation with the new binding before
/// its record.
pub(crate) enum Look<'a> {
    /// The lock is held; nothing read yet.
    Early,
    /// A rebind's checks under the lock passed: what its ops observe with the new binding.
    Rebound(&'a Verified),
}

/// Whether what is seen under the lock is what the preview showed (`false`:
/// [`Refusal::Changed`], nothing written).
pub(crate) type Same<'a> = &'a dyn Fn(Look<'_>) -> bool;

/// [`revert`] with the preview compared under the lock first (`same`, [`Look::Early`]).
pub(crate) fn revert_seen(
    cx: &ExecCtx<'_>,
    t: &TxnId,
    same: Same<'_>,
) -> Result<RevertReport, ExecError> {
    standard_user(cx.sys)?;
    let j = Journal::new(cx.app, cx.tag);
    let lock = j.lock().map_err(Refusal::from)?;
    if !same(Look::Early) {
        return Err(Refusal::Changed { txn: *t }.into());
    }
    let listing = j.list().map_err(Refusal::from)?;
    revert_listed(&listing, t)?;
    let w = lock.resume(t).map_err(Refusal::from)?;
    let before = |k: u16, _: &crate::journal::Digest, max: u64| w.before_bytes(k, max);
    let (plan, b) = revert_plan(t, w.head(), w.ops(), w.rebinds(), &before)?;
    let stores = roots::open_stores(cx, &b);
    let (roots, shares) = revert_roots(
        cx,
        &plan,
        &b,
        &j,
        &listing,
        t,
        w.ops(),
        &stores,
        !w.rebinds().is_empty(),
    )?;
    let plan = knob_rewrite_head(&plan, &b).unwrap_or(plan);
    revert_run(cx, &j, t, &plan, w, &roots, true, shares)
}

/// The revert loop of [`revert`] and [`revert_rebound`] and the close. `early`: no record of
/// this run is written yet, so an error before the loop's first record is a refusal (review S4).
#[expect(
    clippy::too_many_arguments,
    reason = "the revert loop's context and what it hands over"
)]
fn revert_run<W: Reverting>(
    cx: &ExecCtx<'_>,
    j: &Journal<'_>,
    t: &TxnId,
    plan: &Plan,
    mut w: W,
    roots: &roots::Roots<'_>,
    early: bool,
    shares: Shares,
) -> Result<RevertReport, ExecError> {
    let mut touched = Touched::new(cx.sys, roots).of(*t);
    touched.shares = shares;
    let written = revert_records(w.ops());
    let (ops, halted) = match revert_loop(
        cx,
        plan,
        &mut w,
        &mut touched,
        roots,
        Mode::Recovery,
        &BTreeMap::new(),
    ) {
        Ok(x) => x,
        Err(e) if early && revert_records(w.ops()) == written => {
            return Err(refused_early(e).into());
        }
        Err(e) => return Err(e),
    };
    let profiles_moved = roots.profiles_moved().cloned();
    if halted.is_some() || !foreign_ops(&w).is_empty() {
        return Ok(RevertReport {
            txn: *t,
            closed: None,
            ops,
            halted,
            cleanup: Vec::new(),
            profiles_moved,
        });
    }
    // P2-15: the cleanup pass; a deletion is a change of this run (senior-dev B2), so an error
    // after one is never a refusal.
    let mut deleted = false;
    let logs = w.ops().clone();
    let cleaned = cleanup_pass(
        plan,
        &mut touched,
        roots,
        &logs,
        Mode::Recovery,
        &mut deleted,
    );
    let (cleanup, halted) = match cleaned {
        Ok(x) => x,
        Err(e) if early && !deleted && revert_records(w.ops()) == written => {
            return Err(refused_early(e).into());
        }
        Err(e) => return Err(e),
    };
    drop(touched);
    let open = cleanup.iter().any(|p| p.seen.holds_open()) && !knob_close_despite_cleanup();
    if halted.is_some() || open {
        return Ok(RevertReport {
            txn: *t,
            closed: None,
            ops,
            halted,
            cleanup,
            profiles_moved,
        });
    }
    let how = if w.is_applied() {
        Closing::Reverted
    } else {
        Closing::RolledBack
    };
    // Nothing reverted or deleted in this run (every op was before): a `Closed` that did not
    // reach the journal wrote nothing at all.
    let first = early && ops.is_empty() && !deleted;
    if let Err(e) = close(w) {
        return Err(match e {
            ExecError::Journal(e) if closed_now(j, t) => ExecError::Unconfirmed(e),
            ExecError::Journal(e) if first => Refusal::from(e).into(),
            e => e,
        });
    }
    Ok(RevertReport {
        txn: *t,
        closed: Some(how),
        ops,
        halted: None,
        cleanup,
        profiles_moved,
    })
}

/// What each intended op of `t` observes now, newest first and halting where a revert would
/// (read only; an existing `journal\lock` is held read side meanwhile, so no apply, revert or
/// forget runs while it observes: P2-13, review S2).
pub fn verify(cx: &ExecCtx<'_>, t: &TxnId) -> Result<Verified, ExecError> {
    let j = Journal::new(cx.app, cx.tag);
    let _hold = j.hold().map_err(Refusal::from)?;
    verify_in(cx, &j, t)
}

/// [`verify`] without holding the lock file: for a caller that holds the lock already (the
/// comparison with a preview under the lock, ADR 0027 amendment P5-2b).
pub(crate) fn verify_in(
    cx: &ExecCtx<'_>,
    j: &Journal<'_>,
    t: &TxnId,
) -> Result<Verified, ExecError> {
    let v = j.load(t, crate::journal::VerifyBackups::Length)?;
    let blocked = || ExecError::Refused(Refusal::Blocked { txn: *t });
    if !v.head_usable() {
        return Err(blocked());
    }
    let plan = decode_head(v.head.as_deref().unwrap_or_default()).map_err(|_| blocked())?;
    if !records_fit(&plan, &v.ops) {
        return Err(blocked());
    }
    let before = |k: u16, d: &crate::journal::Digest, max: u64| j.read_backup(t, k, d, max);
    if !ini::binds(&plan, &v.ops, &before)? {
        return Err(blocked());
    }
    let b = Bindings::of(&plan, &v.rebinds).ok_or_else(blocked)?;
    let stores = roots::open_stores(cx, &b);
    let roots = roots::Roots::each(cx, &b, &stores)?;
    let mut touched = Touched::new(cx.sys, &roots).of(*t);
    // P4-8b (rule 5): what the revert would hand over and inherit now (a refusal of the revert
    // shows the plain observation; `revert_check` names it).
    touched.shares = verify_shares(j, t, &plan, &b, &v);
    let mut out = verify_ops(&plan, &mut touched, &roots, &v.ops)?;
    // P2-15 (rule 5): what the cleanup pass of a revert would find now, unless it halts first.
    if out.halted.is_none() {
        let (cleanup, halted) = cleanup_pass(
            &plan,
            &mut touched,
            &roots,
            &v.ops,
            Mode::Verify,
            &mut false,
        )?;
        out.cleanup = cleanup;
        out.halted = halted;
    }
    // P3-7: read only, never an error of `verify`.
    let paths: Vec<_> = b.iter().map(|r| &r.path).collect();
    out.virtual_store = crate::policy::root::shadows(cx.sys, &plan, &paths);
    Ok(out)
}

/// The hand-over of `verify` (P4-8b): the derivation of a revert, read only, without its
/// refusals.
fn verify_shares(
    j: &Journal<'_>,
    t: &TxnId,
    plan: &Plan,
    b: &Bindings,
    v: &crate::journal::TxnView,
) -> Shares {
    let Ok(listing) = j.list() else {
        return Shares::default();
    };
    let rebound = !v.rebinds.is_empty();
    let keeps = b
        .objects_by_op(plan)
        .ok()
        .and_then(|by_op| {
            let objects: Vec<Object> = by_op.iter().map(|(_, o)| o.clone()).collect();
            let me = stack::Me {
                plan,
                objs: &by_op,
                rebound,
            };
            stack::for_revert(j, &listing, t, &objects, Some(&me)).ok()
        })
        .unwrap_or_default();
    let inherit = if !matches!(v.state, TxnState::Closed(_))
        && !rebound
        && share::may_inherit(plan, &v.ops)
    {
        share::read(j, &listing, Some(t), true)
            .ok()
            .and_then(|o| share::duties(&o, t, plan, &v.ops).ok())
            .unwrap_or_default()
    } else {
        share::Inherit::default()
    };
    Shares { keeps, inherit }
}

/// Forgets transaction `t` (module docs). Backups stay. Every error before its record or
/// marker is a refusal; a record or marker that reached the journal but whose flush failed is
/// [`ExecError::Unconfirmed`] (security review N1).
pub fn forget(cx: &ExecCtx<'_>, t: &TxnId) -> Result<(), ExecError> {
    forget_seen(cx, t, &|_| true)
}

/// [`forget`] with the preview compared under the lock first (`same`, [`Look::Early`]), before
/// anything is written.
pub(crate) fn forget_seen(cx: &ExecCtx<'_>, t: &TxnId, same: Same<'_>) -> Result<(), ExecError> {
    standard_user(cx.sys)?;
    let j = Journal::new(cx.app, cx.tag);
    let lock = j.lock().map_err(Refusal::from)?;
    if !same(Look::Early) {
        return Err(Refusal::Changed { txn: *t }.into());
    }
    // P4-2d review follow-up (security L2): no request file stays for a late helper to find.
    helper::sweep_leftovers(cx);
    let listing = j.list().map_err(Refusal::from)?;
    let l = listing
        .txns
        .iter()
        .find(|l| l.id == *t)
        .ok_or_else(|| Refusal::from(JournalError::NotFound(*t)))?;
    if l.forgotten {
        return Ok(());
    }
    let head = match &l.view {
        Ok(v) => match v.state {
            TxnState::Closed(_) => {
                return Err(Refusal::from(JournalError::NotResumable {
                    id: *t,
                    state: v.state.clone(),
                })
                .into());
            }
            TxnState::Empty | TxnState::Open | TxnState::Applied => {
                match lock.resume(t) {
                    Ok(w) => {
                        return w
                            .close(Closing::Forgotten)
                            .map_err(|e| closing_failed(&j, t, e));
                    }
                    // Damaged since the listing: the marker below.
                    Err(JournalError::NotResumable { .. }) => v.head_sha256,
                    Err(e) => return Err(Refusal::from(e).into()),
                }
            }
            TxnState::Damaged(_) => v.head_sha256,
        },
        Err(_) => None,
    };
    lock.forget_marker(t, head.as_ref())
        .map_err(|e| closing_failed(&j, t, e))
}

#[cfg(test)]
mod cleanup_crash_tests;
#[cfg(test)]
pub(crate) mod cleanup_tests;
#[cfg(test)]
mod combo_tests;
#[cfg(test)]
mod crash_tests;
#[cfg(test)]
mod front_tests;
#[cfg(test)]
mod fw_crash_tests;
#[cfg(test)]
pub(crate) mod fw_tests;
#[cfg(test)]
mod gpu_pref_crash_tests;
#[cfg(test)]
pub(crate) mod gpu_pref_tests;
#[cfg(test)]
mod halt_tests;
#[cfg(test)]
mod handover_crash_tests;
#[cfg(test)]
mod handover_tests;
#[cfg(test)]
mod hold_tests;
#[cfg(test)]
mod ini_crash_tests;
#[cfg(test)]
pub(crate) mod ini_tests;
#[cfg(test)]
mod layer_crash_tests;
#[cfg(test)]
pub(crate) mod layer_tests;
#[cfg(test)]
mod patch_tests;
#[cfg(test)]
mod profiles_crash_tests;
#[cfg(test)]
mod profiles_tests;
#[cfg(test)]
mod rebind_crash_tests;
#[cfg(test)]
pub(crate) mod rebind_tests;
#[cfg(test)]
mod reg_crash_tests;
#[cfg(test)]
pub(crate) mod reg_tests;
#[cfg(test)]
pub(crate) mod tests;
#[cfg(test)]
pub(crate) mod user_data_tests;
