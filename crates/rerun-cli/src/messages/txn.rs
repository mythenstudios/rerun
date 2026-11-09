//! The messages of the phase 2 commands (`plan`, `apply`, `revert`, `status`, `forget`;
//! P2-13, ADR 0016 amendment "phase 2 commands"). One [`TxnMsg`] is one line. Static text is
//! ASCII; untrusted fields are [`Shown`] and stand last on their line. Registry text appears
//! only in the plan preview (ADR 0016 amendment P2-10b); a recorded head comes masked from the
//! core (`plan::preview_head`).

use std::fmt;

use rerun_core::escape::Shown;
use rerun_core::journal::{Closing, Observed, TxnId};
use rerun_core::plan::{IniOldShown, PlanHash, RegShown};
use rerun_core::policy::ini::KeyState;
use rerun_core::policy::root::RootId;

use super::Count;

fn changes(n: usize) -> Count<'static> {
    Count(n, "change", "changes")
}

/// Where an op acts, as shown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum At<'a> {
    /// A path below a root.
    File {
        /// Root index.
        root: usize,
        /// The path.
        path: Shown<'a>,
    },
    /// A registry key.
    Reg {
        /// `HKCU\…`.
        key: Shown<'a>,
    },
}

/// An op as shown: what it does and where.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpRef<'a> {
    /// `create file`, `set value`, … (Rerun's words).
    pub action: &'static str,
    /// Where.
    pub at: At<'a>,
}

impl fmt::Display for OpRef<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.at {
            At::File { root, path } => write!(f, "{} in root {root}: {path}", self.action),
            At::Reg { key } => write!(f, "{}: {key}", self.action),
        }
    }
}

/// The state of a transaction as shown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TxnText<'a> {
    /// Only its head.
    Empty,
    /// Neither applied nor closed.
    Open,
    /// Applied.
    Applied,
    /// Applied, and a revert began and did not finish.
    Reverting,
    /// Every op reverted, but a file Rerun replaced is still left (P2-15).
    CleanupPending,
    /// Closed.
    Closed(Closing),
    /// Damaged (the reason, escaped).
    Damaged(Shown<'a>),
    /// Its folder cannot be read (the error, escaped).
    Unreadable(Shown<'a>),
}

fn closing(c: Closing) -> &'static str {
    match c {
        Closing::Reverted => "reverted",
        Closing::RolledBack => "rolled back",
        Closing::Forgotten => "forgotten",
    }
}

impl fmt::Display for TxnText<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("empty (it changed nothing)"),
            Self::Open => f.write_str("open (in progress or interrupted)"),
            Self::Applied => f.write_str("applied"),
            Self::Reverting => f.write_str("applied; a revert began and did not finish"),
            Self::CleanupPending => f.write_str("everything reverted, only cleanup pending"),
            Self::Closed(c) => f.write_str(closing(*c)),
            Self::Damaged(why) => write!(f, "damaged: {why}"),
            Self::Unreadable(why) => write!(f, "unreadable: {why}"),
        }
    }
}

/// The state of an op as recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpText {
    /// Intent only.
    Interrupted,
    /// Applied.
    Applied,
    /// A revert began.
    RevertInterrupted,
    /// Reverted with this observation.
    Reverted(Observed),
}

impl fmt::Display for OpText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Interrupted => "interrupted while it was applied",
            Self::Applied => "applied",
            Self::RevertInterrupted => "revert interrupted",
            Self::Reverted(Observed::Before | Observed::After) => "reverted",
            Self::Reverted(Observed::Drifted) => "reverted (Rerun's part)",
            Self::Reverted(Observed::Foreign) => "left as found (changed by someone else)",
        })
    }
}

/// What a revert does with an op, as `verify` sees it now.
fn will(o: Observed) -> &'static str {
    match o {
        Observed::After => "will be undone",
        Observed::Before => "nothing to do (as before)",
        Observed::Drifted => "Rerun's part will be set back, the rest stays",
        Observed::Foreign => "left as it is (changed by someone else); the transaction stays open",
    }
}

/// What a revert did with an op.
fn did(o: Observed) -> &'static str {
    match o {
        Observed::After => "undone",
        Observed::Before => "was already as before",
        Observed::Drifted => "Rerun's part set back, the rest stays",
        Observed::Foreign => "left as found (changed by someone else)",
    }
}

/// A key of an INI op in `verify` or the report.
fn key_state(s: KeyState) -> &'static str {
    match s {
        KeyState::New => "holds Rerun's value",
        KeyState::Old => "as before",
        KeyState::Changed => "changed since; stays as it is",
    }
}

/// The step a `.old` holds the file before.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepText {
    /// The apply.
    Apply,
    /// A restore.
    Restore,
    /// A rewrite.
    Rewrite,
}

impl fmt::Display for StepText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Apply => "apply",
            Self::Restore => "restore",
            Self::Rewrite => "rewrite",
        })
    }
}

/// One line of the phase 2 commands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TxnMsg<'a> {
    // ---------- the preview of a plan ----------
    /// A root.
    Root {
        /// Index.
        index: usize,
        /// Canonical path.
        path: Shown<'a>,
    },
    /// The Steam app of the root above.
    RootSteam {
        /// App ID.
        app_id: u32,
        /// The library.
        library: Shown<'a>,
    },
    /// The main executable of the root above.
    RootMainExe {
        /// Relative to the root.
        path: Shown<'a>,
    },
    /// An op.
    Op {
        /// Index.
        index: usize,
        /// What and where.
        op: OpRef<'a>,
    },
    /// The value name of the registry op above, in a transaction (one level deeper).
    OpValue {
        /// The name.
        name: Shown<'a>,
    },
    /// The value name of the registry op above.
    ValueName {
        /// The name (`(default)` for the default value).
        name: Shown<'a>,
    },
    /// The package source of the file op above.
    Source {
        /// `<package> <version>: <file>`.
        source: Shown<'a>,
    },
    /// The new content of the file op above.
    NewContent {
        /// SHA-256, hex.
        sha256: &'a str,
        /// Length.
        len: u64,
        /// R/H/S letters.
        attrs: Option<&'a str>,
    },
    /// The old content of the file op above.
    OldContent {
        /// SHA-256, hex.
        sha256: &'a str,
        /// Length.
        len: u64,
        /// R/H/S letters.
        attrs: &'a str,
    },
    /// The tokens an `add tokens` op adds.
    Tokens {
        /// The tokens.
        tokens: Shown<'a>,
    },
    /// The "all users" (`HKLM`) value of the executable of an `add tokens` op (P3-6), which
    /// Rerun does not change.
    MachineValue {
        /// `64-bit view`, `32-bit view`.
        view: &'a str,
        /// The value.
        value: &'a RegShown,
    },
    /// The old value of a registry op.
    OldValue(&'a RegShown),
    /// The new value of a registry op.
    NewValue(&'a RegShown),
    /// The registry op above changes the value's type.
    TypeChange,
    /// A key of an `edit ini` op.
    IniKey {
        /// The section.
        section: Shown<'a>,
        /// The key.
        key: Shown<'a>,
    },
    /// The old value of the key above.
    IniOld(&'a IniOldShown),
    /// The new value of the key above.
    IniNew {
        /// The value.
        value: Shown<'a>,
    },
    /// The file op above installs a configuration file.
    Config,
    /// A note of the preview.
    Note(&'static str),
    /// P3-7: a UAC VirtualStore copy of a managed file of root `root` (preview and `verify`).
    VirtualStoreCopy {
        /// Root index.
        root: usize,
        /// The copy's full path, escaped.
        copy: Shown<'a>,
    },
    /// P3-7: a link (junction, symbolic link) on the way to a VirtualStore copy: not followed.
    VirtualStoreLink {
        /// Root index.
        root: usize,
        /// The path looked up, escaped.
        at: Shown<'a>,
    },
    /// P3-7: the VirtualStore lookup could not run for root `root`.
    VirtualStoreUnchecked {
        /// Root index.
        root: usize,
        /// Why, escaped as text (without the path).
        why: Shown<'a>,
        /// The path the reason is about, if any, escaped as a path; shown last.
        at: Option<Shown<'a>>,
    },

    // ---------- plan ----------
    /// The plan has no ops.
    NothingToDo,
    /// Stored.
    PlanStored {
        /// Its hash.
        hash: PlanHash,
        /// Ops.
        ops: usize,
    },
    /// Shown only.
    PlanDryRun {
        /// Its hash.
        hash: PlanHash,
        /// Ops.
        ops: usize,
    },
    /// How to apply it.
    ApplyWith {
        /// Its hash.
        hash: PlanHash,
    },

    // ---------- apply ----------
    /// The head of the apply preview.
    PlanHead {
        /// Its hash.
        hash: PlanHash,
        /// Ops.
        ops: usize,
    },
    /// `apply --dry-run` found nothing to refuse.
    ChecksPassed,
    /// The question.
    AskApply {
        /// Ops.
        ops: usize,
    },
    /// The user said no.
    NothingDone,
    /// Applied.
    Applied {
        /// The transaction.
        txn: TxnId,
    },
    /// How to revert it.
    RevertWith {
        /// The transaction.
        txn: TxnId,
    },
    /// The apply failed and was rolled back.
    RolledBack {
        /// The transaction.
        txn: TxnId,
    },
    /// The apply failed and its rollback did not finish.
    LeftOpen {
        /// The transaction.
        txn: TxnId,
    },
    /// Why the apply failed.
    Cause {
        /// The error, escaped.
        error: Shown<'a>,
    },
    /// Why the rollback did not finish.
    RollbackCause {
        /// The error, escaped.
        error: Shown<'a>,
    },
    /// The apply failed and was rolled back, but a file Rerun replaced is still in use (P2-15).
    RolledBackCleanup {
        /// The transaction.
        txn: TxnId,
    },
    /// What finishes a transaction whose cleanup is pending because a file is in use (P2-15).
    FinishCleanup {
        /// The transaction.
        txn: TxnId,
    },
    /// What finishes a transaction whose copy is kept next to a file that changed (P2-15).
    FinishKept {
        /// The transaction.
        txn: TxnId,
    },
    /// The journal of a transaction has no room for another revert attempt (P2-15, N1).
    JournalFull {
        /// The transaction.
        txn: TxnId,
    },
    /// What finishes a transaction left open.
    FinishWithRevert {
        /// The transaction.
        txn: TxnId,
    },
    /// A transaction left open with changes left as found: forget closes it.
    FinishWithForget {
        /// The transaction.
        txn: TxnId,
    },

    // ---------- status ----------
    /// No journal or no transaction.
    NoTransactions,
    /// A transaction and its state.
    Txn {
        /// The transaction.
        txn: TxnId,
        /// Its state.
        state: TxnText<'a>,
    },
    /// The plan of the transaction above cannot be shown.
    HeadUnreadable {
        /// Why, escaped.
        why: Shown<'a>,
    },
    /// An op of the transaction above, with its recorded state.
    TxnOp {
        /// Index.
        op: u16,
        /// Its state.
        state: OpText,
        /// What and where (`None` without a readable head).
        at: Option<OpRef<'a>>,
    },
    /// The backup file of the op above.
    BackupFile {
        /// The file, escaped.
        path: Shown<'a>,
        /// Its length.
        len: u64,
    },
    /// The old state of the op above is in its record.
    BackupInline,
    /// A `.old` the op above left.
    Cleanup {
        /// Relative to the op's root, escaped.
        path: Shown<'a>,
    },
    /// A `.old` a forgotten transaction may have left (P2-15: from the records, not observed).
    MayRemain {
        /// Relative to the op's root, escaped.
        path: Shown<'a>,
    },
    /// Where the backups of a forgotten transaction stay.
    BackupsIn {
        /// The transaction folder, escaped.
        folder: Shown<'a>,
    },
    /// How to revert the transaction above.
    HintRevert {
        /// The transaction.
        txn: TxnId,
    },
    /// The transaction above blocks every apply; only forget closes it.
    HintForgetOnly {
        /// The transaction.
        txn: TxnId,
    },
    /// The transaction above has changes left as found; forget closes it.
    HintForgetForeign {
        /// The transaction.
        txn: TxnId,
    },
    /// Everything of the transaction above is reverted; only its cleanup is pending (P2-15).
    HintCleanup {
        /// The transaction.
        txn: TxnId,
    },
    /// Entries of `journal\` that are not Rerun's.
    ForeignEntries {
        /// How many.
        n: usize,
    },
    /// The counts.
    StatusCounts {
        /// Not closed.
        open: usize,
        /// Closed, or empty.
        closed: usize,
        /// Forgotten.
        forgotten: usize,
        /// Closed ones listed (`--all`).
        all: bool,
    },
    /// Where to see what is on disk now.
    StatusNote,

    // ---------- revert and forget ----------
    /// The heading of what `verify` sees now.
    NowHeading,
    /// One op as `verify` sees it now.
    Will {
        /// Index.
        op: u16,
        /// What it observes.
        observed: Observed,
        /// What and where (`None` without a readable head).
        at: Option<OpRef<'a>>,
    },
    /// One key of an INI op.
    KeyState {
        /// Its state.
        state: KeyState,
        /// The section.
        section: Shown<'a>,
        /// The key.
        key: Shown<'a>,
    },
    /// A `.old` next to a foreign INI file that holds it before a step of Rerun.
    BeforeStep {
        /// The step.
        step: StepText,
        /// The file, relative to the INI file's folder, escaped.
        file: Shown<'a>,
    },
    /// A `.old` of Rerun's the revert deletes (P2-15, rule 5): its known content.
    WillDelete {
        /// SHA-256 of Rerun's content, hex.
        sha256: String,
        /// Relative to the op's root, escaped.
        path: Shown<'a>,
    },
    /// A `.old` of Rerun's still in use: it stays, and so does the transaction (P2-15).
    OldInUse {
        /// Relative to the op's root, escaped.
        path: Shown<'a>,
    },
    /// A `.old` of Rerun's next to a file that changed since the revert: kept (P2-15).
    OldKept {
        /// Relative to the op's root, escaped.
        path: Shown<'a>,
    },
    /// Something at the name of a `.old` that is not Rerun's: left as it is (P2-15, E-C4).
    OldForeign {
        /// Relative to the op's root, escaped.
        path: Shown<'a>,
    },
    /// A `.old` of Rerun's the revert deleted (P2-15).
    OldDeleted {
        /// Relative to the op's root, escaped.
        path: Shown<'a>,
    },
    /// Where the revert halts.
    Halted {
        /// Index.
        op: u16,
        /// Why, escaped.
        why: Shown<'a>,
    },
    /// What is on disk cannot be observed now.
    CannotObserve {
        /// Why, escaped.
        error: Shown<'a>,
    },
    /// A dry run ended.
    DryRunDone,
    /// The question.
    AskRevert {
        /// Ops to act on.
        ops: usize,
    },
    /// The question of a revert that only cleans up (P2-15).
    AskCleanup {
        /// Files to delete (Rerun's copies, also those in use now).
        n: usize,
        /// Of them, in use now (they may stay).
        in_use: usize,
    },
    /// One op of the revert's report.
    Did {
        /// Index.
        op: u16,
        /// What it observed.
        observed: Observed,
        /// It observed otherwise than the preview showed.
        changed: bool,
    },
    /// A name the revert left in the op's folder.
    Left {
        /// The name, escaped.
        path: Shown<'a>,
    },
    /// Reverted and closed.
    Reverted {
        /// The transaction.
        txn: TxnId,
    },
    /// Closed before.
    AlreadyClosed {
        /// The transaction.
        txn: TxnId,
        /// How.
        how: Closing,
    },
    /// Empty without a readable head: nothing to revert.
    NothingToRevert {
        /// The transaction.
        txn: TxnId,
    },
    /// The revert halted; the transaction stays open.
    StaysOpenHalted {
        /// The transaction.
        txn: TxnId,
    },
    /// The revert met foreign states; the transaction stays open.
    StaysOpenForeign {
        /// The transaction.
        txn: TxnId,
    },
    /// Reverted, but files Rerun replaced are still in use; the transaction stays open (P2-15).
    StaysOpenInUse {
        /// The transaction.
        txn: TxnId,
        /// How many.
        n: usize,
    },
    /// Reverted, but a file Rerun replaced is kept next to a file that changed (P2-15).
    StaysOpenKept {
        /// The transaction.
        txn: TxnId,
    },
    /// The revert failed after it wrote.
    RevertFailed {
        /// The transaction.
        txn: TxnId,
    },
    /// What forget does and does not do (three fixed lines).
    ForgetChangesNothing,
    /// What forget does not revert.
    ForgetStays,
    /// Forget of a transaction whose cleanup is pending (P2-15, senior-dev S3).
    ForgetOnlyCleanup,
    /// What forget does not delete.
    ForgetKeeps,
    /// An applied transaction: every change stays.
    AllStay {
        /// Ops.
        ops: usize,
    },
    /// A revert would finish cleanly.
    RevertIsClean {
        /// The transaction.
        txn: TxnId,
    },
    /// The question.
    AskForget {
        /// The transaction.
        txn: TxnId,
    },
    /// Forgotten now.
    Forgot {
        /// The transaction.
        txn: TxnId,
    },
    /// Forgotten before.
    AlreadyForgotten {
        /// The transaction.
        txn: TxnId,
    },

    // ---------- errors (stderr) ----------
    /// A refusal or another error that changed nothing, escaped.
    Error {
        /// The error.
        error: Shown<'a>,
    },
    /// No console to ask.
    NoConsole,
    /// Rerun's folder does not exist yet.
    NoAppDir,
    /// Rerun's folder is at another path than when the plan was made (P3-3d).
    AppDirMoved,
    /// Rerun's folder cannot be opened.
    AppDir {
        /// The error.
        error: Shown<'a>,
    },
    /// The journal cannot be read.
    JournalUnreadable {
        /// The error.
        error: Shown<'a>,
    },
    /// The step file cannot be read.
    StepFile {
        /// The error.
        error: Shown<'a>,
    },
    /// The steps cannot be planned.
    PlanFailed {
        /// The error.
        error: Shown<'a>,
    },
    /// The game folder of the step file cannot be found or opened.
    GameFolder {
        /// The error.
        error: Shown<'a>,
    },
    /// The Steam app of the step file.
    SteamApp {
        /// The app.
        app_id: u32,
        /// What is wrong.
        why: SteamWhy,
    },
    /// The plan cannot be stored.
    StoreFailed {
        /// The error.
        error: Shown<'a>,
    },
    /// The game folder is another folder now.
    IdentityHint {
        /// The transaction.
        txn: TxnId,
    },
    /// An empty transaction with a readable head: the revert only closes it.
    EmptyCloses {
        /// The transaction.
        txn: TxnId,
    },
    /// Closing may have reached the journal although it failed.
    MayHaveClosed {
        /// The transaction.
        txn: TxnId,
    },
    /// Closed transactions have nothing to forget.
    NothingToForget {
        /// The transaction.
        txn: TxnId,
        /// How it was closed.
        how: Closing,
    },

    // ---------- revert --rebind (P2-14b) ----------
    /// The rebind block of a preview.
    RebindHeading {
        /// Root index.
        root: u16,
    },
    /// The folder the root is bound to now.
    RebindNow {
        /// Its identity.
        id: RootId,
        /// Its path, escaped.
        path: Shown<'a>,
    },
    /// The library of the line above.
    RebindLibrary {
        /// The library, escaped.
        library: Shown<'a>,
    },
    /// Why the folder bound now does not open.
    RebindWhy {
        /// The reason, escaped.
        why: Shown<'a>,
    },
    /// The folder the rebind binds the root to.
    RebindTo {
        /// Its identity.
        id: RootId,
        /// Its path, escaped.
        path: Shown<'a>,
    },
    /// A folder the plan created, found in the new folder: bound by the file ID found.
    CreatedFound {
        /// Its path, escaped.
        path: Shown<'a>,
    },
    /// A folder the plan created, missing in the new folder.
    CreatedMissing {
        /// Its path, escaped.
        path: Shown<'a>,
    },
    /// Heading of what the revert does in the new folder.
    RebindNowHeading,
    /// Registry ops stay where Rerun wrote them.
    RebindRegistryNote,
    /// Only the bound folder is reverted (ADR 0020 table X9).
    RebindScopeNote,
    /// A binding is permanent.
    RebindPermanentNote,
    /// The question of a rebind.
    AskRebind {
        /// The transaction.
        txn: TxnId,
        /// Ops the revert observes.
        ops: usize,
    },
    /// A rebind needs the question.
    RebindNeedsConsole,
    /// The transaction is bound already: the revert runs as it is.
    AlreadyBound {
        /// The bound folder, escaped.
        path: Shown<'a>,
    },
    /// A rebind may have reached the journal although it failed.
    MayBeBound {
        /// The transaction.
        txn: TxnId,
    },
    /// A revert halted at a Steam root that is gone: a rebind may bind it.
    HaltRebindHint {
        /// The transaction.
        txn: TxnId,
    },
    /// A rebind is recorded, then the revert failed: the transaction is bound now.
    BoundNow {
        /// The transaction.
        txn: TxnId,
    },
    /// A rebind is recorded and the revert ran, but its closing may not be durable.
    BoundMayHaveClosed {
        /// The transaction.
        txn: TxnId,
    },
    /// What `root <i>` means below the rebind: the folder Steam lists now.
    RebindRootIs {
        /// Root index.
        root: u16,
        /// The folder, escaped.
        path: Shown<'a>,
    },
    /// A rebind of a transaction (`status`).
    StatusRebind {
        /// Root index.
        root: u16,
        /// The identity bound.
        id: RootId,
        /// The game folder bound (or the library), escaped.
        path: Shown<'a>,
    },
}

/// What is wrong with the Steam app of a step file.
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

impl fmt::Display for SteamWhy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NoSteam => "cannot be looked up: Steam was not found",
            Self::NotListed => "is in no Steam library",
            Self::Twice => "is listed by more than one Steam library; nothing is guessed",
            Self::Updating => "is being updated by Steam; try again when Steam has finished",
            Self::NotInstalled => "is not installed",
        })
    }
}

impl fmt::Display for TxnMsg<'_> {
    #[expect(
        clippy::too_many_lines,
        reason = "one arm per line of the phase 2 commands"
    )]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Root { index, path } => write!(f, "root {index}: {path}"),
            Self::RootSteam { app_id, library } => {
                write!(f, "  Steam app {app_id}, library: {library}")
            }
            Self::RootMainExe { path } => write!(f, "  main executable: {path}"),
            Self::Op { index, op } => write!(f, "op {index}: {op}"),
            Self::ValueName { name } => write!(f, "  value: {name}"),
            Self::OpValue { name } => write!(f, "    value: {name}"),
            Self::Source { source } => write!(f, "  from package: {source}"),
            Self::NewContent {
                sha256,
                len,
                attrs,
            } => {
                write!(f, "  new: sha256 {sha256}, {len} bytes")?;
                match attrs {
                    Some(a) => write!(f, ", attributes {a}"),
                    None => Ok(()),
                }
            }
            Self::OldContent {
                sha256,
                len,
                attrs,
            } => write!(f, "  old: sha256 {sha256}, {len} bytes, attributes {attrs}"),
            Self::Tokens { tokens } => write!(f, "  adds tokens: {tokens}"),
            Self::MachineValue { view, value } => {
                write!(f, "  all users (HKLM, {view}), not changed: {value}")
            }
            Self::OldValue(v) => write!(f, "  old value: {v}"),
            Self::NewValue(v) => write!(f, "  new value: {v}"),
            Self::TypeChange => f.write_str("  the type of the value changes"),
            Self::IniKey { section, key } => write!(f, "  key [{section}] {key}"),
            Self::IniOld(old) => write!(f, "    old: {old}"),
            Self::IniNew { value } => write!(f, "    new: {value}"),
            Self::Config => {
                f.write_str("  configuration file: once edited, a revert leaves it as it is")
            }
            Self::Note(text) => write!(f, "note: {text}"),
            Self::VirtualStoreCopy { root, copy } => write!(
                f,
                "warning: root {root}: Windows keeps a VirtualStore copy of a managed file; the game probably reads this copy, not the managed file: {copy}"
            ),
            Self::VirtualStoreLink { root, at } => write!(
                f,
                "note: root {root}: a link (junction or symbolic link) lies on the way to a VirtualStore copy; it is not followed, nothing behind it was checked: {at}"
            ),
            Self::VirtualStoreUnchecked { root, why, at } => {
                write!(
                    f,
                    "note: root {root}: VirtualStore copies of the managed files were not checked: {why}"
                )?;
                match at {
                    Some(at) => write!(f, ": {at}"),
                    None => Ok(()),
                }
            }

            Self::NothingToDo => {
                f.write_str("nothing to do: everything already is as the steps want it")
            }
            Self::PlanStored { hash, ops } => write!(f, "plan {hash} stored: {}", changes(*ops)),
            Self::PlanDryRun { hash, ops } => write!(
                f,
                "plan {hash} (dry run, not stored): {}",
                changes(*ops)
            ),
            Self::ApplyWith { hash } => write!(f, "apply with: rerun apply {hash}"),

            Self::PlanHead { hash, ops } => write!(f, "plan {hash}: {}", changes(*ops)),
            Self::ChecksPassed => {
                f.write_str("dry run: every check passed; nothing was written")
            }
            Self::AskApply { ops: 1 } => f.write_str("Apply this change? [y/N]"),
            Self::AskApply { ops } => write!(f, "Apply these {ops} changes? [y/N]"),
            Self::NothingDone => f.write_str("nothing done"),
            Self::Applied { txn } => write!(f, "applied as transaction {txn}"),
            Self::RevertWith { txn } => write!(f, "revert with: rerun revert {txn}"),
            Self::RolledBack { txn } => write!(
                f,
                "the apply failed and was rolled back; nothing changed (transaction {txn})"
            ),
            Self::LeftOpen { txn } => write!(
                f,
                "the apply failed and its rollback did not finish: transaction {txn} stays open"
            ),
            Self::Cause { error } => write!(f, "  cause: {error}"),
            Self::RollbackCause { error } => write!(f, "  rollback: {error}"),
            Self::RolledBackCleanup { txn } => write!(
                f,
                "the apply failed and was rolled back, but a file Rerun left is still there: \
                 transaction {txn} stays open until it is deleted"
            ),
            Self::FinishKept { txn } => write!(
                f,
                "a file next to Rerun's copy changed since, so the copy stays; delete it yourself \
                 and run rerun revert {txn}, or rerun forget {txn}"
            ),
            Self::JournalFull { txn } => write!(
                f,
                "the journal of transaction {txn} has no room for another revert attempt; only \
                 rerun forget {txn} closes it (backups stay)"
            ),
            Self::FinishCleanup { txn } => write!(
                f,
                "close the game and any window showing its folder, then run: rerun revert {txn}"
            ),
            Self::FinishWithRevert { txn } => write!(
                f,
                "rerun status shows it; rerun revert {txn} finishes it"
            ),
            Self::FinishWithForget { txn } => write!(
                f,
                "changes were left as found; rerun forget {txn} closes it (backups stay)"
            ),

            Self::NoTransactions => f.write_str("no transactions"),
            Self::Txn { txn, state } => write!(f, "transaction {txn}: {state}"),
            Self::HeadUnreadable { why } => write!(f, "  its plan cannot be shown: {why}"),
            Self::TxnOp { op, state, at } => match at {
                Some(at) => write!(f, "  op {op}, {state}: {at}"),
                None => write!(f, "  op {op}, {state}"),
            },
            Self::BackupFile { path, len } => {
                write!(f, "    backup ({len} bytes): {path}")
            }
            Self::BackupInline => f.write_str("    backup: kept in the journal record"),
            Self::Cleanup { path } => write!(f, "    pending cleanup: {path}"),
            Self::MayRemain { path } => write!(f, "    may remain (pending cleanup): {path}"),
            Self::BackupsIn { folder } => write!(f, "  its backups stay in: {folder}"),
            Self::HintRevert { txn } => write!(f, "  revert with: rerun revert {txn}"),
            Self::HintForgetOnly { txn } => write!(
                f,
                "  blocks every apply; only forget closes it: rerun forget {txn}"
            ),
            Self::HintForgetForeign { txn } => write!(
                f,
                "  changes were left as found; forget closes it: rerun forget {txn}"
            ),
            Self::HintCleanup { txn } => write!(
                f,
                "  a file Rerun left is still there; rerun revert {txn} deletes it or says why it \
                 stays (close the game and any window showing its folder first)"
            ),
            Self::ForeignEntries { n } => write!(
                f,
                "journal: {} not Rerun's (left alone)",
                Count(*n, "entry", "entries")
            ),
            Self::StatusCounts {
                open,
                closed,
                forgotten,
                all,
            } => {
                write!(
                    f,
                    "{}: {open} not closed, {closed} closed, {forgotten} forgotten",
                    Count(open + closed + forgotten, "transaction", "transactions")
                )?;
                if *all || *closed == 0 {
                    Ok(())
                } else {
                    f.write_str(" (rerun status --all lists the closed ones)")
                }
            }
            Self::StatusNote => f.write_str(
                "note: rerun revert --dry-run <txn> and rerun forget <txn> show what is on disk now",
            ),

            Self::NowHeading => f.write_str("on disk now, newest op first:"),
            Self::Will { op, observed, at } => match at {
                Some(at) => write!(f, "  op {op}, {}: {at}", will(*observed)),
                None => write!(f, "  op {op}, {}", will(*observed)),
            },
            Self::KeyState {
                state,
                section,
                key,
            } => write!(f, "    {}: [{section}] {key}", key_state(*state)),
            Self::BeforeStep { step, file } => write!(
                f,
                "    the file as it was before Rerun's {step} is kept next to it (never call it \
                 the original; the backup is): {file}"
            ),
            Self::WillDelete { sha256, path } => write!(
                f,
                "  will delete Rerun's copy (known content, SHA-256 {sha256}): {path}"
            ),
            Self::OldInUse { path } => write!(
                f,
                "  in use, stays for now (Rerun's copy; the transaction stays open): {path}"
            ),
            Self::OldKept { path } => write!(
                f,
                "  kept: the file next to it changed since the revert, so Rerun's copy stays \
                 (delete it yourself, or forget the transaction): {path}"
            ),
            Self::OldForeign { path } => write!(
                f,
                "  not Rerun's file, or it cannot be checked as Rerun's; left as it is: {path}"
            ),
            Self::OldDeleted { path } => write!(f, "  deleted Rerun's copy: {path}"),
            Self::Halted { op, why } => write!(f, "the revert stops at op {op}: {why}"),
            Self::CannotObserve { error } => {
                write!(f, "  what is on disk cannot be observed now: {error}")
            }
            Self::DryRunDone => f.write_str("dry run: nothing was written"),
            Self::AskRevert { ops: 1 } => f.write_str("Revert this op? [y/N]"),
            Self::AskRevert { ops } => write!(f, "Revert these {ops} ops? [y/N]"),
            Self::AskCleanup { n, in_use } => {
                match n {
                    1 => f.write_str("Everything is reverted. Delete the file Rerun left")?,
                    n => write!(f, "Everything is reverted. Delete the {n} files Rerun left")?,
                }
                match in_use {
                    0 => {}
                    1 if *n == 1 => f.write_str(" (it is in use now and may stay)")?,
                    1 => f.write_str(" (one is in use now and may stay)")?,
                    k => write!(f, " ({k} are in use now and may stay)")?,
                }
                f.write_str("? [y/N]")
            }
            Self::Did {
                op,
                observed,
                changed,
            } => {
                write!(f, "  op {op}: {}", did(*observed))?;
                if *changed {
                    f.write_str(" (changed since the preview)")
                } else {
                    Ok(())
                }
            }
            Self::Left { path } => write!(f, "    left: {path}"),
            Self::Reverted { txn } => write!(f, "transaction {txn} reverted and closed"),
            Self::AlreadyClosed { txn, how } => write!(
                f,
                "transaction {txn} is already closed ({}); nothing to revert",
                closing(*how)
            ),
            Self::NothingToRevert { txn } => {
                write!(f, "transaction {txn} changed nothing; nothing to revert")
            }
            Self::StaysOpenHalted { txn } => write!(
                f,
                "transaction {txn} stays open; rerun revert {txn} goes on once the folder is back"
            ),
            Self::StaysOpenForeign { txn } => write!(
                f,
                "transaction {txn} stays open: changes were left as found; rerun forget {txn} \
                 closes it (backups stay)"
            ),
            Self::StaysOpenInUse { txn, n } => write!(
                f,
                "transaction {txn} is reverted; {} Rerun replaced {} still in use and {} for \
                 now; close the game and any window showing its folder, then run rerun revert \
                 {txn} again",
                Count(*n, "file", "files"),
                if *n == 1 { "is" } else { "are" },
                if *n == 1 { "stays" } else { "stay" }
            ),
            Self::StaysOpenKept { txn } => write!(
                f,
                "transaction {txn} is reverted, but a file next to Rerun's copy changed since, so \
                 the copy stays; delete it yourself and run rerun revert {txn}, or rerun forget \
                 {txn}"
            ),
            Self::RevertFailed { txn } => write!(
                f,
                "the revert failed after it began: transaction {txn} stays open; rerun status \
                 shows it, rerun revert {txn} tries again"
            ),
            Self::ForgetChangesNothing => {
                f.write_str("Forget changes nothing in the game folder or the registry.")
            }
            Self::ForgetStays => {
                f.write_str("Changes still in place stay, and Rerun will not revert them.")
            }
            Self::ForgetOnlyCleanup => f.write_str(
                "Everything is reverted; only the files listed as pending cleanup stay, and \
                 Rerun will not delete them.",
            ),
            Self::ForgetKeeps => {
                f.write_str("Backups and files Rerun left are not deleted.")
            }
            Self::AllStay { ops: 1 } => f.write_str("the change stays"),
            Self::AllStay { ops } => write!(f, "all {ops} changes stay"),
            Self::RevertIsClean { txn } => write!(
                f,
                "rerun revert {txn} finishes this cleanly; forget leaves the folder as it is now"
            ),
            Self::AskForget { txn } => write!(f, "Forget transaction {txn}? [y/N]"),
            Self::Forgot { txn } => write!(f, "transaction {txn} forgotten"),
            Self::AlreadyForgotten { txn } => {
                write!(f, "transaction {txn} is already forgotten")
            }

            Self::Error { error } => write!(f, "rerun: {error}"),
            Self::NoConsole => f.write_str(
                "rerun: stdin or stdout is not a console, so nothing can be asked; pass --yes",
            ),
            Self::AppDirMoved => f.write_str(
                "rerun: Rerun's folder moved while the plan was made; nothing stored, plan again",
            ),
            Self::NoAppDir => f.write_str(
                "rerun: Rerun has no folder yet, so there is no plan or transaction; run rerun \
                 plan first",
            ),
            Self::AppDir { error } => write!(f, "rerun: cannot open Rerun's folder: {error}"),
            Self::JournalUnreadable { error } => {
                write!(f, "rerun: cannot read the journal: {error}")
            }
            Self::StepFile { error } => write!(f, "rerun: cannot read the step file: {error}"),
            Self::PlanFailed { error } => write!(f, "rerun: cannot plan the steps: {error}"),
            Self::GameFolder { error } => {
                write!(f, "rerun: cannot open the game folder: {error}")
            }
            Self::SteamApp { app_id, why } => write!(f, "rerun: Steam app {app_id} {why}"),
            Self::StoreFailed { error } => write!(f, "rerun: cannot store the plan: {error}"),
            Self::IdentityHint { txn } => write!(
                f,
                "the game folder is another folder now (a moved library or a reinstall); if Steam \
                 moved or reinstalled it, rerun revert {txn} --rebind shows the folder Steam lists \
                 now; a folder you chose: rerun forget {txn} closes the transaction"
            ),
            Self::EmptyCloses { txn } => write!(
                f,
                "transaction {txn} changed nothing; rerun revert {txn} only closes it"
            ),
            Self::MayHaveClosed { txn } => write!(
                f,
                "transaction {txn} may have been closed although the command failed; rerun \
                 status shows what the journal holds"
            ),
            Self::RebindHeading { root } => write!(f, "rebind of root {root}:"),
            Self::RebindNow { id, path } => write!(f, "  bound now (identity {id}): {path}"),
            Self::RebindLibrary { library } => write!(f, "    in library: {library}"),
            Self::RebindWhy { why } => write!(f, "    does not open: {why}"),
            Self::RebindTo { id, path } => {
                write!(f, "  the folder Steam lists now (identity {id}): {path}")
            }
            Self::CreatedFound { path } => write!(
                f,
                "  a folder the plan created, found there and not provably Rerun's (removed only if empty): {path}"
            ),
            Self::CreatedMissing { path } => {
                write!(f, "  a folder the plan created, missing there: {path}")
            }
            Self::RebindNowHeading => f.write_str("what the revert does there:"),
            Self::RebindRegistryNote => f.write_str(
                "Registry changes are reverted where Rerun made them, also a compatibility-layer \
                 value under the old program path; a value under the new program path is not \
                 touched.",
            ),
            Self::RebindScopeNote => f.write_str(
                "Only the folder bound now is reverted; a copy of the game elsewhere (a renamed                  old folder, a library removed from Steam while its drive was away) keeps                  Rerun's files.",
            ),
            Self::RebindPermanentNote => f.write_str(
                "The binding is permanent: every later revert of this transaction uses the new \
                 folder.",
            ),
            Self::AskRebind { txn, ops: 1 } => {
                write!(f, "Bind transaction {txn} to this folder and revert this op? [y/N]")
            }
            Self::AskRebind { txn, ops } => write!(
                f,
                "Bind transaction {txn} to this folder and revert these {ops} ops? [y/N]"
            ),
            Self::RebindNeedsConsole => f.write_str(
                "rerun: a rebind is only confirmed at a console; --yes is not accepted with \
                 --rebind",
            ),
            Self::AlreadyBound { path } => write!(f, "already bound to: {path}"),
            Self::MayBeBound { txn } => write!(
                f,
                "transaction {txn} may be bound to the new folder although the command failed; \
                 rerun status shows what the journal holds"
            ),
            Self::HaltRebindHint { txn } => write!(
                f,
                "if Steam moved or reinstalled the game: rerun revert {txn} --rebind shows the \
                 folder Steam lists now"
            ),
            Self::BoundNow { txn } => write!(
                f,
                "transaction {txn} is bound to the new folder now; rerun revert {txn} goes on \
                 there"
            ),
            Self::BoundMayHaveClosed { txn } => write!(
                f,
                "transaction {txn} is bound to the new folder and may have been closed; rerun \
                 status shows what the journal holds"
            ),
            Self::RebindRootIs { root, path } => write!(f, "  (root {root} there: {path})"),
            Self::StatusRebind { root, id, path } => {
                write!(f, "  root {root} rebound (identity {id}): {path}")
            }
            Self::NothingToForget { txn, how } => write!(
                f,
                "rerun: transaction {txn} is closed ({}); nothing to forget",
                closing(*how)
            ),
        }
    }
}
