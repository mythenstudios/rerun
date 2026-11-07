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
    /// The revert failed after it wrote.
    RevertFailed {
        /// The transaction.
        txn: TxnId,
    },
    /// What forget does and does not do (three fixed lines).
    ForgetChangesNothing,
    /// What forget does not revert.
    ForgetStays,
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
    /// A damaged or unreadable transaction cannot be reverted.
    Damaged {
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
            Self::Halted { op, why } => write!(f, "the revert stops at op {op}: {why}"),
            Self::CannotObserve { error } => {
                write!(f, "  what is on disk cannot be observed now: {error}")
            }
            Self::DryRunDone => f.write_str("dry run: nothing was written"),
            Self::AskRevert { ops: 1 } => f.write_str("Revert this op? [y/N]"),
            Self::AskRevert { ops } => write!(f, "Revert these {ops} ops? [y/N]"),
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
                "the game folder is another folder now (a moved library or a reinstall); rerun \
                 forget {txn} closes the transaction, a rebind is not supported yet"
            ),
            Self::Damaged { txn } => write!(
                f,
                "rerun: transaction {txn} is damaged or unreadable; only rerun forget {txn} \
                 closes it"
            ),
            Self::NothingToForget { txn, how } => write!(
                f,
                "rerun: transaction {txn} is closed ({}); nothing to forget",
                closing(*how)
            ),
        }
    }
}
