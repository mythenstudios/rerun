//! The messages of the phase 2 commands (P2-13, ADR 0016 amendment "phase 2 commands"): so far
//! `plan` and `apply`. One [`TxnMsg`] is one line. Static text is
//! ASCII; untrusted fields are [`Shown`] and stand last on their line. Registry text appears
//! only in the plan preview (ADR 0016 amendment P2-10b); a recorded head comes masked from the
//! core (`plan::preview_head`).

use std::fmt;

use rerun_core::escape::Shown;
use rerun_core::journal::TxnId;
use rerun_core::plan::{IniOldShown, PlanHash, RegShown};

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
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Root { index, path } => write!(f, "root {index}: {path}"),
            Self::RootSteam { app_id, library } => {
                write!(f, "  Steam app {app_id}, library: {library}")
            }
            Self::RootMainExe { path } => write!(f, "  main executable: {path}"),
            Self::Op { index, op } => write!(f, "op {index}: {op}"),
            Self::ValueName { name } => write!(f, "  value: {name}"),
            Self::Source { source } => write!(f, "  from package: {source}"),
            Self::NewContent { sha256, len, attrs } => {
                write!(f, "  new: sha256 {sha256}, {len} bytes")?;
                match attrs {
                    Some(a) => write!(f, ", attributes {a}"),
                    None => Ok(()),
                }
            }
            Self::OldContent { sha256, len, attrs } => {
                write!(f, "  old: sha256 {sha256}, {len} bytes, attributes {attrs}")
            }
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
            Self::PlanDryRun { hash, ops } => {
                write!(f, "plan {hash} (dry run, not stored): {}", changes(*ops))
            }
            Self::ApplyWith { hash } => write!(f, "apply with: rerun apply {hash}"),

            Self::PlanHead { hash, ops } => write!(f, "plan {hash}: {}", changes(*ops)),
            Self::ChecksPassed => f.write_str("dry run: every check passed; nothing was written"),
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
            Self::FinishWithRevert { txn } => {
                write!(f, "rerun status shows it; rerun revert {txn} finishes it")
            }
            Self::FinishWithForget { txn } => write!(
                f,
                "changes were left as found; rerun forget {txn} closes it (backups stay)"
            ),

            Self::Error { error } => write!(f, "rerun: {error}"),
            Self::NoConsole => f.write_str(
                "rerun: stdin or stdout is not a console, so nothing can be asked; pass --yes",
            ),
            Self::NoAppDir => f.write_str(
                "rerun: Rerun has no folder yet, so there is no plan or transaction; run rerun \
                 plan first",
            ),
            Self::AppDir { error } => write!(f, "rerun: cannot open Rerun's folder: {error}"),
            Self::StepFile { error } => write!(f, "rerun: cannot read the step file: {error}"),
            Self::PlanFailed { error } => write!(f, "rerun: cannot plan the steps: {error}"),
            Self::GameFolder { error } => {
                write!(f, "rerun: cannot open the game folder: {error}")
            }
            Self::SteamApp { app_id, why } => write!(f, "rerun: Steam app {app_id} {why}"),
            Self::StoreFailed { error } => write!(f, "rerun: cannot store the plan: {error}"),
        }
    }
}
