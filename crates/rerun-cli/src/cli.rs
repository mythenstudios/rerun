//! The command line (ADR 0016 and its phase 2 amendment). clap's help texts come from the doc
//! comments here (UI base strings, English); every other user-facing string lives in
//! `messages`.

use std::path::PathBuf;

use clap::{Parser, Subcommand};

use rerun_core::journal::TxnId;
use rerun_core::plan::PlanHash;

/// Rerun by Mythen Studios – detects old PC games and applies (and cleanly removes)
/// the compatibility fixes they need.
#[derive(Debug, Parser)]
// No `about` key: clap uses the doc comment (UI base string) instead of the package
// description from Cargo.toml.
#[command(name = "rerun", bin_name = "rerun", version)]
pub struct Cli {
    /// The command.
    #[command(subcommand)]
    pub command: Command,
}

/// The commands of phases 1 and 2.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// The system profile: GPU, CPU topology, OS build and the facts Topo conditions see.
    System,
    /// Steam games with their main executable, architecture and graphics API.
    Scan {
        /// Only these Steam app IDs.
        app_ids: Vec<u32>,
        /// Also compute SHA-1 and SHA-256 of the game executables (slow).
        #[arg(long)]
        hashes: bool,
    },
    /// Plans the steps of a step file and shows every change; stores the plan for apply.
    Plan {
        /// The step file (JSON, at most 1 MiB).
        steps: PathBuf,
        /// Show the plan only; store nothing.
        #[arg(long)]
        dry_run: bool,
    },
    /// Applies a stored plan after showing it again.
    Apply {
        /// The plan hash `rerun plan` printed.
        #[arg(value_parser = plan_hash)]
        hash: PlanHash,
        /// Run every check, change nothing.
        #[arg(long)]
        dry_run: bool,
        /// Do not ask before applying (needed when not run from a console).
        #[arg(long)]
        yes: bool,
    },
    /// Reverts a transaction after showing what the revert does now.
    Revert {
        /// The transaction `rerun apply` printed.
        #[arg(value_parser = txn_id)]
        txn: TxnId,
        /// Show what the revert would do, change nothing.
        #[arg(long)]
        dry_run: bool,
        /// Do not ask before reverting (needed when not run from a console).
        #[arg(long)]
        yes: bool,
    },
    /// Transactions with their state, backups and pending cleanups.
    Status {
        /// Also list every closed transaction.
        #[arg(long)]
        all: bool,
    },
    /// Closes a transaction without reverting it; changes nothing on disk.
    Forget {
        /// The transaction.
        #[arg(value_parser = txn_id)]
        txn: TxnId,
        /// Do not ask before forgetting (needed when not run from a console).
        #[arg(long)]
        yes: bool,
    },
}

/// A plan hash: exactly 64 lower-case hex digits, checked before any system access.
fn plan_hash(s: &str) -> Result<PlanHash, String> {
    s.parse()
        .map_err(|_| "not a plan hash (64 lower-case hex digits)".to_owned())
}

/// A transaction name: 8 digits, `-`, 16 lower-case hex digits.
fn txn_id(s: &str) -> Result<TxnId, String> {
    s.parse()
        .map_err(|_| "not a transaction name (8 digits, '-', 16 lower-case hex digits)".to_owned())
}

/// Exit codes (ADR 0016 and its phase 2 amendment). Only additive changes: scripts may rely
/// on them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exit {
    /// Done, or a report was printed (also with partial failures, open transactions, or the
    /// output ended by a closed pipe after the change).
    Report = 0,
    /// Fatal, no report.
    Fatal = 1,
    /// Usage error (clap, a malformed hash or transaction, no console without `--yes`).
    Usage = 2,
    /// Nothing was changed: refused, declined, or the preview could not be written.
    Refused = 3,
    /// The apply failed and was rolled back completely.
    RolledBack = 4,
    /// A transaction stays open and needs attention.
    Open = 5,
}

impl From<Exit> for std::process::ExitCode {
    fn from(e: Exit) -> Self {
        Self::from(e as u8)
    }
}

#[cfg(test)]
mod tests {
    use clap::{CommandFactory, Parser};

    use super::{Cli, Command};

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn hashes_and_transactions_are_checked_by_form() {
        let h = "a".repeat(64);
        assert!(matches!(
            Cli::try_parse_from(["rerun", "apply", &h, "--yes"]).map(|c| c.command),
            Ok(Command::Apply {
                yes: true,
                dry_run: false,
                ..
            })
        ));
        for bad in [&"A".repeat(64), &"a".repeat(63), "x", ""] {
            let e = Cli::try_parse_from(["rerun", "apply", bad]).unwrap_err();
            assert!(e.use_stderr(), "{bad}");
        }
        assert!(Cli::try_parse_from(["rerun", "revert", "00000001-00000000000000ab"]).is_ok());
        for bad in ["abc", "1-00000000000000ab", "00000001-00000000000000AB"] {
            assert!(
                Cli::try_parse_from(["rerun", "revert", bad]).is_err(),
                "{bad}"
            );
            assert!(
                Cli::try_parse_from(["rerun", "forget", bad]).is_err(),
                "{bad}"
            );
        }
    }
}
