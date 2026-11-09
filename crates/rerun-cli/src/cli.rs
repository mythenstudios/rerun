//! The command line (ADR 0016 and its phase 2 amendment). clap's help texts come from the doc
//! comments here (UI base strings, English); every other user-facing string lives in
//! `messages`.

use std::path::PathBuf;

use clap::{Parser, Subcommand};

use rerun_core::escape;

use rerun_core::catalog::model::Id;
use rerun_core::journal::TxnId;
use rerun_core::plan::{Pick, PlanHash};

use crate::messages::Message;

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
    /// Plans fixes from the signed index for a Steam app (or the steps of a step file) and shows
    /// every change; stores the plan for apply. Without --pick, an app ID gives a report only.
    Plan {
        /// A Steam app ID (digits only), or a step file (JSON, at most 1 MiB).
        target: PathBuf,
        /// A variant to plan, as <issue>/<variant>; repeat for several issues (app ID only).
        #[arg(long = "pick", value_parser = pick)]
        picks: Vec<Pick>,
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
        /// Bind the transaction to the folder Steam lists now for the game, after a preview, then
        /// revert it there (only at a console; not with --yes).
        #[arg(long, conflicts_with = "yes")]
        rebind: bool,
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
    /// The signed Topo index.
    Index {
        /// What to do with it.
        #[command(subcommand)]
        command: IndexCommand,
    },
}

/// `rerun index`.
#[derive(Debug, Subcommand)]
pub enum IndexCommand {
    /// Checks a signed index and its signature and makes it the current index (never an older
    /// one).
    Import {
        /// The index (index.json, at most 8 MiB).
        index: PathBuf,
        /// Its signature (index.json.sig, 64 bytes).
        sig: PathBuf,
    },
    /// The current index: number, date, entries, key.
    Show,
}

/// A pick `<issue>/<variant>`: two IDs of the Topo form, checked before any system access.
fn pick(s: &str) -> Result<Pick, String> {
    let bad = || "not <issue>/<variant> (IDs of a-z, 0-9 and single hyphens)".to_owned();
    let (issue, variant) = s.split_once('/').ok_or_else(bad)?;
    match (Id::parse(issue), Id::parse(variant)) {
        (Some(i), Some(v)) => Ok(Pick {
            issue: i.to_string(),
            variant: v.to_string(),
        }),
        _ => Err(bad()),
    }
}

/// The target of `rerun plan`: digits only are a Steam app ID (1 to 4294967295).
pub fn app_id(target: &std::path::Path) -> Option<u32> {
    let s = target.to_str()?;
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok().filter(|n| *n > 0)
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

/// The lines of a usage error (security review N5): Rerun's words for the kind, the expected
/// form from Rerun's own value parsers, and the value the user gave through `escape::text`,
/// last on its line. clap's own rendering would repeat the arguments raw.
pub fn usage_lines(e: &clap::Error) -> Vec<Message<'static>> {
    use clap::error::{ContextKind, ContextValue, ErrorKind};
    let what = match e.kind() {
        ErrorKind::InvalidValue | ErrorKind::ValueValidation => "invalid value",
        ErrorKind::UnknownArgument => "unknown argument",
        ErrorKind::InvalidSubcommand => "unknown command",
        ErrorKind::MissingRequiredArgument => "a required argument is missing",
        ErrorKind::MissingSubcommand => "a command is missing",
        ErrorKind::TooManyValues | ErrorKind::TooFewValues | ErrorKind::WrongNumberOfValues => {
            "wrong number of values"
        }
        ErrorKind::ArgumentConflict => "arguments that cannot be used together",
        _ => "invalid command line",
    };
    let value = [
        ContextKind::InvalidValue,
        ContextKind::InvalidArg,
        ContextKind::InvalidSubcommand,
    ]
    .into_iter()
    .find_map(|k| match e.get(k) {
        Some(ContextValue::String(s)) => Some(s.clone()),
        Some(ContextValue::Strings(v)) => Some(v.join(" ")),
        _ => None,
    });
    let why = match e.kind() {
        ErrorKind::ValueValidation => std::error::Error::source(e).map(ToString::to_string),
        _ => None,
    };
    vec![
        Message::Usage {
            what,
            why: why.map(|w| escape::text(&w).into_owned()),
            value: value.map(|v| escape::text(&v).into_owned()),
        },
        Message::UsageHelp,
    ]
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
    fn usage_errors_are_rerun_s_lines_with_the_value_escaped() {
        let text = |args: &[&str]| {
            let e = Cli::try_parse_from(args).unwrap_err();
            let mut out = crate::out::Out::new(Vec::new());
            out.lines(&super::usage_lines(&e)).unwrap();
            String::from_utf8(out.into_inner()).unwrap()
        };
        assert_eq!(
            text(&["rerun", "apply", "abc"]),
            "rerun: invalid value (not a plan hash (64 lower-case hex digits)): abc\n\
             rerun --help lists the commands, rerun <command> --help their arguments\n"
        );
        let evil = text(&["rerun", "scan", "x\u{1b}[2J"]);
        assert!(
            evil.starts_with(
                "rerun: invalid value (invalid digit found in string): \"x\\u{1b}[2J\"\n"
            ),
            "{evil}"
        );
        assert!(text(&["rerun", "nope"]).starts_with("rerun: unknown command: nope\n"));
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
