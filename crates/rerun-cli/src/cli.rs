//! The command line (ADR 0016 and its phase 2 amendment). clap's help texts come from the doc
//! comments here (UI base strings, English); every other user-facing string lives in
//! `messages`.

use std::path::PathBuf;

use clap::{Parser, Subcommand};

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
}

/// Exit codes (ADR 0016 and its phase 2 amendment). Only additive changes: scripts may rely
/// on them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exit {
    /// Done, or a report was printed (also with partial failures, or the output ended by a
    /// closed pipe after the change).
    Report = 0,
    /// Fatal, no report.
    Fatal = 1,
    /// Usage error (clap).
    Usage = 2,
    /// Nothing was changed: refused, or the preview could not be written.
    Refused = 3,
}

impl From<Exit> for std::process::ExitCode {
    fn from(e: Exit) -> Self {
        Self::from(e as u8)
    }
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    use super::Cli;

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }
}
