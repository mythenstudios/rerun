//! The command line (ADR 0016). clap's help texts come from the doc comments here (UI base
//! strings, English); every other user-facing string lives in `messages`.

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

/// The commands of phase 1.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// The system profile: GPU, CPU topology, OS build and the facts Topo conditions see.
    System,
}

/// Exit codes (ADR 0016).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exit {
    /// A report was printed, also with partial failures, or the output ended by a closed pipe.
    Report = 0,
    /// Fatal, no report.
    Fatal = 1,
    /// Usage error (clap).
    Usage = 2,
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
