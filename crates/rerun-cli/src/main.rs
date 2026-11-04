//! `rerun` – command-line interface. Each phase brings its own subcommands (phase 1: `scan`).

use std::process::ExitCode;

use clap::Parser;

/// Rerun by Mythen Studios – detects old PC games and applies (and cleanly removes)
/// the compatibility fixes they need.
#[derive(Debug, Parser)]
// No `about` key: clap uses the doc comment (UI base string) instead of the package
// description from Cargo.toml.
#[command(name = "rerun", bin_name = "rerun", version)]
struct Cli {}

fn main() -> ExitCode {
    // First statement (ADR 0008, H2): no later DLL load may come from the install folder, the
    // current directory or `PATH`. Fail closed.
    #[cfg(windows)]
    if let Err(e) = rerun_core::sys::win::restrict_dll_search() {
        eprintln!("rerun: cannot restrict the DLL search path to System32: {e}");
        return ExitCode::FAILURE;
    }
    let _cli = Cli::parse();
    println!(
        "rerun {}: no commands yet. See `rerun --help`.",
        rerun_core::VERSION
    );
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::Cli;
    use clap::CommandFactory;

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }
}
