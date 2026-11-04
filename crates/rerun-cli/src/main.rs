//! `rerun` – command-line interface. Each phase brings its own subcommands (phase 1: `scan`).

use clap::Parser;

/// Rerun by Mythen Studios – detects old PC games and applies (and cleanly removes)
/// the compatibility fixes they need.
#[derive(Debug, Parser)]
// No `about` key: clap uses the doc comment (UI base string) instead of the package
// description from Cargo.toml.
#[command(name = "rerun", bin_name = "rerun", version)]
struct Cli {}

fn main() {
    let _cli = Cli::parse();
    println!(
        "rerun {}: no commands yet. See `rerun --help`.",
        rerun_core::VERSION
    );
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
