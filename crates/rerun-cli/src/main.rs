//! `rerun` – command-line interface (ADR 0016). Phase 1: `rerun system` and `rerun scan`.
//!
//! Order in `main`: `restrict_dll_search` first (ADR 0008), then clap parses (`--help`,
//! `--version` and usage errors end there, before any registry or file system access), then
//! `WinSystem::new`. The commands take a `&dyn System` and two line writers, so the tests run
//! them against the fake system layer with in-memory output.

mod cli;
mod messages;
mod out;
mod scan;
mod system;

use std::io;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;

use rerun_core::escape;

use crate::cli::{Cli, Command, Exit};
use crate::messages::Message;
use crate::out::Out;

#[cfg(windows)]
fn main() -> ExitCode {
    use rerun_core::sys::win::{WinSystem, restrict_dll_search};

    // First statement (ADR 0008, H2): no later DLL load may come from the install folder, the
    // current directory or `PATH`. Fail closed.
    if let Err(e) = restrict_dll_search() {
        let mut err = Out::new(io::stderr().lock());
        let _ = err.line(&Message::DllSearch {
            error: escape::text(&e.to_string()),
        });
        return Exit::Fatal.into();
    }
    let cli = match parse() {
        Ok(cli) => cli,
        Err(exit) => return exit.into(),
    };
    let mut out = Out::new(io::stdout().lock());
    let mut err = Out::new(io::stderr().lock());
    let sys = match WinSystem::new() {
        Ok(sys) => sys,
        Err(e) => {
            let _ = err.line(&Message::SystemUnavailable {
                error: escape::text(&e.to_string()),
            });
            return Exit::Fatal.into();
        }
    };
    run(&sys, cli.command, &mut out, &mut err).into()
}

#[cfg(not(windows))]
fn main() -> ExitCode {
    if let Err(exit) = parse() {
        return exit.into();
    }
    let _ = Out::new(io::stderr().lock()).line(&Message::WindowsOnly);
    Exit::Fatal.into()
}

/// Parses the command line; help, version and usage errors are printed by clap and end here.
fn parse() -> Result<Cli, Exit> {
    Cli::try_parse().map_err(|e| {
        // A closed pipe while printing help changes nothing.
        let _ = e.print();
        if e.use_stderr() {
            Exit::Usage
        } else {
            Exit::Report
        }
    })
}

/// Runs a command.
fn run<W: io::Write, E: io::Write>(
    sys: &dyn rerun_core::sys::System,
    command: Command,
    out: &mut Out<W>,
    err: &mut Out<E>,
) -> Exit {
    match command {
        Command::System => system::system(sys, out, err),
        Command::Scan { app_ids, hashes } => match install_dir() {
            Ok(dir) => scan::scan(sys, &dir, &app_ids, hashes, out, err),
            Err(error) => {
                let _ = err.line(&Message::CurrentExe {
                    error: escape::text(&error),
                });
                Exit::Fatal
            }
        },
    }
}

/// Rerun's install folder: the folder of `rerun.exe` (ADR 0016), for the forbidden roots.
fn install_dir() -> Result<PathBuf, String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    exe.parent()
        .map(PathBuf::from)
        .ok_or_else(|| "the executable path has no parent folder".to_owned())
}
