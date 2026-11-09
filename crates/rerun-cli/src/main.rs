//! `rerun` – command-line interface (ADR 0016). Phase 1: `rerun system` and `rerun scan`;
//! phase 2 (P2-13): `rerun plan`, `apply`, `revert`, `status` and `forget`; phase 4 (P4-3):
//! `rerun index import` and `rerun index show` (ADR 0024).
//!
//! Order in `main`: `restrict_dll_search` first (ADR 0008), then clap parses (`--help`,
//! `--version` and usage errors, a malformed plan hash or transaction included, end there,
//! before any registry or file system access), then `WinSystem::new`. The commands take a
//! [`Host`] (`&dyn System`, the install folder, the confirmation) and two line writers, so the
//! tests run them against the fake system layer with in-memory output and a fake console.
//!
//! No console control handler: Ctrl+C during an apply or a revert ends the process like a
//! crash, which the journal is built for; `rerun revert <txn>` finishes it (docs/04).

mod apply;
mod cli;
mod confirm;
mod host;
mod index;
mod messages;
mod out;
mod plan;
mod preview;
mod scan;
mod system;
mod txn;

use std::io;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;

use rerun_core::escape;

use crate::cli::{Cli, Command, Exit, IndexCommand};
use crate::host::Host;
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
    let mut console = confirm::Console;
    let mut host = Host {
        sys: &sys,
        install: install_dir(),
        confirm: &mut console,
    };
    run(&mut host, cli.command, &mut out, &mut err).into()
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
        let help = !e.use_stderr()
            || e.kind() == clap::error::ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand;
        if help {
            // Help and version: clap's own text, no user input in it. A closed pipe while
            // printing it changes nothing.
            let _ = e.print();
        } else {
            // Review N5: never clap's rendering, which repeats the arguments raw.
            let _ = Out::new(io::stderr().lock()).lines(&cli::usage_lines(&e));
        }
        if e.use_stderr() {
            Exit::Usage
        } else {
            Exit::Report
        }
    })
}

/// Runs a command.
fn run<W: io::Write, E: io::Write>(
    host: &mut Host<'_>,
    command: Command,
    out: &mut Out<W>,
    err: &mut Out<E>,
) -> Exit {
    match command {
        Command::System => system::system(host.sys, out, err),
        Command::Scan { app_ids, hashes } => match &host.install {
            Ok(dir) => scan::scan(host.sys, dir, &app_ids, hashes, out, err),
            Err(error) => {
                let _ = err.line(&Message::CurrentExe {
                    error: escape::text(error),
                });
                Exit::Fatal
            }
        },
        Command::Plan { steps, dry_run } => plan::plan(host, &steps, dry_run, out, err),
        Command::Apply { hash, dry_run, yes } => apply::apply(host, &hash, dry_run, yes, out, err),
        Command::Revert {
            txn,
            dry_run,
            yes,
            rebind,
        } => txn::revert(host, &txn, dry_run, yes, rebind, out, err),
        Command::Status { all } => txn::status(host.sys, all, out, err),
        Command::Forget { txn, yes } => txn::forget(host, &txn, yes, out, err),
        Command::Index {
            command: IndexCommand::Import { index, sig },
        } => index::import(host, &index, &sig, out, err),
        Command::Index {
            command: IndexCommand::Show,
        } => index::show(host, out, err),
    }
}

/// Rerun's install folder: the folder of `rerun.exe` (ADR 0016), for the forbidden roots.
fn install_dir() -> Result<PathBuf, String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    exe.parent()
        .map(PathBuf::from)
        .ok_or_else(|| "the executable path has no parent folder".to_owned())
}

#[cfg(test)]
mod index_tests;
#[cfg(test)]
mod lm_tests;
#[cfg(test)]
mod tests;
