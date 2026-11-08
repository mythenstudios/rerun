//! `rerun-launch.exe` – launch shim (`docs/04-launch-methods.md`, ADR 0022).
//!
//! `rerun-launch.exe --profile <id> %command%`: reads the profile, selects the processors on
//! the live topology and starts Steam's command in a Job Object with that limit (or with
//! default CPU Sets), then waits for it and exits with its exit code. Any problem with the
//! rule starts the command unchanged (D3). No console (B1): the shim reports through its exit
//! code only (the result file follows in P3-2):
//!
//! - the started command's exit code, if it started;
//! - 1: the DLL search path could not be restricted (ADR 0008, fail closed; nothing started);
//! - 2: the shim's own command line is unusable (nothing started);
//! - 3: the command could not be started, or its exit code could not be read.

#![windows_subsystem = "windows"]

mod cmdline;
mod os;
mod run;

#[cfg(windows)]
mod dll;
#[cfg(test)]
mod fake;
#[cfg(windows)]
mod win;

#[cfg(windows)]
fn main() {
    // First statement (ADR 0008, H2): no later DLL load may come from the game folder, the
    // current directory or `PATH`. Fail closed: nothing is started.
    if dll::restrict_search().is_err() {
        std::process::exit(run::EXIT_HARDENING.cast_signed());
    }
    let report = run::run(&win::WinOs);
    // The full 32-bit exit code of the game (`ExitProcess` takes it unchanged).
    std::process::exit(report.exit_code().cast_signed());
}

#[cfg(not(windows))]
fn main() {
    std::process::exit(run::EXIT_HARDENING.cast_signed());
}
