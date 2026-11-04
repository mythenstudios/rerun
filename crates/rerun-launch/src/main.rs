//! `rerun-launch.exe` – launch shim (see `docs/04-launch-methods.md`).
//!
//! Phase 0: scaffold only. The launch methods arrive in phase 3.

use std::process::ExitCode;

#[cfg(windows)]
mod dll;

fn main() -> ExitCode {
    // First statement (ADR 0008, H2): no later DLL load may come from the game folder, the
    // current directory or `PATH`. Fail closed.
    #[cfg(windows)]
    if let Err(code) = dll::restrict_search() {
        eprintln!(
            "rerun-launch: cannot restrict the DLL search path to System32 (Win32 error {code})"
        );
        return ExitCode::FAILURE;
    }
    eprintln!(
        "rerun-launch {}: not implemented yet",
        env!("CARGO_PKG_VERSION")
    );
    ExitCode::FAILURE
}
