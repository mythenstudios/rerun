//! `rerun-launch.exe` – launch shim (see `docs/04-launch-methods.md`).
//!
//! Phase 0: scaffold only. The launch methods arrive in phase 3.

use std::process::ExitCode;

fn main() -> ExitCode {
    eprintln!(
        "rerun-launch {}: not implemented yet",
        env!("CARGO_PKG_VERSION")
    );
    ExitCode::FAILURE
}
