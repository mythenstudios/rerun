//! `rerun-app.exe`: the Rerun app (ADR 0027), a window over `rerun_core::flow`; Slint is the
//! framework below its `ui` module (ADR 0026). P5-3: read-only (library, game page, system).
//!
//! Order in `main`: `restrict_dll_search` first (ADR 0008, H2: no later DLL load comes from the
//! install folder, the current directory or `PATH`), then the window. The system layer is
//! created on the worker thread (`worker`), which owns it for the session; every job passes
//! `flow::guard` first, so an elevated process reads nothing and shows the blocking page
//! (rule 6). Nothing runs in the background (rule 1): the worker lives as long as the window.
//!
//! The feature `test-key` makes the [DEV] test-key app (as the CLI's, ADR 0024 amendment
//! P4-13): it trusts the published index test key and says so in the status bar.

#![windows_subsystem = "windows"]

// The published index test key never reaches an optimised `rerun-app.exe` (ADR 0024).
#[cfg(all(feature = "test-key", not(debug_assertions)))]
compile_error!(
    "the feature test-key (the published index test key) is for the [DEV] test-key app only, \
     never with debug assertions off (a release build); ADR 0024 amendment P4-13"
);

mod text;
mod theme;
mod trace;
mod ui;
mod vm;
mod worker;

use std::path::PathBuf;
use std::process::ExitCode;

#[cfg(windows)]
fn main() -> ExitCode {
    use rerun_core::sys::win::{WinHttp, WinSystem, restrict_dll_search};

    // First statement (ADR 0008, H2). Fail closed: without a console there is nobody to tell.
    if restrict_dll_search().is_err() {
        return ExitCode::FAILURE;
    }
    trace::start();
    // Rule 6, before any window (security review S1 of P5-3): Slint reads font settings from
    // the environment when it creates the window, so an elevated or undeterminable process
    // stops here with a plain message box and never creates one. The worker's guard checks
    // again for every job.
    let lang = ui::lang();
    match WinSystem::new() {
        Err(_) => {
            ui::refuse_start(lang, false);
            return ExitCode::FAILURE;
        }
        Ok(sys) => {
            if rerun_core::exec::standard_user(&sys).is_err() {
                ui::refuse_start(lang, true);
                return ExitCode::FAILURE;
            }
        }
    }
    ui::run(|| {
        let sys = WinSystem::new().map_err(|e| vm::shown_error(&e))?;
        Ok(worker::World {
            sys: Box::new(sys),
            http: Box::new(WinHttp::new()),
            install: install_dir(),
        })
    })
}

#[cfg(not(windows))]
fn main() -> ExitCode {
    ExitCode::FAILURE
}

/// Rerun's install folder: the folder of `rerun-app.exe` (the forbidden roots, ADR 0016).
fn install_dir() -> Result<PathBuf, String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    exe.parent()
        .map(PathBuf::from)
        .ok_or_else(|| "the executable path has no parent folder".to_owned())
}
