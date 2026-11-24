//! `rerun-app.exe`: the Rerun app (ADR 0027), a window over `rerun_core::flow`; Slint is the
//! framework below its `ui` module (ADR 0026). P5-3: read-only (library, game page, system).
//!
//! Order in `main`: `restrict_dll_search` first (ADR 0008, H2: no later DLL load comes from the
//! install folder, the current directory or `PATH`), then the elevation check, then the settings
//! file through `flow::guard` (P5-10b: read before the window, so its first frame is right; read
//! only, nothing created), then the window. The system layer is
//! created on the worker thread (`worker`), which owns it for the session; every job passes
//! `flow::guard` first, so an elevated process reads nothing and shows the blocking page
//! (rule 6). Nothing runs in the background (rule 1): the worker lives as long as the window.
//!
//! The feature `test-key` makes the [DEV] test-key app (as the CLI's, ADR 0024 amendment
//! P4-13): it trusts the published index test key and says so in the status bar.

#![windows_subsystem = "windows"]

// The published index test key never reaches the shipped `rerun-app.exe`: never in the `release`
// profile, which has debug assertions off; `dev`, `ci` and `dev-release` keep them (ADR 0024).
#[cfg(all(feature = "test-key", not(debug_assertions)))]
compile_error!(
    "the feature test-key (the published index test key) is for the [DEV] test-key app only, \
     never with debug assertions off (a release build); ADR 0024 amendment P4-13"
);

mod notices;
mod settings;
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
    use std::sync::Arc;

    use rerun_core::flow::Env;
    use rerun_core::sys::NoHttp;
    use rerun_core::sys::win::{WinHttp, WinShell, WinSystem, restrict_dll_search};

    // First statement (ADR 0008, H2). Fail closed: without a console there is nobody to tell.
    if restrict_dll_search().is_err() {
        return ExitCode::FAILURE;
    }
    trace::start();
    #[cfg(feature = "test-key")]
    trace::log(|| match ui::process_age_ms() {
        Some(ms) => {
            format!("main: entered {ms:.1} ms after the process was created (loader, scan)")
        }
        None => "main: entered".to_owned(),
    });
    // Rule 6, before any window (security review S1 of P5-3): Slint reads font settings from
    // the environment when it creates the window, so an elevated or undeterminable process
    // stops here with a plain message box and never creates one. The worker's guard checks
    // again for every job.
    let lang = ui::lang();
    let settings = match WinSystem::new() {
        Err(_) => {
            ui::refuse_start(lang, false);
            return ExitCode::FAILURE;
        }
        Ok(sys) => {
            if rerun_core::exec::standard_user(&sys).is_err() {
                ui::refuse_start(lang, true);
                return ExitCode::FAILURE;
            }
            // The guard checks the elevation again; no download, so no HTTPS.
            let install = install_dir();
            settings::at_start(Env {
                sys: &sys,
                http: &NoHttp,
                install: &install,
            })
        }
    };
    crate::trace::log(|| "main: settings read".to_owned());
    // The window fills the slot with its handle once it exists: the UAC dialog of a helper start
    // belongs to the window (P5-5c), not to a console the app does not have.
    // The same slot owns Windows' dialogs of a link or the data folder (P5-10a): a missing
    // browser association asks in front of the window.
    ui::run(settings, |owner| {
        let shell = WinShell::new(owner.clone());
        let sys = WinSystem::new()
            .map_err(|e| vm::shown_error(&e))?
            .with_prompt_owner_slot(owner);
        Ok(worker::World {
            sys: Box::new(sys),
            http: Box::new(WinHttp::new()),
            shell: Arc::new(shell),
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
