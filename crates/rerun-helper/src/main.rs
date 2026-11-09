//! `rerun-helper.exe`, the elevated helper (ADR 0023): started by `rerun apply` or
//! `rerun revert` through the `runas` verb, at most once per run, for one batch of Rerun's own
//! firewall rules; it re-validates everything itself and reports only through its exit code
//! (§7). No console (an elevated process cannot attach to the user's), no output, no files.
//!
//! P4-2a, the scaffold: `restrict_dll_search` first (ADR 0008, H2), then
//! `rerun_core::elevate::serve` with the process's own token: privileges dropped, elevation
//! required, every argument list refused (`Refused(Usage)`). No `System` yet: the helper's
//! own one (`WinHelperSystem`, no GPU, no registry) comes with P4-2c, and this crate never
//! names `WinSystem` or `WinGpu` (`tests/source_rules.rs`).

#![windows_subsystem = "windows"]

// The published index test key is for the [SB] and [DEV] helper only (ADR 0023 §2, A4 S3).
#[cfg(all(feature = "test-key", not(debug_assertions)))]
compile_error!(
    "the feature test-key (the published index test key) is for test builds only, never with \
     optimisation without debug assertions (ADR 0023 §2, ADR 0024)"
);

#[cfg(windows)]
fn main() {
    use rerun_core::elevate::{HelperExit, Reason, serve};
    use rerun_core::sys::win::{WinHelperToken, restrict_dll_search};

    // First statement (ADR 0008, H2; ADR 0023 §3 step 1). Fail closed.
    let exit = if restrict_dll_search().is_err() {
        HelperExit::refused(Reason::Internal)
    } else {
        // The arguments are read only after the privileges are dropped and the elevation checked.
        serve(&WinHelperToken, || std::env::args_os().skip(1).collect())
    };
    // Every code is below 0x8000_0000 (magic 0x52), so the cast keeps its bits.
    std::process::exit(exit.to_code().cast_signed());
}

#[cfg(not(windows))]
fn main() {
    // The helper exists on Windows only; elsewhere the crate builds for `cargo check` and
    // `cargo deny` alone.
    std::process::exit(2);
}
