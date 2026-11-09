//! The elevated helper's side of `rerun-core` (ADR 0023): its exit code and [`serve`], the
//! only entry `rerun-helper.exe` calls after `restrict_dll_search`.
//!
//! P4-2a (the scaffold, ADR 0023 §15): [`exit`] (the code layout of §7, strict decoding, A4
//! N4) and [`serve`] with the steps of §3 that need no file system: drop the privileges
//! (step 2), require elevation (step 3), then refuse every argument list (`Refused(Usage)`):
//! no request form is accepted yet.
//!
//! P4-2b: [`judge`](mod@judge) (is an exit code the helper's statement? A4 S2) and [`prompt`] (the UAC
//! prompt state, §10, N7), both pure over facts from `sys`; the system side (`open_by_id`,
//! `sd_facts`, `policy::root::helper_image`, `sys::Elevation`) is in place. The image check
//! (step 4), the request codec and the validation chain of §5 follow in P4-2c.
//!
//! `serve` never uses `exec`, `journal`, `hw`, `pkg`, `detect::steam`, `topo::when` or
//! `exec::standard_user` (§11); `crates/rerun-helper/tests/source_rules.rs` checks it.

pub mod exit;
pub mod judge;
pub mod prompt;

use std::ffi::OsString;

use crate::sys::HelperToken;
pub use exit::{ExitClass, HelperExit, OpResult, Reason};
pub use judge::{Judged, judge};
pub use prompt::{PromptKind, PromptState};

/// At most this many ops in one helper batch (§5 step 1); the exit code has a 2-bit slot for
/// each.
pub const MAX_BATCH_OPS: usize = 8;

/// Runs the helper (ADR 0023 §3) with its own token and returns its report. `args` reads the
/// arguments (without the program name); it is called only after the privileges are dropped
/// and the elevation is checked, so nothing of the caller is read before steps 2 and 3. Each step is fail closed: a privilege that cannot be dropped
/// or a token that cannot be read is `Refused(Internal)`, a token that is not elevated
/// `Refused(NotElevated)`. P4-2a: every argument list then ends in `Refused(Usage)`.
#[must_use]
pub fn serve(token: &dyn HelperToken, args: impl FnOnce() -> Vec<OsString>) -> HelperExit {
    // §3 step 2, before anything else reads input.
    if token.drop_privileges().is_err() {
        return HelperExit::refused(Reason::Internal);
    }
    // §3 step 3.
    match token.is_elevated() {
        Ok(true) => {}
        Ok(false) => return HelperExit::refused(Reason::NotElevated),
        Err(_) => return HelperExit::refused(Reason::Internal),
    }
    // §3 step 4 (P4-2b) and step 5 (P4-2c): no argument form is accepted yet, not even an
    // empty list.
    let _args = args();
    HelperExit::refused(Reason::Usage)
}

#[cfg(test)]
mod tests;
