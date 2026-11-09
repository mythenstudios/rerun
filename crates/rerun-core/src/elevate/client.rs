//! The CLI's side of one helper run (ADR 0023 §2, §7, A4 S2, S8), without the journal: `exec`
//! (P4-2d) writes the request file under the journal lock and records the batch around these
//! calls; the batch size it passes to [`start`] is the request's `Request::op_count`.
//!
//! - [`start`]: the helper's command line for a written request ([`RequestRef::to_args`]), the
//!   one start through [`Elevation::run_helper`] and [`judge`] of what came back.
//! - [`ensure_idle`] (A4 S8): before the CLI observes a batch that has no result yet (a crash or
//!   Ctrl+C during an earlier run), no process of the pre-checked helper image may run and the
//!   helper's instance lock must be free, else a revert would observe `Before`, close the
//!   transaction, and the old helper could still add its rule afterwards. `Busy` otherwise, with
//!   an honest diagnosis (security review S1): a process of the helper's name that cannot be
//!   asked, or a lock owned by an account that is not Administrators or SYSTEM, is probably
//!   interference by another program, not a running helper. A same-user process can cause this
//!   on purpose: a denial of service, never a privilege gain (ADR 0023 §3, docs/06 #19).

use super::judge::{Judged, judge};
use super::request::RequestRef;
use crate::policy::root::{ADMIN_SIDS, HelperImage};
use crate::sys::{Elevation, HelperLock, HelperPresence, SysError, SysErrorKind, SysResult};

/// Starts the pre-checked helper `image` for the request `at` (its SHA-256 `sha256`, a batch of
/// `batch` ops) and judges the run.
///
/// # Errors
/// The start fails for another reason than a declined prompt.
pub fn start(
    elevation: &dyn Elevation,
    image: &HelperImage,
    at: &RequestRef,
    sha256: &[u8; 32],
    batch: usize,
) -> SysResult<Judged> {
    let args = at.to_args(sha256);
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    #[expect(
        clippy::disallowed_methods,
        reason = "ADR 0023 §2: elevate is the one place that starts the helper"
    )]
    let run = elevation.run_helper(&image.path, &args)?;
    Ok(judge(&run, image, batch))
}

fn busy(why: String) -> SysError {
    SysError::new(SysErrorKind::Busy, why)
}

/// `Ok` if no helper process of `image` runs and the helper's lock is free (module docs).
///
/// # Errors
/// `Busy` with the diagnosis; the error of the process list or of the lock.
pub fn ensure_idle(elevation: &dyn Elevation, image: &HelperImage) -> SysResult<()> {
    match elevation.helper_running(&image.nt_name)? {
        HelperPresence::None => {}
        HelperPresence::Running => {
            return Err(busy(format!(
                "{} still runs from an earlier run; wait until it ends, then try again",
                image.path
            )));
        }
        HelperPresence::Unaskable => {
            return Err(busy(
                "a process named rerun-helper.exe runs that Rerun cannot inspect: likely another \
                 program interfering, not a running helper; end it or sign out, then try again"
                    .to_owned(),
            ));
        }
    }
    match elevation.helper_lock()? {
        HelperLock::Free => Ok(()),
        HelperLock::Held { owner: Some(sid) } if !ADMIN_SIDS.contains(&sid.as_str()) => {
            Err(busy(format!(
                "a non-administrator process ({sid}) holds the helper's lock: likely \
                 interference, not a running helper; sign out or restart Windows to clear it"
            )))
        }
        HelperLock::Held { .. } => Err(busy(
            "the helper's lock is held by an administrator process; wait until it ends, then try \
             again"
                .to_owned(),
        )),
    }
}
