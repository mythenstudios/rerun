//! The CLI's side of one helper run (ADR 0023 §2, §7, A4 S2, S8), without the journal: `exec`
//! (P4-2d) writes the request file under the journal lock and records the batch around these
//! calls.
//!
//! - [`start`]: the helper's command line for a written request ([`RequestRef::to_args`]), the
//!   one start through [`Elevation::run_helper`] and [`judge`] of what came back.
//! - [`ensure_idle`] (A4 S8): before the CLI observes a batch that has no result yet (a crash or
//!   Ctrl+C during an earlier run), no process of the pre-checked helper image may run, else a
//!   revert would observe `Before`, close the transaction, and the old helper could still add
//!   its rule afterwards. `Busy` while one runs (or one cannot be told apart).

use super::judge::{Judged, judge};
use super::request::RequestRef;
use crate::policy::root::HelperImage;
use crate::sys::{Elevation, SysError, SysErrorKind, SysResult};

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

/// `Ok` if no helper process of `image` runs (module docs).
///
/// # Errors
/// `Busy` while one runs; the error of the process list.
pub fn ensure_idle(elevation: &dyn Elevation, image: &HelperImage) -> SysResult<()> {
    if elevation.helper_running(&image.nt_name)? {
        return Err(SysError::new(
            SysErrorKind::Busy,
            format!(
                "{} still runs from an earlier run; wait until it ends, then try again",
                image.path
            ),
        ));
    }
    Ok(())
}
