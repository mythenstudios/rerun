//! Is the exit code the helper's statement? (ADR 0023 §7, A4 S2.) Pure.
//!
//! A same-user process cannot set the exit code of an elevated process, but the CLI does not
//! know by itself that the process it waited on *is* the elevated helper: a redirected start
//! runs another program, and a helper started without elevation can be ended by a same-user
//! process with any code. So the code counts only when, read on `hProcess` before the wait,
//! the image is the pre-checked helper and its token is elevated; anything else, also an
//! unreadable fact, is [`Judged::Unknown`], whatever the code says. A code that does not decode
//! strictly for the batch is `Unknown` as well.
//!
//! The image is compared in its NT form (`\Device\HarddiskVolumeN\…`, folded): the process
//! reports it with `QueryFullProcessImageNameW(PROCESS_NAME_NATIVE)`, which stays readable
//! after the process exited (the Win32 form does not), and the pre-check read the file's NT
//! name on the same handle as its security descriptor ([`HelperImage::nt_name`]).

use super::exit::HelperExit;
use crate::fold::fold;
use crate::policy::root::HelperImage;
use crate::sys::HelperRun;

/// What a helper run means to the CLI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Judged {
    /// The prompt was declined; nothing ran.
    Declined,
    /// The helper's own report.
    Exit(HelperExit),
    /// Not known what happened: the transaction stays open (§8).
    Unknown,
}

/// Judges `run` for the pre-checked `image` and a batch of `batch` ops (module docs).
pub fn judge(run: &HelperRun, image: &HelperImage, batch: usize) -> Judged {
    let (code, proc) = match run {
        HelperRun::Declined => return Judged::Declined,
        HelperRun::Exited { code, proc } => (*code, proc),
    };
    let same_image = proc
        .image
        .as_deref()
        .is_some_and(|i| fold(i) == fold(&image.nt_name));
    if !same_image || proc.elevated != Some(true) {
        return Judged::Unknown;
    }
    HelperExit::from_code(code, batch).map_or(Judged::Unknown, Judged::Exit)
}
