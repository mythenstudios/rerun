//! The CLI's side of elevation (ADR 0023 §2, §7, §10, §12): which token the process holds,
//! and one start of the elevated helper through the `runas` verb.
//!
//! `sys` reports facts only. [`Elevation::run_helper`] returns what it saw on the started
//! process ([`HelperProc`]: its image and whether its token is elevated, read on `hProcess`
//! right after the start and before the wait, A4 S2) next to the exit code; whether that makes
//! the code the helper's statement is decided by `elevate::judge`, which is pure. The UAC
//! prompt state (§10) is read through [`crate::sys::Registry`] by `elevate::prompt`; only the
//! token kind comes from here.
//!
//! The real one is `sys::win::WinElevation` (`ShellExecuteExW`, verb `runas`, the `HKLM`
//! `exefile` class key), the fake one `sys::fake::FakeElevation` (scripted). [`NoElevation`]
//! refuses everything (the helper's own system, §11, and test systems that never elevate).
//!
//! The owner of the UAC dialog (ADR 0023 amendment P5-5c) is a [`PromptOwner`]: an opaque window
//! handle value the caller hands to the system layer when it builds it
//! (`sys::win::WinSystem::with_prompt_owner`; the app passes its window, the CLI none, so its
//! console window stays the owner). Only `sys::win` turns it back into a window handle.

use super::{SysError, SysErrorKind, SysResult};
use crate::path::RootPath;

/// The window that owns the UAC dialog of a helper start (ADR 0023 amendment P5-5c): the raw
/// value of a top-level window handle (`HWND`), opaque everywhere but in `sys::win`, which
/// passes it as `SHELLEXECUTEINFOW::hwnd`. Never null (`from_raw(0)` is `None`).
///
/// A window handle is an index into the window manager's table, not a pointer: Windows checks
/// it on every use, so a stale value (the window closed meanwhile) can at worst name no window
/// or, after reuse, another one; the dialog is then not placed in front of Rerun's window. It is
/// never read as memory. The app keeps its window open while a helper runs (closing is refused
/// during a write), so the value names that window for the whole start.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PromptOwner(isize);

impl PromptOwner {
    /// The owner from a raw window handle value; `None` for 0 (no window).
    pub const fn from_raw(raw: isize) -> Option<Self> {
        if raw == 0 { None } else { Some(Self(raw)) }
    }

    /// The raw window handle value.
    pub const fn raw(self) -> isize {
        self.0
    }
}

/// What the process token is (`TokenElevation`, `TokenElevationType`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenKind {
    /// Elevated (an administrator's full token, also with UAC off or the built-in
    /// Administrator): the CLI refuses to work then (ADR 0018 S2, P2-13 E3).
    Elevated,
    /// The filtered token of an administrator in admin approval mode
    /// (`TokenElevationTypeLimited`): `ConsentPromptBehaviorAdmin` applies.
    Filtered,
    /// Any other token that is not elevated: a standard user (`ConsentPromptBehaviorUser`
    /// applies; with an administrator's password this is over-the-shoulder elevation).
    Standard,
}

/// What the CLI read on the started process's handle before it waited (ADR 0023 §7, A4 S2).
/// `None` = could not be read: never trusted, `elevate::judge` makes the run `Unknown`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelperProc {
    /// `QueryFullProcessImageNameW(PROCESS_NAME_NATIVE)` of the started process: its NT name
    /// (`\Device\HarddiskVolumeN\…`), readable also after it exited. Compared (folded) with the
    /// NT name of the pre-checked image ([`crate::sys::SdFacts::nt_name`]).
    pub image: Option<String>,
    /// `TokenElevation` of its token (`OpenProcessToken(TOKEN_QUERY)` on `hProcess`).
    pub elevated: Option<bool>,
}

/// One start of the helper.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HelperRun {
    /// A process was started and has exited with `code`; `proc` is what was read on it.
    Exited {
        /// `GetExitCodeProcess`.
        code: u32,
        /// The process facts read before the wait.
        proc: HelperProc,
    },
    /// The UAC prompt was declined (`ERROR_CANCELLED`, 1223): nothing was started.
    Declined,
    /// The start succeeded, but there is no result: no process handle came back, or the wait
    /// or the exit code failed (P4-2d review follow-up). A process may have run and may still
    /// run, so this is never "not started": `elevate::judge` makes it `Unknown`.
    Lost {
        /// What failed, with its Win32 code.
        why: crate::sys::SysError,
    },
}

/// Processes of the helper image ([`Elevation::helper_running`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HelperPresence {
    /// None runs.
    None,
    /// A process of exactly that image runs.
    Running,
    /// A process of that file name runs whose image cannot be asked.
    Unaskable,
}

/// The helper's instance lock ([`Elevation::helper_lock`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HelperLock {
    /// The mutex does not exist.
    Free,
    /// It exists; its owner SID if it could be read.
    Held {
        /// The owner SID (`S-1-…`), `None` if unreadable.
        owner: Option<String>,
    },
}

/// Elevation, CLI side (ADR 0023 §12).
pub trait Elevation: Send + Sync {
    /// The kind of this process's token.
    ///
    /// # Errors
    /// The token cannot be read.
    fn token_kind(&self) -> SysResult<TokenKind>;

    /// Starts `image` (the canonical path `policy::root::helper_image` checked) elevated
    /// through the `runas` verb with `args`, in the image's folder, waits without a timeout
    /// (the user may take long with the prompt) and returns the exit code with the process
    /// facts read before the wait. Every argument must be [`is_plain_arg`] (`InvalidPath`
    /// otherwise, nothing started): they are joined by single spaces without any quoting.
    ///
    /// Only `elevate` calls this (`clippy.toml`; from P4-2c).
    ///
    /// # Errors
    /// Only when **no process was created**: an argument is not plain, or the start fails for
    /// another reason than a declined prompt (the Win32 code in the error). Once the start
    /// succeeded, a missing process handle and a failed wait or exit code are
    /// [`HelperRun::Lost`], never an error (P4-2d review follow-up: a helper may be running).
    fn run_helper(&self, image: &RootPath, args: &[&str]) -> SysResult<HelperRun>;

    /// Whether a process of the helper image runs now (A4 S8): before the CLI observes a batch
    /// that has no result yet, a helper of an earlier run may still be working. `nt_name` is
    /// the NT name the pre-check read on the installed file ([`crate::sys::SdFacts::nt_name`]).
    /// Every process whose file name is the last segment of `nt_name` is asked for its image
    /// (`QueryFullProcessImageNameW(PROCESS_NAME_NATIVE)`, compared folded); one that cannot be
    /// opened or asked is [`HelperPresence::Unaskable`] (the caller fails closed, with its own
    /// wording: it may be interference, not a helper). A check at a moment, not a lock: the
    /// helper's own instance lock keeps two helpers apart ([`Self::helper_lock`]).
    ///
    /// # Errors
    /// The process list cannot be read.
    fn helper_running(&self, nt_name: &str) -> SysResult<HelperPresence>;

    /// Whether the helper's instance lock (the named mutex of A4 S8) exists now, and its owner
    /// if it can be read (`READ_CONTROL`; a genuine helper's mutex belongs to Administrators and
    /// is usually unreadable for a non-elevated process).
    ///
    /// # Errors
    /// The open fails for another reason than "not found" or "access denied".
    fn helper_lock(&self) -> SysResult<HelperLock>;
}

/// An argument of the helper's command line: non-empty, printable ASCII without a space or a
/// `"`, so joining by spaces is the exact command line (the request form of §3 step 5 needs
/// nothing else: a GUID, hex digits, a request name).
pub fn is_plain_arg(a: &str) -> bool {
    !a.is_empty() && a.bytes().all(|b| b.is_ascii_graphic() && b != b'"')
}

/// The `lpParameters` for `args`, or `InvalidPath` if one is not [`is_plain_arg`].
///
/// # Errors
/// An argument that is not plain (its position is in the target).
pub fn parameters(args: &[&str]) -> SysResult<String> {
    if let Some(i) = args.iter().position(|a| !is_plain_arg(a)) {
        return Err(SysError::new(
            SysErrorKind::InvalidPath,
            format!("helper argument {i}"),
        ));
    }
    Ok(args.join(" "))
}

/// Refuses everything (`Unsupported`): the helper's own system (no nested elevation, §11) and
/// test systems that never elevate.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoElevation;

impl Elevation for NoElevation {
    fn token_kind(&self) -> SysResult<TokenKind> {
        Err(SysError::new(SysErrorKind::Unsupported, "token kind"))
    }

    fn run_helper(&self, image: &RootPath, _: &[&str]) -> SysResult<HelperRun> {
        Err(SysError::new(
            SysErrorKind::Unsupported,
            format!("{image}: no elevation here"),
        ))
    }

    fn helper_running(&self, _: &str) -> SysResult<HelperPresence> {
        Err(SysError::new(
            SysErrorKind::Unsupported,
            "helper process check: no elevation here",
        ))
    }

    fn helper_lock(&self) -> SysResult<HelperLock> {
        Err(SysError::new(
            SysErrorKind::Unsupported,
            "helper lock: no elevation here",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::{Elevation, NoElevation, PromptOwner, is_plain_arg, parameters};
    use crate::path::RootPath;
    use crate::sys::SysErrorKind;

    #[test]
    fn elevation_is_an_object_safe_send_sync_trait() {
        fn assert_send_sync<T: ?Sized + Send + Sync>() {}
        assert_send_sync::<dyn Elevation>();
    }

    #[test]
    fn a_prompt_owner_is_never_null() {
        assert_eq!(PromptOwner::from_raw(0), None);
        let o = PromptOwner::from_raw(0x0001_0a2c).unwrap();
        assert_eq!(o.raw(), 0x0001_0a2c);
        assert_eq!(PromptOwner::from_raw(-2).map(PromptOwner::raw), Some(-2));
    }

    #[test]
    fn only_plain_arguments_reach_the_command_line() {
        for ok in ["--volume", "{0f}", "00000001-0000000000000abc-1.req", "a=b"] {
            assert!(is_plain_arg(ok), "{ok}");
        }
        for bad in ["", "a b", "\"x", "a\tb", "é", "a\nb", "a\u{0}"] {
            assert!(!is_plain_arg(bad), "{bad:?}");
        }
        assert_eq!(parameters(&["--dir", "ab"]).unwrap(), "--dir ab");
        assert_eq!(parameters(&[]).unwrap(), "");
        let e = parameters(&["ok", "not ok"]).unwrap_err();
        assert_eq!(e.kind, SysErrorKind::InvalidPath);
        assert!(e.to_string().contains("argument 1"), "{e}");
    }

    #[test]
    fn no_elevation_refuses() {
        let image = RootPath::new(r"C:\Program Files\Rerun\rerun-helper.exe").unwrap();
        #[expect(
            clippy::disallowed_methods,
            reason = "test: the refusing implementation"
        )]
        let run = NoElevation.run_helper(&image, &[]);
        assert_eq!(run.unwrap_err().kind, SysErrorKind::Unsupported);
        assert_eq!(
            NoElevation.token_kind().unwrap_err().kind,
            SysErrorKind::Unsupported
        );
        assert_eq!(
            NoElevation.helper_running("x").unwrap_err().kind,
            SysErrorKind::Unsupported
        );
        assert_eq!(
            NoElevation.helper_lock().unwrap_err().kind,
            SysErrorKind::Unsupported
        );
    }
}
