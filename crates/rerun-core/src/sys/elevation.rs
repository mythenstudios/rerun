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

use super::{SysError, SysErrorKind, SysResult};
use crate::path::RootPath;

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
    /// An argument is not plain; the start fails for another reason than a declined prompt
    /// (the Win32 code in the error); the wait or the exit code fails.
    fn run_helper(&self, image: &RootPath, args: &[&str]) -> SysResult<HelperRun>;

    /// Whether a process of the helper image runs now (A4 S8): before the CLI observes a batch
    /// that has no result yet, a helper of an earlier run may still be working. `nt_name` is
    /// the NT name the pre-check read on the installed file ([`crate::sys::SdFacts::nt_name`]).
    /// Every process whose file name is the last segment of `nt_name` is asked for its image
    /// (`QueryFullProcessImageNameW(PROCESS_NAME_NATIVE)`, compared folded); one that cannot be
    /// opened or asked counts as running (fail closed: it cannot be told apart). A check at a
    /// moment, not a lock: the helper's own instance lock keeps two helpers apart.
    ///
    /// # Errors
    /// The process list cannot be read.
    fn helper_running(&self, nt_name: &str) -> SysResult<bool>;
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

    fn helper_running(&self, _: &str) -> SysResult<bool> {
        Err(SysError::new(
            SysErrorKind::Unsupported,
            "helper process check: no elevation here",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::{Elevation, NoElevation, is_plain_arg, parameters};
    use crate::path::RootPath;
    use crate::sys::SysErrorKind;

    #[test]
    fn elevation_is_an_object_safe_send_sync_trait() {
        fn assert_send_sync<T: ?Sized + Send + Sync>() {}
        assert_send_sync::<dyn Elevation>();
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
    }
}
