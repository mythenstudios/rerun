//! Handing a link or a folder to the user's shell (ADR 0027 amendment P5-10a).
//!
//! `sys` is dumb and honest here too: [`Shell::open_url`] hands exactly the URL it is given to
//! the user's `https` handler (the default browser) and [`Shell::open_folder`] shows exactly the
//! folder in Explorer. What may be opened decides `policy::open`, which alone builds
//! [`OpenUrl`] and [`OpenFolder`]; the types are the only way in.
//!
//! The real one is `sys::win::WinShell` (`ShellExecuteExW`, verb `open`, no parameters, no
//! working directory, never waiting for what it started); the fake one `sys::fake::FakeShell`
//! records what it was asked to open. [`NoShell`] refuses everything (the CLI).
//!
//! `Shell` is deliberately **not** part of [`System`](super::System): the elevated helper's
//! system can never reach it, and only the app, which never runs elevated, holds one.

use super::{SysError, SysErrorKind, SysResult};
use crate::policy::open::{OpenFolder, OpenUrl};

/// The user's shell: the default browser and Explorer.
pub trait Shell: Send + Sync {
    /// The user's `https` handler opens `url`. Returns once it is started, never waits for it.
    fn open_url(&self, url: &OpenUrl) -> SysResult<()>;
    /// Explorer shows `folder`. Never opens or runs a file.
    fn open_folder(&self, folder: &OpenFolder) -> SysResult<()>;
}

/// No shell: every request is refused (`Unsupported`).
#[derive(Debug, Default, Clone, Copy)]
pub struct NoShell;

impl Shell for NoShell {
    fn open_url(&self, _url: &OpenUrl) -> SysResult<()> {
        Err(SysError::new(
            SysErrorKind::Unsupported,
            "no shell in this system",
        ))
    }

    fn open_folder(&self, _folder: &OpenFolder) -> SysResult<()> {
        Err(SysError::new(
            SysErrorKind::Unsupported,
            "no shell in this system",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::open::OwnLink;

    #[test]
    fn no_shell_refuses() {
        let e = NoShell
            .open_url(&OpenUrl::own(OwnLink::Repository))
            .unwrap_err();
        assert_eq!(e.kind, SysErrorKind::Unsupported);
    }

    #[test]
    fn shell_is_object_safe_send_and_sync() {
        fn assert_send_sync<T: ?Sized + Send + Sync>() {}
        assert_send_sync::<dyn Shell>();
    }
}
