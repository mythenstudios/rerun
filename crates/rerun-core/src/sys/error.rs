//! Error type of the system layer.

use std::fmt;
use std::io;
use std::path::Path;

use crate::escape;

/// Kind of a system error, modelled on the Win32 error codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SysErrorKind {
    /// File, directory, key or value does not exist (also: parent directory missing).
    NotFound,
    /// Target already exists.
    AlreadyExists,
    /// Access denied (e.g. read-only file, directory instead of file).
    AccessDenied,
    /// Directory or key is not empty.
    NotEmpty,
    /// Invalid path (e.g. relative, `.`/`..`, not a directory).
    InvalidPath,
    /// Path goes through a reparse point (symlink, junction) or an entry with an unknown
    /// reparse tag; it is not followed.
    ReparsePoint,
    /// File is locked by another process (sharing violation).
    Busy,
    /// Operation is not supported (e.g. writes into a case-sensitive directory).
    Unsupported,
    /// In-place change of a file with more than one hard link (ADR 0007).
    Linked,
    /// An expected hash or file ID differs (ADR 0017). Nothing was changed.
    Mismatch,
    /// Other error.
    Other,
}

impl fmt::Display for SysErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotFound => "not found",
            Self::AlreadyExists => "already exists",
            Self::AccessDenied => "access denied",
            Self::NotEmpty => "not empty",
            Self::InvalidPath => "invalid path",
            Self::ReparsePoint => "reparse point",
            Self::Busy => "busy",
            Self::Unsupported => "unsupported",
            Self::Linked => "file has more than one hard link",
            Self::Mismatch => "not the expected content or file",
            Self::Other => "other error",
        })
    }
}

/// Error of the system layer.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{kind}: {target}")]
pub struct SysError {
    /// Error kind.
    pub kind: SysErrorKind,
    /// Affected path or key, human-readable. Never raw text from the system: a target with a
    /// control or an invisible/confusable character ([`escape::path`]) is stored escaped
    /// (`{:?}`), see [`shown_target`]. Build errors with [`SysError::new`] or
    /// [`SysError::path`], which apply it.
    pub target: String,
    /// Original Win32 error code, if any.
    pub win32: Option<u32>,
    /// Original `NTSTATUS`, if any (from `NtCreateFile` and friends).
    pub ntstatus: Option<i32>,
    /// Original `HRESULT`, if any (from `SHGetKnownFolderPath`).
    pub hresult: Option<i32>,
}

impl SysError {
    /// New error without a Win32 code. `target` goes through [`shown_target`].
    pub fn new(kind: SysErrorKind, target: impl Into<String>) -> Self {
        Self {
            kind,
            target: shown_target(target.into()),
            win32: None,
            ntstatus: None,
            hresult: None,
        }
    }

    /// New error for a path.
    pub fn path(kind: SysErrorKind, path: &Path) -> Self {
        Self::new(kind, path.display().to_string())
    }

    /// From an `io::Error` of a read on a handle (`Read` of a [`Dir::open_read`] reader).
    /// The raw OS error, a Win32 code from `ReadFile` on Windows, is kept in
    /// [`Self::win32`] and classified like every Win32 code of `sys` (sharing or lock
    /// violation `Busy`, access denied `AccessDenied`, …); an error without one (from a test
    /// reader) is classified by its [`io::ErrorKind`]. The message is never kept.
    ///
    /// [`Dir::open_read`]: crate::sys::Dir::open_read
    pub fn io(e: &io::Error, target: impl Into<String>) -> Self {
        match e.raw_os_error() {
            Some(raw) => {
                let code = raw.cast_unsigned();
                Self::new(kind_of_win32(code), target).with_win32(code)
            }
            None => Self::new(kind_of_io(e.kind()), target),
        }
    }

    /// Attaches the original Win32 code.
    #[must_use]
    pub fn with_win32(mut self, code: u32) -> Self {
        self.win32 = Some(code);
        self
    }

    /// Attaches the original `NTSTATUS`.
    #[must_use]
    pub fn with_ntstatus(mut self, status: i32) -> Self {
        self.ntstatus = Some(status);
        self
    }

    /// Attaches the original `HRESULT`.
    #[must_use]
    pub fn with_hresult(mut self, hr: i32) -> Self {
        self.hresult = Some(hr);
        self
    }
}

/// Classifies a Win32 error code (winerror.h).
pub(crate) fn kind_of_win32(code: u32) -> SysErrorKind {
    match code {
        // FILE_NOT_FOUND, PATH_NOT_FOUND
        2 | 3 => SysErrorKind::NotFound,
        // ACCESS_DENIED, WRITE_PROTECT
        5 | 19 => SysErrorKind::AccessDenied,
        // INVALID_NAME, BAD_PATHNAME, FILENAME_EXCED_RANGE, DIRECTORY
        123 | 161 | 206 | 267 => SysErrorKind::InvalidPath,
        // CANT_ACCESS_FILE, CANT_RESOLVE_FILENAME
        1920 | 1921 => SysErrorKind::ReparsePoint,
        // SHARING_VIOLATION, LOCK_VIOLATION
        32 | 33 => SysErrorKind::Busy,
        // FILE_EXISTS, ALREADY_EXISTS
        80 | 183 => SysErrorKind::AlreadyExists,
        // DIR_NOT_EMPTY
        145 => SysErrorKind::NotEmpty,
        // INVALID_FUNCTION, NOT_SUPPORTED
        1 | 50 => SysErrorKind::Unsupported,
        _ => SysErrorKind::Other,
    }
}

/// Classifies an `io::Error` without an OS error code.
fn kind_of_io(kind: io::ErrorKind) -> SysErrorKind {
    match kind {
        io::ErrorKind::NotFound => SysErrorKind::NotFound,
        io::ErrorKind::PermissionDenied => SysErrorKind::AccessDenied,
        io::ErrorKind::AlreadyExists => SysErrorKind::AlreadyExists,
        io::ErrorKind::Unsupported => SysErrorKind::Unsupported,
        _ => SysErrorKind::Other,
    }
}

/// `target` as it is if it holds no escapable character, otherwise escaped with
/// [`escape::path`] (ADR 0016): `{:?}`-quoted, and every control, format, default-ignorable,
/// noncharacter, private use or confusable character
/// ([`is_deceptive`](crate::path::is_deceptive)) as `\u{…}`. Idempotent. So a raw name from
/// disk or the registry (a U+202E in a file name, an embedded newline, tag characters) never
/// reaches a message unescaped, whichever error path carries it.
pub fn shown_target(target: String) -> String {
    escape::path(&target).into_escaped().unwrap_or(target)
}

/// Result of a system operation.
pub type SysResult<T> = Result<T, SysError>;

#[cfg(test)]
mod tests {
    use std::io;
    use std::path::Path;

    use super::{SysError, SysErrorKind, shown_target};
    use crate::path::is_deceptive;
    use crate::sys::System;
    use crate::sys::fake::FakeSystem;

    fn clean(s: &str) -> bool {
        !s.chars()
            .any(|c| c.is_control() || is_deceptive(c) || crate::escape::in_base_set(c))
    }

    #[test]
    fn io_errors_keep_their_os_code() {
        for (code, kind) in [
            (32, SysErrorKind::Busy),
            (33, SysErrorKind::Busy),
            (5, SysErrorKind::AccessDenied),
            (23, SysErrorKind::Other),
        ] {
            let e = SysError::io(&io::Error::from_raw_os_error(code), "f.bin");
            assert_eq!(
                (e.kind, e.win32, e.target.as_str()),
                (kind, Some(code.cast_unsigned()), "f.bin"),
                "{code}"
            );
        }
        let e = SysError::io(&io::Error::new(io::ErrorKind::InvalidData, "SECRET"), "f");
        assert_eq!((e.kind, e.win32), (SysErrorKind::Other, None));
        assert!(!format!("{e} {e:?}").contains("SECRET"));
        let e = SysError::io(&io::Error::from(io::ErrorKind::PermissionDenied), "f");
        assert_eq!(e.kind, SysErrorKind::AccessDenied);
    }

    #[test]
    fn plain_targets_stay_as_they_are() {
        for t in [
            r"C:\Games\Some Game",
            r"steamapps\appmanifest_10.acf",
            "Straße ä",
            "",
        ] {
            assert_eq!(shown_target(t.to_owned()), t);
        }
    }

    #[test]
    fn control_and_deceptive_characters_are_escaped_once() {
        for raw in [
            "evil\u{202E}gpj.exe",
            "a\nb",
            "\u{1b}[31mred",
            "zero\u{200B}width",
            "x\u{2215}y",
            "nul\0",
            "tag\u{E0041}\u{E007F}",
            "line\u{2028}sep",
        ] {
            let e = SysError::new(SysErrorKind::Other, raw);
            assert_ne!(e.target, raw);
            assert!(clean(&e.target), "{:?}", e.target);
            assert!(clean(&e.to_string()), "{:?}", e.to_string());
            // Idempotent.
            assert_eq!(shown_target(e.target.clone()), e.target);
        }
        let p = SysError::path(SysErrorKind::NotFound, Path::new("C:\\a\u{202E}b"));
        assert_eq!(p.target, r#""C:\\a\u{202e}b""#);
    }

    #[test]
    #[expect(
        clippy::disallowed_methods,
        reason = "test of the fake system layer itself, not a root for game files"
    )]
    fn an_error_path_with_a_raw_name_carries_it_escaped() {
        // The fake has no rule against bidi characters in an absolute path: the open fails
        // with `NotFound`, and the target is escaped.
        let sys = FakeSystem::new();
        let e = sys
            .fs()
            .open_dir(Path::new("C:\\Games\\x\u{202E}y"))
            .unwrap_err();
        assert_eq!(e.kind, SysErrorKind::NotFound);
        assert!(clean(&e.to_string()), "{e}");
        assert!(e.target.contains(r"\u{202e}"), "{e}");
    }
}
