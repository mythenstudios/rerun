//! Error type of the system layer.

use std::fmt;
use std::path::Path;

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
    /// Affected path or key, human-readable.
    pub target: String,
    /// Original Win32 error code, if any.
    pub win32: Option<u32>,
    /// Original `NTSTATUS`, if any (from `NtCreateFile` and friends).
    pub ntstatus: Option<i32>,
}

impl SysError {
    /// New error without a Win32 code.
    pub fn new(kind: SysErrorKind, target: impl Into<String>) -> Self {
        Self {
            kind,
            target: target.into(),
            win32: None,
            ntstatus: None,
        }
    }

    /// New error for a path.
    pub fn path(kind: SysErrorKind, path: &Path) -> Self {
        Self::new(kind, path.display().to_string())
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
}

/// Result of a system operation.
pub type SysResult<T> = Result<T, SysError>;
