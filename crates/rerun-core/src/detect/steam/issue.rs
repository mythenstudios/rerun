//! Issues of the Steam scan (ADR 0012). The scan never fails as a whole: every problem is an
//! [`Issue`] with a [`Location`], and the scan goes on with what is left.
//!
//! Issues never contain file or registry content other than paths and names the user has to
//! see: raw ones only escaped (`{:?}`, as `PathError` and `Anomaly` do), paths that passed
//! `RootPath` or `RelPath` as they are. Output layers sanitize further.

use std::fmt;

use super::root::RootSource;
use crate::path::RootPath;
use crate::policy::root::RootError;
use crate::sys::SysError;

/// One problem found by the scan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Issue {
    /// Where.
    pub at: Location,
    /// What.
    pub kind: IssueKind,
}

impl fmt::Display for Issue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.at, self.kind)
    }
}

/// Where an issue was found.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Location {
    /// A registry candidate for the Steam root.
    Registry(RootSource),
}

impl fmt::Display for Location {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Registry(source) => write!(f, "{source}"),
        }
    }
}

/// Why a registry value is not used as a path. Never contains the value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum BadValue {
    /// The string is empty.
    Empty,
    /// `REG_EXPAND_SZ` with `%`: Rerun never expands it.
    Unexpanded,
    /// Not a string type.
    NotAString {
        /// The registry type number.
        kind: u32,
    },
    /// A string type whose bytes are not UTF-16LE text (odd length, NUL inside, lone
    /// surrogate).
    InvalidString,
}

impl fmt::Display for BadValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("empty value"),
            Self::Unexpanded => f.write_str("REG_EXPAND_SZ with '%' (never expanded)"),
            Self::NotAString { kind } => write!(f, "registry type {kind}, not a string"),
            Self::InvalidString => f.write_str("not valid UTF-16 text"),
        }
    }
}

/// What went wrong.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum IssueKind {
    /// Error of the system layer (reading a registry value, opening or listing a folder).
    #[error(transparent)]
    Sys(SysError),
    /// A root (Steam folder, library) was refused. Boxed: by far the largest error.
    #[error(transparent)]
    Root(Box<RootError>),
    /// A registry value is not usable as a path.
    #[error("{0}")]
    RegistryValue(BadValue),
    /// A later registry candidate opens a different folder than the Steam root. Not scanned.
    #[error("opens {other}, not the Steam root {root} (from {winner}); not scanned")]
    RootsDisagree {
        /// The candidate that became the root.
        winner: RootSource,
        /// The Steam root.
        root: RootPath,
        /// The folder this candidate opens.
        other: RootPath,
    },
}
