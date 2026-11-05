//! Issues of the exe scan (ADR 0014, "Layers"). The scan never fails as a whole: every problem
//! of the walk is an [`ExeIssue`] relative to the game folder, and the scan goes on.
//!
//! Issues never contain file content: raw names only escaped (`{:?}`, as [`Anomaly`] and
//! [`SysError`] do), `RelPath`s as they are (a valid `RelPath` holds no control, bidi or
//! confusable character). Output layers sanitize further.

use std::fmt;

use crate::path::{Anomaly, RelPath};
use crate::sys::SysError;
use crate::sys::fs::EntryKind;

/// One problem of the exe scan of a game.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExeIssue {
    /// Where, relative to the game folder; `None` is the game folder itself. For an anomalous
    /// name it is the folder that holds it.
    pub at: Option<RelPath>,
    /// What.
    pub kind: ExeIssueKind,
}

impl fmt::Display for ExeIssue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.at {
            Some(p) => write!(f, "{p}: {}", self.kind),
            None => write!(f, "game folder: {}", self.kind),
        }
    }
}

/// The limit that stopped the walk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum LimitKind {
    /// [`super::ExeLimits::max_dirs`].
    Dirs,
    /// [`super::ExeLimits::max_entries`].
    Entries,
}

impl fmt::Display for LimitKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Dirs => "listed directories",
            Self::Entries => "directory entries",
        })
    }
}

/// What went wrong.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ExeIssueKind {
    /// Opening, asking or listing a directory failed. Its target names the folder.
    #[error(transparent)]
    Sys(SysError),
    /// A name that is no valid path segment (or would make the path too long); never opened.
    #[error(transparent)]
    Anomaly(Anomaly),
    /// A case-sensitive directory: two names could fold to one path, so none of its entries
    /// is used.
    #[error("case-sensitive directory; its entries are not used")]
    CaseSensitiveDir,
    /// A reparse point (junction, symlink, unknown tag), or a restricted directory or
    /// executable. Never followed or opened.
    #[error("{}", not_followed(*.kind, *.restricted))]
    NotFollowed {
        /// Kind of the entry.
        kind: EntryKind,
        /// The entry denies the current user every open.
        restricted: bool,
    },
    /// The walk stopped at a limit; the list is incomplete.
    #[error("walk stopped after {max} {limit}; the list of executables is incomplete")]
    WalkLimit {
        /// The limit.
        limit: LimitKind,
        /// Its value.
        max: usize,
    },
    /// More candidates than are parsed; only the first ones in walk order are kept.
    #[error("{found} executables found; only the first {max} in walk order are inspected")]
    TooManyExes {
        /// Candidates found.
        found: usize,
        /// The limit.
        max: usize,
    },
}

fn not_followed(kind: EntryKind, restricted: bool) -> String {
    let what = match kind {
        EntryKind::Reparse => "reparse point (junction, symlink or unknown tag)",
        EntryKind::Dir => "directory",
        EntryKind::File => "file",
    };
    if restricted {
        format!("restricted {what}; not followed")
    } else {
        format!("{what}; not followed")
    }
}
