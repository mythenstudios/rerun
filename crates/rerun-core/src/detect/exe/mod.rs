//! Executable candidates of a game folder (ADR 0014).
//!
//! Store-agnostic: everything here takes a [`GameDir`](crate::policy::root::GameDir), never a
//! bare `Dir`. No new `sys` method, no `unsafe`, no recursion.
//!
//! - [`walk()`]: the bounded breadth-first listing of the game folder ([`ExeLimits`]); every
//!   directory opened relative to the game handle, every listing sorted by folded name, every
//!   name through `policy::path::classify`, reparse points and restricted entries reported
//!   and never followed. A limit keeps a partial result ([`WalkStats::complete`]).
//! - Problems of the walk are [`ExeIssue`]s; they never carry file content, raw names only
//!   escaped.

mod issue;
mod walk;

pub use issue::{ExeIssue, ExeIssueKind, LimitKind};
pub use walk::{SKIP_DIRS, Walk, WalkStats, WalkedExe, walk};

use crate::detect::pe;

/// Bounds of one game scan. A value of exactly the limit is accepted (ADR 0014, "Walk").
/// The numbers are provisional until the developer-machine dump (ADR 0014).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ExeLimits {
    /// Directory levels below the game folder that are listed (the game folder is level 0).
    pub max_depth: usize,
    /// Directories listed (or attempted), the game folder included.
    pub max_dirs: usize,
    /// Entries across all listings.
    pub max_entries: usize,
    /// Candidates opened and parsed, the first ones in walk order.
    pub max_exes: usize,
    /// Bounds of the parser for each candidate.
    pub pe: pe::Limits,
}

impl ExeLimits {
    /// The shipped limits (ADR 0014, user decision 5).
    pub const DEFAULT: Self = Self {
        max_depth: 3,
        max_dirs: 128,
        max_entries: 20_000,
        max_exes: 64,
        pe: pe::Limits::DEFAULT,
    };
}
