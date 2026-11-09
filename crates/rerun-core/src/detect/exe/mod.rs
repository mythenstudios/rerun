//! Executable candidates of a game folder (ADR 0014).
//!
//! Store-agnostic: everything here takes a [`GameDir`](crate::policy::root::GameDir), never a
//! bare `Dir`. No new `sys` method, no `unsafe`, no recursion.
//!
//! - [`walk()`]: the bounded breadth-first listing of the game folder ([`ExeLimits`]); every
//!   directory opened relative to the game handle, every listing sorted by folded name, every
//!   name through `policy::path::classify`, reparse points and restricted entries reported
//!   and never followed. A limit keeps a partial result ([`WalkStats::complete`]).
//! - `api`: the graphics API from the imported DLL names (an [`ApiReport`]);
//!   [`GraphicsApi::topo_name`] maps to the Topo `api` values.
//! - `role`, `rank`: a [`Role`] per candidate from fixed name rules and PE facts (hints,
//!   nothing is dropped), and the ranking that names the main executable ([`Main`]).
//! - [`scan_game`]: all of it for one game ([`GameExes`], owns everything);
//!   [`inspect_exe`]: the per-file pipeline, also for Topo matching.
//! - `hash`: with `--hashes` ([`Options::hashes`]), streaming SHA-1 and SHA-256 of the best
//!   `Game` candidates on the very handle that was parsed ([`HashLimits`], [`HashOutcome`]).
//! - [`anti_cheat`]: markers of anti-cheat systems from a fixed table with sources (P4-4,
//!   user decision E4); the Topo engine refuses or warns by them.
//! - Problems of the walk are [`ExeIssue`]s; they never carry file content, raw names only
//!   escaped. Problems of a file stay on its [`Candidate`].

pub mod anti_cheat;
mod api;
mod hash;
mod issue;
mod rank;
mod role;
mod scan;
mod walk;

pub use anti_cheat::{AntiCheat, AntiCheatHit, AntiCheatScan};
pub use api::{
    ApiEvidence, ApiReport, ApiSet, ApiVerdict, Basis, Engine, GraphicsApi, Source, TableEvidence,
};
pub use hash::{HashError, HashLimits, HashOutcome, HashSkip, Hashes, MAX_CHUNK_BYTES};
pub use issue::{ExeIssue, ExeIssueKind, LimitKind};
pub use role::Role;
pub use scan::{Candidate, ExeError, ExeFacts, GameExes, Main, Options, inspect_exe, scan_game};
pub use walk::{Walk, WalkStats, WalkedExe, walk};

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
    /// Bounds of the hashing (`--hashes` only).
    pub hash: HashLimits,
}

impl ExeLimits {
    /// The shipped limits (ADR 0014, user decision 5).
    pub const DEFAULT: Self = Self {
        max_depth: 3,
        max_dirs: 128,
        max_entries: 20_000,
        max_exes: 64,
        pe: pe::Limits::DEFAULT,
        hash: HashLimits::DEFAULT,
    };
}
