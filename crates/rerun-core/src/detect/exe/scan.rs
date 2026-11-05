//! The exe scan of one game folder (ADR 0014, "Layers"): walk, inspect every candidate, roles,
//! ranking. Never fails as a whole.

use super::ExeLimits;
use super::api::{ApiReport, classify};
use super::issue::ExeIssue;
use super::rank::rank;
use super::role::{Role, name_role, similarity, stem, with_facts};
use super::walk::{WalkStats, walk};
use crate::detect::pe::{self, PeInfo, PeReadError, open_game_exe};
use crate::path::RelPath;
use crate::policy::root::GameDir;

/// What the scan of one game is asked to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Options {
    /// The install folder name (Steam's `installdir`), for roles and ranking.
    pub name_hint: Option<RelPath>,
    /// The bounds.
    pub limits: ExeLimits,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            name_hint: None,
            limits: ExeLimits::DEFAULT,
        }
    }
}

/// An executable could not be inspected. Names the file, never its content.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ExeError {
    /// Opening, parsing or reading it failed (`Legacy` formats are a `Parse` error).
    #[error(transparent)]
    Pe(#[from] PeReadError),
}

/// What [`inspect_exe`] found in one executable. Owns everything, holds no handle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExeFacts {
    /// Headers, imports, delay imports, version resource.
    pub info: PeInfo,
    /// The graphics API from the imports.
    pub api: ApiReport,
    /// Bytes the parser read.
    pub bytes_read: u64,
}

/// One executable of the game folder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    /// The file, relative to the game folder.
    pub path: RelPath,
    /// Level of the folder that holds it (0: the game folder).
    pub depth: usize,
    /// Length as the walk's listing reported it (a hint, not a fact of the file).
    pub listed_len: u64,
    /// Similarity of its stem to the install folder hint (0 to 2).
    pub similarity: u8,
    /// Its role (a hint; nothing is dropped by role).
    pub role: Role,
    /// What inspecting it found, or why that failed.
    pub facts: Result<ExeFacts, ExeError>,
}

/// The main executable, as indices into [`GameExes::candidates`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Main {
    /// Exactly one `Game` candidate ranks first.
    One(usize),
    /// Several `Game` candidates share the best rank (a DX9 and a DX10 executable), in path
    /// order.
    Tied(Vec<usize>),
    /// No `Game` candidate that parsed.
    None,
}

/// The exe scan of one game. Owns everything and borrows nothing, so the [`GameDir`] can be
/// dropped right after the scan. `Debug` never shows file content (version strings are
/// `RawText`, raw names escaped).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GameExes {
    /// Every candidate, ranked.
    pub candidates: Vec<Candidate>,
    /// The main executable.
    pub main: Main,
    /// What the walk did.
    pub stats: WalkStats,
    /// Every problem of the walk, in the order it was found.
    pub issues: Vec<ExeIssue>,
}

/// Opens `exe` (relative to the game folder) through [`open_game_exe`], parses it within
/// `limits` and classifies its graphics API. The per-file pipeline of [`scan_game`] and of
/// Topo matching (which names its paths itself, independent of the walk).
pub fn inspect_exe(
    game: &GameDir<'_>,
    exe: &RelPath,
    limits: &pe::Limits,
) -> Result<ExeFacts, ExeError> {
    let mut pe = open_game_exe(game, exe, limits)?;
    let info = pe.info().map_err(|error| PeReadError::Parse {
        file: exe.clone(),
        error,
    })?;
    let api = classify(&info.imports, &info.delay_imports, info.headers.managed);
    Ok(ExeFacts {
        bytes_read: pe.bytes_read(),
        info,
        api,
    })
}

/// Walks the game folder, inspects every candidate (one handle at a time), assigns roles and
/// ranks them. Never fails as a whole: walk problems are issues, file problems stay on their
/// candidate.
pub fn scan_game(game: &GameDir<'_>, options: &Options) -> GameExes {
    let walked = walk(game, &options.limits);
    let hint = options.name_hint.as_ref();
    let mut candidates: Vec<Candidate> = walked
        .exes
        .into_iter()
        .map(|w| {
            let facts = inspect_exe(game, &w.path, &options.limits.pe);
            let name = w.path.file_name();
            let role = with_facts(name_role(name, hint), &facts);
            Candidate {
                similarity: hint.map_or(0, |h| similarity(stem(name), h.file_name())),
                depth: w.depth,
                listed_len: w.listed_len,
                role,
                facts,
                path: w.path,
            }
        })
        .collect();
    let main = rank(&mut candidates);
    GameExes {
        candidates,
        main,
        stats: walked.stats,
        issues: walked.issues,
    }
}

#[cfg(test)]
mod tests;
