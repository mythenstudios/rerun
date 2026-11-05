//! The exe scan of one game folder (ADR 0014, "Layers"): walk, inspect every candidate, roles,
//! ranking, and with `--hashes` the hashes of the best `Game` candidates. Never fails as a
//! whole.

use std::io::{Read, Seek};

use super::ExeLimits;
use super::api::{ApiReport, classify};
use super::hash::{HashError, HashLimits, HashOutcome, HashSkip, Stop, stream};
use super::issue::ExeIssue;
use super::rank::rank;
use super::role::{Role, name_role, similarity, stem, with_facts};
use super::walk::{WalkStats, walk};
use crate::detect::pe::{self, Pe, PeInfo, PeReadError, open_game_exe};
use crate::path::RelPath;
use crate::policy::root::GameDir;

/// What the scan of one game is asked to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Options {
    /// The install folder name (Steam's `installdir`), for roles and ranking.
    pub name_hint: Option<RelPath>,
    /// `--hashes`: hash the best `Game` candidates within [`ExeLimits::hash`]. Without it
    /// nothing beyond the parser's reads is read.
    pub hashes: bool,
    /// The bounds.
    pub limits: ExeLimits,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            name_hint: None,
            hashes: false,
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
    /// The hashes, computed on the handle that was parsed.
    pub hashes: HashOutcome,
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
/// `limits` and classifies its graphics API; with `hashes`, hashes the very handle that was
/// parsed (no second open; the read share of `open_read` keeps writers out). The per-file
/// pipeline of [`scan_game`] and of Topo matching (which names its paths itself, independent
/// of the walk).
///
/// Only the per-file limits of `hashes` apply here ([`HashLimits::max_file_bytes`],
/// [`HashLimits::chunk_bytes`]); `max_files` and `max_game_bytes` are for [`scan_game`].
pub fn inspect_exe(
    game: &GameDir<'_>,
    exe: &RelPath,
    limits: &pe::Limits,
    hashes: Option<&HashLimits>,
) -> Result<ExeFacts, ExeError> {
    let pe = open_game_exe(game, exe, limits)?;
    inspect_pe(pe, exe, hashes, None).map(|(facts, _)| facts)
}

/// [`inspect_exe`] after the open; separate so the reads can be counted in tests. With
/// `expected`, the file is hashed only if its facts equal them (else `Changed`, after the
/// parser's reads only). Returns the facts and the bytes the hashing read.
fn inspect_pe<R: Read + Seek>(
    mut pe: Pe<R>,
    exe: &RelPath,
    hashes: Option<&HashLimits>,
    expected: Option<&PeInfo>,
) -> Result<(ExeFacts, u64), ExeError> {
    let info = pe.info().map_err(|error| PeReadError::Parse {
        file: exe.clone(),
        error,
    })?;
    let api = classify(&info.imports, &info.delay_imports, info.headers.managed);
    let bytes_read = pe.bytes_read();
    let (hashes, hashed) = match hashes {
        None => (HashOutcome::NotRequested, 0),
        Some(_) if expected.is_some_and(|e| *e != info) => {
            (HashOutcome::Failed(HashError::Changed), 0)
        }
        Some(h) => match stream(pe.into_inner(), h.max_file_bytes, h.chunk_bytes) {
            Ok(done) => {
                let len = done.len;
                (HashOutcome::Done(done), len)
            }
            Err(Stop::TooLarge { read }) => (
                HashOutcome::Skipped(HashSkip::TooLarge {
                    max: h.max_file_bytes,
                }),
                read,
            ),
            Err(Stop::Io { kind, read }) => (HashOutcome::Failed(HashError::Io(kind)), read),
        },
    };
    let facts = ExeFacts {
        info,
        api,
        bytes_read,
        hashes,
    };
    Ok((facts, hashed))
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
            let facts = inspect_exe(game, &w.path, &options.limits.pe, None);
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
    if options.hashes {
        hash_games(game, &mut candidates, &options.limits);
    }
    GameExes {
        candidates,
        main,
        stats: walked.stats,
        issues: walked.issues,
    }
}

/// Hashes the parsed `Game` candidates in rank order within the per-game limits; marks every
/// other parsed candidate `Skipped`. Each selected file is opened and parsed again; only if
/// its facts equal those of the first inspection is that same handle hashed. Otherwise the
/// hash is `Changed` (after the parser's reads only) and the first facts stay, so a hash
/// always belongs to the facts shown. Every byte the hashing read is charged to the game
/// budget, so a game reads at most `max_game_bytes` plus one chunk per hashed file.
fn hash_games(game: &GameDir<'_>, candidates: &mut [Candidate], limits: &ExeLimits) {
    let h = &limits.hash;
    let mut files = 0usize;
    let mut used = 0u64;
    for c in candidates {
        let Ok(facts) = &mut c.facts else {
            continue;
        };
        let remaining = h.max_game_bytes.saturating_sub(used);
        let skip = if c.role != Role::Game {
            Some(HashSkip::NotGame)
        } else if files >= h.max_files {
            Some(HashSkip::TooManyFiles { max: h.max_files })
        } else if c.listed_len > h.max_file_bytes {
            // The listing is a hint; it only spares reading a file that cannot fit.
            Some(HashSkip::TooLarge {
                max: h.max_file_bytes,
            })
        } else if c.listed_len > remaining {
            Some(HashSkip::GameBudget {
                max: h.max_game_bytes,
            })
        } else {
            None
        };
        if let Some(skip) = skip {
            facts.hashes = HashOutcome::Skipped(skip);
            continue;
        }
        files += 1;
        // The remaining game budget caps the read as well, so a listing that understates the
        // length costs at most the remaining budget plus one chunk.
        let cap = remaining.min(h.max_file_bytes);
        let per_file = HashLimits {
            max_file_bytes: cap,
            ..*h
        };
        let again = open_game_exe(game, &c.path, &limits.pe)
            .map_err(ExeError::from)
            .and_then(|pe| inspect_pe(pe, &c.path, Some(&per_file), Some(&facts.info)));
        facts.hashes = match again {
            Err(e) => HashOutcome::Failed(HashError::Inspect(Box::new(e))),
            Ok((again, read)) => match again.hashes {
                HashOutcome::Skipped(HashSkip::TooLarge { .. }) => {
                    used = used.saturating_add(read);
                    let skip = if cap < h.max_file_bytes {
                        HashSkip::GameBudget {
                            max: h.max_game_bytes,
                        }
                    } else {
                        HashSkip::TooLarge {
                            max: h.max_file_bytes,
                        }
                    };
                    HashOutcome::Skipped(skip)
                }
                other => {
                    used = used.saturating_add(read);
                    other
                }
            },
        };
    }
}

#[cfg(test)]
mod tests;
