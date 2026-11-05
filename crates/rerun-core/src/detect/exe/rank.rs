//! Ranking of the candidates and the main executable (ADR 0014, "Ranking"). Pure.

use std::cmp::Reverse;

use super::role::{Role, reduce, stem};
use super::{Candidate, Main};
use crate::detect::pe::layout::SUBSYSTEM_WINDOWS_GUI;

/// The rank key of a candidate, everything but the path; smaller is better.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct Key {
    /// Role group: `Game` 0, `Launcher` 1, `Helper` 2, crash reporter, anti-cheat and
    /// installer 3, `NotAnApp` and `Legacy` 4, failed 5.
    group: u8,
    /// GUI subsystem 0, anything else (console, unknown, failed) 1. Before the API: a
    /// console tool with a helper import never beats a GUI executable (review of step 14).
    console: u8,
    /// API strength by where the evidence comes from, higher first.
    strength: Reverse<u8>,
    /// Similarity to the install folder hint, higher first.
    similarity: Reverse<u8>,
    /// Depth, shallower first.
    depth: usize,
}

impl Key {
    /// The key of `c`.
    pub(super) fn of(c: &Candidate) -> Self {
        let failed = c.facts.is_err() && !matches!(c.role, Role::Legacy(_));
        let group = if failed {
            5
        } else {
            match c.role {
                Role::Game => 0,
                Role::Launcher => 1,
                Role::Helper => 2,
                Role::CrashReporter | Role::AntiCheat | Role::Installer => 3,
                Role::NotAnApp | Role::Legacy(_) => 4,
            }
        };
        let (strength, gui) = match &c.facts {
            Ok(f) => (
                f.api.verdict.strength(),
                f.info.headers.subsystem == SUBSYSTEM_WINDOWS_GUI,
            ),
            Err(_) => (0, false),
        };
        Self {
            group,
            strength: Reverse(strength),
            console: u8::from(!gui),
            similarity: Reverse(c.similarity),
            depth: c.depth,
        }
    }

    /// A parsed `Game` candidate.
    fn is_game(&self) -> bool {
        self.group == 0
    }
}

/// Sorts `candidates` by rank (key, then path) and names the main executable: `One` when
/// exactly one `Game` candidate has the best key, `Tied` when several share it, `None` without
/// a parsed `Game` candidate. A launcher is never the main executable.
///
/// Single-player and multiplayer executables tie (ADR 0014 amendment): a parsed `Game`
/// candidate whose name differs from a chosen one only by a single-player/multiplayer token
/// ([`sp_mp_pair`]) joins the tie, whatever its key. Which one an app starts is not a
/// property of the files; a Topo names it (phase 4).
pub(super) fn rank(candidates: &mut [Candidate]) -> Main {
    candidates.sort_by_cached_key(|c| (Key::of(c), c.path.clone()));
    let keys: Vec<Key> = candidates.iter().map(Key::of).collect();
    let Some(best) = keys.first().filter(|k| k.is_game()) else {
        return Main::None;
    };
    let tied = keys.iter().take_while(|k| *k == best).count();
    let mut chosen: Vec<usize> = (0..tied).collect();
    for (i, (c, k)) in candidates.iter().zip(&keys).enumerate().skip(tied) {
        let name = c.path.file_name();
        if k.is_game()
            && chosen
                .iter()
                .filter_map(|j| candidates.get(*j))
                .any(|m| sp_mp_pair(m.path.file_name(), name))
        {
            chosen.push(i);
        }
    }
    match chosen.as_slice() {
        [_] => Main::One(0),
        _ => Main::Tied(chosen),
    }
}

/// Multiplayer tokens at the end of a reduced stem.
const MP: [&str; 2] = ["multiplayer", "mp"];
/// Single-player tokens at the end of a reduced stem (or none).
const SP: [&str; 3] = ["singleplayer", "sp", ""];
/// The shared part must be at least this long (no `mp.exe` against `sp.exe`).
const MIN_BASE: usize = 2;

/// `a` and `b` (file names) differ only by a single-player/multiplayer token at the end of
/// their stems, compared as lowercase ASCII letters and digits: `BlackOps`/`BlackOpsMP`,
/// `t6sp`/`t6mp`, `CoDWaW`/`CoDWaWmp`, `Game_SP`/`Game_MP`. Never by the app's name.
pub(super) fn sp_mp_pair(a: &str, b: &str) -> bool {
    let (a, b) = (reduce(stem(a)), reduce(stem(b)));
    let one_way = |mp: &str, sp: &str| {
        MP.iter().any(|m| {
            mp.strip_suffix(m).is_some_and(|base| {
                base.len() >= MIN_BASE
                    && SP
                        .iter()
                        .any(|s| sp.strip_suffix(s).is_some_and(|other| other == base))
            })
        })
    };
    a != b && (one_way(&a, &b) || one_way(&b, &a))
}

#[cfg(test)]
mod tests;
