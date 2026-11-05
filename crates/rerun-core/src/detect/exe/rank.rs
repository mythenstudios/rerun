//! Ranking of the candidates and the main executable (ADR 0014, "Ranking"). Pure.

use std::cmp::Reverse;

use super::role::Role;
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
pub(super) fn rank(candidates: &mut [Candidate]) -> Main {
    candidates.sort_by_cached_key(|c| (Key::of(c), c.path.clone()));
    let keys: Vec<Key> = candidates.iter().map(Key::of).collect();
    let Some(best) = keys.first().filter(|k| k.is_game()) else {
        return Main::None;
    };
    let tied = keys.iter().take_while(|k| *k == best).count();
    if tied == 1 {
        Main::One(0)
    } else {
        Main::Tied((0..tied).collect())
    }
}

#[cfg(test)]
mod tests;
