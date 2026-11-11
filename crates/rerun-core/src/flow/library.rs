//! The library (ADR 0016 `rerun scan`, ADR 0027): the Steam libraries and their apps, and for
//! every installed app its executables, streamed.
//!
//! Per app, in library and app ID order: an installed app is opened with
//! `SteamLibrary::open_game`, scanned with `scan_game`, its `GameDir` dropped, and only then
//! handed to the caller, before the next app is opened. Apps Steam is updating or that are not
//! installed are handed on without being opened (`open_read` shares read only and would block
//! Steam's update). The caller may stop the stream (a closed output); the scan never fails as a
//! whole.

use std::collections::BTreeSet;
use std::ops::ControlFlow;

use crate::detect::exe::{Candidate, ExeLimits, GameExes, Main, Options, Role, scan_game};
use crate::detect::steam::{self, AppState, SteamApp, SteamLibrary, SteamScan};
use crate::policy::root::{ForbiddenRoots, RootError};
use crate::sys::System;

/// What the scan found for one listed app.
#[derive(Debug)]
pub enum RowScan {
    /// Not opened: Steam is updating it, or it is not installed.
    NotOpened,
    /// Installed, but its folder did not open.
    Unopened(RootError),
    /// Installed and scanned.
    Scanned(Box<GameExes>),
}

/// One step of the stream, in order: [`Self::Steam`] once, then per library [`Self::Library`]
/// and its rows.
pub enum LibraryEvent<'a> {
    /// Where Steam was found, and every issue of the Steam scan.
    Steam(&'a SteamScan<'a>),
    /// A library, by its index in the scan.
    Library {
        /// Its index.
        index: usize,
        /// The library.
        lib: &'a SteamLibrary<'a>,
    },
    /// One listed app.
    Row {
        /// The app as its manifest lists it.
        app: &'a SteamApp,
        /// What the scan found.
        scan: &'a RowScan,
    },
}

/// The counts at the end of the scan.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LibraryCounts {
    /// Libraries.
    pub libraries: usize,
    /// Apps listed (and requested).
    pub apps: usize,
    /// Of these installed (scanned).
    pub installed: usize,
    /// Update pending (not opened).
    pub pending: usize,
    /// Not installed (not opened).
    pub not_installed: usize,
    /// Games with one main executable.
    pub one: usize,
    /// Games with a tie.
    pub tied: usize,
    /// Games without a main executable (or whose folder did not open).
    pub none: usize,
    /// Issues: of the Steam scan, of each game, and each game candidate that failed.
    pub issues: usize,
}

/// What the whole scan found.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LibraryFacts {
    /// The counts.
    pub counts: LibraryCounts,
    /// Requested app IDs no library lists, in the order asked, each once.
    pub missing: Vec<u32>,
}

/// The game candidates that failed to open or parse, whatever became the main executable
/// (failed candidates rank last, so another one may have won).
pub fn failed_games(exes: &GameExes) -> impl Iterator<Item = &Candidate> {
    exes.candidates
        .iter()
        .filter(|c| c.role == Role::Game && c.facts.is_err())
}

/// Counts one scanned game.
pub fn tally(facts: &mut LibraryCounts, exes: &GameExes) {
    match &exes.main {
        Main::One(_) => facts.one += 1,
        Main::Tied(_) => facts.tied += 1,
        Main::None => facts.none += 1,
    }
    facts.issues += exes.issues.len() + failed_games(exes).count();
}

/// Scans the Steam libraries (module docs): the apps in `app_ids` only (every app if empty),
/// the executables hashed if `hashes`. `on` sees every event in order; [`ControlFlow::Break`]
/// stops the scan there and is returned.
pub fn library<B>(
    sys: &dyn System,
    fr: &ForbiddenRoots,
    app_ids: &[u32],
    hashes: bool,
    on: &mut dyn FnMut(LibraryEvent<'_>) -> ControlFlow<B>,
) -> Result<LibraryFacts, B> {
    let steam = steam::scan(sys, fr);
    let mut facts = LibraryCounts {
        libraries: steam.libraries.len(),
        issues: steam.issues.len(),
        ..LibraryCounts::default()
    };
    let mut missing = Vec::new();
    let go = |c: ControlFlow<B>| match c {
        ControlFlow::Continue(()) => Ok(()),
        ControlFlow::Break(b) => Err(b),
    };
    go(on(LibraryEvent::Steam(&steam)))?;
    let wanted = |id: u32| app_ids.is_empty() || app_ids.contains(&id);
    for (index, lib) in steam.libraries.iter().enumerate() {
        go(on(LibraryEvent::Library { index, lib }))?;
        for app in lib.apps().iter().filter(|a| wanted(a.app_id)) {
            facts.apps += 1;
            let scan = match app.state() {
                AppState::Installed => {
                    facts.installed += 1;
                    match lib.open_game(fr, app.app_id) {
                        Err(e) => {
                            facts.none += 1;
                            facts.issues += 1;
                            RowScan::Unopened(e)
                        }
                        Ok(game) => {
                            let options = Options {
                                name_hint: Some(app.install_dir.clone()),
                                hashes,
                                limits: ExeLimits::DEFAULT,
                            };
                            let exes = scan_game(&game, &options);
                            // The game folder is closed before the caller sees the row and
                            // before the next app is opened.
                            drop(game);
                            tally(&mut facts, &exes);
                            RowScan::Scanned(Box::new(exes))
                        }
                    }
                }
                AppState::UpdatePending => {
                    facts.pending += 1;
                    RowScan::NotOpened
                }
                AppState::NotInstalled => {
                    facts.not_installed += 1;
                    RowScan::NotOpened
                }
            };
            go(on(LibraryEvent::Row { app, scan: &scan }))?;
        }
    }
    let held: BTreeSet<u32> = steam
        .libraries
        .iter()
        .flat_map(|l| l.apps().iter().map(|a| a.app_id))
        .collect();
    for id in app_ids {
        if !held.contains(id) && !missing.contains(id) {
            missing.push(*id);
        }
    }
    Ok(LibraryFacts {
        counts: facts,
        missing,
    })
}
