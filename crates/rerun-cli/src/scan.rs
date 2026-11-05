//! `rerun scan [APP_ID…] [--hashes]` (ADR 0016): the Steam libraries and their apps, and for
//! every installed app its main executable with machine, graphics API and version. Read-only.
//!
//! Per app, in library and app ID order: an installed app is opened with
//! `SteamLibrary::open_game`, scanned with `scan_game`, printed as soon as it is done, and its
//! `GameDir` dropped before the next app. Apps Steam is updating or that are not installed are
//! listed and never opened (`open_read` shares read only and would block Steam's update).
//! Every issue is one line with its location and kind, never file content. Rendering is pure.

use std::collections::BTreeSet;
use std::io::Write;
use std::path::Path;

use rerun_core::detect::exe::{
    Candidate, ExeLimits, GameExes, HashOutcome, Main, Options, Role, scan_game,
};
use rerun_core::detect::steam::{self, AppState, SteamApp, SteamScan};
use rerun_core::escape::{self, Shown};
use rerun_core::path::RootPath;
use rerun_core::policy::root::{ForbiddenRoots, RootError};
use rerun_core::sys::System;

use crate::cli::Exit;
use crate::messages::{Message, NoneReason, ScanCounts};
use crate::out::{Out, OutError, failed};

/// Scans and prints. Exit 0 also with issues, Steam not found or an unknown requested app ID;
/// 1 when the forbidden roots cannot be resolved (no report) or on a write error other than a
/// closed pipe.
pub fn scan<W: Write, E: Write>(
    sys: &dyn System,
    install_dir: &Path,
    app_ids: &[u32],
    hashes: bool,
    out: &mut Out<W>,
    err: &mut Out<E>,
) -> Exit {
    if hashes {
        // A warning only; the scan goes on if stderr is gone.
        let _ = err.line(&Message::HashesWarning);
    }
    let fr = match ForbiddenRoots::resolve(sys, install_dir) {
        Ok(fr) => fr,
        Err(e) => {
            let _ = err.line(&Message::ForbiddenRoots {
                error: escape::text(&e.to_string()),
            });
            return Exit::Fatal;
        }
    };
    let steam = steam::scan(sys, &fr);
    match report(&steam, &fr, app_ids, hashes, out).and_then(|()| out.flush()) {
        Ok(()) => Exit::Report,
        Err(e) => failed(err, e),
    }
}

/// Streams the report: Steam, then per library its apps, each game written when it is done.
fn report<W: Write>(
    steam: &SteamScan<'_>,
    fr: &ForbiddenRoots,
    app_ids: &[u32],
    hashes: bool,
    out: &mut Out<W>,
) -> Result<(), OutError> {
    let mut counts = ScanCounts {
        libraries: steam.libraries.len(),
        issues: steam.issues.len(),
        ..ScanCounts::default()
    };
    out.lines(&render_steam(steam))?;
    let wanted = |id: u32| app_ids.is_empty() || app_ids.contains(&id);
    for (index, lib) in steam.libraries.iter().enumerate() {
        out.line(&Message::Blank)?;
        out.lines(&render_library(index, lib.path(), lib.label()))?;
        for app in lib.apps().iter().filter(|a| wanted(a.app_id)) {
            counts.apps += 1;
            match app.state() {
                AppState::Installed => {
                    counts.installed += 1;
                    match lib.open_game(fr, app.app_id) {
                        Err(e) => {
                            counts.none += 1;
                            counts.issues += 1;
                            out.lines(&render_unopened(app, &e))?;
                        }
                        Ok(game) => {
                            let options = Options {
                                name_hint: Some(app.install_dir.clone()),
                                hashes,
                                limits: ExeLimits::DEFAULT,
                            };
                            let exes = scan_game(&game, &options);
                            // The game folder is closed before anything is printed and before
                            // the next app is opened.
                            drop(game);
                            tally(&mut counts, &exes);
                            out.lines(&render_game(app, &exes))?;
                        }
                    }
                }
                AppState::UpdatePending => {
                    counts.pending += 1;
                    out.lines(&render_app(app))?;
                }
                AppState::NotInstalled => {
                    counts.not_installed += 1;
                    out.lines(&render_app(app))?;
                }
            }
        }
    }
    let held: BTreeSet<u32> = steam
        .libraries
        .iter()
        .flat_map(|l| l.apps().iter().map(|a| a.app_id))
        .collect();
    let mut missing: Vec<u32> = Vec::new();
    for id in app_ids {
        if !held.contains(id) && !missing.contains(id) {
            missing.push(*id);
        }
    }
    if !missing.is_empty() {
        out.line(&Message::Blank)?;
        for app_id in missing {
            out.line(&Message::AppNotFound { app_id })?;
        }
    }
    out.lines(&render_summary(counts))
}

/// The counts of one scanned game.
fn tally(counts: &mut ScanCounts, exes: &GameExes) {
    match &exes.main {
        Main::One(_) => counts.one += 1,
        Main::Tied(_) => counts.tied += 1,
        Main::None => counts.none += 1,
    }
    counts.issues += exes.issues.len() + failed_games(exes).count();
}

/// Where Steam was found and every issue of the Steam scan.
pub fn render_steam<'a>(steam: &'a SteamScan<'_>) -> Vec<Message<'a>> {
    let mut m = vec![match steam.root {
        Some(source) => Message::SteamFound { source },
        None => Message::SteamNotFound,
    }];
    for issue in &steam.issues {
        m.push(Message::SteamIssue {
            issue: escape::text(&issue.to_string()).into_owned(),
        });
    }
    m
}

/// A path for display.
fn root_path(p: &RootPath) -> Shown<'static> {
    escape::path(&p.to_string()).into_owned()
}

/// A library heading and its label.
pub fn render_library<'a>(
    index: usize,
    path: &RootPath,
    label: Option<&'a steam::RawText>,
) -> Vec<Message<'a>> {
    let mut m = vec![Message::Library {
        index,
        path: root_path(path),
    }];
    if let Some(label) = label {
        m.push(Message::LibraryLabel {
            label: label.escaped(),
        });
    }
    m
}

/// An app line (every state).
fn app_line(app: &SteamApp) -> Message<'_> {
    Message::App {
        app_id: app.app_id,
        state: app.state(),
        name: app.name.escaped(),
    }
}

/// An app that is not opened (update pending, not installed): its line only.
pub fn render_app(app: &SteamApp) -> Vec<Message<'_>> {
    vec![app_line(app)]
}

/// An installed app whose game folder did not open.
pub fn render_unopened<'a>(app: &'a SteamApp, e: &RootError) -> Vec<Message<'a>> {
    vec![
        app_line(app),
        Message::InstallFolder {
            folder: escape::path(app.install_dir.as_str()),
        },
        Message::GameNotOpened {
            error: escape::text(&e.to_string()).into_owned(),
        },
    ]
}

/// The game candidates that failed to open or parse.
fn failed_games(exes: &GameExes) -> impl Iterator<Item = &Candidate> {
    let none = matches!(exes.main, Main::None);
    exes.candidates
        .iter()
        .filter(move |c| none && c.role == Role::Game && c.facts.is_err())
}

/// Facts (and hashes) of one executable.
fn exe_lines<'a>(m: &mut Vec<Message<'a>>, c: &'a Candidate) {
    let Ok(f) = &c.facts else {
        return;
    };
    let version = match &f.info.version {
        Ok(Some(v)) => v.fixed.as_ref().map(|x| x.file_version),
        _ => None,
    };
    m.push(Message::ExeFacts {
        machine: f.info.headers.machine,
        api: &f.api,
        version,
    });
    if f.hashes != HashOutcome::NotRequested {
        m.push(Message::ExeHashes { outcome: &f.hashes });
    }
}

/// An installed, scanned app: its main executable (one, a tie, or none with a reason) and
/// every issue.
pub fn render_game<'a>(app: &'a SteamApp, exes: &'a GameExes) -> Vec<Message<'a>> {
    let mut m = vec![
        app_line(app),
        Message::InstallFolder {
            folder: escape::path(app.install_dir.as_str()),
        },
    ];
    let path = |c: &'a Candidate| escape::path(c.path.as_str());
    match &exes.main {
        Main::One(i) => {
            if let Some(c) = exes.candidates.get(*i) {
                m.push(Message::MainOne { path: path(c) });
                exe_lines(&mut m, c);
            }
        }
        Main::Tied(all) => {
            m.push(Message::MainTied { count: all.len() });
            for c in all.iter().filter_map(|i| exes.candidates.get(*i)) {
                m.push(Message::TiedExe { path: path(c) });
                exe_lines(&mut m, c);
            }
        }
        Main::None => {
            let games = exes
                .candidates
                .iter()
                .filter(|c| c.role == Role::Game)
                .count();
            let reason = if exes.candidates.is_empty() {
                NoneReason::NoExecutable
            } else if games == 0 {
                NoneReason::NoGameExecutable {
                    found: exes.candidates.len(),
                }
            } else {
                NoneReason::AllFailed { games }
            };
            m.push(Message::MainNone { reason });
            for c in failed_games(exes) {
                if let Err(e) = &c.facts {
                    m.push(Message::GameIssue {
                        issue: escape::text(&e.to_string()).into_owned(),
                    });
                }
            }
        }
    }
    for issue in &exes.issues {
        m.push(Message::GameIssue {
            issue: escape::text(&issue.to_string()).into_owned(),
        });
    }
    m
}

/// The summary and the closing hint.
pub fn render_summary(counts: ScanCounts) -> Vec<Message<'static>> {
    vec![Message::Blank, Message::Summary(counts), Message::Hints]
}

#[cfg(test)]
mod tests;
