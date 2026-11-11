//! `rerun scan [APP_ID…] [--hashes]` (ADR 0016): the Steam libraries and their apps, and for
//! every installed app its main executable with machine, graphics API and version. Read-only.
//!
//! Per app, in library and app ID order: an installed app is opened with
//! `SteamLibrary::open_game`, scanned with `scan_game`, printed as soon as it is done, and its
//! `GameDir` dropped before the next app. Apps Steam is updating or that are not installed are
//! listed and never opened (`open_read` shares read only and would block Steam's update).
//! Every issue is one line with its location and kind, never file content. The scan and its
//! counts are `rerun_core::flow::library` (ADR 0027); rendering is pure.

use std::io::Write;
use std::ops::ControlFlow;
use std::path::Path;

use rerun_core::detect::exe::{Candidate, ExeLimits, GameExes, HashOutcome, Main, Role};
use rerun_core::detect::steam::{self, SteamApp, SteamScan};
use rerun_core::escape::{self, Shown};
#[cfg(test)]
use rerun_core::flow::tally;
use rerun_core::flow::{self, LibraryEvent, RowScan, failed_games};
use rerun_core::path::RootPath;
use rerun_core::policy::root::{ForbiddenRoots, RootError};
use rerun_core::sys::System;

use crate::cli::Exit;
use crate::host::gate;
use crate::messages::{HashText, Message, NoneReason, ScanCounts};
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
    let fr = match flow::forbidden_roots(sys, &Ok(install_dir.to_path_buf())) {
        Ok(fr) => fr,
        Err(g) => return gate(err, g),
    };
    match report(sys, &fr, app_ids, hashes, out).and_then(|()| out.flush()) {
        Ok(()) => Exit::Report,
        Err(e) => failed(err, e),
    }
}

/// Streams the report: Steam, then per library its apps, each game written when it is done.
fn report<W: Write>(
    sys: &dyn System,
    fr: &ForbiddenRoots,
    app_ids: &[u32],
    hashes: bool,
    out: &mut Out<W>,
) -> Result<(), OutError> {
    let mut on = |ev: LibraryEvent<'_>| {
        let lines = match ev {
            LibraryEvent::Steam(steam) => out.lines(&render_steam(steam)),
            LibraryEvent::Library { index, lib } => out
                .line(&Message::Blank)
                .and_then(|()| out.lines(&render_library(index, lib.path(), lib.label()))),
            LibraryEvent::Row { app, scan } => match scan {
                RowScan::NotOpened => out.lines(&render_app(app)),
                RowScan::Unopened(e) => out.lines(&render_unopened(app, e)),
                RowScan::Scanned(exes) => out.lines(&render_game(app, exes)),
            },
        };
        match lines {
            Ok(()) => ControlFlow::Continue(()),
            Err(e) => ControlFlow::Break(e),
        }
    };
    let facts = flow::library(sys, fr, app_ids, hashes, &mut on)?;
    if !facts.missing.is_empty() {
        out.line(&Message::Blank)?;
        for app_id in &facts.missing {
            out.line(&Message::AppNotFound { app_id: *app_id })?;
        }
    }
    out.lines(&render_summary(facts.counts))
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
    // Steam writes an empty label for unlabelled libraries; an empty or whitespace-only label
    // is no line (a label with a tab or another escapable character is quoted, so it shows).
    if let Some(label) = label.map(steam::RawText::escaped)
        && !label.as_str().trim().is_empty()
    {
        m.push(Message::LibraryLabel { label });
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
        large_address_aware: f.info.headers.large_address_aware(),
        api: &f.api,
        version,
    });
    match &f.hashes {
        HashOutcome::NotRequested => {}
        HashOutcome::Done(h) => m.push(Message::ExeHashes(HashText::Done(h))),
        // Skipped and failed through the text rule: a failure may name a file (ADR 0016).
        other => m.push(Message::ExeHashes(HashText::NotDone(
            escape::text(&other.to_string()).into_owned(),
        ))),
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
        }
    }
    // Only when nothing was found: it explains why (user decision; with a main executable the
    // depth limit cuts engine and data folders in most games and the line was noise).
    let stats = &exes.stats;
    if matches!(exes.main, Main::None) && (stats.depth_cut > 0 || !stats.complete) {
        m.push(Message::WalkIncomplete {
            depth_cut: stats.depth_cut,
            max_depth: ExeLimits::DEFAULT.max_depth,
            stopped: !stats.complete,
        });
    }
    for c in failed_games(exes) {
        if let Err(e) = &c.facts {
            m.push(Message::GameIssue {
                issue: escape::text(&e.to_string()).into_owned(),
            });
        }
    }
    for h in &exes.anti_cheat.found {
        m.push(Message::GameAntiCheat {
            system: h.system.as_str(),
            path: escape::path(h.path.as_str()).into_owned(),
        });
    }
    for p in &exes.anti_cheat.unreadable {
        m.push(Message::GameAntiCheatUnreadable {
            path: escape::path(p.as_str()).into_owned(),
        });
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
