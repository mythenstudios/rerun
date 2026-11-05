//! The Steam scan as a whole (ADR 0012): root, libraries, manifests, duplicate app IDs.

use std::collections::BTreeMap;

use super::issue::{Issue, IssueKind, Location};
use super::library::{SteamLibrary, libraries};
use super::root::{RootSource, find_root};
use crate::policy::root::ForbiddenRoots;
use crate::sys::System;

/// What the scan found. `Debug` never shows file content (names and labels are `RawText`).
#[derive(Debug)]
pub struct SteamScan<'s> {
    /// The registry candidate the Steam root came from; `None`: Steam is not installed (or
    /// every candidate was refused, see [`Self::issues`]).
    pub root: Option<RootSource>,
    /// The libraries; library 0 is the Steam root whenever [`Self::root`] is `Some`.
    pub libraries: Vec<SteamLibrary<'s>>,
    /// Every problem, in the order it was found.
    pub issues: Vec<Issue>,
}

/// Scans the Steam installation of the current user. Never fails as a whole: every problem is
/// an [`Issue`] and the scan goes on with what is left. Read-only: registry values through
/// `Registry::get`, folders only through `policy::root` and handles relative to them.
pub fn scan<'s>(sys: &'s dyn System, fr: &ForbiddenRoots) -> SteamScan<'s> {
    let mut issues = Vec::new();
    let Some((source, root)) = find_root(sys, fr, &mut issues) else {
        return SteamScan {
            root: None,
            libraries: Vec::new(),
            issues,
        };
    };
    let libraries = libraries(sys, fr, root, &mut issues);
    duplicates(&libraries, &mut issues);
    SteamScan {
        root: Some(source),
        libraries,
        issues,
    }
}

/// One [`IssueKind::DuplicateApp`] per copy of an app ID that is in more than one library,
/// naming the first other library and how many more there are. O(1) per copy, so time and
/// the issue list are linear in the number of apps (each issue holds one path and a count).
fn duplicates(libraries: &[SteamLibrary<'_>], issues: &mut Vec<Issue>) {
    let mut holders: BTreeMap<u32, Vec<usize>> = BTreeMap::new();
    for (index, lib) in libraries.iter().enumerate() {
        for app in lib.apps() {
            holders.entry(app.app_id).or_default().push(index);
        }
    }
    for (index, lib) in libraries.iter().enumerate() {
        for app in lib.apps() {
            // `held` lists each library once (app IDs are unique within a library), in
            // library order: the first other one is `held[0]` unless that is this one.
            let Some(held) = holders.get(&app.app_id).filter(|h| h.len() > 1) else {
                continue;
            };
            let other = match held.as_slice() {
                [first, second, ..] => {
                    if *first == index {
                        *second
                    } else {
                        *first
                    }
                }
                _ => continue,
            };
            let Some(other) = libraries.get(other) else {
                continue;
            };
            issues.push(Issue {
                at: Location::Manifest {
                    library: lib.path().clone(),
                    name: app.manifest.file_name().to_owned(),
                },
                kind: IssueKind::DuplicateApp {
                    app_id: app.app_id,
                    other: other.path().clone(),
                    more: held.len().saturating_sub(2),
                },
            });
        }
    }
}

#[cfg(test)]
mod tests;
