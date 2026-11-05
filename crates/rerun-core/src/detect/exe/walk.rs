//! The bounded walk of a game folder (ADR 0014, "Walk").
//!
//! Breadth-first, one level after the other, with an explicit queue (no recursion). Every
//! directory is opened relative to the game handle (`Dir::open_dir` never follows a reparse
//! point, ADR 0007), asked whether it is case-sensitive and listed through that same handle.
//! Every listing is sorted by the folded name before it is used, so the result and the limits
//! do not depend on the listing order of the file system. Nothing but listings is read here.

use std::collections::VecDeque;

use super::ExeLimits;
use super::issue::{ExeIssue, ExeIssueKind, LimitKind};
use crate::fold::fold;
use crate::path::{Anomaly, RelPath, classify};
use crate::policy::root::GameDir;
use crate::sys::fs::{DirEntry, EntryKind};
use crate::sys::{Dir, SysResult};

/// Folders that are never entered (whole segment, ASCII case-insensitive, at every depth):
/// redistributables, installers and anti-cheat services. Provisional until the
/// developer-machine dump (ADR 0014).
pub(crate) const SKIP_DIRS: &[&str] = &[
    "_CommonRedist",
    "CommonRedist",
    "__Installer",
    "Installer",
    "Installers",
    "Redist",
    "Redistributables",
    "DirectX",
    "DXSETUP",
    "vcredist",
    "dotNetFx",
    "Support",
    "EasyAntiCheat",
    "BattlEye",
    "PunkBuster",
];

/// An executable found by the walk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WalkedExe {
    /// The file, relative to the game folder.
    pub path: RelPath,
    /// Level of the folder that holds it (0: the game folder).
    pub depth: usize,
    /// Length as the listing reported it. A hint only (it decides whether a file can fit the
    /// hash budget), never a fact about the file.
    pub listed_len: u64,
}

/// What the walk did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalkStats {
    /// No limit stopped the walk: every directory that was to be listed was listed.
    pub complete: bool,
    /// Directories listed (or attempted), the game folder included.
    pub listed_dirs: usize,
    /// Entries across all listings.
    pub entries: usize,
    /// Candidates found, before [`ExeLimits::max_exes`] applied.
    pub exes_found: usize,
    /// Directories not entered because they lie deeper than [`ExeLimits::max_depth`].
    pub depth_cut: usize,
    /// Directories not entered because of [`SKIP_DIRS`], in walk order.
    pub skipped_dirs: Vec<RelPath>,
}

/// The result of [`walk()`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Walk {
    /// Candidates in walk order, at most [`ExeLimits::max_exes`].
    pub exes: Vec<WalkedExe>,
    /// What the walk did.
    pub stats: WalkStats,
    /// Every problem, in the order it was found.
    pub issues: Vec<ExeIssue>,
}

/// Walks the game folder within `limits`. Never fails as a whole.
pub(crate) fn walk(game: &GameDir<'_>, limits: &ExeLimits) -> Walk {
    walk_dir(game.dir(), limits)
}

/// [`walk()`] on a bare handle; separate so the listing order can be varied in tests.
/// Detection never calls this with anything but a [`GameDir`] handle.
fn walk_dir(root: &dyn Dir, limits: &ExeLimits) -> Walk {
    let mut exes = Vec::new();
    let mut issues = Vec::new();
    let mut stats = WalkStats {
        complete: true,
        listed_dirs: 0,
        entries: 0,
        exes_found: 0,
        depth_cut: 0,
        skipped_dirs: Vec::new(),
    };
    let mut queue: VecDeque<(Option<RelPath>, usize)> = VecDeque::from([(None, 0)]);
    while let Some((dir, depth)) = queue.pop_front() {
        let stop = if stats.listed_dirs >= limits.max_dirs {
            Some((LimitKind::Dirs, limits.max_dirs))
        } else if stats.entries >= limits.max_entries {
            Some((LimitKind::Entries, limits.max_entries))
        } else {
            None
        };
        if let Some((limit, max)) = stop {
            stats.complete = false;
            issues.push(ExeIssue {
                at: None,
                kind: ExeIssueKind::WalkLimit { limit, max },
            });
            break;
        }
        stats.listed_dirs += 1;
        let entries = match list(root, dir.as_ref()) {
            Ok(Some(entries)) => entries,
            Ok(None) => {
                issues.push(ExeIssue {
                    at: dir,
                    kind: ExeIssueKind::CaseSensitiveDir,
                });
                continue;
            }
            Err(e) => {
                issues.push(ExeIssue {
                    at: dir,
                    kind: ExeIssueKind::Sys(e),
                });
                continue;
            }
        };
        stats.entries = stats.entries.saturating_add(entries.len());
        for entry in entries {
            let is_exe = has_exe_extension(&entry.name);
            let kind = entry.meta.kind;
            let restricted = entry.meta.restricted;
            let path = match child(dir.as_ref(), &entry.name) {
                Ok(p) => p,
                Err(anomaly) => {
                    // Only where the name would have mattered: a folder to enter, a reparse
                    // point to report, or an executable.
                    if is_exe || kind != EntryKind::File {
                        issues.push(ExeIssue {
                            at: dir.clone(),
                            kind: ExeIssueKind::Anomaly(anomaly),
                        });
                    }
                    continue;
                }
            };
            let not_followed = |path| ExeIssue {
                at: Some(path),
                kind: ExeIssueKind::NotFollowed { kind, restricted },
            };
            match kind {
                EntryKind::Reparse => issues.push(not_followed(path)),
                EntryKind::Dir if restricted => issues.push(not_followed(path)),
                EntryKind::Dir => {
                    if is_skipped(&entry.name) {
                        stats.skipped_dirs.push(path);
                    } else if depth >= limits.max_depth {
                        stats.depth_cut += 1;
                    } else {
                        queue.push_back((Some(path), depth + 1));
                    }
                }
                EntryKind::File if is_exe && restricted => issues.push(not_followed(path)),
                EntryKind::File if is_exe => exes.push(WalkedExe {
                    path,
                    depth,
                    listed_len: entry.meta.len,
                }),
                EntryKind::File => {}
            }
        }
    }
    stats.exes_found = exes.len();
    if exes.len() > limits.max_exes {
        issues.push(ExeIssue {
            at: None,
            kind: ExeIssueKind::TooManyExes {
                found: exes.len(),
                max: limits.max_exes,
            },
        });
        exes.truncate(limits.max_exes);
    }
    Walk {
        exes,
        stats,
        issues,
    }
}

/// Opens `dir` relative to `root` (or takes `root` itself), and lists it sorted by folded
/// name; `None` for a case-sensitive directory: one that says so (not listed at all), or one
/// whose listing holds two names that fold to the same path (it became case-sensitive between
/// `info` and `read_dir`, or the file system does not fold like NTFS).
fn list(root: &dyn Dir, dir: Option<&RelPath>) -> SysResult<Option<Vec<DirEntry>>> {
    let sub;
    let handle: &dyn Dir = match dir {
        None => root,
        Some(p) => {
            sub = root.open_dir(p)?;
            &*sub
        }
    };
    if handle.info()?.case_sensitive {
        return Ok(None);
    }
    let entries = handle.read_dir(None)?;
    let mut keyed: Vec<(String, DirEntry)> =
        entries.into_iter().map(|e| (fold(&e.name), e)).collect();
    keyed.sort_by(|(a, x), (b, y)| a.cmp(b).then_with(|| x.name.cmp(&y.name)));
    if keyed
        .windows(2)
        .any(|w| matches!(w, [(a, _), (b, _)] if a == b))
    {
        return Ok(None);
    }
    Ok(Some(keyed.into_iter().map(|(_, e)| e).collect()))
}

/// The path of entry `name` below `dir`, or why it is an anomaly (an invalid segment, or a
/// path over [`RelPath::MAX_LEN`]).
fn child(dir: Option<&RelPath>, name: &str) -> Result<RelPath, Anomaly> {
    let seg = classify(name, false)?;
    match dir {
        None => Ok(seg),
        Some(d) => d.child(seg.as_str()).map_err(|e| Anomaly {
            name: name.to_owned(),
            reason: e.reason,
        }),
    }
}

/// The name ends in `.exe`, ASCII case-insensitively, once trailing dots and spaces are
/// removed (Win32 strips them, so `game.exe.` opens as `game.exe`; such a name is an anomaly
/// that matters).
pub(super) fn has_exe_extension(name: &str) -> bool {
    let b = name.trim_end_matches(['.', ' ']).as_bytes();
    b.len() >= 4
        && b.get(b.len() - 4..)
            .is_some_and(|ext| ext.eq_ignore_ascii_case(b".exe"))
}

fn is_skipped(name: &str) -> bool {
    SKIP_DIRS.iter().any(|s| s.eq_ignore_ascii_case(name))
}

#[cfg(test)]
mod tests;
