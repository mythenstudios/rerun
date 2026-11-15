//! What the preview of a launch profile shows beyond the plan (P3-3d; moved from the CLI with
//! P5-5a, ADR 0027 amendment P5-5a): the CPU selection on this computer now, the Steam launch
//! option the user pastes, and whether `rerun-launch.exe` is there. Typed values, no text: the
//! CLI renders them through its `messages`, the app through its view models.

use std::path::PathBuf;

use crate::escape::{self, Shown};
use crate::exec::LaunchResults;
use crate::exec::launch_result::{LaunchResult, Outcome, ProfileId, SkipReason};
use crate::journal::TxnId;
use crate::plan::{Preview, profile_id};
use crate::policy::root::file_present;
use crate::prim::launch_method::ProfileMethod;
use crate::prim::{MachineView, SHIM, on_this_machine, steam_option_text};
use crate::sys::System;

use super::{Holder, profile_of};

/// The launch option for a front end: shown, or why not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OptionText {
    /// The option, as it is.
    Shown(Shown<'static>),
    /// Rerun's install folder is unknown.
    InstallUnknown,
    /// The install folder's path cannot be shown as it is.
    NotShowable,
}

/// The launch option of profile `id` with Rerun's install folder `install`.
pub fn option_text(install: &Result<PathBuf, String>, id: ProfileId) -> OptionText {
    match install {
        Err(_) => OptionText::InstallUnknown,
        Ok(dir) => steam_option_text(dir, id).map_or(OptionText::NotShowable, OptionText::Shown),
    }
}

/// What the preview of a launch profile shows beyond the plan (P3-3d): the selection on this
/// computer now, the launch option and whether the shim is there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchView {
    /// The rule on this computer.
    pub machine: MachineView,
    /// The launch option.
    pub option: OptionText,
    /// `rerun-launch.exe` in the install folder: its path and whether it is a plain file, or
    /// why that could not be checked (`None`: the install folder is unknown).
    pub shim: Option<(Shown<'static>, Result<bool, Shown<'static>>)>,
}

impl LaunchView {
    /// The option can be pasted and the shim is there (review L3: only then "paste it now").
    pub fn ready(&self) -> bool {
        matches!(self.option, OptionText::Shown(_)) && matches!(self.shim, Some((_, Ok(true))))
    }
}

/// The [`LaunchView`] of `p`, if it writes a launch profile.
pub fn launch_view(
    sys: &dyn System,
    install: &Result<PathBuf, String>,
    p: &Preview,
) -> Option<LaunchView> {
    let s = profile_of(p)?;
    let id = ProfileId::from_hex(&s.id)?;
    let machine = on_this_machine(sys.topology().read(), &s.decoded);
    let shim = install.as_ref().ok().map(|dir| {
        (
            escape::path(&dir.join(SHIM).display().to_string()).into_owned(),
            // The error names a path (ADR 0016: `escape::path`).
            file_present(sys, dir, SHIM).map_err(|e| escape::path(&e.to_string()).into_owned()),
        )
    });
    Some(LaunchView {
        machine,
        option: option_text(install, id),
        shim,
    })
}

/// What the last start of a profile adds to its result line (A6, A7, P3-4c).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LaunchNote {
    /// A7: the start had no profile and the Steam launch option still points at the shim. `held`
    /// is a transaction that has not reverted a profile with this ID (the result may be older).
    OptionStillSet {
        /// The holder, if there is one.
        held: Option<TxnId>,
    },
    /// A7: the holder is forgotten; the profile and the option stay until removed by hand.
    OptionStillSetForgotten,
    /// A6: the check covered the launcher Steam starts (its path), not the game.
    CheckedLauncher(Shown<'static>),
    /// P3-4c: the rule and the check concern the game process found after the start (its target).
    Watched(Shown<'static>),
}

/// One launch result as a front end shows it: typed, with the words left to the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchLine {
    /// The profile (the file name).
    pub id: ProfileId,
    /// The last start, or why the file cannot be shown (escaped).
    pub result: Result<LaunchResult, Shown<'static>>,
    /// The words of `watch` apply: the result's own `method=watch`, a reason only `watch` writes,
    /// or a priority restore line (the method of the result, never of a head that may be newer).
    pub watch: bool,
    /// `watch`: the priority class could not be put back (Win32 error).
    pub restore_failed: Option<u32>,
    /// The note after the line, if any.
    pub note: Option<LaunchNote>,
}

/// The lines of `r`, in its order (by profile ID), with the notes `holders` give them.
pub fn launch_lines(r: &LaunchResults, holders: &[Holder]) -> Vec<LaunchLine> {
    r.entries
        .iter()
        .map(|e| {
            let holder = holders.iter().find(|h| h.id == e.id);
            // The method for the wording is the result file's own (`method=`, senior-dev
            // decision 1 of the review of P3-4b/c): a head may be newer than the result.
            let method = e.result.as_ref().ok().and_then(|r| r.method);
            let is_watch = method == Some(ProfileMethod::Watch);
            let mut watch = false;
            let mut restore_failed = None;
            let mut missing = false;
            let mut applied = false;
            if let Ok(res) = &e.result {
                match &res.outcome {
                    Outcome::Applied { .. } => {
                        watch = is_watch;
                        applied = true;
                    }
                    Outcome::Skipped {
                        reason,
                        priority_restore,
                        ..
                    } => {
                        restore_failed = *priority_restore;
                        // Only `watch` writes these reasons and a restore line (N1).
                        watch = is_watch || reason.watch_only() || priority_restore.is_some();
                        missing = matches!(reason, SkipReason::ProfileMissing);
                    }
                }
            }
            let note = if missing {
                // A7: after a revert or forget the option still starts the game through the shim.
                Some(match holder {
                    Some(h) if h.forgotten => LaunchNote::OptionStillSetForgotten,
                    h => LaunchNote::OptionStillSet {
                        held: h.map(|h| h.txn),
                    },
                })
            } else if let Some(start) = holder.and_then(|h| h.launcher.as_ref())
                && method == Some(ProfileMethod::Direct)
                && applied
            {
                // A6: the check covered the launcher Steam starts, not the game.
                Some(LaunchNote::CheckedLauncher(start.clone()))
            } else if let Some(target) = holder.and_then(|h| h.watch.as_ref())
                && is_watch
            {
                // P3-4c: the rule and the check concern the game process found after the start.
                Some(LaunchNote::Watched(target.clone()))
            } else {
                None
            };
            LaunchLine {
                id: e.id,
                result: e.result.clone(),
                watch,
                restore_failed,
                note,
            }
        })
        .collect()
}

/// The line of the game `app_id`: its profile ID is [`profile_id`] (one profile per game).
pub fn launch_of(lines: &[LaunchLine], app_id: u32) -> Option<&LaunchLine> {
    let id = profile_id(app_id);
    lines.iter().find(|l| l.id == id)
}
