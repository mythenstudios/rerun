//! What the preview of a launch profile shows beyond the plan (P3-3d; moved from the CLI with
//! P5-5a, ADR 0027 amendment P5-5a): the CPU selection on this computer now, the Steam launch
//! option the user pastes, and whether `rerun-launch.exe` is there. Typed values, no text: the
//! CLI renders them through its `messages`, the app through its view models.

use std::path::PathBuf;

use crate::escape::{self, Shown};
use crate::exec::launch_result::ProfileId;
use crate::plan::Preview;
use crate::policy::root::file_present;
use crate::prim::{MachineView, SHIM, on_this_machine, steam_option_text};
use crate::sys::System;

use super::profile_of;

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
