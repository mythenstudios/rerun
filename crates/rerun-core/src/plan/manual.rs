//! Manual steps ("Advanced", ADR 0029): what the user chose for a game themselves, recorded in
//! [`super::Plan::manual`] for display ("your own setting") and for filling the form again.
//!
//! The type is the allowlist: a launch part (`method` `direct` or `watch`, a CPU rule, a
//! priority), compatibility flags (tokens of the add allowlist, on the plan's main executable)
//! and, for a game without a matched Topo (slice E-1b), the two executables. There is no field
//! through which a path the user types, a download, a script, a registry or INI value, a
//! firewall rule, a `run` executable or game arguments could enter. Like `PlanSource`, nothing
//! of it authorises anything when read back: the ops are the truth.
//!
//! [`Manual::check`] is the one form check: the CLI flags and the app's fields are parsed into
//! a `Manual` and checked by it before any system access, and the plan format checks it again
//! on encode and decode (the token allowlist only with the rules in force now, so a recorded
//! head keeps decoding if the list shrinks, ADR 0018 open point P2-10b).

use serde::{Deserialize, Serialize};

use super::Rules;
use crate::path::RelPath;
use crate::policy::registry::TokenName;
use crate::policy::registry::layers::{self, MAX_ADD};
use crate::prim::{CpuRuleSpec, MethodSpec, PrioritySpec};

/// The user's own launch settings and compatibility flags for one game (module docs).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manual {
    /// The rule part of the launch profile: method, CPU rule, priority.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub launch: Option<ManualLaunch>,
    /// Compatibility flags for the plan's main executable, 0 to 8 tokens of the add allowlist
    /// (`policy::registry::layers::LAYER_TOKENS`), each once.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub layers: Vec<TokenName>,
    /// The executables of a game without a matched Topo (ADR 0029, slice E-1b): refused by the
    /// planner until that slice, and always with a matched Topo.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exe: Option<ManualExe>,
}

/// The rule part of the launch profile the user chose.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManualLaunch {
    /// `direct` or `watch`; absent: the Topo's resolved method (`direct` without a Topo).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<ManualMethod>,
    /// The CPU rule (every field of `docs/02-topo-format.md` but `report_cores`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu: Option<CpuRuleSpec>,
    /// The priority class.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority: Option<PrioritySpec>,
}

/// The launch methods a manual rule may use: never `auto`, `hold`, `ifeo` or `inproc`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManualMethod {
    /// The shim starts the program in a job with the rule (ADR 0022).
    Direct,
    /// The shim starts Steam's command unchanged and sets the rule on the main executable
    /// (ADR 0022 amendment P3-4).
    Watch,
}

impl ManualMethod {
    /// The method of the `launch_method` step.
    pub fn spec(self) -> MethodSpec {
        match self {
            Self::Direct => MethodSpec::Direct,
            Self::Watch => MethodSpec::Watch,
        }
    }
}

/// The executables of a game without a matched Topo (slice E-1b): each one of the game's
/// detected main-executable candidates, never a free path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManualExe {
    /// The executable that identifies the game (asked before apply and revert, D4).
    pub main_exe: RelPath,
    /// Steam's launch entry (the program the shim is started for).
    pub start: RelPath,
}

/// Why a manual selection is refused by its form.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ManualError {
    /// Nothing chosen.
    #[error("your own settings name nothing: set a CPU rule, a priority or a compatibility flag")]
    Empty,
    /// A launch part without a rule and a priority.
    #[error(
        "your own launch settings need a CPU rule or a priority (the method alone changes \
         nothing)"
    )]
    NoRule,
    /// The CPU rule is refused (`report_cores`, nothing restricted, `max_threads` out of range).
    #[error("your own CPU rule: {0}")]
    Cpu(String),
    /// More than [`MAX_ADD`] flags.
    #[error("at most {MAX_ADD} compatibility flags")]
    TooManyLayers,
    /// A flag twice.
    #[error("the compatibility flag {0} is named twice")]
    LayerTwice(String),
    /// A flag that is not on the add allowlist.
    #[error(
        "{0} is not a compatibility flag Rerun sets (DISABLEDXMAXIMIZEDWINDOWEDMODE: disable \
         fullscreen optimisations; HIGHDPIAWARE: DPI scaling by the application)"
    )]
    LayerNotAllowed(String),
}

impl Manual {
    /// The form rules (module docs), with the rules in force now.
    ///
    /// # Errors
    /// [`ManualError`].
    pub fn check(&self) -> Result<(), ManualError> {
        self.check_with(Rules::Current)
    }

    /// The form rules with `rules`: [`Rules::Recorded`] keeps every rule but the allowlist.
    pub(crate) fn check_with(&self, rules: Rules) -> Result<(), ManualError> {
        if self.launch.is_none() && self.layers.is_empty() {
            return Err(ManualError::Empty);
        }
        if let Some(l) = &self.launch {
            if l.cpu.is_none() && l.priority.is_none() {
                return Err(ManualError::NoRule);
            }
            if let Some(c) = &l.cpu {
                c.rule().map_err(|e| {
                    ManualError::Cpu(
                        e.to_string()
                            .trim_start_matches("launch_method: ")
                            .to_owned(),
                    )
                })?;
            }
        }
        if self.layers.len() > MAX_ADD {
            return Err(ManualError::TooManyLayers);
        }
        for (i, t) in self.layers.iter().enumerate() {
            if self.layers[..i].contains(t) {
                return Err(ManualError::LayerTwice(t.to_string()));
            }
            if rules == Rules::Current && !layers::allowed(t) {
                return Err(ManualError::LayerNotAllowed(t.to_string()));
            }
        }
        Ok(())
    }

    /// The method the launch part asks for, with `default` (the Topo's resolved method) when
    /// it names none.
    pub fn method_or(&self, default: MethodSpec) -> Option<MethodSpec> {
        self.launch
            .as_ref()
            .map(|l| l.method.map_or(default, ManualMethod::spec))
    }
}
