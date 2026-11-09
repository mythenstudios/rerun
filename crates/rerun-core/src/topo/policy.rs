//! The anti-cheat rule of the Topo engine (P4-4, user decision E4 "a+" of the phase 4 plan).
//!
//! When `detect::exe::anti_cheat` finds a system in the game folder (or cannot check a marker),
//! every step kind gets one rule from [`ANTI_CHEAT_RULES`], also the kinds that come later
//! (`package` in P4-7, `firewall_rule` in P4-5, `laa_patch` in P4-10, `gpu_preference` in
//! P4-11), so their planners inherit it rather than define it:
//!
//! - **Refused:** anything that changes modules, the executable, how it is loaded or its
//!   network (`package`, `laa_patch`, `firewall_rule`, `compat_layer`), and the launch methods
//!   `watch` (it opens the protected game process to set the rule), `hold`, `ifeo` and `inproc`
//!   (they open the process, sit in its start or run inside it).
//! - **Warned:** settings outside the game's code (the CPU rule of `direct`, which sets it on
//!   the program Steam starts, `ini_set`, `registry_set`, `gpu_preference`).
//! - **Nothing:** `steam_input` (a hint, Rerun changes nothing).
//!
//! A signed Topo may release a system as dead (`anti_cheat.dead`, with a source); a system
//! found that is released this way does not count. An unreadable marker always counts.

/// The kind of a step as the anti-cheat rule sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum StepKind {
    /// `package` (P4-7): files in the game folder.
    Package,
    /// `laa_patch` (P4-10): patches the executable.
    LaaPatch,
    /// `firewall_rule` (P4-5): blocks the executable's network.
    FirewallRule,
    /// `compat_layer`: shims loaded into the game.
    CompatLayer,
    /// A CPU rule with `watch`: the game process is opened after the start.
    LaunchWatch,
    /// A CPU rule with `direct`: on the program Steam starts, in a job.
    LaunchDirect,
    /// A CPU rule with `hold` (later phase): Rerun waits on the game process.
    LaunchHold,
    /// A CPU rule with `ifeo` (later phase): a debugger entry starts the game.
    LaunchIfeo,
    /// A CPU rule with `inproc` (phase 6): a plugin inside the game.
    LaunchInproc,
    /// `ini_set`.
    IniSet,
    /// `registry_set`.
    RegistrySet,
    /// `gpu_preference` (P4-11).
    GpuPreference,
    /// `steam_input`: a hint.
    SteamInput,
}

impl StepKind {
    /// The name in the Topo format.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Package => "package",
            Self::LaaPatch => "laa_patch",
            Self::FirewallRule => "firewall_rule",
            Self::CompatLayer => "compat_layer",
            Self::LaunchWatch => "cpu (watch)",
            Self::LaunchDirect => "cpu (direct)",
            Self::LaunchHold => "cpu (hold)",
            Self::LaunchIfeo => "cpu (ifeo)",
            Self::LaunchInproc => "cpu (inproc)",
            Self::IniSet => "ini_set",
            Self::RegistrySet => "registry_set",
            Self::GpuPreference => "gpu_preference",
            Self::SteamInput => "steam_input",
        }
    }
}

/// What the anti-cheat rule does with a step kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcRule {
    /// The step is refused.
    Refuse,
    /// The step is planned with a warning.
    Warn,
    /// Nothing changes on the system: no rule.
    None,
}

/// The rule of every step kind (module docs).
pub const ANTI_CHEAT_RULES: [(StepKind, AcRule); 13] = [
    (StepKind::Package, AcRule::Refuse),
    (StepKind::LaaPatch, AcRule::Refuse),
    (StepKind::FirewallRule, AcRule::Refuse),
    (StepKind::CompatLayer, AcRule::Refuse),
    (StepKind::LaunchWatch, AcRule::Refuse),
    (StepKind::LaunchHold, AcRule::Refuse),
    (StepKind::LaunchIfeo, AcRule::Refuse),
    (StepKind::LaunchInproc, AcRule::Refuse),
    (StepKind::LaunchDirect, AcRule::Warn),
    (StepKind::IniSet, AcRule::Warn),
    (StepKind::RegistrySet, AcRule::Warn),
    (StepKind::GpuPreference, AcRule::Warn),
    (StepKind::SteamInput, AcRule::None),
];

/// The rule of `k` (exhaustive; a test binds it to [`ANTI_CHEAT_RULES`]).
pub fn anti_cheat_rule(k: StepKind) -> AcRule {
    match k {
        StepKind::Package
        | StepKind::LaaPatch
        | StepKind::FirewallRule
        | StepKind::CompatLayer
        | StepKind::LaunchWatch
        | StepKind::LaunchHold
        | StepKind::LaunchIfeo
        | StepKind::LaunchInproc => AcRule::Refuse,
        StepKind::LaunchDirect
        | StepKind::IniSet
        | StepKind::RegistrySet
        | StepKind::GpuPreference => AcRule::Warn,
        StepKind::SteamInput => AcRule::None,
    }
}
