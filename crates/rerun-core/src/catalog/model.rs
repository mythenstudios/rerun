//! The typed Topo and package (ADR 0005: the runtime authority from phase 4) and the signed
//! bundle [`Index`] (ADR 0024).
//!
//! Every struct is `deny_unknown_fields`; a field that is optional in the schema is an `Option`
//! that refuses an explicit `null` (`present`), a list the schema allows to be empty is a `Vec`
//! (empty and missing are the same and are not written), a list with `minItems: 1` an
//! `Option<Vec<_>>` whose emptiness [`super::check`] refuses. Paths are [`RelPath`], hashes
//! [`Hex`] (`TODO` or upper-case hex), maps `BTreeMap`: serialising gives one canonical form,
//! the bytes of the bundle (`rerun-workbench index build`).
//!
//! The form rules the types cannot carry (patterns, lengths, unique items, the download forms)
//! are in [`super::check`]; the step types of the planners are reused (`RegistrySetSpec`,
//! `CompatLayerSpec`, `IniSetSpec`, `CpuRuleSpec`), their rules in force now stay the
//! planners'.

use std::collections::BTreeMap;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::detect::exe::AntiCheat;
use crate::hw::arch::ArchId;
use crate::path::RelPath;
use crate::policy::firewall::Direction;
use crate::prim::{
    CompatLayerSpec, CpuRuleSpec, GpuPreferenceSpec, IniSetSpec, PrioritySpec, RegistrySetSpec,
    UserDataSpec,
};

/// The one value of `format` (Topo, package, index).
pub const FORMAT: u32 = 1;

/// The placeholder for an unknown value (`docs/02-topo-format.md`, "TODO").
pub const TODO: &str = "TODO";

/// Refuses an explicit `null` for an optional field (the schema has no `null`).
fn present<'de, D: Deserializer<'de>, T: Deserialize<'de>>(d: D) -> Result<Option<T>, D::Error> {
    T::deserialize(d).map(Some)
}

fn is_false(b: &bool) -> bool {
    !*b
}

/// A hash of `N` bytes as `2N` upper-case hex digits, or `TODO` (only in a draft; the release
/// index refuses it).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Hex<const N: usize>(Option<[u8; N]>);

/// A SHA-1 (`match.exes[].sha1`, `supports_exe_sha1`).
pub type Sha1 = Hex<20>;
/// A SHA-256.
pub type Sha256 = Hex<32>;

impl<const N: usize> Hex<N> {
    /// Parses `TODO` or exactly `2N` upper-case hex digits.
    pub fn parse(s: &str) -> Option<Self> {
        if s == TODO {
            return Some(Self(None));
        }
        let b = s.as_bytes();
        if b.len() != 2 * N {
            return None;
        }
        let digit = |c: u8| match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        };
        let mut out = [0u8; N];
        for (i, o) in out.iter_mut().enumerate() {
            *o = digit(b[2 * i])? << 4 | digit(b[2 * i + 1])?;
        }
        Some(Self(Some(out)))
    }

    /// The hash from its bytes.
    pub const fn new(bytes: [u8; N]) -> Self {
        Self(Some(bytes))
    }

    /// The bytes; `None` for `TODO`.
    pub fn bytes(&self) -> Option<&[u8; N]> {
        self.0.as_ref()
    }

    /// `TODO`.
    pub fn is_todo(&self) -> bool {
        self.0.is_none()
    }
}

impl<const N: usize> std::fmt::Display for Hex<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.0 {
            None => f.write_str(TODO),
            Some(b) => b.iter().try_for_each(|x| write!(f, "{x:02X}")),
        }
    }
}

impl<const N: usize> Serialize for Hex<N> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de, const N: usize> Deserialize<'de> for Hex<N> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Self::parse(&s).ok_or_else(|| {
            serde::de::Error::custom(format!("expected {} upper-case hex digits or TODO", 2 * N))
        })
    }
}

/// An ID: lower-case letters, digits and single hyphens, at most 64 characters.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Id(String);

impl Id {
    /// Most characters.
    pub const MAX_LEN: usize = 64;

    /// Checks the form `^[a-z0-9]+(-[a-z0-9]+)*$`, at most [`Self::MAX_LEN`].
    pub fn parse(s: &str) -> Option<Self> {
        let ok = !s.is_empty()
            && s.len() <= Self::MAX_LEN
            && s.split('-').all(|p| {
                !p.is_empty()
                    && p.bytes()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
            });
        ok.then(|| Self(s.to_owned()))
    }

    /// The ID.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for Id {
    type Error = String;
    fn try_from(s: String) -> Result<Self, String> {
        Self::parse(&s).ok_or_else(|| "not an ID (a-z, 0-9 and single hyphens, at most 64)".into())
    }
}

impl From<Id> for String {
    fn from(i: Id) -> Self {
        i.0
    }
}

impl std::fmt::Display for Id {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// The status of a Topo or package.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Status {
    /// Not curated; never in a release index.
    Draft,
    /// Curated.
    Active,
    /// Curated, to be tested again.
    NeedsRetest,
    /// No longer offered.
    Retired,
}

/// A graphics API of `$defs/api`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Api {
    /// DirectDraw.
    Ddraw,
    /// Direct3D 8.
    D3d8,
    /// Direct3D 9.
    D3d9,
    /// Direct3D 10.
    D3d10,
    /// Direct3D 11.
    D3d11,
    /// OpenGL.
    Opengl,
}

/// A CPU architecture of a package build.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Arch {
    /// 32-bit x86.
    X86,
    /// x64.
    X64,
}

impl Arch {
    /// Its spelling (`x86`, `x64`): also the folder of its build below the version folder of a
    /// package with `assets` (ADR 0025 part 2).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::X86 => "x86",
            Self::X64 => "x64",
        }
    }
}

/// `fix` or `enhancement`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    /// The game runs as intended.
    Fix,
    /// Beyond the original.
    Enhancement,
}

// ---------- Topo ----------

/// A Topo (`docs/02-topo-format.md`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Topo {
    /// [`FORMAT`].
    pub format: u32,
    /// The ID (= file name).
    pub id: Id,
    /// The game's title.
    pub title: String,
    /// The status.
    pub status: Status,
    /// The revision, from 1.
    pub rev: u32,
    /// `x64`, `arm64`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tested_on: Vec<Platform>,
    /// How the game is recognised.
    #[serde(rename = "match")]
    pub matches: Match,
    /// How it is started.
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub launch: Option<Launch>,
    /// Anti-cheat systems of this game that are verifiably dead (P4-4, user decision E4): the
    /// engine does not enforce the anti-cheat rule for them. Draft only until reviewed
    /// ([`super::check::ANTI_CHEAT_RELEASE_REVIEWED`]).
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub anti_cheat: Option<AntiCheatRelease>,
    /// The game's own folder below a known folder of the user (P4-12): `{documents: 'My
    /// Games\X'}`, named once; an `ini_set` with `root: user_data` sets keys of a file there.
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub user_data: Option<UserDataSpec>,
    /// The problems and their solutions.
    pub issues: Vec<Issue>,
    /// Hints.
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub tips: Option<Tips>,
    /// Links.
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub links: Option<Links>,
}

/// `anti_cheat`: systems a signed Topo releases as dead, with the source that shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AntiCheatRelease {
    /// The dead systems, at least one, unique.
    pub dead: Vec<AntiCheat>,
    /// Where it is shown that they are dead (servers shut down, checks off).
    pub source: Source,
}

/// `tested_on`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Platform {
    /// x64 Windows.
    X64,
    /// Arm64 Windows.
    Arm64,
}

/// `match`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Match {
    /// The Steam app ID, 1 to `u32::MAX`.
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub steam_appid: Option<u32>,
    /// The executables, at least one.
    pub exes: Vec<Exe>,
}

/// One executable of `match.exes`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Exe {
    /// Relative to the game folder.
    pub path: RelPath,
    /// SHA-1 of the file.
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub sha1: Option<Sha1>,
    /// SHA-256 of the file: required where the exe anchors an elevated op (P4 R6).
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub sha256: Option<Sha256>,
    /// Its graphics API.
    pub api: Api,
}

/// `launch`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Launch {
    /// The launchers in the chain, unique.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub chain: Vec<Chain>,
    /// The launch method.
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub method: Option<Method>,
    /// The fallback (never `auto`).
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub fallback: Option<Fallback>,
    /// The CPU rule (`report_cores` only with `inproc`).
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub cpu: Option<CpuRuleSpec>,
    /// The program of Steam's launch entry, a `.exe`.
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub start: Option<RelPath>,
    /// The priority class.
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub priority: Option<PrioritySpec>,
}

/// A launcher of `launch.chain`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Chain {
    /// Steam.
    Steam,
    /// Ubisoft Connect.
    Upc,
    /// EA app.
    EaApp,
    /// Rockstar Games Launcher.
    Rockstar,
    /// Battle.net.
    Battlenet,
    /// Epic Games Launcher.
    Epic,
    /// GOG Galaxy.
    GogGalaxy,
}

/// `launch.method`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Method {
    /// Chosen by the engine.
    Auto,
    /// `direct`.
    Direct,
    /// `watch`.
    Watch,
    /// `hold`.
    Hold,
    /// `ifeo`.
    Ifeo,
    /// `inproc`.
    Inproc,
}

/// `launch.fallback`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Fallback {
    /// `direct`.
    Direct,
    /// `watch`.
    Watch,
    /// `hold`.
    Hold,
    /// `ifeo`.
    Ifeo,
    /// `inproc`.
    Inproc,
}

/// One issue.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Issue {
    /// Unique in the Topo.
    pub id: Id,
    /// What happens.
    pub title: String,
    /// On which systems (empty or missing: all).
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub when: Option<When>,
    /// Runtime hints.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub checks: Vec<Check>,
    /// The solutions (may be empty: "no known fix").
    pub variants: Vec<Variant>,
}

/// `when` (ADR 0015): several keys are AND; the GPU keys `gpu.vendor`, `gpu.arch` and
/// `gpu.integrated` are checked together on each hardware adapter (P4-11).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct When {
    /// `gpu.vendor`.
    #[serde(
        rename = "gpu.vendor",
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub gpu_vendor: Option<Vendor>,
    /// `gpu.arch`, at least one, unique.
    #[serde(
        rename = "gpu.arch",
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub gpu_arch: Option<Vec<ArchIdText>>,
    /// `gpu.integrated` (P4-11): the table's `integrated` of the adapter.
    #[serde(
        rename = "gpu.integrated",
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub gpu_integrated: Option<bool>,
    /// `gpu.hybrid` (P4-11): at least two hardware adapters.
    #[serde(
        rename = "gpu.hybrid",
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub gpu_hybrid: Option<bool>,
    /// `cpu.threads`.
    #[serde(
        rename = "cpu.threads",
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub cpu_threads: Option<Compare>,
    /// `cpu.hybrid`.
    #[serde(
        rename = "cpu.hybrid",
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub cpu_hybrid: Option<bool>,
    /// `os.build`.
    #[serde(
        rename = "os.build",
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub os_build: Option<Compare>,
}

/// A GPU architecture identifier of `when.gpu.arch` (the rule of [`ArchId::new`]).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ArchIdText(ArchId);

impl ArchIdText {
    /// The identifier.
    pub fn id(&self) -> &ArchId {
        &self.0
    }
}

impl TryFrom<String> for ArchIdText {
    type Error = String;
    fn try_from(s: String) -> Result<Self, String> {
        ArchId::new(&s).map(Self).map_err(|e| e.to_string())
    }
}

impl From<ArchIdText> for String {
    fn from(a: ArchIdText) -> Self {
        a.0.as_str().to_owned()
    }
}

/// `gpu.vendor`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Vendor {
    /// AMD.
    Amd,
    /// NVIDIA.
    Nvidia,
    /// Intel.
    Intel,
}

/// A comparison of `cpu.threads` or `os.build`; at least one key, several are AND.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Compare {
    /// Greater than.
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub gt: Option<i64>,
    /// Greater or equal.
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub gte: Option<i64>,
    /// Less than.
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub lt: Option<i64>,
    /// Less or equal.
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub lte: Option<i64>,
    /// Equal.
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub eq: Option<i64>,
}

/// A runtime hint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Check {
    /// The runtime.
    pub runtime: Runtime,
}

/// A runtime outside the game folder.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Runtime {
    /// Visual C++ x86.
    VcredistX86,
    /// Visual C++ x64.
    VcredistX64,
    /// DirectX June 2010.
    #[serde(rename = "directx-jun2010")]
    DirectxJun2010,
}

/// One solution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Variant {
    /// Unique in the issue.
    pub id: Id,
    /// How well it is tested.
    pub status: VariantStatus,
    /// `fix` or `enhancement`.
    pub kind: Kind,
    /// The steps, at least one.
    pub steps: Vec<TopoStep>,
    /// Side effects.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tradeoffs: Vec<String>,
    /// Where it comes from.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sources: Vec<Source>,
}

/// The status of a variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VariantStatus {
    /// Tested by us.
    Verified,
    /// Several independent reports.
    Reported,
    /// A single statement.
    Unverified,
}

/// One step of a variant: exactly one key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum TopoStep {
    /// A package by ID.
    Package(Id),
    /// `steam_input: enable` (a hint).
    SteamInput(SteamInput),
    /// A CPU rule (without `report_cores`).
    Cpu(CpuRuleSpec),
    /// `registry_set`.
    RegistrySet(RegistrySetSpec),
    /// `compat_layer`.
    CompatLayer(CompatLayerSpec),
    /// `ini_set`.
    IniSet(IniSetSpec),
    /// `firewall_rule` (P4-5a): Rerun's block rule for one executable of `match.exes`.
    FirewallRule(FirewallRuleSpec),
    /// `laa_patch` (P4-10): the Large Address Aware flag of one 32-bit executable of
    /// `match.exes`.
    LaaPatch(LaaPatchStep),
    /// `gpu_preference` (P4-11): Windows' graphics preference of one executable of
    /// `match.exes` (reviewed since P4-11, [`super::check::GPU_PREFERENCE_REVIEWED`]).
    GpuPreference(GpuPreferenceSpec),
}

impl TopoStep {
    /// The root the step's file lies in (P4-12), as [`crate::prim::Step::root`].
    pub fn root(&self) -> crate::prim::StepRoot {
        match self {
            Self::IniSet(i) => i.root,
            Self::Package(_)
            | Self::SteamInput(_)
            | Self::Cpu(_)
            | Self::RegistrySet(_)
            | Self::CompatLayer(_)
            | Self::FirewallRule(_)
            | Self::LaaPatch(_)
            | Self::GpuPreference(_) => crate::prim::StepRoot::Game,
        }
    }
}

/// `laa_patch` (P4-10, ADR 0020 amendment P4-10): set the Large Address Aware flag of one
/// executable of `match.exes` that carries a `sha256` (the loader rule of ADR 0024, P4 R6, in
/// exactly its spelling). Draft only until reviewed ([`super::check::LAA_PATCH_REVIEWED`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaaPatchStep {
    /// The executable, a `match.exes` path.
    pub exe: RelPath,
}

/// `firewall_rule` (ADR 0023 §6, P4-5a): block the network of one executable of `match.exes`
/// that carries a `sha256` (the loader rule of ADR 0024, P4 R6). Reviewed since P4-5b
/// ([`super::check::FIREWALL_RULE_REVIEWED`]; draft only before); the engine plans it from P4-2d.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FirewallRuleSpec {
    /// The executable, a `match.exes` path.
    pub exe: RelPath,
    /// `out` or `in`.
    pub direction: Direction,
}

/// `steam_input`: only `enable`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SteamInput {
    /// Enable Steam Input for the game.
    Enable,
}

/// A source link.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Source {
    /// Its type.
    #[serde(rename = "type")]
    pub kind: SourceType,
    /// The link (the rule of its type).
    pub url: String,
}

/// The type of a [`Source`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SourceType {
    /// A forge repository.
    Repo,
    /// A Steam guide.
    SteamGuide,
    /// A Steam discussion thread.
    SteamThread,
    /// A PCGamingWiki page.
    Pcgw,
    /// An official page.
    Official,
}

/// `tips`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tips {
    /// Game arguments after `%command%`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub launch_options: Vec<String>,
    /// Notes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<Note>,
}

/// A note.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Note {
    /// The text (never HTML).
    pub text: String,
    /// Its source.
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub source: Option<Source>,
}

/// `links`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Links {
    /// A PCGamingWiki page name.
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub pcgw: Option<String>,
}

// ---------- Package ----------

/// A package: one upstream tool at one pinned version (user decision E2 a).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Package {
    /// [`FORMAT`].
    pub format: u32,
    /// The ID (= file name).
    pub id: Id,
    /// Its name.
    pub name: String,
    /// The status.
    pub status: Status,
    /// The source tier (`docs/05-sources-policy.md`).
    pub tier: Tier,
    /// Where it comes from.
    pub source: PackageSource,
    /// The pinned version.
    pub version: String,
    /// SHA-256 of the one download.
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub sha256: Option<Sha256>,
    /// One download per architecture instead.
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub assets: Option<Vec<Asset>>,
    /// An SPDX expression or `TODO`.
    pub license: String,
    /// The architectures (or `TODO`).
    pub arch: ArchList,
    /// The graphics APIs it wraps.
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub apis: Option<Vec<Api>>,
    /// The DLL names it occupies.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub slots: Vec<String>,
    /// The DLL names it occupies per API.
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub slots_by_api: Option<BTreeMap<Api, Vec<String>>>,
    /// Shared dependencies.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub requires: Vec<Id>,
    /// GPU prerequisites.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub requires_gpu: Vec<GpuRequirement>,
    /// The exe versions it is built for.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub supports_exe_sha1: Vec<Sha1>,
    /// The files it installs.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub files: Vec<PackageFile>,
    /// INI toggles.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub options: BTreeMap<String, PackageOption>,
}

impl Package {
    /// The downloads a file comes from (ADR 0025 part 2, the one placement rule of the loader,
    /// the extraction and the planner): `[None]` for a package with one download; with
    /// `assets`, the file's `arch`, or every asset's architecture when it has none (whether an
    /// asset exists for each is the caller's check).
    pub fn file_archs(&self, f: &PackageFile) -> Vec<Option<Arch>> {
        match (&self.assets, &f.arch) {
            (None, _) => vec![None],
            (Some(_), Some(a)) => a.iter().copied().map(Some).collect(),
            (Some(assets), None) => assets.iter().map(|a| Some(a.arch)).collect(),
        }
    }

    /// Where `f` lies below the version folder for `arch` (pure): its `from` for a package with
    /// one download (whatever `arch`); `<arch>\<from>` with `assets`, `None` if `arch` is
    /// `None`, the file is not for it, or no asset is.
    pub fn place(&self, f: &PackageFile, arch: Option<Arch>) -> Option<RelPath> {
        let Some(assets) = &self.assets else {
            return Some(f.from.clone());
        };
        let arch = arch?;
        let for_arch = f.arch.as_ref().is_none_or(|a| a.contains(&arch));
        if !for_arch || !assets.iter().any(|a| a.arch == arch) {
            return None;
        }
        RelPath::parse(&format!("{}\\{}", arch.as_str(), f.from.as_str())).ok()
    }
}

/// The source tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Tier {
    /// The original author's release.
    Official,
    /// An established project.
    Established,
    /// A community build: the user downloads it.
    Community,
}

/// `source`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageSource {
    /// The forge repository.
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub repo: Option<String>,
    /// The original page.
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub page: Option<String>,
    /// The release download (or `TODO`).
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub release: Option<String>,
}

/// One download per architecture.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Asset {
    /// The architecture.
    pub arch: Arch,
    /// The download (or `TODO`).
    pub url: String,
    /// Its SHA-256.
    pub sha256: Sha256,
}

/// `arch`: a list or `TODO`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ArchList {
    /// The architectures, at least one, unique.
    List(Vec<Arch>),
    /// Unknown (draft only).
    Todo(TodoMark),
}

/// The string `TODO` and nothing else.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct TodoMark;

impl TryFrom<String> for TodoMark {
    type Error = &'static str;
    fn try_from(s: String) -> Result<Self, &'static str> {
        if s == TODO {
            Ok(Self)
        } else {
            Err("expected TODO")
        }
    }
}

impl From<TodoMark> for String {
    fn from(_: TodoMark) -> Self {
        TODO.to_owned()
    }
}

/// `requires_gpu`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GpuRequirement {
    /// A Vulkan driver.
    Vulkan,
}

/// One file of a package.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageFile {
    /// Below the version folder.
    pub from: RelPath,
    /// Below the game folder.
    pub to: RelPath,
    /// SHA-256 of the file (required, user decision E2 a; `TODO` only in a draft).
    pub sha256: Sha256,
    /// The user may edit it.
    #[serde(default, skip_serializing_if = "is_false")]
    pub config: bool,
    /// Only for these architectures.
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub arch: Option<Vec<Arch>>,
    /// Only for these APIs.
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub api: Option<Vec<Api>>,
}

/// An INI toggle of a package.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageOption {
    /// Where it is set.
    pub ini: OptionIni,
    /// Its default.
    pub default: OptionValue,
    /// `fix` or `enhancement`.
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub kind: Option<Kind>,
}

/// The INI key of an option.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OptionIni {
    /// The file, below the game folder.
    pub file: RelPath,
    /// The section.
    pub section: String,
    /// The key.
    pub key: String,
}

/// The default of an option.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum OptionValue {
    /// A switch.
    Bool(bool),
    /// A number.
    Int(i64),
    /// A text.
    Text(String),
}

// ---------- Index ----------

/// The signed bundle (ADR 0024): every released Topo and package, sorted by ID.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Index {
    /// [`FORMAT`].
    pub format: u32,
    /// Monotonic sequence number, from 1; a lower one than the last accepted is a rollback.
    pub seq: u64,
    /// When it was built, `YYYY-MM-DDTHH:MM:SSZ` (UTC).
    pub issued: String,
    /// The Topos, sorted by ID.
    pub topos: Vec<Topo>,
    /// The packages, sorted by ID.
    pub packages: Vec<Package>,
}
