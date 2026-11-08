//! `launch_method` (P3-3c, ADR 0020 and ADR 0022 amendments P3-3): the launch profile of a Steam
//! game for `rerun-launch`, planned as one file op on Rerun's `<LocalAppData>\Rerun\profiles`.
//!
//! What the planner decides (plan `P3-3`, F1 to F12 with the user decisions E1 a, E2 a and the
//! review conditions):
//! - **Steam only, at the canonical path** (F4): the launch option exists only in Steam, and a
//!   game folder reached through a link or another name is refused (Steam's `argv[0]` would not
//!   be the planned start, `path_mismatch`).
//! - **`start`** is the program of Steam's launch entry, explicit in the step (E2 a: `appinfo.vdf`
//!   is not read), relative to the game folder, in the spelling stored on disk; a plain `.exe`
//!   below plain folders, none case-sensitive. The profile names it absolutely, at most
//!   [`MAX_START_UNITS`] UTF-16 units (F7).
//! - **The launcher case** (F5): with `start` other than the main executable (folded) only a hard
//!   CPU rule is allowed: a soft rule (default CPU Sets) and a priority class reach only the
//!   started program, not the game it starts (ADR 0022 amendment P3-3, sources there).
//! - **Bitness** (F6, condition A8): `x86` if a program of the chain the rule reaches is i386,
//!   i.e. `start` or the main executable has machine `IMAGE_FILE_MACHINE_I386`, else `x64`. A
//!   .NET "AnyCPU" image is i386 on disk and may run as x64: counted as x86, conservatively; the
//!   cost is only on a processor group of more than 32 logical processors (ADR 0022 B6). ARM64,
//!   another machine or no PE image is refused. Read through the bounded PE parser (ADR 0013).
//! - **The rule** (F8): every field of `cpu` optional, at least one given; missing fields do not
//!   restrict (`prefer: any`, `single_l3: false`, `prefer_l3` none, `smt: true`, no
//!   `max_threads`, `mode: hard`); `max_threads` 1 to 1024; `report_cores` refused (`inproc`,
//!   phase 6); `method: auto` refused (the Topo engine chooses, phase 4). Neither `cpu` nor
//!   `priority` is refused (F9), and so is a second `launch_method` step.
//! - **`watch_timeout_s`** of a `direct` profile is [`DIRECT_WATCH_TIMEOUT_S`] (120, the format's
//!   largest value; the shim does not read it for `direct`), so equal rules give equal bytes
//!   (review N3).
//! - **The profile file**: [`plan::profile_id`] of the Steam app (E1 a) below the profiles root
//!   (path from [`PlanCtx::app`] or [`PlanCtx::app_path`]); missing → `CreateFile`; the same bytes
//!   → nothing to do; another plain file of at most 8 KiB with one link → `ReplaceFile` (a rest
//!   after `forget`; the revert restores it); a folder, a link, a reparse point or anything
//!   larger is refused (Rerun leaves what is not its own).
//!
//! [`on_this_machine`] is the preview's view of the rule on this computer: it reads only the
//! topology and is never part of the plan (CPU Set IDs are runtime values; the shim selects at
//! every start).

use rerun_proto::cpu::CpuTopology;
use rerun_proto::cpu::rule::{Bitness, CpuRule, Mode, Prefer, PreferL3, SelectError, select};
use rerun_proto::profile::{
    self as proto, LaunchProfile, MAX_WATCH_TIMEOUT_S, Method, Priority, ProfileId,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::compat_layer::stored_exe;
use super::{Builder, PlanCtx};
use crate::detect::pe::{Limits, Machine, open_game_exe};
use crate::escape::Shown;
use crate::fold::fold;
use crate::path::{RelPath, RootPath};
use crate::plan::{
    self, ContentRef, FileState, MAX_INLINE_BYTES, MAX_PROFILE_OLD_BYTES, MAX_START_UNITS, Op,
    PlanError, RootIx,
};
use crate::policy::root::GameOrigin;
use crate::sys::SysResult;
use crate::sys::fs::{Attrs, EntryKind};

/// The rule types a front end shows (`MachineView`).
pub use rerun_proto::cpu::rule::{Mode as RuleMode, SelectStep};

/// `watch_timeout_s` of a `direct` profile (review N3): the format keeps the key for every
/// method; the shim reads it only for `watch`. One fixed value, so equal rules give equal bytes.
pub const DIRECT_WATCH_TIMEOUT_S: u16 = MAX_WATCH_TIMEOUT_S;

/// Largest `max_threads` of a step (`docs/02-topo-format.md`).
pub const MAX_THREADS: u16 = 1024;

/// The `launch_method` step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchMethodSpec {
    /// How the game is started (`direct`; `auto` is refused until phase 4).
    pub method: MethodSpec,
    /// The program of Steam's launch entry (what Steam starts on Play), relative to the game
    /// folder.
    pub start: RelPath,
    /// The CPU rule.
    #[serde(default)]
    pub cpu: Option<CpuRuleSpec>,
    /// The priority class.
    #[serde(default)]
    pub priority: Option<PrioritySpec>,
}

/// `launch_method.method`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MethodSpec {
    /// Start Steam's command in a job with the limit (ADR 0022).
    Direct,
    /// Chosen by the Topo engine (phase 4): refused.
    Auto,
}

/// A CPU rule of `docs/02-topo-format.md`: every field optional, at least one given.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CpuRuleSpec {
    /// At most this many logical processors, 1 to 1024.
    #[serde(default)]
    pub max_threads: Option<u16>,
    /// Default `any`.
    #[serde(default)]
    pub prefer: Option<PreferSpec>,
    /// Default `false`.
    #[serde(default)]
    pub single_l3: Option<bool>,
    /// Default none.
    #[serde(default)]
    pub prefer_l3: Option<PreferL3Spec>,
    /// Default `true`.
    #[serde(default)]
    pub smt: Option<bool>,
    /// Default `hard`.
    #[serde(default)]
    pub mode: Option<ModeSpec>,
    /// Only with `inproc` (phase 6): refused.
    #[serde(default)]
    pub report_cores: Option<u16>,
}

/// `cpu.prefer`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PreferSpec {
    /// The highest efficiency class only.
    Performance,
    /// Every class.
    Any,
}

/// `cpu.prefer_l3`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PreferL3Spec {
    /// The largest last-level cache.
    Largest,
}

/// `cpu.mode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModeSpec {
    /// Job affinity.
    Hard,
    /// Default CPU Sets of the started program.
    Soft,
}

/// `priority`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrioritySpec {
    /// `NORMAL_PRIORITY_CLASS`.
    Normal,
    /// `ABOVE_NORMAL_PRIORITY_CLASS`.
    AboveNormal,
    /// `HIGH_PRIORITY_CLASS`.
    High,
}

fn refuse(what: impl Into<String>) -> PlanError {
    PlanError::Step(format!("launch_method: {}", what.into()))
}

/// A path for messages (ADR 0016).
fn shown(s: &str) -> String {
    crate::escape::path(s).to_string()
}

impl CpuRuleSpec {
    /// The rule with the defaults of F8, or why it is refused.
    pub fn rule(&self) -> Result<CpuRule, PlanError> {
        if self.report_cores.is_some() {
            return Err(refuse(
                "cpu.report_cores needs the in-process method (phase 6)",
            ));
        }
        if *self == Self::default() {
            return Err(refuse("cpu: {} restricts nothing; name at least one field"));
        }
        if let Some(n) = self.max_threads
            && !(1..=MAX_THREADS).contains(&n)
        {
            return Err(refuse("cpu.max_threads is 1 to 1024"));
        }
        Ok(CpuRule {
            max_threads: self.max_threads,
            prefer: match self.prefer {
                Some(PreferSpec::Performance) => Prefer::Performance,
                Some(PreferSpec::Any) | None => Prefer::Any,
            },
            single_l3: self.single_l3.unwrap_or(false),
            prefer_l3: self
                .prefer_l3
                .map(|PreferL3Spec::Largest| PreferL3::Largest),
            smt: self.smt.unwrap_or(true),
            mode: match self.mode {
                Some(ModeSpec::Soft) => Mode::Soft,
                Some(ModeSpec::Hard) | None => Mode::Hard,
            },
        })
    }
}

/// The shim's file name in Rerun's installation folder.
pub const SHIM: &str = "rerun-launch.exe";

/// The launch option for Steam, `"<install>\rerun-launch.exe" --profile <id> %command%`
/// (`install`: Rerun's installation folder, also a drive root), as text to show and copy (ADR
/// 0016). `None` if the path cannot be shown as it is (not Unicode, a quote, or a character
/// `escape::path` escapes): the escaped form would not be the path, so no option is offered. A
/// preview line; Rerun never writes it.
pub fn steam_option_text(install: &std::path::Path, id: ProfileId) -> Option<Shown<'static>> {
    let shim = install.join(SHIM);
    let shim = shim.to_str()?;
    if shim.contains('"') {
        return None;
    }
    let raw = format!("\"{shim}\" --profile {id} %command%");
    let shown = crate::escape::path(&raw).into_owned();
    (shown.as_str() == raw).then_some(shown)
}

/// The bitness of `exe` (F6): `x86` for i386, `x64` for AMD64, anything else refused.
fn bitness_of(
    game: &crate::policy::root::GameDir<'_>,
    exe: &RelPath,
) -> Result<Bitness, PlanError> {
    let pe = open_game_exe(game, exe, &Limits::DEFAULT).map_err(|e| {
        refuse(format!(
            "{}: no Windows executable ({e})",
            shown(exe.as_str())
        ))
    })?;
    match pe.headers().machine {
        Machine::X86 => Ok(Bitness::X86),
        Machine::X64 => Ok(Bitness::X64),
        Machine::Arm64 | Machine::Other(_) => Err(refuse(format!(
            "{}: neither x86 nor x64 (rerun-launch limits x86 and x64 games only)",
            shown(exe.as_str())
        ))),
    }
}

/// The path of `<LocalAppData>\Rerun` for the plan: [`PlanCtx::app`] or [`PlanCtx::app_path`].
fn app_path(ctx: &PlanCtx<'_>) -> Result<RootPath, PlanError> {
    match (ctx.app, ctx.app_path) {
        (Some(a), Some(p)) if a.path() != p => Err(refuse(
            "Rerun's folder changed while the plan was made; plan again",
        )),
        (Some(a), _) => Ok(a.path().clone()),
        (None, Some(p)) => Ok(p.clone()),
        (None, None) => Err(refuse("Rerun's folder is not known")),
    }
}

/// The op that puts `bytes` at `name` below the profiles root, or `None` if it holds them
/// already (module docs).
fn profile_op(ctx: &PlanCtx<'_>, name: &RelPath, bytes: Vec<u8>) -> Result<Option<Op>, PlanError> {
    let sha: [u8; 32] = Sha256::digest(&bytes).into();
    let content = ContentRef::Inline { bytes, sha256: sha };
    let create = |content| {
        Ok(Some(Op::CreateFile {
            root: RootIx(1),
            path: name.clone(),
            content,
            attrs: Attrs::default(),
        }))
    };
    let Some(app) = ctx.app else {
        return create(content);
    };
    let Some(dir) = app.profiles_read()? else {
        return create(content);
    };
    let Some(m) = dir.metadata(name)? else {
        return create(content);
    };
    let not_ours = |why: &str| {
        refuse(format!(
            "the profile {name} in Rerun's profiles folder {why}; Rerun leaves it as it is \
             (remove it to plan again)"
        ))
    };
    if m.kind != EntryKind::File || m.reparse.is_some() || m.restricted {
        return Err(not_ours("is a folder, a link or not readable"));
    }
    if !m.is_single_link() {
        return Err(not_ours("is hard-linked"));
    }
    if m.len > MAX_PROFILE_OLD_BYTES {
        return Err(not_ours("is larger than 8 KiB"));
    }
    let old = dir.read_limited(name, MAX_PROFILE_OLD_BYTES)?;
    let len = u64::try_from(old.len()).unwrap_or(u64::MAX);
    if len > MAX_PROFILE_OLD_BYTES {
        return Err(not_ours("is larger than 8 KiB"));
    }
    let old_sha: [u8; 32] = Sha256::digest(&old).into();
    if old_sha == sha {
        return Ok(None);
    }
    Ok(Some(Op::ReplaceFile {
        root: RootIx(1),
        path: name.clone(),
        old: FileState {
            sha256: old_sha,
            len,
            attrs: m.attrs,
        },
        content,
        attrs: Attrs::default(),
    }))
}

/// Plans `spec` into `b` (module docs).
pub(crate) fn plan_into(
    spec: &LaunchMethodSpec,
    ctx: &PlanCtx<'_>,
    b: &mut Builder,
) -> Result<(), PlanError> {
    if b.launch_method {
        return Err(refuse(
            "a second launch_method step (Steam has one launch option per game)",
        ));
    }
    b.launch_method = true;
    if spec.method == MethodSpec::Auto {
        return Err(refuse(
            "method auto is chosen by the Topo engine (phase 4); name direct",
        ));
    }
    if spec.cpu.is_none() && spec.priority.is_none() {
        return Err(refuse("neither cpu nor priority: nothing to apply"));
    }
    let rule = spec.cpu.as_ref().map(CpuRuleSpec::rule).transpose()?;
    let game = ctx.game;
    let app_id = match (game.origin(), ctx.steam_app) {
        (GameOrigin::Store { .. }, Some(id)) => id,
        _ => {
            return Err(refuse(
                "only for a Steam game (the profile is used through Steam's launch option)",
            ));
        }
    };
    // F4: Steam starts the game by the library path it lists; through a link that is not the
    // canonical path the profile names.
    if game.launch_path() != Some(game.path()) {
        return Err(refuse(format!(
            "the game folder {} is reached through a link or another name; rerun-launch would \
             not recognise Steam's start path",
            shown(&game.path().to_string())
        )));
    }
    if game.info().case_sensitive {
        return Err(refuse("the game folder is case-sensitive"));
    }
    let Some(main) = ctx.main_exe else {
        return Err(refuse("needs the game's main executable"));
    };
    let start = stored_exe(game, &spec.start, "launch_method")?;
    let launcher = fold(start.as_str()) != fold(main.as_str());
    // F5: soft rules and priority classes reach only the started program.
    if launcher {
        if rule.is_some_and(|r| r.mode == Mode::Soft) {
            return Err(refuse(format!(
                "Steam starts {}, not the game {}: CPU Sets (mode soft) reach only the started \
                 program; use mode hard (the game inherits the job) or watch (P3-4)",
                shown(start.as_str()),
                shown(main.as_str())
            )));
        }
        if spec.priority.is_some() {
            return Err(refuse(format!(
                "Steam starts {}, not the game {}: a priority class reaches only the started \
                 program; watch (P3-4) sets it on the game",
                shown(start.as_str()),
                shown(main.as_str())
            )));
        }
    }
    // F6 (A8): x86 if a program of the chain the rule reaches is i386.
    let mut bitness = bitness_of(game, &start)?;
    if bitness_of(game, main)? == Bitness::X86 {
        bitness = Bitness::X86;
    }
    let start_abs = format!(r"{}\{}", game.path(), start);
    if start_abs.encode_utf16().count() > MAX_START_UNITS {
        return Err(refuse(format!(
            "the start path {} is longer than {MAX_START_UNITS} characters",
            shown(&start_abs)
        )));
    }
    let profile = LaunchProfile {
        method: Method::Direct,
        start: start_abs.clone(),
        target: start_abs,
        bitness,
        priority: spec.priority.map(|p| match p {
            PrioritySpec::Normal => Priority::Normal,
            PrioritySpec::AboveNormal => Priority::AboveNormal,
            PrioritySpec::High => Priority::High,
        }),
        watch_timeout_s: DIRECT_WATCH_TIMEOUT_S,
        cpu: rule,
    };
    let bytes = proto::encode(&profile).map_err(|e| refuse(format!("the profile: {e}")))?;
    if bytes.len() > MAX_INLINE_BYTES {
        return Err(refuse("the profile is larger than 2 KiB"));
    }
    let profiles = app_path(ctx)?
        .child("profiles")
        .map_err(|e| refuse(e.to_string()))?;
    let name = plan::profile_file(plan::profile_id(app_id));
    if let Some(op) = profile_op(ctx, &name, bytes)? {
        b.profile = Some((op, profiles));
    }
    Ok(())
}

/// What a rule selects on this computer now (preview only, never in the plan).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineView {
    /// The selection, or why there is none.
    pub selection: Result<SelectionShown, MachineWhy>,
    /// Processor groups of this computer (0 if the topology is unknown).
    pub groups: u16,
    /// A 32-bit game on a group of more than 32 logical processors (ADR 0022 B6): it gets
    /// processors 0 to 31 of that group only.
    pub x86_capped: bool,
}

/// A selection for display.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectionShown {
    /// Selected logical processors.
    pub threads: u16,
    /// Logical processors of the computer.
    pub of: u16,
    /// The processor group.
    pub group: u16,
    /// The affinity mask in that group.
    pub mask: u64,
    /// The physical cores, ascending.
    pub cores: Vec<u32>,
    /// The one last-level cache of the selection (number, level, bytes), if it is one.
    pub llc: Option<(u32, u8, u64)>,
    /// Hard (job affinity) or soft (CPU Sets of the started program).
    pub mode: Mode,
}

/// Why there is no selection to show.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MachineWhy {
    /// The profile has no CPU rule (priority only).
    NoRule,
    /// The topology cannot be read or is invalid (the reason, escaped); `rerun-launch` decides
    /// at every start.
    Topology(String),
    /// The rule selects nothing here; the game would start unchanged.
    Empty {
        /// The step that emptied the candidates.
        after: SelectStep,
    },
}

/// The rule of `p` on the topology `topo` (module docs).
pub fn on_this_machine(topo: SysResult<CpuTopology>, p: &LaunchProfile) -> MachineView {
    let topo = match topo {
        Ok(t) => t,
        Err(e) => {
            return MachineView {
                selection: Err(MachineWhy::Topology(
                    crate::escape::text(&e.to_string()).to_string(),
                )),
                groups: 0,
                x86_capped: false,
            };
        }
    };
    let mut groups: Vec<u16> = topo.cpus.iter().map(|c| c.group).collect();
    groups.sort_unstable();
    groups.dedup();
    let groups = u16::try_from(groups.len()).unwrap_or(u16::MAX);
    let Some(rule) = &p.cpu else {
        return MachineView {
            selection: Err(MachineWhy::NoRule),
            groups,
            x86_capped: false,
        };
    };
    let sel = match select(&topo, rule, p.bitness) {
        Ok(s) => s,
        Err(SelectError::Empty { after }) => {
            return MachineView {
                selection: Err(MachineWhy::Empty { after }),
                groups,
                x86_capped: false,
            };
        }
        Err(e @ SelectError::Invalid(_)) => {
            return MachineView {
                selection: Err(MachineWhy::Topology(
                    crate::escape::text(&e.to_string()).to_string(),
                )),
                groups,
                x86_capped: false,
            };
        }
    };
    let chosen: Vec<_> = topo
        .cpus
        .iter()
        .filter(|c| c.group == sel.group && sel.mask & (1u64 << c.index) != 0)
        .collect();
    let mut cores: Vec<u32> = chosen.iter().map(|c| c.core).collect();
    cores.sort_unstable();
    cores.dedup();
    let llc = match chosen.first() {
        Some(f) if chosen.iter().all(|c| c.llc == f.llc) => usize::try_from(f.llc)
            .ok()
            .and_then(|i| topo.llcs.get(i))
            .map(|l| (f.llc, l.level, l.size)),
        _ => None,
    };
    let in_group = topo.cpus.iter().filter(|c| c.group == sel.group).count();
    MachineView {
        selection: Ok(SelectionShown {
            threads: sel.threads,
            of: sel.of,
            group: sel.group,
            mask: sel.mask,
            cores,
            llc,
            mode: rule.mode,
        }),
        groups,
        x86_capped: p.bitness == Bitness::X86 && in_group > 32,
    }
}
