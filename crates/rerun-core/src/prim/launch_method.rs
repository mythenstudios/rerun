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
//!   [`MAX_EXE_PATH_UNITS`] UTF-16 units (F7).
//! - **`run` and `args`** (ADR 0022 and ADR 0032 amendments P5-OE, profile format 3; `direct`
//!   only): `run` is another plain `.exe` in **the same folder** as `start` (both in the spelling
//!   stored on disk, so the folders are byte for byte equal; not `start` itself), which the shim
//!   starts with the rule when Steam starts `start`; `args` are 1 to 8 arguments of the pattern
//!   `rerun_proto::profile::LaunchArg` ([`LaunchArgText`]), at most 512 bytes, appended to the
//!   command line the shim starts. A step needs at least one of `cpu`, `priority`, `run`,
//!   `args`. Every profile is written as format 3.
//! - **The target** (P3-4 P1, P4): `direct` sets the rule on what it starts, so `target` is
//!   `run` if the step has one, else `start`. `watch` sets it on a new process of the main
//!   executable found after the start:
//!   `target` is `<game folder>\<main_exe>` in the spelling stored on disk (no field of its own:
//!   one identity, the program apply and revert ask, D4), at most [`MAX_EXE_PATH_UNITS`] units.
//! - **The launcher case** (F5, `direct` only, P3-4 P2): with the started program (`run`, else
//!   `start`) other than the main executable (folded) only a hard CPU rule is allowed: a soft
//!   rule (default CPU Sets) and a priority class reach only the started program, not the game
//!   it starts (ADR 0022 amendment P3-3, sources there). `watch` sets both on the game itself; `start` equal to the main
//!   executable is allowed there too (a stub that starts the game again; the preview says so).
//! - **Bitness** (F6, condition A8; P3-4 P3): `x86` if a program of the chain the rule reaches is
//!   i386, else `x64`: for `direct` `start` or the main executable, with `run` `run` or the
//!   main executable (`start` drops out: the shim never starts `start` under the rule then, a
//!   failed `run` falls back to Steam's command without it; `run` may still start the main
//!   executable), for `watch` the main executable alone (`start` runs
//!   unchanged; it must still be a plain `.exe`, its image is not read). A .NET "AnyCPU" image is i386 on disk and may run as x64: counted as x86,
//!   conservatively; the cost is only on a processor group of more than 32 logical processors
//!   (ADR 0022 B6). ARM64, another machine or no PE image is refused. Read through the bounded
//!   PE parser (ADR 0013).
//! - **The rule** (F8): every field of `cpu` optional, at least one given; missing fields do not
//!   restrict (`prefer: any`, `single_l3: false`, `prefer_l3` none, `smt: true`, no
//!   `max_threads`, `mode: hard`, no `exclude_first`); `max_threads` 1 to 1024; `report_cores`
//!   refused (`inproc`, phase 6); `method: auto` refused (the Topo engine chooses, phase 4).
//!   None of `cpu`, `priority`, `run` and `args` is refused (F9), and so is a second
//!   `launch_method` step.
//! - **`watch_timeout_s`** of every profile is [`WATCH_TIMEOUT_S`] (120, the format's largest
//!   value; the search time of `watch`, unread by the shim for `direct`; review N3, P3-4 P5), so
//!   equal rules give equal bytes, and `direct` and `watch` replace the same profile (one ID).
//! - **The profile file**: [`plan::profile_id`] of the Steam app (E1 a) below the profiles root
//!   (path from [`PlanCtx::app`] or [`PlanCtx::app_path`]); missing → `CreateFile`; the same bytes
//!   → nothing to do, and so is a file that decodes to the same profile (in practice an older
//!   format an earlier build wrote; the shim reads formats 1 to 3 alike); another plain file of at most 8 KiB
//!   with one link → `ReplaceFile` (a rest after `forget`; the revert restores it); a folder, a link, a reparse point or anything
//!   larger is refused (Rerun leaves what is not its own).
//!
//! [`on_this_machine`] is the preview's view of the rule on this computer: it reads only the
//! topology and is never part of the plan (CPU Set IDs are runtime values; the shim selects at
//! every start).

use rerun_proto::cpu::CpuTopology;
use rerun_proto::cpu::rule::{
    Bitness, CpuRule, ExcludeFirst, Mode, Prefer, PreferL3, SelectError, select,
};
use rerun_proto::profile::{
    self as proto, LaunchArg, LaunchProfile, MAX_ARGS, MAX_ARGS_BYTES, MAX_WATCH_TIMEOUT_S, Method,
    Priority, ProfileId,
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
    self, ContentRef, FileState, MAX_EXE_PATH_UNITS, MAX_INLINE_BYTES, MAX_PROFILE_OLD_BYTES, Op,
    PlanError, RootIx,
};
use crate::policy::root::GameOrigin;
use crate::sys::SysResult;
use crate::sys::fs::{Attrs, EntryKind};

/// The rule types a front end shows (`MachineView`).
pub use rerun_proto::cpu::rule::{Mode as RuleMode, SelectStep};
/// The method of a decoded profile, typed (`ProfileShown::decoded`; review N3).
pub use rerun_proto::profile::Method as ProfileMethod;

/// `watch_timeout_s` of every profile (review N3, P3-4 P5): the search time of `watch`, fixed
/// (no step field); the format keeps the key for `direct` too, where the shim does not read it.
/// One value, so equal rules give equal bytes.
pub const WATCH_TIMEOUT_S: u16 = MAX_WATCH_TIMEOUT_S;

/// Largest `max_threads` of a step (`docs/02-topo-format.md`).
pub const MAX_THREADS: u16 = 1024;

/// The `launch_method` step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchMethodSpec {
    /// How the game is started (`direct` or `watch`; `auto` is refused until phase 4).
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
    /// The program the shim starts instead of `start` (profile format 3, `direct` only): a
    /// plain `.exe` in the folder of `start`, relative to the game folder. Not written when not
    /// given.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run: Option<RelPath>,
    /// Arguments the shim appends to the command line it starts (profile format 3, `direct`
    /// only). Not written when empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<LaunchArgText>,
}

/// One launch argument of a step (the pattern of `rerun_proto::profile::LaunchArg`, the one
/// place it lives), as text on the wire.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct LaunchArgText(LaunchArg);

impl LaunchArgText {
    /// The argument if `s` matches the pattern.
    pub fn parse(s: &str) -> Option<Self> {
        LaunchArg::parse(s).map(Self)
    }

    /// The argument.
    pub fn arg(&self) -> &LaunchArg {
        &self.0
    }

    /// The argument as text.
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl From<LaunchArg> for LaunchArgText {
    fn from(a: LaunchArg) -> Self {
        Self(a)
    }
}

impl TryFrom<String> for LaunchArgText {
    type Error = String;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::parse(&s).ok_or_else(|| {
            "a launch argument starts with - or + followed by letters, digits and _ . = + -, at \
             most 64 characters"
                .to_owned()
        })
    }
}

impl From<LaunchArgText> for String {
    fn from(a: LaunchArgText) -> Self {
        a.0.as_str().to_owned()
    }
}

/// `launch_method.method`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MethodSpec {
    /// Start Steam's command in a job with the limit (ADR 0022).
    Direct,
    /// Start Steam's command unchanged, then set the rule on a new process of the main
    /// executable (ADR 0022 amendment P3-4).
    Watch,
    /// Chosen by the Topo engine (phase 4): refused.
    Auto,
}

/// A CPU rule of `docs/02-topo-format.md`: every field optional, at least one given. A field
/// that is not given is not written (the Topo bundle, ADR 0024).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CpuRuleSpec {
    /// At most this many logical processors, 1 to 1024.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_threads: Option<u16>,
    /// Default `any`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefer: Option<PreferSpec>,
    /// Default `false`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub single_l3: Option<bool>,
    /// Default none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefer_l3: Option<PreferL3Spec>,
    /// Default `true`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub smt: Option<bool>,
    /// Default `hard`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<ModeSpec>,
    /// Default none (nothing excluded): keep the game off CPU 0 (`thread`) or off its whole
    /// core (`core`); ADR 0022 amendment P4-13. Not written when not given, so existing plans,
    /// Topos and index bundles keep their bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exclude_first: Option<ExcludeFirstSpec>,
    /// Only with `inproc` (phase 6): refused.
    #[serde(default, skip_serializing_if = "Option::is_none")]
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

/// `cpu.exclude_first`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExcludeFirstSpec {
    /// Logical processor 0 of group 0 ("CPU 0"); its SMT sibling stays.
    Thread,
    /// Every thread of the physical core that holds CPU 0.
    Core,
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

impl PrioritySpec {
    /// The step of a priority class a profile holds (carry-over).
    pub fn of_priority(p: Priority) -> Self {
        match p {
            Priority::Normal => Self::Normal,
            Priority::AboveNormal => Self::AboveNormal,
            Priority::High => Self::High,
        }
    }
}

impl MethodSpec {
    /// The step of a method a profile holds (carry-over).
    pub fn of_method(m: Method) -> Self {
        match m {
            Method::Direct => Self::Direct,
            Method::Watch => Self::Watch,
        }
    }
}

fn refuse(what: impl Into<String>) -> PlanError {
    PlanError::Step(format!("launch_method: {}", what.into()))
}

/// A path for messages (ADR 0016).
fn shown(s: &str) -> String {
    crate::escape::path(s).to_string()
}

impl CpuRuleSpec {
    /// The step of a rule a profile holds (ADR 0032 amendment P5-OE, carry-over): every field
    /// named, so [`Self::rule`] gives the same rule back and the profile the same bytes.
    pub fn of_rule(r: &CpuRule) -> Self {
        Self {
            max_threads: r.max_threads,
            prefer: Some(match r.prefer {
                Prefer::Performance => PreferSpec::Performance,
                Prefer::Any => PreferSpec::Any,
            }),
            single_l3: Some(r.single_l3),
            prefer_l3: r.prefer_l3.map(|PreferL3::Largest| PreferL3Spec::Largest),
            smt: Some(r.smt),
            mode: Some(match r.mode {
                Mode::Hard => ModeSpec::Hard,
                Mode::Soft => ModeSpec::Soft,
            }),
            exclude_first: r.exclude_first.map(|e| match e {
                ExcludeFirst::Thread => ExcludeFirstSpec::Thread,
                ExcludeFirst::Core => ExcludeFirstSpec::Core,
            }),
            report_cores: None,
        }
    }

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
            exclude_first: self.exclude_first.map(|e| match e {
                ExcludeFirstSpec::Thread => ExcludeFirst::Thread,
                ExcludeFirstSpec::Core => ExcludeFirst::Core,
            }),
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

/// The op that puts `bytes` (the encoding of `profile`) at `name` below the profiles root, or
/// `None` if the file there holds them already or decodes to `profile` (module docs).
fn profile_op(
    ctx: &PlanCtx<'_>,
    name: &RelPath,
    bytes: Vec<u8>,
    profile: &LaunchProfile,
) -> Result<Option<Op>, PlanError> {
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
    // Other bytes that decode to the same profile (in practice an older format an earlier build
    // wrote): the shim reads it alike, so it stays (no replace only for a format change).
    if proto::decode(&old).is_ok_and(|was| was == *profile) {
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
            "method auto is chosen by the Topo engine (phase 4); name direct or watch",
        ));
    }
    if spec.cpu.is_none() && spec.priority.is_none() && spec.run.is_none() && spec.args.is_empty() {
        return Err(refuse(
            "none of cpu, priority, run and args: nothing to apply",
        ));
    }
    if (spec.run.is_some() || !spec.args.is_empty()) && spec.method != MethodSpec::Direct {
        return Err(refuse(
            "run and args need method direct (rerun-launch starts them in place of Steam's \
             program; watch starts Steam's program unchanged)",
        ));
    }
    let args: Vec<LaunchArg> = spec.args.iter().map(|a| a.arg().clone()).collect();
    if args.len() > MAX_ARGS {
        return Err(refuse(format!("more than {MAX_ARGS} args")));
    }
    if proto::args_value(&args).len() > MAX_ARGS_BYTES {
        return Err(refuse(format!(
            "the args are longer than {MAX_ARGS_BYTES} bytes together"
        )));
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
    let watch = spec.method == MethodSpec::Watch;
    // P5-OE (S2): `run` is another exe in the folder of `start`, both as stored on disk.
    let run = match &spec.run {
        None => None,
        Some(r) => {
            let run = stored_exe(game, r, "launch_method run")?;
            if fold(run.as_str()) == fold(start.as_str()) {
                return Err(refuse(format!(
                    "run {} is the program Steam starts; leave run out",
                    shown(run.as_str())
                )));
            }
            if folder_of(&run) != folder_of(&start) {
                return Err(refuse(format!(
                    "run {} is not in the folder of start {} (rerun-launch starts only a \
                     program next to Steam's)",
                    shown(run.as_str()),
                    shown(start.as_str())
                )));
            }
            Some(run)
        }
    };
    // What the shim starts with the rule.
    let started = run.as_ref().unwrap_or(&start);
    let who = if run.is_some() {
        "rerun-launch starts"
    } else {
        "Steam starts"
    };
    // F5 (`direct` only, P3-4 P2): soft rules and priority classes reach only the started
    // program; `watch` sets them on the game.
    if !watch && fold(started.as_str()) != fold(main.as_str()) {
        if rule.is_some_and(|r| r.mode == Mode::Soft) {
            return Err(refuse(format!(
                "{who} {}, not the game {}: CPU Sets (mode soft) reach only the started \
                 program; use mode hard (the game inherits the job) or method watch",
                shown(started.as_str()),
                shown(main.as_str())
            )));
        }
        if spec.priority.is_some() {
            return Err(refuse(format!(
                "{who} {}, not the game {}: a priority class reaches only the started \
                 program; method watch sets it on the game",
                shown(started.as_str()),
                shown(main.as_str())
            )));
        }
    }
    // F6 (A8, P3-4 P3): x86 if a program of the chain the rule reaches is i386; with `watch`
    // the rule reaches the main executable (and what it starts) only; with `run` the rule
    // reaches `run` and what it starts, which may be the main executable (P5-OE review A-S2):
    // only `start` drops out.
    let bitness = {
        let main_bitness = bitness_of(game, main)?;
        let first = if watch {
            None
        } else if let Some(run) = &run {
            Some(bitness_of(game, run)?)
        } else {
            Some(bitness_of(game, &start)?)
        };
        match (first, main_bitness) {
            (None | Some(Bitness::X64), Bitness::X64) => Bitness::X64,
            _ => Bitness::X86,
        }
    };
    let start_abs = format!(r"{}\{}", game.path(), start);
    let run_abs = run.as_ref().map(|r| format!(r"{}\{}", game.path(), r));
    // P1: the target of `watch` is the main executable in the spelling stored on disk; of
    // `direct` the program the shim starts.
    let target_abs = if watch {
        let main = stored_exe(game, main, "launch_method main_exe")?;
        format!(r"{}\{}", game.path(), main)
    } else {
        run_abs.clone().unwrap_or_else(|| start_abs.clone())
    };
    // F7, P4: both paths as the shim compares them (no long paths yet).
    for (what, abs) in [("start", &start_abs), ("target", &target_abs)] {
        if abs.encode_utf16().count() > MAX_EXE_PATH_UNITS {
            return Err(refuse(format!(
                "the {what} path {} is longer than {MAX_EXE_PATH_UNITS} characters",
                shown(abs)
            )));
        }
    }
    let profile = LaunchProfile {
        method: if watch { Method::Watch } else { Method::Direct },
        start: start_abs,
        target: target_abs,
        bitness,
        priority: spec.priority.map(|p| match p {
            PrioritySpec::Normal => Priority::Normal,
            PrioritySpec::AboveNormal => Priority::AboveNormal,
            PrioritySpec::High => Priority::High,
        }),
        watch_timeout_s: WATCH_TIMEOUT_S,
        cpu: rule,
        run: run_abs,
        args,
    };
    let bytes = proto::encode(&profile).map_err(|e| refuse(format!("the profile: {e}")))?;
    if bytes.len() > MAX_INLINE_BYTES {
        return Err(refuse(format!(
            "the profile is larger than {} KiB (the paths of this game are too long for a \
             launch profile)",
            MAX_INLINE_BYTES >> 10
        )));
    }
    let profiles = app_path(ctx)?
        .child("profiles")
        .map_err(|e| refuse(e.to_string()))?;
    let name = plan::profile_file(plan::profile_id(app_id));
    if let Some(op) = profile_op(ctx, &name, bytes, &profile)? {
        b.profile = Some((op, profiles));
    }
    Ok(())
}

/// The folder of a path relative to the game folder: everything up to and including its last
/// `\`, empty for a file of the game folder itself.
fn folder_of(p: &RelPath) -> &str {
    let s = p.as_str();
    s.rfind('\\').map_or("", |i| &s[..=i])
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

/// What the launcher case (F5) leaves open for the user's own launch settings (the Advanced
/// section's locks, ADR 0029): pure, the planner decides the same again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LaunchAllowed {
    /// A soft CPU rule (CPU Sets of the started program).
    pub soft: bool,
    /// A priority class.
    pub priority: bool,
    /// The method `watch` (a `run` of a live profile needs `direct`).
    pub watch: bool,
}

/// What `method` allows: with `direct` and a started program (`run`, else `start`) other than
/// the main executable only a hard rule reaches the game (F5), `watch` and a started program
/// that is the main executable reach it with everything; `run` (kept from a live profile)
/// needs `direct`.
pub fn allowed(
    method: crate::plan::ManualMethod,
    started_is_main: bool,
    run: bool,
) -> LaunchAllowed {
    let reaches = method == crate::plan::ManualMethod::Watch || started_is_main;
    LaunchAllowed {
        soft: reaches,
        priority: reaches,
        watch: !run,
    }
}

/// The rule of `p` on the topology `topo` (module docs).
pub fn on_this_machine(topo: SysResult<CpuTopology>, p: &LaunchProfile) -> MachineView {
    view(
        topo.as_ref().map_err(ToString::to_string),
        p.cpu.as_ref(),
        p.bitness,
    )
}

/// The rule `rule` of the user's own settings on the topology `topo` (the Advanced section's live
/// readout, ADR 0029): the same selection as [`on_this_machine`] makes for the profile the rule
/// would become, for a program of `bitness`. `Err` is the raw text of the reason the topology
/// is unknown (escaped here). A rule that cannot be built (`max_threads` 0, `report_cores`)
/// shows as no rule: the form's own check refuses it before any plan.
pub fn rule_on_this_machine(
    topo: Result<&CpuTopology, &str>,
    rule: &CpuRuleSpec,
    bitness: Bitness,
) -> MachineView {
    view(
        topo.map_err(str::to_owned),
        rule.rule().ok().as_ref(),
        bitness,
    )
}

fn view(
    topo: Result<&CpuTopology, String>,
    cpu: Option<&CpuRule>,
    bitness: Bitness,
) -> MachineView {
    let topo = match topo {
        Ok(t) => t,
        Err(e) => {
            return MachineView {
                selection: Err(MachineWhy::Topology(crate::escape::text(&e).to_string())),
                groups: 0,
                x86_capped: false,
            };
        }
    };
    let mut groups: Vec<u16> = topo.cpus.iter().map(|c| c.group).collect();
    groups.sort_unstable();
    groups.dedup();
    let groups = u16::try_from(groups.len()).unwrap_or(u16::MAX);
    let Some(rule) = cpu else {
        return MachineView {
            selection: Err(MachineWhy::NoRule),
            groups,
            x86_capped: false,
        };
    };
    let sel = match select(topo, rule, bitness) {
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
        x86_capped: bitness == Bitness::X86 && in_group > 32,
    }
}
