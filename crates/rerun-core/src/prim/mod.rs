//! Primitives as planners (ADR 0020, user decision D9): durable spec types
//! (`deny_unknown_fields`) and one planner each, turning a step into ops of a [`Plan`].
//! Planners only read (through `policy::root` handles); `exec` applies, verifies and reverts
//! the ops.
//!
//! - [`file_install`]: files of a local package below `<AppDir>\packages\<id>\<version>`
//!   into the game folder (ADR 0020, D11).
//! - [`registry_set`]: values below `HKCU\Software\<Vendor>\<Product>[\…]` (P2-10b), read
//!   through [`PlanCtx::reg`].
//! - [`compat_layer`]: compatibility-layer tokens of an executable of the game folder in
//!   `HKCU\…\AppCompatFlags\Layers` (P2-11; the token allowlist from the Sandbox probes,
//!   P2-11b).
//!
//! - [`ini_set`]: keys of an existing INI file of the game folder (P2-12, ADR 0021): one
//!   `IniValue` per file with its edits.
//! - [`launch_method`]: the launch profile of a Steam game for `rerun-launch` (P3-3c, ADR 0022
//!   amendment P3-3): one `CreateFile`/`ReplaceFile` with inline content on the plan root
//!   `<LocalAppData>\Rerun\profiles` (root 1), op 0 of the plan.
//! - [`package`] (P4-7, ADR 0025 part 2): a Topo's `package` step as the `file_install` step of
//!   the package's files for this game's architecture and graphics API; pure, no I/O.
//! - [`laa_patch`] (P4-10): the Large Address Aware flag of a 32-bit executable of the Topo's
//!   `match.exes` as one `ReplaceFile` with a patch (`ContentRef::Patch`); only from a Topo.
//! - [`gpu_preference`] (P4-11): Windows' graphics preference of an executable of the game
//!   folder in `HKCU\…\DirectX\UserGpuPreferences` (only Rerun's pair of the value).
//! - [`StepFile`]: the phase 2 step file `rerun plan <steps.json>` reads (P2-13); since the Topo
//!   engine (P4-4) the local, unsigned input (L8), removed at the earliest before A6.
//!
//! A file of a step lies in the game folder, or (P4-12, [`StepRoot::UserData`]; v1 only
//! `ini_set`) in the plan's user data folder below the user's `Documents`, which the step file
//! or the Topo names once ([`UserDataSpec`]) and the front end opens only when a step needs it
//! ([`needs_user_data`], [`PlanCtx::user_data`]). Its root follows the game root and the profiles
//! root, if any.
//!
//! The builder orders the ops: every file op first (an `IniValue` is one), then every registry
//! op, whatever the order of the steps (6b-d; `plan::check` refuses anything else). An
//! `ini_set` and a `file_install` of the same file in one plan are refused.

pub mod compat_layer;
pub mod file_install;
pub mod gpu_preference;
pub mod ini_set;
pub mod laa_patch;
pub mod launch_method;
pub mod package;
pub mod registry_set;
mod step_file;

use serde::{Deserialize, Serialize};

pub use compat_layer::CompatLayerSpec;
pub use file_install::{FileEntry, FileInstallSpec};
pub use gpu_preference::{AlreadySet, GpuPreferenceSpec};
pub use ini_set::{IniSetSpec, IniSetValue};
pub use laa_patch::{LaaFacts, LaaPatchSpec};
pub use launch_method::{
    CpuRuleSpec, ExcludeFirstSpec, LaunchMethodSpec, MachineView, MachineWhy, MethodSpec, ModeSpec,
    PreferL3Spec, PreferSpec, PrioritySpec, SHIM, SelectionShown, on_this_machine,
    steam_option_text,
};
pub use package::{GameBuild, PackageRefusal};
pub use registry_set::{RegValueEntry, RegistrySetSpec};
pub use step_file::{
    GameRef, MAX_STEP_FILE, ParseClass, STEP_FILE_FORMAT, StepFile, StepFileError,
};

use crate::fold::fold;
use crate::path::{RelPath, RootPath};
use crate::plan::{
    FORMAT, Op, PROFILES_ROOT_ID, Plan, PlanError, PlanOrigin, PlanRoot, RootIx, RootKind, Target,
};
use crate::policy::registry::RegReader;
use crate::policy::root::{AppDir, GameDir, GameOrigin, UserBase, UserDataDir};
use crate::sys::SysErrorKind;
use crate::sys::fs::EntryKind;
use crate::sys::registry::RegKey;

/// One step: an object with exactly one key (ADR 0020, D7).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Step {
    /// [`file_install`].
    FileInstall(FileInstallSpec),
    /// [`registry_set`].
    RegistrySet(RegistrySetSpec),
    /// [`compat_layer`].
    CompatLayer(CompatLayerSpec),
    /// [`ini_set`].
    IniSet(IniSetSpec),
    /// [`launch_method`] (at most one per plan).
    LaunchMethod(LaunchMethodSpec),
    /// [`laa_patch`] (P4-10): only from a Topo, the step file refuses it.
    LaaPatch(LaaPatchSpec),
    /// [`gpu_preference`] (P4-11).
    GpuPreference(GpuPreferenceSpec),
}

/// The root a step's file lies in (P4-12). On the wire omitted for the game folder, so a step
/// of the game folder keeps its bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StepRoot {
    /// The game folder (plan root 0).
    #[default]
    Game,
    /// The plan's user data folder ([`UserDataSpec`], [`PlanCtx::user_data`]).
    UserData,
}

impl StepRoot {
    /// The game folder (serde: omitted on the wire).
    pub fn is_game(&self) -> bool {
        *self == Self::Game
    }
}

/// The user data folder of a plan (P4-12): exactly one key, its base, with the folder below it
/// (`{"documents":"My Games\Fallout3"}`). The root kind is independent of the primitive: v1
/// only `ini_set` uses it (user decision U1 a); a later bounded config primitive can name it the
/// same way.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum UserDataSpec {
    /// A folder below the user's `Documents`.
    Documents(RelPath),
}

impl UserDataSpec {
    /// The base.
    pub fn base(&self) -> UserBase {
        match self {
            Self::Documents(_) => UserBase::Documents,
        }
    }

    /// The folder below the base.
    pub fn sub(&self) -> &RelPath {
        match self {
            Self::Documents(s) => s,
        }
    }
}

impl Step {
    /// The root the step's file lies in (P4-12): its own `root` for a step that has one (v1:
    /// `ini_set`), the game folder for every other. Which op kinds a user data root takes is the
    /// plan fence's alone (`plan::user_data`).
    pub fn root(&self) -> StepRoot {
        match self {
            Self::IniSet(i) => i.root,
            Self::FileInstall(_)
            | Self::RegistrySet(_)
            | Self::CompatLayer(_)
            | Self::LaunchMethod(_)
            | Self::LaaPatch(_)
            | Self::GpuPreference(_) => StepRoot::Game,
        }
    }
}

/// A step of `steps` has its file in the user data folder: the front end opens it then (and
/// only then).
pub fn needs_user_data(steps: &[Step]) -> bool {
    steps.iter().any(|s| s.root() == StepRoot::UserData)
}

/// The root index an op on the user data folder carries while the plan is built; replaced by
/// the real index (after the game root and the profiles root) when the roots are known.
pub(crate) const USER_DATA_PENDING: RootIx = RootIx(u16::MAX);

/// What a planner reads: the game folder, Rerun's folder (packages), and what identifies the
/// game for apply and revert.
#[derive(Debug, Clone, Copy)]
pub struct PlanCtx<'a> {
    /// The game folder (its root becomes the plan's root 0).
    pub game: &'a GameDir<'a>,
    /// Rerun's folder; `None` if it does not exist yet (`rerun plan --dry-run` creates nothing,
    /// review S6): a `file_install` step is refused then (no local packages), `compat_layer`
    /// looks up no transaction.
    pub app: Option<&'a AppDir<'a>>,
    /// The Steam app of a game folder from a Steam library (required for such a root, its
    /// state is checked before apply and revert).
    pub steam_app: Option<u32>,
    /// The game's main executable below the game folder, asked by `users()` (D4). If given,
    /// it must be a file there (audit A2 should-item 8); registry steps need it (E2).
    pub main_exe: Option<&'a RelPath>,
    /// The registry as `registry_set` reads it (`RegPolicy::reader`: no link followed).
    pub reg: RegReader<'a>,
    /// The canonical path of `<LocalAppData>\Rerun` (`AppDir::path_of`) when [`Self::app`] is
    /// `None` (a dry run before the first run creates nothing); with an `app`, its path counts,
    /// and this, if given, must be the same. Only `launch_method` needs it (the path of the
    /// profiles root, so a plan's bytes are the same with and without `--dry-run`).
    pub app_path: Option<&'a RootPath>,
    /// The user data folder (P4-12), opened by the front end only if a step needs it
    /// ([`needs_user_data`]); a step with [`StepRoot::UserData`] is refused without it.
    pub user_data: Option<&'a UserDataDir<'a>>,
}

/// The ops planned so far, shared by the steps of one plan.
#[derive(Debug, Default)]
pub(crate) struct Builder {
    pub(crate) ops: Vec<Op>,
    /// Folded paths of the directories a `CreateDir` creates.
    pub(crate) created: Vec<String>,
    /// Folded target paths of the file ops (also of the omitted ones).
    pub(crate) targets: Vec<String>,
    /// The registry ops, after every file op.
    pub(crate) reg_ops: Vec<Op>,
    /// The keys a `CreateKey` of `reg_ops` creates.
    pub(crate) reg_keys: Vec<RegKey>,
    /// Key and folded name of every value of a step (also of the omitted ones).
    pub(crate) reg_values: Vec<(RegKey, String)>,
    /// Folded paths of the files of the `ini_set` steps in the game folder.
    pub(crate) ini_files: Vec<String>,
    /// Folded paths of the files of the `ini_set` steps in the user data folder (P4-12).
    pub(crate) user_ini_files: Vec<String>,
    /// The profile op of the one `launch_method` step and the path of the profiles root
    /// (`None`: no such step, or its profile is there already: nothing to do).
    pub(crate) profile: Option<(Op, RootPath)>,
    /// A `launch_method` step was planned (F9: at most one).
    pub(crate) launch_method: bool,
}

impl Builder {
    pub(crate) fn creates(&self, folded: &str) -> bool {
        self.created.iter().any(|c| c == folded)
    }

    /// The path, as spelled in the plan, of the directory a `CreateDir` creates.
    pub(crate) fn created_path(&self, folded: &str) -> Option<RelPath> {
        self.ops.iter().find_map(|o| match o {
            Op::CreateDir { path, .. } if fold(path.as_str()) == folded => Some(path.clone()),
            _ => None,
        })
    }
}

/// Plans `steps` against the game folder of `ctx` (reads only). A spec without files gives a
/// plan without ops: nothing to do, no transaction (ADR 0020).
pub fn plan(steps: &[Step], ctx: &PlanCtx<'_>) -> Result<Plan, PlanError> {
    let origin = match (ctx.game.origin(), ctx.steam_app) {
        (
            GameOrigin::Store {
                store,
                store_id,
                installdir,
            },
            Some(app_id),
        ) if app_id > 0 => PlanOrigin::Steam {
            store: store.clone(),
            store_id: *store_id,
            app_id,
            installdir: installdir.clone(),
        },
        (GameOrigin::Store { .. }, _) => {
            return Err(PlanError::Step(
                "a game folder from a Steam library needs its Steam app ID".to_owned(),
            ));
        }
        (GameOrigin::Manual, None) => PlanOrigin::Manual,
        (GameOrigin::Manual, Some(_)) => {
            return Err(PlanError::Step(
                "a manually added game folder has no Steam app ID".to_owned(),
            ));
        }
    };
    // A2 should-item 8: a main executable that is no file of the game folder (a typo, a
    // link) would leave D4 asking nothing about it.
    if let Some(m) = ctx.main_exe {
        main_exe_is_a_file(ctx.game, m)?;
    }
    let mut b = Builder::default();
    for step in steps {
        match step {
            Step::FileInstall(spec) => file_install::plan_into(spec, ctx, &mut b)?,
            Step::RegistrySet(spec) => registry_set::plan_into(spec, ctx, &mut b)?,
            Step::CompatLayer(spec) => compat_layer::plan_into(spec, ctx, &mut b)?,
            Step::IniSet(spec) => ini_set::plan_into(spec, ctx, &mut b)?,
            Step::LaunchMethod(spec) => launch_method::plan_into(spec, ctx, &mut b)?,
            Step::LaaPatch(spec) => laa_patch::plan_into(spec, ctx, &mut b)?,
            Step::GpuPreference(spec) => gpu_preference::plan_into(spec, ctx, &mut b)?,
        }
    }
    // One file is either installed or edited in one plan (the plan format allows one op per
    // object; this says why).
    if let Some(f) = b.ini_files.iter().find(|f| b.targets.contains(f)) {
        return Err(PlanError::Step(format!(
            "ini_set and file_install for the same file {}; ship the file with the values set, \
             or set them in a second plan",
            crate::escape::path(f)
        )));
    }
    // 6b-d: every registry op after every file op.
    let reg_ops = std::mem::take(&mut b.reg_ops);
    b.ops.extend(reg_ops);
    // P4-8: holds only alongside a change; a plan that changes nothing starts no transaction.
    if b.ops.iter().all(|o| matches!(o, Op::Hold { .. })) && b.profile.is_none() {
        b.ops.clear();
    }
    // E2, E5 of P2-12: ops that need it (registry and INI ops) need the main executable.
    if ctx.main_exe.is_none() && b.ops.iter().any(Op::needs_main_exe) {
        return Err(PlanError::Step(
            "registry and INI fixes need the game's main executable".to_owned(),
        ));
    }
    // S1: write access only for a root with file ops; D4 needs read access only. Only root 0
    // is the game folder (P3-3: a launch profile lies in Rerun's folder, root 1).
    let file_ops = b
        .ops
        .iter()
        .any(|o| matches!(o.target(), Target::File { root, .. } if root.0 == 0));
    if file_ops && !ctx.game.info().user_writable {
        return Err(PlanError::NeedsHelper);
    }
    let mut roots = vec![PlanRoot {
        kind: RootKind::Game,
        path: ctx.game.path().clone(),
        id: ctx.game.id(),
        origin,
        main_exe: ctx.main_exe.cloned(),
        main_sha256: None,
    }];
    let mut ops = b.ops;
    // P3-3 (F3): the profile is op 0 on root 1, so a revert reaches it last.
    if let Some((op, path)) = b.profile {
        roots.push(PlanRoot {
            kind: RootKind::Profiles,
            path,
            id: PROFILES_ROOT_ID,
            origin: PlanOrigin::AppDir,
            main_exe: None,
            main_sha256: None,
        });
        ops.insert(0, op);
    }
    // P4-12: the user data root last, its ops renumbered to its index.
    if ops.iter().any(on_pending) {
        let Some(u) = ctx.user_data else {
            return Err(PlanError::Step(
                "a step for the user data folder without that folder".to_owned(),
            ));
        };
        let ix = RootIx(u16::try_from(roots.len()).unwrap_or(u16::MAX));
        for o in &mut ops {
            if let Some(root) = o.root_mut()
                && *root == USER_DATA_PENDING
            {
                *root = ix;
            }
        }
        roots.push(PlanRoot {
            kind: RootKind::UserData,
            path: u.path().clone(),
            id: u.id(),
            origin: PlanOrigin::UserFolder {
                base: u.base(),
                sub: u.sub().clone(),
            },
            main_exe: None,
            main_sha256: None,
        });
    }
    let plan = Plan {
        format: FORMAT,
        source: None,
        roots,
        ops,
    };
    // P4-8: a DLL of a package where a live transaction has another package's DLL (a slot) is
    // refused here already; the apply checks it again under the lock.
    if let Some(app) = ctx.app
        && let Some(r) = crate::exec::slot_taken_now(app, &plan)
    {
        return Err(PlanError::Step(r.to_string()));
    }
    // The bounds of the format (ops, op size, backups): the same check as when applied.
    plan.encode()?;
    Ok(plan)
}

/// An op planned on the user data folder (its root still [`USER_DATA_PENDING`]).
fn on_pending(o: &Op) -> bool {
    matches!(o.target(), Target::File { root, .. } if root == USER_DATA_PENDING)
}

/// `m` is a plain file of the game folder (not missing, not a folder, link or other reparse
/// point, not restricted: D4 could not ask it, security N-3).
fn main_exe_is_a_file(game: &GameDir<'_>, m: &RelPath) -> Result<(), PlanError> {
    let bad = || {
        PlanError::Step(format!(
            "the main executable {} is not a file in the game folder",
            crate::escape::path(m.as_str())
        ))
    };
    match game.dir().metadata(m) {
        Ok(Some(md)) if md.kind == EntryKind::File && md.reparse.is_none() && !md.restricted => {
            Ok(())
        }
        Ok(_) => Err(bad()),
        Err(e) if matches!(e.kind, SysErrorKind::NotFound | SysErrorKind::ReparsePoint) => {
            Err(bad())
        }
        Err(e) => Err(e.into()),
    }
}

/// The newest open Rerun transaction (not forgotten, not closed, its head readable) with an
/// op for which `f(head, index, op)` holds; for messages only: anything unreadable is "none"
/// (`compat_layer` review N2, `gpu_preference` N2).
pub(crate) fn open_txn_with(
    ctx: &PlanCtx<'_>,
    f: impl Fn(&Plan, usize, &Op) -> bool,
) -> Option<crate::journal::TxnId> {
    use crate::journal::{InstanceTag, Journal, TxnState, VerifyBackups};
    let j = Journal::new(ctx.app?, InstanceTag::new());
    let listing = j.list().ok()?;
    listing.txns.iter().rev().find_map(|l| {
        let v = l.view.as_ref().ok()?;
        if l.forgotten || matches!(v.state, TxnState::Closed(_) | TxnState::Empty) {
            return None;
        }
        let full = j.load(&l.id, VerifyBackups::Length).ok()?;
        let p = crate::plan::decode_recorded(full.head.as_deref()?).ok()?;
        p.ops
            .iter()
            .enumerate()
            .any(|(k, op)| f(&p, k, op))
            .then_some(l.id)
    })
}

/// `slot` (op `k` of `p`) names the same registry value as `av` (key, folded name).
pub(crate) fn same_value(
    p: &Plan,
    slot: &crate::policy::registry::RegSlot,
    k: usize,
    av: &crate::policy::registry::AllowedValue,
) -> bool {
    crate::plan::allowed(p, slot, k)
        .is_ok_and(|o| o.key().key() == av.key().key() && fold(o.name()) == fold(av.name()))
}

/// `p` folded, for comparisons between targets.
pub(crate) fn folded(p: &RelPath) -> String {
    fold(p.as_str())
}

#[cfg(test)]
mod gpu_pref_tests;
#[cfg(test)]
pub(crate) mod ini_tests;
#[cfg(test)]
pub(crate) mod launch_tests;
#[cfg(test)]
pub(crate) mod layer_tests;
#[cfg(test)]
pub(crate) mod reg_tests;
#[cfg(test)]
pub(crate) mod tests;
