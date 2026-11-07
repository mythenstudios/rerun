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
//!   `HKCU\…\AppCompatFlags\Layers` (P2-11; no token is allowlisted until the Sandbox probes,
//!   review S8).
//!
//! - [`ini_set`]: keys of an existing INI file of the game folder (P2-12, ADR 0021): one
//!   `IniValue` per file with its edits.
//!
//! The builder orders the ops: every file op first (an `IniValue` is one), then every registry
//! op, whatever the order of the steps (6b-d; `plan::check` refuses anything else). An
//! `ini_set` and a `file_install` of the same file in one plan are refused.

pub mod compat_layer;
pub mod file_install;
pub mod ini_set;
pub mod registry_set;

use serde::{Deserialize, Serialize};

pub use compat_layer::CompatLayerSpec;
pub use file_install::{FileEntry, FileInstallSpec};
pub use ini_set::{IniSetSpec, IniSetValue};
pub use registry_set::{RegValueEntry, RegistrySetSpec};

use crate::fold::fold;
use crate::path::RelPath;
use crate::plan::{FORMAT, Op, Plan, PlanError, PlanOrigin, PlanRoot, RootKind, Target};
use crate::policy::registry::RegReader;
use crate::policy::root::{AppDir, GameDir, GameOrigin};
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
}

/// What a planner reads: the game folder, Rerun's folder (packages), and what identifies the
/// game for apply and revert.
#[derive(Debug, Clone, Copy)]
pub struct PlanCtx<'a> {
    /// The game folder (its root becomes the plan's root 0).
    pub game: &'a GameDir<'a>,
    /// Rerun's folder.
    pub app: &'a AppDir<'a>,
    /// The Steam app of a game folder from a Steam library (required for such a root, its
    /// state is checked before apply and revert).
    pub steam_app: Option<u32>,
    /// The game's main executable below the game folder, asked by `users()` (D4). If given,
    /// it must be a file there (audit A2 should-item 8); registry steps need it (E2).
    pub main_exe: Option<&'a RelPath>,
    /// The registry as `registry_set` reads it (`RegPolicy::reader`: no link followed).
    pub reg: RegReader<'a>,
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
    /// Folded paths of the files of the `ini_set` steps.
    pub(crate) ini_files: Vec<String>,
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
    // E2, E5 of P2-12: ops that need it (registry and INI ops) need the main executable.
    if ctx.main_exe.is_none() && b.ops.iter().any(Op::needs_main_exe) {
        return Err(PlanError::Step(
            "registry and INI fixes need the game's main executable".to_owned(),
        ));
    }
    // S1: write access only for a root with file ops; D4 needs read access only.
    let file_ops = b
        .ops
        .iter()
        .any(|o| matches!(o.target(), Target::File { .. }));
    if file_ops && !ctx.game.info().user_writable {
        return Err(PlanError::NeedsHelper);
    }
    let plan = Plan {
        format: FORMAT,
        roots: vec![PlanRoot {
            kind: RootKind::Game,
            path: ctx.game.path().clone(),
            id: ctx.game.id(),
            origin,
            main_exe: ctx.main_exe.cloned(),
        }],
        ops: b.ops,
    };
    // The bounds of the format (ops, op size, backups): the same check as when applied.
    plan.encode()?;
    Ok(plan)
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

/// `p` folded, for comparisons between targets.
pub(crate) fn folded(p: &RelPath) -> String {
    fold(p.as_str())
}

#[cfg(test)]
pub(crate) mod ini_tests;
#[cfg(test)]
pub(crate) mod layer_tests;
#[cfg(test)]
pub(crate) mod reg_tests;
#[cfg(test)]
pub(crate) mod tests;
