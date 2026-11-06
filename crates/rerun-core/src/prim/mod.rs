//! Primitives as planners (ADR 0020, user decision D9): durable spec types
//! (`deny_unknown_fields`) and one planner each, turning a step into ops of a [`Plan`].
//! Planners only read (through `policy::root` handles); `exec` applies, verifies and reverts
//! the ops.
//!
//! - [`file_install`]: files of a local package below `<AppDir>\packages\<id>\<version>`
//!   into the game folder (ADR 0020, D11).
//!
//! `registry_set`, `compat_layer` and `ini_set` follow with P2-10 to P2-12 (their spec types
//! become further [`Step`] variants and need a `RegPolicy` in [`PlanCtx`]).

pub mod file_install;

use serde::{Deserialize, Serialize};

pub use file_install::{FileEntry, FileInstallSpec};

use crate::fold::fold;
use crate::path::RelPath;
use crate::plan::{FORMAT, Op, Plan, PlanError, PlanOrigin, PlanRoot, RootKind};
use crate::policy::root::{AppDir, GameDir, GameOrigin};

/// One step: an object with exactly one key (ADR 0020, D7).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Step {
    /// [`file_install`].
    FileInstall(FileInstallSpec),
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
    /// The game's main executable below the game folder, asked by `users()` (D4).
    pub main_exe: Option<&'a RelPath>,
}

/// The ops planned so far, shared by the steps of one plan.
#[derive(Debug, Default)]
pub(crate) struct Builder {
    pub(crate) ops: Vec<Op>,
    /// Folded paths of the directories a `CreateDir` creates.
    pub(crate) created: Vec<String>,
    /// Folded target paths of the file ops (also of the omitted ones).
    pub(crate) targets: Vec<String>,
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
    if !ctx.game.info().user_writable {
        return Err(PlanError::NeedsHelper);
    }
    let mut b = Builder::default();
    for step in steps {
        match step {
            Step::FileInstall(spec) => file_install::plan_into(spec, ctx, &mut b)?,
        }
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

/// `p` folded, for comparisons between targets.
pub(crate) fn folded(p: &RelPath) -> String {
    fold(p.as_str())
}

#[cfg(test)]
pub(crate) mod tests;
