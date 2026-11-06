//! The checks before anything is written (ADR 0020, "Apply", steps 3 to 5): every root
//! reopened through `policy::root` and checked by identity, the Steam app state re-read, the
//! game closed (`users()` of every existing target and each main executable, user decision
//! D4), and the old state of every op and every source re-observed (`Mismatch`).

use super::{ExecCtx, Refusal, op_ix};
use crate::detect::steam::{AppState, app_manifest};
use crate::escape;
use crate::path::RelPath;
use crate::plan::{ContentRef, Op, Plan, PlanOrigin};
use crate::policy::root::{AppSub, GameDir, StoreDir};
use crate::prim::file_install::{hash_file, open_package};
use crate::sys::fs::FileGuard;
use crate::sys::{DirWrite, SysErrorKind};

/// The store of each Steam root (`None` for a manual one), reopened and checked by identity.
pub(super) fn open_stores<'s>(
    cx: &ExecCtx<'s>,
    plan: &Plan,
) -> Result<Vec<Option<StoreDir<'s>>>, Refusal> {
    plan.roots
        .iter()
        .map(|r| match &r.origin {
            PlanOrigin::Steam {
                store, store_id, ..
            } => {
                let s = StoreDir::open(cx.sys, cx.fr, store.path())?;
                s.ensure_id(*store_id)?;
                Ok(Some(s))
            }
            PlanOrigin::Manual => Ok(None),
        })
        .collect()
}

/// Every root of the plan, in order: a Steam root after its app state (`Installed`, with the
/// plan's install folder) through its store, a manual one by absolute path; each checked by
/// identity, writable by the current user and on a volume with POSIX semantics.
pub(super) fn open_games<'g>(
    cx: &ExecCtx<'g>,
    plan: &Plan,
    stores: &'g [Option<StoreDir<'g>>],
) -> Result<Vec<GameDir<'g>>, Refusal> {
    let mut games = Vec::with_capacity(plan.roots.len());
    for (r, store) in plan.roots.iter().zip(stores) {
        let game = match (&r.origin, store) {
            (
                PlanOrigin::Steam {
                    app_id, installdir, ..
                },
                Some(store),
            ) => {
                let not_installed = Refusal::Steam {
                    app_id: *app_id,
                    state: AppState::NotInstalled,
                };
                let app = match app_manifest(store, *app_id) {
                    Ok(Some(a)) => a,
                    Ok(None) | Err(_) => return Err(not_installed),
                };
                if app.install_dir != *installdir {
                    return Err(not_installed);
                }
                if app.state() != AppState::Installed {
                    return Err(Refusal::Steam {
                        app_id: *app_id,
                        state: app.state(),
                    });
                }
                store.game(cx.fr, installdir.as_str())?
            }
            _ => GameDir::open_manual(cx.sys, cx.fr, r.path.path())?,
        };
        game.ensure_id(r.id)?;
        if !game.info().user_writable {
            return Err(Refusal::NeedsHelper);
        }
        write_handle(&game)?;
        games.push(game);
    }
    Ok(games)
}

/// The write handle of a game folder (`clippy.toml`: only `exec` and `journal`).
#[expect(
    clippy::disallowed_methods,
    reason = "ADR 0020: exec writes the game folders of a plan"
)]
pub(super) fn write_handle<'g>(game: &'g GameDir<'_>) -> crate::sys::SysResult<&'g dyn DirWrite> {
    game.dir_write()
}

/// `<root>\<path>` for a message.
fn shown(plan: &Plan, root: usize, p: &RelPath) -> escape::Shown<'static> {
    let base = plan
        .roots
        .get(root)
        .map(|r| r.path.to_string())
        .unwrap_or_default();
    escape::path(&format!(r"{base}\{p}")).into_owned()
}

/// `p` has no users, or does not exist (a directory or reparse point is no file to ask).
fn unused(plan: &Plan, games: &[GameDir<'_>], root: usize, p: &RelPath) -> Result<(), Refusal> {
    let Some(g) = games.get(root) else {
        return Ok(());
    };
    match g.dir().users(p) {
        Ok(pids) if pids.is_empty() => Ok(()),
        Ok(_) => Err(Refusal::Busy(shown(plan, root, p))),
        Err(e)
            if matches!(
                e.kind,
                SysErrorKind::NotFound | SysErrorKind::AccessDenied | SysErrorKind::ReparsePoint
            ) =>
        {
            Ok(())
        }
        Err(e) => Err(e.into()),
    }
}

/// D4: the game is closed: no existing target of the file ops `ops` and no main executable
/// is in use.
pub(super) fn game_closed(plan: &Plan, games: &[GameDir<'_>], ops: &[u16]) -> Result<(), Refusal> {
    for k in ops {
        if let Some(op @ (Op::CreateFile { .. } | Op::ReplaceFile { .. })) =
            plan.ops.get(usize::from(*k))
        {
            unused(plan, games, usize::from(op.root().0), op.path())?;
        }
    }
    for (i, r) in plan.roots.iter().enumerate() {
        if let Some(m) = &r.main_exe {
            unused(plan, games, i, m)?;
        }
    }
    Ok(())
}

/// Step 5: a created object is still missing, a replaced file still has its old state (on a
/// guard: hash, length, R/H/S, one link), and every source still has its hash and length.
pub(super) fn old_state(
    cx: &ExecCtx<'_>,
    plan: &Plan,
    games: &[GameDir<'_>],
) -> Result<(), Refusal> {
    let packages = cx.app.sub(AppSub::Packages)?;
    for (k, op) in plan.ops.iter().enumerate() {
        let mismatch = || Refusal::Mismatch { op: op_ix(k) };
        let g = games.get(usize::from(op.root().0)).ok_or_else(mismatch)?;
        match op {
            Op::CreateDir { path, .. } | Op::CreateFile { path, .. } => {
                if g.dir().metadata(path)?.is_some() {
                    return Err(mismatch());
                }
            }
            Op::ReplaceFile { path, old, .. } => {
                let base = write_handle(g)?;
                let name = RelPath::from_segment(path.file_name()).map_err(|_| mismatch())?;
                let parent;
                let dir: &dyn DirWrite = match path.parent() {
                    None => base,
                    Some(p) => {
                        parent = base.open_dir_write(&p)?;
                        &*parent
                    }
                };
                let mut guard = match dir.guard(&name) {
                    Ok(gd) => gd,
                    Err(e)
                        if matches!(
                            e.kind,
                            SysErrorKind::NotFound
                                | SysErrorKind::Linked
                                | SysErrorKind::AccessDenied
                                | SysErrorKind::ReparsePoint
                        ) =>
                    {
                        return Err(mismatch());
                    }
                    Err(e) => return Err(e.into()),
                };
                if !same_state(&mut *guard, old)? {
                    return Err(mismatch());
                }
            }
        }
        if let Some(ContentRef::Package {
            id,
            version,
            file,
            sha256,
            len,
            ..
        }) = op.content()
        {
            let pk = packages.as_deref().ok_or_else(mismatch)?;
            let src = open_package(pk, id, version).map_err(|_| mismatch())?;
            match hash_file(&*src, file) {
                Ok((s, l)) if s == *sha256 && l == *len => {}
                _ => return Err(mismatch()),
            }
        }
    }
    Ok(())
}

/// The guard holds exactly `old`: hash, length, R/H/S (one link: the guard refuses others).
pub(super) fn same_state(
    g: &mut dyn FileGuard,
    old: &crate::plan::FileState,
) -> crate::sys::SysResult<bool> {
    let m = g.metadata()?;
    Ok(m.len == old.len && m.attrs == old.attrs && m.is_single_link() && g.sha256()? == old.sha256)
}
