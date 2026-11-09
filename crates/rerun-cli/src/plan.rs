//! `rerun plan <steps.json> [--dry-run]` (P2-13): reads the step file, plans its steps for the
//! game folder it names, shows the preview of exactly the bytes it stores, and stores them as
//! `<AppDir>\plans\<hash>.json` for `rerun apply <hash>`. No lock (planning only reads).
//!
//! Order: the elevated guard (user decision E3), the forbidden roots, the step file
//! (`read_input`, 1 MiB, `StepFile::parse`), Rerun's folder without creating it (review S6),
//! the game folder (`steam`: exactly one installed app in the libraries; `folder`: opened like
//! a manually added folder), the planner, `encode`, the preview of the encoded bytes. A plan
//! without ops is not stored. The preview is written and flushed before anything is stored:
//! a preview that did not arrive stores nothing (exit 3). `--dry-run` creates nothing at all.

use std::io::Write;
use std::path::Path;

use rerun_core::detect::steam::{self, AppState};
use rerun_core::plan::{self, PlanBytes, Preview};
use rerun_core::policy::registry::RegPolicy;
use rerun_core::policy::root::{
    AppDir, Create, ForbiddenRoots, GameDir, Shadow, preview_with_shadows, read_input,
};
use rerun_core::prim::{self, GameRef, MAX_STEP_FILE, PlanCtx, StepFile};
use rerun_core::sys::System;

use crate::cli::Exit;
use crate::host::{Host, after_change, before_change, fail, forbidden, shown, standard_user};
use crate::messages::{Message, SteamWhy, TxnMsg};
use crate::out::Out;
use crate::preview;

/// Plans and prints (module docs).
pub fn plan<W: Write, E: Write>(
    host: &Host<'_>,
    steps: &Path,
    dry_run: bool,
    out: &mut Out<W>,
    err: &mut Out<E>,
) -> Exit {
    match run(host, steps, dry_run, out, err) {
        Ok(e) | Err(e) => e,
    }
}

fn run<W: Write, E: Write>(
    host: &Host<'_>,
    steps: &Path,
    dry_run: bool,
    out: &mut Out<W>,
    err: &mut Out<E>,
) -> Result<Exit, Exit> {
    let sys = host.sys;
    standard_user(sys, err)?;
    let fr = forbidden(host, err)?;
    let file = std::path::absolute(steps)
        .map_err(|e| fail(err, TxnMsg::StepFile { error: shown(&e) }, Exit::Refused))?;
    let bytes = read_input(sys, &file, MAX_STEP_FILE)
        .map_err(|e| fail(err, TxnMsg::StepFile { error: shown(&e) }, Exit::Refused))?;
    let sf = StepFile::parse(&bytes)
        .map_err(|e| fail(err, TxnMsg::StepFile { error: shown(&e) }, Exit::Refused))?;
    let app = AppDir::open(sys, Create::Never)
        .map_err(|e| fail(err, TxnMsg::AppDir { error: shown(&e) }, Exit::Fatal))?;
    // P3-3c: the path of Rerun's folder without creating it (a launch profile names its
    // profiles root by path); unknown only fails a `launch_method` step.
    let app_path = AppDir::path_of(sys).ok();
    let (bytes, view, shadows) = with_game(sys, &fr, &sf.game, err, |game, steam_app| {
        let ctx = PlanCtx {
            game,
            app: app.as_ref(),
            steam_app,
            main_exe: Some(&sf.main_exe),
            reg: RegPolicy.reader(sys),
            app_path: app_path.as_ref(),
        };
        let p = prim::plan(&sf.steps, &ctx)?;
        let b = p.encode()?;
        // P3-7: the VirtualStore lookup (read only) from the same decode as the preview.
        let (v, sh) = preview_with_shadows(sys, &b)?;
        Ok::<(PlanBytes, Preview, Vec<Shadow>), plan::PlanError>((b, v, sh))
    })?
    .map_err(|e| fail(err, TxnMsg::PlanFailed { error: shown(&e) }, Exit::Refused))?;
    if view.ops.is_empty() {
        let _ = out.line(&Message::Txn(TxnMsg::NothingToDo));
        return Ok(Exit::Report);
    }
    let hash = bytes.hash();
    let ops = view.ops.len();
    // P3-3d: the launch profile's selection here, hints and the launch option (not stored).
    let lv = preview::launch_view(sys, &host.install, &view);
    let mut lines = preview::render(&view);
    // P3-7: a VirtualStore copy of a managed file (looked up with the preview above).
    lines.extend(preview::shadow_lines(&shadows));
    if let Some(lv) = &lv {
        lines.extend(preview::launch_lines(&view, lv));
    }
    out.lines(&lines)
        .and_then(|()| out.line(&Message::Blank))
        .and_then(|()| out.flush())
        .map_err(|e| before_change(err, e))?;
    if dry_run {
        return Ok(out
            .line(&Message::Txn(TxnMsg::PlanDryRun { hash, ops }))
            .map_or_else(|e| before_change(err, e), |()| Exit::Report));
    }
    // Review S6: Rerun's folder is created only now, right before the plan is stored.
    let app = match app {
        Some(a) => a,
        None => match AppDir::open(sys, Create::IfMissing) {
            Ok(Some(a)) => a,
            Ok(None) => return Err(fail(err, TxnMsg::NoAppDir, Exit::Fatal)),
            Err(e) => return Err(fail(err, TxnMsg::AppDir { error: shown(&e) }, Exit::Fatal)),
        },
    };
    // Plan §9 (review of P3-3c): a launch profile names Rerun's folder by the path planned
    // with; one that is another now (LocalAppData moved meanwhile) is not stored.
    if app_path.as_ref().is_some_and(|p| p != app.path()) {
        return Err(fail(err, TxnMsg::AppDirMoved, Exit::Refused));
    }
    plan::store(&app, &bytes)
        .map_err(|e| fail(err, TxnMsg::StoreFailed { error: shown(&e) }, Exit::Refused))?;
    let done = [
        Message::Txn(TxnMsg::PlanStored { hash, ops }),
        Message::Txn(TxnMsg::ApplyWith { hash }),
    ];
    Ok(out
        .lines(&done)
        .and_then(|()| out.flush())
        .map_or_else(|e| after_change(err, e, Exit::Report), |()| Exit::Report))
}

/// Opens the game folder a step file names and runs `f` on it; refusals end with exit 3.
fn with_game<R, E: Write>(
    sys: &dyn System,
    fr: &ForbiddenRoots,
    game: &GameRef,
    err: &mut Out<E>,
    f: impl FnOnce(&GameDir<'_>, Option<u32>) -> R,
) -> Result<R, Exit> {
    let refused = |err: &mut Out<E>, m| fail(err, m, Exit::Refused);
    match game {
        GameRef::Folder(p) => {
            let g = GameDir::open_manual(sys, fr, p.path())
                .map_err(|e| refused(err, TxnMsg::GameFolder { error: shown(&e) }))?;
            Ok(f(&g, None))
        }
        GameRef::Steam(app_id) => {
            let app_id = *app_id;
            let why = |err: &mut Out<E>, why| refused(err, TxnMsg::SteamApp { app_id, why });
            let s = steam::scan(sys, fr);
            if s.root.is_none() {
                return Err(why(err, SteamWhy::NoSteam));
            }
            // Every entry counts: a library may list an app twice (ADR 0012), nothing is
            // guessed.
            let mut found = s.libraries.iter().flat_map(|lib| {
                lib.apps()
                    .iter()
                    .filter(move |a| a.app_id == app_id)
                    .map(move |a| (lib, a.state()))
            });
            let (lib, state) = match (found.next(), found.next()) {
                (None, _) => return Err(why(err, SteamWhy::NotListed)),
                (Some(_), Some(_)) => return Err(why(err, SteamWhy::Twice)),
                (Some(x), None) => x,
            };
            match state {
                AppState::Installed => {}
                AppState::UpdatePending => return Err(why(err, SteamWhy::Updating)),
                AppState::NotInstalled => return Err(why(err, SteamWhy::NotInstalled)),
            }
            let g = lib
                .open_game(fr, app_id)
                .map_err(|e| refused(err, TxnMsg::GameFolder { error: shown(&e) }))?;
            Ok(f(&g, Some(app_id)))
        }
    }
}
