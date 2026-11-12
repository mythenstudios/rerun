//! `rerun plan <steps.json> [--dry-run]` (P2-13): reads the step file, plans its steps for the
//! game folder it names, shows the preview of exactly the bytes it stores, and stores them as
//! `<AppDir>\plans\<hash>.json` for `rerun apply <hash>`. No lock (planning only reads).
//!
//! Order: the guards (`flow::guard`: elevation (user decision E3), the forbidden roots, Rerun's
//! folder without creating it, review S6), the step file (`read_input`, 1 MiB,
//! `StepFile::parse`), then `flow::plan_steps`: the game folder (`steam`: exactly one installed
//! app in the libraries; `folder`: opened like a manually added folder), the game's folder below
//! the user's `Documents` only if a step names it (P4-12, `user_data`), the planner, `encode`,
//! the preview of the encoded bytes. A plan without ops is not stored. The preview is written and
//! flushed before anything is stored: a preview that did not arrive stores nothing (exit 3).
//! `--dry-run` creates nothing at all. Planning and storing are `rerun_core::flow`'s (ADR 0027
//! amendment P5-2a); this module renders and maps the refusals.

use std::io::Write;
use std::path::Path;

use rerun_core::flow::{self, GameOpen, Guarded, Planned, StepsRefusal, StoreRefusal};
use rerun_core::policy::root::read_input;
use rerun_core::prim::{MAX_STEP_FILE, StepFile};
use rerun_core::topo::StepKind;

use crate::cli::Exit;
use crate::host::{Host, after_change, before_change, fail, gate, shown};
use crate::messages::{Message, TopoMsg, TxnMsg};
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
    let g = flow::guard(host.env()).map_err(|x| gate(err, x))?;
    let file = std::path::absolute(steps)
        .map_err(|e| fail(err, TxnMsg::StepFile { error: shown(&e) }, Exit::Refused))?;
    let bytes = read_input(sys, &file, MAX_STEP_FILE)
        .map_err(|e| fail(err, TxnMsg::StepFile { error: shown(&e) }, Exit::Refused))?;
    let sf = StepFile::parse(&bytes)
        .map_err(|e| fail(err, TxnMsg::StepFile { error: shown(&e) }, Exit::Refused))?;
    let (planned, warned) = flow::plan_steps(&g, &sf).map_err(|e| match e {
        StepsRefusal::Game(e) => game_open(err, e),
        StepsRefusal::Plan(e) => fail(err, TxnMsg::PlanFailed { error: shown(&e) }, Exit::Refused),
    })?;
    show_and_store(host, g, planned, &warned_lines(&warned), dry_run, out, err)
}

/// The anti-cheat warnings of a step file, before its preview.
fn warned_lines(warned: &[StepKind]) -> Vec<Message<'static>> {
    let mut m: Vec<Message<'static>> = warned
        .iter()
        .map(|k| {
            Message::Topo(TopoMsg::Warning {
                text: format!(
                    "warning: anti-cheat found; {} is planned, at your own risk",
                    k.as_str()
                ),
            })
        })
        .collect();
    if !m.is_empty() {
        m.push(Message::Blank);
    }
    m
}

/// Prints `before`, then the preview of `p`, then (without `--dry-run`) stores the plan
/// through `flow::shown` and `flow::store` (module docs). Shared by the step file and the Topo
/// engine.
pub(crate) fn show_and_store<W: Write, E: Write>(
    host: &Host<'_>,
    mut g: Guarded<'_>,
    p: Planned,
    before: &[Message<'_>],
    dry_run: bool,
    out: &mut Out<W>,
    err: &mut Out<E>,
) -> Result<Exit, Exit> {
    let sys = host.sys;
    if !before.is_empty() {
        out.lines(before).map_err(|e| before_change(err, e))?;
    }
    if p.preview.ops.is_empty() {
        let _ = out.line(&Message::Txn(TxnMsg::NothingToDo));
        return Ok(Exit::Report);
    }
    let hash = p.hash();
    let ops = p.ops();
    // P3-3d: the launch profile's selection here, hints and the launch option (not stored).
    let lv = preview::launch_view(sys, &host.install, &p.preview);
    let mut lines = preview::render(&p.preview);
    // P3-7: a VirtualStore copy of a managed file (looked up with the preview above).
    lines.extend(preview::shadow_lines(&p.shadows));
    // P4-2d (ADR 0023 §2): the helper's pre-check as a warning, and the prompt to expect.
    lines.extend(preview::helper_lines(sys, &p.preview));
    if let Some(lv) = &lv {
        lines.extend(preview::launch_lines(&p.preview, lv));
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
    let p = flow::shown(p);
    flow::store(&mut g, &p).map_err(|e| match e {
        StoreRefusal::Empty => fail(err, TxnMsg::NothingToDo, Exit::Report),
        StoreRefusal::NoAppDir => fail(err, TxnMsg::NoAppDir, Exit::Fatal),
        StoreRefusal::AppDir(e) => fail(err, TxnMsg::AppDir { error: shown(&e) }, Exit::Fatal),
        StoreRefusal::AppDirMoved => fail(err, TxnMsg::AppDirMoved, Exit::Refused),
        StoreRefusal::Store(e) => {
            fail(err, TxnMsg::StoreFailed { error: shown(&e) }, Exit::Refused)
        }
    })?;
    let done = [
        Message::Txn(TxnMsg::PlanStored { hash, ops }),
        Message::Txn(TxnMsg::ApplyWith { hash }),
    ];
    Ok(out
        .lines(&done)
        .and_then(|()| out.flush())
        .map_or_else(|e| after_change(err, e, Exit::Report), |()| Exit::Report))
}

/// A game folder that did not open, on stderr: exit 3.
pub(crate) fn game_open<E: Write>(err: &mut Out<E>, e: GameOpen) -> Exit {
    let m = match e {
        GameOpen::Steam { app_id, why } => TxnMsg::SteamApp { app_id, why },
        GameOpen::Folder(e) => TxnMsg::GameFolder { error: shown(&e) },
    };
    fail(err, m, Exit::Refused)
}
