//! The test combinations the mid-phase-2 audit (A2) made mandatory before the phase-2 audit: a
//! failure or a crash at every call, then a power loss at every pair of cuts of `C:` (journal,
//! packages) and `D:` (game), for plans with more than one op and for stacked transactions, with
//! the on-disk spelling of A2-B1 inside.
//!
//! - CM1 multi-op plans: two replaces in one folder, a replace and a create in one folder, a
//!   replace in the root and a create in a folder below (the cased kinds spell the replaced
//!   files in another case than the disk).
//! - CM2 stacked transactions: T1 is applied and durable, T2 (the same file, another file in the
//!   same folder, a file in the folder T1 created, a hold of T1's file next to a replace, P4-8)
//!   is applied and reverted with the fault; the recovery reverts T2, then T1, and the game
//!   folder is the one before T1.
//! - Axes: the fault (a failure `Other`, a crash after the call), the point (a call of the apply
//!   or of the revert of T2), the cuts of `C:` times the cuts of `D:`, and the moment of the
//!   cut: right after the run ("direct"), or after a full recovery of the run ("recovered": the
//!   recovery's own writes are cut).
//! - CM3 nested probes: a crash at a call, a restart, the recovery (it reverts T2, then T1)
//!   crashing at one of its calls, then (power-loss form) a power loss at the cuts of `C:` and
//!   `D:`, then the complete recovery.
//!
//! Size and cost: reduced by default ([`Mode`], [`nested`]); `RERUN_UNREDUCED=1` runs every call
//! and every cut of CM1 and CM2, and the full nested probes (every state-changing call of the run
//! and of the recovery, both faults for the recovery, every cut) are `#[ignore]`
//! (`cargo test -p rerun-core --lib combo_tests -- --ignored`). Measured numbers and the
//! reduction rules: `docs/09-testing.md`.
//!
//! P2-15 over every run: `Closed` means the game folder is the one before (the checks above), and
//! a journal that names a `.old` left ([`cleanup_named`]) appears only where a mapping was
//! injected, never in these runs (the control maps one).
//!
//! Controls (each one bites): the J6 flush sites switched off ([`CONTROLS`]) and three test
//! knobs of `exec::knob` like K1 and K3 (`cm_control_*`): K-CM1 a flush deduplicated per folder,
//! K-CM2 a recovery that renames back in another spelling, K-CM3 the parent folder of a revert
//! not marked for the flush.

use std::collections::BTreeMap;
use std::path::Path;
use std::time::Instant;

use super::Flush;
use super::Outcome;
use super::knob as exec_knob;
use super::rebind_crash_tests::changes_state;
use super::reg_tests::Reset;
use super::tests::{Env, NEW, base, finish, game, pkg};
use crate::journal::{FlushSite, Observed, TxnId, TxnState, knob as journal_knob};
use crate::path::RelPath;
use crate::plan::PlanHash;
use crate::prim::FileInstallSpec;
use crate::prim::tests::{app, entry, spec};
use crate::sys::fake::{Domain, Fault, Prim};
use crate::sys::snapshot::Snapshot;
use crate::sys::{Fs, SysErrorKind};

const OLD2: &[u8] = b"old dinput8 of the game";
const NEW2: &[u8] = b"new dinput8 of the package";
const THIRD: &[u8] = b"third d3d9 of the package";
const Y: &[u8] = b"y.dll of the package";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// `d3d9.dll` and `dinput8.dll` replaced (one folder).
    TwoReplace,
    /// The same, both spelled in upper case by the step (A2-B1).
    TwoReplaceCased,
    /// `d3d9.dll` replaced, `new.dll` created (one folder).
    ReplaceCreate,
    /// The same, `d3d9.dll` spelled in upper case.
    ReplaceCreateCased,
    /// `d3d9.dll` replaced in the root, `mods\x.dll` created (two folders).
    ReplaceDeep,
    /// T1 replaces `d3d9.dll`, T2 replaces it again.
    StackSame,
    /// The same, both steps spell it in upper case.
    StackSameCased,
    /// T1 replaces `d3d9.dll`, T2 replaces `dinput8.dll` and creates `new.dll` (same folder).
    StackAdjacent,
    /// T1 creates `mods\x.dll` (and `mods`), T2 creates `mods\y.dll`.
    StackBelow,
    /// T1 creates `new.dll`, T2 holds it (P4-8) and replaces `dinput8.dll`.
    StackHold,
}

const MULTI: [Kind; 5] = [
    Kind::TwoReplace,
    Kind::TwoReplaceCased,
    Kind::ReplaceCreate,
    Kind::ReplaceCreateCased,
    Kind::ReplaceDeep,
];
const STACKED: [Kind; 5] = [
    Kind::StackSame,
    Kind::StackSameCased,
    Kind::StackAdjacent,
    Kind::StackBelow,
    Kind::StackHold,
];

/// The step of T1 (the only one for the multi-op kinds) and of T2.
fn specs(k: Kind) -> (FileInstallSpec, Option<FileInstallSpec>) {
    let d3d9 = |to: &str| entry("d3d9.dll", to, NEW);
    match k {
        Kind::TwoReplace => (
            spec(vec![
                d3d9("d3d9.dll"),
                entry("dinput8.dll", "dinput8.dll", NEW2),
            ]),
            None,
        ),
        Kind::TwoReplaceCased => (
            spec(vec![
                d3d9("D3D9.DLL"),
                entry("dinput8.dll", "DINPUT8.DLL", NEW2),
            ]),
            None,
        ),
        Kind::ReplaceCreate => (
            spec(vec![
                d3d9("d3d9.dll"),
                entry("new.dll", "new.dll", super::tests::N),
            ]),
            None,
        ),
        Kind::ReplaceCreateCased => (
            spec(vec![
                d3d9("D3D9.DLL"),
                entry("new.dll", "new.dll", super::tests::N),
            ]),
            None,
        ),
        Kind::ReplaceDeep => (
            spec(vec![
                d3d9("d3d9.dll"),
                entry(r"mods\x.dll", r"mods\x.dll", super::tests::X),
            ]),
            None,
        ),
        Kind::StackSame => (
            spec(vec![d3d9("d3d9.dll")]),
            Some(spec(vec![entry("d3d9b.dll", "d3d9.dll", THIRD)])),
        ),
        Kind::StackSameCased => (
            spec(vec![d3d9("D3D9.DLL")]),
            Some(spec(vec![entry("d3d9b.dll", "D3D9.DLL", THIRD)])),
        ),
        Kind::StackAdjacent => (
            spec(vec![d3d9("d3d9.dll")]),
            Some(spec(vec![
                entry("dinput8.dll", "dinput8.dll", NEW2),
                entry("new.dll", "new.dll", super::tests::N),
            ])),
        ),
        Kind::StackBelow => (
            spec(vec![entry(r"mods\x.dll", r"mods\x.dll", super::tests::X)]),
            Some(spec(vec![entry(r"mods\y.dll", r"mods\y.dll", Y)])),
        ),
        Kind::StackHold => (
            spec(vec![entry("new.dll", "new.dll", super::tests::N)]),
            Some(spec(vec![
                entry("new.dll", "new.dll", super::tests::N),
                entry("dinput8.dll", "dinput8.dll", NEW2),
            ])),
        ),
    }
}

/// One system of a kind, everything durable, right before the run that is faulted.
struct World {
    env: Env,
    /// The plan that is applied and reverted with the fault (T2 for a stacked kind).
    h: PlanHash,
    /// The game folder before everything (what the recovery of everything must reach).
    floor: Snapshot,
    /// The game folder right before the faulted transaction (`floor` unless stacked).
    mid: Snapshot,
    /// T1 of a stacked kind: applied, durable, untouched by the run.
    base: Option<TxnId>,
    /// The names of the game folder as `floor` and `mid` (their spelling, A2-B1).
    floor_names: Vec<String>,
    mid_names: Vec<String>,
}

fn setup(k: Kind) -> World {
    let env = Env::new(finish(
        base()
            .file(pkg("dinput8.dll"), NEW2.to_vec())
            .file(game("dinput8.dll"), OLD2.to_vec())
            .file(pkg("d3d9b.dll"), THIRD.to_vec())
            .file(pkg(r"mods\y.dll"), Y.to_vec()),
    ));
    let (s1, s2) = specs(k);
    let floor = env.snap();
    let floor_names = names(&env);
    let (h, mid, base) = if let Some(s2) = s2 {
        let t1 = env.applied(&env.plan(&s1));
        env.sys.fake_fs().sync_all();
        (env.plan(&s2), env.snap(), Some(t1))
    } else {
        (env.plan(&s1), floor.clone(), None)
    };
    // `journal\lock` in place, so every run's calls are the same.
    drop(
        crate::journal::Journal::new(&app(&env.sys), crate::journal::InstanceTag::fixed(9))
            .lock()
            .unwrap(),
    );
    env.sys.fake_fs().sync_all();
    let mid_names = names(&env);
    World {
        env,
        h,
        floor,
        mid,
        base,
        floor_names,
        mid_names,
    }
}

/// How much of a matrix runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// The normal suite: the points that change state, a few cuts.
    Reduced,
    /// Every call, every cut. `RERUN_UNREDUCED=1`, and the `#[ignore]` tests.
    Full,
}

/// The mode of the normal tests: `RERUN_UNREDUCED=1` makes it [`Mode::Full`].
fn mode() -> Mode {
    #[expect(
        clippy::disallowed_methods,
        reason = "test gate: a switch, never a path"
    )]
    if std::env::var_os("RERUN_UNREDUCED").is_some_and(|v| v == "1") {
        Mode::Full
    } else {
        Mode::Reduced
    }
}

/// Where a run is interrupted: after call `nth` of `call` in the apply or the revert.
#[derive(Debug, Clone, Copy)]
struct At {
    revert: bool,
    call: Prim,
    nth: usize,
    fault: Fault,
}

/// What the run got back.
#[derive(Debug, Default, Clone, Copy)]
struct Got {
    applied: bool,
    closed: bool,
}

/// Apply, then revert; `at` armed in its phase.
fn run(w: &World, at: Option<At>) -> Got {
    let env = &w.env;
    let mut got = Got::default();
    let arm = |a: At| move |fx: &crate::sys::fake::FakeFs| fx.fault(a.call, a.nth, a.fault);
    let none = |_: &crate::sys::fake::FakeFs| {};
    let r = match at {
        Some(a) if !a.revert => env.apply_armed(&w.h, arm(a)),
        _ => env.apply_armed(&w.h, none),
    };
    let t = match r {
        Ok(Outcome::Applied(t)) => t,
        other => {
            assert!(
                at.is_some_and(|a| !a.revert),
                "apply without a fault: {other:?}"
            );
            return got;
        }
    };
    got.applied = true;
    let r = match at {
        Some(a) if a.revert => env.revert_armed(&t, arm(a)),
        _ => env.revert_armed(&t, none),
    };
    got.closed = r.as_ref().is_ok_and(|r| r.closed.is_some());
    if at.is_none() {
        assert!(got.closed, "revert without a fault: {r:?}");
    }
    got
}

/// The calls of the apply and of the revert of `k`.
fn trace(k: Kind) -> (Vec<Prim>, Vec<Prim>) {
    let w = setup(k);
    let fx = w.env.sys.fake_fs();
    let rec = |f: &crate::sys::fake::FakeFs| f.record_calls(true);
    let t = match w.env.apply_armed(&w.h, rec) {
        Ok(Outcome::Applied(t)) => t,
        other => panic!("{other:?}"),
    };
    fx.record_calls(false);
    let a = fx.take_calls();
    assert!(w.env.revert_armed(&t, rec).unwrap().closed.is_some());
    fx.record_calls(false);
    (a, fx.take_calls())
}

/// The points of a fault: [`Mode::Full`] after every call; [`Mode::Reduced`] after every call
/// that changes state, and the last read-only call before the first one, and the end. The
/// reasoning of `rebind_crash_tests::points` (S5) holds for the points; a failure at a read-only
/// call takes another error path, and together with the reduced cuts ([`cuts`]) the reduced
/// matrix is a sample: the unreduced run (measured, `docs/09-testing.md`) is the claim.
fn points(k: Kind, fault: Fault, mode: Mode) -> Vec<Option<At>> {
    let (a, r) = trace(k);
    let mut v = Vec::new();
    for (revert, calls) in [(false, &a), (true, &r)] {
        let first_write = calls.iter().position(|c| changes_state(*c));
        for (i, call) in calls.iter().enumerate() {
            if mode == Mode::Reduced && !changes_state(*call) && first_write != Some(i + 1) {
                continue;
            }
            v.push(Some(At {
                revert,
                call: *call,
                nth: calls[..=i].iter().filter(|c| *c == call).count(),
                fault,
            }));
        }
    }
    v.push(None);
    v
}

/// The cuts of a domain with `pending` droppable changes: all of them, or (reduced) none, the
/// first one only, and all. The reduced cuts are a sample, not an equivalence (a middle cut can
/// keep a state no other cut keeps); the claim rests on the unreduced run (`RERUN_UNREDUCED=1`,
/// every cut: 16,212 runs, green, `docs/09-testing.md`), as for the nested probes (review N1).
fn cuts(pending: usize, mode: Mode) -> Vec<usize> {
    match mode {
        Mode::Full => (0..=pending).collect(),
        Mode::Reduced => {
            let mut v = vec![0, 1.min(pending), pending];
            v.dedup();
            v
        }
    }
}

/// The kinds of a mode: the cased kinds subsume their plain twins (the same ops, another
/// spelling in the step), so the reduced run takes those.
fn kinds(all: &[Kind], mode: Mode) -> Vec<Kind> {
    all.iter()
        .copied()
        .filter(|k| {
            mode == Mode::Full
                || !matches!(k, Kind::TwoReplace | Kind::ReplaceCreate | Kind::StackSame)
        })
        .collect()
}

/// The spelling of the names in the game folder, sorted.
fn names(env: &Env) -> Vec<String> {
    #[expect(
        clippy::disallowed_methods,
        reason = "test: list the fixture game folder"
    )]
    let d = env
        .sys
        .fake_fs()
        .open_dir(Path::new(crate::prim::tests::GAME))
        .unwrap();
    let mut v: Vec<String> = d
        .read_dir(None)
        .unwrap()
        .into_iter()
        .map(|e| e.name)
        .collect();
    v.sort();
    v
}

/// Whether two name lists agree in every character (A2-B1: `==` of `RelPath` folds).
fn same_names(a: &[String], b: &[String]) -> bool {
    a.len() == b.len()
        && a.iter().zip(b).all(|(x, y)| {
            match (RelPath::from_segment(x), RelPath::from_segment(y)) {
                (Ok(x), Ok(y)) => x.same_spelling(&y),
                _ => x == y,
            }
        })
}

/// A game folder that is not `want`: the lines of the difference and, when the names differ
/// only in case, the spellings.
fn differs(w: &World, want: &Snapshot, want_names: &[String]) -> Option<String> {
    let now = w.env.snap();
    if now != *want {
        return Some(format!("{:?}", want.diff(&now)));
    }
    let n = names(&w.env);
    (!same_names(&n, want_names)).then(|| format!("spelling {n:?}, wanted {want_names:?}"))
}

/// The recovery: every transaction not closed is reverted, newest first, and must close; the
/// game folder is `mid` once the faulted transaction is gone, `floor` at the end.
fn recover(w: &World) -> Vec<String> {
    recover_to(w, false)
}

/// [`recover`]; with `keep_base`, T1 of a stacked kind is left applied, and the end is `mid`.
fn recover_to(w: &World, keep_base: bool) -> Vec<String> {
    let env = &w.env;
    let mut v = Vec::new();
    let mut states = env.states();
    states.sort_by_key(|(t, _)| std::cmp::Reverse(*t));
    for (t, s) in states {
        if Some(t) == w.base {
            // T1's state, unless a recovery began reverting it already.
            if s == Some(TxnState::Applied)
                && !reverting(env, &t)
                && let Some(d) = differs(w, &w.mid, &w.mid_names)
            {
                v.push(format!("before T1's revert, not T1's state: {d}"));
            }
            if keep_base {
                return v;
            }
        }
        match s {
            Some(TxnState::Closed(_)) => {}
            Some(TxnState::Empty | TxnState::Open | TxnState::Applied) => match env.revert(&t) {
                Ok(r) if r.closed.is_some() => {}
                Ok(r) if r.ops.iter().any(|o| o.observed == Observed::Foreign) => {
                    v.push(format!("Foreign: {r:?}"));
                }
                other => {
                    let headless = !super::tests::exists_abs(
                        &env.sys,
                        &format!(r"{}\head.json", env.txn_dir(&t)),
                    );
                    if !(headless && s == Some(TxnState::Empty)) {
                        v.push(format!("recovery failed: {other:?}"));
                    }
                }
            },
            other => v.push(format!("damaged: {t} {other:?}")),
        }
    }
    if let Some(d) = differs(w, &w.floor, &w.floor_names) {
        v.push(format!("not identical after recovery: {d}"));
    }
    v
}

/// A revert of `t` has begun (a `RevertIntent` or a `RevertDone` is durable), or its journal does
/// not load.
fn reverting(env: &Env, t: &TxnId) -> bool {
    let a = app(&env.sys);
    let j = crate::journal::Journal::new(&a, crate::journal::InstanceTag::fixed(5));
    j.load(t, crate::journal::VerifyBackups::Length)
        .map_or(true, |view| {
            view.ops.values().any(|o| !o.reverts.is_empty())
        })
}

/// P2-15: every transaction whose journal names a `.old` left (`OpLog::pending_old`). Without an
/// injected mapping there is none: each one is a violation.
fn cleanup_named(env: &Env) -> Vec<String> {
    let a = app(&env.sys);
    let j = crate::journal::Journal::new(&a, crate::journal::InstanceTag::fixed(5));
    let Ok(l) = j.list() else {
        return Vec::new();
    };
    l.txns
        .iter()
        .filter_map(|t| t.view.as_ref().ok())
        .filter(|v| v.ops.values().any(|o| !o.pending_old().is_empty()))
        .map(|v| {
            format!(
                "open with cleanup items without a mapping: {} {:?}",
                v.id, v.state
            )
        })
        .collect()
}

/// The J5 properties of what is on disk after a power loss, before the recovery (the
/// properties of `crash_tests::violations`, with T1 of a stacked kind untouched), then the
/// recovery.
fn violations(w: &World, got: Got, nested: bool) -> Vec<String> {
    let env = &w.env;
    let mut v = Vec::new();
    let states = env.states();
    let mut run_state = None;
    // What the game folder is when the faulted transaction is closed: T1's state, or (nested:
    // a recovery that went on to T1) the floor once T1 is closed too.
    let mut closed_is = Some((&w.mid, &w.mid_names));
    for (t, s) in &states {
        if Some(*t) == w.base {
            match s {
                Some(TxnState::Applied) if nested && reverting(env, t) => closed_is = None,
                Some(TxnState::Applied) => {}
                Some(TxnState::Closed(crate::journal::Closing::Reverted)) if nested => {
                    closed_is = Some((&w.floor, &w.floor_names));
                    if let Some(d) = differs(w, &w.floor, &w.floor_names) {
                        v.push(format!("T1 closed durable, revert lost: {d}"));
                    }
                }
                _ => v.push(format!("T1 changed by the run: {s:?}")),
            }
            continue;
        }
        run_state = s.clone();
        match s {
            Some(TxnState::Damaged(_)) | None => v.push(format!("damaged: {t} {s:?}")),
            Some(TxnState::Applied) => {
                let reverting = reverting(env, t);
                if !reverting {
                    let seen = env.verify(t);
                    if seen.iter().any(|(_, o)| *o != Observed::After) {
                        v.push(format!("Applied durable, change lost: {seen:?}"));
                    }
                }
            }
            Some(TxnState::Closed(
                crate::journal::Closing::Reverted | crate::journal::Closing::RolledBack,
            )) => {
                if let Some((snap, names)) = closed_is
                    && let Some(d) = differs(w, snap, names)
                {
                    v.push(format!("Closed durable, revert lost: {d}"));
                }
            }
            _ => {}
        }
    }
    if got.applied
        && !matches!(
            run_state,
            Some(TxnState::Applied | TxnState::Closed(crate::journal::Closing::Reverted))
        )
    {
        v.push(format!(
            "Ok lost: apply returned Applied, now {run_state:?}"
        ));
    }
    if got.closed && !matches!(run_state, Some(TxnState::Closed(_))) {
        v.push(format!(
            "Ok lost: revert returned Closed, now {run_state:?}"
        ));
    }
    v.extend(cleanup_named(env));
    if v.is_empty() {
        v.extend(recover(w));
        v.extend(cleanup_named(env));
    }
    v
}

/// The control of [`cleanup_named`]: a `.old` mapped during the restore of the revert is seen.
#[test]
fn cm_control_a_mapped_dot_old_is_seen_by_the_cleanup_property() {
    let w = setup(Kind::TwoReplaceCased);
    let t = match w.env.apply(&w.h) {
        Ok(Outcome::Applied(t)) => t,
        other => panic!("{other:?}"),
    };
    let m = super::cleanup_tests::Mapper::game(&w.env);
    let r = w.env.revert(&t).unwrap();
    super::cleanup_tests::Mapper::stop(&w.env);
    assert!(r.closed.is_none(), "{r:?}");
    let v = violations(&w, Got::default(), false);
    assert!(
        v.iter()
            .any(|x| x.contains("open with cleanup items without a mapping")),
        "{v:?}"
    );
    m.release();
}

/// A flush J6 switches off.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Site {
    Journal(FlushSite),
    Game(Flush),
}

fn knobs(skip: Option<Site>) {
    journal_knob::skip(match skip {
        Some(Site::Journal(s)) => Some(s),
        _ => None,
    });
    exec_knob::skip(match skip {
        Some(Site::Game(g)) => Some(g),
        _ => None,
    });
}

/// When the power is cut.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Moment {
    /// Right after the run was interrupted.
    Direct,
    /// After the run was interrupted, restarted and recovered completely: the recovery's own
    /// writes are cut (M1 did this for `D:` only).
    Recovered,
}

/// Size of a matrix run.
#[derive(Debug, Default)]
struct Size {
    runs: usize,
    points: usize,
    max_c: usize,
    max_d: usize,
}

/// The world of `k` after the run at `at` (restarted after a crash, recovered if `moment` says
/// so, with the flush `skip` switched off throughout).
fn prepare(
    k: Kind,
    at: Option<At>,
    moment: Moment,
    skip: Option<Site>,
) -> (World, Got, Vec<String>) {
    let w = setup(k);
    knobs(skip);
    let mut got = run(&w, at);
    let fx = w.env.sys.fake_fs();
    fx.clear_faults();
    if fx.crashed() {
        fx.restart();
    }
    let mut found = Vec::new();
    if moment == Moment::Recovered {
        let v = recover_to(&w, true);
        found.extend(
            v.into_iter()
                .map(|x| format!("recovery before the cut: {x}")),
        );
        got = Got::default();
    }
    (w, got, found)
}

/// The matrix of `k`: every `fault` at every point, every pair of cuts of `C:` and `D:`. With
/// `want`, stops at the first violation containing it.
fn matrix(
    k: Kind,
    faults: &[Fault],
    moment: Moment,
    mode: Mode,
    skip: Option<Site>,
    want: Option<&str>,
) -> (Vec<String>, Size) {
    let mut found = Vec::new();
    let mut size = Size::default();
    for &fault in faults {
        for at in points(k, fault, mode) {
            size.points += 1;
            // The first world measures the cuts and is then the one cut at (0, 0).
            let (w, got, early) = prepare(k, at, moment, skip);
            knobs(None);
            found.extend(early.iter().map(|x| format!("{k:?} after {at:?}: {x}")));
            let (pc, pd) = (
                w.env.sys.pending(Domain::Volume('C')),
                w.env.sys.pending(Domain::Volume('D')),
            );
            let mut first = Some((w, got));
            size.max_c = size.max_c.max(pc);
            size.max_d = size.max_d.max(pd);
            for c in cuts(pc, mode) {
                for d in cuts(pd, mode) {
                    let (w, got) = first.take().unwrap_or_else(|| {
                        let (w, got, _) = prepare(k, at, moment, skip);
                        (w, got)
                    });
                    w.env.sys.power_loss(&BTreeMap::from([
                        (Domain::Volume('C'), c),
                        (Domain::Volume('D'), d),
                    ]));
                    size.runs += 1;
                    knobs(None);
                    let v = violations(&w, got, false);
                    for x in v {
                        let hit = want.is_some_and(|s| x.contains(s));
                        found.push(format!(
                            "{k:?} {fault:?} after {at:?}, {moment:?}, cut C {c} D {d}: {x}"
                        ));
                        if hit {
                            return (found, size);
                        }
                    }
                }
            }
        }
    }
    (found, size)
}

const FAULTS: [Fault; 2] = [Fault::Fail(SysErrorKind::Other), Fault::CrashAfter];

fn all_clear(all: &[Kind], moment: Moment, mode: Mode, label: &str) {
    for k in kinds(all, mode) {
        let t = Instant::now();
        let (found, size) = matrix(k, &FAULTS, moment, mode, None, None);
        eprintln!(
            "{label} {k:?} {moment:?} {mode:?}: {size:?} in {:.1} s",
            t.elapsed().as_secs_f64()
        );
        assert!(
            found.is_empty(),
            "{k:?}: {} violations: {:#?}",
            found.len(),
            found.iter().take(5).collect::<Vec<_>>()
        );
        // Not trivial. After a complete recovery nothing of `D:` is pending (the recovery
        // flushes the game folder before every `RevertDone`): only `C:` has cuts to try.
        assert!(
            size.max_c >= 2 && (moment == Moment::Recovered || size.max_d >= 1),
            "{k:?}: {size:?}"
        );
    }
}

#[test]
fn cm1_multi_op_plans_survive_a_fault_and_any_pair_of_cuts() {
    all_clear(&MULTI, Moment::Direct, mode(), "CM1");
}

#[test]
fn cm1_multi_op_plans_survive_a_fault_a_recovery_and_any_pair_of_cuts() {
    all_clear(&MULTI, Moment::Recovered, mode(), "CM1");
}

#[test]
fn cm2_stacked_transactions_survive_a_fault_and_any_pair_of_cuts() {
    all_clear(&STACKED, Moment::Direct, mode(), "CM2");
}

#[test]
fn cm2_stacked_transactions_survive_a_fault_a_recovery_and_any_pair_of_cuts() {
    all_clear(&STACKED, Moment::Recovered, mode(), "CM2");
}

/// What a control must see: the flush switched off, the property that then fails.
const CONTROLS: [(Site, &str); 6] = [
    (
        Site::Journal(FlushSite::Intent),
        "not identical after recovery",
    ),
    (
        Site::Game(Flush::GameBeforeApplied),
        "Applied durable, change lost",
    ),
    (Site::Journal(FlushSite::Applied), "Ok lost"),
    (
        Site::Journal(FlushSite::RevertIntent),
        "Applied durable, change lost",
    ),
    (
        Site::Game(Flush::GameBeforeRevertDone),
        "Closed durable, revert lost",
    ),
    (Site::Journal(FlushSite::Close), "Ok lost"),
];

/// J6 for the combinations: without any one flush of `exec` or the journal, each combination
/// family fails with the property the flush guards (the reduced run suffices to see it).
#[test]
fn cm_controls_without_a_flush_the_combinations_fail() {
    for k in [Kind::TwoReplaceCased, Kind::StackSameCased] {
        for (site, property) in CONTROLS {
            let (found, _) = matrix(
                k,
                &FAULTS,
                Moment::Direct,
                Mode::Reduced,
                Some(site),
                Some(property),
            );
            knobs(None);
            let last = found.last().map_or("", String::as_str);
            assert!(
                last.contains(property),
                "{k:?} without the flush at {site:?}: {found:?}"
            );
            eprintln!("CM control {k:?} {site:?}: {last}");
        }
    }
    // The recovery's own writes are cut too: without the flush before a `RevertDone`, the
    // cut after a complete recovery loses the revert.
    for k in [Kind::TwoReplaceCased, Kind::StackSameCased] {
        let (found, _) = matrix(
            k,
            &FAULTS,
            Moment::Recovered,
            Mode::Reduced,
            Some(Site::Game(Flush::GameBeforeRevertDone)),
            Some("Closed durable, revert lost"),
        );
        knobs(None);
        let last = found.last().map_or("", String::as_str);
        assert!(
            last.contains("Closed durable, revert lost"),
            "{k:?}: {found:?}"
        );
    }
}

/// K-CM1: a folder flushed once per run, not before every `RevertDone` of an op in it. The second
/// op of a folder is then lost by a power loss after `Closed`.
#[test]
fn cm_control_k_cm1_a_flush_once_per_folder_loses_the_second_revert() {
    let _r = Reset(|| exec_knob::flush_once_per_folder(false));
    exec_knob::flush_once_per_folder(true);
    let (found, _) = matrix(
        Kind::TwoReplaceCased,
        &FAULTS,
        Moment::Direct,
        Mode::Reduced,
        None,
        Some("Closed durable, revert lost"),
    );
    let last = found.last().map_or("", String::as_str);
    assert!(last.contains("Closed durable, revert lost"), "{found:?}");
}

/// K-CM2 (A2-B1): a recovery that renames back in another spelling leaves the folder different
/// from the one before: the snapshot compares names with their case, so this bites through the
/// snapshot diff ("not identical after recovery"), not through `same_names` in `differs`.
#[test]
fn cm_control_k_cm2_a_rename_back_in_another_spelling_is_seen() {
    let _r = Reset(|| exec_knob::rename_back_upcased(false));
    exec_knob::rename_back_upcased(true);
    let (found, _) = matrix(
        Kind::TwoReplaceCased,
        &FAULTS,
        Moment::Direct,
        Mode::Reduced,
        None,
        Some("not identical after recovery"),
    );
    let last = found.last().map_or("", String::as_str);
    assert!(last.contains("not identical after recovery"), "{last}");
}

/// K-CM2 in the nested probes (CM3): the same mutation fails the reduced probe of a stacked kind
/// whose recovery crashes and restarts.
#[test]
fn cm_control_k_cm2_a_rename_back_in_another_spelling_fails_the_nested_probe() {
    let _r = Reset(|| exec_knob::rename_back_upcased(false));
    exec_knob::rename_back_upcased(true);
    let (found, _) = nested(Kind::StackSameCased, false, true, Some("not identical"));
    let last = found.last().map_or("", String::as_str);
    assert!(last.contains("not identical"), "{} violations", found.len());
}

/// K-CM3 (review M1 of P2-8): the parent folder of an op's target not marked for the flush
/// before its `RevertDone`.
#[test]
fn cm_control_k_cm3_an_unmarked_parent_loses_a_revert() {
    let _r = Reset(|| exec_knob::parent_not_marked(false));
    exec_knob::parent_not_marked(true);
    let mut found = Vec::new();
    for k in [
        Kind::TwoReplaceCased,
        Kind::StackSameCased,
        Kind::ReplaceDeep,
    ] {
        for moment in [Moment::Direct, Moment::Recovered] {
            let (f, _) = matrix(k, &FAULTS, moment, Mode::Reduced, None, None);
            found.extend(f);
        }
    }
    assert!(
        found
            .iter()
            .any(|x| x.contains("Closed durable, revert lost")),
        "K-CM3 does not bite in the combinations: {} violations",
        found.len()
    );
    eprintln!("K-CM3: {}", found[0]);
}

/// The calls to interrupt in a list of calls: all, or the ones that change state and the last
/// read-only call before the first of those (`points`).
fn select(calls: &[Prim], mode: Mode) -> Vec<(Prim, usize)> {
    let first_write = calls.iter().position(|c| changes_state(*c));
    calls
        .iter()
        .enumerate()
        .filter(|(i, c)| mode == Mode::Full || changes_state(**c) || first_write == Some(i + 1))
        .map(|(i, c)| (*c, calls[..=i].iter().filter(|x| *x == c).count()))
        .collect()
}

/// A recovery that may be interrupted: every transaction not closed is reverted, newest first,
/// and its errors are ignored (the next recovery looks at the result). `arm` runs right before
/// the first revert (so the calls it counts are those of the recovery alone).
fn attempt(w: &World, arm: impl FnOnce(&crate::sys::fake::FakeFs)) {
    let todo: Vec<TxnId> = {
        let mut s = w.env.states();
        s.sort_by_key(|(t, _)| std::cmp::Reverse(*t));
        s.into_iter()
            .filter(|(_, s)| {
                matches!(
                    s,
                    Some(TxnState::Empty | TxnState::Open | TxnState::Applied)
                )
            })
            .map(|(t, _)| t)
            .collect()
    };
    let fx = w.env.sys.fake_fs();
    fx.clear_faults();
    arm(fx);
    for t in todo {
        let r = w.env.revert(&t);
        if fx.crashed() || r.is_err() {
            break;
        }
    }
}

/// The world of `k` after the run at `at`, restarted if it crashed.
fn interrupted(k: Kind, at: Option<At>) -> World {
    let w = setup(k);
    run(&w, at);
    let fx = w.env.sys.fake_fs();
    fx.clear_faults();
    if fx.crashed() {
        fx.restart();
    }
    w
}

/// The calls of a recovery after the run at `at`.
fn recovery_calls(k: Kind, at: Option<At>) -> Vec<Prim> {
    let w = interrupted(k, at);
    let fx = w.env.sys.fake_fs();
    attempt(&w, |f| f.record_calls(true));
    fx.record_calls(false);
    fx.take_calls()
}

/// The nested probes of `k` (CM3): the run interrupted at a point `p`, a restart, a recovery
/// interrupted at one of its calls `q` (`power`: then a power loss at every pair of cuts;
/// else none), then the complete recovery must close everything and restore the floor.
/// With `want`, stops at the first violation containing it.
fn nested(k: Kind, power: bool, sampled: bool, want: Option<&str>) -> (Vec<String>, Size) {
    let mut found = Vec::new();
    let mut size = Size::default();
    let mode = Mode::Reduced;
    let fault = Fault::CrashAfter;
    {
        let mut ps = points(k, fault, mode);
        if sampled {
            // Every rename is a step of a replace sequence (ADR 0017): each one is a point.
            ps = first_and_last(ps, |p| {
                p.map(|a| {
                    (
                        a.revert,
                        a.call,
                        if a.call == Prim::Rename { a.nth } else { 0 },
                    )
                })
            });
        }
        for p in ps {
            let calls = recovery_calls(k, p);
            let mut qs = select(&calls, mode);
            if sampled {
                qs = first_and_last(qs, |q| Some(q.0));
            }
            let qfaults: &[Fault] = if sampled { &[fault] } else { &FAULTS };
            for &qfault in qfaults {
                for (call, nth) in qs.iter().copied() {
                    size.points += 1;
                    let label = format!(
                        "{k:?} {fault:?} after {p:?}, recovery {qfault:?} at {call:?}#{nth}"
                    );
                    let after_q = |w: &World| {
                        attempt(w, |f| f.fault(call, nth, qfault));
                        let fx = w.env.sys.fake_fs();
                        fx.clear_faults();
                        if fx.crashed() {
                            fx.restart();
                        }
                    };
                    let hit = |x: &str| want.is_some_and(|s| x.contains(s));
                    if !power {
                        let w = interrupted(k, p);
                        after_q(&w);
                        size.runs += 1;
                        for x in recover(&w) {
                            found.push(format!("{label}: {x}"));
                            if hit(&x) {
                                return (found, size);
                            }
                        }
                        continue;
                    }
                    // The first world measures the cuts and is then the one cut at (0, 0).
                    let w0 = interrupted(k, p);
                    after_q(&w0);
                    let (pc, pd) = (
                        w0.env.sys.pending(Domain::Volume('C')),
                        w0.env.sys.pending(Domain::Volume('D')),
                    );
                    let mut first = Some(w0);
                    size.max_c = size.max_c.max(pc);
                    size.max_d = size.max_d.max(pd);
                    let nested_cuts = |n: usize| {
                        if sampled {
                            let mut v = vec![0, n];
                            v.dedup();
                            v
                        } else {
                            cuts(n, mode)
                        }
                    };
                    for c in nested_cuts(pc) {
                        for d in nested_cuts(pd) {
                            let w = first.take().unwrap_or_else(|| {
                                let w = interrupted(k, p);
                                after_q(&w);
                                w
                            });
                            w.env.sys.power_loss(&BTreeMap::from([
                                (Domain::Volume('C'), c),
                                (Domain::Volume('D'), d),
                            ]));
                            size.runs += 1;
                            for x in violations(&w, Got::default(), true) {
                                found.push(format!("{label}, cut C {c} D {d}: {x}"));
                                if hit(&x) {
                                    return (found, size);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    (found, size)
}

/// The first and the last element of every key, in order, and the elements with no key.
fn first_and_last<T: Copy, K: PartialEq>(v: Vec<T>, key: impl Fn(&T) -> Option<K>) -> Vec<T> {
    let keys: Vec<Option<K>> = v.iter().map(&key).collect();
    (0..v.len())
        .filter(|&i| {
            keys[i].is_none()
                || keys[..i].iter().all(|k| *k != keys[i])
                || keys[i + 1..].iter().all(|k| *k != keys[i])
        })
        .map(|i| v[i])
        .collect()
}

fn nested_clear(all: &[Kind], power: bool, sampled: bool, label: &str) {
    for k in all {
        let t = Instant::now();
        let (found, size) = nested(*k, power, sampled, None);
        eprintln!(
            "{label} {k:?} sampled {sampled}: {size:?} in {:.1} s",
            t.elapsed().as_secs_f64()
        );
        assert!(
            found.is_empty(),
            "{k:?}: {} violations: {:#?}",
            found.len(),
            found.iter().take(5).collect::<Vec<_>>()
        );
        assert!(size.runs > 100, "{k:?}: {size:?}");
    }
}

/// The reduced nested probes run on one multi-op kind and one stacked kind; the others (and
/// every call) are the `#[ignore]` ones.
const NESTED: [Kind; 2] = [Kind::TwoReplaceCased, Kind::StackSameCased];

#[test]
fn cm3_a_crash_during_the_recovery_of_a_crash_still_recovers() {
    nested_clear(&NESTED, false, true, "CM3");
}

#[test]
fn cm3_a_power_loss_after_a_crash_during_the_recovery_still_recovers() {
    // One kind: the stacked one, whose recovery also reverts T1.
    nested_clear(&NESTED[1..], true, true, "CM3 power");
}

/// The full nested probes: every kind, every call, both faults, every cut. Minutes.
#[test]
#[ignore = "minutes; the full form of cm3 (cargo test -p rerun-core --lib combo_tests -- --ignored)"]
fn cm3_full_nested_crash() {
    let all: Vec<Kind> = MULTI.iter().chain(&STACKED).copied().collect();
    nested_clear(&all, false, false, "CM3 full");
}

#[test]
#[ignore = "minutes; the full form of cm3 (cargo test -p rerun-core --lib combo_tests -- --ignored)"]
fn cm3_full_nested_power_loss() {
    let all: Vec<Kind> = MULTI.iter().chain(&STACKED).copied().collect();
    nested_clear(&all, true, false, "CM3 full power");
}
