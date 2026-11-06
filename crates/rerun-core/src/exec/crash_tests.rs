//! `exec` under crashes and power losses (P2-8, C5): T3 a crash after every call of an apply
//! and of a revert, T4 a power loss after every call at every pair of cuts of `C:` (journal,
//! packages) and `D:` (game), J6 every flush site needed, K2 (= J6).
//!
//! Plans (senior-dev condition 7): one per op kind (`CreateDir`, `CreateFile`,
//! `ReplaceFile` over a read-only, hidden target) and the two-op plan `CreateDir` +
//! `CreateFile`. Each run applies and reverts; a crash or power loss interrupts it; the
//! recovery (`revert` of every transaction not closed) must close it with the game folder
//! identical to before, never `Damaged`, never `Foreign`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::time::Instant;

use super::Outcome;
use super::knob::{self as exec_knob, GameFlush};
use super::tests::{Env, NEW, OLD, X, base, finish, game, read_abs};
use crate::journal::{FlushSite, TxnState, knob as journal_knob};
use crate::plan::{self, Plan, PlanHash, store};
use crate::prim::tests::{app, entry, spec};
use crate::sys::Fs;
use crate::sys::fake::{Domain, Fault, Prim};
use crate::sys::snapshot::Snapshot;

/// The plans of condition 7.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    CreateDir,
    CreateFile,
    Replace,
    /// A replace whose step spells the target in another case than the disk (A2-B1).
    ReplaceCased,
    DirAndFile,
}

const KINDS: [Kind; 5] = [
    Kind::CreateDir,
    Kind::CreateFile,
    Kind::Replace,
    Kind::ReplaceCased,
    Kind::DirAndFile,
];

/// A fresh system with the plan of `k` stored, everything durable, and the game folder as
/// it is before.
fn setup(k: Kind) -> (Env, PlanHash, Snapshot) {
    let env = Env::new(finish(base()));
    let s = match k {
        Kind::CreateDir | Kind::DirAndFile => spec(vec![entry(r"mods\x.dll", r"mods\x.dll", X)]),
        Kind::CreateFile => spec(vec![entry("new.dll", "new.dll", super::tests::N)]),
        Kind::Replace => spec(vec![entry("d3d9.dll", "d3d9.dll", NEW)]),
        Kind::ReplaceCased => spec(vec![entry("d3d9.dll", "D3D9.DLL", NEW)]),
    };
    let mut h = env.plan(&s);
    if k == Kind::CreateDir {
        // The planner always ends with a file; keep the folder alone.
        let app = app(&env.sys);
        let mut p: Plan = plan::decode(plan::load(&app, &h).unwrap().bytes()).unwrap();
        p.ops.truncate(1);
        h = store(&app, &p.encode().unwrap()).unwrap();
    }
    // `journal\lock` in place, so every run's calls are the same.
    drop(
        crate::journal::Journal::new(&app(&env.sys), crate::journal::InstanceTag::fixed(9))
            .lock()
            .unwrap(),
    );
    env.sys.fake_fs().sync_all();
    let before = env.snap();
    (env, h, before)
}

/// Where a run is interrupted: after call `i` of the apply or of the revert.
#[derive(Debug, Clone, Copy)]
struct At {
    revert: bool,
    call: Prim,
    nth: usize,
    fault: Fault,
}

/// What the run got back before it was interrupted.
#[derive(Debug, Default, Clone, Copy)]
struct Got {
    /// `apply` returned `Applied`.
    applied: bool,
    /// `revert` returned a closed transaction.
    closed: bool,
}

/// Apply, then revert; the fault of `at` (a crash or a failure) at its call if given.
fn run(env: &Env, h: &PlanHash, at: Option<At>) -> Got {
    let mut got = Got::default();
    let crash = |a: At| move |fx: &crate::sys::fake::FakeFs| fx.fault(a.call, a.nth, a.fault);
    let none = |_: &crate::sys::fake::FakeFs| {};
    let r = match at {
        Some(a) if !a.revert => env.apply_armed(h, crash(a)),
        _ => env.apply_armed(h, none),
    };
    let t = match r {
        Ok(Outcome::Applied(t)) => t,
        other => {
            assert!(
                at.is_some_and(|a| !a.revert),
                "apply without a crash: {other:?}"
            );
            return got;
        }
    };
    got.applied = true;
    let r = match at {
        Some(a) if a.revert => env.revert_armed(&t, crash(a)),
        _ => env.revert_armed(&t, none),
    };
    got.closed = r.as_ref().is_ok_and(|r| r.closed.is_some());
    if at.is_none() {
        assert!(got.closed, "revert without a crash: {r:?}");
    }
    got
}

/// The calls of the apply and of the revert of `k`.
fn trace(k: Kind) -> (Vec<Prim>, Vec<Prim>) {
    let (env, h, _) = setup(k);
    let fx = env.sys.fake_fs();
    let rec = |f: &crate::sys::fake::FakeFs| f.record_calls(true);
    let t = match env.apply_armed(&h, rec) {
        Ok(Outcome::Applied(t)) => t,
        other => panic!("{other:?}"),
    };
    fx.record_calls(false);
    let a = fx.take_calls();
    assert!(env.revert_armed(&t, rec).unwrap().closed.is_some());
    fx.record_calls(false);
    (a, fx.take_calls())
}

/// Every interruption point: after each call of the apply, of the revert, and the end.
fn points(k: Kind) -> Vec<Option<At>> {
    let (a, r) = trace(k);
    let mut v = Vec::new();
    for (revert, calls) in [(false, &a), (true, &r)] {
        for (i, call) in calls.iter().enumerate() {
            let nth = calls[..=i].iter().filter(|c| *c == call).count();
            v.push(Some(At {
                revert,
                call: *call,
                nth,
                fault: Fault::CrashAfter,
            }));
        }
    }
    v.push(None);
    v
}

/// The recovery: every transaction not closed is reverted and must close; returns the
/// violations.
fn recover(env: &Env, before: &Snapshot) -> Vec<String> {
    let mut v = Vec::new();
    for (t, s) in env.states() {
        match s {
            Some(TxnState::Closed(_)) => {}
            Some(TxnState::Empty | TxnState::Open | TxnState::Applied) => match env.revert(&t) {
                Ok(r) if r.closed.is_some() => {}
                Ok(r)
                    if r.ops
                        .iter()
                        .any(|o| o.observed == crate::journal::Observed::Foreign) =>
                {
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
    let now = env.snap();
    if now != *before {
        v.push(format!(
            "not identical after recovery: {:?}",
            before.diff(&now)
        ));
    }
    v
}

#[test]
fn t3_a_crash_after_any_call_recovers_to_the_state_before() {
    let mut phases: BTreeMap<bool, BTreeSet<char>> = BTreeMap::new();
    let mut runs = 0;
    for k in KINDS {
        for at in points(k) {
            let Some(a) = at else { continue };
            let (env, h, before) = setup(k);
            run(&env, &h, at);
            assert!(env.sys.fake_fs().crashed(), "{k:?} {a:?}: no crash");
            env.sys.fake_fs().restart();
            if k == Kind::Replace {
                phases
                    .entry(a.revert)
                    .or_default()
                    .insert(phase(&env, a.revert));
            }
            let v = recover(&env, &before);
            assert!(v.is_empty(), "{k:?} crash after {a:?}: {v:?}");
            runs += 1;
        }
    }
    eprintln!("T3 crash: {runs} crashes; replace phases {phases:?}");
    for revert in [false, true] {
        for p in ['A', 'B', 'C', 'D'] {
            assert!(
                phases.get(&revert).is_some_and(|s| s.contains(&p)),
                "the {} never reached phase {p}: {phases:?}",
                if revert { "restore" } else { "replace" }
            );
        }
    }
}

/// The phase (ADR 0017 A3) of the replace of `d3d9.dll` (`revert`: of its restore) on disk.
fn phase(env: &Env, revert: bool) -> char {
    #[expect(
        clippy::disallowed_methods,
        reason = "test: list the fixture game folder"
    )]
    let d = env
        .sys
        .fake_fs()
        .open_dir(Path::new(crate::prim::tests::GAME))
        .unwrap();
    let names: Vec<String> = d
        .read_dir(None)
        .unwrap()
        .into_iter()
        .map(|e| e.name)
        .collect();
    let old = names.iter().any(|n| n.ends_with(".tmp.old"));
    let tmp = names.iter().any(|n| n.ends_with(".tmp"));
    let target = names
        .iter()
        .any(|n| n.eq_ignore_ascii_case("d3d9.dll"))
        .then(|| read_abs(&env.sys, &game("d3d9.dll")));
    let (from, to) = if revert { (NEW, OLD) } else { (OLD, NEW) };
    match (target.as_deref(), old, tmp) {
        (Some(t), false, true) if t == from => 'A',
        (None, true, _) => 'B',
        (Some(t), true, _) if t == to => 'C',
        (Some(t), false, _) if t == to => 'D',
        _ => '-',
    }
}

/// The J5 properties against `exec` of what is on disk after a power loss, before recovery
/// (S2 included), then the recovery.
fn violations(env: &Env, before: &Snapshot, got: Got) -> Vec<String> {
    let mut v = Vec::new();
    let states = env.states();
    for (t, s) in &states {
        match s {
            Some(TxnState::Damaged(_)) | None => v.push(format!("damaged: {t} {s:?}")),
            Some(TxnState::Applied) => {
                let a = app(&env.sys);
                let j = crate::journal::Journal::new(&a, crate::journal::InstanceTag::fixed(5));
                let reverting = j
                    .load(t, crate::journal::VerifyBackups::Length)
                    .map_or(true, |view| {
                        view.ops.values().any(|o| !o.reverts.is_empty())
                    });
                if !reverting {
                    let seen = env.verify(t);
                    if seen
                        .iter()
                        .any(|(_, o)| *o != crate::journal::Observed::After)
                    {
                        v.push(format!("Applied durable, change lost: {seen:?}"));
                    }
                }
            }
            Some(TxnState::Closed(
                crate::journal::Closing::Reverted | crate::journal::Closing::RolledBack,
            )) => {
                let now = env.snap();
                if now != *before {
                    v.push(format!(
                        "Closed durable, revert lost: {:?}",
                        before.diff(&now)
                    ));
                }
            }
            _ => {}
        }
    }
    let state = states.first().and_then(|(_, s)| s.clone());
    if got.applied
        && !matches!(
            state,
            Some(TxnState::Applied | TxnState::Closed(crate::journal::Closing::Reverted))
        )
    {
        v.push(format!("Ok lost: apply returned Applied, now {state:?}"));
    }
    if got.closed && !matches!(state, Some(TxnState::Closed(_))) {
        v.push(format!("Ok lost: revert returned Closed, now {state:?}"));
    }
    if v.is_empty() {
        v.extend(recover(env, before));
    }
    v
}

/// A flush J6 switches off.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Site {
    Journal(FlushSite),
    Game(GameFlush),
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

/// Size of a T4 run.
#[derive(Debug, Default)]
struct Size {
    runs: usize,
    max_c: usize,
    max_d: usize,
}

/// T4 for `k`: every point, every pair of cuts (`d_cuts`: the cuts of `D:` to try, all if
/// `None`). With `want`, stops at the first violation containing it.
fn matrix(k: Kind, skip: Option<Site>, want: Option<&str>) -> (Vec<String>, Size) {
    knobs(skip);
    let pts = points(k);
    let mut found = Vec::new();
    let mut size = Size::default();
    for at in pts {
        let (pc, pd) = {
            let (env, h, _) = setup(k);
            run(&env, &h, at);
            (
                env.sys.fake_fs().pending('C'),
                env.sys.fake_fs().pending('D'),
            )
        };
        size.max_c = size.max_c.max(pc);
        size.max_d = size.max_d.max(pd);
        for c in 0..=pc {
            for d in 0..=pd {
                let (env, h, before) = setup(k);
                let got = run(&env, &h, at);
                env.sys.power_loss(&BTreeMap::from([
                    (Domain::Volume('C'), c),
                    (Domain::Volume('D'), d),
                ]));
                size.runs += 1;
                knobs(None);
                let v = violations(&env, &before, got);
                knobs(skip);
                for x in v {
                    let hit = want.is_some_and(|w| x.contains(w));
                    found.push(format!("{k:?} after {at:?}, cut C {c} D {d}: {x}"));
                    if hit {
                        knobs(None);
                        return (found, size);
                    }
                }
            }
        }
    }
    knobs(None);
    (found, size)
}

#[test]
fn t4_every_power_loss_cut_recovers_to_the_state_before() {
    for k in KINDS {
        let t = Instant::now();
        let (found, size) = matrix(k, None, None);
        eprintln!("T4 {k:?}: {size:?} in {:.1} s", t.elapsed().as_secs_f64());
        assert!(
            found.is_empty(),
            "{k:?}: {} violations: {:#?}",
            found.len(),
            found
        );
        assert!(size.max_c >= 2 && size.max_d >= 1, "{k:?}: {size:?}");
    }
}

#[test]
fn j6_every_flush_site_is_needed_by_exec() {
    let want = [
        (
            Site::Journal(FlushSite::Intent),
            "not identical after recovery",
        ),
        (
            Site::Game(GameFlush::BeforeApplied),
            "Applied durable, change lost",
        ),
        (Site::Journal(FlushSite::Applied), "Ok lost"),
        (
            Site::Journal(FlushSite::RevertIntent),
            "Applied durable, change lost",
        ),
        (
            Site::Game(GameFlush::BeforeRevertDone),
            "Closed durable, revert lost",
        ),
        (Site::Journal(FlushSite::Close), "Ok lost"),
    ];
    for (site, property) in want {
        let (found, _) = matrix(Kind::DirAndFile, Some(site), Some(property));
        let last = found.last().map_or("", String::as_str);
        assert!(
            last.contains(property),
            "without the flush at {site:?}: {found:?}"
        );
        eprintln!("J6 {site:?}: {last}");
    }
}

/// The txn of `env` (exactly one).
fn only_txn(env: &Env) -> crate::journal::TxnId {
    let s = env.states();
    assert_eq!(s.len(), 1, "{s:?}");
    s[0].0
}

/// Temp names below the game folder.
fn tmp_names(env: &Env) -> Vec<String> {
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
        .filter(|n| n.starts_with(".rerun-"))
        .collect();
    v.sort();
    v
}

/// B2, first scenario: the apply's replace done but its folder not flushed, a recovery whose
/// `RevertIntent` (with a restore's temp name) is durable, then a power loss that takes the
/// game folder back to phase B of the apply's replace: `S0` decides (`Y1` left no trace), the
/// op is `Before`, never `Foreign`.
#[test]
fn b2_a_restore_intent_without_its_restore_falls_back_to_the_replace() {
    let (apply_calls, _) = trace(Kind::Replace);
    // Crash right after the replace's step 8 (the game folder is not flushed yet).
    let deletes = apply_calls
        .iter()
        .filter(|c| **c == Prim::PosixDelete)
        .count();
    let mut reached_b = false;
    for keep_d in 0..8 {
        let (env, h, before) = setup(Kind::Replace);
        let r = env.apply_armed(&h, |fx| {
            fx.fault(Prim::PosixDelete, deletes, Fault::CrashAfter)
        });
        assert!(r.is_err(), "{r:?}");
        env.sys.fake_fs().restart();
        let t = only_txn(&env);
        // The recovery observes `After` and writes `RevertIntent(0, Y1)`, flushed; crash then.
        let r = env.revert_armed(&t, |fx| fx.fault(Prim::FlushDir, 1, Fault::CrashAfter));
        assert!(r.is_err(), "{r:?}");
        let pending = env.sys.fake_fs().pending('D');
        if keep_d > pending {
            break;
        }
        env.sys.power_loss(&BTreeMap::from([
            (Domain::Volume('C'), 0),
            (Domain::Volume('D'), keep_d),
        ]));
        let target = super::tests::exists_abs(&env.sys, &game("d3d9.dll"));
        let names = tmp_names(&env);
        if !target && names.iter().any(|n| n.ends_with(".tmp.old")) {
            reached_b = true;
        }
        let v = recover(&env, &before);
        assert!(
            v.is_empty(),
            "keep D {keep_d} ({names:?}, target {target}): {v:?}"
        );
    }
    assert!(reached_b, "phase B with a restore intent never reached");
}

/// B2, second scenario: the apply's `.old` stays mapped (`Done.old_left`), the recovery
/// restores the old content and crashes before `RevertDone`: the target holds `h0` next to
/// `X.old` holding `h0`; the next recovery finds `Before` (cleanup pending), never `Foreign`.
#[test]
fn b2_the_old_state_next_to_its_mapped_dot_old_is_before() {
    let (env, h, _) = setup(Kind::Replace);
    // Map the old file as an image right after step 6 renamed it to `X.old`.
    let held = std::sync::Arc::new(std::sync::Mutex::new(None));
    let slot = std::sync::Arc::clone(&held);
    let fx = env.sys.fake_fs().clone();
    fx.on_step(move |f, ev| {
        if ev.call == Some(Prim::Rename) && ev.name.eq_ignore_ascii_case("d3d9.dll") {
            // Step 7 (the new file onto the name) comes after step 6: `X.old` exists now.
            let names = {
                #[expect(clippy::disallowed_methods, reason = "test: list the fixture folder")]
                let d = f.open_dir(Path::new(crate::prim::tests::GAME)).unwrap();
                d.read_dir(None).unwrap()
            };
            if let Some(o) = names.iter().find(|e| e.name.ends_with(".tmp.old")) {
                let mut s = slot.lock().unwrap();
                if s.is_none() {
                    *s = Some(
                        f.map_image_as(4242, &Path::new(crate::prim::tests::GAME).join(&o.name))
                            .unwrap(),
                    );
                }
            }
        }
    });
    let t = match env.apply(&h) {
        Ok(Outcome::Applied(t)) => t,
        other => panic!("{other:?}"),
    };
    env.sys.fake_fs().clear_on_step();
    assert!(held.lock().unwrap().is_some(), "the .old was mapped");
    assert_eq!(
        tmp_names(&env).len(),
        1,
        "X.old left: {:?}",
        tmp_names(&env)
    );
    // Revert: `X.old` still mapped (cleanup Busy), the restore runs; crash right after the
    // restore's step 8, before `RevertDone`.
    let (_, revert_calls) = trace(Kind::Replace);
    let restore_delete = revert_calls
        .iter()
        .filter(|c| **c == Prim::PosixDelete)
        .count();
    let r = env.revert_armed(&t, |fx| {
        fx.fault(Prim::PosixDelete, restore_delete + 1, Fault::CrashAfter);
    });
    assert!(r.is_err(), "{r:?}");
    env.sys.fake_fs().restart();
    assert_eq!(read_abs(&env.sys, &game("d3d9.dll")), OLD, "restored");
    assert!(
        tmp_names(&env).iter().any(|n| n.ends_with(".tmp.old")),
        "X.old still there"
    );
    let rep = env.revert(&t).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        rep.ops[0].observed,
        crate::journal::Observed::Before,
        "{rep:?}"
    );
    assert!(rep.closed.is_some(), "{rep:?}");
    // Mapped: a pending cleanup the report names (open point: not cleaned later yet).
    assert!(
        rep.ops[0]
            .left
            .iter()
            .any(|n| n.as_str().ends_with(".tmp.old")),
        "{rep:?}"
    );
    drop(held.lock().unwrap().take());
}

/// Review M1: a failure at any call (the rollback or the revert ends, `sys::seq` may have
/// undone itself without a flush), then a power loss at every cut of `D:` (the journal kept
/// whole): recovery identical, never foreign. And a crash at any call, restart, recovery,
/// then the same power loss: the recovery's revert is durable before its records.
#[test]
fn m1_a_failure_or_a_recovery_then_a_power_loss_on_the_game_volume() {
    let t = Instant::now();
    let mut runs = 0;
    for k in [Kind::Replace, Kind::CreateFile] {
        for at in points(k) {
            let Some(at) = at else { continue };
            for fault in [
                Fault::Fail(crate::sys::SysErrorKind::Other),
                Fault::CrashAfter,
            ] {
                let at = At { fault, ..at };
                let prepare = |env: &Env, h: &PlanHash, before: &Snapshot| -> Got {
                    let got = run(env, h, Some(at));
                    let fx = env.sys.fake_fs();
                    fx.clear_faults();
                    if fx.crashed() {
                        fx.restart();
                        let v = recover(env, before);
                        assert!(v.is_empty(), "{k:?} {at:?}: recovery: {v:?}");
                        return Got::default();
                    }
                    got
                };
                let pd = {
                    let (env, h, before) = setup(k);
                    prepare(&env, &h, &before);
                    env.sys.fake_fs().pending('D')
                };
                for d in 0..=pd {
                    let (env, h, before) = setup(k);
                    let got = prepare(&env, &h, &before);
                    env.sys.power_loss(&BTreeMap::from([
                        (Domain::Volume('C'), 1 << 20),
                        (Domain::Volume('D'), d),
                    ]));
                    runs += 1;
                    let v = violations(&env, &before, got);
                    assert!(v.is_empty(), "{k:?} {at:?}, cut D {d}: {v:?}");
                }
            }
        }
    }
    eprintln!(
        "M1: {runs} power losses in {:.1} s",
        t.elapsed().as_secs_f64()
    );
}

/// Review S1: the apply's `X.old` (the old content, left mapped) survives a restore that fails
/// on a damaged backup; the op stays open.
#[test]
fn s1_a_damaged_backup_never_costs_the_dot_old() {
    let (env, h, _) = setup(Kind::Replace);
    let held = std::sync::Arc::new(std::sync::Mutex::new(None));
    let slot = std::sync::Arc::clone(&held);
    env.sys.fake_fs().on_step(move |f, ev| {
        if ev.call == Some(Prim::Rename) && ev.name.eq_ignore_ascii_case("d3d9.dll") {
            #[expect(clippy::disallowed_methods, reason = "test: list the fixture folder")]
            let d = f.open_dir(Path::new(crate::prim::tests::GAME)).unwrap();
            if let Some(o) = d
                .read_dir(None)
                .unwrap()
                .iter()
                .find(|e| e.name.ends_with(".tmp.old"))
            {
                let mut s = slot.lock().unwrap();
                if s.is_none() {
                    let p = Path::new(crate::prim::tests::GAME).join(&o.name);
                    *s = Some(f.map_image_as(4242, &p).unwrap());
                }
            }
        }
    });
    let t = match env.apply(&h) {
        Ok(Outcome::Applied(t)) => t,
        other => panic!("{other:?}"),
    };
    env.sys.fake_fs().clear_on_step();
    // The game is closed now: the mapping goes, `X.old` stays (Done.old_left).
    drop(held.lock().unwrap().take());
    let old = tmp_names(&env);
    assert_eq!(old.len(), 1, "{old:?}");
    let old_abs = format!(r"{}\{}", crate::prim::tests::GAME, old[0]);
    // The backup damaged (same length).
    let bin = format!(r"{}\op-0000.bin", env.txn_dir(&t));
    let mut bad = OLD.to_vec();
    bad[0] ^= 1;
    let fx = env.sys.fake_fs();
    fx.remove_abs(Path::new(&bin)).unwrap();
    fx.put_file(Path::new(&bin), &bad).unwrap();
    let r = env.revert(&t);
    assert!(
        matches!(&r, Err(super::ExecError::Op { source, .. }) if source.kind == crate::sys::SysErrorKind::Mismatch),
        "{r:?}"
    );
    assert_eq!(read_abs(&env.sys, &old_abs), OLD, "X.old kept");
    assert_eq!(
        read_abs(&env.sys, &game("d3d9.dll")),
        NEW,
        "the target unchanged"
    );
    assert_eq!(env.state(&t), Some(TxnState::Applied), "the op stays open");
}
