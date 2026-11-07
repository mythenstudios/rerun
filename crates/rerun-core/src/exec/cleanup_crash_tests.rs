//! P2-15 under failures, crashes and power losses: the axis "a `.old` mapped during step 8 of a
//! restore or of a rollback" times "a fault at every call of the run that cleans it up" times
//! "every pair of cuts of `C:` (journal) and `D:` (game)".
//!
//! - Kinds: `Restore` (a replace applied and durable, reverted while the restore's `Y.old` is
//!   mapped) and `Rollback` (an apply whose flush before `Applied` fails, rolled back while the
//!   restore's `Y.old` is mapped). Either leaves the transaction open with one pending `.old`;
//!   the mapping is released, and the run that writes it (the mapped run) is **not** synced, so
//!   its `RevertDone` may be lost by a cut while the cleanup's deletion is durable (CL-C2: the
//!   recovery observes the op again).
//! - CL-C1: a failure (`Other`) or a crash after every call of the cleanup run, then the
//!   recovery: closed, the game folder identical to before the apply, never `Damaged` or
//!   `Foreign`; an error of the run after its deletion is never a refusal (senior-dev B2).
//! - CL-C2: a crash after every call of the cleanup run, then a power loss at every pair of cuts,
//!   right after the run ("direct") or after a complete recovery ("recovered"): before the
//!   recovery never a durable `Closed` with a durable `.old` ("Closed durable, cleanup lost") or
//!   another state than before the apply, then the recovery closes, identical.
//! - Controls: K-CL2 (the tenth flush site off) and K-CL2b (the cleanup pass flushes only after a
//!   deletion of its own, senior-dev S1: a deletion of a crashed run is then lost under a closed
//!   transaction) each fail CL-C2.
//!
//! Size: reduced by default (the calls that change state and the last read-only call before the
//! first one; cuts none, the first and all); `RERUN_UNREDUCED=1` runs every call and every cut.

use std::collections::BTreeMap;
use std::time::Instant;

use super::cleanup_tests::{Mapper, replace_env, tmp_in};
use super::knob as exec_knob;
use super::rebind_crash_tests::changes_state;
use super::tests::Env;
use super::{ApplyError, ExecError, Flush};
use crate::journal::{Closing, Observed, TxnId, TxnState};
use crate::prim::tests::GAME;
use crate::sys::SysErrorKind;
use crate::sys::fake::{Domain, FakeFs, Fault, Prim};
use crate::sys::snapshot::Snapshot;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Restore,
    Rollback,
}

const KINDS: [Kind; 2] = [Kind::Restore, Kind::Rollback];

/// One world right before the cleanup run: the transaction open with one pending `.old`, the
/// mapping released, the mapped run's writes not synced.
struct World {
    env: Env,
    t: TxnId,
    before: Snapshot,
}

/// The calls of a successful apply of the replace.
fn apply_flushes() -> usize {
    let (env, h) = replace_env();
    let fx = env.sys.fake_fs();
    let r = env.apply_armed(&h, |f| f.record_calls(true));
    fx.record_calls(false);
    assert!(r.is_ok(), "{r:?}");
    fx.take_calls()
        .iter()
        .filter(|c| **c == Prim::FlushDir)
        .count()
}

fn setup(k: Kind, flushes: usize) -> World {
    let (env, h) = replace_env();
    let before = env.snap();
    let t = match k {
        Kind::Restore => {
            let t = env.applied(&h);
            env.sys.fake_fs().sync_all();
            let m = Mapper::game(&env);
            let r = env.revert(&t).unwrap_or_else(|e| panic!("{e}"));
            Mapper::stop(&env);
            assert!(r.closed.is_none() && r.cleanup.len() == 1, "{r:?}");
            m.release();
            t
        }
        Kind::Rollback => {
            let mut m = None;
            let r = env.apply_armed(&h, |fx| {
                m = Some(Mapper::on(fx, GAME, Some((Prim::FlushDir, flushes - 1))));
                fx.fail_at(Prim::FlushDir, flushes - 1, SysErrorKind::Other);
            });
            Mapper::stop(&env);
            env.sys.fake_fs().clear_faults();
            let t = match r {
                Err(ApplyError::CleanupPending { txn, .. }) => txn,
                other => panic!("{other:?}"),
            };
            if let Some(m) = m {
                m.release();
            }
            t
        }
    };
    World { env, t, before }
}

/// How much of a matrix runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Size {
    Reduced,
    Full,
}

fn size() -> Size {
    #[expect(
        clippy::disallowed_methods,
        reason = "test gate: a switch, never a path"
    )]
    if std::env::var_os("RERUN_UNREDUCED").is_some_and(|v| v == "1") {
        Size::Full
    } else {
        Size::Reduced
    }
}

/// Where the cleanup run is interrupted.
#[derive(Debug, Clone, Copy)]
struct At {
    call: Prim,
    nth: usize,
    fault: Fault,
}

/// The calls of the cleanup run of `k`.
fn trace(k: Kind, flushes: usize) -> Vec<Prim> {
    let w = setup(k, flushes);
    let fx = w.env.sys.fake_fs();
    let r = w.env.revert_armed(&w.t, |f| f.record_calls(true));
    fx.record_calls(false);
    let r = r.unwrap_or_else(|e| panic!("{e}"));
    assert!(r.closed.is_some(), "{r:?}");
    fx.take_calls()
}

fn points(k: Kind, flushes: usize, fault: Fault, s: Size) -> Vec<At> {
    let calls = trace(k, flushes);
    let first_write = calls.iter().position(|c| changes_state(*c));
    calls
        .iter()
        .enumerate()
        .filter(|(i, c)| s == Size::Full || changes_state(**c) || first_write == Some(i + 1))
        .map(|(i, c)| At {
            call: *c,
            nth: calls[..=i].iter().filter(|x| *x == c).count(),
            fault,
        })
        .collect()
}

fn cuts(pending: usize, s: Size) -> Vec<usize> {
    match s {
        Size::Full => (0..=pending).collect(),
        Size::Reduced => {
            let mut v = vec![0, 1.min(pending), pending];
            v.dedup();
            v
        }
    }
}

/// The cleanup run with `at`; restarted after a crash. `Err` names a wrong error class.
fn cleanup_run(w: &World, at: At) -> (bool, Option<String>) {
    let fx = w.env.sys.fake_fs();
    let r = w
        .env
        .revert_armed(&w.t, |f: &FakeFs| f.fault(at.call, at.nth, at.fault));
    fx.clear_faults();
    if fx.crashed() {
        fx.restart();
    }
    let deleted = tmp_in(&w.env, GAME).is_empty();
    let wrong = match &r {
        // B2: an error after the deletion is not "nothing changed".
        Err(ExecError::Refused(e)) if deleted && !fx.crashed() && at.fault != Fault::CrashAfter => {
            Some(format!("refused after its deletion: {e}"))
        }
        _ => None,
    };
    (r.as_ref().is_ok_and(|r| r.closed.is_some()), wrong)
}

/// The recovery: every transaction not closed is reverted and must close, the game folder
/// identical to before the apply.
fn recover(w: &World) -> Vec<String> {
    let mut v = Vec::new();
    for (t, s) in w.env.states() {
        match s {
            Some(TxnState::Closed(_)) => {}
            Some(TxnState::Empty | TxnState::Open | TxnState::Applied) => match w.env.revert(&t) {
                Ok(r) if r.closed.is_some() => {}
                Ok(r) if r.ops.iter().any(|o| o.observed == Observed::Foreign) => {
                    v.push(format!("Foreign: {r:?}"));
                }
                other => v.push(format!("recovery failed: {other:?}")),
            },
            other => v.push(format!("damaged: {t} {other:?}")),
        }
    }
    if w.env.snap() != w.before {
        v.push(format!(
            "not identical after recovery: {:?}",
            w.before.diff(&w.env.snap())
        ));
    }
    v
}

/// The properties of what is on disk after a power loss, before the recovery, then the
/// recovery.
fn violations(w: &World, closed: bool) -> Vec<String> {
    let mut v = Vec::new();
    let state = w.env.state(&w.t);
    match &state {
        None | Some(TxnState::Damaged(_)) => v.push(format!("damaged: {state:?}")),
        Some(TxnState::Closed(Closing::Reverted | Closing::RolledBack)) => {
            if !tmp_in(&w.env, GAME).is_empty() {
                v.push(format!(
                    "Closed durable, cleanup lost: {:?}",
                    tmp_in(&w.env, GAME)
                ));
            } else if w.env.snap() != w.before {
                v.push(format!(
                    "Closed durable, revert lost: {:?}",
                    w.before.diff(&w.env.snap())
                ));
            }
        }
        _ => {}
    }
    if closed && !matches!(state, Some(TxnState::Closed(_))) {
        v.push(format!("Ok lost: the run returned Closed, now {state:?}"));
    }
    if v.is_empty() {
        v.extend(recover(w));
    }
    v
}

/// When the power is cut.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Moment {
    Direct,
    Recovered,
}

/// The knobs of a control.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Control {
    /// K-CL2: the tenth flush site off.
    NoFlush,
    /// K-CL2b: the cleanup pass flushes only after a deletion of its own.
    FlushOnlyAfterDelete,
}

fn knobs(c: Option<Control>) {
    exec_knob::skip((c == Some(Control::NoFlush)).then_some(Flush::GameBeforeClosed));
    exec_knob::flush_only_after_delete(c == Some(Control::FlushOnlyAfterDelete));
}

/// CL-C2 for `k`: a crash at every point of the cleanup run, every pair of cuts. With `want`,
/// stops at the first violation containing it.
fn matrix(
    k: Kind,
    moment: Moment,
    s: Size,
    control: Option<Control>,
    want: Option<&str>,
) -> (Vec<String>, usize, usize) {
    let flushes = apply_flushes();
    let mut found = Vec::new();
    let mut runs = 0;
    // The case of CL-C2: the `RevertDone` lost, the deletion durable.
    let mut done_lost = 0;
    for at in points(k, flushes, Fault::CrashAfter, s) {
        let prepare = || {
            let w = setup(k, flushes);
            knobs(control);
            let (mut closed, _) = cleanup_run(&w, at);
            if moment == Moment::Recovered {
                let _ = recover(&w);
                closed = false;
            }
            knobs(None);
            (w, closed)
        };
        let (w0, c0) = prepare();
        let (pc, pd) = (
            w0.env.sys.pending(Domain::Volume('C')),
            w0.env.sys.pending(Domain::Volume('D')),
        );
        let mut first = Some((w0, c0));
        for c in cuts(pc, s) {
            for d in cuts(pd, s) {
                let (w, closed) = first.take().unwrap_or_else(prepare);
                w.env.sys.power_loss(&BTreeMap::from([
                    (Domain::Volume('C'), c),
                    (Domain::Volume('D'), d),
                ]));
                runs += 1;
                if tmp_in(&w.env, GAME).is_empty() && revert_done_lost(&w) {
                    done_lost += 1;
                }
                for x in violations(&w, closed) {
                    let hit = want.is_some_and(|s| x.contains(s));
                    found.push(format!(
                        "{k:?} {moment:?} after {at:?}, cut C {c} D {d}: {x}"
                    ));
                    if hit {
                        return (found, runs, done_lost);
                    }
                }
            }
        }
    }
    (found, runs, done_lost)
}

/// The op's `RevertDone` is not on disk (the journal still loads).
fn revert_done_lost(w: &World) -> bool {
    let a = crate::prim::tests::app(&w.env.sys);
    let j = crate::journal::Journal::new(&a, crate::journal::InstanceTag::fixed(6));
    j.load(&w.t, crate::journal::VerifyBackups::Length)
        .is_ok_and(|v| v.ops.get(&0).is_some_and(|o| o.reverted.is_none()))
}

#[test]
fn cl_c1_a_failure_or_a_crash_at_any_call_of_the_cleanup_recovers() {
    let t = Instant::now();
    let flushes = apply_flushes();
    let mut runs = 0;
    for k in KINDS {
        for fault in [Fault::Fail(SysErrorKind::Other), Fault::CrashAfter] {
            for at in points(k, flushes, fault, size()) {
                let w = setup(k, flushes);
                let (_, wrong) = cleanup_run(&w, at);
                runs += 1;
                assert!(wrong.is_none(), "{k:?} {at:?}: {wrong:?}");
                let v = recover(&w);
                assert!(v.is_empty(), "{k:?} {at:?}: {v:?}");
            }
        }
    }
    eprintln!("CL-C1: {runs} runs in {:.1} s", t.elapsed().as_secs_f64());
    assert!(runs > 20, "{runs}");
}

#[test]
fn cl_c2_a_power_loss_after_any_call_of_the_cleanup_recovers() {
    for moment in [Moment::Direct, Moment::Recovered] {
        for k in KINDS {
            let t = Instant::now();
            let (found, runs, done_lost) = matrix(k, moment, size(), None, None);
            eprintln!(
                "CL-C2 {k:?} {moment:?}: {runs} power losses ({done_lost} with the RevertDone lost and the deletion durable) in {:.1} s",
                t.elapsed().as_secs_f64()
            );
            assert!(found.is_empty(), "{found:#?}");
            assert!(runs >= 10, "{runs}");
            assert!(
                moment == Moment::Recovered || done_lost > 0,
                "{k:?}: never reached"
            );
        }
    }
}

/// K-CL2: without the flush before `Closed`, a cut keeps `Closed` and brings the `.old` back.
/// K-CL2b (senior-dev S1): flushing only after a deletion of its own, a recovery that finds the
/// `.old` gone (the crashed run deleted it) closes without making that deletion durable.
#[test]
fn k_cl2_without_the_flush_before_closed_the_cleanup_is_lost() {
    let (found, _, _) = matrix(
        Kind::Restore,
        Moment::Direct,
        Size::Reduced,
        Some(Control::NoFlush),
        Some("Closed durable, cleanup lost"),
    );
    assert!(
        found
            .last()
            .is_some_and(|x| x.contains("Closed durable, cleanup lost")),
        "{found:#?}"
    );
    let (found, _, _) = matrix(
        Kind::Restore,
        Moment::Recovered,
        Size::Reduced,
        Some(Control::FlushOnlyAfterDelete),
        Some("Closed durable, cleanup lost"),
    );
    assert!(
        found
            .last()
            .is_some_and(|x| x.contains("Closed durable, cleanup lost")),
        "{found:#?}"
    );
}
