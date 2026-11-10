//! The hand-over under failures, crashes and power losses (P4-8b, ADR 0020 amendment P4-8b;
//! kinds `HandOverFile` and `HandOverDir` of CM2, the order "creator first").
//!
//! T1 (the creator) and T2 (a holder) are applied and durable. The run reverts T1, which keeps
//! the shared objects for T2, then T2, which removes them; a failure or a crash at every call of
//! either revert interrupts it. Then the power is cut at every pair of cuts of `C:` (journal) and
//! `D:` (game), right after the run ("direct") or after a complete recovery ("recovered").
//! Properties after the cut, before the recovery:
//! - nothing damaged;
//! - **never deleted under a live reliance**: a shared object that is gone has, in every
//!   transaction that is not closed, a `RevertIntent` (or a `RevertDone`) for every op on it
//!   (S1: an inherited deletion comes after the carrying op's durable intent);
//! - **never an inherited deletion without its evidence**: gone while T2's op on it is reverted
//!   and T1's op on it has neither intent nor `RevertDone`;
//! - **no removal lost under a durable close**: T2 closed `Reverted` and T1's op `Kept`, but the
//!   object is still there.
//!
//! The recovery then reverts every transaction that is not closed, newest first (so a creator
//! interrupted while keeping is resumed after the holder released: interleaving (a)), and the
//! game folder must be the one before T1. Reduction as in CM2 (`RERUN_UNREDUCED=1`: every call
//! and cut). Interleaving (c), two holders, one interrupted after its intent: `hc_two_holders`.
//! Controls: K-HO4 (the parent of a removed inherited folder not flushed) and K-HO5 (the
//! inherited act before the carrying op's intent) each break a property.

use std::collections::BTreeMap;
use std::time::Instant;

use super::rebind_crash_tests::changes_state;
use super::tests::{Env, N, X, base, finish, game, pkg};
use crate::journal::{Closing, InstanceTag, Journal, Observed, TxnId, TxnState, VerifyBackups};
use crate::prim::FileInstallSpec;
use crate::prim::tests::{app, entry, spec};
use crate::sys::SysErrorKind;
use crate::sys::fake::{Domain, Fault, Prim};
use crate::sys::snapshot::Snapshot;

const Y: &[u8] = b"y.dll of the package";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// T1 creates `new.dll`; T2 holds it and replaces `d3d9.dll`.
    HandOverFile,
    /// T1 creates `new.dll`, `mods` and `mods\x.dll`; T2 holds `new.dll` and puts `mods\y.dll`.
    HandOverDir,
}

const KINDS: [Kind; 2] = [Kind::HandOverFile, Kind::HandOverDir];

fn specs(k: Kind) -> (FileInstallSpec, FileInstallSpec) {
    match k {
        Kind::HandOverFile => (
            spec(vec![entry("new.dll", "new.dll", N)]),
            spec(vec![
                entry("new.dll", "new.dll", N),
                entry("d3d9.dll", "d3d9.dll", super::tests::NEW),
            ]),
        ),
        Kind::HandOverDir => (
            spec(vec![
                entry("new.dll", "new.dll", N),
                entry(r"mods\x.dll", r"mods\x.dll", X),
            ]),
            spec(vec![
                entry("new.dll", "new.dll", N),
                entry(r"mods\y.dll", r"mods\y.dll", Y),
            ]),
        ),
    }
}

/// The shared objects of a kind (relative paths) and whether each is a folder.
fn shared(k: Kind) -> Vec<(&'static str, bool)> {
    match k {
        Kind::HandOverFile => vec![("new.dll", false)],
        Kind::HandOverDir => vec![("new.dll", false), ("mods", true)],
    }
}

struct World {
    env: Env,
    floor: Snapshot,
    t1: TxnId,
    t2: TxnId,
}

fn setup(k: Kind) -> World {
    let env = Env::new(finish(base().file(pkg(r"mods\y.dll"), Y.to_vec())));
    let floor = env.snap();
    let (s1, s2) = specs(k);
    let t1 = env.applied(&env.plan(&s1));
    let t2 = env.applied(&env.plan(&s2));
    drop(
        Journal::new(&app(&env.sys), InstanceTag::fixed(9))
            .lock()
            .unwrap(),
    );
    env.sys.fake_fs().sync_all();
    World { env, floor, t1, t2 }
}

#[derive(Debug, Clone, Copy)]
struct At {
    /// 0: the revert of T1, 1: of T2.
    phase: u8,
    call: Prim,
    nth: usize,
    fault: Fault,
}

/// Reverts T1, then T2; the fault of `at` armed in its phase. Stops at the first error.
fn run(w: &World, at: Option<At>) {
    for (phase, t) in [(0u8, w.t1), (1, w.t2)] {
        let r = w.env.revert_armed(&t, |fx| {
            if let Some(a) = at.filter(|a| a.phase == phase) {
                fx.fault(a.call, a.nth, a.fault);
            }
        });
        if !r.as_ref().is_ok_and(|r| r.closed.is_some()) {
            assert!(at.is_some(), "a run without a fault: {r:?}");
            return;
        }
    }
}

fn trace(k: Kind) -> [Vec<Prim>; 2] {
    let w = setup(k);
    let fx = w.env.sys.fake_fs();
    let mut out = [Vec::new(), Vec::new()];
    for (i, t) in [w.t1, w.t2].iter().enumerate() {
        let r = w.env.revert_armed(t, |f| f.record_calls(true)).unwrap();
        assert!(r.closed.is_some(), "{r:?}");
        fx.record_calls(false);
        out[i] = fx.take_calls();
    }
    out
}

fn full() -> bool {
    #[expect(
        clippy::disallowed_methods,
        reason = "test gate: a switch, never a path"
    )]
    std::env::var_os("RERUN_UNREDUCED").is_some_and(|v| v == "1")
}

fn points(k: Kind, fault: Fault) -> Vec<Option<At>> {
    let calls = trace(k);
    let mut v = Vec::new();
    for (phase, calls) in calls.iter().enumerate() {
        let first_write = calls.iter().position(|c| changes_state(*c));
        for (i, call) in calls.iter().enumerate() {
            if !full() && !changes_state(*call) && first_write != Some(i + 1) {
                continue;
            }
            v.push(Some(At {
                phase: u8::try_from(phase).unwrap_or(0),
                call: *call,
                nth: calls[..=i].iter().filter(|c| *c == call).count(),
                fault,
            }));
        }
    }
    v.push(None);
    v
}

fn cuts(pending: usize) -> Vec<usize> {
    if full() {
        (0..=pending).collect()
    } else {
        let mut v = vec![0, 1.min(pending), pending];
        v.dedup();
        v
    }
}

/// The view of every transaction (`None`: unreadable).
fn views(env: &Env) -> Vec<(TxnId, Option<crate::journal::TxnView>)> {
    let a = app(&env.sys);
    let j = Journal::new(&a, InstanceTag::fixed(5));
    j.list()
        .unwrap()
        .txns
        .into_iter()
        .map(|l| (l.id, j.load(&l.id, VerifyBackups::Length).ok()))
        .collect()
}

/// The op of transaction `v` on the shared object `rel` (a folder: at or below it): its index
/// in the head and its records.
fn ops_on<'a>(
    v: &'a crate::journal::TxnView,
    rel: &str,
    dir: bool,
) -> Vec<(u16, Option<&'a crate::journal::OpLog>)> {
    let Some(p) = v.head.as_deref().and_then(|h| super::decode_head(h).ok()) else {
        return Vec::new();
    };
    let f = crate::fold::fold(rel);
    p.ops
        .iter()
        .enumerate()
        .filter_map(|(k, o)| match o.target() {
            crate::plan::Target::File { path, .. } => {
                let q = crate::fold::fold(path.as_str());
                let on = q == f || (dir && q.starts_with(&format!("{f}\\")));
                on.then(|| {
                    let k = super::op_ix(k);
                    (k, v.ops.get(&k))
                })
            }
            _ => None,
        })
        .collect()
}

fn violations(w: &World, k: Kind) -> Vec<String> {
    let env = &w.env;
    let mut out = Vec::new();
    let vs = views(env);
    for (t, v) in &vs {
        match v {
            None => out.push(format!("unreadable: {t}")),
            Some(v) if matches!(v.state, TxnState::Damaged(_)) => {
                out.push(format!("damaged: {t} {:?}", v.state));
            }
            _ => {}
        }
    }
    let view = |t: &TxnId| {
        vs.iter()
            .find(|(x, _)| x == t)
            .and_then(|(_, v)| v.as_ref())
    };
    for (rel, dir) in shared(k) {
        let there = super::tests::exists_abs(&env.sys, &game(rel));
        for (t, v) in &vs {
            let Some(v) = v else { continue };
            if matches!(v.state, TxnState::Closed(_)) {
                continue;
            }
            for (op, log) in ops_on(v, rel, dir) {
                let intended = log.is_some_and(|l| !l.reverts.is_empty() || l.reverted.is_some());
                let applied = log.is_some_and(|l| l.done.is_some());
                if !there && applied && !intended {
                    out.push(format!(
                        "deleted under a live reliance: {rel} gone, op {op} of {t} relies on it"
                    ));
                }
            }
        }
        let t1_op = view(&w.t1).map(|v| ops_on(v, rel, false));
        let t1_rec = t1_op
            .as_ref()
            .and_then(|o| o.first().copied())
            .and_then(|(_, l)| l);
        let t1_kept = t1_rec.is_some_and(|l| {
            l.reverted
                .as_ref()
                .is_some_and(|r| r.observed == Observed::Kept)
        });
        let t1_untouched = t1_rec.is_some_and(|l| l.reverts.is_empty() && l.reverted.is_none());
        let t2_closed = view(&w.t2).is_some_and(|v| v.state == TxnState::Closed(Closing::Reverted));
        let t2_reverted = view(&w.t2).is_some_and(|v| {
            ops_on(v, rel, dir)
                .iter()
                .any(|(_, l)| l.is_some_and(|l| l.reverted.is_some()))
        });
        if !there && t2_reverted && t1_untouched {
            out.push(format!("inherited deletion without its evidence: {rel}"));
        }
        if there && t2_closed && t1_kept {
            out.push(format!("Closed durable, removal lost: {rel}"));
        }
    }
    out
}

/// Every transaction not closed reverted, newest first, until all are closed; then the floor.
fn recover(w: &World) -> Vec<String> {
    let env = &w.env;
    let mut out = Vec::new();
    for _ in 0..3 {
        let mut states = env.states();
        states.sort_by_key(|(t, _)| std::cmp::Reverse(*t));
        let mut open = false;
        for (t, s) in states {
            match s {
                Some(TxnState::Closed(_)) => {}
                Some(TxnState::Empty | TxnState::Open | TxnState::Applied) => {
                    open = true;
                    match env.revert(&t) {
                        Ok(r) if r.ops.iter().any(|o| o.observed == Observed::Foreign) => {
                            out.push(format!("Foreign: {r:?}"));
                            return out;
                        }
                        Ok(_) => {}
                        // A creator newest first may wait for its holder (`Held`): next round.
                        Err(crate::exec::ExecError::Refused(_)) => {}
                        Err(e) => {
                            out.push(format!("recovery failed: {e}"));
                            return out;
                        }
                    }
                }
                other => {
                    out.push(format!("damaged: {t} {other:?}"));
                    return out;
                }
            }
        }
        if !open {
            break;
        }
    }
    if env
        .states()
        .iter()
        .any(|(_, s)| !matches!(s, Some(TxnState::Closed(_))))
    {
        out.push(format!("not every transaction closed: {:?}", env.states()));
    }
    let now = env.snap();
    if now != w.floor {
        out.push(format!(
            "not identical after recovery: {:?}",
            w.floor.diff(&now)
        ));
    }
    out
}

#[derive(Debug, Default)]
struct Size {
    runs: usize,
    points: usize,
    max_c: usize,
    max_d: usize,
}

/// The matrix of `k` for `recovered` (the cut after a complete recovery) or direct; stops at
/// the first violation containing `want`.
fn matrix(k: Kind, recovered: bool, want: Option<&str>) -> (Vec<String>, Size) {
    let faults = [Fault::Fail(SysErrorKind::Other), Fault::CrashAfter];
    let mut found = Vec::new();
    let mut size = Size::default();
    for fault in faults {
        for at in points(k, fault) {
            size.points += 1;
            let prepare = || {
                let w = setup(k);
                run(&w, at);
                let fx = w.env.sys.fake_fs();
                fx.clear_faults();
                if fx.crashed() {
                    fx.restart();
                }
                let mut early = Vec::new();
                if recovered {
                    early = recover(&w);
                }
                (w, early)
            };
            let (w0, early) = prepare();
            found.extend(
                early
                    .into_iter()
                    .map(|x| format!("{k:?} {at:?} before the cut: {x}")),
            );
            let (pc, pd) = (
                w0.env.sys.pending(Domain::Volume('C')),
                w0.env.sys.pending(Domain::Volume('D')),
            );
            size.max_c = size.max_c.max(pc);
            size.max_d = size.max_d.max(pd);
            let mut first = Some(w0);
            for c in cuts(pc) {
                for d in cuts(pd) {
                    let w = first.take().unwrap_or_else(|| prepare().0);
                    w.env.sys.power_loss(&BTreeMap::from([
                        (Domain::Volume('C'), c),
                        (Domain::Volume('D'), d),
                    ]));
                    size.runs += 1;
                    let mut v = violations(&w, k);
                    if v.is_empty() {
                        v = recover(&w);
                    }
                    for x in v {
                        let hit = want.is_some_and(|s| x.contains(s));
                        found.push(format!(
                            "{k:?} {fault:?} {at:?} recovered={recovered} cut C {c} D {d}: {x}"
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

fn all_clear(recovered: bool) {
    for k in KINDS {
        let t = Instant::now();
        let (found, size) = matrix(k, recovered, None);
        eprintln!(
            "HO-CM {k:?} recovered={recovered} full={}: {size:?} in {:.1} s",
            full(),
            t.elapsed().as_secs_f64()
        );
        assert!(
            found.is_empty(),
            "{k:?}: {} violations: {:#?}",
            found.len(),
            found.iter().take(5).collect::<Vec<_>>()
        );
        // Not trivial; after a complete recovery little of `C:` is pending (as in CM2).
        assert!(
            size.max_c >= if recovered { 1 } else { 2 },
            "{k:?}: {size:?}"
        );
    }
}

#[test]
fn hc_hand_over_survives_a_fault_and_any_pair_of_cuts() {
    all_clear(false);
}

#[test]
fn hc_hand_over_survives_a_fault_a_recovery_and_any_pair_of_cuts() {
    all_clear(true);
}

/// Interleaving (c): T1 keeps `new.dll` for T2 and T3; T2 crashes right after its first revert
/// record; T3's revert defers (T2 still relies); T2 resumes and removes it; identical.
#[test]
fn hc_two_holders_one_interrupted() {
    let env = Env::new(finish(base().file(pkg(r"mods\y.dll"), Y.to_vec())));
    let floor = env.snap();
    let t1 = env.applied(&env.plan(&spec(vec![entry("new.dll", "new.dll", N)])));
    let t2 = env.applied(&env.plan(&specs(Kind::HandOverFile).1));
    let t3 = env.applied(&env.plan(&specs(Kind::HandOverDir).1));
    assert_eq!(env.revert(&t1).unwrap().closed, Some(Closing::Reverted));
    // A crash right after T2's first record (the `RevertIntent` of its replace): its revert has
    // begun, its hold has no `RevertDone`, so it still relies on `new.dll`.
    let nth = 1;
    let r = env.revert_armed(&t2, |f| f.fault(Prim::Rename, nth, Fault::CrashAfter));
    assert!(r.is_err(), "{r:?}");
    env.sys.fake_fs().restart();
    let rep = env.revert(&t3).unwrap();
    assert_eq!(rep.closed, Some(Closing::Reverted));
    assert!(
        super::tests::exists_abs(&env.sys, &game("new.dll")),
        "T3 deferred to the interrupted T2"
    );
    assert_eq!(env.revert(&t2).unwrap().closed, Some(Closing::Reverted));
    assert!(!super::tests::exists_abs(&env.sys, &game("new.dll")));
    let now = env.snap();
    assert!(now == floor, "{:?}", floor.diff(&now));
}

/// K-HO4: the parent of a removed inherited folder not flushed: the removal is lost under a
/// durable record (a durable close, or a `RevertDone` the recovery trusts), so the folder stays.
#[test]
fn hc_control_k_ho4_an_unflushed_parent_loses_the_removal() {
    super::knob::handover(4);
    let (found, _) = matrix(Kind::HandOverDir, false, None);
    super::knob::handover(0);
    assert!(
        found
            .iter()
            .any(|x| x.contains("Closed durable, removal lost")
                || x.contains("not identical after recovery")),
        "K-HO4 not caught: {} violations",
        found.len()
    );
}

/// K-HO5: the inherited act before the carrying op's intent: a deletion under a live reliance.
#[test]
fn hc_control_k_ho5_an_act_before_the_intent_is_seen() {
    super::knob::handover(5);
    let (found, _) = matrix(
        Kind::HandOverFile,
        false,
        Some("deleted under a live reliance"),
    );
    super::knob::handover(0);
    assert!(
        found
            .last()
            .is_some_and(|x| x.contains("deleted under a live reliance")),
        "K-HO5 not caught: {} violations",
        found.len()
    );
}
