//! `exec` with the helper batch under crashes and power losses (P4-2d; ADR 0023 §9, §14; the
//! conventions of docs/09 "Crash and power-loss matrices"), on the two-process fake of
//! `fw_tests`. The helper runs outside the CLI's fault sequence (another process); the fake
//! firewall keeps a rule once its call returned (the "durable on return" model of §6; the lazy
//! model follows with the P4-5b write contract).
//!
//! Phases: `Apply` (the plan applied), `Rollback` (the apply's prompt declined: the batch and the
//! earlier ops rolled back), `Revert` (an applied plan reverted); kinds `Rules` (one rule alone,
//! the batch at op 0) and `Mixed` (a file op, then two rules).
//!
//! - FC1 the CLI crashes after every call of a phase (every record boundary of the batch among
//!   them), restarts, and the recovery (every transaction not closed reverted, newest first)
//!   ends identical: the game folder and the firewall scope; never `Damaged`, never `Foreign`.
//! - FC2 the helper crashes after each of its writes (adds and removes): the CLI judges the run
//!   `Unknown`, the transaction stays open, the revert ends identical.
//! - FC3 a power loss after every call at every cut of `C:` (journal, `elevate`) and `D:` (the
//!   game): a durable `Applied` has every change (`verify` all `After`, the rules too), a durable
//!   `Closed` has the state before, an `Ok` survives, and the recovery ends identical.
//! - FC4 J6 for the batch: without the flush of `HelperBatch` the matrix finds a rule the
//!   recovery cannot see (the journal lost the batch, the rule stays); `RevertBatch`'s flush
//!   (like the flush of the `elevate` folder after the request) has no observable effect: a
//!   lost `RevertBatch` only makes the next revert observe again; it is kept for symmetry with
//!   `RevertIntent` (ADR 0019 amendment P4-2d) and pinned by its place in the code only.

use std::collections::BTreeMap;
use std::time::Instant;

use super::Outcome;
use super::fw_tests::{Fw, Kind, Script, fw_scope, plan, seams};
use crate::journal::{Closing, FlushSite, Observed, TxnState, knob as journal_knob};
use crate::plan::PlanHash;
use crate::sys::FwRule;
use crate::sys::fake::{Domain, Fault, Prim, WriteFault};
use crate::sys::snapshot::Snapshot;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Apply,
    Rollback,
    Revert,
}

const PHASES: [Phase; 3] = [Phase::Apply, Phase::Rollback, Phase::Revert];
const KINDS: [Kind; 2] = [Kind::Rules, Kind::Mixed];

struct Case {
    fw: Fw,
    h: PlanHash,
    before: (Snapshot, Vec<FwRule>),
}

fn setup(k: Kind) -> Case {
    let fw = Fw::new();
    let before = fw.snap();
    let h = plan(&fw.sys, fw.index, k);
    // `journal\lock` and `elevate` in place, so every run's calls are the same.
    {
        let app = crate::prim::tests::app(&fw.sys);
        drop(
            crate::journal::Journal::new(&app, crate::journal::InstanceTag::fixed(9))
                .lock()
                .unwrap(),
        );
    }
    fw.sys
        .fake_fs()
        .mkdir_all(std::path::Path::new(super::fw_tests::ELEVATE))
        .unwrap();
    fw.sys.sync_all();
    Case { fw, h, before }
}

#[derive(Debug, Clone, Copy)]
struct At {
    call: Prim,
    nth: usize,
}

#[derive(Debug, Default, Clone, Copy)]
struct Got {
    applied: bool,
    closed: bool,
}

/// The phase on `c`, the CLI crashing after the call `at` of the phase's own run if given.
fn run(c: &Case, p: Phase, at: Option<At>) -> Got {
    let fx = c.fw.sys.fake_fs();
    let arm = || {
        fx.clear_faults();
        if let Some(a) = at {
            fx.fault(a.call, a.nth, Fault::CrashAfter);
        }
    };
    let mut got = Got::default();
    match p {
        Phase::Apply | Phase::Rollback => {
            let script = if p == Phase::Rollback {
                vec![Script::Decline]
            } else {
                Vec::new()
            };
            let (r, _) = c.fw.run(script, |cx| {
                arm();
                super::apply(cx, &c.h)
            });
            got.applied = matches!(r, Ok(Outcome::Applied(_)));
            got.closed =
                p == Phase::Rollback && matches!(r, Err(super::ApplyError::RolledBack { .. }));
        }
        Phase::Revert => {
            fx.clear_faults();
            let t = match c.fw.apply(&c.h, Vec::new()).0 {
                Ok(Outcome::Applied(t)) => t,
                other => panic!("apply: {other:?}"),
            };
            c.fw.sys.sync_all();
            let (r, _) = c.fw.run(Vec::new(), |cx| {
                arm();
                super::revert(cx, &t)
            });
            got.closed = r.as_ref().is_ok_and(|r| r.closed.is_some());
        }
    }
    got
}

/// The calls of the phase's own run.
fn trace(k: Kind, p: Phase) -> Vec<Prim> {
    let c = setup(k);
    let fx = c.fw.sys.fake_fs();
    if p == Phase::Revert {
        let t = match c.fw.apply(&c.h, Vec::new()).0 {
            Ok(Outcome::Applied(t)) => t,
            other => panic!("apply: {other:?}"),
        };
        let (r, _) = c.fw.run(Vec::new(), |cx| {
            fx.clear_faults();
            fx.record_calls(true);
            super::revert(cx, &t)
        });
        assert!(r.unwrap().closed.is_some());
    } else {
        let script = if p == Phase::Rollback {
            vec![Script::Decline]
        } else {
            Vec::new()
        };
        let _ = c.fw.run(script, |cx| {
            fx.clear_faults();
            fx.record_calls(true);
            super::apply(cx, &c.h)
        });
    }
    fx.record_calls(false);
    fx.take_calls()
}

/// Every interruption point of the phase: after each of its calls.
fn points(k: Kind, p: Phase) -> Vec<At> {
    let calls = trace(k, p);
    calls
        .iter()
        .enumerate()
        .map(|(i, call)| At {
            call: *call,
            nth: calls[..=i].iter().filter(|c| *c == call).count(),
        })
        .collect()
}

/// The recovery: every transaction not closed reverted, newest first (the helper runs when a
/// rule is there), and must close; then everything is as before.
fn recover(c: &Case) -> Vec<String> {
    let mut v = Vec::new();
    let mut states = c.fw.states();
    states.reverse();
    for (t, s) in states {
        match s {
            Some(TxnState::Closed(_)) => {}
            Some(TxnState::Empty | TxnState::Open | TxnState::Applied) => {
                match c.fw.revert(&t, Vec::new()).0 {
                    Ok(r) if r.closed.is_some() => {}
                    Ok(r) if r.ops.iter().any(|o| o.observed == Observed::Foreign) => {
                        v.push(format!("Foreign: {r:?}"));
                    }
                    other => {
                        let headless = !super::tests::exists_abs(
                            &c.fw.sys,
                            &format!(
                                r"{}\Rerun\journal\{t}\head.json",
                                crate::journal::tests::LAD
                            ),
                        );
                        if !(headless && s == Some(TxnState::Empty)) {
                            v.push(format!("recovery failed: {t}: {other:?}"));
                        }
                    }
                }
            }
            other => v.push(format!("damaged: {t} {other:?}")),
        }
    }
    let now = c.fw.snap();
    if now != c.before {
        v.push(format!(
            "not identical after recovery: game {:?}, firewall {:?}",
            c.before.0.diff(&now.0),
            now.1
        ));
    }
    v
}

/// FC1.
#[test]
fn fc1_a_cli_crash_after_any_call_recovers_to_the_state_before() {
    seams(|| {
        let t = Instant::now();
        let mut runs = 0;
        for k in KINDS {
            for p in PHASES {
                for a in points(k, p) {
                    let c = setup(k);
                    run(&c, p, Some(a));
                    assert!(c.fw.sys.fake_fs().crashed(), "{k:?} {p:?} {a:?}: no crash");
                    c.fw.sys.restart();
                    let v = recover(&c);
                    assert!(v.is_empty(), "{k:?} {p:?} crash after {a:?}: {v:?}");
                    runs += 1;
                }
            }
        }
        eprintln!("FC1: {runs} crashes in {:.1} s", t.elapsed().as_secs_f64());
        assert!(runs > 100, "{runs}");
    });
}

/// FC2.
#[test]
fn fc2_a_helper_crash_after_any_write_is_unknown_and_recovers() {
    seams(|| {
        for k in KINDS {
            let n = if k == Kind::Rules { 1 } else { 2 };
            // The apply's adds.
            for w in 1..=n {
                let c = setup(k);
                let crash: fn(&crate::sys::fake::FakeSystem) = match w {
                    1 => |s| s.fake_firewall().fault_write(1, WriteFault::CrashAfter),
                    _ => |s| s.fake_firewall().fault_write(2, WriteFault::CrashAfter),
                };
                let (r, _) = c.fw.apply(&c.h, vec![Script::Before(crash)]);
                assert!(
                    matches!(r, Err(super::ApplyError::HelperOpen { .. })),
                    "{k:?} add {w}: {r:?}"
                );
                assert_eq!(fw_scope(&c.fw.sys).len(), w, "{k:?} add {w}");
                let v = recover(&c);
                assert!(v.is_empty(), "{k:?} add {w}: {v:?}");
            }
            // The revert's removes.
            for w in 1..=n {
                let c = setup(k);
                let t = match c.fw.apply(&c.h, Vec::new()).0 {
                    Ok(Outcome::Applied(t)) => t,
                    other => panic!("{other:?}"),
                };
                let crash: fn(&crate::sys::fake::FakeSystem) = match w {
                    1 => |s| s.fake_firewall().fault_write(1, WriteFault::CrashAfter),
                    _ => |s| s.fake_firewall().fault_write(2, WriteFault::CrashAfter),
                };
                let (r, _) = c.fw.revert(&t, vec![Script::Before(crash)]);
                let r = r.unwrap();
                assert_eq!(r.closed, None, "{k:?} remove {w}");
                assert!(
                    r.halted.as_ref().is_some_and(|h| matches!(
                        *h.why,
                        super::Refusal::Helper(super::HelperFailure::Unknown)
                    )),
                    "{k:?} remove {w}: {r:?}"
                );
                assert_eq!(c.fw.state(&t), Some(TxnState::Applied));
                let v = recover(&c);
                assert!(v.is_empty(), "{k:?} remove {w}: {v:?}");
            }
        }
    });
}

/// The J5 properties after a power loss (FC3), then the recovery.
fn violations(c: &Case, got: Got) -> Vec<String> {
    let mut v = Vec::new();
    let states = c.fw.states();
    for (t, s) in &states {
        match s {
            Some(TxnState::Damaged(_)) | None => v.push(format!("damaged: {t} {s:?}")),
            Some(TxnState::Applied) => {
                let app = crate::prim::tests::app(&c.fw.sys);
                let j = crate::journal::Journal::new(&app, crate::journal::InstanceTag::fixed(5));
                let reverting = j
                    .load(t, crate::journal::VerifyBackups::Length)
                    .map_or(true, |view| {
                        view.ops.values().any(|o| !o.reverts.is_empty())
                    });
                if !reverting {
                    let seen = c.fw.verify(t);
                    if seen.iter().any(|(_, o)| *o != Observed::After) {
                        v.push(format!("Applied durable, change lost: {seen:?}"));
                    }
                }
            }
            Some(TxnState::Closed(Closing::Reverted | Closing::RolledBack)) => {
                let now = c.fw.snap();
                if now != c.before {
                    v.push(format!("Closed durable, revert lost: {:?}", now.1));
                }
            }
            _ => {}
        }
    }
    let state: Option<TxnState> = states.first().and_then(|(_, s)| s.clone());
    if got.applied
        && !matches!(
            state,
            Some(TxnState::Applied | TxnState::Closed(Closing::Reverted))
        )
    {
        v.push(format!("Ok lost: apply returned Applied, now {state:?}"));
    }
    if got.closed && !matches!(state, Some(TxnState::Closed(_))) {
        v.push(format!("Ok lost: the run returned Closed, now {state:?}"));
    }
    if v.is_empty() {
        v.extend(recover(c));
    }
    v
}

/// FC3 for `k` and `p`, with the journal flush `skip` switched off; stops at the first
/// violation containing `want`.
fn matrix(k: Kind, p: Phase, skip: Option<FlushSite>, want: Option<&str>) -> (Vec<String>, usize) {
    let mut found = Vec::new();
    let mut runs = 0;
    for a in points(k, p) {
        let (pc, pd) = {
            let c = setup(k);
            journal_knob::skip(skip);
            run(&c, p, Some(a));
            journal_knob::skip(None);
            (
                c.fw.sys.pending(Domain::Volume('C')),
                c.fw.sys.pending(Domain::Volume('D')),
            )
        };
        for cut_c in 0..=pc {
            for cut_d in 0..=pd {
                let c = setup(k);
                journal_knob::skip(skip);
                let got = run(&c, p, Some(a));
                journal_knob::skip(None);
                c.fw.sys.power_loss(&BTreeMap::from([
                    (Domain::Volume('C'), cut_c),
                    (Domain::Volume('D'), cut_d),
                ]));
                runs += 1;
                for x in violations(&c, got) {
                    let hit = want.is_some_and(|w| x.contains(w));
                    found.push(format!(
                        "{k:?} {p:?} after {a:?}, cut C {cut_c} D {cut_d}: {x}"
                    ));
                    if hit {
                        return (found, runs);
                    }
                }
            }
        }
    }
    (found, runs)
}

/// FC3.
#[test]
fn fc3_a_power_loss_at_any_cut_keeps_every_ok_and_recovers() {
    seams(|| {
        let t = Instant::now();
        let mut total = 0;
        for k in KINDS {
            for p in PHASES {
                let (found, runs) = matrix(k, p, None, None);
                total += runs;
                assert!(found.is_empty(), "{} violations: {found:#?}", found.len());
            }
        }
        eprintln!(
            "FC3: {total} power losses in {:.1} s",
            t.elapsed().as_secs_f64()
        );
    });
}

/// FC4 (J6): the flush of `HelperBatch` is what keeps a rule the helper added visible to the
/// recovery.
#[test]
fn fc4_without_the_helper_batch_flush_a_rule_is_left_behind() {
    seams(|| {
        let (found, _) = matrix(
            Kind::Rules,
            Phase::Apply,
            Some(FlushSite::HelperBatch),
            Some("not identical after recovery"),
        );
        assert!(
            found
                .iter()
                .any(|x| x.contains("not identical after recovery")),
            "{found:#?}"
        );
    });
}
