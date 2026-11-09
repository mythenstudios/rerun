//! `exec` with `TokenList` under failures, crashes and power losses (P2-11, C5): R-L4 a failure
//! and a crash after every call (file system and registry) of an apply and of a revert; R-L5
//! a power loss after every call at every cut of `C:` (journal, packages) and `HKCU`
//! (`Domain::Hive`). The plans have no file op, so `D:` never has a pending change (checked).
//!
//! Kinds: `LayersNew` (`AppCompatFlags` and `Layers` created, a new value), `LayersMerge` (two
//! tokens appended to `~ RUNASADMIN`), `LayersDrift` (as `LayersMerge`, and between the apply
//! and the revert another program appends `X1` and the hive is flushed: the revert under test
//! is the semantic one, E2 b; no `from`/`to`, E8), `LayersStacked` (`ZZ_OS_A` applied durably
//! as T1 with the keys created, then T2 appends `ZZ_FLAG_A` to the same value; the cut is in
//! T2; the recovery reverts T2, then T1). Properties as in R-T4: a durable `Applied` has every
//! change (verify all `After`); a durable `Closed` has the state its revert leaves (before the
//! transaction, or `~ RUNASADMIN X1` after the drift); an `Ok` survives; after the recovery
//! (newest transaction first) everything is as expected, never `Damaged`, never `Foreign`.
//!
//! Size: measured 2026-11-07 (see `docs/09-testing.md`); the full product, no reduction.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Instant;

use super::Outcome;
use super::layer_tests::{layer_base, layer_base_with, layer_value, put_layer, two_tokens};
use super::reg_tests::{plan_all, snap_all};
use super::tests::{Env, finish};
use super::{Flush, knob as exec_knob};
use crate::journal::{Closing, Observed, TxnId, TxnState};
use crate::plan::PlanHash;
use crate::prim::Step;
use crate::prim::layer_tests::layer_step;
use crate::prim::tests::app;
use crate::sys::SysErrorKind;
use crate::sys::fake::{Domain, Fault, Prim};
use crate::sys::registry::{Hive, RegValue};
use crate::sys::snapshot::Snapshot;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[expect(
    clippy::enum_variant_names,
    reason = "the kind names of the plan and docs/09"
)]
enum Kind {
    LayersNew,
    LayersMerge,
    LayersDrift,
    LayersStacked,
}

const KINDS: [Kind; 4] = [
    Kind::LayersNew,
    Kind::LayersMerge,
    Kind::LayersDrift,
    Kind::LayersStacked,
];

/// The old value of `LayersMerge` and `LayersDrift`.
const OLD: &str = "~ RUNASADMIN";
/// What another program writes in `LayersDrift`, and what the revert leaves.
const DRIFTED: &str = "~ RUNASADMIN ZZ_FLAG_A ZZ_OS_A X1";
const DRIFT_END: &str = "~ RUNASADMIN X1";

/// One system of a kind, everything durable.
struct Case {
    env: Env,
    kind: Kind,
    /// The plan under test.
    h: PlanHash,
    /// The state before every transaction (the end of the recovery without the drift).
    before: Snapshot,
    /// The state before the transaction under test (a durable `Closed` of it).
    start: Snapshot,
    /// The transaction applied durably before (`LayersStacked`).
    t1: Option<TxnId>,
}

fn setup(k: Kind) -> Case {
    let b = match k {
        Kind::LayersNew | Kind::LayersStacked => layer_base(),
        Kind::LayersMerge | Kind::LayersDrift => layer_base_with(OLD),
    };
    let env = Env::new(finish(b));
    let before = snap_all(&env);
    let mut t1 = None;
    let steps: Vec<Step> = match k {
        Kind::LayersNew | Kind::LayersMerge | Kind::LayersDrift => vec![two_tokens()],
        Kind::LayersStacked => {
            let t = env.applied(&plan_all(&env, &[layer_step("game.exe", &["ZZ_OS_A"])]));
            t1 = Some(t);
            vec![layer_step("game.exe", &["ZZ_FLAG_A"])]
        }
    };
    let h = plan_all(&env, &steps);
    // `journal\lock` in place, so every run's calls are the same.
    drop(
        crate::journal::Journal::new(&app(&env.sys), crate::journal::InstanceTag::fixed(9))
            .lock()
            .unwrap(),
    );
    env.sys.sync_all();
    let start = snap_all(&env);
    Case {
        env,
        kind: k,
        h,
        before,
        start,
        t1,
    }
}

#[derive(Debug, Clone, Copy)]
struct At {
    revert: bool,
    call: Prim,
    nth: usize,
    fault: Fault,
}

#[derive(Debug, Default, Clone, Copy)]
struct Got {
    applied: bool,
    closed: bool,
    /// The drift of `LayersDrift` was written (the apply succeeded).
    drifted: bool,
}

/// Another program appends `X1` and the hive is flushed (`LayersDrift`).
fn drift(env: &Env) {
    put_layer(&env.sys, &RegValue::String(DRIFTED.into()));
    env.sys.fake_registry().sync_all();
}

/// Apply, (the drift,) then revert the plan under test; the fault of `at` at its call if given.
fn run(c: &Case, at: Option<At>) -> Got {
    let env = &c.env;
    let mut got = Got::default();
    let arm = |a: At| move |fx: &crate::sys::fake::FakeFs| fx.fault(a.call, a.nth, a.fault);
    let none = |_: &crate::sys::fake::FakeFs| {};
    let r = match at {
        Some(a) if !a.revert => env.apply_armed(&c.h, arm(a)),
        _ => env.apply_armed(&c.h, none),
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
    if c.kind == Kind::LayersDrift {
        drift(env);
        got.drifted = true;
    }
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

/// The calls of the apply and of the revert of the plan under test.
fn trace(k: Kind) -> (Vec<Prim>, Vec<Prim>) {
    let c = setup(k);
    let fx = c.env.sys.fake_fs();
    let rec = |f: &crate::sys::fake::FakeFs| f.record_calls(true);
    let t = match c.env.apply_armed(&c.h, rec) {
        Ok(Outcome::Applied(t)) => t,
        other => panic!("{k:?}: {other:?}"),
    };
    fx.record_calls(false);
    let a = fx.take_calls();
    if k == Kind::LayersDrift {
        drift(&c.env);
    }
    assert!(c.env.revert_armed(&t, rec).unwrap().closed.is_some());
    fx.record_calls(false);
    (a, fx.take_calls())
}

/// Every interruption point: after each call of the apply and of the revert, and the end.
fn points(k: Kind, fault: Fault) -> Vec<Option<At>> {
    let (a, r) = trace(k);
    let mut v = Vec::new();
    for (revert, calls) in [(false, &a), (true, &r)] {
        for (i, call) in calls.iter().enumerate() {
            let nth = calls[..=i].iter().filter(|c| *c == call).count();
            v.push(Some(At {
                revert,
                call: *call,
                nth,
                fault,
            }));
        }
    }
    v.push(None);
    v
}

/// The state is `want` (a snapshot), after the drift's remnant is checked exactly and put back
/// to the old value if `drifted`.
fn settled(c: &Case, drifted: bool, want: &Snapshot, what: &str) -> Option<String> {
    let env = &c.env;
    if drifted {
        let v = layer_value(&env.sys);
        if v != Some(RegValue::String(DRIFT_END.into())) {
            return Some(format!("{what}: after the drift the value is {v:?}"));
        }
        put_layer(&env.sys, &RegValue::String(OLD.into()));
    }
    let now = snap_all(env);
    (now != *want).then(|| format!("{what}: {:?}", want.diff(&now)))
}

/// The recovery: every transaction not closed is reverted, newest first, and must close; then
/// everything is as expected.
fn recover(c: &Case, drifted: bool) -> Vec<String> {
    let env = &c.env;
    let mut v = Vec::new();
    let mut states = env.states();
    states.reverse();
    for (t, s) in states {
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
                        v.push(format!("recovery failed: {t}: {other:?}"));
                    }
                }
            },
            other => v.push(format!("damaged: {t} {other:?}")),
        }
    }
    if v.is_empty() {
        v.extend(settled(
            c,
            drifted,
            &c.before,
            "not as expected after recovery",
        ));
    }
    v
}

/// The properties of what is on disk and in the hive after a power loss, before the recovery;
/// then the recovery.
fn violations(c: &Case, got: Got) -> Vec<String> {
    let env = &c.env;
    let mut v = Vec::new();
    let states = env.states();
    let under: Vec<&(TxnId, Option<TxnState>)> =
        states.iter().filter(|(t, _)| Some(*t) != c.t1).collect();
    for (t, s) in &under {
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
                // After the drift the value is not `new` any more: only an untouched apply is
                // checked here (the drift happens after `Applied` returned).
                if !reverting && !got.drifted {
                    let seen = env.verify(t);
                    if seen.iter().any(|(_, o)| *o != Observed::After) {
                        v.push(format!("Applied durable, change lost: {seen:?}"));
                    }
                }
            }
            Some(TxnState::Closed(Closing::Reverted | Closing::RolledBack)) => {
                let drifted = got.drifted && matches!(s, Some(TxnState::Closed(Closing::Reverted)));
                if let Some(x) = settled(c, drifted, &c.start, "Closed durable, revert lost") {
                    v.push(x);
                }
                // `settled` put the old value back; the recovery below checks from there.
                if drifted {
                    return v;
                }
            }
            _ => {}
        }
    }
    let state = under.first().and_then(|(_, s)| s.clone());
    if got.applied
        && !matches!(
            state,
            Some(TxnState::Applied | TxnState::Closed(Closing::Reverted))
        )
    {
        v.push(format!("Ok lost: apply returned Applied, now {state:?}"));
    }
    if got.closed && !matches!(state, Some(TxnState::Closed(_))) {
        v.push(format!("Ok lost: revert returned Closed, now {state:?}"));
    }
    if let Some(t1) = c.t1
        && !matches!(
            states.iter().find(|(t, _)| *t == t1).map(|(_, s)| s),
            Some(Some(TxnState::Applied))
        )
    {
        v.push(format!("T1 changed: {states:?}"));
    }
    if v.is_empty() {
        v.extend(recover(c, got.drifted));
    }
    v
}

/// R-L4, failures: `fail_at` every call (file system and registry) of an apply and of a revert
/// (in `LayersDrift` the semantic one): refused, rolled back identical, or left open and as
/// expected after a later revert.
#[test]
fn r_l4_a_failure_at_any_call_rolls_back_or_leaves_it_for_revert() {
    let t = Instant::now();
    let mut runs = 0;
    let mut outcomes: BTreeMap<&str, usize> = BTreeMap::new();
    for k in KINDS {
        for at in points(k, Fault::Fail(SysErrorKind::Other)) {
            let Some(a) = at else { continue };
            let c = setup(k);
            let mut drifted = false;
            let r = if a.revert {
                let t = c.env.applied(&c.h);
                if k == Kind::LayersDrift {
                    drift(&c.env);
                    drifted = true;
                }
                let r = c
                    .env
                    .revert_armed(&t, |fx| fx.fault(a.call, a.nth, a.fault));
                if r.as_ref().is_ok_and(|r| r.closed.is_some()) {
                    "revert closed"
                } else {
                    "revert failed"
                }
            } else {
                match c
                    .env
                    .apply_armed(&c.h, |fx| fx.fault(a.call, a.nth, a.fault))
                {
                    Ok(Outcome::Applied(t)) => {
                        assert!(c.env.revert(&t).is_ok_and(|r| r.closed.is_some()));
                        "applied"
                    }
                    Ok(Outcome::Nothing) => panic!("{k:?} {a:?}: nothing"),
                    Err(super::ApplyError::Refused(_)) => "refused",
                    Err(super::ApplyError::RolledBack { .. }) => "rolled back",
                    Err(
                        super::ApplyError::LeftOpen { .. } | super::ApplyError::HelperOpen { .. },
                    ) => "left open",
                    Err(e @ super::ApplyError::CleanupPending { .. }) => {
                        panic!("{k:?} {a:?}: cleanup pending without a mapping: {e:?}")
                    }
                }
            };
            *outcomes.entry(r).or_default() += 1;
            c.env.sys.fake_fs().clear_faults();
            let v = recover(&c, drifted);
            assert!(v.is_empty(), "{k:?} fail at {a:?}: {v:?}");
            runs += 1;
        }
    }
    eprintln!(
        "R-L4 fail_at: {runs} runs in {:.1} s: {outcomes:?}",
        t.elapsed().as_secs_f64()
    );
    for want in ["refused", "rolled back", "revert failed"] {
        assert!(outcomes.get(want).is_some_and(|n| *n > 0), "{outcomes:?}");
    }
}

/// R-L4, crashes: a crash after every call, a restart, the recovery: as expected, never
/// `Damaged` or `Foreign`.
#[test]
fn r_l4_a_crash_after_any_call_recovers() {
    let t = Instant::now();
    let mut runs = 0;
    let mut reg_calls = BTreeSet::new();
    for k in KINDS {
        for at in points(k, Fault::CrashAfter) {
            let Some(a) = at else { continue };
            let c = setup(k);
            let got = run(&c, at);
            assert!(c.env.sys.fake_fs().crashed(), "{k:?} {a:?}: no crash");
            c.env.sys.restart();
            if let Prim::Reg(r) = a.call {
                reg_calls.insert(format!("{r:?}"));
            }
            let v = recover(&c, got.drifted);
            assert!(v.is_empty(), "{k:?} crash after {a:?}: {v:?}");
            runs += 1;
        }
    }
    eprintln!(
        "R-L4 crash: {runs} crashes in {:.1} s; registry calls crashed after: {reg_calls:?}",
        t.elapsed().as_secs_f64()
    );
    for want in ["Create", "SetValue", "Delete", "DeleteValue", "Flush"] {
        assert!(reg_calls.contains(want), "{want}: {reg_calls:?}");
    }
}

/// Size of a run of R-L5.
#[derive(Debug, Default)]
struct Size {
    runs: usize,
    max_c: usize,
    max_d: usize,
    max_h: usize,
}

/// R-L5 for `k` (with the flush `skip` of `exec` switched off for the runs): every point,
/// every cut of `C:` and `HKCU` (`D:` has nothing pending).
fn matrix(k: Kind, skip: Option<Flush>) -> (Vec<String>, Size) {
    let mut found = Vec::new();
    let mut size = Size::default();
    for at in points(k, Fault::CrashAfter) {
        let (pc, pd, ph) = {
            let c = setup(k);
            run(&c, at);
            let s = &c.env.sys;
            (
                s.pending(Domain::Volume('C')),
                s.pending(Domain::Volume('D')),
                s.pending(Domain::Hive(Hive::CurrentUser)),
            )
        };
        size.max_c = size.max_c.max(pc);
        size.max_d = size.max_d.max(pd);
        size.max_h = size.max_h.max(ph);
        for cut_c in 0..=pc {
            for h in 0..=ph {
                let c = setup(k);
                exec_knob::skip(skip);
                let got = run(&c, at);
                exec_knob::skip(None);
                c.env.sys.power_loss(&BTreeMap::from([
                    (Domain::Volume('C'), cut_c),
                    (Domain::Volume('D'), 0),
                    (Domain::Hive(Hive::CurrentUser), h),
                ]));
                size.runs += 1;
                for x in violations(&c, got) {
                    found.push(format!("{k:?} after {at:?}, cut C {cut_c} HKCU {h}: {x}"));
                }
            }
        }
    }
    (found, size)
}

fn r_l5(k: Kind) {
    let t = Instant::now();
    let (found, size) = matrix(k, None);
    eprintln!("R-L5 {k:?}: {size:?} in {:.1} s", t.elapsed().as_secs_f64());
    assert!(
        found.is_empty(),
        "{k:?}: {} violations: {:#?}",
        found.len(),
        found
    );
    assert!(size.max_c >= 2 && size.max_h >= 1, "{k:?}: {size:?}");
    assert_eq!(size.max_d, 0, "{k:?}: no file op, nothing pending on D:");
}

#[test]
fn r_l5_layers_new_every_power_loss_cut_recovers() {
    r_l5(Kind::LayersNew);
}

#[test]
fn r_l5_layers_merge_every_power_loss_cut_recovers() {
    r_l5(Kind::LayersMerge);
}

#[test]
fn r_l5_layers_drift_every_power_loss_cut_recovers() {
    r_l5(Kind::LayersDrift);
}

#[test]
fn r_l5_layers_stacked_every_power_loss_cut_recovers() {
    r_l5(Kind::LayersStacked);
}

/// The matrix bites on the semantic revert (J6 for one site, no new flush site): without the
/// `HKCU` flush before a registry `RevertDone`, a power loss keeps `Closed` and loses the
/// removal of Rerun's tokens from the drifted value.
#[test]
fn j6_the_hive_flush_before_revert_done_covers_the_semantic_revert() {
    let (found, _) = matrix(Kind::LayersDrift, Some(Flush::HiveBeforeRevertDone));
    assert!(
        found
            .iter()
            .any(|x| x.contains("Closed durable, revert lost: after the drift")),
        "{found:#?}"
    );
}

/// K-L1 against R-L4 (review nit): a value without any of Rerun's tokens taken as `Foreign`
/// (E2 a) makes the recovery after a crash between the semantic revert's write and its
/// `RevertDone` meet a foreign op; without the knob that state is `Drifted` (E8: no `from`/`to`
/// needed).
#[test]
fn k_l1_no_token_left_as_foreign_breaks_rl4_on_the_drift() {
    let _r = super::reg_tests::Reset(|| {
        super::reg::KNOB_UNTOUCHED_FOREIGN.with(|c| c.set(false));
    });
    super::reg::KNOB_UNTOUCHED_FOREIGN.with(|c| c.set(true));
    let mut hit = None;
    for at in points(Kind::LayersDrift, Fault::CrashAfter) {
        let Some(a) = at else { continue };
        if !a.revert {
            continue;
        }
        let c = setup(Kind::LayersDrift);
        let got = run(&c, at);
        c.env.sys.restart();
        if recover(&c, got.drifted)
            .iter()
            .any(|x| x.starts_with("Foreign"))
        {
            hit = Some(a);
            break;
        }
    }
    assert!(hit.is_some(), "the control did not bite");
}
