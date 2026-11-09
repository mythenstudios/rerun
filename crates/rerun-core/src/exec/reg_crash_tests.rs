//! `exec` with registry ops under failures, crashes and power losses (P2-10b, C7): R-T3 a
//! failure and a crash after every call (file system and registry) of an apply and of a
//! revert; R-T4 a power loss after every call at every cut of `C:` (journal, packages), `D:`
//! (game) and `HKCU` (`Domain::Hive`); J6 with the 8 flush sites of `exec` and the journal.
//!
//! Kinds: `RegNew` (two created keys and a new value), `RegReplace` (a small value replaced
//! inline and a 20 KiB raw value replaced through `op-NNNN.bin`), `Mixed` (`CreateDir`,
//! `CreateFile`, `CreateKey`, `SetValue`), `Stacked` (`RegNew` applied durably as T1, then T2
//! replaces T1's value; the cut is in T2; the recovery reverts T2, then T1). Properties as in
//! T4/J5: a durable `Applied` has every change (verify all `After`); a durable `Closed` has
//! the state before its transaction; an `Ok` survives; after the recovery (newest transaction
//! first) everything is as before, never `Damaged`, never `Foreign`.
//!
//! Size (S5): the full product of the cuts of `C:`, `D:` and `HKCU` takes about 40 s in a
//! debug build (3,157 runs, measured 2026-11-06), under the 60 s of S5, so no reduction is
//! applied: Windows flushes the journal's volume at every intent, so few records of `C:` are
//! ever pending, and a plan has few registry changes between its hive flushes.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Instant;

use super::Flush;
use super::Outcome;
use super::knob as exec_knob;
use super::reg_tests::{VENDOR_GAME, plan_all, reg_base, snap_all};
use super::tests::{Env, X, finish};
use crate::journal::{Closing, FlushSite, Observed, TxnId, TxnState, knob as journal_knob};
use crate::plan::PlanHash;
use crate::prim::Step;
use crate::prim::reg_tests::{BIG, dword, hkcu, step};
use crate::prim::tests::{app, entry, spec};
use crate::sys::SysErrorKind;
use crate::sys::fake::{Domain, Fault, Prim};
use crate::sys::registry::{Hive, RegValue, reg_type};
use crate::sys::snapshot::Snapshot;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    RegNew,
    RegReplace,
    Mixed,
    Stacked,
}

const KINDS: [Kind; 4] = [Kind::RegNew, Kind::RegReplace, Kind::Mixed, Kind::Stacked];

/// `RegNew`'s steps: `Software\New` and `Software\New\Prod` created, `A` new.
fn reg_new() -> Vec<Step> {
    vec![step(r"HKCU\Software\New\Prod", vec![dword("A", 1)])]
}

/// One system of a kind, everything durable.
struct Case {
    env: Env,
    /// The plan under test.
    h: PlanHash,
    /// The state before every transaction (the end of the recovery).
    before: Snapshot,
    /// The state before the transaction under test (a durable `Closed` of it).
    start: Snapshot,
    /// The transaction applied durably before (`Stacked`).
    t1: Option<TxnId>,
}

fn setup(k: Kind) -> Case {
    let b = reg_base()
        .value(hkcu(VENDOR_GAME), "Small", RegValue::Dword(5))
        .raw_value(
            hkcu(VENDOR_GAME),
            "BigRaw",
            reg_type::REG_NONE,
            &vec![3; BIG],
        )
        .key(hkcu(r"Software\Pre"));
    let env = Env::new(finish(b));
    let before = snap_all(&env);
    let mut t1 = None;
    let steps = match k {
        Kind::RegNew => reg_new(),
        Kind::RegReplace => vec![step(
            &format!(r"HKCU\{VENDOR_GAME}"),
            vec![dword("Small", 6), dword("BigRaw", 1)],
        )],
        Kind::Mixed => vec![
            Step::FileInstall(spec(vec![entry(r"mods\x.dll", r"mods\x.dll", X)])),
            step(r"HKCU\Software\Pre\Prod", vec![dword("A", 1)]),
        ],
        Kind::Stacked => {
            let t = env.applied(&plan_all(&env, &reg_new()));
            t1 = Some(t);
            vec![step(r"HKCU\Software\New\Prod", vec![dword("A", 7)])]
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
}

/// Apply, then revert the plan under test; the fault of `at` at its call if given.
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

/// The recovery: every transaction not closed is reverted, newest first, and must close; then
/// everything is as before.
fn recover(c: &Case) -> Vec<String> {
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
    let now = snap_all(env);
    if now != c.before {
        v.push(format!(
            "not identical after recovery: {:?}",
            c.before.diff(&now)
        ));
    }
    v
}

/// The J5 properties of what is on disk and in the hive after a power loss, before the
/// recovery; then the recovery.
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
                if !reverting {
                    let seen = env.verify(t);
                    if seen.iter().any(|(_, o)| *o != Observed::After) {
                        v.push(format!("Applied durable, change lost: {seen:?}"));
                    }
                }
            }
            Some(TxnState::Closed(Closing::Reverted | Closing::RolledBack)) => {
                let now = snap_all(env);
                if now != c.start {
                    v.push(format!(
                        "Closed durable, revert lost: {:?}",
                        c.start.diff(&now)
                    ));
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
        v.extend(recover(c));
    }
    v
}

/// R-T3, failures: `fail_at` every call (file system and registry) of an apply and of a
/// revert: refused, rolled back identical, or left open and identical after a later revert.
#[test]
fn r_t3_a_failure_at_any_call_rolls_back_or_leaves_it_for_revert() {
    let t = Instant::now();
    let mut runs = 0;
    let mut outcomes: BTreeMap<&str, usize> = BTreeMap::new();
    for k in KINDS {
        for at in points(k, Fault::Fail(SysErrorKind::Other)) {
            let Some(a) = at else { continue };
            let c = setup(k);
            let r = if a.revert {
                let t = c.env.applied(&c.h);
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
            let v = recover(&c);
            assert!(v.is_empty(), "{k:?} fail at {a:?}: {v:?}");
            runs += 1;
        }
    }
    eprintln!(
        "R-T3 fail_at: {runs} runs in {:.1} s: {outcomes:?}",
        t.elapsed().as_secs_f64()
    );
    for want in ["refused", "rolled back", "revert failed"] {
        assert!(outcomes.get(want).is_some_and(|n| *n > 0), "{outcomes:?}");
    }
}

/// R-T3, crashes: a crash after every call, a restart, the recovery: identical, never
/// `Damaged` or `Foreign`.
#[test]
fn r_t3_a_crash_after_any_call_recovers_to_the_state_before() {
    let t = Instant::now();
    let mut runs = 0;
    let mut reg_calls = BTreeSet::new();
    for k in KINDS {
        for at in points(k, Fault::CrashAfter) {
            let Some(a) = at else { continue };
            let c = setup(k);
            run(&c, at);
            assert!(c.env.sys.fake_fs().crashed(), "{k:?} {a:?}: no crash");
            c.env.sys.restart();
            if let Prim::Reg(r) = a.call {
                reg_calls.insert(format!("{r:?}"));
            }
            let v = recover(&c);
            assert!(v.is_empty(), "{k:?} crash after {a:?}: {v:?}");
            runs += 1;
        }
    }
    eprintln!(
        "R-T3 crash: {runs} crashes in {:.1} s; registry calls crashed after: {reg_calls:?}",
        t.elapsed().as_secs_f64()
    );
    for want in ["Create", "SetValue", "Delete", "DeleteValue", "Flush"] {
        assert!(reg_calls.contains(want), "{want}: {reg_calls:?}");
    }
}

/// A flush J6 switches off.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Site {
    Journal(FlushSite),
    Exec(Flush),
}

fn knobs(skip: Option<Site>) {
    journal_knob::skip(match skip {
        Some(Site::Journal(s)) => Some(s),
        _ => None,
    });
    exec_knob::skip(match skip {
        Some(Site::Exec(g)) => Some(g),
        _ => None,
    });
}

/// Size of a run of R-T4.
#[derive(Debug, Default)]
struct Size {
    runs: usize,
    max_c: usize,
    max_d: usize,
    max_h: usize,
}

/// R-T4 for `k`. With `want`, stops at the first violation containing it.
fn matrix(k: Kind, skip: Option<Site>, want: Option<&str>) -> (Vec<String>, Size) {
    knobs(skip);
    let pts = points(k, Fault::CrashAfter);
    let mut found = Vec::new();
    let mut size = Size::default();
    for at in pts {
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
            for (d, h) in (0..=pd).flat_map(|d| (0..=ph).map(move |h| (d, h))) {
                let c = setup(k);
                let got = run(&c, at);
                c.env.sys.power_loss(&BTreeMap::from([
                    (Domain::Volume('C'), cut_c),
                    (Domain::Volume('D'), d),
                    (Domain::Hive(Hive::CurrentUser), h),
                ]));
                size.runs += 1;
                knobs(None);
                let v = violations(&c, got);
                knobs(skip);
                for x in v {
                    let hit = want.is_some_and(|w| x.contains(w));
                    found.push(format!(
                        "{k:?} after {at:?}, cut C {cut_c} D {d} HKCU {h}: {x}"
                    ));
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

/// R-T4 for `k`: every point, every cut of `C:`, `D:` and `HKCU` (one test per kind, so they
/// run in parallel; review nit 7).
fn r_t4(k: Kind) {
    let t = Instant::now();
    let (found, size) = matrix(k, None, None);
    eprintln!("R-T4 {k:?}: {size:?} in {:.1} s", t.elapsed().as_secs_f64());
    assert!(
        found.is_empty(),
        "{k:?}: {} violations: {:#?}",
        found.len(),
        found
    );
    assert!(size.max_c >= 2 && size.max_h >= 1, "{k:?}: {size:?}");
    if k == Kind::Mixed {
        assert!(size.max_d >= 1, "{k:?}: {size:?}");
    }
}

#[test]
fn r_t4_reg_new_every_power_loss_cut_recovers() {
    r_t4(Kind::RegNew);
}

#[test]
fn r_t4_reg_replace_every_power_loss_cut_recovers() {
    r_t4(Kind::RegReplace);
}

#[test]
fn r_t4_mixed_every_power_loss_cut_recovers() {
    r_t4(Kind::Mixed);
}

#[test]
fn r_t4_stacked_every_power_loss_cut_recovers() {
    r_t4(Kind::Stacked);
}

/// J6 with 8 sites: without any one flush of the journal or of `exec` (game folders and
/// `HKCU`), a power loss breaks a property on `Mixed`.
#[test]
fn j6_every_flush_site_is_needed_with_registry_ops() {
    let want = [
        (
            Site::Journal(FlushSite::Intent),
            "not identical after recovery",
        ),
        (
            Site::Exec(Flush::GameBeforeApplied),
            "Applied durable, change lost",
        ),
        (
            Site::Exec(Flush::HiveBeforeApplied),
            "Applied durable, change lost",
        ),
        (Site::Journal(FlushSite::Applied), "Ok lost"),
        (
            Site::Journal(FlushSite::RevertIntent),
            "Applied durable, change lost",
        ),
        (
            Site::Exec(Flush::GameBeforeRevertDone),
            "Closed durable, revert lost",
        ),
        (
            Site::Exec(Flush::HiveBeforeRevertDone),
            "Closed durable, revert lost",
        ),
        (Site::Journal(FlushSite::Close), "Ok lost"),
    ];
    for (site, property) in want {
        let (found, _) = matrix(Kind::Mixed, Some(site), Some(property));
        let last = found.last().map_or("", String::as_str);
        assert!(
            last.contains(property),
            "without the flush at {site:?}: {found:?}"
        );
        eprintln!("J6 {site:?}: {last}");
    }
}
