//! `exec` with `IniValue` under failures, crashes and power losses (P2-12, C5): R-I4 a failure
//! and a crash after every call of an apply and of a revert; R-I5 a power loss after every call
//! at every cut of `C:` (journal, packages) times every cut of `D:` (the game folder).
//!
//! Kinds: `IniEdit` (an existing key, a new key, a new section; the revert restores the backup),
//! `IniDrift` (as `IniEdit`, and between the apply and the revert the game rewrites the file,
//! `Volume=5` to `Volume=9`: the revert under test is the semantic rewrite with `from`/`to`),
//! `IniStacked` (T1 sets `Width` durably, T2 sets the same key again, the game rewrites the file
//! after T2; the cut is in T2; the recovery reverts T2, then T1, both semantically). Properties
//! as in R-T4: a durable `Applied` has every change (verify all `After`, before the drift); a
//! durable `Closed` has the state its revert leaves; an `Ok` survives; after the recovery
//! (newest transaction first) the expected end, never `Damaged`, never `Foreign`.
//!
//! M1 (senior-dev): after every cut of the **apply** of `IniEdit` the game runs before the
//! recovery: it rewrites the file it finds (`Volume=9`) or makes a new one if there is none.
//! The recovery then either closes with exactly the rewritten old file, or leaves the op
//! `Foreign` with the user's old file kept in the named `.old` (S6); never is the old file lost.
//!
//! Size: measured 2026-11-07 (see `docs/09-testing.md`).

use std::collections::BTreeMap;
use std::time::Instant;

use super::Outcome;
use super::ini_tests::{APPLIED, ini_env, ini_now, put_ini};
use super::reg_tests::{Reset, plan_all};
use super::tests::{Env, try_read_abs};
use super::{Detail, Flush, knob as exec_knob};
use crate::journal::{Closing, Observed, TxnId, TxnState};
use crate::plan::PlanHash;
use crate::prim::ini_tests::{INI, INI_TEXT, ini_step, three};
use crate::prim::tests::app;
use crate::sys::SysErrorKind;
use crate::sys::fake::{Domain, Fault, Prim};
use crate::sys::snapshot::Snapshot;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[expect(
    clippy::enum_variant_names,
    reason = "the kind names of the plan and docs/09"
)]
enum Kind {
    IniEdit,
    IniDrift,
    IniStacked,
}

const KINDS: [Kind; 3] = [Kind::IniEdit, Kind::IniDrift, Kind::IniStacked];

/// What the game writes over a file (`IniDrift`, `IniStacked`, the M1 fixture).
fn drifted(b: &[u8]) -> Vec<u8> {
    String::from_utf8_lossy(b)
        .replace("Volume=5", "Volume=9")
        .into_bytes()
}

/// A file the game makes when it finds none of its own.
const GAME_NEW: &[u8] = b"[Display]\r\nWidth=640\r\n";

/// One system of a kind, everything durable.
struct Case {
    env: Env,
    kind: Kind,
    /// The plan under test.
    h: PlanHash,
    /// The state before every transaction.
    before: Snapshot,
    /// The state before the transaction under test (a durable `Closed` of it, before a drift).
    start: Snapshot,
    /// The INI file at `start`.
    start_ini: Vec<u8>,
    /// The transaction applied durably before (`IniStacked`).
    t1: Option<TxnId>,
}

fn setup(k: Kind) -> Case {
    let env = ini_env(INI_TEXT);
    let before = env.snap();
    let mut t1 = None;
    let steps: Vec<_> = match k {
        Kind::IniEdit | Kind::IniDrift => vec![three()],
        Kind::IniStacked => {
            let t = env.applied(&plan_all(
                &env,
                &[ini_step(INI, &[("Display", "Width", "1920")])],
            ));
            t1 = Some(t);
            vec![ini_step(INI, &[("Display", "Width", "2560")])]
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
    let start = env.snap();
    let start_ini = ini_now(&env).unwrap();
    Case {
        env,
        kind: k,
        h,
        before,
        start,
        start_ini,
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
    /// The game rewrote the file after the apply.
    drifted: bool,
}

/// The game rewrites the file (`IniDrift`, `IniStacked`); fixture writes are durable.
fn drift(env: &Env) {
    let now = ini_now(env).unwrap();
    put_ini(env, &drifted(&now));
}

fn drifts(k: Kind) -> bool {
    matches!(k, Kind::IniDrift | Kind::IniStacked)
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
    if drifts(c.kind) {
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
    if drifts(k) {
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

/// The state is `want` with the INI file `want_ini` (after the drift: exactly the drift of it,
/// checked, then put back so the snapshots compare).
fn settled(
    c: &Case,
    drifted_now: bool,
    want: &Snapshot,
    want_ini: &[u8],
    what: &str,
) -> Option<String> {
    let env = &c.env;
    if drifted_now {
        let v = ini_now(env);
        if v.as_deref() != Some(&drifted(want_ini)[..]) {
            return Some(format!(
                "{what}: after the drift the file is {:?}",
                v.map(|b| String::from_utf8_lossy(&b).into_owned())
            ));
        }
        put_ini(env, want_ini);
    }
    let now = env.snap();
    (now != *want).then(|| format!("{what}: {:?}", want.diff(&now)))
}

/// The recovery: every transaction not closed is reverted, newest first, and must close; then
/// everything is as expected.
fn recover(c: &Case, drifted_now: bool) -> Vec<String> {
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
            drifted_now,
            &c.before,
            INI_TEXT,
            "not as expected after recovery",
        ));
    }
    v
}

/// The properties after a power loss, before the recovery; then the recovery.
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
                if !reverting && !got.drifted {
                    let seen = env.verify(t);
                    if seen.iter().any(|(_, o)| *o != Observed::After) {
                        v.push(format!("Applied durable, change lost: {seen:?}"));
                    }
                }
            }
            Some(TxnState::Closed(Closing::Reverted | Closing::RolledBack)) => {
                let drifted_now =
                    got.drifted && matches!(s, Some(TxnState::Closed(Closing::Reverted)));
                if let Some(x) = settled(
                    c,
                    drifted_now,
                    &c.start,
                    &c.start_ini,
                    "Closed durable, revert lost",
                ) {
                    v.push(x);
                }
                if drifted_now {
                    // `settled` put the undrifted file back; the recovery checks from there.
                    if v.is_empty() {
                        v.extend(recover(c, false));
                    }
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

/// R-I4, failures: `fail_at` every call of an apply and of a revert (in `IniDrift` and
/// `IniStacked` the semantic one): refused, rolled back identical, or left open and as
/// expected after a later revert.
#[test]
fn r_i4_a_failure_at_any_call_rolls_back_or_leaves_it_for_revert() {
    let t = Instant::now();
    let mut runs = 0;
    let mut outcomes: BTreeMap<&str, usize> = BTreeMap::new();
    for k in KINDS {
        for at in points(k, Fault::Fail(SysErrorKind::Other)) {
            let Some(a) = at else { continue };
            let c = setup(k);
            let mut drifted_now = false;
            let r = if a.revert {
                let t = c.env.applied(&c.h);
                if drifts(k) {
                    drift(&c.env);
                    drifted_now = true;
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
            let v = recover(&c, drifted_now);
            assert!(v.is_empty(), "{k:?} fail at {a:?}: {v:?}");
            runs += 1;
        }
    }
    eprintln!(
        "R-I4 fail_at: {runs} runs in {:.1} s: {outcomes:?}",
        t.elapsed().as_secs_f64()
    );
    for want in ["refused", "rolled back", "revert failed"] {
        assert!(outcomes.get(want).is_some_and(|n| *n > 0), "{outcomes:?}");
    }
}

/// R-I4, crashes: a crash after every call, a restart, the recovery: as expected, never
/// `Damaged` or `Foreign`. The rewrite and the restore each go through the phases A to D of
/// their replace sequence (crashes after `CreateTmp`, the renames and the delete among them).
fn i4_check(kinds: &[Kind]) -> Vec<String> {
    let mut f = Vec::new();
    for &k in kinds {
        for at in points(k, Fault::CrashAfter) {
            let Some(a) = at else { continue };
            let c = setup(k);
            let got = run(&c, at);
            if !c.env.sys.fake_fs().crashed() {
                f.push(format!("{k:?} {a:?}: no crash"));
                continue;
            }
            c.env.sys.restart();
            for x in recover(&c, got.drifted) {
                f.push(format!("{k:?} crash after {a:?}: {x}"));
            }
        }
    }
    f
}

#[test]
fn r_i4_a_crash_after_any_call_recovers() {
    let t = Instant::now();
    let f = i4_check(&KINDS);
    eprintln!("R-I4 crash: {:.1} s", t.elapsed().as_secs_f64());
    assert!(f.is_empty(), "{f:#?}");
}

/// K-I1: a rewrite recorded without `from`/`to` (the sequence then reads as a restore, new to
/// old) fails R-I4 on the drift: a crash inside the rewrite's replace sequence recovers to
/// `Foreign` or a lost file.
#[test]
fn k_i1_a_rewrite_without_from_and_to_breaks_ri4() {
    let _r = Reset(|| super::ini::knob::unrecorded(false));
    super::ini::knob::unrecorded(true);
    let f = i4_check(&[Kind::IniDrift]);
    assert!(
        f.iter()
            .any(|x| x.contains("Foreign") || x.contains("after the drift the file is None")),
        "{f:#?}"
    );
}

/// Size of a run of R-I5.
#[derive(Debug, Default)]
struct Size {
    runs: usize,
    max_c: usize,
    max_d: usize,
}

/// R-I5 for `k` (with the flush `skip` of `exec` switched off for the runs): every point, every
/// cut of `C:` and `D:`.
fn matrix(k: Kind, skip: Option<Flush>) -> (Vec<String>, Size) {
    let mut found = Vec::new();
    let mut size = Size::default();
    for at in points(k, Fault::CrashAfter) {
        let (pc, pd) = {
            let c = setup(k);
            run(&c, at);
            let s = &c.env.sys;
            (
                s.pending(Domain::Volume('C')),
                s.pending(Domain::Volume('D')),
            )
        };
        size.max_c = size.max_c.max(pc);
        size.max_d = size.max_d.max(pd);
        for cut_c in 0..=pc {
            for cut_d in 0..=pd {
                let c = setup(k);
                exec_knob::skip(skip);
                let got = run(&c, at);
                exec_knob::skip(None);
                c.env.sys.power_loss(&BTreeMap::from([
                    (Domain::Volume('C'), cut_c),
                    (Domain::Volume('D'), cut_d),
                ]));
                size.runs += 1;
                for x in violations(&c, got) {
                    found.push(format!("{k:?} after {at:?}, cut C {cut_c} D {cut_d}: {x}"));
                }
            }
        }
    }
    (found, size)
}

fn r_i5(k: Kind) {
    let t = Instant::now();
    let (found, size) = matrix(k, None);
    eprintln!("R-I5 {k:?}: {size:?} in {:.1} s", t.elapsed().as_secs_f64());
    assert!(
        found.is_empty(),
        "{k:?}: {} violations: {:#?}",
        found.len(),
        found
    );
    assert!(size.max_c >= 2 && size.max_d >= 2, "{k:?}: {size:?}");
}

#[test]
fn r_i5_ini_edit_every_power_loss_cut_recovers() {
    r_i5(Kind::IniEdit);
}

#[test]
fn r_i5_ini_drift_every_power_loss_cut_recovers() {
    r_i5(Kind::IniDrift);
}

#[test]
fn r_i5_ini_stacked_every_power_loss_cut_recovers() {
    r_i5(Kind::IniStacked);
}

/// J6 bites on the rewrite (no new flush site): without the game folder's flush before
/// `RevertDone`, a power loss keeps `Closed` and loses the rewrite.
#[test]
fn j6_the_game_flush_before_revert_done_covers_the_rewrite() {
    let (found, _) = matrix(Kind::IniDrift, Some(Flush::GameBeforeRevertDone));
    assert!(
        found
            .iter()
            .any(|x| x.contains("Closed durable, revert lost: after the drift")),
        "{found:#?}"
    );
}

/// The M1 matrix as a check: every cut of the apply of `IniEdit`, then the game runs (it
/// rewrites the file it finds or makes a new one), then the recovery (module docs).
fn m1_check() -> Vec<String> {
    let mut f = Vec::new();
    let k = Kind::IniEdit;
    for at in points(k, Fault::CrashAfter) {
        let Some(a) = at else { continue };
        if a.revert {
            continue;
        }
        let (pc, pd) = {
            let c = setup(k);
            run(&c, at);
            let s = &c.env.sys;
            (
                s.pending(Domain::Volume('C')),
                s.pending(Domain::Volume('D')),
            )
        };
        for cut_c in 0..=pc {
            for cut_d in 0..=pd {
                let c = setup(k);
                run(&c, at);
                c.env.sys.power_loss(&BTreeMap::from([
                    (Domain::Volume('C'), cut_c),
                    (Domain::Volume('D'), cut_d),
                ]));
                let env = &c.env;
                match ini_now(env) {
                    Some(b) => put_ini(env, &drifted(&b)),
                    None => put_ini(env, GAME_NEW),
                }
                let what = format!("M1 after {a:?}, cut C {cut_c} D {cut_d}");
                let mut states = env.states();
                states.reverse();
                for (t, s) in states {
                    if !matches!(
                        s,
                        Some(TxnState::Empty | TxnState::Open | TxnState::Applied)
                    ) {
                        if !matches!(s, Some(TxnState::Closed(_))) {
                            f.push(format!("{what}: damaged {s:?}"));
                        }
                        continue;
                    }
                    match env.revert(&t) {
                        Ok(r) if r.closed.is_some() => {
                            let want = drifted(INI_TEXT);
                            if ini_now(env).as_deref() != Some(&want[..]) {
                                f.push(format!(
                                    "{what}: closed with {:?}: the old file lost",
                                    ini_now(env).map(|b| String::from_utf8_lossy(&b).into_owned())
                                ));
                            }
                        }
                        Ok(r) => {
                            let kept = r.ops.iter().any(|o| {
                                o.observed == Observed::Foreign
                                    && matches!(&o.detail, Some(Detail::Ini { before_step: Some(super::BeforeStep { step: super::RerunStep::Apply, file: p }), .. })
                                        if try_read_abs(&env.sys, &super::tests::game(&format!(r"cfg\{p}")))
                                            .as_deref() == Some(INI_TEXT))
                            });
                            if !kept {
                                f.push(format!("{what}: open without the old file named: {r:?}"));
                            }
                        }
                        Err(e) => {
                            let headless = !super::tests::exists_abs(
                                &env.sys,
                                &format!(r"{}\head.json", env.txn_dir(&t)),
                            );
                            if !(headless && s == Some(TxnState::Empty)) {
                                f.push(format!("{what}: recovery failed: {e}"));
                            }
                        }
                    }
                }
            }
        }
    }
    f
}

#[test]
fn r_i5_m1_the_game_runs_after_a_cut_of_the_apply() {
    let t = Instant::now();
    let f = m1_check();
    eprintln!("R-I5 M1: {:.1} s", t.elapsed().as_secs_f64());
    assert!(f.is_empty(), "{f:#?}");
}

/// K-I5 against the matrix: the leftover `X.old` deleted without M1's conditions loses the
/// user's old file after a cut in phase B or C of the apply.
#[test]
fn k_i5_a_loose_m1_breaks_the_m1_matrix() {
    let _r = Reset(|| super::ini::knob::loose_m1(false));
    super::ini::knob::loose_m1(true);
    let f = m1_check();
    assert!(f.iter().any(|x| x.contains("the old file lost")), "{f:#?}");
}

/// The applied content of `IniEdit` (a constant of the tests, checked here once).
#[test]
fn the_applied_fixture_is_the_edit() {
    let c = setup(Kind::IniEdit);
    let t = c.env.applied(&c.h);
    assert_eq!(ini_now(&c.env).unwrap(), APPLIED.as_bytes());
    assert_eq!(c.env.revert(&t).unwrap().closed, Some(Closing::Reverted));
}
