//! LM-C (P3-3b, ADR 0020 amendment P3-3): the crash and power-loss matrices T3/T4 and the flush
//! controls J6 over launch profiles. A profile is a normal journaled file op on `profiles`
//! below Rerun's folder; the games are on `D:`, the profile, the journal and the plans on `C:`.
//! - LM-C1 (T3) a crash after every call of the apply and of the revert, for each [`Kind`]: the
//!   recovery (`revert` of every transaction not closed) closes it with the game folder, the
//!   profile and `HKCU\Software` identical to before, never `Damaged`, never `Foreign`.
//! - LM-C2 (T4) a power loss after every one of those calls at every pair of cuts of `C:` and
//!   `D:`; the J5 properties before the recovery, then the recovery as in LM-C1.
//! - LM-C3 (J6) the flush controls for the profile ops, see [`lm_c3_the_flushes_for_profile_ops`]
//!   for what they can and cannot show on the real layout.
//!
//! Kinds: `New` (a profile created), `Bare` (as `New`, `profiles` missing: the apply creates
//! the folder, no op of the plan, and the revert leaves it), `Replace` (a read-only, hidden
//! foreign profile replaced), `GameDirFile` (a created folder and file on `D:` and the profile
//! on `C:`), `GameReplace` (the T1 spec of the game folder: a replace over a read-only, hidden
//! file, nested folders, new files, and the profile). The helpers follow `crash_tests.rs`.

use std::collections::BTreeMap;
use std::path::Path;
use std::time::Instant;

use super::knob as exec_knob;
use super::profiles_tests::{PROFILES, lm, lm_sys, profile_abs, snap_all};
use super::tests::{Env, RH, X, exists_abs, sys_put, t1_spec};
use super::{Flush, Outcome};
use crate::journal::knob as journal_knob;
use crate::journal::{Closing, FlushSite, InstanceTag, Journal, Observed, TxnState, VerifyBackups};
use crate::plan::PlanHash;
use crate::prim::Step;
use crate::prim::tests::{app, entry, spec};
use crate::sys::fake::{Domain, Fault, Prim};
use crate::sys::snapshot::Snapshot;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    New,
    Bare,
    Replace,
    GameDirFile,
    GameReplace,
}

const KINDS: [Kind; 5] = [
    Kind::New,
    Kind::Bare,
    Kind::Replace,
    Kind::GameDirFile,
    Kind::GameReplace,
];

/// A fresh system with the plan of `k` stored, everything durable, and the state before.
fn setup(k: Kind) -> (Env, PlanHash, Snapshot) {
    let env = Env::new(lm_sys(k == Kind::Bare));
    if k == Kind::Replace {
        sys_put(&env.sys, &profile_abs(220), b"an orphaned profile");
        env.sys
            .fake_fs()
            .set_attrs(Path::new(&profile_abs(220)), RH)
            .unwrap();
    }
    let steps: Vec<Step> = match k {
        Kind::GameDirFile => vec![Step::FileInstall(spec(vec![entry(
            r"mods\x.dll",
            r"mods\x.dll",
            X,
        )]))],
        Kind::GameReplace => vec![Step::FileInstall(t1_spec())],
        _ => Vec::new(),
    };
    let h = lm(&env, 220, &steps, 8);
    // `journal\lock` in place, so every run's calls are the same.
    drop(
        Journal::new(&app(&env.sys), InstanceTag::fixed(9))
            .lock()
            .unwrap(),
    );
    env.sys.sync_all();
    let before = state(&env, k);
    (env, h, before)
}

/// The state the matrices compare: the game folders, `profiles` and `HKCU\Software`. For
/// `Bare` the folder `profiles` is Rerun's own state that stays (T2): it is present, empty, in
/// the snapshot of the state before and of the state after, so a missing one is not a
/// difference (nothing journaled it).
fn state(env: &Env, k: Kind) -> Snapshot {
    let missing = k == Kind::Bare && !exists_abs(&env.sys, PROFILES);
    if missing {
        env.sys.fake_fs().mkdir_all(Path::new(PROFILES)).unwrap();
    }
    let s = snap_all(env);
    if missing {
        env.sys.fake_fs().remove_abs(Path::new(PROFILES)).unwrap();
    }
    s
}

/// Where a run is interrupted: after call `nth` of `call` of the apply or of the revert.
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
    applied: bool,
    closed: bool,
}

/// Apply, then revert; the fault of `at` at its call if given.
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

/// Every interruption point: after each call of the apply and of the revert, and the end.
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
fn recover(env: &Env, k: Kind, before: &Snapshot) -> Vec<String> {
    let mut v = Vec::new();
    for (t, s) in env.states() {
        match s {
            Some(TxnState::Closed(_)) => {}
            Some(TxnState::Empty | TxnState::Open | TxnState::Applied) => match env.revert(&t) {
                Ok(r) if r.closed.is_some() => {}
                Ok(r) if r.ops.iter().any(|o| o.observed == Observed::Foreign) => {
                    v.push(format!("Foreign: {r:?}"));
                }
                other => {
                    let headless =
                        !exists_abs(&env.sys, &format!(r"{}\head.json", env.txn_dir(&t)));
                    if !(headless && s == Some(TxnState::Empty)) {
                        v.push(format!("recovery failed: {other:?}"));
                    }
                }
            },
            other => v.push(format!("damaged: {t} {other:?}")),
        }
    }
    let now = state(env, k);
    if now != *before {
        v.push(format!(
            "not identical after recovery: {:?}",
            before.diff(&now)
        ));
    }
    v
}

#[test]
fn lm_c1_a_crash_after_any_call_recovers_to_the_state_before() {
    let mut runs = 0;
    for k in KINDS {
        for at in points(k) {
            let Some(a) = at else { continue };
            let (env, h, before) = setup(k);
            run(&env, &h, at);
            assert!(env.sys.fake_fs().crashed(), "{k:?} {a:?}: no crash");
            env.sys.fake_fs().restart();
            let v = recover(&env, k, &before);
            assert!(v.is_empty(), "{k:?} crash after {a:?}: {v:?}");
            runs += 1;
        }
    }
    eprintln!("LM-C1 crash: {runs} crashes");
}

/// The J5 properties of what is on disk after a power loss, before the recovery, then the
/// recovery.
fn violations(env: &Env, k: Kind, before: &Snapshot, got: Got) -> Vec<String> {
    let mut v = Vec::new();
    let states = env.states();
    for (t, s) in &states {
        match s {
            Some(TxnState::Damaged(_)) | None => v.push(format!("damaged: {t} {s:?}")),
            Some(TxnState::Applied) => {
                let a = app(&env.sys);
                let j = Journal::new(&a, InstanceTag::fixed(5));
                let reverting = j.load(t, VerifyBackups::Length).map_or(true, |view| {
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
                let now = state(env, k);
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
    let first = states.first().and_then(|(_, s)| s.clone());
    if got.applied
        && !matches!(
            first,
            Some(TxnState::Applied | TxnState::Closed(Closing::Reverted))
        )
    {
        v.push(format!("Ok lost: apply returned Applied, now {first:?}"));
    }
    if got.closed && !matches!(first, Some(TxnState::Closed(_))) {
        v.push(format!("Ok lost: revert returned Closed, now {first:?}"));
    }
    if v.is_empty() {
        v.extend(recover(env, k, before));
    }
    v
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

/// Size of a T4 run.
#[derive(Debug, Default)]
struct Size {
    runs: usize,
    max_c: usize,
    max_d: usize,
}

/// T4 for `k`: every point, every pair of cuts. With `want`, stops at the first violation
/// containing it.
fn matrix(k: Kind, skip: Option<Site>, want: Option<&str>) -> (Vec<String>, Size) {
    knobs(skip);
    let mut found = Vec::new();
    let mut size = Size::default();
    for at in points(k) {
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
                let v = violations(&env, k, &before, got);
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
fn lm_c2_every_power_loss_cut_recovers_to_the_state_before() {
    for k in KINDS {
        let t = Instant::now();
        let (found, size) = matrix(k, None, None);
        eprintln!(
            "LM-C2 T4 {k:?}: {size:?} in {:.1} s",
            t.elapsed().as_secs_f64()
        );
        assert!(
            found.is_empty(),
            "{k:?}: {} violations: {:#?}",
            found.len(),
            found
        );
        assert!(size.max_c >= 2, "{k:?}: {size:?}");
        if matches!(k, Kind::GameDirFile | Kind::GameReplace) {
            assert!(size.max_d >= 1, "{k:?}: the game volume never pending");
        }
    }
}

/// The first violation containing `property` of `k` without the flush `site`, if any.
fn without(k: Kind, site: Site, property: &str) -> Option<String> {
    let (found, _) = matrix(k, Some(site), Some(property));
    found.into_iter().find(|f| f.contains(property))
}

/// LM-C3 (J6): the flush controls for profile ops, and what they show.
///
/// On the real layout `profiles` and the journal are on the same volume (`C:`, below
/// `<LocalAppData>\Rerun`), and a volume has one ordered log. So for a profile alone only the
/// flushes that make a result durable before it is reported bite (`Applied`, `Close`: "Ok
/// lost"); the order of intent and change, and the flush of the `profiles` folder itself
/// (`GameBeforeApplied`, `GameBeforeRevertDone`), cannot be told apart from a later flush of the
/// same log. That is expected and asserted here, not a gap: `exec` still flushes the profiles
/// root like any root (one flush path), and the other flushes are needed as soon as a second
/// volume is involved: with a game folder on `D:` (`GameDirFile`) every control fails.
///
/// A variant with `profiles` on its own fake volume cannot be built (nit N7): the root's path
/// is pinned to `<AppDir>\profiles` (a moved folder is refused, A1), a mounted volume shares its
/// drive's log in the fake, and the journal is below the same `AppDir`. Such a variant would
/// only show that the code stays generic, not that the real layout needs the flush.
#[test]
fn lm_c3_the_flushes_for_profile_ops() {
    let want = [
        (
            Site::Journal(FlushSite::Intent),
            "not identical after recovery",
        ),
        (Site::Journal(FlushSite::Applied), "Ok lost"),
        (
            Site::Journal(FlushSite::RevertIntent),
            "Applied durable, change lost",
        ),
        (Site::Journal(FlushSite::Close), "Ok lost"),
        (
            Site::Game(Flush::GameBeforeApplied),
            "Applied durable, change lost",
        ),
        (
            Site::Game(Flush::GameBeforeRevertDone),
            "Closed durable, revert lost",
        ),
    ];
    // With a second volume every flush is needed (and bites with the property of J6).
    for k in [Kind::GameDirFile, Kind::GameReplace] {
        for (site, property) in want {
            let hit = without(k, site, property);
            assert!(hit.is_some(), "{k:?} without {site:?}: no {property}");
            eprintln!("LM-C3 J6 {k:?} {site:?}: {}", hit.unwrap());
        }
    }
    // A profile alone, on the journal's volume: the flushes of the results bite ...
    for k in [Kind::New, Kind::Bare, Kind::Replace] {
        for site in [
            Site::Journal(FlushSite::Applied),
            Site::Journal(FlushSite::Close),
        ] {
            let hit = without(k, site, "Ok lost");
            assert!(hit.is_some(), "{k:?} without {site:?}: no Ok lost");
        }
        // ... the others are covered by the one ordered log of `C:` (N7).
        for (site, _) in want {
            if matches!(site, Site::Journal(FlushSite::Applied | FlushSite::Close)) {
                continue;
            }
            let (found, _) = matrix(k, Some(site), None);
            assert!(
                found.is_empty(),
                "{k:?} without {site:?}: the journal's volume covers the profile: {found:?}"
            );
        }
    }
}
