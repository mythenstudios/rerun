//! The history's cap and "clear history" against the fake (P5-6d-1b; plan P5-6d §8):
//! - HP1 the preview of "clear history" lists what goes and what stays with its reason (open,
//!   forgotten, a hand-over), empty ones go;
//! - HP2 the cap keeps exactly the newest 100 entries "undone" or "rolled back", a held one
//!   counts and is skipped, at most 5 go per run (oldest first), open and forgotten ones are
//!   never touched, empty ones go;
//! - HP3 `clear` is exact: an entry no longer removable after the preview, or another head, is
//!   `Changed` with nothing written; one removed meanwhile counts as done;
//! - HP5 a failure of the cap (an error while deleting, the lock held) never fails the apply;
//! - HP6 launch results go only with the bytes the preview read; a start written since, a
//!   result whose Steam option is still set, an unreadable one, the shim's temp files and other
//!   names stay.

use std::path::Path;

use rerun_proto::launch::{Check, LaunchResult, Outcome as Started, SkipReason, Start, encode};

use super::{HISTORY_KEEP, ResultKeep, TIDY_PER_RUN, Tidied, TidyNote, clear, clear_preview, tidy};
use crate::exec::tests::{Env, base, finish, snap_app, t1_spec};
use crate::exec::{Keep, Outcome, TxnLine};
use crate::flow::{ActError, Env as FlowEnv, Guarded, guard};
use crate::journal::{Closing, InstanceTag, Journal, JournalLock, Observed, TxnId, TxnState};
use crate::plan::profile_id;
use crate::prim::tests::{INSTALL, app};
use crate::sys::SysErrorKind;
use crate::sys::fake::{FakeHttp, FakeSystem, Prim};

const RERUN: &str = r"C:\Users\Player\AppData\Local\Rerun";
const HEAD: &[u8] = br#"{"history":1}"#;

fn with_guard<R>(sys: &FakeSystem, f: impl FnOnce(Guarded<'_>) -> R) -> R {
    let http = FakeHttp::default();
    let ok = Ok(std::path::PathBuf::from(INSTALL));
    let g = guard(FlowEnv {
        sys,
        http: &http,
        install: &ok,
    })
    .unwrap_or_else(|e| panic!("{e:?}"));
    f(g)
}

/// `f` under the journal lock of a fresh run (the journal written directly: fast fixtures).
fn journal<R>(sys: &FakeSystem, f: impl FnOnce(&JournalLock<'_>) -> R) -> R {
    let a = app(sys);
    let j = Journal::new(&a, InstanceTag::new());
    let lock = j.lock().unwrap();
    f(&lock)
}

/// A transaction of one op, closed `how`; a `Reverted` one with `kept` keeps its op's object
/// (`Observed::Kept`).
fn settled(l: &JournalLock<'_>, how: Closing, kept: bool) -> TxnId {
    let mut w = l.begin(HEAD).unwrap();
    let id = *w.id();
    w.intent(0, None, None).unwrap();
    w.done(0, Some(1), false).unwrap();
    let observed = if kept {
        Observed::Kept
    } else {
        Observed::After
    };
    match how {
        Closing::RolledBack => {
            w.revert_intent(0, None, None).unwrap();
            w.revert_done(0, observed, &[]).unwrap();
            w.close(Closing::RolledBack).unwrap();
        }
        Closing::Reverted => {
            w.applied(1).unwrap();
            drop(w);
            let mut w = l.resume(&id).unwrap();
            w.revert_intent(0, None, None).unwrap();
            w.revert_done(0, observed, &[]).unwrap();
            w.close(Closing::Reverted).unwrap();
        }
        Closing::Forgotten => {
            w.applied(1).unwrap();
            w.close(Closing::Forgotten).unwrap();
        }
    }
    id
}

/// An applied transaction (open).
fn applied(l: &JournalLock<'_>) -> TxnId {
    let mut w = l.begin(HEAD).unwrap();
    w.intent(0, None, None).unwrap();
    w.done(0, Some(1), false).unwrap();
    w.applied(1).unwrap();
    *w.id()
}

/// An empty transaction (a crash right after `begin`).
fn empty(l: &JournalLock<'_>) -> TxnId {
    *l.begin(HEAD).unwrap().id()
}

fn states(sys: &FakeSystem) -> Vec<(TxnId, Option<TxnState>)> {
    let a = app(sys);
    Journal::new(&a, InstanceTag::new())
        .list()
        .unwrap()
        .txns
        .into_iter()
        .map(|t| (t.id, t.view.ok().map(|v| v.state)))
        .collect()
}

fn ids(sys: &FakeSystem) -> Vec<TxnId> {
    states(sys).into_iter().map(|(t, _)| t).collect()
}

fn undone_count(sys: &FakeSystem) -> usize {
    states(sys)
        .iter()
        .filter(|(_, s)| {
            matches!(
                s,
                Some(TxnState::Closed(Closing::Reverted | Closing::RolledBack))
            )
        })
        .count()
}

fn tidied(sys: &FakeSystem) -> Tidied {
    with_guard(sys, |g| tidy(&g)).unwrap_or_else(|e| panic!("{e:?}"))
}

#[test]
fn hp1_the_preview_lists_what_goes_and_what_stays_with_its_reason() {
    let sys = finish(base());
    let (creator, gone_ok, rolled, open, forgotten, e) = journal(&sys, |l| {
        let creator = settled(l, Closing::Reverted, true);
        let gone_ok = settled(l, Closing::Reverted, false);
        let rolled = settled(l, Closing::RolledBack, false);
        let open = applied(l);
        let forgotten = settled(l, Closing::Forgotten, false);
        let e = empty(l);
        (creator, gone_ok, rolled, open, forgotten, e)
    });
    let (p, shown) = with_guard(&sys, |g| clear_preview(&g)).unwrap();
    let remove: Vec<TxnId> = p.remove.iter().map(|i| i.txn).collect();
    assert_eq!(remove, [gone_ok, rolled, e]);
    assert_eq!(p.remove[2].line, TxnLine::Empty);
    assert_eq!(p.remove[0].line, TxnLine::Closed(Closing::Reverted));
    let stays: Vec<(TxnId, Keep)> = p.stays.iter().map(|(i, k)| (i.txn, *k)).collect();
    assert_eq!(
        stays,
        [
            (creator, Keep::HandedOver),
            (open, Keep::NotSettled),
            (forgotten, Keep::Forgotten)
        ]
    );
    assert!(!shown.is_empty());
    assert!(p.results.is_empty() && p.results_stay.is_empty());
    // Clear removes exactly that; the rest stays.
    let r = with_guard(&sys, |g| clear(&g, shown)).unwrap();
    assert_eq!(r.removed, [gone_ok, rolled, e]);
    assert_eq!(ids(&sys), [creator, open, forgotten]);
}

#[test]
fn hp2_the_cap_keeps_the_newest_hundred_and_removes_at_most_five_per_run() {
    let sys = finish(base());
    let extra = 5;
    let (held, open, forgotten, e) = journal(&sys, |l| {
        // The oldest: an empty one, a forgotten one, and a creator that handed something over.
        let e = empty(l);
        let forgotten = settled(l, Closing::Forgotten, false);
        let held = settled(l, Closing::Reverted, true);
        for i in 0..(HISTORY_KEEP + extra - 1) {
            let how = if i % 3 == 0 {
                Closing::RolledBack
            } else {
                Closing::Reverted
            };
            settled(l, how, false);
        }
        // Newer than the creator, not settled: it may rely on what was kept.
        let open = applied(l);
        (held, open, forgotten, e)
    });
    assert_eq!(undone_count(&sys), HISTORY_KEEP + extra, "precondition");
    // Run 1: the empty one and the four oldest removable undone ones (5 at most); the empty
    // one is not counted (review S2: the history never shows it).
    assert_eq!(tidied(&sys).removed, TIDY_PER_RUN - 1);
    let left = ids(&sys);
    assert!(!left.contains(&e));
    assert!(left.contains(&held) && left.contains(&open) && left.contains(&forgotten));
    assert_eq!(
        undone_count(&sys),
        HISTORY_KEEP + 1,
        "the held one stays and counts"
    );
    // Run 2: nothing removable is left beyond the cap.
    assert_eq!(tidied(&sys).removed, 0);
    assert_eq!(undone_count(&sys), HISTORY_KEEP + 1);
    // Once its heir is settled, the held one goes on the next run.
    journal(&sys, |l| {
        let mut w = l.resume(&open).unwrap();
        w.revert_intent(0, None, None).unwrap();
        w.revert_done(0, Observed::After, &[]).unwrap();
        w.close(Closing::Reverted).unwrap();
    });
    assert_eq!(
        tidied(&sys).removed,
        2,
        "the held one and the one the heir pushed out"
    );
    assert_eq!(undone_count(&sys), HISTORY_KEEP);
    assert!(
        ids(&sys).contains(&forgotten),
        "forgotten ones are never removed"
    );
}

#[test]
fn hp2_more_than_five_go_over_several_runs_oldest_first() {
    let sys = finish(base());
    let all = journal(&sys, |l| {
        (0..HISTORY_KEEP + 12)
            .map(|_| settled(l, Closing::Reverted, false))
            .collect::<Vec<_>>()
    });
    assert_eq!(tidied(&sys).removed, 5);
    assert_eq!(ids(&sys).first(), Some(&all[5]), "the oldest went first");
    assert_eq!(tidied(&sys).removed, 5);
    assert_eq!(tidied(&sys).removed, 2);
    assert_eq!(tidied(&sys).removed, 0);
    assert_eq!(ids(&sys), all[12..]);
}

#[test]
fn hp3_clear_is_exact() {
    let env = Env::new(finish(base()));
    let (a, b) = journal(&env.sys, |l| {
        (
            settled(l, Closing::Reverted, true),
            settled(l, Closing::Reverted, false),
        )
    });
    let (p, shown) = with_guard(&env.sys, |g| clear_preview(&g)).unwrap();
    assert_eq!(
        p.remove.iter().map(|i| i.txn).collect::<Vec<_>>(),
        [a, b],
        "precondition: both removable"
    );
    // Between the preview and the click: an apply makes `a`'s hand-over count again.
    let t = env.applied(&env.plan(&t1_spec()));
    let before = snap_app(&env.sys);
    let r = with_guard(&env.sys, |g| clear(&g, shown));
    assert!(matches!(r, Err(ActError::Changed)), "{r:?}");
    let after = snap_app(&env.sys);
    assert!(before == after, "{:#?}", before.diff(&after));
    // Shown again, `a` stays; `b` removed meanwhile counts as done.
    let (p, shown) = with_guard(&env.sys, |g| clear_preview(&g)).unwrap();
    assert!(
        p.stays
            .iter()
            .any(|(i, k)| i.txn == a && *k == Keep::HandedOver)
    );
    with_guard(&env.sys, |g| {
        let (_, again) = clear_preview(&g).unwrap();
        clear(&g, again).unwrap();
    });
    let r = with_guard(&env.sys, |g| clear(&g, shown)).unwrap();
    assert_eq!((r.removed.len(), r.gone.as_slice()), (0, &[b][..]));
    assert!(ids(&env.sys).contains(&t));
}

#[test]
fn hp5_a_failing_cap_never_fails_the_apply() {
    // Something to remove: an empty transaction.
    let run = |arm: &dyn Fn(&crate::sys::fake::FakeFs)| {
        let env = Env::new(finish(base()));
        let e = journal(&env.sys, empty);
        let fx = env.sys.fake_fs();
        let r = with_guard(&env.sys, |mut g| {
            let (p, _) = super::super::plan_steps(&g, &steps()).unwrap();
            let p = super::super::shown(p);
            super::super::store(&mut g, &p).unwrap();
            fx.clear_faults();
            arm(fx);
            super::super::apply(&g, p)
        });
        let a = r.unwrap_or_else(|e| panic!("the apply fails: {e}"));
        assert!(matches!(a.outcome, Outcome::Applied(_)));
        // Still there: listed, or hidden by its tombstone with its folder in place.
        let there = crate::exec::tests::exists_abs(&env.sys, &env.txn_dir(&e));
        (a.tidied, there, fx.fault_fired())
    };
    // Control: the cap removes the empty one, silently (not counted, review S2).
    let (t, still, _) = run(&|_| {});
    assert_eq!(t.unwrap().removed, 0);
    assert!(!still);
    // An error while deleting: the apply stays a success, the note says why.
    let (t, still, fired) = run(&|fx| fx.fail_at(Prim::OpenFileDelete, 1, SysErrorKind::Other));
    assert!(fired, "precondition: the fault was met");
    assert!(matches!(t, Err(TidyNote::Exec(_))), "{t:?}");
    assert!(still);
    // The lock held by another Rerun when the cap runs: silently nothing.
    let (t, still, fired) = run(&|fx| fx.fail_at(Prim::OpenLock, 2, SysErrorKind::Busy));
    assert!(fired, "precondition: the fault was met");
    assert_eq!(t.unwrap(), Tidied::default());
    assert!(still);
}

fn steps() -> crate::prim::StepFile {
    use crate::path::RootPath;
    use crate::prim::tests::{GAME, rel};
    use crate::prim::{GameRef, STEP_FILE_FORMAT, Step, StepFile};
    StepFile {
        format: STEP_FILE_FORMAT,
        game: GameRef::Folder(RootPath::new(GAME).unwrap()),
        main_exe: rel("game.exe"),
        user_data: None,
        steps: vec![Step::FileInstall(t1_spec())],
    }
}

fn result_at(n: u32) -> String {
    format!(r"{RERUN}\launch\{}.result", profile_id(n))
}

fn started(n: u32, outcome: Started, at: u64) -> Vec<u8> {
    encode(&LaunchResult {
        profile: profile_id(n),
        unix_s: at,
        outcome,
        method: None,
        run: false,
        steam_start: None,
    })
    .unwrap()
}

fn ran() -> Started {
    Started::Applied {
        cpu: None,
        priority: None,
        check: Check::Ok,
    }
}

#[test]
fn hp6_launch_results_go_only_with_the_bytes_the_preview_read() {
    let sys = finish(base());
    let fx = sys.fake_fs();
    let put = |p: &str, b: &[u8]| fx.put_file(Path::new(p), b).unwrap();
    put(&result_at(1), &started(1, ran(), 1_000));
    put(&result_at(2), &started(2, ran(), 1_000));
    let missing = Started::Skipped {
        reason: SkipReason::ProfileMissing,
        start: Start::Created,
        ended: None,
        priority_restore: None,
    };
    put(&result_at(3), &started(3, missing, 1_000));
    put(&result_at(4), b"not a result");
    let temp = format!(r"{RERUN}\launch\{}.x1.tmp", profile_id(5));
    put(&temp, b"the shim is writing");
    let other = format!(r"{RERUN}\launch\notes.txt");
    put(&other, b"someone's");
    let (p, shown) = with_guard(&sys, |g| clear_preview(&g)).unwrap();
    let goes: std::collections::BTreeSet<_> = p.results.iter().copied().collect();
    assert_eq!(
        goes,
        std::collections::BTreeSet::from([profile_id(1), profile_id(2)])
    );
    let stay: std::collections::BTreeMap<_, _> = p.results_stay.iter().copied().collect();
    assert_eq!(stay.get(&profile_id(3)), Some(&ResultKeep::OptionStillSet));
    assert_eq!(stay.get(&profile_id(4)), Some(&ResultKeep::Unreadable));
    // A new start of profile 2 after the preview: its result stays.
    fx.remove_abs(Path::new(&result_at(2))).unwrap();
    put(&result_at(2), &started(2, ran(), 2_000));
    let r = with_guard(&sys, |g| clear(&g, shown)).unwrap();
    assert_eq!(r.results, 1);
    let exists = |p: &str| crate::exec::tests::try_meta_abs(&sys, p).is_some();
    assert!(!exists(&result_at(1)));
    for p in [result_at(2), result_at(3), result_at(4), temp, other] {
        assert!(exists(&p), "{p} stays");
    }
}

#[test]
fn hp2_a_forgotten_entry_does_not_count_towards_the_cap() {
    let sys = finish(base());
    let all = journal(&sys, |l| {
        (0..=HISTORY_KEEP)
            .map(|_| settled(l, Closing::Reverted, false))
            .collect::<Vec<_>>()
    });
    // The newest one is forgotten by a marker (planted: only `forget` writes one).
    let newest = all[HISTORY_KEEP];
    let sha: [u8; 32] =
        sha2::Digest::finalize(<sha2::Sha256 as sha2::Digest>::new_with_prefix(HEAD)).into();
    sys.fake_fs()
        .put_file(
            Path::new(&format!(r"{RERUN}\journal\{newest}.forgotten")),
            crate::wire::hex32::to_string(&sha).as_bytes(),
        )
        .unwrap();
    assert_eq!(
        tidied(&sys).removed,
        0,
        "100 undone that are not forgotten stay"
    );
    assert_eq!(ids(&sys).len(), HISTORY_KEEP + 1);
}

/// Review S1 (S6, "held ones count"): a held entry inside the newest 100 counts towards them, so
/// the one removable entry older than the 100 goes.
#[test]
fn hp2_a_held_entry_inside_the_newest_hundred_counts() {
    let sys = finish(base());
    let (oldest, held, open) = journal(&sys, |l| {
        let oldest = settled(l, Closing::Reverted, false);
        let held = settled(l, Closing::Reverted, true);
        for _ in 0..HISTORY_KEEP - 1 {
            settled(l, Closing::Reverted, false);
        }
        // Newer than the creator, not settled: it holds what was kept.
        (oldest, held, applied(l))
    });
    assert_eq!(undone_count(&sys), HISTORY_KEEP + 1, "precondition");
    let (p, _) = with_guard(&sys, |g| clear_preview(&g)).unwrap();
    assert!(
        p.stays
            .iter()
            .any(|(i, k)| i.txn == held && *k == Keep::HandedOver),
        "precondition: held"
    );
    assert_eq!(tidied(&sys).removed, 1);
    let left = ids(&sys);
    assert!(
        !left.contains(&oldest),
        "the one beyond the newest 100 goes"
    );
    assert!(left.contains(&held) && left.contains(&open));
    assert_eq!(undone_count(&sys), HISTORY_KEEP);
}

/// Review security nit 3: a launch result with a second hard link is unreadable and stays.
#[test]
fn hp6_a_linked_launch_result_is_unreadable_and_stays() {
    let sys = finish(base());
    let fx = sys.fake_fs();
    fx.put_file(Path::new(&result_at(1)), &started(1, ran(), 1_000))
        .unwrap();
    fx.put_hardlink(
        Path::new(&result_at(1)),
        Path::new(r"C:\Users\Player\elsewhere.result"),
    )
    .unwrap();
    let (p, shown) = with_guard(&sys, |g| clear_preview(&g)).unwrap();
    assert!(p.results.is_empty());
    assert_eq!(p.results_stay, [(profile_id(1), ResultKeep::Unreadable)]);
    assert_eq!(with_guard(&sys, |g| clear(&g, shown)).unwrap().results, 0);
    assert!(crate::exec::tests::try_meta_abs(&sys, &result_at(1)).is_some());
}
