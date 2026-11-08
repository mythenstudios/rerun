//! [F] P3-4: `watch` against `FakeOs` on its virtual clock (plan P3-4 §7.1, B1, A1, A3–A6, A9).
//! Every scenario that reaches the search also runs through [`invariants`] (W16).

use rerun_proto::cpu::rule::{CpuRule, Mode};
use rerun_proto::launch::{self as result, Check, Outcome, SkipReason};
use rerun_proto::profile::{LaunchProfile, Method, Priority};

use super::tests::{CCD0_FIRST_THREADS, GAME, fake, id, profile, rule, tail};
use super::watch::{
    ERROR_INVALID_DATA, FAST_POLL_FOR_MS, MAX_OPENS_PER_POLL, MAX_TARGETS, POLL_MS, SLOW_POLL_MS,
    Trust, trust,
};
use super::*;
use crate::fake::{CHILD_PID, Call, FakeOs, FakeProc, own_token};
use crate::os::{Access, JOB_LIMIT_BREAKAWAY_OK, OsError, Spawn, Token, priority_class};

/// The game's image: not the program Steam starts.
const TARGET: &str = r"C:\Games\My Game\bin\real.exe";
/// winnt.h `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`: never set (A1).
const KILL_ON_JOB_CLOSE: u32 = 0x0000_2000;
const T120: u64 = 120_000;

const HARD_8: Applied = Applied {
    mode: Mode::Hard,
    threads: 8,
    of: 32,
};
const SOFT_8: Applied = Applied {
    mode: Mode::Soft,
    threads: 8,
    of: 32,
};
const HIGH: u32 = 0x0000_0080;
const NORMAL: u32 = 0x0000_0020;

fn wprofile(cpu: Option<CpuRule>, priority: Option<Priority>) -> LaunchProfile {
    LaunchProfile {
        method: Method::Watch,
        target: TARGET.to_owned(),
        ..profile(cpu, priority)
    }
}

/// A machine with the `watch` profile `p` and this script of snapshots.
fn wfake(p: &LaunchProfile, snapshots: Vec<Result<Vec<FakeProc>, u32>>) -> FakeOs {
    let os = fake(p);
    *os.table.borrow_mut() = snapshots.into();
    os
}

/// `n` empty snapshots, then `procs` on every later one.
fn after(n: usize, procs: Vec<FakeProc>) -> Vec<Result<Vec<FakeProc>, u32>> {
    let mut v: Vec<_> = (0..n).map(|_| Ok(Vec::new())).collect();
    v.push(Ok(procs));
    v
}

/// The game, created 10 units after the shim.
fn game(pid: u32) -> FakeProc {
    FakeProc::new(pid, TARGET, 10)
}

fn hard_high() -> LaunchProfile {
    wprofile(Some(rule(Mode::Hard)), Some(Priority::High))
}

fn set_access(job: bool, cpu_sets: bool, priority: bool) -> Access {
    Access {
        job,
        cpu_sets,
        priority,
    }
}

fn query(pid: u32) -> Call {
    Call::Open {
        pid,
        access: Access::default(),
    }
}

/// Rule, check, priority restore and exit code of a report.
fn parts(r: &Report) -> (Rule, Option<Check>, Option<u32>, u32) {
    match r {
        Report::Ran {
            rule,
            check,
            priority_restore,
            exit,
            ..
        } => (rule.clone(), *check, *priority_restore, *exit),
        Report::Usage(u) => panic!("usage: {u:?}"),
    }
}

fn applied(cpu: Option<Applied>, priority: Option<Priority>) -> Rule {
    Rule::Applied { cpu, priority }
}

fn skipped(skip: Skip) -> Rule {
    Rule::Skipped(skip)
}

/// The one result file, decoded.
fn outcome(os: &FakeOs) -> Outcome {
    let w = os.written.borrow();
    assert_eq!(w.len(), 1, "{} result files", w.len());
    let r = result::decode(&w[0]).unwrap();
    assert_eq!(r.profile, id());
    r.outcome
}

fn count(os: &FakeOs, f: impl Fn(&Call) -> bool) -> usize {
    os.calls().iter().filter(|c| f(c)).count()
}

fn snapshots(os: &FakeOs) -> usize {
    count(os, |c| *c == Call::Snapshot)
}

/// The calls that set something on a target.
fn sets(os: &FakeOs) -> Vec<Call> {
    os.calls()
        .into_iter()
        .filter(|c| {
            matches!(
                c,
                Call::SetPriority(..) | Call::AttachJob(..) | Call::CpuSets(..)
            )
        })
        .collect()
}

/// The PIDs opened with set rights.
fn set_opened(os: &FakeOs) -> Vec<u32> {
    os.calls()
        .into_iter()
        .filter_map(|c| match c {
            Call::Open { pid, access } if access != Access::default() => Some(pid),
            _ => None,
        })
        .collect()
}

/// W16: what holds for every run that reached the search.
fn invariants(os: &FakeOs, timeout_ms: u64) {
    let calls = os.calls();
    // Exactly one result file, written before the wait for the started program.
    let writes: Vec<usize> = calls
        .iter()
        .enumerate()
        .filter(|(_, c)| matches!(c, Call::WriteResult(_)))
        .map(|(i, _)| i)
        .collect();
    assert_eq!(writes.len(), 1, "{calls:?}");
    if let Some(wait) = calls.iter().position(|c| matches!(c, Call::Wait(_))) {
        assert!(writes[0] < wait);
    }
    // Never an end of anything: no terminate on a target (A2), nor on the started program.
    assert!(!calls.iter().any(|c| matches!(c, Call::Terminate(_))));
    // Bounded search: snapshots, opens with query rights per snapshot, time of the write.
    assert!(snapshots(os) as u64 <= timeout_ms / u64::from(POLL_MS) + 4);
    let mut opens = 0;
    for c in &calls {
        match c {
            Call::Snapshot => opens = 0,
            Call::Open { access, .. } if *access == Access::default() => {
                opens += 1;
                assert!(opens <= MAX_OPENS_PER_POLL, "{calls:?}");
            }
            _ => {}
        }
    }
    let at = os.written_at.borrow()[0];
    assert!(
        at <= timeout_ms + u64::from(CHECK_DELAY_MS) + u64::from(SLOW_POLL_MS),
        "{at}"
    );
    // Set calls only on handles opened with set rights; every job without KILL_ON_JOB_CLOSE.
    let set_handles = os.set_handles();
    for c in sets(os) {
        let (Call::SetPriority(h, _) | Call::AttachJob(h, ..) | Call::CpuSets(h, _)) = c else {
            unreachable!()
        };
        assert!(set_handles.contains(&h), "{c:?} on a query handle");
        if let Call::AttachJob(_, _, flags) = c {
            assert_eq!(flags, JOB_LIMIT_BREAKAWAY_OK);
            assert_eq!(flags & KILL_ON_JOB_CLOSE, 0);
        }
    }
}

/// Runs and checks the invariants.
fn go(os: &FakeOs, timeout_ms: u64) -> Report {
    let r = run(os);
    invariants(os, timeout_ms);
    r
}

// ---- A3: the trust of a token, pure ----

#[test]
fn a3_trust_compares_user_session_and_integrity() {
    let own = own_token();
    assert_eq!(trust(&own, &own), Trust::Same);
    let with = |f: fn(&mut Token)| {
        let mut t = own_token();
        f(&mut t);
        t
    };
    // Another user, another session: foreign, whatever the integrity level.
    assert_eq!(trust(&own, &with(|t| t.user[15] ^= 1)), Trust::Foreign);
    assert_eq!(
        trust(&own, &with(|t| t.user.pop().map_or((), drop))),
        Trust::Foreign
    );
    assert_eq!(trust(&own, &with(|t| t.session = 2)), Trust::Foreign);
    assert_eq!(
        trust(
            &own,
            &with(|t| {
                t.session = 0;
                t.integrity = 0x4000;
            })
        ),
        Trust::Foreign
    );
    // Same user and session: medium plus and high are above medium; low and medium are not.
    assert_eq!(
        trust(&own, &with(|t| t.integrity = 0x2100)),
        Trust::Elevated
    );
    assert_eq!(
        trust(&own, &with(|t| t.integrity = 0x3000)),
        Trust::Elevated
    );
    assert_eq!(trust(&own, &with(|t| t.integrity = 0x2000)), Trust::Same);
    assert_eq!(trust(&own, &with(|t| t.integrity = 0x1000)), Trust::Same);
    // A high shim (never searching, M1; the function alone) sees a medium game as the same.
    let high = with(|t| t.integrity = 0x3000);
    assert_eq!(trust(&high, &own), Trust::Same);
}

// ---- W1: found after some polls ----

#[test]
fn w1_target_found_after_polls_gets_priority_then_cpu_and_is_checked() {
    let os = wfake(&hard_high(), after(3, vec![game(5000)]));
    let r = go(&os, T120);
    assert_eq!(
        parts(&r),
        (
            applied(Some(HARD_8), Some(Priority::High)),
            Some(Check::Ok),
            None,
            42
        )
    );
    let pace = Call::WaitFor(1, POLL_MS);
    assert_eq!(
        os.calls(),
        [
            Call::ReadProfile(id()),
            Call::Topology,
            Call::Spawn {
                app: GAME.to_owned(),
                line: tail(),
                spawn: Spawn::UNCHANGED,
            },
            Call::Snapshot,
            pace.clone(),
            Call::Snapshot,
            pace.clone(),
            Call::Snapshot,
            pace,
            Call::Snapshot,
            query(5000),
            Call::Facts(2),
            Call::Open {
                pid: 5000,
                access: set_access(true, false, true),
            },
            Call::Facts(3),
            Call::PriorityClass(3),
            Call::SetPriority(3, HIGH),
            Call::AttachJob(3, CCD0_FIRST_THREADS, JOB_LIMIT_BREAKAWAY_OK),
            Call::WaitFor(3, CHECK_DELAY_MS),
            Call::JobAffinity(3),
            Call::ProcessAffinity(3),
            Call::PriorityClass(3),
            Call::WriteResult(id()),
            Call::Wait(1),
        ]
    );
    assert_eq!(
        outcome(&os),
        Outcome::Applied {
            cpu: Some(result::AppliedCpu {
                mode: Mode::Hard,
                threads: 8,
                of: 32
            }),
            priority: Some(Priority::High),
            check: Check::Ok,
        }
    );
    // Soft: the CPU Sets on the target, opened with exactly that right.
    let os = wfake(
        &wprofile(Some(rule(Mode::Soft)), None),
        after(0, vec![game(5000)]),
    );
    assert_eq!(
        parts(&go(&os, T120)),
        (applied(Some(SOFT_8), None), Some(Check::Ok), None, 42)
    );
    assert!(os.calls().contains(&Call::Open {
        pid: 5000,
        access: set_access(false, true, false),
    }));
    assert!(matches!(sets(&os)[..], [Call::CpuSets(3, ref ids)] if ids.len() == 8));
}

// ---- W2, A6: never found ----

#[test]
fn w2_a6_no_target_is_target_not_found_after_the_poll_schedule() {
    let os = wfake(&hard_high(), Vec::new());
    let r = go(&os, T120);
    assert_eq!(parts(&r), (skipped(Skip::TargetNotFound), None, None, 42));
    // 100 ms for the first 10 s, 250 ms up to 120 s: 100 + 440 snapshots.
    let fast = FAST_POLL_FOR_MS / u64::from(POLL_MS);
    let slow = (T120 - FAST_POLL_FOR_MS) / u64::from(SLOW_POLL_MS);
    assert_eq!(snapshots(&os) as u64, fast + slow);
    let paces: Vec<u32> = os
        .calls()
        .into_iter()
        .filter_map(|c| match c {
            Call::WaitFor(1, ms) => Some(ms),
            _ => None,
        })
        .collect();
    assert_eq!(paces.len() as u64, fast + slow);
    assert!(paces[..100].iter().all(|ms| *ms == POLL_MS));
    assert!(paces[100..].iter().all(|ms| *ms == SLOW_POLL_MS));
    assert!(sets(&os).is_empty());
    assert_eq!(count(&os, |c| matches!(c, Call::Open { .. })), 0);
    assert_eq!(os.written_at.borrow()[0], T120);
    assert!(matches!(
        outcome(&os),
        Outcome::Skipped {
            reason: SkipReason::TargetNotFound,
            start: result::Start::Created,
            ended: None,
            priority_restore: None,
        }
    ));
    assert_eq!(os.calls().last(), Some(&Call::Wait(1)));
}

// ---- W3: a copy that ran before the shim ----

#[test]
fn w3_a_copy_created_before_the_shim_is_never_a_target() {
    for before in [-1, -1_000_000] {
        let os = wfake(
            &hard_high(),
            after(0, vec![FakeProc::new(5000, TARGET, before)]),
        );
        assert_eq!(
            parts(&go(&os, T120)).0,
            skipped(Skip::TargetNotFound),
            "{before}"
        );
        assert!(set_opened(&os).is_empty());
        // Held after the first look (A5): opened once in 540 snapshots.
        assert_eq!(count(&os, |c| *c == query(5000)), 1);
    }
    // Created in the same FILETIME tick as the shim counts as after it.
    let os = wfake(&hard_high(), after(0, vec![FakeProc::new(5000, TARGET, 0)]));
    assert_eq!(parts(&go(&os, T120)).1, Some(Check::Ok));
}

// ---- W4, B1: the started program is never the target ----

#[test]
fn w4_start_equal_to_target_excludes_the_started_child_by_pid() {
    let mut p = hard_high();
    p.target = GAME.to_owned();
    // The started stub is listed first and earliest; a second process of the same path later.
    let stub = FakeProc::new(CHILD_PID, GAME, 0);
    let second = FakeProc::new(5000, GAME, 50);
    let os = wfake(&p, vec![Ok(vec![stub.clone()]), Ok(vec![stub, second])]);
    assert_eq!(
        parts(&go(&os, T120)).0,
        applied(Some(HARD_8), Some(Priority::High))
    );
    // Never opened at all (B1: excluded by PID before the open).
    assert_eq!(
        count(
            &os,
            |c| matches!(c, Call::Open { pid, .. } if *pid == CHILD_PID)
        ),
        0
    );
    assert_eq!(set_opened(&os), [5000]);
}

// ---- W5: several candidates ----

#[test]
fn w5_the_earliest_candidate_wins_and_the_others_stay_untouched() {
    let os = wfake(
        &hard_high(),
        after(
            0,
            vec![
                FakeProc::new(5002, TARGET, 20),
                FakeProc::new(5001, TARGET, 10),
            ],
        ),
    );
    assert_eq!(parts(&go(&os, T120)).1, Some(Check::Ok));
    assert_eq!(set_opened(&os), [5001]);
    // A tie on the creation time: the smallest PID.
    let os = wfake(
        &hard_high(),
        after(
            0,
            vec![
                FakeProc::new(5003, TARGET, 10),
                FakeProc::new(5001, TARGET, 10),
            ],
        ),
    );
    assert_eq!(parts(&go(&os, T120)).1, Some(Check::Ok));
    assert_eq!(set_opened(&os), [5001]);
}

// ---- W6: PID reuse and the facts of the handle ----

#[test]
fn w6_the_handle_decides_not_the_snapshot() {
    // The name matches, the opened handle reports another image: no target.
    let mut other = game(5000);
    other.facts_mut().image = r"C:\Other\real.exe".encode_utf16().collect();
    let os = wfake(&hard_high(), after(0, vec![other]));
    assert_eq!(parts(&go(&os, T120)).0, skipped(Skip::TargetNotFound));
    assert!(set_opened(&os).is_empty());
    // The name does not match: never opened, even if the image would.
    let mut renamed = game(5000);
    renamed.name = "other.exe".to_owned();
    let os = wfake(&hard_high(), after(0, vec![renamed]));
    assert_eq!(parts(&go(&os, T120)).0, skipped(Skip::TargetNotFound));
    assert_eq!(count(&os, |c| matches!(c, Call::Open { .. })), 0);
    // The second handle reports another creation time: denied, nothing set.
    let mut moved = game(5000);
    let mut f = moved.facts.clone().unwrap();
    f.created += 1;
    moved.facts_set = Some(Ok(f));
    let os = wfake(&hard_high(), after(0, vec![moved]));
    assert_eq!(
        parts(&go(&os, T120)).0,
        skipped(Skip::TargetDenied(ERROR_INVALID_DATA))
    );
    assert!(sets(&os).is_empty());
    // The name comparison is case-insensitive (Windows file names).
    let mut upper = game(5000);
    upper.name = "REAL.EXE".to_owned();
    let os = wfake(&hard_high(), after(0, vec![upper]));
    assert_eq!(parts(&go(&os, T120)).1, Some(Check::Ok));
}

// ---- W7, W8: identity ----

#[test]
fn w7_an_elevated_target_ends_the_search_untouched() {
    for integrity in [0x2100, 0x3000, 0x4000] {
        let mut admin = game(5000);
        admin.facts_mut().token.integrity = integrity;
        let os = wfake(&hard_high(), after(2, vec![admin, game(5001)]));
        assert_eq!(
            parts(&go(&os, T120)),
            (skipped(Skip::TargetElevated), None, None, 42),
            "{integrity:#x}"
        );
        assert_eq!(snapshots(&os), 3);
        assert!(set_opened(&os).is_empty());
        assert!(sets(&os).is_empty());
        assert!(matches!(
            outcome(&os),
            Outcome::Skipped {
                reason: SkipReason::TargetElevated,
                ..
            }
        ));
    }
}

#[test]
fn w8_foreign_processes_are_ignored_and_the_search_goes_on() {
    let mut other_user = FakeProc::new(5001, TARGET, 10);
    other_user.facts_mut().token.user[15] ^= 1;
    let mut other_session = FakeProc::new(5002, TARGET, 10);
    other_session.facts_mut().token.session = 2;
    let mut admin_elsewhere = FakeProc::new(5003, TARGET, 10);
    admin_elsewhere.facts_mut().token.session = 0;
    admin_elsewhere.facts_mut().token.integrity = 0x4000;
    let foreign = vec![other_user, other_session, admin_elsewhere];
    let mut later = foreign.clone();
    later.push(game(5004));
    let os = wfake(
        &hard_high(),
        vec![Ok(foreign.clone()), Ok(foreign), Ok(later)],
    );
    assert_eq!(
        parts(&go(&os, T120)).0,
        applied(Some(HARD_8), Some(Priority::High))
    );
    assert_eq!(set_opened(&os), [5004]);
    // Each foreign process was opened once and then held (A5).
    for pid in [5001, 5002, 5003] {
        assert_eq!(count(&os, |c| *c == query(pid)), 1, "{pid}");
    }
}

// ---- W9: the second open and its facts ----

#[test]
fn w9_set_rights_refused_or_facts_unreadable_is_target_denied() {
    let mut refused = game(5000);
    refused.open_set = Err(5);
    let os = wfake(&hard_high(), after(0, vec![refused]));
    assert_eq!(
        parts(&go(&os, T120)),
        (skipped(Skip::TargetDenied(5)), None, None, 42)
    );
    assert!(sets(&os).is_empty());
    assert!(matches!(
        outcome(&os),
        Outcome::Skipped {
            reason: SkipReason::TargetDenied { code: 5 },
            ..
        }
    ));
    let mut unreadable = game(5000);
    unreadable.facts_set = Some(Err(31));
    let os = wfake(&hard_high(), after(0, vec![unreadable]));
    assert_eq!(parts(&go(&os, T120)).0, skipped(Skip::TargetDenied(31)));
    assert!(sets(&os).is_empty());
}

// ---- B1: two stages ----

#[test]
fn b1_a_failed_first_open_or_read_skips_the_candidate_only() {
    let mut gone = FakeProc::new(5001, TARGET, 5);
    gone.open = Err(87);
    let mut denied = FakeProc::new(5002, TARGET, 5);
    denied.open = Err(5);
    let mut unreadable = FakeProc::new(5003, TARGET, 5);
    unreadable.facts = Err(31);
    let first = vec![gone, denied.clone(), unreadable.clone()];
    let os = wfake(
        &hard_high(),
        vec![Ok(first), Ok(vec![denied, unreadable, game(5004)])],
    );
    assert_eq!(
        parts(&go(&os, T120)),
        (
            applied(Some(HARD_8), Some(Priority::High)),
            Some(Check::Ok),
            None,
            42
        )
    );
    assert_eq!(set_opened(&os), [5004]);
    // The unreadable one was held after its first look; the refused one is tried again.
    assert_eq!(count(&os, |c| *c == query(5003)), 1);
    assert_eq!(count(&os, |c| *c == query(5002)), 2);
}

#[test]
fn b1_a_search_with_refused_candidates_only_ends_target_denied() {
    let mut denied = FakeProc::new(5002, TARGET, 5);
    denied.open = Err(5);
    let os = wfake(&hard_high(), after(0, vec![denied]));
    assert_eq!(parts(&go(&os, T120)).0, skipped(Skip::TargetDenied(5)));
    // The last code counts: a read failure after a refused open.
    let mut denied = FakeProc::new(5002, TARGET, 5);
    denied.open = Err(5);
    let mut unreadable = FakeProc::new(5003, TARGET, 5);
    unreadable.facts = Err(31);
    let os = wfake(&hard_high(), vec![Ok(vec![denied]), Ok(vec![unreadable])]);
    assert_eq!(parts(&go(&os, T120)).0, skipped(Skip::TargetDenied(31)));
    // A candidate that is gone (87) was never refused: not found.
    let mut gone = FakeProc::new(5001, TARGET, 5);
    gone.open = Err(87);
    let os = wfake(&hard_high(), vec![Ok(vec![gone]), Ok(Vec::new())]);
    assert_eq!(parts(&go(&os, T120)).0, skipped(Skip::TargetNotFound));
}

// ---- A5: held handles, the cap on new PIDs only ----

#[test]
fn a5_held_pids_are_skipped_without_opening_and_do_not_count() {
    let old: Vec<FakeProc> = (5001..=5008)
        .map(|p| FakeProc::new(p, TARGET, -5))
        .collect();
    let mut then = old.clone();
    then.push(game(5100));
    let os = wfake(&hard_high(), vec![Ok(old), Ok(then)]);
    assert_eq!(parts(&go(&os, T120)).1, Some(Check::Ok));
    assert_eq!(set_opened(&os), [5100]);
    for pid in 5001..=5008 {
        assert_eq!(count(&os, |c| *c == query(pid)), 1, "{pid}");
    }
    // Nine old ones and the game in one snapshot: 8 opens, the rest in the next poll.
    let mut nine: Vec<FakeProc> = (5001..=5009)
        .map(|p| FakeProc::new(p, TARGET, -5))
        .collect();
    nine.push(game(5100));
    let os = wfake(&hard_high(), after(0, nine));
    assert_eq!(parts(&go(&os, T120)).1, Some(Check::Ok));
    let calls = os.calls();
    let second = calls
        .iter()
        .enumerate()
        .filter(|(_, c)| **c == Call::Snapshot)
        .nth(1)
        .unwrap()
        .0;
    let at = |c: &Call| calls.iter().position(|x| x == c).unwrap();
    assert!(at(&query(5008)) < second);
    assert!(at(&query(5009)) > second);
    assert!(at(&query(5100)) > second);
    assert_eq!(snapshots(&os), 2);
}

// ---- W10: a target that ends within the check ----

#[test]
fn w10_an_early_exit_searches_on_up_to_the_limit_and_the_deadline() {
    let stub = |pid, after| {
        let mut p = FakeProc::new(pid, TARGET, after);
        p.exits_after_ms = Some(1_000);
        p
    };
    // The first one hands over, the second one stays: ok on the second.
    let a = stub(5001, 10);
    let os = wfake(
        &hard_high(),
        vec![Ok(vec![a.clone()]), Ok(vec![a, game(5002)])],
    );
    assert_eq!(
        parts(&go(&os, T120)),
        (
            applied(Some(HARD_8), Some(Priority::High)),
            Some(Check::Ok),
            None,
            42
        )
    );
    assert_eq!(set_opened(&os), [5001, 5002]);
    // Four that end early: the fourth's result; a fifth is never set.
    let all: Vec<FakeProc> = (0..5).map(|i| stub(5001 + i, 10 + i64::from(i))).collect();
    // One more each poll; the fourth poll lists the fifth too (created after the fourth).
    let snaps = vec![
        Ok(all[..1].to_vec()),
        Ok(all[..2].to_vec()),
        Ok(all[..3].to_vec()),
        Ok(all.clone()),
    ];
    let os = wfake(&hard_high(), snaps);
    assert_eq!(parts(&go(&os, T120)).1, Some(Check::ExitedEarly));
    assert_eq!(set_opened(&os).len(), usize::from(MAX_TARGETS));
    assert!(!set_opened(&os).contains(&5005));
    assert!(matches!(
        outcome(&os),
        Outcome::Applied {
            check: Check::ExitedEarly,
            ..
        }
    ));
    // Past the deadline (1 s) after the first one's check: no new target.
    let mut p = hard_high();
    p.watch_timeout_s = 1;
    let mut late = stub(5001, 10);
    late.exits_after_ms = Some(3_000);
    let os = wfake(&p, after(0, vec![late, game(5002)]));
    assert_eq!(parts(&go(&os, 1_000)).1, Some(Check::ExitedEarly));
    assert_eq!(set_opened(&os), [5001]);
}

// ---- W11, A1, A4: the order of the setters and the restore ----

#[test]
fn w11_a_cpu_failure_puts_the_priority_back() {
    // Hard: the job fails after the priority was set.
    let mut os = wfake(&hard_high(), after(0, vec![game(5000)]));
    os.attach_job = Err(5);
    assert_eq!(
        parts(&go(&os, T120)),
        (skipped(Skip::Job(5)), None, None, 42)
    );
    assert_eq!(
        sets(&os),
        [
            Call::SetPriority(3, HIGH),
            Call::AttachJob(3, CCD0_FIRST_THREADS, JOB_LIMIT_BREAKAWAY_OK),
            Call::SetPriority(3, NORMAL),
        ]
    );
    assert!(!os.calls().contains(&Call::WaitFor(3, CHECK_DELAY_MS)));
    assert_eq!(
        outcome(&os),
        Outcome::Skipped {
            reason: SkipReason::JobFailed { code: 5 },
            start: result::Start::Created,
            ended: None,
            priority_restore: None,
        }
    );
    // Soft: the CPU Sets fail.
    let mut os = wfake(
        &wprofile(Some(rule(Mode::Soft)), Some(Priority::AboveNormal)),
        after(0, vec![game(5000)]),
    );
    os.cpu_sets = Err(87);
    assert_eq!(parts(&go(&os, T120)).0, skipped(Skip::CpuSets(87)));
    let s = sets(&os);
    assert_eq!(s.len(), 3);
    assert_eq!(s[2], Call::SetPriority(3, NORMAL));
    // The old class is the one read before, not "normal".
    let mut was_high = game(5000);
    was_high.class = HIGH;
    let mut os = wfake(
        &wprofile(Some(rule(Mode::Hard)), Some(Priority::AboveNormal)),
        after(0, vec![was_high]),
    );
    os.attach_job = Err(5);
    go(&os, T120);
    assert_eq!(sets(&os).last(), Some(&Call::SetPriority(3, HIGH)));
    // Without a priority there is nothing to put back.
    let mut os = wfake(
        &wprofile(Some(rule(Mode::Hard)), None),
        after(0, vec![game(5000)]),
    );
    os.attach_job = Err(5);
    go(&os, T120);
    assert_eq!(
        sets(&os),
        [Call::AttachJob(
            3,
            CCD0_FIRST_THREADS,
            JOB_LIMIT_BREAKAWAY_OK
        )]
    );
}

#[test]
fn w11_a_priority_failure_sets_nothing() {
    let os = wfake(&hard_high(), after(0, vec![game(5000)]));
    os.set_priority.borrow_mut().push_back(Err(5));
    assert_eq!(
        parts(&go(&os, T120)),
        (skipped(Skip::Priority(5)), None, None, 42)
    );
    assert_eq!(sets(&os), [Call::SetPriority(3, HIGH)]);
    assert!(matches!(
        outcome(&os),
        Outcome::Skipped {
            reason: SkipReason::PriorityFailed { code: 5 },
            ..
        }
    ));
    // The old class cannot be read: nothing set either.
    let mut os = wfake(&hard_high(), after(0, vec![game(5000)]));
    os.priority_class = Some(Err(31));
    assert_eq!(parts(&go(&os, T120)).0, skipped(Skip::Priority(31)));
    assert!(sets(&os).is_empty());
}

#[test]
fn a4_a_failed_restore_is_in_the_report_and_the_file() {
    let mut os = wfake(&hard_high(), after(0, vec![game(5000)]));
    os.attach_job = Err(5);
    os.set_priority.borrow_mut().extend([Ok(()), Err(6)]);
    assert_eq!(
        parts(&go(&os, T120)),
        (skipped(Skip::Job(5)), None, Some(6), 42)
    );
    assert_eq!(
        outcome(&os),
        Outcome::Skipped {
            reason: SkipReason::JobFailed { code: 5 },
            start: result::Start::Created,
            ended: None,
            priority_restore: Some(6),
        }
    );
    let bytes = os.written.borrow()[0].clone();
    assert!(
        String::from_utf8(bytes)
            .unwrap()
            .ends_with("rule_child=none\npriority_restore=failed:6\n")
    );
}

#[test]
fn a1_the_job_has_breakaway_ok_and_never_kill_on_job_close() {
    let os = wfake(&hard_high(), after(0, vec![game(5000)]));
    go(&os, T120);
    let jobs: Vec<u32> = os
        .calls()
        .into_iter()
        .filter_map(|c| match c {
            Call::AttachJob(_, _, flags) => Some(flags),
            _ => None,
        })
        .collect();
    assert_eq!(jobs, [JOB_LIMIT_BREAKAWAY_OK]);
    assert_eq!(jobs[0] & KILL_ON_JOB_CLOSE, 0);
}

// ---- W12: the check on the target ----

#[test]
fn w12_the_check_reads_the_target() {
    let reset = |cpu, priority| Some(Check::Reset { cpu, priority });
    let check_with = |p: LaunchProfile, f: fn(&mut FakeOs)| {
        let mut os = wfake(&p, after(0, vec![game(5000)]));
        f(&mut os);
        let c = parts(&go(&os, T120)).1;
        // Every read of the check is on the target handle, none on the started program.
        assert!(os.calls().iter().all(|c| !matches!(
            c,
            Call::JobAffinity(1) | Call::ProcessAffinity(1) | Call::ReadCpuSets(1)
        )));
        c
    };
    let hard = || wprofile(Some(rule(Mode::Hard)), None);
    let soft = || wprofile(Some(rule(Mode::Soft)), None);
    assert_eq!(
        check_with(hard(), |os| os.job_affinity =
            Some(Ok(vec![CCD0_FIRST_THREADS, CCD0_FIRST_THREADS]))),
        reset(true, false)
    );
    assert_eq!(
        check_with(hard(), |os| os.process_affinity = Some(Ok(0x0005))),
        Some(Check::Narrowed)
    );
    assert_eq!(
        check_with(hard(), |os| os.process_affinity = Some(Ok(0x5555 | 0x0002))),
        reset(true, false)
    );
    assert_eq!(
        check_with(hard(), |os| os.job_affinity = Some(Err(6))),
        Some(Check::Failed { code: 6 })
    );
    assert_eq!(
        check_with(soft(), |os| os.read_cpu_sets = Some(Ok(vec![]))),
        reset(true, false)
    );
    assert_eq!(check_with(soft(), |_| {}), Some(Check::Ok));
    assert_eq!(
        check_with(hard_high(), |os| os.priority_class =
            Some(Ok(priority_class(Priority::Normal)))),
        reset(false, true)
    );
    assert_eq!(
        check_with(wprofile(None, Some(Priority::High)), |_| {}),
        Some(Check::Ok)
    );
}

// ---- W13: snapshots that fail ----

#[test]
fn w13_failing_snapshots() {
    let os = wfake(&hard_high(), vec![Err(1), Err(2)]);
    assert_eq!(
        parts(&go(&os, T120)),
        (skipped(Skip::SearchFailed(2)), None, None, 42)
    );
    assert_eq!(snapshots(&os), 540);
    assert!(matches!(
        outcome(&os),
        Outcome::Skipped {
            reason: SkipReason::SearchFailed { code: 2 },
            ..
        }
    ));
    // Failing now and then: the search goes on.
    let os = wfake(
        &hard_high(),
        vec![Err(5), Ok(Vec::new()), Err(5), Ok(vec![game(5000)])],
    );
    assert_eq!(parts(&go(&os, T120)).1, Some(Check::Ok));
    // Listed once, failing afterwards: not found, not search_failed.
    let os = wfake(&hard_high(), vec![Ok(Vec::new()), Err(8)]);
    assert_eq!(parts(&go(&os, T120)).0, skipped(Skip::TargetNotFound));
}

// ---- W14, A9: no search ----

#[test]
fn w14_no_search_without_a_usable_start() {
    let none = |os: &FakeOs| {
        snapshots(os) == 0 && !os.calls().iter().any(|c| matches!(c, Call::Open { .. }))
    };
    // Elevated shim: reads nothing, writes nothing.
    let mut os = wfake(&hard_high(), after(0, vec![game(5000)]));
    os.elevated = true;
    assert_eq!(parts(&run(&os)).0, skipped(Skip::Elevated));
    assert!(none(&os));
    assert!(os.written.borrow().is_empty());
    // argv[0] is not the profile's start.
    let mut p = hard_high();
    p.start = r"C:\Other\launcher.exe".to_owned();
    let os = wfake(&p, after(0, vec![game(5000)]));
    assert_eq!(parts(&run(&os)).0, skipped(Skip::PathMismatch));
    assert!(none(&os));
    // No topology.
    let mut os = wfake(&hard_high(), after(0, vec![game(5000)]));
    os.topology = Err(OsError::Win32(5));
    assert_eq!(
        parts(&run(&os)).0,
        skipped(Skip::Topology(OsError::Win32(5)))
    );
    assert!(none(&os));
    // 740: through the shell, without a rule and without a search.
    let os = wfake(&hard_high(), after(0, vec![game(5000)]));
    os.spawns
        .borrow_mut()
        .push_back(Err(ERROR_ELEVATION_REQUIRED));
    let r = run(&os);
    assert_eq!(parts(&r).0, skipped(Skip::ElevationRequired));
    assert!(matches!(
        r,
        Report::Ran {
            start: Start::ShellExecuted,
            ..
        }
    ));
    assert!(none(&os));
    // The shim's own facts cannot be read: search_failed before the start, started unchanged.
    let mut os = wfake(&hard_high(), after(0, vec![game(5000)]));
    os.own = Err(50);
    let r = run(&os);
    assert_eq!(parts(&r), (skipped(Skip::SearchFailed(50)), None, None, 42));
    assert!(none(&os));
    assert_eq!(
        os.calls()[2..],
        [
            Call::Spawn {
                app: GAME.to_owned(),
                line: tail(),
                spawn: Spawn::UNCHANGED,
            },
            Call::WriteResult(id()),
            Call::Wait(1),
        ]
    );
}

#[test]
fn a9_a_failed_start_is_spawn_failed_without_a_search() {
    let os = wfake(&hard_high(), after(0, vec![game(5000)]));
    os.spawns.borrow_mut().push_back(Err(2));
    let r = run(&os);
    assert_eq!(
        parts(&r),
        (skipped(Skip::Spawn(2)), None, None, EXIT_NOT_STARTED)
    );
    assert!(matches!(
        r,
        Report::Ran {
            start: Start::Failed(2),
            ..
        }
    ));
    // One start only (it was the unchanged one), no search, the file, no wait.
    assert_eq!(count(&os, |c| matches!(c, Call::Spawn { .. })), 1);
    assert_eq!(snapshots(&os), 0);
    assert!(!os.calls().iter().any(|c| matches!(c, Call::Wait(_))));
    assert_eq!(
        outcome(&os),
        Outcome::Skipped {
            reason: SkipReason::SpawnFailed { code: 2 },
            start: result::Start::Failed { code: 2 },
            ended: None,
            priority_restore: None,
        }
    );
}

// ---- W15: the started program ends during the search ----

#[test]
fn w15_the_search_outlives_the_started_program() {
    let mut os = wfake(&hard_high(), after(5, vec![game(5000)]));
    os.child_ends_at = Some(250);
    let r = go(&os, T120);
    assert_eq!(parts(&r).1, Some(Check::Ok));
    let calls = os.calls();
    let first_sleep = calls
        .iter()
        .position(|c| *c == Call::Sleep(POLL_MS))
        .unwrap();
    // Waited on the child until it ended (the third wait), slept from then on.
    assert_eq!(count(&os, |c| matches!(c, Call::WaitFor(1, _))), 3);
    assert!(
        calls[first_sleep..]
            .iter()
            .all(|c| !matches!(c, Call::WaitFor(1, _)))
    );
    assert_eq!(calls.last(), Some(&Call::Wait(1)));
    assert_eq!(r.exit_code(), 42);
    // A wait that fails paces by sleeping too.
    let mut os = wfake(&hard_high(), after(2, vec![game(5000)]));
    os.wait_for = Err(6);
    assert_eq!(parts(&go(&os, T120)).1, Some(Check::Ok));
    assert_eq!(count(&os, |c| matches!(c, Call::WaitFor(1, _))), 1);
    assert_eq!(count(&os, |c| matches!(c, Call::Sleep(_))), 2);
}

// ---- W16: invariants over many scenarios (beyond those above) ----

#[test]
fn w16_invariants_hold_for_mixed_scenarios() {
    for timeout_s in [1u16, 7, 120] {
        let mut p = hard_high();
        p.watch_timeout_s = timeout_s;
        let timeout = u64::from(timeout_s) * 1_000;
        let mut many: Vec<FakeProc> = (6000..6040)
            .map(|pid| FakeProc::new(pid, TARGET, -1))
            .collect();
        let mut denied = FakeProc::new(6100, TARGET, 3);
        denied.open = Err(5);
        many.push(denied);
        let mut stub = FakeProc::new(6200, TARGET, 4);
        stub.exits_after_ms = Some(4_999);
        many.push(stub);
        for snaps in [
            Vec::new(),
            vec![Err(1)],
            vec![Ok(many.clone())],
            vec![
                Err(1),
                Ok(many.clone()),
                Ok({
                    let mut m = many.clone();
                    m.push(game(6300));
                    m
                }),
            ],
        ] {
            let mut os = wfake(&p, snaps);
            os.child_ends_at = Some(3_000);
            go(&os, timeout);
        }
    }
}
