//! [F] P3-2: the post-launch check and the result file, against `FakeOs`.

use rerun_proto::cpu::CpuTopology;
use rerun_proto::cpu::rule::{Bitness, Mode};
use rerun_proto::launch::{self as result, AppliedCpu, Check, Ended, Outcome, SkipReason};
use rerun_proto::profile::{Priority, encode};

use super::tests::{CCD0_FIRST_THREADS, ID, fake, id, line_with, profile, rule, tail, zen3};
use super::*;
use crate::fake::{Call, FakeOs};
use crate::os::{GroupAffinity, OsError, ReadBack, Terminated, priority_class};

/// The one result file `os` wrote, decoded; panics unless exactly one was written.
fn written_one(os: &FakeOs) -> result::LaunchResult {
    let w = os.written.borrow();
    assert_eq!(w.len(), 1, "{} result files", w.len());
    let r = result::decode(&w[0]).unwrap();
    assert_eq!(r.profile, id());
    assert_eq!(r.unix_s, 1_762_600_000);
    // P3-4: the method of the decoded profile is in the file (a skip before the decode has
    // none); these are `direct` profiles.
    if matches!(r.outcome, Outcome::Applied { .. }) {
        assert_eq!(r.method, Some(rerun_proto::profile::Method::Direct));
    } else {
        assert_ne!(r.method, Some(rerun_proto::profile::Method::Watch));
    }
    r
}

fn check_of(r: &Report) -> Option<Check> {
    match r {
        Report::Ran { check, .. } => *check,
        Report::Usage(_) => None,
    }
}

const HARD_8: AppliedCpu = AppliedCpu {
    mode: Mode::Hard,
    threads: 8,
    of: 32,
};

#[test]
fn a_verified_rule_is_ok_in_the_report_and_the_file() {
    let os = fake(&profile(Some(rule(Mode::Hard)), Some(Priority::High)));
    let r = run(&os);
    assert_eq!(check_of(&r), Some(Check::Ok));
    assert!(matches!(
        r,
        Report::Ran {
            written: Written::Yes,
            exit: 42,
            ..
        }
    ));
    assert_eq!(
        written_one(&os).outcome,
        Outcome::Applied {
            cpu: Some(HARD_8),
            priority: Some(Priority::High),
            check: Check::Ok,
        }
    );
    // Soft and priority-only are verified too.
    let os = fake(&profile(Some(rule(Mode::Soft)), None));
    assert_eq!(check_of(&run(&os)), Some(Check::Ok));
    let os = fake(&profile(None, Some(Priority::AboveNormal)));
    assert_eq!(check_of(&run(&os)), Some(Check::Ok));
    // No rule, no priority: nothing to compare, still the wait for an early end.
    let os = fake(&profile(None, None));
    assert_eq!(check_of(&run(&os)), Some(Check::Ok));
    assert!(os.calls().contains(&Call::WaitFor(1, CHECK_DELAY_MS)));
}

#[test]
fn a_changed_affinity_cpu_set_or_priority_is_reset() {
    let reset = |cpu, priority| Some(Check::Reset { cpu, priority });
    // Hard: the job holds another entry (two, or exactly one other mask or group), or the
    // process has bits outside the job's mask.
    let mut os = fake(&profile(Some(rule(Mode::Hard)), None));
    os.job_affinity = Some(Ok(vec![CCD0_FIRST_THREADS, CCD0_FIRST_THREADS]));
    assert_eq!(check_of(&run(&os)), reset(true, false));
    for other in [
        GroupAffinity {
            group: 0,
            mask: 0x5554,
        },
        GroupAffinity {
            group: 1,
            mask: 0x5555,
        },
    ] {
        let mut os = fake(&profile(Some(rule(Mode::Hard)), None));
        os.job_affinity = Some(Ok(vec![other]));
        assert_eq!(check_of(&run(&os)), reset(true, false), "{other:?}");
    }
    let mut os = fake(&profile(Some(rule(Mode::Hard)), None));
    os.process_affinity = Some(Ok(0x5555 | 0x0002));
    assert_eq!(check_of(&run(&os)), reset(true, false));
    // Threads in more than one group: GetProcessAffinityMask reports 0.
    let mut os = fake(&profile(Some(rule(Mode::Hard)), None));
    os.process_affinity = Some(Ok(0));
    assert_eq!(check_of(&run(&os)), reset(true, false));
    // Soft: other CPU Sets, or none; the same set in another order is not a reset.
    let mut os = fake(&profile(Some(rule(Mode::Soft)), None));
    os.read_cpu_sets = Some(Ok(vec![]));
    assert_eq!(check_of(&run(&os)), reset(true, false));
    let mut os = fake(&profile(Some(rule(Mode::Soft)), None));
    os.read_cpu_sets = Some(Ok((0..8).rev().map(|i| 0x100 + 2 * i).collect()));
    assert_eq!(check_of(&run(&os)), Some(Check::Ok));
    // Priority (D6 addition), alone and with the affinity.
    let mut os = fake(&profile(Some(rule(Mode::Hard)), Some(Priority::High)));
    os.priority_class = Some(Ok(priority_class(Priority::Normal)));
    assert_eq!(check_of(&run(&os)), reset(false, true));
    os.process_affinity = Some(Ok(0xFFFF_FFFF));
    os.calls.borrow_mut().clear();
    os.written.borrow_mut().clear();
    assert_eq!(check_of(&run(&os)), reset(true, true));
    assert_eq!(
        written_one(&os).outcome,
        Outcome::Applied {
            cpu: Some(HARD_8),
            priority: Some(Priority::High),
            check: Check::Reset {
                cpu: true,
                priority: true
            },
        }
    );
    // No priority in the profile: the game may set its own class, never a reset.
    let mut os = fake(&profile(Some(rule(Mode::Hard)), None));
    os.priority_class = Some(Ok(0x40));
    assert_eq!(check_of(&run(&os)), Some(Check::Ok));
    assert!(
        !os.calls()
            .iter()
            .any(|c| matches!(c, Call::PriorityClass(_)))
    );
}

#[test]
fn an_early_end_or_a_failed_read_is_recorded_and_the_exit_code_stays() {
    let mut os = fake(&profile(Some(rule(Mode::Hard)), Some(Priority::High)));
    os.wait_for = Ok(true);
    let r = run(&os);
    assert_eq!(check_of(&r), Some(Check::ExitedEarly));
    assert_eq!(r.exit_code(), 42);
    // Nothing is read after the early end.
    assert_eq!(
        os.calls()[6..],
        [
            Call::WaitFor(1, CHECK_DELAY_MS),
            Call::WriteResult(id()),
            Call::Wait(1)
        ]
    );
    let failures: [fn(&mut FakeOs); 4] = [
        |os| os.wait_for = Err(6),
        |os| os.job_affinity = Some(Err(6)),
        |os| os.process_affinity = Some(Err(6)),
        |os| os.priority_class = Some(Err(6)),
    ];
    for set in failures {
        let mut os = fake(&profile(Some(rule(Mode::Hard)), Some(Priority::High)));
        set(&mut os);
        let r = run(&os);
        assert_eq!(check_of(&r), Some(Check::Failed { code: 6 }));
        assert_eq!(r.exit_code(), 42);
        assert_eq!(os.calls().last(), Some(&Call::Wait(1)));
        assert!(matches!(
            written_one(&os).outcome,
            Outcome::Applied {
                check: Check::Failed { code: 6 },
                ..
            }
        ));
    }
    let mut os = fake(&profile(Some(rule(Mode::Soft)), None));
    os.read_cpu_sets = Some(Err(5));
    assert_eq!(check_of(&run(&os)), Some(Check::Failed { code: 5 }));
}

/// A test case: how to break the fake, and the reason the file must name.
type Case = (fn(&mut FakeOs), SkipReason);

#[test]
fn every_skip_with_an_id_writes_its_reason_before_the_wait() {
    let cases: [Case; 17] = [
        (
            |os| os.profile = Err(OsError::Win32(2)),
            SkipReason::ProfileMissing,
        ),
        (
            |os| os.profile = Err(OsError::Win32(3)),
            SkipReason::ProfileMissing,
        ),
        (
            |os| os.profile = Err(OsError::Win32(5)),
            SkipReason::ProfileUnreadable { code: 5 },
        ),
        (
            |os| os.profile = Err(OsError::HResult(-2_147_024_891)),
            SkipReason::ProfileUnreadable { code: 0x8007_0005 },
        ),
        (
            |os| os.profile = Err(OsError::ReparsePoint),
            SkipReason::ProfileReparsePoint,
        ),
        (
            |os| os.profile = Err(OsError::NotAFile),
            SkipReason::ProfileNotAFile,
        ),
        (
            |os| os.profile = Ok(b"rerun-profile 2\n".to_vec()),
            SkipReason::ProfileInvalid,
        ),
        (
            |os| {
                let mut p = profile(Some(rule(Mode::Hard)), None);
                p.start = r"C:\Other\game.exe".to_owned();
                p.target = p.start.clone();
                os.profile = Ok(encode(&p).unwrap());
            },
            SkipReason::PathMismatch,
        ),
        (
            |os| os.topology = Err(OsError::Win32(5)),
            SkipReason::TopologyUnavailable,
        ),
        (
            |os| {
                os.topology = Ok(CpuTopology {
                    cpus: vec![],
                    llcs: vec![],
                });
            },
            SkipReason::TopologyInvalid,
        ),
        (
            |os| {
                let mut t = zen3();
                for c in &mut t.cpus {
                    c.index += 32;
                }
                let mut p = profile(Some(rule(Mode::Hard)), None);
                p.bitness = Bitness::X86;
                os.profile = Ok(encode(&p).unwrap());
                os.topology = Ok(t);
            },
            SkipReason::SelectionEmpty,
        ),
        (
            |os| os.spawns.borrow_mut().push_back(Err(1450)),
            SkipReason::SpawnFailed { code: 1450 },
        ),
        (
            |os| os.limit_job = Err(87),
            SkipReason::JobFailed { code: 87 },
        ),
        (
            |os| os.read_back = Some(Err(5)),
            SkipReason::ReadBackFailed { code: 5 },
        ),
        (
            |os| {
                os.read_back = Some(Ok(ReadBack {
                    job: vec![],
                    thread: CCD0_FIRST_THREADS,
                }));
            },
            SkipReason::Mismatch,
        ),
        (
            |os| os.resume = Err(6),
            SkipReason::ResumeFailed { code: 6 },
        ),
        (
            |os| {
                os.spawns
                    .borrow_mut()
                    .push_back(Err(ERROR_ELEVATION_REQUIRED));
            },
            SkipReason::ElevationRequired,
        ),
    ];
    for (set, reason) in cases {
        let mut os = fake(&profile(Some(rule(Mode::Hard)), None));
        set(&mut os);
        let r = run(&os);
        assert!(
            matches!(
                r,
                Report::Ran {
                    written: Written::Yes,
                    check: None,
                    ..
                }
            ),
            "{reason}"
        );
        let Outcome::Skipped {
            reason: got, start, ..
        } = written_one(&os).outcome
        else {
            panic!("{reason}: not skipped");
        };
        assert_eq!(got, reason);
        let want = if reason == SkipReason::ElevationRequired {
            result::Start::Shell
        } else {
            result::Start::Created
        };
        assert_eq!(start, want, "{reason}");
        // Written right before the wait for the game.
        let calls = os.calls();
        let w = calls
            .iter()
            .position(|c| matches!(c, Call::WriteResult(_)))
            .unwrap();
        assert!(matches!(calls[w + 1], Call::Wait(_)), "{reason}: {calls:?}");
        assert_eq!(w + 2, calls.len(), "{reason}");
    }
    // Soft mode: CPU Sets.
    let mut os = fake(&profile(Some(rule(Mode::Soft)), None));
    os.cpu_sets = Err(87);
    run(&os);
    assert!(matches!(
        written_one(&os).outcome,
        Outcome::Skipped {
            reason: SkipReason::CpuSetsFailed { code: 87 },
            ended: Some(Ended::Ended),
            ..
        }
    ));
}

#[test]
fn starts_and_ends_are_recorded() {
    // A failed unchanged start: written, no wait, exit 3.
    let os = FakeOs::new(&line_with(ID, &tail()));
    os.spawns.borrow_mut().extend([Err(2)]);
    assert_eq!(run(&os).exit_code(), 3);
    assert_eq!(
        written_one(&os).outcome,
        Outcome::Skipped {
            reason: SkipReason::ProfileMissing,
            start: result::Start::Failed { code: 2 },
            ended: None,
            priority_restore: None,
        }
    );
    // 740 to ShellExecuteExW without a process, and with a non-.exe argv[0].
    let mut os = FakeOs::new(&line_with(ID, &tail()));
    os.spawns
        .borrow_mut()
        .push_back(Err(ERROR_ELEVATION_REQUIRED));
    os.shell = Ok(false);
    run(&os);
    assert!(matches!(
        written_one(&os).outcome,
        Outcome::Skipped {
            start: result::Start::ShellNoProcess,
            ..
        }
    ));
    let os = FakeOs::new(&line_with(ID, r"C:\G\game.bat"));
    os.spawns
        .borrow_mut()
        .push_back(Err(ERROR_ELEVATION_REQUIRED));
    run(&os);
    assert!(matches!(
        written_one(&os).outcome,
        Outcome::Skipped {
            start: result::Start::NotExe,
            ..
        }
    ));
    // A child ended before the unchanged start: how it ended.
    for (t, e) in [
        (Terminated::Ended, Ended::Ended),
        (Terminated::Failed(5), Ended::Failed { code: 5 }),
        (
            Terminated::NotConfirmed(258),
            Ended::NotConfirmed { code: 258 },
        ),
    ] {
        let mut os = fake(&profile(Some(rule(Mode::Hard)), None));
        os.limit_job = Err(87);
        os.terminated = t;
        run(&os);
        assert!(matches!(
            written_one(&os).outcome,
            Outcome::Skipped { ended: Some(x), .. } if x == e
        ));
    }
}

#[test]
fn elevated_or_without_an_id_nothing_is_written() {
    let mut os = fake(&profile(Some(rule(Mode::Hard)), None));
    os.elevated = true;
    assert!(matches!(
        run(&os),
        Report::Ran {
            written: Written::No,
            ..
        }
    ));
    assert!(os.written.borrow().is_empty());
    // Elevated and 740: still nothing (B13).
    let mut os = FakeOs::new(&line_with(ID, &tail()));
    os.elevated = true;
    os.spawns
        .borrow_mut()
        .push_back(Err(ERROR_ELEVATION_REQUIRED));
    run(&os);
    assert!(os.written.borrow().is_empty());
    // No profile ID: no file name.
    let mut os = fake(&profile(None, None));
    os.line = line_with("NOT-AN-ID", &tail()).encode_utf16().collect();
    assert!(matches!(
        run(&os),
        Report::Ran {
            written: Written::No,
            ..
        }
    ));
    assert!(os.written.borrow().is_empty());
    // An unusable command line: nothing at all.
    let os = FakeOs::new(r"C:\R\rerun-launch.exe");
    run(&os);
    assert!(os.written.borrow().is_empty());
}

#[test]
fn a_failed_write_changes_neither_the_start_nor_the_exit_code() {
    for e in [OsError::Win32(5), OsError::ReparsePoint, OsError::Escaped] {
        let mut os = fake(&profile(Some(rule(Mode::Hard)), Some(Priority::High)));
        os.write = Err(e.clone());
        let r = run(&os);
        assert!(matches!(
            &r,
            Report::Ran {
                written: Written::Failed(x),
                exit: 42,
                start: Start::Created,
                ..
            } if *x == e
        ));
        assert_eq!(check_of(&r), Some(Check::Ok));
        assert_eq!(os.calls().last(), Some(&Call::Wait(1)));
        let mut os = fake(&profile(None, None));
        os.profile = Err(OsError::Win32(2));
        os.write = Err(e.clone());
        assert_eq!(run(&os).exit_code(), 42);
    }
}

/// Senior-dev B1: a game that narrows its own affinity within the job (an old engine pinning
/// itself to CPU 0) is `narrowed`, not a reset; a priority reset takes precedence.
#[test]
fn a_process_narrowed_within_the_job_is_narrowed() {
    for mask in [0x0001, 0x5554, 0x4000] {
        let mut os = fake(&profile(Some(rule(Mode::Hard)), None));
        os.process_affinity = Some(Ok(mask));
        assert_eq!(check_of(&run(&os)), Some(Check::Narrowed), "{mask:#x}");
        assert!(matches!(
            written_one(&os).outcome,
            Outcome::Applied {
                check: Check::Narrowed,
                ..
            }
        ));
    }
    let mut os = fake(&profile(Some(rule(Mode::Hard)), Some(Priority::High)));
    os.process_affinity = Some(Ok(0x0001));
    os.priority_class = Some(Ok(priority_class(Priority::Normal)));
    assert_eq!(
        check_of(&run(&os)),
        Some(Check::Reset {
            cpu: false,
            priority: true
        })
    );
}

/// Amendment P4-13: a format-2 profile (`exclude_first`) reaches the job as a mask without
/// bit 0; a selection that `exclude_first` empties starts the game unchanged and the result file
/// says `selection_empty`.
#[test]
fn exclude_first_from_a_format_2_profile() {
    use rerun_proto::cpu::rule::{ExcludeFirst, SelectError, SelectStep};
    use rerun_proto::cpu::{Llc, LogicalCpu};
    // `thread`, `max_threads: 8`, `single_l3`, `smt: false` on the 5950X shape: CPU 1 stands
    // in for core 0.
    let mut r = rule(Mode::Hard);
    r.exclude_first = Some(ExcludeFirst::Thread);
    let p = profile(Some(r), None);
    let bytes = encode(&p).unwrap();
    assert!(bytes.starts_with(b"rerun-profile 2\n"));
    let os = fake(&p);
    let _ = run(&os);
    let want = GroupAffinity {
        group: 0,
        mask: 0x5556,
    };
    assert!(
        os.calls().contains(&Call::LimitJob(1, want)),
        "{:?}",
        os.calls()
    );
    assert!(matches!(written_one(&os).outcome, Outcome::Applied { .. }));
    // One processor, CPU 0: nothing left after step 4b.
    let mut os = fake(&p);
    os.topology = Ok(CpuTopology {
        cpus: vec![LogicalCpu {
            cpu_set_id: 0x100,
            group: 0,
            index: 0,
            core: 0,
            llc: 0,
            efficiency_class: 0,
        }],
        llcs: vec![Llc {
            level: 3,
            size: 32 << 20,
        }],
    });
    let report = run(&os);
    assert!(
        matches!(
            &report,
            Report::Ran {
                rule: Rule::Skipped(Skip::Select(SelectError::Empty {
                    after: SelectStep::ExcludeFirst
                })),
                start: Start::Created,
                exit: 42,
                ..
            }
        ),
        "{report:?}"
    );
    assert!(
        !os.calls().iter().any(|c| matches!(c, Call::LimitJob(..))),
        "{:?}",
        os.calls()
    );
    let Outcome::Skipped { reason, start, .. } = written_one(&os).outcome else {
        panic!("not skipped");
    };
    assert_eq!(reason, SkipReason::SelectionEmpty);
    assert_eq!(start, result::Start::Created);
}
