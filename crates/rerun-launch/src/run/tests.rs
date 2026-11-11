//! [F] decision tests of `run` against `FakeOs` (ADR 0022, P3-1b).

use rerun_proto::cpu::rule::{Bitness, CpuRule, Mode, Prefer};
use rerun_proto::cpu::{CpuTopology, Llc, LogicalCpu};
use rerun_proto::profile::{LaunchProfile, Method, Priority, ProfileId, encode};

use super::*;
use crate::fake::{Call, FakeOs};
use crate::os::{GroupAffinity, OsError, ReadBack, Spawn, Terminated};

pub(super) const ID: &str = "0123456789abcdef0123456789abcdef";
pub(super) const GAME: &str = r"C:\Games\My Game\game.exe";
const OWN: &str = r#""C:\Program Files\Rerun\rerun-launch.exe" --profile "#;

/// Steam's quoted command with arguments.
pub(super) fn tail() -> String {
    format!(r#""{GAME}" -window +set name "a b" 100%"#)
}

pub(super) fn line_with(id: &str, tail: &str) -> String {
    format!("{OWN}{id} {tail}")
}

pub(super) fn id() -> ProfileId {
    ProfileId::from_hex(ID).unwrap()
}

/// A 5950X-shaped machine: group 0, 2 L3 x 8 cores x 2 threads, SMT siblings adjacent.
pub(super) fn zen3() -> CpuTopology {
    let cpus = (0u8..32)
        .map(|i| LogicalCpu {
            cpu_set_id: 0x100 + u32::from(i),
            group: 0,
            index: i,
            core: u32::from(i / 2),
            llc: u32::from(i / 16),
            efficiency_class: 0,
        })
        .collect();
    let l3 = Llc {
        level: 3,
        size: 32 << 20,
    };
    CpuTopology {
        cpus,
        llcs: vec![l3, l3],
    }
}

pub(super) fn rule(mode: Mode) -> CpuRule {
    CpuRule {
        max_threads: Some(8),
        prefer: Prefer::Performance,
        single_l3: true,
        prefer_l3: None,
        smt: false,
        mode,
        exclude_first: None,
    }
}

pub(super) fn profile(cpu: Option<CpuRule>, priority: Option<Priority>) -> LaunchProfile {
    LaunchProfile {
        method: Method::Direct,
        start: GAME.to_owned(),
        target: GAME.to_owned(),
        bitness: Bitness::X64,
        priority,
        watch_timeout_s: 120,
        cpu,
    }
}

/// A machine with a valid profile for `GAME` and the zen3 topology.
pub(super) fn fake(p: &LaunchProfile) -> FakeOs {
    let mut os = FakeOs::new(&line_with(ID, &tail()));
    os.profile = Ok(encode(p).unwrap());
    os.topology = Ok(zen3());
    os
}

/// CCD 0, first thread of each of its 8 cores (B5).
pub(super) const CCD0_FIRST_THREADS: GroupAffinity = GroupAffinity {
    group: 0,
    mask: 0x5555,
};

fn spawn_call(app: &str, line: &str, spawn: Spawn) -> Call {
    Call::Spawn {
        app: app.to_owned(),
        line: line.to_owned(),
        spawn,
    }
}

fn unchanged_spawn() -> Call {
    spawn_call(GAME, &tail(), Spawn::UNCHANGED)
}

fn ran(rule: Rule, start: Start, exit: u32) -> Report {
    Report::Ran {
        profile: None,
        rule,
        start,
        exit,
        terminated: None,
        check: None,
        priority_restore: None,
        written: Written::No,
    }
}

/// The report without the profile ID, the termination outcome, the check and the result file
/// (checked separately).
fn core(r: Report) -> Report {
    match r {
        Report::Ran {
            rule, start, exit, ..
        } => ran(rule, start, exit),
        u @ Report::Usage(_) => u,
    }
}

fn skipped(skip: Skip) -> Report {
    ran(Rule::Skipped(skip), Start::Created, 42)
}

#[test]
fn hard_rule_follows_the_b2_order() {
    let os = fake(&profile(Some(rule(Mode::Hard)), Some(Priority::High)));
    let r = core(run(&os));
    assert_eq!(
        r,
        ran(
            Rule::Applied {
                cpu: Some(Applied {
                    mode: Mode::Hard,
                    threads: 8,
                    of: 32
                }),
                priority: Some(Priority::High),
            },
            Start::Created,
            42
        )
    );
    assert_eq!(r.exit_code(), 42);
    let spawn = Spawn {
        in_job: true,
        suspended: true,
        priority: Some(Priority::High),
    };
    assert_eq!(
        os.calls(),
        [
            Call::ReadProfile(id()),
            Call::Topology,
            spawn_call(GAME, &tail(), spawn),
            Call::LimitJob(1, CCD0_FIRST_THREADS),
            Call::ReadBack(1),
            Call::Resume(1),
            Call::WaitFor(1, CHECK_DELAY_MS),
            Call::JobAffinity(1),
            Call::ProcessAffinity(1),
            Call::PriorityClass(1),
            Call::WriteResult(id()),
            Call::Wait(1),
        ]
    );
}

#[test]
fn soft_rule_sets_cpu_sets_on_the_suspended_child() {
    let os = fake(&profile(Some(rule(Mode::Soft)), None));
    let r = core(run(&os));
    assert!(matches!(
        r,
        Report::Ran {
            rule: Rule::Applied {
                cpu: Some(Applied {
                    mode: Mode::Soft,
                    threads: 8,
                    of: 32
                }),
                priority: None
            },
            start: Start::Created,
            exit: 42,
            ..
        }
    ));
    let ids: Vec<u32> = (0..8).map(|i| 0x100 + 2 * i).collect();
    let spawn = Spawn {
        in_job: false,
        suspended: true,
        priority: None,
    };
    assert_eq!(
        os.calls(),
        [
            Call::ReadProfile(id()),
            Call::Topology,
            spawn_call(GAME, &tail(), spawn),
            Call::CpuSets(1, ids),
            Call::Resume(1),
            Call::WaitFor(1, CHECK_DELAY_MS),
            Call::ReadCpuSets(1),
            Call::WriteResult(id()),
            Call::Wait(1),
        ]
    );
}

#[test]
fn priority_without_cpu_rule_reads_no_topology() {
    let os = fake(&profile(None, Some(Priority::AboveNormal)));
    let r = core(run(&os));
    assert_eq!(
        r,
        ran(
            Rule::Applied {
                cpu: None,
                priority: Some(Priority::AboveNormal)
            },
            Start::Created,
            42
        )
    );
    let spawn = Spawn {
        in_job: false,
        suspended: false,
        priority: Some(Priority::AboveNormal),
    };
    assert_eq!(
        os.calls(),
        [
            Call::ReadProfile(id()),
            spawn_call(GAME, &tail(), spawn),
            Call::WaitFor(1, CHECK_DELAY_MS),
            Call::PriorityClass(1),
            Call::WriteResult(id()),
            Call::Wait(1),
        ]
    );
}

#[test]
fn argv0_matches_start_case_insensitively_and_keeps_steams_spelling() {
    let steam = r"c:\games\MY GAME\Game.EXE";
    let mut os = fake(&profile(Some(rule(Mode::Hard)), None));
    let t = format!(r#""{steam}" -x"#);
    os.line = line_with(ID, &t).encode_utf16().collect();
    let r = core(run(&os));
    assert!(matches!(
        r,
        Report::Ran {
            rule: Rule::Applied { .. },
            ..
        }
    ));
    assert!(matches!(&os.calls()[2], Call::Spawn { app, line, .. } if app == steam && *line == t));
}

#[test]
fn profile_missing_starts_unchanged() {
    let mut os = fake(&profile(Some(rule(Mode::Hard)), Some(Priority::High)));
    os.profile = Err(OsError::Win32(2));
    assert_eq!(
        core(run(&os)),
        skipped(Skip::ProfileUnreadable(OsError::Win32(2)))
    );
    assert_eq!(
        os.calls(),
        [
            Call::ReadProfile(id()),
            unchanged_spawn(),
            Call::WriteResult(id()),
            Call::Wait(1)
        ]
    );
    // P3-4: no profile decoded, no `method=` line.
    let w = os.written.borrow().last().cloned().unwrap();
    assert_eq!(rerun_proto::launch::decode(&w).unwrap().method, None);
    assert!(!String::from_utf8(w).unwrap().contains("method="));
    os.calls.borrow_mut().clear();
    os.profile = Err(OsError::ReparsePoint);
    assert_eq!(
        core(run(&os)),
        skipped(Skip::ProfileUnreadable(OsError::ReparsePoint))
    );
}

#[test]
fn profile_broken_or_too_large_starts_unchanged() {
    let mut os = fake(&profile(Some(rule(Mode::Hard)), None));
    os.profile = Ok(b"rerun-profile 2\n".to_vec());
    assert!(matches!(
        core(run(&os)),
        Report::Ran {
            rule: Rule::Skipped(Skip::ProfileInvalid(Some(_))),
            start: Start::Created,
            exit: 42,
            ..
        }
    ));
    let mut big = encode(&profile(None, None)).unwrap();
    big.resize(MAX_PROFILE_BYTES + 1, b'x');
    os.profile = Ok(big);
    assert_eq!(core(run(&os)), skipped(Skip::ProfileInvalid(None)));
    // Never the topology, never a job.
    assert!(!os.calls().contains(&Call::Topology));
    assert!(
        os.calls()
            .iter()
            .all(|c| !matches!(c, Call::Spawn { spawn, .. } if *spawn != Spawn::UNCHANGED))
    );
}

#[test]
fn invalid_profile_token_reads_nothing() {
    for token in [
        "0123456789ABCDEF0123456789ABCDEF",
        "0123456789abcdef",
        "0123456789abcdef0123456789abcdef0",
        r"C:\Users\x\AppData\Local\Rerun\profiles\0123456789abcdef0123456789abcdef.profile",
        "\"0123456789abcdef0123456789abcdef\"",
    ] {
        let mut os = fake(&profile(Some(rule(Mode::Hard)), None));
        os.line = line_with(token, &tail()).encode_utf16().collect();
        assert_eq!(core(run(&os)), skipped(Skip::ProfileId), "{token}");
        assert_eq!(os.calls(), [unchanged_spawn(), Call::Wait(1)], "{token}");
    }
}

#[test]
fn path_mismatch_starts_unchanged() {
    let mut p = profile(Some(rule(Mode::Hard)), None);
    p.start = r"C:\Games\Other\game.exe".to_owned();
    p.target = p.start.clone();
    let os = fake(&p);
    assert_eq!(core(run(&os)), skipped(Skip::PathMismatch));
    assert_eq!(
        os.calls(),
        [
            Call::ReadProfile(id()),
            unchanged_spawn(),
            Call::WriteResult(id()),
            Call::Wait(1)
        ]
    );
}

#[test]
fn unquoted_path_with_spaces_is_a_mismatch_and_never_resolved_piece_by_piece() {
    let os = {
        let mut os = fake(&profile(Some(rule(Mode::Hard)), None));
        os.line = line_with(ID, &format!("{GAME} -x"))
            .encode_utf16()
            .collect();
        os
    };
    assert_eq!(core(run(&os)), skipped(Skip::PathMismatch));
    // lpApplicationName is argv[0] as Steam cut it, the command line the raw tail.
    assert_eq!(
        os.calls()[1],
        spawn_call(r"C:\Games\My", &format!("{GAME} -x"), Spawn::UNCHANGED)
    );
}

#[test]
fn elevated_shim_reads_nothing_and_sets_nothing() {
    let mut os = fake(&profile(Some(rule(Mode::Hard)), Some(Priority::High)));
    os.elevated = true;
    assert_eq!(core(run(&os)), skipped(Skip::Elevated));
    assert_eq!(os.calls(), [unchanged_spawn(), Call::Wait(1)]);
}

#[test]
fn topology_error_or_empty_selection_starts_unchanged() {
    let mut os = fake(&profile(Some(rule(Mode::Hard)), None));
    os.topology = Err(OsError::Win32(5));
    assert_eq!(core(run(&os)), skipped(Skip::Topology(OsError::Win32(5))));

    // An invalid topology: select refuses it.
    os.topology = Ok(CpuTopology {
        cpus: vec![],
        llcs: vec![],
    });
    assert!(matches!(
        core(run(&os)),
        Report::Ran {
            rule: Rule::Skipped(Skip::Select(SelectError::Invalid(_))),
            ..
        }
    ));

    // A 32-bit game on a group whose processors all have indices >= 32: empty after step 2.
    let mut t = zen3();
    for c in &mut t.cpus {
        c.index += 32;
    }
    let mut p = profile(Some(rule(Mode::Hard)), None);
    p.bitness = Bitness::X86;
    let mut os = fake(&p);
    os.topology = Ok(t);
    assert!(matches!(
        core(run(&os)),
        Report::Ran {
            rule: Rule::Skipped(Skip::Select(SelectError::Empty { .. })),
            start: Start::Created,
            exit: 42,
            ..
        }
    ));
    assert_eq!(os.calls().last(), Some(&Call::Wait(1)));
    assert_eq!(os.calls()[2], unchanged_spawn());
}

#[test]
fn read_back_difference_ends_the_child_and_starts_unchanged() {
    let other = GroupAffinity {
        group: 0,
        mask: 0x5554,
    };
    for back in [
        ReadBack {
            job: vec![CCD0_FIRST_THREADS, CCD0_FIRST_THREADS],
            thread: CCD0_FIRST_THREADS,
        },
        ReadBack {
            job: vec![],
            thread: CCD0_FIRST_THREADS,
        },
        ReadBack {
            job: vec![other],
            thread: CCD0_FIRST_THREADS,
        },
        ReadBack {
            job: vec![CCD0_FIRST_THREADS],
            thread: other,
        },
        ReadBack {
            job: vec![CCD0_FIRST_THREADS],
            thread: GroupAffinity {
                group: 1,
                mask: 0x5555,
            },
        },
    ] {
        let mut os = fake(&profile(Some(rule(Mode::Hard)), Some(Priority::High)));
        os.read_back = Some(Ok(back.clone()));
        assert_eq!(core(run(&os)), skipped(Skip::Mismatch), "{back:?}");
        let calls = os.calls();
        assert_eq!(
            calls[3..],
            [
                Call::LimitJob(1, CCD0_FIRST_THREADS),
                Call::ReadBack(1),
                Call::Terminate(1),
                unchanged_spawn(),
                Call::WriteResult(id()),
                Call::Wait(2),
            ]
        );
    }
}

#[test]
fn every_failure_after_the_spawn_ends_the_child_and_starts_unchanged() {
    let base = || fake(&profile(Some(rule(Mode::Hard)), None));

    let mut os = base();
    os.limit_job = Err(87);
    assert_eq!(core(run(&os)), skipped(Skip::Job(87)));
    assert_eq!(
        os.calls()[3..],
        [
            Call::LimitJob(1, CCD0_FIRST_THREADS),
            Call::Terminate(1),
            unchanged_spawn(),
            Call::WriteResult(id()),
            Call::Wait(2)
        ]
    );

    let mut os = base();
    os.read_back = Some(Err(5));
    assert_eq!(core(run(&os)), skipped(Skip::ReadBack(5)));
    assert!(os.calls().contains(&Call::Terminate(1)));

    let mut os = base();
    os.resume = Err(6);
    assert_eq!(core(run(&os)), skipped(Skip::Resume(6)));
    assert_eq!(
        os.calls()[5..],
        [
            Call::Resume(1),
            Call::Terminate(1),
            unchanged_spawn(),
            Call::WriteResult(id()),
            Call::Wait(2)
        ]
    );

    let mut os = fake(&profile(Some(rule(Mode::Soft)), None));
    os.cpu_sets = Err(87);
    assert_eq!(core(run(&os)), skipped(Skip::CpuSets(87)));
    assert_eq!(
        os.calls()[4..],
        [
            Call::Terminate(1),
            unchanged_spawn(),
            Call::WriteResult(id()),
            Call::Wait(2)
        ]
    );
}

#[test]
fn spawn_failure_with_the_rule_retries_unchanged_once() {
    let os = fake(&profile(Some(rule(Mode::Hard)), None));
    os.spawns.borrow_mut().extend([Err(1450), Ok(())]);
    assert_eq!(core(run(&os)), skipped(Skip::Spawn(1450)));
    assert_eq!(
        os.calls()[3..],
        [unchanged_spawn(), Call::WriteResult(id()), Call::Wait(1)]
    );

    let os = fake(&profile(Some(rule(Mode::Hard)), None));
    os.spawns.borrow_mut().extend([Err(2), Err(2)]);
    let r = core(run(&os));
    assert_eq!(
        r,
        ran(
            Rule::Skipped(Skip::Spawn(2)),
            Start::Failed(2),
            EXIT_NOT_STARTED
        )
    );
    assert_eq!(r.exit_code(), 3);
    assert!(!os.calls().iter().any(|c| matches!(c, Call::Wait(_))));
}

#[test]
fn elevation_required_goes_to_shell_execute_without_a_rule() {
    let os = fake(&profile(Some(rule(Mode::Hard)), Some(Priority::High)));
    os.spawns
        .borrow_mut()
        .push_back(Err(ERROR_ELEVATION_REQUIRED));
    assert_eq!(
        core(run(&os)),
        ran(
            Rule::Skipped(Skip::ElevationRequired),
            Start::ShellExecuted,
            42
        )
    );
    assert_eq!(
        os.calls()[3..],
        [
            Call::Shell {
                file: GAME.to_owned(),
                parameters: Some(r#"-window +set name "a b" 100%"#.to_owned()),
            },
            Call::WriteResult(id()),
            Call::Wait(1),
        ]
    );
}

#[test]
fn elevation_required_on_the_unchanged_start_too() {
    // Profile missing: the unchanged start gets 740.
    let os = FakeOs::new(&line_with(ID, &tail()));
    os.spawns
        .borrow_mut()
        .push_back(Err(ERROR_ELEVATION_REQUIRED));
    let r = core(run(&os));
    assert!(matches!(
        r,
        Report::Ran {
            rule: Rule::Skipped(Skip::ProfileUnreadable(_)),
            start: Start::ShellExecuted,
            exit: 42,
            ..
        }
    ));
    // Elevated shim: still the fallback, still no profile read.
    let mut os = FakeOs::new(&line_with(ID, &tail()));
    os.elevated = true;
    os.spawns
        .borrow_mut()
        .push_back(Err(ERROR_ELEVATION_REQUIRED));
    assert_eq!(
        core(run(&os)),
        ran(Rule::Skipped(Skip::Elevated), Start::ShellExecuted, 42)
    );
    assert!(!os.calls().iter().any(|c| matches!(c, Call::ReadProfile(_))));
}

#[test]
fn shell_execute_quoting_cases() {
    let cases: [(&str, &str, Option<&str>); 5] = [
        (r#""C:\G\game.exe""#, r"C:\G\game.exe", None),
        (r#""C:\G\game.exe"   "#, r"C:\G\game.exe", None),
        (r"C:\G\game.exe -a -b ", r"C:\G\game.exe", Some("-a -b ")),
        (
            "\"C:\\G\\game.exe\"\t\"%x%\" \"q\"",
            r"C:\G\game.exe",
            Some("\"%x%\" \"q\""),
        ),
        (
            r"C:\Program Files\G\game.exe",
            r"C:\Program",
            Some(r"Files\G\game.exe"),
        ),
    ];
    for (t, file, params) in cases {
        let os = FakeOs::new(&line_with(ID, t));
        os.spawns
            .borrow_mut()
            .push_back(Err(ERROR_ELEVATION_REQUIRED));
        let r = core(run(&os));
        if file.ends_with(".exe") {
            assert_eq!(
                os.calls()[2],
                Call::Shell {
                    file: file.to_owned(),
                    parameters: params.map(str::to_owned)
                },
                "{t}"
            );
            assert_eq!(os.calls()[1], spawn_call(file, t, Spawn::UNCHANGED), "{t}");
        } else {
            // Not an .exe: nothing is started.
            assert!(
                matches!(
                    r,
                    Report::Ran {
                        start: Start::NotExe,
                        exit: 3,
                        ..
                    }
                ),
                "{t}"
            );
            assert_eq!(os.calls().len(), 3, "{t}");
            assert_eq!(os.calls()[2], Call::WriteResult(id()), "{t}");
        }
    }
}

#[test]
fn shell_execute_failure_or_no_process() {
    let mut os = FakeOs::new(&line_with(ID, &tail()));
    os.spawns
        .borrow_mut()
        .push_back(Err(ERROR_ELEVATION_REQUIRED));
    os.shell = Err(1223);
    assert!(matches!(
        core(run(&os)),
        Report::Ran {
            start: Start::Failed(1223),
            exit: 3,
            ..
        }
    ));
    let mut os = FakeOs::new(&line_with(ID, &tail()));
    os.spawns
        .borrow_mut()
        .push_back(Err(ERROR_ELEVATION_REQUIRED));
    os.shell = Ok(false);
    assert!(matches!(
        core(run(&os)),
        Report::Ran {
            start: Start::ShellWithoutProcess,
            exit: 0,
            ..
        }
    ));
}

#[test]
fn wait_failure_is_exit_3() {
    let mut os = fake(&profile(None, None));
    os.wait = Err(6);
    assert_eq!(
        core(run(&os)),
        ran(
            Rule::Applied {
                cpu: None,
                priority: None
            },
            Start::WaitFailed(6),
            3
        )
    );
}

#[test]
fn the_tail_is_passed_byte_for_byte() {
    for t in [
        r#""C:\Games\My Game\game.exe""#,
        r#""C:\Games\My Game\game.exe" -a "b c" %command% 50%"#,
        "\"C:\\Games\\My Game\\game.exe\" -x\t \t",
        r"C:\Games\game.exe -x",
        r#""C:\Games\My Game\game.exe"-x"#,
    ] {
        let os = FakeOs::new(&line_with(ID, t));
        core(run(&os));
        assert!(
            matches!(&os.calls()[1], Call::Spawn { line, .. } if line == t),
            "{t}"
        );
    }
}

#[test]
fn unusable_command_lines_start_nothing() {
    for (line, want) in [
        (r"C:\R\rerun-launch.exe".to_owned(), Usage::NoProfileOption),
        (
            format!(r#"C:\R\rerun-launch.exe "{GAME}""#),
            Usage::NoProfileOption,
        ),
        (
            r"C:\R\rerun-launch.exe --profile".to_owned(),
            Usage::NoProfileToken,
        ),
        (
            format!(r"C:\R\rerun-launch.exe --profile {ID}"),
            Usage::NoCommand,
        ),
        (
            format!(r"C:\R\rerun-launch.exe --profile {ID}   "),
            Usage::NoCommand,
        ),
        (
            format!(r"C:\R\rerun-launch.exe --profile {ID} game.exe -x"),
            Usage::NotAbsolute,
        ),
        (
            format!(r#"C:\R\rerun-launch.exe --profile {ID} "\\srv\s\g.exe""#),
            Usage::NotAbsolute,
        ),
    ] {
        let os = FakeOs::new(&line);
        let r = core(run(&os));
        assert_eq!(r, Report::Usage(want), "{line}");
        assert_eq!(r.exit_code(), EXIT_USAGE);
        assert!(os.calls().is_empty(), "{line}");
    }
}

#[test]
fn the_report_names_the_profile_id_when_the_token_is_one() {
    let os = fake(&profile(Some(rule(Mode::Hard)), None));
    assert!(matches!(run(&os), Report::Ran { profile: Some(p), .. } if p == id()));
    // Elevated: the ID is still named (the shim writes nothing anyway, B13).
    let mut os = fake(&profile(None, None));
    os.elevated = true;
    assert!(matches!(
        run(&os),
        Report::Ran {
            profile: Some(_),
            ..
        }
    ));
    let mut os = fake(&profile(None, None));
    os.line = line_with("NOT-AN-ID", &tail()).encode_utf16().collect();
    assert!(matches!(run(&os), Report::Ran { profile: None, .. }));
}

#[test]
fn the_termination_outcome_is_reported_and_the_start_stays_fail_open() {
    let os = fake(&profile(Some(rule(Mode::Hard)), None));
    assert!(matches!(
        run(&os),
        Report::Ran {
            terminated: None,
            ..
        }
    ));
    for t in [
        Terminated::Ended,
        Terminated::Failed(5),
        Terminated::NotConfirmed(258),
    ] {
        let mut os = fake(&profile(Some(rule(Mode::Hard)), None));
        os.limit_job = Err(87);
        os.terminated = t;
        let r = run(&os);
        assert!(
            matches!(r, Report::Ran { terminated: Some(x), start: Start::Created, exit: 42, .. } if x == t),
            "{t:?}"
        );
        assert_eq!(os.calls().last(), Some(&Call::Wait(2)));
    }
}
