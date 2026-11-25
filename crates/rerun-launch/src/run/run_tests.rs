//! [F] P5-OE (O-2a): the profile's `run` and `args` against `FakeOs` (ADR 0022 amendment
//! P5-OE): the M2 exception and nothing else, every D3 fallback on Steam's command, the result
//! lines `run=yes`, `run_failed` and `steam_start`.

use rerun_proto::cpu::rule::Mode;
use rerun_proto::launch::{self as result, Check, Outcome, SkipReason};
use rerun_proto::profile::{LaunchArg, LaunchProfile, Priority, encode};

use super::tests::{CCD0_FIRST_THREADS, GAME, ID, fake, id, line_with, profile, rule, tail};
use super::*;
use crate::cmdline;
use crate::fake::{Call, FakeOs};
use crate::os::Spawn;

/// The program the shim starts instead of `GAME`, in its folder.
const RUN: &str = r"C:\Games\My Game\game_dx9.exe";

fn w(s: &str) -> Vec<u16> {
    s.encode_utf16().collect()
}

fn st(u: &[u16]) -> String {
    String::from_utf16(u).unwrap()
}

fn args(a: &[&str]) -> Vec<LaunchArg> {
    a.iter().map(|s| LaunchArg::parse(s).unwrap()).collect()
}

/// `GAME`'s hard 8-thread profile with `run` (and `args`).
fn run_profile(a: &[&str]) -> LaunchProfile {
    LaunchProfile {
        target: RUN.to_owned(),
        run: Some(RUN.to_owned()),
        args: args(a),
        ..profile(Some(rule(Mode::Hard)), None)
    }
}

/// Steam's command after `argv[0]`: what `run` gets, byte for byte.
fn rest() -> String {
    tail()[GAME.len() + 2..].to_owned()
}

fn spawn_call(app: &str, line: &str, spawn: Spawn) -> Call {
    Call::Spawn {
        app: app.to_owned(),
        line: line.to_owned(),
        spawn,
    }
}

const IN_JOB: Spawn = Spawn {
    in_job: true,
    suspended: true,
    priority: None,
};

/// The one result file `os` wrote, decoded.
fn written_one(os: &FakeOs) -> result::LaunchResult {
    let w = os.written.borrow();
    assert_eq!(w.len(), 1, "{} result files", w.len());
    let r = result::decode(&w[0]).unwrap();
    assert_eq!(r.profile, id());
    r
}

fn reason(r: &result::LaunchResult) -> Option<SkipReason> {
    match &r.outcome {
        Outcome::Skipped { reason, .. } => Some(*reason),
        Outcome::Applied { .. } => None,
    }
}

/// The command line `line` parsed as the shim parses its own.
fn parse(line: &[u16]) -> Command<'_> {
    cmdline::parse(line).unwrap()
}

// ---------- with_run: the M2 exception, pure ----------

#[test]
fn with_run_keeps_the_raw_tail_after_argv0_byte_for_byte() {
    // Quoted argv[0] with quotes, spaces and % in the arguments.
    let line = w(&line_with(ID, &tail()));
    let c = with_run(&parse(&line), Some(RUN), &[]);
    assert_eq!(st(&c.app), RUN);
    assert_eq!(st(&c.line), format!(r#""{RUN}"{}"#, rest()));
    assert_eq!(rest(), r#" -window +set name "a b" 100%"#);
    assert_eq!(
        c.parameters.as_deref().map(st).as_deref(),
        Some(r#"-window +set name "a b" 100%"#)
    );
    assert!(c.run);
    for (steam, want) in [
        // Unquoted argv[0]: the rest starts at the blank that ended it.
        (r"C:\G\game.exe -dx9", format!(r#""{RUN}" -dx9"#)),
        // A quote right after the closing quote, tabs and trailing blanks stay.
        (r#""C:\G\game.exe"-x"#, format!(r#""{RUN}"-x"#)),
        ("\"C:\\G\\game.exe\"\t-a \t ", format!("\"{RUN}\"\t-a \t ")),
        // Nothing after argv[0].
        (r#""C:\G\game.exe""#, format!(r#""{RUN}""#)),
        (r"C:\G\game.exe", format!(r#""{RUN}""#)),
        // An unclosed quote runs to the end: argv[0] is all of it, nothing is left.
        (r#""C:\G\game.exe -x"#, format!(r#""{RUN}""#)),
    ] {
        let line = w(&line_with(ID, steam));
        let c = with_run(&parse(&line), Some(RUN), &[]);
        assert_eq!(st(&c.line), want, "{steam:?}");
        assert_eq!(st(&c.app), RUN);
    }
}

#[test]
fn with_run_appends_args_after_one_space() {
    let line = w(&line_with(ID, &tail()));
    let c = with_run(&parse(&line), Some(RUN), &args(&["-skipintro", "+fov=1.2"]));
    assert_eq!(
        st(&c.line),
        format!(r#""{RUN}"{} -skipintro +fov=1.2"#, rest())
    );
    assert_eq!(
        c.parameters.as_deref().map(st).as_deref(),
        Some(r#"-window +set name "a b" 100% -skipintro +fov=1.2"#)
    );
    // Without run: Steam's argv[0] and tail, the arguments after them.
    let c = with_run(&parse(&line), None, &args(&["-dx9"]));
    assert_eq!(st(&c.app), GAME);
    assert_eq!(st(&c.line), format!("{} -dx9", tail()));
    assert!(!c.run);
    // No parameters before: the arguments alone.
    let line = w(&line_with(ID, &format!(r#""{GAME}""#)));
    let c = with_run(&parse(&line), None, &args(&["-dx9"]));
    assert_eq!(c.parameters.as_deref().map(st).as_deref(), Some("-dx9"));
}

#[test]
fn with_run_without_run_or_args_is_steams_command() {
    let line = w(&line_with(ID, &tail()));
    let cmd = parse(&line);
    let c = with_run(&cmd, None, &[]);
    assert_eq!(c.app, cmd.app);
    assert_eq!(c.line, cmd.tail);
    assert_eq!(c.parameters.as_deref(), cmd.parameters);
    assert!(!c.run);
}

// ---------- decide: the gate of run is the gate of the rule ----------

#[test]
fn decide_starts_run_only_when_argv0_is_start() {
    let p = run_profile(&["-dx9"]);
    let os = fake(&p);
    let line = w(&line_with(ID, &tail()));
    match decide(&os, &parse(&line), &p) {
        Plan::Rule { launch, .. } => {
            assert!(launch.run);
            assert_eq!(st(&launch.app), RUN);
            assert_eq!(st(&launch.line), format!(r#""{RUN}"{} -dx9"#, rest()));
        }
        _ => panic!("no rule"),
    }
    // Steam starting run itself (or anything but start) is a path mismatch: no rule, no run.
    for steam in [
        format!(r#""{RUN}" -window"#),
        r#""C:\Games\My Game\launcher.exe""#.to_owned(),
    ] {
        let line = w(&line_with(ID, &steam));
        assert!(
            matches!(
                decide(&os, &parse(&line), &p),
                Plan::Unchanged(Skip::PathMismatch)
            ),
            "{steam}"
        );
    }
    // A rule that selects nothing: unchanged, never run.
    let mut os = fake(&p);
    os.topology = Err(OsError::Unsupported);
    let line = w(&line_with(ID, &tail()));
    assert!(matches!(
        decide(&os, &parse(&line), &p),
        Plan::Unchanged(Skip::Topology(_))
    ));
}

// ---------- the whole run ----------

#[test]
fn run_is_started_in_the_job_instead_of_steams_argv0() {
    let p = run_profile(&["-skipintro"]);
    let os = fake(&p);
    let r = run(&os);
    assert!(matches!(
        r,
        Report::Ran {
            rule: Rule::Applied { .. },
            start: Start::Created,
            exit: 42,
            ..
        }
    ));
    let line = format!(r#""{RUN}"{} -skipintro"#, rest());
    assert_eq!(
        os.calls(),
        [
            Call::ReadProfile(id()),
            Call::Topology,
            spawn_call(RUN, &line, IN_JOB),
            Call::LimitJob(1, CCD0_FIRST_THREADS),
            Call::ReadBack(1),
            Call::Resume(1),
            Call::WaitFor(1, CHECK_DELAY_MS),
            Call::JobAffinity(1),
            Call::ProcessAffinity(1),
            Call::WriteResult(id()),
            Call::Wait(1),
        ]
    );
    let res = written_one(&os);
    assert!(res.run);
    assert_eq!(res.method, Some(Method::Direct));
    assert!(matches!(
        res.outcome,
        Outcome::Applied {
            check: Check::Ok,
            ..
        }
    ));
    assert_eq!(res.steam_start, None);
}

#[test]
fn run_without_a_rule_still_starts_run_and_records_it() {
    let p = LaunchProfile {
        cpu: None,
        ..run_profile(&[])
    };
    let os = fake(&p);
    run(&os);
    let spawn = Spawn {
        in_job: false,
        suspended: false,
        priority: None,
    };
    assert_eq!(
        os.calls()[..2],
        [
            Call::ReadProfile(id()),
            spawn_call(RUN, &format!(r#""{RUN}"{}"#, rest()), spawn),
        ]
    );
    assert!(written_one(&os).run);
}

#[test]
fn a_run_that_cannot_start_falls_back_to_steams_command_unchanged() {
    let p = run_profile(&["-dx9"]);
    let os = fake(&p);
    os.spawns.borrow_mut().push_back(Err(2));
    let r = run(&os);
    assert!(matches!(
        r,
        Report::Ran {
            rule: Rule::Skipped(Skip::RunFailed(2)),
            start: Start::Created,
            exit: 42,
            ..
        }
    ));
    let calls = os.calls();
    assert_eq!(
        calls[2..4],
        [
            spawn_call(RUN, &format!(r#""{RUN}"{} -dx9"#, rest()), IN_JOB),
            // Steam's command exactly as Steam gave it: no run, no args, no job.
            spawn_call(GAME, &tail(), Spawn::UNCHANGED),
        ]
    );
    let res = written_one(&os);
    assert_eq!(reason(&res), Some(SkipReason::RunFailed { code: 2 }));
    assert!(!res.run);
    let text = String::from_utf8(os.written.borrow()[0].clone()).unwrap();
    assert!(text.contains("\nrule=skipped:run_failed:2\n"), "{text}");
}

#[test]
fn every_failure_after_run_started_falls_back_to_steams_command() {
    // The job of run cannot be limited: run is ended, Steam's command starts unchanged.
    let p = run_profile(&["-dx9"]);
    let mut os = fake(&p);
    os.limit_job = Err(5);
    run(&os);
    let calls = os.calls();
    assert_eq!(
        calls[2..6],
        [
            spawn_call(RUN, &format!(r#""{RUN}"{} -dx9"#, rest()), IN_JOB),
            Call::LimitJob(1, CCD0_FIRST_THREADS),
            Call::Terminate(1),
            spawn_call(GAME, &tail(), Spawn::UNCHANGED),
        ]
    );
    let res = written_one(&os);
    assert_eq!(reason(&res), Some(SkipReason::JobFailed { code: 5 }));
    assert!(!res.run);
}

#[test]
fn elevation_required_starts_run_through_the_shell_without_the_rule() {
    let p = run_profile(&["-dx9"]);
    let os = fake(&p);
    os.spawns
        .borrow_mut()
        .push_back(Err(ERROR_ELEVATION_REQUIRED));
    run(&os);
    assert_eq!(
        os.calls()[3],
        Call::Shell {
            file: RUN.to_owned(),
            parameters: Some(r#"-window +set name "a b" 100% -dx9"#.to_owned()),
        }
    );
    let res = written_one(&os);
    assert_eq!(reason(&res), Some(SkipReason::ElevationRequired));
    assert!(res.run);
    assert!(matches!(
        res.outcome,
        Outcome::Skipped {
            start: result::Start::Shell,
            ..
        }
    ));
}

#[test]
fn path_mismatch_starts_steams_command_and_records_its_file_name() {
    let p = run_profile(&["-dx9"]);
    let mut os = fake(&p);
    let steam = r#""C:\Games\My Game\launcher.exe" -x"#;
    os.line = w(&line_with(ID, steam));
    run(&os);
    assert_eq!(
        os.calls(),
        [
            Call::ReadProfile(id()),
            spawn_call(r"C:\Games\My Game\launcher.exe", steam, Spawn::UNCHANGED),
            Call::WriteResult(id()),
            Call::Wait(1),
        ]
    );
    let res = written_one(&os);
    assert_eq!(reason(&res), Some(SkipReason::PathMismatch));
    assert_eq!(res.steam_start.as_deref(), Some("launcher.exe"));
    assert!(!res.run);
    // Steam starting run directly is a mismatch too.
    let mut os = fake(&p);
    os.line = w(&line_with(ID, &format!(r#""{RUN}""#)));
    run(&os);
    assert_eq!(
        written_one(&os).steam_start.as_deref(),
        Some("game_dx9.exe")
    );
}

#[test]
fn a_steam_start_that_is_no_valid_name_is_left_out() {
    let p = profile(Some(rule(Mode::Hard)), None);
    for steam in [
        "\"C:\\Games\\a\u{202E}exe.txt\"",
        "\"C:\\Games\\a\tb.exe\"",
        "\"C:\\Games\\nul.exe\"",
        "\"C:\\Games\\a b.\"",
    ] {
        let mut os = fake(&p);
        os.line = w(&line_with(ID, steam));
        run(&os);
        let res = written_one(&os);
        assert_eq!(reason(&res), Some(SkipReason::PathMismatch), "{steam:?}");
        assert_eq!(res.steam_start, None, "{steam:?}");
    }
    // Longer than 255 UTF-16 units: left out; 255: kept.
    for (n, kept) in [(251, true), (252, false)] {
        let mut os = fake(&p);
        os.line = w(&line_with(ID, &format!(r#""C:\G\{}.exe""#, "a".repeat(n))));
        run(&os);
        assert_eq!(written_one(&os).steam_start.is_some(), kept, "{n}");
    }
}

#[test]
fn an_elevated_shim_never_starts_run() {
    let p = run_profile(&["-dx9"]);
    let mut os = fake(&p);
    os.elevated = true;
    run(&os);
    assert_eq!(
        os.calls(),
        [spawn_call(GAME, &tail(), Spawn::UNCHANGED), Call::Wait(1),]
    );
    assert!(os.written.borrow().is_empty());
}

#[test]
fn an_invalid_profile_never_starts_run() {
    // A run outside the folder of start: the codec refuses the profile (D3, profile_invalid).
    let mut text = String::from_utf8(encode(&run_profile(&[])).unwrap()).unwrap();
    text = text.replace(r"My Game\game_dx9.exe", r"My Game\bin\game_dx9.exe");
    let mut os = fake(&profile(None, Some(Priority::High)));
    os.profile = Ok(text.into_bytes());
    run(&os);
    assert_eq!(os.calls()[1], spawn_call(GAME, &tail(), Spawn::UNCHANGED));
    assert_eq!(reason(&written_one(&os)), Some(SkipReason::ProfileInvalid));
}

#[test]
fn args_without_run_go_to_steams_argv0_with_the_rule() {
    let p = LaunchProfile {
        args: args(&["-dx9"]),
        ..profile(Some(rule(Mode::Hard)), None)
    };
    let os = fake(&p);
    run(&os);
    assert_eq!(
        os.calls()[2],
        spawn_call(GAME, &format!("{} -dx9", tail()), IN_JOB)
    );
    assert!(!written_one(&os).run);
    // A spawn failure is spawn_failed (no run), and Steam's command starts without the args.
    let os = fake(&p);
    os.spawns.borrow_mut().push_back(Err(5));
    run(&os);
    assert_eq!(os.calls()[3], spawn_call(GAME, &tail(), Spawn::UNCHANGED));
    assert_eq!(
        reason(&written_one(&os)),
        Some(SkipReason::SpawnFailed { code: 5 })
    );
}
