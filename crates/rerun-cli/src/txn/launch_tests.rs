//! The launch results in `rerun status` (P3-2): golden lines for every outcome, the date, the
//! escaped reason of an unreadable file, and nothing for an empty or missing folder; C-LW2
//! (P3-4c) every reason only `watch` writes, the failed priority restore, the escaped target.

use rerun_core::escape;
use rerun_core::exec::launch_result::{
    AppliedCpu, Check, Ended, LaunchResult, Mode, Outcome, Priority, ProfileId, SkipReason, Start,
};
use rerun_core::exec::{LaunchEntry, LaunchResults};
use rerun_core::policy::root::RootError;
use rerun_core::sys::{SysError, SysErrorKind};

use super::launch_lines;
use crate::messages::{Message, Utc};
use crate::out::Out;

fn shown(ms: &[Message<'_>]) -> String {
    let mut out = Out::new(Vec::new());
    out.lines(ms).unwrap();
    String::from_utf8(out.into_inner()).unwrap()
}

fn id(b: u8) -> ProfileId {
    ProfileId([b; 16])
}

fn entry(b: u8, outcome: Outcome) -> LaunchEntry {
    LaunchEntry {
        id: id(b),
        result: Ok(LaunchResult {
            profile: id(b),
            unix_s: 1_762_600_000,
            outcome,
            method: None,
        }),
    }
}

const HARD: Option<AppliedCpu> = Some(AppliedCpu {
    mode: Mode::Hard,
    threads: 8,
    of: 32,
});

fn applied(cpu: Option<AppliedCpu>, priority: Option<Priority>, check: Check) -> Outcome {
    Outcome::Applied {
        cpu,
        priority,
        check,
    }
}

#[test]
fn utc_dates() {
    assert_eq!(Utc(0).to_string(), "1970-01-01 00:00:00 UTC");
    assert_eq!(Utc(1_762_600_000).to_string(), "2025-11-08 11:06:40 UTC");
    assert_eq!(Utc(951_782_400).to_string(), "2000-02-29 00:00:00 UTC");
    assert_eq!(Utc(4_107_542_400).to_string(), "2100-03-01 00:00:00 UTC");
    assert_eq!(Utc(253_402_300_799).to_string(), "9999-12-31 23:59:59 UTC");
    assert_eq!(
        Utc(u64::MAX).to_string(),
        "18446744073709551615 s after 1970"
    );
}

#[test]
fn every_outcome_has_its_line() {
    let soft = Some(AppliedCpu {
        mode: Mode::Soft,
        threads: 4,
        of: 16,
    });
    let r = LaunchResults {
        entries: vec![
            entry(0x01, applied(HARD, Some(Priority::High), Check::Ok)),
            entry(0x02, applied(soft, None, Check::Ok)),
            entry(0x03, applied(None, Some(Priority::AboveNormal), Check::Ok)),
            entry(0x04, applied(None, None, Check::Ok)),
            entry(
                0x05,
                applied(
                    HARD,
                    Some(Priority::Normal),
                    Check::Reset {
                        cpu: true,
                        priority: true,
                    },
                ),
            ),
            entry(
                0x06,
                applied(
                    HARD,
                    None,
                    Check::Reset {
                        cpu: true,
                        priority: false,
                    },
                ),
            ),
            entry(0x07, applied(HARD, None, Check::ExitedEarly)),
            entry(0x08, applied(HARD, None, Check::Failed { code: 5 })),
            entry(
                0x09,
                Outcome::Skipped {
                    reason: SkipReason::PathMismatch,
                    start: Start::Created,
                    ended: None,
                    priority_restore: None,
                },
            ),
            entry(
                0x0a,
                Outcome::Skipped {
                    reason: SkipReason::JobFailed { code: 87 },
                    start: Start::Created,
                    ended: Some(Ended::Ended),
                    priority_restore: None,
                },
            ),
            entry(
                0x0b,
                Outcome::Skipped {
                    reason: SkipReason::ElevationRequired,
                    start: Start::Shell,
                    ended: None,
                    priority_restore: None,
                },
            ),
            entry(
                0x0c,
                Outcome::Skipped {
                    reason: SkipReason::ProfileMissing,
                    start: Start::Failed { code: 2 },
                    ended: None,
                    priority_restore: None,
                },
            ),
            LaunchEntry {
                id: id(0x0d),
                result: Err(escape::text("launch result line 2: control character").into_owned()),
            },
        ],
        other: 1,
    };
    let at = "2025-11-08 11:06:40 UTC";
    let p = |b: u8| id(b).to_string();
    let want = [
        String::new(),
        "last start per launch profile (rerun-launch):".to_owned(),
        format!(
            "  {}, {at}: ok, verified: 8 of 32 threads (hard), priority high",
            p(1)
        ),
        format!(
            "  {}, {at}: ok, verified: 4 of 16 threads (soft) (CPU Sets of the started process only)",
            p(2)
        ),
        format!("  {}, {at}: ok, verified: priority above normal", p(3)),
        format!("  {}, {at}: ok, verified: no CPU rule, no priority", p(4)),
        format!(
            "  {}, {at}: reset, the affinity and priority changed after the start (set: 8 of 32 threads (hard), priority normal)",
            p(5)
        ),
        format!(
            "  {}, {at}: reset, the affinity changed after the start (set: 8 of 32 threads (hard))",
            p(6)
        ),
        format!(
            "  {}, {at}: exited_early, the started process ended within 5 s, before the check (set: 8 of 32 threads (hard); it crashed, or it is a launcher that starts the game as another process)",
            p(7)
        ),
        format!(
            "  {}, {at}: check failed (Win32 error 5), set: 8 of 32 threads (hard)",
            p(8)
        ),
        format!(
            "  {}, {at}: rule_skipped: path_mismatch, the game started unchanged",
            p(9)
        ),
        format!(
            "  {}, {at}: rule_skipped: job_failed:87, the game started unchanged; the suspended child with the rule was ended first",
            p(10)
        ),
        format!(
            "  {}, {at}: rule_skipped: elevation_required, the game started unchanged through the shell (administrator prompt)",
            p(11)
        ),
        format!(
            "  {}, {at}: rule_skipped: profile_missing, nothing started (Win32 error 2)",
            p(12)
        ),
        // A7: the launch option still starts the game through the shim.
        format!(
            "    the launch option with --profile {} was still set in Steam at that start; remove it (the game starts unchanged through it)",
            p(12)
        ),
        format!(
            "  {}: unreadable: launch result line 2: control character",
            p(13)
        ),
        "  1 other entry in the launch folder not Rerun's (not read)".to_owned(),
    ];
    assert_eq!(
        shown(&launch_lines(&Ok(Some(r)), &[])),
        want.join("\n") + "\n"
    );
}

#[test]
fn nothing_without_results_and_one_line_for_an_unreadable_folder() {
    assert!(launch_lines(&Ok(None), &[]).is_empty());
    let empty = LaunchResults {
        entries: Vec::new(),
        other: 0,
    };
    assert!(launch_lines(&Ok(Some(empty)), &[]).is_empty());
    // A reason with a terminal escape is shown escaped.
    let bad = LaunchResults {
        entries: vec![LaunchEntry {
            id: id(1),
            result: Err(escape::text("x\u{1b}[31m").into_owned()),
        }],
        other: 0,
    };
    let s = shown(&launch_lines(&Ok(Some(bad)), &[]));
    assert!(!s.contains('\u{1b}'), "{s}");
    let e = RootError::Sys(SysError::new(SysErrorKind::TooLarge, "launch"));
    let s = shown(&launch_lines(&Err(e), &[]));
    assert!(s.starts_with("\nlaunch results cannot be read: "), "{s}");
}

#[test]
fn a_narrowed_affinity_is_explained_not_an_error() {
    let r = LaunchResults {
        entries: vec![entry(0x01, applied(HARD, None, Check::Narrowed))],
        other: 0,
    };
    assert_eq!(
        shown(&launch_lines(&Ok(Some(r)), &[])),
        format!(
            "\nlast start per launch profile (rerun-launch):\n  {}, 2025-11-08 11:06:40 UTC: \
             narrowed, the game limited itself to fewer threads within the rule (set: 8 of 32 \
             threads (hard); not an error, the rule holds)\n",
            id(1)
        )
    );
}

fn skipped(reason: SkipReason, restore: Option<u32>) -> Outcome {
    Outcome::Skipped {
        reason,
        start: Start::Created,
        ended: None,
        priority_restore: restore,
    }
}

/// C-LW2 (P3-4c, plan `P3-4` §7.5): every reason only `watch` writes is explained on its line,
/// with "Steam's command started unchanged"; a failed priority restore has its own line; without
/// a transaction that holds the profile no target line (the method is not known).
#[test]
fn every_watch_reason_has_its_line() {
    let r = LaunchResults {
        entries: vec![
            entry(0x01, skipped(SkipReason::TargetNotFound, None)),
            entry(0x02, skipped(SkipReason::TargetElevated, None)),
            entry(0x03, skipped(SkipReason::TargetDenied { code: 5 }, None)),
            entry(0x04, skipped(SkipReason::SearchFailed { code: 6 }, None)),
            entry(0x05, skipped(SkipReason::PriorityFailed { code: 5 }, None)),
            entry(0x06, skipped(SkipReason::JobIneffective, None)),
            entry(0x07, skipped(SkipReason::JobIneffective, Some(5))),
            entry(
                0x08,
                skipped(SkipReason::CpuSetsFailed { code: 87 }, Some(6)),
            ),
            entry(0x09, skipped(SkipReason::ReadBackFailed { code: 31 }, None)),
            entry(0x0a, skipped(SkipReason::MethodUnsupported, None)),
            // S2: a read-back failure known as `watch` (here by its restore line, N1).
            entry(
                0x0b,
                skipped(SkipReason::ReadBackFailed { code: 31 }, Some(5)),
            ),
        ],
        other: 0,
    };
    let at = "2025-11-08 11:06:40 UTC";
    let p = |b: u8| id(b).to_string();
    let steam = "Steam's command started unchanged";
    let want = [
        String::new(),
        "last start per launch profile (rerun-launch):".to_owned(),
        format!(
            "  {}, {at}: rule_skipped: target_not_found, no new game process appeared within the 120 s search (a launcher waiting for a login or an update: start the game again; a game that is itself the program Steam starts and does not start itself again: use method direct); {steam}",
            p(1)
        ),
        format!(
            "  {}, {at}: rule_skipped: target_elevated, the game process runs as administrator, or was started by a launcher that does; rerun-launch leaves it alone; {steam}",
            p(2)
        ),
        format!(
            "  {}, {at}: rule_skipped: target_denied:5, a process of the game's name could not be opened or read (Win32 error 5: protected or anti-cheat, another account, or possibly running as administrator); nothing was set (if the game itself never appeared, e.g. a launcher waiting for a login or an update: start the game again); {steam}",
            p(3)
        ),
        format!(
            "  {}, {at}: rule_skipped: search_failed:6, no game process could be looked for (Win32 error 6: the process list, or rerun-launch's own process information before the search, could not be read, or the program Steam started could not be identified); nothing was set; {steam}",
            p(4)
        ),
        format!(
            "  {}, {at}: rule_skipped: priority_failed:5, the priority class of the game process could not be read or set (Win32 error 5); nothing was set; {steam}",
            p(5)
        ),
        format!(
            "  {}, {at}: rule_skipped: job_ineffective, the game process joined the job but kept another limit (a job it was already in, e.g. a launcher's); the job stays without effect until the game exits; any priority class set on it was put back; {steam}",
            p(6)
        ),
        format!(
            "  {}, {at}: rule_skipped: job_ineffective, the game process joined the job but kept another limit (a job it was already in, e.g. a launcher's); the job stays without effect until the game exits; {steam}",
            p(7)
        ),
        "    the priority class set on the game process could not be put back (Win32 error 5); it stays until the game exits".to_owned(),
        // A CPU failure `direct` writes too; the restore line marks it as `watch` (N1).
        format!(
            "  {}, {at}: rule_skipped: cpu_sets_failed:87, {steam}",
            p(8)
        ),
        "    the priority class set on the game process could not be put back (Win32 error 6); it stays until the game exits".to_owned(),
        format!(
            "  {}, {at}: rule_skipped: read_back_failed:31, the game started unchanged",
            p(9)
        ),
        format!(
            "  {}, {at}: rule_skipped: method_unsupported, written by an older rerun-launch without method watch; the game started unchanged",
            p(10)
        ),
        // S2: the game joined the job; no "started unchanged".
        format!(
            "  {}, {at}: rule_skipped: read_back_failed:31, the game process joined a job with the selection, but it could not be read back (Win32 error 31); the limit may apply until the game exits",
            p(11)
        ),
        "    the priority class set on the game process could not be put back (Win32 error 5); it stays until the game exits".to_owned(),
    ];
    assert_eq!(
        shown(&launch_lines(&Ok(Some(r)), &[])),
        want.join("\n") + "\n"
    );
}

/// The target of a `watch` profile is escaped and last on its line; `ok` with a soft rule says
/// the soft check is unproven there.
#[test]
fn the_watch_lines_escape_the_target() {
    use crate::messages::LaunchMsg;
    let bad = "D:\\G\u{202e}exe.\\x\u{1b}[2J.exe";
    let lines = vec![
        Message::Launch(LaunchMsg::Applied {
            id: id(1),
            at: Utc(1_762_600_000),
            cpu: Some(AppliedCpu {
                mode: Mode::Soft,
                threads: 4,
                of: 16,
            }),
            priority: None,
            check: Check::Ok,
            watch: true,
        }),
        Message::Launch(LaunchMsg::Watched {
            target: escape::path(bad),
        }),
    ];
    let t = shown(&lines);
    assert!(!t.contains('\u{1b}') && !t.contains('\u{202e}'), "{t}");
    let l: Vec<&str> = t.lines().collect();
    assert!(
        l[0].ends_with("ok, verified: 4 of 16 threads (soft) (CPU Sets of the game process only; whether threads already running follow them is unproven)"),
        "{t}"
    );
    assert!(
        l[1].starts_with("    method watch: the rule is for the game process found after the start, not the program Steam starts: \""),
        "{t}"
    );
    assert!(l[1].ends_with('"'), "untrusted text last: {t}");
}
