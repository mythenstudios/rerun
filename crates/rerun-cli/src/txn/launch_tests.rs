//! The launch results in `rerun status` (P3-2): golden lines for every outcome, the date, the
//! escaped reason of an unreadable file, and nothing for an empty or missing folder.

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
                },
            ),
            entry(
                0x0a,
                Outcome::Skipped {
                    reason: SkipReason::JobFailed { code: 87 },
                    start: Start::Created,
                    ended: Some(Ended::Ended),
                },
            ),
            entry(
                0x0b,
                Outcome::Skipped {
                    reason: SkipReason::ElevationRequired,
                    start: Start::Shell,
                    ended: None,
                },
            ),
            entry(
                0x0c,
                Outcome::Skipped {
                    reason: SkipReason::ProfileMissing,
                    start: Start::Failed { code: 2 },
                    ended: None,
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
        format!("  {}, {at}: ok, verified: 4 of 16 threads (soft)", p(2)),
        format!("  {}, {at}: ok, verified: priority above normal", p(3)),
        format!("  {}, {at}: ok, verified: no CPU rule, no priority", p(4)),
        format!(
            "  {}, {at}: reset, the affinity and priority changed after the start (set: 8 of 32 threads (hard), priority normal; method hold or ifeo would keep it)",
            p(5)
        ),
        format!(
            "  {}, {at}: reset, the affinity changed after the start (set: 8 of 32 threads (hard); method hold or ifeo would keep it)",
            p(6)
        ),
        format!(
            "  {}, {at}: exited_early, the started process ended before the check (set: 8 of 32 threads (hard); a launcher stub needs method watch)",
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
        format!(
            "  {}: unreadable: launch result line 2: control character",
            p(13)
        ),
        "  1 other entry in the launch folder not Rerun's (not read)".to_owned(),
    ];
    assert_eq!(shown(&launch_lines(&Ok(Some(r)))), want.join("\n") + "\n");
}

#[test]
fn nothing_without_results_and_one_line_for_an_unreadable_folder() {
    assert!(launch_lines(&Ok(None)).is_empty());
    let empty = LaunchResults {
        entries: Vec::new(),
        other: 0,
    };
    assert!(launch_lines(&Ok(Some(empty))).is_empty());
    // A reason with a terminal escape is shown escaped.
    let bad = LaunchResults {
        entries: vec![LaunchEntry {
            id: id(1),
            result: Err(escape::text("x\u{1b}[31m").into_owned()),
        }],
        other: 0,
    };
    let s = shown(&launch_lines(&Ok(Some(bad))));
    assert!(!s.contains('\u{1b}'), "{s}");
    let e = RootError::Sys(SysError::new(SysErrorKind::TooLarge, "launch"));
    let s = shown(&launch_lines(&Err(e)));
    assert!(s.starts_with("\nlaunch results cannot be read: "), "{s}");
}
