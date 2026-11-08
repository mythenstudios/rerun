#![allow(
    clippy::unwrap_used,
    reason = "test code: a failure should abort the test"
)]

use super::*;

const ID: &str = "0123456789abcdef0123456789abcdef";

fn id() -> ProfileId {
    ProfileId::from_hex(ID).unwrap()
}

fn ok() -> LaunchResult {
    LaunchResult {
        profile: id(),
        unix_s: 1_762_600_000,
        outcome: Outcome::Applied {
            cpu: Some(AppliedCpu {
                mode: Mode::Hard,
                threads: 8,
                of: 32,
            }),
            priority: None,
            check: Check::Ok,
        },
    }
}

const GOLDEN: &str = "rerun-result 1
profile=0123456789abcdef0123456789abcdef
time=1762600000
rule=applied
cpu=hard:8:32
priority=none
check=ok
start=created
rule_child=none
";

const GOLDEN_SKIPPED: &str = "rerun-result 1
profile=0123456789abcdef0123456789abcdef
time=0
rule=skipped:job_failed:87
cpu=none
priority=none
check=none
start=created
rule_child=not_confirmed:258
";

fn skipped() -> LaunchResult {
    LaunchResult {
        profile: id(),
        unix_s: 0,
        outcome: Outcome::Skipped {
            reason: SkipReason::JobFailed { code: 87 },
            start: Start::Created,
            ended: Some(Ended::NotConfirmed { code: 258 }),
            priority_restore: None,
        },
    }
}

fn err(bytes: &[u8]) -> ResultError {
    decode(bytes).unwrap_err()
}

fn at(line: usize, kind: ResultErrorKind) -> ResultError {
    ResultError { line, kind }
}

/// `GOLDEN` with line `n` (1-based) replaced.
fn with_line(golden: &str, n: usize, new: &str) -> String {
    let mut lines: Vec<&str> = golden.lines().collect();
    lines[n - 1] = new;
    lines.join("\n") + "\n"
}

#[test]
fn golden_bytes() {
    assert_eq!(encode(&ok()).unwrap(), GOLDEN.as_bytes());
    assert_eq!(decode(GOLDEN.as_bytes()).unwrap(), ok());
    assert_eq!(encode(&skipped()).unwrap(), GOLDEN_SKIPPED.as_bytes());
    assert_eq!(decode(GOLDEN_SKIPPED.as_bytes()).unwrap(), skipped());
}

fn all_reasons() -> Vec<SkipReason> {
    use SkipReason as R;
    let mut v = vec![
        R::ProfileMissing,
        R::ProfileReparsePoint,
        R::ProfileNotAFile,
        R::ProfileInvalid,
        R::MethodUnsupported,
        R::PathMismatch,
        R::TopologyUnavailable,
        R::TopologyInvalid,
        R::SelectionEmpty,
        R::MaskTooWide,
        R::Mismatch,
        R::ElevationRequired,
        R::TargetNotFound,
        R::TargetElevated,
    ];
    for code in [0, 5, u32::MAX] {
        v.extend([
            R::ProfileUnreadable { code },
            R::SpawnFailed { code },
            R::JobFailed { code },
            R::ReadBackFailed { code },
            R::CpuSetsFailed { code },
            R::ResumeFailed { code },
            R::TargetDenied { code },
            R::SearchFailed { code },
            R::PriorityFailed { code },
        ]);
    }
    v
}

fn all_outcomes() -> Vec<Outcome> {
    let mut out = Vec::new();
    let cpus = [
        None,
        Some(AppliedCpu {
            mode: Mode::Hard,
            threads: 1,
            of: 1,
        }),
        Some(AppliedCpu {
            mode: Mode::Soft,
            threads: 8,
            of: 4096,
        }),
    ];
    let priorities = [
        None,
        Some(Priority::Normal),
        Some(Priority::AboveNormal),
        Some(Priority::High),
    ];
    for cpu in cpus {
        for priority in priorities {
            let mut checks = vec![
                Check::Ok,
                Check::ExitedEarly,
                Check::Failed { code: 0 },
                Check::Failed { code: 1_234_567 },
            ];
            if cpu.is_some_and(|c| c.mode == Mode::Hard) {
                checks.push(Check::Narrowed);
            }
            for (c, p) in [(true, false), (false, true), (true, true)] {
                if (!c || cpu.is_some()) && (!p || priority.is_some()) {
                    checks.push(Check::Reset {
                        cpu: c,
                        priority: p,
                    });
                }
            }
            for check in checks {
                out.push(Outcome::Applied {
                    cpu,
                    priority,
                    check,
                });
            }
        }
    }
    let starts = [
        Start::Created,
        Start::Shell,
        Start::ShellNoProcess,
        Start::NotExe,
        Start::Failed { code: 2 },
    ];
    let ends = [
        None,
        Some(Ended::Ended),
        Some(Ended::Failed { code: 5 }),
        Some(Ended::NotConfirmed { code: 258 }),
    ];
    for reason in all_reasons() {
        for start in starts {
            for ended in ends {
                out.push(Outcome::Skipped {
                    reason,
                    start,
                    ended,
                    priority_restore: None,
                });
            }
        }
    }
    // A failed priority restore (watch, A4) after either CPU step that can follow it.
    for reason in [
        SkipReason::JobFailed { code: 5 },
        SkipReason::CpuSetsFailed { code: 87 },
    ] {
        for code in [0, 6, u32::MAX] {
            out.push(Outcome::Skipped {
                reason,
                start: Start::Created,
                ended: None,
                priority_restore: Some(code),
            });
        }
    }
    out
}

#[test]
fn every_outcome_round_trips() {
    let outcomes = all_outcomes();
    assert_eq!(outcomes.len(), 75 + 41 * 5 * 4 + 6);
    for outcome in outcomes {
        for unix_s in [0, 1, 1_762_600_000, u64::MAX] {
            let r = LaunchResult {
                profile: ProfileId([0xab; 16]),
                unix_s,
                outcome: outcome.clone(),
            };
            let bytes = encode(&r).unwrap();
            assert!(bytes.len() <= MAX_RESULT_BYTES / 3, "{}", bytes.len());
            assert_eq!(decode(&bytes).unwrap(), r);
        }
    }
}

#[test]
fn reason_names_are_the_documented_tokens() {
    assert_eq!(SkipReason::PathMismatch.to_string(), "path_mismatch");
    assert_eq!(
        SkipReason::ProfileUnreadable { code: 5 }.to_string(),
        "profile_unreadable:5"
    );
    assert_eq!(SkipReason::ElevationRequired.name(), "elevation_required");
    assert_eq!(SkipReason::SpawnFailed { code: 2 }.code(), Some(2));
    assert_eq!(SkipReason::Mismatch.code(), None);
    // Every name parses back with exactly its code form.
    for r in all_reasons() {
        assert_eq!(SkipReason::parse(r.name(), r.code()), Some(r));
        let other = if r.code().is_some() { None } else { Some(1) };
        assert_eq!(SkipReason::parse(r.name(), other), None, "{r}");
    }
}

#[test]
fn the_writer_refuses_values_no_file_may_hold() {
    let applied = |cpu, priority, check| LaunchResult {
        outcome: Outcome::Applied {
            cpu,
            priority,
            check,
        },
        ..ok()
    };
    let cpu = |threads, of| {
        Some(AppliedCpu {
            mode: Mode::Hard,
            threads,
            of,
        })
    };
    let inconsistent = at(0, ResultErrorKind::Inconsistent);
    for r in [
        applied(cpu(0, 32), None, Check::Ok),
        applied(cpu(33, 32), None, Check::Ok),
        applied(cpu(8, 4097), None, Check::Ok),
        applied(
            cpu(8, 32),
            None,
            Check::Reset {
                cpu: false,
                priority: false,
            },
        ),
        applied(
            None,
            Some(Priority::High),
            Check::Reset {
                cpu: true,
                priority: false,
            },
        ),
        applied(
            cpu(8, 32),
            None,
            Check::Reset {
                cpu: true,
                priority: true,
            },
        ),
    ] {
        assert_eq!(encode(&r).unwrap_err(), inconsistent, "{r:?}");
    }
}

#[test]
fn every_truncation_is_refused() {
    let g = GOLDEN.as_bytes();
    for len in 0..g.len() {
        assert!(decode(&g[..len]).is_err(), "prefix of {len} bytes accepted");
    }
    let lines: Vec<&str> = GOLDEN.lines().collect();
    for keep in 1..lines.len() {
        let cut = lines[..keep].join("\n") + "\n";
        assert_eq!(
            err(cut.as_bytes()),
            at(
                keep + 1,
                ResultErrorKind::Truncated {
                    expected: KEYS[keep - 1]
                }
            ),
            "{keep} lines"
        );
    }
    assert_eq!(err(b""), at(0, ResultErrorKind::NoFinalNewline));
}

#[test]
fn oversize_and_bytes_are_refused() {
    let mut big = GOLDEN.as_bytes().to_vec();
    big.resize(MAX_RESULT_BYTES + 1, b'x');
    assert_eq!(err(&big), at(0, ResultErrorKind::TooLarge));
    big.truncate(MAX_RESULT_BYTES);
    assert_ne!(err(&big).kind, ResultErrorKind::TooLarge);

    assert_eq!(
        err(GOLDEN.replace('\n', "\r\n").as_bytes()),
        at(1, ResultErrorKind::CarriageReturn)
    );
    let mut bom = b"\xEF\xBB\xBF".to_vec();
    bom.extend_from_slice(GOLDEN.as_bytes());
    assert_eq!(err(&bom), at(1, ResultErrorKind::BadHeader));
    assert_eq!(
        err(GOLDEN.replace("ok\n", "ok\t\n").as_bytes()),
        at(7, ResultErrorKind::ControlChar)
    );
    assert_eq!(
        err(GOLDEN.replace("ok\n", "o\0k\n").as_bytes()),
        at(7, ResultErrorKind::ControlChar)
    );
    assert_eq!(
        err(GOLDEN.replace("ok\n", "ok\n\n").as_bytes()),
        at(8, ResultErrorKind::EmptyLine)
    );
    let mut latin1 = GOLDEN.as_bytes().to_vec();
    latin1[20] = 0xE9;
    assert_eq!(err(&latin1), at(0, ResultErrorKind::NotUtf8));
    assert_eq!(
        err(GOLDEN.trim_end_matches('\n').as_bytes()),
        at(0, ResultErrorKind::NoFinalNewline)
    );
}

#[test]
fn headers_keys_and_order() {
    assert_eq!(
        err(with_line(GOLDEN, 1, "rerun-result 2").as_bytes()),
        at(1, ResultErrorKind::UnsupportedFormat(2))
    );
    for h in [
        "rerun-result 01",
        "rerun-result",
        "rerun-result  1",
        "rerun-profile 1",
        "Rerun-result 1",
    ] {
        assert_eq!(
            err(with_line(GOLDEN, 1, h).as_bytes()),
            at(1, ResultErrorKind::BadHeader),
            "{h}"
        );
    }
    // Two keys swapped.
    let swapped = GOLDEN.replace(
        "cpu=hard:8:32\npriority=none\n",
        "priority=none\ncpu=hard:8:32\n",
    );
    assert_eq!(
        err(swapped.as_bytes()),
        at(5, ResultErrorKind::UnexpectedKey { expected: "cpu" })
    );
    // A key in another case, with spaces, or unknown.
    for (n, l) in [
        (2, "Profile=0123456789abcdef0123456789abcdef"),
        (3, "time =1762600000"),
        (4, "rules=applied"),
        (9, "ended"),
    ] {
        assert!(
            matches!(
                err(with_line(GOLDEN, n, l).as_bytes()),
                ResultError { line, kind: ResultErrorKind::UnexpectedKey { .. } } if line == n
            ),
            "{l}"
        );
    }
    let trailing = format!("{GOLDEN}ended=none\n");
    assert_eq!(
        err(trailing.as_bytes()),
        at(10, ResultErrorKind::TrailingLine)
    );
}

#[test]
fn bad_values_are_refused() {
    for (n, v) in [
        (2, "profile=0123456789ABCDEF0123456789ABCDEF"),
        (2, "profile=0123456789abcdef"),
        (3, "time=01762600000"),
        (3, "time=-1"),
        (3, "time=+1"),
        (3, "time=18446744073709551616"),
        (3, "time="),
        (4, "rule=Applied"),
        (4, "rule=skipped"),
        (4, "rule=skipped:"),
        (4, "rule=skipped:path_mismatch:5"),
        (4, "rule=skipped:job_failed"),
        (4, "rule=skipped:job_failed:087"),
        (4, "rule=skipped:job_failed:4294967296"),
        (4, "rule=skipped:job_failed:5:6"),
        (4, "rule=skipped:elevated"),
        (5, "cpu=hard:8"),
        (5, "cpu=hard:08:32"),
        (5, "cpu=hard:8:32:1"),
        (5, "cpu=firm:8:32"),
        (5, "cpu=hard:8:40960"),
        (6, "priority=realtime"),
        (7, "check=reset"),
        (7, "check=reset:priority_cpu"),
        (7, "check=failed"),
        (7, "check=failed:x"),
        (8, "start=failed"),
        (8, "start=wait_failed:5"),
        (9, "rule_child=failed:"),
        (9, "rule_child=not_confirmed"),
    ] {
        assert_eq!(
            err(with_line(GOLDEN, n, v).as_bytes()),
            at(n, ResultErrorKind::BadValue { key: KEYS[n - 2] }),
            "{v}"
        );
    }
}

#[test]
fn contradicting_values_are_refused() {
    let inconsistent = at(0, ResultErrorKind::Inconsistent);
    for (golden, n, v) in [
        // Applied: no check, another start, an end.
        (GOLDEN, 7, "check=none"),
        (GOLDEN, 8, "start=shell"),
        (GOLDEN, 9, "rule_child=ended"),
        // A reset of what was not set, or threads above `of`.
        (GOLDEN, 7, "check=reset:priority"),
        (GOLDEN, 5, "cpu=hard:33:32"),
        (GOLDEN, 5, "cpu=hard:0:32"),
        // Skipped: cpu, priority or check.
        (GOLDEN_SKIPPED, 5, "cpu=hard:8:32"),
        (GOLDEN_SKIPPED, 6, "priority=high"),
        (GOLDEN_SKIPPED, 7, "check=ok"),
    ] {
        assert_eq!(err(with_line(golden, n, v).as_bytes()), inconsistent, "{v}");
    }
    // `narrowed` only with a hard limit.
    let narrowed = GOLDEN.replace("check=ok", "check=narrowed");
    assert!(decode(narrowed.as_bytes()).is_ok());
    for cpu in ["cpu=soft:8:32", "cpu=none"] {
        let soft = narrowed.replace("cpu=hard:8:32", cpu);
        assert_eq!(err(soft.as_bytes()), inconsistent, "{cpu}");
    }
}

/// xorshift64*, so the loop is the same on every machine (no proptest dependency).
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: usize) -> usize {
        usize::try_from(self.next() % u64::try_from(n).unwrap()).unwrap()
    }
}

#[test]
fn mutated_results_never_panic_and_never_decode_to_something_else() {
    let mut rng = Rng(0x0BAD_F00D_DEAD_BEEF);
    let mut accepted = 0;
    for i in 0..20_000 {
        let golden = if i % 2 == 0 { GOLDEN } else { GOLDEN_SKIPPED };
        let mut b = golden.as_bytes().to_vec();
        for _ in 0..=rng.below(3) {
            match rng.below(4) {
                0 => {
                    let i = rng.below(b.len());
                    b[i] = u8::try_from(rng.next() & 0xFF).unwrap();
                }
                1 => {
                    let i = rng.below(b.len() + 1);
                    b.truncate(i);
                    if b.is_empty() {
                        b.push(b'\n');
                    }
                }
                2 => {
                    let i = rng.below(b.len() + 1);
                    b.insert(i, b"=:\n\r 0x"[rng.below(7)]);
                }
                _ => {
                    let i = rng.below(b.len());
                    b.remove(i);
                    if b.is_empty() {
                        b.push(b'\n');
                    }
                }
            }
        }
        if let Ok(r) = decode(&b) {
            // Whatever is accepted is canonical: it encodes back to the same bytes.
            assert_eq!(encode(&r).unwrap(), b);
            accepted += 1;
        }
    }
    assert!(accepted > 0, "no mutation decoded");
}

const GOLDEN_RESTORE: &str = "rerun-result 1
profile=0123456789abcdef0123456789abcdef
time=0
rule=skipped:job_failed:5
cpu=none
priority=none
check=none
start=created
rule_child=none
priority_restore=failed:6
";

fn watch_skipped(reason: SkipReason, priority_restore: Option<u32>) -> LaunchResult {
    LaunchResult {
        profile: id(),
        unix_s: 0,
        outcome: Outcome::Skipped {
            reason,
            start: Start::Created,
            ended: None,
            priority_restore,
        },
    }
}

#[test]
fn watch_reasons_golden_and_round_trip() {
    for (reason, line) in [
        (SkipReason::TargetNotFound, "rule=skipped:target_not_found"),
        (SkipReason::TargetElevated, "rule=skipped:target_elevated"),
        (
            SkipReason::TargetDenied { code: 5 },
            "rule=skipped:target_denied:5",
        ),
        (
            SkipReason::SearchFailed { code: 50 },
            "rule=skipped:search_failed:50",
        ),
        (
            SkipReason::PriorityFailed { code: 5 },
            "rule=skipped:priority_failed:5",
        ),
        (
            SkipReason::SpawnFailed { code: 2 },
            "rule=skipped:spawn_failed:2",
        ),
    ] {
        let golden = with_line(GOLDEN_SKIPPED, 4, line)
            .replace("rule_child=not_confirmed:258", "rule_child=none");
        let r = watch_skipped(reason, None);
        assert_eq!(encode(&r).unwrap(), golden.as_bytes(), "{reason}");
        assert_eq!(decode(golden.as_bytes()).unwrap(), r, "{reason}");
    }
    let r = watch_skipped(SkipReason::JobFailed { code: 5 }, Some(6));
    assert_eq!(encode(&r).unwrap(), GOLDEN_RESTORE.as_bytes());
    assert_eq!(decode(GOLDEN_RESTORE.as_bytes()).unwrap(), r);
}

#[test]
fn watch_reasons_take_exactly_their_code_form() {
    let bad = at(4, ResultErrorKind::BadValue { key: "rule" });
    for l in [
        "rule=skipped:target_not_found:5",
        "rule=skipped:target_elevated:0",
        "rule=skipped:target_denied",
        "rule=skipped:search_failed",
        "rule=skipped:priority_failed",
        "rule=skipped:target_denied:05",
        "rule=skipped:target_denied:4294967296",
    ] {
        assert_eq!(err(with_line(GOLDEN_SKIPPED, 4, l).as_bytes()), bad, "{l}");
    }
}

#[test]
fn method_unsupported_of_an_earlier_shim_still_reads() {
    let old = with_line(GOLDEN_SKIPPED, 4, "rule=skipped:method_unsupported");
    assert!(matches!(
        decode(old.as_bytes()).unwrap().outcome,
        Outcome::Skipped {
            reason: SkipReason::MethodUnsupported,
            priority_restore: None,
            ..
        }
    ));
}

#[test]
fn a_priority_restore_line_is_strict() {
    let inconsistent = at(0, ResultErrorKind::Inconsistent);
    // Only after job_failed or cpu_sets_failed; never on an applied rule.
    let cpu_sets = GOLDEN_RESTORE.replace("job_failed:5", "cpu_sets_failed:87");
    assert!(decode(cpu_sets.as_bytes()).is_ok());
    for other in [
        SkipReason::TargetDenied { code: 5 },
        SkipReason::PriorityFailed { code: 5 },
        SkipReason::PathMismatch,
    ] {
        let s = GOLDEN_RESTORE.replace("job_failed:5", &other.to_string());
        assert_eq!(err(s.as_bytes()), inconsistent, "{other}");
        let r = watch_skipped(other, Some(6));
        assert_eq!(encode(&r).unwrap_err(), inconsistent, "{other}");
    }
    let applied = format!(
        "{GOLDEN}priority_restore=failed:6
"
    );
    assert_eq!(err(applied.as_bytes()), inconsistent);
    // Only `failed:<code>`, canonical; `none` is never written (the line is absent instead).
    let bad = at(
        10,
        ResultErrorKind::BadValue {
            key: "priority_restore",
        },
    );
    for v in [
        "priority_restore=none",
        "priority_restore=failed:",
        "priority_restore=failed:06",
        "priority_restore=failed:-1",
        "priority_restore=ok",
        "priority_restore=",
    ] {
        assert_eq!(err(with_line(GOLDEN_RESTORE, 10, v).as_bytes()), bad, "{v}");
    }
    // Another tenth key, or an eleventh line, is trailing.
    assert_eq!(
        err(with_line(GOLDEN_RESTORE, 10, "restore=failed:6").as_bytes()),
        at(10, ResultErrorKind::TrailingLine)
    );
    let eleven = format!(
        "{GOLDEN_RESTORE}priority_restore=failed:6
"
    );
    assert_eq!(
        err(eleven.as_bytes()),
        at(11, ResultErrorKind::TrailingLine)
    );
}
