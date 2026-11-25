#![allow(
    clippy::unwrap_used,
    reason = "test code: a failure should abort the test"
)]

use super::*;

const GAME: &str = r"C:\Program Files (x86)\Steam\steamapps\common\Far Cry 2\bin\FarCry2.exe";

fn rule() -> CpuRule {
    CpuRule {
        max_threads: Some(8),
        prefer: Prefer::Performance,
        single_l3: true,
        prefer_l3: None,
        smt: false,
        mode: Mode::Hard,
        exclude_first: None,
    }
}

fn direct() -> LaunchProfile {
    LaunchProfile {
        method: Method::Direct,
        start: GAME.into(),
        target: GAME.into(),
        bitness: Bitness::X86,
        priority: None,
        watch_timeout_s: 120,
        cpu: Some(rule()),
        run: None,
        args: Vec::new(),
    }
}

const GOLDEN: &str = "rerun-profile 1
method=direct
start=C:\\Program Files (x86)\\Steam\\steamapps\\common\\Far Cry 2\\bin\\FarCry2.exe
target=C:\\Program Files (x86)\\Steam\\steamapps\\common\\Far Cry 2\\bin\\FarCry2.exe
bitness=x86
priority=none
watch_timeout_s=120
cpu=rule
cpu.prefer=performance
cpu.single_l3=true
cpu.prefer_l3=none
cpu.smt=false
cpu.mode=hard
cpu.max_threads=8
";

/// Assassin's Creed II through Ubisoft Connect, with the community fix "no CPU 0".
fn watch_v2() -> LaunchProfile {
    LaunchProfile {
        method: Method::Watch,
        start: r"C:\Games\ACII\AssassinsCreedII.exe".into(),
        target: r"C:\Games\ACII\AssassinsCreedIIGame.exe".into(),
        bitness: Bitness::X86,
        priority: None,
        watch_timeout_s: 120,
        cpu: Some(CpuRule {
            max_threads: None,
            prefer: Prefer::Any,
            single_l3: false,
            prefer_l3: None,
            smt: true,
            mode: Mode::Hard,
            exclude_first: Some(ExcludeFirst::Thread),
        }),
        run: None,
        args: Vec::new(),
    }
}

const GOLDEN_2: &str = "rerun-profile 2
method=watch
start=C:\\Games\\ACII\\AssassinsCreedII.exe
target=C:\\Games\\ACII\\AssassinsCreedIIGame.exe
bitness=x86
priority=none
watch_timeout_s=120
cpu=rule
cpu.prefer=any
cpu.single_l3=false
cpu.prefer_l3=none
cpu.smt=true
cpu.mode=hard
cpu.max_threads=none
cpu.exclude_first=thread
";

/// `GOLDEN_2` with line `n` (1-based) replaced.
fn with_line_2(n: usize, new: &str) -> String {
    let mut lines: Vec<&str> = GOLDEN_2.lines().collect();
    lines[n - 1] = new;
    lines.join("\n") + "\n"
}

fn err(bytes: &[u8]) -> ProfileError {
    decode(bytes).unwrap_err()
}

fn at(line: usize, kind: ProfileErrorKind) -> ProfileError {
    ProfileError { line, kind }
}

/// `GOLDEN` with line `n` (1-based) replaced.
fn with_line(n: usize, new: &str) -> String {
    let mut lines: Vec<&str> = GOLDEN.lines().collect();
    lines[n - 1] = new;
    lines.join("\n") + "\n"
}

/// [`direct`] as format 3, the form every profile is written in (ADR 0022 amendment P5-OE).
const GOLDEN_3: &str = "rerun-profile 3
method=direct
start=C:\\Program Files (x86)\\Steam\\steamapps\\common\\Far Cry 2\\bin\\FarCry2.exe
target=C:\\Program Files (x86)\\Steam\\steamapps\\common\\Far Cry 2\\bin\\FarCry2.exe
bitness=x86
priority=none
watch_timeout_s=120
cpu=rule
cpu.prefer=performance
cpu.single_l3=true
cpu.prefer_l3=none
cpu.smt=false
cpu.mode=hard
cpu.max_threads=8
cpu.exclude_first=none
run=none
args=none
";

const AC1: &str = r"D:\Steam\steamapps\common\Assassin's Creed";

/// Assassin's Creed: Steam starts the detector, the shim starts the DX9 build with arguments.
fn run_dx9() -> LaunchProfile {
    LaunchProfile {
        method: Method::Direct,
        start: format!(r"{AC1}\AssassinsCreed_Game.exe"),
        target: format!(r"{AC1}\AssassinsCreed_Dx9.exe"),
        bitness: Bitness::X86,
        priority: None,
        watch_timeout_s: 120,
        cpu: Some(rule()),
        run: Some(format!(r"{AC1}\AssassinsCreed_Dx9.exe")),
        args: vec![
            LaunchArg::parse("-skipintro").unwrap(),
            LaunchArg::parse("+fov=1.2").unwrap(),
        ],
    }
}

const GOLDEN_RUN: &str = "rerun-profile 3
method=direct
start=D:\\Steam\\steamapps\\common\\Assassin's Creed\\AssassinsCreed_Game.exe
target=D:\\Steam\\steamapps\\common\\Assassin's Creed\\AssassinsCreed_Dx9.exe
bitness=x86
priority=none
watch_timeout_s=120
cpu=rule
cpu.prefer=performance
cpu.single_l3=true
cpu.prefer_l3=none
cpu.smt=false
cpu.mode=hard
cpu.max_threads=8
cpu.exclude_first=none
run=D:\\Steam\\steamapps\\common\\Assassin's Creed\\AssassinsCreed_Dx9.exe
args=-skipintro +fov=1.2
";

/// `GOLDEN_RUN` with line `n` (1-based) replaced.
fn with_line_run(n: usize, new: &str) -> String {
    let mut lines: Vec<&str> = GOLDEN_RUN.lines().collect();
    lines[n - 1] = new;
    lines.join("\n") + "\n"
}

#[test]
fn golden_bytes() {
    // Every profile is written as format 3; the format-1 bytes of an earlier build still read.
    assert_eq!(encode(&direct()).unwrap(), GOLDEN_3.as_bytes());
    assert_eq!(decode(GOLDEN_3.as_bytes()).unwrap(), direct());
    assert_eq!(decode(GOLDEN.as_bytes()).unwrap(), direct());
    assert_eq!(encode_format(&direct(), 1).unwrap(), GOLDEN.as_bytes());
    assert_eq!(encode(&run_dx9()).unwrap(), GOLDEN_RUN.as_bytes());
    assert_eq!(decode(GOLDEN_RUN.as_bytes()).unwrap(), run_dx9());
}

#[test]
fn every_combination_round_trips() {
    let mut n = 0;
    for method in [Method::Direct, Method::Watch] {
        for bitness in [Bitness::X86, Bitness::X64] {
            for priority in [
                None,
                Some(Priority::Normal),
                Some(Priority::AboveNormal),
                Some(Priority::High),
            ] {
                for watch_timeout_s in [1, 37, 120] {
                    let mut cpus = vec![None];
                    for max_threads in [None, Some(1), Some(4096)] {
                        for prefer in [Prefer::Any, Prefer::Performance] {
                            for single_l3 in [false, true] {
                                for prefer_l3 in [None, Some(PreferL3::Largest)] {
                                    for smt in [false, true] {
                                        for mode in [Mode::Hard, Mode::Soft] {
                                            for exclude_first in [
                                                None,
                                                Some(ExcludeFirst::Thread),
                                                Some(ExcludeFirst::Core),
                                            ] {
                                                cpus.push(Some(CpuRule {
                                                    max_threads,
                                                    prefer,
                                                    single_l3,
                                                    prefer_l3,
                                                    smt,
                                                    mode,
                                                    exclude_first,
                                                }));
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    for cpu in cpus {
                        let target = match method {
                            Method::Direct => GAME.to_owned(),
                            Method::Watch => r"D:\Ubisoft\AC\ACBSP.exe".to_owned(),
                        };
                        let p = LaunchProfile {
                            method,
                            start: GAME.into(),
                            target,
                            bitness,
                            priority,
                            watch_timeout_s,
                            cpu,
                            run: None,
                            args: Vec::new(),
                        };
                        let bytes = encode(&p).unwrap();
                        assert!(bytes.len() <= MAX_PROFILE_BYTES);
                        assert_eq!(decode(&bytes).unwrap(), p);
                        assert!(bytes.starts_with(b"rerun-profile 3\n"));
                        n += 1;
                    }
                }
            }
        }
    }
    assert_eq!(n, 2 * 2 * 4 * 3 * (1 + 3 * 2 * 2 * 2 * 2 * 2 * 3));
}

#[test]
fn format_2_golden_bytes() {
    assert_eq!(encode_format(&watch_v2(), 2).unwrap(), GOLDEN_2.as_bytes());
    assert_eq!(decode(GOLDEN_2.as_bytes()).unwrap(), watch_v2());
    let core = GOLDEN_2.replace("=thread\n", "=core\n");
    let p = decode(core.as_bytes()).unwrap();
    assert_eq!(p.cpu.unwrap().exclude_first, Some(ExcludeFirst::Core));
    assert_eq!(encode_format(&p, 2).unwrap(), core.as_bytes());
    // Written today, the same profile is format 3 with the same rule.
    let text = String::from_utf8(encode(&watch_v2()).unwrap()).unwrap();
    assert!(text.starts_with("rerun-profile 3\n"), "{text}");
    assert!(
        text.ends_with("cpu.exclude_first=thread\nrun=none\nargs=none\n"),
        "{text}"
    );
    assert_eq!(decode(text.as_bytes()).unwrap(), watch_v2());
}

#[test]
fn every_profile_is_written_as_format_3_with_every_key() {
    // ADR 0022 P4-13: no third content-chosen format. Format 3 carries every key, always (the
    // seven cpu.* keys with cpu=rule).
    let none = LaunchProfile {
        cpu: None,
        ..direct()
    };
    let mut no_exclude = watch_v2();
    if let Some(r) = no_exclude.cpu.as_mut() {
        r.exclude_first = None;
    }
    for p in [direct(), none, watch_v2(), no_exclude, run_dx9()] {
        let text = String::from_utf8(encode(&p).unwrap()).unwrap();
        assert!(text.starts_with("rerun-profile 3\n"), "{text}");
        let keys: Vec<&str> = text
            .lines()
            .skip(1)
            .map(|l| l.split_once('=').unwrap().0)
            .collect();
        let want: Vec<&str> = if p.cpu.is_some() {
            KEYS_3.to_vec()
        } else {
            KEYS_3
                .iter()
                .copied()
                .filter(|k| !k.starts_with("cpu."))
                .collect()
        };
        assert_eq!(keys, want);
        assert_eq!(decode(text.as_bytes()).unwrap(), p);
    }
}

#[test]
fn format_2_refusals() {
    // Format 2 never carries `cpu=none`: a profile without a rule has one form, format 1.
    let text = "rerun-profile 2\nmethod=direct\nstart=C:\\g.exe\ntarget=C:\\g.exe\nbitness=x64\n\
                priority=none\nwatch_timeout_s=120\ncpu=none\n";
    assert_eq!(
        err(text.as_bytes()),
        at(8, ProfileErrorKind::BadValue { key: "cpu" })
    );
    let text = GOLDEN_2.replacen("cpu=rule", "cpu=none", 1);
    assert_eq!(
        err(text.as_bytes()),
        at(8, ProfileErrorKind::BadValue { key: "cpu" })
    );
    // The line is required, with one of its two values.
    let cut: String = GOLDEN_2
        .lines()
        .take(14)
        .map(|l| format!("{l}\n"))
        .collect();
    assert_eq!(
        err(cut.as_bytes()),
        at(
            15,
            ProfileErrorKind::Truncated {
                expected: "cpu.exclude_first"
            }
        )
    );
    for v in ["false", "true", "none", "Thread", "thread ", "0", ""] {
        assert_eq!(
            err(with_line_2(15, &format!("cpu.exclude_first={v}")).as_bytes()),
            at(
                15,
                ProfileErrorKind::BadValue {
                    key: "cpu.exclude_first"
                }
            ),
            "{v:?}"
        );
    }
    // At the wrong place: before cpu.max_threads.
    let mut lines: Vec<&str> = GOLDEN_2.lines().collect();
    lines.swap(13, 14);
    let swapped = lines.join("\n") + "\n";
    assert_eq!(
        err(swapped.as_bytes()),
        at(
            14,
            ProfileErrorKind::UnexpectedKey {
                expected: "cpu.max_threads"
            }
        )
    );
    // Repeated, or anything after it.
    for (extra, kind) in [
        ("cpu.exclude_first=core", ProfileErrorKind::DuplicateKey),
        ("cpu.smt=true", ProfileErrorKind::DuplicateKey),
        ("cpu.extra=1", ProfileErrorKind::UnknownKey),
    ] {
        let text = format!("{GOLDEN_2}{extra}\n");
        assert_eq!(err(text.as_bytes()), at(16, kind), "{extra}");
    }
}

#[test]
fn format_1_does_not_know_exclude_first() {
    // A format-1 file with the format-2 line: the key is unknown to format 1.
    for v in ["thread", "core"] {
        let text = format!("{GOLDEN}cpu.exclude_first={v}\n");
        assert_eq!(
            err(text.as_bytes()),
            at(15, ProfileErrorKind::UnknownKey),
            "{v}"
        );
    }
    // A format-2 body under a format-1 header.
    let text = GOLDEN_2.replacen("rerun-profile 2", "rerun-profile 1", 1);
    assert_eq!(err(text.as_bytes()), at(15, ProfileErrorKind::UnknownKey));
    // A format-1 body under a format-2 header: the format-2 line is missing.
    let text = GOLDEN.replacen("rerun-profile 1", "rerun-profile 2", 1);
    assert_eq!(
        err(text.as_bytes()),
        at(
            15,
            ProfileErrorKind::Truncated {
                expected: "cpu.exclude_first"
            }
        )
    );
}

#[test]
fn a_profile_without_a_rule_has_no_cpu_lines() {
    let p = LaunchProfile {
        cpu: None,
        priority: Some(Priority::High),
        ..direct()
    };
    let text = String::from_utf8(encode(&p).unwrap()).unwrap();
    assert!(
        text.ends_with("watch_timeout_s=120\ncpu=none\nrun=none\nargs=none\n"),
        "{text}"
    );
    assert!(text.contains("\npriority=high\n"));
    assert_eq!(decode(text.as_bytes()).unwrap(), p);
}

#[test]
fn every_truncation_is_refused() {
    let g = GOLDEN.as_bytes();
    for len in 0..g.len() {
        assert!(decode(&g[..len]).is_err(), "prefix of {len} bytes accepted");
    }
    // Whole lines missing: the first missing key is named.
    let lines: Vec<&str> = GOLDEN.lines().collect();
    for keep in 1..lines.len() {
        let cut = lines[..keep].join("\n") + "\n";
        let expected = KEYS_1[keep - 1];
        assert_eq!(
            err(cut.as_bytes()),
            at(keep + 1, ProfileErrorKind::Truncated { expected }),
            "{keep} lines"
        );
    }
    assert_eq!(err(b""), at(0, ProfileErrorKind::NoFinalNewline));
}

#[test]
fn oversize_is_refused_before_anything_else() {
    let mut big = GOLDEN.as_bytes().to_vec();
    big.resize(MAX_PROFILE_BYTES + 1, b'x');
    assert_eq!(err(&big), at(0, ProfileErrorKind::TooLarge));
    // Exactly the limit is read (and refused for its content only).
    big.truncate(MAX_PROFILE_BYTES);
    assert_ne!(err(&big).kind, ProfileErrorKind::TooLarge);
}

#[test]
fn a_path_over_the_unit_limit_is_refused_by_the_writer() {
    let long = format!(r"C:\{}\game.exe", "a".repeat(MAX_PATH_UNITS));
    let p = LaunchProfile {
        start: long.clone(),
        target: long,
        ..direct()
    };
    assert_eq!(
        encode(&p).unwrap_err(),
        at(3, ProfileErrorKind::BadValue { key: "start" })
    );
}

#[test]
fn two_long_non_ascii_paths_overflow_8_kib_and_are_refused_by_the_writer() {
    // Each path is within MAX_PATH_UNITS (1,510 UTF-16 units) but 4,510 bytes of UTF-8.
    let start = format!(r"C:\{}\g.exe", "名".repeat(1500));
    let target = format!(r"D:\{}\t.exe", "名".repeat(1500));
    assert!(path(&start).is_some() && path(&target).is_some());
    let p = LaunchProfile {
        method: Method::Watch,
        start,
        target,
        ..direct()
    };
    assert_eq!(encode(&p).unwrap_err(), at(0, ProfileErrorKind::TooLarge));
}

#[test]
fn unknown_repeated_and_misplaced_keys_are_refused() {
    assert_eq!(
        err(with_line(5, "bits=x86").as_bytes()),
        at(5, ProfileErrorKind::UnknownKey)
    );
    assert_eq!(
        err(with_line(5, "method=direct").as_bytes()),
        at(5, ProfileErrorKind::DuplicateKey)
    );
    assert_eq!(
        err(with_line(5, "priority=none").as_bytes()),
        at(
            5,
            ProfileErrorKind::UnexpectedKey {
                expected: "bitness"
            }
        )
    );
    // Upper case is another key.
    assert_eq!(
        err(with_line(2, "Method=direct").as_bytes()),
        at(2, ProfileErrorKind::UnknownKey)
    );
    // After the last key.
    for (extra, kind) in [
        ("cpu.mode=hard", ProfileErrorKind::DuplicateKey),
        ("comment=1", ProfileErrorKind::UnknownKey),
        ("# comment", ProfileErrorKind::MissingEquals),
    ] {
        let text = format!("{GOLDEN}{extra}\n");
        assert_eq!(err(text.as_bytes()), at(15, kind), "{extra}");
    }
    // cpu=none followed by cpu lines.
    let text = GOLDEN.replace("cpu=rule", "cpu=none");
    assert_eq!(err(text.as_bytes()), at(9, ProfileErrorKind::TrailingLine));
    // Spaces are not trimmed.
    assert_eq!(
        err(with_line(2, "method = direct").as_bytes()),
        at(2, ProfileErrorKind::UnknownKey)
    );
    assert_eq!(
        err(with_line(2, "method=direct ").as_bytes()),
        at(2, ProfileErrorKind::BadValue { key: "method" })
    );
    assert_eq!(
        err(with_line(2, "method").as_bytes()),
        at(2, ProfileErrorKind::MissingEquals)
    );
}

#[test]
fn cr_nul_controls_empty_lines_and_non_utf8_are_refused() {
    let crlf = GOLDEN.replace('\n', "\r\n");
    assert_eq!(
        err(crlf.as_bytes()),
        at(1, ProfileErrorKind::CarriageReturn)
    );
    for c in ['\0', '\t', '\u{1b}', '\u{7f}', '\u{85}'] {
        let text = with_line(3, &format!(r"start=C:\Games\a{c}b.exe"));
        assert_eq!(
            err(text.as_bytes()),
            at(3, ProfileErrorKind::ControlChar),
            "{c:?}"
        );
    }
    let text = GOLDEN.replace("bitness=x86\n", "bitness=x86\n\n");
    assert_eq!(err(text.as_bytes()), at(6, ProfileErrorKind::EmptyLine));
    let mut bytes = GOLDEN.as_bytes().to_vec();
    bytes[40] = 0xFF;
    assert_eq!(err(&bytes), at(0, ProfileErrorKind::NotUtf8));
    let mut bytes = b"\xEF\xBB\xBF".to_vec();
    bytes.extend_from_slice(GOLDEN.as_bytes());
    assert_eq!(err(&bytes), at(1, ProfileErrorKind::BadHeader));
    let bytes = GOLDEN.trim_end_matches('\n');
    assert_eq!(
        err(bytes.as_bytes()),
        at(0, ProfileErrorKind::NoFinalNewline)
    );
}

#[test]
fn only_formats_1_2_and_3_are_read() {
    assert_eq!(
        at(1, ProfileErrorKind::UnsupportedFormat(4)).to_string(),
        "launch profile line 1: format 4, this version reads formats 1, 2 and 3"
    );
    for (header, kind) in [
        ("rerun-profile 4", ProfileErrorKind::UnsupportedFormat(4)),
        ("rerun-profile 0", ProfileErrorKind::UnsupportedFormat(0)),
        ("rerun-profile 02", ProfileErrorKind::BadHeader),
        (
            "rerun-profile 999999999",
            ProfileErrorKind::UnsupportedFormat(999_999_999),
        ),
        ("rerun-profile 01", ProfileErrorKind::BadHeader),
        ("rerun-profile 1 ", ProfileErrorKind::BadHeader),
        ("rerun-profile  1", ProfileErrorKind::BadHeader),
        ("rerun-profile +1", ProfileErrorKind::BadHeader),
        ("rerun-profile 1234567890", ProfileErrorKind::BadHeader),
        ("rerun-profile", ProfileErrorKind::BadHeader),
        ("Rerun-profile 1", ProfileErrorKind::BadHeader),
        ("method=direct", ProfileErrorKind::BadHeader),
    ] {
        assert_eq!(
            err(with_line(1, header).as_bytes()),
            at(1, kind),
            "{header}"
        );
    }
}

#[test]
fn bad_values_are_refused() {
    for (line, text, key) in [
        (2, "method=hold", "method"),
        (2, "method=Direct", "method"),
        (5, "bitness=arm64", "bitness"),
        (6, "priority=realtime", "priority"),
        (6, "priority=idle", "priority"),
        (7, "watch_timeout_s=0", "watch_timeout_s"),
        (7, "watch_timeout_s=121", "watch_timeout_s"),
        (7, "watch_timeout_s=060", "watch_timeout_s"),
        (7, "watch_timeout_s=-1", "watch_timeout_s"),
        (7, "watch_timeout_s=", "watch_timeout_s"),
        (8, "cpu=yes", "cpu"),
        (9, "cpu.prefer=efficiency", "cpu.prefer"),
        (10, "cpu.single_l3=1", "cpu.single_l3"),
        (10, "cpu.single_l3=True", "cpu.single_l3"),
        (11, "cpu.prefer_l3=smallest", "cpu.prefer_l3"),
        (12, "cpu.smt=off", "cpu.smt"),
        (13, "cpu.mode=auto", "cpu.mode"),
        (14, "cpu.max_threads=0", "cpu.max_threads"),
        (14, "cpu.max_threads=4097", "cpu.max_threads"),
        (14, "cpu.max_threads=08", "cpu.max_threads"),
        (14, "cpu.max_threads=8.0", "cpu.max_threads"),
        (14, "cpu.max_threads=", "cpu.max_threads"),
    ] {
        assert_eq!(
            err(with_line(line, text).as_bytes()),
            at(line, ProfileErrorKind::BadValue { key }),
            "{text}"
        );
    }
}

#[test]
fn paths_must_be_canonical_absolute_drive_paths() {
    let start_ok = [
        r"C:\g.exe",
        r"C:\Games\console.exe",
        r"C:\Games\COM10.exe",
        r"C:\Games\nullify\g.exe",
        r"C:\Games\CONx.exe",
        r"z:\Spiele\Ünïcödé 名前\game.exe",
        r"D:\a b\c.d\e.exe",
    ];
    for p in start_ok {
        let text = with_line(3, &format!("start={p}"));
        let text = text.replacen(&format!("target={GAME}"), &format!("target={p}"), 1);
        assert_eq!(decode(text.as_bytes()).unwrap().start, p);
    }
    let start_bad = [
        "",
        "C:",
        r"C:\",
        r"C:g.exe",
        "C:/Games/g.exe",
        r"\\?\C:\Games\g.exe",
        r"\\server\share\g.exe",
        r"\Games\g.exe",
        r"Games\g.exe",
        r"1:\g.exe",
        r"C:\Games\\g.exe",
        r"C:\Games\.\g.exe",
        r"C:\Games\..\g.exe",
        r"C:\Games\",
        r"C:\Games \g.exe",
        r"C:\Games.\g.exe",
        r"C:\Games\g.exe.",
        r#"C:\Games\"g".exe"#,
        r"C:\Games\g?.exe",
        r"C:\Games\g*.exe",
        r"C:\Games\g|x.exe",
        r"C:\Games\g<x>.exe",
        r"C:\Games\g:stream.exe",
        r"C:\Games/g.exe",
        r"C:\ Games\g.exe",
        // Format and separator characters (docs/06 #6).
        "C:\\Games\\g\u{202E}exe.txt",
        "C:\\Games\\g\u{200B}.exe",
        "C:\\Games\\g\u{200E}.exe",
        "C:\\Games\\\u{FEFF}g.exe",
        "C:\\Games\\g\u{2028}.exe",
        "C:\\Games\\g\u{2029}.exe",
        "C:\\Games\\g\u{2066}.exe",
        "C:\\Games\\g\u{00AD}.exe",
        "C:\\Games\\g\u{E0041}.exe",
        // Reserved device names (docs/06 #4).
        r"C:\CON\g.exe",
        r"C:\Games\nul",
        r"C:\Games\nul.txt",
        r"C:\Games\Nul .exe",
        r"C:\Games\com1",
        r"C:\Games\LPT9.exe",
        r"C:\Games\COM¹.exe",
        r"C:\Games\conin$",
        r"C:\Games\CLOCK$.exe",
    ];
    for p in start_bad {
        assert_eq!(
            err(with_line(3, &format!("start={p}")).as_bytes()),
            at(3, ProfileErrorKind::BadValue { key: "start" }),
            "{p:?}"
        );
    }
    // MAX_PATH_UNITS counts UTF-16 units: one astral character is two.
    let at_limit = format!(r"C:\{}", "a".repeat(MAX_PATH_UNITS - 3));
    assert!(path(&at_limit).is_some());
    let over = format!(r"C:\{}😀", "a".repeat(MAX_PATH_UNITS - 4));
    assert!(path(&over).is_none());
}

#[test]
fn direct_needs_target_equal_to_start() {
    let text = with_line(4, r"target=C:\Games\other.exe");
    assert_eq!(
        err(text.as_bytes()),
        at(4, ProfileErrorKind::TargetNotStart)
    );
    // Exactly equal: another case is another target.
    let text = with_line(4, &format!("target={}", GAME.to_lowercase()));
    assert_eq!(
        err(text.as_bytes()),
        at(4, ProfileErrorKind::TargetNotStart)
    );
    let p = LaunchProfile {
        target: r"C:\Games\other.exe".into(),
        ..direct()
    };
    assert_eq!(
        encode(&p).unwrap_err(),
        at(4, ProfileErrorKind::TargetNotStart)
    );
    // watch may differ.
    let text = with_line(2, "method=watch");
    let text = text.replacen(&format!("target={GAME}"), r"target=C:\Games\other.exe", 1);
    assert_eq!(
        decode(text.as_bytes()).unwrap().target,
        r"C:\Games\other.exe"
    );
}

#[test]
fn the_writer_refuses_what_the_reader_refuses() {
    for p in [
        LaunchProfile {
            watch_timeout_s: 0,
            ..direct()
        },
        LaunchProfile {
            watch_timeout_s: 121,
            ..direct()
        },
        LaunchProfile {
            cpu: Some(CpuRule {
                max_threads: Some(0),
                ..rule()
            }),
            ..direct()
        },
        LaunchProfile {
            cpu: Some(CpuRule {
                max_threads: Some(4097),
                ..rule()
            }),
            ..direct()
        },
        LaunchProfile {
            start: "C:\\Games\\a\nmethod=watch\\g.exe".into(),
            target: "C:\\Games\\a\nmethod=watch\\g.exe".into(),
            ..direct()
        },
        LaunchProfile {
            start: r"\\?\C:\g.exe".into(),
            target: r"\\?\C:\g.exe".into(),
            ..direct()
        },
    ] {
        assert!(encode(&p).is_err(), "{p:?}");
    }
}

#[test]
fn profile_ids_are_32_lower_case_hex_digits() {
    let hex = "00112233445566778899aabbccddeeff";
    let id = ProfileId::from_hex(hex).unwrap();
    assert_eq!(id.0[0], 0x00);
    assert_eq!(id.0[15], 0xFF);
    assert_eq!(id.to_string(), hex);
    for bad in [
        "",
        "00112233445566778899aabbccddeef",
        "00112233445566778899aabbccddeeff0",
        "00112233445566778899AABBCCDDEEFF",
        "00112233445566778899aabbccddeefg",
        "0011223344556677 899aabbccddeeff",
        "+0112233445566778899aabbccddeeff",
        "ü0112233445566778899aabbccddeef",
    ] {
        assert_eq!(ProfileId::from_hex(bad), None, "{bad:?}");
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
fn mutated_profiles_never_panic_and_never_decode_to_something_else() {
    // Seeds: a format-1, a format-2 and two format-3 profiles.
    for (seed, golden) in [
        (0xDEAD_BEEF_CAFE_F00D, GOLDEN.as_bytes()),
        (0x0BAD_C0DE_F00D_2222, GOLDEN_2.as_bytes()),
        (0x5EED_0003_0003_0003, GOLDEN_3.as_bytes()),
        (0x5EED_0003_0000_0A51, GOLDEN_RUN.as_bytes()),
    ] {
        mutate(seed, golden);
    }
}

fn mutate(seed: u64, golden: &[u8]) {
    let mut rng = Rng(seed);
    let mut accepted = 0;
    for _ in 0..20_000 {
        let mut b = golden.to_vec();
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
                    b.insert(i, b"=\n\r 0x"[rng.below(6)]);
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
        if let Ok(p) = decode(&b) {
            // Whatever is accepted is canonical: it encodes back to the same bytes in its
            // format (the digit after "rerun-profile ").
            let format = u32::from(b[14] - b'0');
            assert_eq!(encode_format(&p, format).unwrap(), b);
            accepted += 1;
        }
    }
    assert!(accepted > 0, "no mutation decoded");
}

/// `scripts/dev-launch-profile.ps1` checks its profile writer against its own copy of
/// [`GOLDEN_3`] (review of P3-2; format 3 since P5-OE): that copy must be these bytes
/// (PowerShell's `` `n `` is LF).
#[test]
fn the_dev_script_golden_is_the_codec_golden() {
    let script = include_str!("../../../../scripts/dev-launch-profile.ps1");
    let line = script
        .lines()
        .find_map(|l| l.trim_start().strip_prefix("$golden = \""))
        .expect("the script has a $golden line");
    let copy = line
        .strip_suffix('"')
        .expect("one double-quoted string")
        .replace("`n", "\n");
    assert!(!copy.contains('`') && !copy.contains('$'), "{copy}");
    assert_eq!(copy, GOLDEN_3);
}

#[test]
fn launch_args_follow_the_one_pattern() {
    for ok in [
        "-dx9",
        "+set",
        "-a=b",
        "+fov=1.2",
        "-x_y-z+w.v",
        "--",
        "+-",
        "-0",
    ] {
        assert_eq!(LaunchArg::parse(ok).unwrap().as_str(), ok, "{ok}");
    }
    let long = format!("-{}", "a".repeat(MAX_ARG_CHARS - 1));
    assert!(LaunchArg::parse(&long).is_some());
    let too_long = format!("-{}", "a".repeat(MAX_ARG_CHARS));
    for bad in [
        "",
        "-",
        "+",
        "dx9",
        "/dx9",
        "-dx 9",
        "-\"x\"",
        "-%USERNAME%",
        "-a\\b",
        "-a/b",
        "-a&b",
        "-a|b",
        "-a^b",
        "-a;b",
        "-a,b",
        "-ä",
        "-a\tb",
        "-a\nb",
        too_long.as_str(),
    ] {
        assert_eq!(LaunchArg::parse(bad), None, "{bad:?}");
    }
}

/// `GOLDEN_RUN` with `run` and `target` both set to `run`.
fn with_run(run: &str) -> String {
    let dx9 = format!(r"{AC1}\AssassinsCreed_Dx9.exe");
    with_line_run(16, &format!("run={run}")).replacen(
        &format!("target={dx9}"),
        &format!("target={run}"),
        1,
    )
}

#[test]
fn format_3_run_rules() {
    let refused = |text: String, line, kind| assert_eq!(err(text.as_bytes()), at(line, kind));
    // Watch never starts run.
    refused(
        with_line_run(2, "method=watch"),
        16,
        ProfileErrorKind::RunNeedsDirect,
    );
    // Run in a sub-folder, the parent, another folder, another drive or another case of the
    // folder (byte for byte, S2).
    for run in [
        format!(r"{AC1}\bin\AssassinsCreed_Dx9.exe"),
        r"D:\Steam\steamapps\common\AssassinsCreed_Dx9.exe".to_owned(),
        r"D:\Steam\steamapps\common\Other\AssassinsCreed_Dx9.exe".to_owned(),
        r"E:\Steam\steamapps\common\Assassin's Creed\AssassinsCreed_Dx9.exe".to_owned(),
        r"D:\Steam\steamapps\common\ASSASSIN'S CREED\AssassinsCreed_Dx9.exe".to_owned(),
    ] {
        refused(with_run(&run), 16, ProfileErrorKind::RunNotInStartFolder);
    }
    // Run is start, also in another case.
    for name in ["AssassinsCreed_Game.exe", "assassinscreed_game.EXE"] {
        refused(
            with_run(&format!(r"{AC1}\{name}")),
            16,
            ProfileErrorKind::RunIsStart,
        );
    }
    // Target must be run (not start, not another exe, not another case).
    for target in [
        format!(r"{AC1}\AssassinsCreed_Game.exe"),
        format!(r"{AC1}\AssassinsCreed_Dx10.exe"),
        format!(r"{AC1}\assassinscreed_dx9.exe"),
    ] {
        refused(
            with_line_run(4, &format!("target={target}")),
            4,
            ProfileErrorKind::TargetNotRun,
        );
    }
    // Run is a canonical path ending in .exe.
    for run in [
        "",
        "None",
        r"AssassinsCreed_Dx9.exe",
        r"D:\Steam\steamapps\common\Assassin's Creed\AssassinsCreed_Dx9.bat",
        r"D:\Steam\steamapps\common\Assassin's Creed\AssassinsCreed_Dx9.exe ",
        r"D:\Steam\steamapps\common\Assassin's Creed\x.exe.lnk",
        r"\\?\D:\Steam\steamapps\common\Assassin's Creed\AssassinsCreed_Dx9.exe",
        r"D:\Steam\steamapps\common\Assassin's Creed\..\AssassinsCreed_Dx9.exe",
        r"D:\Steam\steamapps\common\Assassin's Creed\nul.exe",
        r#"D:\Steam\steamapps\common\Assassin's Creed\"a".exe"#,
    ] {
        refused(
            with_line_run(16, &format!("run={run}")),
            16,
            ProfileErrorKind::BadValue { key: "run" },
        );
    }
    // Another case of `.exe` is still an exe.
    let run = format!(r"{AC1}\AssassinsCreed_Dx9.EXE");
    assert_eq!(decode(with_run(&run).as_bytes()).unwrap().run, Some(run));
    // Without run, direct needs target = start as before.
    refused(
        with_line_run(16, "run=none"),
        4,
        ProfileErrorKind::TargetNotStart,
    );
    // The writer refuses what the reader refuses.
    for p in [
        LaunchProfile {
            method: Method::Watch,
            ..run_dx9()
        },
        LaunchProfile {
            target: format!(r"{AC1}\AssassinsCreed_Game.exe"),
            ..run_dx9()
        },
        LaunchProfile {
            run: Some(format!(r"{AC1}\bin\AssassinsCreed_Dx9.exe")),
            target: format!(r"{AC1}\bin\AssassinsCreed_Dx9.exe"),
            ..run_dx9()
        },
    ] {
        assert!(encode(&p).is_err(), "{p:?}");
    }
}

#[test]
fn format_3_args_rules() {
    let refused = |text: String, line, kind| assert_eq!(err(text.as_bytes()), at(line, kind));
    // Watch takes no arguments (and no run).
    let text = with_line_run(2, "method=watch").replacen(
        &format!(r"run={AC1}\AssassinsCreed_Dx9.exe"),
        "run=none",
        1,
    );
    refused(text, 17, ProfileErrorKind::ArgsNeedDirect);
    // The pattern, one space between, 1 to 8, at most 512 bytes.
    let a63 = "a".repeat(63);
    let eight = vec![format!("-{a63}"); 8].join(" ");
    assert_eq!(eight.len(), 519);
    for args in [
        "",
        " ",
        "-a  -b",
        " -a",
        "-a ",
        "-a\t-b",
        "dx9",
        "-a \"b\"",
        "-a %x%",
        "-a,-b",
        "-a -b -c -d -e -f -g -h -i",
        eight.as_str(),
        "None",
    ] {
        let text = with_line_run(17, &format!("args={args}"));
        let e = err(text.as_bytes());
        // A tab is a control character, refused before the key is read.
        if args.contains('\t') {
            assert_eq!(e, at(17, ProfileErrorKind::ControlChar));
        } else {
            assert_eq!(
                e,
                at(17, ProfileErrorKind::BadValue { key: "args" }),
                "{args:?}"
            );
        }
    }
    // Exactly 512 bytes: accepted; one more: refused.
    let mut parts = vec![format!("-{a63}"); 7];
    parts.push(format!("-{}", "b".repeat(56)));
    let exact = parts.join(" ");
    assert_eq!(exact.len(), MAX_ARGS_BYTES);
    let p = decode(with_line_run(17, &format!("args={exact}")).as_bytes()).unwrap();
    assert_eq!(p.args.len(), MAX_ARGS);
    assert_eq!(args_value(&p.args), exact);
    parts[7].push('b');
    refused(
        with_line_run(17, &format!("args={}", parts.join(" "))),
        17,
        ProfileErrorKind::BadValue { key: "args" },
    );
    // Arguments without run, on Steam's own command.
    let p = LaunchProfile {
        args: vec![LaunchArg::parse("-dx9").unwrap()],
        cpu: None,
        ..direct()
    };
    let text = String::from_utf8(encode(&p).unwrap()).unwrap();
    assert!(text.ends_with("cpu=none\nrun=none\nargs=-dx9\n"), "{text}");
    assert_eq!(decode(text.as_bytes()).unwrap(), p);
    // The writer refuses arguments with watch.
    let p = LaunchProfile {
        args: vec![LaunchArg::parse("-dx9").unwrap()],
        ..watch_v2()
    };
    assert_eq!(
        encode(&p).unwrap_err(),
        at(17, ProfileErrorKind::ArgsNeedDirect)
    );
}

#[test]
fn format_3_order_and_old_keys() {
    // run and args only in format 3, in their order, after the cpu lines.
    let text = format!("{GOLDEN}run=none\n");
    assert_eq!(err(text.as_bytes()), at(15, ProfileErrorKind::UnknownKey));
    let text = GOLDEN_RUN.replacen("rerun-profile 3", "rerun-profile 2", 1);
    assert_eq!(
        err(text.as_bytes()),
        at(
            15,
            ProfileErrorKind::BadValue {
                key: "cpu.exclude_first"
            }
        )
    );
    let mut lines: Vec<&str> = GOLDEN_RUN.lines().collect();
    lines.swap(15, 16);
    let swapped = lines.join("\n") + "\n";
    assert_eq!(
        err(swapped.as_bytes()),
        at(16, ProfileErrorKind::UnexpectedKey { expected: "run" })
    );
    // cpu=none skips the seven cpu lines; a cpu line after it is misplaced.
    let none = "rerun-profile 3\nmethod=direct\nstart=C:\\g.exe\ntarget=C:\\g.exe\nbitness=x64\n\
                priority=none\nwatch_timeout_s=120\ncpu=none\ncpu.prefer=any\nrun=none\nargs=none\n";
    assert_eq!(
        err(none.as_bytes()),
        at(9, ProfileErrorKind::UnexpectedKey { expected: "run" })
    );
    // Every truncation names the first missing key.
    let lines: Vec<&str> = GOLDEN_RUN.lines().collect();
    for keep in 1..lines.len() {
        let cut = lines[..keep].join("\n") + "\n";
        let expected = KEYS_3[keep - 1];
        assert_eq!(
            err(cut.as_bytes()),
            at(keep + 1, ProfileErrorKind::Truncated { expected }),
            "{keep} lines"
        );
    }
    // Nothing after args.
    let text = format!("{GOLDEN_RUN}args=none\n");
    assert_eq!(err(text.as_bytes()), at(18, ProfileErrorKind::DuplicateKey));
}

#[test]
fn the_largest_format_3_profile_fits_4_kib() {
    // ADR 0032 amendment P5-OE, S3: non-ASCII paths of 259 UTF-16 units each (start, target =
    // run, three bytes of UTF-8 per unit) and 512 bytes of args: about 3 KiB, above the old
    // 2 KiB inline limit, below the planner's 4 KiB and the shim's 8 KiB read limit.
    let folder = format!(r"C:\{}", "名".repeat(240));
    let name = |stem: &str| {
        let pad = 259 - folder.encode_utf16().count() - 1 - stem.len() - 4;
        format!(r"{folder}\{stem}{}.exe", "名".repeat(pad))
    };
    let start = name("s");
    let run = name("r");
    assert_eq!(start.encode_utf16().count(), 259);
    assert_eq!(run.encode_utf16().count(), 259);
    let mut parts = vec![format!("-{}", "a".repeat(63)); 7];
    parts.push(format!("-{}", "b".repeat(56)));
    let p = LaunchProfile {
        method: Method::Direct,
        start,
        target: run.clone(),
        bitness: Bitness::X86,
        priority: Some(Priority::AboveNormal),
        watch_timeout_s: 120,
        cpu: Some(CpuRule {
            exclude_first: Some(ExcludeFirst::Core),
            prefer_l3: Some(PreferL3::Largest),
            max_threads: Some(4096),
            ..rule()
        }),
        run: Some(run),
        args: parts.iter().map(|a| LaunchArg::parse(a).unwrap()).collect(),
    };
    let bytes = encode(&p).unwrap();
    assert!(
        bytes.len() > 2 << 10 && bytes.len() < 4 << 10,
        "{}",
        bytes.len()
    );
    assert_eq!(decode(&bytes).unwrap(), p);
}
