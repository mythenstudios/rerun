//! C-TE (P4-4): `rerun plan <app-id>` against the fake, with an index signed by the published
//! test key (feature `test-key`). Every Topo, ID and hash is invented or computed here.
//! - C-TE1 no index: a report line, nothing created.
//! - C-TE2 the report: the Topo, the matching executable, the launch (`auto` → `direct`), each
//!   issue with `when` here, each variant; nothing stored.
//! - C-TE3 `--pick … --dry-run`: the origin line before the preview; nothing stored. Without
//!   `--dry-run` the plan is stored and its head names the Topo.
//! - C-TE4 another content of the game: no match, nothing offered; with `--pick` refused.
//! - C-TE5 an anti-cheat folder: the report says so, `compat_layer` is refused.
//! - C-TE6 `--pick` with a step file is a usage error; a pick of the wrong form too.
//! - C-TE11 to C-TE13 the golden plans (P5-1): frozen bytes and hashes in `tests/fixtures/plan/`
//!   (a launch profile and a compat layer; an `ini_set` on the user data folder; a package).

use std::path::Path;

use rerun_core::catalog::key::test_key;
use rerun_core::detect::exe::{HashLimits, HashOutcome, inspect_exe};
use rerun_core::detect::pe::Limits;
use rerun_core::path::RelPath;
use rerun_core::policy::root::{ForbiddenRoots, GameDir};
use rerun_core::sys::fake::{FakeHttp, FakeReply, FakeSystem};

use crate::cli::Exit;
use crate::confirm::Answer;
use crate::lm_tests::{G, lm_sys, steps};
use crate::tests::{INSTALL, RERUN, expect, run_to_http};

const INDEX: &str = r"D:\Work\index.json";
const SIG: &str = r"D:\Work\index.json.sig";

pub(crate) fn sha256_of(sys: &FakeSystem, rel: &str) -> String {
    let fr = ForbiddenRoots::resolve(sys, Path::new(INSTALL)).unwrap();
    let g = GameDir::open_manual(sys, &fr, Path::new(G)).unwrap();
    let f = inspect_exe(
        &g,
        &RelPath::parse(rel).unwrap(),
        &Limits::DEFAULT,
        Some(&HashLimits::DEFAULT),
    )
    .unwrap();
    match f.hashes {
        HashOutcome::Done(h) => h.sha256,
        other => panic!("{other}"),
    }
}

fn index(game_sha256: &str) -> String {
    format!(
        r#"{{"format":1,"seq":1,"issued":"2026-11-09T12:00:00Z","topos":[{{"format":1,"id":"invented-game","title":"Invented Game","status":"active","rev":2,
"match":{{"steam_appid":220,"exes":[{{"path":"game.exe","sha256":"{game_sha256}","api":"d3d9"}}]}},
"launch":{{"chain":["steam"],"method":"auto","start":"FFLauncher.exe","cpu":{{"max_threads":4}}}},
"issues":[
 {{"id":"cores","title":"Too many cores","variants":[{{"id":"limit","status":"verified","kind":"fix","steps":[{{"cpu":{{"max_threads":8,"single_l3":true,"smt":false}}}}]}}]}},
 {{"id":"nvidia","title":"NVIDIA only","when":{{"gpu.vendor":"nvidia"}},"variants":[]}},
 {{"id":"display","title":"Display","variants":[{{"id":"layer","status":"unverified","kind":"fix","steps":[{{"compat_layer":{{"exe":"game.exe","layers":["HIGHDPIAWARE"]}}}}]}}]}}
]}},{{"format":1,"id":"invented-game-old","title":"Invented Game (old)","status":"retired","rev":1,"match":{{"steam_appid":220,"exes":[{{"path":"game.exe","sha256":"{game_sha256}","api":"d3d9"}}]}},"issues":[]}}],"packages":[]}}"#
    )
}

/// `lm_sys` with the index for its `game.exe` imported.
pub(crate) fn sys() -> FakeSystem {
    let sys = lm_sys(false, &steps(8));
    let ix = index(&sha256_of(&sys, "game.exe"));
    sys.fake_fs()
        .put_file(Path::new(INDEX), ix.as_bytes())
        .unwrap();
    sys.fake_fs()
        .put_file(Path::new(SIG), &test_key::sign(ix.as_bytes()))
        .unwrap();
    sys.fake_fs().sync_all();
    expect(
        &sys,
        &["index", "import", INDEX, SIG],
        Answer::No,
        Exit::Report,
    );
    sys
}

fn plans(sys: &FakeSystem) -> usize {
    #[expect(clippy::disallowed_methods, reason = "test: look at the fake's folder")]
    let d = rerun_core::sys::Fs::open_dir(sys.fake_fs(), Path::new(&format!(r"{RERUN}\plans")));
    d.map_or(0, |d| d.read_dir(None).unwrap().len())
}

#[test]
fn c_te1_no_index() {
    let sys = lm_sys(false, &steps(8));
    let r = expect(&sys, &["plan", "220"], Answer::No, Exit::Report);
    assert!(r.stdout.starts_with("no signed index"), "{}", r.stdout);
    let r = expect(
        &sys,
        &["plan", "220", "--pick", "cores/limit"],
        Answer::No,
        Exit::Refused,
    );
    assert!(r.stdout.starts_with("no signed index"), "{}", r.stdout);
}

#[test]
fn c_te2_the_report() {
    let sys = sys();
    let r = expect(&sys, &["plan", "220"], Answer::No, Exit::Report);
    for line in [
        "Topo invented-game rev 2 (active): Invented Game\n",
        "  executable matches: game.exe\n",
        "  launch: direct (auto), Steam starts FFLauncher.exe\n",
        "  issue cores (applies here: yes): Too many cores\n",
        "    cores/limit: verified fix\n",
        "  issue nvidia (applies here: no): NVIDIA only\n",
        "    no known fix\n",
        "    display/layer: unverified fix\n",
        "plan with --pick <issue>/<variant>",
        "Topo invented-game-old rev 1 is retired and offers nothing: Invented Game (old)\n",
        "  launch.cpu: not planned (pick a cpu step)\n",
    ] {
        assert!(r.stdout.contains(line), "{line}\n{}", r.stdout);
    }
    assert!(!r.stdout.contains("anti-cheat"), "{}", r.stdout);
    assert_eq!(plans(&sys), 0);
}

#[test]
fn c_te3_a_pick_plans_with_its_origin() {
    let sys = sys();
    let r = expect(
        &sys,
        &["plan", "220", "--pick", "cores/limit", "--dry-run"],
        Answer::No,
        Exit::Report,
    );
    let origin = r
        .stdout
        .lines()
        .find(|l| l.starts_with("from Topo invented-game rev 2 of the signed index "))
        .unwrap_or_else(|| panic!("{}", r.stdout));
    assert_eq!(
        origin.len(),
        "from Topo invented-game rev 2 of the signed index ".len() + 64
    );
    assert!(r.stdout.contains("method direct"), "{}", r.stdout);
    assert_eq!(plans(&sys), 0, "a dry run stores nothing");
    let r = expect(
        &sys,
        &["plan", "220", "--pick", "cores/limit"],
        Answer::No,
        Exit::Report,
    );
    assert_eq!(plans(&sys), 1, "{}", r.stdout);
}

#[test]
fn c_te4_no_match() {
    let sys = sys();
    let exe = format!(r"{G}\game.exe");
    sys.fake_fs().remove_abs(Path::new(&exe)).unwrap();
    sys.fake_fs()
        .put_file(Path::new(&exe), &crate::lm_tests::x64())
        .unwrap();
    sys.fake_fs().sync_all();
    let r = expect(&sys, &["plan", "220"], Answer::No, Exit::Report);
    assert!(
        r.stdout
            .contains("  executable has another content (no match): game.exe\n"),
        "{}",
        r.stdout
    );
    assert!(r.stdout.contains("nothing is offered"), "{}", r.stdout);
    expect(
        &sys,
        &["plan", "220", "--pick", "cores/limit"],
        Answer::No,
        Exit::Refused,
    );
}

#[test]
fn c_te5_anti_cheat() {
    let sys = sys();
    sys.fake_fs()
        .mkdir_all(Path::new(&format!(r"{G}\BattlEye")))
        .unwrap();
    sys.fake_fs().sync_all();
    let r = expect(&sys, &["plan", "220"], Answer::No, Exit::Report);
    assert!(
        r.stdout.contains("  anti-cheat: battleye: "),
        "{}",
        r.stdout
    );
    assert!(
        r.stdout.contains(
            "    display/layer: unverified fix; refused: anti-cheat found, no compat_layer for this game\n"
        ),
        "{}",
        r.stdout
    );
    assert!(
        r.stdout
            .contains("    cores/limit: verified fix; warning: anti-cheat found (cpu (direct))\n"),
        "{}",
        r.stdout
    );
    let r = expect(
        &sys,
        &["plan", "220", "--pick", "display/layer"],
        Answer::No,
        Exit::Refused,
    );
    assert!(r.stderr.contains("no compat_layer"), "{}", r.stderr);
    let r = expect(
        &sys,
        &["plan", "220", "--pick", "cores/limit", "--dry-run"],
        Answer::No,
        Exit::Report,
    );
    assert!(
        r.stdout
            .contains("warning: cores/limit: anti-cheat found; cpu (direct) is planned"),
        "{}",
        r.stdout
    );
    // `rerun scan` names it too.
    let r = expect(&sys, &["scan", "220"], Answer::No, Exit::Report);
    assert!(
        r.stdout.contains(r"    anti-cheat: battleye at BattlEye"),
        "{}",
        r.stdout
    );
}

#[test]
fn c_te6_usage() {
    let sys = sys();
    let r = expect(
        &sys,
        &["plan", r"D:\Work\steps.json", "--pick", "cores/limit"],
        Answer::No,
        Exit::Usage,
    );
    assert!(
        r.stderr.contains("--pick needs a Steam app ID"),
        "{}",
        r.stderr
    );
    assert!(
        <crate::cli::Cli as clap::Parser>::try_parse_from([
            "rerun", "plan", "220", "--pick", "Cores/x"
        ])
        .is_err()
    );
    assert!(
        <crate::cli::Cli as clap::Parser>::try_parse_from([
            "rerun", "plan", "220", "--pick", "cores"
        ])
        .is_err()
    );
}

/// Review follow-up 1: a step file gets the anti-cheat rule too (warned here, refused below).
#[test]
fn c_te7_step_files_get_the_anti_cheat_rule() {
    let sys = lm_sys(false, &steps(8));
    sys.fake_fs()
        .mkdir_all(Path::new(&format!(r"{G}\BattlEye")))
        .unwrap();
    sys.fake_fs().sync_all();
    let r = expect(
        &sys,
        &["plan", crate::tests::STEPS, "--dry-run"],
        Answer::No,
        Exit::Report,
    );
    assert!(
        r.stdout
            .starts_with("warning: anti-cheat found; cpu (direct) is planned, at your own risk\n"),
        "{}",
        r.stdout
    );
    let watch = steps(8).replace(r#""method":"direct""#, r#""method":"watch""#);
    sys.fake_fs()
        .remove_abs(Path::new(crate::tests::STEPS))
        .unwrap();
    sys.fake_fs()
        .put_file(Path::new(crate::tests::STEPS), watch.as_bytes())
        .unwrap();
    sys.fake_fs().sync_all();
    let r = expect(
        &sys,
        &["plan", crate::tests::STEPS, "--dry-run"],
        Answer::No,
        Exit::Refused,
    );
    assert!(
        r.stderr.contains("no cpu (watch) for this game"),
        "{}",
        r.stderr
    );
}

/// Review follow-up 9: digits only are always an app ID; 0 and more than u32 are usage errors.
#[test]
fn c_te8_digits_out_of_range() {
    let sys = sys();
    for bad in ["0", "4294967296", "99999999999999999999"] {
        let r = expect(&sys, &["plan", bad], Answer::No, Exit::Usage);
        assert!(
            r.stderr.contains("not a Steam app ID"),
            "{bad}: {}",
            r.stderr
        );
    }
}

/// C-TE9 (P4-12): a Topo with `user_data` and a variant with `ini_set` in it: the CLI opens
/// the folder only for that pick, the preview names it; a missing folder refuses the plan.
#[test]
fn c_te9_a_topo_with_a_user_data_folder() {
    let sys = lm_sys(false, &steps(8));
    let sha = sha256_of(&sys, "game.exe");
    let ix = format!(
        r#"{{"format":1,"seq":1,"issued":"2026-11-09T12:00:00Z","topos":[{{"format":1,"id":"invented-game","title":"Invented Game","status":"active","rev":1,
"match":{{"steam_appid":220,"exes":[{{"path":"game.exe","sha256":"{sha}","api":"d3d9"}}]}},
"user_data":{{"documents":"My Games\\Invented"}},
"issues":[
 {{"id":"threads","title":"Threads","variants":[{{"id":"ini","status":"unverified","kind":"fix","steps":[{{"ini_set":{{"root":"user_data","file":"settings.ini","values":[{{"section":"Display","key":"Width","value":"1920"}}]}}}}]}}]}},
 {{"id":"display","title":"Display","variants":[{{"id":"layer","status":"unverified","kind":"fix","steps":[{{"compat_layer":{{"exe":"game.exe","layers":["HIGHDPIAWARE"]}}}}]}}]}}
]}}],"packages":[]}}"#
    );
    sys.fake_fs()
        .put_file(Path::new(INDEX), ix.as_bytes())
        .unwrap();
    sys.fake_fs()
        .put_file(Path::new(SIG), &test_key::sign(ix.as_bytes()))
        .unwrap();
    sys.fake_fs().sync_all();
    expect(
        &sys,
        &["index", "import", INDEX, SIG],
        Answer::No,
        Exit::Report,
    );
    // The folder is missing: the pick in it is refused, another pick plans without it.
    let r = expect(
        &sys,
        &["plan", "220", "--pick", "threads/ini", "--dry-run"],
        Answer::No,
        Exit::Refused,
    );
    assert!(
        r.stdout.is_empty() || !r.stdout.contains("op 0"),
        "{}",
        r.stdout
    );
    expect(
        &sys,
        &["plan", "220", "--pick", "display/layer", "--dry-run"],
        Answer::No,
        Exit::Report,
    );
    sys.fake_fs()
        .put_file(
            Path::new(r"C:\Users\Player\Documents\My Games\Invented\settings.ini"),
            b"[Display]\r\nWidth=1280\r\n",
        )
        .unwrap();
    let r = expect(
        &sys,
        &["plan", "220", "--pick", "threads/ini", "--dry-run"],
        Answer::No,
        Exit::Report,
    );
    assert!(
        r.stdout
            .contains(r"root 1: C:\Users\Player\Documents\My Games\Invented"),
        "{}",
        r.stdout
    );
    assert!(
        r.stdout.contains("  your Documents folder:"),
        "{}",
        r.stdout
    );
    assert!(
        r.stdout.contains("note: your Documents folder"),
        "{}",
        r.stdout
    );
}

/// ADR 0024 amendment P4-13: with the published test key trusted (these tests always are), the
/// index state lives in `<AppDir>\index-test` and never in `index`; a Topo plan is applied and
/// reverted from there (`store::by_hash`), and the banner of a test-key `rerun.exe` comes from
/// `main` only, never from the commands these tests run in-process.
#[test]
fn c_te10_test_key_index_state_is_index_test() {
    let sys = sys();
    let p = expect(
        &sys,
        &["plan", "220", "--pick", "cores/limit"],
        Answer::No,
        Exit::Report,
    );
    let a = expect(
        &sys,
        &["apply", &crate::tests::hash_of(&p), "--yes"],
        Answer::No,
        Exit::Report,
    );
    let v = expect(
        &sys,
        &["revert", &crate::tests::txn_of(&a), "--yes"],
        Answer::No,
        Exit::Report,
    );
    let s = expect(&sys, &["status"], Answer::No, Exit::Report);
    assert!(
        s.stdout
            .starts_with("1 transaction: 0 not closed, 1 closed, 0 forgotten"),
        "{}",
        s.stdout
    );
    #[expect(clippy::disallowed_methods, reason = "test: look at the fake's folder")]
    let d = rerun_core::sys::Fs::open_dir(sys.fake_fs(), Path::new(RERUN)).unwrap();
    let names: Vec<String> = d
        .read_dir(None)
        .unwrap()
        .into_iter()
        .map(|e| e.name)
        .collect();
    assert!(
        names.iter().any(|n| n == "index-test"),
        "{}",
        names.join(", ")
    );
    assert!(!names.iter().any(|n| n == "index"), "{}", names.join(", "));
    for r in [&p, &a, &v, &s] {
        assert!(!r.stderr.contains("TEST-KEY"), "{}", r.stderr);
        assert!(!r.stdout.contains("TEST-KEY"), "{}", r.stdout);
    }
}

/// The lines `scripts/dev-topo-roundtrip.ps1` parses (plan P4-13, the binding test of §6): its
/// regex constants and exit codes are pinned here by their exact text, and rerun's real output
/// of the script's sequence (index import, plan by app ID with a pick, apply, status, revert)
/// is checked line by line against what those regexes accept. Change both together.
#[test]
fn the_dev_topo_script_parses_rerun_s_lines() {
    use rerun_core::escape;

    use crate::messages::{HelperMsg, Message};

    let script = include_str!("../../../scripts/dev-topo-roundtrip.ps1");
    for line in [
        format!("$script:Banner = '{}'", crate::messages::TEST_KEY_BANNER),
        r"$script:ReApplyWith = '^apply with: rerun apply (?<hash>[0-9a-f]{64})$'".to_owned(),
        r"$script:ReRevertWith = '^revert with: rerun revert (?<txn>[0-9]{8}-[0-9a-f]{16})$'"
            .to_owned(),
        r"$script:ReReverted = '^transaction (?<txn>[0-9]{8}-[0-9a-f]{16}) reverted and closed$'"
            .to_owned(),
        r#"$script:ReOption = '^  (?<option>"(?<install>[^"]+)\\rerun-launch\.exe" --profile (?<id>[0-9a-f]{32}) %command%)$'"#
            .to_owned(),
        r"$script:ReProfile = '^     launch profile (?<id>[0-9a-f]{32}): method (?<method>[a-z]+), '"
            .to_owned(),
        r"$script:ReMainExe = '^  main executable: (?<exe>.+)$'".to_owned(),
        r"$script:ReFirewallRule = '^  firewall rule: '".to_owned(),
        r"$script:ReNoTransactions = '^no transactions$'".to_owned(),
        r"$script:ReStatusCounts = '^[0-9]+ transactions?: (?<open>[0-9]+) not closed, [0-9]+ closed, [0-9]+ forgotten'"
            .to_owned(),
        r"$script:ReOrphans = '^Rerun firewall rules'".to_owned(),
        r"$script:ReImported = '^index [0-9]+ imported'".to_owned(),
        r"$script:ReRegistryOp = '^op [0-9]+: (create key|set value|add tokens|set gpu preference): '"
            .to_owned(),
        r"$script:ReRoot = '^root (?<index>[0-9]+): (?<path>.+)$'".to_owned(),
        r"$script:ReSteamRoot = '^  Steam app (?<app>[0-9]+), library: '".to_owned(),
    ] {
        assert!(script.contains(&line), "the script lacks `{line}`");
    }
    for (name, exit) in [
        ("Report", Exit::Report),
        ("Fatal", Exit::Fatal),
        ("Usage", Exit::Usage),
        ("Refused", Exit::Refused),
        ("RolledBack", Exit::RolledBack),
        ("Open", Exit::Open),
    ] {
        let line = format!("$Exit{name} = {}", exit as u8);
        assert!(script.contains(&line), "the script lacks `{line}`");
    }

    let hex = |s: &str, n: usize| {
        s.len() == n
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    };
    let txn_ok = |s: &str| {
        s.len() == 25
            && s[..8].bytes().all(|b| b.is_ascii_digit())
            && &s[8..9] == "-"
            && hex(&s[9..], 16)
    };
    let line_after = |text: &str, prefix: &str| -> String {
        text.lines()
            .find_map(|l| l.strip_prefix(prefix))
            .unwrap_or_else(|| panic!("no line {prefix} in:\n{text}"))
            .to_owned()
    };

    let sys = lm_sys(false, &steps(8));
    let s = expect(&sys, &["status"], Answer::No, Exit::Report);
    assert!(
        s.stdout.lines().any(|l| l == "no transactions"),
        "{}",
        s.stdout
    );
    let ix = index(&sha256_of(&sys, "game.exe"));
    sys.fake_fs()
        .put_file(Path::new(INDEX), ix.as_bytes())
        .unwrap();
    sys.fake_fs()
        .put_file(Path::new(SIG), &test_key::sign(ix.as_bytes()))
        .unwrap();
    sys.fake_fs().sync_all();
    let i = expect(
        &sys,
        &["index", "import", INDEX, SIG],
        Answer::No,
        Exit::Report,
    );
    let seq = line_after(&i.stdout, "index ");
    let seq = seq.strip_suffix(" imported").unwrap_or(&seq);
    assert!(seq.bytes().all(|b| b.is_ascii_digit()), "{}", i.stdout);

    let p = expect(
        &sys,
        &["plan", "220", "--pick", "cores/limit"],
        Answer::No,
        Exit::Report,
    );
    let hash = line_after(&p.stdout, "apply with: rerun apply ");
    assert!(hex(&hash, 64), "{hash}");
    // The game's Steam root: a root line, then its Steam line with the app ID.
    assert!(
        p.stdout
            .contains(&format!("\nroot 0: {G}\n  Steam app 220, library: ")),
        "{}",
        p.stdout
    );
    assert_eq!(line_after(&p.stdout, "  main executable: "), "game.exe");
    let profile = line_after(&p.stdout, "     launch profile ");
    assert!(hex(&profile[..32], 32), "{profile}");
    assert!(profile[32..].starts_with(": method direct, "), "{profile}");
    for out in [
        &p.stdout,
        &crate::tests::expect(
            &sys,
            &["apply", &hash, "--dry-run"],
            Answer::No,
            Exit::Report,
        )
        .stdout,
    ] {
        let option = line_after(
            out,
            &format!("  \"{INSTALL}\\rerun-launch.exe\" --profile "),
        );
        let id = option
            .strip_suffix(" %command%")
            .unwrap_or_else(|| panic!("{option}"));
        assert!(hex(id, 32), "{option}");
        assert_eq!(id, &profile[..32]);
    }

    let a = expect(&sys, &["apply", &hash, "--yes"], Answer::No, Exit::Report);
    let txn = line_after(&a.stdout, "revert with: rerun revert ");
    assert!(txn_ok(&txn), "{txn}");
    assert!(
        a.stdout
            .contains(&format!("  \"{INSTALL}\\rerun-launch.exe\" --profile ")),
        "{}",
        a.stdout
    );
    let s = expect(&sys, &["status"], Answer::No, Exit::Report);
    assert!(
        s.stdout
            .lines()
            .any(|l| l.starts_with("1 transaction: 1 not closed, 0 closed, 0 forgotten")),
        "{}",
        s.stdout
    );
    assert!(!s.stdout.contains("Rerun firewall rules"), "{}", s.stdout);
    let v = expect(&sys, &["revert", &txn, "--yes"], Answer::No, Exit::Report);
    assert!(
        v.stdout
            .lines()
            .any(|l| l == format!("transaction {txn} reverted and closed")),
        "{}",
        v.stdout
    );
    let s = expect(&sys, &["status"], Answer::No, Exit::Report);
    assert!(
        s.stdout
            .lines()
            .any(|l| l.starts_with("1 transaction: 0 not closed, 1 closed, 0 forgotten")),
        "{}",
        s.stdout
    );

    // The registry ops the script refuses: their action words in the core's preview, and the
    // op line of a registry op (no root, so `<action>: <key>`).
    let core_preview = include_str!("../../rerun-core/src/plan/preview.rs");
    for (op, action) in [
        ("CreateKey", "create key"),
        ("SetValue", "set value"),
        ("TokenList", "add tokens"),
    ] {
        let arm = format!("Op::{op} {{ .. }} => (\"{action}\", None, None),");
        assert!(
            core_preview.contains(&arm),
            "the core preview lacks `{arm}`"
        );
    }
    assert!(core_preview.contains("Op::GpuPref { .. } => (GPU_PREF_ACTION, None, None),"));
    assert_eq!(rerun_core::plan::GPU_PREF_ACTION, "set gpu preference");
    let reg = Message::Txn(crate::messages::TxnMsg::Op {
        index: 3,
        op: crate::messages::OpRef {
            action: "set value",
            at: crate::messages::At::Reg {
                key: escape::text(r"HKCU\Software\Invented"),
            },
        },
    })
    .to_string();
    assert_eq!(reg, r"op 3: set value: HKCU\Software\Invented");

    // The firewall lines (rendered: the fake world of these tests has no firewall plan).
    let rule = Message::Helper(HelperMsg::Rule {
        direction: "outbound",
        group: "Rerun",
        name: escape::text("Rerun - invented-game - 00000001-00000000000000ab-001"),
    })
    .to_string();
    assert!(rule.starts_with("  firewall rule: "), "{rule}");
    for m in [
        HelperMsg::OrphansHeading,
        HelperMsg::OrphansUnreadable {
            error: escape::text("x"),
        },
        HelperMsg::OrphansNoJournal {
            error: escape::text("x"),
        },
    ] {
        let l = Message::Helper(m).to_string();
        assert!(l.starts_with("Rerun firewall rules"), "{l}");
    }
}

/// The golden plans (P5-1, ADR 0027): the bytes and the hash a `rerun plan <app-id> --pick …`
/// stores for a fake world, frozen before the CLI became a renderer over `rerun_core::flow`, so
/// the extraction of the write side (P5-2a) can prove it plans exactly the same bytes. A changed
/// plan fails here and writes the new bytes to `target/plan-<name>.golden.json`; check them, then
/// copy them over `tests/fixtures/plan/<name>.json` and the hash into `<name>.sha256` only for an
/// intended change of the plan format or the planners.
#[expect(
    clippy::disallowed_methods,
    reason = "test: the golden fixtures live in the repository, not in the fake"
)]
fn golden(sys: &FakeSystem, http: &FakeHttp, args: &[&str], name: &str) {
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/plan");
    let (mut r, out) = run_to_http(sys, http, args, Answer::No, Vec::new());
    r.stdout = String::from_utf8(out).unwrap();
    assert_eq!(r.exit, Exit::Report, "{}\n{}", r.stdout, r.stderr);
    let hash = crate::tests::hash_of(&r);
    let app = rerun_core::policy::root::AppDir::open(sys, rerun_core::policy::root::Create::Never)
        .unwrap()
        .unwrap();
    let bytes = rerun_core::plan::load(&app, &hash.parse().unwrap()).unwrap();
    let golden = std::fs::read(fixtures.join(format!("{name}.json"))).unwrap_or_default();
    if bytes.bytes() != golden.as_slice() {
        let out = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join(format!("../../target/plan-{name}.golden.json"));
        std::fs::write(&out, bytes.bytes()).unwrap();
        panic!(
            "the plan differs from tests/fixtures/plan/{name}.json (hash {hash}); the new bytes \
             are in {}",
            out.display()
        );
    }
    let want = std::fs::read_to_string(fixtures.join(format!("{name}.sha256"))).unwrap();
    assert_eq!(hash, want.trim());
    assert_eq!(bytes.hash().to_string(), hash);
}

/// C-TE11: a launch profile on the profiles root and a compat layer.
#[test]
fn c_te11_the_golden_plan() {
    golden(
        &sys(),
        &FakeHttp::default(),
        &[
            "plan",
            "220",
            "--pick",
            "cores/limit",
            "--pick",
            "display/layer",
        ],
        "topo-220",
    );
}

/// C-TE12: the C-TE9 world: an `ini_set` on the Topo's user data folder below Documents (the
/// folder opened by the CLI for that pick, P4-12) and a compat layer.
#[test]
fn c_te12_the_golden_plan_with_a_user_data_folder() {
    let sys = lm_sys(false, &steps(8));
    let sha = sha256_of(&sys, "game.exe");
    let ix = format!(
        r#"{{"format":1,"seq":1,"issued":"2026-11-09T12:00:00Z","topos":[{{"format":1,"id":"invented-game","title":"Invented Game","status":"active","rev":1,
"match":{{"steam_appid":220,"exes":[{{"path":"game.exe","sha256":"{sha}","api":"d3d9"}}]}},
"user_data":{{"documents":"My Games\\Invented"}},
"issues":[
 {{"id":"threads","title":"Threads","variants":[{{"id":"ini","status":"unverified","kind":"fix","steps":[{{"ini_set":{{"root":"user_data","file":"settings.ini","values":[{{"section":"Display","key":"Width","value":"1920"}}]}}}}]}}]}},
 {{"id":"display","title":"Display","variants":[{{"id":"layer","status":"unverified","kind":"fix","steps":[{{"compat_layer":{{"exe":"game.exe","layers":["HIGHDPIAWARE"]}}}}]}}]}}
]}}],"packages":[]}}"#
    );
    import(&sys, ix.as_bytes());
    sys.fake_fs()
        .put_file(
            Path::new(r"C:\Users\Player\Documents\My Games\Invented\settings.ini"),
            b"[Display]\r\nWidth=1280\r\n",
        )
        .unwrap();
    sys.fake_fs().sync_all();
    golden(
        &sys,
        &FakeHttp::default(),
        &[
            "plan",
            "220",
            "--pick",
            "threads/ini",
            "--pick",
            "display/layer",
        ],
        "topo-220-user-data",
    );
}

/// C-TE13 (TK): a `package` step of the signed index, fetched and unpacked from its release
/// zip (`rerun package fetch`), planned as a `file_install` of the package's files for the
/// game's architecture.
#[test]
fn c_te13_the_golden_plan_with_a_package() {
    use rerun_core::pkg::archive::testfx::{ZipEntry, zip};
    const ASSET: &str = "https://github.com/owner/fix-pack/releases/download/v1.0/fix-pack.zip";
    const STORE: &str =
        "https://release-assets.githubusercontent.com/github-production-release-asset/1/2?sp=r";
    let upper = |b: &[u8]| -> String {
        use sha2::{Digest, Sha256};
        Sha256::digest(b)
            .iter()
            .map(|x| format!("{x:02X}"))
            .collect()
    };
    let archive = zip(&[
        ZipEntry::file("bin/fix.dll", b"the fix"),
        ZipEntry::file("fix.ini", b"[Fix]\r\nOn=1\r\n"),
    ]);
    let sys = lm_sys(false, &steps(8));
    let sha = sha256_of(&sys, "game.exe");
    let ix = format!(
        r#"{{"format":1,"seq":1,"issued":"2026-11-09T12:00:00Z","topos":[{{"format":1,"id":"invented-game","title":"Invented Game","status":"active","rev":1,
"match":{{"steam_appid":220,"exes":[{{"path":"game.exe","sha256":"{sha}","api":"d3d9"}}]}},
"issues":[
 {{"id":"crash","title":"Crash","variants":[{{"id":"fix-pack","status":"unverified","kind":"fix","steps":[{{"package":"fix-pack"}}]}}]}}
]}}],"packages":[{{"format":1,"id":"fix-pack","name":"Fix pack","status":"active","tier":"established","source":{{"repo":"https://github.com/owner/fix-pack","release":"{ASSET}"}},"version":"1.0","sha256":"{a}","license":"MIT","arch":["x86"],"slots":["fix.dll"],"files":[{{"from":"bin/fix.dll","to":"fix.dll","sha256":"{d}"}},{{"from":"fix.ini","to":"fix.ini","sha256":"{i}","config":true}}]}}]}}"#,
        a = upper(&archive),
        d = upper(b"the fix"),
        i = upper(b"[Fix]\r\nOn=1\r\n"),
    );
    import(&sys, ix.as_bytes());
    let http = FakeHttp::default();
    http.reply(ASSET, FakeReply::redirect(302, STORE));
    http.reply(STORE, FakeReply::ok(&archive));
    let (r, _) = run_to_http(
        &sys,
        &http,
        &["package", "fetch", "fix-pack@1.0"],
        Answer::No,
        Vec::new(),
    );
    assert_eq!(r.exit, Exit::Report, "{}", r.stderr);
    golden(
        &sys,
        &http,
        &["plan", "220", "--pick", "crash/fix-pack"],
        "topo-220-package",
    );
}

/// C-TE14 (P5-2a, finding 12 of plan P5): a game updated between `rerun plan` and `rerun
/// apply` (another `game.exe`): `apply` with and without `--dry-run` is refused (exit 3) with the
/// reason on stderr, nothing applied; with the build the plan was made for it passes again.
#[test]
#[expect(
    clippy::disallowed_methods,
    reason = "test: read and replace a fixture file of the fake"
)]
fn c_te14_a_game_updated_since_the_plan_is_refused() {
    let sys = sys();
    let p = expect(
        &sys,
        &["plan", "220", "--pick", "display/layer"],
        Answer::No,
        Exit::Report,
    );
    let hash = crate::tests::hash_of(&p);
    let exe = format!(r"{G}\game.exe");
    let original = {
        use rerun_core::sys::Fs as _;
        let d = sys.fake_fs().open_dir(Path::new(G)).unwrap();
        d.read(&RelPath::parse("game.exe").unwrap()).unwrap()
    };
    let replace = |b: &[u8]| {
        sys.fake_fs().remove_abs(Path::new(&exe)).unwrap();
        sys.fake_fs().put_file(Path::new(&exe), b).unwrap();
        sys.fake_fs().sync_all();
    };
    let mut updated = original.clone();
    updated.extend_from_slice(b"patch 1.01");
    replace(&updated);
    for args in [
        vec!["apply", hash.as_str(), "--dry-run"],
        vec!["apply", hash.as_str(), "--yes"],
    ] {
        let r = expect(&sys, &args, Answer::No, Exit::Refused);
        let line = r
            .stderr
            .lines()
            .find(|l| l.contains("changed since the plan"))
            .unwrap_or_else(|| panic!("{}", r.stderr));
        assert!(
            line.ends_with(&format!(
                "the main executable {exe} changed since the plan (a game update, or another fix \
                 changed it); plan again"
            )),
            "{line}"
        );
        assert!(!r.stdout.contains("applied as"), "{}", r.stdout);
    }
    replace(&original);
    expect(
        &sys,
        &["apply", hash.as_str(), "--dry-run"],
        Answer::No,
        Exit::Report,
    );
}

/// C-TE15 (P5-2a review): a Topo plan stored by an earlier version (no `main_sha256`) is
/// refused at `rerun apply` with exit 3 and the "plan again" line, never applied unchecked.
#[test]
#[expect(
    clippy::disallowed_methods,
    reason = "test: read and plant a stored plan in the fake"
)]
fn c_te15_an_old_stored_topo_plan_is_refused() {
    use sha2::{Digest, Sha256};
    let sys = sys();
    let p = expect(
        &sys,
        &["plan", "220", "--pick", "display/layer"],
        Answer::No,
        Exit::Report,
    );
    let hash = crate::tests::hash_of(&p);
    let plans = format!(r"{RERUN}\plans");
    let stored = {
        use rerun_core::sys::Fs as _;
        let d = sys.fake_fs().open_dir(Path::new(&plans)).unwrap();
        d.read(&RelPath::parse(&format!("{hash}.json")).unwrap())
            .unwrap()
    };
    let text = String::from_utf8(stored).unwrap();
    const FIELD: &str = r#","main_sha256":""#;
    let at = text.find(FIELD).unwrap();
    let old = format!("{}{}", &text[..at], &text[at + FIELD.len() + 64 + 1..]);
    assert!(
        !old.contains("main_sha256") && old.contains(r#""source":"#),
        "{old}"
    );
    let old_hash: String = Sha256::digest(old.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    sys.fake_fs()
        .put_file(
            Path::new(&format!(r"{plans}\{old_hash}.json")),
            old.as_bytes(),
        )
        .unwrap();
    sys.fake_fs().sync_all();
    for args in [
        vec!["apply", old_hash.as_str(), "--dry-run"],
        vec!["apply", old_hash.as_str(), "--yes"],
    ] {
        let r = expect(&sys, &args, Answer::No, Exit::Refused);
        assert!(
            r.stderr.lines().any(|l| l
                .contains("a plan from a Topo without the hash of the game's main executable")
                && l.ends_with("plan again")),
            "{}",
            r.stderr
        );
        assert!(!r.stdout.contains("applied as"), "{}", r.stdout);
    }
}

/// Imports `ix`, signed with the test key.
fn import(sys: &FakeSystem, ix: &[u8]) {
    sys.fake_fs().put_file(Path::new(INDEX), ix).unwrap();
    sys.fake_fs()
        .put_file(Path::new(SIG), &test_key::sign(ix))
        .unwrap();
    sys.fake_fs().sync_all();
    expect(
        sys,
        &["index", "import", INDEX, SIG],
        Answer::No,
        Exit::Report,
    );
}
