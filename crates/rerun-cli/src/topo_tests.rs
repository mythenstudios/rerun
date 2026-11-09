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

use std::path::Path;

use rerun_core::catalog::key::test_key;
use rerun_core::detect::exe::{HashLimits, HashOutcome, inspect_exe};
use rerun_core::detect::pe::Limits;
use rerun_core::path::RelPath;
use rerun_core::policy::root::{ForbiddenRoots, GameDir};
use rerun_core::sys::fake::FakeSystem;

use crate::cli::Exit;
use crate::confirm::Answer;
use crate::lm_tests::{G, lm_sys, steps};
use crate::tests::{INSTALL, RERUN, expect};

const INDEX: &str = r"D:\Work\index.json";
const SIG: &str = r"D:\Work\index.json.sig";

fn sha256_of(sys: &FakeSystem, rel: &str) -> String {
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
"launch":{{"chain":["steam"],"method":"auto","start":"FFLauncher.exe"}},
"issues":[
 {{"id":"cores","title":"Too many cores","variants":[{{"id":"limit","status":"verified","kind":"fix","steps":[{{"cpu":{{"max_threads":8,"single_l3":true,"smt":false}}}}]}}]}},
 {{"id":"nvidia","title":"NVIDIA only","when":{{"gpu.vendor":"nvidia"}},"variants":[]}},
 {{"id":"display","title":"Display","variants":[{{"id":"layer","status":"unverified","kind":"fix","steps":[{{"compat_layer":{{"exe":"game.exe","layers":["HIGHDPIAWARE"]}}}}]}}]}}
]}}],"packages":[]}}"#
    )
}

/// `lm_sys` with the index for its `game.exe` imported.
fn sys() -> FakeSystem {
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
