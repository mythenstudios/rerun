//! F-G (P5-1, ADR 0027): `rerun_core::flow::game` against the fake with an index signed by the
//! published test key, in the shape of Assassin's Creed (every ID and step invented): the
//! variant `patch` is listed under two issues with identical steps, `online` has a `when` that
//! is no here and a second variant with a CPU rule.
//! - F-G1 one fix per variant ID: `patch` once with two `Solved` (`controller` yes, `online`
//!   no; the evidence per issue), nothing refused; `limit` its own fix.
//! - F-G2 a `BattlEye` folder: `patch` refused per variant (anti-cheat, `compat_layer`) while
//!   each issue keeps its own `when`; the CPU rule only warned.
//! - F-G3 the lookup before the game: no index, no Topo for another app.

use std::path::Path;

use rerun_core::catalog::key::test_key;
use rerun_core::flow::{self, Env, Found, GameView, Lookup, MatchView};
use rerun_core::sys::fake::{FakeHttp, FakeSystem};
use rerun_core::topo::{Refusal, StepKind, Tri};

use crate::cli::Exit;
use crate::confirm::Answer;
use crate::lm_tests::{G, lm_sys, steps};
use crate::tests::{INSTALL, expect};
use crate::topo_tests::sha256_of;

const INDEX: &str = r"D:\Work\index.json";
const SIG: &str = r"D:\Work\index.json.sig";

fn index(sha: &str) -> String {
    let step = r#"{"compat_layer":{"exe":"game.exe","layers":["HIGHDPIAWARE"]}}"#;
    let repo = r#"{"type":"repo","url":"https://github.com/example/patch"}"#;
    let wiki = r#"{"type":"pcgw","url":"https://www.pcgamingwiki.com/wiki/Invented_Game"}"#;
    format!(
        r#"{{"format":1,"seq":1,"issued":"2026-11-11T12:00:00Z","topos":[{{"format":1,"id":"invented-ac","title":"Invented AC","status":"active","rev":1,
"match":{{"steam_appid":220,"exes":[{{"path":"game.exe","sha256":"{sha}","api":"d3d9"}}]}},
"launch":{{"chain":["steam"],"method":"auto","start":"FFLauncher.exe"}},
"issues":[
 {{"id":"controller","title":"Controllers","variants":[{{"id":"patch","status":"unverified","kind":"fix","steps":[{step}],"sources":[{repo}]}}]}},
 {{"id":"online","title":"Online","when":{{"gpu.vendor":"nvidia"}},"variants":[
   {{"id":"patch","status":"verified","kind":"fix","steps":[{step}],"sources":[{repo},{wiki}]}},
   {{"id":"limit","status":"verified","kind":"fix","steps":[{{"cpu":{{"max_threads":8}}}}]}}]}}
]}}],"packages":[]}}"#
    )
}

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

fn game(sys: &FakeSystem, app_id: u32) -> GameView {
    let http = FakeHttp::default();
    let install = Ok(Path::new(INSTALL).to_path_buf());
    let g = flow::guard(Env {
        sys,
        http: &http,
        install: &install,
    })
    .map_err(|_| "guard")
    .unwrap();
    flow::game(&g, app_id).map_err(|_| "game").unwrap()
}

fn matched(v: GameView) -> Box<MatchView> {
    match v.lookup {
        Lookup::Read {
            found: Found::One(m),
            ..
        } => m,
        _ => panic!("not exactly one matching Topo"),
    }
}

#[test]
fn f_g1_one_fix_per_variant_id() {
    let m = matched(game(&sys(), 220));
    let ids: Vec<&str> = m.fixes.iter().map(|f| f.variant.as_str()).collect();
    assert_eq!(ids, ["patch", "limit"]);
    let patch = &m.fixes[0];
    let solved: Vec<(&str, Tri, usize)> = patch
        .solves
        .iter()
        .map(|s| (s.issue.as_str(), s.when, s.sources.len()))
        .collect();
    assert_eq!(
        solved,
        [("controller", Tri::Yes, 1), ("online", Tri::No, 2)]
    );
    assert_eq!(patch.refused, None);
    assert!(patch.warned.is_empty());
    assert_eq!(m.fixes[1].solves.len(), 1);
    assert_eq!(m.fixes[1].solves[0].issue, "online");
    // The report keeps every issue and variant as the engine sees them.
    assert_eq!(m.report.issues.len(), 2);
    assert_eq!(m.report.issues[1].variants.len(), 2);
}

#[test]
fn f_g2_anti_cheat_refuses_per_variant() {
    let sys = sys();
    sys.fake_fs()
        .mkdir_all(Path::new(&format!(r"{G}\BattlEye")))
        .unwrap();
    sys.fake_fs().sync_all();
    let m = matched(game(&sys, 220));
    let patch = &m.fixes[0];
    assert_eq!(
        patch.refused,
        Some(Refusal::AntiCheat(StepKind::CompatLayer))
    );
    let whens: Vec<Tri> = patch.solves.iter().map(|s| s.when).collect();
    assert_eq!(whens, [Tri::Yes, Tri::No]);
    let limit = &m.fixes[1];
    assert_eq!(limit.refused, None);
    assert_eq!(limit.warned, [StepKind::LaunchDirect]);
}

#[test]
fn f_g3_the_lookup_before_the_game() {
    let v = game(&lm_sys(false, &steps(8)), 220);
    assert!(matches!(v.lookup, Lookup::NoIndex));
    let v = game(&sys(), 221);
    assert!(matches!(v.lookup, Lookup::NoTopo { seq: 1, ref aside } if aside.is_empty()));
}
