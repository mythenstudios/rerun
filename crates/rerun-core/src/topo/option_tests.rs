//! Game options (ADR 0032 and its amendment P5-OE, slice O-1) through the Topo engine, against
//! the fake. Every Topo, folder, hash and ID is invented.
//!
//! - OE1 the round trip: an `ini_set` value alone (no pick) → plan (`source.picks` empty,
//!   `source.choices` the value) → apply → `verify` `After` → revert → the game folder
//!   identical; the same with a fix in one plan.
//! - OE2 the selection: unknown option or value, `unchanged`, two values of one option, nothing
//!   selected, too many choices.
//! - OE3 one INI file set by a fix and an option: the engine refuses the plan, naming both and
//!   the file (O-1 review S1).
//! - OE4 `start` and `launch_args` are planned (O-2b; an executable not matched here is said so);
//!   with anti-cheat they are refused (also a value of `launch_args` alone, review N2), an
//!   `ini_set` value is warned.
//! - OE5 the report lists every option with what the engine says per value.
//! - OE6 `needs_user_data` for a chosen value in the user data folder.
//! - OE7 the form of `PlanSource` with choices; a plan without choices has the bytes it had.

use std::path::Path;

use sha2::{Digest, Sha256};

use super::{
    EngineError, EngineSelection, Facts, StepKind, TopoPlan, ValueRefusal, Warning,
    needs_user_data, plan, read_game, report,
};
use crate::catalog::check::{self, Rules};
use crate::catalog::model::Topo;
use crate::detect::pe::testfx::Builder as PeBuilder;
use crate::exec::rebind_tests::rb_sys;
use crate::exec::tests::{Env, same, snap_at};
use crate::hw::{self, GpuArchTable};
use crate::journal::{Closing, Observed};
use crate::plan::{Choice, MAX_CHOICES, Op, Pick, PlanSource};
use crate::policy::registry::RegPolicy;
use crate::policy::root::StoreDir;
use crate::prim::PlanCtx;
use crate::prim::tests::{STEAM_GAME, STEAM_LIB, app, fr};
use crate::sys::fake::FakeSystem;

const APP: u32 = 220;
const INDEX: [u8; 32] = [5; 32];

fn sha256(b: &[u8]) -> String {
    Sha256::digest(b)
        .iter()
        .map(|x| format!("{x:02X}"))
        .collect()
}

fn put(sys: &FakeSystem, rel: &str, data: &[u8]) {
    let abs = format!(r"{STEAM_GAME}\{rel}");
    let _ = sys.fake_fs().remove_abs(Path::new(&abs));
    sys.fake_fs().put_file(Path::new(&abs), data).unwrap();
    sys.sync_all();
}

fn x64() -> Vec<u8> {
    PeBuilder::x64().build().bytes
}

fn x86() -> Vec<u8> {
    PeBuilder::x86().build().bytes
}

/// Steam app 220 in `G`: an x64 `game.exe`, an x86 `game_dx9.exe` and `FFLauncher.exe`, and
/// `cfg\Game.ini` of the INI tests (`[Display] Width=1280`, `[Audio] Volume=5`).
fn game_sys() -> FakeSystem {
    let sys = rb_sys();
    put(&sys, "game.exe", &x64());
    put(&sys, "game_dx9.exe", &x86());
    put(&sys, "FFLauncher.exe", &x86());
    sys
}

/// A draft Topo (so `start` and `launch_args` load): options `frame-cap` (two `ini_set` values
/// on `cfg\Game.ini`), `api` (`start` of `game_dx9.exe`, which is there, or of
/// `game_dx10.exe`, which is not), `intro` (`start` with `launch_args`), `user` (an `ini_set` in
/// the user data folder); issues `settings` (`ini_set` on `cfg\Game.ini` too) and `display`
/// (`compat_layer`).
fn topo() -> Topo {
    let j = format!(
        r#"{{"format":1,"id":"invented-game","title":"Invented Game","status":"draft","rev":2,
"match":{{"steam_appid":{APP},"exes":[
  {{"path":"game.exe","sha256":"{game}","api":"d3d9"}},
  {{"path":"game_dx9.exe","sha256":"{dx9}","api":"d3d9"}},
  {{"path":"game_dx10.exe","sha256":"{dx10}","api":"d3d10"}}]}},
"launch":{{"chain":["steam"],"method":"auto","start":"FFLauncher.exe"}},
"user_data":{{"documents":"My Games\\G"}},
"options":[
 {{"id":"frame-cap","title":"Frame rate cap","sources":[{{"type":"pcgw","url":"https://www.pcgamingwiki.com/wiki/Invented#Cap"}}],"values":[
   {{"id":"wide","title":"Wide","status":"verified","steps":[{{"ini_set":{{"file":"cfg\\Game.ini","values":[{{"section":"Display","key":"Width","value":"1920"}}]}}}}]}},
   {{"id":"quiet","title":"Quiet","status":"reported","steps":[{{"ini_set":{{"file":"cfg\\Game.ini","values":[{{"section":"Audio","key":"Volume","value":"1"}}]}}}}]}}]}},
 {{"id":"api","title":"Graphics API","sources":[{{"type":"pcgw","url":"https://www.pcgamingwiki.com/wiki/Invented#API"}}],"values":[
   {{"id":"dx9","title":"DirectX 9","status":"unverified","steps":[{{"start":"game_dx9.exe"}}]}},
   {{"id":"dx10","title":"DirectX 10","status":"unverified","steps":[{{"start":"game_dx10.exe"}}]}}]}},
 {{"id":"intro","title":"Intro","sources":[{{"type":"pcgw","url":"https://www.pcgamingwiki.com/wiki/Invented#Intro"}}],"values":[
   {{"id":"skip","title":"Skip","status":"unverified","steps":[{{"start":"game_dx9.exe"}},{{"launch_args":["-skipintro"]}}]}}]}},
 {{"id":"user","title":"User","sources":[{{"type":"pcgw","url":"https://www.pcgamingwiki.com/wiki/Invented#User"}}],"values":[
   {{"id":"ud","title":"In Documents","status":"unverified","steps":[{{"ini_set":{{"root":"user_data","file":"settings.ini","values":[{{"section":"Display","key":"Width","value":"1920"}}]}}}}]}}]}}
],
"issues":[
 {{"id":"settings","title":"Settings","variants":[
   {{"id":"ini","status":"reported","kind":"fix","steps":[{{"ini_set":{{"file":"cfg\\Game.ini","values":[{{"section":"Display","key":"Height","value":"1080"}}]}}}}]}}]}},
 {{"id":"display","title":"Display","variants":[
   {{"id":"layer","status":"unverified","kind":"fix","steps":[{{"compat_layer":{{"exe":"game.exe","layers":["ZZ_FLAG_A"]}}}}]}}]}}
]}}"#,
        game = sha256(&x64()),
        dx9 = sha256(&x86()),
        dx10 = "AB".repeat(32),
    );
    let t: Topo = serde_json::from_str(&j).unwrap_or_else(|e| panic!("{e}: {j}"));
    check::topo(&t, Rules::Source).unwrap_or_else(|e| panic!("{e}"));
    t
}

fn choices(c: &[&str]) -> Vec<Choice> {
    c.iter()
        .map(|s| {
            let (option, value) = s.split_once('=').unwrap();
            Choice {
                option: option.to_owned(),
                value: value.to_owned(),
            }
        })
        .collect()
}

fn picks(p: &[&str]) -> Vec<Pick> {
    p.iter()
        .map(|s| {
            let (issue, variant) = s.split_once('/').unwrap();
            Pick {
                issue: issue.to_owned(),
                variant: variant.to_owned(),
            }
        })
        .collect()
}

fn profile() -> hw::SystemProfile {
    hw::read(
        &FakeSystem::builder().build().unwrap(),
        Some(GpuArchTable::builtin().unwrap()),
    )
}

/// Plans picks `p` and choices `c` of `t` on `sys`.
fn plan_on(sys: &FakeSystem, t: &Topo, p: &[&str], c: &[&str]) -> Result<TopoPlan, EngineError> {
    let fr = fr(sys);
    let store = StoreDir::open(sys, &fr, Path::new(STEAM_LIB)).unwrap();
    let g = store.game(&fr, "G").unwrap();
    let gf = read_game(&g, t);
    let a = app(sys);
    let ctx = PlanCtx {
        game: &g,
        app: Some(&a),
        steam_app: Some(APP),
        main_exe: None,
        reg: RegPolicy.reader(sys),
        app_path: None,
        user_data: None,
    };
    let prof = profile();
    let facts = Facts {
        profile: &prof,
        table: Some(GpuArchTable::builtin().unwrap()),
        game: &gf,
        packages: &[],
    };
    let (p, c) = (picks(p), choices(c));
    plan(
        &INDEX,
        t,
        &facts,
        &EngineSelection {
            manual: None,
            picks: &p,
            choices: &c,
        },
        &ctx,
        &crate::exec::LiveState::default(),
    )
}

fn snap(env: &Env) -> crate::sys::snapshot::Snapshot {
    snap_at(&env.sys, STEAM_GAME)
}

// ---------- OE1 ----------

#[test]
fn oe1_an_ini_value_alone_round_trips() {
    let env = Env::new(game_sys());
    let t = topo();
    let before = snap(&env);
    let tp = plan_on(&env.sys, &t, &[], &["frame-cap=wide"]).unwrap_or_else(|e| panic!("{e}"));
    assert!(
        matches!(tp.plan.ops.as_slice(), [Op::IniValue { .. }]),
        "{:?}",
        tp.plan.ops
    );
    assert!(tp.warnings.is_empty(), "{:?}", tp.warnings);
    let src = tp.plan.source.clone().unwrap();
    assert!(src.picks.is_empty());
    assert_eq!(src.choices, choices(&["frame-cap=wide"]));
    let bytes = tp.plan.encode().unwrap();
    let text = String::from_utf8_lossy(bytes.bytes()).into_owned();
    assert!(
        text.contains(r#""picks":[],"choices":[{"option":"frame-cap","value":"wide"}]"#),
        "{text}"
    );
    let h = crate::plan::store(&app(&env.sys), &bytes).unwrap();
    let txn = env.applied(&h);
    let ini = crate::exec::tests::read_abs(&env.sys, &format!(r"{STEAM_GAME}\cfg\Game.ini"));
    assert!(
        String::from_utf8_lossy(&ini).contains("Width=1920"),
        "applied"
    );
    assert!(env.verify(&txn).iter().all(|(_, o)| *o == Observed::After));
    assert_eq!(env.revert(&txn).unwrap().closed, Some(Closing::Reverted));
    same(&before, &snap(&env));
}

#[test]
fn oe1_a_value_and_a_fix_in_one_plan_round_trip() {
    let env = Env::new(game_sys());
    let t = topo();
    let before = snap(&env);
    let tp = plan_on(&env.sys, &t, &["display/layer"], &["frame-cap=quiet"])
        .unwrap_or_else(|e| panic!("{e}"));
    assert!(
        tp.plan.ops.iter().any(|o| matches!(o, Op::IniValue { .. })),
        "{:?}",
        tp.plan.ops
    );
    assert!(
        tp.plan
            .ops
            .iter()
            .any(|o| matches!(o, Op::TokenList { .. })),
        "{:?}",
        tp.plan.ops
    );
    let src = tp.plan.source.clone().unwrap();
    assert_eq!(src.picks, picks(&["display/layer"]));
    assert_eq!(src.choices, choices(&["frame-cap=quiet"]));
    let h = crate::plan::store(&app(&env.sys), &tp.plan.encode().unwrap()).unwrap();
    let txn = env.applied(&h);
    assert!(env.verify(&txn).iter().all(|(_, o)| *o == Observed::After));
    assert_eq!(env.revert(&txn).unwrap().closed, Some(Closing::Reverted));
    same(&before, &snap(&env));
}

// ---------- OE2 ----------

#[test]
fn oe2_the_selection_resolves_or_is_refused() {
    let sys = game_sys();
    let t = topo();
    let err = |p: &[&str], c: &[&str]| match plan_on(&sys, &t, p, c) {
        Err(e) => e,
        Ok(_) => panic!("{p:?} {c:?} planned"),
    };
    assert!(matches!(err(&[], &[]), EngineError::Picks));
    assert!(matches!(err(&[], &["fps=on"]), EngineError::UnknownOption(o) if o == "fps"));
    assert!(matches!(
        err(&[], &["frame-cap=off"]),
        EngineError::UnknownValue { option, value } if option == "frame-cap" && value == "off"
    ));
    assert!(matches!(
        err(&[], &["frame-cap=unchanged"]),
        EngineError::Unchanged(o) if o == "frame-cap"
    ));
    assert!(matches!(
        err(&[], &["frame-cap=wide", "frame-cap=quiet"]),
        EngineError::TwoValues(o) if o == "frame-cap"
    ));
    let nine: Vec<String> = (0..=MAX_CHOICES).map(|i| format!("o{i}=v")).collect();
    let nine: Vec<&str> = nine.iter().map(String::as_str).collect();
    assert!(matches!(err(&[], &nine), EngineError::Picks));
    // A pick still resolves as before; an unknown one is refused before any choice.
    assert!(matches!(
        err(&["nope/x"], &["frame-cap=wide"]),
        EngineError::UnknownIssue(i) if i == "nope"
    ));
    assert!(plan_on(&sys, &t, &["display/layer"], &[]).is_ok());
}

// ---------- OE3 ----------

#[test]
fn oe3_one_ini_file_from_a_fix_and_an_option_is_refused() {
    let sys = game_sys();
    let t = topo();
    let e = plan_on(&sys, &t, &["settings/ini"], &["frame-cap=wide"]).unwrap_err();
    assert!(
        matches!(
            &e,
            EngineError::IniFixAndOption { option, value, issue, variant, file }
                if option == "frame-cap" && value == "wide" && issue == "settings"
                    && variant == "ini" && file == r"cfg\Game.ini"
        ),
        "{e:?}"
    );
    assert_eq!(
        e.to_string(),
        r"option frame-cap=wide and fix settings/ini both set cfg\Game.ini; plan them one after the other"
    );
    // Each on its own plans.
    assert!(plan_on(&sys, &t, &["settings/ini"], &[]).is_ok());
    assert!(plan_on(&sys, &t, &[], &["frame-cap=wide"]).is_ok());
}

// ---------- OE4 ----------

#[test]
fn oe4_start_and_launch_args_plan_and_anti_cheat_refuses_them() {
    let sys = game_sys();
    let t = topo();
    let refused = |s: &FakeSystem, c: &str| match plan_on(s, &t, &[], &[c]) {
        Err(EngineError::OptionRefused { why, .. }) => why,
        other => panic!("{c}: {other:?}"),
    };
    // Planned since O-2b (the launch profile with `run` and `args`, launch_tests.rs).
    assert!(plan_on(&sys, &t, &[], &["api=dx9"]).is_ok());
    assert!(plan_on(&sys, &t, &[], &["intro=skip"]).is_ok());
    assert_eq!(refused(&sys, "api=dx10"), ValueRefusal::NotMatched);
    let e = plan_on(&sys, &t, &[], &["api=dx10"]).unwrap_err();
    assert!(
        e.to_string()
            .starts_with("api=dx10: refused: the executable"),
        "{e}"
    );
    // Anti-cheat: `start` and `launch_args` refused (S1), an `ini_set` value warned.
    sys.fake_fs()
        .mkdir_all(Path::new(&format!(r"{STEAM_GAME}\pb")))
        .unwrap();
    sys.sync_all();
    assert_eq!(
        refused(&sys, "api=dx9"),
        ValueRefusal::AntiCheat(StepKind::Start)
    );
    assert_eq!(
        refused(&sys, "intro=skip"),
        ValueRefusal::AntiCheat(StepKind::Start)
    );
    // Review N2: a value of `launch_args` alone (Steam starts the game itself) is refused by its
    // own kind.
    let mut v = serde_json::to_value(&t).unwrap();
    v["launch"]["start"] = serde_json::json!("game.exe");
    v["options"][2]["values"][0]["steps"] = serde_json::json!([{ "launch_args": ["-skipintro"] }]);
    let args_only: Topo = serde_json::from_value(v).unwrap();
    check::topo(&args_only, Rules::Source).unwrap_or_else(|e| panic!("{e}"));
    match plan_on(&sys, &args_only, &[], &["intro=skip"]) {
        Err(EngineError::OptionRefused { why, .. }) => {
            assert_eq!(why, ValueRefusal::AntiCheat(StepKind::LaunchArgs));
        }
        other => panic!("{other:?}"),
    }
    let tp = plan_on(&sys, &t, &[], &["frame-cap=wide"]).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        tp.warnings,
        [Warning::OptionAntiCheat {
            option: "frame-cap".into(),
            value: "wide".into(),
            step: StepKind::IniSet,
        }]
    );
}

// ---------- OE5 ----------

#[test]
fn oe5_the_report_lists_every_option() {
    let sys = game_sys();
    let t = topo();
    let fr = fr(&sys);
    let store = StoreDir::open(&sys, &fr, Path::new(STEAM_LIB)).unwrap();
    let g = store.game(&fr, "G").unwrap();
    let gf = read_game(&g, &t);
    let prof = profile();
    let r = report(
        &t,
        &Facts {
            profile: &prof,
            table: Some(GpuArchTable::builtin().unwrap()),
            game: &gf,
            packages: &[],
        },
    )
    .unwrap();
    let seen: Vec<(String, Option<ValueRefusal>)> = r
        .options
        .iter()
        .flat_map(|o| {
            o.values
                .iter()
                .map(move |v| (format!("{}={}", o.option.id, v.value.id), v.refused))
        })
        .collect();
    assert_eq!(
        seen,
        [
            ("frame-cap=wide".to_owned(), None),
            ("frame-cap=quiet".to_owned(), None),
            ("api=dx9".to_owned(), None),
            ("api=dx10".to_owned(), Some(ValueRefusal::NotMatched)),
            ("intro=skip".to_owned(), None),
            ("user=ud".to_owned(), None),
        ]
    );
    assert!(
        r.options
            .iter()
            .all(|o| o.values.iter().all(|v| v.warned.is_empty()))
    );
}

// ---------- OE6 ----------

#[test]
fn oe6_a_value_in_the_user_data_folder_needs_it() {
    let t = topo();
    let prof = profile();
    let need = |p: &[&str], c: &[&str]| {
        let (p, c) = (picks(p), choices(c));
        needs_user_data(
            &t,
            &EngineSelection {
                manual: None,
                picks: &p,
                choices: &c,
            },
            &prof,
        )
    };
    assert!(need(&[], &["user=ud"]));
    assert!(need(&["display/layer"], &["user=ud"]));
    assert!(!need(&[], &["frame-cap=wide"]));
    assert!(!need(&["display/layer"], &[]));
    // A selection that does not resolve needs nothing (the plan refuses it).
    assert!(!need(&[], &["user=other"]));
    // Without the folder opened, the engine refuses the value.
    let sys = game_sys();
    assert!(matches!(
        plan_on(&sys, &t, &[], &["user=ud"]),
        Err(EngineError::UserData)
    ));
}

// ---------- OE7 ----------

#[test]
fn oe7_the_source_form_with_choices() {
    let base = PlanSource {
        index: [1; 32],
        topo: "invented-game".into(),
        rev: 1,
        picks: Vec::new(),
        choices: choices(&["api=dx9"]),
        kept_profile: None,
    };
    base.check().unwrap();
    let with = |f: fn(&mut PlanSource)| {
        let mut s = base.clone();
        f(&mut s);
        s.check()
    };
    // Picks only, as before; choices only; both.
    with(|s| {
        s.picks = picks(&["a/b"]);
        s.choices.clear();
    })
    .unwrap();
    with(|s| s.picks = picks(&["a/b"])).unwrap();
    // Neither: the source's own form allows it (a plan of the user's own settings, ADR 0029);
    // the plan refuses it without `manual` (`manual_tests::m1_the_plan_form`).
    with(|s| s.choices.clear()).unwrap();
    // `unchanged`, a value twice, a bad ID, too many.
    with(|s| s.choices = choices(&["api=unchanged"])).unwrap_err();
    with(|s| s.choices = choices(&["api=dx9", "api=dx10"])).unwrap_err();
    with(|s| s.choices = choices(&["API=dx9"])).unwrap_err();
    with(|s| {
        s.choices = (0..=MAX_CHOICES)
            .map(|i| Choice {
                option: format!("o{i}"),
                value: "v".into(),
            })
            .collect();
    })
    .unwrap_err();
    // On the wire: omitted when empty, refused when unknown fields come with it.
    let mut s = base.clone();
    s.picks = picks(&["a/b"]);
    s.choices.clear();
    let j = serde_json::to_string(&s).unwrap();
    assert!(!j.contains("choices"), "{j}");
    let j = serde_json::to_string(&base).unwrap();
    assert!(
        j.contains(r#""choices":[{"option":"api","value":"dx9"}]"#),
        "{j}"
    );
    let bad = j.replace(r#""value":"dx9""#, r#""value":"dx9","x":1"#);
    assert!(serde_json::from_str::<PlanSource>(&bad).is_err());
}

/// A picks-only plan of a Topo with options has the bytes of the same Topo without them: the
/// options change no plan that does not choose one (the golden plans of the CLI pin the rest).
#[test]
fn oe7_options_change_no_plan_without_a_choice() {
    let sys = game_sys();
    let with = topo();
    let mut without = with.clone();
    without.options.clear();
    check::topo(&without, Rules::Source).unwrap();
    let a = plan_on(&sys, &with, &["display/layer"], &[]).unwrap();
    let b = plan_on(&sys, &without, &["display/layer"], &[]).unwrap();
    assert_eq!(
        a.plan.encode().unwrap().bytes(),
        b.plan.encode().unwrap().bytes()
    );
}
