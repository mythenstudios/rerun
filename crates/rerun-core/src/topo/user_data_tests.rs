//! `ini_set` in the Topo's user data folder (P4-12, ADR 0020 amendment P4-12) through the Topo
//! engine, against the fake. Every Topo and folder is invented.
//!
//! - TU1 the round trip: Topo (`user_data: {documents: 'My Games\G'}`, `ini_set` with
//!   `root: user_data`) → plan (root 1 the user data root, the op on it) → apply → `verify`
//!   `After` → revert → the game folder and Documents identical.
//! - TU2 the folder: `needs_user_data` only for a picked step in it; the engine refuses a plan
//!   without the folder opened, or with another folder than the Topo's.
//! - TU3 the loader: `root: user_data` without the Topo's `user_data`; the allowlist at load.
//! - TU4 the bytes of a Topo without `user_data` and of an `ini_set` of the game folder do not
//!   change (no `user_data`, no `root` on the wire); with them the bundle form round-trips.

use std::path::Path;

use super::{EngineError, Facts, needs_user_data, plan, read_game};
use crate::catalog::check::{self, Rules};
use crate::catalog::model::Topo;
use crate::exec::rebind_tests::rb_sys;
use crate::exec::tests::{Env, read_abs};
use crate::exec::user_data_tests::{DOCS, UD_SUB, snap_ud, ud_ini, ud_now};
use crate::hw::{self, GpuArchTable};
use crate::journal::{Closing, Observed};
use crate::plan::{Op, Pick, RootKind};
use crate::policy::registry::RegPolicy;
use crate::policy::root::{StoreDir, UserBase, UserDataDir};
use crate::prim::PlanCtx;
use crate::prim::ini_tests::INI_TEXT;
use crate::prim::tests::{STEAM_GAME, STEAM_LIB, app, fr, rel};
use crate::sys::fake::FakeSystem;

const APP: u32 = 220;
const INDEX: [u8; 32] = [9; 32];

/// A Topo of app 220 with `user_data` (as JSON, or none) and one issue whose variant sets
/// `Display/Width` in `settings.ini` of `root`.
fn topo_with(user_data: Option<&str>, root: Option<&str>, sha1: &str) -> Topo {
    let ud = user_data.map_or(String::new(), |u| format!(r#""user_data":{u},"#));
    let root = root.map_or(String::new(), |r| format!(r#""root":"{r}","#));
    let j = format!(
        r#"{{"format":1,"id":"invented-game","title":"Invented Game","status":"draft","rev":1,
"match":{{"steam_appid":{APP},"exes":[{{"path":"game.exe","sha1":"{sha1}","api":"d3d9"}}]}},{ud}
"issues":[
 {{"id":"threads","title":"Crashes with many cores","variants":[
   {{"id":"ini","status":"unverified","kind":"fix","steps":[{{"ini_set":{{{root}"file":"settings.ini","values":[{{"section":"Display","key":"Width","value":"1920"}}]}}}}]}}]}}
]}}"#
    );
    serde_json::from_str(&j).unwrap_or_else(|e| panic!("{e}: {j}"))
}

const ZERO: &str = "0000000000000000000000000000000000000000";
const UD: &str = r#"{"documents":"My Games\\G"}"#;

/// Steam app 220 with a synthetic `game.exe` image and `Documents\My Games\G\settings.ini`.
fn game_sys() -> FakeSystem {
    let sys = rb_sys();
    let abs = format!(r"{STEAM_GAME}\game.exe");
    let _ = sys.fake_fs().remove_abs(Path::new(&abs));
    sys.fake_fs()
        .put_file(
            Path::new(&abs),
            &crate::detect::pe::testfx::Builder::x86().build().bytes,
        )
        .unwrap();
    sys.fake_fs()
        .put_file(Path::new(&ud_ini(DOCS)), INI_TEXT)
        .unwrap();
    sys.sync_all();
    sys
}

fn sha1_of(sys: &FakeSystem) -> String {
    use sha1::{Digest, Sha1};
    let b = read_abs(sys, &format!(r"{STEAM_GAME}\game.exe"));
    Sha1::digest(&b)
        .iter()
        .map(|x| format!("{x:02X}"))
        .collect::<String>()
}

fn picks() -> Vec<Pick> {
    vec![Pick {
        issue: "threads".to_owned(),
        variant: "ini".to_owned(),
    }]
}

/// Plans `t` with the user data folder `sub` opened (or none).
fn plan_with(
    sys: &FakeSystem,
    t: &Topo,
    sub: Option<&str>,
) -> Result<super::TopoPlan, EngineError> {
    let fr = fr(sys);
    let store = StoreDir::open(sys, &fr, Path::new(STEAM_LIB)).unwrap();
    let g = store.game(&fr, "G").unwrap();
    let u = sub.map(|s| UserDataDir::open(sys, &fr, UserBase::Documents, &rel(s)).unwrap());
    let gf = read_game(&g, t);
    let a = app(sys);
    let profile = hw::read(sys, Some(GpuArchTable::builtin().unwrap()));
    let ctx = PlanCtx {
        game: &g,
        app: Some(&a),
        steam_app: Some(APP),
        main_exe: None,
        reg: RegPolicy.reader(sys),
        app_path: None,
        user_data: u.as_ref(),
    };
    plan(
        &INDEX,
        t,
        &Facts {
            profile: &profile,
            table: Some(GpuArchTable::builtin().unwrap()),
            game: &gf,
            packages: &[],
        },
        &picks(),
        &ctx,
    )
}

#[test]
fn tu1_round_trip_in_the_user_data_folder() {
    let env = Env::new(game_sys());
    let sys = &env.sys;
    let t = topo_with(Some(UD), Some("user_data"), &sha1_of(sys));
    check::topo(&t, Rules::Source).unwrap();
    assert!(needs_user_data(&t, &picks()));
    let before = snap_ud(&env, DOCS);
    let tp = plan_with(sys, &t, Some(UD_SUB)).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(tp.plan.roots.len(), 2);
    assert_eq!(tp.plan.roots[1].kind, RootKind::UserData);
    assert!(matches!(
        tp.plan.ops.as_slice(),
        [Op::IniValue { root, .. }] if root.0 == 1
    ));
    assert!(tp.plan.source.is_some());
    let h = crate::plan::store(&app(sys), &tp.plan.encode().unwrap()).unwrap();
    let txn = env.applied(&h);
    assert!(
        String::from_utf8_lossy(&ud_now(&env, DOCS).unwrap()).contains("Width=1920"),
        "applied"
    );
    assert!(env.verify(&txn).iter().all(|(_, o)| *o == Observed::After));
    assert_eq!(env.revert(&txn).unwrap().closed, Some(Closing::Reverted));
    crate::exec::tests::same(&before, &snap_ud(&env, DOCS));
}

#[test]
fn tu2_the_folder_is_the_topo_s_and_only_when_needed() {
    let sys = game_sys();
    let t = topo_with(Some(UD), Some("user_data"), &sha1_of(&sys));
    // Not opened: refused.
    assert!(matches!(
        plan_with(&sys, &t, None),
        Err(EngineError::UserData)
    ));
    // Another folder than the Topo's: refused.
    sys.fake_fs()
        .mkdir_all(Path::new(&format!(r"{DOCS}\My Games\H")))
        .unwrap();
    assert!(matches!(
        plan_with(&sys, &t, Some(r"My Games\H")),
        Err(EngineError::UserData)
    ));
    // The same folder in another case is the Topo's.
    assert!(plan_with(&sys, &t, Some(r"my games\g")).is_ok());
    // A variant of the game folder needs none, even with a `user_data` in the Topo.
    let g = topo_with(Some(UD), None, &sha1_of(&sys));
    assert!(!needs_user_data(&g, &picks()));
    assert!(!needs_user_data(&t, &[]));
    assert!(!needs_user_data(
        &t,
        &[Pick {
            issue: "threads".to_owned(),
            variant: "other".to_owned()
        }]
    ));
}

#[test]
fn tu3_the_loader() {
    let refused = |t: Topo, at: &str, want: &str| {
        let e = check::topo(&t, Rules::Source).unwrap_err();
        assert_eq!(e.at, at, "{e}");
        assert!(e.what.contains(want), "{want}: {e}");
    };
    refused(
        topo_with(None, Some("user_data"), ZERO),
        "issues[0].variants[0].steps[0].ini_set.root",
        "user_data needs the Topo's user_data folder",
    );
    refused(
        topo_with(Some(r#"{"documents":"My Games"}"#), Some("user_data"), ZERO),
        "user_data.documents",
        "several games share",
    );
    refused(
        topo_with(
            Some(r#"{"documents":"WindowsPowerShell\\Scripts"}"#),
            Some("user_data"),
            ZERO,
        ),
        "user_data.documents",
        "PowerShell",
    );
    // Unknown bases and fields never parse.
    for bad in [
        r#"{"saved_games":"G"}"#,
        r#"{"documents":"G","x":1}"#,
        r#"{}"#,
    ] {
        let j = serde_json::to_value(topo_with(None, None, ZERO)).unwrap();
        let mut j = j.as_object().unwrap().clone();
        j.insert("user_data".into(), serde_json::from_str(bad).unwrap());
        assert!(
            serde_json::from_value::<Topo>(serde_json::Value::Object(j)).is_err(),
            "{bad}"
        );
    }
    // A user_data no step uses is allowed (nothing is opened for it).
    check::topo(&topo_with(Some(UD), None, ZERO), Rules::Source).unwrap();
    check::topo(&topo_with(Some(UD), Some("game"), ZERO), Rules::Source).unwrap();
}

#[test]
fn tu4_the_bundle_form() {
    let plain = topo_with(None, None, ZERO);
    let b = serde_json::to_string(&plain).unwrap();
    assert!(!b.contains("user_data") && !b.contains(r#""root""#), "{b}");
    // An explicit `root: game` is the same Topo with the same bytes.
    let explicit = topo_with(None, Some("game"), ZERO);
    assert_eq!(explicit, plain);
    assert_eq!(serde_json::to_string(&explicit).unwrap(), b);
    let ud = topo_with(Some(UD), Some("user_data"), ZERO);
    let a = serde_json::to_string(&ud).unwrap();
    assert!(
        a.contains(r#""user_data":{"documents":"My Games\\G"}"#),
        "{a}"
    );
    assert!(
        a.contains(r#"{"ini_set":{"root":"user_data","file""#),
        "{a}"
    );
    let back: Topo = serde_json::from_str(&a).unwrap();
    assert_eq!(back, ud);
    assert_eq!(serde_json::to_string(&back).unwrap(), a);
}
