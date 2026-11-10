//! `gpu_preference` (P4-11, ADR 0020 amendment P4-11) through the Topo engine, against the fake.
//! Every Topo, folder and adapter is invented.
//!
//! - GP1 the acceptance round trip on a PC with two adapters: Topo → plan (the two shared keys
//!   and one `set gpu preference`) → apply → the value → `verify` `After` → revert → the game
//!   folder and `HKCU\Software` identical.
//! - GP2 one adapter: the issue's `when` (`gpu.hybrid: true`) is no, the pick refused.
//! - GP3 the loader: reviewed (an active Topo passes the source and release rules), a
//!   `match.exes` entry in exactly its spelling
//!   (no `sha256` needed), only in an issue whose `when` has `gpu.hybrid: true`.
//! - GP4 anti-cheat warns (E4); a preference set already plans nothing and says so, naming the
//!   open Rerun transaction that set it (N2).

use std::path::Path;

use super::{EngineError, Facts, StepKind, Warning, plan, read_game};
use crate::catalog::check::{self, GPU_PREFERENCE_REVIEWED, Rules};
use crate::catalog::model::Topo;
use crate::exec::rebind_tests::rb_sys;
use crate::exec::reg_tests::snap_at_with_keys;
use crate::exec::tests::{Env, read_abs};
use crate::hw::{self, GpuArchTable, SystemProfile};
use crate::journal::{Closing, Observed};
use crate::plan::{Op, Pick};
use crate::policy::registry::RegPolicy;
use crate::policy::root::StoreDir;
use crate::prim::PlanCtx;
use crate::prim::tests::{STEAM_GAME, STEAM_LIB, app, fr};
use crate::sys::fake::FakeSystem;
use crate::sys::registry::{Hive, RegKey, RegValue, RegView};
use crate::sys::{GpuAdapter, System};

const APP: u32 = 220;
const INDEX: [u8; 32] = [7; 32];
const PREFS_KEY: &str = r"Software\Microsoft\DirectX\UserGpuPreferences";

fn hkcu(p: &str) -> RegKey {
    RegKey::new(Hive::CurrentUser, RegView::Native, p)
}

fn adapter(name: &str, vendor_id: u32, device_id: u32) -> GpuAdapter {
    GpuAdapter {
        name: name.to_owned(),
        vendor_id,
        device_id,
        ..GpuAdapter::default()
    }
}

/// A synthetic laptop (two hardware adapters) or a one-adapter PC.
fn profile(adapters: usize) -> SystemProfile {
    let mut b = FakeSystem::builder();
    for i in 0..adapters {
        b = b.gpu(adapter(
            "synthetic",
            0x10DE,
            0xA000 + u32::try_from(i).unwrap(),
        ));
    }
    hw::read(&b.build().unwrap(), Some(GpuArchTable::builtin().unwrap()))
}

/// A Topo with `status`, issue `gpu` (its `when` as given) whose variant `pref` sets the
/// preference of `step_exe`.
fn topo_with(status: &str, when: &str, step_exe: &str) -> Topo {
    let when = if when.is_empty() {
        String::new()
    } else {
        format!(r#""when":{when},"#)
    };
    let j = format!(
        r#"{{"format":1,"id":"invented-game","title":"Invented Game","status":"{status}","rev":1,
"match":{{"steam_appid":{APP},"exes":[{{"path":"game.exe","sha1":"0000000000000000000000000000000000000000","api":"d3d9"}}]}},
"issues":[
 {{"id":"gpu","title":"Runs on the integrated GPU",{when}"variants":[
   {{"id":"pref","status":"unverified","kind":"fix","steps":[{{"gpu_preference":{{"exe":"{step_exe}","preference":"high_performance"}}}}]}}]}}
]}}"#
    );
    serde_json::from_str(&j).unwrap()
}

/// Steam app 220 with a synthetic x86 `game.exe` (an image, so the engine can hash it).
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
    sys.sync_all();
    sys
}

fn topo_for(sys: &FakeSystem) -> Topo {
    let sha1 = {
        use sha1::{Digest, Sha1};
        let b = read_abs(sys, &format!(r"{STEAM_GAME}\game.exe"));
        Sha1::digest(&b)
            .iter()
            .map(|x| format!("{x:02X}"))
            .collect::<String>()
    };
    let mut j: serde_json::Value =
        serde_json::to_value(topo_with("draft", r#"{"gpu.hybrid":true}"#, "game.exe")).unwrap();
    j["match"]["exes"][0]["sha1"] = sha1.into();
    let t: Topo = serde_json::from_value(j).unwrap();
    check::topo(&t, Rules::Source).unwrap();
    t
}

fn plan_with(
    sys: &FakeSystem,
    t: &Topo,
    profile: &SystemProfile,
) -> Result<super::TopoPlan, EngineError> {
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
    plan(
        &INDEX,
        t,
        &Facts {
            profile,
            table: Some(GpuArchTable::builtin().unwrap()),
            game: &gf,
            packages: &[],
        },
        &[Pick {
            issue: "gpu".to_owned(),
            variant: "pref".to_owned(),
        }],
        &ctx,
    )
}

fn value(sys: &FakeSystem) -> Option<RegValue> {
    sys.registry()
        .get(&hkcu(PREFS_KEY), &format!(r"{STEAM_GAME}\game.exe"))
        .ok()
        .flatten()
}

#[test]
fn gp1_round_trip_on_a_pc_with_two_adapters() {
    let env = Env::new(game_sys());
    let sys = &env.sys;
    let t = topo_for(sys);
    let before = snap_at_with_keys(sys, STEAM_GAME);
    let tp = plan_with(sys, &t, &profile(2)).unwrap();
    assert!(tp.warnings.is_empty(), "{:?}", tp.warnings);
    assert!(matches!(
        tp.plan.ops.as_slice(),
        [
            Op::CreateKey { .. },
            Op::CreateKey { .. },
            Op::GpuPref { .. }
        ]
    ));
    let shown = crate::plan::preview(&tp.plan).to_string();
    assert!(shown.contains("set gpu preference"), "{shown}");
    let h = crate::plan::store(&app(sys), &tp.plan.encode().unwrap()).unwrap();
    let txn = env.applied(&h);
    assert_eq!(
        value(sys),
        Some(RegValue::String("GpuPreference=2;".into()))
    );
    assert!(env.verify(&txn).iter().all(|(_, o)| *o == Observed::After));
    assert_eq!(env.revert(&txn).unwrap().closed, Some(Closing::Reverted));
    assert_eq!(before, snap_at_with_keys(sys, STEAM_GAME));
}

#[test]
fn gp2_one_adapter_is_no() {
    let sys = game_sys();
    let t = topo_for(&sys);
    for n in [0, 1] {
        assert!(
            matches!(plan_with(&sys, &t, &profile(n)), Err(EngineError::WhenNo(i)) if i == "gpu"),
            "{n} adapters"
        );
    }
}

#[test]
fn gp3_the_loader() {
    let hybrid = r#"{"gpu.hybrid":true}"#;
    assert!(check::topo(&topo_with("draft", hybrid, "game.exe"), Rules::Source).is_ok());
    let refused = |t: Topo, want: &str| {
        let e = check::topo(&t, Rules::Source).unwrap_err().to_string();
        assert!(e.contains(want), "{want}: {e}");
    };
    // Reviewed (P4-11): an active Topo carries it, also by the release rules.
    const { assert!(GPU_PREFERENCE_REVIEWED, "gpu_preference is reviewed") };
    let active = topo_with("active", hybrid, "game.exe");
    check::topo(&active, Rules::Source).unwrap();
    check::topo(&active, Rules::Release).unwrap();
    // A match.exes entry in exactly its spelling.
    refused(
        topo_with("draft", hybrid, "GAME.exe"),
        "an executable of match.exes",
    );
    refused(
        topo_with("draft", hybrid, "other.exe"),
        "an executable of match.exes",
    );
    // Only behind gpu.hybrid: true.
    for when in ["", r#"{"gpu.hybrid":false}"#, r#"{"gpu.vendor":"nvidia"}"#] {
        refused(topo_with("draft", when, "game.exe"), "gpu.hybrid: true");
    }
    // More keys are fine.
    assert!(
        check::topo(
            &topo_with(
                "draft",
                r#"{"gpu.hybrid":true,"gpu.vendor":"nvidia"}"#,
                "game.exe"
            ),
            Rules::Source
        )
        .is_ok()
    );
}

#[test]
fn gp4_anti_cheat_warns_and_a_set_preference_is_named() {
    let env = Env::new(game_sys());
    let sys = &env.sys;
    let t = topo_for(sys);
    // N2: a preference set by an open Rerun transaction: nothing to do, named.
    let tp = plan_with(sys, &t, &profile(2)).unwrap();
    let h = crate::plan::store(&app(sys), &tp.plan.encode().unwrap()).unwrap();
    let txn = env.applied(&h);
    let again = plan_with(sys, &t, &profile(2)).unwrap();
    assert!(again.plan.ops.is_empty(), "{:?}", again.plan.ops);
    assert_eq!(
        again.warnings,
        vec![Warning::GpuPreferenceSet {
            exe: crate::prim::tests::rel("game.exe"),
            by: Some(txn),
        }]
    );
    assert_eq!(env.revert(&txn).unwrap().closed, Some(Closing::Reverted));
    // Set by the user: named without a transaction.
    sys.fake_registry().put_key_all(&hkcu(PREFS_KEY)).unwrap();
    sys.fake_registry()
        .put_value(
            &hkcu(PREFS_KEY),
            &format!(r"{STEAM_GAME}\game.exe"),
            &RegValue::String("GpuPreference=2;".into()),
        )
        .unwrap();
    let mine = plan_with(sys, &t, &profile(2)).unwrap();
    assert_eq!(
        mine.warnings,
        vec![Warning::GpuPreferenceSet {
            exe: crate::prim::tests::rel("game.exe"),
            by: None,
        }]
    );
    sys.fake_registry()
        .remove_value(&hkcu(PREFS_KEY), &format!(r"{STEAM_GAME}\game.exe"))
        .unwrap();
    // E4: anti-cheat found: planned with a warning.
    sys.fake_fs()
        .mkdir_all(Path::new(&format!(r"{STEAM_GAME}\pb")))
        .unwrap();
    sys.sync_all();
    let warned = plan_with(sys, &t, &profile(2)).unwrap();
    assert!(
        warned.warnings.iter().any(|w| matches!(
            w,
            Warning::AntiCheat {
                step: StepKind::GpuPreference,
                ..
            }
        )),
        "{:?}",
        warned.warnings
    );
    assert!(!warned.plan.ops.is_empty());
}
