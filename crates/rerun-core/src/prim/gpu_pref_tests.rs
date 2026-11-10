//! T9-G: the `gpu_preference` planner against the fake (P4-11): a new value (keys missing), a
//! merge with foreign pairs, `=0` changed in place, `=2` already (no op), `=1` refused (E-G3 a),
//! unusual old values, the executable (missing, no `.exe`, the stored spelling), a game folder
//! reached through a link, two steps for one executable, a link or volatile key on the way, a
//! plan without the main executable, the step's wire form. Values of the documented form.

use std::path::Path;

use super::layer_tests::exe_name;
use super::reg_tests::{hkcu, plan_steps};
use super::tests::{GAME, app, builder, fr, rel};
use super::{GpuPreferenceSpec, PlanCtx, Step, plan};
use crate::plan::{Op, Plan, Target};
use crate::policy::registry::{GpuPref, RegPolicy};
use crate::policy::root::GameDir;
use crate::sys::contract::RegFixture;
use crate::sys::fake::{FakeSystem, FakeSystemBuilder};
use crate::sys::registry::RegValue;

const PREFS_KEY: &str = r"Software\Microsoft\DirectX\UserGpuPreferences";

fn pref_step(exe: &str) -> Step {
    Step::GpuPreference(GpuPreferenceSpec {
        exe: rel(exe),
        preference: GpuPref::HighPerformance,
    })
}

/// [`builder`] with `Software\Microsoft` (the anchor) and `bin\g.exe`.
fn pref_builder() -> FakeSystemBuilder {
    builder()
        .key(hkcu(r"Software\Microsoft"))
        .file(format!(r"{GAME}\bin\g.exe"), b"MZ".to_vec())
}

fn with_value(v: RegValue) -> FakeSystem {
    pref_builder()
        .value(hkcu(PREFS_KEY), &exe_name("game.exe"), v)
        .build()
        .unwrap()
}

fn sz(s: &str) -> RegValue {
    RegValue::String(s.to_owned())
}

fn plan_one(sys: &FakeSystem, step: Step) -> Result<Plan, crate::plan::PlanError> {
    plan_steps(sys, &[step], Some("game.exe"))
}

fn refused(sys: &FakeSystem, step: Step, want: &str) {
    let e = plan_one(sys, step).expect_err(want).to_string();
    assert!(e.contains(want), "{want}: {e}");
}

/// The one `GpuPref` of `p`: value name, old text, new value.
fn pref_op(p: &Plan) -> (String, Option<String>, String) {
    let ops: Vec<_> = p
        .ops
        .iter()
        .enumerate()
        .filter_map(|(k, o)| match o {
            Op::GpuPref { slot, old, new, .. } => {
                let av = crate::plan::allowed(p, slot, k).ok()?;
                Some((
                    av.name().to_owned(),
                    old.as_ref().and_then(crate::plan::pref_old),
                    new.clone(),
                ))
            }
            _ => None,
        })
        .collect();
    assert_eq!(ops.len(), 1, "{:?}", p.ops);
    ops.into_iter().next().unwrap()
}

/// The keys the `CreateKey` ops of `p` create.
fn created(p: &Plan) -> Vec<String> {
    p.ops
        .iter()
        .enumerate()
        .filter_map(|(k, o)| match o.target() {
            Target::Key { slot, segs } => crate::plan::created_key(p, slot, segs, k)
                .ok()
                .map(|(_, key)| key.path),
            _ => None,
        })
        .collect()
}

#[test]
fn t9g_a_new_value_creates_the_shared_keys() {
    let sys = pref_builder().build().unwrap();
    let p = plan_one(&sys, pref_step("game.exe")).unwrap();
    assert_eq!(created(&p), [r"Software\Microsoft\DirectX", PREFS_KEY]);
    assert_eq!(
        pref_op(&p),
        (exe_name("game.exe"), None, "GpuPreference=2;".to_owned())
    );
    // The GpuPref is the last op (after the keys).
    assert!(matches!(p.ops.last(), Some(Op::GpuPref { .. })));
}

#[test]
fn t9g_foreign_pairs_stay_and_zero_changes_in_place() {
    for (old, new) in [
        (
            "AutoHDREnable=1;SwapEffectUpgradeEnable=1;",
            "AutoHDREnable=1;SwapEffectUpgradeEnable=1;GpuPreference=2;",
        ),
        (
            "AutoHDREnable=1;GpuPreference=0;SwapEffectUpgradeEnable=1;",
            "AutoHDREnable=1;GpuPreference=2;SwapEffectUpgradeEnable=1;",
        ),
    ] {
        let p = plan_one(&with_value(sz(old)), pref_step("game.exe")).unwrap();
        assert!(created(&p).is_empty());
        assert_eq!(
            pref_op(&p),
            (exe_name("game.exe"), Some(old.to_owned()), new.to_owned())
        );
    }
}

#[test]
fn t9g_set_already_is_no_op_and_power_saving_is_refused() {
    let p = plan_one(
        &with_value(sz("AutoHDREnable=1;GpuPreference=2;")),
        pref_step("game.exe"),
    )
    .unwrap();
    assert!(p.ops.is_empty(), "{:?}", p.ops);
    refused(
        &with_value(sz("GpuPreference=1;")),
        pref_step("game.exe"),
        "\"Power saving\"",
    );
}

#[test]
fn t9g_unusual_values_are_refused() {
    for v in [
        sz("GpuPreference=7;"),
        sz("GpuPreference=2"),
        sz("gpupreference=0;"),
        sz("GpuPreference=0; AutoHDREnable=1;"),
        sz(""),
        // Longer than 511 characters (9 x 64).
        sz(&(0..9)
            .map(|i| format!("A{i}={};", "1".repeat(60)))
            .collect::<String>()),
        RegValue::Dword(2),
        RegValue::ExpandString("GpuPreference=0;".into()),
    ] {
        refused(&with_value(v.clone()), pref_step("game.exe"), "is unusual");
    }
}

#[test]
fn t9g_the_executable_is_a_plain_exe_named_as_stored() {
    let sys = pref_builder()
        .file(format!(r"{GAME}\Bin2\Game2.EXE"), b"MZ".to_vec())
        .file(format!(r"{GAME}\readme.txt"), b"x".to_vec())
        .build()
        .unwrap();
    refused(&sys, pref_step("gone.exe"), "missing");
    refused(&sys, pref_step("readme.txt"), "not an .exe file");
    refused(&sys, pref_step("bin"), "not an .exe file");
    let p = plan_one(&sys, pref_step(r"bin2\game2.exe")).unwrap();
    assert_eq!(pref_op(&p).0, exe_name(r"Bin2\Game2.EXE"));
}

#[test]
fn t9g_a_game_folder_reached_through_a_link_is_refused() {
    let sys = pref_builder()
        .dir(r"D:\Links")
        .junction(r"D:\Links\G", GAME)
        .build()
        .unwrap();
    let fr = fr(&sys);
    let app = app(&sys);
    let main = rel("game.exe");
    let via = GameDir::open_manual(&sys, &fr, Path::new(r"D:\Links\G")).unwrap();
    let ctx = PlanCtx {
        game: &via,
        app: Some(&app),
        steam_app: None,
        main_exe: Some(&main),
        reg: RegPolicy.reader(&sys),
        app_path: None,
    };
    let e = plan(&[pref_step("game.exe")], &ctx).unwrap_err();
    assert!(e.to_string().contains("reached through a link"), "{e}");
}

#[test]
fn t9g_two_steps_keys_once_and_no_main_executable() {
    let sys = pref_builder().build().unwrap();
    let e = plan_steps(
        &sys,
        &[pref_step("game.exe"), pref_step("GAME.EXE")],
        Some("game.exe"),
    )
    .unwrap_err();
    assert!(e.to_string().contains("two steps for"), "{e}");
    // Two executables: the shared keys are created once.
    let p = plan_steps(
        &sys,
        &[pref_step("game.exe"), pref_step(r"bin\g.exe")],
        Some("game.exe"),
    )
    .unwrap();
    assert_eq!(created(&p).len(), 2);
    assert_eq!(
        p.ops
            .iter()
            .filter(|o| matches!(o, Op::GpuPref { .. }))
            .count(),
        2
    );
    let e = plan_steps(&sys, &[pref_step("game.exe")], None).unwrap_err();
    assert!(e.to_string().contains("main executable"), "{e}");
}

#[test]
fn t9g_a_link_or_volatile_key_on_the_way_is_refused() {
    let sys = pref_builder()
        .key(hkcu(r"Software\Elsewhere"))
        .build()
        .unwrap();
    sys.fake_registry()
        .link(
            &hkcu(r"Software\Microsoft\DirectX"),
            &hkcu(r"Software\Elsewhere"),
        )
        .unwrap();
    refused(&sys, pref_step("game.exe"), "symbolic-link key");
    let sys = pref_builder().build().unwrap();
    sys.fake_registry()
        .put_volatile_key(&hkcu(r"Software\Microsoft\DirectX"))
        .unwrap();
    refused(&sys, pref_step("game.exe"), "volatile key");
}

#[test]
fn t9g_the_step_parses_strictly() {
    let ok = r#"{"gpu_preference":{"exe":"bin\\g.exe","preference":"high_performance"}}"#;
    let s: Step = serde_json::from_str(ok).unwrap();
    assert_eq!(s, pref_step(r"bin\g.exe"));
    assert_eq!(serde_json::to_string(&s).unwrap(), ok);
    for bad in [
        ok.replace(r#","preference":"high_performance""#, ""),
        ok.replace("high_performance", "power_saving"),
        ok.replace("high_performance", "2"),
        ok.replace(r"bin\\g.exe", r"C:\\g.exe"),
        ok.replace(r#""preference":"#, r#""extra":1,"preference":"#),
    ] {
        assert!(serde_json::from_str::<Step>(&bad).is_err(), "{bad}");
    }
}

/// The plan's preview: the action, the value name, old and new, and the note once (N2: the
/// note names a preference set already and an earlier transaction).
#[test]
fn t9g_the_preview_shows_the_value_and_the_note() {
    let p = plan_one(&with_value(sz("AutoHDREnable=1;")), pref_step("game.exe")).unwrap();
    let v = crate::plan::preview(&p);
    let text = v.to_string();
    assert!(
        text.contains(&format!(
            r"set gpu preference HKCU\{PREFS_KEY} @ {}",
            exe_name("game.exe")
        )),
        "{text}"
    );
    assert!(text.contains("AutoHDREnable=1;GpuPreference=2;"), "{text}");
    assert_eq!(v.gpu_pref, Some(crate::plan::GPU_PREF_NOTE));
    assert!(crate::plan::GPU_PREF_NOTE.contains("High performance already"));
    // A recorded head masks old and new.
    let head = crate::plan::preview_head(p.encode().unwrap().bytes()).unwrap();
    assert!(!head.to_string().contains("AutoHDREnable"), "{head}");
}
