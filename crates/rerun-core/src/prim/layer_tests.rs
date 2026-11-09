//! T9-L: the `compat_layer` planner against the fake (P2-11, C3): a new value (keys missing),
//! a merge with foreign tokens, tokens present (omitted, all present: no op), a conflict of a
//! group, a token in another case, unusual old values, the executable (missing, a folder, no
//! `.exe`, a link on the way, restricted, the stored spelling), a game folder reached through
//! a link (E3), two steps for one executable, every token refusal, a link or volatile key on
//! the way, the step's wire form, with synthetic tokens; T9-L-P (P2-11b) the production tokens
//! on every value of the SB-L1 fixture; T9-L-M (P3-6) the "all users" (`HKLM`) value of the
//! same executable in both views.

use std::path::Path;

use super::reg_tests::{hkcu, plan_steps};
use super::tests::{GAME, app, builder, fr, rel};
use super::{CompatLayerSpec, PlanCtx, Step, plan};
use crate::plan::{LayerView, Op, Plan, ValueState};
use crate::policy::registry::RegPolicy;
use crate::policy::registry::layers::knob;
use crate::policy::root::GameDir;
use crate::sys::contract::RegFixture;
use crate::sys::fake::{FakeSystem, FakeSystemBuilder};
use crate::sys::registry::{Hive, RegKey, RegValue, RegView, reg_type};

/// The anchor of `AppCompatFlags\Layers` (it must exist).
pub(crate) const CURRENT_VERSION: &str = r"Software\Microsoft\Windows NT\CurrentVersion";
/// The key of the compatibility-layer values.
pub(crate) const LAYERS_KEY: &str =
    r"Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers";

/// The value name of `exe` in the game folder.
pub(crate) fn exe_name(exe: &str) -> String {
    format!(r"{GAME}\{exe}")
}

pub(crate) fn layer_step(exe: &str, tokens: &[&str]) -> Step {
    Step::CompatLayer(CompatLayerSpec {
        exe: rel(exe),
        layers: tokens.iter().map(|t| (*t).to_owned()).collect(),
    })
}

/// [`builder`] with `CurrentVersion` (the anchor) and `bin\g.exe`.
pub(crate) fn layer_builder() -> FakeSystemBuilder {
    builder()
        .key(hkcu(CURRENT_VERSION))
        .file(format!(r"{GAME}\bin\g.exe"), b"MZ".to_vec())
}

/// [`layer_builder`] with the value of `game.exe` set to `v`.
fn with_value(v: RegValue) -> FakeSystem {
    layer_builder()
        .value(hkcu(LAYERS_KEY), &exe_name("game.exe"), v)
        .build()
        .unwrap()
}

fn plan_one(sys: &FakeSystem, step: Step) -> Result<Plan, crate::plan::PlanError> {
    plan_steps(sys, &[step], Some("game.exe"))
}

/// The token list of `p` (exactly one).
fn token_list(p: &Plan) -> (String, Option<ValueState>, Vec<String>, String) {
    let lists: Vec<_> = p
        .ops
        .iter()
        .filter_map(|o| match o {
            Op::TokenList {
                slot,
                old,
                add,
                new,
                ..
            } => {
                let av = crate::plan::allowed(p, slot, 0).ok()?;
                Some((
                    av.name().to_owned(),
                    old.clone(),
                    add.iter().map(|t| t.as_str().to_owned()).collect(),
                    new.clone(),
                ))
            }
            _ => None,
        })
        .collect();
    assert_eq!(lists.len(), 1, "{p:?}");
    lists.into_iter().next().unwrap()
}

fn refused(sys: &FakeSystem, step: Step, want: &str) {
    let e = plan_one(sys, step).expect_err(want).to_string();
    assert!(e.contains(want), "{want}: {e}");
}

/// Resets the knobs of `policy::registry::layers` when dropped.
struct Reset;

impl Drop for Reset {
    fn drop(&mut self) {
        knob::production(false);
        knob::drop_token(None);
        knob::reverse(false);
    }
}

#[test]
fn t9l_a_new_value_creates_the_shared_keys_and_sorts_the_tokens() {
    let sys = layer_builder().build().unwrap();
    let p = plan_one(&sys, layer_step("game.exe", &["ZZ_OS_A", "ZZ_FLAG_A"])).unwrap();
    let keys: Vec<u8> = p
        .ops
        .iter()
        .filter_map(|o| match o {
            Op::CreateKey { segs, .. } => Some(*segs),
            _ => None,
        })
        .collect();
    assert_eq!(keys, [5, 6], "AppCompatFlags, then Layers");
    let (name, old, add, new) = token_list(&p);
    assert_eq!(name, exe_name("game.exe"));
    assert_eq!(old, None);
    assert_eq!(add, ["ZZ_FLAG_A", "ZZ_OS_A"], "byte order (M1)");
    assert_eq!(new, "~ ZZ_FLAG_A ZZ_OS_A");
    // The same bytes whatever the order of the tokens in the step, or of the allowlist (M1).
    let again = plan_one(&sys, layer_step("game.exe", &["ZZ_FLAG_A", "ZZ_OS_A"])).unwrap();
    assert_eq!(again.encode().unwrap(), p.encode().unwrap());
    let _r = Reset;
    knob::reverse(true);
    let reversed = plan_one(&sys, layer_step("game.exe", &["ZZ_OS_A", "ZZ_FLAG_A"])).unwrap();
    assert_eq!(reversed.encode().unwrap(), p.encode().unwrap());
}

#[test]
fn t9l_foreign_tokens_stay_and_present_tokens_are_left_out() {
    // A merge: the old bytes kept, elevation tokens of the user included.
    let sys = with_value(RegValue::String("$ RUNASADMIN X1".into()));
    let p = plan_one(&sys, layer_step("game.exe", &["ZZ_OS_A"])).unwrap();
    assert!(!p.ops.iter().any(|o| matches!(o, Op::CreateKey { .. })));
    let (_, old, add, new) = token_list(&p);
    assert!(ValueState::is(
        old.as_ref(),
        Some(&RegValue::String("$ RUNASADMIN X1".into()))
    ));
    assert_eq!(add, ["ZZ_OS_A"]);
    assert_eq!(new, "$ RUNASADMIN X1 ZZ_OS_A");
    // Partly present: only the missing one.
    let sys = with_value(RegValue::String("~ ZZ_OS_A".into()));
    let p = plan_one(&sys, layer_step("game.exe", &["ZZ_OS_A", "ZZ_FLAG_A"])).unwrap();
    let (_, _, add, new) = token_list(&p);
    assert_eq!(add, ["ZZ_FLAG_A"]);
    assert_eq!(new, "~ ZZ_OS_A ZZ_FLAG_A");
    // All present: no op at all.
    let p = plan_one(&sys, layer_step("game.exe", &["ZZ_OS_A"])).unwrap();
    assert!(p.ops.is_empty(), "{p:?}");
}

#[test]
fn t9l_conflicts_cases_and_unusual_values_are_refused() {
    // E5 a: a token of the same group is never replaced.
    let sys = with_value(RegValue::String("~ ZZ_OS_C".into()));
    refused(
        &sys,
        layer_step("game.exe", &["ZZ_OS_A"]),
        "remove it in the Compatibility tab",
    );
    let sys = with_value(RegValue::String("~ zz_dpi_b".into()));
    refused(
        &sys,
        layer_step("game.exe", &["ZZ_DPI_A"]),
        "of the same kind as ZZ_DPI_A",
    );
    // S4: our token in another case.
    let sys = with_value(RegValue::String("~ zz_os_a".into()));
    refused(
        &sys,
        layer_step("game.exe", &["ZZ_OS_A"]),
        "in another case",
    );
    // Unusual old values.
    for v in [
        RegValue::Dword(1),
        RegValue::ExpandString("~ X".into()),
        RegValue::String("~  X".into()),
        RegValue::String("~ X\tY".into()),
        RegValue::String("X".repeat(512)),
    ] {
        let sys = with_value(v.clone());
        refused(&sys, layer_step("game.exe", &["ZZ_OS_A"]), "is unusual");
    }
    let sys = layer_builder()
        .raw_value(
            hkcu(LAYERS_KEY),
            &exe_name("game.exe"),
            reg_type::REG_SZ,
            b"~\0 \0X\0",
        )
        .build()
        .unwrap();
    refused(&sys, layer_step("game.exe", &["ZZ_OS_A"]), "is unusual");
}

#[test]
fn t9l_the_executable_is_a_plain_exe_named_as_stored() {
    let sys = layer_builder()
        .file(format!(r"{GAME}\Sub\Game2.EXE"), b"MZ".to_vec())
        .file(format!(r"{GAME}\game.dll"), b"MZ".to_vec())
        .dir(format!(r"{GAME}\folder.exe"))
        .dir(r"D:\Elsewhere")
        .file(r"D:\Elsewhere\x.exe", b"MZ".to_vec())
        .junction(format!(r"{GAME}\link"), r"D:\Elsewhere")
        .file_symlink(format!(r"{GAME}\sym.exe"), r"D:\Elsewhere\x.exe")
        .file(format!(r"{GAME}\locked.exe"), b"MZ".to_vec())
        .restricted(format!(r"{GAME}\locked.exe"))
        .build()
        .unwrap();
    // The stored spelling of every segment, whatever the step says (A2-B1).
    let p = plan_one(&sys, layer_step(r"sub\game2.exe", &["ZZ_OS_A"])).unwrap();
    assert_eq!(token_list(&p).0, exe_name(r"Sub\Game2.EXE"));
    assert!(p.ops.iter().any(|o| matches!(
        o,
        Op::TokenList { slot: crate::policy::registry::RegSlot::CompatLayers { exe, .. }, .. }
            if exe.as_str() == r"Sub\Game2.EXE"
    )));
    for (exe, want) in [
        ("missing.exe", "missing"),
        ("game.dll", "not an .exe file"),
        ("folder.exe", "not a plain file"),
        (r"link\x.exe", "a folder on the way is not a plain folder"),
        ("sym.exe", "not a plain file"),
        ("locked.exe", "not a plain file"),
    ] {
        refused(&sys, layer_step(exe, &["ZZ_OS_A"]), want);
    }
}

/// E3 a: a game folder reached through a junction is refused (its canonical path is not the
/// one it was opened by); opened by its canonical path it is planned.
#[test]
fn t9l_a_game_folder_reached_through_a_link_is_refused() {
    let sys = layer_builder()
        .dir(r"D:\Links")
        .junction(r"D:\Links\G", GAME)
        .build()
        .unwrap();
    let fr = fr(&sys);
    let app = app(&sys);
    let main = rel("game.exe");
    let via = GameDir::open_manual(&sys, &fr, Path::new(r"D:\Links\G")).unwrap();
    assert_eq!(via.path().to_string(), GAME);
    assert_eq!(via.launch_path().unwrap().to_string(), r"D:\Links\G");
    let ctx = |g| PlanCtx {
        game: g,
        app: Some(&app),
        steam_app: None,
        main_exe: Some(&main),
        reg: RegPolicy.reader(&sys),
        app_path: None,
    };
    let e = plan(&[layer_step("game.exe", &["ZZ_OS_A"])], &ctx(&via)).unwrap_err();
    assert!(e.to_string().contains("reached through a link"), "{e}");
    // Another spelling of the drive or the folder is the same path (folded): planned.
    let lower = GameDir::open_manual(&sys, &fr, Path::new(r"d:\games\g")).unwrap();
    assert!(plan(&[layer_step("game.exe", &["ZZ_OS_A"])], &ctx(&lower)).is_ok());
}

#[test]
fn t9l_every_token_refusal() {
    let sys = layer_builder().build().unwrap();
    for (tokens, want) in [
        (&[][..], "1 to 8 layers"),
        (
            &["A1", "A2", "A3", "A4", "A5", "A6", "A7", "A8", "A9"][..],
            "1 to 8 layers",
        ),
        (&["zz_os_a"][..], "is not a token"),
        (&["ZZ OS"][..], "is not a token"),
        (&["RUNASADMIN"][..], "not on the allowlist"),
        (&["ZZ_OS_C"][..], "not on the allowlist"),
        (&["ZZ_OS_A", "ZZ_OS_A"][..], "twice"),
        (&["ZZ_OS_A", "ZZ_OS_B"][..], "two tokens of one group"),
    ] {
        refused(&sys, layer_step("game.exe", tokens), want);
    }
    // The production allowlist knows no synthetic token.
    let _r = Reset;
    knob::production(true);
    refused(
        &sys,
        layer_step("game.exe", &["ZZ_OS_A"]),
        "not on the allowlist",
    );
}

/// T9-L-P (P2-11b): the planner with the production tables on every value of the SB-L1 fixture
/// as the old value: each token of the allowlist alone and all together, planned as a merge,
/// left out when present, refused with a DPI setting of the tab. The never-list is refused,
/// and so is an old value with a joined prefix (B4.3).
#[test]
fn t9l_p_the_production_tokens_on_every_tab_value() {
    use crate::policy::registry::layers::{LAYER_TOKENS, sb_l1_tab};
    let _r = Reset;
    knob::production(true);
    let dpi = ["DPIUNAWARE", "GDIDPISCALING", "HIGHDPIAWARE"];
    for (label, _, old) in sb_l1_tab() {
        let words: Vec<&str> = old.split(' ').collect();
        let sys = with_value(RegValue::String(old.to_owned()));
        let mut asks: Vec<Vec<&str>> = LAYER_TOKENS.iter().map(|t| vec![*t]).collect();
        asks.push(LAYER_TOKENS.to_vec());
        for ask in asks {
            let missing: Vec<&str> = ask.iter().copied().filter(|t| !words.contains(t)).collect();
            let conflict = missing
                .iter()
                .any(|t| dpi.contains(t) && words.iter().any(|w| dpi.contains(w)));
            let r = plan_one(&sys, layer_step("game.exe", &ask));
            if conflict {
                let e = r.expect_err(label).to_string();
                assert!(
                    e.contains("remove it in the Compatibility tab"),
                    "{label}: {e}"
                );
            } else if missing.is_empty() {
                assert!(r.unwrap().ops.is_empty(), "{label} {ask:?}: no op");
            } else {
                let (_, o, add, new) = token_list(&r.unwrap());
                assert!(ValueState::is(
                    o.as_ref(),
                    Some(&RegValue::String(old.to_owned()))
                ));
                assert_eq!(add, missing, "{label}");
                assert_eq!(new, format!("{old} {}", missing.join(" ")), "{label}");
            }
        }
    }
    // A new value: the prefix of the tab and the tokens in byte order.
    let sys = layer_builder().build().unwrap();
    let p = plan_one(&sys, layer_step("game.exe", LAYER_TOKENS)).unwrap();
    assert_eq!(token_list(&p).3, format!("~ {}", LAYER_TOKENS.join(" ")));
    for never in [
        "WINXPSP3",
        "WIN7RTM",
        "RUNASADMIN",
        "RUNASINVOKER",
        "REGISTERAPPRESTART",
    ] {
        refused(
            &sys,
            layer_step("game.exe", &[never]),
            "not on the allowlist",
        );
    }
    for old in ["~HIGHDPIAWARE", "~ RUNASINVOKER ~"] {
        let sys = with_value(RegValue::String(old.to_owned()));
        refused(
            &sys,
            layer_step("game.exe", LAYER_TOKENS),
            "a prefix joined to a word",
        );
    }
}

#[test]
fn t9l_two_steps_keys_once_and_no_main_executable() {
    let sys = layer_builder().build().unwrap();
    let e = plan_one(&sys, layer_step("game.exe", &["ZZ_OS_A"]));
    assert!(e.is_ok());
    let e = plan_steps(
        &sys,
        &[
            layer_step("game.exe", &["ZZ_OS_A"]),
            layer_step("GAME.EXE", &["ZZ_FLAG_A"]),
        ],
        Some("game.exe"),
    )
    .unwrap_err();
    assert!(e.to_string().contains("two steps for"), "{e}");
    // Two executables: the keys once, both values after them.
    let p = plan_steps(
        &sys,
        &[
            layer_step("game.exe", &["ZZ_OS_A"]),
            layer_step(r"bin\g.exe", &["ZZ_FLAG_A"]),
        ],
        Some("game.exe"),
    )
    .unwrap();
    let kinds: Vec<&str> = p
        .ops
        .iter()
        .map(|o| match o {
            Op::CreateKey { .. } => "key",
            Op::TokenList { .. } => "tokens",
            _ => "other",
        })
        .collect();
    assert_eq!(kinds, ["key", "key", "tokens", "tokens"]);
    let e = plan_steps(&sys, &[layer_step("game.exe", &["ZZ_OS_A"])], None).unwrap_err();
    assert!(
        e.to_string()
            .contains("fixes need the game's main executable"),
        "{e}"
    );
}

#[test]
fn t9l_a_link_or_volatile_key_on_the_way_is_refused() {
    let sys = layer_builder()
        .key(hkcu(r"Software\Elsewhere"))
        .build()
        .unwrap();
    sys.fake_registry()
        .link(
            &hkcu(&format!(r"{CURRENT_VERSION}\AppCompatFlags")),
            &hkcu(r"Software\Elsewhere"),
        )
        .unwrap();
    refused(
        &sys,
        layer_step("game.exe", &["ZZ_OS_A"]),
        "symbolic-link key",
    );
    let sys = layer_builder().build().unwrap();
    sys.fake_registry()
        .put_volatile_key(&hkcu(&format!(r"{CURRENT_VERSION}\AppCompatFlags")))
        .unwrap();
    refused(&sys, layer_step("game.exe", &["ZZ_OS_A"]), "volatile key");
}

/// The step's wire form: `deny_unknown_fields`, `exe` required and a valid relative path.
#[test]
fn t9l_the_step_parses_strictly() {
    let ok = r#"{"compat_layer":{"exe":"bin\\g.exe","layers":["ZZ_OS_A","ZZ_FLAG_A"]}}"#;
    let s: Step = serde_json::from_str(ok).unwrap();
    assert_eq!(s, layer_step(r"bin\g.exe", &["ZZ_OS_A", "ZZ_FLAG_A"]));
    assert_eq!(serde_json::to_string(&s).unwrap(), ok);
    for bad in [
        ok.replace(r#""exe":"bin\\g.exe","#, ""),
        ok.replace(r"bin\\g.exe", r"..\\g.exe"),
        ok.replace(r"bin\\g.exe", r"C:\\g.exe"),
        ok.replace(
            r#""layers":["ZZ_OS_A","ZZ_FLAG_A"]"#,
            r#""layers":"ZZ_OS_A""#,
        ),
        ok.replace(r#""layers":"#, r#""extra":1,"layers":"#),
    ] {
        assert!(serde_json::from_str::<Step>(&bad).is_err(), "{bad}");
    }
}

/// E3 a for a Steam library reached through a junction: the launch path is the library's path
/// as Steam names it plus `steamapps\common\<installdir>`, not the canonical one: refused.
#[test]
fn t9l_a_steam_library_reached_through_a_junction_is_refused() {
    use super::tests::{STEAM_GAME, STEAM_LIB};
    let sys = layer_builder()
        .file(format!(r"{STEAM_GAME}\game.exe"), b"MZ".to_vec())
        .junction(r"D:\LibLink", STEAM_LIB)
        .build()
        .unwrap();
    let fr = fr(&sys);
    let app = app(&sys);
    let main = rel("game.exe");
    for (lib, ok) in [(STEAM_LIB, true), (r"D:\LibLink", false)] {
        let store = crate::policy::root::StoreDir::open(&sys, &fr, Path::new(lib)).unwrap();
        let g = store.game(&fr, "G").unwrap();
        assert_eq!(g.path().to_string(), STEAM_GAME);
        let ctx = PlanCtx {
            game: &g,
            app: Some(&app),
            steam_app: Some(220),
            main_exe: Some(&main),
            reg: RegPolicy.reader(&sys),
            app_path: None,
        };
        let r = plan(&[layer_step("game.exe", &["ZZ_OS_A"])], &ctx);
        assert_eq!(r.is_ok(), ok, "{lib}: {r:?}");
        if !ok {
            assert!(format!("{r:?}").contains("reached through a link"), "{r:?}");
        }
    }
}

/// Review S-a: a library reached through a junction whose path is so long that the launch path
/// of the game is no `RootPath` still opens the game (for every primitive); only
/// `compat_layer` refuses it, as reached through a link.
#[test]
fn t9l_a_long_launch_path_opens_the_game_and_refuses_only_compat_layer() {
    use super::tests::{STEAM_GAME, STEAM_LIB};
    let parent = format!(r"D:\{}\{}", "a".repeat(100), "b".repeat(100));
    let lib = format!(r"{parent}\{}", "l".repeat(20));
    assert!(lib.len() - 3 <= crate::path::RelPath::MAX_LEN);
    assert!(format!(r"{lib}\steamapps\common\G").len() - 3 > crate::path::RelPath::MAX_LEN);
    let sys = layer_builder()
        .file(format!(r"{STEAM_GAME}\game.exe"), b"MZ".to_vec())
        .dir(&parent)
        .junction(&lib, STEAM_LIB)
        .build()
        .unwrap();
    let fr = fr(&sys);
    let app = app(&sys);
    let main = rel("game.exe");
    let store = crate::policy::root::StoreDir::open(&sys, &fr, Path::new(&lib)).unwrap();
    let g = store.game(&fr, "G").unwrap();
    assert_eq!(g.path().to_string(), STEAM_GAME);
    assert_eq!(g.launch_path(), None);
    let ctx = PlanCtx {
        game: &g,
        app: Some(&app),
        steam_app: Some(220),
        main_exe: Some(&main),
        reg: RegPolicy.reader(&sys),
        app_path: None,
    };
    let e = plan(&[layer_step("game.exe", &["ZZ_OS_A"])], &ctx).unwrap_err();
    assert!(e.to_string().contains("reached through a link"), "{e}");
}

/// P3-6: the "all users" key of the compatibility-layer values in `view`.
fn hklm(view: RegView) -> RegKey {
    RegKey::new(Hive::LocalMachine, view, LAYERS_KEY)
}

/// P3-6: the 32-bit view's key as the native view names it (`WOW6432Node`).
fn hklm_wow_native() -> RegKey {
    RegKey::new(
        Hive::LocalMachine,
        RegView::Native,
        r"Software\WOW6432Node\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers",
    )
}

/// The `machine` field of the one token list of `p`.
fn machine_of(p: &Plan) -> Vec<(LayerView, String)> {
    p.ops
        .iter()
        .find_map(|o| match o {
            Op::TokenList { machine, .. } => {
                Some(machine.iter().map(|m| (m.view, m.value.clone())).collect())
            }
            _ => None,
        })
        .expect("a token list")
}

/// T9-L-M1 (P3-6): a word of the group of an added token in the "all users" value, in either
/// view, is refused with the value named.
#[test]
fn t9l_m1_hklm_a_group_conflict_in_either_view_is_refused() {
    let exe = exe_name("game.exe");
    // The native view, the 32-bit view (by its view and by its WOW6432Node path), a joined
    // prefix, another case, a second word of the group: each refused, naming the value.
    for (key, value, view, word) in [
        (
            hklm(RegView::Native),
            "~ ZZ_DPI_B",
            "64-bit view",
            "ZZ_DPI_B",
        ),
        (
            hklm(RegView::Wow32),
            "~ RUNASADMIN ZZ_DPI_B",
            "32-bit view",
            "ZZ_DPI_B",
        ),
        (hklm_wow_native(), "~ zz_dpi_b", "32-bit view", "zz_dpi_b"),
        (
            hklm(RegView::Native),
            "~ZZ_DPI_B",
            "64-bit view",
            "~ZZ_DPI_B",
        ),
        (
            hklm(RegView::Native),
            "~ ZZ_OS_C ZZ_DPI_B",
            "64-bit view",
            "ZZ_DPI_B",
        ),
    ] {
        let sys = layer_builder()
            .value(key, &exe, RegValue::String(value.into()))
            .build()
            .unwrap();
        let e = plan_one(&sys, layer_step("game.exe", &["ZZ_DPI_A", "ZZ_FLAG_A"]))
            .expect_err(value)
            .to_string();
        for want in [
            &format!(
                "compat_layer: the all-users compatibility-layer value of game.exe (HKLM, \
                 {view}) holds {word}, of the same kind as ZZ_DPI_A; Rerun does not add \
                 ZZ_DPI_A for the current user over it"
            ) as &str,
            "(Change settings for all users) first",
            &format!("The value: {value}"),
        ] {
            assert!(e.contains(want), "{value}: {want:?} not in {e}");
        }
    }
    // The production tables: an HKLM DPI setting against HKCU `HIGHDPIAWARE` (ADR 0018:154).
    let _r = Reset;
    knob::production(true);
    for (value, word) in [
        ("~ DPIUNAWARE", "DPIUNAWARE"),
        ("~ GDIDPISCALING DPIUNAWARE", "GDIDPISCALING"),
    ] {
        let sys = layer_builder()
            .value(hklm(RegView::Native), &exe, RegValue::String(value.into()))
            .build()
            .unwrap();
        let e = plan_one(&sys, layer_step("game.exe", &["HIGHDPIAWARE"]))
            .unwrap_err()
            .to_string();
        assert!(
            e.contains(&format!("holds {word}, of the same kind as HIGHDPIAWARE")),
            "{e}"
        );
    }
}

/// T9-L-M2 (P3-6): without a conflict the plan proceeds and records, and the preview names,
/// the value of every view where it exists.
#[test]
fn t9l_m2_hklm_without_conflict_plans_and_the_preview_names_it() {
    let exe = exe_name("game.exe");
    // Both views, different values; the added token itself in HKLM is no conflict.
    let sys = layer_builder()
        .value(
            hklm(RegView::Native),
            &exe,
            RegValue::String("~ RUNASADMIN ZZ_OS_A".into()),
        )
        .value(
            hklm_wow_native(),
            &exe,
            RegValue::String("~ ZZ_DPI_A".into()),
        )
        .build()
        .unwrap();
    let p = plan_one(&sys, layer_step("game.exe", &["ZZ_DPI_A", "ZZ_FLAG_A"])).unwrap();
    assert_eq!(
        machine_of(&p),
        [
            (LayerView::Native, "~ RUNASADMIN ZZ_OS_A".to_owned()),
            (LayerView::Wow32, "~ ZZ_DPI_A".to_owned()),
        ]
    );
    let (_, old, add, new) = token_list(&p);
    assert_eq!(old, None);
    assert_eq!(add, ["ZZ_DPI_A", "ZZ_FLAG_A"]);
    assert_eq!(new, "~ ZZ_DPI_A ZZ_FLAG_A");
    let text = crate::plan::preview_stored(&p.encode().unwrap())
        .unwrap()
        .to_string();
    for want in [
        "     all users (HKLM, 64-bit view), not changed: REG_SZ: ~ RUNASADMIN ZZ_OS_A\n",
        "     all users (HKLM, 32-bit view), not changed: REG_SZ: ~ ZZ_DPI_A\n",
    ] {
        assert!(text.contains(want), "{want:?} not in\n{text}");
    }
    // Only one view: only that one is named.
    let sys = layer_builder()
        .value(
            hklm(RegView::Wow32),
            &exe,
            RegValue::String("~ ZZ_FLAG_B".into()),
        )
        .build()
        .unwrap();
    let p = plan_one(&sys, layer_step("game.exe", &["ZZ_DPI_A"])).unwrap();
    assert_eq!(
        machine_of(&p),
        [(LayerView::Wow32, "~ ZZ_FLAG_B".to_owned())]
    );
}

/// T9-L-M3 (P3-6): no "all users" value of the executable: the plan's bytes are those of a
/// system without one.
#[test]
fn t9l_m3_hklm_absent_changes_nothing() {
    let base = plan_one(
        &layer_builder().build().unwrap(),
        layer_step("game.exe", &["ZZ_DPI_A"]),
    )
    .unwrap();
    assert!(machine_of(&base).is_empty());
    for sys in [
        layer_builder()
            .key(hklm(RegView::Native))
            .key(hklm(RegView::Wow32))
            .build()
            .unwrap(),
        layer_builder()
            .value(
                hklm(RegView::Native),
                &exe_name("other.exe"),
                RegValue::String("~ ZZ_DPI_B".into()),
            )
            .build()
            .unwrap(),
    ] {
        let p = plan_one(&sys, layer_step("game.exe", &["ZZ_DPI_A"])).unwrap();
        assert_eq!(p.encode().unwrap(), base.encode().unwrap());
    }
}

/// T9-L-M4 (P3-6): an "all users" value that cannot be read, or whose tokens cannot be
/// checked, is refused in either view (fail closed); with nothing to add it is not read.
#[test]
fn t9l_m4_hklm_unreadable_or_unusual_is_refused() {
    let exe = exe_name("game.exe");
    for (key, view) in [
        (hklm(RegView::Native), "64-bit view"),
        (hklm(RegView::Wow32), "32-bit view"),
        (hklm_wow_native(), "32-bit view"),
    ] {
        let sys = layer_builder().denied_key(key).build().unwrap();
        let e = plan_one(&sys, layer_step("game.exe", &["ZZ_FLAG_A"]))
            .unwrap_err()
            .to_string();
        assert!(
            e.contains(&format!(
                "the all-users compatibility-layer value of game.exe (HKLM, {view}) cannot be \
                 read"
            )) && e.contains("Rerun adds no token it cannot check against it"),
            "{view}: {e}"
        );
    }
    for v in [
        RegValue::Dword(1),
        RegValue::ExpandString("~ ZZ_FLAG_B".into()),
        RegValue::String("~  ZZ_FLAG_B".into()),
        RegValue::String(String::new()),
        RegValue::String(format!("~ {}", "A".repeat(600))),
    ] {
        let sys = layer_builder()
            .value(hklm(RegView::Wow32), &exe, v.clone())
            .build()
            .unwrap();
        let e = plan_one(&sys, layer_step("game.exe", &["ZZ_FLAG_A"]))
            .expect_err(&format!("{v:?}"))
            .to_string();
        assert!(
            e.contains("(HKLM, 32-bit view) is unusual") && e.contains("adds none"),
            "{v:?}: {e}"
        );
    }
    // Nothing to add: HKLM is not read, the step is no op as before.
    let sys = layer_builder()
        .value(
            hkcu(LAYERS_KEY),
            &exe,
            RegValue::String("~ ZZ_FLAG_A".into()),
        )
        .denied_key(hklm(RegView::Native))
        .build()
        .unwrap();
    let p = plan_one(&sys, layer_step("game.exe", &["ZZ_FLAG_A"])).unwrap();
    assert!(!p.ops.iter().any(|o| matches!(o, Op::TokenList { .. })));
}
