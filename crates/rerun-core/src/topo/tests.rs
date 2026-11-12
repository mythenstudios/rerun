//! The Topo engine (P4-4) against the fake. Every Topo, folder, hash and ID is invented.
//!
//! - TW `when`: each key yes, no and unknown; the Kleene AND; empty and missing are yes; the
//!   GPU block per hardware adapter (P4-11, E-G2 d).
//! - TM match: SHA-256 and SHA-1 on the parsed handle; another content, a missing file and a
//!   wrong second hash are no match; the first match is the main executable.
//! - TL `launch`: `auto` resolves to `direct` with `chain: [steam]`, else `watch`; the loader
//!   requires `start` for `auto`, `direct` and `watch`.
//! - TP picks: unknown issue or variant, two variants of one issue, `when = no` refused,
//!   `unknown` planned with a warning, no pick, a package the index does not hold.
//! - TA anti-cheat: refused and warned exactly per user decision E4, also the step kinds that
//!   come later; a dead system released by the Topo; the release is draft only until reviewed.
//! - TB the plan has the bytes of a step file with the same steps (apart from `source`).
//! - TC the whole way from a signed index (test key): the source names the index.
//! - TK `package` (P4-7): the planner's architecture and API filter and refusals; the round trip
//!   from the cached archive through extraction, the engine, apply, verify and revert; `requires`
//!   and the anti-cheat rule.
//! - TS shared files and slots (P4-8): two fixes share the loader across two plans (a hold, the
//!   revert newest first); two packages of one DLL slot; `supports_exe_sha1`; `requires_gpu`.

use std::path::Path;

use sha2::{Digest, Sha256};

use super::{
    ANTI_CHEAT_RULES, AcRule, AntiCheatState, EngineError, ExeState, Facts, GameFacts,
    LaunchProblem, Refusal, StepKind, Tri, Warning, anti_cheat_rule, plan, read_game, report,
    resolve_launch, topos_for, when,
};
use crate::catalog::check::{self, Rules};
use crate::catalog::model::{Topo, When};
use crate::catalog::{Catalog, key::test_key, verify};
use crate::detect::exe::AntiCheat;
use crate::detect::pe::testfx::Builder as PeBuilder;
use crate::exec::rebind_tests::rb_sys;
use crate::hw::{self, GpuArchTable, SystemProfile};
use crate::plan::{Pick, PlanSource};
use crate::policy::registry::RegPolicy;
use crate::policy::root::StoreDir;
use crate::prim::tests::{STEAM_GAME, STEAM_LIB, app, fr};
use crate::prim::{self, MethodSpec, PlanCtx, StepFile};
use crate::sys::GpuAdapter;
use crate::sys::fake::FakeSystem;

const RYZEN_5950X: &str = include_str!("../../../../tests/fixtures/cpu/ryzen9-5950x.json");

// ---------- TW ----------

fn rx_9070_xt() -> GpuAdapter {
    GpuAdapter {
        name: "AMD Radeon RX 9070 XT".to_owned(),
        vendor_id: 0x1002,
        device_id: 0x7550,
        dedicated_video_memory: 16 << 30,
        ..GpuAdapter::default()
    }
}

fn table() -> &'static GpuArchTable {
    GpuArchTable::builtin().unwrap()
}

/// RX 9070 XT (rdna4), 5950X (32 threads, not hybrid), build 26100.
fn full() -> SystemProfile {
    let sys = FakeSystem::builder()
        .gpu(rx_9070_xt())
        .topology_json(RYZEN_5950X)
        .os_build(26100, Some(1))
        .build()
        .unwrap();
    hw::read(&sys, Some(table()))
}

/// Nothing readable: adapters fail, no topology, no build.
fn blind() -> SystemProfile {
    let sys = FakeSystem::builder()
        .gpu_error(crate::sys::SysErrorKind::Other)
        .build()
        .unwrap();
    hw::read(&sys, Some(table()))
}

/// No hardware adapter, an unknown device, or no table.
fn no_adapter() -> SystemProfile {
    hw::read(&FakeSystem::builder().build().unwrap(), Some(table()))
}

fn unknown_device() -> SystemProfile {
    let sys = FakeSystem::builder()
        .gpu(GpuAdapter {
            device_id: 0x0001,
            ..rx_9070_xt()
        })
        .build()
        .unwrap();
    hw::read(&sys, Some(table()))
}

fn w(json: &str) -> When {
    serde_json::from_str(json).unwrap()
}

#[test]
fn tw_each_key_is_yes_no_or_unknown() {
    let (full, blind, none, unknown) = (full(), blind(), no_adapter(), unknown_device());
    let no_table = hw::read(
        &FakeSystem::builder().gpu(rx_9070_xt()).build().unwrap(),
        None,
    );
    let cases: &[(&str, &SystemProfile, Tri)] = &[
        (r#"{"gpu.vendor":"amd"}"#, &full, Tri::Yes),
        (r#"{"gpu.vendor":"nvidia"}"#, &full, Tri::No),
        (r#"{"gpu.vendor":"amd"}"#, &blind, Tri::Unknown),
        (r#"{"gpu.vendor":"amd"}"#, &none, Tri::No),
        (r#"{"gpu.arch":["rdna4"]}"#, &full, Tri::Yes),
        (r#"{"gpu.arch":["rdna2","rdna3"]}"#, &full, Tri::No),
        (r#"{"gpu.arch":["rdna4"]}"#, &blind, Tri::Unknown),
        (r#"{"gpu.arch":["rdna4"]}"#, &none, Tri::No),
        (r#"{"gpu.arch":["rdna4"]}"#, &unknown, Tri::No),
        (r#"{"gpu.arch":["rdna4"]}"#, &no_table, Tri::Unknown),
        (r#"{"gpu.integrated":false}"#, &full, Tri::Yes),
        (r#"{"gpu.integrated":true}"#, &full, Tri::No),
        (r#"{"gpu.integrated":false}"#, &blind, Tri::Unknown),
        (r#"{"gpu.integrated":false}"#, &none, Tri::No),
        (r#"{"gpu.integrated":false}"#, &unknown, Tri::No),
        (r#"{"gpu.integrated":true}"#, &unknown, Tri::No),
        (r#"{"gpu.integrated":false}"#, &no_table, Tri::Unknown),
        (r#"{"gpu.hybrid":false}"#, &full, Tri::Yes),
        (r#"{"gpu.hybrid":true}"#, &full, Tri::No),
        (r#"{"gpu.hybrid":false}"#, &none, Tri::Yes),
        (r#"{"gpu.hybrid":true}"#, &blind, Tri::Unknown),
        (r#"{"cpu.threads":{"gt":16}}"#, &full, Tri::Yes),
        (r#"{"cpu.threads":{"lt":16}}"#, &full, Tri::No),
        (r#"{"cpu.threads":{"gte":32,"lte":32}}"#, &full, Tri::Yes),
        (r#"{"cpu.threads":{"gt":16,"eq":31}}"#, &full, Tri::No),
        (r#"{"cpu.threads":{"gt":16}}"#, &blind, Tri::Unknown),
        (r#"{"cpu.hybrid":false}"#, &full, Tri::Yes),
        (r#"{"cpu.hybrid":true}"#, &full, Tri::No),
        (r#"{"cpu.hybrid":true}"#, &blind, Tri::Unknown),
        (r#"{"os.build":{"gte":22000}}"#, &full, Tri::Yes),
        (r#"{"os.build":{"lt":22000}}"#, &full, Tri::No),
        (r#"{"os.build":{"gte":22000}}"#, &blind, Tri::Unknown),
    ];
    for (json, p, want) in cases {
        assert_eq!(when::eval(Some(&w(json)), p), *want, "{json}");
    }
}

/// A laptop: a synthetic iGPU (Intel `xe_lp`, integrated) and dGPU (NVIDIA `ada`) of the
/// test-only table; with `amd` a third adapter for "all no".
fn laptop(also_amd: bool) -> SystemProfile {
    let mut b = FakeSystem::builder()
        .gpu(GpuAdapter {
            name: "synthetic iGPU".to_owned(),
            vendor_id: 0x8086,
            device_id: 0xB001,
            ..GpuAdapter::default()
        })
        .gpu(GpuAdapter {
            name: "synthetic dGPU".to_owned(),
            vendor_id: 0x10DE,
            device_id: 0xA0FF,
            ..GpuAdapter::default()
        });
    if also_amd {
        b = b.gpu(rx_9070_xt());
    }
    let table = hw::tests::synthetic_table();
    hw::read(&b.build().unwrap(), Some(&table))
}

/// E-G2 d: the GPU keys of one `when` are one block per adapter: all yes is yes, all no is no,
/// else unknown; then ANDed with the other keys. Never "any adapter" or "first adapter".
#[test]
fn tw_gpu_keys_are_one_block_per_adapter() {
    let lap = laptop(false);
    let cases: &[(&str, Tri)] = &[
        // One adapter says yes, the other no.
        (r#"{"gpu.vendor":"nvidia"}"#, Tri::Unknown),
        (r#"{"gpu.integrated":false}"#, Tri::Unknown),
        (r#"{"gpu.arch":["ada"]}"#, Tri::Unknown),
        // Every adapter says no / yes.
        (r#"{"gpu.vendor":"amd"}"#, Tri::No),
        (r#"{"gpu.arch":["ada","xe_lp"]}"#, Tri::Yes),
        // A block, not per key: on the iGPU intel+integrated is yes, on the dGPU no.
        (
            r#"{"gpu.vendor":"intel","gpu.integrated":true}"#,
            Tri::Unknown,
        ),
        // Per key this would be unknown AND unknown; as a block it is no on both adapters.
        (r#"{"gpu.vendor":"nvidia","gpu.integrated":true}"#, Tri::No),
        // The block is ANDed with the rest: no elsewhere wins, yes elsewhere keeps unknown.
        (r#"{"gpu.vendor":"nvidia","gpu.hybrid":false}"#, Tri::No),
        (r#"{"gpu.vendor":"nvidia","gpu.hybrid":true}"#, Tri::Unknown),
        (r#"{"gpu.hybrid":true}"#, Tri::Yes),
        (
            r#"{"gpu.hybrid":true,"gpu.arch":["ada","xe_lp"]}"#,
            Tri::Yes,
        ),
    ];
    for (json, want) in cases {
        assert_eq!(when::eval(Some(&w(json)), &lap), *want, "{json}");
    }
    // Three adapters: intel, nvidia, amd; no one says yes on all, no one no on all.
    let three = laptop(true);
    assert_eq!(
        when::eval(Some(&w(r#"{"gpu.integrated":false}"#)), &three),
        Tri::Unknown
    );
    // Every adapter's architecture is listed: yes.
    assert_eq!(
        when::eval(Some(&w(r#"{"gpu.arch":["rdna4","ada","xe_lp"]}"#)), &three),
        Tri::Yes
    );
    // The laptop without a table: gpu.arch is unavailable on both (unknown); gpu.vendor: amd is
    // no on both (no).
    let lap_adapters = || {
        FakeSystem::builder()
            .gpu(GpuAdapter {
                vendor_id: 0x8086,
                device_id: 0xB001,
                ..GpuAdapter::default()
            })
            .gpu(GpuAdapter {
                vendor_id: 0x10DE,
                device_id: 0xA0FF,
                ..GpuAdapter::default()
            })
    };
    let blind = hw::read(&lap_adapters().build().unwrap(), None);
    assert_eq!(
        when::eval(Some(&w(r#"{"gpu.arch":["ada"]}"#)), &blind),
        Tri::Unknown
    );
    assert_eq!(
        when::eval(Some(&w(r#"{"gpu.vendor":"amd"}"#)), &blind),
        Tri::No
    );
    // An iGPU the table has no entry for: gpu.integrated is no there (no entry), yes on the
    // dGPU: unknown.
    let table = hw::tests::synthetic_table();
    let unlisted = hw::read(
        &FakeSystem::builder()
            .gpu(GpuAdapter {
                vendor_id: 0x8086,
                device_id: 0xB0FE,
                ..GpuAdapter::default()
            })
            .gpu(GpuAdapter {
                vendor_id: 0x10DE,
                device_id: 0xA0FF,
                ..GpuAdapter::default()
            })
            .build()
            .unwrap(),
        Some(&table),
    );
    assert_eq!(
        when::eval(Some(&w(r#"{"gpu.integrated":false}"#)), &unlisted),
        Tri::Unknown
    );
}

#[test]
fn tw_keys_are_and_and_empty_is_yes() {
    let (full, blind) = (full(), blind());
    assert_eq!(when::eval(None, &blind), Tri::Yes);
    assert_eq!(when::eval(Some(&When::default()), &blind), Tri::Yes);
    // no AND unknown is no; unknown AND yes is unknown; yes AND yes is yes.
    let mixed = w(r#"{"gpu.vendor":"nvidia","os.build":{"gte":1}}"#);
    assert_eq!(when::eval(Some(&mixed), &full), Tri::No);
    let blind_no = w(r#"{"gpu.vendor":"amd","cpu.hybrid":true}"#);
    assert_eq!(when::eval(Some(&blind_no), &blind), Tri::Unknown);
    let partly = hw::read(
        &FakeSystem::builder()
            .gpu(rx_9070_xt())
            .os_build(26100, None)
            .build()
            .unwrap(),
        Some(table()),
    );
    let yes_unknown = w(r#"{"gpu.vendor":"amd","cpu.threads":{"gt":1}}"#);
    assert_eq!(when::eval(Some(&yes_unknown), &partly), Tri::Unknown);
    let no_unknown = w(r#"{"gpu.vendor":"intel","cpu.threads":{"gt":1}}"#);
    assert_eq!(when::eval(Some(&no_unknown), &partly), Tri::No);
    let all = w(
        r#"{"gpu.vendor":"amd","gpu.arch":["rdna4"],"cpu.threads":{"gt":12},"cpu.hybrid":false,"os.build":{"gte":22000}}"#,
    );
    assert_eq!(when::eval(Some(&all), &full), Tri::Yes);
    for (a, b, r) in [
        (Tri::Yes, Tri::Yes, Tri::Yes),
        (Tri::Yes, Tri::No, Tri::No),
        (Tri::Yes, Tri::Unknown, Tri::Unknown),
        (Tri::No, Tri::Unknown, Tri::No),
        (Tri::Unknown, Tri::Unknown, Tri::Unknown),
        (Tri::No, Tri::No, Tri::No),
    ] {
        assert_eq!(a.and(b), r);
        assert_eq!(b.and(a), r);
    }
}

// ---------- The game and its Topo ----------

const APP: u32 = 220;

fn pe(x86: bool) -> Vec<u8> {
    if x86 {
        PeBuilder::x86().build().bytes
    } else {
        PeBuilder::x64().build().bytes
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02X}")).collect()
}

fn sha256(b: &[u8]) -> String {
    hex(&Sha256::digest(b))
}

fn sha1(b: &[u8]) -> String {
    use sha1::Sha1;
    hex(&Sha1::digest(b))
}

fn put(sys: &FakeSystem, rel: &str, data: &[u8]) {
    let abs = format!(r"{STEAM_GAME}\{rel}");
    let _ = sys.fake_fs().remove_abs(Path::new(&abs));
    sys.fake_fs().put_file(Path::new(&abs), data).unwrap();
    sys.sync_all();
}

/// Steam app 220 in `G` with an x64 `game.exe` and an x86 `FFLauncher.exe`; `cfg\Game.ini`
/// from the INI tests.
fn game_sys() -> FakeSystem {
    let sys = rb_sys();
    put(&sys, "game.exe", &pe(false));
    put(&sys, "FFLauncher.exe", &pe(true));
    sys
}

/// The Topo: `match` on `game.exe` by SHA-256; `launch` from `extra_launch`; issues `cores`
/// (`cpu`), `settings` (`ini_set` or `registry_set`, `when` on the build), `display`
/// (`compat_layer`), `nvidia` (`when` on the vendor, `steam_input`), `wrapper` (`package`).
fn topo_json(game_sha256: &str, launch: &str) -> String {
    format!(
        r#"{{"format":1,"id":"invented-game","title":"Invented Game","status":"active","rev":3,
"match":{{"steam_appid":{APP},"exes":[{{"path":"game.exe","sha256":"{game_sha256}","api":"d3d9"}}]}},
"launch":{launch},
"issues":[
 {{"id":"cores","title":"Too many cores","variants":[
   {{"id":"limit","status":"verified","kind":"fix","steps":[{{"cpu":{{"max_threads":8,"single_l3":true,"smt":false}}}}]}}]}},
 {{"id":"settings","title":"Settings","when":{{"os.build":{{"gte":22000}}}},"variants":[
   {{"id":"ini","status":"reported","kind":"fix","steps":[{{"ini_set":{{"file":"cfg\\Game.ini","values":[{{"section":"Display","key":"Width","value":"1920"}}]}}}}]}},
   {{"id":"reg","status":"reported","kind":"fix","steps":[{{"registry_set":{{"key":"HKCU\\Software\\Invented\\Game","values":[{{"name":"Windowed","dword":1}}]}}}}]}}]}},
 {{"id":"display","title":"Display","variants":[
   {{"id":"layer","status":"unverified","kind":"fix","steps":[{{"compat_layer":{{"exe":"game.exe","layers":["ZZ_FLAG_A"]}}}}]}}]}},
 {{"id":"nvidia","title":"NVIDIA only","when":{{"gpu.vendor":"nvidia"}},"variants":[
   {{"id":"input","status":"unverified","kind":"fix","steps":[{{"steam_input":"enable"}}]}}]}},
 {{"id":"wrapper","title":"Wrapper","variants":[
   {{"id":"pkg","status":"unverified","kind":"fix","steps":[{{"package":"invented-wrapper"}}]}}]}}
]}}"#
    )
}

const DIRECT: &str = r#"{"chain":["steam"],"method":"auto","start":"FFLauncher.exe"}"#;
const WATCH: &str = r#"{"chain":["steam","upc"],"method":"auto","start":"FFLauncher.exe"}"#;

fn topo(game_sha256: &str, launch: &str) -> Topo {
    let t: Topo = serde_json::from_str(&topo_json(game_sha256, launch)).unwrap();
    check::topo(&t, Rules::Release).unwrap();
    t
}

fn game_topo(launch: &str) -> Topo {
    topo(&sha256(&pe(false)), launch)
}

fn facts_of(sys: &FakeSystem, t: &Topo) -> GameFacts {
    let fr = fr(sys);
    let store = StoreDir::open(sys, &fr, Path::new(STEAM_LIB)).unwrap();
    let g = store.game(&fr, "G").unwrap();
    read_game(&g, t)
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

const INDEX: [u8; 32] = [7; 32];

/// Plans `p` of `t` on `sys` with `profile`.
fn plan_with(
    sys: &FakeSystem,
    t: &Topo,
    profile: &SystemProfile,
    p: &[&str],
) -> Result<super::TopoPlan, EngineError> {
    let gf = facts_of(sys, t);
    let fr = fr(sys);
    let store = StoreDir::open(sys, &fr, Path::new(STEAM_LIB)).unwrap();
    let g = store.game(&fr, "G").unwrap();
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
    let facts = Facts {
        profile,
        table: Some(table()),
        game: &gf,
        packages: &[],
    };
    plan(&INDEX, t, &facts, &picks(p), &ctx)
}

fn plan_on(sys: &FakeSystem, t: &Topo, p: &[&str]) -> Result<super::TopoPlan, EngineError> {
    plan_with(sys, t, &full(), p)
}

// ---------- TM ----------

#[test]
fn tm_matches_by_every_hash_on_the_parsed_handle() {
    let sys = game_sys();
    let exe = pe(false);
    let ok = game_topo(DIRECT);
    let f = facts_of(&sys, &ok);
    assert_eq!(f.exes[0].state, ExeState::Match);
    assert_eq!(f.main_exe().unwrap().as_str(), "game.exe");

    // Another content: no match, and the engine refuses to plan.
    let other = topo(&sha256(b"another build"), DIRECT);
    let f = facts_of(&sys, &other);
    assert_eq!(f.exes[0].state, ExeState::Mismatch);
    assert!(!f.matched());
    assert!(matches!(
        plan_on(&sys, &other, &["cores/limit"]),
        Err(EngineError::NoMatch(id)) if id == "invented-game"
    ));
    let r = report(
        &other,
        &Facts {
            profile: &full(),
            table: Some(table()),
            game: &f,
            packages: &[],
        },
    )
    .unwrap();
    assert!(r.main_exe.is_none(), "a report names no main executable");

    // SHA-1 alone, both right, one of two wrong.
    let with = |sha1_: &str, sha256_: Option<&str>| {
        let mut j: serde_json::Value =
            serde_json::from_str(&topo_json(&sha256(&exe), DIRECT)).unwrap();
        let e = &mut j["match"]["exes"][0];
        e["sha1"] = sha1_.into();
        match sha256_ {
            Some(s) => e["sha256"] = s.into(),
            None => {
                e.as_object_mut().unwrap().remove("sha256");
            }
        }
        serde_json::from_value::<Topo>(j).unwrap()
    };
    let state = |t: &Topo| facts_of(&sys, t).exes[0].state.clone();
    assert_eq!(state(&with(&sha1(&exe), None)), ExeState::Match);
    assert_eq!(
        state(&with(&sha1(&exe), Some(&sha256(&exe)))),
        ExeState::Match
    );
    assert_eq!(
        state(&with(&sha1(b"x"), Some(&sha256(&exe)))),
        ExeState::Mismatch
    );
    assert_eq!(
        state(&with(&sha1(&exe), Some(&sha256(b"x")))),
        ExeState::Mismatch
    );

    // Missing, and a file that is no image.
    let mut j: serde_json::Value = serde_json::from_str(&topo_json(&sha256(&exe), DIRECT)).unwrap();
    j["match"]["exes"] = serde_json::json!([
        {"path": "gone.exe", "sha256": sha256(&exe), "api": "d3d9"},
        {"path": "cfg\\Game.ini", "sha256": sha256(&exe), "api": "d3d9"},
        {"path": "game.exe", "sha256": sha256(&exe), "api": "d3d9"}
    ]);
    let t: Topo = serde_json::from_value(j).unwrap();
    let f = facts_of(&sys, &t);
    assert_eq!(f.exes[0].state, ExeState::Missing);
    assert!(matches!(f.exes[1].state, ExeState::Unreadable(_)));
    assert_eq!(f.main_exe().unwrap().as_str(), "game.exe");
}

// ---------- TL ----------

#[test]
fn tl_auto_resolves_and_start_is_required() {
    let r = |launch: &str| resolve_launch(&game_topo(launch));
    let lp = r(DIRECT).unwrap();
    assert_eq!((lp.method, lp.auto), (MethodSpec::Direct, true));
    assert_eq!(lp.start.as_str(), "FFLauncher.exe");
    assert_eq!(r(WATCH).unwrap().method, MethodSpec::Watch);
    assert_eq!(
        r(r#"{"method":"auto","start":"FFLauncher.exe"}"#)
            .unwrap()
            .method,
        MethodSpec::Watch,
        "no chain is not [steam]"
    );
    assert_eq!(
        r(r#"{"chain":["upc"],"method":"direct","start":"FFLauncher.exe"}"#)
            .unwrap()
            .method,
        MethodSpec::Direct
    );
    let lw = r(r#"{"chain":["steam"],"method":"watch","start":"game.exe"}"#).unwrap();
    assert_eq!((lw.method, lw.auto), (MethodSpec::Watch, false));
    assert_eq!(
        r(r#"{"method":"hold"}"#),
        Err(LaunchProblem::NotYet("hold"))
    );
    assert_eq!(r(r#"{"chain":["steam"]}"#), Err(LaunchProblem::NoMethod));

    // The loader: `start` required for auto, direct and watch; `TODO` only in a draft.
    for m in ["auto", "direct", "watch"] {
        let j = topo_json(&sha256(b"x"), &format!(r#"{{"method":"{m}"}}"#));
        let t: Topo = serde_json::from_str(&j).unwrap();
        let e = check::topo(&t, Rules::Source).unwrap_err();
        assert_eq!(e.at, "launch.start", "{m}");
    }
    let j = topo_json(&sha256(b"x"), r#"{"method":"hold"}"#);
    check::topo(&serde_json::from_str::<Topo>(&j).unwrap(), Rules::Release).unwrap();
    let j = topo_json(&sha256(b"x"), r#"{"method":"auto","start":"TODO"}"#);
    let mut t: Topo = serde_json::from_str(&j).unwrap();
    assert!(check::topo(&t, Rules::Source).is_err(), "TODO needs draft");
    t.status = crate::catalog::model::Status::Draft;
    check::topo(&t, Rules::Source).unwrap();
    assert!(check::topo(&t, Rules::Release).is_err());
    assert_eq!(resolve_launch(&t), Err(LaunchProblem::NoStart));
}

#[test]
fn tl_the_cpu_step_takes_the_resolved_method() {
    let sys = game_sys();
    let direct = plan_on(&sys, &game_topo(DIRECT), &["cores/limit"]).unwrap();
    assert_eq!(direct.launch.unwrap().method, MethodSpec::Direct);
    let watch = plan_on(&sys, &game_topo(WATCH), &["cores/limit"]).unwrap();
    assert_eq!(watch.launch.unwrap().method, MethodSpec::Watch);
    assert!(matches!(
        &watch.steps[..],
        [prim::Step::LaunchMethod(s)] if s.method == MethodSpec::Watch
            && s.start.as_str() == "FFLauncher.exe"
    ));
    // A launch the engine cannot carry refuses the cpu step.
    let hold = game_topo(r#"{"method":"hold"}"#);
    assert!(matches!(
        plan_on(&sys, &hold, &["cores/limit"]),
        Err(EngineError::Refused {
            why: Refusal::Launch(LaunchProblem::NotYet("hold")),
            ..
        })
    ));
}

// ---------- TP ----------

#[test]
fn tp_pick_rules() {
    let sys = game_sys();
    let t = game_topo(DIRECT);
    let err = |p: &[&str]| plan_on(&sys, &t, p).unwrap_err();
    assert!(matches!(err(&[]), EngineError::Picks));
    assert!(matches!(err(&["nope/limit"]), EngineError::UnknownIssue(i) if i == "nope"));
    assert!(matches!(
        err(&["cores/nope"]),
        EngineError::UnknownVariant { issue, variant } if issue == "cores" && variant == "nope"
    ));
    assert!(matches!(
        err(&["settings/ini", "settings/reg"]),
        EngineError::TwoVariants(i) if i == "settings"
    ));
    // `when = no` (an AMD system, an NVIDIA issue) is refused.
    assert!(matches!(err(&["nvidia/input"]), EngineError::WhenNo(i) if i == "nvidia"));
    // A package the index does not hold (the package step itself: `package_tests.rs`).
    assert!(matches!(
        err(&["wrapper/pkg"]),
        EngineError::Package { id, .. } if id == "invented-wrapper"
    ));

    // `when = unknown` (no build readable) only on an explicit pick, with a warning.
    let blind = hw::read(
        &FakeSystem::builder().gpu(rx_9070_xt()).build().unwrap(),
        Some(table()),
    );
    let p = plan_with(&sys, &t, &blind, &["settings/ini"]).unwrap();
    assert_eq!(
        p.warnings,
        vec![Warning::WhenUnknown {
            issue: "settings".into()
        }]
    );
    assert!(!p.plan.ops.is_empty());
    let r = report(
        &t,
        &Facts {
            profile: &blind,
            table: Some(table()),
            game: &facts_of(&sys, &t),
            packages: &[],
        },
    )
    .unwrap();
    let whens: Vec<(&str, Tri)> = r
        .issues
        .iter()
        .map(|i| (i.issue.id.as_str(), i.when))
        .collect();
    assert_eq!(
        whens,
        [
            ("cores", Tri::Yes),
            ("settings", Tri::Unknown),
            ("display", Tri::Yes),
            ("nvidia", Tri::No),
            ("wrapper", Tri::Yes),
        ]
    );

    // A steam_input hint plans nothing; several issues in one plan.
    let p = plan_on(&sys, &t, &["cores/limit", "settings/ini", "display/layer"]).unwrap();
    assert!(p.warnings.is_empty(), "{:?}", p.warnings);
    assert_eq!(p.steps.len(), 3);
    let src = p.plan.source.as_ref().unwrap();
    assert_eq!(
        (src.topo.as_str(), src.rev, src.index, src.picks.len()),
        ("invented-game", 3, INDEX, 3)
    );

    // An undeclared gpu.arch is refused for the whole Topo (ADR 0015).
    let mut j: serde_json::Value =
        serde_json::from_str(&topo_json(&sha256(&pe(false)), DIRECT)).unwrap();
    j["issues"][0]["when"] = serde_json::json!({"gpu.arch": ["invented_arch"]});
    let odd: Topo = serde_json::from_value(j).unwrap();
    assert!(matches!(
        plan_on(&sys, &odd, &["cores/limit"]),
        Err(EngineError::UndeclaredArch { arch, .. }) if arch == "invented_arch"
    ));
}

/// P4-11 (E-G2 d): on a system with several hardware adapters the report says that GPU
/// conditions are unknown where they differ, when an issue has one; `nvidia` is unknown on the
/// laptop (one adapter is NVIDIA, the other Intel) and is planned only with a warning.
#[test]
fn tw_several_gpus_are_named_in_the_report() {
    let sys = game_sys();
    let t = game_topo(DIRECT);
    let gf = facts_of(&sys, &t);
    let lap = laptop(false);
    let run = |profile: &SystemProfile| {
        report(
            &t,
            &Facts {
                profile,
                table: Some(table()),
                game: &gf,
                packages: &[],
            },
        )
        .unwrap()
    };
    let r = run(&lap);
    assert!(r.several_gpus);
    let nvidia = r
        .issues
        .iter()
        .find(|i| i.issue.id.as_str() == "nvidia")
        .unwrap();
    assert_eq!(nvidia.when, Tri::Unknown);
    assert!(!run(&full()).several_gpus, "one adapter");

    // Without a GPU condition in the Topo there is nothing to say.
    let mut j: serde_json::Value =
        serde_json::from_str(&topo_json(&sha256(&pe(false)), DIRECT)).unwrap();
    j["issues"][3].as_object_mut().unwrap().remove("when");
    let plain: Topo = serde_json::from_value(j).unwrap();
    let r = report(
        &plain,
        &Facts {
            profile: &lap,
            table: Some(table()),
            game: &gf,
            packages: &[],
        },
    )
    .unwrap();
    assert!(!r.several_gpus);

    let p = plan_with(&sys, &t, &lap, &["nvidia/input"]).unwrap();
    assert!(p.warnings.contains(&Warning::WhenUnknown {
        issue: "nvidia".into()
    }));
}

// ---------- TA ----------

#[test]
fn ta_the_rule_table_is_exactly_e4() {
    for (k, r) in ANTI_CHEAT_RULES {
        assert_eq!(anti_cheat_rule(k), r, "{k:?}");
    }
    let refused: Vec<StepKind> = ANTI_CHEAT_RULES
        .iter()
        .filter(|(_, r)| *r == AcRule::Refuse)
        .map(|(k, _)| *k)
        .collect();
    assert_eq!(
        refused,
        [
            StepKind::Package,
            StepKind::LaaPatch,
            StepKind::FirewallRule,
            StepKind::CompatLayer,
            StepKind::LaunchWatch,
            StepKind::LaunchHold,
            StepKind::LaunchIfeo,
            StepKind::LaunchInproc
        ]
    );
    let warned: Vec<StepKind> = ANTI_CHEAT_RULES
        .iter()
        .filter(|(_, r)| *r == AcRule::Warn)
        .map(|(k, _)| *k)
        .collect();
    assert_eq!(
        warned,
        [
            StepKind::LaunchDirect,
            StepKind::IniSet,
            StepKind::RegistrySet,
            StepKind::GpuPreference
        ]
    );
}

#[test]
fn ta_anti_cheat_refuses_and_warns_per_e4() {
    let sys = game_sys();
    sys.fake_fs()
        .mkdir_all(Path::new(&format!(r"{STEAM_GAME}\pb")))
        .unwrap();
    sys.sync_all();
    let direct = game_topo(DIRECT);
    let f = facts_of(&sys, &direct);
    assert_eq!(f.anti_cheat.systems(), [AntiCheat::Punkbuster]);
    let refused = |t: &Topo, p: &str| match plan_on(&sys, t, &[p]) {
        Err(EngineError::Refused {
            why: Refusal::AntiCheat(k),
            ..
        }) => k,
        other => panic!("{p}: {other:?}"),
    };
    assert_eq!(refused(&direct, "display/layer"), StepKind::CompatLayer);
    assert_eq!(refused(&direct, "wrapper/pkg"), StepKind::Package);
    assert_eq!(
        refused(&game_topo(WATCH), "cores/limit"),
        StepKind::LaunchWatch
    );
    let warned = |p: &str| {
        plan_on(&sys, &direct, &[p])
            .unwrap()
            .warnings
            .into_iter()
            .map(|w| match w {
                Warning::AntiCheat { step, .. } => step,
                other => panic!("{other:?}"),
            })
            .collect::<Vec<_>>()
    };
    assert_eq!(warned("cores/limit"), [StepKind::LaunchDirect]);
    assert_eq!(warned("settings/ini"), [StepKind::IniSet]);
    assert_eq!(warned("settings/reg"), [StepKind::RegistrySet]);

    // The report says the same per variant, without planning.
    let r = report(
        &direct,
        &Facts {
            profile: &full(),
            table: Some(table()),
            game: &f,
            packages: &[],
        },
    )
    .unwrap();
    assert!(r.anti_cheat.enforced());
    let display = &r.issues[2].variants[0];
    assert_eq!(
        display.refused,
        Some(Refusal::AntiCheat(StepKind::CompatLayer))
    );
    assert_eq!(r.issues[1].variants[0].warned, [StepKind::IniSet]);
    assert_eq!(r.issues[3].variants[0].refused, None, "steam_input");
}

#[test]
fn ta_a_dead_system_released_by_the_topo_does_not_count() {
    let sys = game_sys();
    sys.fake_fs()
        .mkdir_all(Path::new(&format!(r"{STEAM_GAME}\pb")))
        .unwrap();
    sys.sync_all();
    let released = |dead: &str| {
        let mut j: serde_json::Value =
            serde_json::from_str(&topo_json(&sha256(&pe(false)), DIRECT)).unwrap();
        j["status"] = "draft".into();
        j["anti_cheat"] = serde_json::json!({
            "dead": [dead],
            "source": {"type": "pcgw", "url": "https://www.pcgamingwiki.com/wiki/Invented#Multiplayer"}
        });
        let t: Topo = serde_json::from_value(j).unwrap();
        check::topo(&t, Rules::Source).unwrap();
        t
    };
    let t = released("punkbuster");
    let f = facts_of(&sys, &t);
    assert_eq!(
        super::anti_cheat_state(&t, &f.anti_cheat),
        AntiCheatState::Released {
            systems: vec![AntiCheat::Punkbuster]
        }
    );
    let p = plan_on(&sys, &t, &["display/layer"]).unwrap();
    assert!(p.warnings.is_empty());
    // Another system found next to it still counts.
    sys.fake_fs()
        .mkdir_all(Path::new(&format!(r"{STEAM_GAME}\BattlEye")))
        .unwrap();
    sys.sync_all();
    assert!(matches!(
        plan_on(&sys, &t, &["display/layer"]),
        Err(EngineError::Refused {
            why: Refusal::AntiCheat(StepKind::CompatLayer),
            ..
        })
    ));
    // A release of another system does not release this one.
    let other = released("battleye");
    let f = facts_of(&sys, &other);
    assert_eq!(
        super::anti_cheat_state(&other, &f.anti_cheat),
        AntiCheatState::Enforced {
            systems: vec![AntiCheat::Punkbuster],
            unreadable: false
        }
    );
    // Draft only until reviewed: never in the signed index, never active.
    assert!(check::topo(&t, Rules::Release).is_err());
    let mut active = t.clone();
    active.status = crate::catalog::model::Status::Active;
    let e = check::topo(&active, Rules::Source).unwrap_err();
    assert_eq!(e.at, "anti_cheat");
}

// ---------- TB ----------

#[test]
fn tb_the_plan_has_the_bytes_of_the_same_step_file() {
    let sys = game_sys();
    let t = game_topo(DIRECT);
    let p = plan_on(&sys, &t, &["cores/limit", "settings/ini", "display/layer"]).unwrap();
    let sf = StepFile::parse(
        br#"{"format":1,"game":{"steam":220},"main_exe":"game.exe","steps":[
 {"launch_method":{"method":"direct","start":"FFLauncher.exe","cpu":{"max_threads":8,"single_l3":true,"smt":false}}},
 {"ini_set":{"file":"cfg\\Game.ini","values":[{"section":"Display","key":"Width","value":"1920"}]}},
 {"compat_layer":{"exe":"game.exe","layers":["ZZ_FLAG_A"]}}]}"#,
    )
    .unwrap();
    assert_eq!(sf.steps, p.steps);
    let fr = fr(&sys);
    let store = StoreDir::open(&sys, &fr, Path::new(STEAM_LIB)).unwrap();
    let g = store.game(&fr, "G").unwrap();
    let a = app(&sys);
    let from_file = prim::plan(
        &sf.steps,
        &PlanCtx {
            game: &g,
            app: Some(&a),
            steam_app: Some(APP),
            main_exe: Some(&sf.main_exe),
            reg: RegPolicy.reader(&sys),
            app_path: None,
            user_data: None,
        },
    )
    .unwrap();
    assert!(
        from_file.ops.len() >= 3,
        "a profile, an INI and a layer op at least"
    );
    // P5-2a: the engine records the SHA-256 of the matched main executable on the game root.
    let matched = p.plan.roots[0].main_sha256;
    assert_eq!(matched, Some(Sha256::digest(pe(false)).into()));
    assert!(p.plan.roots[1..].iter().all(|r| r.main_sha256.is_none()));
    // ADR 0020 amendment "Other executables": one executable, an empty list.
    assert_eq!(p.plan.roots[0].other_exes, Some(Vec::new()));
    let mut bare = p.plan.clone();
    let source = bare.source.take().unwrap();
    bare.roots[0].main_sha256 = None;
    bare.roots[0].other_exes = None;
    assert_eq!(
        bare.encode().unwrap().bytes(),
        from_file.encode().unwrap().bytes()
    );
    // The source adds exactly one field at the end (the hash and the other executables after
    // `main_exe`).
    let mut hashed = from_file.clone();
    hashed.roots[0].main_sha256 = matched;
    hashed.roots[0].other_exes = Some(Vec::new());
    let with = String::from_utf8(p.plan.encode().unwrap().bytes().to_vec()).unwrap();
    let without = String::from_utf8(serde_json::to_vec(&hashed).unwrap()).unwrap();
    let tail = format!(",\"source\":{}}}", serde_json::to_string(&source).unwrap());
    assert_eq!(with, format!("{}{tail}", &without[..without.len() - 1]));
    // And it survives the strict decode, which checks its form.
    let decoded = crate::plan::decode(p.plan.encode().unwrap().bytes()).unwrap();
    assert_eq!(decoded, p.plan);
}

#[test]
fn tb_a_source_out_of_form_is_refused() {
    let sys = game_sys();
    let base = plan_on(&sys, &game_topo(DIRECT), &["cores/limit"])
        .unwrap()
        .plan;
    let with = |f: &dyn Fn(&mut PlanSource)| {
        let mut p = base.clone();
        f(p.source.as_mut().unwrap());
        p.encode()
    };
    assert!(with(&|_| {}).is_ok());
    assert!(with(&|s| s.topo = "Not An ID".into()).is_err());
    assert!(with(&|s| s.rev = 0).is_err());
    assert!(with(&|s| s.picks.clear()).is_err());
    assert!(with(&|s| s.picks.push(s.picks[0].clone())).is_err());
    assert!(with(&|s| s.picks[0].variant = "a/b".into()).is_err());
}

// ---------- TC ----------

#[test]
fn tc_from_a_signed_index() {
    let sys = game_sys();
    let t = game_topo(DIRECT);
    let index = format!(
        r#"{{"format":1,"seq":1,"issued":"2026-11-09T12:00:00Z","topos":[{}],"packages":[]}}"#,
        serde_json::to_string(&{
            // The index lists every package a Topo names: drop the package issue here.
            let mut t = t.clone();
            t.issues.retain(|i| i.id.as_str() != "wrapper");
            t
        })
        .unwrap()
    );
    let sig = test_key::sign(index.as_bytes());
    let v = verify(index.as_bytes(), &sig, &[test_key::public()]).unwrap();
    let c = Catalog::from_verified(&v).unwrap();
    let found = topos_for(&c, APP);
    assert_eq!(found.len(), 1);
    assert!(topos_for(&c, APP + 1).is_empty());
    let gf = facts_of(&sys, found[0]);
    let fr = fr(&sys);
    let store = StoreDir::open(&sys, &fr, Path::new(STEAM_LIB)).unwrap();
    let g = store.game(&fr, "G").unwrap();
    let a = app(&sys);
    let ctx = PlanCtx {
        game: &g,
        app: Some(&a),
        steam_app: Some(APP),
        main_exe: None,
        reg: RegPolicy.reader(&sys),
        app_path: None,
        user_data: None,
    };
    let profile = full();
    let facts = Facts {
        profile: &profile,
        table: Some(table()),
        game: &gf,
        packages: &[],
    };
    let p = plan(c.sha256(), found[0], &facts, &picks(&["cores/limit"]), &ctx).unwrap();
    assert_eq!(&p.plan.source.unwrap().index, c.sha256());
}

/// FC1 (ADR 0024 amendment "Forward compatibility"): next to a Topo of entry format 2 with an
/// unknown field and an unknown step kind for the same game, the known Topo loads and is
/// planned; the future one is set aside as newer, with its app from the head, and never found.
#[test]
fn fc1_a_known_topo_is_planned_next_to_a_future_one() {
    use crate::catalog::{AsideWhy, EntryKind};
    let sys = game_sys();
    let mut t = game_topo(DIRECT);
    t.issues.retain(|i| i.id.as_str() != "wrapper");
    let future = format!(
        r#"{{"format":2,"id":"zz-future","title":"F","status":"active","rev":1,"new_field":true,"match":{{"steam_appid":{APP},"exes":[{{"path":"game.exe","api":"d3d12","sha256":"{}"}}]}},"issues":[{{"id":"x","title":"X","variants":[{{"id":"v","status":"verified","kind":"fix","steps":[{{"teleport":{{"to":"mars"}}}}]}}]}}]}}"#,
        "11".repeat(32)
    );
    let index = format!(
        r#"{{"format":1,"seq":1,"issued":"2026-11-09T12:00:00Z","topos":[{},{future}],"packages":[]}}"#,
        serde_json::to_string(&t).unwrap()
    );
    let sig = test_key::sign(index.as_bytes());
    let v = verify(index.as_bytes(), &sig, &[test_key::public()]).unwrap();
    let c = Catalog::from_verified(&v).unwrap();
    assert!(c.topo("zz-future").is_none());
    let a: Vec<_> = c.aside_for(APP).collect();
    assert_eq!(a.len(), 1);
    assert_eq!(
        (a[0].kind, a[0].id.as_str(), a[0].format, a[0].steam_appid),
        (EntryKind::Topo, "zz-future", 2, Some(APP))
    );
    assert_eq!(a[0].why, AsideWhy::Newer { format: 2 });
    assert!(a[0].why.needs_newer());
    let found = topos_for(&c, APP);
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].id, t.id);
    let gf = facts_of(&sys, found[0]);
    let fr = fr(&sys);
    let store = StoreDir::open(&sys, &fr, Path::new(STEAM_LIB)).unwrap();
    let g = store.game(&fr, "G").unwrap();
    let a = app(&sys);
    let ctx = PlanCtx {
        game: &g,
        app: Some(&a),
        steam_app: Some(APP),
        main_exe: None,
        reg: RegPolicy.reader(&sys),
        app_path: None,
        user_data: None,
    };
    let profile = full();
    let facts = Facts {
        profile: &profile,
        table: Some(table()),
        game: &gf,
        packages: &[],
    };
    let p = plan(c.sha256(), found[0], &facts, &picks(&["cores/limit"]), &ctx).unwrap();
    assert_eq!(&p.plan.source.unwrap().index, c.sha256());
}

// ---------- Review follow-ups (P4-4) ----------

fn mkdir(sys: &FakeSystem, rel: &str) {
    sys.fake_fs()
        .mkdir_all(Path::new(&format!(r"{STEAM_GAME}\{rel}")))
        .unwrap();
    sys.sync_all();
}

/// Follow-up 2: a marker the user may not open counts even against a release of its system,
/// and alone (no find at all) it triggers the rule.
#[test]
fn rf_an_unreadable_marker_is_never_released() {
    let sys = game_sys();
    mkdir(&sys, "pb");
    sys.fake_fs()
        .set_restricted(Path::new(&format!(r"{STEAM_GAME}\pb")), true)
        .unwrap();
    sys.sync_all();
    let mut j: serde_json::Value =
        serde_json::from_str(&topo_json(&sha256(&pe(false)), DIRECT)).unwrap();
    j["status"] = "draft".into();
    j["anti_cheat"] = serde_json::json!({
        "dead": ["punkbuster"],
        "source": {"type": "pcgw", "url": "https://www.pcgamingwiki.com/wiki/Invented#Multiplayer"}
    });
    let t: Topo = serde_json::from_value(j).unwrap();
    let f = facts_of(&sys, &t);
    assert!(f.anti_cheat.found.is_empty(), "{:?}", f.anti_cheat);
    assert_eq!(f.anti_cheat.unreadable.len(), 1);
    assert_eq!(
        super::anti_cheat_state(&t, &f.anti_cheat),
        AntiCheatState::Enforced {
            systems: vec![],
            unreadable: true
        }
    );
    assert!(matches!(
        plan_on(&sys, &t, &["display/layer"]),
        Err(EngineError::Refused {
            why: Refusal::AntiCheat(StepKind::CompatLayer),
            ..
        })
    ));
}

/// Follow-up 2 and 7: a marker that is a link counts as found; a named folder that is a link
/// is unreadable as a whole, not one find per marker.
#[test]
fn rf_links_as_markers_and_as_folders() {
    let sys = game_sys();
    mkdir(&sys, "BattlEye");
    sys.fake_fs()
        .swap_with_junction(
            Path::new(&format!(r"{STEAM_GAME}\BattlEye")),
            r"D:\Elsewhere",
        )
        .unwrap();
    mkdir(&sys, "bin");
    sys.fake_fs()
        .swap_with_junction(Path::new(&format!(r"{STEAM_GAME}\bin")), r"D:\Elsewhere")
        .unwrap();
    sys.sync_all();
    let fr = fr(&sys);
    let store = StoreDir::open(&sys, &fr, Path::new(STEAM_LIB)).unwrap();
    let g = store.game(&fr, "G").unwrap();
    let bin = crate::path::RelPath::parse("bin").unwrap();
    let s = crate::detect::exe::anti_cheat::find(&g, &[bin]);
    assert_eq!(s.systems(), [AntiCheat::Battleye]);
    assert_eq!(s.found.len(), 1);
    assert_eq!(
        s.unreadable.iter().map(|p| p.as_str()).collect::<Vec<_>>(),
        ["bin"]
    );
}

/// Follow-up 2: `retired` refused, `needs-retest` warned, two CPU rules refused.
#[test]
fn rf_status_and_two_cpu_rules() {
    let sys = game_sys();
    let mut t = game_topo(DIRECT);
    t.status = crate::catalog::model::Status::Retired;
    assert!(matches!(
        plan_on(&sys, &t, &["cores/limit"]),
        Err(EngineError::Retired(_))
    ));
    t.status = crate::catalog::model::Status::NeedsRetest;
    let p = plan_on(&sys, &t, &["cores/limit"]).unwrap();
    assert_eq!(p.warnings, [Warning::NeedsRetest]);

    let mut j: serde_json::Value =
        serde_json::from_str(&topo_json(&sha256(&pe(false)), DIRECT)).unwrap();
    let mut second = j["issues"][0].clone();
    second["id"] = "cores-again".into();
    j["issues"].as_array_mut().unwrap().push(second);
    let two: Topo = serde_json::from_value(j).unwrap();
    assert!(matches!(
        plan_on(&sys, &two, &["cores/limit", "cores-again/limit"]),
        Err(EngineError::TwoCpuRules)
    ));
}

/// Follow-up 3: every launch method that opens or enters the game is refused with anti-cheat.
#[test]
fn rf_hold_ifeo_inproc_are_refused_with_anti_cheat() {
    let sys = game_sys();
    mkdir(&sys, "pb");
    for (m, k) in [
        ("hold", StepKind::LaunchHold),
        ("ifeo", StepKind::LaunchIfeo),
        ("inproc", StepKind::LaunchInproc),
    ] {
        let t = game_topo(&format!(r#"{{"method":"{m}"}}"#));
        assert!(
            matches!(
                plan_on(&sys, &t, &["cores/limit"]),
                Err(EngineError::Refused { why: Refusal::AntiCheat(got), .. }) if got == k
            ),
            "{m}"
        );
        assert_eq!(anti_cheat_rule(k), AcRule::Refuse);
    }
}

/// Follow-up 4: retired Topos aside, exactly one match; two are `Several`.
#[test]
fn rf_select_sets_retired_topos_aside() {
    use super::{Selection, select};
    let sys = game_sys();
    let a = game_topo(DIRECT);
    let mut b = a.clone();
    b.id = crate::catalog::model::Id::parse("invented-game-b").unwrap();
    let fa = facts_of(&sys, &a);
    let fb = facts_of(&sys, &b);
    assert!(matches!(
        select(vec![(&a, fa.clone()), (&b, fb.clone())]).1,
        Selection::Several(v) if v.len() == 2
    ));
    let mut r = b.clone();
    r.status = crate::catalog::model::Status::Retired;
    let (retired, sel) = select(vec![(&a, fa), (&r, fb.clone())]);
    assert_eq!(retired.len(), 1);
    assert!(matches!(sel, Selection::One(t, _) if t.id.as_str() == "invented-game"));
    let (retired, sel) = select(vec![(&r, fb)]);
    assert_eq!(retired.len(), 1);
    assert!(matches!(sel, Selection::NoMatch(v) if v.is_empty()));
}

/// Follow-up 4: the index refuses two live Topos with the same app and an exe hash in common
/// (since the amendment "Forward compatibility" of ADR 0024: both are set aside as refused, the
/// rest of the index stays).
#[test]
fn rf_the_index_refuses_overlapping_topos() {
    let mut a = game_topo(DIRECT);
    a.issues.retain(|i| i.id.as_str() != "wrapper");
    let mut b = a.clone();
    b.id = crate::catalog::model::Id::parse("invented-game-b").unwrap();
    let index = |topos: &[&Topo]| crate::catalog::Index {
        format: 1,
        seq: 1,
        issued: "2026-11-09T12:00:00Z".into(),
        topos: topos.iter().map(|t| (*t).clone()).collect(),
        packages: vec![],
    };
    let aside = |topos: &[&Topo]| {
        let bytes = serde_json::to_vec(&index(topos)).unwrap();
        crate::catalog::check_bundle(&bytes).unwrap()
    };
    let both = aside(&[&a, &b]);
    assert_eq!(both.len(), 2, "{both:?}");
    for x in &both {
        assert!(x.to_string().contains("claims the same app"), "{x}");
    }
    let mut retired = b.clone();
    retired.status = crate::catalog::model::Status::Retired;
    assert_eq!(aside(&[&a, &retired]), vec![]);
    let mut other_app = b.clone();
    other_app.matches.steam_appid = Some(APP + 1);
    assert_eq!(aside(&[&a, &other_app]), vec![]);
}

/// Follow-up 1: a step file gets the same rule (nothing released, a step file has no Topo).
#[test]
fn rf_step_files_get_the_same_rule() {
    use super::anti_cheat_steps;
    let sys = game_sys();
    let sf = StepFile::parse(
        br#"{"format":1,"game":{"steam":220},"main_exe":"game.exe","steps":[
 {"launch_method":{"method":"direct","start":"FFLauncher.exe","cpu":{"max_threads":8}}},
 {"ini_set":{"file":"cfg\\Game.ini","values":[{"section":"Display","key":"Width","value":"1920"}]}}]}"#,
    )
    .unwrap();
    let clear = crate::detect::exe::AntiCheatScan::default();
    assert_eq!(anti_cheat_steps(&sf.steps, &clear), Ok(vec![]));
    mkdir(&sys, "pb");
    let f = facts_of(&sys, &game_topo(DIRECT));
    assert_eq!(
        anti_cheat_steps(&sf.steps, &f.anti_cheat),
        Ok(vec![StepKind::LaunchDirect, StepKind::IniSet])
    );
    let layer = StepFile::parse(
        br#"{"format":1,"game":{"steam":220},"main_exe":"game.exe","steps":[
 {"compat_layer":{"exe":"game.exe","layers":["ZZ_FLAG_A"]}}]}"#,
    )
    .unwrap();
    assert_eq!(
        anti_cheat_steps(&layer.steps, &f.anti_cheat),
        Err(Refusal::AntiCheat(StepKind::CompatLayer))
    );
}

// ---------- TF: firewall rules (P4-2d) ----------

/// The engine plans `firewall_rule` steps as `FirewallRule` ops after every other op, from the
/// anchors of `elevate::check_plan` only (A4 S7), and refuses them where the helper would.
#[test]
fn tf_firewall_rules_are_planned_last_from_the_anchors() {
    {
        let sys = game_sys();
        let json = topo_json(&sha256(&pe(false)), DIRECT).replace(
            r#" {"id":"wrapper""#,
            r#" {"id":"net","title":"Online check","variants":[
   {"id":"block","status":"verified","kind":"fix","steps":[{"firewall_rule":{"exe":"game.exe","direction":"out"}}]}]},
 {"id":"wrapper""#,
        );
        let t: Topo = serde_json::from_str(&json).unwrap();
        check::topo(&t, Rules::Release).unwrap();
        let p = plan_on(&sys, &t, &["cores/limit", "net/block"])
            .unwrap()
            .plan;
        let last = p.ops.last().unwrap();
        assert_eq!(
            last,
            &crate::plan::Op::FirewallRule {
                root: crate::plan::RootIx(0),
                program: crate::path::RelPath::parse("game.exe").unwrap(),
                direction: crate::policy::firewall::Direction::Out,
            }
        );
        assert!(
            p.ops[..p.ops.len() - 1]
                .iter()
                .all(|o| !o.target().is_helper())
        );
        // A rule alone is op 0.
        let p = plan_on(&sys, &t, &["net/block"]).unwrap().plan;
        assert_eq!(p.ops.len(), 1);
        assert!(p.ops[0].target().is_helper());
        assert!(p.source.is_some());
        // The program changed since the scan: refused, as the helper would.
        let json2 = json.replace(
            r#""exe":"game.exe","direction":"out""#,
            r#""exe":"FFLauncher.exe","direction":"out""#,
        );
        let t2: Topo = serde_json::from_str(&json2.replace(
            r#"{"path":"game.exe","sha256""#,
            &format!(
                r#"{{"path":"FFLauncher.exe","sha256":"{}","api":"d3d9"}},{{"path":"game.exe","sha256""#,
                sha256(b"not the launcher")
            ),
        ))
        .unwrap();
        assert!(matches!(
            plan_on(&sys, &t2, &["net/block"]),
            Err(EngineError::Firewall(e))
                if matches!(*e, crate::elevate::PlanRefusal::ExeMismatch(_))
        ));
    }
}

// ---------- TK `package` (P4-7) ----------

use crate::catalog::model::{Api, Arch, Package, PackageFile};
use crate::exec::tests::{Env, snap_at};
use crate::journal::{Closing, Observed};
use crate::path::RelPath;
use crate::pkg::archive::testfx::{ZipEntry, zip};
use crate::pkg::extract::extract;
use crate::pkg::extract_tests::{assets_package, cache, file, package};
use crate::prim::{FileEntry, FileInstallSpec, GameBuild, PackageRefusal, Step};

/// The wrapper's archive: an x64 and an x86 build of `d3d9.dll`, a `d3d11.dll` and a config.
fn wrapper_zip() -> Vec<u8> {
    zip(&[
        ZipEntry::file("x64/d3d9.dll", b"wrapper d3d9 x64"),
        ZipEntry::file("x32/d3d9.dll", b"wrapper d3d9 x86"),
        ZipEntry::file("x64/d3d11.dll", b"wrapper d3d11 x64"),
        ZipEntry::file("wrapper.ini", b"[wrapper]\r\n"),
        ZipEntry::file("readme.md", b"never extracted"),
    ])
}

fn only(mut f: PackageFile, arch: Option<Arch>, api: Option<Api>) -> PackageFile {
    f.arch = arch.map(|a| vec![a]);
    f.api = api.map(|a| vec![a]);
    f
}

/// `invented-wrapper` with [`wrapper_zip`]: per architecture and API.
fn wrapper(archive: &[u8]) -> Package {
    let mut p = package(
        "zip",
        archive,
        vec![
            only(
                file("x64/d3d9.dll", "d3d9.dll", b"wrapper d3d9 x64"),
                Some(Arch::X64),
                Some(Api::D3d9),
            ),
            only(
                file("x32/d3d9.dll", "d3d9.dll", b"wrapper d3d9 x86"),
                Some(Arch::X86),
                Some(Api::D3d9),
            ),
            only(
                file("x64/d3d11.dll", "d3d11.dll", b"wrapper d3d11 x64"),
                Some(Arch::X64),
                Some(Api::D3d11),
            ),
            {
                let mut c = file("wrapper.ini", r"cfg\wrapper.ini", b"[wrapper]\r\n");
                c.config = true;
                c
            },
        ],
    );
    p.id = crate::catalog::model::Id::parse("invented-wrapper").unwrap();
    p
}

fn plan_pkgs(
    sys: &FakeSystem,
    t: &Topo,
    packages: &[Package],
    p: &[&str],
) -> Result<super::TopoPlan, EngineError> {
    let gf = facts_of(sys, t);
    let fr = fr(sys);
    let store = StoreDir::open(sys, &fr, Path::new(STEAM_LIB)).unwrap();
    let g = store.game(&fr, "G").unwrap();
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
    let profile = full();
    let facts = Facts {
        profile: &profile,
        table: Some(table()),
        game: &gf,
        packages,
    };
    plan(&INDEX, t, &facts, &picks(p), &ctx)
}

fn sha_of(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}

#[test]
fn tk_the_package_planner_filters_by_architecture_and_api() {
    let p = wrapper(&wrapper_zip());
    let x64_d3d9 = GameBuild {
        arch: Some(Arch::X64),
        api: Api::D3d9,
    };
    let spec = crate::prim::package::file_install(&p, &x64_d3d9).unwrap();
    assert_eq!(
        spec,
        FileInstallSpec {
            package: "invented-wrapper".into(),
            version: "1.0".into(),
            files: vec![
                FileEntry {
                    from: RelPath::parse("x64/d3d9.dll").unwrap(),
                    to: RelPath::parse("d3d9.dll").unwrap(),
                    sha256: sha_of(b"wrapper d3d9 x64"),
                    config: false,
                },
                FileEntry {
                    from: RelPath::parse("wrapper.ini").unwrap(),
                    to: RelPath::parse(r"cfg\wrapper.ini").unwrap(),
                    sha256: sha_of(b"[wrapper]\r\n"),
                    config: true,
                },
            ],
        }
    );
    let x86 = GameBuild {
        arch: Some(Arch::X86),
        ..x64_d3d9
    };
    let spec = crate::prim::package::file_install(&p, &x86).unwrap();
    assert_eq!(spec.files[0].from.as_str(), r"x32\d3d9.dll");
    // Refusals: an unknown architecture, one the package does not name, an API it does not
    // wrap, nothing left, a community package, a TODO.
    let refuse = |p: &Package, b: GameBuild| crate::prim::package::file_install(p, &b).unwrap_err();
    assert_eq!(
        refuse(
            &p,
            GameBuild {
                arch: None,
                ..x64_d3d9
            }
        ),
        PackageRefusal::UnknownArch
    );
    let mut only_x86 = p.clone();
    only_x86.arch = crate::catalog::model::ArchList::List(vec![Arch::X86]);
    assert_eq!(refuse(&only_x86, x64_d3d9), PackageRefusal::Arch("x64"));
    let mut d3d9_only = p.clone();
    d3d9_only.apis = Some(vec![Api::D3d9]);
    assert_eq!(
        refuse(
            &d3d9_only,
            GameBuild {
                api: Api::D3d11,
                ..x64_d3d9
            }
        ),
        PackageRefusal::Api("d3d11")
    );
    let mut nothing = p.clone();
    nothing.files.retain(|f| f.api.is_some());
    assert_eq!(
        refuse(
            &nothing,
            GameBuild {
                api: Api::Opengl,
                ..x64_d3d9
            }
        ),
        PackageRefusal::Empty
    );
    let mut community = p.clone();
    community.tier = crate::catalog::model::Tier::Community;
    assert_eq!(refuse(&community, x64_d3d9), PackageRefusal::Community);
    let mut todo = p.clone();
    todo.files[0].sha256 = crate::catalog::model::Hex::parse("TODO").unwrap();
    assert_eq!(refuse(&todo, x64_d3d9), PackageRefusal::Draft);
    // An assets package: the build's own folder.
    let mut a86 = file("dinput8.dll", "dinput8.dll", b"x86 loader");
    a86.arch = Some(vec![Arch::X86]);
    let mut a64 = file("dinput8.dll", "dinput8.dll", b"x64 loader");
    a64.arch = Some(vec![Arch::X64]);
    let assets = assets_package(b"a", b"b", vec![a86, a64]);
    let spec = crate::prim::package::file_install(&assets, &x64_d3d9).unwrap();
    assert_eq!(spec.files.len(), 1);
    assert_eq!(spec.files[0].from.as_str(), r"x64\dinput8.dll");
    assert_eq!(spec.files[0].sha256, sha_of(b"x64 loader"));
}

/// The acceptance round trip of P4-7: a Topo's `package` step from the archive in the cache,
/// extracted, planned by the engine, applied, verified and reverted; the game folder is then
/// identical, and only the named files were ever extracted.
#[test]
fn tk_package_round_trip_restores_the_game_folder() {
    let env = Env::new(game_sys());
    let sys = &env.sys;
    let t = game_topo(DIRECT);
    let archive = wrapper_zip();
    let pkg = wrapper(&archive);
    let before = snap_at(sys, STEAM_GAME);

    // Not extracted yet: the planner names the command that does it (the exact text).
    let e = plan_pkgs(sys, &t, std::slice::from_ref(&pkg), &["wrapper/pkg"]).unwrap_err();
    assert!(
        e.to_string().ends_with(
            "package invented-wrapper 1.0 is not in Rerun's packages folder (rerun package \
             fetch invented-wrapper@1.0 downloads and unpacks a package of the signed index)"
        ),
        "{e}"
    );

    cache(sys, &archive);
    extract(sys, &app(sys), &pkg).unwrap();
    let tp = plan_pkgs(sys, &t, std::slice::from_ref(&pkg), &["wrapper/pkg"]).unwrap();
    // The plan is the one of the same file_install step (TB); x64 + d3d9 (the Topo's API).
    let Step::FileInstall(spec) = &tp.steps[0] else {
        panic!("{:?}", tp.steps);
    };
    let froms: Vec<&str> = spec.files.iter().map(|f| f.from.as_str()).collect();
    assert_eq!(froms, [r"x64\d3d9.dll", "wrapper.ini"]);
    // A replace of the game's read-only d3d9.dll and a new config file in the existing cfg.
    let kinds: Vec<&str> = tp
        .plan
        .ops
        .iter()
        .map(|o| match o {
            crate::plan::Op::ReplaceFile { .. } => "replace",
            crate::plan::Op::CreateFile { .. } => "create",
            crate::plan::Op::CreateDir { .. } => "dir",
            _ => "other",
        })
        .collect();
    assert_eq!(kinds, ["replace", "create"]);

    let a = app(sys);
    let h = crate::plan::store(&a, &tp.plan.encode().unwrap()).unwrap();
    drop(a);
    let txn = env.applied(&h);
    assert_eq!(
        crate::exec::tests::read_abs(sys, &format!(r"{STEAM_GAME}\d3d9.dll")),
        b"wrapper d3d9 x64"
    );
    let v = env.verify(&txn);
    assert!(v.iter().all(|(_, o)| *o == Observed::After), "{v:?}");
    let rep = env.revert(&txn).unwrap();
    assert_eq!(rep.closed, Some(Closing::Reverted));
    let after = snap_at(sys, STEAM_GAME);
    assert!(before == after, "not identical: {:#?}", before.diff(&after));
}

#[test]
fn tk_requires_and_anti_cheat_hold_for_packages() {
    let sys = game_sys();
    let archive = wrapper_zip();
    let mut pkg = wrapper(&archive);
    pkg.requires = vec![crate::catalog::model::Id::parse("invented-loader").unwrap()];
    cache(&sys, &archive);
    extract(&sys, &app(&sys), &pkg).unwrap();
    let t = game_topo(DIRECT);
    let e = plan_pkgs(&sys, &t, std::slice::from_ref(&pkg), &["wrapper/pkg"]).unwrap_err();
    assert!(
        matches!(&e, EngineError::Package { id, why } if id == "invented-wrapper" && why.contains("invented-loader")),
        "{e}"
    );
    // An anti-cheat marker refuses the step before anything else (E4).
    mkdir(&sys, "EasyAntiCheat");
    pkg.requires.clear();
    assert!(matches!(
        plan_pkgs(&sys, &t, std::slice::from_ref(&pkg), &["wrapper/pkg"]),
        Err(EngineError::Refused {
            why: Refusal::AntiCheat(StepKind::Package),
            ..
        })
    ));
}

/// The Topo of [`game_topo`] as JSON, to be changed by a test.
fn topo_value() -> serde_json::Value {
    serde_json::from_str(&topo_json(&sha256(&pe(false)), DIRECT)).unwrap()
}

fn topo_of(v: serde_json::Value) -> Topo {
    let t: Topo = serde_json::from_value(v).unwrap();
    check::topo(&t, Rules::Release).unwrap();
    t
}

/// The `file_install` steps of a Topo plan, as (package, sources).
fn installs(tp: &super::TopoPlan) -> Vec<(String, Vec<String>)> {
    tp.steps
        .iter()
        .filter_map(|s| match s {
            Step::FileInstall(f) => Some((
                f.package.clone(),
                f.files.iter().map(|x| x.from.as_str().to_owned()).collect(),
            )),
            _ => None,
        })
        .collect()
}

/// Security follow-up 1: the API comes from the very `match.exes` entry whose hash matched.
/// Two entries name `game.exe`: another build (d3d9) first, this build (d3d11) second.
#[test]
fn tk_the_api_is_the_matched_entrys() {
    let sys = game_sys();
    let mut v = topo_value();
    v["match"]["exes"] = serde_json::json!([
        {"path":"game.exe","sha256":sha256(b"another build"),"api":"d3d9"},
        {"path":"game.exe","sha256":sha256(&pe(false)),"api":"d3d11"}
    ]);
    let t = topo_of(v);
    let archive = wrapper_zip();
    let pkg = wrapper(&archive);
    cache(&sys, &archive);
    extract(&sys, &app(&sys), &pkg).unwrap();
    let tp = plan_pkgs(&sys, &t, std::slice::from_ref(&pkg), &["wrapper/pkg"]).unwrap();
    assert_eq!(
        installs(&tp),
        [(
            "invented-wrapper".to_owned(),
            vec![r"x64\d3d11.dll".to_owned(), "wrapper.ini".to_owned()]
        )]
    );
}

/// Senior follow-up 2: a version folder that exists but lacks a file (or holds another
/// content) also names `package fetch`.
#[test]
fn tk_an_empty_version_folder_names_package_fetch() {
    let sys = game_sys();
    let t = game_topo(DIRECT);
    let pkg = wrapper(&wrapper_zip());
    sys.fake_fs()
        .mkdir_all(Path::new(
            r"C:\Users\Player\AppData\Local\Rerun\packages\invented-wrapper\1.0",
        ))
        .unwrap();
    sys.sync_all();
    let e = plan_pkgs(&sys, &t, std::slice::from_ref(&pkg), &["wrapper/pkg"]).unwrap_err();
    assert!(
        e.to_string().ends_with(
            r"source x64\d3d9.dll: missing (rerun package fetch invented-wrapper@1.0 downloads and unpacks a package of the signed index)"
        ),
        "{e}"
    );
    // Another content there: the same hint.
    let f = r"C:\Users\Player\AppData\Local\Rerun\packages\invented-wrapper\1.0\x64\d3d9.dll";
    sys.fake_fs().put_file(Path::new(f), b"changed").unwrap();
    sys.sync_all();
    let e = plan_pkgs(&sys, &t, std::slice::from_ref(&pkg), &["wrapper/pkg"]).unwrap_err();
    assert!(
        e.to_string().ends_with(
            r"source x64\d3d9.dll: does not have the SHA-256 of the step (rerun package fetch invented-wrapper@1.0 downloads and unpacks a package of the signed index)"
        ),
        "{e}"
    );
}

/// Senior follow-up 3: one package picked twice is planned once; `requires` met in the plan.
#[test]
fn tk_twice_once_and_requires_in_the_plan() {
    let sys = game_sys();
    let archive = wrapper_zip();
    let mut pkg = wrapper(&archive);
    cache(&sys, &archive);
    extract(&sys, &app(&sys), &pkg).unwrap();
    // Twice: a second issue whose variant names the same package.
    let mut v = topo_value();
    v["issues"].as_array_mut().unwrap().push(serde_json::json!(
        {"id":"again","title":"Again","variants":[
            {"id":"pkg","status":"unverified","kind":"fix","steps":[{"package":"invented-wrapper"}]}]}
    ));
    let t = topo_of(v);
    let tp = plan_pkgs(
        &sys,
        &t,
        std::slice::from_ref(&pkg),
        &["wrapper/pkg", "again/pkg"],
    )
    .unwrap();
    assert_eq!(installs(&tp).len(), 1, "{:?}", tp.steps);
    // `requires` met: the loader in the same variant (after the wrapper, order free).
    let loader_zip = zip(&[ZipEntry::file("dinput8.dll", b"loader")]);
    let mut loader = package(
        "zip",
        &loader_zip,
        vec![file("dinput8.dll", "dinput8.dll", b"loader")],
    );
    loader.id = crate::catalog::model::Id::parse("invented-loader").unwrap();
    cache(&sys, &loader_zip);
    extract(&sys, &app(&sys), &loader).unwrap();
    pkg.requires = vec![loader.id.clone()];
    let mut v = topo_value();
    v["issues"][4]["variants"][0]["steps"] = serde_json::json!([
        {"package":"invented-wrapper"},{"package":"invented-loader"}
    ]);
    let t = topo_of(v);
    let both = [loader.clone(), pkg.clone()];
    let tp = plan_pkgs(&sys, &t, &both, &["wrapper/pkg"]).unwrap();
    let names: Vec<String> = installs(&tp).into_iter().map(|(p, _)| p).collect();
    assert_eq!(names, ["invented-wrapper", "invented-loader"]);
    assert!(tp.plan.ops.iter().any(
        |o| matches!(o, crate::plan::Op::CreateFile { path, .. } if path.as_str() == "dinput8.dll")
    ));
}

/// Senior follow-up 3: the round trip with a package of one asset per architecture.
#[test]
fn tk_assets_package_round_trip_restores_the_game_folder() {
    let env = Env::new(game_sys());
    let sys = &env.sys;
    let t = game_topo(DIRECT);
    let x86 = zip(&[ZipEntry::file("dinput8.dll", b"loader x86")]);
    let x64 = zip(&[ZipEntry::file("dinput8.dll", b"loader x64")]);
    let mut a86 = file("dinput8.dll", "dinput8.dll", b"loader x86");
    a86.arch = Some(vec![Arch::X86]);
    let mut a64 = file("dinput8.dll", "dinput8.dll", b"loader x64");
    a64.arch = Some(vec![Arch::X64]);
    let mut pkg = assets_package(&x86, &x64, vec![a86, a64]);
    pkg.id = crate::catalog::model::Id::parse("invented-wrapper").unwrap();
    let before = snap_at(sys, STEAM_GAME);
    cache(sys, &x86);
    cache(sys, &x64);
    extract(sys, &app(sys), &pkg).unwrap();
    let tp = plan_pkgs(sys, &t, std::slice::from_ref(&pkg), &["wrapper/pkg"]).unwrap();
    assert_eq!(
        installs(&tp),
        [(
            "invented-wrapper".to_owned(),
            vec![r"x64\dinput8.dll".to_owned()]
        )]
    );
    let a = app(sys);
    let h = crate::plan::store(&a, &tp.plan.encode().unwrap()).unwrap();
    drop(a);
    let txn = env.applied(&h);
    assert_eq!(
        crate::exec::tests::read_abs(sys, &format!(r"{STEAM_GAME}\dinput8.dll")),
        b"loader x64"
    );
    let v = env.verify(&txn);
    assert!(v.iter().all(|(_, o)| *o == Observed::After), "{v:?}");
    let rep = env.revert(&txn).unwrap();
    assert_eq!(rep.closed, Some(Closing::Reverted));
    let after = snap_at(sys, STEAM_GAME);
    assert!(before == after, "not identical: {:#?}", before.diff(&after));
}

// ---------- TS shared files and slots (P4-8) ----------

/// A package `id` with one zip of `entries` (`from`, `to`, content), cached and extracted.
fn shared_pkg(sys: &FakeSystem, id: &str, entries: &[(&str, &str, &[u8])]) -> Package {
    let archive = zip(&entries
        .iter()
        .map(|(from, _, data)| ZipEntry::file(from, data))
        .collect::<Vec<_>>());
    let files = entries
        .iter()
        .map(|(from, to, data)| file(from, to, data))
        .collect();
    let mut p = package("zip", &archive, files);
    p.id = crate::catalog::model::Id::parse(id).unwrap();
    cache(sys, &archive);
    extract(sys, &app(sys), &p).unwrap();
    p
}

/// The loader and two plugins that need it (EaglePatch and a widescreen fix), and a second
/// loader of the same DLL name.
fn shared_pkgs(sys: &FakeSystem) -> Vec<Package> {
    let loader = shared_pkg(
        sys,
        "invented-loader",
        &[("dinput8.dll", "dinput8.dll", b"asi loader")],
    );
    let mut eagle = shared_pkg(
        sys,
        "invented-eagle",
        &[("Eagle.asi", r"scripts\Eagle.asi", b"eagle patch")],
    );
    eagle.requires = vec![loader.id.clone()];
    let mut wide = shared_pkg(
        sys,
        "invented-wide",
        &[("Wide.asi", r"scripts\Wide.asi", b"widescreen fix")],
    );
    wide.requires = vec![loader.id.clone()];
    let other = shared_pkg(
        sys,
        "invented-other-loader",
        &[("dinput8.dll", "dinput8.dll", b"another loader")],
    );
    vec![eagle, loader, other, wide]
}

/// The Topo with issues `eagle` and `wide`, each with the loader, and `other` (a second loader
/// next to the first in one variant).
fn shared_topo() -> Topo {
    let mut v = topo_value();
    v["issues"].as_array_mut().unwrap().extend([
        serde_json::json!({"id":"eagle","title":"Eagle","variants":[{"id":"patch","status":"unverified","kind":"fix",
            "steps":[{"package":"invented-loader"},{"package":"invented-eagle"}]}]}),
        serde_json::json!({"id":"wide","title":"Wide","variants":[{"id":"fix","status":"unverified","kind":"enhancement",
            "steps":[{"package":"invented-loader"},{"package":"invented-wide"}]}]}),
        serde_json::json!({"id":"two","title":"Two loaders","variants":[{"id":"both","status":"unverified","kind":"fix",
            "steps":[{"package":"invented-loader"},{"package":"invented-other-loader"}]}]}),
        serde_json::json!({"id":"other","title":"Other loader","variants":[{"id":"alone","status":"unverified","kind":"fix",
            "steps":[{"package":"invented-other-loader"}]}]}),
    ]);
    topo_of(v)
}

fn store_plan(env: &Env, tp: &super::TopoPlan) -> crate::plan::PlanHash {
    let a = app(&env.sys);
    crate::plan::store(&a, &tp.plan.encode().unwrap()).unwrap()
}

/// TS1 (the acceptance of P4-8 and P4-8b, user decision E6): EaglePatch and a widescreen fix
/// share the ASI loader (and the `scripts` folder), planned in two plans. The second holds the
/// loader (`Hold`, nothing written). Reverted oldest first, the first removes its own plugin and
/// keeps the loader and the folder for the second; the second's revert removes them; reverted
/// newest first as before. Either order leaves the game folder identical to before both.
#[test]
fn ts1_two_fixes_share_the_loader_in_either_order() {
    use crate::exec::{Detail, Inherited, InheritedOutcome};
    for oldest_first in [true, false] {
        let env = Env::new(game_sys());
        let sys = &env.sys;
        let t = shared_topo();
        let pkgs = shared_pkgs(sys);
        let before = snap_at(sys, STEAM_GAME);
        let a = plan_pkgs(sys, &t, &pkgs, &["eagle/patch"]).unwrap();
        let a = env.applied(&store_plan(&env, &a));
        let b = plan_pkgs(sys, &t, &pkgs, &["wide/fix"]).unwrap();
        let held: Vec<&str> = b
            .plan
            .ops
            .iter()
            .filter_map(|o| match o {
                crate::plan::Op::Hold { path, .. } => Some(path.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(held, ["dinput8.dll"]);
        let shown = crate::plan::preview(&b.plan).to_string();
        assert!(
            shown.contains("keep shared file 0:dinput8.dll from invented-loader 1.0: dinput8.dll"),
            "{shown}"
        );
        assert!(
            shown.contains("(not written)") && shown.contains("note: shared files:"),
            "{shown}"
        );
        let b = env.applied(&store_plan(&env, &b));
        let read = |rel: &str| crate::exec::tests::exists_abs(sys, &format!(r"{STEAM_GAME}\{rel}"));
        if oldest_first {
            let rep = env.revert(&a).unwrap();
            assert_eq!(rep.closed, Some(Closing::Reverted));
            let kept: Vec<u16> = rep
                .ops
                .iter()
                .filter(|o| o.observed == Observed::Kept)
                .map(|o| o.op)
                .collect();
            assert_eq!(kept.len(), 2, "the loader and the folder: {rep:?}");
            assert!(
                rep.ops.iter().all(|o| o.observed != Observed::Kept
                    || o.detail == Some(Detail::Kept { by: vec![b] }))
            );
            assert!(read("dinput8.dll") && read(r"scripts\Wide.asi"));
            assert!(!read(r"scripts\Eagle.asi"));
            // What the second revert will do, before it does it (rule 5).
            let v = env.verified(&b).unwrap();
            let inherited: Vec<&Inherited> = v
                .details
                .values()
                .filter_map(|d| match d {
                    Detail::Inherited(x) => Some(x),
                    _ => None,
                })
                .flatten()
                .collect();
            assert_eq!(inherited.len(), 2, "{v:?}");
            assert!(
                inherited
                    .iter()
                    .all(|i| i.from == a && i.outcome == InheritedOutcome::Removed)
            );
            let rep = env.revert(&b).unwrap();
            assert_eq!(rep.closed, Some(Closing::Reverted));
            let removed = rep
                .ops
                .iter()
                .filter_map(|o| match &o.detail {
                    Some(Detail::Inherited(x)) => Some(x.len()),
                    _ => None,
                })
                .sum::<usize>();
            assert_eq!(removed, 2, "{rep:?}");
        } else {
            assert_eq!(env.revert(&b).unwrap().closed, Some(Closing::Reverted));
            assert!(read("dinput8.dll"));
            assert_eq!(env.revert(&a).unwrap().closed, Some(Closing::Reverted));
        }
        let after = snap_at(sys, STEAM_GAME);
        assert!(before == after, "not identical: {:#?}", before.diff(&after));
    }
}

/// TS2: two packages with the same DLL slot: in one plan the engine refuses (no chainloading);
/// against an open transaction the planner refuses with the transaction and its package.
#[test]
fn ts2_two_packages_of_one_slot_are_refused() {
    let env = Env::new(game_sys());
    let sys = &env.sys;
    let t = shared_topo();
    let pkgs = shared_pkgs(sys);
    match plan_pkgs(sys, &t, &pkgs, &["two/both"]) {
        Err(EngineError::Package { id, why }) => {
            assert_eq!(id, "invented-other-loader");
            assert!(
                why.contains("dinput8.dll is the slot of package invented-loader"),
                "{why}"
            );
            assert!(why.contains("does not chainload"), "{why}");
        }
        r => panic!("{r:?}"),
    }
    let a = env.applied(&store_plan(
        &env,
        &plan_pkgs(sys, &t, &pkgs, &["eagle/patch"]).unwrap(),
    ));
    match plan_pkgs(sys, &t, &pkgs, &["other/alone"]) {
        Err(EngineError::Plan(e)) => {
            let e = e.to_string();
            assert!(
                e.contains(&format!(
                    "dinput8.dll is the DLL slot of package invented-loader from transaction {a}"
                )),
                "{e}"
            );
        }
        r => panic!("{r:?}"),
    }
}

/// TS3: `supports_exe_sha1` (the matched build's SHA-1 listed, or refused) and `requires_gpu`
/// (not checked: a warning).
#[test]
fn ts3_supported_builds_and_gpu_requirements() {
    let sys = game_sys();
    let t = shared_topo();
    let mut pkgs = shared_pkgs(&sys);
    let sha1_of = |b: &[u8]| crate::catalog::model::Sha1::parse(&sha1(b)).unwrap();
    pkgs[0].supports_exe_sha1 = vec![sha1_of(b"another build")];
    match plan_pkgs(&sys, &t, &pkgs, &["eagle/patch"]) {
        Err(EngineError::Package { id, why }) => {
            assert_eq!(id, "invented-eagle");
            assert!(why.contains("supports_exe_sha1"), "{why}");
        }
        r => panic!("{r:?}"),
    }
    pkgs[0].supports_exe_sha1 = vec![sha1_of(b"another build"), sha1_of(&pe(false))];
    let tp = plan_pkgs(&sys, &t, &pkgs, &["eagle/patch"]).unwrap();
    assert!(tp.warnings.is_empty(), "{:?}", tp.warnings);
    pkgs[3].requires_gpu = vec![crate::catalog::model::GpuRequirement::Vulkan];
    let tp = plan_pkgs(&sys, &t, &pkgs, &["wide/fix"]).unwrap();
    assert_eq!(
        tp.warnings,
        [Warning::RequiresGpu {
            package: "invented-wide".into(),
            needs: crate::catalog::model::GpuRequirement::Vulkan,
        }]
    );
}

// ---------- TG the matched build (P5-2a) ----------

/// TG1 (P5-2a, finding 12 of plan P5): a game updated between the plan and the apply (another
/// `game.exe`, as a Steam update leaves it) is refused by `check` and by the apply under the
/// lock, with the executable named; nothing is written, no transaction. The original build
/// back, the same stored plan applies.
#[test]
fn tg1_a_game_updated_since_the_plan_is_refused() {
    let env = Env::new(game_sys());
    let sys = &env.sys;
    let t = game_topo(DIRECT);
    let tp = plan_on(sys, &t, &["settings/ini", "display/layer"]).unwrap();
    assert_eq!(
        tp.plan.roots[0].main_sha256,
        Some(Sha256::digest(pe(false)).into())
    );
    let a = app(sys);
    let h = crate::plan::store(&a, &tp.plan.encode().unwrap()).unwrap();
    drop(a);
    // The update: the same size class, another content.
    let mut updated = pe(false);
    updated.extend_from_slice(b"patch 1.01");
    put(sys, "game.exe", &updated);
    let before = snap_at(sys, STEAM_GAME);
    let changed = |r: crate::exec::Refusal| match r {
        crate::exec::Refusal::GameChanged(exe) => {
            assert!(exe.as_str().ends_with(r"G\game.exe"), "{}", exe.as_str());
            let text = crate::exec::Refusal::GameChanged(exe).to_string();
            assert!(
                text.starts_with("the main executable ")
                    && text.ends_with(
                        "G\\game.exe changed since the plan (a game update, or another fix \
                         changed it); plan again"
                    ),
                "{text}"
            );
        }
        other => panic!("expected GameChanged, got {other:?}"),
    };
    changed(env.check(&h).unwrap_err());
    match env.apply(&h) {
        Err(crate::exec::ApplyError::Refused(r)) => changed(r),
        other => panic!("expected a refusal, got {other:?}"),
    }
    assert!(env.states().is_empty(), "no transaction");
    let after = snap_at(sys, STEAM_GAME);
    assert!(
        before == after,
        "nothing written: {:#?}",
        before.diff(&after)
    );
    // The build the plan was made for: the same plan applies.
    put(sys, "game.exe", &pe(false));
    assert!(env.check(&h).is_ok());
    let txn = env.applied(&h);
    assert_eq!(env.state(&txn), Some(crate::journal::TxnState::Applied));
}

/// TG2 (P5-2a): the hash of the main executable in the plan's form: only on a game root with a
/// main executable (both rule sets); a plan with a `source` needs it on every game root to be
/// encoded or applied (an earlier version's stored plan is refused, never applied unchecked),
/// while a recorded head without it still decodes for its revert.
#[test]
fn tg2_the_hash_in_the_plan_form() {
    let sys = game_sys();
    let p = plan_on(&sys, &game_topo(DIRECT), &["cores/limit"])
        .unwrap()
        .plan;
    assert_eq!(p.roots[1].kind, crate::plan::RootKind::Profiles);
    let bytes = |p: &crate::plan::Plan| serde_json::to_vec(p).unwrap();
    let why = |r: Result<crate::plan::Plan, crate::plan::PlanError>| match r {
        Err(crate::plan::PlanError::Invalid { why, .. }) => why,
        other => panic!("expected Invalid, got {other:?}"),
    };
    // Without it (a plan stored by an earlier version).
    let mut old = p.clone();
    old.roots[0].main_sha256 = None;
    let w = why(crate::plan::decode(&bytes(&old)));
    assert!(
        w.contains("without the hash of the game's main executable"),
        "{w}"
    );
    assert!(w.ends_with("plan again"), "{w}");
    assert!(old.encode().is_err());
    assert_eq!(crate::plan::decode_recorded(&bytes(&old)).unwrap(), old);
    // On the profiles root, or a game root without a main executable: refused by both.
    let mut on_profiles = p.clone();
    on_profiles.roots[1].main_sha256 = Some([7; 32]);
    let mut no_main = p.clone();
    no_main.roots[0].main_exe = None;
    for bad in [on_profiles, no_main] {
        let b = bytes(&bad);
        assert!(why(crate::plan::decode(&b)).contains("root without one"));
        assert!(why(crate::plan::decode_recorded(&b)).contains("root without one"));
    }
    // `null` is not the absent field (one form).
    let s = String::from_utf8(bytes(&old)).unwrap().replace(
        r#""main_exe":"game.exe""#,
        r#""main_exe":"game.exe","main_sha256":null"#,
    );
    assert!(crate::plan::decode_recorded(s.as_bytes()).is_err());
}

// ---------- TX: every matched executable (ADR 0020 amendment "Other executables") ----------

/// The game of [`game_sys`] with a second build, `alt.exe` (x64, another content), and a Topo
/// that matches both: `game.exe` first (d3d9), `alt.exe` second (`alt_api`).
fn two_exes(alt_api: &str) -> (FakeSystem, Topo) {
    let sys = game_sys();
    let mut alt = pe(false);
    alt.extend_from_slice(b"the other build");
    put(&sys, "alt.exe", &alt);
    let mut v = topo_value();
    v["match"]["exes"] = serde_json::json!([
        {"path":"game.exe","sha256":sha256(&pe(false)),"api":"d3d9"},
        {"path":"alt.exe","sha256":sha256(&alt),"api":alt_api}
    ]);
    (sys, topo_of(v))
}

/// TX1: the plan records the other matched executable, and D4 asks it: `alt.exe` running (not
/// the first match) refuses the apply and the revert with the executable named, nothing written;
/// closed, both pass and the revert is exact. A game with one executable records `[]`.
#[test]
fn tx1_a_running_second_executable_refuses_apply_and_revert() {
    let (sys, t) = two_exes("d3d9");
    let env = Env::new(sys);
    let sys = &env.sys;
    let tp = plan_on(sys, &t, &["display/layer"]).unwrap();
    assert_eq!(
        tp.plan.roots[0].other_exes,
        Some(vec![RelPath::parse("alt.exe").unwrap()])
    );
    let a = app(sys);
    let h = crate::plan::store(&a, &tp.plan.encode().unwrap()).unwrap();
    drop(a);
    let before = snap_at(sys, STEAM_GAME);
    let alt = format!(r"{STEAM_GAME}\alt.exe");
    let busy = |r: &crate::exec::Refusal| {
        matches!(r, crate::exec::Refusal::Busy(s) if s.as_str().ends_with(r"G\alt.exe"))
            && r.to_string()
                .ends_with("is in use; close the game and try again later")
    };
    let held = sys.fake_fs().map_image_as(4244, Path::new(&alt)).unwrap();
    match env.apply(&h) {
        Err(crate::exec::ApplyError::Refused(r)) => assert!(busy(&r), "{r:?}"),
        other => panic!("expected Busy, got {other:?}"),
    }
    assert!(env.states().is_empty(), "no transaction");
    assert!(before == snap_at(sys, STEAM_GAME), "nothing written");
    drop(held);
    let txn = env.applied(&h);
    let held = sys.fake_fs().map_image_as(4245, Path::new(&alt)).unwrap();
    match env.revert(&txn) {
        Err(crate::exec::ExecError::Refused(r)) => assert!(busy(&r), "{r:?}"),
        other => panic!("expected Busy, got {other:?}"),
    }
    assert_eq!(env.state(&txn), Some(crate::journal::TxnState::Applied));
    drop(held);
    assert_eq!(env.revert(&txn).unwrap().closed, Some(Closing::Reverted));
    assert!(before == snap_at(sys, STEAM_GAME), "exact revert");
    // One executable: an empty list, nothing else changes.
    let one = plan_on(&game_sys(), &game_topo(DIRECT), &["display/layer"]).unwrap();
    assert_eq!(one.plan.roots[0].other_exes, Some(Vec::new()));
}

/// TX2: the list in the plan's form: a Topo plan without it (an earlier version's) is refused by
/// `encode` and the current decode ("…plan again"), a recorded head without it decodes (its
/// revert asks the main executable only); on a root without a main executable, with the main
/// executable again or an entry twice it is refused by both; `null` is not the absent field.
#[test]
fn tx2_the_other_executables_in_the_plan_form() {
    let (sys, t) = two_exes("d3d9");
    let p = plan_on(&sys, &t, &["cores/limit"]).unwrap().plan;
    let bytes = |p: &crate::plan::Plan| serde_json::to_vec(p).unwrap();
    let why = |r: Result<crate::plan::Plan, crate::plan::PlanError>| match r {
        Err(crate::plan::PlanError::Invalid { why, .. }) => why,
        other => panic!("expected Invalid, got {other:?}"),
    };
    let mut old = p.clone();
    old.roots[0].other_exes = None;
    let w = why(crate::plan::decode(&bytes(&old)));
    assert!(w.contains("without the other executables"), "{w}");
    assert!(w.ends_with("plan again"), "{w}");
    assert!(old.encode().is_err());
    assert_eq!(crate::plan::decode_recorded(&bytes(&old)).unwrap(), old);
    let r = |s: &str| RelPath::parse(s).unwrap();
    let mut on_profiles = p.clone();
    on_profiles.roots[1].other_exes = Some(vec![r("alt.exe")]);
    let mut main_again = p.clone();
    main_again.roots[0].other_exes = Some(vec![r("alt.exe"), r("GAME.exe")]);
    let mut twice = p.clone();
    twice.roots[0].other_exes = Some(vec![r("alt.exe"), r("ALT.EXE")]);
    for (bad, want) in [
        (on_profiles, "without a main executable"),
        (main_again, "listed twice"),
        (twice, "listed twice"),
    ] {
        let b = bytes(&bad);
        assert!(why(crate::plan::decode(&b)).contains(want), "{want}");
        assert!(
            why(crate::plan::decode_recorded(&b)).contains(want),
            "{want}"
        );
    }
    let s = String::from_utf8(bytes(&old)).unwrap().replace(
        r#""main_exe":"game.exe""#,
        r#""main_exe":"game.exe","other_exes":null"#,
    );
    assert!(crate::plan::decode_recorded(s.as_bytes()).is_err());
}

/// TX3: a package whose files depend on the graphics API is refused for a game whose matched
/// executables have different APIs (typed, with the reason), never planned for the first match;
/// one that does not depend on it still plans; the same APIs plan the API's files as before.
#[test]
fn tx3_an_api_dependent_package_waits_for_the_running_executable() {
    let archive = wrapper_zip();
    let pkg = wrapper(&archive);
    let (sys, t) = two_exes("d3d11");
    cache(&sys, &archive);
    extract(&sys, &app(&sys), &pkg).unwrap();
    let e = plan_pkgs(&sys, &t, std::slice::from_ref(&pkg), &["wrapper/pkg"]).unwrap_err();
    assert!(
        matches!(&e, EngineError::PackageApiOpen { id } if id == "invented-wrapper"),
        "{e:?}"
    );
    assert_eq!(
        e.to_string(),
        "package invented-wrapper: its DLLs depend on the graphics API, and this game's \
         executables use more than one; Rerun does not know yet which of them the game runs, so \
         it does not install the package"
    );
    // `apis` alone counts too.
    let mut by_list = pkg.clone();
    by_list.files.iter_mut().for_each(|f| f.api = None);
    by_list.files.truncate(1);
    by_list.apis = Some(vec![Api::D3d9, Api::D3d11]);
    let e = plan_pkgs(&sys, &t, std::slice::from_ref(&by_list), &["wrapper/pkg"]).unwrap_err();
    assert!(matches!(e, EngineError::PackageApiOpen { .. }), "{e:?}");
    // Not API-dependent: planned (the config file only).
    let mut plain = pkg.clone();
    plain.files.retain(|f| f.api.is_none());
    let tp = plan_pkgs(&sys, &t, std::slice::from_ref(&plain), &["wrapper/pkg"]).unwrap();
    assert_eq!(
        installs(&tp),
        [(
            "invented-wrapper".to_owned(),
            vec!["wrapper.ini".to_owned()]
        )]
    );
    // Two executables of one API: planned for it, as for one executable.
    let (sys, t) = two_exes("d3d9");
    cache(&sys, &archive);
    extract(&sys, &app(&sys), &pkg).unwrap();
    let tp = plan_pkgs(&sys, &t, std::slice::from_ref(&pkg), &["wrapper/pkg"]).unwrap();
    assert_eq!(
        installs(&tp),
        [(
            "invented-wrapper".to_owned(),
            vec![r"x64\d3d9.dll".to_owned(), "wrapper.ini".to_owned()]
        )]
    );
}

/// TX4 (P5-5c review): the architecture as the API: a package with DLLs is refused for a game
/// whose matched executables have different architectures (typed, with the reason), never
/// planned for the first match; a package of config files only still plans.
#[test]
fn tx4_a_package_with_dlls_waits_when_the_executables_differ_in_arch() {
    let archive = wrapper_zip();
    let mut pkg = wrapper(&archive);
    pkg.files.iter_mut().for_each(|f| f.api = None);
    pkg.files
        .retain(|f| f.config || f.from.as_str() != "x64/d3d11.dll");
    let sys = game_sys();
    let mut alt = pe(true);
    alt.extend_from_slice(b"the 32-bit build");
    put(&sys, "alt.exe", &alt);
    let mut v = topo_value();
    v["match"]["exes"] = serde_json::json!([
        {"path":"game.exe","sha256":sha256(&pe(false)),"api":"d3d9"},
        {"path":"alt.exe","sha256":sha256(&alt),"api":"d3d9"}
    ]);
    let t = topo_of(v);
    assert!(facts_of(&sys, &t).arches_differ());
    cache(&sys, &archive);
    extract(&sys, &app(&sys), &pkg).unwrap();
    let e = plan_pkgs(&sys, &t, std::slice::from_ref(&pkg), &["wrapper/pkg"]).unwrap_err();
    assert!(
        matches!(&e, EngineError::PackageArchOpen { id } if id == "invented-wrapper"),
        "{e:?}"
    );
    assert!(e.to_string().contains("built for one architecture"), "{e}");
    // Config files only: planned.
    let mut plain = pkg.clone();
    plain.files.retain(|f| f.config);
    let tp = plan_pkgs(&sys, &t, std::slice::from_ref(&plain), &["wrapper/pkg"]).unwrap();
    assert_eq!(
        installs(&tp),
        [(
            "invented-wrapper".to_owned(),
            vec!["wrapper.ini".to_owned()]
        )]
    );
    // One architecture (TX3's world): planned as before.
    let (sys, t) = two_exes("d3d9");
    assert!(!facts_of(&sys, &t).arches_differ());
}
