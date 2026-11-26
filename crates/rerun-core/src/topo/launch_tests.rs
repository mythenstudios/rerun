//! Option values with `start` and `launch_args` in the one launch profile (ADR 0032 amendment
//! P5-OE, slice O-2b), against the fake: the composition of the profile's parts, the carry-over
//! of the live profile (S6), the effective main executable, the switch rule (E4 b) and the
//! stacking rule B1. Every Topo, folder, hash and ID is invented.
//!
//! Scope of every snapshot: the game folder `G`, Rerun's `profiles` and `HKCU\Software`.
//! - LO1 a `start` value alone: a profile with `run` (method `direct`, `target = run`), the
//!   plan's main executable the chosen one; round trip identical. `launch_args` with `start`.
//! - LO2 the stack T1 CPU fix → T2 DX9 (keeps the rule) → T3 package for DX9: revert T1 first
//!   `Later { T2 }` (object), revert T2 `Later { T3 }` (B1), then T3, T2 (the profile of T1 bit
//!   for bit), T1: identical to before.
//! - LO3 B1 with a package: T1 DX9 → T2 package → revert T1 `Later { T2 }`, nothing changed;
//!   revert T2, T1: identical. Control K-B1: the rule off, the revert of T1 goes through.
//! - LO4 B1 with compatibility flags on the executable `run` made the main one.
//! - LO5 a transaction that keeps `run` (a CPU fix over DX9) does not set it: its revert is not
//!   held by B1; the one that set it is.
//! - LO6 E4 b: a live package for another executable refuses the switch, naming the
//!   transaction; the same executable plans.
//! - LO7 the source (S6): the newest holder forgotten (nothing kept, the file replaced and
//!   restored by the revert), an older live holder below a forgotten one is never the source,
//!   the file not the head's (refused, also a plan without a profile part).
//! - LO8 anti-cheat: a kept `run` or `args` is refused (S1).
//! - LO9 conflicts: two `start` values; a kept `watch` with a new `run`; a new `watch` rule with
//!   a kept `run`; a kept `run` whose executable no longer matches; no part set, no profile op
//!   (the plan for the executable of the kept `run`).
//! - LO10 the window between plan and apply: the live profile reverted meanwhile, the apply
//!   refused, nothing written.

use std::path::Path;

use sha2::{Digest, Sha256};

use super::tests::{wrapper, wrapper_zip};
use super::{
    EngineError, EngineSelection, Facts, PartFrom, StepKind, TopoPlan, ValueRefusal, Warning, plan,
    read_game,
};
use crate::catalog::check::{self, Rules};
use crate::catalog::model::{Package, Topo};
use crate::detect::pe::testfx::Builder as PeBuilder;
use crate::exec::rebind_tests::rb_sys;
use crate::exec::tests::Env;
use crate::exec::{ExecError, Refusal};
use crate::hw::{self, GpuArchTable};
use crate::journal::{Closing, Observed, TxnId};
use crate::pkg::extract::extract;
use crate::pkg::extract_tests::cache;
use crate::plan::{
    Choice, ContentRef, Op, Pick, PlanHash, RootKind, profile_file, profile_id, store,
};
use crate::policy::registry::RegPolicy;
use crate::policy::root::{GameDir, StoreDir};
use crate::prim::reg_tests::hkcu;
use crate::prim::tests::{STEAM_GAME, STEAM_LIB, app, fr, rel};
use crate::prim::{CpuRuleSpec, LaunchMethodSpec, MethodSpec, PlanCtx, Step};
use crate::sys::System;
use crate::sys::fake::FakeSystem;
use crate::sys::snapshot::{Scope, SnapRoot, Snapshot, snapshot};
use rerun_proto::profile::{self as proto, LaunchProfile, Method};

pub(super) const APP: u32 = 220;
pub(super) const INDEX: [u8; 32] = [6; 32];

fn hex(b: &[u8]) -> String {
    Sha256::digest(b)
        .iter()
        .map(|x| format!("{x:02X}"))
        .collect()
}

pub(super) fn put(sys: &FakeSystem, rel: &str, data: &[u8]) {
    let abs = format!(r"{STEAM_GAME}\{rel}");
    let _ = sys.fake_fs().remove_abs(Path::new(&abs));
    sys.fake_fs().put_file(Path::new(&abs), data).unwrap();
    sys.sync_all();
}

pub(super) fn x86() -> Vec<u8> {
    PeBuilder::x86().build().bytes
}

/// Steam app 220 in `G` ([`rb_sys`]: a read-only, hidden `d3d9.dll`, `cfg\Game.ini`): x86
/// `game.exe` and `game_dx9.exe` (one build, one architecture and API, so a package is not held
/// by the bundle rule), the launcher `FFLauncher.exe`, and Rerun's `profiles` folder.
pub(super) fn game_sys() -> FakeSystem {
    let sys = rb_sys();
    put(&sys, "game.exe", &x86());
    put(&sys, "game_dx9.exe", &x86());
    put(&sys, "FFLauncher.exe", &x86());
    let profiles = app(&sys).path().child("profiles").unwrap().to_string();
    sys.fake_fs().mkdir_all(Path::new(&profiles)).unwrap();
    sys.sync_all();
    sys
}

/// Options `api` (`dx9`: `start` of `game_dx9.exe`) and `intro` (`skip`: `start` of
/// `game_dx9.exe` and `-skipintro`); issues `cores` (a CPU rule), `wrapper` (a package),
/// `display` (`compat_layer` on `game_dx9.exe`), `settings` (`ini_set`). Steam starts the
/// launcher (`auto` resolves to `direct`).
pub(super) fn topo() -> Topo {
    let sha = hex(&x86());
    let j = format!(
        r#"{{"format":1,"id":"invented-game","title":"Invented Game","status":"draft","rev":3,
"match":{{"steam_appid":{APP},"exes":[
  {{"path":"game.exe","sha256":"{sha}","api":"d3d9"}},
  {{"path":"game_dx9.exe","sha256":"{sha}","api":"d3d9"}}]}},
"launch":{{"chain":["steam"],"method":"auto","start":"FFLauncher.exe"}},
"options":[
 {{"id":"api","title":"Graphics API","sources":[{{"type":"pcgw","url":"https://www.pcgamingwiki.com/wiki/Invented#API"}}],"values":[
   {{"id":"dx9","title":"DirectX 9","status":"unverified","steps":[{{"start":"game_dx9.exe"}}]}}]}},
 {{"id":"intro","title":"Intro","sources":[{{"type":"pcgw","url":"https://www.pcgamingwiki.com/wiki/Invented#Intro"}}],"values":[
   {{"id":"skip","title":"Skip","status":"unverified","steps":[{{"start":"game_dx9.exe"}},{{"launch_args":["-skipintro"]}}]}}]}}
],
"issues":[
 {{"id":"cores","title":"Too many cores","variants":[
   {{"id":"limit","status":"verified","kind":"fix","steps":[{{"cpu":{{"max_threads":8,"smt":false}}}}]}}]}},
 {{"id":"wrapper","title":"Wrapper","variants":[
   {{"id":"pkg","status":"unverified","kind":"fix","steps":[{{"package":"invented-wrapper"}}]}}]}},
 {{"id":"display","title":"Display","variants":[
   {{"id":"layer","status":"unverified","kind":"fix","steps":[{{"compat_layer":{{"exe":"game_dx9.exe","layers":["ZZ_FLAG_A"]}}}}]}}]}},
 {{"id":"settings","title":"Settings","variants":[
   {{"id":"ini","status":"reported","kind":"fix","steps":[{{"ini_set":{{"file":"cfg\\Game.ini","values":[{{"section":"Display","key":"Height","value":"1080"}}]}}}}]}}]}}
]}}"#
    );
    let t: Topo = serde_json::from_str(&j).unwrap_or_else(|e| panic!("{e}: {j}"));
    check::topo(&t, Rules::Source).unwrap_or_else(|e| panic!("{e}"));
    t
}

fn sel<T>(s: &[&str], sep: char, f: fn(String, String) -> T) -> Vec<T> {
    s.iter()
        .map(|x| {
            let (a, b) = x.split_once(sep).unwrap();
            f(a.to_owned(), b.to_owned())
        })
        .collect()
}

pub(super) fn choices(c: &[&str]) -> Vec<Choice> {
    sel(c, '=', |option, value| Choice { option, value })
}

pub(super) fn picks(p: &[&str]) -> Vec<Pick> {
    sel(p, '/', |issue, variant| Pick { issue, variant })
}

/// Plans picks `p` and choices `c` of `t` on `sys` with the packages `pkgs`; the journal of
/// Rerun's folder is read as the flow reads it.
pub(super) fn plan_with(
    sys: &FakeSystem,
    t: &Topo,
    pkgs: &[Package],
    p: &[&str],
    c: &[&str],
) -> Result<TopoPlan, EngineError> {
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
    let prof = hw::read(
        &FakeSystem::builder().build().unwrap(),
        Some(GpuArchTable::builtin().unwrap()),
    );
    let facts = Facts {
        profile: &prof,
        table: Some(GpuArchTable::builtin().unwrap()),
        game: &gf,
        packages: pkgs,
    };
    let (p, c) = (picks(p), choices(c));
    let live = crate::exec::live_state(&a, Some(APP), g.id()).map_err(EngineError::Live)?;
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
        &live,
    )
}

fn plan_on(sys: &FakeSystem, t: &Topo, p: &[&str], c: &[&str]) -> Result<TopoPlan, EngineError> {
    plan_with(sys, t, &[], p, c)
}

/// The wrapper package, cached and unpacked in Rerun's folder.
pub(super) fn pkgs(sys: &FakeSystem) -> Vec<Package> {
    let archive = wrapper_zip();
    let pkg = wrapper(&archive);
    cache(sys, &archive);
    extract(sys, &app(sys), &pkg).unwrap();
    vec![pkg]
}

pub(super) fn stored(sys: &FakeSystem, tp: &TopoPlan) -> PlanHash {
    store(&app(sys), &tp.plan.encode().unwrap()).unwrap()
}

/// Plans, stores and applies.
pub(super) fn apply(env: &Env, t: &Topo, pkgs: &[Package], p: &[&str], c: &[&str]) -> TxnId {
    let tp = plan_with(&env.sys, t, pkgs, p, c).unwrap_or_else(|e| panic!("{p:?} {c:?}: {e}"));
    let txn = env.applied(&stored(&env.sys, &tp));
    let v = env.verify(&txn);
    assert!(v.iter().all(|(_, o)| *o == Observed::After), "{v:?}");
    txn
}

pub(super) fn snap(sys: &FakeSystem) -> Snapshot {
    let fr = fr(sys);
    let g = GameDir::open_manual(sys, &fr, Path::new(STEAM_GAME)).unwrap();
    let a = app(sys);
    snapshot(
        sys.registry(),
        &Scope {
            dirs: vec![
                SnapRoot::new(a.dir(), a.path().to_string()).below(rel("profiles")),
                SnapRoot::new(g.dir(), STEAM_GAME),
            ],
            keys: vec![hkcu("Software")],
        },
    )
    .unwrap()
}

pub(super) fn same(a: &Snapshot, b: &Snapshot) {
    assert!(a == b, "not identical: {:#?}", a.diff(b));
}

/// The profile a plan writes, decoded.
pub(super) fn profile_of(tp: &TopoPlan) -> LaunchProfile {
    let bytes = tp
        .plan
        .ops
        .iter()
        .find_map(|o| match o.content() {
            Some(ContentRef::Inline { bytes, .. }) => Some(bytes.clone()),
            _ => None,
        })
        .unwrap_or_else(|| panic!("no profile op: {:?}", tp.plan.ops));
    proto::decode(&bytes).unwrap()
}

/// The profile file of app 220, absolute.
fn profile_abs(sys: &FakeSystem) -> String {
    let p = app(sys).path().child("profiles").unwrap();
    format!(r"{p}\{}", profile_file(profile_id(APP)))
}

pub(super) fn abs(r: &str) -> String {
    format!(r"{STEAM_GAME}\{r}")
}

pub(super) fn main_exe(tp: &TopoPlan) -> String {
    let r = tp
        .plan
        .roots
        .iter()
        .find(|r| r.kind == RootKind::Game)
        .unwrap();
    r.main_exe.as_ref().unwrap().to_string()
}

pub(super) fn later(r: Result<crate::exec::RevertReport, ExecError>, t: TxnId) {
    match r {
        Err(ExecError::Refused(Refusal::Later { txn })) if txn == t => {}
        other => panic!("not Later {{ {t} }}: {other:?}"),
    }
}

pub(super) fn reverted(env: &Env, t: &TxnId) {
    assert_eq!(env.revert(t).unwrap().closed, Some(Closing::Reverted));
}

// ---------- LO1 ----------

#[test]
fn lo1_a_start_value_writes_run_and_round_trips() {
    let env = Env::new(game_sys());
    let t = topo();
    let before = snap(&env.sys);
    let tp = plan_on(&env.sys, &t, &[], &["api=dx9"]).unwrap_or_else(|e| panic!("{e}"));
    let p = profile_of(&tp);
    assert_eq!(p.method, Method::Direct);
    assert_eq!(p.start, abs("FFLauncher.exe"));
    assert_eq!(p.run.as_deref(), Some(abs("game_dx9.exe").as_str()));
    assert_eq!(p.target, abs("game_dx9.exe"));
    assert!(p.cpu.is_none() && p.args.is_empty());
    // The chosen executable is the plan's main one; the other match is asked too (D4).
    assert_eq!(main_exe(&tp), "game_dx9.exe");
    let root = &tp.plan.roots[0];
    assert_eq!(root.other_exes, Some(vec![rel("game.exe")]));
    let parts = tp.parts.clone().unwrap();
    assert_eq!(parts.start, rel("FFLauncher.exe"));
    assert!(parts.rule.is_none() && parts.args.is_none());
    assert_eq!(
        parts.run,
        Some((
            rel("game_dx9.exe"),
            PartFrom::Option(choices(&["api=dx9"]).remove(0))
        ))
    );
    let src = tp.plan.source.clone().unwrap();
    assert!(src.picks.is_empty());
    assert_eq!(src.choices, choices(&["api=dx9"]));
    let txn = env.applied(&stored(&env.sys, &tp));
    assert!(env.verify(&txn).iter().all(|(_, o)| *o == Observed::After));
    reverted(&env, &txn);
    same(&before, &snap(&env.sys));
    // `start` with `launch_args`.
    let tp = plan_on(&env.sys, &t, &[], &["intro=skip"]).unwrap();
    let p = profile_of(&tp);
    assert_eq!(p.run.as_deref(), Some(abs("game_dx9.exe").as_str()));
    let args: Vec<&str> = p.args.iter().map(|a| a.as_str()).collect();
    assert_eq!(args, ["-skipintro"]);
}

// ---------- LO2 ----------

#[test]
fn lo2_a_stack_of_a_rule_an_option_and_a_package() {
    let env = Env::new(game_sys());
    let t = topo();
    let pk = pkgs(&env.sys);
    let before = snap(&env.sys);
    let tp1 = plan_with(&env.sys, &t, &pk, &["cores/limit"], &[]).unwrap();
    let p1 = profile_of(&tp1);
    let t1 = env.applied(&stored(&env.sys, &tp1));
    let after_t1 = snap(&env.sys);
    // T2 DX9: the rule of T1 is kept exactly (senior-dev S2), `run` is the option's.
    let tp = plan_with(&env.sys, &t, &pk, &[], &["api=dx9"]).unwrap();
    let p = profile_of(&tp);
    assert_eq!(p.cpu.and_then(|r| r.max_threads), Some(8));
    assert_eq!((p.cpu, p.priority), (p1.cpu, p1.priority));
    assert_eq!(p.run.as_deref(), Some(abs("game_dx9.exe").as_str()));
    let parts = tp.parts.clone().unwrap();
    assert_eq!(parts.rule, Some(PartFrom::Kept(t1)));
    assert!(
        matches!(tp.plan.ops[0], Op::ReplaceFile { .. }),
        "{:?}",
        tp.plan.ops
    );
    let t2 = env.applied(&stored(&env.sys, &tp));
    // T3: the package is planned for the executable the kept `run` starts.
    let tp = plan_with(&env.sys, &t, &pk, &["wrapper/pkg"], &[]).unwrap();
    assert_eq!(main_exe(&tp), "game_dx9.exe");
    assert!(tp.parts.is_none(), "no profile part: the profile stays");
    let t3 = env.applied(&stored(&env.sys, &tp));
    // Newest first: T1 is held by T2 (the profile), T2 by T3 (B1).
    later(env.revert(&t1), t2);
    later(env.revert(&t2), t3);
    reverted(&env, &t3);
    reverted(&env, &t2);
    same(&after_t1, &snap(&env.sys));
    reverted(&env, &t1);
    same(&before, &snap(&env.sys));
}

// ---------- LO3 ----------

#[test]
fn lo3_b1_holds_an_option_under_a_package_for_its_executable() {
    let env = Env::new(game_sys());
    let t = topo();
    let pk = pkgs(&env.sys);
    let before = snap(&env.sys);
    let t1 = apply(&env, &t, &pk, &[], &["api=dx9"]);
    let t2 = apply(&env, &t, &pk, &["wrapper/pkg"], &[]);
    let held = snap(&env.sys);
    later(env.revert(&t1), t2);
    same(&held, &snap(&env.sys));
    reverted(&env, &t2);
    reverted(&env, &t1);
    same(&before, &snap(&env.sys));
}

/// K-B1: without the rule the revert of T1 goes through under the package for DX9 (object
/// LIFO alone does not hold it): the control that LO3 needs B1.
#[test]
fn k_b1_without_the_rule_the_option_is_taken_from_under_the_package() {
    let env = Env::new(game_sys());
    let t = topo();
    let pk = pkgs(&env.sys);
    let t1 = apply(&env, &t, &pk, &[], &["api=dx9"]);
    let _t2 = apply(&env, &t, &pk, &["wrapper/pkg"], &[]);
    crate::exec::stack_knob::b1(true);
    let r = env.revert(&t1);
    crate::exec::stack_knob::b1(false);
    assert_eq!(r.unwrap().closed, Some(Closing::Reverted));
}

// ---------- LO4 ----------

#[test]
fn lo4_b1_holds_an_option_under_flags_for_its_executable() {
    let env = Env::new(game_sys());
    let t = topo();
    let before = snap(&env.sys);
    let t1 = apply(&env, &t, &[], &[], &["api=dx9"]);
    let tp = plan_on(&env.sys, &t, &["display/layer"], &[]).unwrap();
    assert!(
        tp.plan
            .ops
            .iter()
            .any(|o| matches!(o, Op::TokenList { .. }))
    );
    assert_eq!(main_exe(&tp), "game_dx9.exe");
    let t2 = env.applied(&stored(&env.sys, &tp));
    later(env.revert(&t1), t2);
    reverted(&env, &t2);
    reverted(&env, &t1);
    same(&before, &snap(&env.sys));
}

// ---------- LO5 ----------

#[test]
fn lo5_a_transaction_that_keeps_run_is_not_held_by_b1() {
    let env = Env::new(game_sys());
    let t = topo();
    let pk = pkgs(&env.sys);
    let before = snap(&env.sys);
    let t1 = apply(&env, &t, &pk, &[], &["api=dx9"]);
    let after_t1 = snap(&env.sys);
    // T2 a CPU fix: it keeps T1's `run`.
    let tp = plan_with(&env.sys, &t, &pk, &["cores/limit"], &[]).unwrap();
    let parts = tp.parts.clone().unwrap();
    assert_eq!(parts.run.map(|(_, f)| f), Some(PartFrom::Kept(t1)));
    assert_eq!(
        profile_of(&tp).run.as_deref(),
        Some(abs("game_dx9.exe").as_str())
    );
    let t2 = env.applied(&stored(&env.sys, &tp));
    let t3 = apply(&env, &t, &pk, &["wrapper/pkg"], &[]);
    // T2 back: the profile of T1 (with the same `run`) is back; the package stays valid.
    reverted(&env, &t2);
    later(env.revert(&t1), t3);
    reverted(&env, &t3);
    same(&after_t1, &snap(&env.sys));
    reverted(&env, &t1);
    same(&before, &snap(&env.sys));
}

// ---------- LO6 ----------

#[test]
fn lo6_no_switch_while_a_package_is_live_for_another_executable() {
    let env = Env::new(game_sys());
    let t = topo();
    let pk = pkgs(&env.sys);
    // T1 the package for the first match.
    let t1 = apply(&env, &t, &pk, &["wrapper/pkg"], &[]);
    let e = plan_with(&env.sys, &t, &pk, &[], &["api=dx9"]).unwrap_err();
    assert!(
        matches!(&e, EngineError::ExeSwitch { txn, from, to }
            if *txn == t1 && from == "game.exe" && to == "game_dx9.exe"),
        "{e:?}"
    );
    assert!(e.to_string().contains(&format!("undo {t1} first")), "{e}");
    // The same executable plans (a CPU rule for the launcher's game).
    assert!(plan_with(&env.sys, &t, &pk, &["cores/limit"], &[]).is_ok());
    reverted(&env, &t1);
    // Flags on another executable than the plan's hold the same way.
    let t2 = apply(&env, &t, &pk, &["display/layer"], &[]);
    assert!(matches!(
        plan_with(&env.sys, &t, &pk, &[], &["api=dx9"]),
        Err(EngineError::ExeSwitch { txn, .. }) if txn == t2
    ));
}

// ---------- LO7 ----------

#[test]
fn lo7_the_newest_holder_forgotten_keeps_nothing() {
    let env = Env::new(game_sys());
    let t = topo();
    let t1 = apply(&env, &t, &[], &[], &["api=dx9"]);
    let file = crate::exec::tests::read_abs(&env.sys, &profile_abs(&env.sys));
    env.forget(&t1).unwrap();
    let with_t1 = snap(&env.sys);
    let tp = plan_on(&env.sys, &t, &["cores/limit"], &[]).unwrap();
    let parts = tp.parts.clone().unwrap();
    assert!(
        parts.run.is_none(),
        "nothing kept from a forgotten transaction"
    );
    assert_eq!(
        parts.rule,
        Some(PartFrom::Fix(picks(&["cores/limit"]).remove(0)))
    );
    assert!(profile_of(&tp).run.is_none());
    // The file there is replaced, its old state its hash; the revert puts it back.
    match &tp.plan.ops[0] {
        Op::ReplaceFile { old, .. } => {
            assert_eq!(old.sha256, <[u8; 32]>::from(Sha256::digest(&file)));
        }
        other => panic!("{other:?}"),
    }
    let t2 = env.applied(&stored(&env.sys, &tp));
    reverted(&env, &t2);
    same(&with_t1, &snap(&env.sys));
}

#[test]
fn lo7_an_older_live_holder_below_a_forgotten_one_is_never_the_source() {
    let env = Env::new(game_sys());
    let t = topo();
    let _t1 = apply(&env, &t, &[], &["cores/limit"], &[]);
    let t2 = apply(&env, &t, &[], &[], &["api=dx9"]);
    env.forget(&t2).unwrap();
    let tp = plan_on(&env.sys, &t, &[], &["intro=skip"]).unwrap();
    let parts = tp.parts.clone().unwrap();
    assert!(parts.rule.is_none(), "T1's rule is not kept: {parts:?}");
    assert!(profile_of(&tp).cpu.is_none());
}

#[test]
fn lo7_a_profile_that_is_not_the_heads_refuses() {
    let env = Env::new(game_sys());
    let t = topo();
    let t1 = apply(&env, &t, &[], &[], &["api=dx9"]);
    let at = profile_abs(&env.sys);
    let mut bytes = crate::exec::tests::read_abs(&env.sys, &at);
    bytes.extend_from_slice(b"x=1\n");
    env.sys.fake_fs().put_file(Path::new(&at), &bytes).unwrap();
    env.sys.sync_all();
    for (p, c) in [
        (&["cores/limit"][..], &[][..]),
        (&["settings/ini"][..], &[][..]),
    ] {
        match plan_on(&env.sys, &t, p, c) {
            Err(EngineError::Live(crate::exec::LiveError::Changed { txn })) => {
                assert_eq!(txn, t1);
            }
            other => panic!("{p:?}: {other:?}"),
        }
    }
    let e = plan_on(&env.sys, &t, &["cores/limit"], &[]).unwrap_err();
    assert!(
        e.to_string()
            .contains(&format!("undo or forget {t1} first")),
        "{e}"
    );
    // Removed: the same.
    env.sys.fake_fs().remove_abs(Path::new(&at)).unwrap();
    env.sys.sync_all();
    assert!(matches!(
        plan_on(&env.sys, &t, &["cores/limit"], &[]),
        Err(EngineError::Live(crate::exec::LiveError::Changed { .. }))
    ));
}

// ---------- LO8 ----------

#[test]
fn lo8_anti_cheat_refuses_a_kept_run_and_args() {
    let env = Env::new(game_sys());
    let t = topo();
    let t1 = apply(&env, &t, &[], &[], &["intro=skip"]);
    env.sys
        .fake_fs()
        .mkdir_all(Path::new(&format!(r"{STEAM_GAME}\pb")))
        .unwrap();
    env.sys.sync_all();
    match plan_on(&env.sys, &t, &["cores/limit"], &[]) {
        Err(EngineError::KeptAntiCheat { txn, step }) => {
            assert_eq!((txn, step), (t1, StepKind::Start));
        }
        other => panic!("{other:?}"),
    }
    // F4: a plan without a profile part is still for the kept `run`'s executable: warned.
    let tp = plan_on(&env.sys, &t, &["settings/ini"], &[]).unwrap();
    assert!(tp.parts.is_none());
    assert!(
        tp.warnings.contains(&Warning::KeptAntiCheat {
            txn: t1,
            step: StepKind::Start
        }),
        "{:?}",
        tp.warnings
    );
    // A new value is refused by its own step, as before.
    assert!(matches!(
        plan_on(&env.sys, &t, &[], &["api=dx9"]),
        Err(EngineError::OptionRefused {
            why: ValueRefusal::AntiCheat(StepKind::Start),
            ..
        })
    ));
}

// ---------- LO9 ----------

#[test]
fn lo9_conflicts_of_the_parts() {
    let env = Env::new(game_sys());
    let t = topo();
    // Two values that start an executable.
    assert!(matches!(
        plan_on(&env.sys, &t, &[], &["api=dx9", "intro=skip"]),
        Err(EngineError::TwoStarts { first, second }) if first == "api=dx9" && second == "intro=skip"
    ));
    // A live `watch` profile (a step file) and a new `run`.
    let h = {
        let fr = fr(&env.sys);
        let store_dir = StoreDir::open(&env.sys, &fr, Path::new(STEAM_LIB)).unwrap();
        let g = store_dir.game(&fr, "G").unwrap();
        let a = app(&env.sys);
        let main = rel("game.exe");
        let watch = crate::prim::plan(
            &[Step::LaunchMethod(LaunchMethodSpec {
                method: MethodSpec::Watch,
                start: rel("FFLauncher.exe"),
                cpu: Some(CpuRuleSpec {
                    max_threads: Some(4),
                    ..CpuRuleSpec::default()
                }),
                priority: None,
                run: None,
                args: Vec::new(),
            })],
            &PlanCtx {
                game: &g,
                app: Some(&a),
                steam_app: Some(APP),
                main_exe: Some(&main),
                reg: RegPolicy.reader(&env.sys),
                app_path: None,
                user_data: None,
            },
        )
        .unwrap();
        store(&a, &watch.encode().unwrap()).unwrap()
    };
    let t1 = env.applied(&h);
    let e = plan_on(&env.sys, &t, &[], &["api=dx9"]).unwrap_err();
    assert!(
        matches!(&e, EngineError::RunNeedsDirect { run_from, watch_from }
            if run_from == "option api=dx9"
                && *watch_from == format!("the launch profile of transaction {t1}")),
        "{e:?}"
    );
    reverted(&env, &t1);
    // A kept `run` and a new `watch` rule (another Topo of the game whose launch is `watch`).
    let t2 = apply(&env, &t, &[], &[], &["api=dx9"]);
    let mut v = serde_json::to_value(&t).unwrap();
    v["launch"]["chain"] = serde_json::json!(["steam", "upc"]);
    v["options"] = serde_json::json!([]);
    let watched: Topo = serde_json::from_value(v).unwrap();
    check::topo(&watched, Rules::Source).unwrap_or_else(|e| panic!("{e}"));
    let e = plan_on(&env.sys, &watched, &["cores/limit"], &[]).unwrap_err();
    assert!(
        matches!(&e, EngineError::RunNeedsDirect { run_from, watch_from }
            if *run_from == format!("the launch profile of transaction {t2}")
                && watch_from == "fix cores/limit"),
        "{e:?}"
    );
    // No part set: no profile op; the plan is for the executable of the kept `run`.
    let tp = plan_on(&env.sys, &t, &["settings/ini"], &[]).unwrap();
    assert!(tp.parts.is_none());
    assert!(
        tp.plan.ops.iter().all(|o| o.content().is_none()),
        "{:?}",
        tp.plan.ops
    );
    assert_eq!(main_exe(&tp), "game_dx9.exe");
    // The kept `run` no longer a matched build: refused, naming the transaction.
    let mut other = x86();
    other.push(0);
    put(&env.sys, "game_dx9.exe", &other);
    match plan_on(&env.sys, &t, &["settings/ini"], &[]) {
        Err(EngineError::RunNotMatched { txn, exe }) => {
            assert_eq!(txn, t2);
            assert_eq!(exe, abs("game_dx9.exe"));
        }
        other => panic!("{other:?}"),
    }
}

// ---------- LO10 ----------

#[test]
fn lo10_a_profile_reverted_between_plan_and_apply_refuses_the_apply() {
    let env = Env::new(game_sys());
    let t = topo();
    let t1 = apply(&env, &t, &[], &["cores/limit"], &[]);
    let tp = plan_on(&env.sys, &t, &[], &["api=dx9"]).unwrap();
    let h = stored(&env.sys, &tp);
    reverted(&env, &t1);
    let before = snap(&env.sys);
    assert!(
        env.apply(&h).is_err(),
        "the old state of the profile changed"
    );
    same(&before, &snap(&env.sys));
}

/// A draft Topo where Steam starts the game itself (`launch.start` is `game.exe`): options
/// `skip` (`-skipintro`) and `fov` (`+fov=1`), each `launch_args` alone; the issues of [`topo`].
fn args_topo() -> Topo {
    let mut v = serde_json::to_value(topo()).unwrap();
    v["launch"]["start"] = serde_json::json!("game.exe");
    let opt = |id: &str, arg: &str| {
        serde_json::json!({ "id": id, "title": id,
            "sources": [{ "type": "pcgw", "url": "https://www.pcgamingwiki.com/wiki/Invented#Args" }],
            "values": [{ "id": "on", "title": "On", "status": "unverified",
                "steps": [{ "launch_args": [arg] }] }] })
    };
    v["options"] = serde_json::json!([opt("skip", "-skipintro"), opt("fov", "+fov=1")]);
    let t: Topo = serde_json::from_value(v).unwrap();
    check::topo(&t, Rules::Source).unwrap_or_else(|e| panic!("{e}"));
    t
}

/// A step file's `direct` rule without `run` (max 4 threads), stored.
fn step_rule(env: &Env) -> PlanHash {
    let fr = fr(&env.sys);
    let store_dir = StoreDir::open(&env.sys, &fr, Path::new(STEAM_LIB)).unwrap();
    let g = store_dir.game(&fr, "G").unwrap();
    let a = app(&env.sys);
    let main = rel("game.exe");
    let p = crate::prim::plan(
        &[Step::LaunchMethod(LaunchMethodSpec {
            method: MethodSpec::Direct,
            start: rel("FFLauncher.exe"),
            cpu: Some(CpuRuleSpec {
                max_threads: Some(4),
                ..CpuRuleSpec::default()
            }),
            priority: None,
            run: None,
            args: Vec::new(),
        })],
        &PlanCtx {
            game: &g,
            app: Some(&a),
            steam_app: Some(APP),
            main_exe: Some(&main),
            reg: RegPolicy.reader(&env.sys),
            app_path: None,
            user_data: None,
        },
    )
    .unwrap();
    store(&a, &p.encode().unwrap()).unwrap()
}

fn refused(r: Result<crate::exec::Outcome, crate::exec::ApplyError>) -> Refusal {
    match r {
        Err(crate::exec::ApplyError::Refused(x)) => x,
        other => panic!("{other:?}"),
    }
}

// ---------- LO10b (security F1 of the O-2b review) ----------

#[test]
fn lo10b_the_apply_checks_the_switch_and_the_kept_profile_under_the_lock() {
    let t = topo();
    // (a) A plan for DX9, then a package for the first match applied: E4 b under the lock.
    let env = Env::new(game_sys());
    let pk = pkgs(&env.sys);
    let h = stored(
        &env.sys,
        &plan_with(&env.sys, &t, &pk, &[], &["api=dx9"]).unwrap(),
    );
    let t1 = apply(&env, &t, &pk, &["wrapper/pkg"], &[]);
    assert!(matches!(refused(env.apply(&h)), Refusal::ExeSwitch { txn } if txn == t1));
    // (b) A package planned for the first match, then DX9 applied: its `run` names another
    // executable than the plan's.
    let env = Env::new(game_sys());
    let pk = pkgs(&env.sys);
    let h = stored(
        &env.sys,
        &plan_with(&env.sys, &t, &pk, &["wrapper/pkg"], &[]).unwrap(),
    );
    apply(&env, &t, &pk, &[], &["api=dx9"]);
    assert!(matches!(refused(env.apply(&h)), Refusal::ProfileChanged));
    // (c) A package planned for DX9 over a live DX9 that is undone before the apply: the plan
    // names the profile it relied on.
    let env = Env::new(game_sys());
    let pk = pkgs(&env.sys);
    let t1 = apply(&env, &t, &pk, &[], &["api=dx9"]);
    let tp = plan_with(&env.sys, &t, &pk, &["wrapper/pkg"], &[]).unwrap();
    assert!(tp.plan.source.as_ref().unwrap().kept_profile.is_some());
    let h = stored(&env.sys, &tp);
    reverted(&env, &t1);
    let before = snap(&env.sys);
    assert!(matches!(refused(env.apply(&h)), Refusal::ProfileChanged));
    same(&before, &snap(&env.sys));
}

// ---------- LO11 the golden plan ----------

/// LO11: the plan of a `start` value over a live CPU rule, frozen (`tests/fixtures/plan`): the
/// kept rule and `run` in one profile replacing the rule's.
#[test]
#[expect(
    clippy::disallowed_methods,
    reason = "test: the golden plan is a fixture of the repository, not a game file"
)]
fn lo11_the_golden_plan_of_a_start_value_over_a_rule() {
    let env = Env::new(game_sys());
    let t = topo();
    apply(&env, &t, &[], &["cores/limit"], &[]);
    let tp = plan_on(&env.sys, &t, &[], &["api=dx9"]).unwrap();
    let bytes = tp.plan.encode().unwrap();
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/plan");
    let golden = std::fs::read(dir.join("topo-220-start.json")).unwrap_or_default();
    if bytes.bytes() != golden.as_slice() {
        let out = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/plan-topo-220-start.golden.json");
        std::fs::write(&out, bytes.bytes()).unwrap();
        panic!(
            "the plan differs from tests/fixtures/plan/topo-220-start.json (hash {}); the new \
             bytes are in {}",
            bytes.hash(),
            out.display()
        );
    }
    let want = std::fs::read_to_string(dir.join("topo-220-start.sha256")).unwrap();
    assert_eq!(bytes.hash().to_string(), want.trim());
}

// ---------- LO12 to LO15 (review S2, F2, F3) ----------

#[test]
fn lo12_kept_args_and_two_args_values() {
    let env = Env::new(game_sys());
    let t = topo();
    let t1 = apply(&env, &t, &[], &[], &["intro=skip"]);
    let tp = plan_on(&env.sys, &t, &["cores/limit"], &[]).unwrap();
    let parts = tp.parts.clone().unwrap();
    assert_eq!(
        parts.args,
        Some((vec!["-skipintro".to_owned()], PartFrom::Kept(t1)))
    );
    assert_eq!(parts.run.map(|(_, f)| f), Some(PartFrom::Kept(t1)));
    let args: Vec<String> = profile_of(&tp)
        .args
        .iter()
        .map(|a| a.as_str().to_owned())
        .collect();
    assert_eq!(args, ["-skipintro"]);
    // Two values that pass arguments.
    let a = args_topo();
    assert!(matches!(
        plan_on(&env.sys, &a, &[], &["skip=on", "fov=on"]),
        Err(EngineError::TwoArgs { first, second }) if first == "skip=on" && second == "fov=on"
    ));
}

#[test]
fn lo13_anti_cheat_refuses_kept_args_alone() {
    let env = Env::new(game_sys());
    let a = args_topo();
    let t1 = apply(&env, &a, &[], &[], &["skip=on"]);
    env.sys
        .fake_fs()
        .mkdir_all(Path::new(&format!(r"{STEAM_GAME}\pb")))
        .unwrap();
    env.sys.sync_all();
    match plan_on(&env.sys, &a, &["cores/limit"], &[]) {
        Err(EngineError::KeptAntiCheat { txn, step }) => {
            assert_eq!((txn, step), (t1, StepKind::LaunchArgs));
        }
        other => panic!("{other:?}"),
    }
}

/// F2: a revert that brings a `run` back (a step file's profile without `run` over DX9) is held
/// by a later package for any executable of the game.
#[test]
fn lo14_b1_holds_a_revert_that_brings_a_run_back() {
    let env = Env::new(game_sys());
    let t = topo();
    let pk = pkgs(&env.sys);
    let before = snap(&env.sys);
    let t1 = apply(&env, &t, &pk, &[], &["api=dx9"]);
    let t2 = env.applied(&step_rule(&env));
    // T3 a package for the first match (no `run` is live now).
    let t3 = apply(&env, &t, &pk, &["wrapper/pkg"], &[]);
    later(env.revert(&t2), t3);
    reverted(&env, &t3);
    reverted(&env, &t2);
    reverted(&env, &t1);
    same(&before, &snap(&env.sys));
}

/// F3: the newest holder interrupted (its revert failed after it began) refuses the plan. Every
/// call of the revert is failed once, on a fresh world each: at least one failure leaves the
/// transaction begun and not reverted, and every such state refuses as `Interrupted`.
#[test]
fn lo15_an_interrupted_holder_refuses() {
    let world = || {
        let env = Env::new(game_sys());
        let t1 = apply(&env, &topo(), &[], &[], &["api=dx9"]);
        (env, t1)
    };
    let (env, t1) = world();
    let fx = env.sys.fake_fs();
    let r = env.revert_armed(&t1, |f| f.record_calls(true));
    fx.record_calls(false);
    assert!(r.is_ok(), "{r:?}");
    let calls = fx.take_calls();
    let mut seen = 0;
    for (k, call) in calls.iter().enumerate() {
        let nth = calls[..k].iter().filter(|c| *c == call).count();
        let (env, t1) = world();
        let r = env.revert_armed(&t1, |f| {
            f.fail_at(*call, nth, crate::sys::SysErrorKind::AccessDenied);
        });
        env.sys.fake_fs().clear_faults();
        if r.is_ok() {
            continue;
        }
        match plan_on(&env.sys, &topo(), &["cores/limit"], &[]) {
            Err(EngineError::Live(crate::exec::LiveError::Interrupted { txn })) => {
                assert_eq!(txn, t1);
                seen += 1;
            }
            // Failed before the revert began (or after the op was reverted): the profile is
            // still live and kept, or gone.
            Ok(_) => {}
            Err(e) => panic!("{call:?} #{nth}: {e}"),
        }
    }
    assert!(
        seen > 0,
        "no failure left the holder interrupted: {calls:?}"
    );
}
