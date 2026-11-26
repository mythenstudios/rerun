//! The user's own settings ("Advanced", ADR 0029, slice E-1a and its review follow-up) on a game
//! with a matched Topo, against the fake: the form of `Plan.manual` (the allowlist), the rule
//! part of the one launch profile, the user's own `start` where the Topo names none, the
//! compatibility flags on the effective main executable, the refusals and the anti-cheat rule.
//! Every Topo, folder, hash and ID is invented ([`super::launch_tests`]).
//!
//! Scope of every snapshot: the game folder `G`, Rerun's `profiles` and `HKCU\Software`.
//! - M1 the form: every bound of `Manual::check` with the rules in force now (a rule that
//!   restricts nothing, elevation tokens even when planted on the allowlist), only the
//!   structure for a recorded head (security F1: 2000 threads and 9 unlisted flags decode as
//!   recorded, not as current), the wire form, a source without picks and choices only with
//!   `manual`, exactly one of `source` and `Manual.exe`, the binding, the form of a release
//!   build (security F2).
//! - M2 an own CPU rule and priority alone: the profile, the origin, the recorded selection;
//!   round trip identical.
//! - M3 own compatibility flags alone: a `TokenList` on the main executable, no profile op;
//!   round trip identical, also after the token left the allowlist (the real head decodes as
//!   recorded).
//! - M4 own settings stacked: over a live option value that sets `run` (the rule composed with
//!   the kept `run`, the flags on the executable `run` made the main one; LIFO holds the
//!   option), own flags alone over it (B1 holds the option), with an option value in one plan,
//!   and over a live CPU fix (replaced with a warning, then back bit for bit).
//! - M5 refusals: a CPU fix and an own rule in one plan, an own `watch` with a kept `run`, own
//!   flags and a fix's flags on one executable, `Manual.exe` with a Topo, an own `start` where
//!   the Topo names one, F5 (a priority with a launcher as `start`), the switch rule (E4 b) for
//!   own flags; never a helper op.
//! - M6 anti-cheat: an own `watch` rule (also the Topo's `watch` taken by default, with the
//!   hint) and own flags refused, an own `direct` rule warned.
//! - M7 a Topo without a launch block (review S1): an own rule with an own `start` plans and
//!   round-trips; without `start` it is refused; a `start` outside the scanned folders too.

use std::path::Path;

use super::launch_tests::{
    APP, INDEX, abs, apply, choices, game_sys, later, main_exe, picks, profile_of, put, reverted,
    same, snap, stored, topo, x86,
};
use super::{
    EngineError, EngineSelection, Facts, LaunchProblem, PartFrom, StepKind, TopoPlan, Warning,
};
use crate::catalog::check::{self, Rules};
use crate::catalog::model::Topo;
use crate::exec::tests::Env;
use crate::hw::{self, GpuArchTable};
use crate::journal::Observed;
use crate::plan::{
    Manual, ManualError, ManualExe, ManualLaunch, ManualMethod, Op, Plan, PlanError, RootKind,
};
use crate::policy::registry::layers::knob as layer_knob;
use crate::policy::registry::{RegPolicy, TokenName};
use crate::policy::root::StoreDir;
use crate::prim::tests::{STEAM_GAME, STEAM_LIB, app, fr, rel};
use crate::prim::{CpuRuleSpec, MethodSpec, ModeSpec, PlanCtx, PrioritySpec};
use crate::sys::fake::FakeSystem;
use rerun_proto::cpu::rule::Mode;
use rerun_proto::profile::{Method, Priority};

/// The Topo of [`super::launch_tests`] with Steam starting `game.exe` itself (so a priority and
/// a soft rule reach the game, F5).
fn own_topo() -> Topo {
    with_topo(|v| v["launch"]["start"] = serde_json::json!("game.exe"))
}

/// The Topo of [`super::launch_tests`] changed by `f`, checked as a source.
fn with_topo(f: impl FnOnce(&mut serde_json::Value)) -> Topo {
    let mut v = serde_json::to_value(topo()).unwrap();
    f(&mut v);
    let t: Topo = serde_json::from_value(v).unwrap();
    check::topo(&t, Rules::Source).unwrap_or_else(|e| panic!("{e}"));
    t
}

/// A Topo without a launch block (as Alice: Madness Returns and Mirror's Edge): no options
/// (their `start` values need `launch.start`).
fn no_launch_topo() -> Topo {
    with_topo(|v| {
        v.as_object_mut().unwrap().remove("launch");
        v["options"] = serde_json::json!([]);
    })
}

fn tok(s: &str) -> TokenName {
    TokenName::parse(s).unwrap()
}

/// An own rule: at most 8 threads, no SMT, `above_normal`, the Topo's method.
fn rule() -> Manual {
    Manual {
        launch: Some(ManualLaunch {
            cpu: Some(CpuRuleSpec {
                max_threads: Some(8),
                smt: Some(false),
                ..CpuRuleSpec::default()
            }),
            priority: Some(PrioritySpec::AboveNormal),
            ..ManualLaunch::default()
        }),
        ..Manual::default()
    }
}

/// [`rule`] with `f` applied to its launch part.
fn rule_with(f: impl FnOnce(&mut ManualLaunch)) -> Manual {
    let mut m = rule();
    if let Some(l) = &mut m.launch {
        f(l);
    }
    m
}

/// Own flags only.
fn flags(t: &[&str]) -> Manual {
    Manual {
        layers: t.iter().map(|s| tok(s)).collect(),
        ..Manual::default()
    }
}

/// Plans picks `p`, choices `c` and the own settings `m` of `t` (the journal read as the flow
/// reads it).
fn plan_m(
    sys: &FakeSystem,
    t: &Topo,
    p: &[&str],
    c: &[&str],
    m: Option<&Manual>,
) -> Result<TopoPlan, EngineError> {
    let fr = fr(sys);
    let store = StoreDir::open(sys, &fr, Path::new(STEAM_LIB)).unwrap();
    let g = store.game(&fr, "G").unwrap();
    let gf = super::read_game(&g, t);
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
        packages: &[],
    };
    let (p, c) = (picks(p), choices(c));
    let live = crate::exec::live_state(&a, Some(APP), g.id()).map_err(EngineError::Live)?;
    super::plan(
        &INDEX,
        t,
        &facts,
        &EngineSelection {
            picks: &p,
            choices: &c,
            manual: m,
        },
        &ctx,
        &live,
    )
}

/// Plans own settings only, applies and verifies.
fn apply_m(env: &Env, t: &Topo, c: &[&str], m: &Manual) -> crate::journal::TxnId {
    let tp = plan_m(&env.sys, t, &[], c, Some(m)).unwrap_or_else(|e| panic!("{m:?}: {e}"));
    let txn = env.applied(&stored(&env.sys, &tp));
    let v = env.verify(&txn);
    assert!(v.iter().all(|(_, o)| *o == Observed::After), "{v:?}");
    txn
}

fn anti_cheat_marker(sys: &FakeSystem) {
    sys.fake_fs()
        .mkdir_all(Path::new(&format!(r"{STEAM_GAME}\pb")))
        .unwrap();
    sys.sync_all();
}

/// The bytes of `p` as serde writes them, without the format's checks (a forged or old head).
fn raw(p: &Plan) -> Vec<u8> {
    serde_json::to_vec(p).unwrap()
}

// ---------- M1 ----------

#[test]
fn m1_every_bound_of_the_allowlist() {
    let err = |m: Manual| m.check().unwrap_err();
    let launch = |l: ManualLaunch| Manual {
        launch: Some(l),
        ..Manual::default()
    };
    let cpu = |c: CpuRuleSpec| {
        launch(ManualLaunch {
            cpu: Some(c),
            ..ManualLaunch::default()
        })
    };
    // Nothing, an executable alone, a method alone, a start alone.
    assert_eq!(err(Manual::default()), ManualError::Empty);
    assert_eq!(
        err(Manual {
            exe: Some(ManualExe {
                main_exe: rel("game.exe"),
            }),
            ..Manual::default()
        }),
        ManualError::Empty
    );
    for l in [
        ManualLaunch {
            method: Some(ManualMethod::Watch),
            ..ManualLaunch::default()
        },
        ManualLaunch {
            start: Some(rel("game.exe")),
            ..ManualLaunch::default()
        },
    ] {
        assert_eq!(err(launch(l)), ManualError::NoRule);
    }
    // The CPU rule: empty, `report_cores`, `max_threads` 0 and 1025.
    for c in [
        CpuRuleSpec::default(),
        CpuRuleSpec {
            report_cores: Some(4),
            ..CpuRuleSpec::default()
        },
        CpuRuleSpec {
            max_threads: Some(0),
            ..CpuRuleSpec::default()
        },
        CpuRuleSpec {
            max_threads: Some(1025),
            ..CpuRuleSpec::default()
        },
    ] {
        assert!(matches!(err(cpu(c)), ManualError::Cpu(_)), "{c:?}");
    }
    // Review S2: a rule that restricts nothing once the defaults are filled in.
    for c in [
        CpuRuleSpec {
            smt: Some(true),
            ..CpuRuleSpec::default()
        },
        CpuRuleSpec {
            mode: Some(ModeSpec::Soft),
            prefer: Some(crate::prim::PreferSpec::Any),
            single_l3: Some(false),
            ..CpuRuleSpec::default()
        },
    ] {
        assert_eq!(err(cpu(c)), ManualError::NoRestriction, "{c:?}");
    }
    // Every field at its bound is taken.
    for c in [
        CpuRuleSpec {
            max_threads: Some(1),
            ..CpuRuleSpec::default()
        },
        CpuRuleSpec {
            max_threads: Some(1024),
            smt: Some(false),
            single_l3: Some(true),
            prefer: Some(crate::prim::PreferSpec::Performance),
            prefer_l3: Some(crate::prim::PreferL3Spec::Largest),
            mode: Some(ModeSpec::Soft),
            exclude_first: Some(crate::prim::ExcludeFirstSpec::Core),
            report_cores: None,
        },
        CpuRuleSpec {
            exclude_first: Some(crate::prim::ExcludeFirstSpec::Thread),
            ..CpuRuleSpec::default()
        },
    ] {
        cpu(c).check().unwrap();
    }
    // A priority alone is a rule part.
    launch(ManualLaunch {
        priority: Some(PrioritySpec::High),
        ..ManualLaunch::default()
    })
    .check()
    .unwrap();
    // Flags: on the allowlist, each once, at most 8.
    flags(&["ZZ_FLAG_A", "ZZ_FLAG_B"]).check().unwrap();
    assert_eq!(
        err(flags(&["ZZ_FLAG_A", "ZZ_FLAG_A"])),
        ManualError::LayerTwice("ZZ_FLAG_A".into())
    );
    assert_eq!(
        err(flags(&["ZZ_NOT_LISTED"])),
        ManualError::LayerNotAllowed("ZZ_NOT_LISTED".into())
    );
    let nine: Vec<String> = (0..9).map(|i| format!("ZZ_X{i}")).collect();
    let nine: Vec<&str> = nine.iter().map(String::as_str).collect();
    assert_eq!(err(flags(&nine)), ManualError::TooManyLayers);
    // Security F4: the elevation tokens are refused even when planted on the allowlist.
    for t in ["RUNASADMIN", "RUNASHIGHEST"] {
        layer_knob::plant(Some(t));
        let e = flags(&[t]).check();
        layer_knob::plant(None);
        assert_eq!(e, Err(ManualError::LayerNotAllowed(t.into())), "{t}");
    }
    // Security F1: a recorded head keeps only the structure.
    let recorded = |m: &Manual| m.check_with(crate::plan::Rules::Recorded);
    recorded(&flags(&nine)).unwrap();
    recorded(&flags(&["ZZ_NOT_LISTED"])).unwrap();
    recorded(&cpu(CpuRuleSpec {
        max_threads: Some(2000),
        ..CpuRuleSpec::default()
    }))
    .unwrap();
    assert_eq!(recorded(&Manual::default()), Err(ManualError::Empty));
    assert_eq!(
        recorded(&flags(&["ZZ_FLAG_A", "ZZ_FLAG_A"])),
        Err(ManualError::LayerTwice("ZZ_FLAG_A".into()))
    );
}

#[test]
fn m1_the_plan_form_and_the_binding() {
    let env = Env::new(game_sys());
    let t = own_topo();
    let tp = plan_m(&env.sys, &t, &[], &[], Some(&rule())).unwrap();
    let src = tp.plan.source.clone().unwrap();
    assert!(src.picks.is_empty() && src.choices.is_empty());
    assert_eq!(tp.plan.manual, Some(rule()));
    // On the wire exactly what was chosen; the plan without `manual` has no such field.
    let j = String::from_utf8(tp.plan.encode().unwrap().bytes().to_vec()).unwrap();
    assert!(
        j.contains(
            r#""manual":{"launch":{"cpu":{"max_threads":8,"smt":false},"priority":"above_normal"}}"#
        ),
        "{j}"
    );
    let other = plan_m(&env.sys, &t, &["settings/ini"], &[], None).unwrap();
    let j = String::from_utf8(other.plan.encode().unwrap().bytes().to_vec()).unwrap();
    assert!(!j.contains("manual"), "{j}");
    let bad = |f: &dyn Fn(&mut Plan)| {
        let mut p = tp.plan.clone();
        f(&mut p);
        p.encode().unwrap_err()
    };
    // A source without picks and choices needs `manual`.
    assert!(matches!(
        bad(&|p| p.manual = None),
        PlanError::Invalid { .. }
    ));
    let exe = || {
        Some(ManualExe {
            main_exe: rel("game.exe"),
        })
    };
    // Review S1: exactly one of `source` and `Manual.exe`.
    assert!(matches!(
        bad(&|p| {
            if let Some(m) = &mut p.manual {
                m.exe = exe();
            }
        }),
        PlanError::Invalid { .. }
    ));
    assert!(matches!(
        bad(&|p| p.source = None),
        PlanError::Invalid { .. }
    ));
    let mut own = tp.plan.clone();
    own.source = None;
    if let Some(m) = &mut own.manual {
        m.exe = exe();
    }
    own.encode().unwrap();
    // The form of `manual` itself.
    assert!(matches!(
        bad(&|p| p.manual = Some(Manual::default())),
        PlanError::Manual(ManualError::Empty)
    ));
    // The binding: a plan with manual steps names the main executable's hash and the others,
    // also without a source.
    for f in [
        &(|p: &mut Plan| p.roots[0].main_sha256 = None) as &dyn Fn(&mut Plan),
        &|p: &mut Plan| p.roots[0].other_exes = None,
    ] {
        assert!(matches!(bad(f), PlanError::Invalid { .. }));
        let mut o = own.clone();
        f(&mut o);
        assert!(matches!(o.encode(), Err(PlanError::Invalid { .. })));
    }
    assert_eq!(tp.plan.roots[0].kind, RootKind::Game);
    // An unknown field next to `manual` is refused on decode.
    let j = String::from_utf8(tp.plan.encode().unwrap().bytes().to_vec()).unwrap();
    let j = j.replace(
        r#""priority":"above_normal"}"#,
        r#""priority":"above_normal","x":1}"#,
    );
    assert!(crate::plan::decode(j.as_bytes()).is_err());
    // Security F1: a head with values a later version refuses decodes as recorded only.
    let mut forged = tp.plan.clone();
    forged.manual = Some(Manual {
        launch: Some(ManualLaunch {
            cpu: Some(CpuRuleSpec {
                max_threads: Some(2000),
                ..CpuRuleSpec::default()
            }),
            ..ManualLaunch::default()
        }),
        layers: (0..9).map(|i| tok(&format!("ZZ_X{i}"))).collect(),
        exe: None,
    });
    let b = raw(&forged);
    crate::plan::decode_recorded(&b).unwrap();
    assert!(matches!(crate::plan::decode(&b), Err(PlanError::Manual(_))));
    // Security F2: the form of a release build: a plan of neither a Topo nor own settings
    // (a step file's) is refused, every other one taken.
    crate::plan::release_form(&tp.plan).unwrap();
    crate::plan::release_form(&own).unwrap();
    let mut step_file = tp.plan.clone();
    step_file.source = None;
    step_file.manual = None;
    assert!(matches!(
        crate::plan::release_form(&step_file),
        Err(PlanError::Invalid { .. })
    ));
}

// ---------- M2 ----------

#[test]
fn m2_an_own_rule_round_trips() {
    let env = Env::new(game_sys());
    let t = own_topo();
    let before = snap(&env.sys);
    let tp = plan_m(&env.sys, &t, &[], &[], Some(&rule())).unwrap();
    let p = profile_of(&tp);
    // `auto` with the chain `[steam]` is `direct`; the rule and priority are the user's.
    assert_eq!(p.method, Method::Direct);
    assert_eq!(p.start, abs("game.exe"));
    assert_eq!(p.target, abs("game.exe"));
    let r = p.cpu.unwrap();
    assert_eq!((r.max_threads, r.smt, r.mode), (Some(8), false, Mode::Hard));
    assert_eq!(p.priority, Some(Priority::AboveNormal));
    assert!(p.run.is_none() && p.args.is_empty());
    let parts = tp.parts.clone().unwrap();
    assert_eq!(parts.rule, Some(PartFrom::Manual));
    assert_eq!(parts.method, MethodSpec::Direct);
    assert!(parts.run.is_none() && parts.args.is_none());
    assert_eq!(main_exe(&tp), "game.exe");
    assert!(tp.warnings.is_empty(), "{:?}", tp.warnings);
    let txn = env.applied(&stored(&env.sys, &tp));
    assert!(env.verify(&txn).iter().all(|(_, o)| *o == Observed::After));
    reverted(&env, &txn);
    same(&before, &snap(&env.sys));
    // `watch` chosen: the profile's method is `watch`, its target the main executable.
    let w = rule_with(|l| l.method = Some(ManualMethod::Watch));
    let tp = plan_m(&env.sys, &t, &[], &[], Some(&w)).unwrap();
    let p = profile_of(&tp);
    assert_eq!((p.method, p.target), (Method::Watch, abs("game.exe")));
    assert_eq!(tp.parts.unwrap().method, MethodSpec::Watch);
}

// ---------- M3 ----------

#[test]
fn m3_own_flags_round_trip() {
    let env = Env::new(game_sys());
    let t = own_topo();
    let before = snap(&env.sys);
    let tp = plan_m(&env.sys, &t, &[], &[], Some(&flags(&["ZZ_FLAG_A"]))).unwrap();
    assert!(tp.parts.is_none(), "no profile part");
    assert!(tp.plan.ops.iter().all(|o| o.content().is_none()));
    let tokens: Vec<_> = tp
        .plan
        .ops
        .iter()
        .filter_map(|o| match o {
            Op::TokenList { add, .. } => Some(add.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(tokens, [vec![tok("ZZ_FLAG_A")]]);
    assert_eq!(main_exe(&tp), "game.exe");
    let txn = env.applied(&stored(&env.sys, &tp));
    assert!(env.verify(&txn).iter().all(|(_, o)| *o == Observed::After));
    reverted(&env, &txn);
    same(&before, &snap(&env.sys));
}

/// Security F4: the real head of own flags whose token left the allowlist since the apply
/// decodes as recorded, and the revert restores everything.
#[test]
fn m3_a_token_off_the_allowlist_never_blocks_the_revert() {
    let env = Env::new(game_sys());
    let t = own_topo();
    let before = snap(&env.sys);
    let tp = plan_m(&env.sys, &t, &[], &[], Some(&flags(&["ZZ_FLAG_A"]))).unwrap();
    let h = stored(&env.sys, &tp);
    let txn = env.applied(&h);
    let head = crate::plan::load(&app(&env.sys), &h).unwrap();
    layer_knob::drop_token(Some("ZZ_FLAG_A"));
    let current = crate::plan::decode(head.bytes());
    let recorded = crate::plan::decode_recorded(head.bytes());
    let r = env.revert(&txn);
    layer_knob::drop_token(None);
    assert!(matches!(current, Err(PlanError::Manual(_))), "{current:?}");
    recorded.unwrap();
    assert_eq!(r.unwrap().closed, Some(crate::journal::Closing::Reverted));
    same(&before, &snap(&env.sys));
}

// ---------- M4 ----------

#[test]
fn m4_own_settings_over_a_live_run_stack_and_round_trip() {
    let env = Env::new(game_sys());
    let t = own_topo();
    let before = snap(&env.sys);
    // T1 DX9 (`run` game_dx9.exe).
    let t1 = apply(&env, &t, &[], &[], &["api=dx9"]);
    let after_t1 = snap(&env.sys);
    // T2 an own rule and flags: `run` kept, the flags on the executable it starts.
    let mut m = rule();
    m.layers = vec![tok("ZZ_FLAG_A")];
    let tp = plan_m(&env.sys, &t, &[], &[], Some(&m)).unwrap();
    let parts = tp.parts.clone().unwrap();
    assert_eq!(parts.rule, Some(PartFrom::Manual));
    assert_eq!(parts.run.map(|(_, f)| f), Some(PartFrom::Kept(t1)));
    let p = profile_of(&tp);
    assert_eq!(p.run.as_deref(), Some(abs("game_dx9.exe").as_str()));
    assert_eq!(p.priority, Some(Priority::AboveNormal));
    assert_eq!(main_exe(&tp), "game_dx9.exe");
    // T1 had no rule part: nothing is replaced.
    assert!(
        !tp.warnings
            .iter()
            .any(|w| matches!(w, Warning::ReplacesRule { .. }))
    );
    let t2 = env.applied(&stored(&env.sys, &tp));
    // Newest first: T1 is held by T2 (the profile object; B1 too, for the flags).
    later(env.revert(&t1), t2);
    reverted(&env, &t2);
    same(&after_t1, &snap(&env.sys));
    reverted(&env, &t1);
    same(&before, &snap(&env.sys));
}

/// Review S4: own flags alone over a live `run` share no object with T1; B1 holds T1.
#[test]
fn m4_own_flags_over_a_live_run_hold_it_by_b1() {
    let env = Env::new(game_sys());
    let t = own_topo();
    let before = snap(&env.sys);
    let t1 = apply(&env, &t, &[], &[], &["api=dx9"]);
    let tp = plan_m(&env.sys, &t, &[], &[], Some(&flags(&["ZZ_FLAG_A"]))).unwrap();
    assert!(tp.parts.is_none(), "no profile part");
    assert_eq!(main_exe(&tp), "game_dx9.exe");
    let t2 = env.applied(&stored(&env.sys, &tp));
    let held = snap(&env.sys);
    later(env.revert(&t1), t2);
    same(&held, &snap(&env.sys));
    reverted(&env, &t2);
    reverted(&env, &t1);
    same(&before, &snap(&env.sys));
}

#[test]
fn m4_an_own_rule_with_an_option_value_in_one_plan() {
    let env = Env::new(game_sys());
    let t = own_topo();
    let before = snap(&env.sys);
    let tp = plan_m(&env.sys, &t, &[], &["intro=skip"], Some(&rule())).unwrap();
    let parts = tp.parts.clone().unwrap();
    assert_eq!(parts.rule, Some(PartFrom::Manual));
    assert!(matches!(parts.run, Some((_, PartFrom::Option(_)))));
    assert!(matches!(parts.args, Some((_, PartFrom::Option(_)))));
    let src = tp.plan.source.clone().unwrap();
    assert_eq!(src.choices, choices(&["intro=skip"]));
    let txn = env.applied(&stored(&env.sys, &tp));
    reverted(&env, &txn);
    same(&before, &snap(&env.sys));
}

#[test]
fn m4_an_own_rule_over_a_live_cpu_fix() {
    let env = Env::new(game_sys());
    let t = own_topo();
    let before = snap(&env.sys);
    let t1 = apply(&env, &t, &[], &["cores/limit"], &[]);
    let after_t1 = snap(&env.sys);
    let m = rule_with(|l| {
        l.cpu = Some(CpuRuleSpec {
            max_threads: Some(4),
            ..CpuRuleSpec::default()
        });
    });
    let tp = plan_m(&env.sys, &t, &[], &[], Some(&m)).unwrap();
    // Review S4: the profile is the own rule's; the fix's `smt: false` is gone.
    let p = profile_of(&tp);
    let r = p.cpu.unwrap();
    assert_eq!((r.max_threads, r.smt), (Some(4), true));
    assert_eq!(p.priority, Some(Priority::AboveNormal));
    assert_eq!(tp.parts.clone().unwrap().rule, Some(PartFrom::Manual));
    // Review S3: the replaced rule part is said.
    assert!(
        tp.warnings.contains(&Warning::ReplacesRule { txn: t1 }),
        "{:?}",
        tp.warnings
    );
    let t2 = env.applied(&stored(&env.sys, &tp));
    later(env.revert(&t1), t2);
    reverted(&env, &t2);
    same(&after_t1, &snap(&env.sys));
    reverted(&env, &t1);
    same(&before, &snap(&env.sys));
}

// ---------- M5 ----------

#[test]
fn m5_refusals() {
    let env = Env::new(game_sys());
    let t = own_topo();
    // A CPU fix and an own rule in one plan.
    match plan_m(&env.sys, &t, &["cores/limit"], &[], Some(&rule())) {
        Err(EngineError::ManualAndCpuFix { issue, variant }) => {
            assert_eq!((issue.as_str(), variant.as_str()), ("cores", "limit"));
        }
        other => panic!("{other:?}"),
    }
    // `Manual.exe` with a Topo.
    let mut x = rule();
    x.exe = Some(ManualExe {
        main_exe: rel("game.exe"),
    });
    assert!(matches!(
        plan_m(&env.sys, &t, &[], &[], Some(&x)),
        Err(EngineError::ManualExe)
    ));
    // An own `start` where the Topo names one.
    match plan_m(
        &env.sys,
        &t,
        &[],
        &[],
        Some(&rule_with(|l| l.start = Some(rel("game_dx9.exe")))),
    ) {
        Err(e @ EngineError::ManualStart { .. }) => {
            assert!(e.to_string().contains("(game.exe)"), "{e}");
        }
        other => panic!("{other:?}"),
    }
    // The form, before anything else.
    assert!(matches!(
        plan_m(&env.sys, &t, &[], &[], Some(&flags(&["ZZ_NOT_LISTED"]))),
        Err(EngineError::Plan(PlanError::Manual(
            ManualError::LayerNotAllowed(_)
        )))
    ));
    // Own flags and a fix's flags on one executable (DX9 chosen: `display/layer` is for it).
    match plan_m(
        &env.sys,
        &t,
        &["display/layer"],
        &["api=dx9"],
        Some(&flags(&["ZZ_FLAG_B"])),
    ) {
        Err(EngineError::ManualAndLayerFix { issue, exe, .. }) => {
            assert_eq!((issue.as_str(), exe.as_str()), ("display", "game_dx9.exe"));
        }
        other => panic!("{other:?}"),
    }
    // F5: with Steam starting the launcher, a priority does not reach the game.
    let e = plan_m(&env.sys, &topo(), &[], &[], Some(&rule())).unwrap_err();
    assert!(matches!(e, EngineError::Plan(PlanError::Step(_))), "{e:?}");
    // Never a helper op.
    let mut m = rule();
    m.layers = vec![tok("ZZ_FLAG_A")];
    let tp = plan_m(&env.sys, &t, &[], &[], Some(&m)).unwrap();
    assert!(!tp.plan.ops.iter().any(|o| o.target().is_helper()));
    // An own `watch` with a kept `run`.
    let t1 = apply(&env, &t, &[], &[], &["api=dx9"]);
    let w = rule_with(|l| l.method = Some(ManualMethod::Watch));
    match plan_m(&env.sys, &t, &[], &[], Some(&w)) {
        Err(EngineError::RunNeedsDirect {
            run_from,
            watch_from,
        }) => {
            assert_eq!(run_from, format!("the launch profile of transaction {t1}"));
            assert_eq!(watch_from, "your own settings");
        }
        other => panic!("{other:?}"),
    }
    reverted(&env, &t1);
    // E4 b: own flags live for game.exe refuse DX9 (another executable), naming them.
    let t2 = apply_m(&env, &t, &[], &flags(&["ZZ_FLAG_A"]));
    assert!(matches!(
        plan_m(&env.sys, &t, &[], &["api=dx9"], None),
        Err(EngineError::ExeSwitch { txn, .. }) if txn == t2
    ));
}

// ---------- M6 ----------

#[test]
fn m6_anti_cheat() {
    let env = Env::new(game_sys());
    let t = own_topo();
    anti_cheat_marker(&env.sys);
    let w = rule_with(|l| l.method = Some(ManualMethod::Watch));
    assert!(matches!(
        plan_m(&env.sys, &t, &[], &[], Some(&w)),
        Err(EngineError::ManualAntiCheat {
            step: StepKind::LaunchWatch,
            topo_method: false,
        })
    ));
    assert!(matches!(
        plan_m(&env.sys, &t, &[], &[], Some(&flags(&["ZZ_FLAG_A"]))),
        Err(EngineError::ManualAntiCheat {
            step: StepKind::CompatLayer,
            ..
        })
    ));
    let tp = plan_m(&env.sys, &t, &[], &[], Some(&rule())).unwrap();
    assert_eq!(
        tp.warnings,
        [Warning::ManualAntiCheat {
            step: StepKind::LaunchDirect
        }]
    );
    // Security F4 / senior-dev N4: no method given and the Topo's is `watch` (also `auto` with
    // another launcher in the chain): refused, with the way out named.
    for watched in [
        with_topo(|v| {
            v["launch"]["start"] = serde_json::json!("game.exe");
            v["launch"]["method"] = serde_json::json!("watch");
            v["options"] = serde_json::json!([]);
        }),
        with_topo(|v| {
            v["launch"]["start"] = serde_json::json!("game.exe");
            v["launch"]["chain"] = serde_json::json!(["steam", "upc"]);
            v["options"] = serde_json::json!([]);
        }),
    ] {
        match plan_m(&env.sys, &watched, &[], &[], Some(&rule())) {
            Err(
                e @ EngineError::ManualAntiCheat {
                    step: StepKind::LaunchWatch,
                    topo_method: true,
                },
            ) => assert!(e.to_string().contains("--method direct"), "{e}"),
            other => panic!("{other:?}"),
        }
    }
}

// ---------- M7 ----------

#[test]
fn m7_a_topo_without_a_launch_block_takes_an_own_start() {
    let env = Env::new(game_sys());
    let t = no_launch_topo();
    let before = snap(&env.sys);
    // Without a start: the Topo names no method, refused as before.
    assert!(matches!(
        plan_m(&env.sys, &t, &[], &[], Some(&rule())),
        Err(EngineError::Launch(LaunchProblem::NoMethod))
    ));
    // Own flags need no launch.
    plan_m(&env.sys, &t, &[], &[], Some(&flags(&["ZZ_FLAG_A"]))).unwrap();
    // With an own start (`direct` by default): the profile, the round trip.
    let m = rule_with(|l| l.start = Some(rel("game.exe")));
    let tp = plan_m(&env.sys, &t, &[], &[], Some(&m)).unwrap();
    let p = profile_of(&tp);
    assert_eq!(
        (p.method, p.start.clone()),
        (Method::Direct, abs("game.exe"))
    );
    assert_eq!(p.target, abs("game.exe"));
    assert_eq!(p.priority, Some(Priority::AboveNormal));
    let parts = tp.parts.clone().unwrap();
    assert_eq!(
        (parts.start.clone(), parts.rule.clone(), parts.method),
        (rel("game.exe"), Some(PartFrom::Manual), MethodSpec::Direct)
    );
    assert_eq!(main_exe(&tp), "game.exe");
    assert_eq!(tp.plan.manual, Some(m.clone()));
    let txn = env.applied(&stored(&env.sys, &tp));
    assert!(env.verify(&txn).iter().all(|(_, o)| *o == Observed::After));
    reverted(&env, &txn);
    same(&before, &snap(&env.sys));
    // `watch` chosen: the rule on the main executable.
    let w = rule_with(|l| {
        l.start = Some(rel("game.exe"));
        l.method = Some(ManualMethod::Watch);
    });
    assert_eq!(
        profile_of(&plan_m(&env.sys, &t, &[], &[], Some(&w)).unwrap()).method,
        Method::Watch
    );
    // A start in a folder the anti-cheat scan does not cover.
    env.sys
        .fake_fs()
        .mkdir_all(Path::new(&format!(r"{STEAM_GAME}\sub")))
        .unwrap();
    put(&env.sys, r"sub\launcher.exe", &x86());
    match plan_m(
        &env.sys,
        &t,
        &[],
        &[],
        Some(&rule_with(|l| l.start = Some(rel(r"sub\launcher.exe")))),
    ) {
        Err(EngineError::ManualStartFolder { start }) => assert_eq!(start, r"sub\launcher.exe"),
        other => panic!("{other:?}"),
    }
}
