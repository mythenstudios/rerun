//! LP and LV (P3-3c): the `launch_method` planner and the preview's view of the rule on this
//! computer, against the fake.
//! - LP1 the Stronghold 2 case (start = Steam's launcher entry, main executable = the game):
//!   bitness x86 whenever a program of the chain is i386 (condition A8: a .NET "AnyCPU" launcher
//!   is i386 on disk), the profile bytes and ID pinned.
//! - LP2 every refusal of the planner.
//! - LP3 the start in the spelling stored on disk.
//! - LP4 `--dry-run` without Rerun's folder: the same plan bytes as with it (F1).
//! - LP5 the same rule twice: nothing to do; another rule replaces the profile; a round trip.
//! - LP6 (review S2) a profile plan while the game runs: refused (D4 also for a plan whose only
//!   op is the profile); a profile plan without a main executable is refused by the current rules
//!   (planning, encode, apply) and accepted as a recorded head (B1, E4: its revert then asks no
//!   main executable).
//! - LP8 `file_install`, `registry_set`, `compat_layer` and `launch_method` in one plan: the
//!   profile is op 0, then the file ops, then the registry ops; the round trip is identical. A
//!   profile-only plan on a game folder the user cannot write needs no helper.
//! - LP9 `app_path` other than the path of Rerun's folder refused; a start of exactly 259
//!   characters accepted.
//! - LV1 `on_this_machine` on fixtures: 5950X, hybrid, more than one group, x86 on a group of more
//!   than 32, an unreadable topology, an empty selection, a priority-only profile.
//! - LW (P3-4b, plan `P3-4` §7.4) `method: watch`: LW1 the target is the main executable in the
//!   spelling on disk, soft and priority allowed with a launcher, the bitness from the target
//!   alone, the profile bytes pinned; LW2 start = main executable (a stub) is allowed and the
//!   preview says so; LW3 every refusal of `watch`; LW4 `direct` keeps F5 and points to
//!   `watch`; LW5 `direct` to `watch` replaces the same profile, the same `watch` rule twice is
//!   nothing to do, and a `watch` profile round-trips (apply, verify, revert, identical).

use std::path::Path;

use rerun_proto::cpu::rule::{Bitness, Mode, SelectStep};
use rerun_proto::cpu::{CpuTopology, Llc, LogicalCpu};
use rerun_proto::profile::{self as proto, LaunchProfile, Method};

use super::launch_method::{WATCH_TIMEOUT_S, on_this_machine};
use super::{
    CpuRuleSpec, LaunchMethodSpec, MachineWhy, MethodSpec, ModeSpec, PlanCtx, PrioritySpec, Step,
    plan,
};
use crate::detect::pe::layout::MACHINE_ARM64;
use crate::detect::pe::testfx::Builder as PeBuilder;
use crate::exec::rebind_tests::rb_sys;
use crate::exec::tests::{Env, sys_put, try_read_abs};
use crate::exec::{ApplyError, Outcome, Refusal};
use crate::journal::{Closing, Observed};
use crate::plan::{
    ContentRef, Op, PROFILE_NOTE, PROFILE_WATCH_NOTE, Plan, PlanError, PlanHash, ProfilePreview,
    ProfileShown, RootKind, preview, profile_file, profile_id, store,
};
use crate::policy::registry::RegPolicy;
use crate::policy::root::{AppDir, Create, GameDir, StoreDir};
use crate::prim::tests::{GAME, STEAM_GAME, STEAM_LIB, app, fr, rel};
use crate::sys::fake::FakeSystem;
use crate::sys::fs::tag;
use crate::sys::snapshot::{Scope, SnapRoot, Snapshot, snapshot};
use crate::sys::{SysError, SysErrorKind, System};

const PROFILES: &str = r"C:\Users\Player\AppData\Local\Rerun\profiles";

fn pe_x86() -> Vec<u8> {
    PeBuilder::x86().build().bytes
}

fn pe_x64() -> Vec<u8> {
    PeBuilder::x64().build().bytes
}

fn pe_arm64() -> Vec<u8> {
    PeBuilder {
        machine: MACHINE_ARM64,
        ..PeBuilder::x64()
    }
    .build()
    .bytes
}

/// Replaces (or creates) the fake file `abs` with `data`.
fn put(sys: &FakeSystem, abs: &str, data: &[u8]) {
    let _ = sys.fake_fs().remove_abs(Path::new(abs));
    sys_put(sys, abs, data);
    sys.sync_all();
}

fn game(name: &str) -> String {
    format!(r"{STEAM_GAME}\{name}")
}

/// Steam with app 220 in `G`: `game.exe` (`game`), `FFLauncher.exe` (`launcher`), and further
/// executables for the refusals.
fn lp_sys(game_pe: &[u8], launcher: &[u8]) -> FakeSystem {
    let sys = rb_sys();
    put(&sys, &game("game.exe"), game_pe);
    put(&sys, &game("FFLauncher.exe"), launcher);
    put(&sys, &game("arm.exe"), &pe_arm64());
    put(&sys, &game("text.exe"), b"MZ not an image");
    put(&sys, &game("readme.txt"), b"text");
    sys.fake_fs()
        .mkdir_all(Path::new(&game("dir.exe")))
        .unwrap();
    sys.sync_all();
    sys
}

fn spec(start: &str) -> LaunchMethodSpec {
    LaunchMethodSpec {
        method: MethodSpec::Direct,
        start: rel(start),
        cpu: Some(CpuRuleSpec {
            max_threads: Some(8),
            single_l3: Some(true),
            smt: Some(false),
            ..CpuRuleSpec::default()
        }),
        priority: None,
    }
}

/// Plans `steps` for app 220 with main executable `main`; `app`: Rerun's folder is open.
fn plan_lm(sys: &FakeSystem, steps: &[Step], main: &str) -> Result<Plan, PlanError> {
    let fr = fr(sys);
    let store = StoreDir::open(sys, &fr, Path::new(STEAM_LIB)).unwrap();
    let g = store.game(&fr, "G").unwrap();
    let a = app(sys);
    let main = rel(main);
    plan(
        steps,
        &PlanCtx {
            game: &g,
            app: Some(&a),
            steam_app: Some(220),
            main_exe: Some(&main),
            reg: RegPolicy.reader(sys),
            app_path: None,
        },
    )
}

fn one(s: LaunchMethodSpec) -> Vec<Step> {
    vec![Step::LaunchMethod(s)]
}

/// The profile of op 0 of `p`.
fn profile_of(p: &Plan) -> LaunchProfile {
    let (Op::CreateFile { content, .. } | Op::ReplaceFile { content, .. }) = &p.ops[0] else {
        panic!("{:?}", p.ops[0])
    };
    let ContentRef::Inline { bytes, .. } = content else {
        panic!("{content:?}")
    };
    proto::decode(bytes).unwrap()
}

#[test]
fn lp1_a_launcher_entry_with_an_i386_game_or_launcher_is_x86() {
    // (launcher, game, bitness): a .NET "AnyCPU" launcher is i386 on disk (A8), and so is an
    // x86 game; only both x64 give x64.
    let cases = [
        (pe_x86(), pe_x86(), Bitness::X86),
        (pe_x64(), pe_x86(), Bitness::X86),
        (pe_x86(), pe_x64(), Bitness::X86),
        (pe_x64(), pe_x64(), Bitness::X64),
    ];
    for (launcher, game_pe, want) in cases {
        let sys = lp_sys(&game_pe, &launcher);
        let p = plan_lm(&sys, &one(spec("FFLauncher.exe")), "game.exe").unwrap();
        assert_eq!(p.roots.len(), 2);
        assert_eq!(p.roots[1].kind, RootKind::Profiles);
        assert_eq!(p.roots[1].path.to_string(), PROFILES);
        assert_eq!(profile_of(&p).bitness, want);
    }
    let sys = lp_sys(&pe_x86(), &pe_x86());
    let p = plan_lm(&sys, &one(spec("FFLauncher.exe")), "game.exe").unwrap();
    let Op::CreateFile { path, content, .. } = &p.ops[0] else {
        panic!("{:?}", p.ops[0])
    };
    assert_eq!(path, &profile_file(profile_id(220)));
    assert_eq!(
        path.as_str(),
        "323ad79fbc93ca3e73b0b152a5d44616.profile",
        "E1 a: from the app ID"
    );
    let ContentRef::Inline { bytes, .. } = content else {
        panic!()
    };
    assert_eq!(
        std::str::from_utf8(bytes).unwrap(),
        "rerun-profile 1\n\
         method=direct\n\
         start=D:\\SteamLibrary\\steamapps\\common\\G\\FFLauncher.exe\n\
         target=D:\\SteamLibrary\\steamapps\\common\\G\\FFLauncher.exe\n\
         bitness=x86\n\
         priority=none\n\
         watch_timeout_s=120\n\
         cpu=rule\n\
         cpu.prefer=any\n\
         cpu.single_l3=true\n\
         cpu.prefer_l3=none\n\
         cpu.smt=false\n\
         cpu.mode=hard\n\
         cpu.max_threads=8\n"
    );
    assert_eq!(WATCH_TIMEOUT_S, 120);
    // Start = main executable: soft and priority allowed.
    let mut s = spec("game.exe");
    s.priority = Some(PrioritySpec::AboveNormal);
    if let Some(c) = &mut s.cpu {
        c.mode = Some(ModeSpec::Soft);
    }
    let p = plan_lm(&sys, &one(s), "game.exe").unwrap();
    let pr = profile_of(&p);
    assert_eq!(pr.method, Method::Direct);
    assert_eq!(pr.cpu.unwrap().mode, Mode::Soft);
    assert!(pr.priority.is_some());
    // A priority-only profile.
    let mut s = spec("game.exe");
    s.cpu = None;
    s.priority = Some(PrioritySpec::High);
    assert!(
        profile_of(&plan_lm(&sys, &one(s), "game.exe").unwrap())
            .cpu
            .is_none()
    );
}

#[test]
fn lp2_every_refusal_of_the_planner() {
    type Case = (&'static str, fn(&mut LaunchMethodSpec), &'static str);
    let cases: Vec<Case> = vec![
        ("auto", |s| s.method = MethodSpec::Auto, "auto"),
        (
            "report_cores",
            |s| {
                if let Some(c) = &mut s.cpu {
                    c.report_cores = Some(8);
                }
            },
            "report_cores",
        ),
        (
            "neither cpu nor priority",
            |s| s.cpu = None,
            "neither cpu nor priority",
        ),
        (
            "cpu {}",
            |s| s.cpu = Some(CpuRuleSpec::default()),
            "restricts nothing",
        ),
        (
            "max_threads 0",
            |s| {
                if let Some(c) = &mut s.cpu {
                    c.max_threads = Some(0);
                }
            },
            "1 to 1024",
        ),
        (
            "max_threads 1025",
            |s| {
                if let Some(c) = &mut s.cpu {
                    c.max_threads = Some(1025);
                }
            },
            "1 to 1024",
        ),
        ("start missing", |s| s.start = rel("nope.exe"), "missing"),
        (
            "start no .exe",
            |s| s.start = rel("readme.txt"),
            "not an .exe",
        ),
        (
            "start a folder",
            |s| s.start = rel("dir.exe"),
            "not a plain file",
        ),
        (
            "start ARM64",
            |s| s.start = rel("arm.exe"),
            "neither x86 nor x64",
        ),
        (
            "start no PE",
            |s| s.start = rel("text.exe"),
            "no Windows executable",
        ),
        (
            "launcher with soft",
            |s| {
                if let Some(c) = &mut s.cpu {
                    c.mode = Some(ModeSpec::Soft);
                }
            },
            "mode soft",
        ),
        (
            "launcher with priority",
            |s| s.priority = Some(PrioritySpec::Normal),
            "priority class",
        ),
    ];
    let sys = lp_sys(&pe_x86(), &pe_x64());
    for (what, m, want) in cases {
        let mut s = spec("FFLauncher.exe");
        m(&mut s);
        let e = plan_lm(&sys, &one(s), "game.exe")
            .expect_err(what)
            .to_string();
        assert!(e.contains(want), "{what}: {e}");
    }
    let e = |r: Result<Plan, PlanError>| r.expect_err("refused").to_string();
    // A second step.
    let two = vec![
        Step::LaunchMethod(spec("game.exe")),
        Step::LaunchMethod(spec("game.exe")),
    ];
    assert!(e(plan_lm(&sys, &two, "game.exe")).contains("second launch_method"));
    // The main executable is not a PE image (F6 reads it too).
    put(&sys, &game("game.exe"), b"MZ");
    assert!(e(plan_lm(&sys, &one(spec("FFLauncher.exe")), "game.exe")).contains("game.exe"));
    put(&sys, &game("game.exe"), &pe_x86());
    // A link on the way and a case-sensitive folder.
    sys.fake_fs()
        .put_link(Path::new(&game("bin")), tag::MOUNT_POINT, r"C:\Out")
        .unwrap();
    let r = e(plan_lm(&sys, &one(spec(r"bin\x.exe")), "game.exe"));
    assert!(
        r.contains("not a plain folder") || r.contains("link"),
        "{r}"
    );
    sys.fake_fs().mkdir_all(Path::new(&game("cs"))).unwrap();
    sys.fake_fs()
        .set_case_sensitive(Path::new(&game("cs")), true)
        .unwrap();
    put(&sys, &game(r"cs\x.exe"), &pe_x64());
    assert!(e(plan_lm(&sys, &one(spec(r"cs\x.exe")), "game.exe")).contains("case-sensitive"));
    // Restricted.
    put(&sys, &game("locked.exe"), &pe_x64());
    sys.fake_fs()
        .set_restricted(Path::new(&game("locked.exe")), true)
        .unwrap();
    let r = e(plan_lm(&sys, &one(spec("locked.exe")), "game.exe"));
    assert!(r.contains("not a plain file"), "{r}");
    // A start path of 260 characters (F7).
    let long = format!(r"{}\{}.exe", "a".repeat(200), "b".repeat(20));
    put(&sys, &game(&long), &pe_x64());
    assert_eq!(game(&long).encode_utf16().count(), 260);
    assert!(e(plan_lm(&sys, &one(spec(&long)), &long)).contains("longer than 259"));
    // A profile at the name that is not Rerun's to replace (F10 of the plan's §4).
    let name = format!(r"{PROFILES}\{}", profile_file(profile_id(220)));
    type Planted = (&'static str, fn(&FakeSystem, &str));
    let planted: [Planted; 4] = [
        ("larger than 8 KiB", |s, p| {
            put(s, p, &vec![b'x'; (8 << 10) + 1])
        }),
        ("a folder", |s, p| {
            s.fake_fs().mkdir_all(Path::new(p)).unwrap()
        }),
        ("a link", |s, p| {
            s.fake_fs()
                .put_link(Path::new(p), tag::SYMLINK, r"C:\Out\x")
                .unwrap();
        }),
        ("hard-linked", |s, p| {
            put(s, p, b"old");
            s.fake_fs()
                .put_hardlink(Path::new(p), Path::new(&format!(r"{PROFILES}\l")))
                .unwrap();
        }),
    ];
    for (what, plant) in planted {
        let sys = lp_sys(&pe_x86(), &pe_x86());
        sys.fake_fs().mkdir_all(Path::new(PROFILES)).unwrap();
        plant(&sys, &name);
        let r = plan_lm(&sys, &one(spec("game.exe")), "game.exe");
        assert!(e(r).contains("Rerun leaves it"), "{what}");
    }
    // A manual folder (no launch option without Steam).
    let sys = lp_sys(&pe_x86(), &pe_x86());
    put(&sys, &format!(r"{GAME}\game.exe"), &pe_x86());
    let fr = fr(&sys);
    let g = GameDir::open_manual(&sys, &fr, Path::new(GAME)).unwrap();
    let a = app(&sys);
    let main = rel("game.exe");
    let r = plan(
        &one(spec("game.exe")),
        &PlanCtx {
            game: &g,
            app: Some(&a),
            steam_app: None,
            main_exe: Some(&main),
            reg: RegPolicy.reader(&sys),
            app_path: None,
        },
    );
    assert!(e(r).contains("only for a Steam game"));
    // A library reached through a junction (F4).
    sys.fake_fs()
        .put_link(Path::new(r"D:\Lib2"), tag::MOUNT_POINT, STEAM_LIB)
        .unwrap();
    let store = StoreDir::open(&sys, &fr, Path::new(r"D:\Lib2")).unwrap();
    let g = store.game(&fr, "G").unwrap();
    let r = plan(
        &one(spec("game.exe")),
        &PlanCtx {
            game: &g,
            app: Some(&a),
            steam_app: Some(220),
            main_exe: Some(&main),
            reg: RegPolicy.reader(&sys),
            app_path: None,
        },
    );
    assert!(e(r).contains("through a link"));
}

#[test]
fn lp3_the_start_is_named_in_the_spelling_on_disk() {
    let sys = lp_sys(&pe_x86(), &pe_x86());
    let p = plan_lm(&sys, &one(spec("fflauncher.EXE")), "GAME.exe").unwrap();
    assert_eq!(
        profile_of(&p).start,
        r"D:\SteamLibrary\steamapps\common\G\FFLauncher.exe"
    );
    // Start and main executable compared folded: `GAME.exe` is `game.exe`, no launcher case.
    let mut s = spec("game.EXE");
    s.priority = Some(PrioritySpec::High);
    let p = plan_lm(&sys, &one(s), "GAME.exe").unwrap();
    assert_eq!(
        profile_of(&p).start,
        r"D:\SteamLibrary\steamapps\common\G\game.exe"
    );
}

#[test]
fn lp4_a_dry_run_without_rerun_s_folder_gives_the_same_plan() {
    let sys = lp_sys(&pe_x86(), &pe_x86());
    let lad = r"C:\Users\Player\AppData\Local";
    if AppDir::open(&sys, Create::Never).unwrap().is_some() {
        crate::exec::rebind_tests::remove_tree(&sys, &format!(r"{lad}\Rerun"));
    }
    assert!(AppDir::open(&sys, Create::Never).unwrap().is_none());
    let path = AppDir::path_of(&sys).unwrap();
    let fr = fr(&sys);
    let store = StoreDir::open(&sys, &fr, Path::new(STEAM_LIB)).unwrap();
    let g = store.game(&fr, "G").unwrap();
    let main = rel("game.exe");
    let ctx = |app, app_path| PlanCtx {
        game: &g,
        app,
        steam_app: Some(220),
        main_exe: Some(&main),
        reg: RegPolicy.reader(&sys),
        app_path,
    };
    let dry = plan(&one(spec("FFLauncher.exe")), &ctx(None, Some(&path))).unwrap();
    assert!(
        crate::exec::tests::try_read_abs(&sys, &format!(r"{lad}\Rerun\x")).is_none()
            && AppDir::open(&sys, Create::Never).unwrap().is_none(),
        "nothing created"
    );
    // Without either, the planner does not guess.
    assert!(plan(&one(spec("FFLauncher.exe")), &ctx(None, None)).is_err());
    let a = AppDir::open(&sys, Create::IfMissing).unwrap().unwrap();
    let real = plan(&one(spec("FFLauncher.exe")), &ctx(Some(&a), None)).unwrap();
    assert_eq!(dry.encode().unwrap(), real.encode().unwrap());
    let both = plan(&one(spec("FFLauncher.exe")), &ctx(Some(&a), Some(&path))).unwrap();
    assert_eq!(both, real);
}

/// Plans and stores `steps` on `env`.
fn stored(env: &Env, steps: &[Step]) -> PlanHash {
    let p = plan_lm(&env.sys, steps, "game.exe").unwrap();
    store(&app(&env.sys), &p.encode().unwrap()).unwrap()
}

/// The game folder and `profiles`.
fn snap_all(sys: &FakeSystem) -> Snapshot {
    let fr = fr(sys);
    let g = GameDir::open_manual(sys, &fr, Path::new(STEAM_GAME)).unwrap();
    let a = app(sys);
    snapshot(
        sys.registry(),
        &Scope {
            dirs: vec![
                SnapRoot::new(g.dir(), STEAM_GAME),
                SnapRoot::new(a.dir(), a.path().to_string()).below(rel("profiles")),
            ],
            keys: Vec::new(),
        },
    )
    .unwrap()
}

#[test]
fn lp5_the_same_rule_twice_is_nothing_to_do_and_a_round_trip_restores_everything() {
    let env = Env::new(lp_sys(&pe_x86(), &pe_x86()));
    env.sys.fake_fs().mkdir_all(Path::new(PROFILES)).unwrap();
    let before = snap_all(&env.sys);
    let t = env.applied(&stored(&env, &one(spec("FFLauncher.exe"))));
    let name = format!(r"{PROFILES}\{}", profile_file(profile_id(220)));
    let bytes = try_read_abs(&env.sys, &name).unwrap();
    // The same rule again: no op, no transaction.
    let p = plan_lm(&env.sys, &one(spec("FFLauncher.exe")), "game.exe").unwrap();
    assert!(p.ops.is_empty(), "{:?}", p.ops);
    let h = store(&app(&env.sys), &p.encode().unwrap()).unwrap();
    assert!(matches!(env.apply(&h), Ok(Outcome::Nothing)));
    // Another rule replaces Rerun's profile (LIFO with the first transaction).
    let mut s = spec("FFLauncher.exe");
    if let Some(c) = &mut s.cpu {
        c.max_threads = Some(4);
    }
    let p = plan_lm(&env.sys, &one(s.clone()), "game.exe").unwrap();
    assert!(matches!(&p.ops[0], Op::ReplaceFile { .. }));
    let t2 = env.applied(&store(&app(&env.sys), &p.encode().unwrap()).unwrap());
    assert_eq!(env.revert(&t2).unwrap().closed, Some(Closing::Reverted));
    assert_eq!(try_read_abs(&env.sys, &name), Some(bytes));
    assert_eq!(env.revert(&t).unwrap().closed, Some(Closing::Reverted));
    assert!(
        before == snap_all(&env.sys),
        "{:#?}",
        before.diff(&snap_all(&env.sys))
    );
}

#[test]
fn lp6_a_profile_plan_while_the_game_runs_is_refused() {
    let env = Env::new(lp_sys(&pe_x86(), &pe_x86()));
    let h = stored(&env, &one(spec("FFLauncher.exe")));
    let hold = env
        .sys
        .fake_fs()
        .hold_open_as(
            4242,
            Path::new(&game("game.exe")),
            crate::sys::contract::Access::READ,
            crate::sys::contract::Share::RWD,
        )
        .unwrap();
    let r = env.apply(&h);
    assert!(
        matches!(&r, Err(ApplyError::Refused(Refusal::Busy(_)))),
        "{r:?}"
    );
    drop(hold);
    let t = env.applied(&h);
    // And the revert, D4 again.
    let hold = env
        .sys
        .fake_fs()
        .hold_open_as(
            4242,
            Path::new(&game("game.exe")),
            crate::sys::contract::Access::READ,
            crate::sys::contract::Share::RWD,
        )
        .unwrap();
    let r = env.revert(&t);
    assert!(
        matches!(&r, Err(crate::exec::ExecError::Refused(Refusal::Busy(_)))),
        "{r:?}"
    );
    drop(hold);
    assert_eq!(env.revert(&t).unwrap().closed, Some(Closing::Reverted));
    // The format (Current): a profile plan without the game's main executable.
    let mut p = plan_lm(&env.sys, &one(spec("FFLauncher.exe")), "game.exe").unwrap();
    p.roots[0].main_exe = None;
    let e = p.encode().unwrap_err().to_string();
    assert!(e.contains("main executable"), "{e}");
    // A recorded head keeps only the form (B1, E4).
    let bytes = serde_json::to_vec(&p).unwrap();
    assert!(crate::plan::decode(&bytes).is_err());
    assert_eq!(crate::plan::decode_recorded(&bytes).unwrap(), p);
}

#[test]
fn lp8_a_profile_with_file_and_registry_ops_orders_them_and_round_trips() {
    let env = Env::new(lp_sys(&pe_x86(), &pe_x86()));
    env.sys.fake_fs().mkdir_all(Path::new(PROFILES)).unwrap();
    let mut steps = crate::exec::rebind_tests::rb_steps(false);
    steps.push(Step::LaunchMethod(spec("FFLauncher.exe")));
    let p = plan_lm(&env.sys, &steps, "game.exe").unwrap();
    assert_eq!(p.roots[1].kind, RootKind::Profiles);
    assert!(matches!(&p.ops[0], Op::CreateFile { root, .. } if root.0 == 1));
    let kinds: Vec<u8> = p
        .ops
        .iter()
        .map(|o| match o.target() {
            crate::plan::Target::File { root, .. } if root.0 == 1 => 0,
            crate::plan::Target::File { .. } => 1,
            _ => 2,
        })
        .collect();
    assert!(kinds.windows(2).all(|w| w[0] <= w[1]), "{kinds:?}");
    assert_eq!(kinds.iter().filter(|k| **k == 0).count(), 1);
    assert!(kinds.contains(&1) && kinds.contains(&2), "{kinds:?}");
    let snap = |sys: &FakeSystem| (snap_all(sys), crate::exec::rebind_tests::keys(sys));
    let before = snap(&env.sys);
    let h = store(&app(&env.sys), &p.encode().unwrap()).unwrap();
    let t = env.applied(&h);
    assert_eq!(env.revert(&t).unwrap().closed, Some(Closing::Reverted));
    let after = snap(&env.sys);
    assert!(
        before.0 == after.0 && before.1 == after.1,
        "{:#?} {:#?}",
        before.0.diff(&after.0),
        before.1.diff(&after.1)
    );

    // A profile-only plan on a game folder the user cannot write: nothing is written there.
    let sys = lp_sys(&pe_x86(), &pe_x86());
    sys.fake_fs()
        .set_user_writable(Path::new(STEAM_GAME), false)
        .unwrap();
    let p = plan_lm(&sys, &one(spec("FFLauncher.exe")), "game.exe").unwrap();
    assert_eq!(p.ops.len(), 1);
    // With a file op in the game folder: the elevated helper (phase 4).
    let mut steps = vec![Step::FileInstall(crate::exec::tests::t1_spec())];
    steps.push(Step::LaunchMethod(spec("FFLauncher.exe")));
    assert!(matches!(
        plan_lm(&sys, &steps, "game.exe"),
        Err(PlanError::NeedsHelper)
    ));
}

#[test]
fn lp9_another_app_path_is_refused_and_259_characters_are_accepted() {
    let sys = lp_sys(&pe_x86(), &pe_x86());
    let fr = fr(&sys);
    let store = StoreDir::open(&sys, &fr, Path::new(STEAM_LIB)).unwrap();
    let g = store.game(&fr, "G").unwrap();
    let a = app(&sys);
    let main = rel("game.exe");
    let other = crate::path::RootPath::new(r"C:\Users\Other\AppData\Local\Rerun").unwrap();
    let r = plan(
        &one(spec("FFLauncher.exe")),
        &PlanCtx {
            game: &g,
            app: Some(&a),
            steam_app: Some(220),
            main_exe: Some(&main),
            reg: RegPolicy.reader(&sys),
            app_path: Some(&other),
        },
    );
    let e = r.expect_err("another app path").to_string();
    assert!(e.contains("Rerun's folder changed"), "{e}");
    // F7: 259 UTF-16 units is the limit, not over it.
    let long = format!(r"{}\{}.exe", "a".repeat(200), "b".repeat(19));
    put(&sys, &game(&long), &pe_x64());
    assert_eq!(game(&long).encode_utf16().count(), 259);
    let p = plan_lm(&sys, &one(spec(&long)), &long).unwrap();
    assert_eq!(profile_of(&p).start, game(&long));
}

const RYZEN_5950X: &str = include_str!("../../../../tests/fixtures/cpu/ryzen9-5950x.json");
const I9_14900K: &str = include_str!("../../../../tests/fixtures/cpu/i9-14900k.json");
const TR_7980X: &str = include_str!("../../../../tests/fixtures/cpu/threadripper-7980x.json");

fn topo(json: &str) -> CpuTopology {
    serde_json::from_str(json).unwrap()
}

fn profile(rule: CpuRuleSpec, bitness: Bitness) -> LaunchProfile {
    LaunchProfile {
        method: Method::Direct,
        start: r"D:\G\game.exe".to_owned(),
        target: r"D:\G\game.exe".to_owned(),
        bitness,
        priority: None,
        watch_timeout_s: WATCH_TIMEOUT_S,
        cpu: Some(rule.rule().unwrap()),
    }
}

#[test]
fn lv1_the_rule_on_this_machine() {
    // 5950X: 8 of 32, cores 0 to 7, L3 #0 (32 MiB), one group.
    let rule = CpuRuleSpec {
        max_threads: Some(8),
        single_l3: Some(true),
        smt: Some(false),
        ..CpuRuleSpec::default()
    };
    let v = on_this_machine(Ok(topo(RYZEN_5950X)), &profile(rule, Bitness::X64));
    let s = v.selection.unwrap();
    assert_eq!((s.threads, s.of, s.group, s.mask), (8, 32, 0, 0x5555));
    assert_eq!(s.cores, (0..8).collect::<Vec<u32>>());
    assert_eq!(s.llc, Some((0, 3, 32 << 20)));
    assert_eq!(s.mode, Mode::Hard);
    assert_eq!(v.groups, 1);
    assert!(!v.x86_capped);
    // Hybrid: the performance class only.
    let perf = CpuRuleSpec {
        prefer: Some(super::PreferSpec::Performance),
        ..CpuRuleSpec::default()
    };
    let v = on_this_machine(Ok(topo(I9_14900K)), &profile(perf, Bitness::X64));
    let s = v.selection.unwrap();
    assert!(s.threads < s.of, "{s:?}");
    // More than one group, and a 32-bit game on a group of 64.
    let any = CpuRuleSpec {
        smt: Some(true),
        ..CpuRuleSpec::default()
    };
    let v = on_this_machine(Ok(topo(TR_7980X)), &profile(any, Bitness::X86));
    assert_eq!(v.groups, 2);
    assert!(v.x86_capped);
    assert_eq!(v.selection.unwrap().threads, 32);
    let v = on_this_machine(Ok(topo(TR_7980X)), &profile(any, Bitness::X64));
    assert!(!v.x86_capped);
    // The topology cannot be read: the shim decides at every start.
    let v = on_this_machine(
        Err(SysError::new(
            SysErrorKind::Unsupported,
            "no topology \x1b[31m",
        )),
        &profile(any, Bitness::X64),
    );
    match v.selection {
        Err(MachineWhy::Topology(why)) => assert!(!why.contains('\x1b'), "{why}"),
        other => panic!("{other:?}"),
    }
    // Nothing left: a group whose processors all lie at index 32 and above, for x86.
    let high = CpuTopology {
        cpus: vec![LogicalCpu {
            cpu_set_id: 0x120,
            group: 0,
            index: 40,
            core: 0,
            llc: 0,
            efficiency_class: 0,
        }],
        llcs: vec![Llc {
            level: 3,
            size: 1 << 20,
        }],
    };
    let v = on_this_machine(Ok(high), &profile(any, Bitness::X86));
    assert!(
        matches!(
            v.selection,
            Err(MachineWhy::Empty {
                after: SelectStep::Bitness
            })
        ),
        "{:?}",
        v.selection
    );
    // A priority-only profile has no rule to show.
    let mut p = profile(any, Bitness::X64);
    p.cpu = None;
    assert_eq!(
        on_this_machine(Ok(topo(RYZEN_5950X)), &p).selection,
        Err(MachineWhy::NoRule)
    );
}

#[test]
fn lp7_the_step_parses_from_a_step_file_and_refuses_unknown_fields() {
    let sf = br#"{"format":1,"game":{"steam":40960},"main_exe":"Stronghold2.exe","steps":[{"launch_method":{"method":"direct","start":"FFLauncher.exe","cpu":{"max_threads":8,"single_l3":true,"smt":false}}}]}"#;
    let f = super::StepFile::parse(sf).unwrap();
    assert!(matches!(&f.steps[0], Step::LaunchMethod(s) if s.start.as_str() == "FFLauncher.exe"));
    for bad in [
        r#"{"method":"hold","start":"a.exe","priority":"high"}"#,
        r#"{"method":"direct","start":"a.exe","cpu":{"threads":[0,1]}}"#,
        r#"{"method":"direct","start":"a.exe","priority":"realtime"}"#,
        r#"{"method":"direct","start":"C:\\a.exe","priority":"high"}"#,
        r#"{"method":"direct","start":"a.exe","priority":"high","x":1}"#,
    ] {
        let s = format!(
            r#"{{"format":1,"game":{{"steam":1}},"main_exe":"a.exe","steps":[{{"launch_method":{bad}}}]}}"#
        );
        assert!(super::StepFile::parse(s.as_bytes()).is_err(), "{bad}");
    }
}

#[test]
fn c_lm1_the_launch_option_is_shown_as_it_is_or_not_at_all() {
    let id = profile_id(220);
    let o = super::steam_option_text(
        Path::new(r"C:\Users\Player\AppData\Local\Programs\Rerun"),
        id,
    )
    .unwrap();
    assert_eq!(
        o.as_str(),
        r#""C:\Users\Player\AppData\Local\Programs\Rerun\rerun-launch.exe" --profile 323ad79fbc93ca3e73b0b152a5d44616 %command%"#
    );
    // An install folder on a drive root (review of P3-3c): one backslash.
    let o = super::steam_option_text(Path::new(r"C:\"), id).unwrap();
    assert_eq!(
        o.as_str(),
        r#""C:\rerun-launch.exe" --profile 323ad79fbc93ca3e73b0b152a5d44616 %command%"#
    );
    // A path that escape::path would change is never offered in its escaped form.
    for bad in [
        "C:\\Pro\u{202e}gram\\Rerun",
        "C:\\R\u{1b}[2Jerun",
        "C:\\R\u{200b}erun",
    ] {
        assert!(
            super::steam_option_text(Path::new(bad), id).is_none(),
            "{bad:?}"
        );
    }
}

fn watch(start: &str) -> LaunchMethodSpec {
    LaunchMethodSpec {
        method: MethodSpec::Watch,
        ..spec(start)
    }
}

/// `watch` with a soft rule and priority high (the Stronghold 2 case of D-W1).
fn watch_soft_high(start: &str) -> LaunchMethodSpec {
    let mut s = watch(start);
    s.priority = Some(PrioritySpec::High);
    if let Some(c) = &mut s.cpu {
        c.mode = Some(ModeSpec::Soft);
    }
    s
}

/// The decoded profile of the preview of `p`.
fn shown_of(p: &Plan) -> (crate::plan::Preview, ProfileShown) {
    let pv = preview(p);
    let Some(ProfilePreview::Decoded(s)) = &pv.ops[0].profile else {
        panic!("{:?}", pv.ops[0].profile)
    };
    let s = (**s).clone();
    (pv, s)
}

const G_GAME: &str = r"D:\SteamLibrary\steamapps\common\G\game.exe";

#[test]
fn lw1_watch_targets_the_main_executable_with_soft_and_priority_allowed() {
    // A launcher entry (x64) and an i386 game: soft and priority are allowed (they land on the
    // game), the target is the main executable in the spelling on disk, x86 from the target.
    let sys = lp_sys(&pe_x86(), &pe_x64());
    let p = plan_lm(&sys, &one(watch_soft_high("FFLauncher.exe")), "GAME.exe").unwrap();
    let Some(ContentRef::Inline { bytes, .. }) = p.ops[0].content() else {
        panic!("{:?}", p.ops[0])
    };
    assert_eq!(
        std::str::from_utf8(bytes).unwrap(),
        "rerun-profile 1\n\
         method=watch\n\
         start=D:\\SteamLibrary\\steamapps\\common\\G\\FFLauncher.exe\n\
         target=D:\\SteamLibrary\\steamapps\\common\\G\\game.exe\n\
         bitness=x86\n\
         priority=high\n\
         watch_timeout_s=120\n\
         cpu=rule\n\
         cpu.prefer=any\n\
         cpu.single_l3=true\n\
         cpu.prefer_l3=none\n\
         cpu.smt=false\n\
         cpu.mode=soft\n\
         cpu.max_threads=8\n"
    );
    // The same file as `direct` (P6): one profile per app.
    let Op::CreateFile { path, .. } = &p.ops[0] else {
        panic!("{:?}", p.ops[0])
    };
    assert_eq!(path, &profile_file(profile_id(220)));
    // Bitness from the target alone (P3): an i386 launcher does not make an x64 game x86, and
    // the start's image is not read (a start that is no PE image is fine with `watch`).
    for (launcher, game_pe, want) in [
        (pe_x86(), pe_x64(), Bitness::X64),
        (pe_x64(), pe_x86(), Bitness::X86),
        (b"MZ not an image".to_vec(), pe_x64(), Bitness::X64),
    ] {
        let sys = lp_sys(&game_pe, &launcher);
        let p = plan_lm(&sys, &one(watch("FFLauncher.exe")), "game.exe").unwrap();
        assert_eq!(profile_of(&p).bitness, want);
        assert_eq!(profile_of(&p).method, Method::Watch);
    }
    // A priority-only profile.
    let mut s = watch("FFLauncher.exe");
    s.cpu = None;
    s.priority = Some(PrioritySpec::Normal);
    let pr = profile_of(&plan_lm(&sys, &one(s), "game.exe").unwrap());
    assert!(pr.cpu.is_none() && pr.priority.is_some());
    // The preview: no launcher (the check covers the game), no stub, the watch note.
    let p = plan_lm(&sys, &one(watch("FFLauncher.exe")), "game.exe").unwrap();
    let (pv, s) = shown_of(&p);
    assert!(!s.launcher && !s.stub);
    assert_eq!(s.method, "watch");
    assert_eq!(s.target.as_str(), G_GAME);
    assert_eq!(pv.profiles, Some(PROFILE_WATCH_NOTE));
    assert!(
        pv.to_string().contains(&format!("     target {G_GAME}")),
        "{pv}"
    );
}

#[test]
fn lw2_watch_with_the_game_as_start_is_a_stub() {
    let sys = lp_sys(&pe_x64(), &pe_x64());
    let p = plan_lm(&sys, &one(watch_soft_high("game.EXE")), "GAME.exe").unwrap();
    let pr = profile_of(&p);
    assert_eq!(pr.start, pr.target);
    assert_eq!(pr.target, G_GAME);
    let (pv, s) = shown_of(&p);
    assert!(s.stub && !s.launcher);
    // The core display names the target of a stub too.
    assert!(
        pv.to_string().contains(&format!("     target {G_GAME}")),
        "{pv}"
    );
    // `direct` with start = main: neither a launcher nor a stub, the `direct` note.
    let (pv, s) = shown_of(&plan_lm(&sys, &one(spec("game.exe")), "game.exe").unwrap());
    assert!(!s.stub && !s.launcher);
    assert_eq!(pv.profiles, Some(PROFILE_NOTE));
    // `direct` with a launcher: the launcher flag, never the stub.
    let (_, s) = shown_of(&plan_lm(&sys, &one(spec("FFLauncher.exe")), "game.exe").unwrap());
    assert!(s.launcher && !s.stub);
}

#[test]
fn lw3_every_refusal_of_watch() {
    let e = |r: Result<Plan, PlanError>| r.expect_err("refused").to_string();
    let sys = lp_sys(&pe_x86(), &pe_x64());
    // The main executable: ARM64, no PE image, no .exe, missing.
    for (main, want) in [
        ("arm.exe", "neither x86 nor x64"),
        ("text.exe", "no Windows executable"),
        ("readme.txt", "readme.txt"),
        ("nope.exe", "nope.exe"),
    ] {
        let r = e(plan_lm(&sys, &one(watch("FFLauncher.exe")), main));
        assert!(r.contains(want), "{main}: {r}");
    }
    // The start must still be a plain .exe of the game folder.
    for (start, want) in [
        ("readme.txt", "not an .exe"),
        ("dir.exe", "not a plain file"),
        ("nope.exe", "missing"),
    ] {
        let r = e(plan_lm(&sys, &one(watch(start)), "game.exe"));
        assert!(r.contains(want), "{start}: {r}");
    }
    // A target of 260 characters (P4), with a short start; 259 is accepted.
    let long = format!(r"{}\{}.exe", "a".repeat(200), "b".repeat(20));
    put(&sys, &game(&long), &pe_x64());
    assert_eq!(game(&long).encode_utf16().count(), 260);
    let r = e(plan_lm(&sys, &one(watch("FFLauncher.exe")), &long));
    assert!(
        r.contains("the target path") && r.contains("longer than 259"),
        "{r}"
    );
    let ok = format!(r"{}\{}.exe", "a".repeat(200), "b".repeat(19));
    put(&sys, &game(&ok), &pe_x64());
    let p = plan_lm(&sys, &one(watch("FFLauncher.exe")), &ok).unwrap();
    assert_eq!(profile_of(&p).target, game(&ok));
    // A start of 260 characters with a short target.
    let r = e(plan_lm(&sys, &one(watch(&long)), "game.exe"));
    assert!(
        r.contains("the start path") && r.contains("longer than 259"),
        "{r}"
    );
    // `auto` names both methods.
    let mut s = watch("FFLauncher.exe");
    s.method = MethodSpec::Auto;
    assert!(e(plan_lm(&sys, &one(s), "game.exe")).contains("name direct or watch"));
    // A manual folder (no launch option without Steam).
    put(&sys, &format!(r"{GAME}\game.exe"), &pe_x86());
    let fr = fr(&sys);
    let g = GameDir::open_manual(&sys, &fr, Path::new(GAME)).unwrap();
    let a = app(&sys);
    let main = rel("game.exe");
    let r = plan(
        &one(watch("game.exe")),
        &PlanCtx {
            game: &g,
            app: Some(&a),
            steam_app: None,
            main_exe: Some(&main),
            reg: RegPolicy.reader(&sys),
            app_path: None,
        },
    );
    assert!(e(r).contains("only for a Steam game"));
}

#[test]
fn lw4_direct_keeps_refusing_soft_and_priority_on_a_launcher() {
    let sys = lp_sys(&pe_x86(), &pe_x64());
    let mut s = watch_soft_high("FFLauncher.exe");
    s.method = MethodSpec::Direct;
    let r = plan_lm(&sys, &one(s), "game.exe").unwrap_err().to_string();
    assert!(r.contains("mode soft") && r.contains("method watch"), "{r}");
    let mut s = spec("FFLauncher.exe");
    s.priority = Some(PrioritySpec::High);
    let r = plan_lm(&sys, &one(s), "game.exe").unwrap_err().to_string();
    assert!(
        r.contains("priority class") && r.contains("method watch sets it"),
        "{r}"
    );
    // `direct` keeps its bitness rule: an i386 launcher makes the profile x86.
    let p = plan_lm(
        &lp_sys(&pe_x64(), &pe_x86()),
        &one(spec("FFLauncher.exe")),
        "game.exe",
    );
    assert_eq!(profile_of(&p.unwrap()).bitness, Bitness::X86);
    // And its target is the start.
    let pr = profile_of(&plan_lm(&sys, &one(spec("FFLauncher.exe")), "game.exe").unwrap());
    assert_eq!(pr.target, pr.start);
}

#[test]
fn lw5_direct_to_watch_replaces_the_profile_and_a_watch_profile_round_trips() {
    let env = Env::new(lp_sys(&pe_x86(), &pe_x64()));
    env.sys.fake_fs().mkdir_all(Path::new(PROFILES)).unwrap();
    let before = snap_all(&env.sys);
    let t1 = env.applied(&stored(&env, &one(spec("FFLauncher.exe"))));
    // `watch` for the same app: the same file, replaced (the launch option stays valid).
    let p = plan_lm(
        &env.sys,
        &one(watch_soft_high("FFLauncher.exe")),
        "game.exe",
    )
    .unwrap();
    let Op::ReplaceFile { path, .. } = &p.ops[0] else {
        panic!("{:?}", p.ops[0])
    };
    assert_eq!(path, &profile_file(profile_id(220)));
    let t2 = env.applied(&store(&app(&env.sys), &p.encode().unwrap()).unwrap());
    assert_eq!(env.verify(&t2), [(0, Observed::After)]);
    // The same `watch` rule again: nothing to do.
    let p = plan_lm(
        &env.sys,
        &one(watch_soft_high("FFLauncher.exe")),
        "game.exe",
    )
    .unwrap();
    assert!(p.ops.is_empty(), "{:?}", p.ops);
    // LIFO back to nothing, identical.
    assert_eq!(env.revert(&t2).unwrap().closed, Some(Closing::Reverted));
    assert_eq!(env.revert(&t1).unwrap().closed, Some(Closing::Reverted));
    assert!(
        before == snap_all(&env.sys),
        "{:#?}",
        before.diff(&snap_all(&env.sys))
    );
    // A `watch` profile alone: apply → verify → revert → identical.
    let t = env.applied(&stored(&env, &one(watch("game.exe"))));
    assert_eq!(env.verify(&t), [(0, Observed::After)]);
    let name = format!(r"{PROFILES}\{}", profile_file(profile_id(220)));
    let bytes = try_read_abs(&env.sys, &name).unwrap();
    assert!(
        std::str::from_utf8(&bytes)
            .unwrap()
            .contains("method=watch\n")
    );
    assert_eq!(env.revert(&t).unwrap().closed, Some(Closing::Reverted));
    assert!(
        before == snap_all(&env.sys),
        "{:#?}",
        before.diff(&snap_all(&env.sys))
    );
}
