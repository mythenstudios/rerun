//! `exec` on real Windows (P2-8, `docs/09-testing.md`): T1 round trip over a read-only,
//! hidden target, T6 a file the user edited, T8 the game running (a handle held, an image
//! mapped as the main executable). The game folder and the fake `LocalAppData` are folders of
//! a [`TestRoot`]; crashes and power losses run only against the fake.
//!
//! Registry ops (P2-10b): the same harness with the real `WinRegistry` on a private app hive
//! ([`HiveRoot`], `HKCU` a `KEY_READ` handle; never the real `HKCU`): R-T1 a mixed round trip,
//! R-T6 a value another program changed, R-T8 a pure registry plan while a handle on the main
//! executable is held, R-H1 the game folder renamed away and back.
//!
//! INI ops (P2-12): R-I1 `file_install` and `ini_set` per encoding, R-I3 a file the game
//! rewrote, R-I6 a swapped backup (the binding of head and backup).

use std::path::{Path, PathBuf};

use super::super::testfx::{HiveRoot, TestRoot, note};
use super::app::{AppTestSys, app_root};
use crate::exec::tests::{N, NEW, OLD, RH, X, t1_spec};
use crate::exec::{ApplyError, ExecCtx, Outcome, Refusal, apply, forget, revert, verify};
use crate::journal::{Closing, InstanceTag, Observed};
use crate::plan::{PlanHash, store};
use crate::policy::root::{AppDir, Create, ForbiddenRoots, GameDir};
use crate::prim::tests::rel;
use crate::prim::{PlanCtx, Step, plan};
use crate::sys::System;
use crate::sys::contract::RegFixture;
use crate::sys::contract::{Access, FsFixture, Share};
use crate::sys::registry::{RegValue, reg_type};
use crate::sys::snapshot::{Scope, SnapRoot, Snapshot, snapshot};

struct Win {
    root: TestRoot,
    sys: AppTestSys,
    game: PathBuf,
    install: PathBuf,
}

fn setup(case: &str) -> Option<Win> {
    setup_with(case, AppTestSys::new)
}

fn setup_with(case: &str, make: impl FnOnce(&Path) -> AppTestSys) -> Option<Win> {
    let (root, lad, _out) = app_root(case)?;
    let game = root.work("game");
    let install = root.work("install");
    let pkg = lad.join(r"Rerun\packages\fix-pack\1.0.2");
    let fx = root.fx();
    fx.file(&pkg.join("d3d9.dll"), NEW).unwrap();
    fx.file(&pkg.join(r"mods\x.dll"), X).unwrap();
    fx.file(&pkg.join("new.dll"), N).unwrap();
    fx.file(&game.join("d3d9.dll"), OLD).unwrap();
    fx.file(&game.join("game.exe"), b"MZ").unwrap();
    fx.set_attrs(&game.join("d3d9.dll"), RH).unwrap();
    let sys = make(&lad);
    // The fake known folders name another profile: a `target/` inside the real user profile
    // is then "another user's profile" for the forbidden list. Skip rather than guess.
    let fr = ForbiddenRoots::resolve(&sys, &install).unwrap_or_else(|e| panic!("{e}"));
    if let Err(e) = GameDir::open_manual(&sys, &fr, &game) {
        note(&format!(
            "exec {case}: skipped, the game folder is refused here: {e}"
        ));
        return None;
    }
    Some(Win {
        root,
        sys,
        game,
        install,
    })
}

impl Win {
    fn with<R>(&self, f: impl FnOnce(&ExecCtx<'_>, &ForbiddenRoots) -> R) -> R {
        let fr =
            ForbiddenRoots::resolve(&self.sys, &self.install).unwrap_or_else(|e| panic!("{e}"));
        let app = AppDir::open(&self.sys, Create::IfMissing).unwrap().unwrap();
        let cx = ExecCtx {
            sys: &self.sys,
            fr: &fr,
            app: &app,
            tag: InstanceTag::new(),
        };
        f(&cx, &fr)
    }

    fn plan(&self) -> PlanHash {
        self.with(|cx, fr| {
            let g =
                GameDir::open_manual(&self.sys, fr, &self.game).unwrap_or_else(|e| panic!("{e}"));
            let main = rel("game.exe");
            let p = plan(
                &[Step::FileInstall(t1_spec())],
                &PlanCtx {
                    game: &g,
                    app: cx.app,
                    steam_app: None,
                    main_exe: Some(&main),
                    reg: crate::policy::registry::RegPolicy.reader(&self.sys),
                },
            )
            .unwrap_or_else(|e| panic!("{e}"));
            store(cx.app, &p.encode().unwrap()).unwrap()
        })
    }

    fn snap(&self) -> Snapshot {
        self.snap_with(Vec::new())
    }

    fn snap_with(&self, keys: Vec<crate::sys::registry::RegKey>) -> Snapshot {
        self.with(|_, fr| {
            let g = GameDir::open_manual(&self.sys, fr, &self.game).unwrap();
            snapshot(
                self.sys.registry(),
                &Scope {
                    dirs: vec![SnapRoot::new(g.dir(), "game")],
                    keys,
                },
            )
            .unwrap()
        })
    }

    /// Plans `steps` (main executable `game.exe`) and stores the plan.
    fn plan_steps(&self, steps: &[Step]) -> PlanHash {
        self.with(|cx, fr| {
            let g =
                GameDir::open_manual(&self.sys, fr, &self.game).unwrap_or_else(|e| panic!("{e}"));
            let main = rel("game.exe");
            let p = plan(
                steps,
                &PlanCtx {
                    game: &g,
                    app: cx.app,
                    steam_app: None,
                    main_exe: Some(&main),
                    reg: crate::policy::registry::RegPolicy.reader(&self.sys),
                },
            )
            .unwrap_or_else(|e| panic!("{e}"));
            store(cx.app, &p.encode().unwrap()).unwrap()
        })
    }
}

/// A [`Win`] whose registry is an app hive; the hive outlives the system (field order).
struct WinReg {
    w: Win,
    h: HiveRoot,
}

fn setup_reg(case: &str) -> Option<WinReg> {
    use crate::exec::reg_tests::VENDOR_GAME;
    let h = HiveRoot::new(&format!("{case}-hive"))?;
    let w = setup_with(case, |lad| AppTestSys::with_hive(lad, &h))?;
    let k = hkcu(VENDOR_GAME);
    h.hive.key(&k).unwrap();
    let text = RegValue::String("text".into()).encode().unwrap().1;
    h.hive
        .raw(&k, "TypeChange", reg_type::REG_SZ, &text)
        .unwrap();
    Some(WinReg { w, h })
}

fn hkcu(p: &str) -> crate::sys::registry::RegKey {
    crate::sys::registry::RegKey::new(
        crate::sys::registry::Hive::CurrentUser,
        crate::sys::registry::RegView::Native,
        p,
    )
}

fn software() -> Vec<crate::sys::registry::RegKey> {
    vec![hkcu("Software")]
}

fn read(p: &Path) -> Vec<u8> {
    std::fs::read(p).unwrap()
}

#[test]
fn t1_exec_round_trip_on_real_windows() {
    let Some(w) = setup("exec-t1") else {
        return;
    };
    let before = w.snap();
    let h = w.plan();
    let t = match w.with(|cx, _| apply(cx, &h)) {
        Ok(Outcome::Applied(t)) => t,
        other => panic!("{other:?}"),
    };
    assert_eq!(read(&w.game.join("d3d9.dll")), NEW);
    assert_eq!(read(&w.game.join(r"mods\a\x.dll")), X);
    let v = w.with(|cx, _| verify(cx, &t)).unwrap();
    assert!(v.halted.is_none(), "{v:?}");
    assert!(v.ops.iter().all(|(_, o)| *o == Observed::After), "{v:?}");
    let rep = w
        .with(|cx, _| revert(cx, &t))
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(rep.closed, Some(Closing::Reverted), "{rep:?}");
    let after = w.snap();
    assert!(before == after, "{:#?}", before.diff(&after));
    assert_eq!(w.plan(), h, "planned again: the same hash");
    drop(w.root);
}

#[test]
fn t6_exec_leaves_a_file_the_user_edited_on_real_windows() {
    let Some(w) = setup("exec-t6") else {
        return;
    };
    let h = w.plan();
    let t = match w.with(|cx, _| apply(cx, &h)) {
        Ok(Outcome::Applied(t)) => t,
        other => panic!("{other:?}"),
    };
    std::fs::write(w.game.join("new.dll"), b"edited by the user").unwrap();
    let rep = w
        .with(|cx, _| revert(cx, &t))
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(rep.closed, None);
    for o in &rep.ops {
        let want = if o.op == 4 {
            Observed::Foreign
        } else {
            Observed::After
        };
        assert_eq!(o.observed, want, "{rep:?}");
    }
    assert_eq!(read(&w.game.join("new.dll")), b"edited by the user");
    assert_eq!(
        read(&w.game.join("d3d9.dll")),
        OLD,
        "the lower ops reverted (R1)"
    );
    w.with(|cx, _| forget(cx, &t)).unwrap();
}

#[test]
fn t8_exec_refuses_while_the_game_runs_on_real_windows() {
    let Some(w) = setup("exec-t8") else {
        return;
    };
    let h = w.plan();
    let before = w.snap();
    {
        let held = w
            .root
            .fx()
            .hold_open(&w.game.join("d3d9.dll"), Access::READ, Share::RWD)
            .unwrap();
        let r = w.with(|cx, _| apply(cx, &h));
        assert!(
            matches!(&r, Err(ApplyError::Refused(Refusal::Busy(s))) if s.as_str().ends_with("d3d9.dll")),
            "{r:?}"
        );
        drop(held);
    }
    let Some(mapped) = w.root.fx().mapped_image(&w.game.join("game.exe")).unwrap() else {
        note("exec T8: no image mapping on this system, the mapped main executable is not checked");
        return;
    };
    let r = w.with(|cx, _| apply(cx, &h));
    assert!(
        matches!(&r, Err(ApplyError::Refused(Refusal::Busy(s))) if s.as_str().ends_with("game.exe")),
        "{r:?}"
    );
    drop(mapped);
    // Only game.exe changed (the fixture copied an image there); no transaction.
    let after = w.snap();
    assert_eq!(before.diff(&after).len(), 1, "{:#?}", before.diff(&after));
    let lad_journal = w
        .sys
        .known_folders()
        .get(crate::sys::KnownFolder::LocalAppData)
        .unwrap()
        .join(r"Rerun\journal");
    let txns = std::fs::read_dir(&lad_journal)
        .map(|d| {
            d.filter_map(Result::ok)
                .filter(|e| e.file_name() != "lock")
                .count()
        })
        .unwrap_or(0);
    assert_eq!(txns, 0);
}

/// R-T1 on Windows: `file_install` and `registry_set` in one plan, applied, verified,
/// reverted; the game folder and `HKCU\Software` of the app hive identical; planned again, the
/// same hash.
#[test]
fn r_t1_exec_round_trip_with_registry_on_real_windows() {
    let Some(r) = setup_reg("exec-rt1") else {
        return;
    };
    let w = &r.w;
    let before = w.snap_with(software());
    let h = w.plan_steps(&crate::exec::reg_tests::rt1_steps());
    let t = match w.with(|cx, _| apply(cx, &h)) {
        Ok(Outcome::Applied(t)) => t,
        other => panic!("{other:?}"),
    };
    let sub = hkcu(crate::exec::reg_tests::SUB);
    assert_eq!(
        w.sys.registry().get(&sub, "A").unwrap(),
        Some(RegValue::Dword(1))
    );
    let v = w.with(|cx, _| verify(cx, &t)).unwrap();
    assert!(v.halted.is_none() && v.ops.len() == 11, "{v:?}");
    assert!(v.ops.iter().all(|(_, o)| *o == Observed::After), "{v:?}");
    let rep = w
        .with(|cx, _| revert(cx, &t))
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(rep.closed, Some(Closing::Reverted), "{rep:?}");
    let after = w.snap_with(software());
    assert!(before == after, "{:#?}", before.diff(&after));
    assert_eq!(
        w.plan_steps(&crate::exec::reg_tests::rt1_steps()),
        h,
        "planned again: the same hash"
    );
    drop(r);
}

/// R-T6 on Windows: another program changes our value; the revert leaves it (`Foreign`) and
/// reverts everything else it can; only forget closes.
#[test]
fn r_t6_exec_leaves_a_value_another_program_changed_on_real_windows() {
    let Some(r) = setup_reg("exec-rt6") else {
        return;
    };
    let w = &r.w;
    let h = w.plan_steps(&crate::exec::reg_tests::rt1_steps());
    let t = match w.with(|cx, _| apply(cx, &h)) {
        Ok(Outcome::Applied(t)) => t,
        other => panic!("{other:?}"),
    };
    let sub = hkcu(crate::exec::reg_tests::SUB);
    r.h.hive
        .raw(&sub, "A", reg_type::REG_DWORD, &9u32.to_le_bytes())
        .unwrap();
    let rep = w
        .with(|cx, _| revert(cx, &t))
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(rep.closed, None);
    let foreign: Vec<u16> = rep
        .ops
        .iter()
        .filter(|o| o.observed == Observed::Foreign)
        .map(|o| o.op)
        .collect();
    assert_eq!(foreign, [8, 7, 6, 5], "{rep:?}");
    assert_eq!(
        w.sys.registry().get(&sub, "A").unwrap(),
        Some(RegValue::Dword(9))
    );
    assert_eq!(w.sys.registry().get(&sub, "B").unwrap(), None, "B reverted");
    assert_eq!(
        read(&w.game.join("d3d9.dll")),
        OLD,
        "the files reverted (R1)"
    );
    w.with(|cx, _| forget(cx, &t)).unwrap();
}

/// R-T8 on Windows (review N7): a pure registry plan is refused while a handle on the main
/// executable is held; nothing is written.
#[test]
fn r_t8_exec_refuses_a_registry_plan_while_the_game_runs_on_real_windows() {
    let Some(r) = setup_reg("exec-rt8") else {
        return;
    };
    let w = &r.w;
    let h = w.plan_steps(&[crate::prim::reg_tests::step(
        r"HKCU\Software\New\Prod",
        vec![crate::prim::reg_tests::dword("A", 1)],
    )]);
    let before = w.snap_with(software());
    let held = w
        .root
        .fx()
        .hold_open(&w.game.join("game.exe"), Access::READ, Share::RWD)
        .unwrap();
    let res = w.with(|cx, _| apply(cx, &h));
    assert!(
        matches!(&res, Err(ApplyError::Refused(Refusal::Busy(s))) if s.as_str().ends_with("game.exe")),
        "{res:?}"
    );
    drop(held);
    let after = w.snap_with(software());
    assert!(before == after, "{:#?}", before.diff(&after));
}

/// R-H1 on Windows: the game folder renamed away after a mixed apply; the revert reverts the
/// registry ops and halts at the newest file op; renamed back, the revert closes and both are
/// as before.
#[test]
fn r_h1_exec_reverts_the_registry_when_the_game_folder_is_gone_on_real_windows() {
    let Some(r) = setup_reg("exec-rh1") else {
        return;
    };
    let w = &r.w;
    let before = w.snap_with(software());
    let h = w.plan_steps(&crate::exec::reg_tests::rt1_steps());
    let t = match w.with(|cx, _| apply(cx, &h)) {
        Ok(Outcome::Applied(t)) => t,
        other => panic!("{other:?}"),
    };
    let away = w.game.with_file_name("game-away");
    w.root.fx().rename(&w.game, &away).unwrap();
    let rep = w
        .with(|cx, _| revert(cx, &t))
        .unwrap_or_else(|e| panic!("{e}"));
    assert!(
        rep.closed.is_none() && rep.halted.as_ref().is_some_and(|x| x.op == 4),
        "{rep:?}"
    );
    assert_eq!(rep.ops.len(), 6, "{rep:?}");
    assert!(!w.sys.registry().key_exists(&hkcu(r"Software\New")).unwrap());
    w.root.fx().rename(&away, &w.game).unwrap();
    let rep = w
        .with(|cx, _| revert(cx, &t))
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(rep.closed, Some(Closing::Reverted), "{rep:?}");
    let after = w.snap_with(software());
    assert!(before == after, "{:#?}", before.diff(&after));
}

/// The value name of the game folder's `game.exe` (its canonical path).
fn layer_name(w: &Win) -> String {
    w.with(|_, fr| {
        let g = GameDir::open_manual(&w.sys, fr, &w.game).unwrap_or_else(|e| panic!("{e}"));
        format!(r"{}\game.exe", g.path())
    })
}

/// [`setup_reg`] with `CurrentVersion`, the anchor of `AppCompatFlags\Layers`.
fn setup_layers(case: &str) -> Option<WinReg> {
    let r = setup_reg(case)?;
    r.h.hive
        .key(&hkcu(crate::prim::layer_tests::CURRENT_VERSION))
        .unwrap();
    Some(r)
}

/// R-L1 on Windows (P2-11): `file_install` and `compat_layer` (synthetic tokens) in one plan
/// on an app hive without `AppCompatFlags`: the value exactly as merged, `verify` all `After`,
/// the revert closes, the game folder and `HKCU\Software` identical (the shared keys deleted
/// again, they were empty).
#[test]
fn r_l1_exec_compat_layer_round_trip_on_real_windows() {
    let Some(r) = setup_layers("exec-rl1") else {
        return;
    };
    let w = &r.w;
    let before = w.snap_with(software());
    let steps = [
        Step::FileInstall(t1_spec()),
        crate::exec::layer_tests::two_tokens(),
    ];
    let h = w.plan_steps(&steps);
    let t = match w.with(|cx, _| apply(cx, &h)) {
        Ok(Outcome::Applied(t)) => t,
        other => panic!("{other:?}"),
    };
    let layers = hkcu(crate::prim::layer_tests::LAYERS_KEY);
    assert_eq!(
        w.sys.registry().get(&layers, &layer_name(w)).unwrap(),
        Some(RegValue::String("~ ZZ_FLAG_A ZZ_OS_A".into()))
    );
    let v = w.with(|cx, _| verify(cx, &t)).unwrap();
    assert!(v.ops.iter().all(|(_, o)| *o == Observed::After), "{v:?}");
    let rep = w
        .with(|cx, _| revert(cx, &t))
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(rep.closed, Some(Closing::Reverted), "{rep:?}");
    let after = w.snap_with(software());
    assert!(before == after, "{:#?}", before.diff(&after));
    assert_eq!(w.plan_steps(&steps), h, "planned again: the same hash");
}

/// R-L3 on Windows: another program appends a token and sets a layer for another executable
/// below the created `Layers`; the revert removes only Rerun's tokens, leaves the shared keys
/// (E6 b) and closes.
#[test]
fn r_l3_exec_compat_layer_drift_on_real_windows() {
    let Some(r) = setup_layers("exec-rl3") else {
        return;
    };
    let w = &r.w;
    let h = w.plan_steps(&[crate::exec::layer_tests::two_tokens()]);
    let t = match w.with(|cx, _| apply(cx, &h)) {
        Ok(Outcome::Applied(t)) => t,
        other => panic!("{other:?}"),
    };
    let layers = hkcu(crate::prim::layer_tests::LAYERS_KEY);
    let name = layer_name(w);
    let sz = |s: &str| RegValue::String(s.into()).encode().unwrap().1;
    r.h.hive
        .raw(
            &layers,
            &name,
            reg_type::REG_SZ,
            &sz("~ ZZ_FLAG_A ZZ_OS_A X1"),
        )
        .unwrap();
    r.h.hive
        .raw(
            &layers,
            r"C:\Other\other.exe",
            reg_type::REG_SZ,
            &sz("~ X2"),
        )
        .unwrap();
    let rep = w
        .with(|cx, _| revert(cx, &t))
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(rep.closed, Some(Closing::Reverted), "{rep:?}");
    assert!(
        rep.ops.iter().all(|o| o.observed == Observed::Drifted),
        "{rep:?}"
    );
    assert_eq!(
        w.sys.registry().get(&layers, &name).unwrap(),
        Some(RegValue::String("~ X1".into()))
    );
    assert_eq!(
        w.sys
            .registry()
            .get(&layers, r"C:\Other\other.exe")
            .unwrap(),
        Some(RegValue::String("~ X2".into()))
    );
}

/// [`setup`] with the INI file of the `ini_set` tests holding `text`.
fn setup_ini(case: &str, text: &[u8]) -> Option<Win> {
    let w = setup(case)?;
    w.root
        .fx()
        .file(&w.game.join(crate::prim::ini_tests::INI), text)
        .unwrap();
    Some(w)
}

/// R-I1 on Windows (P2-12): `file_install` and `ini_set` in one plan, per encoding (ANSI with
/// CRLF, UTF-8 with BOM and LF, mixed line endings): the content exactly as edited, `verify`
/// all `After`, the revert closes, the game folder identical, planned again the same hash. The
/// real replace sequence of NTFS writes the INI file.
#[test]
fn r_i1_exec_ini_set_round_trip_on_real_windows() {
    use crate::exec::ini_tests::{edits3, encodings};
    for (i, (what, text)) in encodings().into_iter().enumerate() {
        let Some(w) = setup_ini(&format!("exec-ri1-{i}"), &text) else {
            return;
        };
        let before = w.snap();
        let steps = [
            Step::FileInstall(t1_spec()),
            crate::prim::ini_tests::three(),
        ];
        let h = w.plan_steps(&steps);
        let t = match w.with(|cx, _| apply(cx, &h)) {
            Ok(Outcome::Applied(t)) => t,
            other => panic!("{what}: {other:?}"),
        };
        let ini = w.game.join(crate::prim::ini_tests::INI);
        assert_eq!(
            read(&ini),
            crate::policy::ini::edit(&text, &edits3()).unwrap(),
            "{what}"
        );
        let v = w.with(|cx, _| verify(cx, &t)).unwrap();
        assert!(
            v.ops.iter().all(|(_, o)| *o == Observed::After),
            "{what}: {v:?}"
        );
        let rep = w
            .with(|cx, _| revert(cx, &t))
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(rep.closed, Some(Closing::Reverted), "{what}: {rep:?}");
        let after = w.snap();
        assert!(before == after, "{what}: {:#?}", before.diff(&after));
        assert_eq!(
            w.plan_steps(&steps),
            h,
            "{what}: planned again, the same hash"
        );
    }
}

/// R-I3 on Windows: the game rewrites the file (a foreign key and one of Rerun's keys changed):
/// the revert is the semantic rewrite through the real replace sequence; the changed key and
/// everything else stay, Rerun's other keys go back exactly.
#[test]
fn r_i3_exec_ini_set_drift_on_real_windows() {
    use crate::exec::ini_tests::APPLIED;
    use crate::prim::ini_tests::{INI, INI_TEXT, three};
    let Some(w) = setup_ini("exec-ri3", INI_TEXT) else {
        return;
    };
    let h = w.plan_steps(&[three()]);
    let t = match w.with(|cx, _| apply(cx, &h)) {
        Ok(Outcome::Applied(t)) => t,
        other => panic!("{other:?}"),
    };
    let ini = w.game.join(INI);
    assert_eq!(read(&ini), APPLIED.as_bytes());
    let drift = APPLIED
        .replace("Volume=5", "Volume=9")
        .replace("Width=1920", "Width=1600");
    std::fs::write(&ini, drift.as_bytes()).unwrap();
    let rep = w
        .with(|cx, _| revert(cx, &t))
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(rep.closed, Some(Closing::Reverted), "{rep:?}");
    assert!(
        rep.ops.iter().all(|o| o.observed == Observed::Drifted),
        "{rep:?}"
    );
    assert_eq!(
        String::from_utf8(read(&ini)).unwrap(),
        String::from_utf8_lossy(INI_TEXT)
            .replace("Volume=5", "Volume=9")
            .replace("Width=1280", "Width=1600")
    );
}

/// R-I6 on Windows: a backup swapped for another content of the same length breaks the binding
/// of head and backup: the revert fails with `BackupMismatch` and writes nothing.
#[test]
fn r_i6_exec_ini_set_swapped_backup_on_real_windows() {
    use crate::exec::ini_tests::APPLIED;
    use crate::prim::ini_tests::{INI, INI_TEXT, three};
    let Some(w) = setup_ini("exec-ri6", INI_TEXT) else {
        return;
    };
    let h = w.plan_steps(&[three()]);
    let t = match w.with(|cx, _| apply(cx, &h)) {
        Ok(Outcome::Applied(t)) => t,
        other => panic!("{other:?}"),
    };
    let ini = w.game.join(INI);
    let drift = APPLIED.replace("Volume=5", "Volume=9");
    std::fs::write(&ini, drift.as_bytes()).unwrap();
    let app = w.with(|cx, _| cx.app.path().to_string());
    let bin = PathBuf::from(format!(r"{app}\journal\{t}\op-0000.bin"));
    let swapped = String::from_utf8_lossy(INI_TEXT).replace("1280", "1281");
    std::fs::write(&bin, swapped.as_bytes()).unwrap();
    let before = w.snap();
    let r = w.with(|cx, _| revert(cx, &t));
    assert!(
        matches!(
            &r,
            Err(crate::exec::ExecError::Journal(
                crate::journal::JournalError::BackupMismatch(0)
            ))
        ),
        "{r:?}"
    );
    let after = w.snap();
    assert!(before == after, "{:#?}", before.diff(&after));
    assert_eq!(read(&ini), drift.as_bytes());
}
