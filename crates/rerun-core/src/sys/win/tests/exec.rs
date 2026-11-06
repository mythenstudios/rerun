//! `exec` on real Windows (P2-8, `docs/09-testing.md`): T1 round trip over a read-only,
//! hidden target, T6 a file the user edited, T8 the game running (a handle held, an image
//! mapped as the main executable). The game folder and the fake `LocalAppData` are folders of
//! a [`TestRoot`]; crashes and power losses run only against the fake.

use std::path::{Path, PathBuf};

use super::super::testfx::{TestRoot, note};
use super::app::{AppTestSys, app_root};
use crate::exec::tests::{N, NEW, OLD, RH, X, t1_spec};
use crate::exec::{ApplyError, ExecCtx, Outcome, Refusal, apply, forget, revert, verify};
use crate::journal::{Closing, InstanceTag, Observed};
use crate::plan::{PlanHash, store};
use crate::policy::root::{AppDir, Create, ForbiddenRoots, GameDir};
use crate::prim::tests::rel;
use crate::prim::{PlanCtx, Step, plan};
use crate::sys::System;
use crate::sys::contract::{Access, FsFixture, Share};
use crate::sys::snapshot::{Scope, SnapRoot, Snapshot, snapshot};

struct Win {
    root: TestRoot,
    sys: AppTestSys,
    game: PathBuf,
    install: PathBuf,
}

fn setup(case: &str) -> Option<Win> {
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
    let sys = AppTestSys::new(&lad);
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
        self.with(|_, fr| {
            let g = GameDir::open_manual(&self.sys, fr, &self.game).unwrap();
            snapshot(
                self.sys.registry(),
                &Scope {
                    dirs: vec![SnapRoot::new(g.dir(), "game")],
                    keys: Vec::new(),
                },
            )
            .unwrap()
        })
    }
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
