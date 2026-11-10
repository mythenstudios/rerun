//! R-U (P4-12, ADR 0020 amendment P4-12): `ini_set` in the game's folder below `Documents`
//! against the fake. R-U1 the round trip (with a `file_install` in the game folder; Documents on
//! `C:` and on `D:`), planned again to the same hash; R-U2 the game rewrites the file: drifted,
//! semantic revert; R-U3 D4 (the game runs); R-U4 Documents moved between plan and apply and
//! between apply and revert: refused without a record, `forget` closes; R-U5 a cloud sync
//! switched on after the apply: refused; R-U6 the folder gone (halt) or another one (refused);
//! R-U7 two transactions on one file, newest first; R-U8 a forged rebind of the user data root
//! is `Blocked`; R-U9 the planner (no user data folder, a placeholder, the same name in both
//! roots). Crashes and power losses: `ini_crash_tests.rs` with the file on the user data root on
//! `D:` (`Place::UserData`).

use std::path::Path;

use super::bind::Bindings;
use super::tests::{Env, base, closed, finish, same, t1_spec, try_read_abs};
use super::{ExecError, Outcome, Refusal};
use crate::journal::{Closing, Observed, RebindRec, TxnState};
use crate::plan::{self, PlanError, PlanHash, RootKind};
use crate::policy::ini;
use crate::policy::registry::RegPolicy;
use crate::policy::root::{GameDir, RootError, RootId, UserBase, UserDataDir};
use crate::prim::ini_tests::INI_TEXT;
use crate::prim::tests::{GAME, app, fr, rel};
use crate::prim::{IniSetSpec, IniSetValue, PlanCtx, Step, StepRoot};
use crate::sys::fake::FakeSystemBuilder;
use crate::sys::fs::tag;
use crate::sys::snapshot::{Scope, SnapRoot, Snapshot, snapshot};
use crate::sys::{KnownFolder, SysErrorKind, System};

/// The fake's Documents.
pub(crate) const DOCS: &str = r"C:\Users\Player\Documents";
/// Documents on `D:` (the game folder's volume).
pub(crate) const DOCS_D: &str = r"D:\Docs";
/// The game's folder below Documents.
pub(crate) const UD_SUB: &str = r"My Games\G";
/// Its INI file.
pub(crate) const UD_FILE: &str = "settings.ini";

pub(crate) fn ud_ini(docs: &str) -> String {
    format!(r"{docs}\{UD_SUB}\{UD_FILE}")
}

/// [`base`] with Documents at `docs` holding `My Games\G\settings.ini` with `text`.
pub(crate) fn ud_builder(docs: &str, text: &[u8]) -> FakeSystemBuilder {
    let b = base();
    let b = if docs == DOCS {
        b
    } else {
        b.known_folder(KnownFolder::Documents, docs).dir(docs)
    };
    b.file(ud_ini(docs), text.to_vec())
}

pub(crate) fn ud_env(docs: &str, text: &[u8]) -> Env {
    Env::new(finish(ud_builder(docs, text)))
}

/// An `ini_set` of [`UD_FILE`] in the user data folder.
pub(crate) fn ud_step(values: &[(&str, &str, &str)]) -> Step {
    Step::IniSet(IniSetSpec {
        root: StepRoot::UserData,
        file: rel(UD_FILE),
        values: values
            .iter()
            .map(|(s, k, v)| IniSetValue {
                section: (*s).to_owned(),
                key: (*k).to_owned(),
                value: (*v).to_owned(),
            })
            .collect(),
    })
}

/// The three values of `prim::ini_tests::three`, in the user data folder.
pub(crate) fn ud_three() -> Step {
    ud_step(&[
        ("Display", "Width", "1920"),
        ("Display", "Fullscreen", "1"),
        ("Zz Extra", "Mode", "2"),
    ])
}

/// Plans `steps` for the manual game folder with the user data folder `My Games\G` and stores
/// the plan, or the planner's refusal.
pub(crate) fn try_plan_ud(env: &Env, steps: &[Step]) -> Result<PlanHash, PlanError> {
    let fr = fr(&env.sys);
    let g = GameDir::open_manual(&env.sys, &fr, Path::new(GAME))?;
    let u = UserDataDir::open(&env.sys, &fr, UserBase::Documents, &rel(UD_SUB))?;
    let a = app(&env.sys);
    let main = rel("game.exe");
    let p = crate::prim::plan(
        steps,
        &PlanCtx {
            game: &g,
            app: Some(&a),
            steam_app: None,
            main_exe: Some(&main),
            reg: RegPolicy.reader(&env.sys),
            app_path: None,
            user_data: Some(&u),
        },
    )?;
    plan::store(&a, &p.encode()?)
}

pub(crate) fn plan_ud(env: &Env, steps: &[Step]) -> PlanHash {
    try_plan_ud(env, steps).unwrap_or_else(|e| panic!("{e}"))
}

/// The game folder and the Documents folder `docs`, as the round trips compare them.
pub(crate) fn snap_ud(env: &Env, docs: &str) -> Snapshot {
    let fr = fr(&env.sys);
    let g = GameDir::open_manual(&env.sys, &fr, Path::new(GAME)).unwrap();
    let d = GameDir::open_manual(&env.sys, &fr, Path::new(docs)).unwrap();
    snapshot(
        env.sys.registry(),
        &Scope {
            dirs: vec![SnapRoot::new(g.dir(), GAME), SnapRoot::new(d.dir(), docs)],
            keys: Vec::new(),
        },
    )
    .unwrap()
}

pub(crate) fn ud_now(env: &Env, docs: &str) -> Option<Vec<u8>> {
    try_read_abs(&env.sys, &ud_ini(docs))
}

fn put(env: &Env, abs: &str, b: &[u8]) {
    super::tests::sys_put(&env.sys, abs, b);
}

fn refused(r: Result<Outcome, super::ApplyError>) -> Refusal {
    match r {
        Err(super::ApplyError::Refused(x)) => x,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

fn revert_refused(r: Result<super::RevertReport, ExecError>) -> Refusal {
    match r {
        Err(ExecError::Refused(x)) => x,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn r_u1_round_trip_on_c_and_on_d() {
    for docs in [DOCS, DOCS_D] {
        let env = ud_env(docs, INI_TEXT);
        let before = snap_ud(&env, docs);
        let steps = [Step::FileInstall(t1_spec()), ud_three()];
        let h = plan_ud(&env, &steps);
        let p = plan::load(&app(&env.sys), &h).unwrap();
        let p = plan::decode_recorded(p.bytes()).unwrap();
        assert_eq!(p.roots.len(), 2, "{docs}");
        assert_eq!(p.roots[1].kind, RootKind::UserData);
        assert_eq!(
            p.roots[1].path.to_string(),
            format!(r"{docs}\{UD_SUB}"),
            "{docs}"
        );
        assert!(
            p.ops
                .iter()
                .any(|o| matches!(o, plan::Op::IniValue { root, .. } if root.0 == 1))
        );
        let t = env.applied(&h);
        assert_eq!(
            ud_now(&env, docs),
            ini::edit(INI_TEXT, &super::ini_tests::edits3()).ok(),
            "{docs}"
        );
        assert!(env.verify(&t).iter().all(|(_, o)| *o == Observed::After));
        let r = env.revert(&t).unwrap();
        assert_eq!(r.closed, Some(Closing::Reverted), "{docs}: {r:?}");
        assert!(r.ops.iter().all(|o| o.observed == Observed::After));
        same(&before, &snap_ud(&env, docs));
        assert_eq!(plan_ud(&env, &steps), h, "{docs}: planned again");
        assert!(env.verify(&t).iter().all(|(_, o)| *o == Observed::Before));
    }
}

#[test]
fn r_u2_the_game_rewrites_the_file_the_revert_is_semantic() {
    let env = ud_env(DOCS_D, INI_TEXT);
    let t = env.applied(&plan_ud(&env, &[ud_three()]));
    let now = ud_now(&env, DOCS_D).unwrap();
    let rewritten = String::from_utf8_lossy(&now).replace("Volume=5", "Volume=9");
    put(&env, &ud_ini(DOCS_D), rewritten.as_bytes());
    let r = env.revert(&t).unwrap();
    assert_eq!(r.closed, Some(Closing::Reverted), "{r:?}");
    assert_eq!(r.ops[0].observed, Observed::Drifted);
    assert_eq!(
        ud_now(&env, DOCS_D).unwrap(),
        String::from_utf8_lossy(INI_TEXT)
            .replace("Volume=5", "Volume=9")
            .as_bytes()
    );
}

#[test]
fn r_u3_the_running_game_refuses() {
    let env = ud_env(DOCS, INI_TEXT);
    let h = plan_ud(&env, &[ud_three()]);
    let hold = env
        .sys
        .fake_fs()
        .map_image_as(4242, Path::new(&format!(r"{GAME}\game.exe")))
        .unwrap();
    assert!(matches!(refused(env.apply(&h)), Refusal::Busy(_)));
    drop(hold);
    let t = env.applied(&h);
    let hold = env
        .sys
        .fake_fs()
        .map_image_as(4242, Path::new(&format!(r"{GAME}\game.exe")))
        .unwrap();
    assert!(matches!(revert_refused(env.revert(&t)), Refusal::Busy(_)));
    drop(hold);
    assert_eq!(closed(&env.revert(&t)), Some(Closing::Reverted));
}

/// Documents is a junction (`C:\Users\Player\Docs` to `D:\Docs`) that is moved to `E:\Docs`.
#[test]
fn r_u4_documents_moved_refuses_without_a_record() {
    const LINK: &str = r"C:\Users\Player\Docs";
    let b = base()
        .known_folder(KnownFolder::Documents, LINK)
        .file(ud_ini(DOCS_D), INI_TEXT.to_vec())
        .file(ud_ini(r"E:\Docs"), INI_TEXT.to_vec())
        .junction(LINK, DOCS_D);
    let env = Env::new(finish(b));
    let fx = env.sys.fake_fs();
    let h = plan_ud(&env, &[ud_three()]);
    // Between plan and apply.
    fx.retarget(Path::new(LINK), r"E:\Docs").unwrap();
    match refused(env.apply(&h)) {
        Refusal::UserDataMoved { planned, now } => {
            assert_eq!(planned.as_str(), format!(r"{DOCS_D}\{UD_SUB}"));
            assert_eq!(now.as_str(), format!(r"E:\Docs\{UD_SUB}"));
        }
        other => panic!("{other:?}"),
    }
    assert!(env.states().is_empty(), "no transaction");
    // Between apply and revert: refused before anything changes, the transaction stays.
    fx.retarget(Path::new(LINK), DOCS_D).unwrap();
    let t = env.applied(&h);
    let applied = ud_now(&env, DOCS_D);
    fx.retarget(Path::new(LINK), r"E:\Docs").unwrap();
    assert!(matches!(
        revert_refused(env.revert(&t)),
        Refusal::UserDataMoved { .. }
    ));
    assert!(matches!(
        env.try_verify(&t),
        Err(ExecError::Refused(Refusal::UserDataMoved { .. }))
    ));
    assert_eq!(env.state(&t), Some(TxnState::Applied));
    assert_eq!(ud_now(&env, DOCS_D), applied);
    assert_eq!(ud_now(&env, r"E:\Docs").as_deref(), Some(INI_TEXT));
    // `forget` closes it; the file at the old place keeps Rerun's values.
    env.forget(&t).unwrap();
    assert_eq!(ud_now(&env, DOCS_D), applied);
}

#[test]
fn r_u5_a_cloud_sync_switched_on_after_the_apply_refuses_the_revert() {
    let env = ud_env(DOCS, INI_TEXT);
    let t = env.applied(&plan_ud(&env, &[ud_three()]));
    let fx = env.sys.fake_fs();
    fx.set_cloud_attrs(Path::new(DOCS), true).unwrap();
    assert!(matches!(
        revert_refused(env.revert(&t)),
        Refusal::Root(e) if matches!(*e, RootError::CloudSynced { .. })
    ));
    assert_eq!(env.state(&t), Some(TxnState::Applied));
    fx.set_cloud_attrs(Path::new(DOCS), false).unwrap();
    // The same for a tag on the folder.
    fx.set_dir_tag(Path::new(&format!(r"{DOCS}\My Games")), tag::CLOUD)
        .unwrap();
    assert!(matches!(
        revert_refused(env.revert(&t)),
        Refusal::Root(e) if matches!(*e, RootError::CloudSynced { .. })
    ));
}

#[test]
fn r_u6_the_folder_gone_halts_another_one_refuses() {
    let env = ud_env(DOCS, INI_TEXT);
    let t = env.applied(&plan_ud(&env, &[Step::FileInstall(t1_spec()), ud_three()]));
    let fx = env.sys.fake_fs();
    let folder = format!(r"{DOCS}\{UD_SUB}");
    let applied = ud_now(&env, DOCS).unwrap();
    fx.remove_abs(Path::new(&ud_ini(DOCS))).unwrap();
    fx.remove_abs(Path::new(&folder)).unwrap();
    // The user data op is the newest file op: the revert halts there, without a record.
    let r = env.revert(&t);
    match &r {
        Ok(rep) => {
            assert!(rep.closed.is_none() && rep.ops.is_empty(), "{rep:?}");
            let h = rep.halted.as_ref().unwrap();
            assert_eq!(h.root, 1);
            assert!(matches!(
                &*h.why,
                Refusal::Root(e) if matches!(&**e, RootError::Sys(s) if s.kind == SysErrorKind::NotFound)
            ));
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(env.state(&t), Some(TxnState::Applied));
    // The game makes the folder again: another folder, refused.
    put(&env, &ud_ini(DOCS), &applied);
    assert!(matches!(
        revert_refused(env.revert(&t)),
        Refusal::Root(e) if matches!(*e, RootError::IdentityMismatch { .. })
    ));
}

#[test]
fn r_u7_two_transactions_on_one_file_newest_first() {
    let env = ud_env(DOCS, INI_TEXT);
    let before = snap_ud(&env, DOCS);
    let t1 = env.applied(&plan_ud(&env, &[ud_step(&[("Display", "Width", "1920")])]));
    let mid = snap_ud(&env, DOCS);
    let t2 = env.applied(&plan_ud(&env, &[ud_step(&[("Display", "Height", "1080")])]));
    assert!(matches!(
        revert_refused(env.revert(&t1)),
        Refusal::Later { txn } if txn == t2
    ));
    assert_eq!(closed(&env.revert(&t2)), Some(Closing::Reverted));
    same(&mid, &snap_ud(&env, DOCS));
    assert_eq!(closed(&env.revert(&t1)), Some(Closing::Reverted));
    same(&before, &snap_ud(&env, DOCS));
}

/// A rebind record for the user data root (a forged journal): never bound, `Blocked`.
#[test]
fn r_u8_a_rebind_of_the_user_data_root_is_blocked() {
    let env = ud_env(DOCS, INI_TEXT);
    let h = plan_ud(&env, &[ud_three()]);
    let p = plan::load(&app(&env.sys), &h).unwrap();
    let p = plan::decode_recorded(p.bytes()).unwrap();
    assert!(Bindings::of(&p, &[]).is_some());
    let rec = |root: u16| RebindRec {
        root,
        old: p.roots[usize::from(root)].id,
        store: crate::path::RootPath::new(r"D:\SteamLibrary").unwrap(),
        store_id: RootId {
            volume_serial: 1,
            file_id: 2,
        },
        id: RootId {
            volume_serial: 1,
            file_id: 3,
        },
        dirs: Vec::new(),
        reverting: None,
    };
    assert!(Bindings::of(&p, &[rec(1)]).is_none());
}

#[test]
fn r_u9_the_planner() {
    let env = ud_env(DOCS, INI_TEXT);
    // No user data folder in the context.
    let fr = fr(&env.sys);
    let g = GameDir::open_manual(&env.sys, &fr, Path::new(GAME)).unwrap();
    let main = rel("game.exe");
    let ctx = PlanCtx {
        game: &g,
        app: None,
        steam_app: None,
        main_exe: Some(&main),
        reg: RegPolicy.reader(&env.sys),
        app_path: None,
        user_data: None,
    };
    let e = crate::prim::plan(&[ud_three()], &ctx)
        .unwrap_err()
        .to_string();
    assert!(e.contains("names no user data folder"), "{e}");
    assert!(crate::prim::needs_user_data(&[ud_three()]));
    assert!(!crate::prim::needs_user_data(&[
        crate::prim::ini_tests::three()
    ]));
    // The same file name in both roots: two ops, two objects.
    let env = Env::new(finish(
        ud_builder(DOCS, INI_TEXT).file(format!(r"{GAME}\{UD_FILE}"), INI_TEXT.to_vec()),
    ));
    let mut game_step = ud_three();
    if let Step::IniSet(s) = &mut game_step {
        s.root = StepRoot::Game;
    }
    let h = plan_ud(&env, &[game_step, ud_three()]);
    let t = env.applied(&h);
    assert_eq!(env.verify(&t).len(), 2);
    assert_eq!(closed(&env.revert(&t)), Some(Closing::Reverted));
    // A placeholder in the user data folder.
    let env = ud_env(DOCS, INI_TEXT);
    env.sys
        .fake_fs()
        .remove_abs(Path::new(&ud_ini(DOCS)))
        .unwrap();
    env.sys
        .fake_fs()
        .put_tagged_file(Path::new(&ud_ini(DOCS)), INI_TEXT, tag::CLOUD)
        .unwrap();
    let e = try_plan_ud(&env, &[ud_three()]).unwrap_err().to_string();
    assert!(e.contains("cloud placeholder"), "{e}");
    // The step file: `user_data` and `root` on the wire, the root omitted for the game folder.
    let sf = crate::prim::StepFile::parse(
        br#"{"format":1,"game":{"steam":440},"main_exe":"game.exe","user_data":{"documents":"My Games\\G"},"steps":[{"ini_set":{"root":"user_data","file":"settings.ini","values":[{"section":"A","key":"b","value":"1"}]}},{"ini_set":{"file":"x.ini","values":[{"section":"A","key":"b","value":"1"}]}}]}"#,
    )
    .unwrap();
    assert_eq!(
        sf.user_data,
        Some(crate::prim::UserDataSpec::Documents(rel(UD_SUB)))
    );
    let s = serde_json::to_string(&sf.steps).unwrap();
    assert!(
        s.contains(r#"{"ini_set":{"root":"user_data","file":"settings.ini""#),
        "{s}"
    );
    assert!(s.contains(r#"{"ini_set":{"file":"x.ini""#), "{s}");
    for bad in [
        r#""user_data":{"saved_games":"G"}"#,
        r#""user_data":{"documents":"G","x":1}"#,
        r#""user_data":{"documents":"..\\G"}"#,
        r#""user_data":{}"#,
    ] {
        let text = format!(
            r#"{{"format":1,"game":{{"steam":440}},"main_exe":"game.exe",{bad},"steps":[]}}"#
        );
        assert!(
            crate::prim::StepFile::parse(text.as_bytes()).is_err(),
            "{bad}"
        );
    }
}
