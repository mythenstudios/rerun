//! LM-T (P3-3a, ADR 0020 amendment P3-3): launch profile ops against the fake, with plans built
//! by hand (the planner is P3-3c). Scope of every snapshot: the Steam game folders, Rerun's
//! `profiles` and `HKCU\Software`; `profiles` exists before the snapshot unless a test says
//! otherwise.
//! - LM-T1 round trip `apply → verify (After) → revert → identical` for (a) a profile alone, (b) a
//!   profile and a `file_install` in the game folder, (c) a replace of a foreign profile (the
//!   old bytes and attributes back exactly).
//! - LM-T2 `profiles` missing: `check` creates nothing, the apply creates it (no op of its own),
//!   the revert removes the profile and leaves the folder.
//! - LM-T3 tampering (other bytes, a folder, a hard link, a link at the name): `Foreign`, left
//!   as it is, the transaction open until `forget`.
//! - LM-T4 deleted by the user: a created profile `Before`, a replaced one `Foreign`.
//! - LM-T5 LIFO on one profile; LM-T5b two apps' profiles revert in either order (A2).
//! - LM-T6 `profiles` deleted before the revert: a halt at op 0 without a record after every
//!   other op is reverted; LM-T6b the game folder gone: a halt at the game op, the profile stays
//!   (A3), also after `forget`.
//! - LM-T7 a junction at `profiles`: apply, revert and `verify` refused before any change.
//! - LM-T8 `<LocalAppData>` moved (A1): the apply refused (`ProfilesMoved`), a revert and
//!   `verify` work at the folder now and report it.
//! - LM-T9 forged heads (fence violations): `Blocked` for revert, `verify` and stacking.
//! - LM-T10 a game folder the user cannot write: a profile-only plan applies, one with a game
//!   file op is `NeedsHelper`.
//! - LM-T11 rebinds: the profiles root is never rebound; a rebind of the game root reverts the
//!   profile normally.
//! - Controls: K-LM1 (inline content on any root) lets LM-T9's forged head pass, so its revert
//!   deletes a game file: the control that `exec` enforces "inline content is never a source
//!   for a game folder" (rule 4). It is no new power of a forged head: a forged `Package` op
//!   with the file's hash deletes it just the same (the same-user class, ADR 0019; review F2);
//!   K-LM2 (no path comparison) makes LM-T8's apply write; K-LM3 (profile op last) makes LM-T6
//!   leave every game op unreverted.

use std::path::Path;

use super::rebind_tests::{
    GAME_E, LIB_E, REF, content_diff, copy_tree, move_lib, rb_sys, remove_tree,
};
use super::tests::{
    Env, N, closed, exists_abs, same, sys_put, t1_spec, try_meta_abs, try_read_abs,
};
use super::{ApplyError, ExecError, Refusal};
use crate::journal::tests::rewrite;
use crate::journal::{Closing, InstanceTag, Journal, Observed, RebindRec, TxnId, TxnState};
use crate::plan::tests::profiles_tests::{inline, profile_bytes};
use crate::plan::{
    FileState, Op, PROFILES_ROOT_ID, Plan, PlanHash, PlanOrigin, PlanRoot, RootIx, RootKind,
    profile_file, profile_id, store,
};
use crate::policy::registry::RegPolicy;
use crate::policy::root::{GameDir, RootError, RootId, StoreDir};
use crate::prim::reg_tests::hkcu;
use crate::prim::tests::{STEAM_GAME, STEAM_LIB, app, entry, fr, rel, spec};
use crate::prim::{PlanCtx, Step, plan as plan_steps};
use crate::sys::System;
use crate::sys::fake::FakeSystem;
use crate::sys::fs::{Attrs, tag};
use crate::sys::snapshot::{Scope, SnapRoot, Snapshot, snapshot};

const LAD: &str = r"C:\Users\Player\AppData\Local";
pub(super) const PROFILES: &str = r"C:\Users\Player\AppData\Local\Rerun\profiles";
/// The game folder of app 221.
const GAME_H: &str = r"D:\SteamLibrary\steamapps\common\H";

/// The program Steam starts for `app_id`.
pub(super) fn start(app_id: u32) -> String {
    let dir = if app_id == 221 { GAME_H } else { STEAM_GAME };
    format!(r"{dir}\game.exe")
}

/// The profile of `app_id` below `profiles`.
fn profile_at(profiles: &str, app_id: u32) -> String {
    format!(r"{profiles}\{}", profile_file(profile_id(app_id)))
}

pub(super) fn profile_abs(app_id: u32) -> String {
    profile_at(PROFILES, app_id)
}

/// [`rb_sys`] (Steam, library [`STEAM_LIB`] with app 220 in `G`), app 221 in `H`, and `profiles`
/// unless `bare`.
pub(super) fn lm_sys(bare: bool) -> FakeSystem {
    let sys = rb_sys();
    let acf = "\"AppState\"\n{\n\t\"appid\"\t\t\"221\"\n\t\"name\"\t\t\"H\"\n\t\"StateFlags\"\t\t\"4\"\n\t\"installdir\"\t\t\"H\"\n}\n";
    sys_put(
        &sys,
        &format!(r"{STEAM_LIB}\steamapps\appmanifest_221.acf"),
        acf.as_bytes(),
    );
    sys_put(&sys, &format!(r"{GAME_H}\game.exe"), b"MZ");
    if !bare {
        sys.fake_fs().mkdir_all(Path::new(PROFILES)).unwrap();
    }
    sys.sync_all();
    sys
}

/// The plan of `steps` for the Steam root of `app_id` (220: `G`, 221: `H`).
fn game_plan(env: &Env, app_id: u32, steps: &[Step]) -> Plan {
    let fr = fr(&env.sys);
    let store = StoreDir::open(&env.sys, &fr, Path::new(STEAM_LIB)).unwrap();
    let g = store
        .game(&fr, if app_id == 221 { "H" } else { "G" })
        .unwrap();
    let a = app(&env.sys);
    let main = rel("game.exe");
    plan_steps(
        steps,
        &PlanCtx {
            game: &g,
            app: Some(&a),
            steam_app: Some(app_id),
            main_exe: Some(&main),
            reg: RegPolicy.reader(&env.sys),
            app_path: None,
            user_data: None,
        },
    )
    .unwrap_or_else(|e| panic!("{e}"))
}

/// `p` with the profiles root and, as op 0 (F3), the profile `bytes` of its app: a create, or a
/// replace of the file there now.
fn with_profile(env: &Env, mut p: Plan, bytes: Vec<u8>) -> Plan {
    let a = app(&env.sys);
    let path = a.path().child("profiles").unwrap();
    let PlanOrigin::Steam { app_id, .. } = p.roots[0].origin else {
        panic!("a Steam root")
    };
    let name = profile_file(profile_id(app_id));
    let abs = format!(r"{path}\{name}");
    p.roots.push(PlanRoot {
        kind: RootKind::Profiles,
        path,
        id: PROFILES_ROOT_ID,
        origin: PlanOrigin::AppDir,
        main_exe: None,
    });
    let content = inline(bytes);
    let op = match try_read_abs(&env.sys, &abs) {
        None => Op::CreateFile {
            root: RootIx(1),
            path: name,
            content,
            attrs: Attrs::default(),
        },
        Some(old) => Op::ReplaceFile {
            root: RootIx(1),
            path: name,
            old: FileState {
                sha256: crate::plan::tests::sha(&old),
                len: u64::try_from(old.len()).unwrap(),
                attrs: try_meta_abs(&env.sys, &abs).unwrap().attrs,
            },
            content,
            attrs: Attrs::default(),
        },
    };
    p.ops.insert(0, op);
    p
}

fn stored(env: &Env, p: &Plan) -> PlanHash {
    store(&app(&env.sys), &p.encode().unwrap()).unwrap()
}

/// The stored plan of `app_id`'s profile (a rule of at most `max` threads) and `steps`.
pub(super) fn lm(env: &Env, app_id: u32, steps: &[Step], max: u16) -> PlanHash {
    let p = game_plan(env, app_id, steps);
    stored(
        env,
        &with_profile(env, p, profile_bytes(&start(app_id), max)),
    )
}

/// The game folders, `profiles` and `HKCU\Software`.
pub(super) fn snap_all(env: &Env) -> Snapshot {
    let fr = fr(&env.sys);
    let g = GameDir::open_manual(&env.sys, &fr, Path::new(STEAM_GAME)).ok();
    let h = GameDir::open_manual(&env.sys, &fr, Path::new(GAME_H)).ok();
    let a = app(&env.sys);
    let mut dirs = vec![SnapRoot::new(a.dir(), a.path().to_string()).below(rel("profiles"))];
    if let Some(g) = &g {
        dirs.push(SnapRoot::new(g.dir(), STEAM_GAME));
    }
    if let Some(h) = &h {
        dirs.push(SnapRoot::new(h.dir(), GAME_H));
    }
    snapshot(
        env.sys.registry(),
        &Scope {
            dirs,
            keys: vec![hkcu("Software")],
        },
    )
    .unwrap()
}

/// The game folder `G` alone.
fn snap_game(env: &Env) -> Snapshot {
    super::tests::snap_at(&env.sys, STEAM_GAME)
}

/// The records of `t`.
fn records(env: &Env, t: &TxnId) -> usize {
    let a = app(&env.sys);
    Journal::new(&a, InstanceTag::fixed(5))
        .load(t, crate::journal::VerifyBackups::Length)
        .map_or(0, |v| v.log.len())
}

fn reverted(env: &Env, t: &TxnId) {
    let r = env.revert(t);
    assert_eq!(closed(&r), Some(Closing::Reverted), "{r:?}");
}

#[test]
fn lm_t1_round_trip_over_the_game_folder_and_profiles() {
    // (a) The profile alone.
    let env = Env::new(lm_sys(false));
    let before = snap_all(&env);
    let h = lm(&env, 220, &[], 8);
    let t = env.applied(&h);
    assert_eq!(env.state(&t), Some(TxnState::Applied));
    assert_eq!(env.verify(&t), [(0, Observed::After)]);
    assert_eq!(
        try_read_abs(&env.sys, &profile_abs(220)),
        Some(profile_bytes(&start(220), 8))
    );
    let r = env.revert(&t).unwrap();
    assert_eq!(r.closed, Some(Closing::Reverted));
    assert_eq!(r.profiles_moved, None);
    same(&before, &snap_all(&env));
    assert_eq!(env.verify(&t), [(0, Observed::Before)]);
    // Planned again: the same plan (no identity, no time in it).
    assert_eq!(lm(&env, 220, &[], 8), h);

    // (b) The profile and a `file_install` in the game folder.
    let env = Env::new(lm_sys(false));
    let before = snap_all(&env);
    let t = env.applied(&lm(&env, 220, &[Step::FileInstall(t1_spec())], 8));
    let v = env.verify(&t);
    assert_eq!(v.len(), 6);
    assert!(v.iter().all(|(_, o)| *o == Observed::After), "{v:?}");
    let r = env.revert(&t).unwrap();
    assert_eq!(r.closed, Some(Closing::Reverted));
    assert_eq!(
        r.ops.iter().map(|o| o.op).collect::<Vec<_>>(),
        [5, 4, 3, 2, 1, 0]
    );
    same(&before, &snap_all(&env));

    // (c) A replace of a foreign profile (a rest after `forget`, read-only and hidden): its
    // bytes and attributes come back exactly.
    let env = Env::new(lm_sys(false));
    sys_put(&env.sys, &profile_abs(220), b"an orphaned profile");
    env.sys
        .fake_fs()
        .set_attrs(Path::new(&profile_abs(220)), super::tests::RH)
        .unwrap();
    env.sys.sync_all();
    let before = snap_all(&env);
    let h = lm(&env, 220, &[], 8);
    let t = env.applied(&h);
    assert_eq!(
        try_read_abs(&env.sys, &profile_abs(220)),
        Some(profile_bytes(&start(220), 8))
    );
    assert_eq!(env.verify(&t), [(0, Observed::After)]);
    reverted(&env, &t);
    same(&before, &snap_all(&env));
}

#[test]
fn lm_t2_a_missing_profiles_folder_is_created_by_the_apply_and_left_by_the_revert() {
    let env = Env::new(lm_sys(true));
    let h = lm(&env, 220, &[], 8);
    let game = snap_game(&env);
    // `check` (read only) creates nothing and finds nothing to refuse.
    assert_eq!(env.check(&h).unwrap(), 1);
    assert!(!exists_abs(&env.sys, PROFILES));
    let t = env.applied(&h);
    assert!(exists_abs(&env.sys, &profile_abs(220)));
    // The folder is no op of the plan.
    assert_eq!(env.verify(&t), [(0, Observed::After)]);
    reverted(&env, &t);
    assert!(exists_abs(&env.sys, PROFILES), "Rerun's own state stays");
    assert!(!exists_abs(&env.sys, &profile_abs(220)));
    same(&game, &snap_game(&env));
}

#[test]
fn lm_t3_a_tampered_profile_is_foreign_left_and_closed_only_by_forget() {
    type Tamper = (&'static str, fn(&FakeSystem));
    let tampers: [Tamper; 4] = [
        ("other bytes", |s| {
            let p = profile_abs(220);
            s.fake_fs().remove_abs(Path::new(&p)).unwrap();
            sys_put(s, &p, b"rerun-profile 1\nmethod=direct\n");
        }),
        ("a folder", |s| {
            let p = profile_abs(220);
            s.fake_fs().remove_abs(Path::new(&p)).unwrap();
            s.fake_fs().mkdir_all(Path::new(&p)).unwrap();
        }),
        ("a hard link", |s| {
            s.fake_fs()
                .put_hardlink(
                    Path::new(&profile_abs(220)),
                    Path::new(&format!(r"{PROFILES}\link.bin")),
                )
                .unwrap();
        }),
        ("a link at the name", |s| {
            let p = profile_abs(220);
            s.fake_fs().remove_abs(Path::new(&p)).unwrap();
            s.fake_fs()
                .put_link(Path::new(&p), tag::SYMLINK, r"C:\Out\x.profile")
                .unwrap();
        }),
    ];
    for (what, tamper) in tampers {
        let env = Env::new(lm_sys(false));
        let t = env.applied(&lm(&env, 220, &[], 8));
        tamper(&env.sys);
        env.sys.sync_all();
        let tampered = snap_all(&env);
        assert_eq!(env.verify(&t), [(0, Observed::Foreign)], "{what}");
        let r = env.revert(&t).unwrap();
        assert_eq!(r.closed, None, "{what}");
        assert_eq!(r.ops[0].observed, Observed::Foreign, "{what}");
        same(&tampered, &snap_all(&env));
        assert_eq!(env.state(&t), Some(TxnState::Applied), "{what}: open");
        env.forget(&t).unwrap();
        assert!(
            matches!(env.state(&t), Some(TxnState::Closed(Closing::Forgotten))),
            "{what}"
        );
        same(&tampered, &snap_all(&env));
    }
}

#[test]
fn lm_t4_a_profile_the_user_deleted() {
    // Created by Rerun, deleted: `Before`, the transaction closes.
    let env = Env::new(lm_sys(false));
    let before = snap_all(&env);
    let t = env.applied(&lm(&env, 220, &[], 8));
    env.sys
        .fake_fs()
        .remove_abs(Path::new(&profile_abs(220)))
        .unwrap();
    let r = env.revert(&t).unwrap();
    assert_eq!(r.ops[0].observed, Observed::Before);
    assert_eq!(r.closed, Some(Closing::Reverted));
    same(&before, &snap_all(&env));

    // Replaced by Rerun, deleted: the old bytes cannot be put back over nothing (`Foreign`).
    let env = Env::new(lm_sys(false));
    sys_put(&env.sys, &profile_abs(220), b"an orphaned profile");
    let t = env.applied(&lm(&env, 220, &[], 8));
    env.sys
        .fake_fs()
        .remove_abs(Path::new(&profile_abs(220)))
        .unwrap();
    let r = env.revert(&t).unwrap();
    assert_eq!(r.ops[0].observed, Observed::Foreign);
    assert_eq!(r.closed, None);
    assert!(!exists_abs(&env.sys, &profile_abs(220)));
    env.forget(&t).unwrap();
}

#[test]
fn lm_t5_two_plans_for_one_profile_revert_newest_first() {
    let env = Env::new(lm_sys(false));
    let before = snap_all(&env);
    let a = profile_bytes(&start(220), 8);
    let t1 = env.applied(&lm(&env, 220, &[], 8));
    // The second plan finds the first profile: a replace with `h0` = rule A.
    let p2 = with_profile(
        &env,
        game_plan(&env, 220, &[]),
        profile_bytes(&start(220), 4),
    );
    assert!(
        matches!(&p2.ops[0], Op::ReplaceFile { old, .. } if old.sha256 == crate::plan::tests::sha(&a))
    );
    let t2 = env.applied(&stored(&env, &p2));
    let after = snap_all(&env);
    let n = records(&env, &t1);
    let r = env.revert(&t1);
    assert!(
        matches!(&r, Err(ExecError::Refused(Refusal::Later { txn })) if *txn == t2),
        "{r:?}"
    );
    same(&after, &snap_all(&env));
    assert_eq!(records(&env, &t1), n, "nothing written");
    reverted(&env, &t2);
    assert_eq!(try_read_abs(&env.sys, &profile_abs(220)), Some(a.clone()));
    reverted(&env, &t1);
    assert!(!exists_abs(&env.sys, &profile_abs(220)));
    same(&before, &snap_all(&env));

    // The same rule again over an applied profile: no replace of a file with its own content
    // (the planner says "nothing to do", P3-3c).
    let t = env.applied(&lm(&env, 220, &[], 8));
    let p = with_profile(&env, game_plan(&env, 220, &[]), a);
    assert!(p.encode().is_err());
    reverted(&env, &t);
}

#[test]
fn lm_t5b_profiles_of_two_apps_revert_in_either_order() {
    for first_a in [true, false] {
        let env = Env::new(lm_sys(false));
        let before = snap_all(&env);
        let ta = env.applied(&lm(&env, 220, &[], 8));
        let tb = env.applied(&lm(&env, 221, &[], 4));
        let (x, y) = if first_a { (ta, tb) } else { (tb, ta) };
        reverted(&env, &x);
        reverted(&env, &y);
        same(&before, &snap_all(&env));
    }
}

/// LM-T6 and its control K-LM3: the profile op at `last` (else op 0), `profiles` deleted before
/// the revert. Whether every game op was reverted.
fn t6(last: bool) -> bool {
    let env = Env::new(lm_sys(false));
    let game = snap_game(&env);
    let mut p = with_profile(
        &env,
        game_plan(&env, 220, &[Step::FileInstall(t1_spec())]),
        profile_bytes(&start(220), 8),
    );
    if last {
        let op = p.ops.remove(0);
        p.ops.push(op);
    }
    crate::plan::profile_knob::allow_profile_op_anywhere(last);
    let t = env.applied(&stored(&env, &p));
    let fx = env.sys.fake_fs();
    fx.remove_abs(Path::new(&profile_abs(220))).unwrap();
    fx.remove_abs(Path::new(PROFILES)).unwrap();
    let n = records(&env, &t);
    let r = env.revert(&t).unwrap();
    crate::plan::profile_knob::allow_profile_op_anywhere(false);
    let profile_op = if last { 5 } else { 0 };
    let h = r.halted.as_ref().unwrap();
    assert_eq!((h.op, h.root), (profile_op, 1), "{r:?}");
    // Review N4: a `RevertIntent` and a `RevertDone` per reverted op, none for the profile op.
    assert_eq!(records(&env, &t), n + 2 * r.ops.len(), "{r:?}");
    assert!(r.ops.iter().all(|o| o.op != profile_op));
    let a = app(&env.sys);
    let v = Journal::new(&a, InstanceTag::fixed(7))
        .load(&t, crate::journal::VerifyBackups::Length)
        .unwrap();
    let log = &v.ops[&profile_op];
    assert!(log.reverts.is_empty() && log.reverted.is_none());
    assert_eq!(r.closed, None);
    assert!(!exists_abs(&env.sys, PROFILES), "a revert never creates it");
    env.forget(&t).unwrap();
    game == snap_game(&env)
}

#[test]
fn lm_t6_a_deleted_profiles_folder_halts_at_op_0_after_every_other_op() {
    assert!(t6(false));
}

#[test]
fn k_lm3_the_profile_op_last_leaves_the_game_ops_unreverted() {
    assert!(!t6(true), "K-LM3 must leave the game folder changed");
}

#[test]
fn lm_t6b_a_missing_game_folder_halts_at_the_game_op_and_the_profile_stays() {
    let env = Env::new(lm_sys(false));
    let bytes = profile_bytes(&start(220), 8);
    let t = env.applied(&lm(
        &env,
        220,
        &[Step::FileInstall(spec(vec![entry(
            "new.dll", "new.dll", N,
        )]))],
        8,
    ));
    remove_tree(&env.sys, STEAM_GAME);
    let r = env.revert(&t).unwrap();
    let h = r.halted.as_ref().unwrap();
    assert_eq!((h.op, h.root), (1, 0), "{r:?}");
    assert!(r.ops.is_empty());
    assert_eq!(
        try_read_abs(&env.sys, &profile_abs(220)),
        Some(bytes.clone())
    );
    // A3: `forget` closes it; the profile stays and keeps applying through the launch option.
    env.forget(&t).unwrap();
    assert_eq!(try_read_abs(&env.sys, &profile_abs(220)), Some(bytes));
}

#[test]
fn lm_t7_a_junction_at_profiles_refuses_before_any_change() {
    let is_reparse = |r: &Refusal| matches!(r, Refusal::Root(e) if matches!(**e, RootError::Reparse { ref at, .. } if at.as_str() == "profiles"));
    // The apply.
    let env = Env::new(lm_sys(false));
    let h = lm(&env, 220, &[Step::FileInstall(t1_spec())], 8);
    env.sys.fake_fs().mkdir_all(Path::new(r"C:\Out")).unwrap();
    env.sys.swap_with_junction(PROFILES, r"C:\Out").unwrap();
    let game = snap_game(&env);
    let r = env.apply(&h);
    assert!(
        matches!(&r, Err(ApplyError::Refused(x)) if is_reparse(x)),
        "{r:?}"
    );
    assert!(env.states().is_empty());
    assert_eq!(
        super::tests::try_read_abs(&env.sys, &profile_at(r"C:\Out", 220)),
        None
    );
    same(&game, &snap_game(&env));

    // The revert and `verify`: a copy of the profile behind the junction stays.
    let env = Env::new(lm_sys(false));
    let t = env.applied(&lm(&env, 220, &[Step::FileInstall(t1_spec())], 8));
    let bytes = super::tests::read_abs(&env.sys, &profile_abs(220));
    sys_put(&env.sys, &profile_at(r"C:\Out", 220), &bytes);
    env.sys.swap_with_junction(PROFILES, r"C:\Out").unwrap();
    let game = snap_game(&env);
    let n = records(&env, &t);
    let v = env.verified(&t);
    assert!(
        matches!(&v, Err(ExecError::Refused(x)) if is_reparse(x)),
        "{v:?}"
    );
    let r = env.revert(&t);
    assert!(
        matches!(&r, Err(ExecError::Refused(x)) if is_reparse(x)),
        "{r:?}"
    );
    assert_eq!(records(&env, &t), n);
    assert_eq!(
        super::tests::try_read_abs(&env.sys, &profile_at(r"C:\Out", 220)),
        Some(bytes)
    );
    same(&game, &snap_game(&env));
}

/// `LocalAppData` as a junction to `LocalA` (Rerun's folder below it), with `profiles`.
fn moved_sys() -> FakeSystem {
    let sys = lm_sys(true);
    let fx = sys.fake_fs();
    fx.rename_abs(Path::new(LAD), Path::new(&format!("{LAD}A")))
        .unwrap();
    fx.put_link(Path::new(LAD), tag::MOUNT_POINT, &format!("{LAD}A"))
        .unwrap();
    fx.mkdir_all(Path::new(&format!(r"{LAD}A\Rerun\profiles")))
        .unwrap();
    sys.sync_all();
    sys
}

/// Moves `LocalA` to `LocalB` and points the junction there.
fn move_lad(sys: &FakeSystem) {
    let fx = sys.fake_fs();
    fx.rename_abs(Path::new(&format!("{LAD}A")), Path::new(&format!("{LAD}B")))
        .unwrap();
    fx.retarget(Path::new(LAD), &format!("{LAD}B")).unwrap();
    sys.sync_all();
}

/// LM-T8's apply; `unchecked`: K-LM2. Whether the apply wrote the profile.
fn t8_apply(unchecked: bool) -> bool {
    let env = Env::new(moved_sys());
    let h = lm(&env, 220, &[], 8);
    move_lad(&env.sys);
    let game = snap_game(&env);
    super::knob::uncheck_profiles_paths(unchecked);
    // `check` (read only) refuses the same way (review N3).
    let c = env.check(&h);
    let r = env.apply(&h);
    super::knob::uncheck_profiles_paths(false);
    let now = format!(r"{LAD}B\Rerun\profiles");
    let wrote = try_read_abs(&env.sys, &profile_at(&now, 220)).is_some();
    if !unchecked {
        match &r {
            Err(ApplyError::Refused(Refusal::ProfilesMoved(m))) => {
                assert_eq!(m.planned.to_string(), format!(r"{LAD}A\Rerun\profiles"));
                assert_eq!(m.now.to_string(), now);
            }
            other => panic!("{other:?}"),
        }
        assert!(matches!(&c, Err(Refusal::ProfilesMoved(_))), "check: {c:?}");
        assert!(env.states().is_empty());
        same(&game, &snap_game(&env));
    }
    wrote
}

#[test]
fn lm_t8_moved_local_app_data_refuses_the_apply_and_the_revert_works_where_it_is() {
    assert!(!t8_apply(false));
    // Revert and `verify` (A1): at the folder now, the move reported.
    let env = Env::new(moved_sys());
    let t = env.applied(&lm(&env, 220, &[], 8));
    move_lad(&env.sys);
    let now = format!(r"{LAD}B\Rerun\profiles");
    assert!(exists_abs(&env.sys, &profile_at(&now, 220)));
    let v = env.verified(&t).unwrap();
    assert_eq!(v.ops, [(0, Observed::After)]);
    assert!(v.profiles_moved.is_some());
    let r = env.revert(&t).unwrap();
    assert_eq!(r.closed, Some(Closing::Reverted));
    let m = r.profiles_moved.unwrap();
    assert_eq!(m.planned.to_string(), format!(r"{LAD}A\Rerun\profiles"));
    assert_eq!(m.now.to_string(), now);
    assert!(!exists_abs(&env.sys, &profile_at(&now, 220)));
}

#[test]
fn k_lm2_without_the_path_comparison_the_apply_writes() {
    assert!(t8_apply(true), "K-LM2 must write");
}

/// A forged head of `t` (records as written): `forge` changes the plan.
fn forge(env: &Env, t: &TxnId, f: impl Fn(&mut Plan)) {
    let dir = env.txn_dir(t);
    let head = super::tests::read_abs(&env.sys, &format!(r"{dir}\head.json"));
    let mut p: Plan = serde_json::from_slice(&head).unwrap();
    f(&mut p);
    let bytes = serde_json::to_vec(&p).unwrap();
    rewrite(env.sys.fake_fs(), &dir, Some(&bytes), |_| {});
}

const SAVE: &[u8] = b"the user's save game";

/// Op 0 of a forged head: the user's save game as "inline content" Rerun "created".
fn inline_on_game(p: &mut Plan) {
    p.ops[0] = Op::CreateFile {
        root: RootIx(0),
        path: rel("save.dat"),
        content: inline(SAVE.to_vec()),
        attrs: Attrs::default(),
    };
}

/// An applied profile and file in `G`, and the user's save game there.
fn t9_env() -> (Env, TxnId) {
    let env = Env::new(lm_sys(false));
    sys_put(&env.sys, &format!(r"{STEAM_GAME}\save.dat"), SAVE);
    let t = env.applied(&lm(
        &env,
        220,
        &[Step::FileInstall(spec(vec![entry(
            "new.dll", "new.dll", N,
        )]))],
        8,
    ));
    (env, t)
}

#[test]
fn lm_t9_forged_heads_are_blocked_for_revert_verify_and_stacking() {
    type Forgery = (&'static str, fn(&mut Plan));
    let forgeries: [Forgery; 5] = [
        ("inline content on the game root", inline_on_game),
        ("a profiles root of a manual origin", |p| {
            p.roots[1].origin = PlanOrigin::Manual;
        }),
        ("a profiles root with an identity", |p| {
            p.roots[1].id = RootId {
                volume_serial: 1,
                file_id: 2,
            };
        }),
        ("an upper-case profile name", |p| {
            if let Op::CreateFile { path, .. } = &mut p.ops[0] {
                *path = rel(&path.as_str().to_uppercase().replace(".PROFILE", ".profile"));
            }
        }),
        ("a package as a profile", |p| {
            let c = p.ops[1].content().unwrap().clone();
            if let Op::CreateFile { content, .. } = &mut p.ops[0] {
                *content = c;
            }
        }),
    ];
    for (what, f) in forgeries {
        let (env, t) = t9_env();
        forge(&env, &t, f);
        let before = snap_all(&env);
        let n = records(&env, &t);
        let blocked = |e: &Refusal| matches!(e, Refusal::Blocked { txn } if *txn == t);
        let v = env.verified(&t);
        assert!(
            matches!(&v, Err(ExecError::Refused(x)) if blocked(x)),
            "{what}: {v:?}"
        );
        let r = env.revert(&t);
        assert!(
            matches!(&r, Err(ExecError::Refused(x)) if blocked(x)),
            "{what}: {r:?}"
        );
        let other = lm(&env, 221, &[], 4);
        let a = env.apply(&other);
        assert!(
            matches!(&a, Err(ApplyError::Refused(x)) if blocked(x)),
            "{what}: {a:?}"
        );
        same(&before, &snap_all(&env));
        assert_eq!(records(&env, &t), n, "{what}");
    }
}

#[test]
fn k_lm1_inline_content_on_any_root_lets_a_forged_head_delete_a_game_file() {
    let (env, t) = t9_env();
    forge(&env, &t, inline_on_game);
    crate::plan::profile_knob::allow_inline_anywhere(true);
    let r = env.revert(&t);
    crate::plan::profile_knob::allow_inline_anywhere(false);
    assert!(r.is_ok(), "{r:?}");
    assert!(
        !exists_abs(&env.sys, &format!(r"{STEAM_GAME}\save.dat")),
        "K-LM1 must delete the save game"
    );
}

#[test]
fn lm_t10_a_game_folder_the_user_cannot_write() {
    // A profile-only plan writes nothing in the game folder.
    let env = Env::new(lm_sys(false));
    env.sys
        .fake_fs()
        .set_user_writable(Path::new(STEAM_GAME), false)
        .unwrap();
    let t = env.applied(&lm(&env, 220, &[], 8));
    reverted(&env, &t);
    // With a file op in the game folder: the elevated helper (phase 4).
    let env = Env::new(lm_sys(false));
    let h = lm(&env, 220, &[Step::FileInstall(t1_spec())], 8);
    env.sys
        .fake_fs()
        .set_user_writable(Path::new(STEAM_GAME), false)
        .unwrap();
    let r = env.apply(&h);
    assert!(
        matches!(&r, Err(ApplyError::Refused(Refusal::NeedsHelper))),
        "{r:?}"
    );
    assert!(!exists_abs(&env.sys, &profile_abs(220)));
}

#[test]
fn lm_t11_the_profiles_root_is_never_rebound_and_a_rebound_game_root_reverts_it() {
    // A `Rebind` record of the profiles root does not fit the head: `Blocked`.
    let env = Env::new(lm_sys(false));
    let p = with_profile(
        &env,
        game_plan(&env, 220, &[]),
        profile_bytes(&start(220), 8),
    );
    let rec = RebindRec {
        root: 1,
        old: PROFILES_ROOT_ID,
        store: crate::path::RootPath::new(LIB_E).unwrap(),
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
    assert!(super::bind::Bindings::of(&p, &[rec]).is_none());

    // The library moved: the revert halts at the game op; the rebind reverts everything, the
    // profile at its path in Rerun's folder (it names the old start: `path_mismatch`).
    let env = Env::new(lm_sys(false));
    copy_tree(&env.sys, STEAM_GAME, REF);
    env.sys.sync_all();
    let t = env.applied(&lm(&env, 220, &[Step::FileInstall(t1_spec())], 8));
    move_lib(&env.sys, STEAM_LIB, LIB_E);
    let r = env.revert(&t).unwrap();
    assert!(r.halted.is_some() && r.ops.is_empty(), "{r:?}");
    assert!(exists_abs(&env.sys, &profile_abs(220)));
    let pv = env.rebind_check(&t).unwrap();
    let r = env.revert_rebound(&t, &pv.to).unwrap();
    assert_eq!(r.closed, Some(Closing::Reverted), "{r:?}");
    assert!(!exists_abs(&env.sys, &profile_abs(220)));
    assert!(content_diff(&env.sys, REF, GAME_E).is_empty());
}

/// Review F3: `profiles` deleted and the library moved. The rebind looks only at game roots
/// (the profiles root is never rebound), so it is not refused as "more than one root"; it
/// reverts every game op and halts at the profile op without a record.
#[test]
fn lm_t11b_a_missing_profiles_folder_does_not_block_the_rebind_of_the_game_root() {
    let env = Env::new(lm_sys(false));
    copy_tree(&env.sys, STEAM_GAME, REF);
    env.sys.sync_all();
    let t = env.applied(&lm(&env, 220, &[Step::FileInstall(t1_spec())], 8));
    let fx = env.sys.fake_fs();
    fx.remove_abs(Path::new(&profile_abs(220))).unwrap();
    fx.remove_abs(Path::new(PROFILES)).unwrap();
    move_lib(&env.sys, STEAM_LIB, LIB_E);
    let pv = env.rebind_check(&t).unwrap();
    assert_eq!(pv.to.root, 0);
    let ph = pv
        .verified
        .halted
        .as_ref()
        .expect("the preview shows the halt (rule 5)");
    assert_eq!((ph.op, ph.root), (0, 1), "{pv:?}");
    let r = env.revert_rebound(&t, &pv.to).unwrap();
    let h = r.halted.as_ref().unwrap();
    assert_eq!((h.op, h.root), (0, 1), "{r:?}");
    assert_eq!(r.ops.len(), 5, "{r:?}");
    assert!(content_diff(&env.sys, REF, GAME_E).is_empty());
    assert!(!exists_abs(&env.sys, PROFILES), "a revert never creates it");
    env.forget(&t).unwrap();
}
