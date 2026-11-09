//! The revert at roots that do not open (P2-10a; user decisions 6b-d and E3): H4 a file plan
//! whose root is gone halts at its newest op without a record and finishes once the root is
//! back; the E3 classes (absent halts, undecided refuses before any change, a root the user
//! cannot write halts after D4); a plan over two roots reverts the open one and halts at the
//! gone one; the control K-R9 (every root opened eagerly, as before) fails H4's check.

use std::path::Path;

use super::tests::{
    Env, N, acf, base, closed, finish, manifest, same, snap_at, steam_plan, steam_sys, sys_put,
    t1_spec,
};
use super::{ExecError, Refusal, RevertReport};
use crate::detect::steam::AppState;
use crate::journal::{Closing, InstanceTag, Journal, TxnId, TxnState, VerifyBackups};
use crate::plan::{self, Op, Plan, RootIx, store};
use crate::policy::root::{GameDir, RootError};
use crate::prim::tests::{GAME, STEAM_LIB, app, entry, fr, spec};
use crate::sys::SysErrorKind;

/// The number of records of `t`, read without changing anything.
fn records(env: &Env, t: &TxnId) -> usize {
    let a = app(&env.sys);
    let j = Journal::new(&a, InstanceTag::fixed(5));
    j.load(t, VerifyBackups::Length).map_or(0, |v| v.log.len())
}

/// The revert halted at `op` of `root`, with nothing reverted in this run, and `why` holds.
fn halted_at(
    r: &Result<RevertReport, ExecError>,
    op: u16,
    root: u16,
    why: impl Fn(&Refusal) -> bool,
) -> bool {
    matches!(r, Ok(rep) if rep.closed.is_none()
        && rep.ops.is_empty()
        && rep.halted.as_ref().is_some_and(|h| h.op == op && h.root == root && why(&h.why)))
}

fn not_found(r: &Refusal) -> bool {
    matches!(r, Refusal::Root(e) if matches!(&**e, RootError::Sys(s) if s.kind == SysErrorKind::NotFound))
}

/// H4 as a check (review N1: scenario and checks in one function, named findings): a file
/// plan whose manual root was moved away. `verify` and `revert` halt at the newest op without
/// a record, the transaction stays applied; with the folder back, the revert closes and the
/// folder is as before.
pub(crate) fn h4_check() -> Vec<String> {
    let mut f = Vec::new();
    let env = Env::new(finish(base()));
    let before = env.snap();
    let t = env.applied(&env.plan(&t1_spec()));
    let n = records(&env, &t);
    env.sys.rename_abs(GAME, r"D:\Games\Away").unwrap();
    match env.verified(&t) {
        Ok(v) if v.ops.is_empty() && v.halted.as_ref().is_some_and(|h| h.op == 4) => {}
        other => f.push(format!("H4 verify: {other:?}")),
    }
    let r = env.revert(&t);
    if !halted_at(&r, 4, 0, not_found) {
        f.push(format!("H4 halted: {r:?}"));
    }
    if records(&env, &t) != n || env.state(&t) != Some(TxnState::Applied) {
        f.push(format!("H4 records: {:?}", env.state(&t)));
    }
    env.sys.rename_abs(r"D:\Games\Away", GAME).unwrap();
    let r = env.revert(&t);
    if closed(&r) != Some(Closing::Reverted) {
        f.push(format!("H4 resumed: {r:?}"));
    }
    let now = env.snap();
    if before != now {
        f.push(format!("H4 snapshot: {:#?}", before.diff(&now)));
    }
    f
}

#[test]
fn h4_a_file_plan_whose_root_is_gone_halts_without_a_record() {
    let f = h4_check();
    assert!(f.is_empty(), "{f:#?}");
}

/// K-R9: a revert that opens every root eagerly (as before P2-10a) refuses instead of
/// halting; H4's check reports it.
#[test]
fn k_r9_opening_every_root_eagerly_breaks_h4() {
    super::knob::open_eagerly(true);
    let f = h4_check();
    super::knob::open_eagerly(false);
    assert!(
        f.iter().any(|x| x.starts_with("H4 halted:")),
        "K-R9 not caught: {f:#?}"
    );
}

/// E3 for a Steam root: absent (manifest removed, not installed, another install folder, the
/// library gone) halts without a record and finishes once the app is back; undecided (an
/// update pending, a manifest that cannot be read) refuses, `verify` too, nothing written.
#[test]
fn h_a_steam_root_halts_when_gone_and_refuses_when_undecided() {
    type Change = fn(&Env);
    let put_manifest = |env: &Env, text: &str| {
        let fx = env.sys.fake_fs();
        fx.remove_abs(Path::new(&manifest(220))).unwrap();
        sys_put(&env.sys, &manifest(220), text.as_bytes());
    };
    let gone: [(&str, Change); 4] = [
        ("manifest removed", |env| {
            env.sys
                .fake_fs()
                .remove_abs(Path::new(&manifest(220)))
                .unwrap();
        }),
        ("not installed", |env| {
            let fx = env.sys.fake_fs();
            fx.remove_abs(Path::new(&manifest(220))).unwrap();
            sys_put(&env.sys, &manifest(220), acf(220, 1).as_bytes());
        }),
        ("another install folder", |env| {
            let fx = env.sys.fake_fs();
            fx.remove_abs(Path::new(&manifest(220))).unwrap();
            let moved = acf(220, 4).replace("\"installdir\"\t\t\"G\"", "\"installdir\"\t\t\"G2\"");
            sys_put(&env.sys, &manifest(220), moved.as_bytes());
        }),
        // Not named by E3: the library path not found counts like a manual root's.
        ("library gone", |env| {
            env.sys.rename_abs(STEAM_LIB, r"D:\Away").unwrap();
        }),
    ];
    for (what, change) in gone {
        let env = Env::new(steam_sys());
        let t = env.applied(&steam_plan(
            &env,
            220,
            &spec(vec![entry("new.dll", "new.dll", N)]),
        ));
        let n = records(&env, &t);
        change(&env);
        let r = env.revert(&t);
        // The halt names the real reason.
        let why = |w: &Refusal| match what {
            "library gone" => not_found(w),
            "manifest removed" => matches!(
                w,
                Refusal::SteamGone {
                    app_id: 220,
                    gone: super::SteamGone::NoManifest
                }
            ),
            "another install folder" => matches!(
                w,
                Refusal::SteamGone {
                    app_id: 220,
                    gone: super::SteamGone::OtherFolder
                }
            ),
            _ => matches!(
                w,
                Refusal::Steam {
                    app_id: 220,
                    state: AppState::NotInstalled
                }
            ),
        };
        assert!(halted_at(&r, 0, 0, why), "{what}: {r:?}");
        assert_eq!(records(&env, &t), n, "{what}: no record");
        // Back: the revert finishes.
        if what == "library gone" {
            env.sys.rename_abs(r"D:\Away", STEAM_LIB).unwrap();
        } else {
            let fx = env.sys.fake_fs();
            let _ = fx.remove_abs(Path::new(&manifest(220)));
            sys_put(&env.sys, &manifest(220), acf(220, 4).as_bytes());
        }
        assert_eq!(
            closed(&env.revert(&t)),
            Some(Closing::Reverted),
            "{what}: resumed"
        );
    }
    let undecided: [(&str, &str); 2] = [
        ("update pending", "pending"),
        ("manifest unreadable", "garbage"),
    ];
    for (what, kind) in undecided {
        let env = Env::new(steam_sys());
        let t = env.applied(&steam_plan(
            &env,
            220,
            &spec(vec![entry("new.dll", "new.dll", N)]),
        ));
        let n = records(&env, &t);
        let text = if kind == "pending" {
            acf(220, 4 | 2)
        } else {
            "\"AppState\"\n{\n".to_owned()
        };
        put_manifest(&env, &text);
        let r = env.revert(&t);
        assert!(
            matches!(
                &r,
                Err(ExecError::Refused(
                    Refusal::Steam {
                        app_id: 220,
                        state: AppState::UpdatePending
                    } | Refusal::SteamManifest { app_id: 220 }
                ))
            ),
            "{what}: {r:?}"
        );
        assert!(
            matches!(env.verified(&t), Err(ExecError::Refused(_))),
            "{what}: verify"
        );
        assert_eq!(records(&env, &t), n, "{what}: nothing written");
    }
}

/// E3 for a manual root: another folder at its path is undecided (refused, nothing written;
/// a rebind may bind it later, D5); a root the user cannot write is open for D4 (a running
/// game refuses) and halts the file ops.
#[test]
fn h_a_manual_root_refuses_when_replaced_and_halts_when_not_writable() {
    let env = Env::new(finish(base()));
    let t = env.applied(&env.plan(&t1_spec()));
    let n = records(&env, &t);
    env.sys.rename_abs(GAME, r"D:\Games\Moved").unwrap();
    env.sys.fake_fs().mkdir_all(Path::new(GAME)).unwrap();
    let r = env.revert(&t);
    assert!(
        matches!(&r, Err(ExecError::Refused(Refusal::Root(e))) if matches!(**e, RootError::IdentityMismatch { .. })),
        "{r:?}"
    );
    assert_eq!(records(&env, &t), n);

    let env = Env::new(finish(base()));
    let before = env.snap();
    let t = env.applied(&env.plan(&t1_spec()));
    env.sys
        .fake_fs()
        .set_user_writable(Path::new(GAME), false)
        .unwrap();
    let held = env
        .sys
        .fake_fs()
        .map_image_as(4242, Path::new(&super::tests::game("game.exe")))
        .unwrap();
    let r = env.revert(&t);
    assert!(
        matches!(&r, Err(ExecError::Refused(Refusal::Busy(s))) if s.as_str().ends_with("game.exe")),
        "D4 on a root that is not writable: {r:?}"
    );
    drop(held);
    let r = env.revert(&t);
    assert!(
        halted_at(&r, 4, 0, |w| matches!(w, Refusal::NeedsHelper)),
        "{r:?}"
    );
    env.sys
        .fake_fs()
        .set_user_writable(Path::new(GAME), true)
        .unwrap();
    assert_eq!(closed(&env.revert(&t)), Some(Closing::Reverted));
    same(&before, &env.snap());
}

/// Sets the root index of a file op.
fn reroot(op: &mut Op, to: u16) {
    match op {
        Op::CreateDir { root, .. }
        | Op::CreateFile { root, .. }
        | Op::ReplaceFile { root, .. }
        | Op::IniValue { root, .. } => {
            *root = RootIx(to);
        }
        Op::CreateKey { .. }
        | Op::SetValue { .. }
        | Op::TokenList { .. }
        | Op::FirewallRule { .. } => {}
    }
}

/// Two roots in one plan (6b-d): the ops of the root that opens are reverted, newest first,
/// down to the newest op of the gone one, where the revert halts; once that root is back,
/// the revert finishes and both folders are as before.
#[test]
fn h_a_plan_over_two_roots_reverts_the_open_one_and_halts_at_the_gone_one() {
    const H: &str = r"D:\Games\H";
    let env = Env::new(finish(
        base().file(format!(r"{H}\game.exe"), b"MZ".to_vec()),
    ));
    let before_g = env.snap();
    let before_h = snap_at(&env.sys, H);
    let a = app(&env.sys);
    let load = |h| -> Plan { plan::decode(plan::load(&a, &h).unwrap().bytes()).unwrap() };
    let g = load(env.plan(&t1_spec()));
    let other = {
        let fr = fr(&env.sys);
        let dir = GameDir::open_manual(&env.sys, &fr, Path::new(H)).unwrap();
        load(env.plan_for(
            &dir,
            None,
            &spec(vec![
                entry("new.dll", "new.dll", N),
                entry(r"mods\x.dll", r"m\x.dll", super::tests::X),
            ]),
        ))
    };
    let mut both = g.clone();
    both.roots.push(other.roots[0].clone());
    for mut op in other.ops.clone() {
        reroot(&mut op, 1);
        both.ops.push(op);
    }
    let first_h = u16::try_from(g.ops.len()).unwrap();
    let last = u16::try_from(both.ops.len() - 1).unwrap();
    let h = store(&a, &both.encode().unwrap()).unwrap();
    let t = env.applied(&h);
    env.sys.rename_abs(GAME, r"D:\Games\Away").unwrap();
    let v = env.verified(&t).unwrap();
    assert_eq!(
        v.ops.iter().map(|(k, _)| *k).collect::<Vec<_>>(),
        (first_h..=last).collect::<Vec<_>>(),
        "{v:?}"
    );
    assert!(v.halted.as_ref().is_some_and(|x| x.op == first_h - 1));
    let rep = env.revert(&t).unwrap();
    assert_eq!(rep.closed, None);
    assert_eq!(
        rep.ops.iter().map(|o| o.op).collect::<Vec<_>>(),
        (first_h..=last).rev().collect::<Vec<_>>(),
        "the open root's ops, newest first"
    );
    let halt = rep.halted.unwrap();
    assert_eq!((halt.op, halt.root), (first_h - 1, 0));
    same(&before_h, &snap_at(&env.sys, H));
    // Applied with revert records: open for stacking (condition 3), resumable.
    assert_eq!(env.state(&t), Some(TxnState::Applied));
    // Review S-b: now `H` is gone and `G` back. The ops of `H` were reverted cleanly, so
    // neither `verify` nor the revert halts at them.
    env.sys.rename_abs(H, r"D:\Games\HAway").unwrap();
    env.sys.rename_abs(r"D:\Games\Away", GAME).unwrap();
    let v = env.verified(&t).unwrap();
    assert!(v.halted.is_none(), "{v:?}");
    assert_eq!(
        v.ops.iter().map(|(k, _)| *k).collect::<Vec<_>>(),
        (0..first_h).collect::<Vec<_>>(),
        "{v:?}"
    );
    assert_eq!(closed(&env.revert(&t)), Some(Closing::Reverted));
    same(&before_g, &env.snap());
    env.sys.rename_abs(r"D:\Games\HAway", H).unwrap();
    same(&before_h, &snap_at(&env.sys, H));
}

/// Security N-5: an op whose revert left it `Foreign`, on a root that cannot run file ops
/// now, stays visible in `verify` (as recorded), so the user sees why the transaction stays
/// open; the revert halts at the other root's newest op.
#[test]
fn h_verify_shows_a_foreign_op_of_a_root_that_is_gone() {
    const H: &str = r"D:\Games\H";
    let env = Env::new(finish(
        base().file(format!(r"{H}\game.exe"), b"MZ".to_vec()),
    ));
    let a = app(&env.sys);
    let load = |h| -> Plan { plan::decode(plan::load(&a, &h).unwrap().bytes()).unwrap() };
    let mut both = load(env.plan(&t1_spec()));
    let other = {
        let fr = fr(&env.sys);
        let dir = GameDir::open_manual(&env.sys, &fr, Path::new(H)).unwrap();
        load(env.plan_for(&dir, None, &spec(vec![entry("new.dll", "new.dll", N)])))
    };
    both.roots.push(other.roots[0].clone());
    for mut op in other.ops.clone() {
        reroot(&mut op, 1);
        both.ops.push(op);
    }
    let mine = u16::try_from(both.ops.len() - 1).unwrap();
    let t = env.applied(&store(&a, &both.encode().unwrap()).unwrap());
    // The user edits our file in `H`; `G` goes away: the revert leaves `H`'s op foreign and
    // halts at `G`'s newest op.
    let p = format!(r"{H}\new.dll");
    env.sys.fake_fs().remove_abs(Path::new(&p)).unwrap();
    sys_put(&env.sys, &p, b"edited");
    env.sys.rename_abs(GAME, r"D:\Games\Away").unwrap();
    let rep = env.revert(&t).unwrap();
    assert!(
        rep.halted.as_ref().is_some_and(|x| x.op == mine - 1),
        "{rep:?}"
    );
    // Now `H` is gone too and `G` back: the foreign op is still shown.
    env.sys.rename_abs(H, r"D:\Games\HAway").unwrap();
    env.sys.rename_abs(r"D:\Games\Away", GAME).unwrap();
    let v = env.verified(&t).unwrap();
    assert!(v.halted.is_none(), "{v:?}");
    assert!(
        v.ops
            .iter()
            .any(|(k, o)| *k == mine && *o == crate::journal::Observed::Foreign),
        "{v:?}"
    );
}

/// Review S-1: a root folder that changes while it is opened is a race (`Busy`), not gone:
/// the revert refuses, nothing written. A Steam game folder swapped between its open and
/// the check of its `common` entry, and a `NotFound` from `Dir::info` after any open.
#[test]
fn h_a_root_swapped_while_it_is_opened_is_refused() {
    use crate::sys::fake::{FsOp, Prim};
    let env = Env::new(steam_sys());
    let t = env.applied(&steam_plan(
        &env,
        220,
        &spec(vec![entry("new.dll", "new.dll", N)]),
    ));
    let n = records(&env, &t);
    let swapped = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let s2 = std::sync::Arc::clone(&swapped);
    env.sys.fake_fs().on_step(move |fs, ev| {
        if ev.op == FsOp::Metadata
            && ev.name == "G"
            && !s2.swap(true, std::sync::atomic::Ordering::SeqCst)
        {
            fs.rename_ignoring_shares(
                Path::new(crate::prim::tests::STEAM_GAME),
                Path::new(r"D:\SteamLibrary\steamapps\common\G.old"),
            )
            .unwrap();
            fs.mkdir_all(Path::new(crate::prim::tests::STEAM_GAME))
                .unwrap();
        }
    });
    let r = env.revert(&t);
    env.sys.fake_fs().clear_on_step();
    assert!(swapped.load(std::sync::atomic::Ordering::SeqCst), "swapped");
    assert!(
        matches!(&r, Err(ExecError::Refused(Refusal::Root(e))) if matches!(&**e, RootError::Sys(s) if s.kind == SysErrorKind::Busy)),
        "{r:?}"
    );
    assert_eq!(records(&env, &t), n, "nothing written");

    // `Dir::info` reports `NotFound` (deleted or renamed meanwhile): at every info call of
    // the revert, never a halt.
    let mut hit = false;
    for nth in 1..=12 {
        let env = Env::new(finish(base()));
        let t = env.applied(&env.plan(&t1_spec()));
        let r = env.revert_armed(&t, |fx| {
            fx.fail_at(Prim::ReadSide(FsOp::Info), nth, SysErrorKind::NotFound);
        });
        env.sys.fake_fs().clear_faults();
        assert!(
            !matches!(&r, Ok(rep) if rep.halted.is_some()),
            "info #{nth}: {r:?}"
        );
        hit |= matches!(&r, Err(ExecError::Refused(Refusal::Root(e))) if matches!(&**e, RootError::Sys(s) if s.kind == SysErrorKind::Busy));
    }
    assert!(hit, "some info call was the root's");
}

/// Review S-d, E3: a root whose open fails `Busy` or `AccessDenied` (at any open of the
/// revert), or that is a reparse point below its store, is undecided: refused, never a
/// halt. A `NotFound` of the open itself is absent (the positive control), and so is a Steam
/// app whose manifest says installed while its folder is not found.
#[test]
fn h_undecided_opens_refuse_and_a_missing_folder_halts() {
    use crate::sys::fake::{FsOp, Prim};
    for kind in [
        SysErrorKind::Busy,
        SysErrorKind::AccessDenied,
        SysErrorKind::NotFound,
    ] {
        let mut refused = false;
        let mut halted = false;
        for nth in 1..=6 {
            let env = Env::new(finish(base()));
            let t = env.applied(&env.plan(&t1_spec()));
            let r = env.revert_armed(&t, |fx| {
                fx.fail_at(Prim::ReadSide(FsOp::OpenDir), nth, kind);
            });
            env.sys.fake_fs().clear_faults();
            let is_halt = matches!(&r, Ok(rep) if rep.halted.is_some());
            halted |= is_halt;
            refused |= matches!(&r, Err(ExecError::Refused(Refusal::Root(e))) if matches!(&**e, RootError::Sys(s) if s.kind == kind));
            if kind != SysErrorKind::NotFound {
                assert!(!is_halt, "{kind:?} at open #{nth}: {r:?}");
            }
        }
        if kind == SysErrorKind::NotFound {
            assert!(halted, "a missing root halts");
        } else {
            assert!(refused, "{kind:?}: some open was the root's");
        }
    }
    // A junction at the Steam game folder: `Reparse`, refused.
    let env = Env::new(steam_sys());
    let t = env.applied(&steam_plan(
        &env,
        220,
        &spec(vec![entry("new.dll", "new.dll", N)]),
    ));
    let n = records(&env, &t);
    env.sys
        .swap_with_junction(crate::prim::tests::STEAM_GAME, r"C:\Elsewhere")
        .unwrap();
    let r = env.revert(&t);
    assert!(
        matches!(&r, Err(ExecError::Refused(Refusal::Root(e))) if matches!(**e, RootError::Reparse { .. })),
        "{r:?}"
    );
    assert_eq!(records(&env, &t), n);
    // The manifest says installed, the folder is not found: absent, a halt.
    let env = Env::new(steam_sys());
    let t = env.applied(&steam_plan(
        &env,
        220,
        &spec(vec![entry("new.dll", "new.dll", N)]),
    ));
    env.sys
        .rename_abs(
            crate::prim::tests::STEAM_GAME,
            r"D:\SteamLibrary\steamapps\common\Gone",
        )
        .unwrap();
    let r = env.revert(&t);
    assert!(halted_at(&r, 0, 0, not_found), "{r:?}");
}
