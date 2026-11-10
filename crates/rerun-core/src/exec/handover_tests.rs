//! The hand-over of shared files and folders (P4-8b, user decision E6, ADR 0020 amendment
//! P4-8b) against the fake: HO1 to HO8, the generations of B1, a new holder after a hand-over
//! (also when its apply rolls back), the tamper rows, the slot check after a hand-over, the
//! controls K-HO1 to K-HO3 and the cost of reading closed transactions (S4). The crash and
//! power-loss matrix is `handover_crash_tests.rs`.

use std::path::Path;

use super::tests::{Env, N, NEW, X, base, finish, game, pkg, read_abs, same};
use super::{
    ApplyError, Detail, ExecError, Inherited, InheritedOutcome, LeftWhy, Refusal, ShareKind,
};
use crate::journal::{Closing, Observed, TxnId};
use crate::prim::FileInstallSpec;
use crate::prim::tests::{GAME, app, entry, spec};
use crate::sys::fake::{FakeSystem, Fault, Prim};

const Y: &[u8] = b"y.dll of the package";
const Z: &[u8] = b"z.dll of the package";

fn sys() -> FakeSystem {
    finish(
        base()
            .file(pkg(r"mods\y.dll"), Y.to_vec())
            .file(pkg(r"mods\sub\z.dll"), Z.to_vec()),
    )
}

/// The creator of `new.dll` alone.
fn c_file() -> FileInstallSpec {
    spec(vec![entry("new.dll", "new.dll", N)])
}

/// The creator of `new.dll`, the folder `mods` and `mods\x.dll`.
fn c_dir() -> FileInstallSpec {
    spec(vec![
        entry("new.dll", "new.dll", N),
        entry(r"mods\x.dll", r"mods\x.dll", X),
    ])
}

/// A holder of `new.dll` that replaces `d3d9.dll`.
fn h_rep() -> FileInstallSpec {
    spec(vec![
        entry("new.dll", "new.dll", N),
        entry("d3d9.dll", "d3d9.dll", NEW),
    ])
}

/// A holder of `new.dll` with a file in `mods`.
fn h_y() -> FileInstallSpec {
    spec(vec![
        entry("new.dll", "new.dll", N),
        entry(r"mods\y.dll", r"mods\y.dll", Y),
    ])
}

/// A holder of `new.dll` with a folder of its own below `mods` (`mods\sub\z.dll`).
fn h_sub() -> FileInstallSpec {
    spec(vec![
        entry("new.dll", "new.dll", N),
        entry(r"mods\sub\z.dll", r"mods\sub\z.dll", Z),
    ])
}

fn exists(env: &Env, rel: &str) -> bool {
    super::tests::exists_abs(&env.sys, &game(rel))
}

fn reverted(env: &Env, t: &TxnId) -> super::RevertReport {
    let r = env.revert(t).unwrap_or_else(|e| panic!("revert {t}: {e}"));
    assert_eq!(r.closed, Some(Closing::Reverted), "{t}: {r:?}");
    r
}

fn kept_by(r: &super::RevertReport) -> Vec<(u16, Vec<TxnId>)> {
    r.ops
        .iter()
        .filter(|o| o.observed == Observed::Kept)
        .map(|o| match &o.detail {
            Some(Detail::Kept { by }) => (o.op, by.clone()),
            d => panic!("a kept op without its detail: {d:?}"),
        })
        .collect()
}

fn inherited(r: &super::RevertReport) -> Vec<Inherited> {
    r.ops
        .iter()
        .filter_map(|o| match &o.detail {
            Some(Detail::Inherited(x)) => Some(x.clone()),
            _ => None,
        })
        .flatten()
        .collect()
}

fn verified_inherited(env: &Env, t: &TxnId) -> Vec<Inherited> {
    env.verified(t)
        .unwrap()
        .details
        .into_values()
        .filter_map(|d| match d {
            Detail::Inherited(x) => Some(x),
            _ => None,
        })
        .flatten()
        .collect()
}

fn shares(env: &Env, t: &TxnId) -> Vec<(String, ShareKind)> {
    super::txn_status(&app(&env.sys), t)
        .unwrap()
        .shares
        .into_iter()
        .map(|s| (s.path.to_string(), s.kind))
        .collect()
}

/// HO1: a file, both orders. T1 creates `new.dll`, T2 holds it and replaces `d3d9.dll`. Newest
/// first as before; oldest first, T1 keeps `new.dll` for T2 ("kept for T2"), `status` and
/// `verify` of T2 name the hand-over, T2's revert removes it. Both identical.
#[test]
fn ho1_a_file_is_handed_over_in_either_order() {
    for oldest_first in [false, true] {
        let env = Env::new(sys());
        let floor = env.snap();
        let a = env.applied(&env.plan(&c_file()));
        let b = env.applied(&env.plan(&h_rep()));
        assert_eq!(
            shares(&env, &b),
            [(
                "new.dll".to_owned(),
                ShareKind::RemovedBy { from: a, by: a }
            )]
        );
        if oldest_first {
            let r = reverted(&env, &a);
            assert_eq!(kept_by(&r), [(0, vec![b])]);
            assert_eq!(read_abs(&env.sys, &game("new.dll")), N);
            assert_eq!(
                shares(&env, &b),
                [("new.dll".to_owned(), ShareKind::Inherits { from: a })]
            );
            let v = verified_inherited(&env, &b);
            assert_eq!(v.len(), 1);
            assert_eq!(
                (v[0].from, v[0].dir, v[0].outcome),
                (a, false, InheritedOutcome::Removed)
            );
            let r = reverted(&env, &b);
            let i = inherited(&r);
            assert_eq!(i.len(), 1);
            assert_eq!(i[0].outcome, InheritedOutcome::Removed);
            assert_eq!(i[0].path.to_string(), "new.dll");
        } else {
            reverted(&env, &b);
            assert!(exists(&env, "new.dll"));
            reverted(&env, &a);
        }
        same(&floor, &env.snap());
    }
}

/// HO2: folders. T1 creates `new.dll`, `mods` and `mods\x.dll`; T2 holds `new.dll` and puts
/// `mods\y.dll`; T3 holds it and creates `mods\sub` (nested). Every order identical; oldest
/// first, T1 keeps `new.dll` and `mods` and removes only `mods\x.dll`.
#[test]
fn ho2_folders_are_handed_over_with_the_files_below() {
    let orders: [[usize; 3]; 6] = [
        [0, 1, 2],
        [0, 2, 1],
        [1, 0, 2],
        [1, 2, 0],
        [2, 0, 1],
        [2, 1, 0],
    ];
    for order in orders {
        let env = Env::new(sys());
        let floor = env.snap();
        let t = [
            env.applied(&env.plan(&c_dir())),
            env.applied(&env.plan(&h_y())),
            env.applied(&env.plan(&h_sub())),
        ];
        for (i, k) in order.iter().enumerate() {
            let r = reverted(&env, &t[*k]);
            if i == 0 && *k == 0 {
                let kept: Vec<u16> = kept_by(&r).into_iter().map(|(op, _)| op).collect();
                assert_eq!(kept.len(), 2, "new.dll and mods: {r:?}");
                assert!(!exists(&env, r"mods\x.dll"));
                assert!(exists(&env, r"mods\y.dll") && exists(&env, r"mods\sub\z.dll"));
            }
        }
        same(&floor, &env.snap());
    }
}

/// HO3: a creator and three holders (one also creating in `mods`): every one of the 24 orders
/// of the revert leaves the game folder identical, and `new.dll` is there until the last
/// transaction that relies on it is reverted.
#[test]
fn ho3_every_order_of_four_transactions_is_identical() {
    let mut orders = Vec::new();
    for a in 0..4 {
        for b in 0..4 {
            for c in 0..4 {
                for d in 0..4 {
                    let o = [a, b, c, d];
                    if (0..4).all(|x| o.contains(&x)) {
                        orders.push(o);
                    }
                }
            }
        }
    }
    assert_eq!(orders.len(), 24);
    for order in orders {
        let env = Env::new(sys());
        let floor = env.snap();
        let t = [
            env.applied(&env.plan(&c_dir())),
            env.applied(&env.plan(&h_rep())),
            env.applied(&env.plan(&h_y())),
            env.applied(&env.plan(&h_sub())),
        ];
        for (i, k) in order.iter().enumerate() {
            reverted(&env, &t[*k]);
            if i < 3 {
                assert!(
                    exists(&env, "new.dll"),
                    "{order:?}: new.dll gone while a transaction relies on it"
                );
            }
        }
        same(&floor, &env.snap());
    }
}

/// HO4: forget. (a) a creator forgotten before its hand-over gives no duty: the holder's revert
/// leaves `new.dll` (X11); (b) one forgotten after it (left open by a foreign op) neither; (c) a
/// forgotten holder no longer relies: the other holder removes it; (d) the inheritor forgotten
/// after the hand-over leaves it, its `forget` preview names it, and a new holder's revert
/// removes it (S3).
#[test]
fn ho4_forget_and_the_hand_over() {
    // (a)
    let env = Env::new(sys());
    let a = env.applied(&env.plan(&c_file()));
    let b = env.applied(&env.plan(&h_rep()));
    env.forget(&a).unwrap();
    reverted(&env, &b);
    assert!(
        exists(&env, "new.dll"),
        "a forgotten creator: nothing to inherit"
    );

    // (b): T1's `mods\x.dll` changed, so T1 stays open after keeping `new.dll`.
    let env = Env::new(sys());
    let a = env.applied(&env.plan(&c_dir()));
    let b = env.applied(&env.plan(&h_rep()));
    let fx = env.sys.fake_fs();
    fx.remove_abs(Path::new(&game(r"mods\x.dll"))).unwrap();
    fx.put_file(Path::new(&game(r"mods\x.dll")), b"edited")
        .unwrap();
    let r = env.revert(&a).unwrap();
    assert_eq!(r.closed, None);
    assert_eq!(kept_by(&r).len(), 1);
    env.forget(&a).unwrap();
    reverted(&env, &b);
    assert!(
        exists(&env, "new.dll"),
        "a forgotten creator after its hand-over"
    );

    // (c)
    let env = Env::new(sys());
    let floor = env.snap();
    let a = env.applied(&env.plan(&c_file()));
    let b = env.applied(&env.plan(&h_rep()));
    let c = env.applied(&env.plan(&h_y()));
    reverted(&env, &a);
    env.forget(&c).unwrap();
    // C's own files stay (forget); restore them by hand to compare the rest.
    reverted(&env, &b);
    assert!(
        !exists(&env, "new.dll"),
        "the forgotten holder does not keep it"
    );
    let fx = env.sys.fake_fs();
    fx.remove_abs(Path::new(&game(r"mods\y.dll"))).unwrap();
    fx.remove_abs(Path::new(&game("mods"))).unwrap();
    same(&floor, &env.snap());

    // (d)
    let env = Env::new(sys());
    let floor = env.snap();
    let a = env.applied(&env.plan(&c_file()));
    let b = env.applied(&env.plan(&h_rep()));
    reverted(&env, &a);
    assert_eq!(
        shares(&env, &b),
        [("new.dll".to_owned(), ShareKind::Inherits { from: a })]
    );
    env.forget(&b).unwrap();
    assert!(exists(&env, "new.dll"));
    // T2's replace of d3d9.dll stays too (forget); a new holder takes `new.dll` over.
    let e = env.applied(&env.plan(&spec(vec![
        entry("new.dll", "new.dll", N),
        entry(r"mods\y.dll", r"mods\y.dll", Y),
    ])));
    reverted(&env, &e);
    assert!(
        !exists(&env, "new.dll"),
        "the new holder's revert removes it"
    );
    let after = env.snap();
    let d3d9 = read_abs(&env.sys, &game("d3d9.dll"));
    assert_eq!(d3d9, NEW, "the forgotten replace stays");
    assert_ne!(floor, after);
}

/// HO5: not Rerun's. A file the user provided, held twice, stays; a file the user put back after
/// the creator's revert deleted it stays under a later holder; a file rewritten with the same
/// content under a holder cannot be handed over (`Held` before the first record), newest first
/// identical.
#[test]
fn ho5_files_rerun_did_not_create_are_never_removed() {
    // The user's own file, held by two transactions.
    let env = Env::new(finish(
        base()
            .file(pkg(r"mods\y.dll"), Y.to_vec())
            .file(game("new.dll"), N.to_vec()),
    ));
    let before = env.snap();
    let b = env.applied(&env.plan(&h_rep()));
    let c = env.applied(&env.plan(&h_y()));
    reverted(&env, &b);
    reverted(&env, &c);
    assert!(exists(&env, "new.dll"));
    same(&before, &env.snap());

    // Put back after the creator's revert deleted it.
    let env = Env::new(sys());
    let a = env.applied(&env.plan(&c_file()));
    let b = env.applied(&env.plan(&h_rep()));
    reverted(&env, &a);
    reverted(&env, &b);
    assert!(!exists(&env, "new.dll"));
    env.sys
        .fake_fs()
        .put_file(Path::new(&game("new.dll")), N)
        .unwrap();
    let before = env.snap();
    let c = env.applied(&env.plan(&h_y()));
    reverted(&env, &c);
    assert!(
        exists(&env, "new.dll"),
        "another file ID: not the creator's"
    );
    same(&before, &env.snap());

    // Rewritten with the same content under a holder.
    let env = Env::new(sys());
    let floor = env.snap();
    let a = env.applied(&env.plan(&c_file()));
    let b = env.applied(&env.plan(&h_rep()));
    let fx = env.sys.fake_fs();
    fx.remove_abs(Path::new(&game("new.dll"))).unwrap();
    fx.put_file(Path::new(&game("new.dll")), N).unwrap();
    let mid = env.snap();
    match env.revert(&a) {
        Err(ExecError::Refused(Refusal::Held { txn })) if txn == b => {}
        r => panic!("{r:?}"),
    }
    same(&mid, &env.snap());
    assert!(matches!(
        env.with(|cx| super::revert_check(cx, &a)),
        Err(Refusal::Held { .. })
    ));
    reverted(&env, &b);
    reverted(&env, &a);
    same(&floor, &env.snap());
}

/// HO6: still newest first. A hold of a file the creator replaced (`Held`); a later replace of a
/// created file (`Later`); a plan that changes a held file (`HeldChange`, S2); a holder whose
/// apply was interrupted (no `Done`).
#[test]
fn ho6_what_stays_newest_first() {
    // A hold of a replaced file.
    let env = Env::new(sys());
    let a = env.applied(&env.plan(&spec(vec![entry("d3d9.dll", "d3d9.dll", NEW)])));
    let b = env.applied(&env.plan(&spec(vec![
        entry("d3d9.dll", "d3d9.dll", NEW),
        entry("new.dll", "new.dll", N),
    ])));
    match env.revert(&a) {
        Err(ExecError::Refused(Refusal::Held { txn })) if txn == b => {}
        r => panic!("{r:?}"),
    }
    reverted(&env, &b);
    reverted(&env, &a);

    // A later replace of a created file.
    let env = Env::new(finish(
        base().file(pkg("new2.dll"), b"another new.dll".to_vec()),
    ));
    let a = env.applied(&env.plan(&c_file()));
    let b = env.applied(&env.plan(&spec(vec![entry(
        "new2.dll",
        "new.dll",
        b"another new.dll",
    )])));
    match env.revert(&a) {
        Err(ExecError::Refused(Refusal::Later { txn })) if txn == b => {}
        r => panic!("{r:?}"),
    }

    // S2: a plan that would change a held file.
    let env = Env::new(finish(
        base().file(pkg("new2.dll"), b"another new.dll".to_vec()),
    ));
    let _a = env.applied(&env.plan(&c_file()));
    let b = env.applied(&env.plan(&h_rep()));
    let h = env.plan(&spec(vec![entry(
        "new2.dll",
        "new.dll",
        b"another new.dll",
    )]));
    let before = env.snap();
    match env.apply(&h) {
        Err(ApplyError::Refused(Refusal::HeldChange { txn })) if txn == b => {}
        r => panic!("{r:?}"),
    }
    same(&before, &env.snap());

    // A holder whose apply was interrupted: it relies, so the creator waits.
    let env = Env::new(sys());
    let a = env.applied(&env.plan(&c_file()));
    let h = env.plan(&h_y());
    // The second folder created is `mods` (the first is the transaction's own).
    let r = env.apply_armed(&h, |fx| fx.fault(Prim::CreateDir, 2, Fault::CrashAfter));
    assert!(r.is_err(), "{r:?}");
    env.sys.fake_fs().restart();
    match env.revert(&a) {
        Err(ExecError::Refused(Refusal::Held { .. })) => {}
        r => panic!("{r:?}"),
    }
}

/// HO7: changed after the hand-over. The held file edited, a user file in the handed-over
/// folder: the inheritor leaves them, says why, and closes (X14).
#[test]
fn ho7_a_changed_object_is_left_and_the_inheritor_closes() {
    let env = Env::new(sys());
    let a = env.applied(&env.plan(&c_dir()));
    let b = env.applied(&env.plan(&h_y()));
    reverted(&env, &a);
    let fx = env.sys.fake_fs();
    fx.remove_abs(Path::new(&game("new.dll"))).unwrap();
    fx.put_file(Path::new(&game("new.dll")), b"edited by the user")
        .unwrap();
    fx.put_file(Path::new(&game(r"mods\user.txt")), b"mine")
        .unwrap();
    let v = verified_inherited(&env, &b);
    assert!(
        v.iter()
            .any(|i| i.outcome == InheritedOutcome::Left(LeftWhy::Changed)),
        "{v:?}"
    );
    let r = reverted(&env, &b);
    let mut outcomes: Vec<InheritedOutcome> = inherited(&r).iter().map(|i| i.outcome).collect();
    outcomes.sort_by_key(|o| format!("{o:?}"));
    assert_eq!(
        outcomes,
        [
            InheritedOutcome::Left(LeftWhy::Changed),
            InheritedOutcome::Left(LeftWhy::NotEmpty)
        ]
    );
    assert!(exists(&env, "new.dll") && exists(&env, r"mods\user.txt"));
}

/// HO8: an entry of the listing that cannot be read while a duty arises: `Blocked` before any
/// record; after `forget` of that entry the revert removes the file.
#[test]
fn ho8_an_unreadable_entry_blocks_a_duty() {
    let env = Env::new(sys());
    let floor = env.snap();
    // An earlier, unrelated transaction, made unreadable afterwards.
    let z = env.applied(&env.plan(&spec(vec![entry(r"mods\y.dll", r"mods\y.dll", Y)])));
    let a = env.applied(&env.plan(&c_file()));
    let b = env.applied(&env.plan(&h_rep()));
    reverted(&env, &a);
    let head = format!(r"{}\head.json", env.txn_dir(&z));
    env.sys.fake_fs().remove_abs(Path::new(&head)).unwrap();
    env.sys.fake_fs().put_file(Path::new(&head), b"{}").unwrap();
    let mid = env.snap();
    match env.revert(&b) {
        Err(ExecError::Refused(Refusal::Blocked { txn })) if txn == z => {}
        r => panic!("{r:?}"),
    }
    same(&mid, &env.snap());
    env.forget(&z).unwrap();
    reverted(&env, &b);
    assert!(!exists(&env, "new.dll"));
    // Z's own files stay (forgotten): remove them to compare the rest.
    let fx = env.sys.fake_fs();
    fx.remove_abs(Path::new(&game(r"mods\y.dll"))).unwrap();
    fx.remove_abs(Path::new(&game("mods"))).unwrap();
    same(&floor, &env.snap());
}

/// HO8 with an entry whose folder cannot be read at all (a junction in its place, a view
/// error): the holder's revert is `Blocked` while the held file still has the ID it recorded.
#[test]
fn ho8_an_unreadable_folder_blocks_a_holder() {
    let env = Env::new(sys());
    let z = env.applied(&env.plan(&spec(vec![entry(r"mods\y.dll", r"mods\y.dll", Y)])));
    let a = env.applied(&env.plan(&c_file()));
    let b = env.applied(&env.plan(&h_rep()));
    reverted(&env, &a);
    env.sys
        .swap_with_junction(env.txn_dir(&z), r"C:\x")
        .unwrap();
    let mid = env.snap();
    match env.revert(&b) {
        Err(ExecError::Refused(Refusal::Blocked { txn })) if txn == z => {}
        r => panic!("{r:?}"),
    }
    same(&mid, &env.snap());
    env.forget(&z).unwrap();
    reverted(&env, &b);
    assert!(!exists(&env, "new.dll"));
}

/// B1: generations. T1 creates `new.dll` and `mods`, hands them to T2, T2 removes them; T3
/// creates them again (new file IDs) and hands them to T4. T4's revert inherits only from T3
/// (T1's closed `Kept` ops name other IDs), and the folder is identical.
#[test]
fn ho_generations_inherit_only_from_the_creator_of_this_instance() {
    let env = Env::new(sys());
    let floor = env.snap();
    for _ in 0..2 {
        let a = env.applied(&env.plan(&c_dir()));
        let b = env.applied(&env.plan(&h_y()));
        reverted(&env, &a);
        let r = reverted(&env, &b);
        let from: Vec<TxnId> = inherited(&r).iter().map(|i| i.from).collect();
        assert_eq!(from, [a, a], "{r:?}");
        same(&floor, &env.snap());
    }
}

/// A new holder after a hand-over whose apply rolls back leaves the file (the state before its
/// apply); applied and reverted, it removes it.
#[test]
fn ho_a_new_holder_rolled_back_keeps_the_file() {
    let env = Env::new(sys());
    let a = env.applied(&env.plan(&c_file()));
    let b = env.applied(&env.plan(&h_rep()));
    reverted(&env, &a);
    env.forget(&b).unwrap();
    let h = env.plan(&h_y());
    let before = env.snap();
    let r = env.apply_armed(&h, |fx| {
        fx.fault(
            Prim::CreateDir,
            2,
            Fault::Fail(crate::sys::SysErrorKind::Other),
        );
    });
    assert!(matches!(r, Err(ApplyError::RolledBack { .. })), "{r:?}");
    same(&before, &env.snap());
    let e = env.applied(&h);
    reverted(&env, &e);
    assert!(!exists(&env, "new.dll"));
}

/// The slot check after a hand-over: the holder's `Hold` keeps the slot of its package; the
/// creator's reverted op does not.
#[test]
fn ho_the_slot_stays_with_the_holder() {
    let env = Env::new(finish(base().file(
        r"C:\Users\Player\AppData\Local\Rerun\packages\other-pack\1.0.2\new.dll",
        b"another new.dll".to_vec(),
    )));
    let a = env.applied(&env.plan(&c_file()));
    let b = env.applied(&env.plan(&h_rep()));
    reverted(&env, &a);
    let fr = crate::prim::tests::fr(&env.sys);
    let g = crate::policy::root::GameDir::open_manual(&env.sys, &fr, Path::new(GAME)).unwrap();
    let ap = app(&env.sys);
    let main = crate::prim::tests::rel("game.exe");
    let mut s = spec(vec![entry("new.dll", "new.dll", b"another new.dll")]);
    s.package = "other-pack".into();
    let e = crate::prim::plan(
        &[crate::prim::Step::FileInstall(s)],
        &crate::prim::PlanCtx {
            game: &g,
            app: Some(&ap),
            steam_app: None,
            main_exe: Some(&main),
            reg: crate::policy::registry::RegPolicy.reader(&env.sys),
            app_path: None,
        },
    )
    .unwrap_err()
    .to_string();
    assert!(e.contains(&format!("from transaction {b}")), "{e}");
}

/// Tamper rows (docs/06 row 14): a forged hold over a user file finds no creator; a hold whose
/// `Done.file_id` was changed fails the ID chain (no duty); a planted `RevertDone { Kept }` on
/// a live creator makes the holder remove exactly the creator's instance.
#[test]
fn ho_tamper_rows() {
    use crate::journal::tests::{append_revert_done, rewrite};
    // Another `Done.file_id` of the hold: no duty, the file stays.
    let env = Env::new(sys());
    let a = env.applied(&env.plan(&c_file()));
    let b = env.applied(&env.plan(&h_rep()));
    reverted(&env, &a);
    rewrite(env.sys.fake_fs(), &env.txn_dir(&b), None, |e| {
        e.done_file_id(0, 0x1234);
    });
    reverted(&env, &b);
    assert!(exists(&env, "new.dll"));

    // A planted `RevertDone { Kept }` on a live creator: the holder removes the creator's file.
    let env = Env::new(sys());
    let a = env.applied(&env.plan(&c_file()));
    let b = env.applied(&env.plan(&h_rep()));
    append_revert_done(env.sys.fake_fs(), &env.txn_dir(&a), 0, Observed::Kept);
    reverted(&env, &b);
    assert!(!exists(&env, "new.dll"), "exactly the creator's instance");
    // `Kept` on an op that is no created object is refused for the revert (records_fit).
    let env = Env::new(sys());
    let a = env.applied(&env.plan(&spec(vec![entry("d3d9.dll", "d3d9.dll", NEW)])));
    append_revert_done(env.sys.fake_fs(), &env.txn_dir(&a), 0, Observed::Kept);
    assert!(matches!(
        env.revert(&a),
        Err(ExecError::Refused(Refusal::Blocked { .. }))
    ));
}

/// The controls (`exec::knob`): each one breaks a property the tests above pin.
#[test]
fn ho_controls_bite() {
    // K-HO1: the ID chain off: the file the user put back is removed by a later holder.
    super::knob::handover(1);
    let env = Env::new(sys());
    let a = env.applied(&env.plan(&c_file()));
    let b = env.applied(&env.plan(&h_rep()));
    reverted(&env, &a);
    reverted(&env, &b);
    env.sys
        .fake_fs()
        .put_file(Path::new(&game("new.dll")), N)
        .unwrap();
    let c = env.applied(&env.plan(&h_y()));
    reverted(&env, &c);
    super::knob::handover(0);
    assert!(!exists(&env, "new.dll"), "K-HO1 does not bite");

    // K-HO2: condition (d) off: removed under a live holder.
    super::knob::handover(2);
    let env = Env::new(sys());
    let a = env.applied(&env.plan(&c_file()));
    let b = env.applied(&env.plan(&h_rep()));
    let _c = env.applied(&env.plan(&h_y()));
    reverted(&env, &a);
    reverted(&env, &b);
    super::knob::handover(0);
    assert!(!exists(&env, "new.dll"), "K-HO2 does not bite");

    // K-HO3: a forgotten creator honoured.
    super::knob::handover(3);
    let env = Env::new(sys());
    let a = env.applied(&env.plan(&c_dir()));
    let b = env.applied(&env.plan(&h_rep()));
    let fx = env.sys.fake_fs();
    fx.remove_abs(Path::new(&game(r"mods\x.dll"))).unwrap();
    fx.put_file(Path::new(&game(r"mods\x.dll")), b"edited")
        .unwrap();
    let _ = env.revert(&a).unwrap();
    env.forget(&a).unwrap();
    reverted(&env, &b);
    super::knob::handover(0);
    assert!(!exists(&env, "new.dll"), "K-HO3 does not bite");
}

/// S4: the cost of the hand-over with many closed transactions. `n` creators each handed a file
/// to a holder that removed it (closed transactions with `Kept` ops, the case the prefilter
/// cannot skip), then one more hand-over: the time of the last revert, printed.
fn cost(n: usize) -> std::time::Duration {
    let mut b = base();
    for i in 0..n {
        b = b.file(pkg(&format!("f{i}.dll")), format!("f{i}").into_bytes());
    }
    let env = Env::new(finish(b));
    for i in 0..n {
        let f = format!("f{i}.dll");
        let data = format!("f{i}").into_bytes();
        let a = env.applied(&env.plan(&spec(vec![entry(&f, &f, &data)])));
        let h = env.applied(&env.plan(&spec(vec![
            entry(&f, &f, &data),
            entry("new.dll", "new.dll", N),
        ])));
        reverted(&env, &a);
        reverted(&env, &h);
    }
    let a = env.applied(&env.plan(&c_file()));
    let h = env.applied(&env.plan(&h_rep()));
    reverted(&env, &a);
    let t0 = std::time::Instant::now();
    reverted(&env, &h);
    let dt = t0.elapsed();
    assert!(!exists(&env, "new.dll"));
    dt
}

#[test]
fn ho_cost_with_closed_transactions_small() {
    let dt = cost(20);
    assert!(dt.as_secs() < 10, "{dt:?}");
}

/// The measured case of docs/09 (S4): 500 closed creators with `Kept` ops.
#[test]
#[ignore = "cost measurement, about 13 minutes in a debug build (the setup of 500 hand-overs)"]
fn ho_cost_with_500_closed_transactions() {
    let dt = cost(500);
    println!("MEASURED S4: the revert after 500 hand-overs took {dt:?}");
}

// ---------- Review follow-ups (P4-8b) ----------

/// Review follow-up 1 (security 1): the last transaction that relies on a handed-over folder is
/// an interrupted apply. T1 keeps `new.dll` and `mods` for T2; T3 holds `new.dll`, creates
/// `mods\sub` and crashes; T2's revert leaves both to T3 (`status` and the report say so); T3's
/// revert (the recovery of its apply) removes them: identical.
#[test]
fn ho_an_interrupted_reliant_carries_the_hand_over() {
    let env = Env::new(sys());
    let floor = env.snap();
    let a = env.applied(&env.plan(&c_dir()));
    let b = env.applied(&env.plan(&h_y()));
    reverted(&env, &a);
    let h = env.plan(&h_sub());
    // The second folder created is `mods\sub` (the first is the transaction's own).
    let r = env.apply_armed(&h, |fx| fx.fault(Prim::CreateDir, 2, Fault::CrashAfter));
    assert!(r.is_err(), "{r:?}");
    env.sys.fake_fs().restart();
    let c = *env
        .states()
        .iter()
        .map(|(t, _)| t)
        .max()
        .expect("the interrupted transaction");
    let r = reverted(&env, &b);
    let still: Vec<InheritedOutcome> = inherited(&r).iter().map(|i| i.outcome).collect();
    assert!(
        !still.is_empty() && still.iter().all(|o| *o == InheritedOutcome::StillRelied(c)),
        "{r:?}"
    );
    assert!(exists(&env, "new.dll") && exists(&env, "mods"));
    // The status of the interrupted transaction is truthful: it inherits both.
    let s = shares(&env, &c);
    assert!(
        s.iter().all(|(_, k)| *k == ShareKind::Inherits { from: a }) && s.len() == 2,
        "{s:?}"
    );
    let r = env.revert(&c).unwrap();
    assert!(r.closed.is_some(), "{r:?}");
    same(&floor, &env.snap());
}

/// Review follow-up 2 (security 2, senior N-4): a same-content swap of a handed-over file right
/// before the guard that would delete it: the guard sees another file ID and leaves it.
#[test]
fn ho_a_swap_before_the_deleting_guard_is_left() {
    use std::sync::{Arc, Mutex};
    let count_guards = |env: &Env, t: &TxnId| -> usize {
        let n = Arc::new(Mutex::new(0usize));
        let m = Arc::clone(&n);
        env.sys.fake_fs().on_step(move |_, ev| {
            if ev.call == Some(Prim::OpenGuard) && ev.name.eq_ignore_ascii_case("new.dll") {
                *m.lock().unwrap() += 1;
            }
        });
        reverted(env, t);
        env.sys.fake_fs().clear_on_step();
        *n.lock().unwrap()
    };
    // A dry run counts the guards of `new.dll` in the holder's revert.
    let env = Env::new(sys());
    let a = env.applied(&env.plan(&c_file()));
    let b = env.applied(&env.plan(&h_rep()));
    reverted(&env, &a);
    let last = count_guards(&env, &b);
    assert!(last >= 1);
    // The run: before the last guard of `new.dll`, the file is rewritten with the same content.
    let env = Env::new(sys());
    let a = env.applied(&env.plan(&c_file()));
    let b = env.applied(&env.plan(&h_rep()));
    reverted(&env, &a);
    let seen = Arc::new(Mutex::new(0usize));
    let s2 = Arc::clone(&seen);
    let abs = game("new.dll");
    env.sys.fake_fs().on_step(move |f, ev| {
        if ev.call == Some(Prim::OpenGuard) && ev.name.eq_ignore_ascii_case("new.dll") {
            let mut k = s2.lock().unwrap();
            *k += 1;
            if *k == last {
                f.remove_abs(Path::new(&abs)).unwrap();
                f.put_file(Path::new(&abs), N).unwrap();
            }
        }
    });
    let r = env.revert(&b).unwrap();
    env.sys.fake_fs().clear_on_step();
    assert_eq!(r.closed, Some(Closing::Reverted));
    let i = inherited(&r);
    assert_eq!(
        i.iter().map(|x| x.outcome).collect::<Vec<_>>(),
        [InheritedOutcome::Left(LeftWhy::OtherFileId)],
        "{r:?}"
    );
    assert!(
        exists(&env, "new.dll"),
        "the swapped-in file is not Rerun's"
    );
}

/// Review follow-up 3 (security 3, senior S-2): a closed creator whose records do not fit its
/// head (`Kept` on a replace) is never a basis of a deletion: it is blocked, and the holder's
/// revert is refused while the held file is there.
#[test]
fn ho_a_creator_that_does_not_fit_its_records_is_blocked() {
    use crate::journal::tests::rewrite;
    let env = Env::new(sys());
    let a = env.applied(&env.plan(&c_file()));
    let b = env.applied(&env.plan(&h_rep()));
    reverted(&env, &a);
    // Rewrite T1's head (records rewritten consistently) so op 0 is a replace: `Kept` on it does
    // not fit.
    let dir = env.txn_dir(&a);
    let head = String::from_utf8(read_abs(&env.sys, &format!(r"{dir}\head.json"))).unwrap();
    let start = head.find(r#"{"create_file":"#).unwrap();
    let forged = head[..start].to_owned()
        + &head[start..].replacen(
            r#"{"create_file":{"root":0,"path":"new.dll","#,
            &format!(
                r#"{{"replace_file":{{"root":0,"path":"new.dll","old":{{"sha256":"{}","len":3,"attrs":{{"readonly":false,"hidden":false,"system":false}}}},"#,
                "ab".repeat(32)
            ),
            1,
        );
    rewrite(env.sys.fake_fs(), &dir, Some(forged.as_bytes()), |_| {});
    let mid = env.snap();
    match env.revert(&b) {
        Err(ExecError::Refused(Refusal::Blocked { txn })) if txn == a => {}
        r => panic!("{r:?}"),
    }
    same(&mid, &env.snap());
}

/// Review follow-up 4 (security 4): the ID chain breaks after the check before the first record
/// (a same-content rewrite while the revert runs): the revert halts there with `Held` (open,
/// resumable), it does not fail after its records.
#[test]
fn ho_a_chain_broken_mid_revert_is_a_halt() {
    use std::sync::{Arc, Mutex};
    let env = Env::new(sys());
    let a = env.applied(&env.plan(&c_dir()));
    let b = env.applied(&env.plan(&h_y()));
    // The second guard of `new.dll` in T1's revert is the loop's (the first is the check).
    let seen = Arc::new(Mutex::new(0usize));
    let s2 = Arc::clone(&seen);
    let abs = game("new.dll");
    env.sys.fake_fs().on_step(move |f, ev| {
        if ev.call == Some(Prim::OpenGuard) && ev.name.eq_ignore_ascii_case("new.dll") {
            let mut k = s2.lock().unwrap();
            *k += 1;
            if *k == 2 {
                f.remove_abs(Path::new(&abs)).unwrap();
                f.put_file(Path::new(&abs), N).unwrap();
            }
        }
    });
    let r = env.revert(&a);
    env.sys.fake_fs().clear_on_step();
    let r = r.unwrap();
    assert_eq!(r.closed, None);
    let h = r.halted.as_ref().expect("a halt");
    assert_eq!(h.op, 0);
    assert!(matches!(*h.why, Refusal::Held { txn } if txn == b), "{h:?}");
    assert!(!r.ops.is_empty(), "the ops above were reverted first");
    // Newest first then closes both.
    reverted(&env, &b);
    reverted(&env, &a);
}

/// Review follow-up 5 (senior S-1): a changed held file inside a handed-over folder: `verify`
/// predicts exactly what the revert then does (the file left, the folder not empty).
#[test]
fn ho7_verify_predicts_the_revert_for_a_changed_file_in_the_folder() {
    let env = Env::new(sys());
    let a = env.applied(&env.plan(&spec(vec![entry(r"mods\x.dll", r"mods\x.dll", X)])));
    let b = env.applied(&env.plan(&spec(vec![
        entry(r"mods\x.dll", r"mods\x.dll", X),
        entry(r"mods\y.dll", r"mods\y.dll", Y),
    ])));
    reverted(&env, &a);
    let fx = env.sys.fake_fs();
    fx.remove_abs(Path::new(&game(r"mods\x.dll"))).unwrap();
    fx.put_file(Path::new(&game(r"mods\x.dll")), b"edited")
        .unwrap();
    let key = |v: Vec<Inherited>| {
        let mut x: Vec<(String, InheritedOutcome)> = v
            .into_iter()
            .map(|i| (i.path.to_string(), i.outcome))
            .collect();
        x.sort_by(|p, q| p.0.cmp(&q.0));
        x
    };
    let predicted = key(verified_inherited(&env, &b));
    let r = reverted(&env, &b);
    let done = key(inherited(&r));
    assert_eq!(predicted, done);
    assert_eq!(
        done,
        [
            ("mods".to_owned(), InheritedOutcome::Left(LeftWhy::NotEmpty)),
            (
                r"mods\x.dll".to_owned(),
                InheritedOutcome::Left(LeftWhy::Changed)
            ),
        ]
    );
}

/// Review follow-up 9 (senior N-1, N3): an heir that recorded a `Rebind` gets no duty (X14):
/// after its library moved, its revert inherits nothing and reports nothing inherited.
#[test]
fn ho_an_heir_after_a_rebind_inherits_nothing() {
    use super::rebind_tests::{LIB_E, move_lib, rb_plan, rb_sys};
    use crate::prim::Step;
    use crate::prim::tests::{STEAM_GAME, STEAM_LIB};
    let env = Env::new(rb_sys());
    let a = env.applied(&rb_plan(&env, &[Step::FileInstall(c_file())]));
    let b = env.applied(&rb_plan(&env, &[Step::FileInstall(h_rep())]));
    reverted(&env, &a);
    assert!(super::tests::exists_abs(
        &env.sys,
        &format!(r"{STEAM_GAME}\new.dll")
    ));
    move_lib(&env.sys, STEAM_LIB, LIB_E);
    let p = env.rebind_check(&b).unwrap();
    // A crash right after the `Rebind` record; the next revert is a plain one with the record.
    let r = env.revert_rebound_armed(&b, &p.to, |fx| {
        fx.fault(Prim::FlushDir, 1, Fault::CrashAfter);
    });
    assert!(r.is_err(), "{r:?}");
    env.sys.fake_fs().restart();
    let r = env.revert(&b).unwrap();
    assert!(r.closed.is_some(), "{r:?}");
    assert!(inherited(&r).is_empty(), "no duty after a rebind: {r:?}");
    let moved = format!(r"{LIB_E}\steamapps\common\G\new.dll");
    assert!(super::tests::exists_abs(&env.sys, &moved), "X14: left");
}

/// Review follow-up 8 (senior N-3): the text of `TooManyTransactions` says what helps.
#[test]
fn ho_too_many_transactions_says_what_helps() {
    let t = Refusal::TooManyTransactions {
        limit: super::share::MAX_SHARE_HEADS,
    }
    .to_string();
    assert!(t.contains("nothing was changed"), "{t}");
    assert!(t.contains("prunes its journal"), "{t}");
    assert!(!t.contains("  "), "one space between words: {t}");
}
