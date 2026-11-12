//! `ContentRef::Patch` (P4-10, ADR 0020 amendment P4-10) in `exec`, against the fake, with a
//! hand-made patch op (the `laa_patch` planner has its own tests, `prim::laa_tests`):
//!
//! - PT1 round trip: only the edited bytes change, R/H/S kept; `verify` `After`; the revert
//!   restores the file bit for bit (snapshot identical).
//! - PT2 the original put back by someone else (Steam's "Verify integrity of game files", the
//!   game's repair) before the revert: `Before`, the revert changes nothing and closes; with other
//!   attributes than before it is a different state (`Foreign`, left).
//! - PT3 another content (an update): `Foreign`, left; the transaction stays open until `forget`.
//! - PT4 a patch whose old byte or result hash does not fit the file (a forged or stale head):
//!   nothing is written, the apply rolls back, the folder is identical.
//! - PT5 a failure at every call of the apply and the revert: rolled back or revertable, then
//!   identical.
//! - PT6 a patch of a file another live transaction holds (`HeldChange`, P4-8b S2).

use std::path::Path;

use sha2::{Digest, Sha256};

use super::tests::{Env, N, OLD, base, closed, finish, finish_open, game, read_abs, same};
use super::{ApplyError, Outcome, Refusal};
use crate::journal::{Closing, Observed, TxnState};
use crate::plan::{
    ByteEdit, ContentRef, FORMAT, FileState, Op, Plan, PlanHash, PlanOrigin, PlanRoot, RootIx,
    RootKind, store,
};
use crate::policy::root::GameDir;
use crate::prim::tests::{GAME, app, entry, fr, rel, spec};
use crate::sys::SysErrorKind;
use crate::sys::fake::FakeSystem;
use crate::sys::fs::Attrs;

/// The edits of the tests: `old` → `Old`, `d3d9` → `D3d9`.
fn edits() -> Vec<ByteEdit> {
    vec![
        ByteEdit {
            offset: 0,
            old: b'o',
            new: b'O',
        },
        ByteEdit {
            offset: 4,
            old: b'd',
            new: b'D',
        },
    ]
}

const PATCHED: &[u8] = b"Old D3d9 of the game";

fn sha(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}

/// A plan of one patch of `d3d9.dll` (read-only, hidden: `base`/`finish`) in the manual game
/// folder, with `edits` and the result hash `result`.
fn patch_plan(env: &Env, edits: Vec<ByteEdit>, result: [u8; 32]) -> PlanHash {
    let fr = fr(&env.sys);
    let g = GameDir::open_manual(&env.sys, &fr, Path::new(GAME)).unwrap();
    let old = FileState {
        sha256: sha(OLD),
        len: u64::try_from(OLD.len()).unwrap(),
        attrs: super::tests::RH,
    };
    let p = Plan {
        format: FORMAT,
        roots: vec![PlanRoot {
            kind: RootKind::Game,
            path: g.path().clone(),
            id: g.id(),
            origin: PlanOrigin::Manual,
            main_exe: Some(rel("game.exe")),
            main_sha256: None,
            other_exes: None,
        }],
        ops: vec![Op::ReplaceFile {
            root: RootIx(0),
            path: rel("d3d9.dll"),
            old,
            content: ContentRef::Patch {
                base: old,
                edits,
                sha256: result,
            },
            attrs: super::tests::RH,
        }],
        source: None,
    };
    let a = app(&env.sys);
    store(&a, &p.encode().unwrap()).unwrap()
}

fn good(env: &Env) -> PlanHash {
    patch_plan(env, edits(), sha(PATCHED))
}

fn put_back(sys: &FakeSystem, data: &[u8], attrs: Attrs) {
    let abs = game("d3d9.dll");
    sys.fake_fs().remove_abs(Path::new(&abs)).unwrap();
    sys.fake_fs().put_file(Path::new(&abs), data).unwrap();
    sys.fake_fs().set_attrs(Path::new(&abs), attrs).unwrap();
    sys.sync_all();
}

#[test]
fn pt1_round_trip_changes_only_the_edited_bytes() {
    let env = Env::new(finish(base()));
    let before = env.snap();
    let h = good(&env);
    let shown = {
        let a = app(&env.sys);
        crate::plan::preview_stored(&crate::plan::load(&a, &h).unwrap())
            .unwrap()
            .to_string()
    };
    assert!(shown.contains("  0. patch file 0:d3d9.dll\n"), "{shown}");
    assert!(
        shown.contains("     byte at 0x0: 0x6f -> 0x4f\n     byte at 0x4: 0x64 -> 0x44\n"),
        "{shown}"
    );
    assert!(shown.contains("note: patched files:"), "{shown}");
    let t = env.applied(&h);
    assert_eq!(read_abs(&env.sys, &game("d3d9.dll")), PATCHED);
    assert_eq!(env.verify(&t), [(0, Observed::After)]);
    let rep = env.revert(&t).unwrap();
    assert_eq!(rep.closed, Some(Closing::Reverted));
    same(&before, &env.snap());
}

#[test]
fn pt2_the_original_put_back_first_is_before() {
    let env = Env::new(finish(base()));
    let before = env.snap();
    let t = env.applied(&good(&env));
    // Steam's file check writes the original bytes again (here with the old attributes).
    put_back(&env.sys, OLD, super::tests::RH);
    assert_eq!(env.verify(&t), [(0, Observed::Before)]);
    let rep = env.revert(&t).unwrap();
    assert_eq!(rep.closed, Some(Closing::Reverted));
    assert_eq!(rep.ops[0].observed, Observed::Before);
    same(&before, &env.snap());

    // The original bytes without the attributes it had: not the state before, left as it is.
    let env = Env::new(finish(base()));
    let t = env.applied(&good(&env));
    put_back(&env.sys, OLD, Attrs::default());
    assert_eq!(env.verify(&t), [(0, Observed::Foreign)]);
    let rep = env.revert(&t).unwrap();
    assert_eq!(rep.closed, None);
    assert_eq!(read_abs(&env.sys, &game("d3d9.dll")), OLD);
    env.forget(&t).unwrap();
}

#[test]
fn pt3_another_content_is_foreign_and_left() {
    let env = Env::new(finish(base()));
    let t = env.applied(&good(&env));
    put_back(&env.sys, b"d3d9 of the update 1.1", super::tests::RH);
    assert_eq!(env.verify(&t), [(0, Observed::Foreign)]);
    let rep = env.revert(&t).unwrap();
    assert_eq!(rep.closed, None, "open until forget");
    assert_eq!(
        read_abs(&env.sys, &game("d3d9.dll")),
        b"d3d9 of the update 1.1"
    );
    assert_eq!(env.state(&t), Some(TxnState::Applied));
    env.forget(&t).unwrap();
    assert!(matches!(env.state(&t), Some(TxnState::Closed(_))));
}

#[test]
fn pt4_a_patch_that_does_not_fit_writes_nothing() {
    // Another old byte than the file has at an edited offset.
    let wrong_old = vec![ByteEdit {
        offset: 0,
        old: b'x',
        new: b'O',
    }];
    // The right edits with another result hash.
    for (edits, result) in [
        (wrong_old, sha(b"Old d3d9 of the game")),
        (edits(), sha(b"something else")),
    ] {
        let env = Env::new(finish(base()));
        let before = env.snap();
        let h = patch_plan(&env, edits, result);
        match env.apply(&h) {
            Err(ApplyError::RolledBack { .. }) => {}
            r => panic!("{r:?}"),
        }
        same(&before, &env.snap());
        assert!(
            env.states()
                .iter()
                .all(|(_, s)| matches!(s, Some(TxnState::Closed(Closing::RolledBack))))
        );
    }
}

#[test]
fn pt5_a_failure_at_any_call_ends_identical() {
    let (apply_calls, revert_calls) = {
        let env = Env::new(finish(base()));
        let h = good(&env);
        let fx = env.sys.fake_fs();
        let rec = |f: &crate::sys::fake::FakeFs| f.record_calls(true);
        let t = match env.apply_armed(&h, rec) {
            Ok(Outcome::Applied(t)) => t,
            other => panic!("{other:?}"),
        };
        fx.record_calls(false);
        let a = fx.take_calls();
        assert!(closed(&env.revert_armed(&t, rec)).is_some());
        fx.record_calls(false);
        (a, fx.take_calls())
    };
    for (in_revert, trace) in [(false, &apply_calls), (true, &revert_calls)] {
        for (i, call) in trace.iter().enumerate() {
            let nth = trace[..=i].iter().filter(|c| *c == call).count();
            let env = Env::new(finish(base()));
            let before = env.snap();
            let h = good(&env);
            let what = format!("fail at call {i} ({call:?} #{nth}), revert {in_revert}");
            let arm = |f: &crate::sys::fake::FakeFs| f.fail_at(*call, nth, SysErrorKind::Other);
            if in_revert {
                let t = env.applied(&h);
                let _ = env.revert_armed(&t, arm);
            } else if let Ok(Outcome::Applied(t)) = env.apply_armed(&h, arm) {
                let _ = env.revert(&t);
            }
            env.sys.fake_fs().clear_faults();
            finish_open(&env, &what);
            assert!(
                before == env.snap(),
                "{what}: {:#?}",
                before.diff(&env.snap())
            );
        }
    }
}

#[test]
fn pt6_a_held_file_is_not_patched() {
    let env = Env::new(finish(base()));
    let created = env.applied(&env.plan(&spec(vec![entry("new.dll", "new.dll", N)])));
    // A second transaction holds `new.dll` next to a change of its own.
    let holder = env.applied(&env.plan(&spec(vec![
        entry("new.dll", "new.dll", N),
        entry("d3d9.dll", "d3d9.dll", super::tests::NEW),
    ])));
    let fr = fr(&env.sys);
    let g = GameDir::open_manual(&env.sys, &fr, Path::new(GAME)).unwrap();
    let old = FileState {
        sha256: sha(N),
        len: u64::try_from(N.len()).unwrap(),
        attrs: Attrs::default(),
    };
    let mut patched = N.to_vec();
    patched[0] ^= 0x20;
    let p = Plan {
        format: FORMAT,
        roots: vec![PlanRoot {
            kind: RootKind::Game,
            path: g.path().clone(),
            id: g.id(),
            origin: PlanOrigin::Manual,
            main_exe: Some(rel("game.exe")),
            main_sha256: None,
            other_exes: None,
        }],
        ops: vec![Op::ReplaceFile {
            root: RootIx(0),
            path: rel("new.dll"),
            old,
            content: ContentRef::Patch {
                base: old,
                edits: vec![ByteEdit {
                    offset: 0,
                    old: N[0],
                    new: patched[0],
                }],
                sha256: sha(&patched),
            },
            attrs: Attrs::default(),
        }],
        source: None,
    };
    let h = store(&app(&env.sys), &p.encode().unwrap()).unwrap();
    let before = env.snap();
    match env.apply(&h) {
        Err(ApplyError::Refused(Refusal::HeldChange { txn })) if txn == holder => {}
        r => panic!("{r:?}"),
    }
    same(&before, &env.snap());
    let _ = created;
}
