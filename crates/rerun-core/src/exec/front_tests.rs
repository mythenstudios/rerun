//! P2-13: the front-end API of `exec` against the fake: the core guard of user decision E3
//! (an elevated process changes nothing, whatever the plan), review S4 (a revert error before
//! the run's first record is a refusal), and `status`/`txn_status` for every state.

use std::path::Path;
use std::sync::{Arc, Mutex};

use super::tests::{Env, OLD, base, finish, interrupted, same, snap_app, sys_put, t1_spec};
use super::{
    ApplyError, Backup, ExecError, OpState, Outcome, Refusal, TxnLine, standard_user, status,
    txn_status,
};
use crate::journal::{Closing, InstanceTag, Journal, JournalError, Observed, TxnId};
use crate::prim::tests::{GAME, app, entry, spec};
use crate::sys::fake::Prim;
use crate::sys::{Fs, SysErrorKind};

/// E3: elevated (or undeterminable), `apply`, `check`, `revert` and `forget` refuse a plan
/// without any registry op before anything is written; as a standard user they run.
#[test]
fn e3_an_elevated_process_changes_nothing_whatever_the_plan() {
    let env = Env::new(finish(base()));
    let h = env.plan(&t1_spec());
    let game0 = env.snap();
    let app0 = snap_app(&env.sys);
    env.sys.fake_registry().set_elevated(true);
    assert!(matches!(standard_user(&env.sys), Err(Refusal::Elevated)));
    assert!(matches!(env.check(&h), Err(Refusal::Elevated)));
    assert!(matches!(
        env.apply(&h),
        Err(ApplyError::Refused(Refusal::Elevated))
    ));
    same(&game0, &env.snap());
    same(&app0, &snap_app(&env.sys));
    env.sys.fake_registry().set_elevated(false);
    assert!(standard_user(&env.sys).is_ok());
    let t = env.applied(&h);
    let game1 = env.snap();
    let app1 = snap_app(&env.sys);
    env.sys.fake_registry().set_elevated(true);
    assert!(matches!(
        env.revert(&t),
        Err(ExecError::Refused(Refusal::Elevated))
    ));
    assert!(matches!(
        env.forget(&t),
        Err(ExecError::Refused(Refusal::Elevated))
    ));
    same(&game1, &env.snap());
    same(&app1, &snap_app(&env.sys));
    // The message no longer speaks of the registry only (review S5).
    let text = Refusal::Elevated.to_string();
    assert!(text.contains("changes nothing"), "{text}");
    assert!(text.contains("with UAC turned off"), "{text}");
    env.sys.fake_registry().set_elevated(false);
    assert_eq!(
        super::tests::closed(&env.revert(&t)),
        Some(Closing::Reverted)
    );
    same(&game0, &env.snap());
}

/// S4: every error of a revert before its first record of the run is a refusal; an error
/// after a record of the run is not.
#[test]
fn s4_revert_errors_before_the_first_record_are_refusals() {
    let env = Env::new(finish(base()));
    // A transaction that does not exist.
    let gone: TxnId = "00000042-00000000000000ab".parse().unwrap();
    let r = env.revert(&gone);
    assert!(
        matches!(&r, Err(ExecError::Refused(Refusal::Journal(e))) if matches!(**e, JournalError::NotFound(_))),
        "{r:?}"
    );
    // The first observation fails (a read of the target): nothing recorded, a refusal.
    let t = env.applied(&env.plan(&t1_spec()));
    let app1 = snap_app(&env.sys);
    let r = env.revert_armed(&t, |fx| {
        fx.fail_at(Prim::ReadAt, 1, SysErrorKind::Other);
    });
    assert!(matches!(&r, Err(ExecError::Refused(_))), "{r:?}");
    same(&app1, &snap_app(&env.sys));
    // A failure after the run's first `RevertIntent`: not a refusal (the run wrote).
    let r = env.revert_armed(&t, |fx| {
        fx.fail_at(Prim::PosixDelete, 1, SysErrorKind::AccessDenied);
    });
    assert!(
        r.as_ref()
            .err()
            .is_some_and(|e| !matches!(e, ExecError::Refused(_))),
        "{r:?}"
    );
    assert_eq!(
        super::tests::closed(&env.revert(&t)),
        Some(Closing::Reverted)
    );
}

/// `status` and `txn_status`: every state, the ops newest first with their backups, the
/// preview of an unsettled transaction only.
#[test]
fn status_shows_every_state_of_the_journal() {
    let env = Env::new(finish(base()));
    {
        let a = app(&env.sys);
        let s = status(&a).unwrap();
        assert!(s.txns.is_empty() && s.foreign_entries == 0);
    }
    // Applied: five ops newest first, the replace's backup a `.bin`.
    let h = env.plan(&t1_spec());
    let t = env.applied(&h);
    let a = app(&env.sys);
    let st = txn_status(&a, &t).unwrap();
    assert_eq!(st.state, TxnLine::Applied);
    assert!(!st.is_settled() && !st.is_forgotten());
    let ops: Vec<u16> = st.ops.iter().map(|o| o.op).collect();
    assert_eq!(ops, vec![4, 3, 2, 1, 0]);
    assert!(st.ops.iter().all(|o| o.state == OpState::Applied));
    let replace = st.ops.iter().find(|o| o.op == 0).unwrap();
    match &replace.backup {
        Some(Backup::Bin { path, len }) => {
            assert!(
                path.as_str()
                    .ends_with(&format!(r"\Rerun\journal\{t}\op-0000.bin")),
                "{path:?}"
            );
            assert_eq!(*len, u64::try_from(OLD.len()).unwrap());
        }
        other => panic!("{other:?}"),
    }
    assert!(
        st.ops
            .iter()
            .filter(|o| o.op != 0)
            .all(|o| o.backup.is_none())
    );
    let p = st.preview.as_ref().unwrap().as_ref().unwrap();
    assert_eq!(p.ops.len(), 5);
    assert!(
        st.folder
            .as_str()
            .ends_with(&format!(r"\Rerun\journal\{t}"))
    );
    // Reverted: settled, no preview in `status`.
    assert_eq!(
        super::tests::closed(&env.revert(&t)),
        Some(Closing::Reverted)
    );
    let s = status(&a).unwrap();
    assert_eq!(s.txns.len(), 1);
    let st = &s.txns[0];
    assert_eq!(st.state, TxnLine::Closed(Closing::Reverted));
    assert!(st.is_settled() && st.preview.is_none());
    assert!(
        st.ops
            .iter()
            .all(|o| o.state == OpState::Reverted(Observed::After))
    );
    // Forgotten by its record: the backup is still named.
    let t2 = env.applied(&h);
    env.forget(&t2).unwrap();
    let st = txn_status(&a, &t2).unwrap();
    assert_eq!(st.state, TxnLine::Closed(Closing::Forgotten));
    assert!(st.is_forgotten() && st.is_settled());
    assert!(matches!(
        st.ops.iter().find(|o| o.op == 0).unwrap().backup,
        Some(Backup::Bin { .. })
    ));
}

#[test]
fn status_shows_rolled_back_open_empty_damaged_unreadable_and_marked() {
    // Rolled back.
    let env = Env::new(finish(base()));
    let h = env.plan(&t1_spec());
    let r = env.apply_armed(&h, |fx| fx.fail_at(Prim::CreateTmp, 2, SysErrorKind::Other));
    let t = match r {
        Err(ApplyError::RolledBack { txn, .. }) => txn,
        other => panic!("{other:?}"),
    };
    let a = app(&env.sys);
    assert_eq!(
        txn_status(&a, &t).unwrap().state,
        TxnLine::Closed(Closing::RolledBack)
    );
    // Open (an interrupted apply): an op with its intent only.
    let env = Env::new(finish(base()));
    let t = interrupted(&env, &t1_spec());
    let a = app(&env.sys);
    let st = txn_status(&a, &t).unwrap();
    assert_eq!(st.state, TxnLine::Open);
    assert!(!st.is_settled());
    assert!(
        st.ops.iter().any(|o| o.state == OpState::Interrupted),
        "{:?}",
        st.ops
    );
    // Empty: a head only.
    let env = Env::new(finish(base()));
    let h = env.plan(&t1_spec());
    let a = app(&env.sys);
    let bytes = crate::plan::load(&a, &h).unwrap();
    let j = Journal::new(&a, InstanceTag::fixed(0x51));
    let empty = {
        let lock = j.lock().unwrap();
        let w = lock.begin(bytes.bytes()).unwrap();
        *w.id()
    };
    let st = txn_status(&a, &empty).unwrap();
    assert_eq!(st.state, TxnLine::Empty);
    assert!(st.is_settled() && st.ops.is_empty());
    // Damaged (a gap in the records), forgotten by a marker.
    let t = env.applied(&h);
    sys_put(&env.sys, &format!(r"{}\0099.json", env.txn_dir(&t)), b"{}");
    let st = txn_status(&a, &t).unwrap();
    assert!(matches!(st.state, TxnLine::Damaged(_)), "{:?}", st.state);
    assert!(!st.is_settled());
    env.forget(&t).unwrap();
    let st = txn_status(&a, &t).unwrap();
    assert!(st.forgotten && st.is_forgotten() && st.is_settled());
    // Unreadable: an entry with a transaction name that is no folder; and a foreign entry.
    let odd = r"C:\Users\Player\AppData\Local\Rerun\journal\00000077-00000000000000cd";
    sys_put(&env.sys, odd, b"x");
    sys_put(
        &env.sys,
        r"C:\Users\Player\AppData\Local\Rerun\journal\notes.txt",
        b"x",
    );
    let s = status(&a).unwrap();
    assert_eq!(s.foreign_entries, 1);
    let st = s.txns.iter().find(|x| x.id.seq() == 77).unwrap();
    assert!(matches!(st.state, TxnLine::Unreadable(_)), "{:?}", st.state);
    assert!(!st.is_settled());
}

/// A `.old` the apply left mapped (`Done.old_left`): named as a pending cleanup while the
/// transaction is applied (once it is closed `Reverted`, nothing of Rerun's is left, P2-15:
/// `cleanup_tests.rs`).
#[test]
fn status_names_a_pending_cleanup() {
    let env = Env::new(finish(base()));
    let h = env.plan(&spec(vec![entry(
        "d3d9.dll",
        "d3d9.dll",
        super::tests::NEW,
    )]));
    let held = Arc::new(Mutex::new(None));
    let slot = Arc::clone(&held);
    env.sys.fake_fs().on_step(move |f, ev| {
        if ev.call == Some(Prim::Rename) && ev.name.eq_ignore_ascii_case("d3d9.dll") {
            #[expect(clippy::disallowed_methods, reason = "test: list the fixture folder")]
            let d = f.open_dir(Path::new(GAME)).unwrap();
            if let Some(o) = d
                .read_dir(None)
                .unwrap()
                .iter()
                .find(|e| e.name.ends_with(".tmp.old"))
            {
                let mut s = slot.lock().unwrap();
                if s.is_none() {
                    *s = Some(
                        f.map_image_as(4242, &Path::new(GAME).join(&o.name))
                            .unwrap(),
                    );
                }
            }
        }
    });
    let t = match env.apply(&h) {
        Ok(Outcome::Applied(t)) => t,
        other => panic!("{other:?}"),
    };
    env.sys.fake_fs().clear_on_step();
    drop(held.lock().unwrap().take());
    let a = app(&env.sys);
    let st = txn_status(&a, &t).unwrap();
    let c = &st.ops[0].cleanup;
    assert_eq!(c.len(), 1, "{c:?}");
    assert!(c[0].as_str().ends_with(".tmp.old"), "{c:?}");
    assert!(!c[0].as_str().contains('\\'), "in the root folder: {c:?}");
}

/// Review S3: the preview of a recorded head (`status`, `revert`, `forget`) shows an old
/// registry value by type, length and SHA-256 only; the plan preview shows its text (ADR 0016
/// amendment P2-10b). Everything else is the same.
#[test]
fn s3_a_recorded_head_shows_no_registry_data() {
    use super::reg_tests::{plan_all, reg_base, rt1_steps};
    let env = Env::new(finish(reg_base()));
    let h = plan_all(&env, &rt1_steps());
    let a = app(&env.sys);
    let b = crate::plan::load(&a, &h).unwrap();
    let stored = crate::plan::preview_stored(&b).unwrap();
    let head = crate::plan::preview_head(b.bytes()).unwrap();
    assert_eq!(stored.ops.len(), 11);
    let old = |p: &crate::plan::Preview| p.ops[10].old_value.clone().unwrap();
    assert_eq!(old(&stored).to_string(), "REG_SZ: text");
    let masked = old(&head);
    assert!(masked.text.is_none(), "{masked:?}");
    assert!(
        masked.kind.starts_with("REG_SZ, 10 bytes, sha256 "),
        "{masked:?}"
    );
    assert_eq!(head.ops[10].new_value, stored.ops[10].new_value);
    for k in 0..10 {
        assert_eq!(head.ops[k], stored.ops[k], "op {k}");
    }
    assert_eq!(head.roots, stored.roots);
}

/// Review S6: without Rerun's folder a `file_install` step is refused (no local packages) and
/// a registry step plans as before; nothing is created.
#[test]
fn s6_planning_without_rerun_s_folder() {
    use crate::policy::registry::RegPolicy;
    use crate::policy::root::GameDir;
    use crate::prim::tests::{fr, rel};
    use crate::prim::{PlanCtx, Step, plan};
    let env = Env::new(finish(super::reg_tests::reg_base()));
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
    let app0 = snap_app(&env.sys);
    let e = plan(&[Step::FileInstall(t1_spec())], &ctx).unwrap_err();
    assert!(e.to_string().contains("packages folder"), "{e}");
    let steps: Vec<Step> = super::reg_tests::rt1_steps()
        .into_iter()
        .filter(|s| !matches!(s, Step::FileInstall(_)))
        .collect();
    let p = plan(&steps, &ctx).unwrap();
    assert_eq!(p.ops.len(), 6);
    same(&app0, &snap_app(&env.sys));
}

/// Review S3 for `add tokens`: the old and the new value of a recorded `TokenList` (the new one
/// holds the old) by type, length and SHA-256 only.
#[test]
fn s3_a_recorded_token_list_shows_no_registry_text() {
    use super::layer_tests::{layer_base_with, two_tokens};
    use super::reg_tests::plan_all;
    let env = Env::new(finish(layer_base_with("~ RUNASADMIN")));
    let h = plan_all(&env, &[two_tokens()]);
    let a = app(&env.sys);
    let b = crate::plan::load(&a, &h).unwrap();
    let stored = crate::plan::preview_stored(&b).unwrap();
    let head = crate::plan::preview_head(b.bytes()).unwrap();
    let k = stored
        .ops
        .iter()
        .position(|o| o.action == "add tokens")
        .unwrap();
    assert_eq!(
        stored.ops[k].new_value.as_ref().unwrap().to_string(),
        "REG_SZ: ~ RUNASADMIN ZZ_FLAG_A ZZ_OS_A"
    );
    for v in [&head.ops[k].old_value, &head.ops[k].new_value] {
        let v = v.as_ref().unwrap();
        assert!(v.text.is_none(), "{v:?}");
        assert!(v.kind.starts_with("REG_SZ, "), "{v:?}");
        assert!(v.kind.contains(" bytes, sha256 "), "{v:?}");
    }
    assert_eq!(head.ops[k].tokens, stored.ops[k].tokens);
}

/// Senior-dev S-a: `revert_check` runs the revert's chain without writing and refuses as the
/// revert does: a later transaction on the same objects, the game running, forgotten.
#[test]
fn revert_check_refuses_as_the_revert_does() {
    let env = Env::new(finish(base()));
    let t = env.applied(&env.plan(&t1_spec()));
    assert!(env.with(|cx| super::revert_check(cx, &t)).is_ok());
    // The game runs.
    let image = env
        .sys
        .fake_fs()
        .map_image_as(4242, Path::new(&format!(r"{GAME}\game.exe")))
        .unwrap();
    let app0 = snap_app(&env.sys);
    let c = env.with(|cx| super::revert_check(cx, &t));
    let r = env.revert(&t);
    match (&c, &r) {
        (Err(c), Err(ExecError::Refused(r))) => assert_eq!(c.to_string(), r.to_string()),
        other => panic!("{other:?}"),
    }
    assert!(matches!(c, Err(Refusal::Busy(_))));
    same(&app0, &snap_app(&env.sys));
    drop(image);
    // A later transaction that replaces a file of it: `Later` for both. (A new file in a
    // folder it created would be handed over, P4-8b.)
    let t2 = env.applied(&env.plan(&spec(vec![entry("d3d9.dll", "new.dll", super::tests::NEW)])));
    let c = env.with(|cx| super::revert_check(cx, &t));
    assert!(
        matches!(&c, Err(Refusal::Later { txn }) if *txn == t2),
        "{c:?}"
    );
    assert!(matches!(
        env.revert(&t),
        Err(ExecError::Refused(Refusal::Later { txn })) if txn == t2
    ));
    // Closed by forget, not found.
    env.forget(&t2).unwrap();
    assert!(matches!(
        env.with(|cx| super::revert_check(cx, &t2)),
        Err(Refusal::Journal(_))
    ));
    let gone: TxnId = "00000077-00000000000000ab".parse().unwrap();
    assert!(matches!(
        env.with(|cx| super::revert_check(cx, &gone)),
        Err(Refusal::Journal(e)) if matches!(*e, JournalError::NotFound(_))
    ));
}

/// Review S2 / senior-dev S-b: while the lock is held, `verify` and `revert_check` are
/// `JournalBusy`; while a check holds the lock file read side, the lock is `Busy`.
#[test]
fn checks_and_the_lock_exclude_each_other() {
    let env = Env::new(finish(base()));
    let t = env.applied(&env.plan(&t1_spec()));
    let a = app(&env.sys);
    let j = Journal::new(&a, InstanceTag::fixed(0x77));
    let held = j.lock().unwrap();
    assert!(matches!(
        env.verified(&t),
        Err(ExecError::Refused(Refusal::JournalBusy))
    ));
    assert!(matches!(
        env.with(|cx| super::revert_check(cx, &t)),
        Err(Refusal::JournalBusy)
    ));
    drop(held);
    let hold = j.hold().unwrap();
    assert!(matches!(j.lock(), Err(JournalError::Busy)));
    assert!(env.verified(&t).is_ok(), "two readers share the lock file");
    drop(hold);
    assert!(j.lock().is_ok());
}

/// Security review N1: a `Closed` that did not reach the journal is a refusal (nothing written,
/// the `first` branch); one that reached it but whose flush failed is `Unconfirmed`. Forget
/// alike.
#[test]
fn a_failed_close_is_a_refusal_or_unconfirmed() {
    let env = Env::new(finish(base()));
    let h = env.plan(&t1_spec());
    let a = app(&env.sys);
    let bytes = crate::plan::load(&a, &h).unwrap();
    let j = Journal::new(&a, InstanceTag::fixed(0x52));
    let empty = |n: u64| {
        let j = Journal::new(&a, InstanceTag::fixed(n));
        let lock = j.lock().unwrap();
        let w = lock.begin(bytes.bytes()).unwrap();
        *w.id()
    };
    // The record is never written: refused, still empty.
    let t = empty(0x61);
    let r = env.revert_armed(&t, |fx| fx.fail_at(Prim::CreateTmp, 1, SysErrorKind::Other));
    assert!(matches!(r, Err(ExecError::Refused(_))), "{r:?}");
    assert_eq!(env.state(&t), Some(crate::journal::TxnState::Empty));
    // The record is written, its flush fails: unconfirmed, closed on disk.
    let r = env.revert_armed(&t, |fx| fx.fail_at(Prim::FlushDir, 1, SysErrorKind::Other));
    env.sys.fake_fs().clear_faults();
    assert!(matches!(r, Err(ExecError::Unconfirmed(_))), "{r:?}");
    assert_eq!(
        env.state(&t),
        Some(crate::journal::TxnState::Closed(Closing::RolledBack))
    );
    // Forget: before its record a refusal, after it unconfirmed.
    let t = empty(0x62);
    let r = env.with(|cx| {
        env.sys.fake_fs().clear_faults();
        env.sys
            .fake_fs()
            .fail_at(Prim::CreateTmp, 1, SysErrorKind::Other);
        super::forget(cx, &t)
    });
    assert!(matches!(r, Err(ExecError::Refused(_))), "{r:?}");
    let r = env.with(|cx| {
        env.sys.fake_fs().clear_faults();
        env.sys
            .fake_fs()
            .fail_at(Prim::FlushDir, 1, SysErrorKind::Other);
        super::forget(cx, &t)
    });
    env.sys.fake_fs().clear_faults();
    assert!(matches!(r, Err(ExecError::Unconfirmed(_))), "{r:?}");
    assert_eq!(
        env.state(&t),
        Some(crate::journal::TxnState::Closed(Closing::Forgotten))
    );
    // Errors before forget writes: refusals.
    let gone: TxnId = "00000077-00000000000000ab".parse().unwrap();
    assert!(matches!(env.forget(&gone), Err(ExecError::Refused(_))));
    let held = j.lock().unwrap();
    assert!(matches!(
        env.forget(&t),
        Err(ExecError::Refused(Refusal::JournalBusy))
    ));
    drop(held);
}
