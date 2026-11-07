//! P2-15: the `.old` files a step of Rerun leaves while a process maps them as an image: the
//! journal names them by sequence (`RevertDone.old_left`), `status` names exactly those, and a
//! transaction closes only once nothing of Rerun's is left (CL-T1 to CL-T9, the controls K-CL1
//! and K-CL3; crashes and power losses: `cleanup_crash_tests.rs`).

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use super::tests::{Env, NEW, base, finish};
use super::{ApplyError, ExecError, OldSeen, Outcome, Refusal, RevertReport, TxnLine, txn_status};
use crate::journal::{Closing, Observed, TxnId};
use crate::plan::PlanHash;
use crate::prim::tests::{GAME, app, entry, spec};
use crate::sys::Fs;
use crate::sys::fake::{FakeFs, FakeHold, Prim};
use crate::sys::snapshot::Snapshot;

/// Maps every `.tmp.old` that appears in a folder as an image of process 4242 while a step of
/// Rerun runs (the hook looks before every rename, so the `.old` of step 6 is mapped before
/// step 8 tries to delete it), until [`Self::release`].
pub(crate) struct Mapper {
    held: Arc<Mutex<Vec<(String, FakeHold)>>>,
}

impl Mapper {
    /// From now on, in the folder `abs` of `env`.
    pub(crate) fn arm(env: &Env, abs: &str) -> Self {
        Self::on(env.sys.fake_fs(), abs, None)
    }

    /// On `fx`, in the folder `abs`; with `start`, only once the `nth` call of a primitive was
    /// seen (counted from here).
    pub(crate) fn on(fx: &FakeFs, abs: &str, start: Option<(Prim, usize)>) -> Self {
        let held: Arc<Mutex<Vec<(String, FakeHold)>>> = Arc::new(Mutex::new(Vec::new()));
        let slot = Arc::clone(&held);
        let dir = PathBuf::from(abs);
        let mut seen = 0;
        fx.on_step(move |f, ev| {
            if let Some((call, _)) = start
                && ev.call == Some(call)
            {
                seen += 1;
            }
            let active = start.is_none_or(|(_, nth)| seen >= nth);
            if active && ev.call == Some(Prim::Rename) {
                map_olds(f, &dir, &slot);
            }
        });
        Self { held }
    }

    /// The game folder of the fixtures.
    pub(crate) fn game(env: &Env) -> Self {
        Self::arm(env, GAME)
    }

    /// No more new mappings (the ones made stay).
    pub(crate) fn stop(env: &Env) {
        env.sys.fake_fs().clear_on_step();
    }

    /// The names mapped so far.
    pub(crate) fn names(&self) -> Vec<String> {
        self.held
            .lock()
            .unwrap()
            .iter()
            .map(|(n, _)| n.clone())
            .collect()
    }

    /// Every mapping goes (the game was closed).
    pub(crate) fn release(&self) {
        self.held.lock().unwrap().clear();
    }
}

fn map_olds(f: &FakeFs, dir: &Path, slot: &Mutex<Vec<(String, FakeHold)>>) {
    #[expect(clippy::disallowed_methods, reason = "test: list the fixture folder")]
    let Ok(d) = f.open_dir(dir) else {
        return;
    };
    let Ok(entries) = d.read_dir(None) else {
        return;
    };
    let mut held = slot.lock().unwrap();
    for e in entries.iter().filter(|e| e.name.ends_with(".tmp.old")) {
        if held.iter().any(|(n, _)| *n == e.name) {
            continue;
        }
        if let Ok(h) = f.map_image_as(4242, &dir.join(&e.name)) {
            held.push((e.name.clone(), h));
        }
    }
}

/// The plan that replaces `d3d9.dll`.
pub(crate) fn replace_env() -> (Env, PlanHash) {
    let env = Env::new(finish(base()));
    let h = env.plan(&spec(vec![entry("d3d9.dll", "d3d9.dll", NEW)]));
    (env, h)
}

/// The `.old` names `status` shows for op 0 of `t`.
pub(crate) fn status_names(env: &Env, t: &TxnId) -> Vec<String> {
    let a = app(&env.sys);
    let st = txn_status(&a, t).unwrap();
    st.ops
        .iter()
        .find(|o| o.op == 0)
        .map(|o| o.cleanup.iter().map(ToString::to_string).collect())
        .unwrap_or_default()
}

/// CL-T9 (P2-15, the display bug of `status`): `status` names exactly the `.old` files the
/// journal says are left. `Done.old_left` whose `X.old` the revert deleted: nothing; an `X.old`
/// still mapped after the restore: `X.old`, not the restore's `Y.old`.
#[test]
fn cl_t9_status_names_exactly_what_the_journal_says_is_left() {
    // The apply leaves `X.old` (mapped), the game is closed, the revert deletes it.
    let (env, h) = replace_env();
    let m = Mapper::game(&env);
    let t = match env.apply(&h) {
        Ok(Outcome::Applied(t)) => t,
        other => panic!("{other:?}"),
    };
    Mapper::stop(&env);
    let x_old = m.names();
    assert_eq!(x_old.len(), 1, "X.old mapped: {x_old:?}");
    assert_eq!(status_names(&env, &t), x_old, "Done.old_left");
    m.release();
    let r = env.revert(&t).unwrap();
    assert!(r.ops[0].left.is_empty(), "{r:?}");
    assert!(
        status_names(&env, &t).is_empty(),
        "X.old was deleted: {:?}",
        status_names(&env, &t)
    );

    // `X.old` stays mapped through the revert: the restore's `Y.old` goes, `X.old` is named.
    let (env, h) = replace_env();
    let m = Mapper::game(&env);
    let t = match env.apply(&h) {
        Ok(Outcome::Applied(t)) => t,
        other => panic!("{other:?}"),
    };
    Mapper::stop(&env);
    let x_old = m.names();
    let r = env.revert(&t).unwrap();
    assert_eq!(r.ops[0].observed, Observed::After, "{r:?}");
    let a = app(&env.sys);
    let j = crate::journal::Journal::new(&a, crate::journal::InstanceTag::fixed(3));
    let v = j.load(&t, crate::journal::VerifyBackups::Length).unwrap();
    let rd = v.ops[&0].reverted.clone().unwrap();
    assert_eq!(rd.old_left, vec![0], "only X.old (sequence 0)");
    assert_eq!(status_names(&env, &t), x_old, "X.old, not Y.old");
    m.release();
}

/// A replace applied (durable) and reverted while the restore's `Y.old` is mapped: the
/// transaction stays open with one pending `.old`. Returns the transaction, the mapper (still
/// holding it), the game folder before the apply and the report.
pub(crate) fn open_y() -> (Env, PlanHash, TxnId, Mapper, Snapshot, RevertReport) {
    let (env, h) = replace_env();
    let before = env.snap();
    let t = env.applied(&h);
    let m = Mapper::game(&env);
    let r = env.revert(&t).unwrap_or_else(|e| panic!("{e}"));
    Mapper::stop(&env);
    (env, h, t, m, before, r)
}

fn only(r: &RevertReport, seen: OldSeen) -> bool {
    matches!(&r.cleanup[..], [p] if p.seen == seen)
}

fn txn_line(env: &Env, t: &TxnId) -> TxnLine {
    txn_status(&app(&env.sys), t).unwrap().state
}

/// The `.tmp` and `.tmp.old` names in the folder `abs`.
pub(crate) fn tmp_in(env: &Env, abs: &str) -> Vec<String> {
    #[expect(clippy::disallowed_methods, reason = "test: list the fixture folder")]
    let d = env.sys.fake_fs().open_dir(Path::new(abs)).unwrap();
    d.read_dir(None)
        .unwrap()
        .into_iter()
        .map(|e| e.name)
        .filter(|n| n.starts_with(".rerun-"))
        .collect()
}

/// CL-T1 as a check (one function, named findings; the control K-CL1 must make it report
/// ".old after Reverted"): `Y.old` mapped during step 8 of the restore keeps the transaction
/// open (`CleanupPending`, exactly that name, an apply on its object refused); once it is free,
/// `verify` shows it as Rerun's, the next revert deletes it and closes, identical.
pub(crate) fn cl_t1_check() -> Vec<String> {
    let mut v = Vec::new();
    let (env, h, t, m, before, r) = open_y();
    let y = m.names();
    if y.len() != 1 {
        v.push(format!("CL-T1 Y.old not mapped: {y:?}"));
    }
    if r.closed.is_some() {
        v.push(format!("CL-T1 .old after Reverted: {r:?}"));
    } else if !only(&r, OldSeen::InUse)
        || r.cleanup.first().map(|p| p.path.as_str()) != y.first().map(String::as_str)
    {
        v.push(format!("CL-T1 cleanup: {r:?}"));
    }
    if txn_line(&env, &t) != TxnLine::CleanupPending {
        v.push(format!("CL-T1 status: {:?}", txn_line(&env, &t)));
    }
    if status_names(&env, &t) != y {
        v.push(format!("CL-T1 status names {:?}", status_names(&env, &t)));
    }
    match env.apply(&h) {
        Err(ApplyError::Refused(Refusal::CleanupPending { txn })) if txn == t => {}
        other => v.push(format!("CL-T1 apply on its object: {other:?}")),
    }
    match env.verified(&t) {
        Ok(x) if matches!(&x.cleanup[..], [p] if p.seen == OldSeen::InUse) => {}
        other => v.push(format!("CL-T1 verify while mapped: {other:?}")),
    }
    m.release();
    match env.verified(&t) {
        Ok(x) if matches!(&x.cleanup[..], [p] if p.seen == OldSeen::Ours) => {}
        other => v.push(format!("CL-T1 verify once free: {other:?}")),
    }
    match env.revert(&t) {
        Ok(r) if r.closed == Some(Closing::Reverted) && only(&r, OldSeen::Deleted) => {}
        other => v.push(format!("CL-T1 revert once free: {other:?}")),
    }
    if env.snap() != before {
        v.push(format!(
            "CL-T1 not identical: {:?}",
            before.diff(&env.snap())
        ));
    }
    v
}

#[test]
fn cl_t1_a_mapped_restore_old_keeps_the_transaction_open_until_a_revert_deletes_it() {
    let v = cl_t1_check();
    assert!(v.is_empty(), "{v:#?}");
}

/// K-CL1: closing although a `.old` of Rerun's is left breaks CL-T1.
#[test]
fn k_cl1_closing_despite_the_cleanup_breaks_cl_t1() {
    super::knob::close_despite_cleanup(true);
    let v = cl_t1_check();
    super::knob::close_despite_cleanup(false);
    assert!(
        v.iter().any(|x| x.contains(".old after Reverted")),
        "{v:#?}"
    );
}

/// CL-T2: the apply's `X.old` stays mapped through the revert: the target gets its old
/// content, `X.old` (not a `Y.old`) holds the transaction open, then it closes identical.
#[test]
fn cl_t2_a_mapped_apply_old_stays_until_it_is_free() {
    let (env, h) = replace_env();
    let before = env.snap();
    let m = Mapper::game(&env);
    let t = env.applied(&h);
    Mapper::stop(&env);
    let x = m.names();
    assert_eq!(x.len(), 1, "{x:?}");
    let r = env.revert(&t).unwrap();
    assert_eq!(r.closed, None, "{r:?}");
    assert!(only(&r, OldSeen::InUse), "{r:?}");
    assert_eq!(r.cleanup[0].path.as_str(), x[0]);
    assert_eq!(
        super::tests::read_abs(&env.sys, &super::tests::game("d3d9.dll")),
        super::tests::OLD
    );
    assert_eq!(status_names(&env, &t), x, "X.old named");
    m.release();
    let r = env.revert(&t).unwrap();
    assert_eq!(r.closed, Some(Closing::Reverted), "{r:?}");
    assert!(r.ops.is_empty() && only(&r, OldSeen::Deleted), "{r:?}");
    super::tests::same(&before, &env.snap());
    assert!(status_names(&env, &t).is_empty(), "closed: nothing named");
}

/// CL-T3: the `.old` of an INI rewrite (the file the game wrote) mapped: open, then closed.
#[test]
fn cl_t3_a_mapped_ini_rewrite_old_stays_until_it_is_free() {
    use crate::prim::ini_tests::{INI_TEXT, three};
    let env = super::ini_tests::ini_env(INI_TEXT);
    let h = super::reg_tests::plan_all(&env, &[three()]);
    let t = env.applied(&h);
    let drift = format!("{}[Video]\r\nVsync=1\r\n", super::ini_tests::APPLIED);
    super::ini_tests::put_ini(&env, drift.as_bytes());
    let cfg = super::tests::game(r"cfg");
    let m = Mapper::arm(&env, &cfg);
    let r = env.revert(&t).unwrap();
    Mapper::stop(&env);
    assert_eq!(r.ops[0].observed, Observed::Drifted, "{r:?}");
    assert_eq!(r.closed, None, "{r:?}");
    assert!(only(&r, OldSeen::InUse), "{r:?}");
    assert_eq!(r.cleanup[0].path.as_str(), format!(r"cfg\{}", m.names()[0]));
    let rewritten = super::ini_tests::ini_now(&env);
    m.release();
    let r = env.revert(&t).unwrap();
    assert_eq!(r.closed, Some(Closing::Reverted), "{r:?}");
    assert!(only(&r, OldSeen::Deleted), "{r:?}");
    assert!(tmp_in(&env, &cfg).is_empty(), "{:?}", tmp_in(&env, &cfg));
    assert_eq!(
        super::ini_tests::ini_now(&env),
        rewritten,
        "the target untouched"
    );
}

/// The calls of a successful apply of `h` on a fresh copy of the world.
fn apply_calls(h: &PlanHash) -> Vec<Prim> {
    let (env, _) = replace_env();
    let fx = env.sys.fake_fs();
    let r = env.apply_armed(h, |f| f.record_calls(true));
    fx.record_calls(false);
    assert!(matches!(r, Ok(Outcome::Applied(_))), "{r:?}");
    fx.take_calls()
}

/// CL-T4 (senior-dev B1): an apply that fails after its replace is rolled back while the
/// restore's `Y.old` is mapped: its own result, not `Closed`; a later revert closes it
/// `RolledBack`, identical.
#[test]
fn cl_t4_a_rollback_with_a_mapped_old_stays_open_until_a_revert() {
    let (env, h) = replace_env();
    let before = env.snap();
    // The game folder's flush before `Applied` fails: the second-to-last flush of the apply.
    let calls = apply_calls(&h);
    let flushes = calls.iter().filter(|c| **c == Prim::FlushDir).count();
    let mut m = None;
    let r = env.apply_armed(&h, |fx| {
        m = Some(Mapper::on(fx, GAME, Some((Prim::FlushDir, flushes - 1))));
        fx.fail_at(Prim::FlushDir, flushes - 1, crate::sys::SysErrorKind::Other);
    });
    let m = m.unwrap();
    Mapper::stop(&env);
    env.sys.fake_fs().clear_faults();
    let t = match &r {
        Err(ApplyError::CleanupPending { txn, cleanup, .. }) if matches!(&cleanup[..], [p] if p.seen == OldSeen::InUse) => {
            *txn
        }
        other => panic!("{other:?}"),
    };
    assert_eq!(m.names().len(), 1);
    assert_eq!(env.state(&t), Some(crate::journal::TxnState::Open));
    assert_eq!(txn_line(&env, &t), TxnLine::CleanupPending);
    m.release();
    let r = env.revert(&t).unwrap();
    assert_eq!(r.closed, Some(Closing::RolledBack), "{r:?}");
    assert!(only(&r, OldSeen::Deleted), "{r:?}");
    super::tests::same(&before, &env.snap());
}

/// CL-T5: the user deleted the `.old`: the next revert finds it gone, deletes nothing, closes.
#[test]
fn cl_t5_a_dot_old_the_user_deleted_closes_without_a_deletion() {
    let (env, _, t, m, before, _) = open_y();
    let y = m.names();
    m.release();
    env.sys
        .fake_fs()
        .remove_abs(&Path::new(GAME).join(&y[0]))
        .unwrap();
    let r = env.revert(&t).unwrap();
    assert_eq!(r.closed, Some(Closing::Reverted), "{r:?}");
    assert!(r.ops.is_empty() && only(&r, OldSeen::Gone), "{r:?}");
    super::tests::same(&before, &env.snap());
}

/// CL-T6 as a check (user decision E-C4; the control K-CL3 must make it report "deleted"):
/// another content, a hard link, a folder or a junction at the `.old` name is not Rerun's: never
/// touched, reported, and the transaction closes `Reverted` (Rerun's changes are undone; what
/// is at its name is not one of them).
pub(crate) fn cl_t6_check() -> Vec<String> {
    let mut v = Vec::new();
    type Plant = fn(&Env, &Path);
    let cases: [(&str, Plant); 4] = [
        ("other content", |env, p| {
            let fx = env.sys.fake_fs();
            fx.remove_abs(p).unwrap();
            fx.put_file(p, b"someone else's file").unwrap();
        }),
        ("a hard link", |env, p| {
            let fx = env.sys.fake_fs();
            let other = Path::new(GAME).join("keep.dll");
            fx.put_file(&other, b"kept").unwrap();
            fx.remove_abs(p).unwrap();
            fx.put_hardlink(&other, p).unwrap();
        }),
        ("a folder", |env, p| {
            let fx = env.sys.fake_fs();
            fx.remove_abs(p).unwrap();
            fx.mkdir_all(p).unwrap();
        }),
        ("a junction", |env, p| {
            let fx = env.sys.fake_fs();
            fx.remove_abs(p).unwrap();
            fx.put_link(p, crate::sys::fs::tag::MOUNT_POINT, r"D:\Elsewhere")
                .unwrap();
        }),
    ];
    for (what, plant) in cases {
        let (env, _, t, m, _, _) = open_y();
        let y = Path::new(GAME).join(&m.names()[0]);
        m.release();
        plant(&env, &y);
        let planted = env.snap();
        match env.revert(&t) {
            Ok(r) if r.closed == Some(Closing::Reverted) && only(&r, OldSeen::Foreign) => {}
            Ok(r) if r.cleanup.iter().any(|p| p.seen == OldSeen::Deleted) => {
                v.push(format!("CL-T6 {what}: deleted: {r:?}"));
            }
            other => v.push(format!("CL-T6 {what}: {other:?}")),
        }
        if env.snap() != planted {
            v.push(format!(
                "CL-T6 {what}: deleted or changed: {:?}",
                planted.diff(&env.snap())
            ));
        }
    }
    v
}

#[test]
fn cl_t6_foreign_content_at_the_name_is_reported_and_never_touched() {
    let v = cl_t6_check();
    assert!(v.is_empty(), "{v:#?}");
}

/// K-CL3: a cleanup without its known hash deletes what is not Rerun's: CL-T6 reports it.
#[test]
fn k_cl3_a_cleanup_without_the_hash_breaks_cl_t6() {
    super::knob::cleanup_without_hash(true);
    let v = cl_t6_check();
    super::knob::cleanup_without_hash(false);
    assert!(v.iter().any(|x| x.contains("deleted")), "{v:#?}");
}

/// CL-T7: the game folder gone while the cleanup is pending halts the revert without a record;
/// back, the revert closes; a reinstall (another folder at the path) is refused. A rebind is
/// not possible once a file op of the root has a `RevertIntent` (user decision E-R3), so only
/// `forget` ends such a transaction.
#[test]
fn cl_t7_a_root_that_is_gone_halts_the_cleanup_without_a_record() {
    let (env, _, t, m, before, _) = open_y();
    m.release();
    let records = |env: &Env| {
        let a = app(&env.sys);
        let j = crate::journal::Journal::new(&a, crate::journal::InstanceTag::fixed(4));
        j.load(&t, crate::journal::VerifyBackups::Length)
            .unwrap()
            .ops
            .values()
            .map(|o| o.reverts.len())
            .sum::<usize>()
    };
    let n = records(&env);
    env.sys.rename_abs(GAME, r"D:\Games\Away").unwrap();
    let r = env.revert(&t).unwrap();
    assert!(
        r.closed.is_none() && r.ops.is_empty() && r.halted.as_ref().is_some_and(|h| h.op == 0),
        "{r:?}"
    );
    assert_eq!(records(&env), n, "no record");
    let v = env.verified(&t).unwrap();
    assert!(v.halted.is_some(), "{v:?}");
    env.sys.rename_abs(r"D:\Games\Away", GAME).unwrap();
    // A reinstall: another folder at the path.
    env.sys.rename_abs(GAME, r"D:\Games\Old").unwrap();
    env.sys.fake_fs().mkdir_all(Path::new(GAME)).unwrap();
    assert!(
        matches!(env.revert(&t), Err(ExecError::Refused(Refusal::Root(_)))),
        "reinstall refused"
    );
    env.sys.fake_fs().remove_abs(Path::new(GAME)).unwrap();
    env.sys.rename_abs(r"D:\Games\Old", GAME).unwrap();
    let r = env.revert(&t).unwrap();
    assert_eq!(r.closed, Some(Closing::Reverted), "{r:?}");
    super::tests::same(&before, &env.snap());
}

/// CL-T8: the game running (D4) refuses the cleanup run before anything is deleted.
#[test]
fn cl_t8_the_game_running_refuses_the_cleanup() {
    let (env, _, t, m, _, _) = open_y();
    m.release();
    let held = env
        .sys
        .fake_fs()
        .map_image_as(4243, &Path::new(GAME).join("game.exe"))
        .unwrap();
    let left = tmp_in(&env, GAME);
    assert!(
        matches!(env.revert(&t), Err(ExecError::Refused(Refusal::Busy(_)))),
        "D4"
    );
    assert_eq!(tmp_in(&env, GAME), left, "nothing deleted");
    drop(held);
    assert_eq!(env.revert(&t).unwrap().closed, Some(Closing::Reverted));
}

/// `forget` of a transaction with a pending cleanup: closed `Forgotten`, and `status` keeps
/// naming the `.old` from the records (it may remain).
#[test]
fn cl_forget_keeps_naming_the_old_that_may_remain() {
    let (env, _, t, m, _, _) = open_y();
    let y = m.names();
    env.forget(&t).unwrap();
    assert_eq!(txn_line(&env, &t), TxnLine::Closed(Closing::Forgotten));
    assert_eq!(status_names(&env, &t), y);
    m.release();
}

/// A revert that only cleans up counts its deletion as a change (senior-dev B2): a failure of
/// its `Closed` after the deletion is never a refusal ("nothing changed").
#[test]
fn cl_b2_a_cleanup_deletion_is_a_change() {
    let (env, _, t, m, _, _) = open_y();
    m.release();
    // The calls of the cleanup run: fail its last flush (the one of `Closed`).
    let r = env.revert_armed(&t, |fx| fx.record_calls(true));
    let fx = env.sys.fake_fs();
    fx.record_calls(false);
    let calls = fx.take_calls();
    assert_eq!(r.unwrap().closed, Some(Closing::Reverted));
    let (env, _, t, m, _, _) = open_y();
    m.release();
    let renames = calls.iter().filter(|c| **c == Prim::Rename).count();
    assert!(calls.contains(&Prim::PosixDelete), "{calls:?}");
    let r = env.revert_armed(&t, |fx| {
        fx.fail_at(Prim::Rename, renames, crate::sys::SysErrorKind::Other);
    });
    assert!(
        matches!(&r, Err(e) if !matches!(e, ExecError::Refused(_))),
        "after a deletion: {r:?}"
    );
    // Retried, it closes.
    assert_eq!(env.revert(&t).unwrap().closed, Some(Closing::Reverted));
}
