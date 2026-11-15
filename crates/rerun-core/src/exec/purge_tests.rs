//! `purge_seen` against the fake (P5-6d-1a): HP4, the hand-over kept fail closed (B1), also
//! with an unreadable heir; the profile holder; what is refused and reported; nothing outside
//! `journal\` changes.

use std::path::Path;

use super::tests::{Env, N, NEW, base, finish, same, snap_app};
use super::{ExecError, Keep, PurgeMode, PurgeReport, Refusal, purge_seen};
use crate::journal::{Closing, InstanceTag, Journal, Observed, TxnId, TxnState};
use crate::prim::FileInstallSpec;
use crate::prim::tests::{app, entry, spec};
use crate::sys::contract::{Access, Share};

/// The creator of `new.dll`.
fn c_file() -> FileInstallSpec {
    spec(vec![entry("new.dll", "new.dll", N)])
}

/// A holder of `new.dll` that replaces `d3d9.dll`.
fn h_rep() -> FileInstallSpec {
    spec(vec![
        entry("new.dll", "new.dll", N),
        entry("d3d9.dll", "d3d9.dll", NEW),
    ])
}

/// The transaction and the hash of its head as listed now (what a preview saw).
fn seen(env: &Env, t: &TxnId) -> (TxnId, Option<[u8; 32]>) {
    let a = app(&env.sys);
    let l = Journal::new(&a, InstanceTag::fixed(1)).list().unwrap();
    let head = l
        .txns
        .iter()
        .find(|x| x.id == *t)
        .and_then(|x| x.view.as_ref().ok())
        .and_then(|v| v.head_sha256);
    (*t, head)
}

fn purge(env: &Env, ts: &[TxnId]) -> Result<PurgeReport, ExecError> {
    let ids: Vec<_> = ts.iter().map(|t| seen(env, t)).collect();
    env.with(|cx| purge_seen(cx, &ids, PurgeMode::Lenient))
}

fn listed(env: &Env) -> Vec<TxnId> {
    env.states().into_iter().map(|(t, _)| t).collect()
}

fn reverted(env: &Env, t: &TxnId) {
    let r = env.revert(t).unwrap_or_else(|e| panic!("revert {t}: {e}"));
    assert_eq!(r.closed, Some(Closing::Reverted), "{t}: {r:?}");
}

/// The creator `A` reverted with a `Kept` op (`new.dll` handed to `B`).
fn handed_over() -> (Env, TxnId, TxnId) {
    let env = Env::new(finish(base()));
    let a = env.applied(&env.plan(&c_file()));
    let b = env.applied(&env.plan(&h_rep()));
    let r = env.revert(&a).unwrap();
    assert!(
        r.ops.iter().any(|o| o.observed == Observed::Kept),
        "precondition: A kept new.dll for B: {r:?}"
    );
    (env, a, b)
}

#[test]
fn hp4_a_hand_over_is_kept_until_the_heir_is_settled() {
    let env = Env::new(finish(base()));
    let floor = env.snap();
    let a = env.applied(&env.plan(&c_file()));
    let b = env.applied(&env.plan(&h_rep()));
    let r = env.revert(&a).unwrap();
    assert!(
        r.ops.iter().any(|o| o.observed == Observed::Kept),
        "precondition"
    );
    let game = env.snap();
    let r = purge(&env, &[a]).unwrap();
    assert_eq!(r.refused, [(a, Keep::HandedOver)]);
    assert!(r.removed.is_empty());
    assert_eq!(listed(&env), [a, b]);
    // B's revert removes the object it inherits (no X14: A's records were there to read).
    reverted(&env, &b);
    assert!(!super::tests::exists_abs(
        &env.sys,
        &super::tests::game("new.dll")
    ));
    same(&floor, &env.snap());
    let r = purge(&env, &[a, b]).unwrap();
    assert_eq!(r.removed, [a, b]);
    assert!(r.refused.is_empty() && r.gone.is_empty());
    assert!(listed(&env).is_empty());
    same(&floor, &env.snap());
    let _ = game;
}

#[test]
fn hp4_an_unreadable_heir_keeps_the_creator() {
    let (env, a, b) = handed_over();
    env.sys.fake_fs().mkdir_all(Path::new(r"C:\x")).unwrap();
    env.sys
        .fake_fs()
        .swap_with_junction(Path::new(&env.txn_dir(&b)), r"C:\x")
        .unwrap();
    assert_eq!(env.state(&b), None, "precondition: B cannot be read");
    let r = purge(&env, &[a, b]).unwrap();
    assert_eq!(r.refused, [(a, Keep::HandedOver), (b, Keep::Unreadable)]);
    assert!(r.removed.is_empty());
    // Forgotten, an unreadable heir no longer holds (it will never revert).
    env.forget(&b).unwrap();
    let r = purge(&env, &[a]).unwrap();
    assert_eq!(r.removed, [a]);
}

#[test]
fn hp4_a_damaged_heir_keeps_the_creator_and_a_closed_one_does_not() {
    let (env, a, b) = handed_over();
    let gap = format!(r"{}\0042.json", env.txn_dir(&b));
    env.sys.fake_fs().put_file(Path::new(&gap), b"{}").unwrap();
    assert!(
        matches!(env.state(&b), Some(TxnState::Damaged(_))),
        "precondition"
    );
    assert_eq!(purge(&env, &[a]).unwrap().refused, [(a, Keep::HandedOver)]);
    env.sys.fake_fs().remove_abs(Path::new(&gap)).unwrap();
    // Control: a creator without a `Kept` op goes while B is applied.
    let c = env.applied(&env.plan(&spec(vec![entry("new.dll", "other.dll", N)])));
    reverted(&env, &c);
    assert_eq!(purge(&env, &[c]).unwrap().removed, [c]);
    assert_eq!(purge(&env, &[a]).unwrap().refused, [(a, Keep::HandedOver)]);
}

#[test]
fn what_is_never_purged_is_reported_and_nothing_is_written() {
    let env = Env::new(finish(base()));
    let applied = env.applied(&env.plan(&c_file()));
    let forgotten = env.applied(&env.plan(&spec(vec![entry("new.dll", "f.dll", N)])));
    env.forget(&forgotten).unwrap();
    let before = snap_app(&env.sys);
    let r = purge(&env, &[applied, forgotten]).unwrap();
    assert_eq!(
        r.refused,
        [(applied, Keep::NotSettled), (forgotten, Keep::Forgotten)]
    );
    assert!(r.removed.is_empty());
    same(&before, &snap_app(&env.sys));

    // A head other than the one seen: `Changed`, nothing written, also not the others.
    let done = env.applied(&env.plan(&spec(vec![entry("new.dll", "g.dll", N)])));
    reverted(&env, &done);
    let before = snap_app(&env.sys);
    let ids = [seen(&env, &done), (applied, Some([1; 32]))];
    match env.with(|cx| purge_seen(cx, &ids, PurgeMode::Lenient)) {
        Err(ExecError::Refused(Refusal::Changed { txn })) if txn == applied => {}
        r => panic!("{r:?}"),
    }
    same(&before, &snap_app(&env.sys));

    // Purged already: gone, which counts as done.
    let ids = [seen(&env, &done)];
    assert_eq!(
        env.with(|cx| purge_seen(cx, &ids, PurgeMode::Lenient))
            .unwrap()
            .removed,
        [done]
    );
    let r = env
        .with(|cx| purge_seen(cx, &ids, PurgeMode::Lenient))
        .unwrap();
    assert_eq!((r.removed.len(), r.gone.as_slice()), (0, &[done][..]));

    // The lock held by another Rerun.
    let a = app(&env.sys);
    let j = Journal::new(&a, InstanceTag::fixed(5));
    let held = j.lock().unwrap();
    match purge(&env, &[applied]) {
        Err(ExecError::Refused(Refusal::JournalBusy)) => {}
        r => panic!("{r:?}"),
    }
    drop(held);
}

#[test]
fn a_forgotten_profile_holder_is_reported_as_such() {
    let env = Env::new(super::profiles_tests::lm_sys(false));
    let h = super::profiles_tests::lm(&env, 220, &[], 8);
    let t = env.applied(&h);
    env.forget(&t).unwrap();
    assert_eq!(
        env.state(&t),
        Some(TxnState::Closed(Closing::Forgotten)),
        "precondition"
    );
    assert_eq!(
        purge(&env, &[t]).unwrap().refused,
        [(t, Keep::HoldsProfile)]
    );
    // Control: reverted first, then forgotten is impossible; a forgotten one without a profile
    // op is only `Forgotten` (the test above).
}

#[test]
fn a_file_in_use_stops_only_its_own_purge_and_a_later_run_finishes() {
    let env = Env::new(finish(base()));
    let x = env.applied(&env.plan(&spec(vec![entry("d3d9.dll", "d3d9.dll", NEW)])));
    reverted(&env, &x);
    let y = env.applied(&env.plan(&spec(vec![entry("new.dll", "y.dll", N)])));
    reverted(&env, &y);
    let bin = format!(r"{}\op-0000.bin", env.txn_dir(&x));
    assert!(
        super::tests::exists_abs(&env.sys, &bin),
        "precondition: x has a backup"
    );
    let held = env
        .sys
        .fake_fs()
        .hold_open_as(4242, Path::new(&bin), Access::READ, Share::RW)
        .unwrap();
    let r = purge(&env, &[x, y]).unwrap();
    assert_eq!(
        (r.removed.as_slice(), r.refused.as_slice()),
        (&[y][..], &[(x, Keep::InUse)][..])
    );
    assert!(listed(&env).is_empty(), "x is hidden by its tombstone");
    let a = app(&env.sys);
    assert_eq!(
        Journal::new(&a, InstanceTag::fixed(1))
            .list()
            .unwrap()
            .purging,
        1
    );
    drop(held);
    // The next run (with nothing asked) finishes it.
    let r = env
        .with(|cx| purge_seen(cx, &[], PurgeMode::Lenient))
        .unwrap();
    assert_eq!(r, PurgeReport::default());
    assert_eq!(
        Journal::new(&a, InstanceTag::fixed(1))
            .list()
            .unwrap()
            .purging,
        0
    );
    assert!(!super::tests::exists_abs(&env.sys, &env.txn_dir(&x)));
}

/// Review S-1 (reproduced by the reviewer): an applied heir made unreadable and a tombstone
/// with any content planted next to it. The heir stays listed (unreadable), so the creator
/// stays (`HandedOver`).
#[test]
fn a_planted_tombstone_never_hides_an_unreadable_heir() {
    let (env, a, b) = handed_over();
    let fx = env.sys.fake_fs();
    fx.mkdir_all(Path::new(r"C:\x")).unwrap();
    fx.swap_with_junction(Path::new(&env.txn_dir(&b)), r"C:\x")
        .unwrap();
    fx.put_file(
        Path::new(&format!("{}.purge", env.txn_dir(&b))),
        b"not the head at all",
    )
    .unwrap();
    assert!(listed(&env).contains(&b), "B is listed");
    assert_eq!(env.state(&b), None, "precondition: B cannot be read");
    let r = purge(&env, &[a]).unwrap();
    assert_eq!(r.refused, [(a, Keep::HandedOver)]);
    assert!(r.removed.is_empty());
}

/// Review S-2: "clear history" is exact. A transaction applied between the preview and the
/// confirmation makes the creator `HandedOver`: `Exact` refuses with nothing written, `Lenient`
/// (the cap) reports it and goes on.
#[test]
fn exact_refuses_what_is_no_longer_removable_and_lenient_reports_it() {
    let env = Env::new(finish(base()));
    let a = env.applied(&env.plan(&c_file()));
    let b = env.applied(&env.plan(&h_rep()));
    let r = env.revert(&a).unwrap();
    assert!(
        r.ops.iter().any(|o| o.observed == Observed::Kept),
        "precondition"
    );
    reverted(&env, &b);
    // The preview: both removable.
    let shown = [seen(&env, &a), seen(&env, &b)];
    // Between preview and confirmation: a new apply.
    let c = env.applied(&env.plan(&spec(vec![entry("new.dll", "other.dll", N)])));
    let before = snap_app(&env.sys);
    match env.with(|cx| purge_seen(cx, &shown, PurgeMode::Exact)) {
        Err(ExecError::Refused(Refusal::Changed { txn })) if txn == a => {}
        r => panic!("{r:?}"),
    }
    same(&before, &snap_app(&env.sys));
    let r = env
        .with(|cx| purge_seen(cx, &shown, PurgeMode::Lenient))
        .unwrap();
    assert_eq!(
        (r.removed.as_slice(), r.refused.as_slice()),
        (&[b][..], &[(a, Keep::HandedOver)][..])
    );
    // Exact with what is still removable, and an ID gone already: done.
    reverted(&env, &c);
    let shown = [seen(&env, &a), (b, shown[1].1)];
    let r = env
        .with(|cx| purge_seen(cx, &shown, PurgeMode::Exact))
        .unwrap();
    assert_eq!(
        (r.removed.as_slice(), r.gone.as_slice()),
        (&[a][..], &[b][..])
    );
}

/// Review nits: an access error of one transaction is reported and the run goes on; an ID given
/// twice is purged and reported once.
#[test]
fn an_access_error_of_one_transaction_keeps_the_report() {
    let env = Env::new(finish(base()));
    let x = env.applied(&env.plan(&spec(vec![entry("d3d9.dll", "d3d9.dll", NEW)])));
    reverted(&env, &x);
    let y = env.applied(&env.plan(&spec(vec![entry("new.dll", "y.dll", N)])));
    reverted(&env, &y);
    let ids = [seen(&env, &x), seen(&env, &y), seen(&env, &y)];
    let fx = env.sys.fake_fs();
    let r = env
        .with(|cx| {
            fx.clear_faults();
            fx.fail_at(
                crate::sys::fake::Prim::OpenFileDelete,
                1,
                crate::sys::SysErrorKind::AccessDenied,
            );
            purge_seen(cx, &ids, PurgeMode::Lenient)
        })
        .unwrap_or_else(|e| panic!("{e}"));
    assert!(fx.fault_fired(), "precondition");
    assert_eq!(
        (r.removed.as_slice(), r.refused.as_slice()),
        (&[y][..], &[(x, Keep::Foreign)][..])
    );
    assert!(r.gone.is_empty(), "y once: {r:?}");
}
