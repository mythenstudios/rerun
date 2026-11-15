//! JP1 to JP7: purging settled transactions against the fake (P5-6d-1a, ADR 0019 amendment
//! P5-6d). The world: `A` and `B`, both applied (two ops, a backup of `D:\G\a.bin`) and
//! reverted, closed `Reverted`; `B` is newer. Purging `A` removes its folder; purging `B` (the
//! highest `seq`) leaves the anchor of `seq`.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use sha2::{Digest as _, Sha256};

use super::tests::{HEAD, JDIR, TAG, apply2, game, open_app, system, txn_dir};
use super::{
    Closing, InstanceTag, Journal, JournalError, JournalLock, Limits, Observed, PurgeStop, Purged,
    TxnId, TxnState, VerifyBackups, read,
};
use crate::policy::root::AppSub;
use crate::sys::System;
use crate::sys::contract::{Access, Share};
use crate::sys::fake::{Domain, FakeSystem, Fault, Prim};
use crate::sys::fs::{Attrs, DirWrite, Fs};
use crate::sys::snapshot::{Scope, SnapRoot, Snapshot, snapshot};

/// The records, the head and the backup of a transaction of [`closed`].
pub(crate) const FULL: [&str; 12] = [
    "0001.json",
    "0002.json",
    "0003.json",
    "0004.json",
    "0005.json",
    "0006.json",
    "0007.json",
    "0008.json",
    "0009.json",
    "0010.json",
    "head.json",
    "op-0000.bin",
];

pub(crate) fn head() -> [u8; 32] {
    Sha256::digest(HEAD).into()
}

/// Applies two ops and reverts them: `Closed { Reverted }`, ten records and `op-0000.bin`.
pub(crate) fn closed(lock: &JournalLock<'_>, g: &dyn DirWrite) -> TxnId {
    let id = *apply2(lock, g).id();
    let mut w = lock.resume(&id).unwrap();
    for k in [1u16, 0] {
        w.revert_intent(k, None, None).unwrap();
        w.revert_done(k, Observed::After, &[]).unwrap();
    }
    w.close(Closing::Reverted).unwrap();
    id
}

/// The world of the module docs, everything durable.
fn world() -> (FakeSystem, TxnId, TxnId) {
    let sys = system();
    let (a, b) = {
        let app = open_app(&sys);
        let g = game(&sys, r"D:\G");
        let j = Journal::new(&app, InstanceTag::fixed(TAG));
        let lock = j.lock().unwrap();
        (closed(&lock, &*g), closed(&lock, &*g))
    };
    sys.sync_all();
    (sys, a, b)
}

/// The names in `abs`, sorted; empty if it does not exist.
fn ls(sys: &FakeSystem, abs: &str) -> Vec<String> {
    #[expect(clippy::disallowed_methods, reason = "test: list a fixture folder")]
    let Ok(d) = sys.fake_fs().open_dir(Path::new(abs)) else {
        return Vec::new();
    };
    let mut v: Vec<String> = d
        .read_dir(None)
        .unwrap()
        .into_iter()
        .map(|e| e.name)
        .collect();
    v.sort();
    v
}

fn exists(sys: &FakeSystem, abs: &str) -> bool {
    #[expect(clippy::disallowed_methods, reason = "test: look at a fixture")]
    let found = sys.fake_fs().open_dir(Path::new(JDIR)).ok().and_then(|d| {
        let name = Path::new(abs).file_name()?.to_str()?.to_owned();
        d.read_dir(None).ok()?.into_iter().find(|e| e.name == name)
    });
    found.is_some()
}

fn tomb(id: &TxnId) -> String {
    format!(r"{JDIR}\{id}.purge")
}

fn marker(id: &TxnId) -> String {
    format!(r"{JDIR}\{id}.forgotten")
}

/// A snapshot of `abs`.
fn snap(sys: &FakeSystem, abs: &str) -> Snapshot {
    #[expect(clippy::disallowed_methods, reason = "test: snapshot a fixture folder")]
    let d = sys.fake_fs().open_dir(Path::new(abs)).unwrap();
    snapshot(
        sys.registry(),
        &Scope {
            dirs: vec![SnapRoot::new(&*d, abs.to_owned())],
            keys: Vec::new(),
        },
    )
    .unwrap()
}

/// Every snapshot this module compares: Rerun's folder and the game folder.
fn snaps(sys: &FakeSystem) -> (Snapshot, Snapshot) {
    (
        snap(sys, r"C:\Users\Player\AppData\Local\Rerun"),
        snap(sys, r"D:\G"),
    )
}

/// The state of `id` as listed (`None`: not listed). An unreadable view panics.
fn listed(sys: &FakeSystem, id: &TxnId) -> Option<TxnState> {
    let app = open_app(sys);
    let l = Journal::new(&app, InstanceTag::fixed(1)).list().unwrap();
    l.txns.into_iter().find(|t| t.id == *id).map(|t| {
        t.view
            .unwrap_or_else(|e| panic!("{id} unreadable: {e}"))
            .state
    })
}

fn purging(sys: &FakeSystem) -> usize {
    let app = open_app(sys);
    Journal::new(&app, InstanceTag::fixed(1))
        .list()
        .unwrap()
        .purging
}

/// A fresh instance tag per run, as `InstanceTag::new` gives one (a crashed run's temp names
/// never meet the next run's).
fn run_tag() -> InstanceTag {
    static N: AtomicU64 = AtomicU64::new(0x9000);
    InstanceTag::fixed(N.fetch_add(1, Ordering::Relaxed))
}

/// `f` under the lock of a fresh run.
fn locked<R>(sys: &FakeSystem, f: impl FnOnce(&JournalLock<'_>) -> R) -> R {
    let app = open_app(sys);
    let j = Journal::new(&app, run_tag());
    let lock = j.lock().unwrap();
    f(&lock)
}

fn purge(sys: &FakeSystem, id: &TxnId) -> Result<Purged, JournalError> {
    locked(sys, |l| l.purge(id, Some(&head())))
}

fn stopped(r: &Result<Purged, JournalError>) -> Option<PurgeStop> {
    match r {
        Err(JournalError::Purge { why, .. }) => Some(*why),
        _ => None,
    }
}

/// The diff lines of `a` → `b` that are not below `journal\<id>` (its folder, marker or
/// tombstone).
fn other_changes(a: &Snapshot, b: &Snapshot, id: &TxnId) -> Vec<String> {
    // Snapshot locations are folded (upper case).
    let mine = format!(r"journal\{id}").to_uppercase();
    a.diff(b)
        .into_iter()
        .filter(|l| !l.to_uppercase().contains(&mine))
        .collect()
}

#[test]
fn jp1_a_purge_removes_the_folder_and_its_marker_and_nothing_else() {
    let (sys, a, b) = world();
    // A forget marker of `a` (planted: `a` is closed) goes with it.
    sys.fake_fs().put_file(Path::new(&marker(&a)), b"").unwrap();
    let (app0, game0) = snaps(&sys);
    assert_eq!(ls(&sys, &txn_dir(&a)), FULL, "precondition");
    assert_eq!(purge(&sys, &a).unwrap(), Purged { anchor: false });
    assert!(!exists(&sys, &txn_dir(&a)) && !exists(&sys, &tomb(&a)) && !exists(&sys, &marker(&a)));
    let (app1, game1) = snaps(&sys);
    assert!(game0 == game1, "{:#?}", game0.diff(&game1));
    assert_eq!(other_changes(&app0, &app1, &a), Vec::<String>::new());
    assert!(!app0.diff(&app1).is_empty(), "the folder went");
    assert_eq!(listed(&sys, &a), None);
    assert_eq!(listed(&sys, &b), Some(TxnState::Closed(Closing::Reverted)));
    assert_eq!(purging(&sys), 0);

    // The highest one: the anchor stays, empty, with its tombstone, and nobody sees it.
    assert_eq!(purge(&sys, &b).unwrap(), Purged { anchor: true });
    assert!(ls(&sys, &txn_dir(&b)).is_empty() && exists(&sys, &txn_dir(&b)));
    assert!(exists(&sys, &tomb(&b)));
    assert_eq!(listed(&sys, &b), None);
    assert_eq!(purging(&sys), 0, "the anchor is no purge begun");
    let (app2, game2) = snaps(&sys);
    assert!(game0 == game2);
    assert_eq!(other_changes(&app1, &app2, &b), Vec::<String>::new());
    // An empty transaction (a crash right after `begin`) goes silently too.
    let e = locked(&sys, |l| *l.begin(HEAD).unwrap().id());
    assert_eq!(listed(&sys, &e), Some(TxnState::Empty));
    assert_eq!(purge(&sys, &e).unwrap(), Purged { anchor: true });
    assert_eq!(listed(&sys, &e), None);
}

/// What `JournalLock::purge` refuses, each with nothing written.
#[test]
fn jp2_every_never_row_is_refused_and_writes_nothing() {
    let refused = |sys: &FakeSystem, id: &TxnId, h: Option<[u8; 32]>| {
        let before = snaps(sys);
        let r = locked(sys, |l| l.purge(id, h.as_ref()));
        // The lock file is created by the first lock of a run only; it is there already.
        assert!(before == snaps(sys), "{id}: something was written: {r:?}");
        r
    };
    let fresh = || {
        let (sys, a, b) = world();
        // Make sure the lock file exists before the snapshots.
        locked(&sys, |_| ());
        (sys, a, b)
    };
    // Open (an interrupted apply) and Applied with a `.old` left (a cleanup pending).
    {
        let (sys, _, _) = fresh();
        let (open, applied) = locked(&sys, |l| {
            let g = game(&sys, r"D:\G");
            let applied = *apply2(l, &*g).id();
            let mut w = l.begin(HEAD).unwrap();
            w.intent(0, None, None).unwrap();
            (*w.id(), applied)
        });
        assert_eq!(listed(&sys, &open), Some(TxnState::Open), "precondition");
        assert_eq!(
            listed(&sys, &applied),
            Some(TxnState::Applied),
            "precondition"
        );
        for id in [open, applied] {
            assert_eq!(
                stopped(&refused(&sys, &id, Some(head()))),
                Some(PurgeStop::NotSettled)
            );
        }
    }
    // Damaged without a marker (a gap), and `TooManyEntries` with and without a marker.
    {
        let (sys, a, _) = fresh();
        sys.fake_fs()
            .put_file(Path::new(&format!(r"{}\0012.json", txn_dir(&a))), b"{}")
            .unwrap();
        assert!(
            matches!(listed(&sys, &a), Some(TxnState::Closed(_))),
            "a planted tail"
        );
        assert_eq!(
            stopped(&refused(&sys, &a, Some(head()))),
            Some(PurgeStop::Foreign)
        );
    }
    {
        let (sys, _, _) = fresh();
        let open = locked(&sys, |l| {
            let mut w = l.begin(HEAD).unwrap();
            w.intent(0, None, None).unwrap();
            *w.id()
        });
        sys.fake_fs()
            .remove_abs(Path::new(&format!(r"{}\0001.json", txn_dir(&open))))
            .unwrap();
        sys.fake_fs()
            .put_file(Path::new(&format!(r"{}\0002.json", txn_dir(&open))), b"{}")
            .unwrap();
        assert!(
            matches!(listed(&sys, &open), Some(TxnState::Damaged(_))),
            "precondition"
        );
        assert_eq!(
            stopped(&refused(&sys, &open, Some(head()))),
            Some(PurgeStop::NotSettled)
        );
    }
    {
        let (sys, a, _) = fresh();
        let app = open_app(&sys);
        let lim = Limits {
            txn_entries: 4,
            ..Limits::default()
        };
        let j = Journal::with_limits(&app, run_tag(), lim);
        let v = j.load(&a, VerifyBackups::Length).unwrap();
        assert_eq!(
            v.state,
            TxnState::Damaged(super::Damage::TooManyEntries),
            "precondition"
        );
        // The lock file is share 0: snapshots only while it is not held.
        let small = |f: &dyn Fn(&JournalLock<'_>) -> Result<Purged, JournalError>| {
            let j = Journal::with_limits(&app, run_tag(), lim);
            let lock = j.lock().unwrap();
            f(&lock)
        };
        let before = snaps(&sys);
        // Too many entries: no head was read, so the caller saw none.
        assert_eq!(v.head_sha256, None, "precondition");
        let r = small(&|l| l.purge(&a, None));
        assert_eq!(stopped(&r), Some(PurgeStop::NotSettled));
        assert!(before == snaps(&sys));
        locked(&sys, |l| l.forget_marker(&a, None).unwrap());
        let before2 = snaps(&sys);
        assert!(before != before2, "the marker is there");
        assert_eq!(
            stopped(&small(&|l| l.purge(&a, None))),
            Some(PurgeStop::TooManyEntries)
        );
        assert!(before2 == snaps(&sys));
    }
    // Another head than the one seen; a tombstone for another head.
    {
        let (sys, a, _) = fresh();
        assert_eq!(
            stopped(&refused(&sys, &a, Some([7; 32]))),
            Some(PurgeStop::HeadChanged)
        );
        assert_eq!(
            stopped(&refused(&sys, &a, None)),
            Some(PurgeStop::HeadChanged)
        );
        sys.fake_fs()
            .put_file(Path::new(&tomb(&a)), &[b'0'; 64])
            .unwrap();
        assert_eq!(
            listed(&sys, &a),
            Some(TxnState::Closed(Closing::Reverted)),
            "it hides nothing"
        );
        assert_eq!(
            stopped(&refused(&sys, &a, Some(head()))),
            Some(PurgeStop::TombstoneInTheWay)
        );
        // A folder under the tombstone's name: in the way as well, not an error of the run.
        sys.fake_fs().remove_abs(Path::new(&tomb(&a))).unwrap();
        sys.fake_fs().mkdir_all(Path::new(&tomb(&a))).unwrap();
        assert_eq!(listed(&sys, &a), Some(TxnState::Closed(Closing::Reverted)));
        assert_eq!(
            stopped(&refused(&sys, &a, Some(head()))),
            Some(PurgeStop::TombstoneInTheWay)
        );
    }
    // Foreign content: an unknown file, a folder, a hard link, a read-only record; an
    // unreadable folder (a junction), also with a marker.
    for case in 0..5 {
        let (sys, a, _) = fresh();
        let fx = sys.fake_fs();
        let dir = txn_dir(&a);
        match case {
            0 => fx
                .put_file(Path::new(&format!(r"{dir}\notes.txt")), b"x")
                .unwrap(),
            1 => fx.mkdir_all(Path::new(&format!(r"{dir}\sub"))).unwrap(),
            2 => fx
                .put_hardlink(
                    Path::new(&format!(r"{dir}\0003.json")),
                    Path::new(r"C:\Users\Player\elsewhere.json"),
                )
                .unwrap(),
            3 => fx
                .set_attrs(
                    Path::new(&format!(r"{dir}\0003.json")),
                    Attrs {
                        readonly: true,
                        ..Attrs::default()
                    },
                )
                .unwrap(),
            _ => {
                fx.mkdir_all(Path::new(r"C:\x")).unwrap();
                fx.swap_with_junction(Path::new(&dir), r"C:\x").unwrap();
            }
        }
        let r = refused(&sys, &a, Some(head()));
        match case {
            4 => {
                assert!(super::tests::is_reparse(&r), "{r:?}");
                locked(&sys, |l| l.forget_marker(&a, None).unwrap());
                let r = refused(&sys, &a, None);
                assert!(super::tests::is_reparse(&r), "with a marker: {r:?}");
            }
            _ => assert_eq!(stopped(&r), Some(PurgeStop::Foreign), "case {case}"),
        }
    }
}

/// The calls of a complete purge of `target` in the world.
fn trace(target: fn(&TxnId, &TxnId) -> TxnId) -> Vec<Prim> {
    let (sys, a, b) = world();
    let fx = sys.fake_fs();
    let t = target(&a, &b);
    let r = locked(&sys, |l| {
        fx.clear_faults();
        fx.record_calls(true);
        let r = l.purge(&t, Some(&head()));
        fx.record_calls(false);
        r
    });
    r.unwrap();
    fx.take_calls()
}

fn nth_of(calls: &[Prim], i: usize) -> usize {
    calls[..=i].iter().filter(|c| **c == calls[i]).count()
}

/// The world, with the purge of `target` crashed after `calls[i]` (or complete for
/// `i == calls.len()`). Not restarted.
fn crashed(
    calls: &[Prim],
    i: usize,
    target: fn(&TxnId, &TxnId) -> TxnId,
) -> (FakeSystem, TxnId, TxnId) {
    let (sys, a, b) = world();
    crash_on(&sys, calls, i, &target(&a, &b));
    (sys, a, b)
}

/// The purge of `t` on `sys`, crashed after `calls[i]` (or complete). Not restarted.
fn crash_on(sys: &FakeSystem, calls: &[Prim], i: usize, t: &TxnId) {
    let fx = sys.fake_fs();
    let r = locked(sys, |l| {
        fx.clear_faults();
        if let Some(c) = calls.get(i) {
            fx.fault(*c, nth_of(calls, i), Fault::CrashAfter);
        }
        l.purge(t, Some(&head()))
    });
    if i == calls.len() {
        r.unwrap();
    } else {
        assert!(r.is_err() && fx.crashed(), "crash after call {i}");
    }
}

fn older(a: &TxnId, _: &TxnId) -> TxnId {
    *a
}

fn newest(_: &TxnId, b: &TxnId) -> TxnId {
    *b
}

/// After a restart or power loss: `t` is listed exactly as before or not at all, and never
/// damaged or open; if any of its files is gone, its tombstone is there.
fn unchanged_or_hidden(sys: &FakeSystem, t: &TxnId) -> Vec<String> {
    let mut v = Vec::new();
    let files = ls(sys, &txn_dir(t));
    match listed(sys, t) {
        None => {}
        Some(TxnState::Closed(Closing::Reverted)) if files == FULL => {}
        Some(s) => v.push(format!("listed as {s:?} with {files:?}")),
    }
    let started = files != FULL;
    if started && exists(sys, &txn_dir(t)) && !exists(sys, &tomb(t)) {
        v.push(format!("{files:?} without a tombstone"));
    }
    // S2, the order: even a reader that missed the tombstone never sees it open or applied.
    if let Ok(r) = raw(sys, t)
        && matches!(r.state, TxnState::Open | TxnState::Applied)
    {
        v.push(format!(
            "{files:?} reads as {:?} without its tombstone",
            r.state
        ));
    }
    v
}

/// The next run finishes: `finish_purges`, then a purge if `t` is still listed. Afterwards
/// `t` is gone (or the anchor, for the highest) and the lock is free.
fn finished(sys: &FakeSystem, t: &TxnId, anchor: bool) {
    locked(sys, |l| {
        l.finish_purges().unwrap();
    });
    if listed(sys, t).is_some() {
        assert_eq!(purge(sys, t).unwrap().anchor, anchor);
    }
    assert_eq!(listed(sys, t), None);
    assert!(!exists(sys, &marker(t)));
    if anchor {
        assert!(exists(sys, &txn_dir(t)) && ls(sys, &txn_dir(t)).is_empty());
        assert!(exists(sys, &tomb(t)));
    } else {
        assert!(
            !exists(sys, &txn_dir(t)) && !exists(sys, &tomb(t)),
            "{:?}",
            ls(sys, JDIR)
        );
    }
    assert_eq!(purging(sys), 0);
    let app = open_app(sys);
    drop(Journal::new(&app, InstanceTag::fixed(3)).lock().unwrap());
}

/// The highest `seq` in use after a purge: a new transaction takes one more.
fn next_seq(sys: &FakeSystem) -> u32 {
    locked(sys, |l| l.begin(HEAD).unwrap().id().seq())
}

#[test]
fn jp3_a_crash_after_any_call_leaves_it_unchanged_or_invisible_and_the_next_run_finishes() {
    for target in [older as fn(&TxnId, &TxnId) -> TxnId, newest] {
        let calls = trace(target);
        assert!(
            calls.contains(&Prim::OpenFileDelete),
            "remove_file is on the path"
        );
        let mut hidden = 0;
        for i in 0..=calls.len() {
            let (sys, a, b) = crashed(&calls, i, target);
            let t = target(&a, &b);
            sys.restart();
            let bad = unchanged_or_hidden(&sys, &t);
            assert!(
                bad.is_empty(),
                "after call {i} ({:?}): {bad:?}",
                calls.get(i)
            );
            hidden += usize::from(listed(&sys, &t).is_none() && exists(&sys, &txn_dir(&t)));
            finished(&sys, &t, t == b);
            assert_eq!(next_seq(&sys), b.seq() + 1, "after call {i}");
        }
        assert!(hidden > 3, "the matrix reaches purges begun: {hidden}");
    }
}

/// A closed transaction without a backup (one op that kept its old state inline), older than
/// another one: only the order of the records keeps a purge begun from reading as applied.
fn plain_world() -> (FakeSystem, TxnId) {
    let sys = system();
    let t = locked(&sys, |l| {
        let mut w = l.begin(HEAD).unwrap();
        let t0 = w.tmp();
        w.intent(0, Some(t0), Some(super::BeforeArg::Inline(b"old".to_vec())))
            .unwrap();
        w.done(0, Some(7), false).unwrap();
        w.applied(1).unwrap();
        let id = *w.id();
        drop(w);
        let mut w = l.resume(&id).unwrap();
        w.revert_intent(0, None, None).unwrap();
        w.revert_done(0, Observed::After, &[]).unwrap();
        w.close(Closing::Reverted).unwrap();
        drop(l.begin(HEAD).unwrap());
        id
    });
    sys.sync_all();
    (sys, t)
}

#[test]
fn jp3_the_order_never_shows_a_closed_one_open_or_applied() {
    let calls = {
        let (sys, t) = plain_world();
        let fx = sys.fake_fs();
        locked(&sys, |l| {
            fx.clear_faults();
            fx.record_calls(true);
            l.purge(&t, Some(&head())).unwrap();
            fx.record_calls(false);
        });
        fx.take_calls()
    };
    let mut partial = 0;
    for i in 0..=calls.len() {
        let (sys, t) = plain_world();
        crash_on(&sys, &calls, i, &t);
        sys.restart();
        let r = raw(&sys, &t);
        if let Ok(v) = &r {
            assert!(
                !matches!(v.state, TxnState::Open | TxnState::Applied),
                "after call {i}: {:?} with {:?}",
                v.state,
                ls(&sys, &txn_dir(&t))
            );
            partial += usize::from(matches!(v.state, TxnState::Damaged(_)));
        }
        assert_eq!(
            listed(&sys, &t).filter(|s| *s != TxnState::Closed(Closing::Reverted)),
            None
        );
    }
    assert!(partial > 0, "the matrix reaches records partly deleted");
}

#[test]
fn jp4_a_power_loss_never_keeps_a_deletion_without_its_tombstone() {
    let mut runs = 0;
    for target in [older as fn(&TxnId, &TxnId) -> TxnId, newest] {
        let calls = trace(target);
        for i in 0..=calls.len() {
            let pending = {
                let (sys, _, _) = crashed(&calls, i, target);
                sys.pending(Domain::Volume('C'))
            };
            for c in 0..=pending {
                let (sys, a, b) = crashed(&calls, i, target);
                let t = target(&a, &b);
                sys.power_loss(&BTreeMap::from([(Domain::Volume('C'), c)]));
                runs += 1;
                let bad = unchanged_or_hidden(&sys, &t);
                assert!(
                    bad.is_empty(),
                    "after call {i} ({:?}), cut {c}: {bad:?}",
                    calls.get(i)
                );
                finished(&sys, &t, t == b);
                assert_eq!(next_seq(&sys), b.seq() + 1, "after call {i}, cut {c}");
            }
        }
    }
    assert!(runs > 100, "{runs}");
}

#[test]
fn jp5_seq_stays_monotonic_after_purging_everything() {
    let (sys, a, b) = world();
    purge(&sys, &a).unwrap();
    assert!(purge(&sys, &b).unwrap().anchor);
    assert_eq!(purging(&sys), 0, "the anchor does not count");
    let app = open_app(&sys);
    assert!(
        Journal::new(&app, InstanceTag::fixed(1))
            .list()
            .unwrap()
            .txns
            .is_empty()
    );
    drop(app);
    // Control: without the anchor, the number of `b` would come back.
    {
        let (sys2, a2, b2) = world();
        purge(&sys2, &a2).unwrap();
        purge(&sys2, &b2).unwrap();
        sys2.fake_fs().remove_abs(Path::new(&tomb(&b2))).unwrap();
        sys2.fake_fs().remove_abs(Path::new(&txn_dir(&b2))).unwrap();
        assert!(
            next_seq(&sys2) <= b2.seq(),
            "the control hands a number out again"
        );
    }
    let c = locked(&sys, |l| *l.begin(HEAD).unwrap().id());
    assert_eq!(c.seq(), b.seq() + 1);
    // A newer transaction exists: the next run removes the anchor, also after a crash at any
    // call of it.
    let calls = {
        let fx = sys.fake_fs();
        let snap = snaps(&sys);
        locked(&sys, |l| {
            fx.clear_faults();
            fx.record_calls(true);
            l.finish_purges().unwrap();
            fx.record_calls(false);
        });
        let calls = fx.take_calls();
        assert!(snap != snaps(&sys), "the anchor went");
        calls
    };
    assert!(!exists(&sys, &txn_dir(&b)) && !exists(&sys, &tomb(&b)));
    assert!(calls.contains(&Prim::OpenDirDelete));
    for i in 0..calls.len() {
        let (sys, a, b) = world();
        purge(&sys, &a).unwrap();
        purge(&sys, &b).unwrap();
        let c = locked(&sys, |l| *l.begin(HEAD).unwrap().id());
        let fx = sys.fake_fs();
        let r = locked(&sys, |l| {
            fx.clear_faults();
            fx.fault(calls[i], nth_of(&calls, i), Fault::CrashAfter);
            l.finish_purges()
        });
        assert!(r.is_err() && fx.crashed(), "crash after call {i}");
        sys.restart();
        assert_eq!(listed(&sys, &b), None);
        assert_eq!(
            purging(&sys),
            usize::from(exists(&sys, &tomb(&b)) && !exists(&sys, &txn_dir(&b)))
        );
        let d = locked(&sys, |l| *l.begin(HEAD).unwrap().id());
        assert_eq!(d.seq(), c.seq() + 1, "after call {i}");
        // `c` and `d` are empty; purge both, the newest stays the anchor.
        purge(&sys, &c).unwrap();
        assert!(purge(&sys, &d).unwrap().anchor);
        locked(&sys, |l| l.finish_purges().unwrap());
        assert!(
            !exists(&sys, &txn_dir(&b)) && !exists(&sys, &tomb(&b)),
            "after call {i}"
        );
        assert_eq!(next_seq(&sys), d.seq() + 1);
    }
}

#[test]
fn jp6_tampering() {
    // A tombstone with another hash hides nothing and is not continued, not even by the run
    // that finishes purges.
    {
        let (sys, a, _) = world();
        sys.fake_fs()
            .put_file(Path::new(&tomb(&a)), b"not the head")
            .unwrap();
        assert_eq!(listed(&sys, &a), Some(TxnState::Closed(Closing::Reverted)));
        assert_eq!(purging(&sys), 0);
        let before = snaps(&sys);
        locked(&sys, |l| l.finish_purges().unwrap());
        assert!(before == snaps(&sys));
        assert_eq!(ls(&sys, &txn_dir(&a)), FULL);
    }
    // A tombstone that applies hides the transaction (scenario 29: as forgetting it would).
    {
        let (sys, a, _) = world();
        sys.fake_fs()
            .put_file(
                Path::new(&tomb(&a)),
                crate::wire::hex32::to_string(&head()).as_bytes(),
            )
            .unwrap();
        assert_eq!(listed(&sys, &a), None);
        assert_eq!(purging(&sys), 1);
        let app = open_app(&sys);
        let j = Journal::new(&app, InstanceTag::fixed(1));
        assert!(matches!(
            j.load(&a, VerifyBackups::Length),
            Err(JournalError::NotFound(_))
        ));
        let lock = j.lock().unwrap();
        assert!(matches!(lock.resume(&a), Err(JournalError::NotFound(_))));
    }
    // Markers and tombstones without a folder go; a marker that is a folder stays foreign.
    {
        let (sys, a, _) = world();
        let gone = TxnId::new(77, 1).unwrap();
        let fx = sys.fake_fs();
        fx.put_file(Path::new(&marker(&gone)), b"").unwrap();
        fx.put_file(Path::new(&tomb(&gone)), b"").unwrap();
        fx.mkdir_all(Path::new(&tomb(&TxnId::new(78, 1).unwrap())))
            .unwrap();
        fx.put_file(Path::new(&marker(&a)), b"").unwrap();
        assert_eq!(purging(&sys), 1, "an orphan tombstone is a purge begun");
        let app = open_app(&sys);
        assert_eq!(
            Journal::new(&app, InstanceTag::fixed(1))
                .list()
                .unwrap()
                .foreign,
            1
        );
        drop(app);
        locked(&sys, |l| l.finish_purges().unwrap());
        assert!(!exists(&sys, &marker(&gone)) && !exists(&sys, &tomb(&gone)));
        assert!(
            exists(&sys, &marker(&a)),
            "a's folder is there: its marker stays"
        );
        assert_eq!(purging(&sys), 0);
    }
    // A file in use without share-delete (a scanner): the purge stops, the tombstone stays,
    // the transaction is hidden; once released, the next run finishes.
    {
        let (sys, a, _) = world();
        let bin = format!(r"{}\op-0000.bin", txn_dir(&a));
        let held = sys
            .fake_fs()
            .hold_open_as(4242, Path::new(&bin), Access::READ, Share::RW)
            .unwrap();
        assert_eq!(stopped(&purge(&sys, &a)), Some(PurgeStop::InUse));
        assert!(exists(&sys, &tomb(&a)));
        assert_eq!(listed(&sys, &a), None);
        assert_eq!(purging(&sys), 1);
        locked(&sys, |l| l.finish_purges().unwrap());
        assert!(
            exists(&sys, &bin.replace(r"\op-0000.bin", "")),
            "still held"
        );
        drop(held);
        finished(&sys, &a, false);
    }
    // A hard link added between the check and the deletion: the purge stops there, deletes
    // nothing more, and keeps refusing.
    {
        let (sys, a, _) = world();
        let fx = sys.fake_fs();
        let rec = format!(r"{}\0005.json", txn_dir(&a));
        let mut done = false;
        let target = rec.clone();
        fx.on_step(move |fx, ev| {
            if !done && ev.call == Some(Prim::OpenFileDelete) && ev.name == "0005.json" {
                done = true;
                fx.put_hardlink(Path::new(&target), Path::new(r"C:\Users\Player\keep.json"))
                    .unwrap();
            }
        });
        assert_eq!(stopped(&purge(&sys, &a)), Some(PurgeStop::Foreign));
        fx.clear_on_step();
        let left = ls(&sys, &txn_dir(&a));
        assert!(
            left.contains(&"0005.json".to_owned()) && left.contains(&"head.json".to_owned()),
            "{left:?}"
        );
        assert!(
            !left.contains(&"op-0000.bin".to_owned()) && !left.contains(&"0006.json".to_owned())
        );
        assert_eq!(listed(&sys, &a), None);
        locked(&sys, |l| l.finish_purges().unwrap());
        assert_eq!(ls(&sys, &txn_dir(&a)), left, "nothing more");
    }
    // The lock is held: `Busy`.
    {
        let (sys, _, _) = world();
        let app = open_app(&sys);
        let j = Journal::new(&app, InstanceTag::fixed(1));
        let _held = j.lock().unwrap();
        let app2 = open_app(&sys);
        assert!(matches!(
            Journal::new(&app2, InstanceTag::fixed(2)).lock(),
            Err(JournalError::Busy)
        ));
    }
}

/// The raw view of `t` (whatever tombstone there is), as a reader without the tombstone rule
/// would see it.
fn raw(sys: &FakeSystem, t: &TxnId) -> Result<super::TxnView, JournalError> {
    let app = open_app(sys);
    let jdir = app.sub(AppSub::Journal).unwrap().unwrap();
    read::load_raw(
        &*jdir,
        t,
        VerifyBackups::Length,
        &Limits::default(),
        app.path(),
    )
}

#[test]
fn jp7_a_reader_between_scan_and_load_sees_it_settled_or_not_at_all() {
    let calls = trace(older);
    let mut bites = 0;
    for i in 0..=calls.len() {
        let (sys, a, _) = world();
        // The reader's scan, before the purge.
        {
            let app = open_app(&sys);
            let l = Journal::new(&app, InstanceTag::fixed(1)).list().unwrap();
            assert!(l.txns.iter().any(|t| t.id == a));
        }
        crash_on(&sys, &calls, i, &a);
        sys.restart();
        // The reader's load of what it scanned.
        let app = open_app(&sys);
        let j = Journal::new(&app, InstanceTag::fixed(1));
        match j.load(&a, VerifyBackups::Length) {
            Ok(v) => assert_eq!(
                v.state,
                TxnState::Closed(Closing::Reverted),
                "after call {i}"
            ),
            Err(JournalError::NotFound(_)) => {}
            Err(e) => panic!("after call {i}: {e}"),
        }
        for t in j.list().unwrap().txns {
            let s = t.view.unwrap().state;
            assert!(matches!(s, TxnState::Closed(_)), "after call {i}: {s:?}");
        }
        drop(j);
        drop(app);
        // Bite: without the tombstone, some step reads as damaged.
        if let Ok(v) = raw(&sys, &a)
            && matches!(v.state, TxnState::Damaged(_))
        {
            bites += 1;
        }
    }
    assert!(bites > 3, "the tombstone hid damaged views: {bites}");

    // The purge finishes between a reader's load and its tombstone read: the folder is gone,
    // so it is not listed.
    let (sys, a, _) = crashed(&calls, calls.len() / 2, older);
    sys.restart();
    let raw_state = raw(&sys, &a).unwrap().state;
    assert!(
        matches!(raw_state, TxnState::Damaged(_)),
        "precondition: {raw_state:?}"
    );
    let fx = sys.fake_fs();
    let dir = txn_dir(&a);
    let t = tomb(&a);
    let name = format!("{a}.purge");
    let mut done = false;
    fx.on_step(move |fx, ev| {
        if !done && ev.name == name {
            done = true;
            for f in [
                "0001.json",
                "0002.json",
                "0003.json",
                "0004.json",
                "0005.json",
                "0006.json",
                "0007.json",
                "0008.json",
                "0009.json",
                "0010.json",
                "head.json",
                "op-0000.bin",
            ] {
                let _ = fx.remove_abs(Path::new(&format!(r"{dir}\{f}")));
            }
            fx.remove_abs(Path::new(&dir)).unwrap();
            fx.remove_abs(Path::new(&t)).unwrap();
        }
    });
    let app = open_app(&sys);
    let j = Journal::new(&app, InstanceTag::fixed(1));
    assert!(matches!(
        j.load(&a, VerifyBackups::Length),
        Err(JournalError::NotFound(_))
    ));
    fx.clear_on_step();
}
