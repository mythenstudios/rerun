//! J4 to J6: the journal under crashes and power losses (ADR 0019 amendment, P2-7).
//!
//! The script applies two ops and reverts them, the journal on `C:` and the stub changes on
//! `D:` (op `k` creates `D:\G\c<k>.bin`, its revert deletes it); op 0 takes a backup of
//! `D:\G\a.bin`. The game folder is flushed before `applied` and before each `revert_done`, as
//! `exec` does (ADR 0019 amendment P2-8: a durable `RevertDone` has a durable change).
//! - J4 crashes after every call of Rerun the script makes (condition S1), restarts and
//!   requires: never damaged, a prefix of the full log, the lock free, and `resume` finishes
//!   and closes.
//! - J5 cuts power after every call and after the end, at every cut of `C:` times every cut
//!   of `D:`, and requires the properties of [`violations`].
//! - J6 switches off one flush site at a time; each time some property must fail.

use std::collections::BTreeMap;
use std::time::Instant;

use sha2::{Digest, Sha256};

use super::record::Record;
use super::tests::{HEAD, TAG, game, open_app, r, system};
use super::{
    Closing, FlushSite, InstanceTag, Journal, JournalError, Observed, TxnState, VerifyBackups, knob,
};
use crate::policy::root::AppDir;
use crate::sys::fake::{Domain, FakeSystem, Fault, Prim};
use crate::sys::fs::{Attrs, DirWrite, NewFile, TmpName};

const C: [&[u8]; 2] = [b"change of op 0", b"change of op 1"];

fn sha(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}

fn stub(k: usize) -> String {
    format!("c{k}.bin")
}

/// A flush of the script that J6 switches off.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Site {
    Journal(FlushSite),
    GameBeforeApplied,
    GameBeforeRevertDone,
}

const SITES: [Site; 6] = [
    Site::Journal(FlushSite::Intent),
    Site::GameBeforeApplied,
    Site::Journal(FlushSite::Applied),
    Site::Journal(FlushSite::RevertIntent),
    Site::GameBeforeRevertDone,
    Site::Journal(FlushSite::Close),
];

/// What the script got back: records whose flushing call returned `Ok`.
#[derive(Debug, Default, Clone, Copy)]
struct Progress {
    flushed: usize,
}

fn script(
    app: &AppDir<'_>,
    g: &dyn DirWrite,
    skip: Option<Site>,
    p: &mut Progress,
) -> Result<(), JournalError> {
    let j = Journal::new(app, InstanceTag::fixed(TAG));
    let lock = j.lock()?;
    let mut w = lock.begin(HEAD)?;
    let game_flush = |site: Site| -> Result<(), JournalError> {
        if skip == Some(site) {
            Ok(())
        } else {
            Ok(g.flush()?)
        }
    };
    let change = |k: usize, tmp: TmpName| -> Result<u128, JournalError> {
        let new = NewFile {
            tmp,
            attrs: Attrs::default(),
            sha256: sha(C[k]),
            max_len: 64,
        };
        Ok(g.create_new(&r(&stub(k)), &mut &C[k][..], &new)?.file_id)
    };
    let mut guard = g.guard(&r("a.bin"))?;
    let b = w.backup(&mut *guard)?;
    drop(guard);
    let t0 = w.tmp();
    w.intent(
        0,
        Some(t0.clone()),
        Some(crate::journal::BeforeArg::Backup(b)),
    )?;
    p.flushed = 1;
    let id0 = change(0, t0)?;
    w.done(0, Some(id0), false)?;
    let t1 = w.tmp();
    w.intent(1, Some(t1.clone()), None)?;
    p.flushed = 3;
    let id1 = change(1, t1)?;
    w.done(1, Some(id1), false)?;
    game_flush(Site::GameBeforeApplied)?;
    w.applied(2)?;
    p.flushed = 5;
    for (k, n) in [(1u16, 6), (0, 8)] {
        w.revert_intent(k, None, None)?;
        p.flushed = n;
        let name = r(&stub(usize::from(k)));
        g.guard(&name)?.delete(&sha(C[usize::from(k)]))?;
        game_flush(Site::GameBeforeRevertDone)?;
        w.revert_done(k, Observed::After, false)?;
    }
    w.close(Closing::Reverted)?;
    p.flushed = 10;
    Ok(())
}

/// A fresh system with `Rerun\journal\lock` in place, everything durable.
fn setup() -> FakeSystem {
    let sys = system();
    {
        let app = open_app(&sys);
        drop(Journal::new(&app, InstanceTag::fixed(1)).lock().unwrap());
    }
    sys.fake_fs().sync_all();
    sys
}

/// Occurrence (1-based) of `calls[i]` among `calls[..=i]`.
fn nth_of(calls: &[Prim], i: usize) -> usize {
    calls[..=i].iter().filter(|c| **c == calls[i]).count()
}

/// Runs the script, crashing after `calls[i]` (or completing for `i == calls.len()`).
fn run(sys: &FakeSystem, calls: &[Prim], i: usize, skip: Option<Site>) -> Progress {
    let app = open_app(sys);
    let g = game(sys, r"D:\G");
    let fx = sys.fake_fs();
    fx.clear_faults();
    if let Some(c) = calls.get(i) {
        fx.fault(*c, nth_of(calls, i), Fault::CrashAfter);
    }
    if let Some(Site::Journal(s)) = skip {
        knob::skip(Some(s));
    }
    let mut p = Progress::default();
    let res = script(&app, &*g, skip, &mut p);
    knob::skip(None);
    if i == calls.len() {
        res.unwrap_or_else(|e| panic!("the script without a crash: {e}"));
    } else {
        assert!(res.is_err() && fx.crashed(), "crash after call {i}");
    }
    p
}

/// The calls of a complete run and its log.
fn trace(skip: Option<Site>) -> (Vec<Prim>, Vec<Record>) {
    let sys = setup();
    let app = open_app(&sys);
    let g = game(&sys, r"D:\G");
    let fx = sys.fake_fs();
    fx.clear_faults();
    fx.record_calls(true);
    if let Some(Site::Journal(s)) = skip {
        knob::skip(Some(s));
    }
    let res = script(&app, &*g, skip, &mut Progress::default());
    knob::skip(None);
    fx.record_calls(false);
    res.unwrap();
    let calls = fx.take_calls();
    let j = Journal::new(&app, InstanceTag::fixed(2));
    let listing = j.list().unwrap();
    let log = listing.txns[0].view.as_ref().unwrap().log.clone();
    assert_eq!(log.len(), 10);
    (calls, log)
}

/// What is on disk after a restart or power loss: the log of the transaction (if its folder
/// exists) and which stub changes exist.
struct Seen {
    view: Option<super::TxnView>,
    stubs: [bool; 2],
}

fn see(sys: &FakeSystem) -> Seen {
    let app = open_app(sys);
    let j = Journal::new(&app, InstanceTag::fixed(TAG + 1));
    let listing = j.list().unwrap();
    assert!(listing.txns.len() <= 1, "{listing:?}");
    let view = listing
        .txns
        .into_iter()
        .next()
        .map(|l| j.load(&l.id, VerifyBackups::Hash).unwrap());
    let g = game(sys, r"D:\G");
    let stubs = [0, 1].map(|k| g.metadata(&r(&stub(k))).unwrap().is_some());
    Seen { view, stubs }
}

fn has(log: &[Record], f: impl Fn(&Record) -> bool) -> bool {
    log.iter().any(f)
}

/// The J5 properties (and S2) of what is on disk.
fn violations(s: &Seen, p: Progress) -> Vec<String> {
    let mut v = Vec::new();
    let empty = Vec::new();
    let log = s.view.as_ref().map_or(&empty, |x| &x.log);
    if let Some(view) = &s.view
        && (matches!(view.state, TxnState::Damaged(_)) || view.anomaly.is_some())
    {
        v.push(format!("damaged: {:?} {:?}", view.state, view.anomaly));
    }
    for k in 0..2u16 {
        let intent = has(log, |r| matches!(r, Record::Intent { op, .. } if *op == k));
        let reverting = has(
            log,
            |r| matches!(r, Record::RevertIntent { op, .. } if *op == k),
        );
        let exists = s.stubs[usize::from(k)];
        if exists && !intent {
            v.push(format!("change {k} durable without its intent"));
        }
        let applied = has(log, |r| matches!(r, Record::Applied { .. }));
        if applied && !reverting && !exists {
            v.push(format!("Applied durable, change {k} lost"));
        }
        let closed = has(log, |r| {
            matches!(
                r,
                Record::Closed {
                    how: Closing::Reverted | Closing::RolledBack
                }
            )
        });
        if closed && exists {
            v.push(format!("Closed durable, the revert of {k} lost"));
        }
        let reverted = has(
            log,
            |r| matches!(r, Record::RevertDone { op, .. } if *op == k),
        );
        if reverted && exists {
            v.push(format!("RevertDone durable, the revert of {k} lost"));
        }
    }
    if log.len() < p.flushed {
        v.push(format!(
            "{} records returned Ok after their flush, {} kept",
            p.flushed,
            log.len()
        ));
    }
    v
}

/// Size of a J5 run: power losses, the largest cut of `C:` and of `D:`.
#[derive(Debug, Default)]
struct Size {
    runs: usize,
    max_c: usize,
    max_d: usize,
}

/// J5 over every crash point and every pair of cuts. With `want`, stops at the first
/// violation that contains it.
fn matrix(skip: Option<Site>, want: Option<&str>) -> (Vec<String>, Size) {
    let (calls, _) = trace(skip);
    let mut found = Vec::new();
    let mut size = Size::default();
    for i in 0..=calls.len() {
        let (pc, pd) = {
            let sys = setup();
            run(&sys, &calls, i, skip);
            (sys.fake_fs().pending('C'), sys.fake_fs().pending('D'))
        };
        size.max_c = size.max_c.max(pc);
        size.max_d = size.max_d.max(pd);
        for c in 0..=pc {
            for d in 0..=pd {
                let sys = setup();
                let p = run(&sys, &calls, i, skip);
                sys.power_loss(&BTreeMap::from([
                    (Domain::Volume('C'), c),
                    (Domain::Volume('D'), d),
                ]));
                size.runs += 1;
                for x in violations(&see(&sys), p) {
                    let hit = want.is_some_and(|w| x.contains(w));
                    found.push(format!(
                        "after call {i} ({:?}), cut C {c} D {d}: {x}",
                        calls.get(i)
                    ));
                    if hit {
                        return (found, size);
                    }
                }
            }
        }
    }
    (found, size)
}

#[test]
fn j4_a_crash_after_any_call_leaves_a_valid_prefix_that_resume_closes() {
    let (calls, full) = trace(None);
    let mut states = Vec::new();
    for i in 0..calls.len() {
        let sys = setup();
        let what = format!("crash after call {i} ({:?})", calls[i]);
        run(&sys, &calls, i, None);
        sys.fake_fs().restart();
        let s = see(&sys);
        let Some(view) = s.view else {
            assert_eq!(
                s.stubs,
                [false, false],
                "{what}: a change without a transaction"
            );
            states.push(None);
            continue;
        };
        assert!(
            !matches!(view.state, TxnState::Damaged(_)) && view.anomaly.is_none(),
            "{what}: {:?} {:?}",
            view.state,
            view.anomaly
        );
        assert_eq!(
            view.log[..],
            full[..view.log.len()],
            "{what}: a prefix of the full log"
        );
        states.push(Some(view.state.clone()));
        // The lock is free; resume finishes the revert and closes.
        let app = open_app(&sys);
        let j = Journal::new(&app, InstanceTag::fixed(TAG + 1));
        let lock = j.lock().unwrap_or_else(|e| panic!("{what}: {e}"));
        if matches!(view.state, TxnState::Closed(_)) {
            continue;
        }
        if view.head.is_none() {
            // B2: the folder was created, the head not yet: nothing to resume.
            assert_eq!(view.state, TxnState::Empty, "{what}");
            continue;
        }
        let mut w = lock
            .resume(&view.id)
            .unwrap_or_else(|e| panic!("{what}: {e}"));
        let g = game(&sys, r"D:\G");
        while let Some(k) = w.next_revert() {
            w.revert_intent(k, Some(w.tmp()), None).unwrap();
            let name = r(&stub(usize::from(k)));
            let observed = match g.guard(&name) {
                Ok(guard) => {
                    guard.delete(&sha(C[usize::from(k)])).unwrap();
                    Observed::After
                }
                Err(_) => Observed::Before,
            };
            w.revert_done(k, observed, false).unwrap();
        }
        g.flush().unwrap();
        let how = if w.is_applied() {
            Closing::Reverted
        } else {
            Closing::RolledBack
        };
        w.close(how).unwrap_or_else(|e| panic!("{what}: {e}"));
        drop(lock);
        let after = see(&sys);
        assert_eq!(
            after.view.map(|v| v.state),
            Some(TxnState::Closed(how)),
            "{what}"
        );
        assert_eq!(after.stubs, [false, false], "{what}");
    }
    // The crash points reach every state.
    for want in [
        None,
        Some(TxnState::Empty),
        Some(TxnState::Open),
        Some(TxnState::Applied),
        Some(TxnState::Closed(Closing::Reverted)),
    ] {
        assert!(states.contains(&want), "{want:?} not reached");
    }
}

#[test]
fn j5_every_power_loss_cut_keeps_the_journal_ahead_of_the_changes() {
    let t = Instant::now();
    let (found, size) = matrix(None, None);
    assert!(
        found.is_empty(),
        "{} violations, first: {:?}",
        found.len(),
        found.first()
    );
    eprintln!("J5: {size:?} in {:.1} s", t.elapsed().as_secs_f64());
    // Not trivial: some crash point leaves several changes of each volume unflushed.
    assert!(size.max_c >= 3 && size.max_d >= 2, "{size:?}");
}

#[test]
fn j6_every_flush_site_is_needed() {
    let want = [
        (
            Site::Journal(FlushSite::Intent),
            "durable without its intent",
        ),
        (Site::GameBeforeApplied, "Applied durable, change"),
        (
            Site::Journal(FlushSite::Applied),
            "returned Ok after their flush",
        ),
        (
            Site::Journal(FlushSite::RevertIntent),
            "Applied durable, change",
        ),
        (Site::GameBeforeRevertDone, "durable, the revert of"),
        (
            Site::Journal(FlushSite::Close),
            "returned Ok after their flush",
        ),
    ];
    assert_eq!(want.map(|(s, _)| s), SITES);
    for (site, property) in want {
        let (found, _) = matrix(Some(site), Some(property));
        let last = found.last().map_or("", String::as_str);
        assert!(
            last.contains(property),
            "without the flush at {site:?}: {found:?}"
        );
        eprintln!("J6 {site:?}: {last}");
    }
}
