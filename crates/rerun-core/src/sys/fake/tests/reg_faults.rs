//! Faults, crashes and power loss of the registry write side (P2-9, RF1 to RF4, K-R4): the
//! fake's shared fault hub and hive logs against the one sequence of `sys::seq::reg`.

use std::collections::BTreeMap;
use std::path::Path;

use super::super::{Domain, FakeSystem, Fault, Prim, RegPrim};
use super::{hkcu, nf, nth_of, open, r};
use crate::sys::registry::{Hive, RegKey, RegValue, RegistryWrite};
use crate::sys::seq::reg::{KeyAccess, PrimHive, PrimKey};
use crate::sys::snapshot::{Scope, Snapshot, snapshot};
use crate::sys::{SysErrorKind, SysResult, System};

const GAME: &str = r"Software\Vendor\Game";

fn game() -> RegKey {
    hkcu(GAME)
}

/// The operations of the matrix, each from the same start state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    CreateKey,
    SetNew,
    SetReplace,
    DeleteValue,
    DeleteEmptyKey,
    Flush,
}

const OPS: [Op; 6] = [
    Op::CreateKey,
    Op::SetNew,
    Op::SetReplace,
    Op::DeleteValue,
    Op::DeleteEmptyKey,
    Op::Flush,
];

/// `GAME` with the value `Old = 1` and the empty subkey `Empty`, everything durable.
fn system() -> FakeSystem {
    let sys = FakeSystem::builder()
        .value(game(), "Old", RegValue::Dword(1))
        .key(game().join("Empty"))
        .key(hkcu(r"Software\Other"))
        .file(r"C:\G\t.bin", "old")
        .build()
        .unwrap();
    sys.sync_all();
    sys
}

fn run(sys: &FakeSystem, op: Op) -> SysResult<()> {
    let w: &dyn RegistryWrite = sys.fake_registry();
    let g = game();
    match op {
        Op::CreateKey => w.create_key(&g.join("New")).map(drop),
        Op::SetNew => w.set(&g, "New", None, &RegValue::Dword(2)),
        Op::SetReplace => w.set(
            &g,
            "Old",
            Some(&RegValue::Dword(1)),
            &RegValue::String("x".into()),
        ),
        Op::DeleteValue => w.delete_value(&g, "Old", &RegValue::Dword(1)),
        Op::DeleteEmptyKey => w.delete_empty_key(&g.join("Empty")),
        Op::Flush => w.flush(Hive::CurrentUser),
    }
}

/// The primitive that changes the hive (none for a flush).
fn act(op: Op) -> Option<RegPrim> {
    match op {
        Op::CreateKey => Some(RegPrim::Create),
        Op::SetNew | Op::SetReplace => Some(RegPrim::SetValue),
        Op::DeleteValue => Some(RegPrim::DeleteValue),
        Op::DeleteEmptyKey => Some(RegPrim::Delete),
        Op::Flush => None,
    }
}

fn snap(sys: &FakeSystem) -> Snapshot {
    snapshot(
        sys.registry(),
        &Scope {
            dirs: vec![],
            keys: vec![hkcu(r"Software\Vendor")],
        },
    )
    .unwrap()
}

/// The calls of a successful run, the index of its changing call, and the state after it.
fn trace(op: Op) -> (Vec<Prim>, Option<usize>, Snapshot) {
    let sys = system();
    let fx = sys.fake_fs();
    fx.record_calls(true);
    run(&sys, op).unwrap();
    fx.record_calls(false);
    let calls = fx.take_calls();
    let at = act(op).map(|a| {
        calls
            .iter()
            .position(|c| *c == Prim::Reg(a))
            .unwrap_or_else(|| panic!("{op:?}: no {a:?} in {calls:?}"))
    });
    (calls, at, snap(&sys))
}

/// RF1: a fault at any registry primitive is returned; the hive is as before if it hit at or
/// before the changing call, as after if it hit the read-back.
#[test]
fn rf1_a_fault_at_any_registry_primitive_leaves_before_or_after() {
    let before = snap(&system());
    let mut runs = 0;
    for op in OPS {
        let (calls, at, after) = trace(op);
        assert!(
            calls.iter().all(|c| matches!(c, Prim::Reg(_))),
            "{op:?}: {calls:?}"
        );
        for i in 0..calls.len() {
            let sys = system();
            sys.fake_fs()
                .fail_at(calls[i], nth_of(&calls, i), SysErrorKind::Other);
            let e = run(&sys, op).unwrap_err();
            assert!(e.target.contains("injected fault"), "{op:?} #{i}: {e}");
            let want = if at.is_some_and(|a| i > a) {
                &after
            } else {
                &before
            };
            assert_eq!(
                snap(&sys),
                *want,
                "{op:?} failed at {:?} #{i}: {:#?}",
                calls[i],
                want.diff(&snap(&sys))
            );
            runs += 1;
        }
    }
    assert!(runs > 40, "{runs} runs");
}

/// RF2: a crash after any registry primitive blocks the file system and the registry until
/// the restart; the registry's changes survive it: before or after.
#[test]
fn rf2_a_crash_after_any_registry_primitive_blocks_both_until_the_restart() {
    let before = snap(&system());
    for op in OPS {
        let (calls, at, after) = trace(op);
        for i in 0..calls.len() {
            let sys = system();
            sys.fake_fs()
                .fault(calls[i], nth_of(&calls, i), Fault::CrashAfter);
            assert!(run(&sys, op).is_err(), "{op:?} #{i}");
            assert!(sys.fake_fs().crashed());
            // Every later call of Rerun fails: registry reads and writes, the file system.
            assert_eq!(
                sys.registry().key_exists(&game()).unwrap_err().kind,
                SysErrorKind::Other
            );
            assert_eq!(run(&sys, Op::Flush).unwrap_err().kind, SysErrorKind::Other);
            assert!(sys.fs().open_dir(Path::new(r"C:\G")).is_err());
            // A fixture is never blocked.
            sys.fake_registry()
                .put_value(&hkcu(r"Software\Other"), "x", &RegValue::Dword(1))
                .unwrap();
            sys.restart();
            let want = if at.is_some_and(|a| i >= a) {
                &after
            } else {
                &before
            };
            assert_eq!(
                snap(&sys),
                *want,
                "{op:?} crashed after {:?} #{i}",
                calls[i]
            );
        }
    }
}

/// A registry handle of the crashed process is stale after the restart.
#[test]
fn a_restart_makes_registry_handles_stale() {
    let sys = system();
    let root = sys
        .fake_registry()
        .open_root(Hive::CurrentUser, KeyAccess::Query)
        .unwrap();
    assert!(root.flags().is_ok());
    sys.restart();
    assert_eq!(root.flags().unwrap_err().kind, SysErrorKind::Other);
}

/// Runs `op` on a fresh system, crashing after `calls[i]` (or completing for `i == len`).
fn run_until(op: Op, calls: &[Prim], i: usize) -> FakeSystem {
    let sys = system();
    if let Some(c) = calls.get(i) {
        sys.fake_fs().fault(*c, nth_of(calls, i), Fault::CrashAfter);
    }
    let _ = run(&sys, op);
    sys
}

/// RF3: a power loss after any registry primitive, at every cut of the hive's log, leaves
/// before or after; nothing is durable without a flush, everything after one.
#[test]
fn rf3_every_hive_cut_after_any_primitive_is_before_or_after() {
    let before = snap(&system());
    let mut runs = 0;
    for op in OPS {
        let (calls, at, after) = trace(op);
        for i in 0..=calls.len() {
            let pending = run_until(op, &calls, i).pending(Domain::Hive(Hive::CurrentUser));
            let acted = at.is_some_and(|a| i >= a);
            assert_eq!(pending, usize::from(acted), "{op:?} #{i}");
            for keep in 0..=pending {
                let sys = run_until(op, &calls, i);
                sys.power_loss(&BTreeMap::from([(Domain::Hive(Hive::CurrentUser), keep)]));
                let now = snap(&sys);
                let want = if keep == pending && acted {
                    &after
                } else {
                    &before
                };
                assert_eq!(
                    now,
                    *want,
                    "{op:?} #{i} keep {keep}: {:#?}",
                    want.diff(&now)
                );
                // The process is fresh and writes again.
                assert!(run(&sys, Op::Flush).is_ok());
                runs += 1;
            }
        }
    }
    assert!(runs > 50, "{runs} runs");
    flush_survives_every_cut().unwrap();
}

/// After a write and the flush nothing is pending, and every cut keeps the write.
fn flush_survives_every_cut() -> Result<(), String> {
    for op in OPS {
        let (_, _, after) = trace(op);
        let sys = system();
        sys.fake_registry()
            .break_flush(BROKEN.with(std::cell::Cell::get));
        run(&sys, op).map_err(|e| e.to_string())?;
        run(&sys, Op::Flush).map_err(|e| e.to_string())?;
        let pending = sys.pending(Domain::Hive(Hive::CurrentUser));
        if pending != 0 {
            return Err(format!("{op:?}: {pending} changes pending after the flush"));
        }
        sys.power_loss(&BTreeMap::new());
        if snap(&sys) != after {
            return Err(format!("{op:?}: the flushed change was lost"));
        }
    }
    Ok(())
}

thread_local! {
    static BROKEN: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// K-R4: a fake flush without effect fails RF3's flush rule.
#[test]
fn rf3_catches_a_flush_without_effect() {
    BROKEN.with(|b| b.set(true));
    let r = flush_survives_every_cut();
    BROKEN.with(|b| b.set(false));
    assert!(r.unwrap_err().contains("pending after the flush"));
}

/// RF4: two domains are ordered only by their flushes. A file on `C:` and then a registry
/// value: with the folder flushed before the `set`, no pair of cuts (C:, HKCU) keeps the value
/// without the file; without that flush one does (the model bites, like F9).
#[test]
fn rf4_a_flush_orders_the_file_before_the_registry_value() {
    let bad_pairs = |flush_first: bool| -> (usize, usize) {
        let setup = |sys: &FakeSystem| {
            let g = open(sys, r"C:\G");
            g.create_new(&r("n.bin"), &mut &b"new"[..], &nf(3, b"new"))
                .unwrap();
            if flush_first {
                g.flush().unwrap();
            }
            drop(g);
            run(sys, Op::SetNew).unwrap();
        };
        let probe = system();
        setup(&probe);
        let (pc, ph) = (
            probe.pending(Domain::Volume('C')),
            probe.pending(Domain::Hive(Hive::CurrentUser)),
        );
        let mut bad = 0;
        let mut pairs = 0;
        for c in 0..=pc {
            for h in 0..=ph {
                let sys = system();
                setup(&sys);
                sys.power_loss(&BTreeMap::from([
                    (Domain::Volume('C'), c),
                    (Domain::Hive(Hive::CurrentUser), h),
                ]));
                let value = sys.registry().get(&game(), "New").unwrap().is_some();
                let file = open(&sys, r"C:\G").metadata(&r("n.bin")).unwrap().is_some();
                if value && !file {
                    bad += 1;
                }
                pairs += 1;
            }
        }
        (bad, pairs)
    };
    let (bad, pairs) = bad_pairs(true);
    assert_eq!(
        bad, 0,
        "flushed first: {bad} of {pairs} cut pairs keep the value alone"
    );
    let (bad, pairs) = bad_pairs(false);
    assert!(
        bad > 0,
        "without the flush the model must allow the value without the file ({pairs} pairs)"
    );
}

/// The registry hook runs before each primitive (another program) and its calls are not
/// counted: a link planted at the next segment during the walk is caught, nothing written.
#[test]
fn a_link_planted_during_the_walk_is_caught() {
    use crate::sys::contract::RegFixture;
    let sys = system();
    let reg = sys.fake_registry();
    let mut planted = false;
    reg.on_step(move |r, call| {
        if call == RegPrim::Open && !planted {
            planted = true;
            RegFixture::delete_value(r, &game(), "Old").unwrap();
            r.remove_key(&game().join("Empty")).unwrap();
            r.remove_key(&game()).unwrap();
            RegFixture::link(r, &game(), &hkcu(r"Software\Other")).unwrap();
        }
    });
    let e = RegistryWrite::set(reg, &game(), "New", None, &RegValue::Dword(2)).unwrap_err();
    reg.clear_on_step();
    assert_eq!(e.kind, SysErrorKind::ReparsePoint, "{e}");
    assert_eq!(sys.registry().values(&hkcu(r"Software\Other")).unwrap(), []);
}
