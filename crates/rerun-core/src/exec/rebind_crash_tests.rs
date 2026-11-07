//! Rebind under failures, crashes and power losses (P2-14a; ADR 0020 amendment P2-14, the
//! senior-dev matrix condition):
//! - RB-C1 a failure and a crash after every call (file system and registry) of
//!   `revert_rebound`, before, in and after its record: refused without a record, or left open
//!   and bound; after a restart the recovery (`revert`, and when the rebind did not reach the
//!   journal, `rebind_check` and `revert_rebound` again) ends with the bound folder identical
//!   by content to the folder before the apply and `HKCU\Software` identical, never `Damaged`,
//!   never `Foreign`.
//! - RB-C2 a power loss after every call and after the end at every cut of `C:` (the journal),
//!   the volume of the bound folder (`E:` for a moved library, on another volume than the old
//!   one; `D:` for a reinstall) and `HKCU`: before the recovery never damaged; a durable change
//!   in the bound folder or the registry has a durable `Rebind`; a `Rebind` whose call
//!   returned `Ok` survives every cut; a durable `Closed` has the state of the end; then the
//!   recovery as in RB-C1.
//! - J6 for the rebind: without `FlushSite::Rebind`, "Ok rebind lost" fails.
//! - RB-C3 a halt after a rebind goes on once the folder is writable again; a second rebind
//!   after a revert intent of a file op of the root is refused (`RevertPending`, E-R3).
//!
//! Kinds (the existing file, INI and layer matrices once with a bound root): `Moved` (a
//! library moved to another volume, rebound before any revert: file ops, the layer, the
//! registry value), `Halted` (the same after a revert that halted at the file ops, its
//! registry ops reverted), `Reinstall` (a reinstall at the same path) and `Ini` (`Moved` with an
//! INI file the game rewrote there).

use std::collections::BTreeMap;
use std::path::Path;
use std::time::Instant;

use super::RebindTo;
use super::rebind_tests::{
    GAME_E, LIB_E, REF, Rb, applied, content_diff, copy_tree, keys, move_tree, remove_tree,
};
use super::tests::{read_abs, sys_put};
use crate::journal::{Closing, FlushSite, InstanceTag, Journal, Observed, TxnState};
use crate::prim::ini_tests::{INI, INI_TEXT};
use crate::prim::tests::{STEAM_GAME, STEAM_LIB, app};
use crate::sys::SysErrorKind;
use crate::sys::fake::{Domain, Fault, Prim};
use crate::sys::registry::Hive;
use crate::sys::snapshot::Snapshot;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Moved,
    Halted,
    Reinstall,
    Ini,
}

/// The expected end of an `Ini` case: the folder before the apply with the key the game
/// changed.
const REF_INI: &str = r"D:\RefIni\G";

/// One system of a kind, everything durable, right before `revert_rebound`.
struct Case {
    rb: Rb,
    /// The binding the preview showed.
    to: RebindTo,
    /// The library to bind to.
    lib: &'static str,
    /// The bound folder.
    game: &'static str,
    /// The volume of the bound folder.
    drive: char,
    /// The expected end of the bound folder (by content).
    want: &'static str,
    /// The bound folder right before the rebind (by content: a change since needs the record).
    start: Snapshot,
    /// `HKCU\Software` right before the rebind.
    start_keys: Snapshot,
}

fn setup(k: Kind) -> Case {
    let rb = applied(k == Kind::Ini);
    let sys = &rb.env.sys;
    let (lib, game, drive) = match k {
        Kind::Reinstall => (STEAM_LIB, STEAM_GAME, 'D'),
        _ => (LIB_E, GAME_E, 'E'),
    };
    match k {
        Kind::Moved | Kind::Ini => move_tree(sys, STEAM_LIB, LIB_E),
        Kind::Halted => {
            move_tree(sys, STEAM_LIB, LIB_E);
            let r = rb.env.revert(&rb.t);
            assert!(
                r.as_ref().is_ok_and(|r| r.halted.is_some()),
                "{k:?}: halt {r:?}"
            );
        }
        Kind::Reinstall => {
            remove_tree(sys, STEAM_GAME);
            copy_tree(sys, REF, STEAM_GAME);
        }
    }
    let want = if k == Kind::Ini {
        let ini = format!(r"{GAME_E}\{INI}");
        let now = String::from_utf8(read_abs(sys, &ini)).unwrap();
        sys.fake_fs().remove_abs(Path::new(&ini)).unwrap();
        sys_put(
            sys,
            &ini,
            now.replace("Height = 720", "Height = 1080").as_bytes(),
        );
        copy_tree(sys, REF, REF_INI);
        let r = format!(r"{REF_INI}\{INI}");
        sys.fake_fs().remove_abs(Path::new(&r)).unwrap();
        let old = String::from_utf8(INI_TEXT.to_vec()).unwrap();
        sys_put(
            sys,
            &r,
            old.replace("Height = 720", "Height = 1080").as_bytes(),
        );
        REF_INI
    } else {
        REF
    };
    sys.sync_all();
    let to = rb
        .env
        .rebind_check(&rb.t, lib)
        .unwrap_or_else(|e| panic!("{k:?}: {e:?}"))
        .to;
    let start = super::tests::snap_at(sys, game);
    let start_keys = keys(sys);
    Case {
        rb,
        to,
        lib,
        game,
        drive,
        want,
        start,
        start_keys,
    }
}

#[derive(Debug, Clone, Copy)]
struct At {
    call: Prim,
    nth: usize,
    fault: Fault,
    /// The index of the call in the trace.
    i: usize,
}

/// The calls of a `revert_rebound` of `k`, and the index of the call after which the rebind's
/// call has returned: the rename of its record (the checks write nothing, so it is the run's
/// first), and the flush after it unless J6 switched that off (`skipped`).
fn trace(k: Kind, skipped: bool) -> (Vec<Prim>, usize) {
    let c = setup(k);
    let fx = c.rb.env.sys.fake_fs();
    let r =
        c.rb.env
            .revert_rebound_armed(&c.rb.t, &c.to, |f| f.record_calls(true));
    fx.record_calls(false);
    assert_eq!(
        r.as_ref().ok().and_then(|r| r.closed),
        Some(Closing::Reverted),
        "{k:?}: {r:?}"
    );
    let calls = fx.take_calls();
    let rename = calls
        .iter()
        .position(|c| *c == Prim::Rename)
        .unwrap_or_else(|| panic!("{k:?}: no record"));
    let done = if skipped {
        rename
    } else {
        rename
            + calls[rename..]
                .iter()
                .position(|c| *c == Prim::FlushDir)
                .unwrap_or_else(|| panic!("{k:?}: no flush"))
    };
    (calls, done)
}

/// A call that changes persistent state (a file, folder, attribute, content, rename, delete,
/// flush, or a registry key or value). Every other call only reads or opens a handle that a
/// restart closes, and arms no pending delete.
fn changes_state(p: Prim) -> bool {
    use crate::sys::fake::RegPrim as R;
    match p {
        Prim::CreateTmp
        | Prim::CreateDir
        | Prim::Rename
        | Prim::FlushDir
        | Prim::Write
        | Prim::SetAttrs
        | Prim::FlushFile
        | Prim::PosixDelete
        | Prim::Reg(R::Create | R::SetValue | R::DeleteValue | R::Delete | R::Flush) => true,
        Prim::Reg(_) => false,
        // Read side: Support, VolumeName, OpenGuard, Lookup, OpenLock, OpenDirDelete (the
        // delete comes with `PosixDelete`), State, Name, ReadAt, Users, ReadSide.
        _ => false,
    }
}

/// The interruption points: after each call of the run (`every`), or (`!every`) after each call
/// that changes persistent state and after the last read-only call before the record, and the
/// end. The reduction is exact for a crash and a power loss (S5): after a read-only call the
/// persistent state, the pending changes of every domain and so every cut are those after the
/// last call that changed state before it, so a crash or power loss there is the same case. A
/// failure differs per call (another error path) and keeps every call.
fn points(k: Kind, fault: Fault, skipped: bool, every: bool) -> (Vec<Option<At>>, usize) {
    let (calls, flush) = trace(k, skipped);
    let first_write = calls.iter().position(|c| changes_state(*c));
    let mut v: Vec<Option<At>> = calls
        .iter()
        .enumerate()
        .filter(|(i, call)| every || changes_state(**call) || first_write == Some(i + 1))
        .map(|(i, call)| {
            Some(At {
                call: *call,
                nth: calls[..=i].iter().filter(|c| *c == call).count(),
                fault,
                i,
            })
        })
        .collect();
    v.push(None);
    (v, flush)
}

/// Runs `revert_rebound` with the fault of `at`; whether it returned a closed transaction.
fn run(c: &Case, at: Option<At>) -> bool {
    let r = c.rb.env.revert_rebound_armed(&c.rb.t, &c.to, |fx| {
        if let Some(a) = at {
            fx.fault(a.call, a.nth, a.fault);
        }
    });
    if at.is_none() {
        assert!(r.as_ref().is_ok_and(|r| r.closed.is_some()), "{r:?}");
    }
    r.is_ok_and(|r| r.closed.is_some())
}

/// The rebinds of `t` on disk.
fn rebinds(c: &Case) -> usize {
    let a = app(&c.rb.env.sys);
    Journal::new(&a, InstanceTag::fixed(5))
        .load(&c.rb.t, crate::journal::VerifyBackups::Length)
        .map_or(0, |v| v.rebinds.len())
}

/// The end: the bound folder by content as `want`, `HKCU\Software` as before the apply.
fn at_end(c: &Case) -> Vec<String> {
    let mut v = Vec::new();
    let d = content_diff(&c.rb.env.sys, c.want, c.game);
    if !d.is_empty() {
        v.push(format!("the folder: {d:?}"));
    }
    let now = keys(&c.rb.env.sys);
    if now != c.rb.keys {
        v.push(format!("the registry: {:?}", c.rb.keys.diff(&now)));
    }
    v
}

/// The recovery: `revert`; when the rebind did not reach the journal (the folder bound before
/// does not open), a new `rebind_check` and `revert_rebound`. It must close, never meet
/// `Foreign`, and end as expected.
fn recover(c: &Case) -> Vec<String> {
    let env = &c.rb.env;
    let t = &c.rb.t;
    let mut v = Vec::new();
    match env.state(t) {
        Some(TxnState::Closed(_)) => {}
        Some(TxnState::Applied) => {
            let r = env.revert(t);
            let foreign =
                |r: &super::RevertReport| r.ops.iter().any(|o| o.observed == Observed::Foreign);
            match &r {
                Ok(r) if r.closed.is_some() => {}
                Ok(r) if foreign(r) => v.push(format!("Foreign: {r:?}")),
                // The rebind lost: halted (gone) or refused (another folder).
                Ok(_) | Err(super::ExecError::Refused(_)) => match env.rebind_check(t, c.lib) {
                    Ok(p) => match env.revert_rebound(t, &p.to) {
                        Ok(r) if r.closed.is_some() => {}
                        r => v.push(format!("rebound again: {r:?}")),
                    },
                    Err(e) => v.push(format!("rebind_check again: {e:?} after {r:?}")),
                },
                Err(e) => v.push(format!("recovery failed: {e:?}")),
            }
        }
        other => v.push(format!("damaged: {t} {other:?}")),
    }
    v.extend(at_end(c));
    v
}

/// RB-C1 for `k`: `fault` after every call (`every`) or every call that changes state.
fn rb_c1(k: Kind, faults: &[(Fault, bool)]) {
    let t0 = Instant::now();
    let mut runs = 0;
    let mut outcomes: BTreeMap<&str, usize> = BTreeMap::new();
    for (fault, every) in faults {
        let (pts, flush) = points(k, *fault, false, *every);
        for at in pts.into_iter().flatten() {
            let c = setup(k);
            let n = rebinds(&c);
            let r = c.rb.env.revert_rebound_armed(&c.rb.t, &c.to, |fx| {
                fx.fault(at.call, at.nth, at.fault);
            });
            let fx = c.rb.env.sys.fake_fs();
            fx.clear_faults();
            if fx.crashed() {
                fx.restart();
            }
            // A refusal never has its record on disk; once the rebind's call returned, its
            // record is on disk.
            let recorded = rebinds(&c) > n;
            let what = match &r {
                Ok(r) if r.closed.is_some() => "closed",
                Err(super::ExecError::Refused(_)) => {
                    assert!(!recorded, "{k:?} {at:?}: refused after its record: {r:?}");
                    "refused"
                }
                _ if recorded => "open and bound",
                _ => "failed before the record",
            };
            if at.i > flush {
                assert!(recorded, "{k:?} {at:?}: the rebind is lost after Ok");
            }
            *outcomes.entry(what).or_default() += 1;
            let v = recover(&c);
            assert!(v.is_empty(), "{k:?} {at:?} ({what}): {v:#?}");
            runs += 1;
        }
    }
    eprintln!(
        "RB-C1 {k:?}: {runs} runs in {:.1} s: {outcomes:?}",
        t0.elapsed().as_secs_f64()
    );
    for want in ["refused", "open and bound"] {
        assert!(
            outcomes.contains_key(want),
            "{k:?}: {want} never reached: {outcomes:?}"
        );
    }
}

/// `Moved`: a failure at every call (every error path of the checks, the record and the revert
/// loop on a bound root) and a crash after every call that changes state.
#[test]
fn rb_c1_moved_a_failure_or_a_crash_at_any_call_recovers() {
    rb_c1(
        Kind::Moved,
        &[
            (Fault::Fail(SysErrorKind::Other), true),
            (Fault::CrashAfter, false),
        ],
    );
}

/// The other kinds: a failure and a crash after every call that changes state.
#[test]
fn rb_c1_halted_reinstall_ini_a_failure_or_a_crash_recovers() {
    for k in [Kind::Halted, Kind::Reinstall, Kind::Ini] {
        rb_c1(
            k,
            &[
                (Fault::Fail(SysErrorKind::Other), false),
                (Fault::CrashAfter, false),
            ],
        );
    }
}

/// The RB-C2 properties of what is on disk and in the hive after a power loss, before the
/// recovery; then the recovery. `ok_rebind`: the rebind's call had returned `Ok`; `closed`: the
/// run returned a closed transaction.
fn violations(c: &Case, ok_rebind: bool, closed: bool) -> Vec<String> {
    let env = &c.rb.env;
    let mut v = Vec::new();
    let state = env.state(&c.rb.t);
    if !matches!(
        state,
        Some(TxnState::Applied | TxnState::Closed(Closing::Reverted))
    ) {
        v.push(format!("damaged or lost: {state:?}"));
    }
    let bound = rebinds(c) > 0;
    let changed = super::tests::snap_at(&env.sys, c.game)
        .diff(&c.start)
        .iter()
        .any(|l| !l.starts_with("~ root "));
    if changed && !bound {
        v.push("a change in the bound folder durable without its rebind".to_owned());
    }
    if keys(&env.sys) != c.start_keys && !bound {
        v.push("a registry change durable without its rebind".to_owned());
    }
    if ok_rebind && !bound {
        v.push("Ok rebind lost".to_owned());
    }
    if closed && !matches!(state, Some(TxnState::Closed(_))) {
        v.push(format!(
            "Ok lost: the rebind returned Closed, now {state:?}"
        ));
    }
    if matches!(state, Some(TxnState::Closed(Closing::Reverted))) {
        let e = at_end(c);
        if !e.is_empty() {
            v.push(format!("Closed durable, revert lost: {e:?}"));
        }
    }
    if v.is_empty() {
        v.extend(recover(c));
    }
    v
}

/// Size of an RB-C2 run.
#[derive(Debug, Default)]
struct Size {
    runs: usize,
    max_c: usize,
    max_g: usize,
    max_h: usize,
}

/// RB-C2 for `k`: every point, every cut of `C:`, the bound folder's volume and `HKCU`. With
/// `want`, stops at the first violation containing it.
fn matrix(k: Kind, skip: Option<FlushSite>, want: Option<&str>) -> (Vec<String>, Size) {
    crate::journal::knob::skip(skip);
    let (pts, flush) = points(k, Fault::CrashAfter, skip.is_some(), false);
    crate::journal::knob::skip(None);
    let mut found = Vec::new();
    let mut size = Size::default();
    for at in pts {
        let ok_rebind = at.is_none_or(|a| a.i > flush);
        let dom = |c: &Case| {
            [
                Domain::Volume('C'),
                Domain::Volume(c.drive),
                Domain::Hive(Hive::CurrentUser),
            ]
        };
        let (pc, pg, ph) = {
            let c = setup(k);
            crate::journal::knob::skip(skip);
            run(&c, at);
            crate::journal::knob::skip(None);
            let s = &c.rb.env.sys;
            let [dc, dg, dh] = dom(&c);
            (s.pending(dc), s.pending(dg), s.pending(dh))
        };
        size.max_c = size.max_c.max(pc);
        size.max_g = size.max_g.max(pg);
        size.max_h = size.max_h.max(ph);
        for cut_c in 0..=pc {
            for g in 0..=pg {
                for h in 0..=ph {
                    let c = setup(k);
                    crate::journal::knob::skip(skip);
                    let closed = run(&c, at);
                    crate::journal::knob::skip(None);
                    let [dc, dg, dh] = dom(&c);
                    c.rb.env
                        .sys
                        .power_loss(&BTreeMap::from([(dc, cut_c), (dg, g), (dh, h)]));
                    size.runs += 1;
                    for x in violations(&c, ok_rebind, closed) {
                        let hit = want.is_some_and(|w| x.contains(w));
                        found.push(format!(
                            "{k:?} after {at:?}, cut C {cut_c} {} {g} HKCU {h}: {x}",
                            c.drive
                        ));
                        if hit {
                            return (found, size);
                        }
                    }
                }
            }
        }
    }
    (found, size)
}

fn rb_c2(k: Kind) {
    let t = Instant::now();
    let (found, size) = matrix(k, None, None);
    eprintln!(
        "RB-C2 {k:?}: {size:?} in {:.1} s",
        t.elapsed().as_secs_f64()
    );
    assert!(
        found.is_empty(),
        "{k:?}: {} violations: {:#?}",
        found.len(),
        found.iter().take(5).collect::<Vec<_>>()
    );
    // Not trivial: changes of the bound folder or the hive are pending at some point (a
    // reinstall changes nothing in the folder: every file op is `Before` there).
    assert!(
        size.max_c >= 1 && size.max_g + size.max_h >= 1,
        "{k:?}: {size:?}"
    );
}

#[test]
fn rb_c2_moved_every_power_loss_cut_recovers() {
    rb_c2(Kind::Moved);
}

#[test]
fn rb_c2_halted_every_power_loss_cut_recovers() {
    rb_c2(Kind::Halted);
}

#[test]
fn rb_c2_reinstall_every_power_loss_cut_recovers() {
    rb_c2(Kind::Reinstall);
}

#[test]
fn rb_c2_ini_every_power_loss_cut_recovers() {
    rb_c2(Kind::Ini);
}

/// J6 for the rebind (the ninth flush site): without its flush, a rebind whose call returned
/// `Ok` can be lost.
#[test]
fn j6_the_rebind_flush_is_needed() {
    let (found, _) = matrix(Kind::Moved, Some(FlushSite::Rebind), Some("Ok rebind lost"));
    let last = found.last().map_or("", String::as_str);
    assert!(last.contains("Ok rebind lost"), "{found:#?}");
    eprintln!("J6 Rebind: {last}");
}

/// RB-C3: a halt after a rebind goes on once the folder is writable again; a second rebind is
/// refused once a file op of the root has a revert intent (E-R3).
#[test]
fn rb_c3_a_halt_after_a_rebind_resumes_and_a_second_rebind_needs_no_revert_of_the_root() {
    let c = setup(Kind::Moved);
    let env = &c.rb.env;
    let t = &c.rb.t;
    // The record, then a crash; the folder not writable now: the revert halts after the
    // registry ops, open and bound.
    let r = env.revert_rebound_armed(t, &c.to, |fx| {
        fx.fault(Prim::FlushDir, 1, Fault::CrashAfter);
    });
    assert!(r.is_err(), "{r:?}");
    env.sys.fake_fs().restart();
    let fx = env.sys.fake_fs();
    fx.set_user_writable(Path::new(GAME_E), false).unwrap();
    let r = env.revert(t).unwrap();
    assert!(r.closed.is_none() && r.halted.is_some(), "{r:?}");
    assert_eq!(rebinds(&c), 1);
    fx.set_user_writable(Path::new(GAME_E), true).unwrap();
    let r = env.revert(t).unwrap();
    assert_eq!(r.closed, Some(Closing::Reverted), "{r:?}");
    assert_eq!(at_end(&c), Vec::<String>::new());

    // A revert that reverted a file op of the bound root, then failed; the library moved again:
    // a second rebind is refused.
    let c = setup(Kind::Moved);
    let env = &c.rb.env;
    let t = &c.rb.t;
    let r = env.revert_rebound_armed(t, &c.to, |fx| {
        // The second delete of a file of the root (the first one is reverted).
        fx.fail_at(Prim::PosixDelete, 2, SysErrorKind::Other);
    });
    assert!(r.is_err(), "{r:?}");
    env.sys.fake_fs().clear_faults();
    move_tree(&env.sys, LIB_E, r"F:\SteamLibrary");
    let r = env.rebind_check(t, r"F:\SteamLibrary");
    assert!(
        matches!(
            &r,
            Err(super::Refusal::Rebind(
                super::RebindRefusal::RevertPending { .. }
            ))
        ),
        "{r:?}"
    );
    // Only forget closes it now (the folder bound is gone).
    env.forget(t).unwrap();
    assert!(matches!(
        env.state(t),
        Some(TxnState::Closed(Closing::Forgotten))
    ));
}
