//! `exec` with `GpuPref` against the fake (P4-11): R-G1 the round trip without a value and
//! without the `DirectX` key, R-G2 foreign pairs kept byte for byte, R-G3 `GpuPreference=0` in
//! the middle changed in place, R-G4 every row of the observation and the drift with exact
//! strings, X15/S3 (the user chooses High performance after the apply: the revert sets the old
//! value back), shared keys over two executables, D4 for the executable. Crashes and power
//! losses: `gpu_pref_crash_tests.rs`. Every value is of the documented form; the SB-G1 dump is
//! pending.

use std::path::Path;

use super::reg_tests::{plan_all, reg_base, snap_all};
use super::tests::{Env, finish, game};
use super::{ApplyError, ExecError, Outcome, Refusal};
use crate::journal::{Closing, Observed, TxnState};
use crate::policy::registry::GpuPref;
use crate::prim::layer_tests::exe_name;
use crate::prim::reg_tests::hkcu;
use crate::prim::tests::rel;
use crate::prim::{GpuPreferenceSpec, Step};
use crate::sys::System;
use crate::sys::fake::{FakeSystem, FakeSystemBuilder};
use crate::sys::registry::RegValue;

/// The key of the graphics preferences.
pub(crate) const PREFS_KEY: &str = r"Software\Microsoft\DirectX\UserGpuPreferences";
/// The key Rerun may create first.
pub(crate) const DIRECTX: &str = r"Software\Microsoft\DirectX";

/// [`reg_base`] with `Software\Microsoft` (the anchor) and a second executable `bin\g.exe`.
pub(crate) fn pref_base() -> FakeSystemBuilder {
    reg_base()
        .key(hkcu(r"Software\Microsoft"))
        .file(game(r"bin\g.exe"), b"MZ".to_vec())
}

/// [`pref_base`] with the value of `game.exe` set to `v` (the keys exist then).
pub(crate) fn pref_base_with(v: &str) -> FakeSystemBuilder {
    pref_base().value(hkcu(PREFS_KEY), &exe_name("game.exe"), sz(v))
}

/// The value of `exe`.
pub(crate) fn pref_value_of(sys: &FakeSystem, exe: &str) -> Option<RegValue> {
    sys.registry()
        .get(&hkcu(PREFS_KEY), &exe_name(exe))
        .ok()
        .flatten()
}

/// The value of `game.exe`.
pub(crate) fn pref_value(sys: &FakeSystem) -> Option<RegValue> {
    pref_value_of(sys, "game.exe")
}

pub(crate) fn put_pref(sys: &FakeSystem, v: &RegValue) {
    sys.fake_registry()
        .put_value(&hkcu(PREFS_KEY), &exe_name("game.exe"), v)
        .unwrap();
}

pub(crate) fn sz(s: &str) -> RegValue {
    RegValue::String(s.to_owned())
}

/// The step: High performance for `exe`.
pub(crate) fn pref_step(exe: &str) -> Step {
    Step::GpuPreference(GpuPreferenceSpec {
        exe: rel(exe),
        preference: GpuPref::HighPerformance,
    })
}

fn key_exists(sys: &FakeSystem, k: &str) -> bool {
    sys.registry().key_exists(&hkcu(k)).unwrap_or(false)
}

/// R-G1 to R-G3: apply → the value exactly → verify all `After` → revert closes with every op
/// `After` → the snapshot of the game folder and `HKCU\Software` identical → verify all
/// `Before`.
#[test]
fn r_g1_to_g3_round_trips_restore_the_bytes() {
    for (what, old, want) in [
        ("R-G1 no value, no DirectX key", None, "GpuPreference=2;"),
        (
            "R-G2 foreign pairs",
            Some("AutoHDREnable=1;SwapEffectUpgradeEnable=1;"),
            "AutoHDREnable=1;SwapEffectUpgradeEnable=1;GpuPreference=2;",
        ),
        (
            "R-G3 =0 in the middle",
            Some("AutoHDREnable=1;GpuPreference=0;SwapEffectUpgradeEnable=1;"),
            "AutoHDREnable=1;GpuPreference=2;SwapEffectUpgradeEnable=1;",
        ),
    ] {
        let b = old.map_or_else(pref_base, pref_base_with);
        let env = Env::new(finish(b));
        let before = snap_all(&env);
        let h = plan_all(&env, &[pref_step("game.exe")]);
        let t = env.applied(&h);
        assert_eq!(pref_value(&env.sys), Some(sz(want)), "{what}");
        if old.is_none() {
            assert!(key_exists(&env.sys, PREFS_KEY), "{what}");
        }
        let v = env.verify(&t);
        assert!(
            v.iter().all(|(_, o)| *o == Observed::After),
            "{what}: {v:?}"
        );
        let r = env.revert(&t).unwrap();
        assert_eq!(r.closed, Some(Closing::Reverted), "{what}");
        assert_eq!(before, snap_all(&env), "{what}");
        if old.is_none() {
            assert!(!key_exists(&env.sys, DIRECTX), "{what}: DirectX left");
        }
        let v = env.verify(&t);
        assert!(
            v.iter().all(|(_, o)| *o == Observed::Before),
            "{what}: {v:?}"
        );
    }
}

/// R-G4: every row of the observation (verify of the value op), and what the revert leaves.
#[test]
fn r_g4_every_row_and_the_drift() {
    type Change = fn(&FakeSystem);
    /// What, old, change, observed, the value after the revert, closes.
    type Case = (
        &'static str,
        Option<&'static str>,
        Change,
        Observed,
        Option<&'static str>,
        bool,
    );
    let cases: [Case; 9] = [
        (
            "Windows adds a pair",
            None,
            |s| put_pref(s, &sz("AutoHDREnable=0;GpuPreference=2;")),
            Observed::Drifted,
            Some("AutoHDREnable=0;"),
            true,
        ),
        (
            "Windows adds a pair, old =0",
            Some("GpuPreference=0;"),
            |s| put_pref(s, &sz("GpuPreference=2;AutoHDREnable=0;")),
            Observed::Drifted,
            Some("GpuPreference=0;AutoHDREnable=0;"),
            true,
        ),
        (
            "the user chose Power saving (D10)",
            Some("AutoHDREnable=1;"),
            |s| put_pref(s, &sz("AutoHDREnable=1;GpuPreference=1;")),
            Observed::Drifted,
            Some("AutoHDREnable=1;GpuPreference=1;"),
            true,
        ),
        (
            "Settings removed the value",
            Some("AutoHDREnable=1;"),
            |s| {
                s.fake_registry()
                    .remove_value(&hkcu(PREFS_KEY), &exe_name("game.exe"))
                    .unwrap();
            },
            Observed::Drifted,
            None,
            true,
        ),
        (
            "missing, no old value",
            None,
            |s| {
                s.fake_registry()
                    .remove_value(&hkcu(PREFS_KEY), &exe_name("game.exe"))
                    .unwrap();
            },
            Observed::Before,
            None,
            true,
        ),
        (
            "back to the old value",
            Some("AutoHDREnable=1;"),
            |s| put_pref(s, &sz("AutoHDREnable=1;")),
            Observed::Before,
            Some("AutoHDREnable=1;"),
            true,
        ),
        (
            "another type",
            None,
            |s| put_pref(s, &RegValue::ExpandString("GpuPreference=2;".into())),
            Observed::Foreign,
            Some("(kept)"),
            false,
        ),
        (
            "the pair twice",
            None,
            |s| put_pref(s, &sz("GpuPreference=2;GpuPreference=2;")),
            Observed::Foreign,
            Some("GpuPreference=2;GpuPreference=2;"),
            false,
        ),
        (
            "outside the grammar",
            None,
            |s| put_pref(s, &sz("GpuPreference=2; AutoHDREnable=1;")),
            Observed::Foreign,
            Some("GpuPreference=2; AutoHDREnable=1;"),
            false,
        ),
    ];
    for (what, old, change, observed, after, closes) in cases {
        let b = old.map_or_else(pref_base, pref_base_with);
        let env = Env::new(finish(b));
        let t = env.applied(&plan_all(&env, &[pref_step("game.exe")]));
        change(&env.sys);
        let changed = pref_value(&env.sys);
        let v = env.verify(&t);
        assert_eq!(v.last().map(|(_, o)| *o), Some(observed), "{what}: {v:?}");
        let r = env.revert(&t);
        assert_eq!(
            r.as_ref()
                .is_ok_and(|r| r.closed == Some(Closing::Reverted)),
            closes,
            "{what}: {r:?}"
        );
        let want = match after {
            Some("(kept)") => changed,
            a => a.map(sz),
        };
        assert_eq!(pref_value(&env.sys), want, "{what}");
        if !closes {
            assert_eq!(env.state(&t), Some(TxnState::Applied), "{what}");
        }
    }
}

/// X15 (S3): the user chooses High performance in Settings after the apply. The value is the
/// same bytes as Rerun's: `After`, and the revert sets the old value back (here: deletes it).
/// Rerun cannot tell the two apart; the preview note says so.
#[test]
fn x15_the_user_s_own_high_performance_is_reverted_too() {
    let env = Env::new(finish(pref_base_with("AutoHDREnable=1;")));
    let t = env.applied(&plan_all(&env, &[pref_step("game.exe")]));
    // Settings writes the same value again (its own pair order is the same here).
    put_pref(&env.sys, &sz("AutoHDREnable=1;GpuPreference=2;"));
    let v = env.verify(&t);
    assert_eq!(v.last().map(|(_, o)| *o), Some(Observed::After), "{v:?}");
    assert_eq!(env.revert(&t).unwrap().closed, Some(Closing::Reverted));
    assert_eq!(pref_value(&env.sys), Some(sz("AutoHDREnable=1;")));
    assert!(
        crate::plan::GPU_PREF_NOTE.contains("cannot tell it from its own"),
        "the note names it"
    );
}

/// Shared keys (R-L7 analogue): two transactions on two executables share the created keys;
/// reverted newest first both keys go, in the other order the first leaves them (another value
/// in them) and the second deletes them.
#[test]
fn r_g_shared_keys_over_two_executables() {
    for newest_first in [true, false] {
        let env = Env::new(finish(pref_base()));
        let before = snap_all(&env);
        let t1 = env.applied(&plan_all(&env, &[pref_step("game.exe")]));
        let t2 = env.applied(&plan_all(&env, &[pref_step(r"bin\g.exe")]));
        assert_eq!(
            pref_value_of(&env.sys, r"bin\g.exe"),
            Some(sz("GpuPreference=2;"))
        );
        let (a, b) = if newest_first { (t2, t1) } else { (t1, t2) };
        assert_eq!(env.revert(&a).unwrap().closed, Some(Closing::Reverted));
        if !newest_first {
            // t1 created the keys; t2's value is still there: the keys stay.
            assert!(key_exists(&env.sys, PREFS_KEY));
        }
        assert_eq!(env.revert(&b).unwrap().closed, Some(Closing::Reverted));
        if newest_first {
            assert_eq!(before, snap_all(&env));
        } else {
            // The keys t1 created were left by its revert; t2 created none: they stay, empty
            // (the class of LAYERS_NOTE: another order can leave them).
            assert!(
                pref_value(&env.sys).is_none() && pref_value_of(&env.sys, r"bin\g.exe").is_none()
            );
        }
    }
}

/// D4: the executable of a graphics preference is asked too, also when it is not the main one,
/// at the apply and at the revert.
#[test]
fn r_g_d4_the_executable_must_be_closed() {
    let env = Env::new(finish(pref_base()));
    let h = plan_all(&env, &[pref_step(r"bin\g.exe")]);
    let held = env
        .sys
        .fake_fs()
        .map_image_as(4242, Path::new(&game(r"bin\g.exe")))
        .unwrap();
    let r = env.apply(&h);
    assert!(
        matches!(&r, Err(ApplyError::Refused(Refusal::Busy(s))) if s.as_str().ends_with(r"bin\g.exe")),
        "{r:?}"
    );
    drop(held);
    let t = env.applied(&h);
    let _held = env
        .sys
        .fake_fs()
        .map_image_as(4242, Path::new(&game(r"bin\g.exe")))
        .unwrap();
    assert!(matches!(
        env.revert(&t),
        Err(ExecError::Refused(Refusal::Busy(_)))
    ));
    assert_eq!(env.state(&t), Some(TxnState::Applied));
}

/// The value changed between the plan and the apply: refused before anything is written.
#[test]
fn r_g_a_change_after_the_plan_is_a_mismatch() {
    let env = Env::new(finish(pref_base_with("AutoHDREnable=1;")));
    let h = plan_all(&env, &[pref_step("game.exe")]);
    put_pref(&env.sys, &sz("AutoHDREnable=0;"));
    let before = snap_all(&env);
    assert!(matches!(
        env.apply(&h),
        Err(ApplyError::Refused(Refusal::Mismatch { .. }))
    ));
    assert_eq!(before, snap_all(&env));
    put_pref(&env.sys, &sz("AutoHDREnable=1;"));
    assert!(matches!(env.apply(&h), Ok(Outcome::Applied(_))));
}

/// The records of the transaction directory `dir`.
fn records(env: &Env, t: &crate::journal::TxnId) -> usize {
    crate::journal::tests::rewrite(env.sys.fake_fs(), &env.txn_dir(t), None, |_| {}).into()
}

/// R-G6, tampering (review follow-up, `records_fit`): an `Intent.before` other than the planned
/// old value, a `.bin` for it, none although there is an old value: `Blocked` for verify and
/// revert, nothing written.
#[test]
fn r_g6_records_that_do_not_fit_a_gpu_pref_are_blocked() {
    use crate::journal::tests::rewrite;
    use crate::journal::{Before, Digest};
    type Tamper = (&'static str, fn(&Env, &str));
    let tampers: [Tamper; 3] = [
        ("before other than old", |env, dir| {
            rewrite(env.sys.fake_fs(), dir, None, |e| {
                e.intent_inline(0, &sz("AutoHDREnable=0;").encode().unwrap().1);
            });
        }),
        ("before as a .bin", |env, dir| {
            let old = sz("AutoHDREnable=1;").encode().unwrap().1;
            rewrite(env.sys.fake_fs(), dir, None, |e| {
                e.intent_before(
                    0,
                    Some(Before::Bin(Digest {
                        sha256: crate::plan::tests::sha(&old),
                        len: u64::try_from(old.len()).unwrap(),
                    })),
                );
            });
        }),
        ("no before for an old value", |env, dir| {
            rewrite(env.sys.fake_fs(), dir, None, |e| e.intent_before(0, None));
        }),
    ];
    for (what, tamper) in tampers {
        let env = Env::new(finish(pref_base_with("AutoHDREnable=1;")));
        let t = env.applied(&plan_all(&env, &[pref_step("game.exe")]));
        tamper(&env, &env.txn_dir(&t));
        let after = snap_all(&env);
        let n = records(&env, &t);
        assert!(
            matches!(
                env.try_verify(&t),
                Err(ExecError::Refused(Refusal::Blocked { .. }))
            ),
            "{what}: verify"
        );
        let r = env.revert(&t);
        assert!(
            matches!(&r, Err(ExecError::Refused(Refusal::Blocked { .. }))),
            "{what}: {r:?}"
        );
        assert_eq!(after, snap_all(&env), "{what}");
        assert_eq!(records(&env, &t), n, "{what}: no record written");
    }
}

/// `NotWritten` (the counterpart of R-T3): Settings writes exactly `GpuPreference=2;` between
/// the apply's read and `set_pref`; `set_pref` refuses (`Mismatch`, nothing written), so the
/// value there is not Rerun's: the rollback finds it `Foreign` and leaves it, never "restores"
/// over it.
#[test]
fn r_g7_a_value_settings_wrote_before_our_set_is_left() {
    use crate::sys::fake::RegPrim;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    let env = Env::new(finish(pref_base().key(hkcu(PREFS_KEY))));
    let h = plan_all(&env, &[pref_step("game.exe")]);
    let fired = Arc::new(AtomicBool::new(false));
    let f2 = Arc::clone(&fired);
    // The first kernel-name check is the one of `set_pref`, after the apply's own read.
    env.sys.fake_registry().on_step(move |r, call| {
        if call == RegPrim::KernelName && !f2.swap(true, Ordering::SeqCst) {
            r.put_value(
                &hkcu(PREFS_KEY),
                &exe_name("game.exe"),
                &sz("GpuPreference=2;"),
            )
            .unwrap();
        }
    });
    let r = env.apply(&h);
    env.sys.fake_registry().clear_on_step();
    assert!(fired.load(Ordering::SeqCst));
    let Err(ApplyError::LeftOpen { txn, cause, .. }) = r else {
        panic!("{r:?}");
    };
    assert!(
        matches!(&*cause, ExecError::Op { op: 0, source }
            if source.kind == crate::sys::SysErrorKind::Mismatch),
        "{cause:?}"
    );
    assert_eq!(pref_value(&env.sys), Some(sz("GpuPreference=2;")));
    assert!(env.revert(&txn).is_ok_and(|r| r.closed.is_none()));
    assert_eq!(pref_value(&env.sys), Some(sz("GpuPreference=2;")));
}
