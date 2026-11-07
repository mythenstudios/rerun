//! `exec` with `TokenList` against the fake (P2-11, C4), each scenario a check function with
//! named findings (review N1): R-L1 round trips (a new value with the shared keys, a merge into
//! an existing value), R-L2 every row of the observation, R-L3 drift with exact strings, R-L6
//! tampering, R-L7 stacking and LIFO over a shared key, R-L8 a token dropped from the allowlist,
//! D4 for the layer executable, N2 in the planner. Controls (through the check functions):
//! K-L1 (no token of Rerun's left counted `Foreign`, E2 a) and the `unmerge` control fail
//! R-L3; K-L2 (every drift `Foreign`) fails R-L3; K-L4 (`merge` normalising the old value)
//! fails R-L1. Crashes and power losses: `layer_crash_tests.rs`. Synthetic tokens only.

use std::path::Path;

use super::reg_tests::{Reset, plan_all, reg_base, snap_all};
use super::tests::{Env, closed, finish, game, same, t1_spec};
use super::{ApplyError, ExecError, Outcome, Refusal};
use crate::journal::{Closing, Observed, TxnId, TxnState};
use crate::plan::{self, Op, Plan, PlanHash, store};
use crate::policy::registry::layers::knob as layers_knob;
use crate::prim::Step;
use crate::prim::layer_tests::{CURRENT_VERSION, LAYERS_KEY, exe_name, layer_step};
use crate::prim::reg_tests::hkcu;
use crate::prim::tests::app;
use crate::sys::System;
use crate::sys::contract::RegFixture;
use crate::sys::fake::{FakeSystem, FakeSystemBuilder};
use crate::sys::registry::RegValue;

/// The keys `AppCompatFlags` and `Layers`.
pub(crate) const APPCOMPAT: &str = r"Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags";

/// [`reg_base`] with `CurrentVersion` (the anchor) and a second executable `bin\g.exe`.
pub(crate) fn layer_base() -> FakeSystemBuilder {
    reg_base()
        .key(hkcu(CURRENT_VERSION))
        .file(game(r"bin\g.exe"), b"MZ".to_vec())
}

/// [`layer_base`] with the value of `game.exe` set to `v` (the keys exist then).
pub(crate) fn layer_base_with(v: &str) -> FakeSystemBuilder {
    layer_base().value(
        hkcu(LAYERS_KEY),
        &exe_name("game.exe"),
        RegValue::String(v.to_owned()),
    )
}

/// The value of `game.exe`.
pub(crate) fn layer_value(sys: &FakeSystem) -> Option<RegValue> {
    sys.registry()
        .get(&hkcu(LAYERS_KEY), &exe_name("game.exe"))
        .ok()
        .flatten()
}

pub(crate) fn put_layer(sys: &FakeSystem, v: &RegValue) {
    sys.fake_registry()
        .put_value(&hkcu(LAYERS_KEY), &exe_name("game.exe"), v)
        .unwrap();
}

fn sz(s: &str) -> RegValue {
    RegValue::String(s.to_owned())
}

fn key_exists(sys: &FakeSystem, k: &str) -> bool {
    sys.registry().key_exists(&hkcu(k)).unwrap_or(false)
}

/// The step every test uses: two tokens for `game.exe`.
pub(crate) fn two_tokens() -> Step {
    layer_step("game.exe", &["ZZ_OS_A", "ZZ_FLAG_A"])
}

/// Applies `steps` and returns the transaction, or a finding.
fn applied(env: &Env, steps: &[Step], what: &str) -> Result<TxnId, String> {
    match env.apply(&plan_all(env, steps)) {
        Ok(Outcome::Applied(t)) => Ok(t),
        other => Err(format!("{what} apply: {other:?}")),
    }
}

/// R-L1 as a check: `file_install` + `compat_layer` without a `Layers` key (R-L1a), and a merge
/// into `~ RUNASADMIN` (R-L1b): the value after the apply exactly, `verify` all `After`, the
/// revert closes with every op `After`, the snapshot of the game folder and `HKCU\Software`
/// identical, planned again the same hash, `verify` all `Before`.
pub(crate) fn l1_check() -> Vec<String> {
    let mut f = Vec::new();
    for (what, b, want) in [
        ("RL1a", layer_base(), "~ ZZ_FLAG_A ZZ_OS_A"),
        (
            "RL1b",
            layer_base_with("~ RUNASADMIN"),
            "~ RUNASADMIN ZZ_FLAG_A ZZ_OS_A",
        ),
    ] {
        let env = Env::new(finish(b));
        let before = snap_all(&env);
        let steps = [Step::FileInstall(t1_spec()), two_tokens()];
        let h = match try_plan(&env, &steps) {
            Ok(h) => h,
            Err(e) => {
                f.push(format!("{what} plan: {e}"));
                continue;
            }
        };
        let t = match env.apply(&h) {
            Ok(Outcome::Applied(t)) => t,
            other => {
                f.push(format!("{what} apply: {other:?}"));
                continue;
            }
        };
        if layer_value(&env.sys) != Some(sz(want)) {
            f.push(format!(
                "{what} value after apply: {:?}",
                layer_value(&env.sys)
            ));
        }
        match env.try_verify(&t) {
            Ok(v) if v.iter().all(|(_, o)| *o == Observed::After) => {}
            v => f.push(format!("{what} verify after apply: {v:?}")),
        }
        match env.revert(&t) {
            Ok(r)
                if r.closed == Some(Closing::Reverted)
                    && r.ops.iter().all(|o| o.observed == Observed::After) => {}
            r => f.push(format!("{what} revert: {r:?}")),
        }
        let now = snap_all(&env);
        if before != now {
            f.push(format!("{what} snapshot: {:#?}", before.diff(&now)));
        }
        if try_plan(&env, &steps).ok() != Some(h) {
            f.push(format!("{what} planned again: another hash"));
        }
        match env.try_verify(&t) {
            Ok(v) if v.iter().all(|(_, o)| *o == Observed::Before) => {}
            v => f.push(format!("{what} verify after revert: {v:?}")),
        }
    }
    f
}

#[test]
fn r_l1_compat_layer_round_trips_exactly() {
    let f = l1_check();
    assert!(f.is_empty(), "{f:#?}");
}

/// Plans `steps` for the manual game folder and stores the plan, or the planner's refusal.
fn try_plan(env: &Env, steps: &[Step]) -> Result<PlanHash, plan::PlanError> {
    let fr = crate::prim::tests::fr(&env.sys);
    let g = crate::policy::root::GameDir::open_manual(
        &env.sys,
        &fr,
        Path::new(crate::prim::tests::GAME),
    )?;
    let a = app(&env.sys);
    let main = crate::prim::tests::rel("game.exe");
    let p = crate::prim::plan(
        steps,
        &crate::prim::PlanCtx {
            game: &g,
            app: Some(&a),
            steam_app: None,
            main_exe: Some(&main),
            reg: crate::policy::registry::RegPolicy.reader(&env.sys),
        },
    )?;
    store(&a, &p.encode()?)
}

/// K-L4: `merge` normalising the old value fails R-L1 (R-L1b: since review S-1 the plan
/// format itself refuses a new value that is not the old one with the tokens appended).
#[test]
fn k_l4_merge_normalising_the_old_value_breaks_rl1() {
    let _r = Reset(|| layers_knob::normalise_old(false));
    layers_knob::normalise_old(true);
    let f = l1_check();
    assert!(
        f.iter().any(|x| x.starts_with("RL1b plan: ")
            && x.contains("not the old one with the tokens appended")),
        "{f:#?}"
    );
}

/// The ops of a plan as (kind, observed) of `verify`, for messages.
fn verify_of(env: &Env, t: &TxnId) -> Result<Vec<(u16, Observed)>, ExecError> {
    env.try_verify(t)
}

/// R-L2: every row of the observation of a `TokenList`, through `verify` (newest op, op 2 of a
/// plan with the two shared keys created, or op 0 with an old value).
#[test]
fn r_l2_verify_meets_every_row() {
    type Case = (&'static str, bool, fn(&FakeSystem), Observed);
    let cases: [Case; 10] = [
        ("after", false, |_| {}, Observed::After),
        (
            "before",
            false,
            |s| put_layer(s, &sz("~ RUNASADMIN")),
            Observed::Before,
        ),
        (
            "missing, no old value",
            true,
            |s| {
                s.fake_registry()
                    .remove_value(&hkcu(LAYERS_KEY), &exe_name("game.exe"))
                    .unwrap();
            },
            Observed::Before,
        ),
        (
            "missing, an old value (S3)",
            false,
            |s| {
                s.fake_registry()
                    .remove_value(&hkcu(LAYERS_KEY), &exe_name("game.exe"))
                    .unwrap();
            },
            Observed::Drifted,
        ),
        (
            "a foreign token appended",
            false,
            |s| {
                put_layer(s, &sz("~ RUNASADMIN ZZ_FLAG_A ZZ_OS_A X1"));
            },
            Observed::Drifted,
        ),
        (
            "none of ours left (E2 b)",
            false,
            |s| put_layer(s, &sz("~ RUNASADMIN X1")),
            Observed::Drifted,
        ),
        (
            "another type",
            false,
            |s| {
                put_layer(
                    s,
                    &RegValue::ExpandString("~ RUNASADMIN ZZ_FLAG_A ZZ_OS_A".into()),
                );
            },
            Observed::Foreign,
        ),
        (
            "one of ours twice",
            false,
            |s| {
                put_layer(s, &sz("~ RUNASADMIN ZZ_FLAG_A ZZ_OS_A ZZ_OS_A"));
            },
            Observed::Foreign,
        ),
        (
            "one of ours in another case (S4)",
            false,
            |s| {
                put_layer(s, &sz("~ RUNASADMIN ZZ_FLAG_A zz_os_a"));
            },
            Observed::Foreign,
        ),
        (
            "outside the grammar",
            false,
            |s| {
                put_layer(s, &sz("~ RUNASADMIN  ZZ_FLAG_A ZZ_OS_A"));
            },
            Observed::Foreign,
        ),
    ];
    for (what, new, change, want) in cases {
        let b = if new {
            layer_base()
        } else {
            layer_base_with("~ RUNASADMIN")
        };
        let env = Env::new(finish(b));
        let t = applied(&env, &[two_tokens()], what).unwrap();
        change(&env.sys);
        let v = verify_of(&env, &t).unwrap();
        let (_, got) = v.last().copied().unwrap();
        assert_eq!(got, want, "{what}: {v:?}");
    }
    // A link key planted at `AppCompatFlags` after the apply: `Foreign`, nothing behind it
    // changed by the revert.
    let env = Env::new(finish(layer_base_with("~ RUNASADMIN")));
    let t = applied(&env, &[two_tokens()], "link").unwrap();
    let r = env.sys.fake_registry();
    r.rename_key(&hkcu(APPCOMPAT), "Moved").unwrap();
    r.link(
        &hkcu(APPCOMPAT),
        &hkcu(&format!(r"{CURRENT_VERSION}\Moved")),
    )
    .unwrap();
    assert_eq!(verify_of(&env, &t).unwrap(), [(0, Observed::Foreign)]);
    let rep = env.revert(&t).unwrap();
    assert_eq!(rep.closed, None);
    assert_eq!(
        env.sys
            .registry()
            .get(
                &hkcu(&format!(r"{CURRENT_VERSION}\Moved\Layers")),
                &exe_name("game.exe")
            )
            .unwrap(),
        Some(sz("~ RUNASADMIN ZZ_FLAG_A ZZ_OS_A")),
        "behind the link: unchanged"
    );
}

/// One drift of R-L3: its name, the value before the apply (`None`: missing, keys created),
/// the change after the apply (`None`: deleted), the value after the revert (`None`: missing),
/// whether the transaction closes, whether `AppCompatFlags` is left.
type L3Case = (
    &'static str,
    Option<&'static str>,
    Option<fn() -> RegValue>,
    Option<&'static str>,
    bool,
    bool,
);

const L3_CASES: [L3Case; 10] = [
    (
        "a foreign token appended, keys created",
        None,
        Some(|| sz("~ ZZ_FLAG_A ZZ_OS_A X1")),
        Some("~ X1"),
        true,
        true,
    ),
    (
        "reordered with $ (as the tab might)",
        Some("~ RUNASADMIN"),
        Some(|| sz("$ ~ ZZ_OS_A RUNASADMIN ZZ_FLAG_A")),
        Some("$ ~ RUNASADMIN"),
        true,
        true,
    ),
    (
        "one of ours removed (E2 b)",
        Some("~ RUNASADMIN"),
        Some(|| sz("~ RUNASADMIN ZZ_OS_A")),
        Some("~ RUNASADMIN"),
        true,
        true,
    ),
    (
        "all of ours removed (E2 b)",
        Some("~ RUNASADMIN"),
        Some(|| sz("~ RUNASADMIN X1")),
        Some("~ RUNASADMIN X1"),
        true,
        true,
    ),
    ("deleted, no old value", None, None, None, true, false),
    (
        "deleted, an old value (S3)",
        Some("~ RUNASADMIN"),
        None,
        None,
        true,
        true,
    ),
    (
        "REG_EXPAND_SZ",
        Some("~ RUNASADMIN"),
        Some(|| RegValue::ExpandString("~ RUNASADMIN ZZ_FLAG_A ZZ_OS_A".into())),
        Some("~ RUNASADMIN ZZ_FLAG_A ZZ_OS_A"),
        false,
        true,
    ),
    (
        "ours twice",
        Some("~ RUNASADMIN"),
        Some(|| sz("~ RUNASADMIN ZZ_FLAG_A ZZ_OS_A ZZ_FLAG_A")),
        Some("~ RUNASADMIN ZZ_FLAG_A ZZ_OS_A ZZ_FLAG_A"),
        false,
        true,
    ),
    (
        "only the prefix left, no old value: deleted, keys deleted",
        None,
        Some(|| sz("~ ZZ_FLAG_A")),
        None,
        true,
        false,
    ),
    (
        "only the prefix left, an old value (S2): deleted",
        Some("~ RUNASADMIN"),
        Some(|| sz("~ ZZ_FLAG_A ZZ_OS_A")),
        None,
        true,
        true,
    ),
];

/// R-L3 as a check: every drift of [`L3_CASES`] reverted to exactly the expected value, the
/// transaction closed or left open as expected, the shared keys as expected; and a created
/// `Layers` with another program's value in it (E6 b) is left while the transaction closes.
pub(crate) fn l3_check() -> Vec<String> {
    let mut f = Vec::new();
    for (what, old, change, want, closes, keys_left) in L3_CASES {
        let b = match old {
            None => layer_base(),
            Some(o) => layer_base_with(o),
        };
        let env = Env::new(finish(b));
        let t = match applied(&env, &[two_tokens()], what) {
            Ok(t) => t,
            Err(e) => {
                f.push(format!("RL3 {e}"));
                continue;
            }
        };
        match change {
            Some(v) => put_layer(&env.sys, &v()),
            None => env
                .sys
                .fake_registry()
                .remove_value(&hkcu(LAYERS_KEY), &exe_name("game.exe"))
                .unwrap(),
        }
        let r = env.revert(&t);
        let got_closed = r
            .as_ref()
            .is_ok_and(|r| r.closed == Some(Closing::Reverted));
        if got_closed != closes {
            f.push(format!("RL3 {what}: closed {r:?}"));
        }
        let got = layer_value(&env.sys);
        let want = want.map(|w| match change {
            Some(v) if !matches!(v(), RegValue::String(_)) => v(),
            _ => sz(w),
        });
        if got != want {
            f.push(format!("RL3 {what}: value {got:?}, want {want:?}"));
        }
        if key_exists(&env.sys, APPCOMPAT) != keys_left {
            f.push(format!("RL3 {what}: AppCompatFlags left {}", !keys_left));
        }
    }
    // E6 b: a created `Layers` holding another program's value is left; the transaction closes.
    let env = Env::new(finish(layer_base()));
    match applied(&env, &[two_tokens()], "E6") {
        Ok(t) => {
            let other = exe_name(r"bin\g.exe");
            env.sys
                .fake_registry()
                .put_value(&hkcu(LAYERS_KEY), &other, &sz("~ X1"))
                .unwrap();
            let v = verify_of(&env, &t);
            if !v.as_ref().is_ok_and(|v| {
                v.iter().map(|(_, o)| *o).collect::<Vec<_>>()
                    == [Observed::Drifted, Observed::Drifted, Observed::After]
            }) {
                f.push(format!("RL3 E6 verify: {v:?}"));
            }
            match env.revert(&t) {
                Ok(r) if r.closed == Some(Closing::Reverted) => {}
                r => f.push(format!("RL3 E6 revert: {r:?}")),
            }
            if layer_value(&env.sys).is_some()
                || env
                    .sys
                    .registry()
                    .get(&hkcu(LAYERS_KEY), &other)
                    .ok()
                    .flatten()
                    != Some(sz("~ X1"))
            {
                f.push("RL3 E6 values after the revert".to_owned());
            }
        }
        Err(e) => f.push(format!("RL3 {e}")),
    }
    f
}

#[test]
fn r_l3_a_drifted_value_loses_only_rerun_tokens() {
    let f = l3_check();
    assert!(f.is_empty(), "{f:#?}");
}

/// K-L2: every drift taken as `Foreign` (as a `SetValue`) fails R-L3.
#[test]
fn k_l2_drift_as_foreign_breaks_rl3() {
    let _r = Reset(|| super::reg::KNOB_DRIFT_FOREIGN.with(|c| c.set(false)));
    super::reg::KNOB_DRIFT_FOREIGN.with(|c| c.set(true));
    let f = l3_check();
    assert!(
        f.iter()
            .any(|x| x.starts_with("RL3 a foreign token appended")),
        "{f:#?}"
    );
}

/// K-L1 (replaces the `from`/`to` control, E8): a value without any of Rerun's tokens taken as
/// `Foreign` (E2 a) fails R-L3.
#[test]
fn k_l1_no_token_left_as_foreign_breaks_rl3() {
    let _r = Reset(|| super::reg::KNOB_UNTOUCHED_FOREIGN.with(|c| c.set(false)));
    super::reg::KNOB_UNTOUCHED_FOREIGN.with(|c| c.set(true));
    let f = l3_check();
    assert!(
        f.iter().any(|x| x.starts_with("RL3 all of ours removed")),
        "{f:#?}"
    );
}

/// K-L1, the second half: `unmerge` removing only the first of Rerun's tokens fails R-L3.
#[test]
fn k_l1_unmerge_removing_only_the_first_token_breaks_rl3() {
    let _r = Reset(|| layers_knob::first_only(false));
    layers_knob::first_only(true);
    let f = l3_check();
    assert!(
        f.iter()
            .any(|x| x.starts_with("RL3 a foreign token appended")),
        "{f:#?}"
    );
}

/// The records of the transaction directory `dir`.
fn records(env: &Env, t: &TxnId) -> usize {
    crate::journal::tests::rewrite(env.sys.fake_fs(), &env.txn_dir(t), None, |_| {}).into()
}

/// R-L6: tampering. `from`/`to` on a token list, an `Intent.before` other than the planned old
/// value, a `.bin` for it: `Blocked`, nothing written. A stored plan with an elevation token is
/// refused by the apply (current rules); a recorded head with one (recorded rules) only makes
/// the revert remove that word if it is there (review N8), never add one.
#[test]
fn r_l6_tampering_is_refused_or_only_removes() {
    use crate::journal::tests::{append_semantic_revert_intent, rewrite};
    use crate::journal::{Before, Digest};
    type Tamper = (&'static str, fn(&Env, &str));
    let tampers: [Tamper; 4] = [
        ("from/to on a token list", |env, dir| {
            append_semantic_revert_intent(env.sys.fake_fs(), dir, 0);
        }),
        ("before other than old", |env, dir| {
            rewrite(env.sys.fake_fs(), dir, None, |e| {
                e.intent_inline(0, &sz("~ OTHER").encode().unwrap().1);
            });
        }),
        ("before as a .bin", |env, dir| {
            let old = sz("~ RUNASADMIN").encode().unwrap().1;
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
        let env = Env::new(finish(layer_base_with("~ RUNASADMIN")));
        let t = applied(&env, &[two_tokens()], what).unwrap();
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
        same(&after, &snap_all(&env));
        assert_eq!(records(&env, &t), n, "{what}: no record written");
    }

    // Security review S-1: the old value and `Intent.before` rewritten consistently to hold an
    // elevation token, `new` left: the restore of `After` would add it. The plan format binds
    // `new` to `old` under the recorded rules too: `Blocked`, nothing written.
    let env = Env::new(finish(layer_base_with("~ X1")));
    let t = applied(&env, &[layer_step("game.exe", &["ZZ_OS_A"])], "S-1").unwrap();
    let dir = env.txn_dir(&t);
    let head = super::tests::read_abs(&env.sys, &format!(r"{dir}\head.json"));
    let mut p: Plan = serde_json::from_slice(&head).unwrap();
    let forged = sz("~ X1 RUNASADMIN");
    match p.ops.last_mut() {
        Some(Op::TokenList { old, .. }) => *old = crate::plan::ValueState::of(&forged),
        other => panic!("{other:?}"),
    }
    let bytes = serde_json::to_vec(&p).unwrap();
    let data = forged.encode().unwrap().1;
    let n = rewrite(env.sys.fake_fs(), &dir, Some(&bytes), |e| {
        e.intent_inline(0, &data)
    });
    let after = snap_all(&env);
    assert!(matches!(
        env.try_verify(&t),
        Err(ExecError::Refused(Refusal::Blocked { .. }))
    ));
    let r = env.revert(&t);
    assert!(
        matches!(&r, Err(ExecError::Refused(Refusal::Blocked { .. }))),
        "{r:?}"
    );
    same(&after, &snap_all(&env));
    assert_eq!(records(&env, &t), usize::from(n), "S-1: no record written");
    assert_eq!(layer_value(&env.sys), Some(sz("~ X1 ZZ_OS_A")));

    // A stored plan adding an elevation token (written around `encode`): refused by the apply.
    let env = Env::new(finish(layer_base_with("~ X1")));
    let fr = crate::prim::tests::fr(&env.sys);
    let g = crate::policy::root::GameDir::open_manual(
        &env.sys,
        &fr,
        Path::new(crate::prim::tests::GAME),
    )
    .unwrap();
    let a = app(&env.sys);
    let mut p = good_plan(&env, &g);
    if let Some(Op::TokenList { add, new, .. }) = p.ops.last_mut() {
        *add = vec![crate::policy::registry::TokenName::parse("RUNASADMIN").unwrap()];
        *new = "~ X1 RUNASADMIN".to_owned();
    }
    let bytes = plan::PlanBytes::from_bytes(serde_json::to_vec(&p).unwrap());
    let h: PlanHash = store(&a, &bytes).unwrap();
    let r = env.apply(&h);
    assert!(
        matches!(
            &r,
            Err(ApplyError::Refused(Refusal::Plan(
                plan::PlanError::Registry { .. }
            )))
        ),
        "{r:?}"
    );
    assert_eq!(layer_value(&env.sys), Some(sz("~ X1")));

    // A recorded head rewritten to "add" the user's own elevation token (N8): the revert
    // removes it with Rerun's, and writes nothing else.
    let env = Env::new(finish(layer_base_with("~ X1")));
    let t = applied(&env, &[layer_step("game.exe", &["ZZ_OS_A"])], "N8").unwrap();
    put_layer(&env.sys, &sz("~ X1 ZZ_OS_A RUNASADMIN"));
    let dir = env.txn_dir(&t);
    let head = super::tests::read_abs(&env.sys, &format!(r"{dir}\head.json"));
    let head = String::from_utf8(head)
        .unwrap()
        .replacen(
            r#""add":["ZZ_OS_A"]"#,
            r#""add":["RUNASADMIN","ZZ_OS_A"]"#,
            1,
        )
        .replacen(
            r#""new":"~ X1 ZZ_OS_A""#,
            r#""new":"~ X1 RUNASADMIN ZZ_OS_A""#,
            1,
        );
    rewrite(env.sys.fake_fs(), &dir, Some(head.as_bytes()), |_| {});
    let r = env.revert(&t).unwrap();
    assert_eq!(r.closed, Some(Closing::Reverted), "{r:?}");
    assert_eq!(layer_value(&env.sys), Some(sz("~ X1")));
}

/// The plan of one `compat_layer` step for `game.exe` (`ZZ_OS_A`).
fn good_plan(env: &Env, g: &crate::policy::root::GameDir<'_>) -> Plan {
    let a = app(&env.sys);
    let main = crate::prim::tests::rel("game.exe");
    crate::prim::plan(
        &[layer_step("game.exe", &["ZZ_OS_A"])],
        &crate::prim::PlanCtx {
            game: g,
            app: Some(&a),
            steam_app: None,
            main_exe: Some(&main),
            reg: crate::policy::registry::RegPolicy.reader(&env.sys),
        },
    )
    .unwrap()
}

/// R-L7: stacking and LIFO. Two games below one created `Layers` (E7): no overlap, either
/// order closes; reverted newest first, everything is as before; oldest first, the shared keys
/// stay (E6 b). The same value twice (T2.old = T1.new): LIFO, identical.
#[test]
fn r_l7_stacking_and_lifo_over_shared_keys() {
    let other = || layer_step(r"bin\g.exe", &["ZZ_FLAG_A"]);
    // Newest first: identical.
    let env = Env::new(finish(layer_base()));
    let before = snap_all(&env);
    let t1 = applied(&env, &[two_tokens()], "T1").unwrap();
    let t2 = applied(&env, &[other()], "T2").unwrap();
    assert_eq!(closed(&env.revert(&t2)), Some(Closing::Reverted));
    assert_eq!(closed(&env.revert(&t1)), Some(Closing::Reverted));
    same(&before, &snap_all(&env));
    // Oldest first: allowed (no shared object), the keys stay while T2's value is there.
    let env = Env::new(finish(layer_base()));
    let t1 = applied(&env, &[two_tokens()], "T1").unwrap();
    let t2 = applied(&env, &[other()], "T2").unwrap();
    let r = env.revert(&t1).unwrap();
    assert_eq!(r.closed, Some(Closing::Reverted));
    assert_eq!(
        r.ops.iter().map(|o| o.observed).collect::<Vec<_>>(),
        [Observed::After, Observed::Drifted, Observed::Drifted]
    );
    assert_eq!(closed(&env.revert(&t2)), Some(Closing::Reverted));
    assert!(key_exists(&env.sys, LAYERS_KEY), "shared keys stay (E6 b)");
    assert_eq!(layer_value(&env.sys), None);

    // The same value twice: T2 adds to what T1 left; T1 is `Later` until T2 is reverted.
    let env = Env::new(finish(layer_base_with("~ X1")));
    let before = snap_all(&env);
    let t1 = applied(&env, &[layer_step("game.exe", &["ZZ_OS_A"])], "T1").unwrap();
    let mid = snap_all(&env);
    let t2 = applied(&env, &[layer_step("game.exe", &["ZZ_FLAG_A"])], "T2").unwrap();
    assert_eq!(layer_value(&env.sys), Some(sz("~ X1 ZZ_OS_A ZZ_FLAG_A")));
    assert!(matches!(
        env.revert(&t1),
        Err(ExecError::Refused(Refusal::Later { txn })) if txn == t2
    ));
    assert_eq!(closed(&env.revert(&t2)), Some(Closing::Reverted));
    same(&mid, &snap_all(&env));
    assert_eq!(closed(&env.revert(&t1)), Some(Closing::Reverted));
    same(&before, &snap_all(&env));
}

/// R-L8 for `compat_layer` (E4, M1): a token dropped from the allowlist after the apply does not
/// block the applied transaction (`verify`, another apply, the revert identical); the same plan
/// applied again is refused. The allowlist in another order changes nothing (M1).
#[test]
fn r_l8_a_dropped_token_never_blocks_the_revert() {
    let _r = Reset(|| {
        layers_knob::drop_token(None);
        layers_knob::reverse(false);
    });
    let env = Env::new(finish(layer_base_with("~ X1")));
    let before = snap_all(&env);
    let h = plan_all(&env, &[two_tokens()]);
    let t = env.applied(&h);
    layers_knob::reverse(true);
    layers_knob::drop_token(Some("ZZ_OS_A"));
    assert!(
        env.verify(&t).iter().all(|(_, o)| *o == Observed::After),
        "verify"
    );
    let other = plan_all(&env, &[layer_step(r"bin\g.exe", &["ZZ_FLAG_A"])]);
    let t2 = env.applied(&other);
    assert_eq!(closed(&env.revert(&t2)), Some(Closing::Reverted));
    assert_eq!(closed(&env.revert(&t)), Some(Closing::Reverted));
    same(&before, &snap_all(&env));
    assert!(matches!(
        env.apply(&h),
        Err(ApplyError::Refused(Refusal::Plan(
            plan::PlanError::Registry { .. }
        )))
    ));
    // Back on the list (in reverse order): the same plan applies again.
    layers_knob::drop_token(None);
    assert!(matches!(env.apply(&h), Ok(Outcome::Applied(_))));
}

/// D4: the executable of a compatibility layer is asked too, also when it is not the main one.
#[test]
fn r_l_d4_the_layer_executable_must_be_closed() {
    let env = Env::new(finish(layer_base()));
    let h = plan_all(&env, &[layer_step(r"bin\g.exe", &["ZZ_OS_A"])]);
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

/// N2: a token of the same group that an open Rerun transaction added names that transaction.
#[test]
fn r_l_n2_a_conflict_with_an_active_transaction_names_it() {
    let env = Env::new(finish(layer_base()));
    let t = env.applied(&plan_all(&env, &[layer_step("game.exe", &["ZZ_OS_A"])]));
    let sys: &FakeSystem = &env.sys;
    let e = crate::prim::reg_tests::plan_steps(
        sys,
        &[layer_step("game.exe", &["ZZ_OS_B"])],
        Some("game.exe"),
    )
    .unwrap_err()
    .to_string();
    assert!(
        e.contains(&format!(
            "from Rerun transaction {t}; revert that transaction first"
        )),
        "{e}"
    );
    assert_eq!(closed(&env.revert(&t)), Some(Closing::Reverted));
}
