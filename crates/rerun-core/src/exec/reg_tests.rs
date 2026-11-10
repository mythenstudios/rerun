//! `exec` with registry ops against the fake (P2-10b, C6): R-T1 a mixed round trip, R-T2
//! verify, R-T5 tampering, R-T6 foreign states, R-T7 stacking, R-T8 refusals without a
//! transaction, R-H a mixed plan whose root does not open, the controls K1 (registry), K-R7 and
//! K-R9 (through the check functions). Crashes and power losses: `reg_crash_tests.rs`.

use std::path::Path;

use super::tests::{
    Env, N, acf, base, closed, finish, game, manifest, same, steam_sys, sys_put, t1_spec,
};
use super::{ApplyError, ExecError, Outcome, Refusal};
use crate::journal::{Closing, InstanceTag, Journal, Observed, TxnId, TxnState, VerifyBackups};
use crate::plan::{self, Plan, PlanHash, store};
use crate::policy::registry::RegPolicy;
use crate::policy::root::{GameDir, StoreDir};
use crate::prim::reg_tests::{BIG, dword, hkcu, step, sz};
use crate::prim::tests::{GAME, STEAM_LIB, app, entry, fr, rel, spec};
use crate::prim::{PlanCtx, Step, plan as plan_steps};
use crate::sys::contract::RegFixture;
use crate::sys::fake::{FakeSystem, FakeSystemBuilder, Prim, RegPrim};
use crate::sys::registry::{RegValue, reg_type};
use crate::sys::snapshot::{Scope, SnapRoot, Snapshot, snapshot};
use crate::sys::{SysErrorKind, System};

/// The existing key the replaced value lives in.
pub(crate) const VENDOR_GAME: &str = r"Software\Vendor\Game";
/// The keys R-T1 creates, top-down.
pub(crate) const SUB: &str = r"Software\New\Prod\Sub";

/// [`base`] plus an existing key with a `REG_SZ` R-T1 replaces by a `REG_DWORD`, and a value
/// of 20 KiB (above the journal's inline limit).
pub(crate) fn reg_base() -> FakeSystemBuilder {
    base()
        .value(
            hkcu(VENDOR_GAME),
            "TypeChange",
            RegValue::String("text".into()),
        )
        .value(hkcu(VENDOR_GAME), "Big", RegValue::Binary(vec![7; BIG]))
}

/// R-T1's steps: `file_install` (5 ops) and `registry_set` (3 new keys, 2 new values in the
/// deepest, 1 replaced value of another type). Ops 0 to 4 files, 5 to 7 keys, 8 and 9 the new
/// values, 10 the replaced one.
pub(crate) fn rt1_steps() -> Vec<Step> {
    vec![
        step(&format!(r"HKCU\{SUB}"), vec![dword("A", 1), sz("B", "en")]),
        Step::FileInstall(t1_spec()),
        step(
            &format!(r"HKCU\{VENDOR_GAME}"),
            vec![dword("TypeChange", 2)],
        ),
    ]
}

/// Plans `steps` for the manual game folder and stores the plan.
pub(crate) fn plan_all(env: &Env, steps: &[Step]) -> PlanHash {
    let fr = fr(&env.sys);
    let g = GameDir::open_manual(&env.sys, &fr, Path::new(GAME)).unwrap();
    plan_for(env, &g, None, steps)
}

pub(crate) fn plan_for(
    env: &Env,
    g: &GameDir<'_>,
    steam_app: Option<u32>,
    steps: &[Step],
) -> PlanHash {
    let app = app(&env.sys);
    let main = rel("game.exe");
    let p = plan_steps(
        steps,
        &PlanCtx {
            game: g,
            app: Some(&app),
            steam_app,
            main_exe: Some(&main),
            reg: RegPolicy.reader(&env.sys),
            app_path: None,
            user_data: None,
        },
    )
    .unwrap_or_else(|e| panic!("{e}"));
    store(&app, &p.encode().unwrap()).unwrap()
}

/// The game folder and `HKCU\Software`, as the round trip compares them.
pub(crate) fn snap_all(env: &Env) -> Snapshot {
    snap_at_with_keys(&env.sys, GAME)
}

pub(crate) fn snap_at_with_keys(sys: &FakeSystem, abs: &str) -> Snapshot {
    let fr = fr(sys);
    let g = GameDir::open_manual(sys, &fr, Path::new(abs)).unwrap();
    snapshot(
        sys.registry(),
        &Scope {
            dirs: vec![SnapRoot::new(g.dir(), abs)],
            keys: vec![hkcu("Software")],
        },
    )
    .unwrap()
}

/// The registry part only (the game folder may be gone).
fn snap_keys(sys: &FakeSystem) -> Snapshot {
    snapshot(
        sys.registry(),
        &Scope {
            dirs: Vec::new(),
            keys: vec![hkcu("Software")],
        },
    )
    .unwrap()
}

fn value(sys: &FakeSystem, key: &str, name: &str) -> Option<RegValue> {
    sys.registry().get(&hkcu(key), name).ok().flatten()
}

fn key_exists(sys: &FakeSystem, key: &str) -> bool {
    sys.registry().key_exists(&hkcu(key)).unwrap_or(false)
}

fn foreign_of(v: &[(u16, Observed)]) -> Vec<u16> {
    v.iter()
        .filter(|(_, o)| *o == Observed::Foreign)
        .map(|(k, _)| *k)
        .collect()
}

/// R-T1 as a check (review N1): the findings, each named; empty if R-T1 holds. K1 (the
/// registry part) and K3 ask for theirs.
pub(crate) fn rt1_check() -> Vec<String> {
    let mut f = Vec::new();
    let env = Env::new(finish(reg_base()));
    let before = snap_all(&env);
    let h = plan_all(&env, &rt1_steps());
    let t = match env.apply(&h) {
        Ok(Outcome::Applied(t)) => t,
        other => return vec![format!("RT1 apply: {other:?}")],
    };
    let v = env.try_verify(&t);
    if !v
        .as_ref()
        .is_ok_and(|v| v.len() == 11 && v.iter().all(|(_, o)| *o == Observed::After))
    {
        f.push(format!("RT1 verify after apply: {v:?}"));
    }
    let sub = SUB;
    if value(&env.sys, sub, "A") != Some(RegValue::Dword(1))
        || value(&env.sys, sub, "B") != Some(RegValue::String("en".into()))
        || value(&env.sys, VENDOR_GAME, "TypeChange") != Some(RegValue::Dword(2))
    {
        f.push("RT1 values after apply".to_owned());
    }
    let rep = match env.revert(&t) {
        Ok(r) => r,
        Err(e) => {
            f.push(format!("RT1 revert: {e}"));
            return f;
        }
    };
    if rep.closed != Some(Closing::Reverted) {
        f.push(format!("RT1 closed: {:?}", rep.closed));
    }
    let order: Vec<u16> = rep.ops.iter().map(|o| o.op).collect();
    if order != (0..11).rev().collect::<Vec<u16>>()
        || !rep.ops.iter().all(|o| o.observed == Observed::After)
    {
        f.push(format!("RT1 reverted ops: {rep:?}"));
    }
    let now = snap_all(&env);
    if before != now {
        f.push(format!("RT1 snapshot: {:#?}", before.diff(&now)));
    }
    if plan_all(&env, &rt1_steps()) != h {
        f.push("RT1 planned again: another hash".to_owned());
    }
    let v = env.try_verify(&t);
    if !v
        .as_ref()
        .is_ok_and(|v| v.iter().all(|(_, o)| *o == Observed::Before))
    {
        f.push(format!("RT1 verify after revert: {v:?}"));
    }
    f
}

#[test]
fn r_t1_a_mixed_plan_round_trips_the_game_folder_and_the_registry() {
    let f = rt1_check();
    assert!(f.is_empty(), "{f:#?}");
}

/// R-T1, the plan itself: file ops first, the registry ops in their order, the replaced
/// value's old state of another type; the preview names the keys.
#[test]
fn r_t1_the_plan_puts_files_first() {
    let env = Env::new(finish(reg_base()));
    let h = plan_all(&env, &rt1_steps());
    let a = app(&env.sys);
    let p: Plan = plan::decode(plan::load(&a, &h).unwrap().bytes()).unwrap();
    assert_eq!(p.ops.len(), 11);
    assert!(p.ops[..5].iter().all(|o| !o.target().is_registry()));
    assert!(p.ops[5..].iter().all(|o| o.target().is_registry()));
    let text = plan::preview(&p).to_string();
    assert!(
        text.contains(r"create key HKCU\Software\New\Prod\Sub"),
        "{text}"
    );
    assert!(text.contains("the type of the value changes"), "{text}");
}

/// R-T2: `verify` names exactly the ops someone changed (and the created keys above a change
/// that the revert will find not empty, S3); the revert meets exactly these.
#[test]
fn r_t2_verify_names_exactly_the_op_someone_changed() {
    type Change = fn(&FakeSystem);
    let cases: [(&str, &[u16], Change); 7] = [
        ("our value changed", &[5, 6, 7, 8], |s| {
            s.fake_registry()
                .put_value(&hkcu(SUB), "A", &RegValue::Dword(9))
                .unwrap();
        }),
        ("the replaced value changed", &[10], |s| {
            s.fake_registry()
                .put_value(&hkcu(VENDOR_GAME), "TypeChange", &RegValue::Dword(7))
                .unwrap();
        }),
        ("a value of the game in a created key", &[5, 6, 7], |s| {
            s.fake_registry()
                .put_value(&hkcu(SUB), "GameVal", &RegValue::Dword(1))
                .unwrap();
        }),
        ("a key of the game in a created key", &[5, 6], |s| {
            s.fake_registry()
                .put_key(&hkcu(r"Software\New\Prod\Other"))
                .unwrap();
        }),
        // S6: our value grown over 1 MiB by the game: `Foreign`, verify does not abort.
        ("our value grown over 1 MiB", &[5, 6, 7, 8], |s| {
            s.fake_registry()
                .put_value(&hkcu(SUB), "A", &RegValue::Binary(vec![1; (1 << 20) + 1]))
                .unwrap();
        }),
        // S6: the counts fit the later ops, but listing the key is too large (our value
        // deleted, a value over 1 MiB put beside ours): the created key is `Foreign`.
        ("a key too large to list", &[5, 6, 7], |s| {
            let r = s.fake_registry();
            r.remove_value(&hkcu(SUB), "A").unwrap();
            r.put_value(&hkcu(SUB), "X", &RegValue::Binary(vec![1; (1 << 20) + 1]))
                .unwrap();
        }),
        ("a file", &[0], |s| {
            let p = game("d3d9.dll");
            s.fake_fs().remove_abs(Path::new(&p)).unwrap();
            s.fake_fs().put_file(Path::new(&p), b"user").unwrap();
        }),
    ];
    for (what, ops, change) in cases {
        let env = Env::new(finish(reg_base()));
        let t = env.applied(&plan_all(&env, &rt1_steps()));
        change(&env.sys);
        let v = env.verify(&t);
        assert_eq!(foreign_of(&v), ops, "{what}: {v:?}");
        assert!(
            v.iter().all(|(k, o)| ops.contains(k)
                    || *o == Observed::After
                    // Our value deleted by the game: as before the op.
                    || (what == "a key too large to list" && *k == 8 && *o == Observed::Before)),
            "{what}: {v:?}"
        );
        let rep = env.revert(&t).unwrap();
        let mut met: Vec<u16> = rep
            .ops
            .iter()
            .filter(|o| o.observed == Observed::Foreign)
            .map(|o| o.op)
            .collect();
        met.sort_unstable();
        assert_eq!(
            met, ops,
            "{what}: the revert meets what verify showed: {rep:?}"
        );
        assert_eq!(rep.closed, None, "{what}");
    }
}

/// The records of `t`, without changing anything.
fn records(env: &Env, t: &TxnId) -> usize {
    let a = app(&env.sys);
    let j = Journal::new(&a, InstanceTag::fixed(5));
    j.load(t, VerifyBackups::Length).map_or(0, |v| v.log.len())
}

/// R-T5: a head rewritten consistently (a denied vendor, a registry op before a file op,
/// `segs` at the anchor) is refused before anything is written; an `Intent.before` that is not
/// the planned old value is `Blocked`; a swapped `.bin` is refused by the restore and the op
/// stays open; a link key planted on the way after the apply is `Foreign`, and the key behind
/// it unchanged.
#[test]
fn r_t5_tampering_is_refused_or_left() {
    use crate::journal::tests::rewrite;
    let good = {
        let env = Env::new(finish(reg_base()));
        let t = env.applied(&plan_all(&env, &rt1_steps()));
        let b = super::tests::read_abs(&env.sys, &format!(r"{}\head.json", env.txn_dir(&t)));
        String::from_utf8(b).unwrap()
    };
    let reordered = {
        let mut p: Plan = serde_json::from_str(&good).unwrap();
        let last = p.ops.remove(10);
        p.ops.insert(0, last);
        String::from_utf8(serde_json::to_vec(&p).unwrap()).unwrap()
    };
    let heads = [
        (
            "vendor Microsoft",
            good.replacen(r#""vendor":"New""#, r#""vendor":"Microsoft""#, 1),
        ),
        ("registry before file", reordered),
        (
            "segs at the anchor",
            good.replacen(r#""segs":2"#, r#""segs":1"#, 1),
        ),
    ];
    for (what, head) in heads {
        assert_ne!(head, good, "{what}");
        let env = Env::new(finish(reg_base()));
        let t = env.applied(&plan_all(&env, &rt1_steps()));
        let dir = env.txn_dir(&t);
        let n = rewrite(env.sys.fake_fs(), &dir, Some(head.as_bytes()), |_| {});
        let after = snap_all(&env);
        let r = env.revert(&t);
        assert!(
            matches!(&r, Err(ExecError::Refused(Refusal::Blocked { .. }))),
            "{what}: {r:?}"
        );
        assert!(
            matches!(
                env.try_verify(&t),
                Err(ExecError::Refused(Refusal::Blocked { .. }))
            ),
            "{what}: verify"
        );
        same(&after, &snap_all(&env));
        assert_eq!(rewrite(env.sys.fake_fs(), &dir, None, |_| {}), n, "{what}");
    }

    // `Intent.before` is not the planned old value (checklist P2-10b): Blocked.
    let env = Env::new(finish(reg_base()));
    let t = env.applied(&plan_all(&env, &rt1_steps()));
    let dir = env.txn_dir(&t);
    rewrite(env.sys.fake_fs(), &dir, None, |e| {
        e.intent_inline(10, &RegValue::String("TEXT".into()).encode().unwrap().1);
    });
    let after = snap_all(&env);
    assert!(matches!(
        env.revert(&t),
        Err(ExecError::Refused(Refusal::Blocked { .. }))
    ));
    same(&after, &snap_all(&env));

    // A swapped `.bin` of a 20 KiB old value: the restore refuses, the value stays new.
    let env = Env::new(finish(reg_base()));
    let h = plan_all(
        &env,
        &[step(&format!(r"HKCU\{VENDOR_GAME}"), vec![dword("Big", 1)])],
    );
    let t = env.applied(&h);
    let bin = format!(r"{}\op-0000.bin", env.txn_dir(&t));
    let fx = env.sys.fake_fs();
    fx.remove_abs(Path::new(&bin)).unwrap();
    fx.put_file(Path::new(&bin), &vec![8; BIG]).unwrap();
    let r = env.revert(&t);
    assert!(
        matches!(
            &r,
            Err(ExecError::Journal(
                crate::journal::JournalError::BackupMismatch(0)
            ))
        ),
        "{r:?}"
    );
    assert_eq!(
        value(&env.sys, VENDOR_GAME, "Big"),
        Some(RegValue::Dword(1))
    );
    assert_eq!(env.state(&t), Some(TxnState::Applied));

    // A link key on the way after the apply: Foreign, the key behind the link unchanged.
    let env = Env::new(finish(reg_base()));
    let t = env.applied(&plan_all(&env, &rt1_steps()));
    let r = env.sys.fake_registry();
    r.rename_key(&hkcu(r"Software\New"), "Moved").unwrap();
    r.link(&hkcu(r"Software\New"), &hkcu(r"Software\Moved"))
        .unwrap();
    let v = env.verify(&t);
    assert_eq!(foreign_of(&v), [5, 6, 7, 8, 9], "{v:?}");
    let rep = env.revert(&t).unwrap();
    assert_eq!(rep.closed, None);
    assert_eq!(
        value(&env.sys, r"Software\Moved\Prod\Sub", "A"),
        Some(RegValue::Dword(1)),
        "behind the link: unchanged"
    );
    assert_eq!(
        value(&env.sys, VENDOR_GAME, "TypeChange"),
        Some(RegValue::String("text".into()))
    );
}

/// A change of R-T6: its name, the ops it makes foreign, the change, what must stay.
type Rt6Case = (
    &'static str,
    &'static [u16],
    fn(&FakeSystem),
    fn(&FakeSystem) -> bool,
);

const RT6_CASES: [Rt6Case; 4] = [
    (
        "the game fills a created key",
        &[5, 6, 7],
        |s| {
            s.fake_registry()
                .put_value(&hkcu(SUB), "GameVal", &RegValue::Dword(3))
                .unwrap();
        },
        |s| {
            value(s, SUB, "GameVal") == Some(RegValue::Dword(3))
                && value(s, SUB, "A").is_none()
                && value(s, SUB, "B").is_none()
        },
    ),
    (
        "the user changes our value",
        &[5, 6, 7, 8],
        |s| {
            s.fake_registry()
                .put_value(&hkcu(SUB), "A", &RegValue::Dword(9))
                .unwrap();
        },
        |s| value(s, SUB, "A") == Some(RegValue::Dword(9)),
    ),
    (
        "S4: the game writes our REG_SZ without its NUL",
        &[5, 6, 7, 9],
        |s| {
            s.fake_registry()
                .put_value(
                    &hkcu(SUB),
                    "B",
                    &RegValue::decode(reg_type::REG_SZ, &[b'e', 0, b'n', 0]),
                )
                .unwrap();
        },
        |s| value(s, SUB, "B") == Some(RegValue::decode(reg_type::REG_SZ, &[b'e', 0, b'n', 0])),
    ),
    (
        "S4: the game writes our value with another type",
        &[10],
        |s| {
            s.fake_registry()
                .put_value(&hkcu(VENDOR_GAME), "TypeChange", &RegValue::Qword(2))
                .unwrap();
        },
        |s| value(s, VENDOR_GAME, "TypeChange") == Some(RegValue::Qword(2)),
    ),
];

/// R-T6 for one case as a check (review N1); K1 asks for its finding.
pub(crate) fn rt6_check(case: &Rt6Case) -> Vec<String> {
    let (what, ops, change, kept) = *case;
    let mut f = Vec::new();
    let env = Env::new(finish(reg_base()));
    let t = match env.apply(&plan_all(&env, &rt1_steps())) {
        Ok(Outcome::Applied(t)) => t,
        other => return vec![format!("RT6 {what} apply: {other:?}")],
    };
    change(&env.sys);
    let v = env.try_verify(&t);
    if !v.as_ref().is_ok_and(|v| foreign_of(v) == ops) {
        f.push(format!("RT6 {what} verify: {v:?}"));
    }
    let rep = match env.revert(&t) {
        Ok(r) => r,
        Err(e) => {
            f.push(format!("RT6 {what} revert: {e}"));
            return f;
        }
    };
    if rep.closed.is_some() {
        f.push(format!("RT6 {what} closed: {:?}", rep.closed));
    }
    let mut met: Vec<u16> = rep
        .ops
        .iter()
        .filter(|o| o.observed == Observed::Foreign)
        .map(|o| o.op)
        .collect();
    met.sort_unstable();
    if met != ops
        || !rep
            .ops
            .iter()
            .all(|o| matches!(o.observed, Observed::After | Observed::Foreign))
    {
        f.push(format!("RT6 {what} ops: {rep:?}"));
    }
    if !kept(&env.sys) {
        f.push(format!(
            "RT6 {what} object: not as the game or user left it"
        ));
    }
    // The files are reverted (R1).
    if super::tests::try_read_abs(&env.sys, &game("d3d9.dll")).as_deref() != Some(super::tests::OLD)
    {
        f.push(format!("RT6 {what} files"));
    }
    if !env.revert(&t).is_ok_and(|r| r.closed.is_none()) {
        f.push(format!("RT6 {what} revert again"));
    }
    if env.forget(&t).is_err() || env.state(&t) != Some(TxnState::Closed(Closing::Forgotten)) {
        f.push(format!("RT6 {what} forget: {:?}", env.state(&t)));
    }
    f
}

#[test]
fn r_t6_a_foreign_key_or_value_is_left_and_only_forget_closes() {
    for case in &RT6_CASES {
        let f = rt6_check(case);
        assert!(f.is_empty(), "{f:#?}");
    }
}

/// K1 for registry ops: a revert that trusts the records tries to put back a value the user
/// changed (the sequence refuses the write, the revert fails); R-T6's check reports it.
#[test]
fn k1_trusting_the_records_breaks_rt6() {
    let case = RT6_CASES
        .iter()
        .find(|c| c.0 == "the user changes our value")
        .unwrap();
    super::knob::trust_records(true);
    let f = rt6_check(case);
    super::knob::trust_records(false);
    assert!(
        f.iter()
            .any(|x| x.starts_with("RT6 the user changes our value revert:")),
        "K1 not caught: {f:#?}"
    );
}

/// R-T6, rest risk of `docs/06-security.md` scenario 10 (6a): a crash after the create of a
/// key, before its `Done`; another program puts an empty key of the same name there before the
/// recovery. The recovery cannot tell and deletes the empty key (pinned, accepted).
#[test]
fn r_t6_rest_risk_an_empty_key_of_another_program_after_a_crash_is_deleted() {
    let env = Env::new(finish(reg_base()));
    let before = snap_all(&env);
    let h = plan_all(&env, &rt1_steps());
    let r = env.apply_armed(&h, |fx| {
        // The first `create` of a key is op 5's (`Software\New`).
        fx.fault(
            Prim::Reg(RegPrim::Create),
            1,
            crate::sys::fake::Fault::CrashAfter,
        );
    });
    assert!(r.is_err(), "{r:?}");
    env.sys.restart();
    let reg = env.sys.fake_registry();
    reg.remove_key(&hkcu(r"Software\New")).unwrap();
    assert!(
        reg.put_key(&hkcu(r"Software\New")).unwrap(),
        "another program's key"
    );
    let open: Vec<TxnId> = env.states().into_iter().map(|(t, _)| t).collect();
    assert_eq!(open.len(), 1);
    let rep = env.revert(&open[0]).unwrap();
    assert_eq!(rep.closed, Some(Closing::RolledBack), "{rep:?}");
    assert!(
        !key_exists(&env.sys, r"Software\New"),
        "deleted: the rest risk"
    );
    same(&before, &snap_all(&env));
}

/// R-T3, 6a: a key appears between the check and `create_key` (another program): `false`,
/// `Mismatch`, the key stays (never deleted); only forget closes. As a check for K-R7.
pub(crate) fn t3_key_check() -> Vec<String> {
    let mut f = Vec::new();
    let env = Env::new(finish(reg_base()));
    let h = plan_all(&env, &rt1_steps());
    // Before Rerun's first `create` (op 5, `Software\New`), another program creates it.
    let fired = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let f2 = std::sync::Arc::clone(&fired);
    env.sys.fake_registry().on_step(move |r, call| {
        if call == RegPrim::Create && !f2.swap(true, std::sync::atomic::Ordering::SeqCst) {
            r.put_key(&hkcu(r"Software\New")).unwrap();
        }
    });
    let r = env.apply(&h);
    env.sys.fake_registry().clear_on_step();
    let txn = match r {
        Err(ApplyError::LeftOpen { txn, cause, .. }) if matches!(&*cause, ExecError::Op { op: 5, source } if source.kind == SysErrorKind::Mismatch) => {
            txn
        }
        other => {
            f.push(format!("T3 key apply: {other:?}"));
            match &other {
                Err(ApplyError::LeftOpen { txn, .. } | ApplyError::RolledBack { txn, .. }) => *txn,
                Ok(Outcome::Applied(t)) => *t,
                _ => return f,
            }
        }
    };
    if !key_exists(&env.sys, r"Software\New") {
        f.push("T3 key kept: the other program's key was deleted".to_owned());
    }
    if let Ok(rep) = env.revert(&txn)
        && rep.closed.is_some()
    {
        f.push(format!("T3 key revert closed: {rep:?}"));
    }
    if !key_exists(&env.sys, r"Software\New") {
        f.push("T3 key kept after revert: deleted".to_owned());
    }
    f
}

#[test]
fn r_t3_a_key_created_by_another_program_is_never_deleted() {
    let f = t3_key_check();
    assert!(f.is_empty(), "{f:#?}");
}

/// K-R7: `create_key == false` taken as Rerun's own key deletes the other program's key;
/// the check reports it.
#[test]
fn k_r7_an_existing_key_taken_as_own_breaks_t3_key() {
    super::reg::KNOB_EXISTED_AS_OWN.with(|k| k.set(true));
    let f = t3_key_check();
    super::reg::KNOB_EXISTED_AS_OWN.with(|k| k.set(false));
    assert!(
        f.iter().any(|x| x.starts_with("T3 key kept")),
        "K-R7 not caught: {f:#?}"
    );
}

/// R-T3, the other results of `create_key` in the rollback: its flags failing right after the
/// create (`Unknown`: the empty key is deleted), `done` failing after `true` (`Created`:
/// deleted). Both roll back to the state before.
#[test]
fn r_t3_the_rollback_uses_the_result_of_create_key() {
    // Count the `Flags` calls up to and including the first `Create`.
    let env = Env::new(finish(reg_base()));
    let h = plan_all(&env, &rt1_steps());
    let calls = {
        let fx = env.sys.fake_fs();
        let t = match env.apply_armed(&h, |f| f.record_calls(true)) {
            Ok(Outcome::Applied(t)) => t,
            other => panic!("{other:?}"),
        };
        fx.record_calls(false);
        let c = fx.take_calls();
        assert!(closed(&env.revert(&t)).is_some());
        c
    };
    let create = calls
        .iter()
        .position(|c| *c == Prim::Reg(RegPrim::Create))
        .unwrap();
    let flags_after = calls[..=create]
        .iter()
        .filter(|c| **c == Prim::Reg(RegPrim::Flags))
        .count()
        + 1;
    let creates_tmp = calls[..=create]
        .iter()
        .filter(|c| **c == Prim::CreateTmp)
        .count()
        + 1;
    let arms: [(&str, Prim, usize); 2] = [
        (
            "flags fail after the create",
            Prim::Reg(RegPrim::Flags),
            flags_after,
        ),
        ("done fails after true", Prim::CreateTmp, creates_tmp),
    ];
    for (what, call, nth) in arms {
        let env = Env::new(finish(reg_base()));
        let before = snap_all(&env);
        let h = plan_all(&env, &rt1_steps());
        let r = env.apply_armed(&h, |fx| fx.fail_at(call, nth, SysErrorKind::Other));
        let Err(ApplyError::RolledBack { txn, cause, .. }) = &r else {
            panic!("{what}: {r:?}");
        };
        // Review nit 4: the failure is op 5's (its call, or its `Done` record).
        match &**cause {
            ExecError::Op { op, .. } => assert_eq!(*op, 5, "{what}: {cause:?}"),
            ExecError::Journal(_) => {
                let a = app(&env.sys);
                let j = Journal::new(&a, InstanceTag::fixed(5));
                let v = j.load(txn, VerifyBackups::Length).unwrap();
                assert_eq!(v.ops.keys().max(), Some(&5), "{what}");
                assert!(v.ops[&5].done.is_none(), "{what}");
            }
            other => panic!("{what}: {other:?}"),
        }
        assert!(!key_exists(&env.sys, r"Software\New"), "{what}: deleted");
        same(&before, &snap_all(&env));
    }
}

/// R-T7: stacking and LIFO with registry objects.
#[test]
fn r_t7_stacking_and_lifo() {
    // T1 creates a key and a value, T2 sets a value below it: revert T1 is `Later(T2)`.
    let env = Env::new(finish(reg_base()));
    let before = snap_all(&env);
    let t1 = env.applied(&plan_all(
        &env,
        &[step(&format!(r"HKCU\{SUB}"), vec![dword("A", 1)])],
    ));
    let t2 = env.applied(&plan_all(
        &env,
        &[step(&format!(r"HKCU\{SUB}"), vec![dword("C", 1)])],
    ));
    assert!(matches!(
        env.revert(&t1),
        Err(ExecError::Refused(Refusal::Later { txn })) if txn == t2
    ));
    assert_eq!(closed(&env.revert(&t2)), Some(Closing::Reverted));
    assert_eq!(closed(&env.revert(&t1)), Some(Closing::Reverted));
    same(&before, &snap_all(&env));

    // The same value in T1 and T2 (T2.old = T1.new): LIFO, identical.
    let env = Env::new(finish(reg_base()));
    let before = snap_all(&env);
    let k = format!(r"HKCU\{VENDOR_GAME}");
    let t1 = env.applied(&plan_all(&env, &[step(&k, vec![dword("TypeChange", 2)])]));
    let mid = snap_all(&env);
    let t2 = env.applied(&plan_all(
        &env,
        &[step(&k, vec![sz("TypeChange", "three")])],
    ));
    assert!(matches!(
        env.revert(&t1),
        Err(ExecError::Refused(Refusal::Later { txn })) if txn == t2
    ));
    assert_eq!(closed(&env.revert(&t2)), Some(Closing::Reverted));
    same(&mid, &snap_all(&env));
    assert_eq!(closed(&env.revert(&t1)), Some(Closing::Reverted));
    same(&before, &snap_all(&env));

    // An open T1 (crashed after creating its keys) blocks an apply on a value in its key.
    let env = Env::new(finish(reg_base()));
    let h1 = plan_all(&env, &[step(&format!(r"HKCU\{SUB}"), vec![dword("A", 1)])]);
    let r = env.apply_armed(&h1, |fx| {
        fx.fault(
            Prim::Reg(RegPrim::SetValue),
            1,
            crate::sys::fake::Fault::CrashAfter,
        );
    });
    assert!(r.is_err());
    env.sys.restart();
    let h2 = plan_all(&env, &[step(&format!(r"HKCU\{SUB}"), vec![dword("C", 1)])]);
    assert!(
        matches!(
            env.apply(&h2),
            Err(ApplyError::Refused(Refusal::Interrupted { .. }))
        ),
        "an open transaction blocks its keys"
    );
    // A value elsewhere is not blocked.
    let h3 = plan_all(
        &env,
        &[step(
            &format!(r"HKCU\{VENDOR_GAME}"),
            vec![dword("Other", 1)],
        )],
    );
    assert!(matches!(env.apply(&h3), Ok(Outcome::Applied(_))));
}

/// R-T8: refusals of a pure registry plan before anything is written: the game running (its
/// main executable held), the main executable deleted, a value or key changed since the plan,
/// a link planted on the way, an elevated process. And a revert in an elevated process (S2).
#[test]
fn r_t8_refusals_write_no_transaction() {
    let steps = || {
        vec![
            step(&format!(r"HKCU\{SUB}"), vec![dword("A", 1)]),
            step(
                &format!(r"HKCU\{VENDOR_GAME}"),
                vec![dword("TypeChange", 2)],
            ),
        ]
    };
    type Make = fn(&Env);
    type Want = fn(&Refusal) -> bool;
    let cases: Vec<(&str, Make, Want)> = vec![
        (
            "the game runs",
            |env| {
                std::mem::forget(
                    env.sys
                        .fake_fs()
                        .map_image_as(4242, Path::new(&game("game.exe")))
                        .unwrap(),
                );
            },
            |r| matches!(r, Refusal::Busy(s) if s.as_str().ends_with("game.exe")),
        ),
        (
            "the main executable deleted",
            |env| {
                env.sys
                    .fake_fs()
                    .remove_abs(Path::new(&game("game.exe")))
                    .unwrap();
            },
            |r| matches!(r, Refusal::MainExe(_)),
        ),
        (
            "a value changed since the plan",
            |env| {
                env.sys
                    .fake_registry()
                    .put_value(
                        &hkcu(VENDOR_GAME),
                        "TypeChange",
                        &RegValue::String("other".into()),
                    )
                    .unwrap();
            },
            |r| matches!(r, Refusal::Mismatch { op: 4 }),
        ),
        (
            "a key created since the plan",
            |env| {
                env.sys
                    .fake_registry()
                    .put_key_all(&hkcu(r"Software\New"))
                    .unwrap();
            },
            |r| matches!(r, Refusal::Mismatch { op: 0 }),
        ),
        (
            "a link planted on the way",
            |env| {
                let r = env.sys.fake_registry();
                r.put_key_all(&hkcu(r"Software\Elsewhere")).unwrap();
                r.link(&hkcu(r"Software\New"), &hkcu(r"Software\Elsewhere"))
                    .unwrap();
            },
            |r| matches!(r, Refusal::Registry { op: 0, source } if source.kind == SysErrorKind::ReparsePoint),
        ),
        (
            "elevated",
            |env| env.sys.fake_registry().set_elevated(true),
            |r| matches!(r, Refusal::Elevated),
        ),
    ];
    for (what, make, want) in cases {
        let env = Env::new(finish(reg_base()));
        let h = plan_all(&env, &steps());
        make(&env);
        let before = snap_keys(&env.sys);
        // P2-13 (review S1): `check` refuses alike.
        let c = env.check(&h);
        match env.apply(&h) {
            Err(ApplyError::Refused(r)) => {
                assert!(want(&r), "{what}: {r:?}");
                assert_eq!(
                    c.as_ref().err().map(ToString::to_string),
                    Some(r.to_string()),
                    "{what}: check"
                );
            }
            other => panic!("{what}: {other:?}"),
        }
        assert!(env.states().is_empty(), "{what}: no transaction folder");
        same(&before, &snap_keys(&env.sys));
    }
    // S2 in the revert: refused before the first record.
    let env = Env::new(finish(reg_base()));
    let t = env.applied(&plan_all(&env, &steps()));
    let n = records(&env, &t);
    env.sys.fake_registry().set_elevated(true);
    let r = env.revert(&t);
    assert!(
        matches!(r, Err(ExecError::Refused(Refusal::Elevated))),
        "{r:?}"
    );
    assert_eq!(records(&env, &t), n, "no record");
    env.sys.fake_registry().set_elevated(false);
    assert_eq!(closed(&env.revert(&t)), Some(Closing::Reverted));
}

/// R-H1 as a check: a mixed plan whose manual root was moved away. The revert reverts every
/// registry op and halts at the newest file op without a record; `verify` shows the same;
/// with the folder back the revert closes and everything is as before. K-R9 asks for its
/// finding.
pub(crate) fn h1_check() -> Vec<String> {
    let mut f = Vec::new();
    let env = Env::new(finish(reg_base()));
    let before = snap_all(&env);
    let t = env.applied(&plan_all(&env, &rt1_steps()));
    env.sys.rename_abs(GAME, r"D:\Games\Away").unwrap();
    match env.verified(&t) {
        Ok(v)
            if v.halted.as_ref().is_some_and(|h| h.op == 4)
                && v.ops.iter().map(|(k, _)| *k).collect::<Vec<_>>()
                    == (5..11).collect::<Vec<u16>>() => {}
        other => f.push(format!("H1 verify: {other:?}")),
    }
    match env.revert(&t) {
        Ok(rep)
            if rep.closed.is_none()
                && rep
                    .halted
                    .as_ref()
                    .is_some_and(|h| h.op == 4 && h.root == 0)
                && rep.ops.iter().map(|o| o.op).collect::<Vec<_>>()
                    == (5..11).rev().collect::<Vec<u16>>() => {}
        other => f.push(format!("H1 halted: {other:?}")),
    }
    if key_exists(&env.sys, r"Software\New")
        || value(&env.sys, VENDOR_GAME, "TypeChange") != Some(RegValue::String("text".into()))
    {
        f.push("H1 registry reverted".to_owned());
    }
    env.sys.rename_abs(r"D:\Games\Away", GAME).unwrap();
    match env.revert(&t) {
        Ok(rep) if rep.closed == Some(Closing::Reverted) => {}
        other => f.push(format!("H1 resumed: {other:?}")),
    }
    let now = snap_all(&env);
    if before != now {
        f.push(format!("H1 snapshot: {:#?}", before.diff(&now)));
    }
    f
}

#[test]
fn r_h1_a_mixed_plan_reverts_the_registry_and_halts_at_the_files() {
    let f = h1_check();
    assert!(f.is_empty(), "{f:#?}");
}

/// K-R9 for a mixed plan: every root opened eagerly refuses instead of reverting the registry
/// ops; H1's check reports it.
#[test]
fn k_r9_opening_every_root_eagerly_breaks_h1() {
    super::knob::open_eagerly(true);
    let f = h1_check();
    super::knob::open_eagerly(false);
    assert!(
        f.iter().any(|x| x.starts_with("H1 halted:")),
        "K-R9 not caught: {f:#?}"
    );
}

/// R-H2, R-H3 (user decision E3: undecided refuses before any change, the registry ops
/// included): a Steam update pending, and a folder that is another one now
/// (`IdentityMismatch`). The records stay unchanged; once the update has finished, the revert
/// closes. A root the user cannot write (absent from file ops, D4 still asked) halts after the
/// registry ops (6b-d).
#[test]
fn r_h2_h3_undecided_roots_refuse_and_a_read_only_root_halts_after_the_registry() {
    let mixed = || {
        vec![
            Step::FileInstall(spec(vec![entry("new.dll", "new.dll", N)])),
            step(&format!(r"HKCU\{SUB}"), vec![dword("A", 1)]),
        ]
    };
    // H2: update pending.
    let env = Env::new(steam_sys());
    let fr = fr(&env.sys);
    let store_dir = StoreDir::open(&env.sys, &fr, Path::new(STEAM_LIB)).unwrap();
    let g = store_dir.game(&fr, "G").unwrap();
    let t = env.applied(&plan_for(&env, &g, Some(220), &mixed()));
    drop(g);
    let n = records(&env, &t);
    let set_flags = |env: &Env, flags: u32| {
        env.sys
            .fake_fs()
            .remove_abs(Path::new(&manifest(220)))
            .unwrap();
        sys_put(&env.sys, &manifest(220), acf(220, flags).as_bytes());
    };
    set_flags(&env, 4 | 2);
    let r = env.revert(&t);
    assert!(
        matches!(
            &r,
            Err(ExecError::Refused(Refusal::Steam { app_id: 220, .. }))
        ),
        "{r:?}"
    );
    assert_eq!(records(&env, &t), n, "H2: no record");
    assert!(key_exists(&env.sys, SUB), "H2: the registry op waits too");
    set_flags(&env, 4);
    assert_eq!(closed(&env.revert(&t)), Some(Closing::Reverted));
    assert!(!key_exists(&env.sys, r"Software\New"));

    // H3: another folder now.
    let env = Env::new(finish(reg_base()));
    let t = env.applied(&plan_all(&env, &mixed()));
    let n = records(&env, &t);
    env.sys.rename_abs(GAME, r"D:\Games\Moved").unwrap();
    env.sys.fake_fs().mkdir_all(Path::new(GAME)).unwrap();
    let r = env.revert(&t);
    assert!(
        matches!(&r, Err(ExecError::Refused(Refusal::Root(e))) if matches!(**e, crate::policy::root::RootError::IdentityMismatch { .. })),
        "{r:?}"
    );
    assert_eq!(records(&env, &t), n, "H3: records unchanged");
    assert!(key_exists(&env.sys, SUB));

    // A root the user cannot write: the registry ops are reverted, the file op halts.
    let env = Env::new(finish(reg_base()));
    let t = env.applied(&plan_all(&env, &mixed()));
    env.sys
        .fake_fs()
        .set_user_writable(Path::new(GAME), false)
        .unwrap();
    let rep = env.revert(&t).unwrap();
    assert!(
        rep.halted
            .as_ref()
            .is_some_and(|h| h.op == 0 && matches!(*h.why, Refusal::NeedsHelper)),
        "{rep:?}"
    );
    assert!(!key_exists(&env.sys, r"Software\New"));
    env.sys
        .fake_fs()
        .set_user_writable(Path::new(GAME), true)
        .unwrap();
    assert_eq!(closed(&env.revert(&t)), Some(Closing::Reverted));
}

/// R-T3, `NotWritten` (review N3): another program writes our new value between the apply's
/// read and its `set`; `set` refuses (`Mismatch`, nothing written), so the new value there is
/// not Rerun's: the rollback finds it `Foreign` and leaves it, never "restores" over it.
#[test]
fn r_t3_a_value_another_program_wrote_before_our_set_is_left() {
    let env = Env::new(finish(reg_base()));
    let h = plan_all(
        &env,
        &[step(
            &format!(r"HKCU\{VENDOR_GAME}"),
            vec![dword("TypeChange", 2)],
        )],
    );
    let fired = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let f2 = std::sync::Arc::clone(&fired);
    // The first kernel-name check is the one of `set`, after the apply's own read.
    env.sys.fake_registry().on_step(move |r, call| {
        if call == RegPrim::KernelName && !f2.swap(true, std::sync::atomic::Ordering::SeqCst) {
            r.put_value(&hkcu(VENDOR_GAME), "TypeChange", &RegValue::Dword(2))
                .unwrap();
        }
    });
    let r = env.apply(&h);
    env.sys.fake_registry().clear_on_step();
    assert!(fired.load(std::sync::atomic::Ordering::SeqCst));
    let Err(ApplyError::LeftOpen { txn, cause, .. }) = r else {
        panic!("{r:?}");
    };
    assert!(
        matches!(&*cause, ExecError::Op { op: 0, source } if source.kind == SysErrorKind::Mismatch),
        "{cause:?}"
    );
    assert_eq!(
        value(&env.sys, VENDOR_GAME, "TypeChange"),
        Some(RegValue::Dword(2))
    );
    assert!(env.revert(&txn).is_ok_and(|r| r.closed.is_none()));
    assert_eq!(
        value(&env.sys, VENDOR_GAME, "TypeChange"),
        Some(RegValue::Dword(2))
    );
}

/// R-T5, the record form of registry ops (senior-dev should-item 1): records that are
/// grammatical but do not fit the op's planned old value or kind are `Blocked` for revert and
/// verify, nothing written.
#[test]
fn r_t5_records_that_do_not_fit_a_registry_op_are_blocked() {
    use crate::journal::tests::{RecordEdit, append_semantic_revert_intent, rewrite};
    use crate::journal::{Before, Digest};
    type Tamper = fn(&Env, &str);
    let edit = |env: &Env, dir: &str, f: fn(&mut RecordEdit)| {
        rewrite(env.sys.fake_fs(), dir, None, f);
    };
    // Op 10 of R-T1 replaces a small value (inline), op 8 sets a new one, op 5 creates a key;
    // op 0 of `big` replaces a 20 KiB value (`.bin`).
    let cases: [(&str, bool, Tamper); 8] = [
        ("Bin with another digest", true, |env, dir| {
            rewrite(env.sys.fake_fs(), dir, None, |e| {
                e.intent_before(
                    0,
                    Some(Before::Bin(Digest {
                        sha256: [9; 32],
                        len: u64::try_from(BIG).unwrap(),
                    })),
                );
            });
        }),
        ("Inline above 16 KiB", true, |env, dir| {
            rewrite(env.sys.fake_fs(), dir, None, |e| {
                e.intent_before(0, Some(Before::Inline(vec![7; BIG])));
            });
        }),
        ("Bin at 16 KiB or less", false, |_, _| {}),
        ("before on a CreateKey", false, |env, dir| {
            rewrite(env.sys.fake_fs(), dir, None, |e| {
                e.intent_before(5, Some(Before::Inline(vec![1])));
            });
        }),
        ("before on a new value", false, |env, dir| {
            rewrite(env.sys.fake_fs(), dir, None, |e| {
                e.intent_before(8, Some(Before::Inline(vec![1])));
            });
        }),
        ("a file ID on a registry op", false, |env, dir| {
            rewrite(env.sys.fake_fs(), dir, None, |e| e.done_file_id(5, 1));
        }),
        ("a temp name on a registry op", false, |env, dir| {
            rewrite(env.sys.fake_fs(), dir, None, |e| {
                e.intent_tmp(8, crate::sys::fs::TmpName::new(0x77, 1));
            });
        }),
        ("from/to on a registry op", false, |env, dir| {
            append_semantic_revert_intent(env.sys.fake_fs(), dir, 10);
        }),
    ];
    for (what, big, tamper) in cases {
        let env = Env::new(finish(reg_base()));
        let steps = if big {
            vec![step(&format!(r"HKCU\{VENDOR_GAME}"), vec![dword("Big", 1)])]
        } else {
            rt1_steps()
        };
        let t = env.applied(&plan_all(&env, &steps));
        let dir = env.txn_dir(&t);
        if what == "Bin at 16 KiB or less" {
            edit(&env, &dir, |e| {
                let old = RegValue::String("text".into()).encode().unwrap().1;
                e.intent_before(
                    10,
                    Some(Before::Bin(Digest {
                        sha256: crate::plan::tests::sha(&old),
                        len: u64::try_from(old.len()).unwrap(),
                    })),
                );
            });
        } else {
            tamper(&env, &dir);
        }
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
}

/// Resets a test knob when dropped, also when a check panics.
pub(crate) struct Reset(pub(crate) fn());

impl Drop for Reset {
    fn drop(&mut self) {
        (self.0)();
    }
}

/// R-L8 for `registry_set` (P2-11, user decision E4; the rule half of ADR 0018 open point S1)
/// as a check: a rule for new values tightened after the apply (the `REG_SZ` limit, from 1,024
/// down to 3 units) does not block the applied transaction: `verify` sees it, a later apply on
/// another value is not `Blocked` by it, the revert restores everything exactly; the same plan
/// applied again is refused (the apply decodes with the current rules).
pub(crate) fn l8_set_check() -> Vec<String> {
    use crate::policy::registry::KNOB_MAX_SZ;
    let mut f = Vec::new();
    let _reset = Reset(|| KNOB_MAX_SZ.with(|c| c.set(None)));
    let env = Env::new(finish(reg_base()));
    let before = snap_all(&env);
    let h = plan_all(
        &env,
        &[step(&format!(r"HKCU\{SUB}"), vec![sz("B", "english")])],
    );
    let t = env.applied(&h);
    KNOB_MAX_SZ.with(|c| c.set(Some(3)));
    match env.try_verify(&t) {
        Ok(v) if v.iter().all(|(_, o)| *o == Observed::After) => {}
        other => f.push(format!("RL8 verify under the tightened rule: {other:?}")),
    }
    let other = plan_all(
        &env,
        &[step(
            &format!(r"HKCU\{VENDOR_GAME}"),
            vec![dword("Other", 1)],
        )],
    );
    match env.apply(&other) {
        Ok(Outcome::Applied(t2)) => {
            if closed(&env.revert(&t2)) != Some(Closing::Reverted) {
                f.push("RL8 the other transaction did not revert".to_owned());
            }
        }
        r => f.push(format!("RL8 an apply on another value: {r:?}")),
    }
    match env.revert(&t) {
        Ok(r) if r.closed == Some(Closing::Reverted) => {}
        r => f.push(format!("RL8 revert under the tightened rule: {r:?}")),
    }
    let now = snap_all(&env);
    if before != now {
        f.push(format!("RL8 snapshot: {:#?}", before.diff(&now)));
    }
    if !matches!(
        env.apply(&h),
        Err(ApplyError::Refused(Refusal::Plan(
            plan::PlanError::Registry { .. }
        )))
    ) {
        f.push("RL8 the same plan applied again under the tightened rule".to_owned());
    }
    f
}

#[test]
fn r_l8_a_tightened_rule_never_blocks_the_revert_of_a_registry_set() {
    let f = l8_set_check();
    assert!(f.is_empty(), "{f:#?}");
}

/// K-L3: decoding a recorded head with the current rules (as before P2-11) fails R-L8.
#[test]
fn k_l3_recorded_heads_decoded_with_current_rules_break_l8() {
    let _reset = Reset(|| super::knob::current_for_recorded(false));
    super::knob::current_for_recorded(true);
    let f = l8_set_check();
    assert!(
        f.iter()
            .any(|x| x.starts_with("RL8 revert under the tightened rule")),
        "{f:#?}"
    );
    assert!(
        f.iter()
            .any(|x| x.starts_with("RL8 an apply on another value")),
        "{f:#?}"
    );
}
