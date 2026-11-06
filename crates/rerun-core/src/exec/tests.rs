//! `exec` against the fake (P2-8): T1 round trip, T2 verify, T3 a failure at every call, T5
//! tampering, T6 foreign states, T7 stacking and LIFO, T8 refusals without a transaction.
//! Crashes and power losses: `crash_tests.rs`.

use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use super::{
    ApplyError, ExecCtx, ExecError, Outcome, Refusal, RevertReport, apply, forget, revert, verify,
};
use crate::detect::steam::AppState;
use crate::journal::{Closing, InstanceTag, Journal, Observed, TxnId, TxnState};

use crate::plan::{PlanHash, store};
use crate::policy::root::{GameDir, StoreDir};
use crate::prim::tests::{GAME, PKG, STEAM_GAME, STEAM_LIB, app, builder, entry, fr, rel, spec};
use crate::prim::{FileInstallSpec, PlanCtx, Step, plan as plan_steps};
use crate::sys::fake::{FakeSystem, FakeSystemBuilder, Prim};
use crate::sys::fs::Attrs;
use crate::sys::snapshot::{Scope, SnapRoot, Snapshot, snapshot};
use crate::sys::{Fs, SysErrorKind, System};

pub(crate) const OLD: &[u8] = b"old d3d9 of the game";
pub(crate) const NEW: &[u8] = b"new d3d9 of the package";
pub(crate) const X: &[u8] = b"x.dll of the package";
pub(crate) const N: &[u8] = b"new.dll of the package";
pub(crate) const RH: Attrs = Attrs {
    readonly: true,
    hidden: true,
    system: false,
};

pub(crate) fn pkg(name: &str) -> String {
    format!(r"{PKG}\{name}")
}

pub(crate) fn game(name: &str) -> String {
    format!(r"{GAME}\{name}")
}

/// Package files and a game folder with a read-only, hidden `d3d9.dll` and `game.exe`.
pub(crate) fn base() -> FakeSystemBuilder {
    builder()
        .file(pkg("d3d9.dll"), NEW.to_vec())
        .file(pkg(r"mods\x.dll"), X.to_vec())
        .file(pkg("new.dll"), N.to_vec())
        .file(game("d3d9.dll"), OLD.to_vec())
        .file(game("game.exe"), b"MZ".to_vec())
}

pub(crate) fn finish(b: FakeSystemBuilder) -> FakeSystem {
    let sys = b.build().unwrap();
    sys.fake_fs()
        .set_attrs(Path::new(&game("d3d9.dll")), RH)
        .unwrap();
    sys.fake_fs().sync_all();
    sys
}

/// T1: a replace over a read-only, hidden target, two nested folders, two new files.
pub(crate) fn t1_spec() -> FileInstallSpec {
    spec(vec![
        entry("d3d9.dll", "d3d9.dll", NEW),
        entry(r"mods\x.dll", r"mods\a\x.dll", X),
        entry("new.dll", "new.dll", N),
    ])
}

/// A fresh instance tag per call (temp names never repeat between runs, as in the product).
static TAG: AtomicU64 = AtomicU64::new(0xe000);

/// One test system and the calls on it.
pub(crate) struct Env {
    pub(crate) sys: FakeSystem,
}

impl Env {
    pub(crate) fn new(sys: FakeSystem) -> Self {
        Self { sys }
    }

    pub(crate) fn with<R>(&self, f: impl FnOnce(&ExecCtx<'_>) -> R) -> R {
        let fr = fr(&self.sys);
        let app = app(&self.sys);
        let cx = ExecCtx {
            sys: &self.sys,
            fr: &fr,
            app: &app,
            tag: InstanceTag::fixed(TAG.fetch_add(1, Ordering::Relaxed)),
        };
        f(&cx)
    }

    /// Plans `s` for the manual game folder and stores it.
    pub(crate) fn plan(&self, s: &FileInstallSpec) -> PlanHash {
        let fr = fr(&self.sys);
        let g = GameDir::open_manual(&self.sys, &fr, Path::new(GAME)).unwrap();
        self.plan_for(&g, None, s)
    }

    pub(crate) fn plan_for(
        &self,
        g: &GameDir<'_>,
        steam_app: Option<u32>,
        s: &FileInstallSpec,
    ) -> PlanHash {
        let app = app(&self.sys);
        let main = rel("game.exe");
        let p = plan_steps(
            &[Step::FileInstall(s.clone())],
            &PlanCtx {
                game: g,
                app: &app,
                steam_app,
                main_exe: Some(&main),
            },
        )
        .unwrap_or_else(|e| panic!("{e}"));
        store(&app, &p.encode().unwrap()).unwrap()
    }

    pub(crate) fn apply(&self, h: &PlanHash) -> Result<Outcome, ApplyError> {
        self.with(|cx| apply(cx, h))
    }

    /// `apply` with `arm` run on the fake right before it (after `AppDir` and the forbidden
    /// list are opened, so faults and recorded calls are those of `apply` alone; the call
    /// counts start there).
    pub(crate) fn apply_armed(
        &self,
        h: &PlanHash,
        arm: impl FnOnce(&crate::sys::fake::FakeFs),
    ) -> Result<Outcome, ApplyError> {
        self.with(|cx| {
            let fx = self.sys.fake_fs();
            fx.clear_faults();
            arm(fx);
            apply(cx, h)
        })
    }

    /// `revert` like [`Self::apply_armed`].
    pub(crate) fn revert_armed(
        &self,
        t: &TxnId,
        arm: impl FnOnce(&crate::sys::fake::FakeFs),
    ) -> Result<RevertReport, ExecError> {
        self.with(|cx| {
            let fx = self.sys.fake_fs();
            fx.clear_faults();
            arm(fx);
            revert(cx, t)
        })
    }

    pub(crate) fn applied(&self, h: &PlanHash) -> TxnId {
        match self.apply(h) {
            Ok(Outcome::Applied(t)) => t,
            other => panic!("apply: {other:?}"),
        }
    }

    pub(crate) fn revert(&self, t: &TxnId) -> Result<RevertReport, ExecError> {
        self.with(|cx| revert(cx, t))
    }

    pub(crate) fn verify(&self, t: &TxnId) -> Vec<(u16, Observed)> {
        self.try_verify(t).unwrap_or_else(|e| panic!("{e}"))
    }

    /// The ops `verify` observed; a halt (not expected by the callers) is an error.
    pub(crate) fn try_verify(&self, t: &TxnId) -> Result<Vec<(u16, Observed)>, ExecError> {
        let v = self.verified(t)?;
        match v.halted {
            None => Ok(v.ops),
            Some(h) => Err(ExecError::Refused(*h.why)),
        }
    }

    pub(crate) fn verified(&self, t: &TxnId) -> Result<super::Verified, ExecError> {
        self.with(|cx| verify(cx, t))
    }

    pub(crate) fn forget(&self, t: &TxnId) -> Result<(), ExecError> {
        self.with(|cx| forget(cx, t))
    }

    /// The game folder [`GAME`] as the round trip compares it.
    pub(crate) fn snap(&self) -> Snapshot {
        snap_at(&self.sys, GAME)
    }

    /// Every transaction with its state (`None` for an unreadable one).
    pub(crate) fn states(&self) -> Vec<(TxnId, Option<TxnState>)> {
        let app = app(&self.sys);
        let j = Journal::new(&app, InstanceTag::fixed(1));
        j.list()
            .unwrap()
            .txns
            .into_iter()
            .map(|l| (l.id, l.view.ok().map(|v| v.state)))
            .collect()
    }

    pub(crate) fn state(&self, t: &TxnId) -> Option<TxnState> {
        self.states()
            .into_iter()
            .find(|(i, _)| i == t)
            .and_then(|(_, s)| s)
    }

    /// The path of transaction `t`'s folder.
    pub(crate) fn txn_dir(&self, t: &TxnId) -> String {
        format!(r"{}\Rerun\journal\{t}", crate::journal::tests::LAD)
    }
}

pub(crate) fn snap_at(sys: &FakeSystem, abs: &str) -> Snapshot {
    let fr = fr(sys);
    let g = GameDir::open_manual(sys, &fr, Path::new(abs)).unwrap();
    snapshot(
        sys.registry(),
        &Scope {
            dirs: vec![SnapRoot::new(g.dir(), abs)],
            keys: Vec::new(),
        },
    )
    .unwrap()
}

pub(crate) fn same(a: &Snapshot, b: &Snapshot) {
    assert!(a == b, "not identical: {:#?}", a.diff(b));
}

pub(crate) fn closed(r: &Result<RevertReport, ExecError>) -> Option<Closing> {
    r.as_ref().ok().and_then(|r| r.closed)
}

fn ops_of(v: &[(u16, Observed)]) -> Vec<Observed> {
    v.iter().map(|(_, o)| *o).collect()
}

/// T1 as a check (audit A2 should-item 7, review N1): the scenario and its checks in one
/// function, each finding with its name (`T1 <check>: …`); empty if T1 holds. The test asks
/// for no finding, the control K3 for its finding.
pub(crate) fn t1_check() -> Vec<String> {
    let mut f = Vec::new();
    let env = Env::new(finish(base()));
    let before = env.snap();
    let h = env.plan(&t1_spec());
    let t = match env.apply(&h) {
        Ok(Outcome::Applied(t)) => t,
        other => return vec![format!("T1 apply: {other:?}")],
    };
    if env.state(&t) != Some(TxnState::Applied) {
        f.push(format!("T1 applied: {:?}", env.state(&t)));
    }
    let v = env.try_verify(&t);
    if v.as_deref().ok().map(ops_of) != Some(vec![Observed::After; 5]) {
        f.push(format!("T1 verify after apply: {v:?}"));
    }
    if try_read_abs(&env.sys, &game("d3d9.dll")).as_deref() != Some(NEW) {
        f.push("T1 new content: d3d9.dll".to_owned());
    }
    let rep = match env.revert(&t) {
        Ok(r) => r,
        Err(e) => {
            f.push(format!("T1 revert: {e}"));
            return f;
        }
    };
    if rep.closed != Some(Closing::Reverted) {
        f.push(format!("T1 closed: {:?}", rep.closed));
    }
    if rep.ops.len() != 5
        || !rep
            .ops
            .iter()
            .all(|o| o.observed == Observed::After && o.left.is_empty())
    {
        f.push(format!("T1 reverted ops: {:?}", rep.ops));
    }
    if rep.ops.iter().map(|o| o.op).collect::<Vec<_>>() != [4, 3, 2, 1, 0] {
        f.push(format!("T1 newest first: {:?}", rep.ops));
    }
    let now = env.snap();
    if before != now {
        f.push(format!("T1 snapshot: {:#?}", before.diff(&now)));
    }
    if env.plan(&t1_spec()) != h {
        f.push("T1 planned again: another hash".to_owned());
    }
    let v = env.try_verify(&t);
    if v.as_deref().ok().map(ops_of) != Some(vec![Observed::Before; 5]) {
        f.push(format!("T1 verify after revert: {v:?}"));
    }
    f
}

#[test]
fn t1_round_trip_restores_the_game_folder_exactly() {
    let f = t1_check();
    assert!(f.is_empty(), "{f:#?}");
}

/// T2: `verify` names exactly the ops someone changed, and the folders above a changed one
/// that the revert must leave because they will not be empty (review S3: newest op first, a
/// created folder counts only later targets that will be gone); the revert then finds
/// exactly these foreign.
#[test]
fn t2_verify_names_exactly_the_op_someone_changed() {
    type Change = fn(&FakeSystem);
    let cases: [(&[u16], Change); 5] = [
        (&[0], |s| {
            s.fake_fs()
                .set_attrs(Path::new(&game("d3d9.dll")), RH)
                .unwrap();
        }),
        (&[1], |s| {
            s.fake_fs()
                .put_file(Path::new(&game(r"mods\extra.txt")), b"user")
                .unwrap();
        }),
        // `mods\a` stays, so `mods` will not be empty either.
        (&[1, 2], |s| {
            s.fake_fs()
                .put_file(Path::new(&game(r"mods\a\extra.txt")), b"user")
                .unwrap();
        }),
        // The edited `x.dll` stays, so do `mods\a` and `mods`.
        (&[1, 2, 3], |s| {
            let p = game(r"mods\a\x.dll");
            s.fake_fs().remove_abs(Path::new(&p)).unwrap();
            s.fake_fs().put_file(Path::new(&p), b"edited").unwrap();
        }),
        (&[4], |s| {
            s.fake_fs()
                .put_hardlink(Path::new(&game("new.dll")), Path::new(&game("link.dll")))
                .unwrap();
        }),
    ];
    for (ops, change) in cases {
        let env = Env::new(finish(base()));
        let t = env.applied(&env.plan(&t1_spec()));
        change(&env.sys);
        let v = env.verify(&t);
        let foreign: Vec<u16> = v
            .iter()
            .filter(|(_, o)| *o == Observed::Foreign)
            .map(|(k, _)| *k)
            .collect();
        assert_eq!(foreign, ops, "{v:?}");
        assert!(
            v.iter()
                .all(|(k, o)| ops.contains(k) || *o == Observed::After),
            "{v:?}"
        );
        let rep = env.revert(&t).unwrap();
        let mut met: Vec<u16> = rep
            .ops
            .iter()
            .filter(|o| o.observed == Observed::Foreign)
            .map(|o| o.op)
            .collect();
        met.sort_unstable();
        assert_eq!(met, ops, "the revert meets what verify showed: {rep:?}");
    }
}

// Reverts every transaction that is not closed; each must close.
pub(crate) fn finish_open(env: &Env, what: &str) {
    for (t, s) in env.states() {
        match s {
            Some(TxnState::Closed(_)) => {}
            // An empty one without a head (begin failed) blocks nothing and is never resumed.
            Some(TxnState::Empty)
                if !exists_abs(&env.sys, &format!(r"{}\head.json", env.txn_dir(&t))) => {}
            Some(TxnState::Empty | TxnState::Open | TxnState::Applied) => {
                let r = env.revert(&t);
                assert!(closed(&r).is_some(), "{what}: revert of {t}: {r:?}");
            }
            other => panic!("{what}: {t} is {other:?}"),
        }
    }
}

#[test]
fn t3_a_failure_at_any_call_rolls_back_or_leaves_it_for_revert() {
    let (apply_calls, revert_calls) = {
        let env = Env::new(finish(base()));
        let h = env.plan(&t1_spec());
        let fx = env.sys.fake_fs();
        let rec = |f: &crate::sys::fake::FakeFs| f.record_calls(true);
        let t = match env.apply_armed(&h, rec) {
            Ok(Outcome::Applied(t)) => t,
            other => panic!("{other:?}"),
        };
        fx.record_calls(false);
        let a = fx.take_calls();
        assert!(closed(&env.revert_armed(&t, rec)).is_some());
        fx.record_calls(false);
        (a, fx.take_calls())
    };
    let mut outcomes = [0usize; 5];
    let phases = [(false, &apply_calls), (true, &revert_calls)];
    for (in_revert, trace) in phases {
        for (i, call) in trace.iter().enumerate() {
            let nth = trace[..=i].iter().filter(|c| *c == call).count();
            let env = Env::new(finish(base()));
            let before = env.snap();
            let h = env.plan(&t1_spec());
            let fx = env.sys.fake_fs();
            let what = format!(
                "fail at call {i} of the {} ({call:?} #{nth})",
                if in_revert { "revert" } else { "apply" }
            );
            let arm = |f: &crate::sys::fake::FakeFs| f.fail_at(*call, nth, SysErrorKind::Other);
            if in_revert {
                let t = env.applied(&h);
                match env.revert_armed(&t, arm) {
                    Ok(r) if r.closed.is_some() => outcomes[4] += 0,
                    _ => outcomes[4] += 1,
                }
            } else {
                match env.apply_armed(&h, arm) {
                    Ok(Outcome::Applied(t)) => {
                        outcomes[0] += 1;
                        let _ = env.revert(&t);
                    }
                    Ok(Outcome::Nothing) => panic!("{what}: nothing"),
                    Err(ApplyError::Refused(_)) => outcomes[1] += 1,
                    Err(ApplyError::RolledBack { .. }) => outcomes[2] += 1,
                    Err(ApplyError::LeftOpen { .. }) => outcomes[3] += 1,
                }
            }
            fx.clear_faults();
            finish_open(&env, &what);
            assert!(
                before == env.snap(),
                "{what}: {:#?}",
                before.diff(&env.snap())
            );
            assert!(
                env.states()
                    .iter()
                    .all(|(_, s)| matches!(s, Some(TxnState::Closed(_) | TxnState::Empty))),
                "{what}: {:?}",
                env.states()
            );
        }
    }
    eprintln!(
        "T3 fail_at: {} + {} calls; applied {}, refused {}, rolled back {}, left open {}, revert failed {}",
        apply_calls.len(),
        revert_calls.len(),
        outcomes[0],
        outcomes[1],
        outcomes[2],
        outcomes[3],
        outcomes[4]
    );
    assert!(
        [outcomes[1], outcomes[2], outcomes[4]]
            .iter()
            .all(|n| *n > 0),
        "{outcomes:?}"
    );

    // A failure that the rollback meets too: left open, a later revert finishes it.
    let last_tmp = apply_calls
        .iter()
        .filter(|c| **c == Prim::CreateTmp)
        .count();
    let env = Env::new(finish(base()));
    let before = env.snap();
    let h = env.plan(&t1_spec());
    let r = env.apply_armed(&h, |fx| {
        // `Applied`, then the rollback's first `RevertIntent`.
        fx.fail_at(Prim::CreateTmp, last_tmp, SysErrorKind::Other);
        fx.fail_at(Prim::CreateTmp, last_tmp + 1, SysErrorKind::Other);
    });
    let Err(ApplyError::LeftOpen { txn, .. }) = r else {
        panic!("{r:?}");
    };
    assert_eq!(env.state(&txn), Some(TxnState::Open));
    env.sys.fake_fs().clear_faults();
    assert_eq!(closed(&env.revert(&txn)), Some(Closing::RolledBack));
    same(&before, &env.snap());
}

#[test]
fn t3_rollback_uses_the_result_of_the_call_condition_4() {
    // `create_dir` finds the name taken (someone created it after the check): foreign, kept.
    let env = Env::new(finish(base()));
    let before = env.snap();
    let h = env.plan(&spec(vec![entry(r"mods\x.dll", r"mods\x.dll", X)]));
    let fx = env.sys.fake_fs().clone();
    fx.on_step(move |f, ev| {
        if ev.call == Some(Prim::CreateDir) && ev.name == "mods" {
            f.mkdir_all(Path::new(&game("mods"))).unwrap();
        }
    });
    let r = env.apply(&h);
    env.sys.fake_fs().clear_on_step();
    let Err(ApplyError::LeftOpen { txn, .. }) = r else {
        panic!("{r:?}");
    };
    assert!(exists_abs(&env.sys, &game("mods")), "never removed");
    // Only forget closes it.
    let rep = env.revert(&txn).unwrap();
    assert_eq!(rep.closed, None);
    env.forget(&txn).unwrap();
    assert_eq!(env.state(&txn), Some(TxnState::Closed(Closing::Forgotten)));
    env.sys
        .fake_fs()
        .remove_abs(Path::new(&game("mods")))
        .unwrap();
    same(&before, &env.snap());

    // `done` fails after `create_dir` succeeded: the ID from the call removes it.
    let env = Env::new(finish(base()));
    let before = env.snap();
    let h = env.plan(&spec(vec![entry(r"mods\x.dll", r"mods\x.dll", X)]));
    drop(
        Journal::new(&app(&env.sys), InstanceTag::fixed(3))
            .lock()
            .unwrap(),
    );
    // The temp files of the apply: `head.json`, the intent of op 0, then (after the folder is
    // created) its `Done`.
    let r = env.apply_armed(&h, |fx| fx.fail_at(Prim::CreateTmp, 3, SysErrorKind::Other));
    assert!(
        matches!(&r, Err(ApplyError::RolledBack { cause, .. }) if matches!(**cause, ExecError::Journal(_))),
        "{r:?}"
    );
    same(&before, &env.snap());
}

#[test]
fn t5_tampering_is_refused_or_left() {
    use crate::journal::tests::rewrite;
    // A stored plan changed after the preview.
    let env = Env::new(finish(base()));
    let h = env.plan(&t1_spec());
    let file = format!(r"{}\Rerun\plans\{h}.json", crate::journal::tests::LAD);
    let mut bytes = read_abs(&env.sys, &file);
    let fx = env.sys.fake_fs();
    let at = bytes.windows(3).position(|w| w == b"new").unwrap();
    bytes[at] = b'N';
    fx.remove_abs(Path::new(&file)).unwrap();
    fx.put_file(Path::new(&file), &bytes).unwrap();
    assert!(matches!(
        env.apply(&h),
        Err(ApplyError::Refused(Refusal::Plan(_)))
    ));
    assert!(env.states().is_empty());

    // Head and records rewritten consistently: refused, nothing written.
    let good = {
        let e = Env::new(finish(base()));
        let h = e.plan(&t1_spec());
        let t = e.applied(&h);
        read_abs(&e.sys, &format!(r"{}\head.json", e.txn_dir(&t)))
    };
    let s = String::from_utf8(good).unwrap();
    let many = {
        let one = r#"{"create_dir":{"root":0,"path":"d"}}"#;
        let ops: Vec<String> = (0..129)
            .map(|i| one.replace(r#""d""#, &format!(r#""d{i}""#)))
            .collect();
        let start = s.find(r#""ops":["#).unwrap() + 7;
        format!("{}{}]}}", &s[..start], ops.join(","))
    };
    let heads = [
        s.replacen(r"mods\\a\\x.dll", r"..\\a\\x.dll", 1),
        s.replacen(r#""root":0"#, r#""root":1"#, 1),
        many,
        s.replacen(r"D:\\Games\\G", r"D:\\Games\\Other", 1),
        s.replacen(r"D:\\Games\\G", r"C:\\Windows", 1),
    ];
    for (i, head) in heads.iter().enumerate() {
        let env = Env::new(finish(base().dir(r"D:\Games\Other")));
        let t = env.applied(&env.plan(&t1_spec()));
        let dir = env.txn_dir(&t);
        let n = rewrite(env.sys.fake_fs(), &dir, Some(head.as_bytes()), |_| {});
        let after = env.snap();
        let r = env.revert(&t);
        assert!(
            matches!(
                &r,
                Err(ExecError::Refused(
                    Refusal::Blocked { .. } | Refusal::Root(_)
                ))
            ),
            "head {i}: {r:?}"
        );
        same(&after, &env.snap());
        assert_eq!(
            rewrite(env.sys.fake_fs(), &dir, None, |_| {}),
            n,
            "head {i}: no record written"
        );
        // Also refuses to stack on it.
        if i < 3 {
            let h2 = env.plan(&spec(vec![entry("new.dll", "other.dll", N)]));
            assert!(
                matches!(
                    env.apply(&h2),
                    Err(ApplyError::Refused(Refusal::Blocked { .. }))
                ),
                "head {i}"
            );
        }
    }

    // A swapped backup: the restore is a mismatch, the target stays, the op stays open.
    let env = Env::new(finish(base()));
    let t = env.applied(&env.plan(&t1_spec()));
    let bin = format!(r"{}\op-0000.bin", env.txn_dir(&t));
    let fx = env.sys.fake_fs();
    let mut swapped = OLD.to_vec();
    swapped[0] ^= 1;
    fx.remove_abs(Path::new(&bin)).unwrap();
    fx.put_file(Path::new(&bin), &swapped).unwrap();
    let r = env.revert(&t);
    assert!(
        matches!(&r, Err(ExecError::Op { op: 0, source }) if source.kind == SysErrorKind::Mismatch),
        "{r:?}"
    );
    assert_eq!(read_abs(&env.sys, &game("d3d9.dll")), NEW);
    assert_eq!(env.state(&t), Some(TxnState::Applied));

    // `Done.file_id` of a created folder changed: foreign, the folder stays.
    let env = Env::new(finish(base()));
    let t = env.applied(&env.plan(&t1_spec()));
    rewrite(env.sys.fake_fs(), &env.txn_dir(&t), None, |e| {
        e.done_file_id(2, 0x1234);
    });
    let rep = env.revert(&t).unwrap();
    assert_eq!(rep.closed, None);
    let foreign: Vec<u16> = rep
        .ops
        .iter()
        .filter(|o| o.observed == Observed::Foreign)
        .map(|o| o.op)
        .collect();
    assert_eq!(foreign, [2, 1], "mods\\a, and mods that holds it");
    assert!(exists_abs(&env.sys, &game(r"mods\a")));
    assert!(!exists_abs(&env.sys, &game(r"mods\a\x.dll")));

    // A junction at the folder of a target: ReparsePoint, the canary unchanged.
    let env = Env::new(finish(base().file(r"C:\out\x.dll", b"canary".to_vec())));
    let t = env.applied(&env.plan(&t1_spec()));
    env.sys
        .swap_with_junction(game(r"mods\a"), r"C:\out")
        .unwrap();
    let r = env.revert(&t);
    // Refused by the game-closed check already (nothing written), or by the op itself.
    let reparse = match &r {
        Err(ExecError::Op { source, .. }) => source.kind == SysErrorKind::ReparsePoint,
        Err(ExecError::Refused(Refusal::Root(e))) => {
            matches!(&**e, crate::policy::root::RootError::Sys(s) if s.kind == SysErrorKind::ReparsePoint)
        }
        _ => false,
    };
    assert!(reparse, "{r:?}");
    assert_eq!(read_abs(&env.sys, r"C:\out\x.dll"), b"canary");
}

/// A change of T6: its name, the op it makes foreign, the change.
type T6Case = (&'static str, u16, fn(&FakeSystem));

/// The cases of T6.
const T6_CASES: [T6Case; 5] = [
    ("content", 0, |s| {
        let p = game("d3d9.dll");
        s.fake_fs().remove_abs(Path::new(&p)).unwrap();
        s.fake_fs().put_file(Path::new(&p), b"user's own").unwrap();
    }),
    ("R/H/S", 4, |s| {
        s.fake_fs()
            .set_attrs(Path::new(&game("new.dll")), RH)
            .unwrap();
    }),
    ("hard link", 0, |s| {
        s.fake_fs()
            .put_hardlink(Path::new(&game("d3d9.dll")), Path::new(&game("vortex.dll")))
            .unwrap();
    }),
    ("a file in a created folder", 2, |s| {
        s.fake_fs()
            .put_file(Path::new(&game(r"mods\a\mine.txt")), b"user")
            .unwrap();
    }),
    // A2-B1 review S1: a case-only rename is a change (ADR 0017 D3), not the planned name.
    ("another spelling", 0, |s| {
        s.rename_abs(game("d3d9.dll"), game("D3D9.DLL")).unwrap();
    }),
];

/// T6 for one case as a check (audit A2 should-item 7, review N1): the findings, each with
/// its name (`T6 <case> <check>: …`); empty if T6 holds. The control K1 asks for its finding.
pub(crate) fn t6_check(case: &T6Case) -> Vec<String> {
    let (what, op, change) = *case;
    let mut f = Vec::new();
    let env = Env::new(finish(base()));
    let t = match env.apply(&env.plan(&t1_spec())) {
        Ok(Outcome::Applied(t)) => t,
        other => return vec![format!("T6 {what} apply: {other:?}")],
    };
    change(&env.sys);
    let p = game(target(op));
    let changed = try_meta_abs(&env.sys, &p);
    let user = try_read_abs(&env.sys, &p);
    let spelled = try_stored_abs(&env.sys, &p);
    // `verify` names it before the revert meets it (rule 5).
    let v = env.try_verify(&t);
    if !v
        .as_ref()
        .is_ok_and(|v| v.iter().any(|(k, o)| *k == op && *o == Observed::Foreign))
    {
        f.push(format!("T6 {what} verify: {v:?}"));
    }
    let rep = match env.revert(&t) {
        Ok(r) => r,
        Err(e) => {
            f.push(format!("T6 {what} revert: {e}"));
            return f;
        }
    };
    if rep.closed.is_some() {
        f.push(format!("T6 {what} closed: {:?}", rep.closed));
    }
    let foreign: Vec<&super::OpReport> = rep
        .ops
        .iter()
        .filter(|o| o.observed == Observed::Foreign)
        .collect();
    // R1: the foreign op (and a folder above it) is left, every other op reverted.
    if !foreign.iter().any(|o| o.op == op) {
        f.push(format!("T6 {what} foreign op: {rep:?}"));
    }
    if !rep
        .ops
        .iter()
        .all(|o| o.observed == Observed::After || o.observed == Observed::Foreign)
    {
        f.push(format!("T6 {what} lower ops: {rep:?}"));
    }
    if op == 0 {
        let b = foreign.first().and_then(|o| o.backup.as_deref());
        if !b.is_some_and(|b| b.ends_with(r"\op-0000.bin") && exists_abs(&env.sys, b)) {
            f.push(format!("T6 {what} backup kept: {b:?}"));
        }
    }
    // The foreign object is as the user left it.
    let now = try_meta_abs(&env.sys, &p);
    let attrs =
        |m: &Option<crate::sys::fs::Metadata>| m.as_ref().map(|m| (m.attrs, m.links, m.len));
    if try_read_abs(&env.sys, &p) != user || attrs(&now) != attrs(&changed) {
        f.push(format!(
            "T6 {what} object: content, attributes, links or length not as the user left them"
        ));
    }
    if try_stored_abs(&env.sys, &p) != spelled {
        f.push(format!("T6 {what} spelling: not as the user named it"));
    }
    // Revert again: still foreign; forget closes.
    if !env.revert(&t).is_ok_and(|r| r.closed.is_none()) {
        f.push(format!("T6 {what} revert again"));
    }
    if env.forget(&t).is_err() || env.state(&t) != Some(TxnState::Closed(Closing::Forgotten)) {
        f.push(format!("T6 {what} forget: {:?}", env.state(&t)));
    }
    f
}

/// T5, the record form of P2-10a: records that are grammatical but do not fit a file op are
/// `Blocked` for revert and verify, nothing written: a `RevertIntent` with `from`/`to` (a
/// semantic revert, no op kind of P2-10 has one), a `Done` without a file ID, a replace whose
/// old state is kept inline instead of in its backup.
#[test]
fn t5_records_of_another_form_than_the_op_kind_are_blocked() {
    use crate::journal::tests::{append_semantic_revert_intent, rewrite};
    type Tamper = fn(&Env, &str);
    let cases: [(&str, Tamper); 3] = [
        ("from/to", |env, dir| {
            append_semantic_revert_intent(env.sys.fake_fs(), dir, 4);
        }),
        ("no file ID", |env, dir| {
            rewrite(env.sys.fake_fs(), dir, None, |e| e.done_without_file_id(3));
        }),
        ("inline old state", |env, dir| {
            rewrite(env.sys.fake_fs(), dir, None, |e| e.intent_inline(0, OLD));
            env.sys
                .fake_fs()
                .remove_abs(Path::new(&format!(r"{dir}\op-0000.bin")))
                .unwrap();
        }),
    ];
    for (what, tamper) in cases {
        let env = Env::new(finish(base()));
        let t = env.applied(&env.plan(&t1_spec()));
        let dir = env.txn_dir(&t);
        tamper(&env, &dir);
        let after = env.snap();
        let n = rewrite(env.sys.fake_fs(), &dir, None, |_| {});
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
        same(&after, &env.snap());
        assert_eq!(
            rewrite(env.sys.fake_fs(), &dir, None, |_| {}),
            n,
            "{what}: no record written"
        );
    }
}

#[test]
fn t6_a_foreign_state_is_left_with_its_backup_and_only_forget_closes() {
    for case in &T6_CASES {
        let f = t6_check(case);
        assert!(f.is_empty(), "{f:#?}");
    }
}

fn target(op: u16) -> &'static str {
    match op {
        0 => "d3d9.dll",
        4 => "new.dll",
        _ => r"mods\a\mine.txt",
    }
}

/// The stored spelling of the last segment of the fake entry `abs`.
pub(crate) fn stored_abs(sys: &FakeSystem, abs: &str) -> String {
    let p = Path::new(abs);
    #[expect(clippy::disallowed_methods, reason = "test: read a fixture name")]
    let d = sys.fake_fs().open_dir(p.parent().unwrap()).unwrap();
    let name = p.file_name().unwrap().to_str().unwrap();
    d.stored_name(&rel(name)).unwrap().unwrap()
}

/// The content of the fake file `abs`, `None` if it cannot be read.
pub(crate) fn try_read_abs(sys: &FakeSystem, abs: &str) -> Option<Vec<u8>> {
    let p = Path::new(abs);
    #[expect(clippy::disallowed_methods, reason = "test: read a fixture file")]
    let d = sys.fake_fs().open_dir(p.parent()?).ok()?;
    d.read(&rel(&p.file_name()?.to_string_lossy())).ok()
}

/// The metadata of the fake entry `abs`, `None` if it is missing.
pub(crate) fn try_meta_abs(sys: &FakeSystem, abs: &str) -> Option<crate::sys::fs::Metadata> {
    let p = Path::new(abs);
    #[expect(clippy::disallowed_methods, reason = "test: look at a fixture entry")]
    let d = sys.fake_fs().open_dir(p.parent()?).ok()?;
    d.metadata(&rel(&p.file_name()?.to_string_lossy()))
        .ok()
        .flatten()
}

/// The stored spelling of the fake entry `abs`, `None` if it is missing.
pub(crate) fn try_stored_abs(sys: &FakeSystem, abs: &str) -> Option<String> {
    let p = Path::new(abs);
    #[expect(clippy::disallowed_methods, reason = "test: read a fixture name")]
    let d = sys.fake_fs().open_dir(p.parent()?).ok()?;
    d.stored_name(&rel(p.file_name()?.to_str()?)).ok().flatten()
}

/// The content of the fake file `abs`.
pub(crate) fn read_abs(sys: &FakeSystem, abs: &str) -> Vec<u8> {
    let p = Path::new(abs);
    #[expect(clippy::disallowed_methods, reason = "test: read a fixture file")]
    let d = sys.fake_fs().open_dir(p.parent().unwrap()).unwrap();
    d.read(&rel(&p.file_name().unwrap().to_string_lossy()))
        .unwrap_or_else(|e| panic!("{abs}: {e}"))
}

/// The fake entry `abs` exists.
pub(crate) fn exists_abs(sys: &FakeSystem, abs: &str) -> bool {
    let p = Path::new(abs);
    #[expect(clippy::disallowed_methods, reason = "test: look at a fixture entry")]
    let d = sys.fake_fs().open_dir(p.parent().unwrap()).unwrap();
    d.metadata(&rel(&p.file_name().unwrap().to_string_lossy()))
        .unwrap()
        .is_some()
}

/// A Steam library with app `id` installed in `G` (`StateFlags` `flags`).
pub(crate) fn acf(id: u32, flags: u32) -> String {
    format!(
        "\"AppState\"\n{{\n\t\"appid\"\t\t\"{id}\"\n\t\"name\"\t\t\"G\"\n\t\"StateFlags\"\t\t\"{flags}\"\n\t\"installdir\"\t\t\"G\"\n}}\n"
    )
}

pub(crate) fn manifest(id: u32) -> String {
    format!(r"{STEAM_LIB}\steamapps\appmanifest_{id}.acf")
}

pub(crate) fn steam_sys() -> FakeSystem {
    finish(
        base()
            .file(manifest(220), acf(220, 4).into_bytes())
            .file(manifest(221), acf(221, 4).into_bytes())
            .file(format!(r"{STEAM_GAME}\game.exe"), b"MZ".to_vec())
            .file(format!(r"{STEAM_GAME}\d3d9.dll"), OLD.to_vec()),
    )
}

pub(crate) fn steam_plan(env: &Env, app_id: u32, s: &FileInstallSpec) -> PlanHash {
    let fr = fr(&env.sys);
    let store = StoreDir::open(&env.sys, &fr, Path::new(STEAM_LIB)).unwrap();
    let g = store.game(&fr, "G").unwrap();
    env.plan_for(&g, Some(app_id), s)
}

#[test]
fn t7_stacking_and_lifo() {
    // Two transactions on one file: LIFO.
    let env = Env::new(finish(base()));
    let before = env.snap();
    let t1 = env.applied(&env.plan(&t1_spec()));
    let mid = env.snap();
    sys_put(&env.sys, &pkg("d3d9b.dll"), b"third d3d9");
    let t2 = env.applied(&env.plan(&spec(vec![entry("d3d9b.dll", "d3d9.dll", b"third d3d9")])));
    assert!(matches!(
        env.revert(&t1),
        Err(ExecError::Refused(Refusal::Later { txn })) if txn == t2
    ));
    assert_eq!(closed(&env.revert(&t2)), Some(Closing::Reverted));
    same(&mid, &env.snap());
    assert_eq!(closed(&env.revert(&t1)), Some(Closing::Reverted));
    same(&before, &env.snap());

    // Two Steam apps sharing one install folder: the same root identity.
    let env = Env::new(steam_sys());
    let t1 = env.applied(&steam_plan(
        &env,
        220,
        &spec(vec![entry("new.dll", "new.dll", N)]),
    ));
    let t2 = env.applied(&steam_plan(
        &env,
        221,
        &spec(vec![entry("d3d9.dll", "new.dll", NEW)]),
    ));
    assert!(matches!(
        env.revert(&t1),
        Err(ExecError::Refused(Refusal::Later { txn })) if txn == t2
    ));
    assert!(closed(&env.revert(&t2)).is_some());
    assert!(closed(&env.revert(&t1)).is_some());

    // An open transaction blocks only its objects, also below a folder it created.
    let env = Env::new(finish(base()));
    let open = interrupted(&env, &spec(vec![entry(r"mods\x.dll", r"mods\x.dll", X)]));
    let other = env.plan(&spec(vec![entry("new.dll", "new.dll", N)]));
    let t = env.applied(&other);
    assert!(closed(&env.revert(&t)).is_some());
    let below = env.plan(&spec(vec![entry("new.dll", r"mods\new.dll", N)]));
    assert!(matches!(
        env.apply(&below),
        Err(ApplyError::Refused(Refusal::Interrupted { txn })) if txn == open
    ));
    // Applied with a revert begun counts as open (condition 3).
    let env = Env::new(finish(base()));
    let t = env.applied(&env.plan(&t1_spec()));
    // The first rename of the revert is its first `RevertIntent`, the second its `RevertDone`.
    let r = env.revert_armed(&t, |fx| fx.fail_at(Prim::Rename, 2, SysErrorKind::Other));
    assert!(r.is_err(), "{r:?}");
    env.sys.fake_fs().clear_faults();
    let on_it = env.plan(&spec(vec![entry("new.dll", r"mods\a\y.dll", N)]));
    assert!(matches!(
        env.apply(&on_it),
        Err(ApplyError::Refused(Refusal::Interrupted { .. }))
    ));
    // Damaged with a usable head: open with its objects.
    let env = Env::new(finish(base()));
    let t = env.applied(&env.plan(&t1_spec()));
    let fx = env.sys.fake_fs();
    fx.put_file(Path::new(&format!(r"{}\0099.json", env.txn_dir(&t))), b"{}")
        .unwrap();
    assert!(matches!(env.state(&t), Some(TxnState::Damaged(_))));
    let on_it = env.plan(&spec(vec![entry("new.dll", r"mods\a\y.dll", N)]));
    assert!(matches!(
        env.apply(&on_it),
        Err(ApplyError::Refused(Refusal::Interrupted { .. }))
    ));
    let beside = env.plan(&spec(vec![entry("new.dll", "beside.dll", N)]));
    let t2 = env.applied(&beside);
    assert!(matches!(
        env.revert(&t),
        Err(ExecError::Refused(Refusal::Blocked { .. }))
    ));
    assert!(closed(&env.revert(&t2)).is_some());
    // Unusable head, unreadable folder, duplicate seq: every apply blocked until forgotten.
    type Damage = fn(&Env, &TxnId) -> TxnId;
    let damages: [(&str, Damage); 3] = [
        ("unusable head", |env, t| {
            let p = format!(r"{}\head.json", env.txn_dir(t));
            env.sys.fake_fs().remove_abs(Path::new(&p)).unwrap();
            env.sys.fake_fs().put_file(Path::new(&p), b"{}").unwrap();
            *t
        }),
        ("unreadable folder", |env, t| {
            let d = env.txn_dir(t);
            env.sys.swap_with_junction(&d, r"C:\x").unwrap();
            *t
        }),
        ("duplicate seq", |env, t| {
            let dup = TxnId::new(t.seq(), t.tag() ^ 1).unwrap();
            let d = format!(r"{}\Rerun\journal\{dup}", crate::journal::tests::LAD);
            env.sys.fake_fs().mkdir_all(Path::new(&d)).unwrap();
            dup
        }),
    ];
    for (what, damage) in damages {
        let env = Env::new(finish(base()));
        let t = env.applied(&env.plan(&spec(vec![entry("new.dll", "new.dll", N)])));
        let blocker = damage(&env, &t);
        let h = env.plan(&spec(vec![entry(r"mods\x.dll", "elsewhere.dll", X)]));
        let r = env.apply(&h);
        assert!(
            matches!(&r, Err(ApplyError::Refused(Refusal::Blocked { txn })) if *txn == blocker || *txn == t),
            "{what}: {r:?}"
        );
        // D2: forget the blocker (and, for a duplicate, the damaged original).
        env.forget(&blocker).unwrap();
        if blocker != t {
            env.forget(&t).unwrap();
        }
        assert!(
            matches!(env.apply(&h), Ok(Outcome::Applied(_))),
            "{what}: unblocked"
        );
    }
}

pub(crate) fn sys_put(sys: &FakeSystem, abs: &str, data: &[u8]) {
    sys.fake_fs().put_file(Path::new(abs), data).unwrap();
}

/// An apply of `s` interrupted by a crash after its first change (the folder of a
/// `CreateDir`), restarted: an open transaction.
pub(crate) fn interrupted(env: &Env, s: &FileInstallSpec) -> TxnId {
    let h = env.plan(s);
    // `journal\` exists, so the apply's first `create_dir` is its transaction folder, the
    // second the plan's first folder.
    drop(
        Journal::new(&app(&env.sys), InstanceTag::fixed(3))
            .lock()
            .unwrap(),
    );
    let r = env.apply_armed(&h, |fx| {
        fx.fault(Prim::CreateDir, 2, crate::sys::fake::Fault::CrashAfter);
    });
    assert!(r.is_err(), "{r:?}");
    let fx = env.sys.fake_fs();
    fx.restart();
    let open: Vec<TxnId> = env
        .states()
        .into_iter()
        .filter(|(_, s)| *s == Some(TxnState::Open))
        .map(|(t, _)| t)
        .collect();
    assert_eq!(open.len(), 1, "{:?}", env.states());
    open[0]
}

#[test]
fn t8_refusals_write_no_transaction() {
    // A plan without ops: nothing, no lock, no transaction.
    let env = Env::new(finish(base()));
    let same_content = spec(vec![entry("d3d9.dll", "x.dll", NEW)]);
    sys_put(&env.sys, &game("x.dll"), NEW);
    assert_eq!(
        env.apply(&env.plan(&same_content)).unwrap(),
        Outcome::Nothing
    );
    assert!(env.states().is_empty());

    type Make = fn(&Env);
    type Want = fn(&Refusal) -> bool;
    let refusals: Vec<(&str, Make, Want)> = vec![
        (
            "main executable running",
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
            "target held open",
            |env| {
                std::mem::forget(
                    env.sys
                        .fake_fs()
                        .hold_open_as(
                            4242,
                            Path::new(&game("d3d9.dll")),
                            crate::sys::contract::Access::READ,
                            crate::sys::contract::Share::RWD,
                        )
                        .unwrap(),
                );
            },
            |r| matches!(r, Refusal::Busy(_)),
        ),
        (
            "old state changed",
            |env| {
                env.sys
                    .fake_fs()
                    .set_attrs(Path::new(&game("d3d9.dll")), Attrs::default())
                    .unwrap();
            },
            |r| matches!(r, Refusal::Mismatch { op: 0 }),
        ),
        (
            "a target appeared",
            |env| sys_put(&env.sys, &game("new.dll"), b"x"),
            |r| matches!(r, Refusal::Mismatch { op: 4 }),
        ),
        (
            "package file changed",
            |env| {
                let p = pkg("new.dll");
                env.sys.fake_fs().remove_abs(Path::new(&p)).unwrap();
                sys_put(&env.sys, &p, b"changed");
            },
            |r| matches!(r, Refusal::Mismatch { op: 4 }),
        ),
        (
            "needs the helper",
            |env| {
                env.sys
                    .fake_fs()
                    .set_user_writable(Path::new(GAME), false)
                    .unwrap();
            },
            |r| matches!(r, Refusal::NeedsHelper),
        ),
        (
            "the target renamed in another case (A2-B1)",
            |env| {
                env.sys
                    .rename_abs(game("d3d9.dll"), game("D3D9.DLL"))
                    .unwrap()
            },
            |r| matches!(r, Refusal::Mismatch { op: 0 }),
        ),
        (
            "another folder now",
            |env| {
                env.sys.rename_abs(GAME, r"D:\Games\Moved").unwrap();
                env.sys.fake_fs().mkdir_all(Path::new(GAME)).unwrap();
            },
            |r| matches!(r, Refusal::Root(e) if matches!(**e, crate::policy::root::RootError::IdentityMismatch { .. })),
        ),
    ];
    for (what, make, want) in refusals {
        let env = Env::new(finish(base()));
        let h = env.plan(&t1_spec());
        make(&env);
        let before = env.snap();
        match env.apply(&h) {
            Err(ApplyError::Refused(r)) => assert!(want(&r), "{what}: {r:?}"),
            other => panic!("{what}: {other:?}"),
        }
        assert!(env.states().is_empty(), "{what}: no transaction folder");
        same(&before, &env.snap());
    }
    // The lock is taken.
    let env = Env::new(finish(base()));
    let h = env.plan(&t1_spec());
    let app = app(&env.sys);
    let j = Journal::new(&app, InstanceTag::fixed(7));
    let held = j.lock().unwrap();
    assert!(matches!(
        env.apply(&h),
        Err(ApplyError::Refused(Refusal::JournalBusy))
    ));
    drop(held);
    // The Steam app updates or is gone.
    for (flags, state) in [
        (4 | 2, AppState::UpdatePending),
        (1, AppState::NotInstalled),
    ] {
        let env = Env::new(steam_sys());
        let h = steam_plan(&env, 220, &spec(vec![entry("new.dll", "new.dll", N)]));
        env.sys
            .fake_fs()
            .remove_abs(Path::new(&manifest(220)))
            .unwrap();
        sys_put(&env.sys, &manifest(220), acf(220, flags).as_bytes());
        assert!(matches!(
            env.apply(&h),
            Err(ApplyError::Refused(Refusal::Steam { app_id: 220, state: s })) if s == state
        ));
        assert!(env.states().is_empty());
    }
    // Condition 8: the game starts between the check and the guard; `users()` on the guard.
    let env = Env::new(finish(base()));
    let before = env.snap();
    let h = env.plan(&t1_spec());
    let guards = std::sync::Arc::new(AtomicU64::new(0));
    let g2 = std::sync::Arc::clone(&guards);
    env.sys.fake_fs().on_step(move |f, ev| {
        if ev.call == Some(Prim::OpenGuard) && ev.name.eq_ignore_ascii_case("d3d9.dll") {
            // The first guard is the old-state check (step 5), the second the apply's.
            if g2.fetch_add(1, Ordering::SeqCst) == 1 {
                std::mem::forget(f.map_image_as(4242, Path::new(&game("d3d9.dll"))).unwrap());
            }
        }
    });
    let r = env.apply(&h);
    env.sys.fake_fs().clear_on_step();
    assert!(
        matches!(&r, Err(ApplyError::RolledBack { cause, .. })
            if matches!(&**cause, ExecError::Op { op: 0, source } if source.kind == SysErrorKind::Busy)),
        "{r:?}"
    );
    same(&before, &env.snap());
}

/// A2-B1 review S2: a case-only rename between the old-state check and the apply's guard is
/// caught on the guard itself (pattern of condition 8): rolled back with `Mismatch`, the file
/// kept as the user named it, nothing else changed.
#[test]
fn t8_a_case_only_rename_before_the_apply_guard_is_a_mismatch() {
    let env = Env::new(finish(base()));
    let before = env.snap();
    let h = env.plan(&t1_spec());
    let guards = std::sync::Arc::new(AtomicU64::new(0));
    let g2 = std::sync::Arc::clone(&guards);
    env.sys.fake_fs().on_step(move |f, ev| {
        if ev.call == Some(Prim::OpenGuard) && ev.name.eq_ignore_ascii_case("d3d9.dll") {
            // The first guard is the old-state check (step 5), the second the apply's.
            if g2.fetch_add(1, Ordering::SeqCst) == 1 {
                f.rename_abs(Path::new(&game("d3d9.dll")), Path::new(&game("D3D9.DLL")))
                    .unwrap();
            }
        }
    });
    let r = env.apply(&h);
    env.sys.fake_fs().clear_on_step();
    assert!(
        guards.load(Ordering::SeqCst) >= 2,
        "the apply's guard was reached"
    );
    assert!(
        matches!(&r, Err(ApplyError::RolledBack { cause, .. })
            if matches!(&**cause, ExecError::Op { op: 0, source } if source.kind == SysErrorKind::Mismatch)),
        "{r:?}"
    );
    assert_eq!(
        stored_abs(&env.sys, &game("d3d9.dll")),
        "D3D9.DLL",
        "the user's name"
    );
    assert_eq!(read_abs(&env.sys, &game("d3d9.dll")), OLD);
    // Apart from the user's rename, the game folder is as before.
    env.sys
        .rename_abs(game("D3D9.DLL"), game("d3d9.dll"))
        .unwrap();
    same(&before, &env.snap());
}

/// A2-B1: a replace names its target in the stored spelling, and the apply refuses any other
/// (a recovery renames back onto the planned name, so it must be the one on disk). The plan
/// here is written by hand in the step's spelling, which the planner never produces.
#[test]
fn t8_a_replace_in_another_spelling_than_the_disk_is_a_mismatch() {
    use crate::plan::{self, Op, Plan};
    let env = Env::new(finish(base()));
    let h = env.plan(&spec(vec![entry("d3d9.dll", "D3D9.DLL", NEW)]));
    let app = app(&env.sys);
    let mut p: Plan = plan::decode(plan::load(&app, &h).unwrap().bytes()).unwrap();
    match p.ops.first_mut() {
        Some(Op::ReplaceFile { path, .. }) => {
            assert_eq!(
                path.as_str(),
                "d3d9.dll",
                "the planner writes the stored spelling"
            );
            *path = rel("D3D9.DLL");
        }
        other => panic!("{other:?}"),
    }
    let crafted = store(&app, &p.encode().unwrap()).unwrap();
    let before = env.snap();
    match env.apply(&crafted) {
        Err(ApplyError::Refused(Refusal::Mismatch { op: 0 })) => {}
        other => panic!("{other:?}"),
    }
    assert!(env.states().is_empty(), "no transaction folder");
    same(&before, &env.snap());
    // The plan in the stored spelling applies and reverts to the exact name.
    let t = env.applied(&h);
    assert!(closed(&env.revert(&t)).is_some());
    same(&before, &env.snap());
}

#[test]
fn forget_closes_applied_and_open_transactions() {
    let env = Env::new(finish(base()));
    let t = env.applied(&env.plan(&t1_spec()));
    env.forget(&t).unwrap();
    assert_eq!(env.state(&t), Some(TxnState::Closed(Closing::Forgotten)));
    assert!(env.forget(&t).is_err(), "closed");
    let env = Env::new(finish(base()));
    let open = interrupted(&env, &spec(vec![entry(r"mods\x.dll", r"mods\x.dll", X)]));
    env.forget(&open).unwrap();
    assert_eq!(env.state(&open), Some(TxnState::Closed(Closing::Forgotten)));
}

/// K1: a revert that trusts the records instead of observing deletes a file the user changed
/// (T6's "R/H/S" case: the user made our new file read-only and hidden); T6's check reports
/// the object and the closing.
#[test]
fn k1_trusting_the_records_breaks_t6() {
    let case = T6_CASES.iter().find(|c| c.0 == "R/H/S").unwrap();
    super::knob::trust_records(true);
    let f = t6_check(case);
    super::knob::trust_records(false);
    for want in ["T6 R/H/S object:", "T6 R/H/S closed:"] {
        assert!(
            f.iter().any(|x| x.starts_with(want)),
            "K1 not caught ({want}): {f:#?}"
        );
    }
}

/// K3: a restore without the old R/H/S; T1's check reports the snapshot.
#[test]
fn k3_restoring_without_attributes_breaks_t1() {
    super::knob::restore_without_attrs(true);
    let f = t1_check();
    super::knob::restore_without_attrs(false);
    assert!(
        f.iter().any(|x| x.starts_with("T1 snapshot:")),
        "K3 not caught: {f:#?}"
    );
}

/// Review S2: a manual root inside a Steam install folder overlaps that root as a whole.
#[test]
fn t7_nested_roots_overlap() {
    let sub = format!(r"{STEAM_GAME}\sub");
    let env = Env::new(finish(
        base()
            .file(manifest(220), acf(220, 4).into_bytes())
            .file(format!(r"{STEAM_GAME}\game.exe"), b"MZ".to_vec())
            .dir(&sub),
    ));
    let t1 = env.applied(&steam_plan(
        &env,
        220,
        &spec(vec![entry("new.dll", "new.dll", N)]),
    ));
    let fr = fr(&env.sys);
    let g = GameDir::open_manual(&env.sys, &fr, Path::new(&sub)).unwrap();
    let h2 = env.plan_for(&g, None, &spec(vec![entry("new.dll", "other.dll", N)]));
    drop(g);
    let t2 = env.applied(&h2);
    assert!(matches!(
        env.revert(&t1),
        Err(ExecError::Refused(Refusal::Later { txn })) if txn == t2
    ));
    assert!(closed(&env.revert(&t2)).is_some());
    assert!(closed(&env.revert(&t1)).is_some());
}
