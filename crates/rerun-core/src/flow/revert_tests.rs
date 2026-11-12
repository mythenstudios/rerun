//! Tests of revert, rebind and forget in `flow` against the fake (P5-2b, ADR 0027 amendment
//! P5-2b). The CLI's tests run `rerun revert` (`--dry-run`, `--yes`, `--rebind`) and `rerun
//! forget` through it with golden output. Here, on T1 of `exec` (a manual game folder) and on
//! the rebind world of `exec::rebind_tests`:
//! - FR1 a revert preview writes nothing; a revert after an unchanged preview restores the game
//!   folder exactly (round trip) and says how it ended.
//! - FR2 a file the revert touches changes between preview and revert: `Changed`, nothing
//!   written (Rerun's folder and the game folder identical); a new preview then reverts.
//! - FR3 another process reverts meanwhile: `Changed`, the journal unchanged.
//! - FR4 rebind: the preview writes nothing; another process forgets meanwhile, or a file of the
//!   new folder changes: `Changed`, no record; unchanged, it binds and reverts exactly.
//! - FR5 forget: a file changes or another process reverts between preview and forget:
//!   `Changed`, the journal unchanged; unchanged, it forgets.
//! - FR6 the gates: not found, no Rerun folder, forgotten, closed, damaged, refused (LIFO), an
//!   empty transaction with a head (no question).
//! - FX1 the launch profile's fate (X12) before a revert, after it and before a forget (moved
//!   from the CLI, review of P5-2b).
//!
//! The `compile_fail` doctests of `flow::revert` and `flow::RevertShown` check that `revert`
//! takes no transaction ID and that a `RevertShown` comes only from `revert_preview`.

use std::path::{Path, PathBuf};

use crate::exec::rebind_tests::{GAME_E, LIB_E, REF, applied, content_diff, move_lib};
use crate::exec::tests::{Env, N, base, closed, finish, game, sys_put, t1_spec};
use crate::exec::{Refusal, TxnLine};
use crate::journal::{Closing, InstanceTag, Journal, TxnId};
use crate::prim::tests::{GAME, INSTALL, entry, spec};
use crate::sys::fake::{FakeHttp, FakeSystem, Prim};
use crate::sys::snapshot::Snapshot;

use super::{
    ActError, RevertAsk, RevertEnd, RevertGate, forget, forget_preview, rebind, rebind_preview,
    revert, revert_preview,
};
use crate::flow::{Env as FlowEnv, Guarded, guard};

fn with_guard<R>(sys: &FakeSystem, f: impl FnOnce(Guarded<'_>) -> R) -> R {
    let http = FakeHttp::default();
    let ok: Result<PathBuf, String> = Ok(PathBuf::from(INSTALL));
    let g = guard(FlowEnv {
        sys,
        http: &http,
        install: &ok,
    })
    .unwrap_or_else(|e| panic!("{e:?}"));
    f(g)
}

/// A file system call that changes something (the lock file is opened read side by a preview
/// and taken by an operation: it exists already and is compared by the snapshots).
fn writes(c: &Prim) -> bool {
    matches!(
        c,
        Prim::CreateTmp
            | Prim::CreateDir
            | Prim::Rename
            | Prim::Write
            | Prim::SetAttrs
            | Prim::FlushFile
            | Prim::PosixDelete
            | Prim::OpenDirDelete
    )
}

/// Rerun's folder and the game folder `at`.
fn snaps(env: &Env, at: &str) -> (Snapshot, Snapshot) {
    (
        crate::exec::tests::snap_app(&env.sys),
        crate::exec::tests::snap_at(&env.sys, at),
    )
}

fn same(a: &(Snapshot, Snapshot), b: &(Snapshot, Snapshot)) {
    crate::exec::tests::same(&a.0, &b.0);
    crate::exec::tests::same(&a.1, &b.1);
}

/// T1 applied on the manual game folder, with the game folder before the apply.
fn t1() -> (Env, TxnId, Snapshot) {
    let env = Env::new(finish(base()));
    let before = env.snap();
    let t = env.applied(&env.plan(&t1_spec()));
    (env, t, before)
}

fn remove(sys: &FakeSystem, abs: &str) {
    sys.fake_fs().remove_abs(Path::new(abs)).unwrap();
}

#[test]
fn fr1_a_revert_after_an_unchanged_preview_restores_the_folder() {
    let (env, t, before) = t1();
    let at = snaps(&env, GAME);
    env.sys.fake_fs().record_calls(true);
    let (p, s) =
        with_guard(&env.sys, |g| revert_preview(&g, &t)).unwrap_or_else(|e| panic!("{e:?}"));
    let calls = env.sys.fake_fs().take_calls();
    env.sys.fake_fs().record_calls(false);
    assert!(!calls.is_empty(), "the record bites");
    assert!(!calls.iter().any(writes), "the preview wrote: {calls:?}");
    same(&at, &snaps(&env, GAME));
    assert_eq!(s.txn(), t);
    assert!(!p.empty);
    assert_eq!(p.status.id, t);
    assert_eq!(
        p.ask,
        RevertAsk::Revert {
            ops: p.verified.ops.len()
        }
    );
    assert!(p.verified.halted.is_none() && !p.verified.ops.is_empty());
    assert!(p.launch_option.is_none() && p.prompt.is_none());
    let o = with_guard(&env.sys, |g| revert(&g, s)).unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(o.end, RevertEnd::Closed);
    assert_eq!(o.report.closed, Some(Closing::Reverted));
    crate::exec::tests::same(&before, &env.snap());
}

#[test]
fn fr2_a_file_changed_since_the_preview_is_changed_and_nothing_written() {
    let (env, t, before) = t1();
    let (_, s) = with_guard(&env.sys, |g| revert_preview(&g, &t)).unwrap();
    // The new file the revert would remove is gone (another program deleted it).
    remove(&env.sys, &game("new.dll"));
    env.sys.sync_all();
    let at = snaps(&env, GAME);
    env.sys.fake_fs().record_calls(true);
    let r = with_guard(&env.sys, |g| revert(&g, s));
    let calls = env.sys.fake_fs().take_calls();
    env.sys.fake_fs().record_calls(false);
    assert!(matches!(r, Err(ActError::Changed)), "{r:?}");
    assert!(!calls.iter().any(writes), "written: {calls:?}");
    same(&at, &snaps(&env, GAME));
    // Shown again, it reverts what is there now.
    let (p, s) = with_guard(&env.sys, |g| revert_preview(&g, &t)).unwrap();
    assert!(
        p.verified
            .ops
            .iter()
            .any(|(_, o)| *o == crate::journal::Observed::Before)
    );
    let o = with_guard(&env.sys, |g| revert(&g, s)).unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(o.end, RevertEnd::Closed);
    crate::exec::tests::same(&before, &env.snap());
}

#[test]
fn fr2b_a_replaced_file_since_the_preview_is_changed() {
    let (env, t, _) = t1();
    let (_, s) = with_guard(&env.sys, |g| revert_preview(&g, &t)).unwrap();
    // The installed d3d9.dll rewritten with other content: the revert would leave it now.
    remove(&env.sys, &game("d3d9.dll"));
    sys_put(&env.sys, &game("d3d9.dll"), b"patched by someone else");
    env.sys.sync_all();
    let at = snaps(&env, GAME);
    let r = with_guard(&env.sys, |g| revert(&g, s));
    assert!(matches!(r, Err(ActError::Changed)), "{r:?}");
    same(&at, &snaps(&env, GAME));
}

#[test]
fn fr3_another_revert_meanwhile_is_changed() {
    let (env, t, before) = t1();
    let (_, s) = with_guard(&env.sys, |g| revert_preview(&g, &t)).unwrap();
    assert_eq!(closed(&env.revert(&t)), Some(Closing::Reverted));
    let at = snaps(&env, GAME);
    let r = with_guard(&env.sys, |g| revert(&g, s));
    assert!(matches!(r, Err(ActError::Changed)), "{r:?}");
    same(&at, &snaps(&env, GAME));
    crate::exec::tests::same(&before, &env.snap());
}

#[test]
fn fr4_rebind_compares_the_transaction_and_the_new_folder() {
    // Unchanged: it binds and reverts exactly; the preview writes nothing.
    let rb = applied(false);
    move_lib(&rb.env.sys, crate::prim::tests::STEAM_LIB, LIB_E);
    let at = snaps(&rb.env, GAME_E);
    let (v, s) =
        with_guard(&rb.env.sys, |g| rebind_preview(&g, &rb.t)).unwrap_or_else(|e| panic!("{e:?}"));
    same(&at, &snaps(&rb.env, GAME_E));
    assert_eq!(v.status.id, rb.t);
    assert_eq!(s.txn(), rb.t);
    let o = with_guard(&rb.env.sys, |g| rebind(&g, s)).unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(o.end, RevertEnd::Closed);
    assert!(content_diff(&rb.env.sys, REF, GAME_E).is_empty());

    // A file of the new folder changed since the preview (the new file gone): no record.
    let rb = applied(false);
    move_lib(&rb.env.sys, crate::prim::tests::STEAM_LIB, LIB_E);
    let (_, s) = with_guard(&rb.env.sys, |g| rebind_preview(&g, &rb.t)).unwrap();
    remove(&rb.env.sys, &format!(r"{GAME_E}\new.dll"));
    rb.env.sys.sync_all();
    let n = rb.env.records(&rb.t);
    let at = snaps(&rb.env, GAME_E);
    let r = with_guard(&rb.env.sys, |g| rebind(&g, s));
    assert!(matches!(r, Err(ActError::Changed)), "{r:?}");
    assert_eq!(rb.env.records(&rb.t), n);
    same(&at, &snaps(&rb.env, GAME_E));

    // Another process forgot it meanwhile.
    let rb = applied(false);
    move_lib(&rb.env.sys, crate::prim::tests::STEAM_LIB, LIB_E);
    let (_, s) = with_guard(&rb.env.sys, |g| rebind_preview(&g, &rb.t)).unwrap();
    rb.env.forget(&rb.t).unwrap();
    let at = snaps(&rb.env, GAME_E);
    let r = with_guard(&rb.env.sys, |g| rebind(&g, s));
    assert!(matches!(r, Err(ActError::Changed)), "{r:?}");
    same(&at, &snaps(&rb.env, GAME_E));
}

#[test]
fn fr5_forget_compares_what_it_showed() {
    let (env, t, _) = t1();
    let at = snaps(&env, GAME);
    let (p, s) = with_guard(&env.sys, |g| forget_preview(&g, &t)).unwrap();
    same(&at, &snaps(&env, GAME));
    assert!(matches!(p.verified, Some(Ok(_))));
    assert_eq!(p.revert_would, Some(super::RevertWould::BeClean));
    // A file changed since the preview.
    sys_put(&env.sys, &game("other.dll"), N);
    remove(&env.sys, &game("new.dll"));
    env.sys.sync_all();
    let at = snaps(&env, GAME);
    let r = with_guard(&env.sys, |g| forget(&g, s));
    assert!(matches!(r, Err(ActError::Changed)), "{r:?}");
    same(&at, &snaps(&env, GAME));
    // Shown again: it forgets.
    let (_, s) = with_guard(&env.sys, |g| forget_preview(&g, &t)).unwrap();
    with_guard(&env.sys, |g| forget(&g, s)).unwrap_or_else(|e| panic!("{e:?}"));
    assert!(matches!(
        with_guard(&env.sys, |g| forget_preview(&g, &t)),
        Err(RevertGate::Forgotten)
    ));

    // Another process reverted meanwhile.
    let (env, t, _) = t1();
    let (_, s) = with_guard(&env.sys, |g| forget_preview(&g, &t)).unwrap();
    assert!(closed(&env.revert(&t)).is_some());
    let at = snaps(&env, GAME);
    let r = with_guard(&env.sys, |g| forget(&g, s));
    assert!(matches!(r, Err(ActError::Changed)), "{r:?}");
    same(&at, &snaps(&env, GAME));
}

#[test]
fn fr6_the_gates() {
    // No Rerun folder; a transaction the journal does not name.
    let bare = FakeSystem::builder()
        .windows_layout()
        .dir(INSTALL)
        .build()
        .unwrap();
    let t0 = TxnId::new(999, 1).unwrap();
    assert!(matches!(
        with_guard(&bare, |g| revert_preview(&g, &t0)),
        Err(RevertGate::NoAppDir)
    ));
    let (env, t, _) = t1();
    assert!(matches!(
        with_guard(&env.sys, |g| revert_preview(&g, &t0)),
        Err(RevertGate::NotFound(_))
    ));
    // LIFO: a later transaction on the same file refuses the revert in the preview.
    sys_put(
        &env.sys,
        &crate::exec::tests::pkg("d3d9b.dll"),
        b"third d3d9",
    );
    env.sys.sync_all();
    let t2 = env.applied(&env.plan(&spec(vec![entry("d3d9b.dll", "d3d9.dll", b"third d3d9")])));
    assert!(matches!(
        with_guard(&env.sys, |g| revert_preview(&g, &t)),
        Err(RevertGate::Refused(Refusal::Later { txn })) if txn == t2
    ));
    // Closed.
    assert!(closed(&env.revert(&t2)).is_some());
    assert!(matches!(
        with_guard(&env.sys, |g| revert_preview(&g, &t2)),
        Err(RevertGate::Closed(Closing::Reverted))
    ));
    assert!(matches!(
        with_guard(&env.sys, |g| forget_preview(&g, &t2)),
        Err(RevertGate::Closed(Closing::Reverted))
    ));
    // Forgotten.
    env.forget(&t).unwrap();
    assert!(matches!(
        with_guard(&env.sys, |g| revert_preview(&g, &t)),
        Err(RevertGate::Forgotten)
    ));
    assert!(matches!(
        with_guard(&env.sys, |g| rebind_preview(&g, &t)),
        Err(RevertGate::Forgotten)
    ));
    // Damaged: only forget closes it.
    let (env, t, _) = t1();
    sys_put(&env.sys, &format!(r"{}\0099.json", env.txn_dir(&t)), b"{}");
    assert!(matches!(
        with_guard(&env.sys, |g| revert_preview(&g, &t)),
        Err(RevertGate::Blocked)
    ));
    let (p, _) = with_guard(&env.sys, |g| forget_preview(&g, &t)).unwrap();
    assert!(matches!(p.status.state, TxnLine::Damaged(_)));
    // Empty with a head: the revert only closes it, nothing to ask.
    let env = Env::new(finish(base()));
    let h = env.plan(&t1_spec());
    let a = crate::prim::tests::app(&env.sys);
    let bytes = crate::plan::load(&a, &h).unwrap();
    let empty = {
        let j = Journal::new(&a, InstanceTag::fixed(0x71));
        let lock = j.lock().unwrap();
        *lock.begin(bytes.bytes()).unwrap().id()
    };
    let (p, s) = with_guard(&env.sys, |g| revert_preview(&g, &empty)).unwrap();
    assert!(p.empty);
    assert_eq!(p.ask, RevertAsk::Nothing);
    assert!(p.launch_option.is_none());
    let o = with_guard(&env.sys, |g| revert(&g, s)).unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(o.end, RevertEnd::Closed);
    assert_eq!(
        crate::exec::tests::try_read_abs(&env.sys, &game("d3d9.dll")).as_deref(),
        Some(crate::exec::tests::OLD)
    );
}

// ---------- FX1: the launch profile's fate (X12, review M1/B1; moved from the CLI) ----------

mod x12 {
    use std::collections::BTreeMap;

    use crate::escape;
    use crate::exec::{
        Halt, OpReport, OpState, OpStatus, Refusal, RevertReport, TxnLine, TxnStatus, Verified,
    };
    use crate::journal::{Observed, TxnId};
    use crate::plan::{NOT_RESTORED, Preview, PreviewOp, PreviewRoot, ProfilePreview, RootKind};

    use super::super::{LaunchOption, ProfileFate as F, fate_after, fate_before, fate_forget};

    fn txn() -> TxnId {
        "00000004-00000000000000ab".parse().unwrap()
    }

    fn file_op(index: usize, action: &'static str, path: &str) -> PreviewOp {
        PreviewOp {
            index,
            action,
            root: Some(0),
            path: escape::path(path).into_owned(),
            name: None,
            old_value: None,
            new_value: None,
            tokens: None,
            machine: Vec::new(),
            type_change: false,
            source: None,
            content: None,
            attrs: None,
            old: None,
            config: false,
            ini: Vec::new(),
            profile: None,
            replaces: false,
            firewall: None,
            held: false,
            patch: Vec::new(),
        }
    }

    fn root(index: usize, kind: RootKind, path: &str) -> PreviewRoot {
        PreviewRoot {
            index,
            kind,
            path: escape::path(path).into_owned(),
            steam: None,
            main_exe: None,
        }
    }

    /// A head with a game file op 1 and, with `profile`, a launch profile op 0 (`Some(true)`: it
    /// replaced a profile).
    fn head(profile: Option<bool>) -> Preview {
        let mut ops = vec![
            file_op(0, "create file", "a.dll"),
            file_op(1, "create file", "new.dll"),
        ];
        let mut roots = vec![root(0, RootKind::Game, r"D:\Games\G")];
        if let Some(replace) = profile {
            let prof = &mut ops[0];
            prof.action = if replace {
                "replace file"
            } else {
                "create file"
            };
            prof.path = escape::path("323ad79fbc93ca3e73b0b152a5d44616.profile").into_owned();
            prof.root = Some(1);
            prof.replaces = replace;
            // The ID comes from the file name.
            prof.profile = Some(ProfilePreview::Unreadable("x".to_owned()));
            roots.push(root(
                1,
                RootKind::Profiles,
                r"C:\Users\Player\AppData\Local\Rerun\profiles",
            ));
        }
        Preview {
            roots,
            ops,
            not_restored: NOT_RESTORED,
            registry: None,
            layers: None,
            ini: None,
            profiles: None,
            firewall: None,
            held: None,
            patched: None,
            gpu_pref: None,
            user_data: None,
        }
    }

    fn st(state: TxnLine, profile: Option<bool>, ops: &[(u16, OpState)]) -> TxnStatus {
        TxnStatus {
            id: txn(),
            state,
            forgotten: false,
            folder: escape::path(r"C:\x").into_owned(),
            preview: Some(Ok(head(profile))),
            ops: ops
                .iter()
                .map(|(op, state)| OpStatus {
                    op: *op,
                    state: *state,
                    backup: None,
                    cleanup: Vec::new(),
                })
                .collect(),
            rebinds: Vec::new(),
            shares: Vec::new(),
            shares_error: None,
        }
    }

    fn halt(h: Option<(u16, u16)>) -> Option<Halt> {
        h.map(|(op, root)| Halt {
            op,
            root,
            why: Box::new(Refusal::NeedsHelper),
        })
    }

    fn verified(ops: Vec<(u16, Observed)>, halted: Option<(u16, u16)>) -> Verified {
        Verified {
            ops,
            halted: halt(halted),
            details: BTreeMap::new(),
            cleanup: Vec::new(),
            profiles_moved: None,
            virtual_store: Vec::new(),
        }
    }

    fn report(ops: Vec<(u16, Observed)>, halted: Option<(u16, u16)>) -> RevertReport {
        RevertReport {
            txn: txn(),
            closed: None,
            ops: ops
                .into_iter()
                .map(|(op, observed)| OpReport {
                    op,
                    observed,
                    left: Vec::new(),
                    backup: None,
                    detail: None,
                })
                .collect(),
            halted: halt(halted),
            cleanup: Vec::new(),
            profiles_moved: None,
        }
    }

    fn fate(lo: Option<LaunchOption>) -> F {
        lo.map(|l| l.fate).expect("a launch profile")
    }

    /// FX1 (moved from the CLI's X12 test, review of P5-2b): which fate a revert's preview, its
    /// report and a forget give.
    #[test]
    fn fx1_the_fate_follows_what_becomes_of_the_profile() {
        let a = OpState::Applied;
        let applied = |replace| st(TxnLine::Applied, Some(replace), &[(1, a), (0, a)]);
        // A created profile reverted: gone; a replaced one: the previous profile is back.
        let both = vec![(0, Observed::After), (1, Observed::After)];
        let v = verified(both.clone(), None);
        assert_eq!(fate(fate_before(&applied(false), &v)), F::Gone);
        assert_eq!(fate(fate_before(&applied(true), &v)), F::PreviousBack);
        let r = report(both, None);
        assert_eq!(fate(fate_after(&applied(false), &r)), F::Gone);
        assert_eq!(fate(fate_after(&applied(true), &r)), F::PreviousBack);
        // The game folder gone: a halt at the game op before the profile is reached: it stays.
        let v = verified(Vec::new(), Some((1, 0)));
        assert_eq!(fate(fate_before(&applied(false), &v)), F::Stays);
        let r = report(Vec::new(), Some((1, 0)));
        assert_eq!(fate(fate_after(&applied(false), &r)), F::Stays);
        // `profiles` gone: a halt at the profile op itself: no profile.
        let r = report(vec![(1, Observed::After)], Some((0, 1)));
        assert_eq!(fate(fate_after(&applied(false), &r)), F::Gone);
        // Changed by someone else: left, it keeps applying.
        let r = report(vec![(1, Observed::After), (0, Observed::Foreign)], None);
        assert_eq!(fate(fate_after(&applied(false), &r)), F::Stays);
        // Forget: as it is now. Applied: it stays.
        let now = verified(vec![(0, Observed::After), (1, Observed::After)], None);
        assert_eq!(fate(fate_forget(&applied(false), Some(&now))), F::Stays);
        assert_eq!(fate(fate_forget(&applied(false), None)), F::Stays);
        // Forget with only the cleanup pending: the profile op was reverted already.
        let rv = OpState::Reverted(Observed::After);
        let cleanup = |replace| st(TxnLine::CleanupPending, Some(replace), &[(1, rv), (0, rv)]);
        assert_eq!(fate(fate_forget(&cleanup(false), Some(&now))), F::Gone);
        assert_eq!(
            fate(fate_forget(&cleanup(true), Some(&now))),
            F::PreviousBack
        );
        // Review L-a: `profiles` missing, forget: `verify` halts at the profile op itself.
        let v = verified(vec![(1, Observed::After)], Some((0, 1)));
        assert_eq!(fate(fate_forget(&applied(false), Some(&v))), F::Gone);
        // Review L-a: an earlier revert left the profile foreign; whether it is still there is
        // not known.
        let left = st(
            TxnLine::Applied,
            Some(false),
            &[(1, a), (0, OpState::Reverted(Observed::Foreign))],
        );
        let v = verified(vec![(0, Observed::Foreign), (1, Observed::After)], None);
        assert_eq!(fate(fate_before(&left, &v)), F::Left);
        let r = report(vec![(1, Observed::After)], None);
        assert_eq!(fate(fate_after(&left, &r)), F::Left);
        assert_eq!(fate(fate_forget(&left, Some(&v))), F::Left);
        // A head without a profile: nothing.
        let plain = st(TxnLine::Applied, None, &[]);
        assert!(fate_forget(&plain, None).is_none());
        assert!(fate_before(&plain, &now).is_none());
    }
}
