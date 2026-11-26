//! `exec::remove_packages` and `exec::package_users_with_status` against the fake (P5-8b-1):
//! - PS2 who uses a package: every live state (open, applied, a cleanup pending, damaged with a
//!   head, a `Hold`) keeps it; closed, empty and forgotten ones do not; an unreadable one keeps
//!   every package (E3 a) but not an archive without a package.
//! - PS3 the round trip with a real download: fetch, apply, revert, remove: Rerun's folder outside
//!   `packages` and `cache` and the game folder identical; then fetch, apply, revert again.
//! - PS4 the invariant (P5-8b finding 1): with `packages` gone, revert, rollback and the revert of
//!   a rebind still restore the game folder exactly.
//! - PS5 a package applied between the preview and the removal: refused, nothing deleted.
//! - PS7 a crash after any call of a removal: the planner refuses what is incomplete, a fetch
//!   completes it, and the round trip holds.
//! - PS8 `journal\lock` held: `JournalBusy`, nothing deleted.

use std::path::Path;

use super::cleanup_tests::open_y;
use super::rebind_tests::{GAME_E, LIB_E, REF, applied as rb_applied, content_diff, move_lib};
use super::tests::{Env, N, NEW, base, finish, same, t1_spec};
use super::{ExecError, Refusal, package_users_with_status, remove_packages};
use crate::journal::{Closing, InstanceTag, Journal, TxnId, TxnState};
use crate::pkg::store::tests::{CACHE, PACKAGES, all_of, ls, snap};
use crate::pkg::store::{Removed, Shown, list};
use crate::plan::Op;
use crate::prim::tests::{STEAM_LIB, app, entry, spec};
use crate::sys::fake::{FakeFs, Fault, Prim};

const VERSION: &str = r"C:\Users\Player\AppData\Local\Rerun\packages\fix-pack\1.0.2";

fn shown_now(env: &Env) -> Vec<Shown> {
    all_of(&list(&app(&env.sys)).unwrap())
}

fn rm(env: &Env, shown: &[Shown]) -> Result<Removed, ExecError> {
    env.with(|cx| remove_packages(cx, shown))
}

fn users_of_pack(env: &Env) -> Vec<TxnId> {
    package_users_with_status(&app(&env.sys))
        .unwrap()
        .0
        .of("fix-pack", "1.0.2")
}

/// `t` keeps `fix-pack`: listed as its user, the removal refused naming it, nothing deleted.
fn kept_by(env: &Env, t: &TxnId) -> Result<(), String> {
    if users_of_pack(env) != [*t] {
        return Err(format!("users: {:?}", users_of_pack(env)));
    }
    let files = ls(&env.sys, VERSION);
    match rm(env, &shown_now(env)) {
        Err(ExecError::Refused(Refusal::PackageInUse { txn, package })) if txn == *t => {
            if package.as_str() != "fix-pack@1.0.2" {
                return Err(format!("package: {package}"));
            }
        }
        r => return Err(format!("remove: {r:?}")),
    }
    if ls(&env.sys, VERSION) != files {
        return Err("something was deleted".to_owned());
    }
    Ok(())
}

/// No live transaction keeps `fix-pack`: it goes.
fn free(env: &Env) -> Result<(), String> {
    if !users_of_pack(env).is_empty() {
        return Err(format!("users: {:?}", users_of_pack(env)));
    }
    match rm(env, &shown_now(env)) {
        Ok(r) if r.packages.len() == 1 => Ok(()),
        r => Err(format!("remove: {r:?}")),
    }
}

/// The newest transaction.
fn newest(env: &Env) -> TxnId {
    env.states().last().map(|(t, _)| *t).unwrap()
}

#[test]
fn ps2_every_live_state_keeps_its_package_and_settled_ones_do_not() {
    // Applied.
    let env = Env::new(finish(base()));
    let t = env.applied(&env.plan(&t1_spec()));
    kept_by(&env, &t).unwrap();

    // Open: an apply that crashed.
    let env = Env::new(finish(base()));
    let h = env.plan(&t1_spec());
    // The third rename: after the head and the backup, the intent of op 0 is on disk.
    let r = env.apply_armed(&h, |fx| fx.fault(Prim::Rename, 3, Fault::CrashAfter));
    assert!(r.is_err());
    env.sys.restart();
    let t = newest(&env);
    assert_eq!(env.state(&t), Some(TxnState::Open));
    kept_by(&env, &t).unwrap();

    // A cleanup pending (every op reverted, a `.old` left).
    let (env, _, t, m, _, _) = open_y();
    assert!(
        env.state(&t)
            .is_some_and(|s| s != TxnState::Closed(Closing::Reverted))
    );
    kept_by(&env, &t).unwrap();
    drop(m);

    // Damaged with a head that decodes (something planted in its folder).
    let env = Env::new(finish(base()));
    let t = env.applied(&env.plan(&t1_spec()));
    let planted = format!(r"{}\planted.txt", env.txn_dir(&t));
    env.sys
        .fake_fs()
        .put_file(Path::new(&planted), b"x")
        .unwrap();
    assert!(matches!(env.state(&t), Some(TxnState::Damaged(_))));
    kept_by(&env, &t).unwrap();

    // A `Hold`: `b` holds `new.dll` of `a`; after `a` handed it over, `b` alone uses the package.
    let env = Env::new(finish(base()));
    let a = env.applied(&env.plan(&spec(vec![entry("new.dll", "new.dll", N)])));
    let hb = env.plan(&spec(vec![
        entry("new.dll", "new.dll", N),
        entry("d3d9.dll", "d3d9.dll", NEW),
    ]));
    let b = env.applied(&hb);
    let p = crate::plan::decode(crate::plan::load(&app(&env.sys), &hb).unwrap().bytes()).unwrap();
    assert!(matches!(p.ops[0], Op::Hold { .. }), "{:?}", p.ops);
    let r = env.revert(&a).unwrap();
    assert_eq!(r.closed, Some(Closing::Reverted));
    kept_by(&env, &b).unwrap();

    // Closed, forgotten, empty: free.
    let env = Env::new(finish(base()));
    let t = env.applied(&env.plan(&t1_spec()));
    env.revert(&t).unwrap();
    free(&env).unwrap();
    let env = Env::new(finish(base()));
    let t = env.applied(&env.plan(&t1_spec()));
    env.forget(&t).unwrap();
    free(&env).unwrap();
    let env = Env::new(finish(base()));
    {
        let a = app(&env.sys);
        let j = Journal::new(&a, InstanceTag::fixed(0x77));
        let lock = j.lock().unwrap();
        drop(lock.begin(b"{}").unwrap());
    }
    assert_eq!(env.state(&newest(&env)), Some(TxnState::Empty));
    free(&env).unwrap();
}

#[test]
fn ps2_an_unreadable_transaction_keeps_every_package_but_not_a_loose_archive() {
    let env = Env::new(finish(base()));
    let t = env.applied(&env.plan(&t1_spec()));
    let fx = env.sys.fake_fs();
    fx.swap_with_junction(Path::new(&env.txn_dir(&t)), r"D:\Elsewhere")
        .unwrap();
    let loose = format!(r"{CACHE}\{}", "ab".repeat(32));
    fx.put_file(Path::new(&loose), b"old archive").unwrap();
    assert_eq!(env.state(&t), None, "unreadable");
    let u = package_users_with_status(&app(&env.sys)).unwrap().0;
    assert_eq!(u.unreadable, [t]);
    let shown = shown_now(&env);
    let files = ls(&env.sys, VERSION);
    assert!(matches!(
        rm(&env, &shown),
        Err(ExecError::Refused(Refusal::Blocked { txn })) if txn == t
    ));
    assert_eq!(ls(&env.sys, VERSION), files);
    let archives: Vec<Shown> = shown
        .into_iter()
        .filter(|s| matches!(s, Shown::Archive { .. }))
        .collect();
    let r = rm(&env, &archives).unwrap();
    assert_eq!(r.archives, 1);
    assert_eq!(ls(&env.sys, CACHE), ["lock"]);
}

/// Review D4: a folder that reads but whose head does not decode keeps every package; a
/// transaction on another version of the same package does not keep this one.
#[test]
fn ps2_an_undecodable_head_keeps_everything_and_another_version_keeps_only_itself() {
    let env = Env::new(finish(base()));
    let t = env.applied(&env.plan(&t1_spec()));
    let head = format!(r"{}\head.json", env.txn_dir(&t));
    let fx = env.sys.fake_fs();
    fx.remove_abs(Path::new(&head)).unwrap();
    fx.put_file(Path::new(&head), b"not a plan").unwrap();
    assert!(env.state(&t).is_some(), "the folder reads");
    let u = package_users_with_status(&app(&env.sys)).unwrap().0;
    assert_eq!(u.unreadable, [t]);
    assert!(u.by.is_empty());
    assert!(matches!(
        rm(&env, &shown_now(&env)),
        Err(ExecError::Refused(Refusal::Blocked { txn })) if txn == t
    ));

    // `fix-pack` 0.9 applied: 1.0.2 stays free, 0.9 is kept.
    let env = Env::new(finish(
        base().file(format!(r"{PACKAGES}\fix-pack\0.9\new.dll"), N.to_vec()),
    ));
    let mut old = spec(vec![entry("new.dll", "new.dll", N)]);
    old.version = "0.9".to_owned();
    let t = env.applied(&env.plan(&old));
    let u = package_users_with_status(&app(&env.sys)).unwrap().0;
    assert_eq!(u.of("fix-pack", "0.9"), [t]);
    assert!(u.of("fix-pack", "1.0.2").is_empty());
    let shown = shown_now(&env);
    let (newer, older): (Vec<Shown>, Vec<Shown>) = shown
        .into_iter()
        .partition(|s| matches!(s, Shown::Package(v) if v.version == "1.0.2"));
    assert!(matches!(
        rm(&env, &older),
        Err(ExecError::Refused(Refusal::PackageInUse { txn, .. })) if txn == t
    ));
    let r = rm(&env, &newer).unwrap();
    assert_eq!(r.packages, [("fix-pack".to_owned(), "1.0.2".to_owned())]);
}

/// Security review S3: an archive is checked against the users of the packages it belongs to (a
/// package that was only its archive may have been unpacked and applied since the preview).
#[test]
fn ps5_an_archive_of_a_package_applied_after_the_preview_is_refused() {
    let env = Env::new(finish(base()));
    let archive = format!(r"{CACHE}\{}", "ab".repeat(32));
    env.sys
        .fake_fs()
        .put_file(Path::new(&archive), b"the archive")
        .unwrap();
    let shown: Vec<Shown> = shown_now(&env)
        .into_iter()
        .filter_map(|s| match s {
            Shown::Archive { entry, .. } => Some(Shown::Archive {
                entry,
                owners: vec![("fix-pack".to_owned(), "1.0.2".to_owned())],
            }),
            _ => None,
        })
        .collect();
    assert_eq!(shown.len(), 1);
    let t = env.applied(&env.plan(&t1_spec()));
    assert!(matches!(
        rm(&env, &shown),
        Err(ExecError::Refused(Refusal::PackageInUse { txn, .. })) if txn == t
    ));
    assert_eq!(ls(&env.sys, CACHE).len(), 1, "the archive stays");
}

#[test]
fn ps5_a_package_applied_after_the_preview_is_refused() {
    let env = Env::new(finish(base()));
    let shown = shown_now(&env);
    let t = env.applied(&env.plan(&t1_spec()));
    let before = snap(&env.sys, PACKAGES);
    assert!(matches!(
        rm(&env, &shown),
        Err(ExecError::Refused(Refusal::PackageInUse { txn, .. })) if txn == t
    ));
    assert!(before == snap(&env.sys, PACKAGES));
}

#[test]
fn ps8_the_journal_lock_held_is_busy() {
    let env = Env::new(finish(base()));
    let shown = shown_now(&env);
    let a = app(&env.sys);
    let j = Journal::new(&a, InstanceTag::fixed(0x55));
    let lock = j.lock().unwrap();
    assert!(matches!(
        rm(&env, &shown),
        Err(ExecError::Refused(Refusal::JournalBusy))
    ));
    drop(lock);
    assert_eq!(ls(&env.sys, VERSION).len(), 3, "nothing deleted");
}

/// Deletes the package folder of `base` with fixture calls only (no walk, so a hook may call it).
fn drop_packages(fx: &FakeFs) {
    for p in ["d3d9.dll", r"mods\x.dll", "new.dll", "mods"] {
        let _ = fx.remove_abs(Path::new(&format!(r"{VERSION}\{p}")));
    }
    let _ = fx.remove_abs(Path::new(VERSION));
    let _ = fx.remove_abs(Path::new(&format!(r"{PACKAGES}\fix-pack")));
}

#[test]
fn ps4_a_revert_never_needs_the_package() {
    // Revert.
    let env = Env::new(finish(base()));
    let before = env.snap();
    let t = env.applied(&env.plan(&t1_spec()));
    drop_packages(env.sys.fake_fs());
    assert_eq!(ls(&env.sys, PACKAGES), Vec::<String>::new());
    let r = env.revert(&t).unwrap();
    assert_eq!(r.closed, Some(Closing::Reverted));
    same(&before, &env.snap());

    // Rollback: the package goes while the apply runs; the next op fails, the rollback restores.
    let env = Env::new(finish(base()));
    let before = env.snap();
    let h = env.plan(&t1_spec());
    // The second folder created (the first is the transaction's): an op of the game is done.
    let n = std::sync::atomic::AtomicUsize::new(0);
    env.sys.fake_fs().on_step(move |fx, ev| {
        if ev.call == Some(Prim::CreateDir)
            && n.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1 == 2
        {
            drop_packages(fx);
        }
    });
    let r = env.apply(&h);
    env.sys.fake_fs().clear_on_step();
    assert!(
        matches!(&r, Err(super::ApplyError::RolledBack { .. })),
        "{r:?}"
    );
    assert_eq!(ls(&env.sys, PACKAGES), Vec::<String>::new());
    same(&before, &env.snap());

    // The revert of a rebind (the library moved).
    let rb = rb_applied(false);
    crate::exec::rebind_tests::remove_tree(&rb.env.sys, PACKAGES);
    move_lib(&rb.env.sys, STEAM_LIB, LIB_E);
    let p = rb.env.rebind_check(&rb.t).unwrap();
    let r = rb.env.revert_rebound(&rb.t, &p.to).unwrap();
    assert_eq!(r.closed, Some(Closing::Reverted));
    assert_eq!(content_diff(&rb.env.sys, REF, GAME_E), Vec::<String>::new());
}

// ---------- With the signed index and a download ----------

/// The index is trusted only with the published test key (feature `test-key`, as
/// `flow::packages`' tests).
#[cfg(feature = "test-key")]
mod index {
    use sha2::{Digest, Sha256};

    use super::super::tests::{OLD, X, game};
    use super::*;
    use crate::catalog;
    use crate::catalog::key::test_key;
    use crate::pkg::archive::testfx::{ZipEntry, zip};
    use crate::pkg::store::tests::{APP, outside_store};
    use crate::prim::tests::{builder, plan_manual};
    use crate::sys::fake::{FakeHttp, FakeReply};

    const ASSET: &str = "https://github.com/owner/fix-pack/releases/download/v1.0.2/fix-pack.zip";

    fn upper(b: &[u8]) -> String {
        Sha256::digest(b)
            .iter()
            .map(|x| format!("{x:02X}"))
            .collect()
    }

    fn archive() -> Vec<u8> {
        zip(&[
            ZipEntry::file("d3d9.dll", NEW),
            ZipEntry::file("mods/x.dll", X),
            ZipEntry::file("new.dll", N),
        ])
    }

    /// The game folder of `exec::tests` without a package, and the signed index naming `fix-pack`
    /// 1.0.2 with one download that `FakeHttp` serves.
    fn index_world() -> (Env, FakeHttp) {
        let sys = finish(builder().file(game("d3d9.dll"), OLD.to_vec()));
        let a = archive();
        let pkg = format!(
            r#"{{"format":1,"id":"fix-pack","name":"Fix pack","status":"active","tier":"established","source":{{"repo":"https://github.com/owner/fix-pack","page":"https://github.com/owner/fix-pack","release":"{ASSET}"}},"version":"1.0.2","sha256":"{}","license":"MIT","arch":["x86"],"slots":["d3d9.dll","x.dll","new.dll"],"files":[{{"from":"d3d9.dll","to":"d3d9.dll","sha256":"{}"}},{{"from":"mods/x.dll","to":"mods/a/x.dll","sha256":"{}"}},{{"from":"new.dll","to":"new.dll","sha256":"{}"}}]}}"#,
            upper(&a),
            upper(NEW),
            upper(X),
            upper(N),
        );
        let ix = format!(
            r#"{{"format":1,"seq":1,"issued":"2026-11-10T12:00:00Z","topos":[],"packages":[{pkg}]}}"#
        );
        {
            let app = app(&sys);
            catalog::store::import(
                &app,
                ix.as_bytes(),
                &test_key::sign(ix.as_bytes()),
                &catalog::trusted_keys(),
            )
            .unwrap_or_else(|e| panic!("{e}"));
        }
        sys.sync_all();
        let http = FakeHttp::default();
        http.reply(ASSET, FakeReply::ok(&a));
        (Env::new(sys), http)
    }

    /// `package fetch fix-pack`: download and unpack.
    fn fetch(env: &Env, http: &FakeHttp) {
        let a = app(&env.sys);
        let c = catalog::store::current(&a, &catalog::trusted_keys())
            .unwrap()
            .unwrap();
        let p = c.package("fix-pack").unwrap();
        for d in crate::pkg::download::downloads(p).unwrap() {
            crate::pkg::download::fetch(&env.sys, http, &a, &d).unwrap_or_else(|e| panic!("{e}"));
        }
        crate::pkg::extract::extract(&env.sys, &a, p).unwrap_or_else(|e| panic!("{e}"));
    }

    /// Apply and revert T1: the game folder identical to `before`.
    fn round_trip(env: &Env, before: &crate::sys::snapshot::Snapshot) {
        let t = env.applied(&env.plan(&t1_spec()));
        assert_ne!(&env.snap(), before);
        let r = env.revert(&t).unwrap();
        assert_eq!(r.closed, Some(Closing::Reverted));
        same(before, &env.snap());
    }

    #[test]
    fn ps3_fetch_apply_revert_remove_and_again() {
        let (env, http) = index_world();
        let game0 = env.snap();
        fetch(&env, &http);
        round_trip(&env, &game0);
        let app0 = snap(&env.sys, APP);
        let r = rm(&env, &shown_now(&env)).unwrap();
        assert_eq!(r.packages, [("fix-pack".to_owned(), "1.0.2".to_owned())]);
        assert_eq!(r.archives, 1);
        assert_eq!(ls(&env.sys, PACKAGES), [".lock"]);
        assert_eq!(ls(&env.sys, CACHE), ["lock"]);
        assert_eq!(
            outside_store(&app0, &snap(&env.sys, APP)),
            Vec::<String>::new(),
            "journal, plans and index unchanged (the store's lock files are checked above)"
        );
        same(&game0, &env.snap());
        // The planner refuses until the package is fetched again.
        assert!(plan_manual(&env.sys, &t1_spec()).is_err());
        fetch(&env, &http);
        round_trip(&env, &game0);
    }

    /// The calls of a complete removal in the index world (fetched, nothing applied).
    fn trace() -> Vec<Prim> {
        let (env, http) = index_world();
        fetch(&env, &http);
        let shown = shown_now(&env);
        env.with(|cx| {
            let fx = env.sys.fake_fs();
            fx.clear_faults();
            fx.record_calls(true);
            remove_packages(cx, &shown).unwrap();
            fx.record_calls(false);
            fx.take_calls()
        })
    }

    #[test]
    fn ps7_after_a_crash_the_planner_refuses_what_is_incomplete_and_a_fetch_completes_it() {
        let calls = trace();
        assert!(calls.contains(&Prim::OpenFileDelete));
        for i in 0..calls.len() {
            let (env, http) = index_world();
            let game0 = env.snap();
            fetch(&env, &http);
            let shown = shown_now(&env);
            let nth = calls[..=i].iter().filter(|c| **c == calls[i]).count();
            let _ = env.with(|cx| {
                let fx = env.sys.fake_fs();
                fx.clear_faults();
                fx.fault(calls[i], nth, Fault::CrashAfter);
                remove_packages(cx, &shown)
            });
            assert!(env.sys.fake_fs().crashed(), "crash after call {i}");
            env.sys.restart();
            let whole = ls(&env.sys, VERSION) == ["d3d9.dll", "mods", "new.dll"]
                && ls(&env.sys, &format!(r"{VERSION}\mods")) == ["x.dll"];
            assert_eq!(
                plan_manual(&env.sys, &t1_spec()).is_ok(),
                whole,
                "{i}: the planner takes only a whole package"
            );
            fetch(&env, &http);
            round_trip(&env, &game0);
        }
    }
}
