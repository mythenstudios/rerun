//! Tests of the write side of `flow` against the fake (P5-2a, ADR 0027 amendment P5-2a). The
//! CLI's tests run `rerun plan` and `rerun apply` through it with golden output, the golden
//! plans C-TE11 to C-TE13 included (`rerun-cli`). Here, on a step file with a `file_install`
//! for a manual game folder (the T1 world of `exec`):
//! - FW1 planning stores nothing and creates nothing, Rerun's folder absent or present; the
//!   preview is the preview of the plan's bytes.
//! - FW2 `store` creates Rerun's folder only then and stores exactly the planned bytes; a plan
//!   made with another path of Rerun's folder is not stored (`AppDirMoved`) .
//! - FW3 `check` and `apply` run on the stored bytes of the `Previewed` and nothing else: before
//!   `store` they find no plan and write nothing; after it the game folder holds the new files;
//!   `load_stored` gives the same bytes and preview back.
//! - FW4 a plan without ops is never stored.
//!
//! The `compile_fail` doctests of `flow::apply` and `flow::Previewed` check that `apply` takes
//! no plan hash and that a `Previewed` comes only from `shown`.

use std::path::{Path, PathBuf};

use crate::exec::tests::{OLD, base, finish, game, t1_spec, try_meta_abs, try_read_abs};
use crate::exec::{ApplyError, Outcome, Refusal};
use crate::path::RootPath;
use crate::plan::{PlanError, preview_stored};
use crate::policy::root::{AppDir, Create};
use crate::prim::tests::{GAME, INSTALL, rel};
use crate::prim::{GameRef, STEP_FILE_FORMAT, Step, StepFile};
use crate::sys::fake::{FakeHttp, FakeSystem, Prim};

use super::{
    LoadRefusal, StepsRefusal, StoreRefusal, apply, check, load_stored, plan_steps, shown, store,
};
use crate::flow::{Env, Guarded, guard};

const RERUN: &str = r"C:\Users\Player\AppData\Local\Rerun";

fn install() -> Result<PathBuf, String> {
    Ok(PathBuf::from(INSTALL))
}

fn steps(s: Vec<Step>) -> StepFile {
    StepFile {
        format: STEP_FILE_FORMAT,
        game: GameRef::Folder(RootPath::new(GAME).unwrap()),
        main_exe: rel("game.exe"),
        user_data: None,
        steps: s,
    }
}

fn t1() -> StepFile {
    steps(vec![Step::FileInstall(t1_spec())])
}

/// The T1 world without Rerun's folder (the package files are below it, so the folder is
/// removed again after the build: the planner reads the packages through `AppDir`).
fn world() -> FakeSystem {
    finish(base())
}

fn exists(sys: &FakeSystem, p: &str) -> bool {
    try_meta_abs(sys, p).is_some()
}

fn read(sys: &FakeSystem, p: &str) -> Option<Vec<u8>> {
    try_read_abs(sys, p)
}

/// A file system call that writes.
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
            | Prim::OpenLock
            | Prim::OpenDirDelete
    )
}

fn with_guard<R>(sys: &FakeSystem, f: impl FnOnce(Guarded<'_>) -> R) -> R {
    let http = FakeHttp::default();
    let ok = install();
    let g = guard(Env {
        sys,
        http: &http,
        install: &ok,
    })
    .unwrap_or_else(|e| panic!("{e:?}"));
    f(g)
}

#[test]
fn fw1_planning_stores_nothing() {
    let sys = world();
    sys.fake_fs().record_calls(true);
    let planned = with_guard(&sys, |g| {
        assert!(g.app().is_some(), "the packages are below Rerun's folder");
        let (p, warned) = plan_steps(&g, &t1()).unwrap_or_else(|e| panic!("{e:?}"));
        assert!(warned.is_empty());
        p
    });
    let calls = sys.fake_fs().take_calls();
    assert!(!calls.is_empty(), "the record bites");
    assert!(
        !calls.iter().any(writes),
        "planning wrote nothing: {calls:?}"
    );
    assert!(!exists(&sys, &format!(r"{RERUN}\plans")));
    assert_eq!(planned.ops(), planned.preview.ops.len());
    assert!(planned.ops() > 0);
    assert!(planned.warnings.is_empty());
    // The preview is the one of the bytes that would be stored.
    assert_eq!(
        planned.preview,
        preview_stored(&planned.bytes).unwrap(),
        "the preview is decoded from the plan's own bytes"
    );
}

#[test]
fn fw2_store_creates_rerun_folder_only_then() {
    // A step file that needs no package: Rerun's folder does not exist while planning.
    let sys = FakeSystem::builder()
        .windows_layout()
        .dir(INSTALL)
        .dir(GAME)
        .file(format!(r"{GAME}\game.exe"), b"MZ".to_vec())
        .key(crate::sys::registry::RegKey::new(
            crate::sys::registry::Hive::CurrentUser,
            crate::sys::registry::RegView::Native,
            "Software",
        ))
        .build()
        .unwrap();
    let sf = steps(vec![
        serde_json::from_str::<Step>(
            r#"{"compat_layer":{"exe":"game.exe","layers":["ZZ_FLAG_A"]}}"#,
        )
        .unwrap(),
    ]);
    with_guard(&sys, |mut g| {
        assert!(g.app().is_none());
        let (p, _) = plan_steps(&g, &sf).unwrap_or_else(|e| panic!("{e:?}"));
        assert!(!exists(&sys, RERUN), "planning creates no Rerun folder");
        let bytes = p.bytes.bytes().to_vec();
        let p = shown(p);
        assert!(!exists(&sys, RERUN), "shown creates nothing");
        let h = store(&mut g, &p).unwrap_or_else(|e| panic!("{e:?}"));
        assert_eq!(h, p.hash());
        assert!(g.app().is_some(), "the guard keeps the folder it created");
        assert_eq!(
            read(&sys, &format!(r"{RERUN}\plans\{h}.json")).as_deref(),
            Some(bytes.as_slice()),
            "exactly the planned bytes are stored"
        );
        // The same bytes again: no change.
        assert_eq!(store(&mut g, &p).unwrap(), h);
    });
    // A plan made with another path of Rerun's folder (LocalAppData moved meanwhile).
    with_guard(&sys, |mut g| {
        let (mut p, _) = plan_steps(&g, &sf).unwrap_or_else(|e| panic!("{e:?}"));
        p.app_path = Some(RootPath::new(r"E:\Elsewhere\Rerun").unwrap());
        let p = shown(p);
        assert!(matches!(store(&mut g, &p), Err(StoreRefusal::AppDirMoved)));
    });
}

#[test]
fn fw3_apply_applies_exactly_the_stored_bytes() {
    let sys = world();
    with_guard(&sys, |mut g| {
        let (p, _) = plan_steps(&g, &t1()).unwrap_or_else(|e| panic!("{e:?}"));
        let h = p.hash();
        let p = shown(p);
        // Not stored yet: `check` and `apply` find no plan of that hash and write nothing.
        assert!(matches!(
            check(&g, &p),
            Err(Refusal::Plan(PlanError::NotFound(x))) if x == h
        ));
        let p2 = {
            let (q, _) = plan_steps(&g, &t1()).unwrap();
            shown(q)
        };
        assert!(matches!(
            apply(&g, p2),
            Err(ApplyError::Refused(Refusal::Plan(PlanError::NotFound(_))))
        ));
        assert_eq!(read(&sys, &game("d3d9.dll")).as_deref(), Some(OLD));
        assert!(!exists(&sys, &format!(r"{RERUN}\journal")));
        // Stored: the stored plan loads with the same bytes and preview.
        store(&mut g, &p).unwrap();
        let again = load_stored(&g, &h).unwrap_or_else(|e| panic!("{e:?}"));
        assert_eq!(again.hash(), h);
        assert_eq!(again.ops(), p.ops());
        assert_eq!(check(&g, &p).unwrap(), p.ops());
        assert!(matches!(apply(&g, p), Ok(Outcome::Applied(_))));
    });
    assert_eq!(
        read(&sys, &game("d3d9.dll")).as_deref(),
        Some(crate::exec::tests::NEW)
    );
    assert!(exists(&sys, &game(r"mods\a\x.dll")));
}

#[test]
fn fw3b_stored_bytes_changed_on_disk_are_refused() {
    // Another file under the plan's name: `exec` loads by hash and refuses it, so nothing but
    // the shown bytes can be applied under that name.
    let sys = world();
    with_guard(&sys, |mut g| {
        let (p, _) = plan_steps(&g, &t1()).unwrap();
        let p = shown(p);
        let h = store(&mut g, &p).unwrap();
        let at = format!(r"{RERUN}\plans\{h}.json");
        let mut b = read(&sys, &at).unwrap();
        b.push(b' ');
        sys.fake_fs().put_file(Path::new(&at), &b).unwrap();
        assert!(matches!(
            check(&g, &p),
            Err(Refusal::Plan(PlanError::HashMismatch(_)))
        ));
        assert!(matches!(
            load_stored(&g, &h),
            Err(LoadRefusal::Plan(PlanError::HashMismatch(_)))
        ));
        assert!(matches!(
            apply(&g, p),
            Err(ApplyError::Refused(Refusal::Plan(PlanError::HashMismatch(
                _
            ))))
        ));
    });
    assert_eq!(read(&sys, &game("d3d9.dll")).as_deref(), Some(OLD));
}

#[test]
fn fw4_a_plan_without_ops_is_never_stored() {
    let sys = FakeSystem::builder()
        .windows_layout()
        .dir(INSTALL)
        .dir(GAME)
        .file(format!(r"{GAME}\game.exe"), b"MZ".to_vec())
        .build()
        .unwrap();
    with_guard(&sys, |mut g| {
        let (p, _) = plan_steps(&g, &steps(Vec::new())).unwrap_or_else(|e| panic!("{e:?}"));
        assert_eq!(p.ops(), 0);
        let p = shown(p);
        assert!(matches!(store(&mut g, &p), Err(StoreRefusal::Empty)));
    });
    assert!(!exists(&sys, RERUN));
    // Rerun's folder never created for a missing game folder either.
    let gone = FakeSystem::builder()
        .windows_layout()
        .dir(INSTALL)
        .build()
        .unwrap();
    with_guard(&gone, |g| {
        assert!(matches!(plan_steps(&g, &t1()), Err(StepsRefusal::Game(_))));
    });
    assert!(!AppDir::open(&gone, Create::Never).unwrap().is_some());
}
