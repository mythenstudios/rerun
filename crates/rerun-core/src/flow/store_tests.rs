//! The store flow (P5-8b-1, ADR 0027 amendment P5-8b) against the fake world, with the signed
//! index and the fake HTTPS side; no network. Every ID, URL and file is invented.
//! - PS1 the view: a package of the index unpacked, incomplete, only its archive; one no longer
//!   in the index; an archive without a package; leftovers; foreign entries; sizes; no `AppDir`;
//!   looking creates nothing.
//! - PS9 an archive two packages name goes only with both.
//! - PS10 elevated: refused before anything is read.
//! - The token: a store that changed after the preview is `ActError::Changed`, nothing removed.

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use super::{PackageKeep, Pick, StoreGate, StoredState, package_store, remove, remove_preview};
use crate::catalog::key::test_key;
use crate::catalog::{self};
use crate::exec::TxnLine;
use crate::flow::ActError;
use crate::flow::{Env, Gate, Guarded, guard};
use crate::journal::TxnId;
use crate::pkg::archive::testfx::{ZipEntry, zip};
use crate::pkg::store::StoreKeep;
use crate::policy::root::{AppDir, Create};
use crate::sys::fake::{FakeHttp, FakeReply, FakeSystem, Prim};

const INSTALL: &str = r"C:\Users\Player\AppData\Local\Programs\Rerun";
const PACKAGES: &str = r"C:\Users\Player\AppData\Local\Rerun\packages";
const CACHE: &str = r"C:\Users\Player\AppData\Local\Rerun\cache";
const ASSET: &str = "https://github.com/owner/fix-pack/releases/download/v1.0/fix-pack.zip";
const DLL: &[u8] = b"the fix dll";

fn upper(b: &[u8]) -> String {
    Sha256::digest(b)
        .iter()
        .map(|x| format!("{x:02X}"))
        .collect()
}

fn lower(b: &[u8]) -> String {
    upper(b).to_ascii_lowercase()
}

fn archive() -> Vec<u8> {
    zip(&[ZipEntry::file("bin/fix.dll", DLL)])
}

/// A package of the index whose one download is [`archive`].
fn package(id: &str, name: &str, a: &[u8]) -> String {
    format!(
        r#"{{"format":1,"id":"{id}","name":"{name}","status":"active","tier":"established","source":{{"repo":"https://github.com/owner/fix-pack","page":"https://github.com/owner/fix-pack","release":"{ASSET}"}},"version":"1.0","sha256":"{}","license":"MIT","arch":["x86"],"slots":["fix.dll"],"files":[{{"from":"bin/fix.dll","to":"fix.dll","sha256":"{}"}}]}}"#,
        upper(a),
        upper(DLL),
    )
}

/// The fake Windows layout with Rerun's install folder and the game folder of `prim::tests`.
fn system() -> FakeSystem {
    crate::prim::tests::builder().build().unwrap()
}

/// Applies `fix-pack` 1.0 (`bin\fix.dll` as `fix.dll`) to the game folder of `prim::tests`.
fn apply_fix(sys: &FakeSystem) -> TxnId {
    use crate::prim::tests::{GAME, entry, fr};
    use crate::prim::{FileInstallSpec, PlanCtx, Step, plan};
    let fr = fr(sys);
    let app = AppDir::open(sys, Create::Never).unwrap().unwrap();
    let game = crate::policy::root::GameDir::open_manual(sys, &fr, Path::new(GAME)).unwrap();
    let main = crate::path::RelPath::parse("game.exe").unwrap();
    let spec = FileInstallSpec {
        package: "fix-pack".to_owned(),
        version: "1.0".to_owned(),
        files: vec![entry(r"bin\fix.dll", "fix.dll", DLL)],
    };
    let p = plan(
        &[Step::FileInstall(spec)],
        &PlanCtx {
            game: &game,
            app: Some(&app),
            steam_app: None,
            main_exe: Some(&main),
            reg: crate::policy::registry::RegPolicy.reader(sys),
            app_path: None,
            user_data: None,
        },
    )
    .unwrap_or_else(|e| panic!("{e}"));
    let h = crate::plan::store(&app, &p.encode().unwrap()).unwrap();
    let cx = crate::exec::ExecCtx {
        sys,
        fr: &fr,
        app: &app,
        tag: crate::journal::InstanceTag::new(),
    };
    match crate::exec::apply(&cx, &h) {
        Ok(crate::exec::Outcome::Applied(t)) => t,
        r => panic!("{r:?}"),
    }
}

/// The signed index with `fix-pack` and `twin-pack` (one archive for both), `fix-pack` fetched
/// and unpacked.
fn world() -> (FakeSystem, FakeHttp) {
    let sys = system();
    let a = archive();
    let ix = format!(
        r#"{{"format":1,"seq":1,"issued":"2026-11-10T12:00:00Z","topos":[],"packages":[{},{}]}}"#,
        package("fix-pack", "Fix pack", &a),
        package("twin-pack", "Twin pack", &a),
    );
    let http = FakeHttp::default();
    http.reply(ASSET, FakeReply::ok(&a));
    {
        let app = AppDir::open(&sys, Create::IfMissing).unwrap().unwrap();
        catalog::store::import(
            &app,
            ix.as_bytes(),
            &test_key::sign(ix.as_bytes()),
            &catalog::trusted_keys(),
        )
        .unwrap_or_else(|e| panic!("{e}"));
        let c = catalog::store::current(&app, &catalog::trusted_keys())
            .unwrap()
            .unwrap();
        let p = c.package("fix-pack").unwrap();
        for d in crate::pkg::download::downloads(p).unwrap() {
            crate::pkg::download::fetch(&sys, &http, &app, &d).unwrap();
        }
        crate::pkg::extract::extract(&sys, &app, p).unwrap();
    }
    sys.fake_fs().sync_all();
    (sys, http)
}

fn with_guard<R>(sys: &FakeSystem, http: &FakeHttp, f: impl FnOnce(&Guarded<'_>) -> R) -> R {
    let ok: Result<PathBuf, String> = Ok(PathBuf::from(INSTALL));
    let g = guard(Env {
        sys,
        http,
        install: &ok,
    })
    .unwrap_or_else(|e| panic!("{e:?}"));
    f(&g)
}

fn put(sys: &FakeSystem, abs: &str, data: &[u8]) {
    sys.fake_fs().put_file(Path::new(abs), data).unwrap();
}

fn ls(sys: &FakeSystem, abs: &str) -> Vec<String> {
    #[expect(clippy::disallowed_methods, reason = "test: list a fixture folder")]
    let Ok(d) = crate::sys::Fs::open_dir(sys.fake_fs(), Path::new(abs)) else {
        return Vec::new();
    };
    let mut v: Vec<String> = d
        .read_dir(None)
        .unwrap()
        .into_iter()
        .map(|e| e.name)
        .collect();
    v.sort();
    v
}

#[test]
fn ps1_the_view_names_every_part_and_looking_creates_nothing() {
    let (sys, http) = world();
    let a = archive();
    let loose = "cd".repeat(32);
    put(&sys, &format!(r"{PACKAGES}\old-pack\0.9\a.dll"), b"old");
    put(&sys, &format!(r"{CACHE}\{loose}"), b"older archive");
    put(
        &sys,
        &format!(r"{CACHE}\.rerun-00000000000000ab-0.tmp"),
        b"half",
    );
    put(&sys, &format!(r"{PACKAGES}\Bad"), b"x");
    sys.fake_fs()
        .mkdir_all(Path::new(&format!(r"{PACKAGES}\empty-pack")))
        .unwrap();
    sys.fake_fs().record_calls(true);
    let v = with_guard(&sys, &http, |g| package_store(g).unwrap());
    let calls = sys.fake_fs().take_calls();
    sys.fake_fs().record_calls(false);
    assert!(!calls.is_empty());
    assert!(
        !calls.iter().any(|c| matches!(
            c,
            Prim::CreateTmp
                | Prim::CreateDir
                | Prim::Rename
                | Prim::Write
                | Prim::OpenLock
                | Prim::OpenFileDelete
                | Prim::OpenDirDelete
        )),
        "looking writes nothing: {calls:?}"
    );
    let ids: Vec<(&str, &str)> = v
        .packages
        .iter()
        .map(|p| (p.id.as_str(), p.version.as_str()))
        .collect();
    assert_eq!(
        ids,
        [
            ("fix-pack", "1.0"),
            ("old-pack", "0.9"),
            ("twin-pack", "1.0")
        ]
    );
    let fix = &v.packages[0];
    assert_eq!(fix.name.as_deref(), Some("Fix pack"));
    assert!(fix.in_index);
    assert_eq!(fix.state, StoredState::Unpacked);
    assert_eq!(fix.files, 1);
    assert_eq!(fix.paths, [r"bin\fix.dll"], "the list, not a count (D1)");
    assert_eq!(fix.archives, [lower(&a)]);
    assert_eq!(fix.bytes, (DLL.len() + a.len()) as u64);
    assert!(fix.used_by.is_empty() && fix.keep.is_none());
    let old = &v.packages[1];
    assert_eq!((old.name.as_deref(), old.in_index), (None, false));
    assert_eq!(old.state, StoredState::Unpacked);
    assert_eq!(old.bytes, 3);
    assert_eq!(old.paths, ["a.dll"]);
    let twin = &v.packages[2];
    assert_eq!(twin.state, StoredState::ArchiveOnly);
    assert_eq!(twin.archives, [lower(&a)]);
    assert!(twin.paths.is_empty());
    assert_eq!(v.loose_archives, [(loose.clone(), 13)]);
    assert_eq!(v.leftovers, (2, 4));
    assert_eq!(
        v.foreign,
        [(r"packages\Bad".to_owned(), StoreKeep::BadName)]
    );

    // A file of the layout missing: incomplete.
    sys.fake_fs()
        .remove_abs(Path::new(&format!(r"{PACKAGES}\fix-pack\1.0\bin\fix.dll")))
        .unwrap();
    let v = with_guard(&sys, &http, |g| package_store(g).unwrap());
    assert_eq!(v.packages[0].state, StoredState::Incomplete);

    // No Rerun folder: nothing to show, nothing created.
    let sys = system();
    let http = FakeHttp::default();
    let r = with_guard(&sys, &http, |g| package_store(g).map(|_| ()));
    assert!(matches!(r, Err(StoreGate::NoAppDir)));
    assert!(AppDir::open(&sys, Create::Never).unwrap().is_none());
}

#[test]
fn ps9_an_archive_two_packages_name_goes_only_with_both() {
    let (sys, http) = world();
    let a = lower(&archive());
    // One package: its folder goes, the shared archive stays.
    let (p, s) = with_guard(&sys, &http, |g| {
        remove_preview(
            g,
            &Pick::Package {
                id: "fix-pack".to_owned(),
                version: "1.0".to_owned(),
            },
        )
        .unwrap()
    });
    assert_eq!(p.remove.len(), 1);
    assert!(p.remove[0].archives.is_empty(), "{:?}", p.remove[0]);
    assert_eq!(p.bytes, DLL.len() as u64);
    let r = with_guard(&sys, &http, |g| remove(g, s).unwrap());
    assert_eq!(r.packages.len(), 1);
    assert_eq!(r.archives, 0);
    assert_eq!(ls(&sys, CACHE), [a.as_str(), "lock"]);

    // All unused: the archive goes once, with both.
    let (sys, http) = world();
    let (p, s) = with_guard(&sys, &http, |g| remove_preview(g, &Pick::Unused).unwrap());
    assert_eq!(p.remove.len(), 2);
    assert!(p.remove.iter().all(|x| x.archives == [a.clone()]));
    assert_eq!(p.bytes, (DLL.len() + archive().len()) as u64);
    assert!(p.stays.is_empty());
    let r = with_guard(&sys, &http, |g| remove(g, s).unwrap());
    assert_eq!(
        r.packages,
        [
            ("fix-pack".to_owned(), "1.0".to_owned()),
            ("twin-pack".to_owned(), "1.0".to_owned())
        ],
        "the package that was only its archive counts too"
    );
    assert_eq!(r.archives, 1);
    assert_eq!(ls(&sys, CACHE), ["lock"]);
    assert_eq!(ls(&sys, PACKAGES), [".lock"]);
    // The view is empty now (`twin-pack` was only its archive).
    let v = with_guard(&sys, &http, |g| package_store(g).unwrap());
    assert!(v.packages.is_empty(), "{:?}", v.packages);

    // Review D2: `twin-pack` is only the archive `fix-pack` names, and `fix-pack` stays: nothing
    // of `twin-pack` would go, so it stays with its own reason and the token is empty.
    let (sys, http) = world();
    sys.fake_fs()
        .put_link(
            Path::new(&format!(r"{PACKAGES}\fix-pack\1.0\link")),
            crate::sys::fs::tag::MOUNT_POINT,
            r"D:\Elsewhere",
        )
        .unwrap();
    let twin = Pick::Package {
        id: "twin-pack".to_owned(),
        version: "1.0".to_owned(),
    };
    for pick in [twin, Pick::Unused] {
        let (p, s) = with_guard(&sys, &http, |g| remove_preview(g, &pick).unwrap());
        assert!(p.remove.is_empty(), "{pick:?}: {:?}", p.remove);
        assert!(s.is_empty(), "{pick:?}");
        let keeps: Vec<(&str, Option<PackageKeep>)> = p
            .stays
            .iter()
            .map(|x| (x.id.as_str(), x.keep.clone()))
            .collect();
        assert!(
            keeps.contains(&("twin-pack", Some(PackageKeep::SharedArchive))),
            "{pick:?}: {keeps:?}"
        );
    }
}

/// Review D3: who uses a package, and the order of the reasons: in use before what its folder
/// holds, what its folder holds before an unreadable transaction.
#[test]
fn used_by_and_the_order_of_the_reasons() {
    let (sys, http) = world();
    let t = apply_fix(&sys);
    let v = with_guard(&sys, &http, |g| package_store(g).unwrap());
    let fix = &v.packages[0];
    assert_eq!(fix.id, "fix-pack");
    assert_eq!(fix.keep, Some(PackageKeep::InUse));
    assert_eq!(fix.used_by.len(), 1);
    assert_eq!(fix.used_by[0].txn, t);
    assert_eq!(
        fix.used_by[0].app, None,
        "a manual game folder names no Steam app"
    );
    assert_eq!(fix.used_by[0].line, TxnLine::Applied);
    assert_eq!(v.packages[1].keep, None, "twin-pack is not used");
    let (p, s) = with_guard(&sys, &http, |g| {
        remove_preview(
            g,
            &Pick::Package {
                id: "fix-pack".to_owned(),
                version: "1.0".to_owned(),
            },
        )
        .unwrap()
    });
    assert!(p.remove.is_empty() && s.is_empty());
    assert_eq!(p.stays[0].keep, Some(PackageKeep::InUse));

    // In use comes before what the folder holds.
    sys.fake_fs()
        .put_link(
            Path::new(&format!(r"{PACKAGES}\fix-pack\1.0\link")),
            crate::sys::fs::tag::MOUNT_POINT,
            r"D:\Elsewhere",
        )
        .unwrap();
    let v = with_guard(&sys, &http, |g| package_store(g).unwrap());
    assert_eq!(v.packages[0].keep, Some(PackageKeep::InUse));

    // The transaction unreadable: the folder's reason first, then the unknown use.
    let txn_dir = format!(r"C:\Users\Player\AppData\Local\Rerun\journal\{t}");
    sys.fake_fs()
        .swap_with_junction(Path::new(&txn_dir), r"D:\Elsewhere")
        .unwrap();
    let v = with_guard(&sys, &http, |g| package_store(g).unwrap());
    assert_eq!(
        v.packages[0].keep,
        Some(PackageKeep::Store(StoreKeep::Reparse))
    );
    assert!(v.packages[0].used_by.is_empty());
    assert_eq!(v.packages[1].keep, Some(PackageKeep::UnknownUse(vec![t])));
}

#[test]
fn a_package_that_stays_is_listed_with_its_reason_and_nothing_is_shown() {
    let (sys, http) = world();
    sys.fake_fs()
        .put_link(
            Path::new(&format!(r"{PACKAGES}\fix-pack\1.0\link")),
            crate::sys::fs::tag::MOUNT_POINT,
            r"D:\Elsewhere",
        )
        .unwrap();
    let (p, s) = with_guard(&sys, &http, |g| {
        remove_preview(
            g,
            &Pick::Package {
                id: "fix-pack".to_owned(),
                version: "1.0".to_owned(),
            },
        )
        .unwrap()
    });
    assert!(p.remove.is_empty() && s.is_empty());
    assert_eq!(
        p.stays[0].keep,
        Some(PackageKeep::Store(StoreKeep::Reparse))
    );
    let missing = with_guard(&sys, &http, |g| {
        remove_preview(
            g,
            &Pick::Package {
                id: "nope".to_owned(),
                version: "1.0".to_owned(),
            },
        )
        .map(|_| ())
    });
    assert!(matches!(missing, Err(StoreGate::NotFound)));
}

#[test]
fn a_store_that_changed_after_the_preview_is_changed_and_nothing_goes() {
    let (sys, http) = world();
    let (_, s) = with_guard(&sys, &http, |g| remove_preview(g, &Pick::Unused).unwrap());
    put(
        &sys,
        &format!(r"{PACKAGES}\fix-pack\1.0\bin\new.dll"),
        b"new",
    );
    let before = (ls(&sys, PACKAGES), ls(&sys, CACHE));
    let r = with_guard(&sys, &http, |g| remove(g, s));
    assert!(matches!(r, Err(ActError::Changed)), "{r:?}");
    assert_eq!(before, (ls(&sys, PACKAGES), ls(&sys, CACHE)));
}

#[test]
fn ps10_an_elevated_process_is_refused_by_the_guard() {
    let (sys, http) = world();
    sys.fake_registry().set_elevated(true);
    sys.fake_fs().record_calls(true);
    let ok: Result<PathBuf, String> = Ok(PathBuf::from(INSTALL));
    let g = guard(Env {
        sys: &sys,
        http: &http,
        install: &ok,
    });
    assert!(matches!(g, Err(Gate::Elevated(_))));
    assert_eq!(sys.fake_fs().take_calls(), [], "nothing read but the token");
}
