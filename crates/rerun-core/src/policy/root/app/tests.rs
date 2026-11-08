//! AppDir against the fake (P2-6, tests A1 to A3 of the plan; A4 runs in `sys::win::tests`).

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use super::{AppDir, AppSub, Create};
use crate::path::{RelPath, RootPath};
use crate::policy::root::{Forbidden, RootError};
use crate::sys::fake::{FakeSystem, FakeSystemBuilder, FsOp};
use crate::sys::fs::FsKind;
use crate::sys::{KnownFolder, SysErrorKind};

const LAD: &str = r"C:\Users\Player\AppData\Local";

fn base() -> FakeSystemBuilder {
    FakeSystem::builder().dir(LAD).dir(r"C:\Out")
}

fn r(s: &str) -> RelPath {
    RelPath::parse(s).unwrap()
}

fn names(sys: &FakeSystem, abs: &str) -> Vec<String> {
    let fs = sys.fake_fs();
    #[expect(clippy::disallowed_methods, reason = "test: list a fixture folder")]
    let d = crate::sys::Fs::open_dir(fs, Path::new(abs)).unwrap();
    let mut v: Vec<String> = d
        .read_dir(None)
        .unwrap()
        .into_iter()
        .map(|e| e.name)
        .collect();
    v.sort();
    v
}

fn sys_kind<T: std::fmt::Debug>(r: Result<T, RootError>) -> SysErrorKind {
    match r {
        Err(RootError::Sys(e)) => e.kind,
        other => panic!("expected a sys error, got {other:?}"),
    }
}

fn reparse_at<T: std::fmt::Debug>(r: Result<T, RootError>) -> (RootPath, String) {
    match r {
        Err(RootError::Reparse { store, at }) => (store, at.as_str().to_owned()),
        other => panic!("expected Reparse, got {other:?}"),
    }
}

// ---------- A1: the open table ----------

#[test]
fn a1_missing_rerun_is_none_with_never_and_created_with_if_missing() {
    let sys = base().build().unwrap();
    assert!(AppDir::open(&sys, Create::Never).unwrap().is_none());
    assert!(names(&sys, LAD).is_empty(), "Never creates nothing");

    let app = AppDir::open(&sys, Create::IfMissing).unwrap().unwrap();
    assert_eq!(app.path(), &RootPath::new(format!(r"{LAD}\Rerun")).unwrap());
    assert_eq!(names(&sys, LAD), ["Rerun"]);
    assert_eq!(app.id().file_id, app.info().file_id);
    // Opened again: the same directory, nothing new.
    let again = AppDir::open(&sys, Create::Never).unwrap().unwrap();
    assert_eq!(again.id(), app.id());
}

#[test]
fn a1_known_folder_errors_and_bad_locations_are_refused() {
    let sys = base()
        .without_known_folder(KnownFolder::LocalAppData)
        .build()
        .unwrap();
    assert_eq!(
        sys_kind(AppDir::open(&sys, Create::IfMissing)),
        SysErrorKind::NotFound
    );
    for bad in [
        r"\\server\share\Local",
        r"C:\",
        r"Local",
        r"\\?\UNC\server\share",
    ] {
        let sys = base()
            .known_folder(KnownFolder::LocalAppData, bad)
            .build()
            .unwrap();
        assert!(
            matches!(
                AppDir::open(&sys, Create::IfMissing),
                Err(RootError::InvalidPath(_))
            ),
            "{bad}"
        );
    }
    // A volume mounted in a folder: its root is no AppDir parent.
    let sys = base()
        .mounted_volume(r"C:\Mnt")
        .known_folder(KnownFolder::LocalAppData, r"C:\Mnt")
        .build()
        .unwrap();
    assert!(matches!(
        AppDir::open(&sys, Create::IfMissing),
        Err(RootError::Forbidden {
            reason: Forbidden::VolumeRoot,
            ..
        })
    ));
    assert!(names(&sys, r"C:\Mnt").is_empty());
}

#[test]
fn a1_a_redirection_above_local_app_data_is_followed() {
    let sys = FakeSystem::builder()
        .dir(r"D:\Moved\AppData\Local")
        .dir(r"C:\Users\Player")
        .junction(r"C:\Users\Player\AppData", r"D:\Moved\AppData")
        .build()
        .unwrap();
    let app = AppDir::open(&sys, Create::IfMissing).unwrap().unwrap();
    assert_eq!(
        app.path(),
        &RootPath::new(r"D:\Moved\AppData\Local\Rerun").unwrap()
    );
    assert_eq!(names(&sys, r"D:\Moved\AppData\Local"), ["Rerun"]);
}

#[test]
fn a1_a_file_named_rerun_is_an_error_and_never_replaced() {
    let sys = base()
        .file(format!(r"{LAD}\Rerun"), b"not a folder")
        .build()
        .unwrap();
    for create in [Create::Never, Create::IfMissing] {
        let k = sys_kind(AppDir::open(&sys, create));
        assert!(
            matches!(k, SysErrorKind::InvalidPath | SysErrorKind::AccessDenied),
            "{create:?}: {k:?}"
        );
    }
    let fs = sys.fake_fs();
    #[expect(clippy::disallowed_methods, reason = "test: read a fixture")]
    let lad = crate::sys::Fs::open_dir(fs, Path::new(LAD)).unwrap();
    assert_eq!(lad.read(&r("Rerun")).unwrap(), b"not a folder");
}

#[test]
fn a1_fat_opens_but_refuses_the_write_handle() {
    let sys = base().dir(format!(r"{LAD}\Rerun")).build().unwrap();
    sys.fake_fs().set_fs_kind('C', FsKind::Fat);
    let app = AppDir::open(&sys, Create::Never).unwrap().unwrap();
    #[expect(clippy::disallowed_methods, reason = "test of the accessor itself")]
    let e = app.dir_write().unwrap_err();
    assert_eq!(e.kind, SysErrorKind::Unsupported);
    assert_eq!(
        sys_kind(app.sub_write(AppSub::Journal, Create::IfMissing)),
        SysErrorKind::Unsupported
    );
    assert!(app.sub(AppSub::Journal).unwrap().is_none());
    // Missing `Rerun` on FAT: the create is refused by `sys`.
    let sys = base().build().unwrap();
    sys.fake_fs().set_fs_kind('C', FsKind::Fat);
    assert_eq!(
        sys_kind(AppDir::open(&sys, Create::IfMissing)),
        SysErrorKind::Unsupported
    );
    assert!(names(&sys, LAD).is_empty());
}

#[test]
fn a1_sub_folders_are_opened_and_created_one_level() {
    let sys = base().build().unwrap();
    let app = AppDir::open(&sys, Create::IfMissing).unwrap().unwrap();
    for s in [AppSub::Journal, AppSub::Plans, AppSub::Packages] {
        assert!(app.sub(s).unwrap().is_none(), "{s:?}");
        assert!(app.sub_write(s, Create::Never).unwrap().is_none(), "{s:?}");
        let w = app.sub_write(s, Create::IfMissing).unwrap().unwrap();
        let id = w.info().unwrap().file_id;
        assert_eq!(app.sub(s).unwrap().unwrap().info().unwrap().file_id, id);
    }
    assert_eq!(
        names(&sys, &format!(r"{LAD}\Rerun")),
        ["journal", "packages", "plans"]
    );
}

// ---------- A2: reparse points at Rerun and below ----------

#[test]
fn a2_a_junction_or_mount_point_at_rerun_is_refused_and_nothing_is_created_behind_it() {
    for mount in [false, true] {
        let b = base().file(r"C:\Out\canary.txt", b"canary");
        let b = if mount {
            b.mounted_volume(format!(r"{LAD}\Rerun"))
        } else {
            b.junction(format!(r"{LAD}\Rerun"), r"C:\Out")
        };
        let sys = b.build().unwrap();
        for create in [Create::Never, Create::IfMissing] {
            let (store, at) = reparse_at(AppDir::open(&sys, create));
            assert_eq!(store, RootPath::new(LAD).unwrap(), "mount {mount}");
            assert_eq!(at, "Rerun", "mount {mount}");
        }
        assert_eq!(names(&sys, r"C:\Out"), ["canary.txt"], "mount {mount}");
        if mount {
            assert!(names(&sys, &format!(r"{LAD}\Rerun")).is_empty());
        }
    }
}

#[test]
fn a2_a_junction_at_a_sub_folder_is_refused_and_nothing_is_created_behind_it() {
    let sys = base()
        .file(r"C:\Out\canary.txt", b"canary")
        .junction(format!(r"{LAD}\Rerun\journal"), r"C:\Out")
        .build()
        .unwrap();
    let app = AppDir::open(&sys, Create::Never).unwrap().unwrap();
    for create in [Create::Never, Create::IfMissing] {
        let (store, at) = reparse_at(app.sub_write(AppSub::Journal, create));
        assert_eq!((store, at.as_str()), (app.path().clone(), "journal"));
    }
    let (_, at) = reparse_at(app.sub(AppSub::Journal));
    assert_eq!(at, "journal");
    assert_eq!(names(&sys, r"C:\Out"), ["canary.txt"]);
}

// ---------- A3: a swap between create_dir and the open ----------

#[test]
fn a3_a_folder_swapped_between_create_and_open_is_busy() {
    let sys = base().build().unwrap();
    let opens = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&opens);
    let rerun = format!(r"{LAD}\Rerun");
    sys.fake_fs().on_step(move |fs, ev| {
        if ev.op == FsOp::OpenDirWrite && ev.name == "Rerun" {
            // The first open finds nothing; before the second, swap the new folder.
            if seen.fetch_add(1, Ordering::SeqCst) == 1 {
                fs.rename_abs(Path::new(&rerun), Path::new(r"C:\Out\Rerun"))
                    .unwrap();
                fs.mkdir_all(Path::new(&rerun)).unwrap();
            }
        }
    });
    assert_eq!(
        sys_kind(AppDir::open(&sys, Create::IfMissing)),
        SysErrorKind::Busy
    );
    sys.fake_fs().clear_on_step();
    assert_eq!(opens.load(Ordering::SeqCst), 2);
}

#[test]
fn a3_a_folder_swapped_before_the_absolute_reopen_is_busy() {
    let sys = base().dir(format!(r"{LAD}\Rerun")).build().unwrap();
    let rerun = format!(r"{LAD}\Rerun");
    sys.fake_fs().on_step(move |fs, ev| {
        if ev.op == FsOp::OpenAbs && ev.name.ends_with(r"\Rerun") {
            fs.rename_abs(Path::new(&rerun), Path::new(r"C:\Out\Rerun"))
                .unwrap();
            fs.mkdir_all(Path::new(&rerun)).unwrap();
        }
    });
    let r = AppDir::open(&sys, Create::Never);
    sys.fake_fs().clear_on_step();
    assert_eq!(sys_kind(r), SysErrorKind::Busy);
}

#[test]
fn a3_a_junction_to_the_moved_folder_is_escaped() {
    // Same directory (same file ID) reached through a junction: only the path check tells.
    let sys = base().dir(format!(r"{LAD}\Rerun")).build().unwrap();
    let rerun = format!(r"{LAD}\Rerun");
    let moved = format!(r"{LAD}\Rerun2");
    sys.fake_fs().on_step(move |fs, ev| {
        if ev.op == FsOp::OpenAbs && ev.name.ends_with(r"\Rerun") {
            fs.rename_abs(Path::new(&rerun), Path::new(&moved)).unwrap();
            fs.put_link(Path::new(&rerun), crate::sys::fs::tag::MOUNT_POINT, &moved)
                .unwrap();
        }
    });
    let r = AppDir::open(&sys, Create::Never);
    sys.fake_fs().clear_on_step();
    match r {
        Err(RootError::Escaped { store, child }) => {
            assert_eq!(store, RootPath::new(LAD).unwrap());
            assert_eq!(child, RootPath::new(format!(r"{LAD}\Rerun2")).unwrap());
        }
        other => panic!("expected Escaped, got {other:?}"),
    }
}

// ---------- P3-3: `profiles` and the path without opening ----------

#[test]
fn p3_profiles_is_opened_created_and_checked_like_the_other_sub_folders() {
    let sys = base().build().unwrap();
    let app = AppDir::open(&sys, Create::IfMissing).unwrap().unwrap();
    assert!(app.profiles(Create::Never).unwrap().is_none());
    assert!(
        names(&sys, &format!(r"{LAD}\Rerun")).is_empty(),
        "Never creates nothing"
    );
    let p = app.profiles(Create::IfMissing).unwrap().unwrap();
    assert_eq!(
        p.path(),
        &RootPath::new(format!(r"{LAD}\Rerun\profiles")).unwrap()
    );
    #[expect(
        clippy::disallowed_methods,
        reason = "test: profiles hands out its write handle"
    )]
    let w = p.dir_write().is_ok();
    assert!(w);
    drop(p);
    assert!(app.profiles(Create::Never).unwrap().is_some());
    assert_eq!(names(&sys, &format!(r"{LAD}\Rerun")), ["profiles"]);
}

#[test]
fn p3_a_junction_or_mount_point_at_profiles_is_refused_and_nothing_is_created_behind_it() {
    for mount in [false, true] {
        let b = base()
            .file(r"C:\Out\canary.txt", b"canary")
            .dir(format!(r"{LAD}\Rerun"));
        let b = if mount {
            b.mounted_volume(format!(r"{LAD}\Rerun\profiles"))
        } else {
            b.junction(format!(r"{LAD}\Rerun\profiles"), r"C:\Out")
        };
        let sys = b.build().unwrap();
        let app = AppDir::open(&sys, Create::Never).unwrap().unwrap();
        for create in [Create::Never, Create::IfMissing] {
            let (store, at) = reparse_at(app.profiles(create));
            assert_eq!((store, at.as_str()), (app.path().clone(), "profiles"));
        }
        assert_eq!(names(&sys, r"C:\Out"), ["canary.txt"], "mount {mount}");
    }
}

#[test]
fn p3_profiles_on_fat_opens_but_refuses_the_write_handle() {
    let sys = base()
        .dir(format!(r"{LAD}\Rerun\profiles"))
        .build()
        .unwrap();
    sys.fake_fs().set_fs_kind('C', FsKind::Fat);
    let app = AppDir::open(&sys, Create::Never).unwrap().unwrap();
    let r = app.profiles(Create::Never);
    // The write handle of `AppDir` itself is refused first (journal and plans need it too).
    assert_eq!(sys_kind(r), SysErrorKind::Unsupported);
}

#[test]
fn p3_path_of_is_the_path_open_checks_and_creates_nothing() {
    let sys = base().build().unwrap();
    let p = AppDir::path_of(&sys).unwrap();
    assert_eq!(p, RootPath::new(format!(r"{LAD}\Rerun")).unwrap());
    assert!(names(&sys, LAD).is_empty(), "nothing created");
    let app = AppDir::open(&sys, Create::IfMissing).unwrap().unwrap();
    assert_eq!(app.path(), &p);
    // A redirection above `LocalAppData` is followed by both.
    let sys = FakeSystem::builder()
        .dir(r"D:\Moved\AppData\Local")
        .dir(r"C:\Users\Player")
        .junction(r"C:\Users\Player\AppData", r"D:\Moved\AppData")
        .build()
        .unwrap();
    let p = AppDir::path_of(&sys).unwrap();
    assert_eq!(p, RootPath::new(r"D:\Moved\AppData\Local\Rerun").unwrap());
    assert!(names(&sys, r"D:\Moved\AppData\Local").is_empty());
    assert_eq!(
        AppDir::open(&sys, Create::IfMissing)
            .unwrap()
            .unwrap()
            .path(),
        &p
    );
    // A missing `LocalAppData` is an error, never a guess.
    let sys = FakeSystem::builder().build().unwrap();
    assert!(AppDir::path_of(&sys).is_err());
}
