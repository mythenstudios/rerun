use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use super::{Forbidden, ForbiddenRoots, GameOrigin, Protected, RootError, RootId, StoreDir};
use crate::path::{RelPath, RootPath};
use crate::policy::root::GameDir;
use crate::sys::fake::{FakeSystem, FakeSystemBuilder, FsOp};
use crate::sys::fs::tag;
use crate::sys::{KnownFolder, SysErrorKind};

const INSTALL: &str = r"C:\Users\Player\AppData\Local\Programs\Rerun";

fn base() -> FakeSystemBuilder {
    FakeSystem::builder().windows_layout().dir(INSTALL)
}

fn resolve(sys: &FakeSystem) -> Result<ForbiddenRoots, RootError> {
    ForbiddenRoots::resolve(sys, Path::new(INSTALL))
}

fn fr(sys: &FakeSystem) -> ForbiddenRoots {
    resolve(sys).unwrap()
}

fn check(fr: &ForbiddenRoots, s: &str) -> Result<(), Forbidden> {
    fr.check(&RootPath::new(s).unwrap())
}

fn rp(s: &str) -> RootPath {
    RootPath::new(s).unwrap()
}

fn forbidden_reason(r: Result<impl std::fmt::Debug, RootError>) -> Forbidden {
    match r {
        Err(RootError::Forbidden { reason, .. }) => reason,
        other => panic!("expected Forbidden, got {other:?}"),
    }
}

fn sys_kind(r: Result<impl std::fmt::Debug, RootError>) -> SysErrorKind {
    match r {
        Err(RootError::Sys(e)) => e.kind,
        other => panic!("expected Sys, got {other:?}"),
    }
}

fn is_incomplete(r: &Result<ForbiddenRoots, RootError>) -> bool {
    matches!(r, Err(RootError::ForbiddenListIncomplete { .. }))
}

// ---------- Forbidden list ----------

#[test]
fn ordinary_folders_are_allowed() {
    let sys = base().build().unwrap();
    let fr = fr(&sys);
    for ok in [
        r"D:\SteamLibrary",
        r"C:\Program Files (x86)\Steam",
        r"C:\Program Files\Some Game",
        r"C:\ProgramData\GOG\Game",
        r"C:\Games\X",
        r"C:\Users\Player\Games",
        r"C:\Users\Player\AppData\Local\Programs\Game",
        // Component-wise, not prefix matching.
        r"C:\WindowsAppsGames",
        r"C:\Windows2",
        r"C:\Program Files Games",
        r"C:\UsersData",
        r"D:\Recovery Disk Games",
    ] {
        assert_eq!(check(&fr, ok), Ok(()), "{ok}");
    }
}

#[test]
fn protected_folders_are_refused_with_the_right_reason() {
    use Forbidden::{Contains, Inside, Is, OtherUserProfile, VolumeFolder};
    use KnownFolder as K;
    use Protected::{Derived, InstallDir, Known};
    let sys = base().build().unwrap();
    let fr = fr(&sys);
    let cases: Vec<(&str, Forbidden)> = vec![
        (r"C:\Windows", Is(Known(K::Windows))),
        (r"c:\WINDOWS\system32", Inside(Known(K::Windows))),
        (r"C:\Program Files", Is(Known(K::ProgramFiles))),
        (r"C:\Program Files (x86)", Is(Known(K::ProgramFilesX86))),
        (
            r"C:\Program Files\Common Files\x",
            Inside(Known(K::ProgramFilesCommon)),
        ),
        (
            r"C:\Program Files (x86)\Common Files",
            Is(Known(K::ProgramFilesCommonX86)),
        ),
        (
            r"C:\Program Files\WindowsApps\x",
            Inside(Derived(K::ProgramFiles, "WindowsApps")),
        ),
        (
            r"C:\Program Files\Windows Defender",
            Is(Derived(K::ProgramFiles, "Windows Defender")),
        ),
        (
            r"C:\Program Files (x86)\Windows Defender\x",
            Inside(Derived(K::ProgramFilesX86, "Windows Defender")),
        ),
        (r"C:\ProgramData", Is(Known(K::ProgramData))),
        (
            r"C:\ProgramData\Microsoft\x",
            Inside(Derived(K::ProgramData, "Microsoft")),
        ),
        (r"C:\Users", Is(Known(K::UserProfiles))),
        (r"C:\Users\Player", Is(Known(K::Profile))),
        (r"C:\Users\Other\Games", OtherUserProfile),
        (r"C:\Users\Player2", OtherUserProfile),
        (r"C:\Users\Public\Games", OtherUserProfile),
        (r"C:\Users\Default", OtherUserProfile),
        (
            r"C:\Users\Player\AppData\Local\Microsoft\x",
            Inside(Derived(K::LocalAppData, "Microsoft")),
        ),
        (
            r"C:\Users\Player\AppData\Local\Packages\x",
            Inside(Derived(K::LocalAppData, "Packages")),
        ),
        (
            r"C:\Users\Player\AppData\Local\VirtualStore\x",
            Inside(Derived(K::LocalAppData, "VirtualStore")),
        ),
        (
            r"C:\Users\Player\AppData\Local\Rerun",
            Is(Derived(K::LocalAppData, "Rerun")),
        ),
        (
            r"C:\Users\Player\AppData\Roaming\Microsoft\x",
            Inside(Derived(K::RoamingAppData, "Microsoft")),
        ),
        // Containing a protected folder is as bad as being inside it.
        (
            r"C:\Users\Player\AppData",
            Contains(Derived(K::RoamingAppData, "Microsoft")),
        ),
        (
            r"C:\Users\Player\AppData\Local",
            Contains(Derived(K::LocalAppData, "Microsoft")),
        ),
        (INSTALL, Is(InstallDir)),
        (
            r"C:\Users\Player\AppData\Local\Programs\Rerun\x",
            Inside(InstallDir),
        ),
        (
            r"C:\Users\Player\AppData\Local\Programs",
            Contains(InstallDir),
        ),
        // On every volume.
        (r"D:\$Recycle.Bin\x", VolumeFolder("$Recycle.Bin".into())),
        (r"D:\$WinREAgent", VolumeFolder("$WinREAgent".into())),
        (
            r"E:\System Volume Information",
            VolumeFolder("System Volume Information".into()),
        ),
        (r"D:\Recovery", VolumeFolder("Recovery".into())),
        (r"D:\boot\x", VolumeFolder("boot".into())),
        (r"D:\Windows.old\x", VolumeFolder("Windows.old".into())),
        (r"C:\Config.Msi", VolumeFolder("Config.Msi".into())),
        (r"D:\WindowsApps\x", VolumeFolder("WindowsApps".into())),
        (r"D:\WpSystem", VolumeFolder("WpSystem".into())),
        (
            r"E:\WUDownloadCache\x",
            VolumeFolder("WUDownloadCache".into()),
        ),
    ];
    for (path, expected) in cases {
        assert_eq!(check(&fr, path), Err(expected), "{path}");
    }
}

#[test]
fn relocated_folders_are_followed() {
    let sys = FakeSystem::builder()
        .known_folder(KnownFolder::Windows, r"C:\OS\Windows")
        .known_folder(KnownFolder::Profile, r"D:\Profiles\Player")
        .windows_layout()
        .dir(INSTALL)
        .build()
        .unwrap();
    let fr = fr(&sys);
    assert_eq!(
        check(&fr, r"C:\OS"),
        Err(Forbidden::Contains(Protected::Known(KnownFolder::Windows)))
    );
    assert_eq!(check(&fr, r"C:\Windows\Games"), Ok(()));
    assert_eq!(check(&fr, r"D:\Profiles\Player\Games"), Ok(()));
    assert_eq!(
        check(&fr, r"D:\Profiles"),
        Err(Forbidden::Contains(Protected::Known(KnownFolder::Profile)))
    );
    assert_eq!(
        check(&fr, r"C:\Users\Player\Games"),
        Err(Forbidden::OtherUserProfile),
        "the old profile location is no longer the own profile"
    );
}

#[test]
fn a_known_folder_behind_a_junction_is_forbidden_in_both_forms() {
    let link = r"C:\Users\Player\AppData\LocalLink";
    let sys = base()
        .known_folder(KnownFolder::LocalAppData, link)
        .dir(r"D:\Local")
        .junction(link, r"D:\Local")
        .build()
        .unwrap();
    let fr = fr(&sys);
    let derived = Protected::Derived(KnownFolder::LocalAppData, "Microsoft");
    assert_eq!(
        check(&fr, r"D:\Local\Microsoft\x"),
        Err(Forbidden::Inside(derived))
    );
    assert_eq!(
        check(&fr, r"C:\Users\Player\AppData\LocalLink\Microsoft\x"),
        Err(Forbidden::Inside(derived))
    );
}

#[test]
fn roaming_on_a_share_is_skipped() {
    let sys = base()
        .known_folder(KnownFolder::RoamingAppData, r"\\srv\home\Player")
        .build()
        .unwrap();
    let fr = fr(&sys);
    assert_eq!(check(&fr, r"C:\Users\Player\AppData\Roaming\Game"), Ok(()));
}

#[test]
fn every_missing_known_folder_fails_closed() {
    for f in super::forbidden::FORBIDDEN_SOURCES {
        let sys = FakeSystem::builder()
            .windows_layout()
            .without_known_folder(f)
            .dir(INSTALL)
            .build()
            .unwrap();
        assert!(is_incomplete(&resolve(&sys)), "{f}");
    }
}

#[test]
fn unusable_folders_fail_closed() {
    let cases: Vec<(&str, FakeSystem)> = vec![
        (
            "known folder is a file",
            base()
                .known_folder(KnownFolder::Windows, r"C:\WinFile")
                .file(r"C:\WinFile", b"x".to_vec())
                .build()
                .unwrap(),
        ),
        (
            "non-Roaming folder on a share",
            base()
                .known_folder(KnownFolder::ProgramData, r"\\srv\pd")
                .build()
                .unwrap(),
        ),
        (
            // Accepted denial of service by the same user (ADR 0007, ADR 0009): fail closed.
            "LocalAppData on a share",
            base()
                .known_folder(KnownFolder::LocalAppData, r"\\srv\home\Player\Local")
                .build()
                .unwrap(),
        ),
        (
            "Roaming as a device path",
            base()
                .known_folder(KnownFolder::RoamingAppData, r"\\?\C:\Roaming")
                .build()
                .unwrap(),
        ),
        (
            "short name",
            base()
                .known_folder(KnownFolder::ProgramFiles, r"C:\PROGRA~1")
                .build()
                .unwrap(),
        ),
        (
            "drive root",
            base()
                .known_folder(KnownFolder::ProgramData, r"D:\")
                .build()
                .unwrap(),
        ),
        (
            "install folder missing",
            FakeSystem::builder().windows_layout().build().unwrap(),
        ),
    ];
    for (what, sys) in cases {
        assert!(is_incomplete(&resolve(&sys)), "{what}");
    }
}

#[test]
fn a_missing_known_folder_directory_keeps_its_lexical_form() {
    let sys = FakeSystem::builder().dir(INSTALL).build().unwrap();
    let fr = fr(&sys);
    assert_eq!(
        check(&fr, r"C:\Windows\x"),
        Err(Forbidden::Inside(Protected::Known(KnownFolder::Windows)))
    );
}

// ---------- StoreDir ----------

#[test]
fn store_opens_with_canonical_path_and_identity() {
    let sys = base()
        .dir(r"D:\SteamLibrary\steamapps\common\Game")
        .build()
        .unwrap();
    let fr = fr(&sys);
    let store = StoreDir::open(&sys, &fr, Path::new(r"d:\steamlibrary\")).unwrap();
    assert_eq!(store.path(), &rp(r"D:\SteamLibrary"));
    assert_eq!(store.id(), RootId::of(store.info()));
    store.ensure_id(store.id()).unwrap();
}

#[test]
fn moved_library_behind_a_junction_is_allowed() {
    let sys = base()
        .dir(r"D:\Lib\steamapps\common")
        .junction(r"C:\SteamLib", r"D:\Lib")
        .build()
        .unwrap();
    let fr = fr(&sys);
    let store = StoreDir::open(&sys, &fr, Path::new(r"C:\SteamLib")).unwrap();
    assert_eq!(store.path(), &rp(r"D:\Lib"));
}

#[test]
fn junction_into_a_protected_folder_is_caught_canonically() {
    let sys = base()
        .dir(r"C:\Windows\System32")
        .junction(r"D:\Evil", r"C:\Windows\System32")
        .build()
        .unwrap();
    let fr = fr(&sys);
    assert_eq!(
        forbidden_reason(StoreDir::open(&sys, &fr, Path::new(r"D:\Evil"))),
        Forbidden::Inside(Protected::Known(KnownFolder::Windows))
    );
}

#[test]
fn lexically_invalid_store_paths_are_refused() {
    let sys = base().build().unwrap();
    let fr = fr(&sys);
    for bad in [
        r"\\srv\share\lib",
        r"\\?\UNC\srv\share",
        r"\\.\GLOBALROOT\Device\HarddiskVolume1",
        r"\\?\C:\Lib",
        r"C:\",
        r"C:\x\..\Windows",
        r"relative\lib",
        r"C:\PROGRA~1",
    ] {
        let r = StoreDir::open(&sys, &fr, Path::new(bad));
        assert!(matches!(r, Err(RootError::InvalidPath(_))), "{bad}: {r:?}");
    }
}

#[test]
fn store_errors_from_the_system_are_passed_on() {
    let sys = base().file(r"D:\file.txt", b"x".to_vec()).build().unwrap();
    let fr = fr(&sys);
    assert_eq!(
        sys_kind(StoreDir::open(&sys, &fr, Path::new(r"D:\file.txt"))),
        SysErrorKind::InvalidPath
    );
    assert_eq!(
        sys_kind(StoreDir::open(&sys, &fr, Path::new(r"D:\missing"))),
        SysErrorKind::NotFound
    );
}

#[test]
fn a_folder_mounted_volume_is_not_a_root() {
    let sys = base().mounted_volume(r"D:\Mounts\Lib").build().unwrap();
    let fr = fr(&sys);
    assert_eq!(
        forbidden_reason(StoreDir::open(&sys, &fr, Path::new(r"D:\Mounts\Lib"))),
        Forbidden::VolumeRoot
    );
}

#[test]
fn per_volume_folders_apply_on_folder_mounted_volumes() {
    // ADR 0007 amendment: the per-volume rule also runs on the volume-relative path.
    let sys = base()
        .mounted_volume(r"D:\Mounts\Data")
        .dir(r"D:\Mounts\Data\$Recycle.Bin\G")
        .dir(r"D:\Mounts\Data\Recovery\G")
        .dir(r"D:\Mounts\Data\WindowsApps\G")
        .dir(r"D:\Mounts\Data\Games\G")
        .build()
        .unwrap();
    let fr = fr(&sys);
    for (abs, first) in [
        (r"D:\Mounts\Data\$Recycle.Bin\G", "$Recycle.Bin"),
        (r"D:\Mounts\Data\Recovery\G", "Recovery"),
        (r"D:\Mounts\Data\WindowsApps\G", "WindowsApps"),
    ] {
        assert!(check(&fr, abs).is_ok(), "lexically allowed: {abs}");
        assert_eq!(
            forbidden_reason(StoreDir::open(&sys, &fr, Path::new(abs))),
            Forbidden::VolumeFolder(first.to_owned()),
            "{abs}"
        );
    }
    StoreDir::open(&sys, &fr, Path::new(r"D:\Mounts\Data\Games\G")).unwrap();
}

// ---------- GameDir ----------

const LIB: &str = r"D:\Lib";
const GAME: &str = r"D:\Lib\steamapps\common\Game";

#[test]
fn game_opens_relative_to_its_store() {
    let sys = base().dir(GAME).build().unwrap();
    let fr = fr(&sys);
    let store = StoreDir::open(&sys, &fr, Path::new(LIB)).unwrap();
    let game = store.game(&fr, "game").unwrap();
    assert_eq!(game.path(), &rp(GAME));
    assert_eq!(
        game.origin(),
        &GameOrigin::Store {
            store: rp(LIB),
            store_id: store.id(),
            installdir: RelPath::parse("game").unwrap(),
        }
    );
    game.ensure_id(game.id()).unwrap();
}

#[test]
fn invalid_installdir_is_an_anomaly_without_any_lookup() {
    let sys = base().dir(GAME).build().unwrap();
    let fr = fr(&sys);
    let store = StoreDir::open(&sys, &fr, Path::new(LIB)).unwrap();
    let steps = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&steps);
    sys.fake_fs().on_step(move |_, _| {
        counter.fetch_add(1, Ordering::SeqCst);
    });
    for bad in [
        "",
        "..",
        ".",
        r"a\b",
        "a/b",
        "CON",
        "x.",
        "PROGRA~1",
        "bad\u{FFFD}",
        "C:",
    ] {
        let r = store.game(&fr, bad);
        assert!(matches!(r, Err(RootError::Anomaly(_))), "{bad:?}: {r:?}");
    }
    assert_eq!(steps.load(Ordering::SeqCst), 0, "no lookup for a bad name");
}

#[test]
fn case_sensitive_common_is_an_anomaly() {
    let sys = base()
        .case_sensitive_dir(r"D:\Lib\steamapps\common")
        .dir(GAME)
        .build()
        .unwrap();
    let fr = fr(&sys);
    let store = StoreDir::open(&sys, &fr, Path::new(LIB)).unwrap();
    assert!(matches!(
        store.game(&fr, "Game"),
        Err(RootError::Anomaly(_))
    ));
}

#[test]
fn reparse_points_between_store_and_game_are_anomalies() {
    let other = r"D:\Other\steamapps\common\Game";
    let cases = [
        (r"D:\Lib\steamapps", r"D:\Other\steamapps"),
        (r"D:\Lib\steamapps\common", r"D:\Other\steamapps\common"),
        (GAME, other),
    ];
    for (link, target) in cases {
        let sys = base()
            .dir(other)
            .dir(Path::new(link).parent().unwrap())
            .junction(link, target)
            .build()
            .unwrap();
        let fr = fr(&sys);
        let store = StoreDir::open(&sys, &fr, Path::new(LIB)).unwrap();
        let r = store.game(&fr, "Game");
        assert!(matches!(r, Err(RootError::Reparse { .. })), "{link}: {r:?}");
    }
}

#[test]
fn data_tags_pass_unknown_tags_do_not() {
    for (t, ok) in [(tag::CLOUD, true), (tag::PROJFS, false)] {
        let sys = base().tagged_dir(GAME, t).build().unwrap();
        let fr = fr(&sys);
        let store = StoreDir::open(&sys, &fr, Path::new(LIB)).unwrap();
        let r = store.game(&fr, "Game");
        if ok {
            assert!(r.is_ok(), "{t:#x}: {r:?}");
        } else {
            assert!(matches!(r, Err(RootError::Reparse { .. })), "{t:#x}: {r:?}");
        }
    }
}

#[test]
fn swap_to_a_junction_during_the_walk_is_caught() {
    let canary = r"C:\Windows\System32\canary.dll";
    let sys = base()
        .dir(GAME)
        .protected_dir(r"C:\Windows\System32")
        .file(canary, b"canary".to_vec())
        .build()
        .unwrap();
    let fr = fr(&sys);
    let store = StoreDir::open(&sys, &fr, Path::new(LIB)).unwrap();
    let fired = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&fired);
    sys.fake_fs().on_step(move |fs, e| {
        if e.op == FsOp::OpenDirWrite && e.index == 2 && !flag.swap(true, Ordering::SeqCst) {
            fs.swap_with_junction(Path::new(GAME), r"C:\Windows\System32")
                .unwrap();
        }
    });
    let r = store.game(&fr, "Game");
    sys.fake_fs().clear_on_step();
    assert!(fired.load(Ordering::SeqCst), "hook ran");
    assert!(matches!(r, Err(RootError::Reparse { .. })), "{r:?}");
    let sys32 = StoreDir::open(&sys, &fr, Path::new(r"C:\Windows\System32"));
    assert!(sys32.is_err(), "System32 is never a root");
    let windows = super::open_abs(&sys, Path::new(r"C:\Windows\System32")).unwrap();
    assert_eq!(
        windows
            .read(&RelPath::parse("canary.dll").unwrap())
            .unwrap(),
        b"canary"
    );
}

#[test]
fn swap_after_open_keeps_the_handle_and_identity_catches_a_replacement() {
    let sys = base().dir(GAME).dir(r"D:\Other").build().unwrap();
    let fr = fr(&sys);
    let store = StoreDir::open(&sys, &fr, Path::new(LIB)).unwrap();
    let game = store.game(&fr, "Game").unwrap();
    let id = game.id();
    let hidden = sys.swap_with_junction(GAME, r"D:\Other").unwrap();

    let now = game.dir().info().unwrap();
    assert!(
        now.final_path.ends_with(&hidden),
        "the held handle follows its directory"
    );
    assert!(matches!(
        store.game(&fr, "Game"),
        Err(RootError::Reparse { .. })
    ));

    sys.fake_fs().remove_abs(Path::new(GAME)).unwrap();
    sys.fake_fs().mkdir_all(Path::new(GAME)).unwrap();
    let fresh = store.game(&fr, "Game").unwrap();
    assert!(matches!(
        fresh.ensure_id(id),
        Err(RootError::IdentityMismatch { .. })
    ));
}

#[test]
#[expect(
    clippy::disallowed_methods,
    reason = "test of GameDir::dir_write itself"
)]
fn only_a_game_folder_on_a_posix_volume_hands_out_a_write_handle() {
    // `StoreDir` has no write accessor at all (ADR 0017); its `dir()` is `&dyn Dir`.
    let sys = base()
        .file(format!(r"{GAME}\game.exe"), "MZ")
        .file(r"E:\Lib\steamapps\common\Game\game.exe", "MZ")
        .dir(r"E:\Manual")
        .build()
        .unwrap();
    sys.fake_fs()
        .set_fs_kind('E', crate::sys::fs::FsKind::ExFat);
    let fr = fr(&sys);
    let store = StoreDir::open(&sys, &fr, Path::new(LIB)).unwrap();
    let game = store.game(&fr, "Game").unwrap();
    let w = game.dir_write().unwrap();
    // The same directory as the read side.
    assert_eq!(w.info().unwrap().file_id, game.id().file_id);
    assert_eq!(w.read(&RelPath::parse("GAME.EXE").unwrap()).unwrap(), b"MZ");

    let exfat = StoreDir::open(&sys, &fr, Path::new(r"E:\Lib")).unwrap();
    for g in [
        exfat.game(&fr, "Game").unwrap(),
        GameDir::open_manual(&sys, &fr, Path::new(r"E:\Manual")).unwrap(),
    ] {
        let e = g.dir_write().map(|_| ()).unwrap_err();
        assert_eq!(e.kind, SysErrorKind::Unsupported);
        assert!(e.target.contains("POSIX"), "{e}");
        // Reading stays possible.
        g.dir().read_dir(None).unwrap();
    }
}

#[test]
fn a_mounted_volume_at_the_game_folder_is_refused_below_the_store() {
    // Below a root a mounted volume is a mount point (a name surrogate), so the relative walk
    // refuses it as a reparse point before the volume-root check could apply. The check on
    // the opened directory stays for roots opened by absolute path
    // (`a_folder_mounted_volume_is_not_a_root`).
    let sys = base()
        .dir(r"D:\Lib\steamapps\common")
        .mounted_volume(GAME)
        .build()
        .unwrap();
    let fr = fr(&sys);
    let store = StoreDir::open(&sys, &fr, Path::new(LIB)).unwrap();
    assert!(matches!(
        store.game(&fr, "Game"),
        Err(RootError::Reparse { .. })
    ));
}

#[test]
fn manual_game_folders() {
    let sys = base()
        .dir(r"D:\Games\Old")
        .junction(r"C:\OldLink", r"D:\Games\Old")
        .dir(r"C:\Windows\Games")
        .protected_dir(r"D:\Protected\Game")
        .build()
        .unwrap();
    let fr = fr(&sys);

    let g = GameDir::open_manual(&sys, &fr, Path::new(r"D:\Games\Old")).unwrap();
    assert_eq!(g.origin(), &GameOrigin::Manual);

    let via = GameDir::open_manual(&sys, &fr, Path::new(r"C:\OldLink")).unwrap();
    assert_eq!(via.path(), &rp(r"D:\Games\Old"));
    assert_eq!(via.id(), g.id());

    assert_eq!(
        forbidden_reason(GameDir::open_manual(
            &sys,
            &fr,
            Path::new(r"C:\Windows\Games")
        )),
        Forbidden::Inside(Protected::Known(KnownFolder::Windows))
    );

    let p = GameDir::open_manual(&sys, &fr, Path::new(r"D:\Protected\Game")).unwrap();
    assert!(
        !p.info().user_writable,
        "admin-only folders are allowed roots"
    );
}

// ---------- Store identity ----------

#[test]
fn a_recreated_store_has_another_identity() {
    let sys = base().dir(LIB).build().unwrap();
    let fr = fr(&sys);
    let id = StoreDir::open(&sys, &fr, Path::new(LIB)).unwrap().id();
    sys.rename_abs(LIB, r"D:\LibOld").unwrap();
    sys.fake_fs().mkdir_all(Path::new(LIB)).unwrap();
    let again = StoreDir::open(&sys, &fr, Path::new(LIB)).unwrap();
    assert!(matches!(
        again.ensure_id(id),
        Err(RootError::IdentityMismatch { .. })
    ));
}

#[test]
fn a_renamed_parent_is_not_found_by_the_old_path() {
    let sys = base().dir(r"D:\Parent\Lib").build().unwrap();
    let fr = fr(&sys);
    let store = StoreDir::open(&sys, &fr, Path::new(r"D:\Parent\Lib")).unwrap();
    let old = store.path().clone();
    sys.rename_abs(r"D:\Parent", r"D:\P2").unwrap();
    assert_eq!(
        sys_kind(StoreDir::open(&sys, &fr, old.path())),
        SysErrorKind::NotFound
    );
    assert_eq!(
        store.dir().info().unwrap().final_path,
        Path::new(r"\\?\D:\P2\Lib")
    );
}

#[test]
fn root_id_display_is_fixed_width_hex() {
    let id = RootId {
        volume_serial: 0x5EED_0044,
        file_id: 7,
    };
    assert_eq!(
        id.to_string(),
        "000000005eed0044-00000000000000000000000000000007"
    );
}

// ---------- Review follow-ups ----------

#[test]
fn own_profile_exemption_does_not_fold_beyond_ascii() {
    // `ſ` (long s) upper-cases to `S` in Rust but not in the NTFS upcase table.
    let sys = FakeSystem::builder()
        .known_folder(KnownFolder::Profile, r"C:\Users\ſam")
        .known_folder(KnownFolder::LocalAppData, r"C:\Users\ſam\AppData\Local")
        .known_folder(KnownFolder::RoamingAppData, r"C:\Users\ſam\AppData\Roaming")
        .windows_layout()
        .dir(r"C:\Rerun")
        .build()
        .unwrap();
    let fr = ForbiddenRoots::resolve(&sys, Path::new(r"C:\Rerun")).unwrap();
    assert_eq!(check(&fr, r"C:\Users\ſam\Games"), Ok(()));
    assert_eq!(
        check(&fr, r"C:\Users\ſAM\Games"),
        Ok(()),
        "ASCII case is ignored"
    );
    assert_eq!(
        check(&fr, r"C:\Users\SAM\Games"),
        Err(Forbidden::OtherUserProfile)
    );
}

#[test]
fn a_store_moved_after_open_is_reported() {
    let sys = base().dir(GAME).build().unwrap();
    let fr = fr(&sys);
    let store = StoreDir::open(&sys, &fr, Path::new(LIB)).unwrap();
    sys.rename_abs(LIB, r"D:\Lib2").unwrap();
    assert!(matches!(
        store.game(&fr, "Game"),
        Err(RootError::StoreMoved { .. })
    ));
}

#[test]
fn game_whose_common_was_swapped_during_the_open_is_refused() {
    // After the game walk, `common` is renamed and an empty case-insensitive `common` put in
    // its place: the game handle no longer belongs to the `common` that is checked.
    let sys = base().dir(GAME).build().unwrap();
    let fr = fr(&sys);
    let store = StoreDir::open(&sys, &fr, Path::new(LIB)).unwrap();
    // `game()` walks `steamapps`, `common`, `Game` with the write capability (events 1–3),
    // then opens `steamapps\common` again (events 4–5). Swap right before event 4.
    let events = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&events);
    sys.fake_fs().on_step(move |fs, e| {
        let walk = matches!(e.op, FsOp::OpenDir | FsOp::OpenDirWrite);
        if walk && seen.fetch_add(1, Ordering::SeqCst) == 3 {
            fs.rename_abs(
                Path::new(r"D:\Lib\steamapps\common"),
                Path::new(r"D:\Lib\steamapps\common.old"),
            )
            .unwrap();
            fs.mkdir_all(Path::new(r"D:\Lib\steamapps\common")).unwrap();
        }
    });
    let r = store.game(&fr, "Game");
    sys.fake_fs().clear_on_step();
    assert!(events.load(Ordering::SeqCst) >= 4, "swap happened");
    assert!(
        matches!(&r, Err(RootError::Sys(e)) if e.kind == SysErrorKind::NotFound),
        "{r:?}"
    );
}

#[test]
fn root_path_child_takes_one_segment_only() {
    let root = rp(r"C:\Games");
    assert!(root.child("X").is_ok());
    for bad in [r"a\b", r"C:\Windows", "..", "", "CON"] {
        assert!(root.child(bad).is_err(), "{bad}");
    }
}

#[test]
fn redirected_appdata_keeps_the_default_forms_forbidden() {
    use Forbidden::{Contains, Inside, Is};
    use KnownFolder as K;
    use Protected::{Derived, ProfileDefault};
    let sys = base()
        .known_folder(K::LocalAppData, r"D:\Redirected\Local")
        .known_folder(K::RoamingAppData, r"E:\Redirected\Roaming")
        .dir(r"D:\Redirected\Local")
        .dir(r"E:\Redirected\Roaming")
        .build()
        .unwrap();
    let fr = fr(&sys);
    let cases: Vec<(&str, Forbidden)> = vec![
        // The default forms below the profile stay forbidden.
        (
            r"C:\Users\Player\AppData\Local\Microsoft\x",
            Inside(ProfileDefault(r"AppData\Local\Microsoft")),
        ),
        (
            r"C:\Users\Player\AppData\Local\Packages",
            Is(ProfileDefault(r"AppData\Local\Packages")),
        ),
        (
            r"C:\Users\Player\AppData\Local\VirtualStore\x",
            Inside(ProfileDefault(r"AppData\Local\VirtualStore")),
        ),
        (
            r"C:\Users\Player\AppData\Local\Rerun",
            Is(ProfileDefault(r"AppData\Local\Rerun")),
        ),
        (
            r"C:\Users\Player\AppData\Roaming\Microsoft\x",
            Inside(ProfileDefault(r"AppData\Roaming\Microsoft")),
        ),
        (
            r"C:\Users\Player\AppData\Local",
            Contains(ProfileDefault(r"AppData\Local\Microsoft")),
        ),
        (
            r"C:\Users\Player\AppData\Roaming",
            Contains(ProfileDefault(r"AppData\Roaming\Microsoft")),
        ),
        // The redirected forms are forbidden too.
        (
            r"D:\Redirected\Local\Microsoft\x",
            Inside(Derived(K::LocalAppData, "Microsoft")),
        ),
        (
            r"D:\Redirected\Local\Rerun",
            Is(Derived(K::LocalAppData, "Rerun")),
        ),
        (
            r"E:\Redirected\Roaming\Microsoft",
            Is(Derived(K::RoamingAppData, "Microsoft")),
        ),
        (
            r"D:\Redirected",
            Contains(Derived(K::LocalAppData, "Microsoft")),
        ),
    ];
    for (path, expected) in cases {
        assert_eq!(check(&fr, path), Err(expected), "{path}");
    }
    for ok in [
        r"C:\Users\Player\AppData\Local\Programs\Game",
        r"D:\Redirected\Local\Programs\Game",
        r"E:\Redirected\Roaming\Game",
    ] {
        assert_eq!(check(&fr, ok), Ok(()), "{ok}");
    }
    assert_eq!(
        ProfileDefault(r"AppData\Local\Microsoft").to_string(),
        r"Profile\AppData\Local\Microsoft"
    );
}

#[test]
fn the_default_forms_follow_every_form_of_the_profile() {
    // A profile behind a junction: its lexical and its canonical form both get the defaults.
    let sys = base()
        .dir(r"D:\Profiles\Player")
        .junction(r"C:\Users\Link", r"D:\Profiles\Player")
        .known_folder(KnownFolder::Profile, r"C:\Users\Link")
        .build()
        .unwrap();
    let fr = fr(&sys);
    let microsoft = Protected::ProfileDefault(r"AppData\Local\Microsoft");
    for p in [
        r"C:\Users\Link\AppData\Local\Microsoft\x",
        r"D:\Profiles\Player\AppData\Local\Microsoft\x",
    ] {
        assert_eq!(check(&fr, p), Err(Forbidden::Inside(microsoft)), "{p}");
    }
}

#[test]
fn the_default_forms_follow_a_junctioned_appdata_local() {
    // LocalAppData redirected to E:\X, and <Profile>\AppData\Local itself a junction to D:\L:
    // the defaults are forbidden in the junction's canonical form as well.
    let install = r"E:\X\Programs\Rerun";
    let sys = FakeSystem::builder()
        .known_folder(KnownFolder::LocalAppData, r"E:\X")
        .windows_layout()
        .dir(install)
        .dir(r"D:\L")
        .junction(r"C:\Users\Player\AppData\Local", r"D:\L")
        .build()
        .unwrap();
    let fr = ForbiddenRoots::resolve(&sys, Path::new(install)).unwrap();
    let packages = Protected::ProfileDefault(r"AppData\Local\Packages");
    for p in [r"D:\L\Packages", r"C:\Users\Player\AppData\Local\Packages"] {
        assert_eq!(check(&fr, p), Err(Forbidden::Is(packages)), "{p}");
    }
    assert_eq!(
        check(&fr, r"D:\L\Microsoft\x"),
        Err(Forbidden::Inside(Protected::ProfileDefault(
            r"AppData\Local\Microsoft"
        )))
    );
    assert_eq!(check(&fr, r"D:\L\Games"), Ok(()));
}
