#![expect(
    clippy::disallowed_methods,
    reason = "tests of the fake open directories by absolute path"
)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use super::{FakeFs, FakeSystem, FsOp, StepEvent};
use crate::path::RelPath;
use crate::sys::contract::{
    fs_link_contract, fs_read_contract, fs_write_contract, gpu_contract, known_folders_contract,
    registry_contract, topology_contract,
};
use crate::sys::fs::{Attrs, Dir, EntryKind, Fs, FsKind, tag};
use crate::sys::registry::{Hive, RegKey, RegValue, RegView};
use crate::sys::snapshot::{Scope, snapshot};
use crate::sys::{DriverVersion, GpuAdapter, KnownFolder};
use crate::sys::{SysErrorKind, System};

const RYZEN_5950X: &str = include_str!("../../../../../tests/fixtures/cpu/ryzen9-5950x.json");
const I5_6600: &str = include_str!("../../../../../tests/fixtures/cpu/i5-6600.json");

fn p(s: &str) -> PathBuf {
    PathBuf::from(s)
}

fn r(s: &str) -> RelPath {
    RelPath::parse(s).unwrap()
}

fn hkcu(path: &str) -> RegKey {
    RegKey::new(Hive::CurrentUser, RegView::Native, path)
}

fn open<'a>(sys: &'a FakeSystem, abs: &str) -> Box<dyn Dir + 'a> {
    sys.fs().open_dir(Path::new(abs)).unwrap()
}

fn kind<T: std::fmt::Debug>(res: crate::sys::SysResult<T>) -> SysErrorKind {
    res.unwrap_err().kind
}

// ---------- Contracts ----------

#[test]
fn fake_fulfils_fs_read_contract() {
    let sys = FakeSystem::builder().dir(r"C:\Work").build().unwrap();
    fs_read_contract(&sys, Path::new(r"C:\Work")).unwrap();
}

#[test]
fn fake_fulfils_fs_write_contract() {
    let sys = FakeSystem::builder().dir(r"C:\Work").build().unwrap();
    fs_write_contract(&sys, Path::new(r"C:\Work")).unwrap();
}

#[test]
fn fake_fulfils_fs_link_contract() {
    let sys = FakeSystem::builder().dir(r"D:\Work").build().unwrap();
    fs_link_contract(&sys, sys.fake_fs(), Path::new(r"D:\Work")).unwrap();
}

#[test]
fn contracts_can_run_twice_on_the_same_dir() {
    let sys = FakeSystem::builder().dir(r"C:\Work").build().unwrap();
    let work = Path::new(r"C:\Work");
    for _ in 0..2 {
        fs_read_contract(&sys, work).unwrap();
        fs_write_contract(&sys, work).unwrap();
        fs_link_contract(&sys, sys.fake_fs(), work).unwrap();
    }
}

#[test]
fn fake_fulfils_registry_contract() {
    let root = hkcu(r"Software\RerunContract");
    let sys = FakeSystem::builder().key(root.clone()).build().unwrap();
    registry_contract(&sys, &root).unwrap();
}

#[test]
fn fixtures_fulfil_topology_contract() {
    for json in [RYZEN_5950X, I5_6600] {
        let sys = FakeSystem::builder().topology_json(json).build().unwrap();
        topology_contract(&sys).unwrap();
    }
}

fn adapter(name: &str, luid: u64) -> GpuAdapter {
    GpuAdapter {
        name: name.to_owned(),
        vendor_id: 0x1002,
        device_id: 0x1234,
        luid,
        dedicated_video_memory: 16 << 30,
        umd_version: Some(DriverVersion([32, 0, 21001, 9])),
        ..GpuAdapter::default()
    }
}

fn basic_render(luid: u64) -> GpuAdapter {
    GpuAdapter {
        name: "Microsoft Basic Render Driver".to_owned(),
        vendor_id: 0x1414,
        device_id: 0x8c,
        luid,
        software: true,
        ..GpuAdapter::default()
    }
}

#[test]
fn fake_fulfils_known_folders_contract() {
    let sys = FakeSystem::builder().windows_layout().build().unwrap();
    known_folders_contract(&sys).unwrap();
}

#[test]
fn known_folders_contract_allows_roaming_on_a_share() {
    let sys = FakeSystem::builder()
        .known_folder(KnownFolder::RoamingAppData, r"\\server\home\player\Roaming")
        .windows_layout()
        .build()
        .unwrap();
    known_folders_contract(&sys).unwrap();
}

#[test]
fn known_folders_contract_catches_bad_folders() {
    let cases: [(&str, FakeSystem); 5] = [
        (
            "missing folder",
            FakeSystem::builder()
                .without_known_folder(KnownFolder::ProgramData)
                .windows_layout()
                .build()
                .unwrap(),
        ),
        ("directory missing", FakeSystem::builder().build().unwrap()),
        (
            "two folders equal (other case)",
            FakeSystem::builder()
                .known_folder(KnownFolder::ProgramFilesX86, r"c:\PROGRAM FILES")
                .windows_layout()
                .build()
                .unwrap(),
        ),
        (
            "share outside Roaming",
            FakeSystem::builder()
                .known_folder(KnownFolder::LocalAppData, r"\\server\local")
                .windows_layout()
                .build()
                .unwrap(),
        ),
        (
            "device path for Roaming",
            FakeSystem::builder()
                .known_folder(KnownFolder::RoamingAppData, r"\\?\C:\Users\Player\Roaming")
                .windows_layout()
                .build()
                .unwrap(),
        ),
    ];
    for (what, sys) in cases {
        assert!(known_folders_contract(&sys).is_err(), "{what}");
    }
}

#[test]
fn known_folders_are_configurable() {
    let sys = FakeSystem::builder()
        .known_folder(KnownFolder::Profile, r"D:\Profiles\Alice")
        .without_known_folder(KnownFolder::ProgramFilesX86)
        .build()
        .unwrap();
    let kf = sys.known_folders();
    assert_eq!(
        kf.get(KnownFolder::Profile).unwrap(),
        p(r"D:\Profiles\Alice")
    );
    assert_eq!(kf.get(KnownFolder::Windows).unwrap(), p(r"C:\Windows"));
    assert_eq!(
        kind(kf.get(KnownFolder::ProgramFilesX86)),
        SysErrorKind::NotFound
    );
}

#[test]
fn windows_layout_creates_the_configured_directories() {
    let sys = FakeSystem::builder()
        .known_folder(KnownFolder::Profile, r"D:\Profiles\Alice")
        .windows_layout()
        .build()
        .unwrap();
    for f in KnownFolder::ALL {
        let path = sys.known_folders().get(f).unwrap();
        assert!(sys.fs().open_dir(&path).is_ok(), "{f}");
    }
}

#[test]
fn fake_fulfils_gpu_contract() {
    let sys = FakeSystem::builder()
        .gpu(adapter("Fake Radeon", 1))
        .gpu(basic_render(2))
        .build()
        .unwrap();
    gpu_contract(&sys).unwrap();
    let adapters = sys.gpu().adapters().unwrap();
    assert_eq!(adapters[0].name, "Fake Radeon", "builder keeps DXGI order");
    assert!(adapters[1].software);
}

#[test]
fn gpu_contract_catches_bad_adapters() {
    let long = "x".repeat(128);
    let cases: [(&str, FakeSystem); 5] = [
        ("no adapter", FakeSystem::new()),
        (
            "error",
            FakeSystem::builder()
                .gpu(basic_render(1))
                .gpu_error(SysErrorKind::Unsupported)
                .build()
                .unwrap(),
        ),
        (
            "duplicate luid",
            FakeSystem::builder()
                .gpu(adapter("A", 7))
                .gpu(adapter("B", 7))
                .build()
                .unwrap(),
        ),
        (
            "empty name",
            FakeSystem::builder().gpu(adapter("", 1)).build().unwrap(),
        ),
        (
            "name too long",
            FakeSystem::builder()
                .gpu(adapter(&long, 1))
                .build()
                .unwrap(),
        ),
    ];
    for (what, sys) in cases {
        assert!(gpu_contract(&sys).is_err(), "{what}");
    }
    let nul = FakeSystem::builder()
        .gpu(adapter("A\0B", 1))
        .build()
        .unwrap();
    assert!(gpu_contract(&nul).is_err(), "control character");
}

#[test]
fn gpu_error_is_reported() {
    let sys = FakeSystem::builder()
        .gpu_error(SysErrorKind::Unsupported)
        .build()
        .unwrap();
    assert_eq!(kind(sys.gpu().adapters()), SysErrorKind::Unsupported);
}

// ---------- File system ----------

#[test]
fn reparse_point_is_visible_but_not_followed() {
    let sys = FakeSystem::builder()
        .file(r"C:\Outside\secret.txt", "x")
        .junction(r"C:\Games\G\link", r"C:\Outside")
        .build()
        .unwrap();
    let g = open(&sys, r"C:\Games\G");
    let meta = g.metadata(&r("link")).unwrap().unwrap();
    assert_eq!(meta.kind, EntryKind::Reparse);
    let info = meta.reparse.unwrap();
    assert!(info.surrogate);
    assert_eq!(info.tag, tag::MOUNT_POINT);
    assert_eq!(info.target.as_deref(), Some(r"C:\Outside"));
    assert_eq!(
        sys.fake_fs()
            .reparse_target(&p(r"C:\Games\G\link"))
            .unwrap(),
        Some(r"C:\Outside".to_owned())
    );
    assert_eq!(
        kind(g.read(&r(r"link\secret.txt"))),
        SysErrorKind::ReparsePoint
    );
    assert_eq!(
        kind(g.metadata(&r(r"link\secret.txt"))),
        SysErrorKind::ReparsePoint
    );
    // Deleting removes only the link, never the target.
    g.remove_file(&r("link")).unwrap();
    assert!(
        open(&sys, r"C:\Outside")
            .metadata(&r("secret.txt"))
            .unwrap()
            .is_some()
    );
}

#[test]
fn absolute_open_follows_links_and_reports_the_final_path() {
    let sys = FakeSystem::builder()
        .dir(r"E:\Library\steamapps")
        .junction(r"C:\Steam\Moved", r"E:\Library")
        .junction(r"C:\Steam\Rel", r"..\Steam\Moved\steamapps")
        .build()
        .unwrap();
    let a = open(&sys, r"c:\steam\moved\STEAMAPPS");
    let info = a.info().unwrap();
    assert_eq!(info.final_path, p(r"\\?\E:\Library\steamapps"));
    assert_ne!(
        info.volume_serial,
        open(&sys, r"C:\Steam").info().unwrap().volume_serial
    );
    let b = open(&sys, r"C:\Steam\Rel");
    assert_eq!(b.info().unwrap().file_id, info.file_id);
    assert_eq!(
        open(&sys, r"\\?\C:\Steam").info().unwrap().final_path,
        p(r"\\?\C:\Steam")
    );
    assert_eq!(open(&sys, r"C:\").info().unwrap().final_path, p(r"\\?\C:\"));
}

#[test]
fn link_loops_are_an_error() {
    let sys = FakeSystem::builder()
        .junction(r"C:\a", r"C:\b")
        .junction(r"C:\b", r"C:\a")
        .build()
        .unwrap();
    assert_eq!(kind(sys.fs().open_dir(&p(r"C:\a"))), SysErrorKind::Other);
}

#[test]
fn dot_segments_and_non_drive_paths_are_rejected() {
    let sys = FakeSystem::new();
    for bad in [
        r"C:\a\..\b",
        r"C:\.\a",
        r"\\server\share\a",
        r"\\?\UNC\server\share",
        r"a\b",
        r"C:a",
        r"C:\a|b",
    ] {
        assert_eq!(
            kind(sys.fs().open_dir(&p(bad))),
            SysErrorKind::InvalidPath,
            "{bad}"
        );
    }
    assert_eq!(
        kind(sys.fs().open_dir(&p(r"C:\missing"))),
        SysErrorKind::NotFound
    );
}

#[test]
fn forward_slashes_are_accepted() {
    let sys = FakeSystem::builder()
        .file("C:/Games/a.txt", "x")
        .build()
        .unwrap();
    assert_eq!(open(&sys, "c:/games").read(&r("A.TXT")).unwrap(), b"x");
}

#[test]
fn rename_moves_directory_with_children() {
    let sys = FakeSystem::builder()
        .file(r"C:\G\scripts\a.asi", "a")
        .file(r"C:\G\scripts\sub\b.ini", "b")
        .build()
        .unwrap();
    let g = open(&sys, r"C:\G");
    g.rename(&r("scripts"), &r("plugins")).unwrap();
    assert_eq!(g.read(&r(r"plugins\sub\b.ini")).unwrap(), b"b");
    assert!(g.metadata(&r("scripts")).unwrap().is_none());
    assert_eq!(
        kind(g.rename(&r("plugins"), &r(r"plugins\sub\x"))),
        SysErrorKind::InvalidPath
    );
}

#[test]
fn directory_is_not_a_file() {
    let sys = FakeSystem::builder()
        .dir(r"C:\G\d")
        .file(r"C:\G\f", "x")
        .build()
        .unwrap();
    let g = open(&sys, r"C:\G");
    assert_eq!(kind(g.read(&r("d"))), SysErrorKind::AccessDenied);
    assert_eq!(
        kind(g.replace(&r("d"), b"x", "d.tmp")),
        SysErrorKind::AccessDenied
    );
    assert_eq!(kind(g.remove_file(&r("d"))), SysErrorKind::AccessDenied);
    assert_eq!(kind(g.remove_dir(&r("f"))), SysErrorKind::InvalidPath);
    assert_eq!(kind(g.read_dir(Some(&r("f")))), SysErrorKind::InvalidPath);
    // File as parent directory.
    assert_eq!(
        kind(g.create_new(&r(r"f\x"), b"x")),
        SysErrorKind::InvalidPath
    );
    assert_eq!(g.metadata(&r(r"f\x")).unwrap(), None);
}

#[test]
fn replace_keeps_existing_name_case() {
    let sys = FakeSystem::builder()
        .file(r"C:\G\Game.ini", "a")
        .build()
        .unwrap();
    let g = open(&sys, r"C:\G");
    g.replace(&r("GAME.INI"), b"b", "Game.ini.rerun-1").unwrap();
    let entries = g.read_dir(None).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, "Game.ini");
    assert_eq!(g.read(&r("game.ini")).unwrap(), b"b");
}

#[test]
fn rename_onto_itself_is_a_no_op() {
    let sys = FakeSystem::builder().file(r"C:\G\a", "x").build().unwrap();
    let g = open(&sys, r"C:\G");
    g.rename(&r("a"), &r("a")).unwrap();
    assert_eq!(g.read(&r("a")).unwrap(), b"x");
}

#[test]
fn builder_reports_first_error() {
    let err = FakeSystem::builder()
        .file(r"C:\G\f", "x")
        .file(r"C:\G\f\g", "y") // file as parent directory
        .file("relative", "z")
        .build()
        .unwrap_err();
    assert_eq!(err.kind, SysErrorKind::AlreadyExists);
}

#[test]
fn data_tags_are_files_unknown_tags_are_reparse_points() {
    let sys = FakeSystem::builder()
        .tagged_file(r"C:\G\compressed.dll", "wof", tag::WOF)
        .tagged_file(r"C:\G\cloud.pak", "cloud", 0x9000_101A)
        .tagged_file(r"C:\G\alias.exe", "alias", tag::APPEXECLINK)
        .build()
        .unwrap();
    let g = open(&sys, r"C:\G");
    for (name, data, t) in [
        ("compressed.dll", &b"wof"[..], tag::WOF),
        ("cloud.pak", b"cloud", 0x9000_101A),
    ] {
        let m = g.metadata(&r(name)).unwrap().unwrap();
        assert_eq!(m.kind, EntryKind::File, "{name}");
        assert_eq!(m.reparse.as_ref().map(|i| i.tag), Some(t));
        assert_eq!(g.read(&r(name)).unwrap(), data);
    }
    let m = g.metadata(&r("alias.exe")).unwrap().unwrap();
    assert_eq!(m.kind, EntryKind::Reparse);
    assert!(!m.reparse.unwrap().surrogate);
    assert_eq!(kind(g.read(&r("alias.exe"))), SysErrorKind::ReparsePoint);
    assert_eq!(
        kind(g.replace(&r("alias.exe"), b"x", "a.tmp")),
        SysErrorKind::ReparsePoint
    );
    assert_eq!(
        kind(g.set_readonly(&r("alias.exe"), true)),
        SysErrorKind::ReparsePoint
    );
    g.remove_file(&r("alias.exe")).unwrap();
    // Tagged files can be replaced (never written in place).
    g.replace(&r("compressed.dll"), b"new", "c.tmp").unwrap();
    let m = g.metadata(&r("compressed.dll")).unwrap().unwrap();
    assert!(m.reparse.is_none());
    let err = FakeSystem::builder()
        .tagged_file(r"C:\G\x", "x", tag::SYMLINK)
        .build()
        .unwrap_err();
    assert_eq!(err.kind, SysErrorKind::InvalidPath);
}

#[test]
fn file_symlink_is_never_followed_below_the_root() {
    let sys = FakeSystem::builder()
        .file(r"C:\Windows\System32\kernel32.dll", "k")
        .file_symlink(r"C:\G\d3d9.dll", r"C:\Windows\System32\kernel32.dll")
        .build()
        .unwrap();
    let g = open(&sys, r"C:\G");
    assert_eq!(kind(g.read(&r("d3d9.dll"))), SysErrorKind::ReparsePoint);
    assert_eq!(
        kind(g.replace(&r("d3d9.dll"), b"evil", "d3d9.tmp")),
        SysErrorKind::ReparsePoint
    );
    assert_eq!(
        kind(g.remove_dir(&r("d3d9.dll"))),
        SysErrorKind::InvalidPath
    );
    g.remove_file(&r("d3d9.dll")).unwrap();
    assert_eq!(
        open(&sys, r"C:\Windows\System32")
            .read(&r("kernel32.dll"))
            .unwrap(),
        b"k"
    );
}

#[test]
fn raw_names_are_listed_as_on_disk() {
    let sys = FakeSystem::builder()
        .file(r"C:\G\d3d9.dll", "real")
        .raw_file(r"C:\G", "d3d9.dll.", "shadow")
        .raw_file(r"C:\G", "CON", "dev")
        .build()
        .unwrap();
    let g = open(&sys, r"C:\G");
    let mut names: Vec<String> = g
        .read_dir(None)
        .unwrap()
        .into_iter()
        .map(|e| e.name)
        .collect();
    names.sort();
    assert_eq!(names, ["CON", "d3d9.dll", "d3d9.dll."]);
    assert_eq!(g.read(&r("d3d9.dll")).unwrap(), b"real");
    let err = FakeSystem::builder()
        .raw_file(r"C:\G", r"a\b", "x")
        .build()
        .unwrap_err();
    assert_eq!(err.kind, SysErrorKind::InvalidPath);
}

#[test]
fn case_sensitive_dir_refuses_writes_and_matches_exactly() {
    let sys = FakeSystem::builder()
        .case_sensitive_dir(r"C:\G\cs")
        .file(r"C:\G\cs\a.txt", "lower")
        .file(r"C:\G\cs\A.txt", "upper")
        .build()
        .unwrap();
    let g = open(&sys, r"C:\G");
    assert_eq!(g.read(&r(r"cs\a.txt")).unwrap(), b"lower");
    assert_eq!(g.read(&r(r"cs\A.txt")).unwrap(), b"upper");
    assert!(g.metadata(&r(r"cs\A.TXT")).unwrap().is_none());
    let us = SysErrorKind::Unsupported;
    assert_eq!(kind(g.replace(&r(r"cs\a.txt"), b"x", "t")), us);
    assert_eq!(kind(g.remove_file(&r(r"cs\a.txt"))), us);
    assert_eq!(kind(g.set_readonly(&r(r"cs\a.txt"), true)), us);
    assert_eq!(kind(g.rename(&r(r"cs\a.txt"), &r("b.txt"))), us);
    assert_eq!(kind(g.rename(&r("x"), &r(r"cs\x"))), us);
    assert_eq!(
        kind(sys.fake_fs().set_case_sensitive(&p(r"C:\G\cs"), false)),
        SysErrorKind::NotEmpty
    );
}

#[test]
fn protected_dir_is_reported_and_inherited() {
    let sys = FakeSystem::builder()
        .protected_dir(r"C:\Program Files\Game")
        .dir(r"C:\Program Files\Game\bin")
        .dir(r"C:\Games\G")
        .build()
        .unwrap();
    assert!(
        !open(&sys, r"C:\Program Files\Game")
            .info()
            .unwrap()
            .user_writable
    );
    assert!(
        !open(&sys, r"C:\Program Files\Game\bin")
            .info()
            .unwrap()
            .user_writable
    );
    assert!(open(&sys, r"C:\Games\G").info().unwrap().user_writable);
}

#[test]
fn handle_to_a_deleted_dir_is_not_found() {
    let sys = FakeSystem::builder().dir(r"C:\G\d").build().unwrap();
    let g = open(&sys, r"C:\G");
    let d = g.open_dir(&r("d")).unwrap();
    g.remove_dir(&r("d")).unwrap();
    assert_eq!(kind(d.info()), SysErrorKind::NotFound);
    assert_eq!(kind(d.create_new(&r("x"), b"x")), SysErrorKind::NotFound);
    assert_eq!(kind(d.read_dir(None)), SysErrorKind::NotFound);
    assert_eq!(kind(d.metadata(&r("x"))), SysErrorKind::NotFound);
}

#[test]
fn tagged_dirs_allowlisted_are_traversed_unknown_are_refused() {
    let sys = FakeSystem::builder()
        .tagged_dir(r"C:\G\OneDrive", tag::CLOUD)
        .file(r"C:\G\OneDrive\save.dat", "s")
        .file(r"C:\G\Projected\x.dat", "x")
        .tagged_dir(r"C:\G\Projected", tag::PROJFS)
        .build()
        .unwrap();
    let g = open(&sys, r"C:\G");
    let m = g.metadata(&r("OneDrive")).unwrap().unwrap();
    assert_eq!(m.kind, EntryKind::Dir);
    assert_eq!(m.reparse.map(|i| i.tag), Some(tag::CLOUD));
    assert_eq!(g.read(&r(r"OneDrive\save.dat")).unwrap(), b"s");
    g.open_dir(&r("OneDrive")).unwrap();
    open(&sys, r"C:\G\OneDrive");

    let m = g.metadata(&r("Projected")).unwrap().unwrap();
    assert_eq!(m.kind, EntryKind::Reparse);
    assert_eq!(
        m.reparse.as_ref().map(|i| (i.tag, i.surrogate)),
        Some((tag::PROJFS, false))
    );
    let rp = SysErrorKind::ReparsePoint;
    assert_eq!(kind(g.read(&r(r"Projected\x.dat"))), rp);
    assert_eq!(kind(g.open_dir(&r("Projected"))), rp);
    assert_eq!(kind(g.read_dir(Some(&r("Projected")))), rp);
    assert_eq!(kind(g.set_readonly(&r("Projected"), true)), rp);
    assert_eq!(
        kind(g.remove_file(&r("Projected"))),
        SysErrorKind::AccessDenied
    );
    assert_eq!(kind(sys.fs().open_dir(&p(r"C:\G\Projected"))), rp);
    assert_eq!(
        kind(
            FakeSystem::builder()
                .tagged_dir(r"C:\x", tag::MOUNT_POINT)
                .build()
        ),
        SysErrorKind::InvalidPath
    );
}

#[test]
fn fs_kind_is_reported() {
    let sys = FakeSystem::builder()
        .dir(r"E:\G")
        .dir(r"C:\G")
        .build()
        .unwrap();
    sys.fake_fs().set_fs_kind('e', FsKind::ExFat);
    let e = open(&sys, r"E:\G").info().unwrap();
    assert_eq!((e.fs_kind, e.supports_posix_rename), (FsKind::ExFat, false));
    let c = open(&sys, r"C:\G").info().unwrap();
    assert_eq!((c.fs_kind, c.supports_posix_rename), (FsKind::Ntfs, true));
}

#[test]
fn replace_rejects_temp_names_equal_to_the_target() {
    let sys = FakeSystem::builder()
        .file(r"C:\G\x.old", "a")
        .build()
        .unwrap();
    let g = open(&sys, r"C:\G");
    let ip = SysErrorKind::InvalidPath;
    assert_eq!(kind(g.replace(&r("x.old"), b"b", "X.OLD")), ip);
    assert_eq!(kind(g.replace(&r("x.old"), b"b", "X")), ip);
    assert_eq!(g.read(&r("x.old")).unwrap(), b"a");
    assert_eq!(g.read_dir(None).unwrap().len(), 1);
}

#[test]
fn hard_links_share_content_and_attributes() {
    let sys = FakeSystem::builder()
        .file(r"C:\G\a.bin", "x")
        .hardlink(r"C:\G\a.bin", r"C:\Other\b.bin")
        .build()
        .unwrap();
    let ro = Attrs {
        readonly: true,
        ..Attrs::default()
    };
    sys.fake_fs().set_attrs(&p(r"C:\Other\b.bin"), ro).unwrap();
    let g = open(&sys, r"C:\G");
    let m = g.metadata(&r("a.bin")).unwrap().unwrap();
    assert_eq!((m.links, m.attrs), (2, ro));
    assert_eq!(kind(g.remove_file(&r("a.bin"))), SysErrorKind::AccessDenied);
    assert_eq!(
        kind(FakeSystem::builder().hardlink(r"C:\G\x", r"D:\y").build()),
        SysErrorKind::NotFound
    );
}

// ---------- TOCTOU (hooks) ----------

/// Root `C:\G` with `sub\deep`, an `outside` dir with a canary.
fn toctou_system() -> FakeSystem {
    FakeSystem::builder()
        .dir(r"C:\G\sub\deep")
        .file(r"C:\G\sub\deep\target.ini", "orig")
        .file(r"C:\Outside\canary.txt", "canary")
        .build()
        .unwrap()
}

fn assert_canary(sys: &FakeSystem) {
    let out = open(sys, r"C:\Outside");
    let names: Vec<String> = out
        .read_dir(None)
        .unwrap()
        .into_iter()
        .map(|e| e.name)
        .collect();
    assert_eq!(names, ["canary.txt"]);
    assert_eq!(out.read(&r("canary.txt")).unwrap(), b"canary");
}

/// Installs a one-shot hook that swaps `victim` for a junction to `C:\Outside` when `op`
/// reaches component `index`.
fn swap_at(sys: &FakeSystem, op: FsOp, index: usize, victim: &'static str) -> Arc<AtomicBool> {
    let fired = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&fired);
    sys.fake_fs().on_step(move |fs: &FakeFs, ev: &StepEvent| {
        if ev.op == op && ev.index == index && !flag.swap(true, Ordering::SeqCst) {
            fs.swap_with_junction(Path::new(victim), r"C:\Outside")
                .unwrap();
        }
    });
    fired
}

#[test]
fn swap_during_create_new_walk_hits_reparse_point() {
    let sys = toctou_system();
    let fired = swap_at(&sys, FsOp::CreateNew, 1, r"C:\G\sub\deep");
    let g = open(&sys, r"C:\G");
    let res = g.create_new(&r(r"sub\deep\canary.txt"), b"evil");
    assert!(fired.load(Ordering::SeqCst));
    assert_eq!(kind(res), SysErrorKind::ReparsePoint);
    assert_canary(&sys);
}

#[test]
fn swap_of_an_already_opened_component_keeps_the_original() {
    let sys = toctou_system();
    // `sub` was resolved before the swap: the walk continues in the original node.
    let fired = swap_at(&sys, FsOp::CreateNew, 1, r"C:\G\sub");
    let g = open(&sys, r"C:\G");
    g.create_new(&r(r"sub\deep\new.txt"), b"mine").unwrap();
    assert!(fired.load(Ordering::SeqCst));
    assert_canary(&sys);
    let moved: Vec<String> = g
        .read_dir(None)
        .unwrap()
        .into_iter()
        .map(|e| e.name)
        .filter(|n| n.starts_with("sub.swapped"))
        .collect();
    assert_eq!(moved.len(), 1);
    let new = r(&format!(r"{}\deep\new.txt", moved[0]));
    assert_eq!(g.read(&new).unwrap(), b"mine");
}

#[test]
fn swap_before_the_last_component_of_replace_hits_reparse_point() {
    let sys = toctou_system();
    let fired = swap_at(&sys, FsOp::Replace, 1, r"C:\G\sub\deep");
    let g = open(&sys, r"C:\G");
    let res = g.replace(&r(r"sub\deep\target.ini"), b"evil", "target.tmp");
    assert!(fired.load(Ordering::SeqCst));
    assert_eq!(kind(res), SysErrorKind::ReparsePoint);
    assert_canary(&sys);
}

#[test]
fn swap_during_metadata_and_open_read_walks() {
    for op in [FsOp::Metadata, FsOp::OpenRead, FsOp::OpenDir, FsOp::ReadDir] {
        let sys = toctou_system();
        swap_at(&sys, op, 1, r"C:\G\sub\deep");
        let g = open(&sys, r"C:\G");
        let res = match op {
            FsOp::Metadata => g.metadata(&r(r"sub\deep\canary.txt")).map(|_| ()),
            FsOp::OpenRead => g.read(&r(r"sub\deep\canary.txt")).map(|_| ()),
            FsOp::OpenDir => g.open_dir(&r(r"sub\deep")).map(|_| ()),
            _ => g.read_dir(Some(&r(r"sub\deep"))).map(|_| ()),
        };
        assert_eq!(kind(res), SysErrorKind::ReparsePoint, "{op:?}");
    }
}

#[test]
fn planted_old_name_during_replace_leaves_target_and_no_temp() {
    let sys = toctou_system();
    sys.fake_fs().on_step(|fs: &FakeFs, ev: &StepEvent| {
        if ev.op == FsOp::ReplaceRenameOld {
            fs.put_file(Path::new(r"C:\G\sub\deep\t.old"), b"planted")
                .unwrap();
        }
    });
    let deep = open(&sys, r"C:\G\sub\deep");
    let res = deep.replace(&r("target.ini"), b"new", "t");
    assert_eq!(kind(res), SysErrorKind::AlreadyExists);
    sys.fake_fs().clear_on_step();
    assert_eq!(deep.read(&r("target.ini")).unwrap(), b"orig");
    let mut names: Vec<String> = deep
        .read_dir(None)
        .unwrap()
        .into_iter()
        .map(|e| e.name)
        .collect();
    names.sort();
    assert_eq!(names, ["t.old", "target.ini"]);
}

#[test]
fn planted_target_during_replace_never_gets_overwritten() {
    let sys = toctou_system();
    sys.fake_fs().on_step(|fs: &FakeFs, ev: &StepEvent| {
        if ev.op == FsOp::ReplaceRenameTmp {
            fs.put_link(
                Path::new(r"C:\G\sub\deep\target.ini"),
                tag::SYMLINK,
                r"C:\Outside\canary.txt",
                false,
            )
            .unwrap();
        }
    });
    let deep = open(&sys, r"C:\G\sub\deep");
    let res = deep.replace(&r("target.ini"), b"new", "t");
    assert_eq!(kind(res), SysErrorKind::AlreadyExists);
    sys.fake_fs().clear_on_step();
    assert_canary(&sys);
    // Temp and .old stay for the journal to recover.
    assert_eq!(deep.read(&r("t")).unwrap(), b"new");
    assert_eq!(deep.read(&r("t.old")).unwrap(), b"orig");
}

#[test]
fn target_renamed_during_replace_aborts_with_busy() {
    let sys = toctou_system();
    sys.fake_fs().on_step(|fs: &FakeFs, ev: &StepEvent| {
        if ev.op == FsOp::ReplaceRenameOld {
            fs.rename_abs(
                Path::new(r"C:\G\sub\deep\target.ini"),
                Path::new(r"C:\G\sub\deep\renamed.ini"),
            )
            .unwrap();
        }
    });
    let deep = open(&sys, r"C:\G\sub\deep");
    let res = deep.replace(&r("target.ini"), b"new", "t");
    sys.fake_fs().clear_on_step();
    assert_eq!(kind(res), SysErrorKind::Busy);
    let names: Vec<String> = deep
        .read_dir(None)
        .unwrap()
        .into_iter()
        .map(|e| e.name)
        .collect();
    assert_eq!(names, ["renamed.ini"], "temp removed, nothing else created");
    assert_eq!(deep.read(&r("renamed.ini")).unwrap(), b"orig");
}

#[test]
fn target_moved_out_of_the_root_during_replace_is_not_pulled_back() {
    for op in [FsOp::ReplaceRenameOld, FsOp::ReplaceRenameTmp] {
        let sys = toctou_system();
        let from = if op == FsOp::ReplaceRenameOld {
            r"C:\G\sub\deep\target.ini"
        } else {
            r"C:\G\sub\deep\t.old"
        };
        sys.fake_fs().on_step(move |fs: &FakeFs, ev: &StepEvent| {
            if ev.op == op {
                fs.rename_abs(Path::new(from), Path::new(r"C:\Outside\moved.ini"))
                    .unwrap();
            }
        });
        let deep = open(&sys, r"C:\G\sub\deep");
        let res = deep.replace(&r("target.ini"), b"new", "t");
        sys.fake_fs().clear_on_step();
        assert_eq!(kind(res), SysErrorKind::Busy, "{op:?}");
        assert!(
            deep.read_dir(None).unwrap().is_empty(),
            "{op:?}: temp removed"
        );
        let out = open(&sys, r"C:\Outside");
        assert_eq!(out.read(&r("moved.ini")).unwrap(), b"orig", "{op:?}");
        assert_eq!(out.read(&r("canary.txt")).unwrap(), b"canary");
    }
}

#[test]
fn hook_sees_every_component_and_is_not_reentrant() {
    let sys = toctou_system();
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let log = Arc::clone(&seen);
    sys.fake_fs().on_step(move |fs: &FakeFs, ev: &StepEvent| {
        // An operation inside the hook does not trigger the hook again.
        let _ = fs
            .open_dir(Path::new(r"C:\G"))
            .and_then(|d| d.metadata(&r("sub")));
        log.lock().unwrap().push((ev.op, ev.index, ev.name.clone()));
    });
    let g = open(&sys, r"C:\G");
    g.metadata(&r(r"sub\deep\target.ini")).unwrap();
    let seen = seen.lock().unwrap().clone();
    assert_eq!(
        seen,
        [
            (FsOp::Metadata, 0, "sub".to_owned()),
            (FsOp::Metadata, 1, "deep".to_owned()),
            (FsOp::Metadata, 2, "target.ini".to_owned()),
        ]
    );
}

// ---------- Registry ----------

#[test]
fn views_are_separate() {
    let native = hkcu(r"Software\Game");
    let wow = RegKey::new(Hive::CurrentUser, RegView::Wow32, r"Software\Game");
    let sys = FakeSystem::builder()
        .value(native.clone(), "v", RegValue::Dword(1))
        .build()
        .unwrap();
    assert!(sys.registry().key_exists(&native).unwrap());
    assert!(!sys.registry().key_exists(&wow).unwrap());
}

#[test]
fn hives_are_separate_and_roots_cannot_be_deleted() {
    let sys = FakeSystem::builder().key(hkcu("Software")).build().unwrap();
    let hklm = RegKey::new(Hive::LocalMachine, RegView::Native, "Software");
    assert!(!sys.registry().key_exists(&hklm).unwrap());
    let err = sys.registry().delete_key(&hkcu("")).unwrap_err();
    assert_eq!(err.kind, SysErrorKind::AccessDenied);
}

#[test]
fn empty_path_segments_are_rejected() {
    let sys = FakeSystem::new();
    let k = RegKey {
        hive: Hive::CurrentUser,
        view: RegView::Native,
        path: r"A\\B".into(),
    };
    assert_eq!(
        sys.registry().key_exists(&k).unwrap_err().kind,
        SysErrorKind::InvalidPath
    );
}

// ---------- Snapshot ----------

fn game_system() -> FakeSystem {
    FakeSystem::builder()
        .file(r"C:\Games\AC\AssassinsCreed_Dx9.exe", "MZ-dx9")
        .file(r"C:\Games\AC\Data\a.forge", "forge")
        .junction(r"C:\Games\AC\Saves", r"C:\Users\me\Saves")
        .value(
            hkcu(r"Software\Ubisoft\AC"),
            "Language",
            RegValue::String("de".into()),
        )
        .build()
        .unwrap()
}

fn game_scope() -> Scope {
    Scope {
        dirs: vec![p(r"C:\Games\AC")],
        keys: vec![hkcu(r"Software\Ubisoft\AC")],
    }
}

#[test]
fn snapshot_is_identical_after_create_and_remove() {
    let sys = game_system();
    let before = snapshot(&sys, &game_scope()).unwrap();
    assert!(!before.is_empty());

    let ac = open(&sys, r"C:\Games\AC");
    let reg = sys.registry();
    ac.create_dir(&r("scripts")).unwrap();
    ac.create_new(&r(r"scripts\EaglePatchAC1.asi"), b"asi")
        .unwrap();
    ac.create_new(&r("dinput8.dll"), b"dll").unwrap();
    let key = hkcu(r"Software\Ubisoft\AC\Rerun");
    reg.create_key(&key).unwrap();
    reg.set(&key, "x", &RegValue::Dword(1)).unwrap();

    let during = snapshot(&sys, &game_scope()).unwrap();
    assert_eq!(before.diff(&during).len(), 5, "{:#?}", before.diff(&during));

    reg.delete_value(&key, "x").unwrap();
    reg.delete_key(&key).unwrap();
    ac.remove_file(&r("dinput8.dll")).unwrap();
    ac.remove_file(&r(r"scripts\EaglePatchAC1.asi")).unwrap();
    ac.remove_dir(&r("scripts")).unwrap();

    let after = snapshot(&sys, &game_scope()).unwrap();
    assert_eq!(before, after, "{:#?}", before.diff(&after));
}

#[test]
fn snapshot_is_identical_after_replace_and_restore() {
    let sys = game_system();
    let before = snapshot(&sys, &game_scope()).unwrap();
    let ac = open(&sys, r"C:\Games\AC");
    let exe = r("AssassinsCreed_Dx9.exe");
    ac.replace(&exe, b"patched", "exe.rerun-1").unwrap();
    assert_eq!(
        before.diff(&snapshot(&sys, &game_scope()).unwrap()).len(),
        1
    );
    ac.replace(&exe, b"MZ-dx9", "exe.rerun-2").unwrap();
    let after = snapshot(&sys, &game_scope()).unwrap();
    assert_eq!(before, after, "{:#?}", before.diff(&after));
}

/// Every mutation must produce exactly one difference.
#[test]
fn snapshot_detects_every_kind_of_change() {
    type Mutation = fn(&FakeSystem);
    let cases: [(&str, Mutation); 11] = [
        ("content", |s| {
            open(s, r"C:\Games\AC")
                .replace(&r(r"Data\a.forge"), b"FORGE", "a.tmp")
                .unwrap();
        }),
        ("readonly", |s| {
            open(s, r"C:\Games\AC")
                .set_readonly(&r(r"Data\a.forge"), true)
                .unwrap();
        }),
        ("hidden", |s| {
            let hidden = Attrs {
                hidden: true,
                ..Attrs::default()
            };
            s.fake_fs()
                .set_attrs(&p(r"C:\Games\AC\Data\a.forge"), hidden)
                .unwrap();
        }),
        ("case-only rename", |s| {
            open(s, r"C:\Games\AC")
                .rename(&r(r"Data\a.forge"), &r(r"Data\A.forge"))
                .unwrap();
        }),
        ("new empty key", |s| {
            s.registry()
                .create_key(&hkcu(r"Software\Ubisoft\AC\Empty"))
                .unwrap();
        }),
        ("value type", |s| {
            let k = hkcu(r"Software\Ubisoft\AC");
            s.registry()
                .set(&k, "Language", &RegValue::ExpandString("de".into()))
                .unwrap();
        }),
        ("new empty dir", |s| {
            open(s, r"C:\Games\AC").create_dir(&r("scripts")).unwrap();
        }),
        ("anomaly appears", |s| {
            s.fake_fs()
                .put_raw_file(&p(r"C:\Games\AC"), "d3d9.dll.", b"x")
                .unwrap();
        }),
        ("reparse target", |s| {
            s.fake_fs()
                .retarget(&p(r"C:\Games\AC\Saves"), r"C:\Windows")
                .unwrap();
        }),
        ("link count", |s| {
            s.fake_fs()
                .put_hardlink(&p(r"C:\Games\AC\Data\a.forge"), &p(r"C:\Elsewhere\a.forge"))
                .unwrap();
        }),
        ("data tag (same content)", |s| {
            s.fake_fs()
                .put_tagged_file(&p(r"C:\Games\AC\Data\a.forge"), b"forge", tag::WOF)
                .unwrap();
        }),
    ];
    for (name, mutate) in cases {
        let sys = game_system();
        let before = snapshot(&sys, &game_scope()).unwrap();
        mutate(&sys);
        let after = snapshot(&sys, &game_scope()).unwrap();
        assert_ne!(before, after, "{name} not detected");
        assert_eq!(
            before.diff(&after).len(),
            1,
            "{name}: {:#?}",
            before.diff(&after)
        );
    }
}

#[test]
fn snapshot_captures_anomalies_without_opening_them() {
    let sys = FakeSystem::builder()
        .file(r"C:\G\d3d9.dll", "real")
        .raw_file(r"C:\G", "d3d9.dll.", "shadow")
        .raw_file(r"C:\G", "CON", "dev")
        .case_sensitive_dir(r"C:\G\cs")
        .file(r"C:\G\cs\a", "1")
        .file(r"C:\G\cs\A", "2")
        .build()
        .unwrap();
    let scope = Scope {
        dirs: vec![p(r"C:\G")],
        keys: vec![],
    };
    // Any open of an anomaly name would hit this hook.
    sys.fake_fs().on_step(|_: &FakeFs, ev: &StepEvent| {
        assert!(
            crate::path::classify(&ev.name, false).is_ok(),
            "opened anomaly {ev:?}"
        );
    });
    let snap = snapshot(&sys, &scope);
    sys.fake_fs().clear_on_step();
    let snap = snap.unwrap();
    // Root, d3d9.dll, d3d9.dll., CON, cs, cs\a, cs\A.
    assert_eq!(snap.len(), 7);
    let shown = Scope::default();
    assert!(snapshot(&sys, &shown).unwrap().is_empty());
    let lines = snap.diff(&Default::default());
    assert_eq!(
        lines.iter().filter(|l| l.contains("anomaly")).count(),
        4,
        "{lines:#?}"
    );
}

#[test]
fn snapshot_does_not_hash_cloud_placeholders() {
    let sys = FakeSystem::builder()
        .tagged_file(r"C:\G\cloud.pak", "remote", tag::CLOUD)
        .tagged_file(r"C:\G\wof.dll", "local", tag::WOF)
        .build()
        .unwrap();
    let scope = Scope {
        dirs: vec![p(r"C:\G")],
        keys: vec![],
    };
    sys.fake_fs().on_step(|_: &FakeFs, ev: &StepEvent| {
        assert!(
            !(ev.op == FsOp::OpenRead && ev.name == "cloud.pak"),
            "cloud placeholder opened"
        );
    });
    let snap = snapshot(&sys, &scope);
    sys.fake_fs().clear_on_step();
    let lines = snap.unwrap().diff(&Default::default());
    assert!(
        lines
            .iter()
            .any(|l| l.contains("cloud.pak") && l.contains("not hashed")),
        "{lines:#?}"
    );
    assert!(
        lines
            .iter()
            .any(|l| l.contains("wof.dll") && l.contains("sha256")),
        "{lines:#?}"
    );
}

#[test]
fn snapshot_depth_is_capped() {
    let deep: String = (0..crate::sys::snapshot::MAX_DEPTH + 2)
        .map(|i| format!(r"\d{i}"))
        .collect();
    let sys = FakeSystem::builder()
        .dir(format!(r"C:\G{deep}"))
        .build()
        .unwrap();
    let scope = Scope {
        dirs: vec![p(r"C:\G")],
        keys: vec![],
    };
    assert_eq!(kind(snapshot(&sys, &scope)), SysErrorKind::Other);
    let ok_depth: String = (0..crate::sys::snapshot::MAX_DEPTH)
        .map(|i| format!(r"\d{i}"))
        .collect();
    let sys = FakeSystem::builder()
        .dir(format!(r"C:\G{ok_depth}"))
        .build()
        .unwrap();
    snapshot(&sys, &scope).unwrap();
}

#[test]
fn snapshot_records_missing_roots() {
    let sys = FakeSystem::builder().dir(r"C:\Base").build().unwrap();
    let scope = Scope {
        dirs: vec![p(r"C:\Base\Nope")],
        keys: vec![hkcu(r"Software\Nope")],
    };
    let before = snapshot(&sys, &scope).unwrap();
    assert_eq!(before.len(), 2);
    open(&sys, r"C:\Base").create_dir(&r("Nope")).unwrap();
    let after = snapshot(&sys, &scope).unwrap();
    let diff = before.diff(&after);
    assert_eq!(diff.len(), 1);
    assert!(diff[0].starts_with('~'), "{diff:?}");
}

#[test]
fn diff_is_readable() {
    let sys = game_system();
    let before = snapshot(&sys, &game_scope()).unwrap();
    let ac = open(&sys, r"C:\Games\AC");
    ac.create_new(&r("dinput8.dll"), b"dll").unwrap();
    ac.remove_file(&r(r"Data\a.forge")).unwrap();
    let diff = before.diff(&snapshot(&sys, &game_scope()).unwrap());
    assert_eq!(diff.len(), 2);
    assert!(
        diff.iter()
            .any(|l| l.starts_with("- ") && l.contains("a.forge")),
        "{diff:#?}"
    );
    assert!(
        diff.iter()
            .any(|l| l.starts_with("+ ") && l.contains("dinput8.dll")),
        "{diff:#?}"
    );
}

// ---------- Topology ----------

#[test]
fn ryzen_5950x_fixture() {
    let sys = FakeSystem::builder()
        .topology_json(RYZEN_5950X)
        .build()
        .unwrap();
    let t = sys.topology().read().unwrap();
    assert_eq!(t.logical_count(), 32);
    assert_eq!(t.core_count(), 16);
    assert_eq!(t.llc_count(), 2);
    assert!(t.has_smt());
    assert!(!t.is_hybrid());
}

#[test]
fn i5_6600_fixture() {
    let sys = FakeSystem::builder()
        .topology_json(I5_6600)
        .build()
        .unwrap();
    let t = sys.topology().read().unwrap();
    assert_eq!(t.logical_count(), 4);
    assert_eq!(t.core_count(), 4);
    assert_eq!(t.llc_count(), 1);
    assert!(!t.has_smt());
}

#[test]
fn broken_fixture_is_an_error() {
    let err = FakeSystem::builder()
        .topology_json(r#"{"cpus": [], "extra": 1}"#)
        .build();
    assert!(err.is_err());
}

#[test]
fn volume_roots_are_reported() {
    let sys = FakeSystem::builder()
        .mounted_volume(r"D:\Mounts\Data")
        .dir(r"D:\Mounts\Data\Games")
        .build()
        .unwrap();
    let is_root = |abs: &str| open(&sys, abs).info().unwrap().is_volume_root();
    assert!(is_root(r"D:\"));
    assert!(is_root(r"D:\Mounts\Data"));
    assert!(!is_root(r"D:\Mounts"));
    assert!(!is_root(r"D:\Mounts\Data\Games"));
    let mounts = open(&sys, r"D:\Mounts");
    let data = mounts.open_dir(&r("data")).unwrap();
    assert!(
        data.info().unwrap().is_volume_root(),
        "also via a relative open"
    );

    let path_of = |abs: &str| open(&sys, abs).info().unwrap().volume_path;
    assert_eq!(path_of(r"D:\Mounts"), "Mounts");
    assert_eq!(path_of(r"D:\Mounts\Data\Games"), "Games");
    let serial = |abs: &str| open(&sys, abs).info().unwrap().volume_serial;
    assert_ne!(
        serial(r"D:\Mounts"),
        serial(r"D:\Mounts\Data"),
        "a mounted volume has its own serial"
    );
    assert_eq!(serial(r"D:\Mounts\Data"), serial(r"D:\Mounts\Data\Games"));
}
