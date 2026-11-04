use std::path::{Path, PathBuf};

use super::FakeSystem;
use crate::sys::contract::{fs_contract, registry_contract, topology_contract};
use crate::sys::fs::EntryKind;
use crate::sys::registry::{Hive, RegKey, RegValue, RegView};
use crate::sys::snapshot::{Scope, snapshot};
use crate::sys::{SysErrorKind, System};

const RYZEN_5950X: &str = include_str!("../../../../../tests/fixtures/cpu/ryzen9-5950x.json");
const I5_6600: &str = include_str!("../../../../../tests/fixtures/cpu/i5-6600.json");

fn p(s: &str) -> PathBuf {
    PathBuf::from(s)
}

fn hkcu(path: &str) -> RegKey {
    RegKey::new(Hive::CurrentUser, RegView::Native, path)
}

// ---------- Contracts ----------

#[test]
fn fake_fulfils_fs_contract() {
    let sys = FakeSystem::builder().dir(r"C:\Work").build().unwrap();
    fs_contract(&sys, Path::new(r"C:\Work")).unwrap();
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

// ---------- File system ----------

#[test]
fn reparse_point_is_visible_but_not_followed() {
    let sys = FakeSystem::builder()
        .file(r"C:\Outside\secret.txt", "x")
        .reparse(r"C:\Games\G\link", r"C:\Outside")
        .build()
        .unwrap();
    let fs = sys.fs();
    let meta = fs.metadata(&p(r"C:\Games\G\link")).unwrap().unwrap();
    assert_eq!(meta.kind, EntryKind::Reparse);
    assert_eq!(
        sys.fs.reparse_target(&p(r"C:\Games\G\link")).unwrap(),
        Some(p(r"C:\Outside"))
    );
    let err = fs.read(&p(r"C:\Games\G\link\secret.txt")).unwrap_err();
    assert_eq!(err.kind, SysErrorKind::ReparsePoint);
    let err = fs.metadata(&p(r"C:\Games\G\link\secret.txt")).unwrap_err();
    assert_eq!(err.kind, SysErrorKind::ReparsePoint);
    // Deleting removes only the link, never the target.
    fs.remove_file(&p(r"C:\Games\G\link")).unwrap();
    assert!(fs.metadata(&p(r"C:\Outside\secret.txt")).unwrap().is_some());
}

#[test]
fn dot_segments_and_non_drive_paths_are_rejected() {
    let sys = FakeSystem::new();
    for bad in [
        r"C:\a\..\b",
        r"C:\.\a",
        r"\\server\share\a",
        r"\\?\C:\a",
        r"a\b",
        r"C:a",
    ] {
        let err = sys.fs().metadata(&p(bad)).unwrap_err();
        assert_eq!(err.kind, SysErrorKind::InvalidPath, "{bad}");
    }
}

#[test]
fn forward_slashes_are_accepted() {
    let sys = FakeSystem::builder()
        .file("C:/Games/a.txt", "x")
        .build()
        .unwrap();
    assert_eq!(sys.fs().read(&p(r"C:\games\A.TXT")).unwrap(), b"x");
}

#[test]
fn rename_moves_directory_with_children() {
    let sys = FakeSystem::builder()
        .file(r"C:\G\scripts\a.asi", "a")
        .file(r"C:\G\scripts\sub\b.ini", "b")
        .build()
        .unwrap();
    let fs = sys.fs();
    fs.rename(&p(r"C:\G\scripts"), &p(r"C:\G\plugins")).unwrap();
    assert_eq!(fs.read(&p(r"C:\G\plugins\sub\b.ini")).unwrap(), b"b");
    assert!(fs.metadata(&p(r"C:\G\scripts")).unwrap().is_none());
    let err = fs
        .rename(&p(r"C:\G\plugins"), &p(r"C:\G\plugins\sub\x"))
        .unwrap_err();
    assert_eq!(err.kind, SysErrorKind::InvalidPath);
}

#[test]
fn directory_is_not_a_file() {
    let sys = FakeSystem::builder()
        .dir(r"C:\G\d")
        .file(r"C:\G\f", "x")
        .build()
        .unwrap();
    let fs = sys.fs();
    assert_eq!(
        fs.read(&p(r"C:\G\d")).unwrap_err().kind,
        SysErrorKind::AccessDenied
    );
    assert_eq!(
        fs.write(&p(r"C:\G\d"), b"x").unwrap_err().kind,
        SysErrorKind::AccessDenied
    );
    assert_eq!(
        fs.remove_file(&p(r"C:\G\d")).unwrap_err().kind,
        SysErrorKind::AccessDenied
    );
    assert_eq!(
        fs.remove_dir(&p(r"C:\G\f")).unwrap_err().kind,
        SysErrorKind::InvalidPath
    );
    assert_eq!(
        fs.read_dir(&p(r"C:\G\f")).unwrap_err().kind,
        SysErrorKind::InvalidPath
    );
    // File as parent directory.
    assert_eq!(
        fs.write(&p(r"C:\G\f\x"), b"x").unwrap_err().kind,
        SysErrorKind::NotFound
    );
}

#[test]
fn overwrite_keeps_existing_name_case() {
    let sys = FakeSystem::builder()
        .file(r"C:\G\Game.ini", "a")
        .build()
        .unwrap();
    sys.fs().write(&p(r"C:\G\GAME.INI"), b"b").unwrap();
    let entries = sys.fs().read_dir(&p(r"C:\G")).unwrap();
    assert_eq!(entries[0].name, "Game.ini");
    assert_eq!(sys.fs().read(&p(r"C:\G\game.ini")).unwrap(), b"b");
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

    let fs = sys.fs();
    let reg = sys.registry();
    fs.create_dir(&p(r"C:\Games\AC\scripts")).unwrap();
    fs.write(&p(r"C:\Games\AC\scripts\EaglePatchAC1.asi"), b"asi")
        .unwrap();
    fs.write(&p(r"C:\Games\AC\dinput8.dll"), b"dll").unwrap();
    let key = hkcu(r"Software\Ubisoft\AC\Rerun");
    reg.create_key(&key).unwrap();
    reg.set(&key, "x", &RegValue::Dword(1)).unwrap();

    let during = snapshot(&sys, &game_scope()).unwrap();
    assert_eq!(before.diff(&during).len(), 5, "{:#?}", before.diff(&during));

    reg.delete_value(&key, "x").unwrap();
    reg.delete_key(&key).unwrap();
    fs.remove_file(&p(r"C:\Games\AC\dinput8.dll")).unwrap();
    fs.remove_file(&p(r"C:\Games\AC\scripts\EaglePatchAC1.asi"))
        .unwrap();
    fs.remove_dir(&p(r"C:\Games\AC\scripts")).unwrap();

    let after = snapshot(&sys, &game_scope()).unwrap();
    assert_eq!(before, after, "{:#?}", before.diff(&after));
}

/// Every mutation must produce a difference.
#[test]
fn snapshot_detects_every_kind_of_change() {
    type Mutation = fn(&FakeSystem);
    let cases: [(&str, Mutation); 6] = [
        ("content", |s| {
            s.fs()
                .write(&p(r"C:\Games\AC\Data\a.forge"), b"FORGE")
                .unwrap()
        }),
        ("readonly", |s| {
            s.fs()
                .set_readonly(&p(r"C:\Games\AC\Data\a.forge"), true)
                .unwrap()
        }),
        ("case-only rename", |s| {
            s.fs()
                .rename(
                    &p(r"C:\Games\AC\Data\a.forge"),
                    &p(r"C:\Games\AC\Data\A.forge"),
                )
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
            s.fs().create_dir(&p(r"C:\Games\AC\scripts")).unwrap()
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
fn snapshot_records_missing_roots() {
    let sys = FakeSystem::new();
    let scope = Scope {
        dirs: vec![p(r"C:\Nope")],
        keys: vec![hkcu(r"Software\Nope")],
    };
    let before = snapshot(&sys, &scope).unwrap();
    assert_eq!(before.len(), 2);
    sys.fs().create_dir(&p(r"C:\Nope")).unwrap();
    let after = snapshot(&sys, &scope).unwrap();
    let diff = before.diff(&after);
    assert_eq!(diff.len(), 1);
    assert!(diff[0].starts_with('~'), "{diff:?}");
}

#[test]
fn diff_is_readable() {
    let sys = game_system();
    let before = snapshot(&sys, &game_scope()).unwrap();
    sys.fs()
        .write(&p(r"C:\Games\AC\dinput8.dll"), b"dll")
        .unwrap();
    sys.fs()
        .remove_file(&p(r"C:\Games\AC\Data\a.forge"))
        .unwrap();
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
