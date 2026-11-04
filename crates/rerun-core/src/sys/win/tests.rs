//! Tests of the read-only `sys::win` on the developer's own machine and on GitHub runners:
//! smoke tests and the `sys::contract` file system, registry and known-folder contracts against
//! real Windows.
//!
//! Every test that sets up data works in a fresh [`TestRoot`] below the cargo `target/`
//! directory (safeguards in `docs/09-testing.md`), registry data in a private app hive inside
//! one ([`HiveRoot`]); a locally elevated process skips them. The registry system contract and
//! the known-folder contract only read the real system.

#![expect(
    clippy::disallowed_methods,
    reason = "test fixture under target/: std::fs sets up the tree, Fs::open_dir opens it"
)]

use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::testfx::{
    HiveRoot, NaiveFs, TestRoot, TestWinSystem, hosted_ci, note, workflow_warning,
};
use super::{WinFs, WinKnownFolders, WinRegistry};
use crate::path::{RelPath, RootPath};
use crate::policy::root::{Forbidden, ForbiddenRoots, Protected, RootError, RootId, StoreDir};
use crate::sys::contract::{
    FsContractResult, FsFixture, RegFixture, fs_link_read_contract, fs_race_contract,
    fs_read_contract, fs_volume_contract, known_folders_contract, registry_read_contract,
    registry_system_contract,
};
use crate::sys::fs::{EntryKind, Fs};
use crate::sys::registry::{Hive, RegKey, RegValue, RegView, Registry, reg_type};
use crate::sys::{KnownFolder, SysErrorKind, System};

/// A [`TestRoot`] for the smoke tests; `.0` is its verbatim path (`\\?\X:\…`), as
/// `final_path` reports it.
struct Fixture(
    PathBuf,
    #[expect(dead_code, reason = "held for its drop, which removes the tree")] TestRoot,
);

impl Fixture {
    fn new(case: &str) -> Option<Self> {
        let root = TestRoot::new(case)?;
        let verbatim = PathBuf::from(format!(r"\\?\{}", root.path().display()));
        Some(Self(verbatim, root))
    }

    fn path(&self, rel: &str) -> PathBuf {
        self.0.join(rel)
    }
}

fn rel(s: &str) -> RelPath {
    RelPath::parse(s).unwrap()
}

fn kind_of<T>(r: Result<T, crate::sys::SysError>) -> SysErrorKind {
    match r {
        Ok(_) => panic!("expected an error"),
        Err(e) => e.kind,
    }
}

#[test]
fn read_only_walk_metadata_and_identity() {
    let Some(fx) = Fixture::new("smoke-walk") else {
        return;
    };
    std::fs::write(fx.path("a.txt"), b"hello").unwrap();
    std::fs::hard_link(fx.path("a.txt"), fx.path("link.txt")).unwrap();
    std::fs::create_dir(fx.path("Sub")).unwrap();
    std::fs::write(fx.path(r"Sub\b.bin"), [1u8, 2, 3]).unwrap();

    let fs = WinFs::new();
    let root = fs.open_dir(&fx.0).unwrap();
    let info = root.info().unwrap();
    assert_eq!(info.final_path, fx.0);
    assert!(!info.is_volume_root());
    let shown = info.final_path.to_str().unwrap().replace('/', "\\");
    assert!(
        shown.ends_with(&info.volume_path),
        "{shown} / {}",
        info.volume_path
    );
    assert!(info.volume_first_segment().is_some());
    assert!(info.user_writable, "the test created this directory");
    assert!(!info.case_sensitive);
    assert_ne!(info.file_id, 0);

    // Listing: raw names, kinds, hard link count shared by both names.
    let mut entries = root.read_dir(None).unwrap();
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(names, ["Sub", "a.txt", "link.txt"]);
    assert_eq!(entries[0].meta.kind, EntryKind::Dir);
    assert_eq!(
        (
            entries[1].meta.kind,
            entries[1].meta.len,
            entries[1].meta.links
        ),
        (EntryKind::File, 5, Some(2))
    );
    assert_eq!(entries[1].meta.file_id, entries[2].meta.file_id);

    // Metadata: case-insensitive, missing and below-a-file are None.
    let sub_meta = root.metadata(&rel("SUB")).unwrap().unwrap();
    assert_eq!(
        (sub_meta.kind, sub_meta.len, sub_meta.links),
        (EntryKind::Dir, 0, Some(1))
    );
    assert_eq!(root.metadata(&rel("missing")).unwrap(), None);
    assert_eq!(root.metadata(&rel(r"missing\x")).unwrap(), None);
    assert_eq!(root.metadata(&rel(r"a.txt\x")).unwrap(), None);
    assert_eq!(
        root.metadata(&rel(r"sub\B.BIN")).unwrap().map(|m| m.len),
        Some(3)
    );

    // Reads.
    assert_eq!(root.read(&rel("a.txt")).unwrap(), b"hello");
    assert_eq!(root.read(&rel(r"Sub\b.bin")).unwrap(), [1, 2, 3]);
    assert_eq!(
        kind_of(root.open_read(&rel("Sub"))),
        SysErrorKind::AccessDenied
    );
    assert_eq!(
        kind_of(root.open_read(&rel("nope"))),
        SysErrorKind::NotFound
    );

    // Relative opens and handle identity.
    let sub = root.open_dir(&rel("sub")).unwrap();
    let sub_info = sub.info().unwrap();
    assert_eq!(sub_info.file_id, sub_meta.file_id);
    assert_eq!(sub_info.volume_serial, info.volume_serial);
    assert_eq!(
        sub_info.final_path,
        fx.path("Sub"),
        "stored case is reported"
    );
    let sub_entries = sub.read_dir(None).unwrap();
    assert_eq!(sub_entries.len(), 1);
    assert_eq!(sub_entries[0].name, "b.bin");
    assert_eq!(root.read_dir(Some(&rel("Sub"))).unwrap(), sub_entries);
    assert_eq!(
        kind_of(root.open_dir(&rel("a.txt"))),
        SysErrorKind::InvalidPath
    );
    assert_eq!(
        kind_of(root.open_dir(&rel("missing"))),
        SysErrorKind::NotFound
    );
    assert_eq!(
        kind_of(root.open_dir(&rel(r"a.txt\x"))),
        SysErrorKind::InvalidPath
    );

    // Writes are refused in phase 1.
    let p = rel("new.txt");
    for r in [
        root.create_new(&p, b"x"),
        root.replace(&rel("a.txt"), b"x", "tmp"),
        root.create_dir(&p),
        root.remove_file(&rel("a.txt")),
        root.remove_dir(&rel("Sub")),
        root.rename(&rel("a.txt"), &p),
        root.set_readonly(&rel("a.txt"), true),
    ] {
        assert_eq!(kind_of(r), SysErrorKind::Unsupported);
    }
    assert_eq!(root.read(&rel("a.txt")).unwrap(), b"hello");
}

#[test]
fn absolute_open_input_rules() {
    let Some(fx) = Fixture::new("smoke-abs") else {
        return;
    };
    std::fs::write(fx.path("f"), b"").unwrap();
    let fs = WinFs::new();
    let s = fx.0.to_str().unwrap().to_owned();
    let plain = s.strip_prefix(r"\\?\").unwrap_or(&s).to_owned();
    // Plain drive path and forward slashes reach the same directory.
    let id = fs.open_dir(&fx.0).unwrap().info().unwrap().file_id;
    assert_eq!(
        fs.open_dir(Path::new(&plain))
            .unwrap()
            .info()
            .unwrap()
            .file_id,
        id
    );
    assert_eq!(
        fs.open_dir(Path::new(&plain.replace('\\', "/")))
            .unwrap()
            .info()
            .unwrap()
            .file_id,
        id
    );
    assert_eq!(
        kind_of(fs.open_dir(&fx.path("f"))),
        SysErrorKind::InvalidPath
    );
    assert_eq!(
        kind_of(fs.open_dir(&fx.path("missing"))),
        SysErrorKind::NotFound
    );
    assert_eq!(
        kind_of(fs.open_dir(&fx.path(r"missing\deeper"))),
        SysErrorKind::NotFound
    );
    for bad in [
        "relative".to_owned(),
        format!(r"{plain}\.."),
        format!(r"{plain}\.\x"),
        format!(r"{plain}\a?b"),
        r"\\localhost\c$".to_owned(),
    ] {
        assert_eq!(
            kind_of(fs.open_dir(Path::new(&bad))),
            SysErrorKind::InvalidPath,
            "{bad}"
        );
    }
}

#[test]
fn concurrent_writer_is_busy_and_rename_keeps_the_handle() {
    let Some(fx) = Fixture::new("smoke-busy") else {
        return;
    };
    std::fs::write(fx.path("w.log"), b"x").unwrap();
    std::fs::create_dir(fx.path("d")).unwrap();
    let fs = WinFs::new();
    let root = fs.open_dir(&fx.0).unwrap();

    // D10: open_read shares read only.
    let writer = std::fs::OpenOptions::new()
        .append(true)
        .open(fx.path("w.log"))
        .unwrap();
    assert_eq!(kind_of(root.open_read(&rel("w.log"))), SysErrorKind::Busy);
    // Attribute-only opens never conflict.
    assert_eq!(
        root.metadata(&rel("w.log")).unwrap().map(|m| m.len),
        Some(1)
    );
    drop(writer);
    let mut s = String::new();
    root.open_read(&rel("w.log"))
        .unwrap()
        .read_to_string(&mut s)
        .unwrap();
    assert_eq!(s, "x");

    // A Dir handle shares delete: its directory can be renamed and the handle follows.
    let d = root.open_dir(&rel("d")).unwrap();
    std::fs::rename(fx.path("d"), fx.path("e")).unwrap();
    assert_eq!(d.info().unwrap().final_path, fx.path("e"));

    // ... and deleted: the handle then reports NotFound.
    std::fs::remove_dir(fx.path("e")).unwrap();
    assert_eq!(kind_of(d.info()), SysErrorKind::NotFound);
    assert_eq!(kind_of(d.metadata(&rel("x"))), SysErrorKind::NotFound);
    assert_eq!(kind_of(d.read_dir(None)), SysErrorKind::NotFound);
}

/// Needs the symlink privilege or developer mode; skipped (with a note) otherwise.
#[test]
fn symlinks_are_never_followed_below_a_root() {
    let Some(fx) = Fixture::new("smoke-symlink") else {
        return;
    };
    std::fs::create_dir(fx.path("real")).unwrap();
    std::fs::write(fx.path(r"real\x"), b"x").unwrap();
    if let Err(e) = std::os::windows::fs::symlink_dir("real", fx.path("link")) {
        eprintln!("skipped: cannot create a directory symlink ({e})");
        return;
    }
    let fs = WinFs::new();
    let root = fs.open_dir(&fx.0).unwrap();
    let m = root.metadata(&rel("link")).unwrap().unwrap();
    assert_eq!(m.kind, EntryKind::Reparse);
    let r = m.reparse.unwrap();
    assert_eq!(
        (r.tag, r.surrogate, r.target.as_deref()),
        (crate::sys::fs::tag::SYMLINK, true, Some("real"))
    );
    assert_eq!(
        kind_of(root.open_dir(&rel("link"))),
        SysErrorKind::ReparsePoint
    );
    assert_eq!(
        kind_of(root.open_read(&rel(r"link\x"))),
        SysErrorKind::ReparsePoint
    );
    assert_eq!(
        kind_of(root.metadata(&rel(r"link\x"))),
        SysErrorKind::ReparsePoint
    );
    let listed: Vec<_> = root
        .read_dir(None)
        .unwrap()
        .into_iter()
        .map(|e| (e.name, e.meta.kind))
        .collect();
    assert!(listed.contains(&("link".to_owned(), EntryKind::Reparse)));
    // Fs::open_dir follows it (above the root).
    let via = WinFs::new()
        .open_dir(&fx.path("link"))
        .unwrap()
        .info()
        .unwrap();
    assert_eq!(via.final_path, fx.path("real"));
}

// ---------- Contracts against real Windows ----------

/// Skips that are acceptable on a GitHub runner (warnings): no second NTFS volume, 8.3 names
/// disabled, no WOF. Any other skip there fails the test.
const CI_TOLERATED: [&str; 3] = ["mount_volume", "short_name", "wof_compress"];

/// Reports the skips of a contract run: on GitHub runners a skip outside [`CI_TOLERATED`]
/// panics and the tolerated ones become `::warning::` lines; locally each skip is a note.
fn report(case: &str, result: FsContractResult) {
    let skips = result.unwrap_or_else(|e| panic!("{case}: {e}"));
    for s in skips {
        if !hosted_ci() {
            note(&format!(
                "note: {case}: skipped {s} (not available on this machine)"
            ));
        } else if CI_TOLERATED.contains(&s) {
            workflow_warning(&format!(
                "fs contract {case}: {s} skipped (not available on this runner)"
            ));
        } else {
            panic!("{case}: {s} skipped on a GitHub runner (every runner must support it)");
        }
    }
}

#[test]
fn win_fulfils_fs_read_contract() {
    let Some(root) = TestRoot::new("read") else {
        return;
    };
    let work = root.work("w");
    report(
        "fs_read_contract",
        fs_read_contract(&WinFs::new(), root.fx(), &work),
    );
}

#[test]
fn win_fulfils_fs_link_read_contract() {
    let Some(root) = TestRoot::new("link-read") else {
        return;
    };
    let work = root.work("w");
    report(
        "fs_link_read_contract",
        fs_link_read_contract(&WinFs::new(), root.fx(), &work),
    );
}

#[test]
fn win_fulfils_fs_volume_contract() {
    let Some(root) = TestRoot::new("volume") else {
        return;
    };
    let work = root.work("w");
    report(
        "fs_volume_contract",
        fs_volume_contract(&WinFs::new(), root.fx(), &work),
    );
}

/// The race harness must catch the naive implementation within this time.
const TEETH: Duration = Duration::from_secs(30);

/// A race contract failure that is a leak (canary content, file ID or name), not a harness
/// problem (flipper error, unexpected error kind).
fn is_leak(e: &str) -> bool {
    e.contains("race:") && !e.contains("unexpected error") && !e.contains("flip")
}

#[test]
fn win_fulfils_fs_race_contract_and_the_harness_has_teeth() {
    let Some(root) = TestRoot::new("race") else {
        return;
    };
    // Control: the check-then-use-by-path implementation must be caught.
    let started = Instant::now();
    let mut attempt = 0u32;
    let caught = loop {
        let work = root.work(&format!("naive-{attempt}"));
        attempt += 1;
        match fs_race_contract(&NaiveFs, root.fx(), &work, Duration::from_millis(500)) {
            Err(e) if is_leak(&e) => break started.elapsed(),
            Err(e) => panic!("race harness broken against NaiveFs: {e}"),
            Ok(_) => {}
        }
        assert!(
            started.elapsed() < TEETH,
            "harness lost its teeth: the naive implementation was not caught within {TEETH:?}"
        );
    };
    let budget = (caught * 10).max(Duration::from_secs(5));
    note(&format!(
        "note: race: NaiveFs caught after {caught:?} ({attempt} attempts); WinFs runs {budget:?}"
    ));
    let work = root.work("win");
    report(
        "fs_race_contract",
        fs_race_contract(&WinFs::new(), root.fx(), &work, budget),
    );
}

#[test]
fn win_dir_write_methods_are_unsupported() {
    let Some(root) = TestRoot::new("read-only") else {
        return;
    };
    let fx = root.fx();
    let base = root.path();
    fx.file(&base.join("a.txt"), b"a").unwrap();
    fx.dir(&base.join("d")).unwrap();
    let fs = WinFs::new();
    let dir = fs.open_dir(base).unwrap();
    let (a, n) = (rel("a.txt"), rel("new"));
    for (what, r) in [
        ("create_new", dir.create_new(&n, b"x")),
        ("replace", dir.replace(&a, b"x", "a.tmp")),
        ("create_dir", dir.create_dir(&n)),
        ("remove_file", dir.remove_file(&a)),
        ("remove_dir", dir.remove_dir(&rel("d"))),
        ("rename", dir.rename(&a, &n)),
        ("set_readonly", dir.set_readonly(&a, true)),
    ] {
        let e = r.expect_err(what);
        assert_eq!(e.kind, SysErrorKind::Unsupported, "{what}");
        assert!(e.target.contains("read-only in phase 1"), "{what}: {e}");
    }
    assert_eq!(dir.read(&a).unwrap(), b"a");
    assert!(dir.metadata(&n).unwrap().is_none());
    let names: Vec<String> = dir
        .read_dir(None)
        .unwrap()
        .into_iter()
        .map(|e| e.name)
        .collect();
    assert_eq!(names.len(), 2, "{names:?}");
}

/// The runner's cleanup (`std::fs::remove_dir_all` in `TestRoot`'s drop) removes a junction
/// itself and never what it points to, also for a junction to a directory outside the root.
#[test]
fn cleanup_never_follows_a_junction() {
    let Some(keep) = TestRoot::new("cleanup-keep") else {
        return;
    };
    let canary = keep.path().join("canary.txt");
    keep.fx().file(&canary, b"canary").unwrap();
    {
        let doomed = TestRoot::new("cleanup-doomed").unwrap();
        let fx = doomed.fx();
        fx.junction(&doomed.path().join("j"), keep.path()).unwrap();
        fx.junction(&doomed.path().join(r"deep\er\j"), keep.path())
            .unwrap();
        // Restricted entries are restored before the removal.
        fx.file(&doomed.path().join("locked.txt"), b"x").unwrap();
        assert!(fx.restricted(&doomed.path().join("locked.txt")).unwrap());
        let gone = doomed.path().to_path_buf();
        drop(doomed);
        assert!(!gone.exists(), "{} was not removed", gone.display());
    }
    assert_eq!(std::fs::read(&canary).unwrap(), b"canary");
}

// ---------- Registry against real Windows ----------

/// Runs the registry read contract in a fresh app hive (one per run: the contract deletes
/// nothing and leaves about 17 MiB, 16,385 values and 65,537 subkeys behind) at `root`, which
/// lies outside `SOFTWARE`, and reports the duration.
fn registry_read_run(case: &str, root: &RegKey) {
    let Some(h) = HiveRoot::new(case) else {
        return;
    };
    h.hive.key(root).unwrap();
    let started = Instant::now();
    let skips = registry_read_contract(&h.registry, &h.hive, root)
        .unwrap_or_else(|e| panic!("{case}: {e}"));
    note(&format!(
        "note: {case}: registry_read_contract took {:?}",
        started.elapsed()
    ));
    // Always skipped on Windows: following a link key in an app hive is denied
    // (`key_link`), and a single value above 1,048,572 bytes is refused by the kernel, so the
    // 1 MiB limit cases cannot be set up (`value_at_limit`, `value_over_limit`).
    const WIN_SKIPS: [&str; 3] = ["key_link", "value_at_limit", "value_over_limit"];
    for s in skips {
        if hosted_ci() && !WIN_SKIPS.contains(&s) {
            panic!("{case}: {s} skipped on a GitHub runner");
        }
        note(&format!("note: {case}: skipped {s} (not available)"));
    }
    drop(h);
}

#[test]
fn win_fulfils_registry_read_contract_hkcu_native() {
    registry_read_run(
        "reg-hkcu-native",
        &RegKey::new(Hive::CurrentUser, RegView::Native, "RerunContract"),
    );
}

#[test]
fn win_fulfils_registry_read_contract_hkcu_wow32() {
    registry_read_run(
        "reg-hkcu-wow32",
        &RegKey::new(Hive::CurrentUser, RegView::Wow32, "RerunContract"),
    );
}

#[test]
fn win_fulfils_registry_read_contract_hklm_native() {
    registry_read_run(
        "reg-hklm-native",
        &RegKey::new(Hive::LocalMachine, RegView::Native, r"SYSTEM\RerunContract"),
    );
}

#[test]
fn win_fulfils_registry_read_contract_hklm_wow32() {
    registry_read_run(
        "reg-hklm-wow32",
        &RegKey::new(Hive::LocalMachine, RegView::Wow32, r"SYSTEM\RerunContract"),
    );
}

/// Read-only on the real registry: stable system keys, WOW64 views, a link, access errors.
#[test]
fn win_fulfils_registry_system_contract() {
    let reg = Arc::new(WinRegistry::new().unwrap());
    let kf = WinKnownFolders::new(reg.clone());
    let skips = registry_system_contract(&*reg, &kf).unwrap_or_else(|e| panic!("{e}"));
    for s in skips {
        assert!(!hosted_ci(), "{s} skipped on a GitHub runner");
        note(&format!("note: registry_system_contract: skipped {s}"));
    }
}

#[test]
fn win_fulfils_known_folders_contract() {
    let kf = WinKnownFolders::new(Arc::new(WinRegistry::new().unwrap()));
    known_folders_contract(&kf, &WinFs::new()).unwrap_or_else(|e| panic!("{e}"));
}

#[test]
fn win_registry_write_methods_are_unsupported() {
    let Some(h) = HiveRoot::new("reg-read-only") else {
        return;
    };
    let k = RegKey::new(Hive::CurrentUser, RegView::Native, "Existing");
    h.hive.key(&k).unwrap();
    h.hive
        .raw(&k, "v", reg_type::REG_DWORD, &[1, 0, 0, 0])
        .unwrap();
    let reg = &h.registry;
    let new = k.join("New");
    for (what, r) in [
        ("create_key", reg.create_key(&new).map(drop)),
        ("set", reg.set(&k, "v", &RegValue::Dword(2))),
        ("set new", reg.set(&k, "w", &RegValue::Dword(2))),
        ("delete_value", reg.delete_value(&k, "v")),
        ("delete_key", reg.delete_key(&k)),
    ] {
        let e = r.expect_err(what);
        assert_eq!(e.kind, SysErrorKind::Unsupported, "{what}");
        assert!(e.target.contains("read-only in phase 1"), "{what}: {e}");
    }
    assert!(reg.key_exists(&k).unwrap());
    assert!(!reg.key_exists(&new).unwrap());
    assert_eq!(
        reg.values(&k).unwrap(),
        [("v".to_owned(), RegValue::Dword(1))]
    );
    // The input rules come first.
    assert_eq!(
        reg.create_key(&k.join("a\0b")).unwrap_err().kind,
        SysErrorKind::InvalidPath
    );
}

/// Pins what ADR 0009 leaves to real Windows (read-only): an explicit `WOW6432Node` in the
/// 32-bit view is not redirected a second time, so it names the same key as the logical path
/// (the fake models the same); and the 32-bit view of `HKLM\SOFTWARE` does not list
/// `WOW6432Node` (a listed deviation of the fake). Callers never spell `WOW6432Node`.
#[test]
fn explicit_wow6432node_in_the_32_bit_view_is_the_same_key() {
    let reg = WinRegistry::new().unwrap();
    let lm = |v, p: &str| RegKey::new(Hive::LocalMachine, v, p);
    let cv = r"Microsoft\Windows\CurrentVersion";
    let logical = lm(RegView::Wow32, &format!(r"SOFTWARE\{cv}"));
    let explicit = lm(RegView::Wow32, &format!(r"SOFTWARE\WOW6432Node\{cv}"));
    let native = lm(RegView::Native, &format!(r"SOFTWARE\WOW6432Node\{cv}"));
    let pf = |k: &RegKey| reg.get(k, "ProgramFilesDir").unwrap();
    assert!(pf(&logical).is_some());
    assert_eq!(pf(&explicit), pf(&logical));
    assert_eq!(pf(&native), pf(&logical));
    assert!(
        !reg.key_exists(&lm(RegView::Wow32, r"SOFTWARE\WOW6432Node\WOW6432Node"))
            .unwrap()
    );
    let listed = reg.subkeys(&lm(RegView::Wow32, "SOFTWARE")).unwrap();
    assert!(
        !listed.iter().any(|n| n.eq_ignore_ascii_case("WOW6432Node")),
        "{listed:?}"
    );
}

/// Enumerations under concurrent writes: every `values`/`subkeys` result is either complete and
/// without duplicates, or `Busy` (the key kept changing); never another error, never a value
/// read half-written.
#[test]
fn win_registry_enumerations_survive_concurrent_writes() {
    let Some(h) = HiveRoot::new("reg-race") else {
        return;
    };
    let k = RegKey::new(Hive::CurrentUser, RegView::Native, "Race");
    h.hive.key(&k).unwrap();
    for i in 0..64 {
        h.hive
            .raw(&k, &format!("base{i}"), reg_type::REG_BINARY, &[1; 64])
            .unwrap();
        h.hive.key(&k.join(&format!("sub{i}"))).unwrap();
    }
    let stop = std::sync::atomic::AtomicBool::new(false);
    let (mut ok, mut busy) = (0u32, 0u32);
    std::thread::scope(|s| {
        s.spawn(|| {
            let mut n = 0u32;
            while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                let name = format!("churn{}", n % 8);
                // Sizes alternate, so a read can race a growing value.
                let len = if n.is_multiple_of(2) { 16 } else { 4096 };
                h.hive
                    .raw(&k, &name, reg_type::REG_BINARY, &vec![2; len])
                    .unwrap();
                h.hive.key(&k.join(&format!("churn{n}"))).unwrap();
                n = n.wrapping_add(1);
            }
        });
        let started = Instant::now();
        while started.elapsed() < Duration::from_secs(1) {
            match h.registry.values(&k) {
                Ok(list) => {
                    let mut names: Vec<&str> = list.iter().map(|(n, _)| n.as_str()).collect();
                    names.sort_unstable();
                    let all = names.len();
                    names.dedup();
                    assert_eq!(names.len(), all, "duplicate value names");
                    assert!(all >= 64);
                    for (n, v) in &list {
                        if n.starts_with("churn") {
                            let RegValue::Binary(b) = v else {
                                panic!("{n}: {v:?}")
                            };
                            assert!(b.len() == 16 || b.len() == 4096, "{n}: {}", b.len());
                            assert!(b.iter().all(|x| *x == 2));
                        }
                    }
                    ok += 1;
                }
                Err(e) if e.kind == SysErrorKind::Busy => busy += 1,
                Err(e) => panic!("values: {e:?}"),
            }
            match h.registry.subkeys(&k) {
                Ok(mut list) => {
                    let all = list.len();
                    list.sort_unstable();
                    list.dedup();
                    assert_eq!(list.len(), all, "duplicate subkey names");
                    ok += 1;
                }
                Err(e) if e.kind == SysErrorKind::Busy => busy += 1,
                Err(e) => panic!("subkeys: {e:?}"),
            }
        }
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
    });
    note(&format!(
        "note: registry race: {ok} complete enumerations, {busy} Busy"
    ));
}

// ---------- policy::root against real Windows ----------

fn known(sys: &TestWinSystem, f: KnownFolder) -> RootPath {
    RootPath::new(sys.known_folders().get(f).unwrap()).unwrap()
}

/// `ForbiddenRoots::resolve` against the real known folders (a `TestRoot` directory stands in
/// for Rerun's install folder) refuses the real protected folders with the right reason and
/// allows an ordinary folder.
#[test]
fn forbidden_roots_resolve_on_real_windows() {
    use Forbidden::{Inside, Is};
    use KnownFolder as K;
    use Protected::{InstallDir, Known};
    let Some(root) = TestRoot::new("policy-forbidden") else {
        return;
    };
    let install = root.work("Rerun");
    let games = root.work("Games");
    let sys = TestWinSystem::new();
    let fr = ForbiddenRoots::resolve(&sys, &install).unwrap_or_else(|e| panic!("{e}"));
    let check = |p: &RootPath| fr.check(p);
    for f in [
        K::Windows,
        K::ProgramFiles,
        K::ProgramFilesX86,
        K::ProgramData,
    ] {
        assert_eq!(check(&known(&sys, f)), Err(Is(Known(f))), "{f}");
    }
    assert_eq!(
        check(&known(&sys, K::Windows).child("System32").unwrap()),
        Err(Inside(Known(K::Windows)))
    );
    assert_eq!(
        check(&known(&sys, K::UserProfiles)),
        Err(Is(Known(K::UserProfiles)))
    );
    assert_eq!(check(&known(&sys, K::Profile)), Err(Is(Known(K::Profile))));
    // Below LocalAppData, and the default form below the profile (ADR 0009), whatever the
    // redirection of this machine.
    let local = known(&sys, K::LocalAppData);
    assert!(check(&local.child("Microsoft").unwrap()).is_err());
    let mut default = known(&sys, K::Profile);
    for seg in ["AppData", "Local", "Microsoft"] {
        default = default.child(seg).unwrap();
    }
    assert!(check(&default).is_err());
    assert!(check(&local.child("Programs").unwrap().child("Game").unwrap()).is_ok());
    let install_rp = RootPath::new(&install).unwrap();
    assert_eq!(check(&install_rp), Err(Is(InstallDir)));
    assert_eq!(check(&RootPath::new(&games).unwrap()), Ok(()));
    // Opening goes through the same list.
    match StoreDir::open(&sys, &fr, &install) {
        Err(RootError::Forbidden { reason, .. }) => assert_eq!(reason, Is(InstallDir)),
        other => panic!("install folder opened as a store: {other:?}"),
    }
}

/// A store under a `TestRoot`: a plain game folder opens with the right identity; a junction,
/// a directory symlink, a file symlink or a mount point at `steamapps`, `common` or the
/// install folder is refused (`RootError::Reparse`), and the canary outside stays unread.
#[test]
fn store_dir_game_refuses_links_on_real_windows() {
    const LEVELS: [&str; 3] = ["steamapps", "common", "Game"];
    const CANARY: &[u8] = b"canary";
    let Some(root) = TestRoot::new("policy-store") else {
        return;
    };
    let fx = root.fx();
    let sys = TestWinSystem::new();
    let install = root.work("Rerun");
    let fr = ForbiddenRoots::resolve(&sys, &install).unwrap_or_else(|e| panic!("{e}"));

    // The plain case.
    let plain_store = root.path().join("plain");
    fx.file(&plain_store.join(r"steamapps\common\Game\game.exe"), b"exe")
        .unwrap();
    let store = StoreDir::open(&sys, &fr, &plain_store).unwrap_or_else(|e| panic!("{e}"));
    let game = store.game(&fr, "game").unwrap_or_else(|e| panic!("{e}"));
    let direct = WinFs::new()
        .open_dir(&plain_store.join(r"steamapps\common\Game"))
        .unwrap()
        .info()
        .unwrap();
    assert_eq!(game.id(), RootId::of(&direct));
    assert_eq!(
        game.path(),
        &RootPath::from_final_path(&direct.final_path).unwrap()
    );
    assert_eq!(
        game.path().path().file_name().and_then(|n| n.to_str()),
        Some("Game"),
        "the stored case is reported"
    );
    assert_eq!(game.dir().read(&rel("game.exe")).unwrap(), b"exe");
    assert_ne!(game.id(), store.id());

    // Every link kind at every level.
    let win_fs = WinFs::new();
    let mut skipped: Vec<&str> = Vec::new();
    for (ki, kind) in ["junction", "dir_symlink", "file_symlink", "mount_volume"]
        .into_iter()
        .enumerate()
    {
        for (level, at) in LEVELS.iter().enumerate() {
            let case = root.path().join(format!("links-{ki}-{level}"));
            let (store_path, out) = (case.join("store"), case.join("out"));
            // The target holds the rest of the path, so a followed link would find a game.
            for p in [r"common\Game\game.exe", r"Game\game.exe", "game.exe"] {
                fx.file(&out.join(p), CANARY).unwrap();
            }
            fx.dir(&store_path).unwrap();
            if level > 0 {
                fx.dir(&store_path.join(LEVELS[..level].join("\\")))
                    .unwrap();
            }
            let link = store_path.join(LEVELS[..=level].join("\\"));
            let made = match kind {
                "junction" => fx.junction(&link, &out).map(|()| true),
                "dir_symlink" => fx.dir_symlink(&link, &out),
                "file_symlink" => fx.file_symlink(&link, &out.join("game.exe")),
                _ => fx.mount_volume(&link),
            }
            .unwrap();
            if !made {
                if !skipped.contains(&kind) {
                    skipped.push(kind);
                }
                continue;
            }
            let store = StoreDir::open(&sys, &fr, &store_path).unwrap_or_else(|e| panic!("{e}"));
            match store.game(&fr, "Game") {
                Err(RootError::Reparse { .. }) => {}
                other => panic!("{kind} at {at}: expected Reparse, got {other:?}"),
            }
            let od = win_fs.open_dir(&out).unwrap();
            for p in [r"common\Game\game.exe", r"Game\game.exe", "game.exe"] {
                assert_eq!(od.read(&rel(p)).unwrap(), CANARY, "{kind} at {at}: canary");
            }
        }
    }
    for s in skipped {
        if !hosted_ci() {
            note(&format!(
                "note: store_dir_game_refuses_links_on_real_windows: skipped {s} (not available)"
            ));
        } else if CI_TOLERATED.contains(&s) {
            workflow_warning(&format!(
                "policy::root link test: {s} skipped (not available on this runner)"
            ));
        } else {
            panic!("{s} skipped on a GitHub runner");
        }
    }
}
