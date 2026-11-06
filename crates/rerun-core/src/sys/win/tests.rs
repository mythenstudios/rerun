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
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use super::testfx::{
    HiveRoot, NaiveFs, TestRoot, backup_restore_privileges, hosted_ci, note, workflow_warning,
};
use super::{WinFs, WinGpu, WinKnownFolders, WinRegistry, WinSystem, WinTopology};
use crate::path::{RelPath, RootPath};
use crate::policy::root::{
    Forbidden, ForbiddenRoots, GameDir, Protected, RootError, RootId, StoreDir,
};
use crate::sys::contract::{
    FsContractResult, FsFixture, RACE_LEAK, RegFixture, WriteOp, fs_link_read_contract,
    fs_link_write_contract, fs_race_contract, fs_read_contract, fs_volume_contract,
    fs_write_contract, fs_write_race_contract, gpu_contract, known_folders_contract,
    registry_read_contract, registry_system_contract, registry_write_contract, snapshot_contract,
    topology_contract,
};
use crate::sys::fs::{EntryKind, Fs, WriteCap};
use crate::sys::registry::{Hive, RegKey, RegValue, RegView, Registry, RegistryWrite, reg_type};
use crate::sys::snapshot::SnapRoot;
use crate::sys::{Gpu, KnownFolder, KnownFolders, SysErrorKind, System, Topology};

mod app;
mod exec;
mod sandbox;

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

    // The write capability opens the same directory.
    let w = fs.open_dir_write(&fx.0, &WriteCap::new()).unwrap();
    assert_eq!(w.info().unwrap().file_id, info.file_id);
    drop(w);
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

/// The race harness must catch the naive implementation within this time per round on an
/// ordinary machine; [`teeth_window`] stretches it on a slow or loaded one.
const TEETH: Duration = Duration::from_secs(30);

/// Fixture renames that fit into one teeth window: about [`TEETH`] at the developer machine's
/// speed (a rename by path takes 200 to 300 µs there), so a machine whose renames are slower
/// (load, a scanner) gets proportionally more time, at most four times [`TEETH`].
const TEETH_RENAMES: u32 = 100_000;

/// Rounds of [`catch_naive`]: a second, freshly measured window when the first one ends
/// without a catch (the machine was busier than the measurement showed).
const TEETH_ROUNDS: u32 = 2;

/// The budget of the safe implementation after the naive control was caught: ten times the
/// time to the catch, at least 5 s, at most 60 s (a slow catch on a loaded machine must not
/// make the suite run for many minutes).
fn safe_budget(caught: Duration) -> Duration {
    (caught * 10).clamp(Duration::from_secs(5), Duration::from_secs(60))
}

/// Serialises the heavy file system tests of this process (both race contracts and the write
/// contracts): run in parallel they slow each other's renames and flushes so much that a race
/// harness gets a fraction of its usual flips (found in review: the whole suite took twenty
/// minutes and a naive control escaped two windows). Poisoning is ignored: a failed test must
/// not fail the others.
fn heavy() -> MutexGuard<'static, ()> {
    static HEAVY: Mutex<()> = Mutex::new(());
    HEAVY.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A race contract failure that is a leak or a violation of core rule 2 ([`RACE_LEAK`]), not a
/// harness problem (an attacker error, an unexpected error kind).
fn is_leak(e: &str) -> bool {
    e.contains(RACE_LEAK)
}

/// The teeth window for this machine right now: the time of [`TEETH_RENAMES`] fixture
/// renames, measured on 32 renames of a scratch folder, within [`TEETH`] and four times that.
/// A flip of the race harness is renames, so this keeps the number of flips the naive control
/// gets about the same on a loaded machine instead of failing on a slow one.
fn teeth_window(root: &TestRoot, name: &str) -> Duration {
    let (a, b) = (root.work(name), root.path().join(format!("{name}-b")));
    let started = Instant::now();
    for i in 0..32 {
        let (from, to) = if i % 2 == 0 { (&a, &b) } else { (&b, &a) };
        root.fx().rename(from, to).unwrap();
    }
    let per = started.elapsed() / 32;
    (per * TEETH_RENAMES).clamp(TEETH, TEETH * 4)
}

/// Runs `attempt` (one contract run against a naive control in a fresh work directory under
/// `name`) until it reports a leak; panics on a harness problem, or with "harness lost its
/// teeth" when no attempt leaked within [`TEETH_ROUNDS`] windows of [`teeth_window`]. What it
/// proves is unchanged: the naive control is caught. Returns the total time to the catch (all
/// rounds and speed measurements included), the number of attempts and the leak that caught
/// it. A catch only in a later round is a `::warning::` on GitHub runners.
fn catch_naive(
    root: &TestRoot,
    name: &str,
    attempt: impl Fn(&Path) -> FsContractResult,
) -> (Duration, u32, String) {
    let mut attempts = 0u32;
    let mut windows = Vec::new();
    let total = Instant::now();
    for round in 0..TEETH_ROUNDS {
        let window = teeth_window(root, &format!("{name}-speed-{round}"));
        windows.push(window);
        let started = Instant::now();
        while started.elapsed() < window {
            let work = root.work(&format!("{name}-{attempts}"));
            attempts += 1;
            match attempt(&work) {
                Err(e) if is_leak(&e) => return (total.elapsed(), attempts, e),
                Err(e) => panic!("race harness broken against the naive control: {e}"),
                Ok(_) => {}
            }
        }
        let msg = format!("{name}: the naive control was not caught in round {round} ({window:?})");
        if hosted_ci() {
            workflow_warning(&msg);
        }
        note(&format!("note: {msg}"));
    }
    panic!(
        "harness lost its teeth: the naive implementation was not caught in {TEETH_ROUNDS} \
         windows ({windows:?}, {attempts} attempts)"
    )
}

#[test]
fn win_fulfils_fs_race_contract_and_the_harness_has_teeth() {
    let _heavy = heavy();
    let Some(root) = TestRoot::new("race") else {
        return;
    };
    // Control: the check-then-use-by-path implementation must be caught.
    let (caught, attempts, leak) = catch_naive(&root, "naive", |work| {
        fs_race_contract(&NaiveFs, root.fx(), work, Duration::from_millis(500))
    });
    let budget = safe_budget(caught);
    note(&format!(
        "note: race: NaiveFs caught after {caught:?} ({attempts} attempts: {leak}); WinFs runs \
         {budget:?}"
    ));
    let work = root.work("win");
    report(
        "fs_race_contract",
        fs_race_contract(&WinFs::new(), root.fx(), &work, budget),
    );
}

#[test]
fn win_fulfils_fs_write_contract() {
    let _heavy = heavy();
    let Some(root) = TestRoot::new("write") else {
        return;
    };
    let work = root.work("w");
    report(
        "fs_write_contract",
        fs_write_contract(&WinFs::new(), root.fx(), &work),
    );
}

#[test]
fn win_fulfils_fs_link_write_contract() {
    let _heavy = heavy();
    let Some(root) = TestRoot::new("link-write") else {
        return;
    };
    let work = root.work("w");
    report(
        "fs_link_write_contract",
        fs_link_write_contract(&WinFs::new(), root.fx(), &work),
    );
}

/// The snapshot contract on real Windows: the work directory is opened as a manually added
/// game folder through `policy::root` (a `TestRoot` folder stands in for Rerun's install
/// folder), its handle is the snapshot root; the key lives in a private app hive.
#[test]
fn win_fulfils_snapshot_contract() {
    let _heavy = heavy();
    let Some(root) = TestRoot::new("snapshot") else {
        return;
    };
    let Some(h) = HiveRoot::new("snapshot-hive") else {
        return;
    };
    let sys = WinSystem::new().unwrap();
    let install = root.work("Rerun");
    let fr = ForbiddenRoots::resolve(&sys, &install).unwrap_or_else(|e| panic!("{e}"));
    let work = root.work("w");
    let game = GameDir::open_manual(&sys, &fr, &work).unwrap_or_else(|e| panic!("{e}"));
    let key = RegKey::new(Hive::CurrentUser, RegView::Native, "RerunSnapshot");
    h.hive.key(&key).unwrap();
    let started = Instant::now();
    let result = snapshot_contract(
        SnapRoot::new(game.dir(), game.path().to_string()),
        root.fx(),
        &work,
        &h.registry,
        &h.hive,
        &key,
    );
    note(&format!(
        "note: snapshot_contract took {:?}",
        started.elapsed()
    ));
    report("snapshot_contract", result);
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

/// Read-only: the real topology is valid, non-empty and stable across two reads (ADR 0010).
#[test]
fn win_fulfils_topology_contract() {
    topology_contract(&WinTopology::new()).unwrap_or_else(|e| panic!("{e}"));
}

/// Read-only: `WinSystem` hands out the real parts, each fulfilling its contract (the file
/// system and registry contracts need fixtures and run on the parts directly above).
#[test]
fn win_system_bundles_the_real_parts() {
    super::restrict_dll_search().unwrap();
    let sys = WinSystem::new().unwrap();
    assert_eq!(format!("{sys:?}"), "WinSystem { .. }");
    topology_contract(sys.topology()).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        sys.topology().read().unwrap(),
        WinTopology::new().read().unwrap()
    );
    known_folders_contract(sys.known_folders(), sys.fs()).unwrap_or_else(|e| panic!("{e}"));
    gpu_contract(sys.gpu()).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        sys.gpu().adapters().unwrap(),
        WinGpu::new().adapters().unwrap()
    );
    let reg = WinRegistry::new().unwrap();
    let kf = WinKnownFolders::new(Arc::new(reg));
    for f in KnownFolder::ALL {
        assert_eq!(
            sys.known_folders().get(f).unwrap(),
            kf.get(f).unwrap(),
            "{f}"
        );
    }
    // The registry is the real, read-only one.
    let k = RegKey::new(Hive::CurrentUser, RegView::Native, "Software");
    assert_eq!(sys.registry().key_exists(&k), Ok(true));
}

// ---------- OS build (ADR 0015) ----------

/// Read-only: `hw::os` reads the build from the real registry (`CurrentBuildNumber`, native
/// view), and it equals the build `RtlGetVersion` reports. No assumption about the version
/// itself: Windows 10 and Server 2022 (20348) are below 22000.
#[test]
fn os_build_matches_rtl_get_version() {
    let reg = WinRegistry::new().unwrap();
    let os = crate::hw::os::read(&reg).unwrap();
    assert_eq!(os.build, super::testfx::rtl_build_number());
    assert!(os.build > 0);
    // Windows 10, Server 2022 and Windows 11 always set `UBR`.
    assert!(os.ubr.is_some(), "UBR missing");
}

/// Read-only: the system profile of this machine (ADR 0015). CPU and OS are read, the build
/// equals `RtlGetVersion`'s. The GPU expectation comes from the raw DXGI list, with no CI
/// special case: if it has a hardware adapter (no software flag, not vendor `0x1414`), the
/// primary adapter is exactly the first one; otherwise (a GitHub runner, a VM without a GPU)
/// the vendor fact is `NoAdapter` and the test says so on stderr.
#[test]
fn system_profile_of_this_machine() {
    use crate::hw::{self, ArchFact, Fact, GpuArchTable, VendorFact};

    super::restrict_dll_search().unwrap();
    let sys = WinSystem::new().unwrap();
    let p = hw::read(&sys, Some(GpuArchTable::builtin().unwrap()));
    let cpu = p.cpu.as_ref().unwrap();
    assert_eq!(
        p.cpu_threads(),
        Fact::Known(u32::try_from(cpu.logical_count()).unwrap())
    );
    assert_eq!(p.cpu_hybrid(), Fact::Known(cpu.is_hybrid()));
    assert_eq!(p.os_build(), Fact::Known(super::testfx::rtl_build_number()));
    let gpu = p.gpu.as_ref().unwrap();
    let raw = sys.gpu().adapters().unwrap();
    let hardware: Vec<_> = raw
        .iter()
        .filter(|a| !a.software && a.vendor_id != 0x1414)
        .collect();
    let kept: Vec<_> = gpu.adapters.iter().map(|e| &e.adapter).collect();
    assert_eq!(kept, hardware, "hardware adapters in DXGI order");
    match hardware.first() {
        Some(first) => {
            let primary = gpu.primary().unwrap();
            assert_eq!(&&primary.adapter, first);
            assert_eq!(
                p.gpu_vendor(),
                VendorFact::Known(hw::GpuVendor::from_id(first.vendor_id))
            );
            assert_ne!(p.gpu_arch(), ArchFact::NoAdapter);
        }
        None => {
            assert_eq!(gpu.primary(), None);
            assert_eq!(p.gpu_vendor(), VendorFact::NoAdapter);
            assert_eq!(p.gpu_arch(), ArchFact::NoAdapter);
            note(&format!(
                "system_profile_of_this_machine: no hardware adapter among {} DXGI adapters \
                 (GitHub runner or a VM without a GPU): gpu facts are NoAdapter",
                raw.len()
            ));
        }
    }
}

// ---------- GPU (DXGI) ----------

/// Read-only: the real adapters fulfil the GPU contract, and the Microsoft Basic Render Driver
/// (vendor `0x1414`, device `0x8c`) is listed exactly once as a software adapter, on every
/// machine and on GitHub runners without a GPU.
#[test]
fn win_fulfils_gpu_contract() {
    super::restrict_dll_search().unwrap();
    let gpu = WinGpu::new();
    gpu_contract(&gpu).unwrap_or_else(|e| panic!("{e}"));
    let adapters = gpu.adapters().unwrap();
    // A VM without a GPU (GitHub runner) lists the Basic Render Driver twice: once as the
    // display adapter of the VM (no software flag) and once as WARP (software flag). Exactly
    // one of them is the software adapter.
    let basic_software = adapters
        .iter()
        .filter(|a| a.vendor_id == 0x1414 && a.device_id == 0x8c && a.software)
        .count();
    assert_eq!(basic_software, 1, "{adapters:#?}");
}

/// `dxgi.dll` is the one in `<Windows>\System32`, never one from the application directory.
#[test]
fn dxgi_dll_is_loaded_from_system32() {
    super::restrict_dll_search().unwrap();
    WinGpu::new().adapters().unwrap();
    let dxgi = super::loader::load_system32("dxgi.dll").unwrap();
    let path = super::testfx::module_path(dxgi.handle());
    let windows = WinKnownFolders::new(Arc::new(WinRegistry::new().unwrap()))
        .get(KnownFolder::Windows)
        .unwrap();
    let expected = windows.join("System32").join("dxgi.dll");
    assert!(
        path.to_string_lossy()
            .eq_ignore_ascii_case(&expected.to_string_lossy()),
        "{} is not {}",
        path.display(),
        expected.display()
    );
}

/// Prints the adapters of this machine and the time of a first (loads `dxgi.dll`) and a second
/// enumeration. Read-only; run by hand:
/// `cargo test -p rerun-core --lib dump_gpu_adapters -- --ignored --nocapture`.
#[test]
#[ignore = "prints this machine's adapters; run by hand"]
fn dump_gpu_adapters() {
    super::restrict_dll_search().unwrap();
    let gpu = WinGpu::new();
    let started = Instant::now();
    let adapters = gpu.adapters().unwrap();
    let first = started.elapsed();
    let started = Instant::now();
    assert_eq!(gpu.adapters().unwrap(), adapters);
    let second = started.elapsed();
    for (i, a) in adapters.iter().enumerate() {
        let umd = a.umd_version.map_or("none".to_owned(), |v| v.to_string());
        note(&format!(
            "adapter {i}: {:?} vendor {:#06x} device {:#06x} subsys {:#010x} rev {:#x} \
             dedicated {} MiB shared {} MiB software {} umd {umd}",
            a.name,
            a.vendor_id,
            a.device_id,
            a.subsys_id,
            a.revision,
            a.dedicated_video_memory >> 20,
            a.shared_system_memory >> 20,
            a.software,
        ));
    }
    note(&format!(
        "gpu: {} adapters, first enumeration {first:?}, second {second:?}",
        adapters.len()
    ));
}

/// `bytes` as JSON strings of 32 bytes (64 hex digits) each, one per line.
fn hex_lines(bytes: &[u8]) -> String {
    let lines: Vec<String> = bytes
        .chunks(32)
        .map(|c| {
            let hex: String = c.iter().map(|b| format!("{b:02x}")).collect();
            format!("    \"{hex}\"")
        })
        .collect();
    lines.join(",\n")
}

/// The CPU Set bytes with every byte the parser does not read zeroed (an allowlist: bytes
/// `CPU_SET_MIN_SIZE..Size` of each record). Found on the 5950X: `SchedulingClass` holds the
/// firmware's preferred-core ranking (CPPC), which differs from one chip sample to the next, so
/// it is a fingerprint; `AllocationTag` and future fields could be one too (ADR 0010).
fn scrub_cpu_sets(sets: &[u8]) -> Vec<u8> {
    use rerun_proto::cpu::parse::layout::{CPU_SET_MIN_SIZE, CPU_SET_SIZE};
    let mut out = sets.to_vec();
    let mut at = 0;
    while let Some(head) = out.get(at + CPU_SET_SIZE..at + CPU_SET_SIZE + 4) {
        let size = u32::from_le_bytes([head[0], head[1], head[2], head[3]]);
        let size = usize::try_from(size).unwrap();
        // The parser refuses such a buffer anyway; the parse-equality assert catches it.
        assert!(size >= CPU_SET_MIN_SIZE, "cpu set record of {size} bytes");
        let end = (at + size).min(out.len());
        out[at + CPU_SET_MIN_SIZE..end].fill(0);
        at += size;
    }
    out
}

/// Writes the raw bytes of both topology calls to `target/cpu-dump.json` (fixture format 1,
/// `tests/fixtures/cpu/README.md`; unread bytes zeroed, see [`scrub_cpu_sets`]) and the
/// parsed topology to `target/cpu-dump.parsed.json`. Read-only on the system; run by hand on a
/// machine whose fixture is wanted:
/// `cargo test -p rerun-core --lib dump_cpu_topology -- --ignored`, then fill in the
/// description.
#[test]
#[ignore = "writes target/cpu-dump.json from this machine; run by hand for a new fixture"]
fn dump_cpu_topology() {
    let sets = super::cpu::system_cpu_sets().unwrap();
    let info = super::cpu::processor_information().unwrap();
    let parsed =
        rerun_proto::cpu::CpuTopology::from_windows(&sets, &info).unwrap_or_else(|e| panic!("{e}"));
    let scrubbed = scrub_cpu_sets(&sets);
    assert_eq!(
        rerun_proto::cpu::CpuTopology::from_windows(&scrubbed, &info),
        Ok(parsed.clone())
    );
    let raw = [
        "{".to_owned(),
        "  \"format\": 1,".to_owned(),
        "  \"description\": \"TODO: CPU model, Windows build\",".to_owned(),
        "  \"cpu_sets\": [".to_owned(),
        hex_lines(&scrubbed),
        "  ],".to_owned(),
        "  \"processor_info\": [".to_owned(),
        hex_lines(&info),
        "  ]".to_owned(),
        "}".to_owned(),
        String::new(),
    ]
    .join("\n");
    let target = super::testfx::target_dir();
    std::fs::write(target.join("cpu-dump.json"), raw).unwrap();
    let json = serde_json::to_string_pretty(&parsed).unwrap() + "\n";
    std::fs::write(target.join("cpu-dump.parsed.json"), json).unwrap();
    note(&format!(
        "wrote {} ({} logical processors, {} cores, {} llcs)",
        target.join("cpu-dump.json").display(),
        parsed.logical_count(),
        parsed.core_count(),
        parsed.llc_count()
    ));
}

/// The registry write contract against `sys::win` in a private app hive whose `HKCU` root is a
/// `KEY_READ` handle, like `RegOpenCurrentUser(KEY_READ)`: every write opens its segments
/// relative to that read handle (ADR 0018 amendment P2-9).
#[test]
fn win_fulfils_registry_write_contract() {
    let Some(h) = HiveRoot::new("reg-write") else {
        return;
    };
    let root = RegKey::new(Hive::CurrentUser, RegView::Native, "RerunWrite");
    h.hive.key(&root).unwrap();
    let started = Instant::now();
    let skips = registry_write_contract(&h.registry, &h.hive, &root)
        .unwrap_or_else(|e| panic!("registry_write_contract: {e}"));
    note(&format!(
        "note: registry_write_contract took {:?}",
        started.elapsed()
    ));
    for s in skips {
        assert!(
            !hosted_ci(),
            "registry_write_contract: {s} skipped on a GitHub runner"
        );
        note(&format!("note: registry_write_contract: skipped {s}"));
    }
}

/// K-R2 on Windows: without the kernel-name comparison the write lands in the key renamed by
/// another program (`RegRenameKey`), and the contract fails at RW9.
#[test]
fn win_registry_write_contract_catches_a_missing_kernel_name_check() {
    let Some(h) = HiveRoot::new("reg-write-kr2") else {
        return;
    };
    let root = RegKey::new(Hive::CurrentUser, RegView::Native, "RerunWrite");
    h.hive.key(&root).unwrap();
    crate::sys::seq::reg::knob::no_kernel_name(true);
    let r = registry_write_contract(&h.registry, &h.hive, &root);
    crate::sys::seq::reg::knob::no_kernel_name(false);
    let e = r.unwrap_err();
    assert!(e.contains("renamed key"), "{e}");
}

/// S2: in an elevated process the write side changes nothing (here forced on an app hive);
/// reads and the flush still work.
#[test]
fn win_registry_write_refuses_an_elevated_process() {
    let Some(mut h) = HiveRoot::new("reg-write-elevated") else {
        return;
    };
    let k = RegKey::new(Hive::CurrentUser, RegView::Native, "Existing");
    h.hive.key(&k).unwrap();
    h.hive
        .raw(&k, "v", reg_type::REG_DWORD, &[1, 0, 0, 0])
        .unwrap();
    h.registry.set_elevated(true);
    let reg = &h.registry;
    let (one, two) = (RegValue::Dword(1), RegValue::Dword(2));
    for (what, r) in [
        (
            "create_key",
            RegistryWrite::create_key(reg, &k.join("New")).map(drop),
        ),
        ("set", RegistryWrite::set(reg, &k, "v", Some(&one), &two)),
        (
            "delete_value",
            RegistryWrite::delete_value(reg, &k, "v", &one),
        ),
        ("delete_empty_key", reg.delete_empty_key(&k)),
    ] {
        let e = r.expect_err(what);
        assert_eq!(e.kind, SysErrorKind::Unsupported, "{what}");
        assert!(e.target.contains("elevated"), "{what}: {e}");
    }
    assert_eq!(reg.read(&k, "v").unwrap(), Some(one));
    assert!(!reg.key_exists(&k.join("New")).unwrap());
    reg.flush(Hive::CurrentUser).unwrap();
}

/// The real `WinRegistry` knows whether this process is elevated. The write it tries can never
/// create anything in the real `HKCU`, even if the guard regressed: the parent of its key is
/// missing, so without the guard it is `NotFound` (review S2).
#[test]
fn win_registry_reports_elevation_like_the_token() {
    let reg = WinRegistry::new().unwrap();
    let k = RegKey::new(Hive::CurrentUser, RegView::Native, "Software");
    assert!(matches!(
        reg.key_state(&k).unwrap(),
        crate::sys::registry::KeyState::Present { .. }
    ));
    let parent = k.join("RerunNeverCreated");
    assert!(!reg.key_exists(&parent).unwrap(), "{parent} must not exist");
    let e = RegistryWrite::create_key(&reg, &parent.join("X")).unwrap_err();
    let want = if super::token::process_elevated().unwrap_or(true) {
        // Elevated (a GitHub runner): refused before anything is opened.
        SysErrorKind::Unsupported
    } else {
        SysErrorKind::NotFound
    };
    assert_eq!(e.kind, want, "{e}");
    assert!(!reg.key_exists(&parent).unwrap());
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

fn known(sys: &WinSystem, f: KnownFolder) -> RootPath {
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
    let sys = WinSystem::new().unwrap();
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
    let sys = WinSystem::new().unwrap();
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

#[test]
fn win_fulfils_fs_write_race_contract_and_the_harness_has_teeth() {
    let _heavy = heavy();
    let Some(root) = TestRoot::new("write-race") else {
        return;
    };
    // Control: the path-based writer (hash, pause, act by path) must be caught with each
    // operation alone, so each operation is shown to be caught by at least one assertion.
    let mut slowest = Duration::ZERO;
    for op in WriteOp::ALL {
        let (caught, attempts, leak) = catch_naive(&root, &format!("naive-{op:?}"), |work| {
            fs_write_race_contract(&NaiveFs, root.fx(), work, Duration::from_millis(500), &[op])
        });
        note(&format!(
            "note: write race: NaiveFs {op:?} caught after {caught:?} ({attempts} attempts: \
             {leak})"
        ));
        slowest = slowest.max(caught);
    }
    let budget = safe_budget(slowest);
    note(&format!("note: write race: WinFs runs {budget:?}"));
    let work = root.work("win");
    report(
        "fs_write_race_contract",
        fs_write_race_contract(&WinFs::new(), root.fx(), &work, budget, &WriteOp::ALL),
    );
}

/// An open of `p` by another program: read or write access, share read, write and delete, with
/// or without backup intent (`FILE_FLAG_BACKUP_SEMANTICS`). `Ok` or the raw Win32 error.
fn foreign_open(p: &Path, write: bool, backup: bool) -> Result<(), i32> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE,
        FILE_SHARE_READ, FILE_SHARE_WRITE,
    };
    let flags = FILE_FLAG_OPEN_REPARSE_POINT
        | if backup {
            FILE_FLAG_BACKUP_SEMANTICS
        } else {
            0
        };
    std::fs::OpenOptions::new()
        .read(!write)
        .write(write)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(flags)
        .open(p)
        .map(drop)
        .map_err(|e| e.raw_os_error().unwrap_or(-1))
}

/// Backup intent against the journal lock and the guard (ADR 0017, "Backup intent"). Without
/// backup intent another program's read of the lock and write of the guarded file are sharing
/// violations (as K1 and the guard contract require). With `SeBackupPrivilege` enabled, a read
/// with backup intent passes both, a write does not (observed in CI run 42134204098, also with
/// `SeRestorePrivilege` enabled). Runs only where the privilege is enabled (the elevated GitHub
/// runner); prints the privilege state and the outcomes.
#[test]
fn backup_intent_against_lock_and_guard() {
    const SHARING_VIOLATION: i32 = 32;
    let (backup, restore) = backup_restore_privileges();
    if backup != "enabled" {
        note(&format!(
            "skipped backup_intent_against_lock_and_guard: SeBackupPrivilege {backup} (runs on the elevated GitHub runner)"
        ));
        return;
    }
    let Some(root) = TestRoot::new("backup-intent") else {
        return;
    };
    let work = root.work("w");
    std::fs::write(work.join("game.bin"), b"guarded").unwrap();
    let fs = WinFs::new();
    let d = fs.open_dir_write(&work, &WriteCap::new()).unwrap();
    let lock = d.lock(&rel("journal.lock")).unwrap();
    let guard = d.guard(&rel("game.bin")).unwrap();
    let lock_p = work.join("journal.lock");
    let game_p = work.join("game.bin");

    assert_eq!(foreign_open(&lock_p, false, false), Err(SHARING_VIOLATION));
    assert_eq!(foreign_open(&game_p, true, false), Err(SHARING_VIOLATION));
    let outcomes = [
        ("read of the lock", foreign_open(&lock_p, false, true)),
        ("write of the lock", foreign_open(&lock_p, true, true)),
        (
            "read of the guarded file",
            foreign_open(&game_p, false, true),
        ),
        (
            "write of the guarded file",
            foreign_open(&game_p, true, true),
        ),
    ];
    let shown: Vec<String> = outcomes
        .iter()
        .map(|(what, r)| match r {
            Ok(()) => format!("{what}: opened"),
            Err(e) => format!("{what}: error {e}"),
        })
        .collect();
    note(&format!(
        "note: backup intent (SeBackupPrivilege {backup}, SeRestorePrivilege {restore}): {}",
        shown.join("; ")
    ));
    drop((guard, lock));
    let got: Vec<_> = outcomes.iter().map(|(_, r)| *r).collect();
    assert_eq!(
        got,
        [
            Ok(()),
            Err(SHARING_VIOLATION),
            Ok(()),
            Err(SHARING_VIOLATION)
        ],
        "backup intent: reads pass the lock and the guard, writes do not"
    );
}
