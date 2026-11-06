#![expect(
    clippy::disallowed_methods,
    reason = "tests of the fake open directories by absolute path"
)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::{FakeFs, FakeSystem, Fault, FsOp, Prim, StepEvent};
use crate::path::RelPath;
use crate::sys::contract::{
    Access, FsFixture, Held, Share, fs_link_read_contract, fs_link_write_contract,
    fs_race_contract, fs_read_contract, fs_volume_contract, fs_write_contract,
    fs_write_race_contract, gpu_contract, known_folders_contract, registry_read_contract,
    registry_system_contract, registry_write_contract, topology_contract,
};
use crate::sys::fs::{Attrs, DirWrite, EntryKind, Fs, FsKind, NewFile, TmpName, WriteCap, tag};
use crate::sys::registry::{Hive, RegKey, RegValue, RegView, Registry, reg_type};
use crate::sys::snapshot::{Scope, SnapRoot, Snapshot, snapshot};
use crate::sys::{DriverVersion, GpuAdapter, KnownFolder};
use crate::sys::{SysErrorKind, SysResult, System, Topology};
use rerun_proto::cpu::CpuTopology;
use sha2::{Digest, Sha256};

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

fn open<'a>(sys: &'a FakeSystem, abs: &str) -> Box<dyn DirWrite + 'a> {
    sys.fs()
        .open_dir_write(Path::new(abs), &WriteCap::new())
        .unwrap()
}

fn kind<T: std::fmt::Debug>(res: crate::sys::SysResult<T>) -> SysErrorKind {
    res.unwrap_err().kind
}

// ---------- Contracts ----------

/// System with an existing, empty work directory. Every contract run gets a fresh one: the
/// contracts do not clean up, the runner does by not reusing a directory.
fn fresh(work: &str) -> FakeSystem {
    FakeSystem::builder().dir(work).build().unwrap()
}

const RACE_BUDGET: Duration = Duration::from_millis(200);

#[test]
fn fake_fulfils_fs_read_contract() {
    let sys = fresh(r"C:\Work");
    let skips = fs_read_contract(sys.fs(), sys.fake_fs(), Path::new(r"C:\Work")).unwrap();
    // The fake has no 8.3 names and no WOF.
    assert_eq!(skips, ["short_name", "wof_compress"]);
}

#[test]
fn fake_fulfils_fs_link_read_contract() {
    let sys = fresh(r"D:\Work");
    let skips = fs_link_read_contract(sys.fs(), sys.fake_fs(), Path::new(r"D:\Work")).unwrap();
    assert!(skips.is_empty(), "{skips:?}");
}

#[test]
fn fake_fulfils_fs_volume_contract() {
    let sys = fresh(r"D:\Work");
    let skips = fs_volume_contract(sys.fs(), sys.fake_fs(), Path::new(r"D:\Work")).unwrap();
    // The fake has no drive substitution.
    assert_eq!(skips, ["subst"]);
}

#[test]
fn fake_fulfils_fs_race_contract() {
    let sys = fresh(r"D:\Work");
    let skips =
        fs_race_contract(sys.fs(), sys.fake_fs(), Path::new(r"D:\Work"), RACE_BUDGET).unwrap();
    assert!(skips.is_empty(), "{skips:?}");
}

#[test]
fn contracts_can_run_twice_in_fresh_dirs() {
    let sys = fresh(r"C:\Work");
    let fx = sys.fake_fs();
    for run in 1..=2 {
        let dir = |name: &str| {
            let p = PathBuf::from(format!(r"C:\Work\{name}{run}"));
            fx.mkdir_all(&p).unwrap();
            p
        };
        fs_read_contract(sys.fs(), fx, &dir("read")).unwrap();
        fs_link_read_contract(sys.fs(), fx, &dir("link-read")).unwrap();
        fs_volume_contract(sys.fs(), fx, &dir("volume")).unwrap();
        fs_race_contract(sys.fs(), fx, &dir("race"), Duration::from_millis(20)).unwrap();
        fs_write_contract(sys.fs(), fx, &dir("write")).unwrap();
        fs_link_write_contract(sys.fs(), fx, &dir("link-write")).unwrap();
    }
}

#[test]
fn fake_fulfils_fs_link_write_contract() {
    let sys = fresh(r"D:\Work");
    let skips = fs_link_write_contract(sys.fs(), sys.fake_fs(), Path::new(r"D:\Work")).unwrap();
    assert!(skips.is_empty(), "{skips:?}");
}

#[test]
fn fake_fulfils_fs_write_contract() {
    let sys = fresh(r"C:\Work");
    let skips = fs_write_contract(sys.fs(), sys.fake_fs(), Path::new(r"C:\Work")).unwrap();
    // The fake has no WOF.
    assert_eq!(skips, ["wof_compress"]);
}

/// The writing race against the fake, with a short budget: a sanity check of the harness (the
/// fake's renames are atomic and instant; its deterministic step hooks remain the precise
/// TOCTOU tests).
#[test]
fn fake_fulfils_fs_write_race_contract() {
    let sys = fresh(r"C:\Work");
    let skips = fs_write_race_contract(
        sys.fs(),
        sys.fake_fs(),
        Path::new(r"C:\Work"),
        Duration::from_millis(200),
        &crate::sys::contract::WriteOp::ALL,
    )
    .unwrap();
    assert!(skips.is_empty(), "{skips:?}");
}

#[test]
fn a_read_contract_needs_an_empty_work_dir() {
    let sys = fresh(r"C:\Work");
    let work = Path::new(r"C:\Work");
    fs_read_contract(sys.fs(), sys.fake_fs(), work).unwrap();
    let e = fs_read_contract(sys.fs(), sys.fake_fs(), work).unwrap_err();
    assert!(e.contains("empty"), "{e}");
}

/// Fixture whose "junction" is a plain copy of the target: reading through it exposes the
/// content, like a naive implementation would. The race contract must notice.
struct CopyFixture {
    inner: FakeFs,
    files: Mutex<Vec<(PathBuf, Vec<u8>)>>,
}

impl FsFixture for CopyFixture {
    fn dir(&self, p: &Path) -> SysResult<()> {
        self.inner.dir(p)
    }
    fn file(&self, p: &Path, data: &[u8]) -> SysResult<()> {
        self.files
            .lock()
            .unwrap()
            .push((p.to_path_buf(), data.to_vec()));
        self.inner.file(p, data)
    }
    fn utf16_file(&self, parent: &Path, units: &[u16], data: &[u8]) -> SysResult<bool> {
        self.inner.utf16_file(parent, units, data)
    }
    fn junction(&self, link: &Path, target: &Path) -> SysResult<()> {
        self.inner.dir(link)?;
        let files = self.files.lock().unwrap().clone();
        for (path, data) in files {
            if let Ok(rest) = path.strip_prefix(target) {
                self.inner.file(&link.join(rest), &data)?;
            }
        }
        Ok(())
    }
    fn dir_symlink(&self, link: &Path, target: &Path) -> SysResult<bool> {
        self.inner.dir_symlink(link, target)
    }
    fn file_symlink(&self, link: &Path, target: &Path) -> SysResult<bool> {
        self.inner.file_symlink(link, target)
    }
    fn hardlink(&self, existing: &Path, new: &Path) -> SysResult<()> {
        self.inner.hardlink(existing, new)
    }
    fn rename(&self, from: &Path, to: &Path) -> SysResult<()> {
        self.inner.rename(from, to)
    }
    fn case_sensitive_dir(&self, p: &Path) -> SysResult<bool> {
        self.inner.case_sensitive_dir(p)
    }
    fn mount_volume(&self, at: &Path) -> SysResult<bool> {
        self.inner.mount_volume(at)
    }
    fn subst(&self, target: &Path) -> SysResult<Option<PathBuf>> {
        self.inner.subst(target)
    }
    fn short_name(&self, p: &Path, short: &str) -> SysResult<bool> {
        self.inner.short_name(p, short)
    }
    fn wof_compress(&self, p: &Path) -> SysResult<bool> {
        self.inner.wof_compress(p)
    }
    fn restricted(&self, p: &Path) -> SysResult<bool> {
        self.inner.restricted(p)
    }
    fn hold_open(&self, p: &Path, access: Access, share: Share) -> SysResult<Held<'_>> {
        self.inner.hold_open(p, access, share)
    }
    fn remove(&self, p: &Path) -> SysResult<()> {
        self.inner.remove(p)
    }
    fn set_attrs(&self, p: &Path, attrs: Attrs) -> SysResult<()> {
        FsFixture::set_attrs(&self.inner, p, attrs)
    }
    fn mapped_image(&self, p: &Path) -> SysResult<Option<Held<'_>>> {
        self.inner.mapped_image(p)
    }
    fn delete_pending(&self, p: &Path) -> SysResult<Option<Held<'_>>> {
        FsFixture::delete_pending(&self.inner, p)
    }
    fn mapped_data(&self, p: &Path) -> SysResult<Option<Held<'_>>> {
        self.inner.mapped_data(p)
    }
    fn data_section(&self, p: &Path) -> SysResult<Option<Held<'_>>> {
        self.inner.data_section(p)
    }
}

#[test]
fn the_race_contract_catches_a_leaking_swap() {
    let sys = fresh(r"D:\Work");
    let fx = CopyFixture {
        inner: sys.fake_fs().clone(),
        files: Mutex::new(Vec::new()),
    };
    let started = Instant::now();
    for attempt in 0.. {
        let work = PathBuf::from(format!(r"D:\Work\attempt-{attempt}"));
        fx.dir(&work).unwrap();
        if let Err(e) = fs_race_contract(sys.fs(), &fx, &work, Duration::from_millis(100)) {
            assert!(e.contains(crate::sys::contract::RACE_LEAK), "{e}");
            return;
        }
        assert!(
            started.elapsed() < Duration::from_secs(30),
            "harness lost its teeth: a leaking swap was never caught"
        );
    }
}

#[test]
fn fake_fulfils_registry_write_contract() {
    let root = hkcu(r"Software\RerunContract");
    let sys = FakeSystem::builder().key(root.clone()).build().unwrap();
    registry_write_contract(sys.registry(), &root).unwrap();
}

fn key(hive: Hive, view: RegView, path: &str) -> RegKey {
    RegKey::new(hive, view, path)
}

#[test]
fn fake_fulfils_registry_read_contract_in_both_views() {
    // Roots outside HKLM\SOFTWARE are shared between the views; the contract deletes nothing,
    // so every run gets its own root.
    let roots = [
        key(
            Hive::CurrentUser,
            RegView::Native,
            r"Software\RerunContract\native",
        ),
        key(
            Hive::CurrentUser,
            RegView::Wow32,
            r"Software\RerunContract\wow32",
        ),
        key(
            Hive::LocalMachine,
            RegView::Native,
            r"SYSTEM\RerunContract\native",
        ),
        key(
            Hive::LocalMachine,
            RegView::Wow32,
            r"SYSTEM\RerunContract\wow32",
        ),
    ];
    let mut b = FakeSystem::builder();
    for r in &roots {
        b = b.key(r.clone());
    }
    let sys = b.build().unwrap();
    for r in &roots {
        let skips = registry_read_contract(sys.registry(), sys.fake_registry(), r).unwrap();
        // The fake has no symbolic-link keys.
        assert_eq!(skips, ["key_link"], "{r}");
    }
}

/// Registry that hands out a raw value as if it were binary: the read contract must notice.
struct LossyRegistry<'a>(&'a dyn Registry);

impl Registry for LossyRegistry<'_> {
    fn key_exists(&self, k: &RegKey) -> SysResult<bool> {
        self.0.key_exists(k)
    }
    fn get(&self, k: &RegKey, name: &str) -> SysResult<Option<RegValue>> {
        Ok(self.0.get(k, name)?.map(|v| match v {
            RegValue::Raw(r) => RegValue::Binary(r.data().to_vec()),
            v => v,
        }))
    }
    fn values(&self, k: &RegKey) -> SysResult<Vec<(String, RegValue)>> {
        self.0.values(k)
    }
    fn subkeys(&self, k: &RegKey) -> SysResult<Vec<String>> {
        self.0.subkeys(k)
    }
    fn create_key(&self, k: &RegKey) -> SysResult<bool> {
        self.0.create_key(k)
    }
    fn set(&self, k: &RegKey, name: &str, v: &RegValue) -> SysResult<()> {
        self.0.set(k, name, v)
    }
    fn delete_value(&self, k: &RegKey, name: &str) -> SysResult<()> {
        self.0.delete_value(k, name)
    }
    fn delete_key(&self, k: &RegKey) -> SysResult<()> {
        self.0.delete_key(k)
    }
}

#[test]
fn the_registry_read_contract_catches_a_lossy_registry() {
    let root = hkcu(r"Software\RerunContract");
    let sys = FakeSystem::builder().key(root.clone()).build().unwrap();
    let lossy = LossyRegistry(sys.registry());
    let e = registry_read_contract(&lossy, sys.fake_registry(), &root).unwrap_err();
    assert!(e.contains("decoding case"), "{e}");
}

#[test]
fn the_registry_read_contract_needs_an_empty_root() {
    let root = hkcu(r"Software\RerunContract");
    let sys = FakeSystem::builder().key(root.clone()).build().unwrap();
    registry_read_contract(sys.registry(), sys.fake_registry(), &root).unwrap();
    let e = registry_read_contract(sys.registry(), sys.fake_registry(), &root).unwrap_err();
    assert!(e.contains("empty"), "{e}");
}

/// A fake with the system keys that `registry_system_contract` reads, from the standard layout.
fn system_keys() -> crate::sys::fake::FakeSystemBuilder {
    let cv = r"SOFTWARE\Microsoft\Windows\CurrentVersion";
    let wow = r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion";
    let hklm = |p: &str| key(Hive::LocalMachine, RegView::Native, p);
    let sz = |s: &str| RegValue::String(s.into());
    FakeSystem::builder()
        .value(hklm(cv), "ProgramFilesDir", sz(r"C:\Program Files"))
        .value(
            hklm(cv),
            "CommonFilesDir",
            sz(r"C:\Program Files\Common Files"),
        )
        .value(hklm(wow), "ProgramFilesDir", sz(r"C:\Program Files (x86)"))
        .value(
            hklm(wow),
            "CommonFilesDir",
            sz(r"C:\Program Files (x86)\Common Files"),
        )
        .key(hklm(r"SYSTEM\CurrentControlSet\Control"))
        .denied_key(hklm("SECURITY"))
}

#[test]
fn fake_fulfils_registry_system_contract() {
    let sys = system_keys().build().unwrap();
    let skips = registry_system_contract(sys.registry(), sys.known_folders()).unwrap();
    assert!(skips.is_empty(), "{skips:?}");
}

#[test]
fn the_registry_system_contract_catches_wrong_data() {
    let hklm = |p: &str| key(Hive::LocalMachine, RegView::Native, p);
    let cv = r"SOFTWARE\Microsoft\Windows\CurrentVersion";
    let known = FakeSystem::new();
    // Nothing seeded.
    let empty = FakeSystem::new();
    assert!(registry_system_contract(empty.registry(), known.known_folders()).is_err());
    // The 32-bit value in the native location (no redirection modelled).
    let swapped = system_keys()
        .value(
            hklm(cv),
            "ProgramFilesDir",
            RegValue::String(r"C:\Program Files (x86)".into()),
        )
        .build()
        .unwrap();
    assert!(registry_system_contract(swapped.registry(), known.known_folders()).is_err());
    // A value of another type.
    let typed = system_keys()
        .value(hklm(cv), "CommonFilesDir", RegValue::Dword(1))
        .build()
        .unwrap();
    assert!(registry_system_contract(typed.registry(), known.known_folders()).is_err());
    // Missing CurrentControlSet.
    let mut b = FakeSystem::builder();
    for (name, v) in [
        ("ProgramFilesDir", r"C:\Program Files"),
        ("CommonFilesDir", r"C:\Program Files\Common Files"),
    ] {
        b = b.value(hklm(cv), name, RegValue::String(v.into()));
    }
    for (name, v) in [
        ("ProgramFilesDir", r"C:\Program Files (x86)"),
        ("CommonFilesDir", r"C:\Program Files (x86)\Common Files"),
    ] {
        b = b.value(
            hklm(r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion"),
            name,
            RegValue::String(v.into()),
        );
    }
    let no_control = b.denied_key(hklm("SECURITY")).build().unwrap();
    assert!(registry_system_contract(no_control.registry(), known.known_folders()).is_err());
    // SECURITY readable: the case is skipped, not failed.
    let open = FakeSystem::builder()
        .value(
            hklm(cv),
            "ProgramFilesDir",
            RegValue::String(r"C:\Program Files".into()),
        )
        .value(
            hklm(cv),
            "CommonFilesDir",
            RegValue::String(r"C:\Program Files\Common Files".into()),
        )
        .value(
            hklm(r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion"),
            "ProgramFilesDir",
            RegValue::String(r"C:\Program Files (x86)".into()),
        )
        .value(
            hklm(r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion"),
            "CommonFilesDir",
            RegValue::String(r"C:\Program Files (x86)\Common Files".into()),
        )
        .key(hklm(r"SYSTEM\CurrentControlSet\Control"))
        .build()
        .unwrap();
    let skips = registry_system_contract(open.registry(), known.known_folders()).unwrap();
    assert_eq!(skips, ["security_denied"]);
}

#[test]
fn fixtures_fulfil_topology_contract() {
    for json in [RYZEN_5950X, I5_6600] {
        let sys = FakeSystem::builder().topology_json(json).build().unwrap();
        topology_contract(sys.topology()).unwrap();
    }
}

/// A topology source that hands out whatever it holds, unvalidated (the fake refuses that).
struct RawTopology(CpuTopology);

impl Topology for RawTopology {
    fn read(&self) -> SysResult<CpuTopology> {
        Ok(self.0.clone())
    }
}

#[test]
fn the_topology_contract_catches_raw_numbering() {
    // The pre-ADR-0010 fixture semantics: `core` and `llc` are the raw Windows CoreIndex and
    // LastLevelCacheIndex (first logical processor of the core or cache).
    let mut t: CpuTopology = serde_json::from_str(RYZEN_5950X).unwrap();
    for c in &mut t.cpus {
        c.core = u32::from(c.index & !1);
        c.llc = u32::from(c.index & !15);
    }
    let err = topology_contract(&RawTopology(t.clone())).unwrap_err();
    assert!(err.contains("dense core numbering"), "{err}");
    // The fake itself refuses it.
    assert!(FakeSystem::builder().topology(t).build().is_err());
}

/// Differs on every second read.
struct Flapping(std::sync::atomic::AtomicU32, CpuTopology);

impl Topology for Flapping {
    fn read(&self) -> SysResult<CpuTopology> {
        let mut t = self.1.clone();
        t.cpus[0].cpu_set_id += self.0.fetch_add(1, Ordering::Relaxed);
        Ok(t)
    }
}

#[test]
fn the_topology_contract_catches_an_unstable_topology() {
    let t = serde_json::from_str(I5_6600).unwrap();
    let err = topology_contract(&Flapping(0.into(), t)).unwrap_err();
    assert!(err.contains("stable across calls"), "{err}");
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
    known_folders_contract(sys.known_folders(), sys.fs()).unwrap();
}

#[test]
fn known_folders_contract_allows_roaming_on_a_share() {
    let sys = FakeSystem::builder()
        .known_folder(KnownFolder::RoamingAppData, r"\\server\home\player\Roaming")
        .windows_layout()
        .build()
        .unwrap();
    known_folders_contract(sys.known_folders(), sys.fs()).unwrap();
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
        assert!(
            known_folders_contract(sys.known_folders(), sys.fs()).is_err(),
            "{what}"
        );
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
    gpu_contract(sys.gpu()).unwrap();
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
        assert!(gpu_contract(sys.gpu()).is_err(), "{what}");
    }
    let nul = FakeSystem::builder()
        .gpu(adapter("A\0B", 1))
        .build()
        .unwrap();
    assert!(gpu_contract(nul.gpu()).is_err(), "control character");
    let bidi = FakeSystem::builder()
        .gpu(adapter("A\u{202E}B", 1))
        .build()
        .unwrap();
    assert!(gpu_contract(bidi.gpu()).is_err(), "bidi override");
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
fn directory_is_not_a_file() {
    let sys = FakeSystem::builder()
        .dir(r"C:\G\d")
        .file(r"C:\G\f", "x")
        .build()
        .unwrap();
    let g = open(&sys, r"C:\G");
    assert_eq!(kind(g.read(&r("d"))), SysErrorKind::AccessDenied);
    assert_eq!(kind(g.users(&r("d"))), SysErrorKind::AccessDenied);
    assert_eq!(kind(g.read_dir(Some(&r("f")))), SysErrorKind::InvalidPath);
    assert_eq!(kind(g.open_dir(&r("f"))), SysErrorKind::InvalidPath);
    // File as parent directory.
    assert_eq!(kind(g.read(&r(r"f\x"))), SysErrorKind::InvalidPath);
    assert_eq!(g.metadata(&r(r"f\x")).unwrap(), None);
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
    assert_eq!(kind(g.users(&r("alias.exe"))), SysErrorKind::ReparsePoint);
    assert_eq!(g.users(&r("compressed.dll")).unwrap(), Vec::<u32>::new());
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
    assert_eq!(kind(g.users(&r("d3d9.dll"))), SysErrorKind::ReparsePoint);
    assert_eq!(kind(g.open_dir(&r("d3d9.dll"))), SysErrorKind::ReparsePoint);
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
fn case_sensitive_dir_matches_exactly() {
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
    sys.fake_fs().remove_abs(&p(r"C:\G\d")).unwrap();
    assert_eq!(kind(d.info()), SysErrorKind::NotFound);
    assert_eq!(kind(d.open_dir(&r("x"))), SysErrorKind::NotFound);
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
    assert_eq!(kind(g.users(&r("Projected"))), rp);
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
    assert_eq!((m.links, m.attrs), (Some(2), ro));
    assert_eq!(
        kind(FakeSystem::builder().hardlink(r"C:\G\x", r"D:\y").build()),
        SysErrorKind::NotFound
    );
}

#[test]
fn share_model_records_handles_by_process_and_checks_fixture_moves() {
    let sys = FakeSystem::builder()
        .file(r"C:\G\sub\a.bin", "a")
        .hardlink(r"C:\G\sub\a.bin", r"C:\G\b.bin")
        .build()
        .unwrap();
    let fx = sys.fake_fs();
    let g = open(&sys, r"C:\G");
    let me = std::process::id();
    // Another process's hold and our own reader, also through the second hard link.
    let other = fx
        .hold_open_as(4242, &p(r"C:\G\sub\a.bin"), Access::READ, Share::RWD)
        .unwrap();
    let reader = g.open_read(&r(r"sub\a.bin")).unwrap();
    let mut expected = vec![me, 4242];
    expected.sort_unstable();
    assert_eq!(g.users(&r("b.bin")).unwrap(), expected);
    // The reader shares read only: an overwrite, a rename and a remove are `Busy`.
    assert_eq!(
        kind(fx.put_file(&p(r"C:\G\b.bin"), b"x")),
        SysErrorKind::Busy
    );
    assert_eq!(
        kind(fx.rename_abs(&p(r"C:\G\b.bin"), &p(r"C:\G\c.bin"))),
        SysErrorKind::Busy
    );
    assert_eq!(kind(fx.remove_abs(&p(r"C:\G\b.bin"))), SysErrorKind::Busy);
    // A handle below `sub`: renaming `sub` is refused, the fake-only rename is not.
    assert_eq!(
        kind(fx.rename_abs(&p(r"C:\G\sub"), &p(r"C:\G\sub2"))),
        SysErrorKind::AccessDenied
    );
    drop(reader);
    assert_eq!(g.users(&r("b.bin")).unwrap(), [4242]);
    fx.rename_ignoring_shares(&p(r"C:\G\sub"), &p(r"C:\G\sub2"))
        .unwrap();
    drop(other);
    assert!(g.users(&r("b.bin")).unwrap().is_empty());
    // A handle opened and dropped inside a hook (during another operation) is closed.
    fx.on_step(|fs, _| {
        let h = fs.open_dir(Path::new(r"C:\G\sub2")).unwrap();
        drop(h);
    });
    assert!(g.metadata(&r(r"sub2\a.bin")).unwrap().is_some());
    fx.clear_on_step();
    fx.rename_abs(&p(r"C:\G\sub2"), &p(r"C:\G\sub3")).unwrap();
}

#[test]
fn restricted_entries_are_described_but_never_opened() {
    let sys = FakeSystem::builder()
        .file(r"C:\G\secret.bin", "secret")
        .hardlink(r"C:\G\secret.bin", r"C:\G\alias.bin")
        .file(r"C:\G\locked\inner.txt", "inner")
        .junction(r"C:\G\jlink", r"C:\Elsewhere")
        .file(r"C:\G\plain.txt", "plain")
        .restricted(r"C:\G\secret.bin")
        .restricted(r"C:\G\locked")
        .restricted(r"C:\G\jlink")
        .build()
        .unwrap();
    let g = open(&sys, r"C:\G");
    let listed = g.read_dir(None).unwrap();
    assert_eq!(listed.len(), 5, "restricted entries are never dropped");
    for e in &listed {
        let expected = e.name != "plain.txt";
        assert_eq!(e.meta.restricted, expected, "{}", e.name);
        assert_eq!(e.meta.is_single_link(), !expected, "{}", e.name);
        assert_eq!(g.metadata(&r(&e.name)).unwrap().as_ref(), Some(&e.meta));
    }
    // The flag belongs to the file, so the second hard link is restricted too.
    let alias = g.metadata(&r("ALIAS.BIN")).unwrap().unwrap();
    assert!(alias.restricted && alias.links.is_none() && alias.len == 6);
    // A restricted link keeps its tag, not its target.
    let j = g.metadata(&r("jlink")).unwrap().unwrap();
    let rp = j.reparse.unwrap();
    assert_eq!(
        (j.kind, rp.tag, rp.target),
        (EntryKind::Reparse, tag::MOUNT_POINT, None)
    );

    let ad = SysErrorKind::AccessDenied;
    assert_eq!(
        g.open_read(&r("secret.bin")).err().map(|e| e.kind),
        Some(ad)
    );
    assert_eq!(kind(g.open_dir(&r("locked"))), ad);
    assert_eq!(kind(g.open_dir(&r("jlink"))), ad);
    assert_eq!(kind(g.read_dir(Some(&r("locked")))), ad);
    assert_eq!(kind(g.metadata(&r(r"locked\inner.txt"))), ad);
    assert_eq!(kind(sys.fs().open_dir(&p(r"C:\G\locked"))), ad);
    assert_eq!(kind(g.users(&r("secret.bin"))), ad);
    assert_eq!(g.read(&r("plain.txt")).unwrap(), b"plain");

    // Lifting the restriction restores normal access.
    sys.fake_fs()
        .set_restricted(&p(r"C:\G\secret.bin"), false)
        .unwrap();
    let m = g.metadata(&r("secret.bin")).unwrap().unwrap();
    assert!(!m.restricted && m.links == Some(2));
    assert_eq!(g.read(&r("alias.bin")).unwrap(), b"secret");
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
fn swap_of_an_already_opened_component_keeps_the_original() {
    let sys = toctou_system();
    // `sub` was resolved before the swap: the walk continues in the original node.
    let fired = swap_at(&sys, FsOp::OpenRead, 1, r"C:\G\sub");
    let g = open(&sys, r"C:\G");
    assert_eq!(g.read(&r(r"sub\deep\target.ini")).unwrap(), b"orig");
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
}

#[test]
fn swap_during_metadata_and_open_read_walks() {
    for op in [
        FsOp::Metadata,
        FsOp::OpenRead,
        FsOp::OpenDir,
        FsOp::ReadDir,
        FsOp::Users,
        FsOp::OpenDirWrite,
    ] {
        let sys = toctou_system();
        swap_at(&sys, op, 1, r"C:\G\sub\deep");
        let g = open(&sys, r"C:\G");
        let res = match op {
            FsOp::Metadata => g.metadata(&r(r"sub\deep\canary.txt")).map(|_| ()),
            FsOp::OpenRead => g.read(&r(r"sub\deep\canary.txt")).map(|_| ()),
            FsOp::OpenDir => g.open_dir(&r(r"sub\deep")).map(|_| ()),
            FsOp::Users => g.users(&r(r"sub\deep\canary.txt")).map(|_| ()),
            FsOp::OpenDirWrite => g.open_dir_write(&r(r"sub\deep")).map(|_| ()),
            _ => g.read_dir(Some(&r(r"sub\deep"))).map(|_| ()),
        };
        assert_eq!(kind(res), SysErrorKind::ReparsePoint, "{op:?}");
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
fn hkcu_is_shared_between_the_views() {
    let native = hkcu(r"Software\Game");
    let wow = RegKey::new(Hive::CurrentUser, RegView::Wow32, r"Software\Game");
    let sys = FakeSystem::builder()
        .value(native.clone(), "v", RegValue::Dword(1))
        .build()
        .unwrap();
    assert!(sys.registry().key_exists(&wow).unwrap());
    assert_eq!(
        sys.registry().get(&wow, "v").unwrap(),
        Some(RegValue::Dword(1))
    );
    sys.registry().set(&wow, "w", &RegValue::Dword(2)).unwrap();
    assert_eq!(
        sys.registry().get(&native, "w").unwrap(),
        Some(RegValue::Dword(2))
    );
}

#[test]
fn hklm_outside_software_is_shared_between_the_views() {
    let native = key(Hive::LocalMachine, RegView::Native, r"SYSTEM\Setup");
    let wow = key(Hive::LocalMachine, RegView::Wow32, r"SYSTEM\Setup");
    let sys = FakeSystem::builder()
        .value(native.clone(), "v", RegValue::Dword(1))
        .build()
        .unwrap();
    assert_eq!(
        sys.registry().get(&wow, "v").unwrap(),
        Some(RegValue::Dword(1))
    );
    // Names that merely start like SOFTWARE are not redirected.
    let near = key(Hive::LocalMachine, RegView::Native, r"SOFTWAREX\Y");
    let near_wow = key(Hive::LocalMachine, RegView::Wow32, r"SOFTWAREX\Y");
    sys.registry().create_key(&near.parent().unwrap()).unwrap();
    sys.registry().create_key(&near).unwrap();
    assert!(sys.registry().key_exists(&near_wow).unwrap());
}

#[test]
fn hklm_software_is_redirected_in_the_32_bit_view() {
    let native = |p: &str| key(Hive::LocalMachine, RegView::Native, p);
    let wow = |p: &str| key(Hive::LocalMachine, RegView::Wow32, p);
    let sys = FakeSystem::builder()
        .value(
            native(r"SOFTWARE\Valve\Steam"),
            "Native",
            RegValue::Dword(64),
        )
        .value(
            native(r"SOFTWARE\WOW6432Node\Valve\Steam"),
            "Wow",
            RegValue::Dword(32),
        )
        .build()
        .unwrap();
    let reg = sys.registry();

    // The 32-bit view of SOFTWARE\X is SOFTWARE\WOW6432Node\X, not SOFTWARE\X.
    let steam = wow(r"SOFTWARE\Valve\Steam");
    assert_eq!(reg.get(&steam, "Wow").unwrap(), Some(RegValue::Dword(32)));
    assert_eq!(reg.get(&steam, "Native").unwrap(), None);
    assert_eq!(
        reg.get(&native(r"SOFTWARE\Valve\Steam"), "Wow").unwrap(),
        None
    );
    // Case-insensitive, including the redirected prefix.
    assert!(reg.key_exists(&wow(r"software\VALVE")).unwrap());
    // SOFTWARE itself is one key.
    assert!(reg.key_exists(&wow("SOFTWARE")).unwrap());
    reg.set(&wow("SOFTWARE"), "Shared", &RegValue::Dword(1))
        .unwrap();
    assert_eq!(
        reg.get(&native("SOFTWARE"), "Shared").unwrap(),
        Some(RegValue::Dword(1))
    );
    // An explicit WOW6432Node is not redirected a second time.
    assert_eq!(
        reg.get(&wow(r"SOFTWARE\WOW6432Node\Valve\Steam"), "Wow")
            .unwrap(),
        Some(RegValue::Dword(32))
    );
    assert_eq!(
        reg.get(&native(r"SOFTWARE\WOW6432Node\Valve\Steam"), "Wow")
            .unwrap(),
        Some(RegValue::Dword(32))
    );

    // Subkeys come back with their own case.
    assert_eq!(reg.subkeys(&wow(r"SOFTWARE\Valve")).unwrap(), ["Steam"]);

    // Writing through the 32-bit view lands in WOW6432Node and creates it if needed.
    let fresh = FakeSystem::builder()
        .key(native("SOFTWARE"))
        .build()
        .unwrap();
    let k = wow(r"SOFTWARE\Game\Sub");
    assert!(fresh.registry().create_key(&k.parent().unwrap()).unwrap());
    assert!(fresh.registry().create_key(&k).unwrap());
    fresh.registry().set(&k, "v", &RegValue::Dword(7)).unwrap();
    let physical = native(r"SOFTWARE\WOW6432Node\Game\Sub");
    assert_eq!(
        fresh.registry().get(&physical, "v").unwrap(),
        Some(RegValue::Dword(7))
    );
    assert_eq!(
        fresh.registry().subkeys(&native("SOFTWARE")).unwrap(),
        ["WOW6432Node"]
    );
    // The parent has to exist.
    assert_eq!(
        fresh
            .registry()
            .create_key(&wow(r"SOFTWARE\No\Parent"))
            .unwrap_err()
            .kind,
        SysErrorKind::NotFound
    );
    // Deleting goes to the same place.
    fresh.registry().delete_value(&k, "v").unwrap();
    fresh.registry().delete_key(&k).unwrap();
    assert!(!fresh.registry().key_exists(&physical).unwrap());
}

#[test]
fn a_denied_key_refuses_everything_below_it() {
    let hklm = |p: &str| key(Hive::LocalMachine, RegView::Native, p);
    let sys = FakeSystem::builder()
        .value(hklm(r"SECURITY\Policy"), "v", RegValue::Dword(1))
        .denied_key(hklm("SECURITY"))
        .key(hklm("SECURITYX"))
        .build()
        .unwrap();
    let reg = sys.registry();
    for k in [hklm("SECURITY"), hklm(r"security\Policy")] {
        assert_eq!(
            reg.key_exists(&k).unwrap_err().kind,
            SysErrorKind::AccessDenied
        );
        assert_eq!(
            reg.get(&k, "v").unwrap_err().kind,
            SysErrorKind::AccessDenied
        );
        assert_eq!(reg.values(&k).unwrap_err().kind, SysErrorKind::AccessDenied);
        assert_eq!(
            reg.subkeys(&k).unwrap_err().kind,
            SysErrorKind::AccessDenied
        );
        assert_eq!(
            reg.create_key(&k).unwrap_err().kind,
            SysErrorKind::AccessDenied
        );
        assert_eq!(
            reg.set(&k, "v", &RegValue::Dword(2)).unwrap_err().kind,
            SysErrorKind::AccessDenied
        );
        assert_eq!(
            reg.delete_key(&k).unwrap_err().kind,
            SysErrorKind::AccessDenied
        );
    }
    // A sibling with the same prefix is not denied.
    assert!(reg.key_exists(&hklm("SECURITYX")).unwrap());
}

#[test]
fn registry_fixture_stores_exactly_what_it_is_told() {
    use crate::sys::contract::RegFixture;
    let root = hkcu(r"Software\Fx");
    let sys = FakeSystem::builder().key(root.clone()).build().unwrap();
    let fx = sys.fake_registry();
    fx.raw(&root, "n", reg_type::REG_NONE, &[9]).unwrap();
    fx.raw(&root, "d", reg_type::REG_DWORD, &[1, 0, 0, 0])
        .unwrap();
    assert_eq!(
        sys.registry().get(&root, "n").unwrap().unwrap().encode(),
        Some((0, vec![9]))
    );
    assert_eq!(
        sys.registry().get(&root, "d").unwrap(),
        Some(RegValue::Dword(1))
    );
    RegFixture::delete_value(fx, &root, "n").unwrap();
    assert_eq!(sys.registry().get(&root, "n").unwrap(), None);
    assert!(!fx.link(&root.join("l"), &root).unwrap());
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

#[test]
fn registry_input_rules_apply_to_every_method() {
    let sys = FakeSystem::builder().key(hkcu("Software")).build().unwrap();
    let reg = sys.registry();
    let key = |p: &str| RegKey {
        hive: Hive::CurrentUser,
        view: RegView::Native,
        path: p.into(),
    };
    let seg = "a".repeat(256);
    let bad_keys = [
        key("A\0B"),
        key(&format!("Software\\{seg}")),
        key(&vec!["a".repeat(255); 129].join("\\")),
        key("Software\\"),
    ];
    for k in &bad_keys {
        let v = RegValue::Dword(1);
        let kinds = [
            reg.key_exists(k).map(drop),
            reg.get(k, "x").map(drop),
            reg.values(k).map(drop),
            reg.subkeys(k).map(drop),
            reg.create_key(k).map(drop),
            reg.set(k, "x", &v),
            reg.delete_value(k, "x"),
            reg.delete_key(k),
        ];
        for r in kinds {
            assert_eq!(
                r.unwrap_err().kind,
                SysErrorKind::InvalidPath,
                "{}",
                k.path.len()
            );
        }
    }
    let k = hkcu("Software");
    let long_name = "n".repeat(16_384);
    for name in ["a\0b", long_name.as_str()] {
        assert_eq!(
            reg.get(&k, name).unwrap_err().kind,
            SysErrorKind::InvalidPath
        );
        assert_eq!(
            reg.set(&k, name, &RegValue::Dword(1)).unwrap_err().kind,
            SysErrorKind::InvalidPath
        );
        assert_eq!(
            reg.delete_value(&k, name).unwrap_err().kind,
            SysErrorKind::InvalidPath
        );
    }
    // Exactly at the limits works.
    let ok_name = "n".repeat(16_383);
    reg.set(&k, &ok_name, &RegValue::Dword(1)).unwrap();
    assert_eq!(reg.get(&k, &ok_name).unwrap(), Some(RegValue::Dword(1)));
    reg.create_key(&k.join(&"a".repeat(255))).unwrap();
}

#[test]
fn a_typed_value_without_canonical_encoding_is_refused() {
    let sys = FakeSystem::builder().key(hkcu("Software")).build().unwrap();
    let k = hkcu("Software");
    for v in [
        RegValue::String("a\0b".into()),
        RegValue::MultiString(vec![String::new()]),
    ] {
        assert_eq!(
            sys.registry().set(&k, "v", &v).unwrap_err().kind,
            SysErrorKind::Unsupported
        );
    }
    assert!(sys.registry().get(&k, "v").unwrap().is_none());
}

#[test]
fn raw_values_are_kept_exactly_and_snapshotted() {
    let key = hkcu(r"Software\Raw");
    let sys = FakeSystem::builder()
        .raw_value(key.clone(), "none", 0, &[1, 2, 3])
        .raw_value(key.clone(), "bigendian", 5, &[0, 0, 0, 1])
        .raw_value(key.clone(), "odd_sz", 1, &[b'a', 0, 0])
        .raw_value(key.clone(), "canonical", 4, &[1, 0, 0, 0])
        .build()
        .unwrap();
    let reg = sys.registry();
    let get = |n: &str| reg.get(&key, n).unwrap().unwrap().encode().unwrap();
    assert_eq!(get("none"), (0, vec![1, 2, 3]));
    assert_eq!(get("bigendian"), (5, vec![0, 0, 0, 1]));
    assert_eq!(get("odd_sz"), (1, vec![b'a', 0, 0]));
    assert_eq!(
        reg.get(&key, "canonical").unwrap(),
        Some(RegValue::Dword(1))
    );
    assert!(matches!(
        reg.get(&key, "NONE").unwrap(),
        Some(RegValue::Raw(_))
    ));

    // A snapshot tells two raw values apart, so a revert can restore the exact bytes.
    let scope = Scope {
        dirs: vec![],
        keys: vec![key.clone()],
    };
    let before = snapshot(sys.registry(), &scope).unwrap();
    reg.set(&key, "none", &RegValue::decode(0, &[1, 2, 4]))
        .unwrap();
    assert_eq!(
        before
            .diff(&snapshot(sys.registry(), &scope).unwrap())
            .len(),
        1
    );
    reg.set(&key, "none", &RegValue::decode(0, &[1, 2, 3]))
        .unwrap();
    assert_eq!(before, snapshot(sys.registry(), &scope).unwrap());
    // Same bytes under another type number differ as well.
    reg.set(&key, "none", &RegValue::decode(8, &[1, 2, 3]))
        .unwrap();
    assert_eq!(
        before
            .diff(&snapshot(sys.registry(), &scope).unwrap())
            .len(),
        1
    );
}

/// `r` is `TooLarge` with the bound `limit` (registry read limits, ADR 0009).
fn assert_too_large<T: std::fmt::Debug>(r: SysResult<T>, limit: u64) {
    let e = r.unwrap_err();
    assert_eq!(
        (e.kind, e.limit),
        (SysErrorKind::TooLarge, Some(limit)),
        "{e}"
    );
}

#[test]
fn reads_refuse_hostile_amounts_of_data() {
    let key = hkcu(r"Software\Big");
    let mib = || vec![7_u8; 1 << 20];

    // One value: 1 MiB is fine, one byte more is not (get and values).
    let sys = FakeSystem::builder()
        .raw_value(key.clone(), "ok", 3, &mib())
        .build()
        .unwrap();
    assert!(sys.registry().get(&key, "ok").unwrap().is_some());
    assert_eq!(sys.registry().values(&key).unwrap().len(), 1);
    let mut over = mib();
    over.push(0);
    sys.registry()
        .set(&key, "over", &RegValue::decode(3, &over))
        .unwrap();
    assert_too_large(sys.registry().get(&key, "over"), 1 << 20);
    assert_too_large(sys.registry().values(&key), 1 << 20);
    // Other values stay readable one by one.
    assert!(sys.registry().get(&key, "ok").unwrap().is_some());

    // Total (names as UTF-16 plus data): exactly 16 MiB is fine, one byte more is not.
    let mut b = FakeSystem::builder();
    let mut used = 0;
    for i in 0..16 {
        let name = format!("v{i}");
        let len = if i < 15 {
            mib().len()
        } else {
            (16 << 20) - used - 2 * name.len()
        };
        used += 2 * name.len() + len;
        b = b.raw_value(key.clone(), &name, 3, &vec![7; len]);
    }
    let sys = b.build().unwrap();
    assert_eq!(sys.registry().values(&key).unwrap().len(), 16);
    sys.registry()
        .set(&key, "v16", &RegValue::decode(3, &[0]))
        .unwrap();
    assert_too_large(sys.registry().values(&key), 16 << 20);

    // Count: 16,384 values are fine, one more is not.
    let mut b = FakeSystem::builder();
    for i in 0..16_384 {
        b = b.value(key.clone(), &format!("v{i}"), RegValue::Dword(1));
    }
    let sys = b.build().unwrap();
    assert_eq!(sys.registry().values(&key).unwrap().len(), 16_384);
    sys.registry()
        .set(&key, "one more", &RegValue::Dword(1))
        .unwrap();
    assert_too_large(sys.registry().values(&key), 16_384);

    // Subkeys: 65,536 are fine, one more is not.
    let sys = FakeSystem::builder().key(key.clone()).build().unwrap();
    for i in 0..65_536 {
        sys.registry()
            .create_key(&key.join(&format!("k{i}")))
            .unwrap();
    }
    assert_eq!(sys.registry().subkeys(&key).unwrap().len(), 65_536);
    sys.registry().create_key(&key.join("one more")).unwrap();
    assert_too_large(sys.registry().subkeys(&key), 65_536);
}

// ---------- Snapshot ----------

/// Snapshot of the directories `dirs` (opened by absolute path, as test code may) and `keys`.
fn snap_of(sys: &FakeSystem, dirs: &[&str], keys: &[RegKey]) -> SysResult<Snapshot> {
    let handles = dirs
        .iter()
        .map(|d| sys.fs().open_dir(Path::new(d)))
        .collect::<SysResult<Vec<_>>>()?;
    let scope = Scope {
        dirs: handles
            .iter()
            .zip(dirs)
            .map(|(h, d)| SnapRoot::new(&**h, *d))
            .collect(),
        keys: keys.to_vec(),
    };
    snapshot(sys.registry(), &scope)
}

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

fn game_snap(sys: &FakeSystem) -> Snapshot {
    snap_of(sys, &[r"C:\Games\AC"], &[hkcu(r"Software\Ubisoft\AC")]).unwrap()
}

#[test]
fn snapshot_is_identical_after_create_and_remove() {
    let sys = game_system();
    let before = game_snap(&sys);
    assert!(!before.is_empty());

    let fs = sys.fake_fs();
    let reg = sys.registry();
    fs.put_file(&p(r"C:\Games\AC\scripts\EaglePatchAC1.asi"), b"asi")
        .unwrap();
    fs.put_file(&p(r"C:\Games\AC\dinput8.dll"), b"dll").unwrap();
    let key = hkcu(r"Software\Ubisoft\AC\Rerun");
    reg.create_key(&key).unwrap();
    reg.set(&key, "x", &RegValue::Dword(1)).unwrap();

    let during = game_snap(&sys);
    assert_eq!(before.diff(&during).len(), 5, "{:#?}", before.diff(&during));

    reg.delete_value(&key, "x").unwrap();
    reg.delete_key(&key).unwrap();
    fs.remove_abs(&p(r"C:\Games\AC\dinput8.dll")).unwrap();
    fs.remove_abs(&p(r"C:\Games\AC\scripts\EaglePatchAC1.asi"))
        .unwrap();
    fs.remove_abs(&p(r"C:\Games\AC\scripts")).unwrap();

    let after = game_snap(&sys);
    assert_eq!(before, after, "{:#?}", before.diff(&after));
}

#[test]
fn snapshot_is_identical_after_replace_and_restore() {
    let sys = game_system();
    let before = game_snap(&sys);
    let exe = p(r"C:\Games\AC\AssassinsCreed_Dx9.exe");
    sys.fake_fs().put_file(&exe, b"patched").unwrap();
    assert_eq!(before.diff(&game_snap(&sys)).len(), 1);
    sys.fake_fs().put_file(&exe, b"MZ-dx9").unwrap();
    let after = game_snap(&sys);
    assert_eq!(before, after, "{:#?}", before.diff(&after));
}

/// Every mutation must produce exactly one difference.
#[test]
fn snapshot_detects_every_kind_of_change() {
    type Mutation = fn(&FakeSystem);
    let cases: [(&str, Mutation); 14] = [
        ("content", |s| {
            s.fake_fs()
                .put_file(&p(r"C:\Games\AC\Data\a.forge"), b"FORGE")
                .unwrap();
        }),
        ("length", |s| {
            s.fake_fs()
                .put_file(&p(r"C:\Games\AC\Data\a.forge"), b"forge!")
                .unwrap();
        }),
        ("hidden directory", |s| {
            let hidden = Attrs {
                hidden: true,
                ..Attrs::default()
            };
            s.fake_fs()
                .set_attrs(&p(r"C:\Games\AC\Data"), hidden)
                .unwrap();
        }),
        ("system reparse point", |s| {
            let system = Attrs {
                system: true,
                ..Attrs::default()
            };
            s.fake_fs()
                .set_attrs(&p(r"C:\Games\AC\Saves"), system)
                .unwrap();
        }),
        ("readonly", |s| {
            let ro = Attrs {
                readonly: true,
                ..Attrs::default()
            };
            s.fake_fs()
                .set_attrs(&p(r"C:\Games\AC\Data\a.forge"), ro)
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
            s.rename_abs(r"C:\Games\AC\Data\a.forge", r"C:\Games\AC\Data\A.forge")
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
            s.fake_fs().mkdir_all(&p(r"C:\Games\AC\scripts")).unwrap();
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
        ("restricted", |s| {
            s.fake_fs()
                .set_restricted(&p(r"C:\Games\AC\Data\a.forge"), true)
                .unwrap();
        }),
    ];
    for (name, mutate) in cases {
        let sys = game_system();
        let before = game_snap(&sys);
        mutate(&sys);
        let after = game_snap(&sys);
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
    // Any open of an anomaly name would hit this hook.
    sys.fake_fs().on_step(|_: &FakeFs, ev: &StepEvent| {
        assert!(
            crate::path::classify(&ev.name, false).is_ok(),
            "opened anomaly {ev:?}"
        );
    });
    let snap = snap_of(&sys, &[r"C:\G"], &[]);
    sys.fake_fs().clear_on_step();
    let snap = snap.unwrap();
    // d3d9.dll, d3d9.dll., CON, cs, cs\a, cs\A.
    assert_eq!(snap.len(), 6);
    assert!(
        snapshot(sys.registry(), &Scope::default())
            .unwrap()
            .is_empty()
    );
    let lines = snap.diff(&Snapshot::default());
    assert_eq!(
        lines.iter().filter(|l| l.contains("anomaly")).count(),
        4,
        "{lines:#?}"
    );
}

#[test]
fn snapshot_records_restricted_entries_without_opening_them() {
    let build = || {
        FakeSystem::builder()
            .file(r"C:\G\secret.bin", "secret")
            .file(r"C:\G\locked\inner.txt", "inner")
            .file(r"C:\G\plain.txt", "plain")
            .restricted(r"C:\G\secret.bin")
            .restricted(r"C:\G\locked")
            .build()
            .unwrap()
    };
    let sys = build();
    // Any open of a restricted entry (data, descent) would hit this hook.
    sys.fake_fs().on_step(|_: &FakeFs, ev: &StepEvent| {
        assert!(
            ev.name != "secret.bin" && ev.name != "locked",
            "opened a restricted entry {ev:?}"
        );
    });
    let snap = snap_of(&sys, &[r"C:\G"], &[]);
    sys.fake_fs().clear_on_step();
    let snap = snap.unwrap();
    // secret.bin, locked (not descended into), plain.txt.
    assert_eq!(snap.len(), 3);
    let lines = snap.diff(&Snapshot::default());
    assert!(
        lines
            .iter()
            .any(|l| l.contains("restricted \"secret.bin\" File 6 bytes")),
        "{lines:#?}"
    );
    assert!(
        lines
            .iter()
            .any(|l| l.contains("restricted \"locked\" Dir")),
        "{lines:#?}"
    );
    assert!(!lines.iter().any(|l| l.contains("inner.txt")), "{lines:#?}");

    // Identity: the same state is identical; attributes and the flag itself count.
    let again = build();
    assert_eq!(snap_of(&again, &[r"C:\G"], &[]).unwrap(), snap);
    let hidden = Attrs {
        hidden: true,
        ..Attrs::default()
    };
    again
        .fake_fs()
        .set_attrs(&p(r"C:\G\secret.bin"), hidden)
        .unwrap();
    assert_eq!(
        snap.diff(&snap_of(&again, &[r"C:\G"], &[]).unwrap()).len(),
        1
    );
    let lifted = build();
    lifted
        .fake_fs()
        .set_restricted(&p(r"C:\G\secret.bin"), false)
        .unwrap();
    assert_eq!(
        snap.diff(&snap_of(&lifted, &[r"C:\G"], &[]).unwrap()).len(),
        1
    );
}

#[test]
fn snapshot_does_not_hash_cloud_placeholders() {
    let sys = FakeSystem::builder()
        .tagged_file(r"C:\G\cloud.pak", "remote", tag::CLOUD)
        .tagged_file(r"C:\G\wof.dll", "local", tag::WOF)
        .build()
        .unwrap();
    sys.fake_fs().on_step(|_: &FakeFs, ev: &StepEvent| {
        assert!(
            !(ev.op == FsOp::OpenRead && ev.name == "cloud.pak"),
            "cloud placeholder opened"
        );
    });
    let snap = snap_of(&sys, &[r"C:\G"], &[]);
    sys.fake_fs().clear_on_step();
    let lines = snap.unwrap().diff(&Snapshot::default());
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
    use crate::sys::snapshot::MAX_DEPTH;
    let nested = |levels: usize| {
        let deep: String = (0..levels).map(|i| format!(r"\d{i}")).collect();
        FakeSystem::builder()
            .dir(format!(r"C:\G{deep}"))
            .build()
            .unwrap()
    };
    // Exactly 64 levels of directories below the root are walked (with a file in the
    // deepest one), 65 are refused with the limit.
    let deep: String = (0..MAX_DEPTH).map(|i| format!(r"\d{i}")).collect();
    let sys = FakeSystem::builder()
        .file(format!(r"C:\G{deep}\leaf.bin"), "x")
        .build()
        .unwrap();
    assert_eq!(snap_of(&sys, &[r"C:\G"], &[]).unwrap().len(), MAX_DEPTH + 1);
    let e = snap_of(&nested(MAX_DEPTH + 1), &[r"C:\G"], &[]).unwrap_err();
    assert_eq!((e.kind, e.limit), (SysErrorKind::TooLarge, Some(64)), "{e}");
}

/// The data tag of a file (WOF, dedup, cloud) is shown, never compared (user decision E3):
/// compressing a file changes nothing, a cloud placeholder differs by its missing hash.
#[test]
fn snapshot_shows_data_tags_without_comparing_them() {
    let sys = game_system();
    let before = game_snap(&sys);
    let forge = p(r"C:\Games\AC\Data\a.forge");
    sys.fake_fs()
        .put_tagged_file(&forge, b"forge", tag::WOF)
        .unwrap();
    let after = game_snap(&sys);
    assert_eq!(before, after, "{:#?}", before.diff(&after));
    let shown = after.diff(&Snapshot::default());
    assert!(
        shown
            .iter()
            .any(|l| l.contains("a.forge") && l.contains("tag 0x80000017")),
        "{shown:#?}"
    );
    sys.fake_fs()
        .put_tagged_file(&forge, b"forge", tag::DEDUP)
        .unwrap();
    assert_eq!(before, game_snap(&sys));
    // A placeholder of the same content is not hashed: one difference.
    sys.fake_fs()
        .put_tagged_file(&forge, b"forge", tag::CLOUD)
        .unwrap();
    let cloud = before.diff(&game_snap(&sys));
    assert!(
        cloud.len() == 1 && cloud[0].contains("not hashed"),
        "{cloud:#?}"
    );
}

/// A delete-pending entry is skipped like every listing skips it (user decision E2): the
/// snapshot equals one taken before the file existed, and taking it does not fail.
#[test]
fn snapshot_skips_delete_pending_entries() {
    let sys = game_system();
    let before = game_snap(&sys);
    let doomed = p(r"C:\Games\AC\Data\doomed.bin");
    sys.fake_fs().put_file(&doomed, b"going").unwrap();
    let hold = sys.fake_fs().delete_pending(&doomed).unwrap();
    let during = game_snap(&sys);
    assert_eq!(before, during, "{:#?}", before.diff(&during));
    drop(hold);
    assert_eq!(before, game_snap(&sys));
}

/// Two names that differ only in an unpaired surrogate list alike: both are anomalies under
/// one location, kept as a multiset (neither overwrites the other), in any listing order.
#[test]
fn snapshot_keeps_anomalies_with_the_same_raw_name_apart() {
    let sys = game_system();
    let data = p(r"C:\Games\AC\Data");
    let (high, low) = ([0x61, 0xD800], [0x61, 0xDC00]);
    sys.fake_fs().put_utf16_file(&data, &high, b"1").unwrap();
    sys.fake_fs().put_utf16_file(&data, &low, b"22").unwrap();
    let before = game_snap(&sys);
    let lines = before.diff(&Snapshot::default());
    assert_eq!(
        lines
            .iter()
            .filter(|l| l.contains("anomaly \"a\u{FFFD}\""))
            .count(),
        2,
        "{lines:#?}"
    );
    assert_eq!(before, game_snap(&sys));
    // A change to one of them is exactly one difference at that location.
    sys.fake_fs().put_utf16_file(&data, &low, b"333").unwrap();
    let diff = before.diff(&game_snap(&sys));
    assert!(
        diff.len() == 1 && diff[0].starts_with('~') && diff[0].contains("3 bytes"),
        "{diff:#?}"
    );
    sys.fake_fs().put_utf16_file(&data, &low, b"22").unwrap();
    assert_eq!(before, game_snap(&sys));
    // A third one with the same raw name is one more entry, not a change.
    sys.fake_fs()
        .put_utf16_file(&data, &[0x61, 0xDFFF], b"1")
        .unwrap();
    let diff = before.diff(&game_snap(&sys));
    assert!(diff.len() == 1 && diff[0].starts_with('+'), "{diff:#?}");
}

/// A missing key of the scope and a missing subtree of a root are recorded as missing.
#[test]
fn snapshot_records_missing_keys_and_subtrees() {
    let sys = FakeSystem::builder()
        .dir(r"C:\Base")
        .key(hkcu("Software"))
        .build()
        .unwrap();
    let base = sys.fs().open_dir(Path::new(r"C:\Base")).unwrap();
    let take = || {
        let scope = Scope {
            dirs: vec![SnapRoot::new(&*base, r"C:\Base").below(r("Nope"))],
            keys: vec![hkcu(r"Software\Nope")],
        };
        snapshot(sys.registry(), &scope).unwrap()
    };
    let before = take();
    assert_eq!(before.len(), 2);
    sys.fake_fs().mkdir_all(&p(r"C:\Base\Nope")).unwrap();
    sys.registry().create_key(&hkcu(r"Software\Nope")).unwrap();
    let diff = before.diff(&take());
    assert_eq!(diff.len(), 2, "{diff:#?}");
    assert!(diff.iter().all(|l| l.starts_with('~')), "{diff:#?}");
}

/// `below` captures the entry itself like an entry of its parent's listing: a directory and
/// the tree below it, a file hashed, a reparse point recorded and not followed; a file on the
/// way is missing, a reparse point on the way is refused.
#[test]
fn snapshot_below_captures_the_entry_and_its_tree() {
    let sys = FakeSystem::builder()
        .file(r"C:\G\Data\Sub\x.bin", "x")
        .file(r"C:\G\Data\file.bin", "f")
        .file(r"C:\G\outside.bin", "o")
        .junction(r"C:\G\Link", r"C:\Elsewhere")
        .file(r"C:\Elsewhere\secret.bin", "s")
        .build()
        .unwrap();
    let g = sys.fs().open_dir(Path::new(r"C:\G")).unwrap();
    let take = |sub: &str| {
        let scope = Scope {
            dirs: vec![SnapRoot::new(&*g, r"C:\G").below(r(sub))],
            keys: vec![],
        };
        snapshot(sys.registry(), &scope)
    };
    // The entries only, without the line of the root itself.
    let lines = |sub: &str| -> Vec<String> {
        let all = take(sub).unwrap().diff(&Snapshot::default());
        all.into_iter()
            .filter(|l| !l.starts_with("- root "))
            .collect()
    };

    let data = lines(r"DATA\sub");
    assert_eq!(data.len(), 2, "{data:#?}");
    assert!(data.iter().any(|l| l.contains("dir \"Sub\"")), "{data:#?}");
    assert!(data.iter().any(|l| l.contains("x.bin")), "{data:#?}");
    assert!(!data.iter().any(|l| l.contains("outside")), "{data:#?}");

    let file = lines(r"Data\file.bin");
    assert!(
        file.len() == 1 && file[0].contains("file \"file.bin\" 1 bytes sha256"),
        "{file:#?}"
    );
    let link = lines("Link");
    assert!(
        link.len() == 1 && link[0].contains("reparse \"Link\""),
        "{link:#?}"
    );
    for missing in [r"Data\file.bin\x", "nope", r"nope\x"] {
        let m = lines(missing);
        assert!(
            m.len() == 1 && m[0].contains("<missing>"),
            "{missing}: {m:#?}"
        );
    }
    assert_eq!(kind(take(r"Link\secret.bin")), SysErrorKind::ReparsePoint);

    // The subtree is part of the root's identity.
    let whole = snap_of(&sys, &[r"C:\G"], &[]).unwrap();
    let below = take("Data").unwrap();
    let diff = whole.diff(&below);
    assert!(diff.iter().any(|l| l.starts_with("~ root 0")), "{diff:#?}");
}

/// Two snapshots of different roots differ even with identical content; the label is never
/// compared.
#[test]
fn snapshot_roots_are_compared_by_identity_not_by_label() {
    let sys = FakeSystem::builder()
        .file(r"C:\A\x.bin", "same")
        .file(r"C:\B\x.bin", "same")
        .build()
        .unwrap();
    let a = sys.fs().open_dir(Path::new(r"C:\A")).unwrap();
    let b = sys.fs().open_dir(Path::new(r"C:\B")).unwrap();
    let take = |dir: &dyn crate::sys::Dir, label: &str| {
        let scope = Scope {
            dirs: vec![SnapRoot::new(dir, label)],
            keys: vec![],
        };
        snapshot(sys.registry(), &scope).unwrap()
    };
    assert_eq!(take(&*a, "one label"), take(&*a, "another label"));
    let (sa, sb) = (take(&*a, "A"), take(&*b, "A"));
    assert_ne!(sa, sb);
    assert_eq!(sa.diff(&sb).len(), 1, "{:#?}", sa.diff(&sb));
    // A different number of roots differs too, also without entries.
    let none = snapshot(sys.registry(), &Scope::default()).unwrap();
    assert_ne!(none, sa);
    assert!(
        none.diff(&sa).iter().any(|l| l.starts_with("+ root 0 (A)")),
        "{:#?}",
        none.diff(&sa)
    );
}

#[test]
fn diff_is_readable() {
    let sys = game_system();
    let before = game_snap(&sys);
    let fs = sys.fake_fs();
    fs.put_file(&p(r"C:\Games\AC\dinput8.dll"), b"dll").unwrap();
    fs.remove_abs(&p(r"C:\Games\AC\Data\a.forge")).unwrap();
    let diff = before.diff(&game_snap(&sys));
    assert_eq!(diff.len(), 2);
    assert!(
        diff.iter()
            .any(|l| l.starts_with(r"- C:\Games\AC\") && l.contains("a.forge")),
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
    // 2 L3 × 8 cores × 2 threads, dense, all in group 0.
    for c in &t.cpus {
        assert_eq!(
            (c.group, c.core, c.llc),
            (0, u32::from(c.index / 2), u32::from(c.index / 16))
        );
    }
    assert!(t.llcs.iter().all(|l| l.level == 3 && l.size == 32 << 20));
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
fn old_shape_fixtures_are_rejected() {
    // `numa` and `llc_sizes` are gone, `cpu_set_id` is required (ADR 0010).
    let old = r#"{"cpus": [{"group": 0, "index": 0, "core": 0, "efficiency_class": 0,
        "llc": 0, "numa": 0}], "llc_sizes": {"0": 6291456}}"#;
    let err = FakeSystem::builder()
        .topology_json(old)
        .build()
        .unwrap_err();
    assert!(err.target.contains("cpu fixture"), "{err}");
}

#[test]
fn invalid_topologies_are_rejected_by_the_builder() {
    let empty = r#"{"cpus": [], "llcs": []}"#;
    let err = FakeSystem::builder()
        .topology_json(empty)
        .build()
        .unwrap_err();
    assert!(err.target.contains("non-empty"), "{err}");
    let mut t: CpuTopology = serde_json::from_str(RYZEN_5950X).unwrap();
    t.llcs.pop();
    let err = FakeSystem::builder().topology(t).build().unwrap_err();
    assert!(err.target.contains("one llcs entry per llc"), "{err}");
}

#[test]
fn a_fake_without_topology_fails_to_read() {
    let err = FakeSystem::new().topology().read().unwrap_err();
    assert_eq!(err.kind, SysErrorKind::Unsupported);
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
    // Below a root a mounted volume is a mount point: a name surrogate, never traversed.
    let mounts = open(&sys, r"D:\Mounts");
    assert_eq!(
        kind(mounts.open_dir(&r("data"))),
        SysErrorKind::ReparsePoint,
        "no relative open into a mounted volume"
    );
    let m = mounts.metadata(&r("data")).unwrap().unwrap();
    assert_eq!(m.kind, EntryKind::Reparse);
    assert_eq!(m.reparse.unwrap().tag, tag::MOUNT_POINT);
    assert_eq!(
        kind(mounts.read(&r(r"data\Games\x"))),
        SysErrorKind::ReparsePoint
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

/// The total limit of `values` counts the names (UTF-16 bytes) as well as the data: 16 values
/// with names of 16,383 units fill exactly 16 MiB; one byte more is refused although the data
/// alone stays far below the limit.
#[test]
fn the_values_total_counts_long_names() {
    use crate::sys::contract::RegFixture as _;
    use crate::sys::registry::{MAX_VALUE_NAME_UTF16, MAX_VALUES_TOTAL_BYTES};
    let root = hkcu(r"Software\Names");
    let sys = FakeSystem::builder().key(root.clone()).build().unwrap();
    let fx = sys.fake_registry();
    let parts = 16;
    let name = |i: usize| format!("{i:02}{}", "n".repeat(MAX_VALUE_NAME_UTF16 - 2));
    let data = MAX_VALUES_TOTAL_BYTES / parts - 2 * MAX_VALUE_NAME_UTF16;
    for i in 0..parts {
        fx.raw(&root, &name(i), reg_type::REG_BINARY, &vec![1; data])
            .unwrap();
    }
    assert_eq!(sys.registry().values(&root).unwrap().len(), parts);
    fx.raw(&root, &name(0), reg_type::REG_BINARY, &vec![1; data + 1])
        .unwrap();
    assert!(
        parts * (data + 1) < MAX_VALUES_TOTAL_BYTES,
        "data alone is below"
    );
    assert_too_large(sys.registry().values(&root), 16 << 20);
}

// ---------- Write side ----------

/// The primitive calls of a sequence, in order, as the step hook sees them.
fn record_calls(sys: &FakeSystem) -> Arc<Mutex<Vec<Prim>>> {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::clone(&calls);
    sys.fake_fs().on_step(move |_, e| {
        if let Some(c) = e.call {
            assert_eq!(e.op, FsOp::Write);
            seen.lock().unwrap().push(c);
        }
    });
    calls
}

#[test]
fn create_new_runs_the_sequence_of_adr_0017_through_primitives() {
    let sys = FakeSystem::builder().dir(r"C:\G").build().unwrap();
    let g = open(&sys, r"C:\G");
    let data = vec![5u8; 64 * 1024 + 1];
    let new = NewFile {
        tmp: TmpName::new(1, 1),
        attrs: Attrs {
            hidden: true,
            ..Attrs::default()
        },
        sha256: Sha256::digest(&data).into(),
        max_len: 1 << 20,
    };
    let calls = record_calls(&sys);
    g.create_new(&r("new.bin"), &mut &data[..], &new).unwrap();
    sys.fake_fs().clear_on_step();
    use Prim::{CreateTmp, FlushFile, Lookup, Rename, SetAttrs, State, Support, Write};
    assert_eq!(
        *calls.lock().unwrap(),
        [
            Support, Lookup, CreateTmp, Write, Write, SetAttrs, FlushFile, State, State, Rename
        ]
    );
    assert_eq!(g.read(&r("new.bin")).unwrap(), data);
    let names: Vec<String> = g
        .read_dir(None)
        .unwrap()
        .into_iter()
        .map(|e| e.name)
        .collect();
    assert_eq!(names, ["new.bin"]);
}

fn sha(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// What a write must produce: `data` with temp name `n` of instance tag 1.
fn nf(n: u64, data: &[u8]) -> NewFile {
    NewFile {
        tmp: TmpName::new(1, n),
        attrs: Attrs::default(),
        sha256: sha(data),
        max_len: 1 << 20,
    }
}

/// Sorted names in `C:\G`.
fn listing(sys: &FakeSystem, abs: &str) -> Vec<String> {
    let mut v: Vec<String> = open(sys, abs)
        .read_dir(None)
        .unwrap()
        .into_iter()
        .map(|e| e.name)
        .collect();
    v.sort();
    v
}

/// Runs `act` once, the `nth` (1-based) time the primitive `call` is about to run.
fn before_nth(
    sys: &FakeSystem,
    call: Prim,
    nth: usize,
    act: impl Fn(&FakeFs) + Send + 'static,
) -> Arc<AtomicBool> {
    let fired = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&fired);
    let mut seen = 0;
    sys.fake_fs().on_step(move |fs, e| {
        if e.call == Some(call) {
            seen += 1;
            if seen == nth {
                act(fs);
                flag.store(true, Ordering::SeqCst);
            }
        }
    });
    fired
}

fn g_system() -> FakeSystem {
    FakeSystem::builder()
        .file(r"C:\G\t.bin", "old")
        .dir(r"C:\Out")
        .build()
        .unwrap()
}

#[test]
fn f1_an_intruder_between_the_two_renames_is_never_overwritten() {
    let sys = g_system();
    let g = open(&sys, r"C:\G");
    let fired = before_nth(&sys, Prim::Rename, 2, |fs| {
        fs.put_file(&p(r"C:\G\t.bin"), b"intruder").unwrap();
    });
    let guard = g.guard(&r("t.bin")).unwrap();
    let new = nf(1, b"new");
    let e = guard
        .replace(&sha(b"old"), &mut &b"new"[..], &new)
        .unwrap_err();
    sys.fake_fs().clear_on_step();
    assert!(fired.load(Ordering::SeqCst));
    assert_eq!(e.kind, SysErrorKind::Busy);
    // The intruder and `.old` (h0) stay, `<tmp>` is gone: a Foreign combination (A3).
    assert_eq!(g.read(&r("t.bin")).unwrap(), b"intruder");
    assert_eq!(g.read(&new.tmp.old()).unwrap(), b"old");
    assert_eq!(
        listing(&sys, r"C:\G"),
        [new.tmp.old().as_str().to_owned(), "t.bin".to_owned()]
    );
}

#[test]
fn f2_a_junction_planted_before_the_rename_of_create_new_is_refused() {
    let sys = g_system();
    let g = open(&sys, r"C:\G");
    let fired = before_nth(&sys, Prim::Rename, 1, |fs| {
        fs.put_link(&p(r"C:\G\n.bin"), tag::MOUNT_POINT, r"C:\Out")
            .unwrap();
    });
    let e = g
        .create_new(&r("n.bin"), &mut &b"n"[..], &nf(1, b"n"))
        .unwrap_err();
    sys.fake_fs().clear_on_step();
    assert!(fired.load(Ordering::SeqCst));
    assert_eq!(e.kind, SysErrorKind::Busy);
    assert_eq!(
        g.metadata(&r("n.bin")).unwrap().unwrap().kind,
        EntryKind::Reparse
    );
    assert!(
        listing(&sys, r"C:\Out").is_empty(),
        "nothing behind the junction"
    );
    assert_eq!(listing(&sys, r"C:\G"), ["n.bin", "t.bin"], "no <tmp> left");
}

#[test]
fn f3_a_guarded_file_renamed_away_is_never_pulled_back() {
    // Windows refuses these renames (the guard does not share delete); the fake-only rename
    // checks the name re-check behind them.
    for to in [r"C:\G\t-moved.bin", r"C:\Out\t.bin"] {
        let sys = g_system();
        let g = open(&sys, r"C:\G");
        // Before step 6: the re-check sees the new name, nothing is renamed.
        let target = to.to_owned();
        before_nth(&sys, Prim::VolumeName, 2, move |fs| {
            fs.rename_ignoring_shares(&p(r"C:\G\t.bin"), &p(&target))
                .unwrap();
        });
        let e = g
            .guard(&r("t.bin"))
            .unwrap()
            .replace(&sha(b"old"), &mut &b"new"[..], &nf(1, b"new"))
            .unwrap_err();
        sys.fake_fs().clear_on_step();
        assert_eq!(e.kind, SysErrorKind::Busy, "{to}");
        assert!(g.metadata(&r("t.bin")).unwrap().is_none(), "{to}");
        let moved = open(&sys, r"C:\").read(&r(&to[3..])).unwrap();
        assert_eq!(moved, b"old", "{to}: left where it was moved");
        assert!(
            listing(&sys, r"C:\G")
                .iter()
                .all(|n| !n.starts_with(".rerun-")),
            "{to}: no <tmp>"
        );
        assert_eq!(
            listing(&sys, r"C:\Out").len(),
            usize::from(to.starts_with(r"C:\Out"))
        );
    }
    // After step 7, before the re-check of step 8: `.old` moved out of the root. The replace
    // succeeded; step 8 fails its re-check, so `.old` is pending cleanup (A2), never deleted
    // or pulled back where it went.
    let sys = g_system();
    let g = open(&sys, r"C:\G");
    let new = nf(1, b"new");
    let old_abs = format!(r"C:\G\{}", new.tmp.old().as_str());
    before_nth(&sys, Prim::VolumeName, 3, move |fs| {
        fs.rename_ignoring_shares(&p(&old_abs), &p(r"C:\Out\old.bin"))
            .unwrap();
    });
    let done = g
        .guard(&r("t.bin"))
        .unwrap()
        .replace(&sha(b"old"), &mut &b"new"[..], &new)
        .unwrap();
    sys.fake_fs().clear_on_step();
    assert_eq!(done.old_left, Some(new.tmp.clone()));
    assert_eq!(g.read(&r("t.bin")).unwrap(), b"new");
    assert_eq!(open(&sys, r"C:\Out").read(&r("old.bin")).unwrap(), b"old");
    assert_eq!(listing(&sys, r"C:\G"), ["t.bin"]);
}

#[test]
fn f4_a_volume_without_posix_semantics_refuses_every_write() {
    let sys = FakeSystem::builder()
        .file(r"F:\G\t.bin", "old")
        .dir(r"F:\G\d")
        .build()
        .unwrap();
    sys.fake_fs().set_fs_kind('F', FsKind::Fat);
    let g = open(&sys, r"F:\G");
    let un = SysErrorKind::Unsupported;
    assert_eq!(kind(g.guard(&r("t.bin")).map(|_| ())), un);
    assert_eq!(
        kind(g.create_new(&r("n.bin"), &mut &b"n"[..], &nf(1, b"n"))),
        un
    );
    assert_eq!(kind(g.create_dir(&r("n"))), un);
    assert_eq!(kind(g.remove_dir(&r("d"), 0)), un);
    assert_eq!(kind(g.flush()), un);
    assert_eq!(kind(g.lock(&r("l")).map(|_| ())), un);
    assert_eq!(listing(&sys, r"F:\G"), ["d", "t.bin"]);
}

#[test]
fn f11_share_conflict_matches_the_observed_guard_matrix() {
    use crate::sys::contract::share_conflict;
    // ADR 0017: while a guard (DELETE | read data, shares read) is held, another open for
    // write, for delete, or for read without FILE_SHARE_DELETE fails; read with
    // FILE_SHARE_DELETE and attribute-only opens succeed.
    let guard = (
        Access {
            read: true,
            write: false,
            delete: true,
        },
        Share::R,
    );
    let refused = [
        (Access::WRITE, Share::RWD),
        (Access::DELETE, Share::RWD),
        (Access::READ, Share::R),
        (Access::READ, Share::NONE),
    ];
    for (a, s) in refused {
        assert!(share_conflict(a, s, guard.0, guard.1), "{a:?} {s:?}");
    }
    for (a, s) in [
        (Access::READ, Share::RD),
        (Access::READ, Share::RWD),
        (Access::ATTRS, Share::NONE),
    ] {
        assert!(!share_conflict(a, s, guard.0, guard.1), "{a:?} {s:?}");
    }
    // A `Dir` handle never conflicts with a reader; a reader does with a writer (D10).
    assert!(!share_conflict(
        Access::READ,
        Share::RWD,
        Access::READ,
        Share::R
    ));
    assert!(share_conflict(
        Access::READ,
        Share::R,
        Access::WRITE,
        Share::RWD
    ));
    // Symmetric for every combination.
    let all: Vec<(Access, Share)> = (0..64u8)
        .map(|b| {
            (
                Access {
                    read: b & 1 != 0,
                    write: b & 2 != 0,
                    delete: b & 4 != 0,
                },
                Share {
                    read: b & 8 != 0,
                    write: b & 16 != 0,
                    delete: b & 32 != 0,
                },
            )
        })
        .collect();
    for &(a, s) in &all {
        for &(b, t) in &all {
            assert_eq!(share_conflict(a, s, b, t), share_conflict(b, t, a, s));
        }
    }
}

#[test]
fn f12_the_guard_rechecks_before_every_act() {
    let hidden = Attrs {
        hidden: true,
        ..Attrs::default()
    };
    // Before step 6 (hook before step 5): an attribute change and a new hard link.
    for (what, expected) in [
        ("attributes", SysErrorKind::Mismatch),
        ("hard link", SysErrorKind::Linked),
    ] {
        let sys = g_system();
        let g = open(&sys, r"C:\G");
        before_nth(&sys, Prim::FlushFile, 1, move |fs| {
            if what == "attributes" {
                fs.set_attrs(&p(r"C:\G\t.bin"), hidden).unwrap();
            } else {
                fs.put_hardlink(&p(r"C:\G\t.bin"), &p(r"C:\Out\link.bin"))
                    .unwrap();
            }
        });
        let e = g
            .guard(&r("t.bin"))
            .unwrap()
            .replace(&sha(b"old"), &mut &b"new"[..], &nf(1, b"new"))
            .unwrap_err();
        sys.fake_fs().clear_on_step();
        assert_eq!(e.kind, expected, "{what}");
        assert_eq!(g.read(&r("t.bin")).unwrap(), b"old", "{what}");
        assert_eq!(listing(&sys, r"C:\G"), ["t.bin"], "{what}: nothing renamed");
    }
    // Before step 8 (hook before step 7): `.old` changed; the replace succeeded and `.old`
    // stays as pending cleanup.
    let sys = g_system();
    let g = open(&sys, r"C:\G");
    let new = nf(1, b"new");
    let old_abs = format!(r"C:\G\{}", new.tmp.old().as_str());
    before_nth(&sys, Prim::Rename, 2, move |fs| {
        fs.set_attrs(&p(&old_abs), hidden).unwrap();
    });
    let done = g
        .guard(&r("t.bin"))
        .unwrap()
        .replace(&sha(b"old"), &mut &b"new"[..], &new)
        .unwrap();
    sys.fake_fs().clear_on_step();
    assert_eq!(done.old_left, Some(new.tmp.clone()));
    assert_eq!(g.read(&new.tmp.old()).unwrap(), b"old");
    assert_eq!(g.read(&r("t.bin")).unwrap(), b"new");
    // Before a delete: an attribute change refuses it.
    let sys = g_system();
    let g = open(&sys, r"C:\G");
    before_nth(&sys, Prim::VolumeName, 2, move |fs| {
        fs.set_attrs(&p(r"C:\G\t.bin"), hidden).unwrap();
    });
    let e = g
        .guard(&r("t.bin"))
        .unwrap()
        .delete(&sha(b"old"))
        .unwrap_err();
    sys.fake_fs().clear_on_step();
    assert_eq!(e.kind, SysErrorKind::Mismatch);
    assert_eq!(g.read(&r("t.bin")).unwrap(), b"old");
}

#[test]
fn f10_users_reports_handles_and_images_by_process() {
    let sys = g_system();
    let fx = sys.fake_fs();
    let g = open(&sys, r"C:\G");
    let me = std::process::id();
    let t = p(r"C:\G\t.bin");
    let hold = fx.hold_open_as(100, &t, Access::READ, Share::RWD).unwrap();
    let image = fx.map_image_as(200, &t).unwrap();
    let mut all = vec![100, 200];
    all.sort_unstable();
    assert_eq!(g.users(&r("t.bin")).unwrap(), all);
    // The guard: `Dir::users` counts it, `FileGuard::users` does not count itself.
    let guard = g.guard(&r("t.bin")).unwrap();
    let mut with_me = vec![100, 200, me];
    with_me.sort_unstable();
    assert_eq!(g.users(&r("t.bin")).unwrap(), with_me);
    assert_eq!(guard.users().unwrap(), all);
    // An image section blocks writes and deletes, not renames; it follows the file.
    assert_eq!(kind(fx.put_file(&t, b"x")), SysErrorKind::Busy);
    drop(guard);
    drop(hold);
    assert_eq!(kind(fx.remove_abs(&t)), SysErrorKind::Busy);
    fx.rename_abs(&t, &p(r"C:\G\moved.bin")).unwrap();
    assert_eq!(g.users(&r("moved.bin")).unwrap(), [200]);
    drop(image);
    assert!(g.users(&r("moved.bin")).unwrap().is_empty());
    fx.remove_abs(&p(r"C:\G\moved.bin")).unwrap();
}

/// F13 (W24 in the fake's terms): a writable data section without a handle is share-checked
/// like an open with write access sharing everything (the guard, `open_read` and a hold that
/// does not share write are `Busy`; a hold sharing write, a rename and a delete work), counts
/// for `users` and never for the ancestor rule (all observed on Windows).
#[test]
fn f13_a_writable_data_mapping_refuses_the_guard() {
    let sys = g_system();
    let fx = sys.fake_fs();
    let t = p(r"C:\G\sub\t.bin");
    fx.put_file(&t, b"mapped").unwrap();
    let view = fx.map_data_as(300, &t).unwrap();
    {
        let sub = open(&sys, r"C:\G\sub");
        assert_eq!(sub.users(&r("t.bin")).unwrap(), [300]);
        assert_eq!(kind(sub.guard(&r("t.bin"))), SysErrorKind::Busy);
        assert_eq!(
            kind(sub.open_read(&r("t.bin")).map(drop)),
            SysErrorKind::Busy
        );
        assert_eq!(
            kind(fx.hold_open_as(1, &t, Access::READ, Share::R)),
            SysErrorKind::Busy
        );
        drop(fx.hold_open_as(1, &t, Access::READ, Share::RW).unwrap());
    }
    fx.rename_abs(&p(r"C:\G\sub"), &p(r"C:\G\moved")).unwrap();
    let moved = p(r"C:\G\moved\t.bin");
    fx.rename_abs(&moved, &p(r"C:\G\moved\u.bin")).unwrap();
    fx.remove_abs(&p(r"C:\G\moved\u.bin")).unwrap();
    drop(view);
    fx.put_file(&moved, b"plain").unwrap();
    let g = open(&sys, r"C:\G\moved");
    drop(g.guard(&r("t.bin")).unwrap());
}

// ---------- Faults and crashes at the primitive layer ----------

/// Name, content and R/H/S of every entry of a directory, sorted by name.
type Tree = Vec<(String, Vec<u8>, Attrs)>;

fn tree(sys: &FakeSystem, abs: &str) -> Tree {
    let d = open(sys, abs);
    let mut v: Tree = d
        .read_dir(None)
        .unwrap()
        .into_iter()
        .map(|e| {
            let data = if e.meta.kind == EntryKind::File {
                d.read(&r(&e.name)).unwrap()
            } else {
                Vec::new()
            };
            (e.name, data, e.meta.attrs)
        })
        .collect();
    v.sort_by(|a, b| a.0.cmp(&b.0));
    v
}

/// The write operations whose every primitive is faulted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WriteOp {
    Replace,
    CreateNew,
    Delete,
    CreateDir,
    RemoveDir,
}

const WRITE_OPS: [WriteOp; 5] = [
    WriteOp::Replace,
    WriteOp::CreateNew,
    WriteOp::Delete,
    WriteOp::CreateDir,
    WriteOp::RemoveDir,
];

fn op_system() -> FakeSystem {
    FakeSystem::builder()
        .file(r"C:\G\t.bin", "old")
        .dir(r"C:\G\d")
        .build()
        .unwrap()
}

/// Temp name of every operation below.
fn op_tmp() -> TmpName {
    TmpName::new(1, 9)
}

/// Runs `op` on `C:\G`; `Ok(old_left)` for a replace.
fn run_op(g: &dyn DirWrite, op: WriteOp) -> crate::sys::SysResult<Option<TmpName>> {
    let mut new = nf(9, b"new");
    new.tmp = op_tmp();
    match op {
        WriteOp::Replace => g
            .guard(&r("t.bin"))?
            .replace(&sha(b"old"), &mut &b"new"[..], &new)
            .map(|done| done.old_left),
        WriteOp::CreateNew => g
            .create_new(&r("n.bin"), &mut &b"new"[..], &new)
            .map(|_| None),
        WriteOp::Delete => g.guard(&r("t.bin"))?.delete(&sha(b"old")).map(|()| None),
        WriteOp::CreateDir => g.create_dir(&r("nd")).map(|_| None),
        WriteOp::RemoveDir => {
            let id = g.metadata(&r("d"))?.map_or(0, |m| m.file_id);
            g.remove_dir(&r("d"), id).map(|()| None)
        }
    }
}

/// The calls of a successful run of `op` and the tree after it.
fn trace_of(op: WriteOp) -> (Vec<Prim>, Tree) {
    let sys = op_system();
    let g = open(&sys, r"C:\G");
    sys.fake_fs().clear_faults();
    sys.fake_fs().record_calls(true);
    assert_eq!(run_op(&*g, op).unwrap(), None, "{op:?}");
    sys.fake_fs().record_calls(false);
    (sys.fake_fs().take_calls(), tree(&sys, r"C:\G"))
}

/// Occurrence (1-based) of `calls[i]` among `calls[..=i]`.
fn nth_of(calls: &[Prim], i: usize) -> usize {
    calls[..=i].iter().filter(|c| **c == calls[i]).count()
}

#[test]
fn f5_a_fault_at_any_primitive_leaves_the_state_before() {
    let before = tree(&op_system(), r"C:\G");
    for op in WRITE_OPS {
        let (calls, after) = trace_of(op);
        assert!(calls.contains(&Prim::Support), "{op:?}: {calls:?}");
        let step7 = (op == WriteOp::Replace).then(|| {
            calls
                .iter()
                .enumerate()
                .filter(|(_, c)| **c == Prim::Rename)
                .nth(1)
                .map(|(i, _)| i)
                .unwrap()
        });
        for i in 0..calls.len() {
            let sys = op_system();
            let g = open(&sys, r"C:\G");
            let fx = sys.fake_fs();
            fx.clear_faults();
            fx.fail_at(calls[i], nth_of(&calls, i), SysErrorKind::Other);
            let res = run_op(&*g, op);
            let what = format!("{op:?}: fault at {:?} #{}", calls[i], nth_of(&calls, i));
            assert!(fx.fault_fired(), "{what}");
            if step7.is_some_and(|s| i > s) {
                // Step 8 (its re-check or the delete): success with pending cleanup (A2).
                assert_eq!(res.unwrap(), Some(op_tmp()), "{what}");
                let mut expected = after.clone();
                expected.push((
                    op_tmp().old().as_str().to_owned(),
                    b"old".to_vec(),
                    Attrs::default(),
                ));
                expected.sort_by(|a, b| a.0.cmp(&b.0));
                assert_eq!(tree(&sys, r"C:\G"), expected, "{what}");
            } else {
                assert_eq!(res.unwrap_err().kind, SysErrorKind::Other, "{what}");
                assert_eq!(tree(&sys, r"C:\G"), before, "{what}");
            }
        }
    }
}

#[test]
fn f6_a_failed_undo_leaves_phase_b_without_tmp() {
    let hidden = Attrs {
        hidden: true,
        ..Attrs::default()
    };
    // Step 7 and the undo rename fail; or step 7 fails and the undo's re-check refuses
    // (`.old` changed, A4).
    for variant in ["undo fails", "undo re-check fails"] {
        let sys = op_system();
        let g = open(&sys, r"C:\G");
        let fx = sys.fake_fs();
        fx.clear_faults();
        fx.fail_at(Prim::Rename, 2, SysErrorKind::Busy);
        let old = op_tmp().old();
        if variant == "undo fails" {
            fx.fail_at(Prim::Rename, 3, SysErrorKind::Other);
        } else {
            let old_abs = format!(r"C:\G\{}", old.as_str());
            before_nth(&sys, Prim::Rename, 2, move |fs| {
                fs.set_attrs(&p(&old_abs), hidden).unwrap();
            });
        }
        let e = run_op(&*g, WriteOp::Replace).unwrap_err();
        fx.clear_on_step();
        assert_eq!(e.kind, SysErrorKind::Busy, "{variant}: the step-7 error");
        assert!(g.metadata(&r("t.bin")).unwrap().is_none(), "{variant}");
        assert_eq!(g.read(&old).unwrap(), b"old", "{variant}");
        assert!(
            g.metadata(&op_tmp().to_rel()).unwrap().is_none(),
            "{variant}: no <tmp>"
        );
        // Recovery of phase B: `.old` back onto the target name.
        g.guard(&old).unwrap().rename_to(&r("t.bin")).unwrap();
        assert_eq!(g.read(&r("t.bin")).unwrap(), b"old", "{variant}");
    }
}

/// A3 phase of a replace found on disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    A,
    B,
    C,
    D,
    Foreign,
}

/// The hash of `p` taken on a guard: `None` missing, `Some(None)` not guardable (linked …).
fn guarded_hash(g: &dyn DirWrite, p: &RelPath) -> Option<Option<[u8; 32]>> {
    g.metadata(p).unwrap()?;
    Some(g.guard(p).ok().and_then(|mut gd| gd.sha256().ok()))
}

/// Deletes the journaled `<tmp>` if present (on a guard: hash, then delete with it).
fn delete_tmp(g: &dyn DirWrite, x: &RelPath) {
    if let Ok(mut gx) = g.guard(x) {
        let h = gx.sha256().unwrap();
        gx.delete(&h).unwrap();
    }
}

/// Recovery of a replace by the A3 table, with the API only.
fn recover_replace(g: &dyn DirWrite, tmp: &TmpName) -> Phase {
    let (h0, h1) = (sha(b"old"), sha(b"new"));
    let (target, old, x) = (r("t.bin"), tmp.old(), tmp.to_rel());
    match (guarded_hash(g, &target), guarded_hash(g, &old)) {
        (Some(Some(t)), None) if t == h0 => {
            delete_tmp(g, &x);
            Phase::A
        }
        (None, Some(Some(o))) if o == h0 => {
            g.guard(&old).unwrap().rename_to(&target).unwrap();
            delete_tmp(g, &x);
            Phase::B
        }
        (Some(Some(t)), Some(Some(o))) if t == h1 && o == h0 => {
            g.guard(&old).unwrap().delete(&h0).unwrap();
            Phase::C
        }
        (Some(Some(t)), None) if t == h1 => Phase::D,
        _ => Phase::Foreign,
    }
}

/// Recovery of `op` after a crash or a power loss, with the API only (A3): whether the op
/// ended `After` (else `Before`), and the phase of a replace. Panics on `Foreign`.
fn recover_op(g: &dyn DirWrite, op: WriteOp, what: &str) -> (bool, Option<Phase>) {
    let x = op_tmp().to_rel();
    match op {
        WriteOp::Replace => {
            let phase = recover_replace(g, &op_tmp());
            assert_ne!(phase, Phase::Foreign, "{what}");
            (matches!(phase, Phase::C | Phase::D), Some(phase))
        }
        WriteOp::CreateNew => match guarded_hash(g, &r("n.bin")) {
            None => {
                delete_tmp(g, &x);
                (false, None)
            }
            Some(Some(h)) if h == sha(b"new") => {
                assert!(g.metadata(&x).unwrap().is_none(), "{what}: X absent");
                (true, None)
            }
            other => panic!("{what}: Foreign {other:?}"),
        },
        WriteOp::Delete => (g.metadata(&r("t.bin")).unwrap().is_none(), None),
        WriteOp::CreateDir => (g.metadata(&r("nd")).unwrap().is_some(), None),
        WriteOp::RemoveDir => (g.metadata(&r("d")).unwrap().is_none(), None),
    }
}

#[test]
fn f7_s7_a_crash_after_any_primitive_recovers_to_before_or_after() {
    let before = tree(&op_system(), r"C:\G");
    let planted = op_tmp().as_str().to_owned();
    for op in WRITE_OPS {
        let (calls, after) = trace_of(op);
        let mut phases = Vec::new();
        for i in 0..calls.len() {
            let sys = op_system();
            let fx = sys.fake_fs();
            let what = format!("{op:?}: crash after {:?} #{}", calls[i], nth_of(&calls, i));
            {
                let g = open(&sys, r"C:\G");
                fx.clear_faults();
                fx.fault(calls[i], nth_of(&calls, i), Fault::CrashAfter);
                match run_op(&*g, op) {
                    Err(e) => assert_eq!(e.kind, SysErrorKind::Other, "{what}"),
                    // A crash in step 8 is a failed step 8: success with `old_left` (A2).
                    Ok(left) => {
                        assert_eq!((op, left), (WriteOp::Replace, Some(op_tmp())), "{what}")
                    }
                }
                assert!(fx.crashed(), "{what}");
            }
            fx.restart();
            let g = open(&sys, r"C:\G");
            // A file at X before recovery: deleted where the target does not hold the new
            // content (A, B; ours or planted under our name), left in C and D (not ours).
            if op == WriteOp::Replace {
                fx.put_file(&p(&format!(r"C:\G\{planted}")), b"planted")
                    .unwrap();
            }
            let (result_after, phase) = recover_op(&*g, op, &what);
            if let Some(phase) = phase {
                phases.push(phase);
                let x = op_tmp().to_rel();
                if matches!(phase, Phase::C | Phase::D) {
                    assert_eq!(g.read(&x).unwrap(), b"planted", "{what}: X left");
                    fx.remove_abs(&p(&format!(r"C:\G\{planted}"))).unwrap();
                } else {
                    assert!(g.metadata(&x).unwrap().is_none(), "{what}: X deleted");
                }
            }
            let expected = if result_after { &after } else { &before };
            assert_eq!(&tree(&sys, r"C:\G"), expected, "{what}");
        }
        if op == WriteOp::Replace {
            // Each phase is reached: A up to step 5, B after step 6, C after step 7 and the
            // re-check of step 8, D after the delete of step 8 once restarted.
            for ph in [Phase::A, Phase::B, Phase::C, Phase::D] {
                assert!(phases.contains(&ph), "{ph:?} not reached: {phases:?}");
            }
            let at = |c: Prim, n: usize| {
                phases[calls
                    .iter()
                    .enumerate()
                    .filter(|(_, x)| **x == c)
                    .nth(n - 1)
                    .unwrap()
                    .0]
            };
            assert_eq!(at(Prim::FlushFile, 1), Phase::A);
            assert_eq!(at(Prim::Rename, 1), Phase::B);
            assert_eq!(at(Prim::Rename, 2), Phase::C);
            assert_eq!(at(Prim::PosixDelete, 1), Phase::D);
        }
    }
}

#[test]
fn f8_f13_after_a_crash_rerun_is_dead_until_restart_and_others_live_on() {
    let sys = op_system();
    let fx = sys.fake_fs();
    let g = open(&sys, r"C:\G");
    let other = fx
        .hold_open_as(77, &p(r"C:\G\t.bin"), Access::READ, Share::RWD)
        .unwrap();
    let image = fx.map_image_as(78, &p(r"C:\G\t.bin")).unwrap();
    let lock = g.lock(&r("journal.lock")).unwrap();
    fx.fault(Prim::ReadSide(FsOp::Metadata), 1, Fault::CrashAfter);
    assert_eq!(kind(g.metadata(&r("t.bin"))), SysErrorKind::Other);
    assert!(fx.crashed());
    // Every later call of Rerun fails, on old handles and new opens alike.
    assert_eq!(kind(g.read(&r("t.bin"))), SysErrorKind::Other);
    assert_eq!(kind(g.read_dir(None)), SysErrorKind::Other);
    assert_eq!(kind(g.guard(&r("t.bin")).map(|_| ())), SysErrorKind::Other);
    assert_eq!(
        kind(g.lock(&r("other.lock")).map(|_| ())),
        SysErrorKind::Other
    );
    assert_eq!(
        kind(sys.fs().open_dir(Path::new(r"C:\G")).map(|_| ())),
        SysErrorKind::Other
    );
    // Fixture and attacker helpers are never blocked.
    fx.put_file(&p(r"C:\G\new.bin"), b"x").unwrap();
    fx.rename_abs(&p(r"C:\G\new.bin"), &p(r"C:\G\new2.bin"))
        .unwrap();
    drop(
        fx.hold_open_as(79, &p(r"C:\G\new2.bin"), Access::READ, Share::RWD)
            .unwrap(),
    );
    // Dropping the lock while crashed does not release it (the process is dead, not closed).
    drop(lock);
    fx.restart();
    assert!(!fx.crashed());
    // The old handle is stale; a new one works; other programs' handles and images survive.
    assert_eq!(kind(g.metadata(&r("t.bin"))), SysErrorKind::Other);
    let g2 = open(&sys, r"C:\G");
    let mut users = vec![77, 78];
    users.sort_unstable();
    assert_eq!(g2.users(&r("t.bin")).unwrap(), users);
    // The lock was released by the restart.
    drop(g2.lock(&r("journal.lock")).unwrap());
    drop(other);
    drop(image);
    assert!(g2.users(&r("t.bin")).unwrap().is_empty());
}

// ---------- Power loss (ADR 0019 amendment, D-1) ----------

/// Runs `op` on a fresh `C:\G`, crashing after `calls[i]` (or completing for `i == len`).
fn run_until(sys: &FakeSystem, op: WriteOp, calls: &[Prim], i: usize) {
    let g = open(sys, r"C:\G");
    let fx = sys.fake_fs();
    fx.clear_faults();
    if let Some(call) = calls.get(i) {
        fx.fault(*call, nth_of(calls, i), Fault::CrashAfter);
    }
    let _ = run_op(&*g, op);
}

#[test]
fn f9_every_power_loss_cut_recovers_to_before_or_after() {
    let before = tree(&op_system(), r"C:\G");
    for op in WRITE_OPS {
        let (calls, after) = trace_of(op);
        let mut phases = Vec::new();
        let mut final_phases = Vec::new();
        // A power loss after each call and after the whole op, at every cut of `C:`.
        for i in 0..=calls.len() {
            let pending = {
                let sys = op_system();
                run_until(&sys, op, &calls, i);
                sys.fake_fs().pending('C')
            };
            for keep in 0..=pending {
                let sys = op_system();
                run_until(&sys, op, &calls, i);
                sys.fake_fs().power_loss(&BTreeMap::from([('C', keep)]));
                let what = format!("{op:?}: power loss after call {i} of {calls:?}, cut {keep}");
                let g = open(&sys, r"C:\G");
                let (is_after, phase) = recover_op(&*g, op, &what);
                phases.extend(phase);
                if i == calls.len() {
                    final_phases.extend(phase);
                }
                let expected = if is_after { &after } else { &before };
                assert_eq!(&tree(&sys, r"C:\G"), expected, "{what}");
            }
        }
        if op == WriteOp::Replace {
            for ph in [Phase::A, Phase::B, Phase::C, Phase::D] {
                assert!(phases.contains(&ph), "{ph:?} not reached: {phases:?}");
                // The cuts of the completed replace alone reach every phase: a power loss keeps
                // any prefix of the unflushed log (D-1), not only all of it or nothing.
                assert!(
                    final_phases.contains(&ph),
                    "{ph:?} not reached by the cuts after the whole replace: {final_phases:?}"
                );
            }
        }
    }
}

#[test]
fn f9_flush_rules_for_create_new() {
    // Step 5 flushes `<tmp>`: its creation and content are durable, the rename is not until
    // the folder is flushed.
    let sys = op_system();
    let g = open(&sys, r"C:\G");
    let fx = sys.fake_fs();
    g.create_new(&r("n.bin"), &mut &b"new"[..], &nf(3, b"new"))
        .unwrap();
    assert_eq!(fx.pending('C'), 1);
    g.flush().unwrap();
    assert_eq!(fx.pending('C'), 0);
    fx.power_loss(&BTreeMap::new());
    assert_eq!(open(&sys, r"C:\G").read(&r("n.bin")).unwrap(), b"new");
    // Unflushed content is lost: a file reads as its last flushed content.
    let sys = op_system();
    let g = open(&sys, r"C:\G");
    let fx = sys.fake_fs();
    let mut tmp = nf(4, b"new");
    tmp.attrs.hidden = true;
    fx.fault(Prim::SetAttrs, 1, Fault::CrashAfter);
    assert!(g.create_new(&r("n.bin"), &mut &b"new"[..], &tmp).is_err());
    let all = fx.pending('C');
    assert_eq!(all, 2, "created and attributes, nothing flushed");
    fx.power_loss(&BTreeMap::from([('C', all)]));
    let g = open(&sys, r"C:\G");
    let m = g.metadata(&tmp.tmp.to_rel()).unwrap().unwrap();
    assert_eq!(
        (m.len, m.attrs.hidden),
        (0, true),
        "the content was never flushed"
    );
}

#[test]
fn f9_two_volumes_are_ordered_only_by_flushes() {
    let setup = || {
        FakeSystem::builder()
            .dir(r"C:\J")
            .dir(r"D:\G")
            .build()
            .unwrap()
    };
    let act = |sys: &FakeSystem, flush_c: bool| {
        let j = open(sys, r"C:\J");
        j.create_new(&r("rec.bin"), &mut &b"intent"[..], &nf(5, b"intent"))
            .unwrap();
        if flush_c {
            j.flush().unwrap();
        }
        open(sys, r"D:\G")
            .create_new(&r("n.bin"), &mut &b"change"[..], &nf(6, b"change"))
            .unwrap();
    };
    for flush_c in [true, false] {
        let (pc, pd) = {
            let sys = setup();
            act(&sys, flush_c);
            (sys.fake_fs().pending('C'), sys.fake_fs().pending('D'))
        };
        let mut violated = false;
        for c in 0..=pc {
            for d in 0..=pd {
                let sys = setup();
                act(&sys, flush_c);
                sys.fake_fs()
                    .power_loss(&BTreeMap::from([('C', c), ('D', d)]));
                let on_c = open(&sys, r"C:\J")
                    .metadata(&r("rec.bin"))
                    .unwrap()
                    .is_some();
                let on_d = open(&sys, r"D:\G").metadata(&r("n.bin")).unwrap().is_some();
                violated |= on_d && !on_c;
            }
        }
        // With the flush of C: before the change on D:, every pair of cuts keeps the order;
        // without it, some pair loses the intent but keeps the change.
        assert_eq!(violated, !flush_c, "flush of C: {flush_c}");
    }
}

// ---------- Review follow-ups ----------

#[test]
fn a_hard_link_added_to_tmp_is_never_renamed_onto_the_target() {
    // `create_new`: the link check before the rename is the 2nd `State`.
    let sys = g_system();
    let g = open(&sys, r"C:\G");
    let new = nf(1, b"n");
    let tmp_abs = format!(r"C:\G\{}", new.tmp.as_str());
    before_nth(&sys, Prim::State, 2, move |fs| {
        fs.put_hardlink(&p(&tmp_abs), &p(r"C:\Out\stolen.bin"))
            .unwrap();
    });
    let e = g.create_new(&r("n.bin"), &mut &b"n"[..], &new).unwrap_err();
    sys.fake_fs().clear_on_step();
    assert_eq!(e.kind, SysErrorKind::Linked);
    assert_eq!(
        listing(&sys, r"C:\G"),
        ["t.bin"],
        "target absent, our <tmp> name gone"
    );
    assert_eq!(open(&sys, r"C:\Out").read(&r("stolen.bin")).unwrap(), b"n");
    // replace: guard open, fill, step-6 re-check, then the link check of step 7 (4th `State`);
    // the guard goes back (A2), nothing changed at the target.
    let sys = g_system();
    let g = open(&sys, r"C:\G");
    let new = nf(2, b"new");
    let tmp_abs = format!(r"C:\G\{}", new.tmp.as_str());
    before_nth(&sys, Prim::State, 4, move |fs| {
        fs.put_hardlink(&p(&tmp_abs), &p(r"C:\Out\stolen.bin"))
            .unwrap();
    });
    let e = g
        .guard(&r("t.bin"))
        .unwrap()
        .replace(&sha(b"old"), &mut &b"new"[..], &new)
        .unwrap_err();
    sys.fake_fs().clear_on_step();
    assert_eq!(e.kind, SysErrorKind::Linked);
    assert_eq!(g.read(&r("t.bin")).unwrap(), b"old");
    assert_eq!(listing(&sys, r"C:\G"), ["t.bin"]);
}

#[test]
fn a_guard_compares_the_full_path_when_it_opens() {
    // The file is moved to another folder under the same name right after the open: only
    // the full volume path tells.
    let sys = g_system();
    let g = open(&sys, r"C:\G");
    before_nth(&sys, Prim::State, 1, |fs| {
        fs.rename_ignoring_shares(&p(r"C:\G\t.bin"), &p(r"C:\Out\t.bin"))
            .unwrap();
    });
    let e = g.guard(&r("t.bin")).map(|_| ()).unwrap_err();
    sys.fake_fs().clear_on_step();
    assert_eq!(e.kind, SysErrorKind::Busy);
}

#[test]
fn hooks_stop_after_a_crash_and_calls_from_hooks_are_not_counted() {
    let sys = g_system();
    let fx = sys.fake_fs();
    let g = open(&sys, r"C:\G");
    fx.clear_faults();
    fx.fail_at(Prim::ReadSide(FsOp::OpenDir), 1, SysErrorKind::Busy);
    let fired = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&fired);
    fx.on_step(move |fs, _| {
        seen.fetch_add(1, Ordering::SeqCst);
        // A call of the test from inside a hook: neither counted nor faulted.
        drop(fs.open_dir(Path::new(r"C:\G")).unwrap());
    });
    assert!(g.metadata(&r("t.bin")).unwrap().is_some());
    assert!(fired.load(Ordering::SeqCst) > 0);
    assert_eq!(
        kind(sys.fs().open_dir(Path::new(r"C:\G")).map(|_| ())),
        SysErrorKind::Busy,
        "the first counted open is the faulted one"
    );
    fx.fault(Prim::Lookup, 1, Fault::CrashAfter);
    assert!(
        g.create_new(&r("n.bin"), &mut &b"n"[..], &nf(1, b"n"))
            .is_err()
    );
    assert!(fx.crashed());
    let before = fired.load(Ordering::SeqCst);
    assert!(g.create_dir(&r("x")).is_err());
    assert_eq!(
        fired.load(Ordering::SeqCst),
        before,
        "no hook after a crash"
    );
    fx.clear_on_step();
}
