//! `AppDir` (and, from P2-7, the journal) on real Windows. `LocalAppData` is a fake known
//! folder inside a [`TestRoot`] under `target/`; the real `LocalAppData` is never touched
//! (that runs only in Windows Sandbox, `docs/09-testing.md`).

use std::path::{Path, PathBuf};

use super::super::WinFs;
use super::super::testfx::{TestRoot, target_dir};
use crate::journal::tests::j1_round_trip;
use crate::journal::{InstanceTag, Journal, JournalError, TxnState, VerifyBackups};
use crate::path::{RelPath, RootPath};
use crate::policy::root::{AppDir, AppSub, Create, RootError};
use crate::sys::contract::FsFixture;
use crate::sys::fake::{FakeGpu, FakeKnownFolders, FakeRegistry, FakeTopology};
use crate::sys::fs::WriteCap;
use crate::sys::{Fs, Gpu, KnownFolder, KnownFolders, Registry, RegistryWrite, System, Topology};

/// The real file system with fake known folders (and fake everything else): `LocalAppData`
/// is a folder of a [`TestRoot`].
pub(super) struct AppTestSys {
    fs: WinFs,
    kf: FakeKnownFolders,
    reg: FakeRegistry,
    topo: FakeTopology,
    gpu: FakeGpu,
}

impl AppTestSys {
    /// Panics unless `lad` lies inside the canonical cargo target directory.
    pub(super) fn new(lad: &Path) -> Self {
        let target = std::fs::canonicalize(target_dir()).unwrap();
        let canon = std::fs::canonicalize(lad).unwrap();
        assert!(
            canon.starts_with(&target) && canon != target,
            "{} is not inside {}",
            canon.display(),
            target.display()
        );
        let mut kf = FakeKnownFolders::default();
        kf.set(KnownFolder::LocalAppData, lad);
        Self {
            fs: WinFs::new(),
            kf,
            reg: FakeRegistry::default(),
            topo: FakeTopology::default(),
            gpu: FakeGpu::default(),
        }
    }
}

impl System for AppTestSys {
    fn fs(&self) -> &dyn Fs {
        &self.fs
    }
    fn registry(&self) -> &dyn Registry {
        &self.reg
    }
    fn registry_write(&self) -> &dyn RegistryWrite {
        &self.reg
    }
    fn topology(&self) -> &dyn Topology {
        &self.topo
    }
    fn known_folders(&self) -> &dyn KnownFolders {
        &self.kf
    }
    fn gpu(&self) -> &dyn Gpu {
        &self.gpu
    }
}

/// A test root with `lad\` as the fake `LocalAppData` and `out\canary.txt` as the target of
/// planted junctions.
pub(super) fn app_root(case: &str) -> Option<(TestRoot, PathBuf, PathBuf)> {
    let root = TestRoot::new(case)?;
    let lad = root.work("lad");
    let out = root.work("out");
    root.fx().file(&out.join("canary.txt"), b"canary").unwrap();
    Some((root, lad, out))
}

fn listing(p: &Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(p)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}

#[test]
fn a4_app_dir_opens_creates_and_refuses_links_on_real_windows() {
    let Some((root, lad, out)) = app_root("app-dir") else {
        return;
    };
    let sys = AppTestSys::new(&lad);
    assert!(AppDir::open(&sys, Create::Never).unwrap().is_none());
    assert!(listing(&lad).is_empty());
    let app = AppDir::open(&sys, Create::IfMissing)
        .unwrap_or_else(|e| panic!("{e}"))
        .unwrap();
    let rerun = lad.join("Rerun");
    assert_eq!(app.path(), &RootPath::new(&rerun).unwrap());
    let direct = WinFs::new().open_dir(&rerun).unwrap().info().unwrap();
    assert_eq!(app.id().file_id, direct.file_id);
    assert!(
        app.sub_write(AppSub::Journal, Create::IfMissing)
            .unwrap()
            .is_some()
    );
    assert_eq!(listing(&rerun), ["journal"]);
    drop(app);

    // A junction at a sub folder: refused, nothing created behind it.
    std::fs::remove_dir(rerun.join("journal")).unwrap();
    root.fx().junction(&rerun.join("journal"), &out).unwrap();
    let app = AppDir::open(&sys, Create::Never).unwrap().unwrap();
    for create in [Create::Never, Create::IfMissing] {
        match app.sub_write(AppSub::Journal, create) {
            Err(RootError::Reparse { at, .. }) => {
                assert_eq!(at, RelPath::parse("journal").unwrap())
            }
            other => panic!("journal junction ({create:?}): {other:?}"),
        }
    }
    assert!(matches!(
        app.sub(AppSub::Journal),
        Err(RootError::Reparse { .. })
    ));
    drop(app);
    assert_eq!(listing(&out), ["canary.txt"]);

    // A junction at `Rerun` itself.
    root.fx().remove(&rerun.join("journal")).unwrap();
    std::fs::remove_dir(&rerun).unwrap();
    root.fx().junction(&rerun, &out).unwrap();
    for create in [Create::Never, Create::IfMissing] {
        match AppDir::open(&sys, create) {
            Err(RootError::Reparse { store, at }) => {
                assert_eq!(store, RootPath::new(&lad).unwrap());
                assert_eq!(at, RelPath::parse("Rerun").unwrap());
            }
            other => panic!("Rerun junction ({create:?}): {other:?}"),
        }
    }
    assert_eq!(listing(&out), ["canary.txt"]);
}

#[test]
fn j1_j3_j7_journal_on_real_windows() {
    let Some((root, lad, out)) = app_root("journal") else {
        return;
    };
    let sys = AppTestSys::new(&lad);
    let app = AppDir::open(&sys, Create::IfMissing).unwrap().unwrap();
    let game = root.work("game");
    let old = b"old content on real Windows";
    std::fs::write(game.join("a.bin"), old).unwrap();
    let fs = WinFs::new();
    let g = fs.open_dir_write(&game, &WriteCap::new()).unwrap();
    let id = j1_round_trip(&app, &*g, old);

    // J7: one lock at a time, also between two AppDir handles; status without it.
    let app2 = AppDir::open(&sys, Create::Never).unwrap().unwrap();
    let j1 = Journal::new(&app, InstanceTag::new());
    let j2 = Journal::new(&app2, InstanceTag::new());
    let held = j1.lock().unwrap();
    assert!(matches!(j2.lock(), Err(JournalError::Busy)));
    assert_eq!(j2.list().unwrap().txns.len(), 2);
    drop(held);
    drop(j2.lock().unwrap());

    // J3: a junction in place of a transaction folder is refused, never followed.
    let txn = lad.join(format!(r"Rerun\journal\{id}"));
    std::fs::rename(&txn, root.path().join("moved")).unwrap();
    root.fx().junction(&txn, &out).unwrap();
    assert!(crate::journal::tests::is_reparse(
        &j1.load(&id, VerifyBackups::Length)
    ));
    let txns = j1.list().unwrap().txns;
    assert!(txns.iter().any(|l| l.id == id && l.view.is_err()));
    assert!(
        txns.iter()
            .any(|l| l.id != id
                && matches!(&l.view, Ok(v) if matches!(v.state, TxnState::Closed(_))))
    );
    assert_eq!(listing(&out), ["canary.txt"]);
}
