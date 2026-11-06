//! In-memory system layer for tests. Never changes the real system.
//!
//! ```
//! use rerun_core::policy::path::RelPath;
//! use rerun_core::sys::fake::FakeSystem;
//! use rerun_core::sys::System;
//! use std::path::Path;
//!
//! let sys = FakeSystem::builder()
//!     .file(r"C:\Games\AC\AssassinsCreed_Dx9.exe", b"MZ".to_vec())
//!     .build()
//!     .unwrap();
//! let game = sys.fs().open_dir(Path::new(r"c:\games\ac")).unwrap();
//! let exe = RelPath::parse("assassinscreed_dx9.exe").unwrap();
//! assert_eq!(game.read(&exe).unwrap(), b"MZ");
//! ```

mod faults;
mod fs;
mod gpu;
mod known_folders;
mod registry;
mod topology;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rerun_proto::cpu::CpuTopology;

pub use faults::{Fault, Prim, RegPrim};
pub use fs::{FakeDir, FakeFile, FakeFs, FakeHold, FsOp, StepEvent, StepHook};
pub use gpu::FakeGpu;
pub use known_folders::FakeKnownFolders;
pub use registry::{FakeRegistry, MAX_LINK_HOPS, RegHook};
pub use topology::FakeTopology;

use super::contract::{Access, FsFixture, Held, Share};
use super::fs::{Attrs, tag};
use super::registry::{Hive, RegKey, RegValue};
use super::{
    Fs, Gpu, GpuAdapter, KnownFolder, KnownFolders, Registry, RegistryWrite, SysErrorKind,
    SysResult, System, Topology,
};
use faults::FaultHub;

/// A durability domain of the power-loss model (ADR 0019 amendment, P2-9): a volume of the
/// file system or a registry hive. Nothing orders two domains except their flushes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Domain {
    /// The volume with this drive letter.
    Volume(char),
    /// A registry hive.
    Hive(Hive),
}

/// Fake system made of [`FakeFs`], [`FakeRegistry`], [`FakeTopology`],
/// [`FakeKnownFolders`] and [`FakeGpu`]. The file system and the registry share one fault
/// hub: their calls are counted, failed and crashed in one sequence, a crash blocks both, and
/// [`FakeSystem::power_loss`] cuts volumes and hives in one go.
#[derive(Debug)]
pub struct FakeSystem {
    fs: FakeFs,
    registry: FakeRegistry,
    topology: FakeTopology,
    known_folders: FakeKnownFolders,
    gpu: FakeGpu,
}

impl Default for FakeSystem {
    fn default() -> Self {
        let sys = Self {
            fs: FakeFs::default(),
            registry: FakeRegistry::default(),
            topology: FakeTopology::default(),
            known_folders: FakeKnownFolders::default(),
            gpu: FakeGpu::default(),
        };
        let hub = Arc::new(FaultHub::default());
        sys.fs.set_hub(hub.clone());
        sys.registry.set_hub(hub);
        sys
    }
}

impl FakeSystem {
    /// Empty system: only drive roots and hive roots exist, the known folders point to the
    /// standard layout (without directories), no graphics adapter.
    pub fn new() -> Self {
        Self::default()
    }

    /// A power loss (ADR 0019 amendment, P2-9): per domain the durable changes plus
    /// `keep[domain]` (default 0) more survive, the rest is undone newest first, volumes and
    /// hives under both locks (file system first, then registry); every handle is gone and the
    /// process starts fresh (see `FakeFs` and `FakeRegistry`).
    pub fn power_loss(&self, keep: &BTreeMap<Domain, usize>) {
        let mut volumes = BTreeMap::new();
        let mut hives = BTreeMap::new();
        for (d, n) in keep {
            match d {
                Domain::Volume(c) => {
                    volumes.insert(c.to_ascii_uppercase(), *n);
                }
                Domain::Hive(h) => {
                    hives.insert(*h, *n);
                }
            }
        }
        self.fs
            .power_loss_with(&volumes, || self.registry.cut(&hives));
    }

    /// Changes of `d` that a power loss could drop (logged, not durable).
    pub fn pending(&self, d: Domain) -> usize {
        match d {
            Domain::Volume(c) => self.fs.pending(c),
            Domain::Hive(h) => self.registry.pending(h),
        }
    }

    /// Restarts after a crash: see [`FakeFs::restart`] (it also makes every registry handle
    /// stale; registry changes stay).
    pub fn restart(&self) {
        self.fs.restart();
    }

    /// Makes every change so far durable on every volume and in every hive.
    pub fn sync_all(&self) {
        self.fs.sync_all();
        self.registry.sync_all();
    }

    /// Builder for an initial state.
    pub fn builder() -> FakeSystemBuilder {
        FakeSystemBuilder {
            sys: Self::new(),
            error: None,
        }
    }

    /// The fake file system with its setup, attacker and hook helpers.
    pub fn fake_fs(&self) -> &FakeFs {
        &self.fs
    }

    /// The fake registry, also the [`RegFixture`](super::contract::RegFixture) of the contracts.
    pub fn fake_registry(&self) -> &FakeRegistry {
        &self.registry
    }

    /// Attacker: see [`FakeFs::swap_with_junction`].
    pub fn swap_with_junction(&self, abs: impl AsRef<Path>, target: &str) -> SysResult<String> {
        self.fs.swap_with_junction(abs.as_ref(), target)
    }

    /// Attacker: see [`FakeFs::rename_abs`].
    pub fn rename_abs(&self, from: impl AsRef<Path>, to: impl AsRef<Path>) -> SysResult<()> {
        self.fs.rename_abs(from.as_ref(), to.as_ref())
    }
}

impl System for FakeSystem {
    fn fs(&self) -> &dyn Fs {
        &self.fs
    }
    fn registry(&self) -> &dyn Registry {
        &self.registry
    }
    fn registry_write(&self) -> &dyn RegistryWrite {
        &self.registry
    }
    fn topology(&self) -> &dyn Topology {
        &self.topology
    }
    fn known_folders(&self) -> &dyn KnownFolders {
        &self.known_folders
    }
    fn gpu(&self) -> &dyn Gpu {
        &self.gpu
    }
}

impl FsFixture for FakeFs {
    fn dir(&self, p: &Path) -> SysResult<()> {
        self.mkdir_all(p)
    }

    fn file(&self, p: &Path, data: &[u8]) -> SysResult<()> {
        self.put_file(p, data)
    }

    fn utf16_file(&self, parent: &Path, units: &[u16], data: &[u8]) -> SysResult<bool> {
        self.put_utf16_file(parent, units, data)?;
        Ok(true)
    }

    fn junction(&self, link: &Path, target: &Path) -> SysResult<()> {
        self.put_link(link, tag::MOUNT_POINT, &target.display().to_string())
    }

    fn dir_symlink(&self, link: &Path, target: &Path) -> SysResult<bool> {
        self.put_link(link, tag::SYMLINK, &target.display().to_string())?;
        Ok(true)
    }

    fn file_symlink(&self, link: &Path, target: &Path) -> SysResult<bool> {
        self.put_link(link, tag::SYMLINK, &target.display().to_string())?;
        Ok(true)
    }

    fn hardlink(&self, existing: &Path, new: &Path) -> SysResult<()> {
        self.put_hardlink(existing, new)
    }

    fn rename(&self, from: &Path, to: &Path) -> SysResult<()> {
        self.rename_abs(from, to)
    }

    fn case_sensitive_dir(&self, p: &Path) -> SysResult<bool> {
        self.mkdir_all(p)?;
        self.set_case_sensitive(p, true)?;
        Ok(true)
    }

    fn mount_volume(&self, at: &Path) -> SysResult<bool> {
        self.mkdir_all(at)?;
        self.set_volume_root(at)?;
        Ok(true)
    }

    fn subst(&self, _target: &Path) -> SysResult<Option<PathBuf>> {
        Ok(None)
    }

    fn short_name(&self, _p: &Path, _short: &str) -> SysResult<bool> {
        Ok(false)
    }

    fn wof_compress(&self, _p: &Path) -> SysResult<bool> {
        Ok(false)
    }

    fn restricted(&self, p: &Path) -> SysResult<bool> {
        self.set_restricted(p, true)?;
        Ok(true)
    }

    fn remove(&self, p: &Path) -> SysResult<()> {
        self.remove_abs(p)
    }

    fn set_attrs(&self, p: &Path, attrs: Attrs) -> SysResult<()> {
        FakeFs::set_attrs(self, p, attrs)
    }

    fn mapped_image(&self, p: &Path) -> SysResult<Option<Held<'_>>> {
        self.put_file(p, b"MZ fake image")?;
        Ok(Some(Box::new(self.map_image_as(std::process::id(), p)?)))
    }

    fn delete_pending(&self, p: &Path) -> SysResult<Option<Held<'_>>> {
        self.put_file(p, b"pending")?;
        Ok(Some(Box::new(FakeFs::delete_pending(self, p)?)))
    }

    fn mapped_data(&self, p: &Path) -> SysResult<Option<Held<'_>>> {
        self.put_file(p, b"mapped data")?;
        Ok(Some(Box::new(self.map_data_as(std::process::id(), p)?)))
    }

    /// A writable section without a view behaves as a writable view (observed, W24b).
    fn data_section(&self, p: &Path) -> SysResult<Option<Held<'_>>> {
        self.put_file(p, b"data section")?;
        Ok(Some(Box::new(self.map_data_as(std::process::id(), p)?)))
    }

    fn hold_open(&self, p: &Path, access: Access, share: Share) -> SysResult<Held<'_>> {
        Ok(Box::new(self.hold_open_as(
            std::process::id(),
            p,
            access,
            share,
        )?))
    }
}

/// Builder for [`FakeSystem`]. Parent directories and keys are created automatically.
/// The first error is remembered and returned by [`FakeSystemBuilder::build`].
#[derive(Debug)]
pub struct FakeSystemBuilder {
    sys: FakeSystem,
    error: Option<super::SysError>,
}

impl FakeSystemBuilder {
    fn step(mut self, f: impl FnOnce(&FakeSystem) -> SysResult<()>) -> Self {
        if self.error.is_none()
            && let Err(e) = f(&self.sys)
        {
            self.error = Some(e);
        }
        self
    }

    /// Directory including missing parents.
    pub fn dir(self, path: impl AsRef<Path>) -> Self {
        self.step(|s| s.fs.mkdir_all(path.as_ref()))
    }

    /// File including missing parent directories.
    pub fn file(self, path: impl AsRef<Path>, data: impl Into<Vec<u8>>) -> Self {
        let data = data.into();
        self.step(|s| s.fs.put_file(path.as_ref(), &data))
    }

    /// Read-only file.
    pub fn readonly_file(self, path: impl AsRef<Path>, data: impl Into<Vec<u8>>) -> Self {
        let p = path.as_ref().to_path_buf();
        let attrs = Attrs {
            readonly: true,
            ..Attrs::default()
        };
        self.file(&p, data).step(|s| s.fs.set_attrs(&p, attrs))
    }

    /// File with a reparse tag, e.g. [`tag::WOF`] (allowed) or [`tag::APPEXECLINK`] (rejected).
    pub fn tagged_file(
        self,
        path: impl AsRef<Path>,
        data: impl Into<Vec<u8>>,
        reparse_tag: u32,
    ) -> Self {
        let data = data.into();
        self.step(|s| s.fs.put_tagged_file(path.as_ref(), &data, reparse_tag))
    }

    /// Directory with a non-surrogate reparse tag, e.g. [`tag::CLOUD`] (allowed) or
    /// [`tag::PROJFS`] (rejected).
    pub fn tagged_dir(self, path: impl AsRef<Path>, reparse_tag: u32) -> Self {
        let p = path.as_ref();
        self.step(|s| {
            s.fs.mkdir_all(p)?;
            s.fs.set_dir_tag(p, reparse_tag)
        })
    }

    /// Junction with a target. The target need not exist.
    pub fn junction(self, path: impl AsRef<Path>, target: &str) -> Self {
        self.step(|s| s.fs.put_link(path.as_ref(), tag::MOUNT_POINT, target))
    }

    /// File symbolic link with a target (absolute or relative). The target need not exist.
    pub fn file_symlink(self, path: impl AsRef<Path>, target: &str) -> Self {
        self.step(|s| s.fs.put_link(path.as_ref(), tag::SYMLINK, target))
    }

    /// Hard link `new` to the existing file `existing`.
    pub fn hardlink(self, existing: impl AsRef<Path>, new: impl AsRef<Path>) -> Self {
        self.step(|s| s.fs.put_hardlink(existing.as_ref(), new.as_ref()))
    }

    /// File with a raw name that is not a valid segment (`d3d9.dll.`, `CON`).
    pub fn raw_file(
        self,
        parent: impl AsRef<Path>,
        raw_name: &str,
        data: impl Into<Vec<u8>>,
    ) -> Self {
        let data = data.into();
        self.step(|s| s.fs.put_raw_file(parent.as_ref(), raw_name, &data))
    }

    /// Empty case-sensitive directory (files can still be added by the builder).
    pub fn case_sensitive_dir(self, path: impl AsRef<Path>) -> Self {
        let p = path.as_ref();
        self.step(|s| {
            s.fs.mkdir_all(p)?;
            s.fs.set_case_sensitive(p, true)
        })
    }

    /// Directory the current user cannot write (`RootInfo::user_writable == false`).
    /// Directories created below it later inherit the flag.
    pub fn protected_dir(self, path: impl AsRef<Path>) -> Self {
        let p = path.as_ref();
        self.step(|s| {
            s.fs.mkdir_all(p)?;
            s.fs.set_user_writable(p, false)
        })
    }

    /// Makes the existing file, directory or link at `path` restricted: its DACL denies the
    /// current user every open (see [`FakeFs::set_restricted`]). Call it after creating the
    /// entry.
    pub fn restricted(self, path: impl AsRef<Path>) -> Self {
        self.step(|s| s.fs.set_restricted(path.as_ref(), true))
    }

    /// Directory that is the root of a volume mounted in a folder (no drive letter).
    pub fn mounted_volume(self, path: impl AsRef<Path>) -> Self {
        let p = path.as_ref();
        self.step(|s| {
            s.fs.mkdir_all(p)?;
            s.fs.set_volume_root(p)
        })
    }

    /// Registry key including missing parents.
    pub fn key(self, key: RegKey) -> Self {
        self.step(move |s| s.registry.put_key_all(&key))
    }

    /// Registry key (created if needed) that refuses every method with `AccessDenied`, like
    /// `HKLM\SECURITY` for a standard user; everything below it is refused as well. Call it
    /// after the keys and values below it are set up.
    pub fn denied_key(self, key: RegKey) -> Self {
        self.step(move |s| {
            s.registry.put_key_all(&key)?;
            s.registry.deny(&key)
        })
    }

    /// Registry value; the key is created if needed.
    pub fn value(self, key: RegKey, name: &str, value: RegValue) -> Self {
        let name = name.to_owned();
        self.step(move |s| {
            s.registry.put_key_all(&key)?;
            s.registry.put_value(&key, &name, &value)
        })
    }

    /// Registry value from a stored type number and bytes, the way a registry hands it out:
    /// typed if the bytes are canonical, [`RegValue::Raw`] otherwise (see
    /// [`RegValue::decode`]). The key is created if needed.
    pub fn raw_value(self, key: RegKey, name: &str, kind: u32, data: &[u8]) -> Self {
        self.value(key, name, RegValue::decode(kind, data))
    }

    fn set_topology(mut self, topology: SysResult<FakeTopology>) -> Self {
        match topology {
            Ok(t) => self.sys.topology = t,
            Err(e) => {
                if self.error.is_none() {
                    self.error = Some(e);
                }
            }
        }
        self
    }

    /// Windows build as `hw::os` reads it: `CurrentBuildNumber` (`REG_SZ`) and, if given,
    /// `UBR` (`REG_DWORD`) in `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`, native
    /// view. Malformed forms are set up with [`Self::value`] or [`Self::raw_value`].
    pub fn os_build(self, build: u32, ubr: Option<u32>) -> Self {
        let key = RegKey::new(
            super::registry::Hive::LocalMachine,
            super::registry::RegView::Native,
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
        );
        let b = self.value(
            key.clone(),
            "CurrentBuildNumber",
            RegValue::String(build.to_string()),
        );
        match ubr {
            Some(ubr) => b.value(key, "UBR", RegValue::Dword(ubr)),
            None => b,
        }
    }

    /// CPU topology; must pass [`CpuTopology::validate`]. Without one, reading the
    /// topology fails.
    pub fn topology(self, topology: CpuTopology) -> Self {
        self.set_topology(FakeTopology::new(topology))
    }

    /// CPU topology from a JSON fixture (`tests/fixtures/cpu/*.json`), validated.
    pub fn topology_json(self, json: &str) -> Self {
        self.set_topology(FakeTopology::from_json(json))
    }

    /// Sets a known folder (default: [`FakeKnownFolders::standard`]).
    pub fn known_folder(
        mut self,
        folder: KnownFolder,
        path: impl Into<std::path::PathBuf>,
    ) -> Self {
        self.sys.known_folders.set(folder, path);
        self
    }

    /// Removes a known folder; resolving it then fails with `NotFound`.
    pub fn without_known_folder(mut self, folder: KnownFolder) -> Self {
        self.sys.known_folders.remove(folder);
        self
    }

    /// Creates the directories of all known folders as configured at this point. Call it
    /// after [`Self::known_folder`]. Network and device paths (`\\…`) are skipped: the
    /// fake file system only has drive letters.
    pub fn windows_layout(self) -> Self {
        let paths: Vec<_> = self
            .sys
            .known_folders
            .paths()
            .filter(|(_, p)| !p.to_string_lossy().starts_with(r"\\"))
            .map(|(_, p)| p.clone())
            .collect();
        paths.into_iter().fold(self, |b, p| b.dir(p))
    }

    /// Appends a graphics adapter (DXGI order: the first one drives the primary display).
    pub fn gpu(mut self, adapter: GpuAdapter) -> Self {
        self.sys.gpu.push(adapter);
        self
    }

    /// Adapter enumeration fails with `kind` (DXGI unavailable).
    pub fn gpu_error(mut self, kind: SysErrorKind) -> Self {
        self.sys.gpu.fail_with(kind);
        self
    }

    /// The finished system or the first error that occurred.
    pub fn build(self) -> SysResult<FakeSystem> {
        match self.error {
            Some(e) => Err(e),
            None => Ok(self.sys),
        }
    }
}

#[cfg(test)]
mod tests;
