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

mod fs;
mod registry;
mod topology;

use std::path::Path;

use rerun_proto::cpu::CpuTopology;

pub use fs::{FakeDir, FakeFs, FsOp, StepEvent, StepHook};
pub use registry::FakeRegistry;
pub use topology::FakeTopology;

use super::contract::FsFixture;
use super::fs::{Attrs, tag};
use super::registry::{RegKey, RegValue};
use super::{Fs, Registry, SysResult, System, Topology};

/// Fake system made of [`FakeFs`], [`FakeRegistry`] and [`FakeTopology`].
#[derive(Debug, Default)]
pub struct FakeSystem {
    fs: FakeFs,
    registry: FakeRegistry,
    topology: FakeTopology,
}

impl FakeSystem {
    /// Empty system (only drive roots and hive roots exist).
    pub fn new() -> Self {
        Self::default()
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
    fn topology(&self) -> &dyn Topology {
        &self.topology
    }
}

impl FsFixture for FakeFs {
    fn junction(&self, link: &Path, target: &Path) -> SysResult<()> {
        self.put_link(link, tag::MOUNT_POINT, &target.display().to_string(), true)
    }

    fn hardlink(&self, existing: &Path, new: &Path) -> SysResult<()> {
        self.put_hardlink(existing, new)
    }

    fn file_symlink(&self, link: &Path, target: &Path) -> SysResult<bool> {
        self.put_link(link, tag::SYMLINK, &target.display().to_string(), false)?;
        Ok(true)
    }

    fn rename(&self, from: &Path, to: &Path) -> SysResult<()> {
        self.rename_abs(from, to)
    }

    fn case_sensitive_dir(&self, p: &Path) -> SysResult<bool> {
        self.mkdir_all(p)?;
        self.set_case_sensitive(p, true)?;
        Ok(true)
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
        self.step(|s| s.fs.put_link(path.as_ref(), tag::MOUNT_POINT, target, true))
    }

    /// File symbolic link with a target (absolute or relative). The target need not exist.
    pub fn file_symlink(self, path: impl AsRef<Path>, target: &str) -> Self {
        self.step(|s| s.fs.put_link(path.as_ref(), tag::SYMLINK, target, false))
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

    /// Registry key including missing parents.
    pub fn key(self, key: RegKey) -> Self {
        self.step(move |s| s.registry.create_key_all(&key))
    }

    /// Registry value; the key is created if needed.
    pub fn value(self, key: RegKey, name: &str, value: RegValue) -> Self {
        let name = name.to_owned();
        self.step(move |s| {
            s.registry.create_key_all(&key)?;
            s.registry.set(&key, &name, &value)
        })
    }

    /// CPU topology.
    pub fn topology(mut self, topology: CpuTopology) -> Self {
        self.sys.topology = FakeTopology::new(topology);
        self
    }

    /// CPU topology from a JSON fixture (`tests/fixtures/cpu/*.json`).
    pub fn topology_json(mut self, json: &str) -> Self {
        match FakeTopology::from_json(json) {
            Ok(t) => self.sys.topology = t,
            Err(e) => {
                if self.error.is_none() {
                    self.error = Some(e);
                }
            }
        }
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
