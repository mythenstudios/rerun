//! In-memory system layer for tests. Never changes the real system.
//!
//! ```
//! use rerun_core::sys::fake::FakeSystem;
//! use rerun_core::sys::System;
//! use std::path::Path;
//!
//! let sys = FakeSystem::builder()
//!     .file(r"C:\Games\AC\AssassinsCreed_Dx9.exe", b"MZ".to_vec())
//!     .build()
//!     .unwrap();
//! let data = sys.fs().read(Path::new(r"c:\games\ac\assassinscreed_dx9.exe")).unwrap();
//! assert_eq!(data, b"MZ");
//! ```

mod fs;
mod registry;
mod topology;

use std::path::{Path, PathBuf};

use rerun_proto::cpu::CpuTopology;

pub use fs::FakeFs;
pub use registry::FakeRegistry;
pub use topology::FakeTopology;

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
        let p = path.as_ref().to_path_buf();
        self.step(move |s| s.fs.create_dir_all(&p))
    }

    /// File including missing parent directories.
    pub fn file(self, path: impl AsRef<Path>, data: impl Into<Vec<u8>>) -> Self {
        let p = path.as_ref().to_path_buf();
        let data = data.into();
        self.step(move |s| {
            if let Some(parent) = p.parent() {
                s.fs.create_dir_all(parent)?;
            }
            s.fs.write(&p, &data)
        })
    }

    /// Read-only file.
    pub fn readonly_file(self, path: impl AsRef<Path>, data: impl Into<Vec<u8>>) -> Self {
        let p = path.as_ref().to_path_buf();
        self.file(&p, data)
            .step(move |s| s.fs.set_readonly(&p, true))
    }

    /// Reparse point (symlink/junction) with a target. The target need not exist.
    pub fn reparse(self, path: impl AsRef<Path>, target: impl Into<PathBuf>) -> Self {
        let p = path.as_ref().to_path_buf();
        let target = target.into();
        self.step(move |s| {
            if let Some(parent) = p.parent() {
                s.fs.create_dir_all(parent)?;
            }
            s.fs.add_reparse(&p, target)
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
