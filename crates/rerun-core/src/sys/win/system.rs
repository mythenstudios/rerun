//! [`WinSystem`]: the real [`System`] (ADR 0004). No `unsafe`.

use std::fmt;
use std::sync::Arc;

use super::{WinElevation, WinFirewall, WinFs, WinGpu, WinKnownFolders, WinRegistry, WinTopology};
use crate::sys::{
    Elevation, Firewall, Fs, Gpu, KnownFolders, PromptOwner, Registry, RegistryWrite, SysResult,
    System, Topology,
};

/// The real file system, registry, known folders (on that registry), CPU topology and graphics
/// adapters of this machine. Opening it opens the current user's registry root; `dxgi.dll` is
/// loaded only on the first [`Gpu::adapters`] call, which needs
/// [`restrict_dll_search`](super::restrict_dll_search) first (else `Unsupported`).
///
/// The elevated helper (phase 3) builds its own `System` without the GPU (ADR 0008, H2).
pub struct WinSystem {
    fs: WinFs,
    registry: Arc<WinRegistry>,
    known_folders: WinKnownFolders,
    topology: WinTopology,
    gpu: WinGpu,
    firewall: WinFirewall,
    elevation: WinElevation,
}

impl WinSystem {
    /// The real system.
    ///
    /// # Errors
    /// The error of [`WinRegistry::new`] (the current user's registry root cannot be opened).
    pub fn new() -> SysResult<Self> {
        let registry = Arc::new(WinRegistry::new()?);
        Ok(Self {
            fs: WinFs::new(),
            known_folders: WinKnownFolders::new(registry.clone()),
            registry,
            topology: WinTopology::new(),
            gpu: WinGpu::new(),
            firewall: WinFirewall,
            elevation: WinElevation::default(),
        })
    }

    /// The UAC dialog of a helper start belongs to `owner` (ADR 0023 amendment P5-5c): the app
    /// passes its window, so the dialog appears in front of it. Without this the owner is the
    /// console window, as for the CLI.
    #[must_use]
    pub fn with_prompt_owner(mut self, owner: PromptOwner) -> Self {
        self.elevation = WinElevation::owned_by(owner);
        self
    }
}

impl fmt::Debug for WinSystem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WinSystem").finish_non_exhaustive()
    }
}

impl System for WinSystem {
    fn fs(&self) -> &dyn Fs {
        &self.fs
    }

    fn registry(&self) -> &dyn Registry {
        &*self.registry
    }

    fn registry_write(&self) -> &dyn RegistryWrite {
        &*self.registry
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

    fn firewall(&self) -> &dyn Firewall {
        &self.firewall
    }

    fn elevation(&self) -> &dyn Elevation {
        &self.elevation
    }
}
