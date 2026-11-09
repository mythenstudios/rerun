//! The elevated helper's own token and system (ADR 0023 §3, §11, §12). No `unsafe` here.
//!
//! - [`WinHelperToken`]: `drop_privileges` and `is_elevated` over `token`, `own_image` and
//!   `instance_lock` over `process` (A4 S8).
//! - [`WinHelperSystem`]: the file system read side with `open_by_id` ([`WinFs`]), the known
//!   folders over a machine-only registry (the `ProfileList` values of `HKLM`; no user hive is
//!   opened), the token; [`NoGpu`], [`NoTopology`], [`NoRegistry`] (as `registry()` and
//!   `registry_write()`), `NoElevation`, and in P4-2c [`NoFirewall`]: the COM binding enters the
//!   helper with the write side in P4-5b, so its imports stay without COM until then.
//!
//! Nothing here references `WinSystem`, `WinGpu`, `dxgi` or `loader`'s DLL loading: the helper
//! links only what it uses, which the import and content tests of
//! `crates/rerun-helper/tests/hardening.rs` check.

use std::fmt;
use std::sync::Arc;

use super::registry::WinRegistry;
use super::status::kind_of_win32;
use super::{WinFs, WinKnownFolders, process, token};
use crate::sys::{
    Elevation, Firewall, Fs, Gpu, HelperSystem, HelperToken, InstanceLock, KnownFolders,
    NoElevation, NoFirewall, NoGpu, NoRegistry, NoTopology, Registry, RegistryWrite, SysError,
    SysErrorKind, SysResult, System, Topology,
};

/// The real [`HelperToken`]: the token of the current process.
#[derive(Debug, Clone, Copy, Default)]
pub struct WinHelperToken;

fn err(op: &'static str, code: u32) -> SysError {
    SysError::new(kind_of_win32(code), op).with_win32(code)
}

impl HelperToken for WinHelperToken {
    fn drop_privileges(&self) -> SysResult<()> {
        token::drop_privileges().map_err(|c| err("drop privileges of the process token", c))
    }

    fn is_elevated(&self) -> SysResult<bool> {
        token::process_elevated().map_err(|c| err("TokenElevation of the process token", c))
    }

    fn own_image(&self) -> SysResult<String> {
        process::own_image().map_err(|c| err("the image of this process", c))
    }

    fn instance_lock(&self) -> SysResult<InstanceLock> {
        match process::instance_mutex() {
            Ok(m) => Ok(InstanceLock::new(Box::new(m))),
            Err(c) if c == windows_sys::Win32::Foundation::ERROR_ALREADY_EXISTS => {
                Err(SysError::new(SysErrorKind::Busy, "another elevated helper runs").with_win32(c))
            }
            Err(c) => Err(err("the helper's instance lock", c)),
        }
    }
}

/// The real helper's [`HelperSystem`] (module docs).
pub struct WinHelperSystem {
    fs: WinFs,
    known_folders: WinKnownFolders,
    token: WinHelperToken,
}

impl WinHelperSystem {
    /// The helper's system. Opens nothing yet.
    pub fn new() -> Self {
        let machine: Arc<dyn Registry> = Arc::new(WinRegistry::machine_only());
        Self {
            fs: WinFs::new(),
            known_folders: WinKnownFolders::new(machine),
            token: WinHelperToken,
        }
    }
}

impl Default for WinHelperSystem {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for WinHelperSystem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WinHelperSystem").finish_non_exhaustive()
    }
}

impl System for WinHelperSystem {
    fn fs(&self) -> &dyn Fs {
        &self.fs
    }
    fn registry(&self) -> &dyn Registry {
        &NoRegistry
    }
    fn registry_write(&self) -> &dyn RegistryWrite {
        &NoRegistry
    }
    fn topology(&self) -> &dyn Topology {
        &NoTopology
    }
    fn known_folders(&self) -> &dyn KnownFolders {
        &self.known_folders
    }
    fn gpu(&self) -> &dyn Gpu {
        &NoGpu
    }
    fn firewall(&self) -> &dyn Firewall {
        &NoFirewall
    }
    fn elevation(&self) -> &dyn Elevation {
        &NoElevation
    }
}

impl HelperSystem for WinHelperSystem {
    fn token(&self) -> &dyn HelperToken {
        &self.token
    }
}
