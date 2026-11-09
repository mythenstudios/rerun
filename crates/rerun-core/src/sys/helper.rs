//! The elevated helper's own process and system (ADR 0023 §3, §11, §12).
//!
//! [`HelperToken`] is what `elevate::serve` asks about its own process before it reads
//! anything: drop every privilege it does not need (§3 step 2), check that it runs elevated
//! (§3 step 3), name its own image (§3 step 4) and hold the one helper instance lock (A4 S8).
//! The real one is `sys::win::WinHelperToken`, the fake one `sys::fake::FakeHelperToken`. Only
//! the helper uses it; the CLI and the GUI never drop privileges (they never have any worth
//! dropping, core rule 6).
//!
//! [`HelperSystem`] is the helper's [`System`] (§11): the file system read side with
//! `open_by_id`, the known folders, the firewall and its token. What it must not have refuses:
//! [`NoGpu`] (docs/08 acceptance: the helper's system has no GPU), [`NoTopology`],
//! [`NoRegistry`] (no registry in phase 4, read or write) and `NoElevation` (no nested
//! elevation). [`NoFirewall`] is the firewall of a system that has none yet: the real helper
//! until the COM binding enters it with the write side (P4-5b), so its imports stay without COM
//! in P4-2c.

use std::fmt;

use rerun_proto::cpu::CpuTopology;

use super::firewall::{Firewall, FwSelection};
use super::registry::{KeyState, RegKey, RegLink, RegValue, Registry, RegistryWrite};
use super::{Gpu, GpuAdapter, SysError, SysErrorKind, SysResult, System, Topology};
use crate::sys::registry::Hive;

/// The helper's instance lock (A4 S8): held while it lives, so a second helper refuses with
/// `Busy`. Dropping it releases the lock; the kernel releases it when the process ends.
pub struct InstanceLock(
    #[allow(dead_code, reason = "held for its drop only")] Box<dyn Send + Sync>,
);

impl InstanceLock {
    /// A lock that holds `inner` until it drops.
    pub fn new(inner: Box<dyn Send + Sync>) -> Self {
        Self(inner)
    }
}

impl fmt::Debug for InstanceLock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("InstanceLock")
    }
}

/// The helper's own process token (ADR 0023 §3, §12).
pub trait HelperToken: Send + Sync {
    /// Removes every privilege of the process token except `SeChangeNotifyPrivilege`
    /// (`SE_PRIVILEGE_REMOVED`, so none can be enabled again), then reads the token back:
    /// any privilege left besides that one is an error (fail closed).
    ///
    /// # Errors
    /// The token cannot be opened, adjusted or read back, or a privilege is still there.
    fn drop_privileges(&self) -> SysResult<()>;

    /// Whether the process token is elevated (`TokenElevation`).
    ///
    /// # Errors
    /// The token cannot be read.
    fn is_elevated(&self) -> SysResult<bool>;

    /// The NT name of this process's image (`QueryFullProcessImageNameW(PROCESS_NAME_NATIVE)`,
    /// `\Device\HarddiskVolumeN\…`), compared folded with the NT name the pre-check reads on the
    /// installed file (§3 step 4, the same comparison as `elevate::judge`).
    ///
    /// # Errors
    /// The image cannot be read.
    fn own_image(&self) -> SysResult<String>;

    /// Takes the one helper instance lock (A4 S8): a named mutex in the global namespace that
    /// only the helper creates. `Busy` while another helper (of any build) holds it.
    ///
    /// # Errors
    /// `Busy` for another helper; the lock cannot be created.
    fn instance_lock(&self) -> SysResult<InstanceLock>;
}

/// The elevated helper's system (ADR 0023 §11, §12): only `WinHelperSystem` and the fake's
/// helper view implement it.
pub trait HelperSystem: System {
    /// The helper's own token.
    fn token(&self) -> &dyn HelperToken;
}

fn refused(what: &str) -> SysError {
    SysError::new(
        SysErrorKind::Unsupported,
        format!("{what}: not in the elevated helper's system (ADR 0023 §11)"),
    )
}

/// No graphics adapters: every call `Unsupported` (ADR 0023 §11, docs/08 acceptance). Names no
/// DXGI and loads nothing.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoGpu;

impl Gpu for NoGpu {
    fn adapters(&self) -> SysResult<Vec<GpuAdapter>> {
        Err(refused("graphics adapters"))
    }
}

/// No CPU topology: `Unsupported`.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoTopology;

impl Topology for NoTopology {
    fn read(&self) -> SysResult<CpuTopology> {
        Err(refused("CPU topology"))
    }
}

/// No registry, read or write: every call `Unsupported` (phase 4, ADR 0023 §1, §11).
#[derive(Debug, Clone, Copy, Default)]
pub struct NoRegistry;

impl Registry for NoRegistry {
    fn key_exists(&self, k: &RegKey) -> SysResult<bool> {
        Err(refused(&k.to_string()))
    }
    fn get(&self, k: &RegKey, _: &str) -> SysResult<Option<RegValue>> {
        Err(refused(&k.to_string()))
    }
    fn values(&self, k: &RegKey) -> SysResult<Vec<(String, RegValue)>> {
        Err(refused(&k.to_string()))
    }
    fn subkeys(&self, k: &RegKey) -> SysResult<Vec<String>> {
        Err(refused(&k.to_string()))
    }
    fn link(&self, k: &RegKey) -> SysResult<Option<RegLink>> {
        Err(refused(&k.to_string()))
    }
}

impl RegistryWrite for NoRegistry {
    fn key_state(&self, k: &RegKey) -> SysResult<KeyState> {
        Err(refused(&k.to_string()))
    }
    fn read(&self, k: &RegKey, _: &str) -> SysResult<Option<RegValue>> {
        Err(refused(&k.to_string()))
    }
    fn create_key(&self, k: &RegKey) -> SysResult<bool> {
        Err(refused(&k.to_string()))
    }
    fn set(&self, k: &RegKey, _: &str, _: Option<&RegValue>, _: &RegValue) -> SysResult<()> {
        Err(refused(&k.to_string()))
    }
    fn delete_value(&self, k: &RegKey, _: &str, _: &RegValue) -> SysResult<()> {
        Err(refused(&k.to_string()))
    }
    fn delete_empty_key(&self, k: &RegKey) -> SysResult<()> {
        Err(refused(&k.to_string()))
    }
    fn flush(&self, _: Hive) -> SysResult<()> {
        Err(refused("registry flush"))
    }
    fn writable(&self) -> SysResult<()> {
        Err(refused("registry write side"))
    }
}

/// No firewall: `Unsupported` (the real helper until P4-5b binds COM in it).
#[derive(Debug, Clone, Copy, Default)]
pub struct NoFirewall;

impl Firewall for NoFirewall {
    fn select(&self, _: &dyn Fn(&str, &str) -> bool) -> SysResult<FwSelection> {
        Err(refused("firewall rules"))
    }
}

#[cfg(test)]
mod tests {
    use super::{HelperSystem, HelperToken, NoFirewall, NoGpu, NoRegistry, NoTopology};
    use crate::sys::registry::{Hive, RegKey, RegView};
    use crate::sys::{Firewall, Gpu, Registry, RegistryWrite, SysErrorKind, Topology};

    #[test]
    fn helper_traits_are_object_safe_send_sync() {
        fn assert_send_sync<T: ?Sized + Send + Sync>() {}
        assert_send_sync::<dyn HelperToken>();
        assert_send_sync::<dyn HelperSystem>();
    }

    #[test]
    fn the_refusing_parts_refuse_everything() {
        let k = RegKey::new(Hive::LocalMachine, RegView::Native, "SOFTWARE");
        let unsupported = |e: crate::sys::SysError| assert_eq!(e.kind, SysErrorKind::Unsupported);
        unsupported(NoGpu.adapters().unwrap_err());
        unsupported(NoTopology.read().unwrap_err());
        unsupported(NoFirewall.select(&|_, _| true).unwrap_err());
        unsupported(NoRegistry.get(&k, "x").unwrap_err());
        unsupported(NoRegistry.key_exists(&k).unwrap_err());
        unsupported(NoRegistry.values(&k).unwrap_err());
        unsupported(NoRegistry.subkeys(&k).unwrap_err());
        unsupported(NoRegistry.link(&k).unwrap_err());
        unsupported(RegistryWrite::read(&NoRegistry, &k, "x").unwrap_err());
        unsupported(NoRegistry.key_state(&k).unwrap_err());
        unsupported(NoRegistry.writable().unwrap_err());
        #[expect(clippy::disallowed_methods, reason = "test: the refusing write side")]
        let flushed = NoRegistry.flush(Hive::LocalMachine);
        unsupported(flushed.unwrap_err());
    }
}
