//! System layer: the only way Rerun reads or changes the system.
//!
//! Principles (ADR 0004, ADR 0007):
//! - All traits take `&self`, are `Send + Sync` and object-safe: primitives receive
//!   `&dyn System`.
//! - `sys` is "dumb and honest": no allowlist, no forbidden roots. That is done by
//!   [`crate::policy`] one level above, so the fake and the real system behave the same.
//! - File access is handle-based: [`Fs::open_dir`] is the only absolute operation, everything
//!   else goes through a [`Dir`] handle with a [`crate::path::RelPath`] and never follows
//!   reparse points below the handle. Reading and writing are separate capabilities: [`Dir`]
//!   reads, [`DirWrite`] writes direct children of its handle (ADR 0017).
//! - `sys::fake` emulates Win32 semantics (case handling, error kinds, handle identity). The
//!   contract tests in `sys::contract` check this; they also run against `sys::win`.
//! - `sys::win` (Windows only) is the real file system with its write side (ADR 0017) and
//!   the real registry with its write side ([`RegistryWrite`], ADR 0018, reached only through
//!   `policy::registry`); the real known folders;
//!   the real CPU topology (ADR 0010); the real graphics adapters (DXGI, ADR 0008
//!   amendment); and the real firewall rules (read side, COM, ADR 0008 amendment P4-5a). `unsafe`
//!   exists only in its modules `nt`, `token`, `reg`, `shell`, `cpu`, `loader`, `dxgi`,
//!   `elevation`, `com` and `firewall`.
//!
//! - [`KnownFolders`] never reads environment variables (ADR 0007, ADR 0009).
//!
//! `sys::win::WinSystem` bundles the real parts into one [`System`]. [`HelperToken`] is the
//! elevated helper's own token (ADR 0023, P4-2a) and [`HelperSystem`] its system (P4-2c); [`Firewall`] the firewall's read side (ADR 0023
//! §8, P4-5a).

pub mod elevation;
mod error;
pub mod firewall;
pub mod fs;
pub mod gpu;
pub mod helper;
pub mod known_folders;
pub mod registry;
pub mod topology;

#[cfg(any(test, feature = "fake"))]
pub mod contract;
#[cfg(any(test, feature = "fake"))]
pub mod fake;
// The state comparison of the round-trip tests (ADR 0004, test code only like `contract`).
#[cfg(any(test, feature = "fake"))]
pub mod snapshot;
// The write sequences (ADR 0017, A1) over the primitives of `sys::fake` and `sys::win`.
pub(crate) mod seq;
#[cfg(windows)]
pub mod win;

pub use elevation::{
    Elevation, HelperLock, HelperPresence, HelperProc, HelperRun, NoElevation, TokenKind,
};
pub use error::{SysError, SysErrorKind, SysResult, shown_target};
pub use firewall::{Firewall, FirewallWrite, FwRest, FwRule, FwRule3, FwSelection};
pub use fs::{AceFact, Dir, DirWrite, Fs, SdFacts, VolumeGuid, WriteCap};
pub use gpu::{DriverVersion, Gpu, GpuAdapter};
pub use helper::{
    HelperSystem, HelperToken, InstanceLock, NoFirewall, NoGpu, NoRegistry, NoTopology,
};
pub use known_folders::{KnownFolder, KnownFolders};
pub use registry::{Registry, RegistryWrite};
pub use topology::Topology;

/// Entry point for all system access.
pub trait System: Send + Sync {
    /// File system.
    fn fs(&self) -> &dyn Fs;
    /// Registry, read side.
    fn registry(&self) -> &dyn Registry;
    /// Registry, write side (ADR 0018): a `clippy.toml` ban outside `policy::registry`, like
    /// `Fs::open_dir` outside `policy::root`.
    fn registry_write(&self) -> &dyn RegistryWrite;
    /// CPU topology.
    fn topology(&self) -> &dyn Topology;
    /// Known folders (Windows, Program Files, profile, …).
    fn known_folders(&self) -> &dyn KnownFolders;
    /// Graphics adapters.
    fn gpu(&self) -> &dyn Gpu;
    /// Windows Firewall, read side (ADR 0023 §8 outcome A, §12; P4-5a): one enumeration per
    /// call. The write side is the elevated helper's alone (P4-5b).
    fn firewall(&self) -> &dyn Firewall;
    /// Elevation, CLI side: the token kind and the one start of the elevated helper (ADR 0023
    /// §12). The helper's own system refuses it (`NoElevation`, §11).
    fn elevation(&self) -> &dyn Elevation;
}

#[cfg(test)]
mod tests {
    use super::System;

    // Compile test: `System` must be usable as a trait object.
    fn _object_safe(_: &dyn System) {}

    #[test]
    fn system_is_send_and_sync_as_trait_object() {
        fn assert_send_sync<T: ?Sized + Send + Sync>() {}
        assert_send_sync::<dyn System>();
        assert_send_sync::<dyn super::Dir>();
    }
}
