//! System layer: the only way Rerun reads or changes the system.
//!
//! Principles (ADR 0004, ADR 0007):
//! - All traits take `&self`, are `Send + Sync` and object-safe: primitives receive
//!   `&dyn System`.
//! - `sys` is "dumb and honest": no allowlist, no forbidden roots. That is done by
//!   [`crate::policy`] one level above, so the fake and the real system behave the same.
//! - File access is handle-based: [`Fs::open_dir`] is the only absolute operation, everything
//!   else goes through a [`Dir`] handle with a [`crate::path::RelPath`] and never follows
//!   reparse points below the handle.
//! - `sys::fake` emulates Win32 semantics (case handling, error kinds, handle identity). The
//!   contract tests in `sys::contract` check this; they also run against `sys::win`.
//! - `sys::win` (Windows only) is the real file system and registry, **read-only in phase 1**:
//!   every writing `Dir` and `Registry` method returns `Unsupported`; the real known folders;
//!   the real CPU topology (ADR 0010); and the real graphics adapters (DXGI, ADR 0008
//!   amendment). `unsafe` exists only in its modules `nt`, `token`, `reg`, `shell`, `cpu`,
//!   `loader` and `dxgi`.
//!
//! - [`KnownFolders`] never reads environment variables (ADR 0007, ADR 0009).
//!
//! `Firewall` and `Process` arrive in phase 3. The `WinSystem` bundle follows in the next step
//! of phase 1.

mod error;
pub mod fs;
pub mod gpu;
pub mod known_folders;
pub mod registry;
pub mod snapshot;
pub mod topology;

#[cfg(any(test, feature = "fake"))]
pub mod contract;
#[cfg(any(test, feature = "fake"))]
pub mod fake;
#[cfg(windows)]
pub mod win;

pub use error::{SysError, SysErrorKind, SysResult};
pub use fs::{Dir, Fs};
pub use gpu::{DriverVersion, Gpu, GpuAdapter};
pub use known_folders::{KnownFolder, KnownFolders};
pub use registry::Registry;
pub use topology::Topology;

/// Entry point for all system access.
pub trait System: Send + Sync {
    /// File system.
    fn fs(&self) -> &dyn Fs;
    /// Registry.
    fn registry(&self) -> &dyn Registry;
    /// CPU topology.
    fn topology(&self) -> &dyn Topology;
    /// Known folders (Windows, Program Files, profile, …).
    fn known_folders(&self) -> &dyn KnownFolders;
    /// Graphics adapters.
    fn gpu(&self) -> &dyn Gpu;
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
