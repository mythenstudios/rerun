//! System layer: the only way Rerun reads or changes the system.
//!
//! Principles (ADR 0004):
//! - All traits take `&self`, are `Send + Sync` and object-safe: primitives receive
//!   `&dyn System`.
//! - `sys` is "dumb and honest": no confinement, no allowlist. That is done by
//!   [`crate::policy`] one level above, so the fake and the real system behave the same.
//! - `sys::fake` emulates Win32 semantics (case handling, error kinds). The contract tests
//!   in `sys::contract` check this; from phase 1/2 they also run against `sys::win` in
//!   Windows Sandbox.
//!
//! `Firewall` and `Process` arrive in phase 3, `sys::win` from phase 1.

mod error;
pub mod fs;
pub mod registry;
pub mod snapshot;
pub mod topology;

#[cfg(any(test, feature = "fake"))]
pub mod contract;
#[cfg(any(test, feature = "fake"))]
pub mod fake;

pub use error::{SysError, SysErrorKind, SysResult};
pub use fs::Fs;
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
    }
}
