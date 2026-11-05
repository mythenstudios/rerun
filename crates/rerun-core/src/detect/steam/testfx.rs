//! Test fixtures for `detect::steam`: a fake Windows layout with Rerun's install folder (as in
//! the `policy::root` tests) and builders for the registry values and Steam files. Every path,
//! name and ID is invented (`docs/09-testing.md`, VDF fixtures).

use std::path::Path;

use super::root::RootSource;
use crate::policy::root::ForbiddenRoots;
use crate::sys::fake::{FakeSystem, FakeSystemBuilder};
use crate::sys::registry::RegValue;

/// Rerun's install folder in the fake layout.
pub(super) const INSTALL: &str = r"C:\Users\Player\AppData\Local\Programs\Rerun";

/// The fake Windows layout with the install folder.
pub(super) fn base() -> FakeSystemBuilder {
    FakeSystem::builder().windows_layout().dir(INSTALL)
}

/// The resolved forbidden list of `sys`.
pub(super) fn fr(sys: &FakeSystem) -> ForbiddenRoots {
    ForbiddenRoots::resolve(sys, Path::new(INSTALL)).unwrap_or_else(|e| panic!("{e}"))
}

/// Extension of the builder for Steam fixtures.
pub(super) trait SteamFixture: Sized {
    /// Sets the value of a registry candidate.
    fn candidate(self, source: RootSource, value: RegValue) -> Self;

    /// Sets a registry candidate to a `REG_SZ` path.
    fn candidate_path(self, source: RootSource, path: &str) -> Self {
        self.candidate(source, RegValue::String(path.to_owned()))
    }
}

impl SteamFixture for FakeSystemBuilder {
    fn candidate(self, source: RootSource, value: RegValue) -> Self {
        self.value(source.key(), source.value_name(), value)
    }
}
