//! OS build from the registry (ADR 0015).
//!
//! Source: `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion` in the native view, read through
//! the read-only [`Registry::get`] (ADR 0009). `CurrentBuildNumber` must be a `REG_SZ` of ASCII
//! digits without a leading zero, at least 1, fitting `u32`; anything else is
//! [`ProfileError::Malformed`], an absent value [`ProfileError::Missing`]. `UBR` is display
//! only: absent, another type or a read error give `None` and never fail the build.
//!
//! The version APIs (`GetVersion*`, `VerifyVersionInfo*`, `VerSetConditionMask`,
//! `RtlGetVersion`, `RtlVerifyVersionInfo`) are banned in `clippy.toml`: compatibility shims
//! bend their answers. A Windows test cross-checks the build against `RtlGetVersion`.

use std::fmt;

use super::{ProfileError, ProfileSource};
use crate::sys::registry::{Hive, RegKey, RegValue, RegView, Registry};

/// Path of the key below `HKLM`.
pub(crate) const CURRENT_VERSION: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion";
/// Value with the build number (`REG_SZ`).
pub(crate) const BUILD_VALUE: &str = "CurrentBuildNumber";
/// Value with the update build revision (`REG_DWORD`).
pub(crate) const UBR_VALUE: &str = "UBR";

/// The Windows build.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OsBuild {
    /// Build number, e.g. `26100`. The fact `os.build` compares.
    pub build: u32,
    /// Update build revision, e.g. `4061`; for display only, never compared.
    pub ubr: Option<u32>,
}

impl fmt::Display for OsBuild {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.ubr {
            Some(ubr) => write!(f, "{}.{ubr}", self.build),
            None => write!(f, "{}", self.build),
        }
    }
}

/// The key the build is read from.
pub(crate) fn current_version_key() -> RegKey {
    RegKey::new(Hive::LocalMachine, RegView::Native, CURRENT_VERSION)
}

/// Reads the build. A failed read of the key or value is [`ProfileError::Sys`]; the error
/// never carries the registry content.
pub(crate) fn read(registry: &dyn Registry) -> Result<OsBuild, ProfileError> {
    const SOURCE: ProfileSource = ProfileSource::CurrentBuildNumber;
    let key = current_version_key();
    let build = match registry.get(&key, BUILD_VALUE) {
        Err(e) => return Err(ProfileError::Sys(SOURCE, e)),
        Ok(None) => return Err(ProfileError::Missing(SOURCE)),
        Ok(Some(RegValue::String(s))) => parse_build(&s).ok_or(ProfileError::Malformed(SOURCE))?,
        Ok(Some(_)) => return Err(ProfileError::Malformed(SOURCE)),
    };
    let ubr = match registry.get(&key, UBR_VALUE) {
        Ok(Some(RegValue::Dword(ubr))) => Some(ubr),
        _ => None,
    };
    Ok(OsBuild { build, ubr })
}

/// ASCII digits only, no leading zero, at least 1, fitting `u32`.
fn parse_build(s: &str) -> Option<u32> {
    if s.is_empty() || s.starts_with('0') || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

#[cfg(test)]
mod tests;
