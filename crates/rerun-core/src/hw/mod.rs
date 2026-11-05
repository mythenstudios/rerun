//! Hardware facts (ADR 0015): the GPU architecture table ([`arch`]) and the OS build
//! ([`os`]).
//!
//! `hw` sits above `sys` and only consumes it: no FFI, no `unsafe`, no serde. Everything it
//! reads is untrusted (driver strings and IDs, an admin-writable `HKLM` value); errors name the
//! source and the kind, never the content.

use std::fmt;

use crate::sys::SysError;

pub mod arch;
pub mod os;

/// The source a [`ProfileError`] is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProfileSource {
    /// The graphics adapters (`sys::Gpu`).
    Gpu,
    /// The CPU topology (`sys::Topology`).
    CpuTopology,
    /// `CurrentBuildNumber` in the registry.
    CurrentBuildNumber,
}

impl fmt::Display for ProfileSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Gpu => "GPU",
            Self::CpuTopology => "CPU topology",
            Self::CurrentBuildNumber => "CurrentBuildNumber",
        })
    }
}

/// Why one part of the profile could not be read. Names the source and the kind, never raw
/// registry or driver content.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ProfileError {
    /// The system layer failed (its error names a key or API, never a value).
    #[error("{0}: {1}")]
    Sys(ProfileSource, SysError),
    /// The value does not exist.
    #[error("{0}: missing")]
    Missing(ProfileSource),
    /// The value exists but has the wrong type or form.
    #[error("{0}: malformed")]
    Malformed(ProfileSource),
}

impl ProfileError {
    /// The source the error is about.
    pub fn origin(&self) -> ProfileSource {
        match self {
            Self::Sys(s, _) | Self::Missing(s) | Self::Malformed(s) => *s,
        }
    }
}
