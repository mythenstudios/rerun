//! System profile (ADR 0015): the facts the `when` keys `gpu.vendor`, `gpu.arch`,
//! `gpu.integrated`, `gpu.hybrid`, `cpu.threads`, `cpu.hybrid` and `os.build` are evaluated
//! against (phase 4), and what `rerun system` shows.
//!
//! - [`read`] builds a [`SystemProfile`] and never fails as a whole: GPU ([`gpu`]), CPU
//!   (`sys::Topology`) and OS ([`os`]) are read independently, each a `Result`.
//! - [`arch`]: the GPU architecture table that maps PCI IDs to an architecture.
//! - The accessors turn the parts into facts; a fact that could not be read is `Unavailable`
//!   (a condition on it is `Unknown`), a missing adapter `NoAdapter` and an unknown device
//!   `Unknown` (both `No`). The per-adapter GPU facts come one entry per hardware adapter
//!   ([`SystemProfile::gpu_facts`], P4-11, ADR 0015 amendment): `when` checks its GPU keys on
//!   each of them.
//!
//! `hw` sits above `sys` and only consumes it: no FFI, no `unsafe`, no serde. Everything it
//! reads is untrusted (driver strings and IDs, an admin-writable `HKLM` value); errors name the
//! source and the kind, never the content. A profile never authorises anything: the elevated
//! helper never builds one and never evaluates `when`.

use std::fmt;

use crate::sys::{SysError, System};

pub mod arch;
pub mod gpu;
pub mod os;
pub mod sac;

pub use arch::{ArchId, GpuArchTable};
pub use gpu::{GpuArch, GpuEntry, GpuProfile, GpuVendor};
pub use os::OsBuild;
/// The CPU topology type of [`SystemProfile::cpu`], re-exported so output layers need no
/// direct dependency on `rerun-proto` (ADR 0016 amendment).
pub use rerun_proto::cpu::CpuTopology;
pub use sac::SacState;

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

/// The system profile: three independently read parts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemProfile {
    /// Hardware graphics adapters.
    pub gpu: Result<GpuProfile, ProfileError>,
    /// CPU topology (system-wide, `RealTime`/`Allocated` CPU Sets excluded, ADR 0010).
    pub cpu: Result<CpuTopology, ProfileError>,
    /// Windows build.
    pub os: Result<OsBuild, ProfileError>,
    /// Smart App Control (P4-10): `laa_patch` is planned with a warning while it is not off
    /// (P4-13).
    pub sac: SacState,
    /// Whether an architecture table was given: without one `gpu.arch` and `gpu.integrated` are `Unavailable`.
    has_table: bool,
}

/// The `gpu.vendor` fact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VendorFact {
    /// The adapters could not be read.
    Unavailable,
    /// No hardware adapter.
    NoAdapter,
    /// Vendor of the primary adapter.
    Known(GpuVendor),
}

/// The `gpu.arch` fact.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ArchFact {
    /// The adapters could not be read, or no table was given.
    Unavailable,
    /// No hardware adapter.
    NoAdapter,
    /// The table has no entry for the primary adapter.
    Unknown,
    /// Architecture of the primary adapter.
    Known(ArchId),
}

/// The `gpu.integrated` fact of one adapter (P4-11).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IntegratedFact {
    /// The adapters could not be read, or no table was given.
    Unavailable,
    /// No hardware adapter.
    NoAdapter,
    /// The table has no entry for the adapter.
    Unknown,
    /// From the adapter's table entry.
    Known(bool),
}

/// The GPU facts of one hardware adapter, or of the one stand-in entry when the adapters could
/// not be read (every fact `Unavailable`) or there is none (every fact `NoAdapter`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GpuFacts {
    /// `gpu.vendor`.
    pub vendor: VendorFact,
    /// `gpu.arch`.
    pub arch: ArchFact,
    /// `gpu.integrated`.
    pub integrated: IntegratedFact,
}

/// A plain fact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Fact<T> {
    /// Read.
    Known(T),
    /// Could not be read.
    Unavailable,
}

/// Reads the profile. `table` is the architecture table the Topos are validated with (the
/// built-in one until the phase 4 index); `None` makes `gpu.arch` and `gpu.integrated` `Unavailable`.
pub fn read(sys: &dyn System, table: Option<&GpuArchTable>) -> SystemProfile {
    SystemProfile {
        gpu: gpu::read(sys.gpu(), table),
        cpu: sys
            .topology()
            .read()
            .map_err(|e| ProfileError::Sys(ProfileSource::CpuTopology, e)),
        os: os::read(sys.registry()),
        sac: sac::read(sys.registry()),
        has_table: table.is_some(),
    }
}

impl SystemProfile {
    /// The GPU facts, one entry per hardware adapter in DXGI order (P4-11). Never empty: when
    /// the adapters could not be read one entry with every fact `Unavailable`, without a
    /// hardware adapter one with every fact `NoAdapter`. Per adapter the checks run in the
    /// order of ADR 0015 ("Facts"): no table, then no table entry.
    pub fn gpu_facts(&self) -> Vec<GpuFacts> {
        let g = match &self.gpu {
            Err(_) => {
                return vec![GpuFacts {
                    vendor: VendorFact::Unavailable,
                    arch: ArchFact::Unavailable,
                    integrated: IntegratedFact::Unavailable,
                }];
            }
            Ok(g) => g,
        };
        if g.adapters.is_empty() {
            return vec![GpuFacts {
                vendor: VendorFact::NoAdapter,
                arch: ArchFact::NoAdapter,
                integrated: IntegratedFact::NoAdapter,
            }];
        }
        g.adapters.iter().map(|e| self.facts_of(e)).collect()
    }

    fn facts_of(&self, e: &GpuEntry) -> GpuFacts {
        let (arch, integrated) = if self.has_table {
            (
                match &e.arch {
                    GpuArch::Known(id) => ArchFact::Known(id.clone()),
                    GpuArch::Unknown => ArchFact::Unknown,
                },
                e.integrated
                    .map_or(IntegratedFact::Unknown, IntegratedFact::Known),
            )
        } else {
            (ArchFact::Unavailable, IntegratedFact::Unavailable)
        };
        GpuFacts {
            vendor: VendorFact::Known(e.vendor),
            arch,
            integrated,
        }
    }

    /// `gpu.hybrid` (P4-11, user decision E-G1 c): at least two hardware adapters. Not whether
    /// one is integrated, not Windows' adapter order; an iGPU next to a dGPU on a desktop
    /// counts as well (a game can land on either).
    pub fn gpu_hybrid(&self) -> Fact<bool> {
        match &self.gpu {
            Ok(g) => Fact::Known(g.hybrid()),
            Err(_) => Fact::Unavailable,
        }
    }

    /// Logical processors available to games, system-wide (never Rerun's own affinity).
    pub fn cpu_threads(&self) -> Fact<u32> {
        match &self.cpu {
            Ok(t) => u32::try_from(t.logical_count()).map_or(Fact::Unavailable, Fact::Known),
            Err(_) => Fact::Unavailable,
        }
    }

    /// Windows reports more than one efficiency class (not "Intel P/E-cores").
    pub fn cpu_hybrid(&self) -> Fact<bool> {
        match &self.cpu {
            Ok(t) => Fact::Known(t.is_hybrid()),
            Err(_) => Fact::Unavailable,
        }
    }

    /// The Windows build number.
    pub fn os_build(&self) -> Fact<u32> {
        match &self.os {
            Ok(b) => Fact::Known(b.build),
            Err(_) => Fact::Unavailable,
        }
    }
}

#[cfg(test)]
pub(crate) mod tests;
