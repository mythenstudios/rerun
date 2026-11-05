//! GPU part of the system profile (ADR 0015, `docs/03b-gpu-display.md`).
//!
//! Only hardware adapters count, in DXGI order: an adapter with the software flag **or** the
//! Microsoft vendor ID `0x1414` is dropped (CI runners list the Basic Render Driver without the
//! flag). The first remaining one is [`GpuProfile::primary`], the adapter `when` conditions are
//! evaluated against in step 15. Vendor from the PCI vendor ID; architecture and `integrated`
//! from the table by `(vendor, device)`; revision and subsystem IDs are never consulted.

use std::fmt;

use super::arch::{ArchId, GpuArchTable, VENDOR_AMD, VENDOR_INTEL, VENDOR_NVIDIA};
use super::{ProfileError, ProfileSource};
use crate::sys::{Gpu, GpuAdapter};

/// PCI vendor ID of Microsoft (Basic Render Driver, WARP).
pub const VENDOR_MICROSOFT: u32 = 0x1414;

/// GPU vendor, from the PCI vendor ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GpuVendor {
    /// `0x1002`
    Amd,
    /// `0x10DE`
    Nvidia,
    /// `0x8086`
    Intel,
    /// Any other vendor ID (e.g. Qualcomm `0x5143`). Matches no `gpu.vendor` value yet.
    Other(u32),
}

impl GpuVendor {
    /// From a PCI vendor ID.
    pub fn from_id(vendor_id: u32) -> Self {
        match vendor_id {
            VENDOR_AMD => Self::Amd,
            VENDOR_NVIDIA => Self::Nvidia,
            VENDOR_INTEL => Self::Intel,
            other => Self::Other(other),
        }
    }

    /// The PCI vendor ID.
    pub fn id(self) -> u32 {
        match self {
            Self::Amd => VENDOR_AMD,
            Self::Nvidia => VENDOR_NVIDIA,
            Self::Intel => VENDOR_INTEL,
            Self::Other(id) => id,
        }
    }
}

impl fmt::Display for GpuVendor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Amd => f.write_str("AMD"),
            Self::Nvidia => f.write_str("NVIDIA"),
            Self::Intel => f.write_str("Intel"),
            Self::Other(id) => write!(f, "vendor {id:#06x}"),
        }
    }
}

/// GPU architecture of one adapter.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum GpuArch {
    /// From the table entry covering the device.
    Known(ArchId),
    /// No table, or no entry for the device: never a `gpu.arch` value.
    Unknown,
}

/// A hardware adapter with what the table says about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GpuEntry {
    /// Raw DXGI data (`sys::gpu`).
    pub adapter: GpuAdapter,
    /// Vendor from `adapter.vendor_id`.
    pub vendor: GpuVendor,
    /// Architecture from the table.
    pub arch: GpuArch,
    /// From the table entry, not guessed from memory; `None` without an entry.
    pub integrated: Option<bool>,
}

impl GpuEntry {
    /// Builds the entry for `adapter`, looked up in `table` if one is given.
    pub(crate) fn new(adapter: GpuAdapter, table: Option<&GpuArchTable>) -> Self {
        let found = table.and_then(|t| t.lookup(adapter.vendor_id, adapter.device_id));
        Self {
            vendor: GpuVendor::from_id(adapter.vendor_id),
            arch: found.map_or(GpuArch::Unknown, |e| GpuArch::Known(e.arch.clone())),
            integrated: found.map(|e| e.integrated),
            adapter,
        }
    }

    /// Dedicated video memory in MiB (rounded down). For display; not a `when` key yet.
    pub fn vram_mb(&self) -> u64 {
        self.adapter.dedicated_video_memory >> 20
    }
}

/// The hardware adapters, in DXGI order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GpuProfile {
    /// Hardware adapters only: software adapters and vendor `0x1414` dropped.
    pub adapters: Vec<GpuEntry>,
}

impl GpuProfile {
    /// Keeps the hardware adapters of `adapters` in their order.
    pub(crate) fn new(adapters: Vec<GpuAdapter>, table: Option<&GpuArchTable>) -> Self {
        Self {
            adapters: adapters
                .into_iter()
                .filter(is_hardware)
                .map(|a| GpuEntry::new(a, table))
                .collect(),
        }
    }

    /// The conditions adapter: the first hardware adapter in DXGI order.
    pub fn primary(&self) -> Option<&GpuEntry> {
        self.adapters.first()
    }
}

/// Not a software adapter and not Microsoft's (the Basic Render Driver comes without the
/// software flag on CI runners).
fn is_hardware(a: &GpuAdapter) -> bool {
    !a.software && a.vendor_id != VENDOR_MICROSOFT
}

/// Reads the adapters.
pub(crate) fn read(
    gpu: &dyn Gpu,
    table: Option<&GpuArchTable>,
) -> Result<GpuProfile, ProfileError> {
    gpu.adapters()
        .map(|a| GpuProfile::new(a, table))
        .map_err(|e| ProfileError::Sys(ProfileSource::Gpu, e))
}
