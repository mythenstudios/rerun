//! Graphics adapters.
//!
//! The real implementation (`sys::win`) enumerates DXGI adapters (`IDXGIFactory1::
//! EnumAdapters1`, ADR 0008). It is only reachable from non-elevated code (ADR 0008, H2).
//! Raw data only: mapping vendor and device IDs to a vendor or architecture is done by `hw`.

use std::fmt;

use super::SysResult;

/// Longest adapter name DXGI can report (`DXGI_ADAPTER_DESC1::Description`, UTF-16 units
/// including the terminating NUL).
pub const MAX_NAME_UTF16: usize = 128;

/// Version of the user-mode driver, `a.b.c.d` as Windows shows it in the device manager.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DriverVersion(pub [u16; 4]);

impl DriverVersion {
    /// From the 64-bit value DXGI reports (`CheckInterfaceSupport`), most significant part
    /// first.
    pub fn from_u64(v: u64) -> Self {
        let part = |shift: u32| u16::try_from((v >> shift) & 0xFFFF).unwrap_or(u16::MAX);
        Self([part(48), part(32), part(16), part(0)])
    }
}

impl fmt::Display for DriverVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [a, b, c, d] = self.0;
        write!(f, "{a}.{b}.{c}.{d}")
    }
}

/// One graphics adapter, as DXGI describes it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GpuAdapter {
    /// Name from the driver, e.g. `AMD Radeon RX 9070 XT`.
    pub name: String,
    /// PCI vendor ID (`0x1002` AMD, `0x10DE` NVIDIA, `0x8086` Intel, `0x1414` Microsoft).
    pub vendor_id: u32,
    /// PCI device ID.
    pub device_id: u32,
    /// PCI subsystem ID.
    pub subsys_id: u32,
    /// PCI revision.
    pub revision: u32,
    /// Locally unique ID, valid until the next reboot. Distinguishes two identical cards.
    pub luid: u64,
    /// Dedicated video memory in bytes.
    pub dedicated_video_memory: u64,
    /// System memory the adapter may use, in bytes.
    pub shared_system_memory: u64,
    /// Software adapter (`DXGI_ADAPTER_FLAG_SOFTWARE`, e.g. Microsoft Basic Render Driver).
    pub software: bool,
    /// Version of the user-mode driver; `None` if the driver does not report it.
    pub umd_version: Option<DriverVersion>,
}

/// Enumerates graphics adapters.
pub trait Gpu: Send + Sync {
    /// All adapters in DXGI order: the first one drives the primary display. Software
    /// adapters are included and flagged.
    fn adapters(&self) -> SysResult<Vec<GpuAdapter>>;
}

#[cfg(test)]
mod tests {
    use super::DriverVersion;

    #[test]
    fn driver_version_from_dxgi_value() {
        let v = DriverVersion::from_u64(0x0020_0000_5209_0009);
        assert_eq!(v, DriverVersion([32, 0, 21001, 9]));
        assert_eq!(v.to_string(), "32.0.21001.9");
        assert_eq!(
            DriverVersion::from_u64(u64::MAX),
            DriverVersion([u16::MAX; 4])
        );
    }

    #[test]
    fn driver_versions_order_by_part() {
        assert!(DriverVersion([31, 9, 0, 0]) < DriverVersion([32, 0, 0, 0]));
        assert!(DriverVersion([32, 0, 1, 0]) < DriverVersion([32, 0, 1, 1]));
    }
}
