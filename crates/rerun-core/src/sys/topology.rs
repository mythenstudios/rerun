//! CPU topology trait.

use rerun_proto::cpu::CpuTopology;

use super::SysResult;

/// Reads the CPU topology (real: `GetSystemCpuSetInformation`, fake: fixture).
pub trait Topology: Send + Sync {
    /// Current topology.
    fn read(&self) -> SysResult<CpuTopology>;
}
