//! Fake topology from fixtures.

use rerun_proto::cpu::CpuTopology;

use crate::sys::{SysError, SysErrorKind, SysResult, Topology};

/// Returns a fixed topology.
#[derive(Debug, Clone, Default)]
pub struct FakeTopology {
    topology: CpuTopology,
}

impl FakeTopology {
    /// Fixed topology.
    pub fn new(topology: CpuTopology) -> Self {
        Self { topology }
    }

    /// From a JSON fixture (serialized [`CpuTopology`]).
    pub fn from_json(json: &str) -> SysResult<Self> {
        serde_json::from_str(json)
            .map(Self::new)
            .map_err(|e| SysError::new(SysErrorKind::Other, format!("cpu fixture: {e}")))
    }
}

impl Topology for FakeTopology {
    fn read(&self) -> SysResult<CpuTopology> {
        Ok(self.topology.clone())
    }
}
