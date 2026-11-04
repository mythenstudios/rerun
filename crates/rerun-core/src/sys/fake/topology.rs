//! Fake topology from fixtures.
//!
//! Every topology the fake hands out has passed [`CpuTopology::validate`], like the output of
//! the real parser (ADR 0010). A fake without a configured topology fails `read` instead of
//! returning an empty one, which no real machine reports.

use rerun_proto::cpu::CpuTopology;

use crate::sys::{SysError, SysErrorKind, SysResult, Topology};

/// Returns a fixed, validated topology.
#[derive(Debug, Clone, Default)]
pub struct FakeTopology {
    topology: Option<CpuTopology>,
}

impl FakeTopology {
    /// Fixed topology; `Other` if it violates an invariant.
    pub fn new(topology: CpuTopology) -> SysResult<Self> {
        topology
            .validate()
            .map_err(|e| SysError::new(SysErrorKind::Other, format!("cpu fixture: {e}")))?;
        Ok(Self {
            topology: Some(topology),
        })
    }

    /// From a JSON fixture (serialized [`CpuTopology`]); `Other` if it does not parse or
    /// violates an invariant.
    pub fn from_json(json: &str) -> SysResult<Self> {
        let topology = serde_json::from_str(json)
            .map_err(|e| SysError::new(SysErrorKind::Other, format!("cpu fixture: {e}")))?;
        Self::new(topology)
    }
}

impl Topology for FakeTopology {
    fn read(&self) -> SysResult<CpuTopology> {
        self.topology.clone().ok_or_else(|| {
            SysError::new(
                SysErrorKind::Unsupported,
                "fake topology: none configured (FakeSystemBuilder::topology)",
            )
        })
    }
}
