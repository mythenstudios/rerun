//! Fake graphics adapters.

use crate::sys::{Gpu, GpuAdapter, SysError, SysErrorKind, SysResult};

/// Returns a fixed list of adapters, or a fixed error (DXGI unavailable). The default has no
/// adapters, which a real machine never reports; tests that need one add it via
/// [`FakeSystemBuilder::gpu`](super::FakeSystemBuilder::gpu).
#[derive(Debug, Clone, Default)]
pub struct FakeGpu {
    adapters: Vec<GpuAdapter>,
    error: Option<SysErrorKind>,
}

impl FakeGpu {
    /// Appends an adapter.
    pub fn push(&mut self, adapter: GpuAdapter) {
        self.adapters.push(adapter);
    }

    /// From now on [`Gpu::adapters`] fails with `kind`.
    pub fn fail_with(&mut self, kind: SysErrorKind) {
        self.error = Some(kind);
    }
}

impl Gpu for FakeGpu {
    fn adapters(&self) -> SysResult<Vec<GpuAdapter>> {
        match self.error {
            Some(kind) => Err(SysError::new(kind, "gpu adapters")),
            None => Ok(self.adapters.clone()),
        }
    }
}
