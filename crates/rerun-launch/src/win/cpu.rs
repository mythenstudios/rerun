//! `rerun-launch`'s copy of the two topology calls (ADR 0010; the original is
//! `rerun_core::sys::win::cpu`, the shim does not depend on `rerun-core`, ADR 0006).
//!
//! - `GetSystemCpuSetInformation(Process = NULL, Flags = 0)`: the CPU Sets of the system,
//!   never filtered by the shim's own affinity (a job Steam holds the shim in must not shrink
//!   the topology).
//! - `GetLogicalProcessorInformationEx(RelationAll)`: one call.
//!
//! Size query, then a `u64`-aligned buffer, at most [`RETRIES`] sized calls while Windows
//! reports `ERROR_INSUFFICIENT_BUFFER`, capped at [`MAX_BUFFER`]; only the returned length goes
//! to the parser. The parser reads the x64 layout, so this module exists in 64-bit builds only;
//! a 32-bit shim reports the topology as unsupported (ADR 0010: "`compile_error!` or a runtime
//! `Unsupported`"; the runtime form keeps the CI's i686 clippy run of the shim building).

#![allow(
    unsafe_code,
    reason = "FFI to the two kernel32 topology APIs (ADR 0010); every block has a SAFETY \
              comment"
)]

use std::ptr;

use rerun_proto::cpu::CpuTopology;
use rerun_proto::cpu::parse::MAX_BUFFER;
use windows_sys::Win32::Foundation::ERROR_INSUFFICIENT_BUFFER;
use windows_sys::Win32::System::SystemInformation::{
    GetLogicalProcessorInformationEx, GetSystemCpuSetInformation, RelationAll,
    SYSTEM_CPU_SET_INFORMATION, SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX,
};

use super::last_error;
use crate::os::OsError;

/// Sized calls after the size query.
const RETRIES: usize = 4;

/// A zeroed buffer of at least `len` bytes, aligned to 8 (the alignment of both structures).
struct Aligned(Vec<u64>);

impl Aligned {
    fn new(len: usize) -> Self {
        Self(vec![0; len.div_ceil(8)])
    }

    /// Null for an empty buffer (the size query), else the start of the buffer.
    fn ptr<T>(&mut self) -> *mut T {
        if self.0.is_empty() {
            ptr::null_mut()
        } else {
            self.0.as_mut_ptr().cast()
        }
    }

    fn into_bytes(self, len: usize) -> Vec<u8> {
        self.0
            .iter()
            .flat_map(|w| w.to_ne_bytes())
            .take(len)
            .collect()
    }
}

/// Size query, then at most [`RETRIES`] sized calls. `call(buffer, capacity)` returns
/// `(succeeded, returned length, last error)`.
fn sized(mut call: impl FnMut(&mut Aligned, u32) -> (bool, u32, u32)) -> Result<Vec<u8>, OsError> {
    let mut cap: u32 = 0;
    for _ in 0..=RETRIES {
        let len = usize::try_from(cap).map_err(|_| OsError::Unsupported)?;
        let mut buf = Aligned::new(len);
        let (ok, returned, code) = call(&mut buf, cap);
        let returned_len = usize::try_from(returned).unwrap_or(usize::MAX);
        if ok {
            if returned_len > len {
                return Err(OsError::Win32(ERROR_INSUFFICIENT_BUFFER));
            }
            return Ok(buf.into_bytes(returned_len));
        }
        if code != ERROR_INSUFFICIENT_BUFFER {
            return Err(OsError::Win32(code));
        }
        if returned_len > MAX_BUFFER {
            return Err(OsError::Unsupported);
        }
        if returned <= cap {
            return Err(OsError::Win32(code));
        }
        cap = returned;
    }
    Err(OsError::Win32(ERROR_INSUFFICIENT_BUFFER))
}

fn system_cpu_sets() -> Result<Vec<u8>, OsError> {
    sized(|buf, cap| {
        let mut returned: u32 = 0;
        let info = buf.ptr::<SYSTEM_CPU_SET_INFORMATION>();
        #[expect(
            clippy::disallowed_methods,
            reason = "rerun-launch's one GetSystemCpuSetInformation call site (ADR 0010)"
        )]
        // SAFETY: `info` is null with `cap == 0` (the documented size query) or points to a
        // writable, 8-aligned buffer of at least `cap` bytes (`Aligned::new(cap)`) that `buf`
        // keeps alive for the call; the API writes at most `cap` bytes. `returned` is a valid
        // u32 for a write. A null process handle asks for the system's CPU Sets; flags 0.
        let ok =
            unsafe { GetSystemCpuSetInformation(info, cap, &mut returned, ptr::null_mut(), 0) };
        let code = if ok == 0 { last_error() } else { 0 };
        (ok != 0, returned, code)
    })
}

fn processor_information() -> Result<Vec<u8>, OsError> {
    sized(|buf, cap| {
        let mut returned: u32 = cap;
        let info = buf.ptr::<SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX>();
        #[expect(
            clippy::disallowed_methods,
            reason = "rerun-launch's one GetLogicalProcessorInformationEx call site (ADR 0010)"
        )]
        // SAFETY: `info` is null with `returned == 0` (the size query) or points to a writable,
        // 8-aligned buffer of at least `cap` bytes (`Aligned::new(cap)`) that `buf` keeps alive
        // for the call; `returned` holds that capacity on input, so the API writes at most
        // `cap` bytes, and is a valid u32 for the write of the result.
        let ok = unsafe { GetLogicalProcessorInformationEx(RelationAll, info, &mut returned) };
        let code = if ok == 0 { last_error() } else { 0 };
        (ok != 0, returned, code)
    })
}

/// The live topology, parsed and validated by `rerun-proto`.
pub(super) fn topology() -> Result<CpuTopology, OsError> {
    let sets = system_cpu_sets()?;
    let info = processor_information()?;
    CpuTopology::from_windows(&sets, &info).map_err(OsError::Topology)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sized_is_bounded() {
        let mut calls = 0;
        let r = sized(|_, cap| {
            calls += 1;
            (false, cap + 8, ERROR_INSUFFICIENT_BUFFER)
        });
        assert_eq!(r, Err(OsError::Win32(ERROR_INSUFFICIENT_BUFFER)));
        assert_eq!(calls, RETRIES + 1);
        let max = u32::try_from(MAX_BUFFER).unwrap();
        assert_eq!(
            sized(|_, _| (false, max + 1, ERROR_INSUFFICIENT_BUFFER)),
            Err(OsError::Unsupported)
        );
        assert_eq!(sized(|_, _| (false, 0, 5)), Err(OsError::Win32(5)));
        assert_eq!(
            sized(|_, cap| if cap == 0 {
                (false, 16, ERROR_INSUFFICIENT_BUFFER)
            } else {
                (true, 16, 0)
            })
            .map(|b| b.len()),
            Ok(16)
        );
    }

    /// Read-only: the real calls give a valid topology (as `rerun-core`'s contract test).
    #[test]
    fn the_real_topology_parses() {
        let t = topology().unwrap();
        assert!(t.logical_count() > 0);
        t.validate().unwrap();
    }
}
