//! [`WinTopology`]: the real CPU topology (ADR 0010). No `unsafe`: the calls are in `cpu`, the
//! parser in `rerun-proto`.

use rerun_proto::cpu::CpuTopology;

use super::cpu::{self, CallError, MAX_BUFFER};
use super::status::kind_of_win32;
use crate::sys::{SysError, SysErrorKind, SysResult, Topology};

/// winerror.h `ERROR_INSUFFICIENT_BUFFER`.
const ERROR_INSUFFICIENT_BUFFER: u32 = 122;

/// Reads the topology from `GetSystemCpuSetInformation` and
/// `GetLogicalProcessorInformationEx` on every call (CPU Set IDs are runtime values; nothing is
/// cached). A machine whose two sources disagree gets an error naming the failed check, never a
/// best-effort topology.
#[derive(Debug, Default)]
pub struct WinTopology(());

impl WinTopology {
    /// The real topology source.
    pub fn new() -> Self {
        Self(())
    }
}

impl Topology for WinTopology {
    fn read(&self) -> SysResult<CpuTopology> {
        let sets =
            cpu::system_cpu_sets().map_err(|e| call_error("GetSystemCpuSetInformation", e))?;
        let info = cpu::processor_information()
            .map_err(|e| call_error("GetLogicalProcessorInformationEx", e))?;
        CpuTopology::from_windows(&sets, &info)
            .map_err(|e| SysError::new(SysErrorKind::Other, format!("cpu topology: {e}")))
    }
}

/// A failed call as a [`SysError`] with the Win32 code.
fn call_error(api: &str, e: CallError) -> SysError {
    match e {
        CallError::Win32(code) => SysError::new(kind_of_win32(code), api).with_win32(code),
        CallError::TooLarge(len) => SysError::new(
            SysErrorKind::Unsupported,
            format!("{api}: needs {len} bytes, more than {MAX_BUFFER}"),
        )
        .with_win32(ERROR_INSUFFICIENT_BUFFER),
        CallError::Unstable => SysError::new(
            SysErrorKind::Other,
            format!("{api}: the buffer size kept changing"),
        )
        .with_win32(ERROR_INSUFFICIENT_BUFFER),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn call_errors_keep_the_win32_code() {
        let e = call_error("X", CallError::Win32(5));
        assert_eq!((e.kind, e.win32), (SysErrorKind::AccessDenied, Some(5)));
        let e = call_error("X", CallError::TooLarge(MAX_BUFFER + 1));
        assert_eq!(
            (e.kind, e.win32),
            (SysErrorKind::Unsupported, Some(ERROR_INSUFFICIENT_BUFFER))
        );
        let e = call_error("X", CallError::Unstable);
        assert_eq!(
            (e.kind, e.win32),
            (SysErrorKind::Other, Some(ERROR_INSUFFICIENT_BUFFER))
        );
    }
}
