//! The only calls to `GetSystemCpuSetInformation` and `GetLogicalProcessorInformationEx`
//! (ADR 0010). FFI only: the bytes go unchanged to the safe parser in `rerun-proto`
//! (`CpuTopology::from_windows`); `topology` turns errors into `SysError`.
//!
//! - `GetSystemCpuSetInformation` with `Process = NULL` and `Flags = 0`: the CPU Sets of the
//!   system, never filtered by Rerun's own affinity (the topology is a machine property).
//! - `GetLogicalProcessorInformationEx(RelationAll)`: one call, so cores, caches and groups
//!   come from the same snapshot.
//!
//! Each call is a size query (null buffer), then a `u64`-aligned buffer of the reported size,
//! retried at most [`RETRIES`] times while Windows reports `ERROR_INSUFFICIENT_BUFFER` (a
//! processor added in between), capped at [`MAX_BUFFER`]. Only the returned length is handed
//! on. Both functions are `clippy.toml` bans everywhere else.

#![allow(
    unsafe_code,
    reason = "FFI to the two kernel32 topology APIs (ADR 0010); every block has a SAFETY \
              comment"
)]

use std::ptr;

use windows_sys::Win32::Foundation::ERROR_INSUFFICIENT_BUFFER;
use windows_sys::Win32::System::SystemInformation::{
    GetLogicalProcessorInformationEx, GetSystemCpuSetInformation, RelationAll,
    SYSTEM_CPU_SET_INFORMATION, SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX,
};

/// Largest buffer accepted from either call: the parser's own cap.
pub(super) use rerun_proto::cpu::parse::MAX_BUFFER;
/// Sized calls after the size query.
pub(super) const RETRIES: usize = 4;

/// A failed topology call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CallError {
    /// The call failed with this Win32 error code.
    Win32(u32),
    /// The call needs a buffer of this many bytes, more than [`MAX_BUFFER`].
    TooLarge(usize),
    /// Still `ERROR_INSUFFICIENT_BUFFER` after [`RETRIES`] sized calls.
    Unstable,
}

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

    /// The first `len` bytes (`len` ≤ capacity, checked by the caller).
    fn into_bytes(self, len: usize) -> Vec<u8> {
        self.0
            .iter()
            .flat_map(|w| w.to_ne_bytes())
            .take(len)
            .collect()
    }
}

/// One call: `(succeeded, returned length, last error right after the call)`.
type Outcome = (bool, u32, u32);

/// Size query, then at most [`RETRIES`] sized calls. `call(buffer, capacity)` makes the API
/// call into `buffer` (null for capacity 0) of `capacity` bytes.
fn sized(mut call: impl FnMut(&mut Aligned, u32) -> Outcome) -> Result<Vec<u8>, CallError> {
    let mut cap: u32 = 0;
    for _ in 0..=RETRIES {
        let len = usize::try_from(cap).map_err(|_| CallError::TooLarge(usize::MAX))?;
        let mut buf = Aligned::new(len);
        let (ok, returned, code) = call(&mut buf, cap);
        let returned_len = usize::try_from(returned).unwrap_or(usize::MAX);
        if ok {
            // Windows never reports more than the buffer it was given; refuse if it does.
            if returned_len > len {
                return Err(CallError::Win32(ERROR_INSUFFICIENT_BUFFER));
            }
            return Ok(buf.into_bytes(returned_len));
        }
        if code != ERROR_INSUFFICIENT_BUFFER {
            return Err(CallError::Win32(code));
        }
        if returned_len > MAX_BUFFER {
            return Err(CallError::TooLarge(returned_len));
        }
        // No progress (the size did not grow) would loop forever on a broken API.
        if returned <= cap {
            return Err(CallError::Win32(code));
        }
        cap = returned;
    }
    Err(CallError::Unstable)
}

/// The last Win32 error of this thread (read right after a failed call).
fn last_error() -> u32 {
    std::io::Error::last_os_error()
        .raw_os_error()
        .map_or(0, i32::cast_unsigned)
}

/// The bytes of `GetSystemCpuSetInformation(Process = NULL, Flags = 0)`.
pub(super) fn system_cpu_sets() -> Result<Vec<u8>, CallError> {
    sized(|buf, cap| {
        let mut returned: u32 = 0;
        let info = buf.ptr::<SYSTEM_CPU_SET_INFORMATION>();
        #[expect(
            clippy::disallowed_methods,
            reason = "the one GetSystemCpuSetInformation call site (ADR 0010)"
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

/// The bytes of `GetLogicalProcessorInformationEx(RelationAll)`.
pub(super) fn processor_information() -> Result<Vec<u8>, CallError> {
    sized(|buf, cap| {
        let mut returned: u32 = cap;
        let info = buf.ptr::<SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX>();
        #[expect(
            clippy::disallowed_methods,
            reason = "the one GetLogicalProcessorInformationEx call site (ADR 0010)"
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

#[cfg(test)]
mod tests {
    use std::mem::{offset_of, size_of};

    use rerun_proto::cpu::parse::{self, layout as l};
    use windows_sys::Win32::System::SystemInformation::{
        CACHE_RELATIONSHIP, CacheData, CacheUnified, CpuSetInformation, GROUP_AFFINITY,
        GROUP_RELATIONSHIP, PROCESSOR_GROUP_INFO, PROCESSOR_RELATIONSHIP, RelationCache,
        RelationGroup, RelationProcessorCore, SYSTEM_CPU_SET_INFORMATION,
        SYSTEM_CPU_SET_INFORMATION_0_0, SYSTEM_CPU_SET_INFORMATION_ALLOCATED,
        SYSTEM_CPU_SET_INFORMATION_REALTIME, SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX,
    };

    use super::*;

    /// The parser's offsets (64-bit layout, ADR 0010) are the `windows-sys` structures'.
    #[test]
    fn parser_offsets_match_windows_sys() {
        type Cs = SYSTEM_CPU_SET_INFORMATION_0_0;
        assert_eq!(
            size_of::<SYSTEM_CPU_SET_INFORMATION>(),
            l::CPU_SET_STRUCT_SIZE
        );
        assert_eq!(
            offset_of!(SYSTEM_CPU_SET_INFORMATION, Size),
            l::CPU_SET_SIZE
        );
        assert_eq!(
            offset_of!(SYSTEM_CPU_SET_INFORMATION, Type),
            l::CPU_SET_TYPE
        );
        // `Anonymous` is a union whose only member is `CpuSet`, at offset 0.
        let cs = offset_of!(SYSTEM_CPU_SET_INFORMATION, Anonymous);
        assert_eq!(cs + offset_of!(Cs, Id), l::CPU_SET_ID);
        assert_eq!(cs + offset_of!(Cs, Group), l::CPU_SET_GROUP);
        assert_eq!(
            cs + offset_of!(Cs, LogicalProcessorIndex),
            l::CPU_SET_LOGICAL_PROCESSOR_INDEX
        );
        assert_eq!(cs + offset_of!(Cs, CoreIndex), l::CPU_SET_CORE_INDEX);
        assert_eq!(
            cs + offset_of!(Cs, LastLevelCacheIndex),
            l::CPU_SET_LAST_LEVEL_CACHE_INDEX
        );
        assert_eq!(
            cs + offset_of!(Cs, EfficiencyClass),
            l::CPU_SET_EFFICIENCY_CLASS
        );
        // `Anonymous1` is the union of `AllFlags` and the bit fields, at offset 0.
        assert_eq!(cs + offset_of!(Cs, Anonymous1), l::CPU_SET_ALL_FLAGS);
        assert!(cs + offset_of!(Cs, Anonymous1) < l::CPU_SET_MIN_SIZE);

        type Ex = SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX;
        assert_eq!(offset_of!(Ex, Relationship), l::INFO_RELATIONSHIP);
        assert_eq!(offset_of!(Ex, Size), l::INFO_SIZE);
        let body = offset_of!(Ex, Anonymous);
        assert_eq!(body, l::INFO_BODY);

        assert_eq!(
            body + offset_of!(PROCESSOR_RELATIONSHIP, EfficiencyClass),
            l::PROCESSOR_EFFICIENCY_CLASS
        );
        assert_eq!(
            body + offset_of!(PROCESSOR_RELATIONSHIP, GroupCount),
            l::PROCESSOR_GROUP_COUNT
        );
        assert_eq!(
            body + offset_of!(PROCESSOR_RELATIONSHIP, GroupMask),
            l::PROCESSOR_GROUP_MASK
        );

        assert_eq!(body + offset_of!(CACHE_RELATIONSHIP, Level), l::CACHE_LEVEL);
        assert_eq!(
            body + offset_of!(CACHE_RELATIONSHIP, CacheSize),
            l::CACHE_SIZE
        );
        assert_eq!(body + offset_of!(CACHE_RELATIONSHIP, Type), l::CACHE_TYPE);
        assert_eq!(
            body + offset_of!(CACHE_RELATIONSHIP, GroupCount),
            l::CACHE_GROUP_COUNT
        );
        // `Anonymous` is the union of `GroupMask` and `GroupMasks`, both at offset 0.
        assert_eq!(
            body + offset_of!(CACHE_RELATIONSHIP, Anonymous),
            l::CACHE_GROUP_MASK
        );

        assert_eq!(
            body + offset_of!(GROUP_RELATIONSHIP, ActiveGroupCount),
            l::GROUP_ACTIVE_GROUP_COUNT
        );
        assert_eq!(
            body + offset_of!(GROUP_RELATIONSHIP, GroupInfo),
            l::GROUP_INFO
        );
        assert_eq!(size_of::<PROCESSOR_GROUP_INFO>(), l::GROUP_INFO_SIZE);
        assert_eq!(
            offset_of!(PROCESSOR_GROUP_INFO, ActiveProcessorCount),
            l::GROUP_INFO_ACTIVE_PROCESSOR_COUNT
        );
        assert_eq!(
            offset_of!(PROCESSOR_GROUP_INFO, ActiveProcessorMask),
            l::GROUP_INFO_ACTIVE_PROCESSOR_MASK
        );

        assert_eq!(size_of::<GROUP_AFFINITY>(), l::GROUP_AFFINITY_SIZE);
        assert_eq!(offset_of!(GROUP_AFFINITY, Mask), l::GROUP_AFFINITY_MASK);
        assert_eq!(offset_of!(GROUP_AFFINITY, Group), l::GROUP_AFFINITY_GROUP);
    }

    #[test]
    fn parser_constants_match_windows_sys() {
        let u = |v: i32| v.cast_unsigned();
        assert_eq!(u(CpuSetInformation), parse::CPU_SET_INFORMATION);
        assert_eq!(u(RelationProcessorCore), parse::RELATION_PROCESSOR_CORE);
        assert_eq!(u(RelationCache), parse::RELATION_CACHE);
        assert_eq!(u(RelationGroup), parse::RELATION_GROUP);
        assert_eq!(u(CacheUnified), parse::CACHE_UNIFIED);
        assert_eq!(u(CacheData), parse::CACHE_DATA);
        assert_eq!(
            SYSTEM_CPU_SET_INFORMATION_ALLOCATED,
            u32::from(parse::FLAG_ALLOCATED)
        );
        assert_eq!(
            SYSTEM_CPU_SET_INFORMATION_REALTIME,
            u32::from(parse::FLAG_REALTIME)
        );
    }

    #[test]
    fn sized_queries_then_retries_a_bounded_number_of_times() {
        // Size query reports 40, the sized call succeeds with 40.
        let mut caps = Vec::new();
        let r = sized(|buf, cap| {
            caps.push(cap);
            if cap == 0 {
                (false, 40, ERROR_INSUFFICIENT_BUFFER)
            } else {
                assert!(!buf.ptr::<u8>().is_null());
                (true, 40, 0)
            }
        });
        assert_eq!(r.map(|b| b.len()), Ok(40));
        assert_eq!(caps, [0, 40]);
        // Grows every time: size query + RETRIES sized calls, then Unstable.
        let mut calls = 0;
        let r = sized(|_, cap| {
            calls += 1;
            (false, cap + 8, ERROR_INSUFFICIENT_BUFFER)
        });
        assert_eq!(r, Err(CallError::Unstable));
        assert_eq!(calls, RETRIES + 1);
        // Too large, another error, no progress, a returned length beyond the buffer.
        let max = u32::try_from(MAX_BUFFER).unwrap();
        assert_eq!(
            sized(|_, _| (false, max + 1, ERROR_INSUFFICIENT_BUFFER)),
            Err(CallError::TooLarge(MAX_BUFFER + 1))
        );
        assert_eq!(sized(|_, _| (false, 0, 5)), Err(CallError::Win32(5)));
        assert_eq!(
            sized(|_, _| (false, 0, ERROR_INSUFFICIENT_BUFFER)),
            Err(CallError::Win32(ERROR_INSUFFICIENT_BUFFER))
        );
        assert_eq!(
            sized(|_, cap| if cap == 0 {
                (false, 16, ERROR_INSUFFICIENT_BUFFER)
            } else {
                (true, 17, 0)
            }),
            Err(CallError::Win32(ERROR_INSUFFICIENT_BUFFER))
        );
    }

    #[test]
    fn the_real_calls_return_records() {
        let sets = system_cpu_sets().unwrap();
        let info = processor_information().unwrap();
        assert!(!sets.is_empty() && sets.len() <= MAX_BUFFER);
        assert!(!info.is_empty() && info.len() <= MAX_BUFFER);
        // The first CPU Set record reports its own size.
        assert_eq!(
            usize::try_from(u32::from_le_bytes([sets[0], sets[1], sets[2], sets[3]])).unwrap(),
            l::CPU_SET_STRUCT_SIZE
        );
    }
}
