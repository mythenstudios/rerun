//! [`WinGpu`]: the real graphics adapters via DXGI (ADR 0008 amendment 2026-11-05). No
//! `unsafe`: the calls are in `dxgi`.
//!
//! Raw data only, in DXGI order (never reordered, never deduplicated): the name is the
//! `Description` field up to its first NUL within the first 127 units, decoded lossily, with
//! control characters and bidirectional formatting characters replaced by U+FFFD and nothing
//! trimmed; the LUID is `HighPart << 32 | LowPart`; `software` is `DXGI_ADAPTER_FLAG_SOFTWARE` (the remote flag is
//! ignored); the driver version is `None` whenever `CheckInterfaceSupport` fails. A failed
//! `GetDesc1` fails the whole list.

use super::dxgi::{self, DxgiError, MAX_ADAPTERS, RawAdapter};
use crate::sys::gpu::{MAX_NAME_UTF16, is_bidi_control};
use crate::sys::{DriverVersion, Gpu, GpuAdapter, SysError, SysErrorKind, SysResult};

/// winerror.h `E_ACCESSDENIED`.
const E_ACCESSDENIED: i32 = 0x8007_0005_u32.cast_signed();

/// Enumerates the adapters with a fresh DXGI factory on every call (nothing is cached but the
/// `CreateDXGIFactory1` address). `dxgi.dll` is loaded from System32 on the first call. Every
/// call fails with `Unsupported` until the process called
/// [`restrict_dll_search`](super::restrict_dll_search) (ADR 0008, H2).
#[derive(Debug, Default)]
pub struct WinGpu(());

impl WinGpu {
    /// The real adapter source.
    pub fn new() -> Self {
        Self(())
    }
}

impl Gpu for WinGpu {
    fn adapters(&self) -> SysResult<Vec<GpuAdapter>> {
        let raw = dxgi::enumerate().map_err(gpu_error)?;
        Ok(raw.iter().map(adapter_from).collect())
    }
}

/// A [`GpuAdapter`] from what DXGI reported.
fn adapter_from(raw: &RawAdapter) -> GpuAdapter {
    let d = &raw.desc;
    let bytes = |v: usize| u64::try_from(v).unwrap_or(u64::MAX);
    GpuAdapter {
        name: adapter_name(&d.description),
        vendor_id: d.vendor_id,
        device_id: d.device_id,
        subsys_id: d.subsys_id,
        revision: d.revision,
        luid: luid_u64(d.luid_low, d.luid_high),
        dedicated_video_memory: bytes(d.dedicated_video_memory),
        shared_system_memory: bytes(d.shared_system_memory),
        software: d.flags & dxgi::DXGI_ADAPTER_FLAG_SOFTWARE != 0,
        umd_version: raw.umd.map(|v| DriverVersion::from_u64(v.cast_unsigned())),
    }
}

/// The adapter name: the units before the first NUL within the first 127 (the field holds 128
/// with the terminator), unpaired surrogates, control characters and bidirectional formatting
/// characters ([`is_bidi_control`]: a name must not reorder the text around it in the UI) as
/// U+FFFD, untrimmed. At
/// most 127 UTF-16 units, so it always fits [`MAX_NAME_UTF16`].
fn adapter_name(units: &[u16; MAX_NAME_UTF16]) -> String {
    let field = &units[..MAX_NAME_UTF16 - 1];
    let end = field.iter().position(|&u| u == 0).unwrap_or(field.len());
    char::decode_utf16(field[..end].iter().copied())
        .map(|c| {
            c.ok()
                .filter(|&c| !c.is_control() && !is_bidi_control(c))
                .unwrap_or(char::REPLACEMENT_CHARACTER)
        })
        .collect()
}

/// `LUID` as one number: `HighPart` (as its bit pattern) in the upper 32 bits.
fn luid_u64(low: u32, high: i32) -> u64 {
    u64::from(high.cast_unsigned()) << 32 | u64::from(low)
}

/// The kind of a failed DXGI call.
fn kind_of_gpu_hresult(hr: i32) -> SysErrorKind {
    match hr {
        E_ACCESSDENIED => SysErrorKind::AccessDenied,
        dxgi::DXGI_ERROR_UNSUPPORTED => SysErrorKind::Unsupported,
        dxgi::DXGI_ERROR_NOT_CURRENTLY_AVAILABLE => SysErrorKind::Busy,
        _ => SysErrorKind::Other,
    }
}

/// A failed enumeration as a [`SysError`] with the Win32 code or `HRESULT`.
fn gpu_error(e: DxgiError) -> SysError {
    match e {
        DxgiError::Load(code) => {
            SysError::new(SysErrorKind::NotFound, "gpu: dxgi.dll in System32").with_win32(code)
        }
        DxgiError::Symbol(code) => {
            SysError::new(SysErrorKind::NotFound, "gpu: dxgi.dll CreateDXGIFactory1")
                .with_win32(code)
        }
        DxgiError::Call { call, hr } => {
            SysError::new(kind_of_gpu_hresult(hr), format!("gpu: {call}")).with_hresult(hr)
        }
        DxgiError::NotRestricted => SysError::new(
            SysErrorKind::Unsupported,
            "gpu: DLL search not restricted; call restrict_dll_search first",
        ),
        DxgiError::TooMany => SysError::new(
            SysErrorKind::Other,
            format!("gpu: more than {MAX_ADAPTERS} adapters"),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::super::dxgi::{AdapterDesc1, E_POINTER};
    use super::*;

    fn units(s: &str) -> [u16; MAX_NAME_UTF16] {
        let mut out = [0; MAX_NAME_UTF16];
        for (o, u) in out.iter_mut().zip(s.encode_utf16()) {
            *o = u;
        }
        out
    }

    #[test]
    fn adapter_names_stop_at_the_first_nul_within_127_units() {
        assert_eq!(
            adapter_name(&units("AMD Radeon RX 9070 XT")),
            "AMD Radeon RX 9070 XT"
        );
        assert_eq!(adapter_name(&units("A\0B")), "A");
        assert_eq!(adapter_name(&units("")), "");
        // No trimming, non-ASCII kept.
        assert_eq!(adapter_name(&units(" Grafik é ")), " Grafik é ");
        // A full field without NUL: the 128th unit is never read.
        let full = [u16::from(b'x'); MAX_NAME_UTF16];
        assert_eq!(adapter_name(&full), "x".repeat(127));
    }

    #[test]
    fn adapter_names_replace_control_characters_and_lone_surrogates() {
        let mut u = units("a\tb\u{7f}c");
        assert_eq!(adapter_name(&u), "a\u{fffd}b\u{fffd}c");
        u[1] = 0xD800;
        assert_eq!(adapter_name(&u), "a\u{fffd}b\u{fffd}c");
        // A pair split by the 127-unit cut is one replacement character.
        let mut cut = [u16::from(b'x'); MAX_NAME_UTF16];
        cut[126] = 0xD83D;
        cut[127] = 0xDE00;
        let name = adapter_name(&cut);
        assert!(name.ends_with('\u{fffd}') && name.encode_utf16().count() == 127);
    }

    #[test]
    fn adapter_names_replace_bidi_controls() {
        for c in [
            '\u{061C}', '\u{200E}', '\u{200F}', '\u{202A}', '\u{202B}', '\u{202C}', '\u{202D}',
            '\u{202E}', '\u{2066}', '\u{2067}', '\u{2068}', '\u{2069}',
        ] {
            assert_eq!(
                adapter_name(&units(&format!("a{c}b"))),
                "a\u{fffd}b",
                "{c:?}"
            );
        }
        // Other format characters (zero-width joiner) and RTL letters stay.
        assert_eq!(adapter_name(&units("a\u{200D}b")), "a\u{200D}b");
        assert_eq!(adapter_name(&units("\u{05D0}")), "\u{05D0}");
    }

    #[test]
    fn luids_keep_the_bit_pattern_of_both_halves() {
        assert_eq!(luid_u64(0x1234, 0), 0x1234);
        assert_eq!(luid_u64(1, 2), 0x2_0000_0001);
        assert_eq!(luid_u64(u32::MAX, -1), u64::MAX);
    }

    #[test]
    fn adapters_map_every_field() {
        let mut desc = AdapterDesc1::ZERO;
        desc.description = units("Microsoft Basic Render Driver");
        (
            desc.vendor_id,
            desc.device_id,
            desc.subsys_id,
            desc.revision,
        ) = (0x1414, 0x8c, 0, 0);
        desc.dedicated_video_memory = 1;
        desc.shared_system_memory = 2;
        (desc.luid_low, desc.luid_high) = (7, 1);
        desc.flags = 2 | 1;
        let a = adapter_from(&RawAdapter { desc, umd: None });
        assert_eq!(a.name, "Microsoft Basic Render Driver");
        assert_eq!((a.vendor_id, a.device_id), (0x1414, 0x8c));
        assert_eq!((a.dedicated_video_memory, a.shared_system_memory), (1, 2));
        assert_eq!(a.luid, 0x1_0000_0007);
        assert!(a.software);
        assert_eq!(a.umd_version, None);
        desc.flags = 1; // remote only
        let a = adapter_from(&RawAdapter {
            desc,
            umd: Some(0x0020_0000_5209_0009),
        });
        assert!(!a.software);
        assert_eq!(a.umd_version, Some(DriverVersion([32, 0, 21001, 9])));
        // A negative LARGE_INTEGER keeps its bit pattern.
        let a = adapter_from(&RawAdapter {
            desc,
            umd: Some(-1),
        });
        assert_eq!(a.umd_version, Some(DriverVersion([u16::MAX; 4])));
    }

    #[test]
    fn gpu_errors_keep_their_code() {
        let e = gpu_error(DxgiError::Load(126));
        assert_eq!((e.kind, e.win32), (SysErrorKind::NotFound, Some(126)));
        let e = gpu_error(DxgiError::Symbol(127));
        assert_eq!((e.kind, e.win32), (SysErrorKind::NotFound, Some(127)));
        for (hr, kind) in [
            (E_ACCESSDENIED, SysErrorKind::AccessDenied),
            (dxgi::DXGI_ERROR_UNSUPPORTED, SysErrorKind::Unsupported),
            (dxgi::DXGI_ERROR_NOT_CURRENTLY_AVAILABLE, SysErrorKind::Busy),
            (E_POINTER, SysErrorKind::Other),
        ] {
            let e = gpu_error(DxgiError::Call {
                call: "EnumAdapters1",
                hr,
            });
            assert_eq!((e.kind, e.hresult), (kind, Some(hr)));
            assert!(e.target.contains("EnumAdapters1"), "{e}");
        }
        assert_eq!(gpu_error(DxgiError::TooMany).kind, SysErrorKind::Other);
        let e = gpu_error(DxgiError::NotRestricted);
        assert_eq!(e.kind, SysErrorKind::Unsupported);
        assert!(e.target.contains("restrict_dll_search"), "{e}");
    }
}
