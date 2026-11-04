//! The only DXGI calls (ADR 0008 amendment 2026-11-05): a hand-written binding of the four
//! methods Rerun needs, on `windows-sys` types, no `windows` crate.
//!
//! `windows-sys` 0.61 has no DXGI at all (no interfaces, no `DXGI_ADAPTER_DESC1`, no
//! `CreateDXGIFactory1`), so this module defines, from `dxgi.h` of the Windows SDK
//! (10.0.26100):
//! - [`AdapterDesc1`], the `DXGI_ADAPTER_DESC1` layout (a test pins size and offsets);
//! - prefixes of the vtables of `IDXGIFactory1` (slot 12 `EnumAdapters1`) and `IDXGIAdapter1`
//!   (slot 9 `CheckInterfaceSupport`, slot 10 `GetDesc1`), slot 2 `IUnknown::Release` (a test
//!   pins the slot offsets); only the slots in use are typed, the others are placeholders and
//!   never read;
//! - the IIDs of `IDXGIFactory1` and `IDXGIDevice`, the HRESULTs and the software flag.
//!
//! `dxgi.dll` is loaded on the first enumeration through `loader::load_system32` (System32
//! only, never freed) and `CreateDXGIFactory1` is cached in a `OnceLock`; there is no static
//! or delay-load import of `dxgi.dll` (the shipped binaries' hardening tests check it). The
//! elevated helper (phase 3) builds a `System` without a GPU and never reaches this module.
//! DXGI needs no `CoInitialize`.
//!
//! Each enumeration creates a fresh factory (a factory caches the adapter list of its creation
//! time) and walks `EnumAdapters1(0, 1, …)` until `DXGI_ERROR_NOT_FOUND`, at most
//! [`MAX_ADAPTERS`]. Interface pointers live in [`Com`], which releases its one reference on
//! drop and is neither `Send` nor `Sync`; nothing outlives [`enumerate`].

#![allow(
    unsafe_code,
    reason = "hand-written COM calls into dxgi.dll (ADR 0008 amendment); every block has a \
              SAFETY comment"
)]

use std::ffi::c_void;
use std::marker::PhantomData;
use std::ptr::{self, NonNull};
use std::sync::OnceLock;

use windows_sys::core::{GUID, HRESULT};

use super::loader;

/// `IID_IDXGIFactory1` (dxgi.h: `770aae78-f26f-4dba-a829-253c83d1b387`).
pub(super) const IID_IDXGI_FACTORY1: GUID =
    GUID::from_u128(0x770a_ae78_f26f_4dba_a829_253c_83d1_b387);
/// `IID_IDXGIDevice` (dxgi.h: `54ec77fa-1377-44e6-8c32-88fd5f44c84c`), the interface whose
/// support `CheckInterfaceSupport` reports together with the user-mode driver version.
pub(super) const IID_IDXGI_DEVICE: GUID =
    GUID::from_u128(0x54ec_77fa_1377_44e6_8c32_88fd_5f44_c84c);
/// winerror.h `DXGI_ERROR_NOT_FOUND`: no adapter at this index (the end of the list).
pub(super) const DXGI_ERROR_NOT_FOUND: HRESULT = 0x887A_0002_u32.cast_signed();
/// winerror.h `DXGI_ERROR_UNSUPPORTED`.
pub(super) const DXGI_ERROR_UNSUPPORTED: HRESULT = 0x887A_0004_u32.cast_signed();
/// winerror.h `DXGI_ERROR_NOT_CURRENTLY_AVAILABLE`.
pub(super) const DXGI_ERROR_NOT_CURRENTLY_AVAILABLE: HRESULT = 0x887A_0022_u32.cast_signed();
/// winerror.h `E_POINTER`: a call reported success but returned no interface.
pub(super) const E_POINTER: HRESULT = 0x8000_4003_u32.cast_signed();
/// dxgi.h `DXGI_ADAPTER_FLAG_SOFTWARE` (`DXGI_ADAPTER_FLAG_REMOTE` is 1 and ignored).
pub(super) const DXGI_ADAPTER_FLAG_SOFTWARE: u32 = 2;
/// More adapters than this is an error, never a truncated list.
pub(super) const MAX_ADAPTERS: u32 = 64;

/// `DXGI_ADAPTER_DESC1` (dxgi.h), x64 layout: 312 bytes, alignment 8.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct AdapterDesc1 {
    /// `Description`: UTF-16, NUL-terminated if shorter than 128 units.
    pub(super) description: [u16; 128],
    /// `VendorId`.
    pub(super) vendor_id: u32,
    /// `DeviceId`.
    pub(super) device_id: u32,
    /// `SubSysId`.
    pub(super) subsys_id: u32,
    /// `Revision`.
    pub(super) revision: u32,
    /// `DedicatedVideoMemory` (`SIZE_T`).
    pub(super) dedicated_video_memory: usize,
    /// `DedicatedSystemMemory` (`SIZE_T`).
    pub(super) dedicated_system_memory: usize,
    /// `SharedSystemMemory` (`SIZE_T`).
    pub(super) shared_system_memory: usize,
    /// `AdapterLuid.LowPart`.
    pub(super) luid_low: u32,
    /// `AdapterLuid.HighPart`.
    pub(super) luid_high: i32,
    /// `Flags` (`DXGI_ADAPTER_FLAG`).
    pub(super) flags: u32,
}

impl AdapterDesc1 {
    /// All zero, the buffer `GetDesc1` fills.
    pub(super) const ZERO: Self = Self {
        description: [0; 128],
        vendor_id: 0,
        device_id: 0,
        subsys_id: 0,
        revision: 0,
        dedicated_video_memory: 0,
        dedicated_system_memory: 0,
        shared_system_memory: 0,
        luid_low: 0,
        luid_high: 0,
        flags: 0,
    };
}

/// One adapter as DXGI reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct RawAdapter {
    /// `GetDesc1`.
    pub(super) desc: AdapterDesc1,
    /// `CheckInterfaceSupport(IID_IDXGIDevice)`: the user-mode driver version; `None` if the
    /// call failed for any reason.
    pub(super) umd: Option<i64>,
}

/// A failed enumeration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum DxgiError {
    /// `dxgi.dll` could not be loaded from System32 (Win32 error).
    Load(u32),
    /// `dxgi.dll` has no `CreateDXGIFactory1` (Win32 error).
    Symbol(u32),
    /// A DXGI call failed.
    Call {
        /// `CreateDXGIFactory1`, `EnumAdapters1` or `GetDesc1`.
        call: &'static str,
        /// Its `HRESULT`.
        hr: HRESULT,
    },
    /// More than [`MAX_ADAPTERS`] adapters.
    TooMany,
}

/// An unused vtable slot (never read).
type Slot = *const c_void;

/// `IUnknownVtbl`: slots 0 to 2.
#[repr(C)]
struct UnknownVtbl {
    _query_interface: Slot,
    _add_ref: Slot,
    /// Slot 2.
    release: unsafe extern "system" fn(this: *mut c_void) -> u32,
}

/// The `IDXGIFactory1Vtbl` prefix up to `EnumAdapters1`.
#[repr(C)]
struct Factory1Vtbl {
    unknown: UnknownVtbl,
    /// Slots 3 to 11: `IDXGIObject` (`SetPrivateData`, `SetPrivateDataInterface`,
    /// `GetPrivateData`, `GetParent`), `IDXGIFactory` (`EnumAdapters`,
    /// `MakeWindowAssociation`, `GetWindowAssociation`, `CreateSwapChain`,
    /// `CreateSoftwareAdapter`).
    _object_and_factory: [Slot; 9],
    /// Slot 12.
    enum_adapters1:
        unsafe extern "system" fn(this: *mut c_void, index: u32, out: *mut *mut c_void) -> HRESULT,
}

/// The `IDXGIAdapter1Vtbl` prefix up to `GetDesc1` (its last slot).
#[repr(C)]
struct Adapter1Vtbl {
    unknown: UnknownVtbl,
    /// Slots 3 to 8: `IDXGIObject` (four), `IDXGIAdapter` (`EnumOutputs`, `GetDesc`).
    _object_and_adapter: [Slot; 6],
    /// Slot 9; `LARGE_INTEGER *pUMDVersion` as `*mut i64` (same size and alignment).
    check_interface_support:
        unsafe extern "system" fn(this: *mut c_void, name: *const GUID, umd: *mut i64) -> HRESULT,
    /// Slot 10.
    get_desc1: unsafe extern "system" fn(this: *mut c_void, desc: *mut AdapterDesc1) -> HRESULT,
}

/// A vtable prefix that [`Com`] can hold.
///
/// # Safety
/// The implementor is `#[repr(C)]`, its first field is an [`UnknownVtbl`] and every typed slot
/// matches the interface's vtable in `dxgi.h`.
unsafe trait Vtable {}

// SAFETY: `repr(C)`, first field `UnknownVtbl`, slots checked by `vtable_slots_match_dxgi_h`.
unsafe impl Vtable for Factory1Vtbl {}
// SAFETY: `repr(C)`, first field `UnknownVtbl`, slots checked by `vtable_slots_match_dxgi_h`.
unsafe impl Vtable for Adapter1Vtbl {}

/// One owned reference to a COM interface with vtable `V`; `Release` on drop. Not `Send` and
/// not `Sync` (the raw-pointer marker): it never leaves the thread that created it.
struct Com<V: Vtable> {
    this: NonNull<c_void>,
    _vtbl: PhantomData<*const V>,
}

impl<V: Vtable> Com<V> {
    /// Takes over the reference in `this`; `None` for null.
    ///
    /// # Safety
    /// `this` is null or an interface pointer whose vtable starts like `V`, and the caller owns
    /// one reference to it, which the returned value releases.
    unsafe fn from_raw(this: *mut c_void) -> Option<Self> {
        NonNull::new(this).map(|this| Self {
            this,
            _vtbl: PhantomData,
        })
    }

    fn as_raw(&self) -> *mut c_void {
        self.this.as_ptr()
    }

    fn vtbl(&self) -> &V {
        // SAFETY: a COM interface pointer points to its vtable pointer (the object's first
        // field), valid while the object lives; `from_raw` guarantees the object is alive (one
        // reference is held) and that the vtable starts like `V`.
        let vtbl = unsafe { *self.this.as_ptr().cast::<*const V>() };
        // SAFETY: the vtable is non-null, aligned and immutable for the object's lifetime, which
        // the reference held by `self` extends past the borrow.
        unsafe { &*vtbl }
    }
}

impl<V: Vtable> Drop for Com<V> {
    fn drop(&mut self) {
        // SAFETY: `V: Vtable` is `repr(C)` and starts with an `UnknownVtbl`, so the pointer to
        // `V` is a valid pointer to that prefix.
        let unknown = unsafe { &*ptr::from_ref(self.vtbl()).cast::<UnknownVtbl>() };
        // SAFETY: `self` owns one reference to a live object; `Release` gives it up, and
        // `self.this` is not used afterwards.
        unsafe { (unknown.release)(self.as_raw()) };
    }
}

impl Com<Factory1Vtbl> {
    /// `EnumAdapters1(index)`: `None` at the end of the list.
    fn adapter(&self, index: u32) -> Result<Option<Com<Adapter1Vtbl>>, DxgiError> {
        let mut out = ptr::null_mut();
        // SAFETY: `self` is a live IDXGIFactory1; slot 12 is EnumAdapters1 (dxgi.h); `out` is a
        // valid location for the returned interface pointer.
        let hr = unsafe { (self.vtbl().enum_adapters1)(self.as_raw(), index, &mut out) };
        if hr == DXGI_ERROR_NOT_FOUND {
            return Ok(None);
        }
        let call = "EnumAdapters1";
        if hr < 0 {
            return Err(DxgiError::Call { call, hr });
        }
        // SAFETY: on success `out` is an IDXGIAdapter1 with one reference owned by the caller.
        let adapter = unsafe { Com::from_raw(out) };
        adapter.map(Some).ok_or(DxgiError::Call {
            call,
            hr: E_POINTER,
        })
    }
}

impl Com<Adapter1Vtbl> {
    fn desc1(&self) -> Result<AdapterDesc1, DxgiError> {
        let mut desc = AdapterDesc1::ZERO;
        // SAFETY: `self` is a live IDXGIAdapter1; slot 10 is GetDesc1 (dxgi.h); `desc` is a
        // writable DXGI_ADAPTER_DESC1 (layout checked by `adapter_desc1_layout_matches_dxgi_h`).
        let hr = unsafe { (self.vtbl().get_desc1)(self.as_raw(), &mut desc) };
        if hr < 0 {
            return Err(DxgiError::Call {
                call: "GetDesc1",
                hr,
            });
        }
        Ok(desc)
    }

    /// The user-mode driver version; `None` if DXGI reports none.
    fn umd_version(&self) -> Option<i64> {
        let mut version = 0i64;
        // SAFETY: `self` is a live IDXGIAdapter1; slot 9 is CheckInterfaceSupport (dxgi.h); the
        // GUID is a static and `version` a writable 8-byte LARGE_INTEGER.
        let hr = unsafe {
            (self.vtbl().check_interface_support)(self.as_raw(), &IID_IDXGI_DEVICE, &mut version)
        };
        (hr >= 0).then_some(version)
    }
}

/// `CreateDXGIFactory1` (dxgi.h: `HRESULT WINAPI CreateDXGIFactory1(REFIID, void **)`).
type CreateFactory1 =
    unsafe extern "system" fn(riid: *const GUID, out: *mut *mut c_void) -> HRESULT;

/// `CreateDXGIFactory1` from `dxgi.dll` in System32, loaded on first use and kept (the DLL is
/// never freed).
fn create_factory1() -> Result<CreateFactory1, DxgiError> {
    static CREATE: OnceLock<Result<CreateFactory1, DxgiError>> = OnceLock::new();
    *CREATE.get_or_init(|| {
        let dll = loader::load_system32("dxgi.dll").map_err(DxgiError::Load)?;
        let symbol = dll
            .symbol(c"CreateDXGIFactory1")
            .map_err(DxgiError::Symbol)?;
        // SAFETY: the export CreateDXGIFactory1 has exactly this signature (dxgi.h, `WINAPI` =
        // "system"); `dxgi.dll` is never freed, so the address stays valid for the process.
        Ok(unsafe { std::mem::transmute::<*mut c_void, CreateFactory1>(symbol.as_ptr()) })
    })
}

/// All adapters of a fresh factory, in DXGI order.
pub(super) fn enumerate() -> Result<Vec<RawAdapter>, DxgiError> {
    let create = create_factory1()?;
    let mut out = ptr::null_mut();
    // SAFETY: `create` is CreateDXGIFactory1; the IID is a static GUID; `out` is a valid
    // location for the returned interface pointer.
    let hr = unsafe { create(&IID_IDXGI_FACTORY1, &mut out) };
    let call = "CreateDXGIFactory1";
    if hr < 0 {
        return Err(DxgiError::Call { call, hr });
    }
    // SAFETY: on success `out` is an IDXGIFactory1 (the IID asked for) with one reference owned
    // by the caller.
    let factory = unsafe { Com::<Factory1Vtbl>::from_raw(out) }.ok_or(DxgiError::Call {
        call,
        hr: E_POINTER,
    })?;
    collect(|index| {
        let Some(adapter) = factory.adapter(index)? else {
            return Ok(None);
        };
        Ok(Some(RawAdapter {
            desc: adapter.desc1()?,
            umd: adapter.umd_version(),
        }))
    })
}

/// Calls `next(0)`, `next(1)`, … until it returns `None`; an error ends the list with that
/// error, an item at index [`MAX_ADAPTERS`] with [`DxgiError::TooMany`].
pub(super) fn collect<T>(
    mut next: impl FnMut(u32) -> Result<Option<T>, DxgiError>,
) -> Result<Vec<T>, DxgiError> {
    let mut items = Vec::new();
    for index in 0..=MAX_ADAPTERS {
        match next(index)? {
            None => return Ok(items),
            Some(_) if index == MAX_ADAPTERS => break,
            Some(item) => items.push(item),
        }
    }
    Err(DxgiError::TooMany)
}

#[cfg(test)]
mod tests {
    use std::mem::{align_of, offset_of, size_of};

    use super::*;

    /// Offsets of `DXGI_ADAPTER_DESC1` (dxgi.h, x64: `WCHAR[128]`, four `UINT`, three
    /// `SIZE_T`, `LUID { DWORD; LONG }`, `UINT`, padded to 8).
    #[test]
    fn adapter_desc1_layout_matches_dxgi_h() {
        type D = AdapterDesc1;
        assert_eq!((size_of::<D>(), align_of::<D>()), (312, 8));
        assert_eq!(offset_of!(D, description), 0);
        assert_eq!(offset_of!(D, vendor_id), 256);
        assert_eq!(offset_of!(D, device_id), 260);
        assert_eq!(offset_of!(D, subsys_id), 264);
        assert_eq!(offset_of!(D, revision), 268);
        assert_eq!(offset_of!(D, dedicated_video_memory), 272);
        assert_eq!(offset_of!(D, dedicated_system_memory), 280);
        assert_eq!(offset_of!(D, shared_system_memory), 288);
        assert_eq!(offset_of!(D, luid_low), 296);
        assert_eq!(offset_of!(D, luid_high), 300);
        assert_eq!(offset_of!(D, flags), 304);
        assert_eq!(
            size_of::<windows_sys::Win32::Foundation::LUID>(),
            offset_of!(D, flags) - offset_of!(D, luid_low)
        );
    }

    /// Slot numbers from the `*Vtbl` structs in dxgi.h (SDK 10.0.26100), counted from 0.
    #[test]
    fn vtable_slots_match_dxgi_h() {
        let slot = |n: usize| n * size_of::<usize>();
        assert_eq!(offset_of!(UnknownVtbl, release), slot(2));
        assert_eq!(offset_of!(Factory1Vtbl, enum_adapters1), slot(12));
        assert_eq!(offset_of!(Adapter1Vtbl, check_interface_support), slot(9));
        assert_eq!(offset_of!(Adapter1Vtbl, get_desc1), slot(10));
    }

    #[test]
    fn iids_match_dxgi_h() {
        // DEFINE_GUID(IID_IDXGIFactory1,0x770aae78,0xf26f,0x4dba,0xa8,0x29,0x25,0x3c,0x83,0xd1,0xb3,0x87)
        let f = IID_IDXGI_FACTORY1;
        assert_eq!((f.data1, f.data2, f.data3), (0x770a_ae78, 0xf26f, 0x4dba));
        assert_eq!(f.data4, [0xa8, 0x29, 0x25, 0x3c, 0x83, 0xd1, 0xb3, 0x87]);
        // DEFINE_GUID(IID_IDXGIDevice,0x54ec77fa,0x1377,0x44e6,0x8c,0x32,0x88,0xfd,0x5f,0x44,0xc8,0x4c)
        let d = IID_IDXGI_DEVICE;
        assert_eq!((d.data1, d.data2, d.data3), (0x54ec_77fa, 0x1377, 0x44e6));
        assert_eq!(d.data4, [0x8c, 0x32, 0x88, 0xfd, 0x5f, 0x44, 0xc8, 0x4c]);
    }

    #[test]
    fn collect_stops_at_the_end_and_caps_the_list() {
        assert_eq!(collect(|i| Ok((i < 3).then_some(i))), Ok(vec![0, 1, 2]));
        assert_eq!(collect::<u32>(|_| Ok(None)), Ok(vec![]));
        let max = collect(|i| Ok((i < MAX_ADAPTERS).then_some(i))).unwrap();
        assert_eq!(max.len(), 64);
        assert_eq!(collect(|i| Ok(Some(i))), Err(DxgiError::TooMany));
        let failing = |i| {
            if i == 2 {
                Err(DxgiError::Call {
                    call: "GetDesc1",
                    hr: E_POINTER,
                })
            } else {
                Ok(Some(i))
            }
        };
        assert_eq!(
            collect(failing),
            Err(DxgiError::Call {
                call: "GetDesc1",
                hr: E_POINTER
            })
        );
    }

    /// Read-only: two enumerations of the real DXGI give the same list (each with a fresh
    /// factory), and the Microsoft Basic Render Driver is a software adapter.
    #[test]
    fn the_real_enumeration_lists_the_basic_render_driver() {
        let first = enumerate().unwrap();
        assert_eq!(enumerate().unwrap(), first);
        assert!(
            first
                .iter()
                .any(|a| a.desc.vendor_id == 0x1414
                    && a.desc.flags & DXGI_ADAPTER_FLAG_SOFTWARE != 0),
            "{first:?}"
        );
    }
}
