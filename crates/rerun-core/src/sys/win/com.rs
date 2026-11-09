//! The COM plumbing of `rerun-core` (ADR 0008 amendment P4-5a, ADR 0023 §3 step 6, §13):
//! the one `CoCreateInstance` ([`create_inproc`], `CLSCTX_INPROC_SERVER` only), the apartment
//! guard ([`Apartment`], the second `CoInitializeEx` call site next to `elevation`), owned
//! interface pointers ([`Com`]), `BSTR` and `VARIANT` guards ([`Bstr`], [`Variant`]: the only
//! `SysStringLen`, `SysFreeString` and `VariantClear`), and the environment check of A4 S10
//! ([`check_environment`]).
//!
//! **S10.** A4 assumed `InprocServer32` of `HNetCfg.FwPolicy2` to be a `REG_EXPAND_SZ` with
//! `%SystemRoot%`, which combase might expand from the process environment (the elevated
//! helper's comes from the user-writable `HKCU\Environment`). Measured on Windows 11 build
//! 26300 (`com_and_the_process_environment` in `sys::win::tests::firewall`): the value is a
//! `REG_SZ` `C:\Windows\System32\FirewallAPI.dll`, and a child process whose own `SystemRoot`
//! and `windir` name an empty decoy folder still activates the class and loads
//! `FirewallAPI.dll` from System32. So for this class nothing is expanded on that build. Other
//! builds and other classes may register `%SystemRoot%`; hence [`create_inproc`] still first
//! requires that `SystemRoot` and `windir` both name the folder `GetSystemWindowsDirectoryW`
//! reports (compared folded) and refuses with [`EnvMismatch`] before any activation otherwise.
//! Nothing sets the environment: a process with a changed one gets no COM object.
//!
//! Interface pointers live in [`Com`], which releases its one reference on drop and is neither
//! `Send` nor `Sync`. Elevated processes ignore per-user COM registrations (`HKCU\Software\
//! Classes`); a non-elevated CLI does not, which gives same-user code nothing it does not
//! already have.

#![allow(
    unsafe_code,
    reason = "FFI to combase/ole32/oleaut32 for in-process COM (ADR 0008 amendment P4-5a); \
              every block has a SAFETY comment"
)]

use std::ffi::{OsString, c_void};
use std::marker::PhantomData;
use std::ptr::{self, NonNull};

use windows_sys::Win32::Foundation::{SysFreeString, SysStringLen};
use windows_sys::Win32::System::Com::{
    CLSCTX_INPROC_SERVER, COINIT_DISABLE_OLE1DDE, COINIT_MULTITHREADED, CoCreateInstance,
    CoInitializeEx, CoUninitialize,
};
use windows_sys::Win32::System::Variant::{VARIANT, VariantClear};
use windows_sys::core::{BSTR, GUID, HRESULT};

use super::shell;
use crate::fold::fold;

/// winerror.h `E_POINTER`: a call reported success but returned no interface.
pub(super) const E_POINTER: HRESULT = 0x8000_4003_u32.cast_signed();
/// winerror.h `RPC_E_CHANGED_MODE`: COM is initialised on this thread in another apartment.
const RPC_E_CHANGED_MODE: HRESULT = 0x8001_0106_u32.cast_signed();
/// The `HRESULT` of [`Bstr::text`] for a string longer than its bound.
pub(super) const E_TOO_LONG: HRESULT = 0x8007_00CE_u32.cast_signed(); // HRESULT_FROM_WIN32(206)

/// An unused vtable slot (never read).
pub(super) type Slot = *const c_void;

/// `IUnknownVtbl`: slots 0 to 2.
#[repr(C)]
pub(super) struct UnknownVtbl {
    /// Slot 0.
    query_interface: unsafe extern "system" fn(
        this: *mut c_void,
        iid: *const GUID,
        out: *mut *mut c_void,
    ) -> HRESULT,
    _add_ref: Slot,
    /// Slot 2.
    release: unsafe extern "system" fn(this: *mut c_void) -> u32,
}

/// `IDispatchVtbl`: `IUnknown`, then slots 3 to 6 (`GetTypeInfoCount`, `GetTypeInfo`,
/// `GetIDsOfNames`, `Invoke`), never called.
#[repr(C)]
pub(super) struct DispatchVtbl {
    pub(super) unknown: UnknownVtbl,
    _dispatch: [Slot; 4],
}

/// A vtable prefix that [`Com`] can hold.
///
/// # Safety
/// The implementor is `#[repr(C)]`, starts with an [`UnknownVtbl`] (directly or through
/// [`DispatchVtbl`]) and every typed slot matches the interface's vtable in the SDK header.
pub(super) unsafe trait Vtable {}

// SAFETY: `repr(C)`, the `IUnknown` vtable itself (slots checked by the test below).
unsafe impl Vtable for UnknownVtbl {}
// SAFETY: `repr(C)`, first field `UnknownVtbl`.
unsafe impl Vtable for DispatchVtbl {}

/// One owned reference to a COM interface with vtable `V`; `Release` on drop. Not `Send` and
/// not `Sync` (the raw-pointer marker): it never leaves the thread that created it.
pub(super) struct Com<V: Vtable> {
    this: NonNull<c_void>,
    _vtbl: PhantomData<*const V>,
}

impl<V: Vtable> Com<V> {
    /// Takes over the reference in `this`; `None` for null.
    ///
    /// # Safety
    /// `this` is null or an interface pointer whose vtable starts like `V`, and the caller owns
    /// one reference to it, which the returned value releases.
    pub(super) unsafe fn from_raw(this: *mut c_void) -> Option<Self> {
        NonNull::new(this).map(|this| Self {
            this,
            _vtbl: PhantomData,
        })
    }

    pub(super) fn as_raw(&self) -> *mut c_void {
        self.this.as_ptr()
    }

    pub(super) fn vtbl(&self) -> &V {
        // SAFETY: a COM interface pointer points to its vtable pointer (the object's first
        // field), valid while the object lives; `from_raw` guarantees the object is alive (one
        // reference is held) and that the vtable starts like `V`.
        let vtbl = unsafe { *self.this.as_ptr().cast::<*const V>() };
        // SAFETY: the vtable is non-null, aligned and immutable for the object's lifetime, which
        // the reference held by `self` extends past the borrow.
        unsafe { &*vtbl }
    }

    fn unknown(&self) -> &UnknownVtbl {
        // SAFETY: `V: Vtable` is `repr(C)` and starts with an `UnknownVtbl`, so the pointer to
        // `V` is a valid pointer to that prefix.
        unsafe { &*ptr::from_ref(self.vtbl()).cast::<UnknownVtbl>() }
    }

    /// `QueryInterface(iid)` as an interface with vtable `W`.
    ///
    /// # Safety
    /// `W` is the vtable of the interface `iid` names.
    pub(super) unsafe fn cast<W: Vtable>(&self, iid: &GUID) -> Result<Com<W>, HRESULT> {
        let mut out = ptr::null_mut();
        // SAFETY: `self` is a live interface; slot 0 is QueryInterface; `iid` is a valid GUID
        // and `out` a valid location for the returned pointer.
        let hr = unsafe { (self.unknown().query_interface)(self.as_raw(), iid, &mut out) };
        if hr < 0 {
            return Err(hr);
        }
        // SAFETY: on success `out` is the interface `iid` names (vtable `W`, the caller's
        // promise) with one reference owned by the caller.
        unsafe { Com::from_raw(out) }.ok_or(E_POINTER)
    }
}

impl<V: Vtable> Drop for Com<V> {
    fn drop(&mut self) {
        // SAFETY: `self` owns one reference to a live object; `Release` gives it up, and
        // `self.this` is not used afterwards.
        unsafe { (self.unknown().release)(self.as_raw()) };
    }
}

/// A `BSTR` the caller owns, freed with `SysFreeString` on drop (null allowed).
pub(super) struct Bstr(pub(super) BSTR);

impl Bstr {
    /// An empty slot for an `[out] BSTR*` parameter.
    pub(super) fn null() -> Self {
        Self(ptr::null())
    }

    /// The text (`NULL` is empty), lossy for text that is not valid UTF-16; longer than
    /// `max` UTF-16 units is [`E_TOO_LONG`].
    pub(super) fn text(&self, max: usize) -> Result<String, HRESULT> {
        if self.0.is_null() {
            return Ok(String::new());
        }
        #[expect(
            clippy::disallowed_methods,
            reason = "the one SysStringLen call site (ADR 0008 amendment P4-5a)"
        )]
        // SAFETY: `self.0` is a non-null BSTR returned by a COM call and owned by `self`; its
        // length prefix is valid.
        let len = unsafe { SysStringLen(self.0) } as usize;
        if len > max {
            return Err(E_TOO_LONG);
        }
        // SAFETY: a BSTR is `len` initialised UTF-16 units at `self.0` (plus a NUL), aligned and
        // alive while `self` owns it; the slice borrows `self`.
        let units = unsafe { std::slice::from_raw_parts(self.0, len) };
        Ok(String::from_utf16_lossy(units))
    }
}

impl Drop for Bstr {
    fn drop(&mut self) {
        #[expect(
            clippy::disallowed_methods,
            reason = "the one SysFreeString call site (ADR 0008 amendment P4-5a)"
        )]
        // SAFETY: `self.0` is null or a BSTR this guard owns; it is freed exactly once.
        // SysFreeString accepts null.
        unsafe {
            SysFreeString(self.0)
        };
    }
}

/// A `VARIANT` the caller owns, cleared with `VariantClear` on drop. `repr(transparent)`: an array
/// of them is an array of `VARIANT`s (`IEnumVARIANT::Next`).
#[repr(transparent)]
pub(super) struct Variant(pub(super) VARIANT);

impl Variant {
    /// `VT_EMPTY`, the state `VariantInit` sets (all zero).
    pub(super) fn empty() -> Self {
        Self(VARIANT::default())
    }

    /// The `vt` field.
    pub(super) fn vt(&self) -> u16 {
        // SAFETY: every VARIANT has the tagged layout with `vt` first; reading a `u16` of a
        // union field of plain data is always initialised (all zero or written by COM).
        unsafe { self.0.Anonymous.Anonymous.vt }
    }

    /// The `pdispVal`/`punkVal` pointer of a `VT_DISPATCH` or `VT_UNKNOWN` variant, still owned
    /// by `self`.
    pub(super) fn object(&self) -> *mut c_void {
        // SAFETY: as in `vt` (the tagged struct is plain `Copy` data).
        let tagged = unsafe { self.0.Anonymous.Anonymous };
        // SAFETY: a pointer-sized union field of plain data, always initialised; the caller
        // checked `vt` before using the pointer.
        unsafe { tagged.Anonymous.pdispVal }
    }
}

impl Drop for Variant {
    fn drop(&mut self) {
        #[expect(
            clippy::disallowed_methods,
            reason = "the one VariantClear call site (ADR 0008 amendment P4-5a)"
        )]
        // SAFETY: `self.0` is a valid VARIANT (all zero or filled by COM) that this guard owns;
        // VariantClear releases what it holds and sets it to VT_EMPTY. Its result is ignored:
        // nothing else can be done in a destructor.
        unsafe {
            VariantClear(&mut self.0)
        };
    }
}

/// The multithreaded apartment for one firewall read on this thread: `CoUninitialize` on drop
/// if the call took a reference (`S_OK` or `S_FALSE`). A thread already in another apartment
/// (`RPC_E_CHANGED_MODE`) is used as it is.
pub(super) struct Apartment(bool);

impl Apartment {
    /// Enters the MTA (`COINIT_MULTITHREADED | COINIT_DISABLE_OLE1DDE`).
    pub(super) fn enter() -> Result<Self, HRESULT> {
        let flags = (COINIT_MULTITHREADED | COINIT_DISABLE_OLE1DDE).cast_unsigned();
        #[expect(
            clippy::disallowed_methods,
            reason = "rerun-core's second CoInitializeEx call site: the firewall read (ADR 0008 \
                      amendment P4-5a, ADR 0023 §3 step 6)"
        )]
        // SAFETY: the reserved pointer must be null; the flags are documented COINIT values.
        let hr = unsafe { CoInitializeEx(ptr::null(), flags) };
        match hr {
            RPC_E_CHANGED_MODE => Ok(Self(false)),
            hr if hr < 0 => Err(hr),
            _ => Ok(Self(true)),
        }
    }
}

impl Drop for Apartment {
    fn drop(&mut self) {
        if self.0 {
            // SAFETY: balances the successful CoInitializeEx of this thread, exactly once.
            unsafe { CoUninitialize() };
        }
    }
}

/// `SystemRoot` or `windir` does not name the Windows folder (A4 S10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum EnvMismatch {
    /// `GetSystemWindowsDirectoryW` failed (Win32 error).
    Windows(u32),
    /// The variable is missing, not Unicode or names another folder.
    Var(&'static str),
}

/// The variables combase expands in `InprocServer32` paths of system classes.
const ENV_VARS: [&str; 2] = ["SystemRoot", "windir"];

/// A4 S10: `SystemRoot` and `windir` of this process both name the Windows folder (folded,
/// without a trailing separator). Read only; the environment is compared, never used.
pub(super) fn check_environment() -> Result<(), EnvMismatch> {
    let windows = shell::system_windows_directory().map_err(EnvMismatch::Windows)?;
    environment_matches(&windows, |name| {
        #[expect(
            clippy::disallowed_methods,
            reason = "A4 S10: compared with GetSystemWindowsDirectoryW, never a path source"
        )]
        std::env::var_os(name)
    })
}

/// The pure part of [`check_environment`].
pub(super) fn environment_matches(
    windows: &OsString,
    var: impl Fn(&str) -> Option<OsString>,
) -> Result<(), EnvMismatch> {
    let norm = |s: &str| fold(s.trim_end_matches('\\'));
    let want = windows
        .to_str()
        .map(norm)
        .ok_or(EnvMismatch::Windows(1113))?; // ERROR_NO_UNICODE_TRANSLATION
    for name in ENV_VARS {
        let ok = var(name)
            .as_deref()
            .and_then(|v| v.to_str())
            .is_some_and(|v| !v.is_empty() && norm(v) == want);
        if !ok {
            return Err(EnvMismatch::Var(name));
        }
    }
    Ok(())
}

/// The one `CoCreateInstance` (`CLSCTX_INPROC_SERVER`, no aggregation), without the
/// environment check: only [`create_inproc`] and the S10 measurement call it.
///
/// # Safety
/// `V` is the vtable of the interface `iid` names.
pub(super) unsafe fn activate<V: Vtable>(clsid: &GUID, iid: &GUID) -> Result<Com<V>, HRESULT> {
    let mut out = ptr::null_mut();
    #[expect(
        clippy::disallowed_methods,
        reason = "the one CoCreateInstance call site, CLSCTX_INPROC_SERVER only (ADR 0008 \
                  amendment P4-5a)"
    )]
    // SAFETY: `clsid` and `iid` are valid GUIDs for the call; no outer unknown; `out` is a valid
    // location for the returned interface pointer.
    let hr =
        unsafe { CoCreateInstance(clsid, ptr::null_mut(), CLSCTX_INPROC_SERVER, iid, &mut out) };
    if hr < 0 {
        return Err(hr);
    }
    // SAFETY: on success `out` is the interface `iid` names (vtable `V`, the caller's promise)
    // with one reference owned by the caller.
    unsafe { Com::from_raw(out) }.ok_or(E_POINTER)
}

/// Why [`create_inproc`] gave no object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum CreateError {
    /// A4 S10 refused.
    Env(EnvMismatch),
    /// `CoCreateInstance` failed.
    Com(HRESULT),
}

/// A4 S10, then the in-process server of `clsid` as the interface `iid`. The caller is in an
/// [`Apartment`].
///
/// # Safety
/// `V` is the vtable of the interface `iid` names.
pub(super) unsafe fn create_inproc<V: Vtable>(
    clsid: &GUID,
    iid: &GUID,
) -> Result<Com<V>, CreateError> {
    check_environment().map_err(CreateError::Env)?;
    // SAFETY: forwarded from the caller.
    unsafe { activate(clsid, iid) }.map_err(CreateError::Com)
}

/// `IID_IUnknown`.
#[cfg(test)]
const IID_UNKNOWN: GUID = GUID::from_u128(0x0000_0000_0000_0000_c000_0000_0000_0046);

/// Test only (the A4 S10 measurement): `IUnknown` of `clsid` through [`create_inproc`] and
/// through the raw [`activate`]; the error of the first (`None` on success) and the `HRESULT` of
/// the second (0 on success). Both objects are released at once.
#[cfg(test)]
pub(super) fn probe(clsid: &GUID) -> (Option<CreateError>, HRESULT) {
    // SAFETY: `UnknownVtbl` is the vtable of `IUnknown`, the interface `IID_UNKNOWN` names.
    let product = unsafe { create_inproc::<UnknownVtbl>(clsid, &IID_UNKNOWN) };
    // SAFETY: as above.
    let raw = unsafe { activate::<UnknownVtbl>(clsid, &IID_UNKNOWN) };
    (product.err(), raw.err().unwrap_or(0))
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::mem::{offset_of, size_of};

    use super::*;

    #[test]
    fn unknown_and_dispatch_slots_match_unknwn_h_and_oaidl_h() {
        let slot = |n: usize| n * size_of::<usize>();
        assert_eq!(offset_of!(UnknownVtbl, query_interface), slot(0));
        assert_eq!(offset_of!(UnknownVtbl, release), slot(2));
        assert_eq!(size_of::<DispatchVtbl>(), slot(7));
    }

    #[test]
    fn the_environment_must_name_the_windows_folder() {
        let win = OsString::from(r"C:\Windows");
        let env = |root: &'static str, windir: &'static str| {
            move |n: &str| match n {
                "SystemRoot" => Some(OsString::from(root)),
                "windir" => Some(OsString::from(windir)),
                _ => None,
            }
        };
        assert_eq!(
            environment_matches(&win, env(r"C:\WINDOWS", r"c:\windows\")),
            Ok(())
        );
        assert_eq!(
            environment_matches(&win, env(r"C:\Evil", r"C:\Windows")),
            Err(EnvMismatch::Var("SystemRoot"))
        );
        assert_eq!(
            environment_matches(&win, env(r"C:\Windows", r"D:\Windows")),
            Err(EnvMismatch::Var("windir"))
        );
        assert_eq!(
            environment_matches(&win, env("", r"C:\Windows")),
            Err(EnvMismatch::Var("SystemRoot"))
        );
        assert_eq!(
            environment_matches(&win, |_| None),
            Err(EnvMismatch::Var("SystemRoot"))
        );
        assert_eq!(
            environment_matches(&win, env(r"C:\Windows\System32", r"C:\Windows")),
            Err(EnvMismatch::Var("SystemRoot"))
        );
    }

    #[test]
    fn this_process_passes_the_environment_check() {
        assert_eq!(check_environment(), Ok(()));
    }
}
