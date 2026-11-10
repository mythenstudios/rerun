//! [`WinFirewall`]: the firewall's read side (ADR 0023 §6, §8 outcome A, §13; P4-5a), a
//! hand-written binding of the few `netfw.h` methods Rerun reads, on `windows-sys` types (no
//! `windows` crate, ADR 0008 amendment P4-5a).
//!
//! Bound from `netfw.h` and `oaidl.h` (SDK 10.0.26100), slot numbers pinned by tests: the
//! `INetFwPolicy2` prefix up to `get_Rules` (slot 18), `INetFwRules` up to `get__NewEnum`
//! (slot 11), every getter of `INetFwRule` (slots 7 to 41, the setters are placeholders and
//! never read), `INetFwRule2::get_EdgeTraversalOptions` (43), the getters of `INetFwRule3`
//! (45 to 55), and `IEnumVARIANT::Next` (3). The IIDs are pinned against the header too.
//!
//! One [`Firewall::select`] is one enumeration (A4 S11): the MTA is entered for the call
//! ([`Apartment`]), `HNetCfg.FwPolicy2` is created through `com::create_inproc` (after the
//! environment check of A4 S10), `get__NewEnum` walks every rule in batches of
//! [`BATCH`] through `IEnumVARIANT::Next`, and per rule only `Name` and `Grouping` are read
//! before `keep` decides whether the rest is read. More than [`MAX_RULES`] rules, a text longer
//! than [`MAX_TEXT_UTF16`] or an enumeration longer than [`ENUM_DEADLINE`] is `TooLarge`,
//! never a partial list (the deadline is checked between batches, module constant docs).
//! Nothing here writes: no setter slot is typed.

#![allow(
    unsafe_code,
    reason = "hand-written COM calls into FirewallAPI.dll (ADR 0008 amendment P4-5a); every \
              block has a SAFETY comment"
)]

use std::ffi::c_void;
use std::mem::ManuallyDrop;
use std::ptr;
use std::time::{Duration, Instant};

use windows_sys::Win32::NetworkManagement::WindowsFirewall::{NetFwPolicy2, NetFwRule};
use windows_sys::Win32::System::Variant::{VARIANT, VT_DISPATCH, VT_EMPTY};
use windows_sys::core::{BSTR, GUID, HRESULT};

use super::com::{
    Apartment, Bstr, Com, CreateError, DispatchVtbl, E_POINTER, EnvMismatch, Slot, UnknownVtbl,
    Variant, Vtable, create_inproc,
};
use crate::sys::firewall::{FwRest, FwRule, FwRule3, FwSelection, MAX_RULES, MAX_TEXT_UTF16};
use crate::sys::{Firewall, FirewallWrite, SysError, SysErrorKind, SysResult};

/// `IID_INetFwPolicy2` (netfw.h).
pub(super) const IID_POLICY2: GUID = GUID::from_u128(0x9832_5047_c671_4174_8d81_defc_d3f0_3186);
/// `IID_INetFwRule`.
pub(super) const IID_RULE: GUID = GUID::from_u128(0xaf23_0d27_baba_4e42_aced_f524_f22c_fce2);
/// `IID_INetFwRule2`.
pub(super) const IID_RULE2: GUID = GUID::from_u128(0x9c27_c8da_189b_4dde_89f7_8b39_a316_782c);
/// `IID_INetFwRule3`.
pub(super) const IID_RULE3: GUID = GUID::from_u128(0xb215_63ff_d696_4222_ab46_4e89_b73a_b34a);
/// `IID_IEnumVARIANT` (oaidl.h).
pub(super) const IID_ENUM_VARIANT: GUID =
    GUID::from_u128(0x0002_0404_0000_0000_c000_0000_0000_0046);

/// winerror.h `S_FALSE`: `Next` returned fewer than asked, the end of the collection.
const S_FALSE: HRESULT = 1;
/// winerror.h `E_NOINTERFACE`.
const E_NOINTERFACE: HRESULT = 0x8000_4002_u32.cast_signed();
/// winerror.h `E_ACCESSDENIED`.
const E_ACCESSDENIED: HRESULT = 0x8007_0005_u32.cast_signed();
/// Variants per `IEnumVARIANT::Next`.
pub(super) const BATCH: u32 = 64;
/// The time bound of one enumeration (A4 S11; measured cost in ADR 0023 §6). Cooperative: it is
/// checked between two `IEnumVARIANT::Next` batches, so a single COM call that hangs (the
/// firewall service not answering) is not cut off.
pub(super) const ENUM_DEADLINE: Duration = Duration::from_secs(60);

type GetBstr = unsafe extern "system" fn(this: *mut c_void, out: *mut BSTR) -> HRESULT;
type GetLong = unsafe extern "system" fn(this: *mut c_void, out: *mut i32) -> HRESULT;
type GetBool = unsafe extern "system" fn(this: *mut c_void, out: *mut i16) -> HRESULT;
type GetVariant = unsafe extern "system" fn(this: *mut c_void, out: *mut VARIANT) -> HRESULT;
type GetObject = unsafe extern "system" fn(this: *mut c_void, out: *mut *mut c_void) -> HRESULT;
type PutBstr = unsafe extern "system" fn(this: *mut c_void, value: BSTR) -> HRESULT;
type PutLong = unsafe extern "system" fn(this: *mut c_void, value: i32) -> HRESULT;
type PutBool = unsafe extern "system" fn(this: *mut c_void, value: i16) -> HRESULT;
type PutObject = unsafe extern "system" fn(this: *mut c_void, value: *mut c_void) -> HRESULT;

/// The `INetFwPolicy2Vtbl` prefix up to `get_Rules`.
#[repr(C)]
struct PolicyVtbl {
    dispatch: DispatchVtbl,
    /// Slots 7 to 17: `get_CurrentProfileTypes` to `put_UnicastResponsesTo…Disabled`.
    _profiles: [Slot; 11],
    /// Slot 18.
    get_rules: GetObject,
}

/// The `INetFwRulesVtbl` prefix up to `get__NewEnum`.
#[repr(C)]
struct RulesVtbl {
    dispatch: DispatchVtbl,
    /// Slot 7.
    get_count: GetLong,
    /// Slot 8: `Add(INetFwRule*)`.
    add: PutObject,
    /// Slot 9: `Remove(BSTR name)`.
    remove: PutBstr,
    /// Slot 10: `Item`.
    _item: Slot,
    /// Slot 11.
    get_new_enum: GetObject,
}

/// `INetFwRuleVtbl`: every getter typed; the setters of the fields Rerun's one
/// rule form sets typed (P4-5b), the others placeholders.
#[repr(C)]
struct RuleVtbl {
    dispatch: DispatchVtbl,
    get_name: GetBstr,
    put_name: PutBstr,
    get_description: GetBstr,
    put_description: PutBstr,
    get_application_name: GetBstr,
    put_application_name: PutBstr,
    get_service_name: GetBstr,
    _put_service_name: Slot,
    get_protocol: GetLong,
    put_protocol: PutLong,
    get_local_ports: GetBstr,
    _put_local_ports: Slot,
    get_remote_ports: GetBstr,
    _put_remote_ports: Slot,
    get_local_addresses: GetBstr,
    _put_local_addresses: Slot,
    get_remote_addresses: GetBstr,
    _put_remote_addresses: Slot,
    get_icmp_types_and_codes: GetBstr,
    _put_icmp_types_and_codes: Slot,
    get_direction: GetLong,
    put_direction: PutLong,
    get_interfaces: GetVariant,
    _put_interfaces: Slot,
    get_interface_types: GetBstr,
    _put_interface_types: Slot,
    get_enabled: GetBool,
    put_enabled: PutBool,
    get_grouping: GetBstr,
    put_grouping: PutBstr,
    get_profiles: GetLong,
    put_profiles: PutLong,
    get_edge_traversal: GetBool,
    _put_edge_traversal: Slot,
    /// Slot 41.
    get_action: GetLong,
    /// Slot 42, the last of `INetFwRule`.
    put_action: PutLong,
}

/// `INetFwRule2Vtbl` up to `get_EdgeTraversalOptions`.
#[repr(C)]
struct Rule2Vtbl {
    rule: RuleVtbl,
    /// Slot 43.
    get_edge_traversal_options: GetLong,
}

/// `INetFwRule3Vtbl` up to `get_SecureFlags`.
#[repr(C)]
struct Rule3Vtbl {
    rule2: Rule2Vtbl,
    _put_edge_traversal_options: Slot,
    get_local_app_package_id: GetBstr,
    _put_local_app_package_id: Slot,
    get_local_user_owner: GetBstr,
    _put_local_user_owner: Slot,
    get_local_user_authorized_list: GetBstr,
    _put_local_user_authorized_list: Slot,
    get_remote_user_authorized_list: GetBstr,
    _put_remote_user_authorized_list: Slot,
    get_remote_machine_authorized_list: GetBstr,
    _put_remote_machine_authorized_list: Slot,
    /// Slot 55.
    get_secure_flags: GetLong,
}

/// `IEnumVARIANTVtbl` up to `Next`.
#[repr(C)]
struct EnumVtbl {
    unknown: UnknownVtbl,
    /// Slot 3.
    next: unsafe extern "system" fn(
        this: *mut c_void,
        celt: u32,
        out: *mut VARIANT,
        fetched: *mut u32,
    ) -> HRESULT,
}

// SAFETY: `repr(C)`, first field `DispatchVtbl` (which starts with `UnknownVtbl`), slots checked
// by `vtable_slots_match_netfw_h`.
unsafe impl Vtable for PolicyVtbl {}
// SAFETY: as for `PolicyVtbl`.
unsafe impl Vtable for RulesVtbl {}
// SAFETY: as for `PolicyVtbl`.
unsafe impl Vtable for RuleVtbl {}
// SAFETY: as for `PolicyVtbl`.
unsafe impl Vtable for Rule2Vtbl {}
// SAFETY: as for `PolicyVtbl`.
unsafe impl Vtable for Rule3Vtbl {}
// SAFETY: `repr(C)`, first field `UnknownVtbl`, slot checked by `vtable_slots_match_netfw_h`.
unsafe impl Vtable for EnumVtbl {}

/// A failed read: the call and its `HRESULT`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fail {
    /// The call failed with this `HRESULT`.
    Hr(&'static str, HRESULT),
    /// The call returned a text longer than `MAX_TEXT_UTF16`: Rerun's own bound, never mixed
    /// up with an `HRESULT` a getter returns itself.
    TooLong(&'static str),
    /// A text to set holds a NUL or is longer than `MAX_TEXT_UTF16` (or its `BSTR` could not
    /// be allocated): nothing was set.
    Text(&'static str),
}

/// `$com.$slot(out)` for a `BSTR` property, bounded: `Result<String, Fail>`. `$slot` must be a
/// field of `$com`'s vtable, so the getter always belongs to the object it is called on.
macro_rules! text {
    ($com:expr, $slot:ident, $call:literal) => {{
        let c = &$com;
        let mut b = Bstr::null();
        // SAFETY: `c` is a live interface (one reference held by `Com`) whose vtable types
        // `$slot` as a BSTR getter (netfw.h, pinned by `vtable_slots_match_netfw_h`); `b.0` is
        // a valid BSTR slot that `b` frees afterwards.
        let hr = unsafe { (c.vtbl().$slot)(c.as_raw(), &mut b.0) };
        if hr < 0 {
            Err(Fail::Hr($call, hr))
        } else {
            b.text(MAX_TEXT_UTF16).ok_or(Fail::TooLong($call))
        }
    }};
}

/// `$com.$slot(out)` for a `long` or enum property: `Result<i32, Fail>`.
macro_rules! long {
    ($com:expr, $slot:ident, $call:literal) => {{
        let c = &$com;
        let mut v: i32 = 0;
        // SAFETY: `c` is a live interface whose vtable types `$slot` as a `long` getter
        // (netfw.h, pinned by the slot test); `v` is valid for a write.
        let hr = unsafe { (c.vtbl().$slot)(c.as_raw(), &mut v) };
        if hr < 0 {
            Err(Fail::Hr($call, hr))
        } else {
            Ok(v)
        }
    }};
}

/// `$com.$slot(out)` for a `VARIANT_BOOL` property: `Result<bool, Fail>`.
macro_rules! flag {
    ($com:expr, $slot:ident, $call:literal) => {{
        let c = &$com;
        let mut v: i16 = 0;
        // SAFETY: `c` is a live interface whose vtable types `$slot` as a `VARIANT_BOOL` getter
        // (netfw.h, pinned by the slot test); `v` is valid for a write.
        let hr = unsafe { (c.vtbl().$slot)(c.as_raw(), &mut v) };
        if hr < 0 {
            Err(Fail::Hr($call, hr))
        } else {
            Ok(v != 0)
        }
    }};
}

/// `$com.$slot(value)` for a `BSTR` property: `Result<(), Fail>`. The `BSTR` is allocated for
/// the call and freed afterwards (the callee copies it).
macro_rules! put_text {
    ($com:expr, $slot:ident, $call:literal, $value:expr) => {{
        let c = &$com;
        let b = Bstr::new($value, MAX_TEXT_UTF16).ok_or(Fail::Text($call))?;
        // SAFETY: `c` is a live interface whose vtable types `$slot` as a BSTR setter (netfw.h,
        // pinned by the slot test); `b.0` is a valid BSTR that outlives the call.
        let hr = unsafe { (c.vtbl().$slot)(c.as_raw(), b.0) };
        if hr < 0 {
            Err(Fail::Hr($call, hr))
        } else {
            Ok(())
        }
    }};
}

/// `$com.$slot(value)` for a `long` or enum property: `Result<(), Fail>`.
macro_rules! put_long {
    ($com:expr, $slot:ident, $call:literal, $value:expr) => {{
        let c = &$com;
        // SAFETY: `c` is a live interface whose vtable types `$slot` as a `long` setter (netfw.h,
        // pinned by the slot test); the value is passed by value.
        let hr = unsafe { (c.vtbl().$slot)(c.as_raw(), $value) };
        if hr < 0 {
            Err(Fail::Hr($call, hr))
        } else {
            Ok(())
        }
    }};
}

/// `$com.$slot(value)` for a `VARIANT_BOOL` property (`VARIANT_TRUE` = -1): `Result<(), Fail>`.
macro_rules! put_flag {
    ($com:expr, $slot:ident, $call:literal, $value:expr) => {{
        let c = &$com;
        let v: i16 = if $value { -1 } else { 0 };
        // SAFETY: `c` is a live interface whose vtable types `$slot` as a `VARIANT_BOOL` setter
        // (netfw.h, pinned by the slot test); the value is passed by value.
        let hr = unsafe { (c.vtbl().$slot)(c.as_raw(), v) };
        if hr < 0 {
            Err(Fail::Hr($call, hr))
        } else {
            Ok(())
        }
    }};
}

/// `QueryInterface` that maps `E_NOINTERFACE` to `None`.
///
/// # Safety
/// `W` is the vtable of the interface `iid` names.
unsafe fn optional<V: Vtable, W: Vtable>(
    c: &Com<V>,
    iid: &GUID,
    call: &'static str,
) -> Result<Option<Com<W>>, Fail> {
    // SAFETY: forwarded from the caller.
    match unsafe { c.cast::<W>(iid) } {
        Ok(w) => Ok(Some(w)),
        Err(E_NOINTERFACE) => Ok(None),
        Err(hr) => Err(Fail::Hr(call, hr)),
    }
}

impl Com<RuleVtbl> {
    /// Sets the fields of Rerun's rule form on a fresh rule object (P4-5b); every other field
    /// keeps the object's default. Protocol before anything that depends on it (`netfw.h`:
    /// ports and ICMP types need the protocol first; none is set here).
    fn fill(&self, r: &FwRule) -> Result<(), Fail> {
        put_text!(self, put_name, "put_Name", &r.name)?;
        put_text!(self, put_description, "put_Description", &r.description)?;
        put_text!(
            self,
            put_application_name,
            "put_ApplicationName",
            &r.program
        )?;
        put_text!(self, put_grouping, "put_Grouping", &r.grouping)?;
        put_long!(self, put_protocol, "put_Protocol", r.protocol)?;
        put_long!(self, put_direction, "put_Direction", r.direction)?;
        put_long!(self, put_action, "put_Action", r.action)?;
        put_long!(self, put_profiles, "put_Profiles", r.profiles)?;
        put_flag!(self, put_enabled, "put_Enabled", r.enabled)
    }

    fn name_and_group(&self) -> Result<(String, String), Fail> {
        Ok((
            text!(self, get_name, "get_Name")?,
            text!(self, get_grouping, "get_Grouping")?,
        ))
    }

    fn read(&self, name: String, grouping: String) -> Result<FwRule, Fail> {
        let mut interfaces = Variant::empty();
        // SAFETY: `self` is a live INetFwRule; slot 29 is get_Interfaces; `interfaces` is a
        // VARIANT slot that its guard clears.
        let hr = unsafe { (self.vtbl().get_interfaces)(self.as_raw(), &mut interfaces.0) };
        if hr < 0 {
            return Err(Fail::Hr("get_Interfaces", hr));
        }
        // SAFETY: `Rule2Vtbl` is the vtable of INetFwRule2, the interface IID_RULE2 names.
        let r2 = unsafe { optional::<_, Rule2Vtbl>(self, &IID_RULE2, "INetFwRule2") }?;
        // SAFETY: `Rule3Vtbl` is the vtable of INetFwRule3, the interface IID_RULE3 names.
        let r3 = unsafe { optional::<_, Rule3Vtbl>(self, &IID_RULE3, "INetFwRule3") }?;
        let edge_options = match &r2 {
            Some(r2) => Some(long!(
                r2,
                get_edge_traversal_options,
                "get_EdgeTraversalOptions"
            )?),
            None => None,
        };
        let v3 = match &r3 {
            Some(r3) => Some(FwRule3 {
                package_id: text!(r3, get_local_app_package_id, "get_LocalAppPackageId")?,
                user_owner: text!(r3, get_local_user_owner, "get_LocalUserOwner")?,
                local_users: text!(
                    r3,
                    get_local_user_authorized_list,
                    "get_LocalUserAuthorizedList"
                )?,
                remote_users: text!(
                    r3,
                    get_remote_user_authorized_list,
                    "get_RemoteUserAuthorizedList"
                )?,
                remote_machines: text!(
                    r3,
                    get_remote_machine_authorized_list,
                    "get_RemoteMachineAuthorizedList"
                )?,
                secure_flags: long!(r3, get_secure_flags, "get_SecureFlags")?,
            }),
            None => None,
        };
        Ok(FwRule {
            name,
            description: text!(self, get_description, "get_Description")?,
            grouping,
            program: text!(self, get_application_name, "get_ApplicationName")?,
            direction: long!(self, get_direction, "get_Direction")?,
            action: long!(self, get_action, "get_Action")?,
            profiles: long!(self, get_profiles, "get_Profiles")?,
            protocol: long!(self, get_protocol, "get_Protocol")?,
            enabled: flag!(self, get_enabled, "get_Enabled")?,
            rest: FwRest {
                service: text!(self, get_service_name, "get_ServiceName")?,
                local_ports: text!(self, get_local_ports, "get_LocalPorts")?,
                remote_ports: text!(self, get_remote_ports, "get_RemotePorts")?,
                local_addresses: text!(self, get_local_addresses, "get_LocalAddresses")?,
                remote_addresses: text!(self, get_remote_addresses, "get_RemoteAddresses")?,
                icmp_types: text!(self, get_icmp_types_and_codes, "get_IcmpTypesAndCodes")?,
                interface_types: text!(self, get_interface_types, "get_InterfaceTypes")?,
                interfaces: interfaces.vt() != VT_EMPTY,
                edge_traversal: flag!(self, get_edge_traversal, "get_EdgeTraversal")?,
                edge_options,
                v3,
            },
        })
    }
}

/// Why an enumeration or a write stopped.
#[derive(Debug, Clone, PartialEq, Eq)]
enum EnumError {
    Create(CreateError),
    Apartment(HRESULT),
    Call(Fail),
    /// A collection element that is no `VT_DISPATCH`.
    Element(u16),
    TooMany,
    Deadline,
    /// A rule to add whose fields beyond the rule form differ from a fresh rule object's: the
    /// write side sets only the form's fields (P4-5b), so it refuses rather than add another.
    Rest,
}

impl From<Fail> for EnumError {
    fn from(f: Fail) -> Self {
        Self::Call(f)
    }
}

/// The rule collection of `HNetCfg.FwPolicy2` (the caller is in an [`Apartment`]).
fn rule_collection() -> Result<Com<RulesVtbl>, EnumError> {
    // SAFETY: `PolicyVtbl` is the vtable prefix of INetFwPolicy2, the interface IID_POLICY2
    // names.
    let policy = unsafe { create_inproc::<PolicyVtbl>(&NetFwPolicy2, &IID_POLICY2) }
        .map_err(EnumError::Create)?;
    let mut raw = ptr::null_mut();
    // SAFETY: `policy` is a live INetFwPolicy2; slot 18 is get_Rules; `raw` is a valid location.
    let hr = unsafe { (policy.vtbl().get_rules)(policy.as_raw(), &mut raw) };
    if hr < 0 {
        return Err(Fail::Hr("get_Rules", hr).into());
    }
    // SAFETY: on success `raw` is an INetFwRules with one reference owned by the caller.
    Ok(unsafe { Com::<RulesVtbl>::from_raw(raw) }.ok_or(Fail::Hr("get_Rules", E_POINTER))?)
}

/// One enumeration (module docs).
fn enumerate(keep: &dyn Fn(&str, &str) -> bool) -> Result<FwSelection, EnumError> {
    let start = Instant::now();
    let _apartment = Apartment::enter().map_err(EnumError::Apartment)?;
    let rules = rule_collection()?;
    let count = long!(rules, get_count, "get_Count")?;
    if !usize::try_from(count).is_ok_and(|c| c <= MAX_RULES) {
        return Err(EnumError::TooMany);
    }
    let mut raw = ptr::null_mut();
    // SAFETY: `rules` is live; slot 11 is get__NewEnum; `raw` is a valid location.
    let hr = unsafe { (rules.vtbl().get_new_enum)(rules.as_raw(), &mut raw) };
    if hr < 0 {
        return Err(Fail::Hr("get__NewEnum", hr).into());
    }
    // SAFETY: on success `raw` is an IUnknown with one reference owned by the caller.
    let unknown =
        unsafe { Com::<UnknownVtbl>::from_raw(raw) }.ok_or(Fail::Hr("get__NewEnum", E_POINTER))?;
    // SAFETY: `EnumVtbl` is the vtable prefix of IEnumVARIANT, the interface the IID names.
    let walk = unsafe { unknown.cast::<EnumVtbl>(&IID_ENUM_VARIANT) }
        .map_err(|hr| Fail::Hr("IEnumVARIANT", hr))?;
    let mut out = FwSelection::default();
    loop {
        if start.elapsed() > ENUM_DEADLINE {
            return Err(EnumError::Deadline);
        }
        let mut batch: [Variant; BATCH as usize] = std::array::from_fn(|_| Variant::empty());
        let mut fetched = 0u32;
        // SAFETY: `walk` is a live IEnumVARIANT; slot 3 is Next; `batch` is BATCH VARIANTs in
        // a row (`Variant` is `repr(transparent)`), each VT_EMPTY, which Next may overwrite and
        // the guards clear; `fetched` is valid for a write.
        let hr = unsafe {
            (walk.vtbl().next)(
                walk.as_raw(),
                BATCH,
                batch.as_mut_ptr().cast::<VARIANT>(),
                &mut fetched,
            )
        };
        if hr < 0 {
            return Err(Fail::Hr("IEnumVARIANT::Next", hr).into());
        }
        let n = fetched.min(BATCH) as usize;
        for v in &batch[..n] {
            out.total += 1;
            if out.total > MAX_RULES {
                return Err(EnumError::TooMany);
            }
            if v.vt() != VT_DISPATCH {
                return Err(EnumError::Element(v.vt()));
            }
            // SAFETY: a VT_DISPATCH variant holds an IDispatch (or null) that the variant owns;
            // `ManuallyDrop` keeps this borrowed view from releasing that reference.
            let Some(d) = (unsafe { Com::<DispatchVtbl>::from_raw(v.object()) }) else {
                return Err(EnumError::Element(VT_EMPTY));
            };
            let d = ManuallyDrop::new(d);
            // SAFETY: `RuleVtbl` is the vtable of INetFwRule, the interface IID_RULE names.
            let rule = unsafe { d.cast::<RuleVtbl>(&IID_RULE) }
                .map_err(|hr| Fail::Hr("INetFwRule", hr))?;
            let (name, grouping) = rule.name_and_group()?;
            if keep(&name, &grouping) {
                out.rules.push(rule.read(name, grouping)?);
            }
        }
        if hr == S_FALSE || fetched < BATCH {
            return Ok(out);
        }
    }
}

/// `INetFwRules::Add` of a fresh `HNetCfg.FWRule` object with the fields of `r` (P4-5b). The
/// fields beyond the rule form are never set: `r.rest` must be what the fresh object holds
/// (`policy::firewall::rest`), else [`EnumError::Rest`] before anything is added.
fn add_rule(r: &FwRule) -> Result<(), EnumError> {
    let _apartment = Apartment::enter().map_err(EnumError::Apartment)?;
    let rules = rule_collection()?;
    // SAFETY: `RuleVtbl` is the vtable of INetFwRule, the interface IID_RULE names.
    let obj =
        unsafe { create_inproc::<RuleVtbl>(&NetFwRule, &IID_RULE) }.map_err(EnumError::Create)?;
    let (name, grouping) = obj.name_and_group()?;
    if obj.read(name, grouping)?.rest != r.rest {
        return Err(EnumError::Rest);
    }
    obj.fill(r)?;
    // SAFETY: `rules` is a live INetFwRules; slot 8 is Add; `obj` is a live INetFwRule, which
    // the collection takes its own reference to (ours is released when `obj` drops).
    let hr = unsafe { (rules.vtbl().add)(rules.as_raw(), obj.as_raw()) };
    if hr < 0 {
        return Err(Fail::Hr("INetFwRules::Add", hr).into());
    }
    Ok(())
}

/// `INetFwRules::Remove(name)` (P4-5b): what it removes (every rule of the name, or one; the
/// case of the name) is the [SB] write contract's measurement.
fn remove_rule(name: &str) -> Result<(), EnumError> {
    let _apartment = Apartment::enter().map_err(EnumError::Apartment)?;
    let rules = rule_collection()?;
    put_text!(rules, remove, "INetFwRules::Remove", name)?;
    Ok(())
}

fn sys_error(e: EnumError, t: &str) -> SysError {
    match e {
        EnumError::Create(CreateError::Env(EnvMismatch::Var(v))) => SysError::new(
            SysErrorKind::Other,
            format!("{t}: the environment variable {v} does not name the Windows folder"),
        ),
        EnumError::Create(CreateError::Env(EnvMismatch::Windows(c))) => {
            SysError::new(SysErrorKind::Other, format!("{t}: the Windows folder")).with_win32(c)
        }
        EnumError::Create(CreateError::Com(hr)) => {
            SysError::new(kind_of_hresult(hr), format!("{t}: HNetCfg.FwPolicy2")).with_hresult(hr)
        }
        EnumError::Create(CreateError::NotAllowed) => SysError::new(
            SysErrorKind::Unsupported,
            format!("{t}: a COM class outside the allowlist"),
        ),
        EnumError::Apartment(hr) => {
            SysError::new(SysErrorKind::Other, format!("{t}: CoInitializeEx")).with_hresult(hr)
        }
        EnumError::Call(Fail::TooLong(call)) => {
            SysError::too_large(format!("{t}: {call}"), MAX_TEXT_UTF16 as u64)
        }
        EnumError::Call(Fail::Hr(call, hr)) => {
            SysError::new(kind_of_hresult(hr), format!("{t}: {call}")).with_hresult(hr)
        }
        EnumError::Element(vt) => {
            SysError::new(SysErrorKind::Other, format!("{t}: an element of type {vt}"))
        }
        EnumError::TooMany => SysError::too_large(t, MAX_RULES as u64),
        EnumError::Call(Fail::Text(call)) => SysError::new(
            SysErrorKind::Other,
            format!("{t}: {call}: a text with a NUL or longer than {MAX_TEXT_UTF16} units"),
        ),
        EnumError::Rest => SysError::new(
            SysErrorKind::Unsupported,
            format!("{t}: fields beyond Rerun's rule form are not set by this write side"),
        ),
        EnumError::Deadline => {
            SysError::too_large(format!("{t}: seconds"), ENUM_DEADLINE.as_secs())
        }
    }
}

fn kind_of_hresult(hr: HRESULT) -> SysErrorKind {
    if hr == E_ACCESSDENIED {
        SysErrorKind::AccessDenied
    } else {
        SysErrorKind::Other
    }
}

/// The real [`Firewall`] read side.
#[derive(Debug, Clone, Copy, Default)]
pub struct WinFirewall;

impl Firewall for WinFirewall {
    fn select(&self, keep: &dyn Fn(&str, &str) -> bool) -> SysResult<FwSelection> {
        enumerate(keep).map_err(|e| sys_error(e, "firewall rules"))
    }
}

/// The real [`FirewallWrite`] (P4-5b): only `WinHelperSystem` hands it out, and only
/// `policy::firewall` calls it (`clippy.toml`). Without administrator rights the firewall
/// service refuses every write (`E_ACCESSDENIED`).
#[derive(Debug, Clone, Copy, Default)]
pub struct WinFirewallWrite;

impl FirewallWrite for WinFirewallWrite {
    fn add(&self, rule: &FwRule) -> SysResult<()> {
        add_rule(rule).map_err(|e| sys_error(e, "firewall rules, add"))
    }

    fn remove_named(&self, name: &str) -> SysResult<()> {
        remove_rule(name).map_err(|e| sys_error(e, "firewall rules, remove"))
    }
}

#[cfg(test)]
mod tests {
    use std::mem::{offset_of, size_of};

    use windows_sys::Win32::NetworkManagement::WindowsFirewall as wf;

    use super::*;
    use crate::sys::firewall;

    /// Slot numbers from the `*Vtbl` structs in netfw.h and oaidl.h (SDK 10.0.26100).
    #[test]
    fn vtable_slots_match_netfw_h() {
        let slot = |n: usize| n * size_of::<usize>();
        assert_eq!(offset_of!(PolicyVtbl, get_rules), slot(18));
        assert_eq!(offset_of!(RulesVtbl, get_count), slot(7));
        assert_eq!(offset_of!(RulesVtbl, add), slot(8));
        assert_eq!(offset_of!(RulesVtbl, remove), slot(9));
        assert_eq!(offset_of!(RulesVtbl, get_new_enum), slot(11));
        assert_eq!(offset_of!(RuleVtbl, get_name), slot(7));
        assert_eq!(offset_of!(RuleVtbl, get_description), slot(9));
        assert_eq!(offset_of!(RuleVtbl, get_application_name), slot(11));
        assert_eq!(offset_of!(RuleVtbl, get_service_name), slot(13));
        assert_eq!(offset_of!(RuleVtbl, get_protocol), slot(15));
        assert_eq!(offset_of!(RuleVtbl, get_local_ports), slot(17));
        assert_eq!(offset_of!(RuleVtbl, get_remote_ports), slot(19));
        assert_eq!(offset_of!(RuleVtbl, get_local_addresses), slot(21));
        assert_eq!(offset_of!(RuleVtbl, get_remote_addresses), slot(23));
        assert_eq!(offset_of!(RuleVtbl, get_icmp_types_and_codes), slot(25));
        assert_eq!(offset_of!(RuleVtbl, get_direction), slot(27));
        assert_eq!(offset_of!(RuleVtbl, get_interfaces), slot(29));
        assert_eq!(offset_of!(RuleVtbl, get_interface_types), slot(31));
        assert_eq!(offset_of!(RuleVtbl, get_enabled), slot(33));
        assert_eq!(offset_of!(RuleVtbl, get_grouping), slot(35));
        assert_eq!(offset_of!(RuleVtbl, get_profiles), slot(37));
        assert_eq!(offset_of!(RuleVtbl, get_edge_traversal), slot(39));
        assert_eq!(offset_of!(RuleVtbl, get_action), slot(41));
        // The setters of the rule form (P4-5b): each right after its getter.
        assert_eq!(offset_of!(RuleVtbl, put_name), slot(8));
        assert_eq!(offset_of!(RuleVtbl, put_description), slot(10));
        assert_eq!(offset_of!(RuleVtbl, put_application_name), slot(12));
        assert_eq!(offset_of!(RuleVtbl, put_protocol), slot(16));
        assert_eq!(offset_of!(RuleVtbl, put_direction), slot(28));
        assert_eq!(offset_of!(RuleVtbl, put_enabled), slot(34));
        assert_eq!(offset_of!(RuleVtbl, put_grouping), slot(36));
        assert_eq!(offset_of!(RuleVtbl, put_profiles), slot(38));
        assert_eq!(offset_of!(RuleVtbl, put_action), slot(42));
        assert_eq!(size_of::<RuleVtbl>(), slot(43));
        assert_eq!(offset_of!(Rule2Vtbl, get_edge_traversal_options), slot(43));
        assert_eq!(offset_of!(Rule3Vtbl, get_local_app_package_id), slot(45));
        assert_eq!(offset_of!(Rule3Vtbl, get_local_user_owner), slot(47));
        assert_eq!(
            offset_of!(Rule3Vtbl, get_local_user_authorized_list),
            slot(49)
        );
        assert_eq!(
            offset_of!(Rule3Vtbl, get_remote_user_authorized_list),
            slot(51)
        );
        assert_eq!(
            offset_of!(Rule3Vtbl, get_remote_machine_authorized_list),
            slot(53)
        );
        assert_eq!(offset_of!(Rule3Vtbl, get_secure_flags), slot(55));
        assert_eq!(offset_of!(EnumVtbl, next), slot(3));
        assert_eq!(size_of::<Variant>(), size_of::<VARIANT>());
        assert_eq!(size_of::<VARIANT>(), 24);
    }

    #[test]
    fn iids_match_netfw_h_and_oaidl_h() {
        let parts = |g: GUID| (g.data1, g.data2, g.data3, g.data4);
        // MIDL_INTERFACE("98325047-C671-4174-8D81-DEFCD3F03186") INetFwPolicy2
        assert_eq!(
            parts(IID_POLICY2),
            (
                0x9832_5047,
                0xc671,
                0x4174,
                [0x8d, 0x81, 0xde, 0xfc, 0xd3, 0xf0, 0x31, 0x86]
            )
        );
        // MIDL_INTERFACE("AF230D27-BABA-4E42-ACED-F524F22CFCE2") INetFwRule
        assert_eq!(
            parts(IID_RULE),
            (
                0xaf23_0d27,
                0xbaba,
                0x4e42,
                [0xac, 0xed, 0xf5, 0x24, 0xf2, 0x2c, 0xfc, 0xe2]
            )
        );
        // MIDL_INTERFACE("9C27C8DA-189B-4DDE-89F7-8B39A316782C") INetFwRule2
        assert_eq!(
            parts(IID_RULE2),
            (
                0x9c27_c8da,
                0x189b,
                0x4dde,
                [0x89, 0xf7, 0x8b, 0x39, 0xa3, 0x16, 0x78, 0x2c]
            )
        );
        // MIDL_INTERFACE("B21563FF-D696-4222-AB46-4E89B73AB34A") INetFwRule3
        assert_eq!(
            parts(IID_RULE3),
            (
                0xb215_63ff,
                0xd696,
                0x4222,
                [0xab, 0x46, 0x4e, 0x89, 0xb7, 0x3a, 0xb3, 0x4a]
            )
        );
        // MIDL_INTERFACE("00020404-0000-0000-C000-000000000046") IEnumVARIANT
        assert_eq!(
            parts(IID_ENUM_VARIANT),
            (0x0002_0404, 0, 0, [0xc0, 0, 0, 0, 0, 0, 0, 0x46])
        );
    }

    /// A4 S6 d: a fresh `HNetCfg.FWRule` object (created in this process, never added to the
    /// policy) reads back the fields Rerun leaves at their default as `policy::firewall::rest`.
    #[test]
    fn a_fresh_rule_object_has_the_default_rest() {
        let _apartment = Apartment::enter().unwrap();
        // SAFETY: `RuleVtbl` is the vtable of INetFwRule, the interface IID_RULE names.
        let rule = unsafe { create_inproc::<RuleVtbl>(&wf::NetFwRule, &IID_RULE) }.unwrap();
        let (name, grouping) = rule.name_and_group().unwrap();
        let fresh = rule.read(name, grouping).unwrap();
        eprintln!("MEASURED fresh rule object: {fresh:?}");
        assert_eq!(fresh.rest, crate::policy::firewall::rest());
    }

    /// P4-5b, the setters without the firewall: a fresh `HNetCfg.FWRule` object in this process
    /// (never added to the policy, so nothing on the machine changes) takes Rerun's rule form
    /// through `fill` and reads it back exactly through the getters. That an *added* rule reads
    /// back the same is the [SB] write contract (`sb_firewall_write_contract`).
    #[test]
    fn a_fresh_rule_object_takes_rerun_s_form() {
        use crate::catalog::model::Id;
        use crate::policy::firewall::{Direction, Program, rule};
        let _apartment = Apartment::enter().unwrap();
        let topo = Id::parse("setter-check").unwrap();
        let txn = "00000001-00000000000000ab".parse().unwrap();
        let program = Program::parse(r"C:\Games\Setter Check\bin\Game.exe").unwrap();
        let want = rule(&topo, &txn, 7, &program, Direction::Out);
        // SAFETY: `RuleVtbl` is the vtable of INetFwRule, the interface IID_RULE names.
        let obj = unsafe { create_inproc::<RuleVtbl>(&wf::NetFwRule, &IID_RULE) }.unwrap();
        obj.fill(&want).unwrap();
        let (name, grouping) = obj.name_and_group().unwrap();
        let got = obj.read(name, grouping).unwrap();
        eprintln!("MEASURED filled rule object: {got:?}");
        assert_eq!(got, want);
        // A text with a NUL is refused before anything is set.
        let nul = FwRule {
            name: "Rerun - a\0b".to_owned(),
            ..want
        };
        assert_eq!(obj.fill(&nul), Err(Fail::Text("put_Name")));
    }

    #[test]
    fn sys_constants_match_windows_sys() {
        assert_eq!(firewall::DIR_IN, wf::NET_FW_RULE_DIR_IN);
        assert_eq!(firewall::DIR_OUT, wf::NET_FW_RULE_DIR_OUT);
        assert_eq!(firewall::ACTION_BLOCK, wf::NET_FW_ACTION_BLOCK);
        assert_eq!(firewall::ACTION_ALLOW, wf::NET_FW_ACTION_ALLOW);
        assert_eq!(firewall::PROFILES_ALL, wf::NET_FW_PROFILE2_ALL);
        assert_eq!(firewall::PROTOCOL_ANY, wf::NET_FW_IP_PROTOCOL_ANY);
    }
}
