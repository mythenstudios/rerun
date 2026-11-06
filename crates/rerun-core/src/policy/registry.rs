//! `policy::registry`: which registry values Rerun may write (ADR 0018, amendment P2-9).
//!
//! `sys` executes, this module decides (ADR 0004). A write names a [`RegSlot`]; [`RegPolicy::check`]
//! turns it into an [`AllowedValue`] (the exact key, the anchor below which keys may be
//! created, the value name), [`RegPolicy::check_new`] decides whether a new value may be
//! written there, and [`RegWriter`] is the only way to reach [`RegistryWrite`]
//! (`System::registry_write` is a `clippy.toml` ban everywhere else).
//!
//! - `HKCU` only, native view; `HKLM` is `NeedsHelper` (the GUI never writes it, core rule 6).
//! - `CompatLayers`: `HKCU\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers`,
//!   the value name the canonical path of an executable in a plan root, built from the root's
//!   path (parsed again) and a [`RelPath`] (M2); new values are refused until `compat_layer`
//!   (P2-11) brings its token allowlist.
//! - `GameValue`: `HKCU\Software\<Vendor>\<Product>` plus at most 4 segments, printable ASCII,
//!   `<Vendor>` not on the deny list (folded); value names printable ASCII without `\ / : %`;
//!   new values `REG_DWORD`, `REG_QWORD` or a `REG_SZ` of printable ASCII (review M1: no best-fit
//!   or bidi characters) without `\ / : %` (G1: no paths, no variables), at most 1,024 units.
//! - `GpuPreference`: reserved (phase 4), refused.
//!
//! The rules guard what a Topo may ask for (phase 4); they are never loosened for a caller.
//! Old values are restored exactly whatever they are ([`RegWriter::restore`] does not apply
//! [`RegPolicy::check_new`]).

use std::fmt;

use crate::fold::fold;
use crate::path::{RelPath, RootPath};
use crate::plan::RootIx;
use crate::sys::registry::{
    Hive, KeyState, MAX_VALUE_NAME_UTF16, RegKey, RegValue, RegView, RegistryWrite,
};
use crate::sys::{SysError, SysErrorKind, SysResult, System};

/// The fixed key of `AppCompatFlags\Layers` below `HKCU`.
const LAYERS: &str = r"Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers";
/// Segments of [`LAYERS`] that must exist (`…\CurrentVersion`): `AppCompatFlags` and `Layers`
/// may be created.
const LAYERS_ANCHOR: usize = 4;
/// The reserved key of `UserGpuPreferences` below `HKCU`.
const GPU_PREFERENCES: &str = r"Software\Microsoft\DirectX\UserGpuPreferences";
/// Segments of a game key that must exist (`Software`).
const GAME_ANCHOR: usize = 1;

/// `<Vendor>` names a game key may not use (compared folded, ADR 0018 and G1).
pub const VENDOR_DENY: [&str; 11] = [
    "Microsoft",
    "Classes",
    "Policies",
    "Wow6432Node",
    "Clients",
    "RegisteredApplications",
    "AppDataLow",
    "Valve",
    "Rerun",
    "Mythen Studios",
    "Khronos",
];

/// Longest key segment of a game key.
pub const MAX_SEGMENT: usize = 64;
/// Longest value name of a game value.
pub const MAX_NAME: usize = 128;
/// Most segments of a game key below `<Product>`.
pub const MAX_REST: usize = 4;
/// Longest `REG_SZ` of a game value in UTF-16 units.
pub const MAX_SZ_UTF16: usize = 1_024;
/// Characters a game value name and its string data may not hold (G1: no path, no variable).
pub const NOT_IN_TEXT: [char; 4] = ['\\', '/', ':', '%'];

/// Why `policy::registry` refuses.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RegPolicyError {
    /// A key outside `HKCU`: only the elevated helper (phase 3) writes there.
    #[error("{0}: needs the elevated helper (phase 3)")]
    NeedsHelper(String),
    /// A slot reserved for a later phase.
    #[error("{0}: reserved until its phase")]
    Reserved(String),
    /// Allowed in principle, not yet (`compat_layer` lands in P2-11).
    #[error("{0}: not supported yet")]
    Unsupported(String),
    /// The slot or the value breaks a rule.
    #[error("{what}: {why}")]
    Denied {
        /// What was checked.
        what: String,
        /// The rule.
        why: &'static str,
    },
    /// The slot names a root the plan does not have.
    #[error("root {0} is not in the plan")]
    UnknownRoot(u16),
}

#[cfg(test)]
thread_local! {
    /// Control K-R6: the vendor deny list is compared without folding.
    pub(crate) static KNOB_UNFOLDED_DENY: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// Control K-R6: the G1 content rule is off.
    pub(crate) static KNOB_NO_CONTENT_RULE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

fn unfolded_deny() -> bool {
    #[cfg(test)]
    return KNOB_UNFOLDED_DENY.with(std::cell::Cell::get);
    #[cfg(not(test))]
    false
}

/// `s` holds one of [`NOT_IN_TEXT`] (G1).
fn path_like(s: &str) -> bool {
    #[cfg(test)]
    if KNOB_NO_CONTENT_RULE.with(std::cell::Cell::get) {
        return false;
    }
    s.contains(NOT_IN_TEXT)
}

fn denied(what: impl fmt::Display, why: &'static str) -> RegPolicyError {
    RegPolicyError::Denied {
        what: what.to_string(),
        why,
    }
}

/// Printable ASCII (`0x20` to `0x7E`) without `\` and without a space at either end.
fn ascii_rule(s: &str) -> Option<&'static str> {
    if !s.bytes().all(|b| (0x20..=0x7E).contains(&b)) {
        Some("only printable ASCII")
    } else if s.contains('\\') {
        Some("no backslash")
    } else if s.starts_with(' ') || s.ends_with(' ') {
        Some("no space at either end")
    } else {
        None
    }
}

/// One segment of a game key: printable ASCII, 1 to [`MAX_SEGMENT`] characters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AsciiSeg(String);

impl AsciiSeg {
    /// Checks a segment.
    pub fn parse(s: &str) -> Result<Self, RegPolicyError> {
        if s.is_empty() || s.len() > MAX_SEGMENT {
            return Err(denied(
                format!("{s:?}"),
                "a key segment has 1 to 64 characters",
            ));
        }
        match ascii_rule(s) {
            Some(why) => Err(denied(format!("{s:?}"), why)),
            None => Ok(Self(s.to_owned())),
        }
    }

    /// The segment.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A game value name: printable ASCII without `\ / : %`, 0 to [`MAX_NAME`] characters (`""`
/// is the default value).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AsciiName(String);

impl AsciiName {
    /// Checks a value name.
    pub fn parse(s: &str) -> Result<Self, RegPolicyError> {
        if s.len() > MAX_NAME {
            return Err(denied(
                format!("{s:?}"),
                "a value name has at most 128 characters",
            ));
        }
        if let Some(why) = ascii_rule(s) {
            return Err(denied(format!("{s:?}"), why));
        }
        if path_like(s) {
            return Err(denied(
                format!("{s:?}"),
                "no path or variable characters (\\ / : %)",
            ));
        }
        Ok(Self(s.to_owned()))
    }

    /// The name.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A game key `HKCU\Software\<Vendor>\<Product>[\…]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GameKey {
    vendor: AsciiSeg,
    product: AsciiSeg,
    rest: Vec<AsciiSeg>,
}

impl GameKey {
    /// Checks a game key: `<Vendor>` not on [`VENDOR_DENY`] (folded), at most [`MAX_REST`]
    /// segments below `<Product>`.
    pub fn new(
        vendor: AsciiSeg,
        product: AsciiSeg,
        rest: Vec<AsciiSeg>,
    ) -> Result<Self, RegPolicyError> {
        let hit = if unfolded_deny() {
            VENDOR_DENY.contains(&vendor.as_str())
        } else {
            let v = fold(vendor.as_str());
            VENDOR_DENY.iter().any(|d| fold(d) == v)
        };
        if hit {
            return Err(denied(vendor.as_str(), "this vendor key is not writable"));
        }
        if rest.len() > MAX_REST {
            return Err(denied(
                product.as_str(),
                "at most 4 segments below <Vendor>\\<Product>",
            ));
        }
        Ok(Self {
            vendor,
            product,
            rest,
        })
    }

    /// The path below `HKCU`.
    fn path(&self) -> String {
        let mut p = format!(
            r"Software\{}\{}",
            self.vendor.as_str(),
            self.product.as_str()
        );
        for s in &self.rest {
            p.push('\\');
            p.push_str(s.as_str());
        }
        p
    }
}

/// Where a value is written (ADR 0018).
///
/// On the wire (a plan's `head.json`, ADR 0020 amendment P2-10b) a slot is externally tagged
/// in `snake_case`: `{"game_value":{"vendor":…,"product":…,"rest":[…],"name":…}}`,
/// `{"compat_layers":{"root":0,"exe":"…"}}`, `{"gpu_preference":{…}}`. Deserialising goes
/// through [`AsciiSeg::parse`], [`AsciiName::parse`], [`GameKey::new`] and `RelPath::parse`
/// (amendment P2-9): a manipulated journal cannot name a key the rules refuse.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(try_from = "SlotWire", into = "SlotWire")]
pub enum RegSlot {
    /// `AppCompatFlags\Layers`, value name the canonical path of `exe` in plan root `root`.
    CompatLayers {
        /// The plan root.
        root: RootIx,
        /// The executable, relative to the root.
        exe: RelPath,
    },
    /// A value of a game key.
    GameValue {
        /// The key.
        key: GameKey,
        /// The value name.
        name: AsciiName,
    },
    /// `UserGpuPreferences` (reserved, D8): refused until phase 4.
    GpuPreference {
        /// The plan root.
        root: RootIx,
        /// The executable, relative to the root.
        exe: RelPath,
    },
}

/// [`RegSlot`] on the wire: plain fields, checked by [`TryFrom`].
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
enum SlotWire {
    CompatLayers {
        root: RootIx,
        exe: RelPath,
    },
    GameValue {
        vendor: String,
        product: String,
        rest: Vec<String>,
        name: String,
    },
    GpuPreference {
        root: RootIx,
        exe: RelPath,
    },
}

impl TryFrom<SlotWire> for RegSlot {
    type Error = RegPolicyError;

    fn try_from(w: SlotWire) -> Result<Self, RegPolicyError> {
        Ok(match w {
            SlotWire::CompatLayers { root, exe } => Self::CompatLayers { root, exe },
            SlotWire::GpuPreference { root, exe } => Self::GpuPreference { root, exe },
            SlotWire::GameValue {
                vendor,
                product,
                rest,
                name,
            } => {
                if rest.len() > MAX_REST {
                    return Err(denied(
                        product,
                        "at most 4 segments below <Vendor>\\<Product>",
                    ));
                }
                let rest = rest
                    .iter()
                    .map(|s| AsciiSeg::parse(s))
                    .collect::<Result<Vec<_>, _>>()?;
                Self::GameValue {
                    key: GameKey::new(AsciiSeg::parse(&vendor)?, AsciiSeg::parse(&product)?, rest)?,
                    name: AsciiName::parse(&name)?,
                }
            }
        })
    }
}

impl From<RegSlot> for SlotWire {
    fn from(s: RegSlot) -> Self {
        match s {
            RegSlot::CompatLayers { root, exe } => Self::CompatLayers { root, exe },
            RegSlot::GpuPreference { root, exe } => Self::GpuPreference { root, exe },
            RegSlot::GameValue { key, name } => Self::GameValue {
                vendor: key.vendor.0,
                product: key.product.0,
                rest: key.rest.into_iter().map(|s| s.0).collect(),
                name: name.0,
            },
        }
    }
}

/// A key `policy::registry` allows, with its anchor: the first `anchor` segments must exist,
/// the ones below may be created.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllowedKey {
    key: RegKey,
    anchor: usize,
}

impl AllowedKey {
    /// `HKCU` only (`NeedsHelper` otherwise), native view.
    fn new(hive: Hive, path: &str, anchor: usize) -> Result<Self, RegPolicyError> {
        let key = RegKey::new(hive, RegView::Native, path);
        if hive != Hive::CurrentUser {
            return Err(RegPolicyError::NeedsHelper(key.to_string()));
        }
        Ok(Self { key, anchor })
    }

    /// The key.
    pub fn key(&self) -> &RegKey {
        &self.key
    }

    /// The key cut to its first `segs` segments below the hive root, if that lies below the
    /// anchor and at most at the key itself (a `CreateKey` op names its key this way, so no
    /// key outside the slot can be expressed).
    pub(crate) fn cut(&self, segs: u8) -> Option<RegKey> {
        let all: Vec<&str> = self.key.path.split('\\').collect();
        let n = usize::from(segs);
        (n > self.anchor && n <= all.len())
            .then(|| RegKey::new(self.key.hive, self.key.view, all[..n].join("\\")))
    }

    /// The keys from just below the anchor down to the key itself, top-down.
    fn below_anchor(&self) -> Vec<RegKey> {
        let segs: Vec<&str> = self.key.path.split('\\').collect();
        (self.anchor + 1..=segs.len())
            .map(|n| RegKey::new(self.key.hive, self.key.view, segs[..n].join("\\")))
            .collect()
    }
}

/// A value `policy::registry` allows: its key, its name and the slot it came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllowedValue {
    key: AllowedKey,
    name: String,
    slot: RegSlot,
}

impl AllowedValue {
    /// The key.
    pub fn key(&self) -> &AllowedKey {
        &self.key
    }

    /// The value name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The slot.
    pub fn slot(&self) -> &RegSlot {
        &self.slot
    }
}

/// The canonical path of `exe` in `root` as Windows writes it (`D:\Games\X\game.exe`): the
/// root's path parsed again (it may come from the journal) plus the relative path, at most
/// [`MAX_VALUE_NAME_UTF16`] units.
fn exe_name(root: &RootPath, exe: &RelPath) -> Result<String, RegPolicyError> {
    let root = RootPath::new(root.path()).map_err(|e| denied(e.path, "not a plain root path"))?;
    let name = format!("{}\\{}", root, exe.as_str());
    exe_name_fits(&name)?;
    Ok(name)
}

fn exe_name_fits(name: &str) -> Result<(), RegPolicyError> {
    if name.encode_utf16().count() > MAX_VALUE_NAME_UTF16 {
        return Err(denied(
            "executable path",
            "longer than a registry value name may be",
        ));
    }
    Ok(())
}

/// The rules of `policy::registry` (no state in phase 2).
#[derive(Debug, Clone, Copy, Default)]
pub struct RegPolicy;

impl RegPolicy {
    /// The value `slot` names, if allowed. `roots` are the paths of the plan's roots, by
    /// [`RootIx`].
    pub fn check(
        &self,
        slot: &RegSlot,
        roots: &[RootPath],
    ) -> Result<AllowedValue, RegPolicyError> {
        let root_of = |ix: RootIx| {
            roots
                .get(usize::from(ix.0))
                .ok_or(RegPolicyError::UnknownRoot(ix.0))
        };
        match slot {
            RegSlot::CompatLayers { root, exe } => {
                let name = exe_name(root_of(*root)?, exe)?;
                Ok(AllowedValue {
                    key: AllowedKey::new(Hive::CurrentUser, LAYERS, LAYERS_ANCHOR)?,
                    name,
                    slot: slot.clone(),
                })
            }
            RegSlot::GameValue { key, name } => Ok(AllowedValue {
                key: AllowedKey::new(Hive::CurrentUser, &key.path(), GAME_ANCHOR)?,
                name: name.as_str().to_owned(),
                slot: slot.clone(),
            }),
            RegSlot::GpuPreference { .. } => {
                Err(RegPolicyError::Reserved(format!(r"HKCU\{GPU_PREFERENCES}")))
            }
        }
    }

    /// May `new` be written to `v`? Old values are never checked (a restore writes back
    /// exactly what was there).
    pub fn check_new(&self, v: &AllowedValue, new: &RegValue) -> Result<(), RegPolicyError> {
        let what = || format!("{} @ {:?}", v.key.key, v.name);
        match &v.slot {
            RegSlot::CompatLayers { .. } => Err(RegPolicyError::Unsupported(format!(
                "{}: compatibility layers land with compat_layer (P2-11)",
                what()
            ))),
            RegSlot::GpuPreference { .. } => Err(RegPolicyError::Reserved(what())),
            RegSlot::GameValue { .. } => match new {
                RegValue::Dword(_) | RegValue::Qword(_) => Ok(()),
                RegValue::String(s) => {
                    if s.encode_utf16().count() > MAX_SZ_UTF16 {
                        Err(denied(what(), "a REG_SZ has at most 1,024 UTF-16 units"))
                    } else if !s.bytes().all(|b| (0x20..=0x7E).contains(&b)) {
                        // M1 (review): best-fit characters (U+FF1A, U+FF3C, U+2215, ...) turn
                        // into `: \ /` for an ANSI reader, bidi and format characters pass
                        // `is_control`: printable ASCII only, like the value names.
                        Err(denied(what(), "a REG_SZ holds printable ASCII only"))
                    } else if path_like(s) {
                        Err(denied(
                            what(),
                            "no path or variable characters (\\ / : %) in a REG_SZ",
                        ))
                    } else {
                        Ok(())
                    }
                }
                _ => Err(denied(
                    what(),
                    "only REG_DWORD, REG_QWORD and REG_SZ are written",
                )),
            },
        }
    }

    /// The read side of the write side, for planners: state, value and missing keys without
    /// following links (ADR 0018 amendment P2-10b).
    pub fn reader<'s>(&self, sys: &'s dyn System) -> RegReader<'s> {
        #[expect(
            clippy::disallowed_methods,
            reason = "policy::registry is the one caller of System::registry_write (ADR 0018)"
        )]
        let w = sys.registry_write();
        RegReader { w }
    }

    /// The writer over the system's registry write side; the only caller of
    /// `System::registry_write`.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "exec writes the registry through it from P2-10 on"
        )
    )]
    pub(crate) fn writer<'s>(&self, sys: &'s dyn System) -> RegWriter<'s> {
        RegWriter {
            r: self.reader(sys),
            policy: *self,
        }
    }
}

/// What a planner reads of the registry (P2-10b): the methods of the write side that change
/// nothing, so a link or volatile key on the way is reported (`ReparsePoint`,
/// `Unsupported`), never followed.
#[derive(Clone, Copy)]
pub struct RegReader<'s> {
    w: &'s dyn RegistryWrite,
}

impl fmt::Debug for RegReader<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RegReader").finish_non_exhaustive()
    }
}

impl RegReader<'_> {
    /// The state of the key.
    pub fn state(&self, k: &AllowedKey) -> SysResult<KeyState> {
        self.w.key_state(&k.key)
    }

    /// The current value (without following links). Key missing → `NotFound`.
    pub fn get(&self, v: &AllowedValue) -> SysResult<Option<RegValue>> {
        self.w.read(&v.key.key, &v.name)
    }

    /// The missing keys between the anchor and the key itself, top-down: each one a
    /// `CreateKey` op.
    pub fn missing_keys(&self, k: &AllowedKey) -> SysResult<Vec<RegKey>> {
        let mut out = Vec::new();
        for key in k.below_anchor() {
            if !out.is_empty() || self.w.key_state(&key)? == KeyState::Missing {
                out.push(key);
            }
        }
        Ok(out)
    }
}

/// A refused or failed write.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RegWriteError {
    /// The policy refused the new value.
    #[error(transparent)]
    Policy(#[from] RegPolicyError),
    /// The system call failed.
    #[error(transparent)]
    Sys(#[from] SysError),
}

/// The write side, reachable only through `policy::registry`: every method takes an
/// [`AllowedKey`] or [`AllowedValue`].
pub struct RegWriter<'s> {
    r: RegReader<'s>,
    policy: RegPolicy,
}

impl fmt::Debug for RegWriter<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RegWriter").finish_non_exhaustive()
    }
}

/// `k` is `of` itself or one of its keys below the anchor, else `InvalidPath`.
fn inside(k: &RegKey, of: &AllowedKey) -> SysResult<()> {
    if of.below_anchor().contains(k) {
        Ok(())
    } else {
        Err(SysError::new(
            SysErrorKind::InvalidPath,
            format!("{k}: not below the anchor of {}", of.key),
        ))
    }
}

#[expect(
    clippy::disallowed_methods,
    reason = "RegWriter is the one caller of the registry write methods (ADR 0018)"
)]
impl RegWriter<'_> {
    /// The state of the key.
    pub fn state(&self, k: &AllowedKey) -> SysResult<KeyState> {
        self.r.state(k)
    }

    /// The current value (without following links).
    pub fn get(&self, v: &AllowedValue) -> SysResult<Option<RegValue>> {
        self.r.get(v)
    }

    /// The missing keys between the anchor and the key itself, top-down: each one a
    /// `CreateKey` op.
    pub fn missing_keys(&self, k: &AllowedKey) -> SysResult<Vec<RegKey>> {
        self.r.missing_keys(k)
    }

    /// Creates `k`, which must be `of` or one of its keys below the anchor.
    pub fn create_key(&self, k: &RegKey, of: &AllowedKey) -> SysResult<bool> {
        inside(k, of)?;
        self.r.w.create_key(k)
    }

    /// Writes `new` if the current value is `expected` and the policy allows `new` (checked
    /// again here, whatever the caller checked before).
    pub fn set(
        &self,
        v: &AllowedValue,
        expected: Option<&RegValue>,
        new: &RegValue,
    ) -> Result<(), RegWriteError> {
        self.policy.check_new(v, new)?;
        Ok(self.r.w.set(&v.key.key, &v.name, expected, new)?)
    }

    /// Revert: puts `old` back exactly (also a raw or otherwise disallowed value), or deletes
    /// the value for `None`, if the current value is still `expected` (`Mismatch` otherwise).
    pub fn restore(
        &self,
        v: &AllowedValue,
        expected: &RegValue,
        old: Option<&RegValue>,
    ) -> SysResult<()> {
        match old {
            Some(old) => self.r.w.set(&v.key.key, &v.name, Some(expected), old),
            None => self.r.w.delete_value(&v.key.key, &v.name, expected),
        }
    }

    /// Deletes the empty key `k`, which must be `of` or one of its keys below the anchor.
    pub fn delete_empty_key(&self, k: &RegKey, of: &AllowedKey) -> SysResult<()> {
        inside(k, of)?;
        self.r.w.delete_empty_key(k)
    }

    /// Flushes `HKCU`.
    pub fn flush(&self) -> SysResult<()> {
        self.r.w.flush(Hive::CurrentUser)
    }
}

#[cfg(test)]
mod tests;
