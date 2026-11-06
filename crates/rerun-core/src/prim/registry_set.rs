//! `registry_set` (ADR 0020 amendment P2-10b): values below
//! `HKCU\Software\<Vendor>\<Product>[\…]`.
//!
//! The step `{"registry_set":{"key":"HKCU\\Software\\<Vendor>\\<Product>[\\…]","values":[{"name":
//! "Windowed","dword":1},{"name":"Lang","sz":"en"},{"name":"Seed","qword":"18446744073709551615"}]}}`:
//! `key` begins exactly with `HKCU\Software\` (`HKLM\…` needs the elevated helper of phase 3:
//! `PlanError::NeedsHelper`), its segments pass `AsciiSeg::parse` and `GameKey::new` (the vendor
//! deny list, folded; at most 4 segments below `<Product>`); 1 to 32 values, each with a name
//! (`AsciiName::parse`), names unique (folded), and exactly one of `dword` (a number), `qword`
//! (a decimal string without leading zero, `"0"` allowed; no JSON number above 2^53) or `sz`
//! (`null` refused); every new value passes `RegPolicy::check_new` (G1: printable ASCII without
//! `\ / : %`, at most 1,024 characters).
//!
//! Per value, the planner reads the current value through `policy::registry` without following
//! links: equal to the new one, it is omitted (ADR 0020); otherwise a `SetValue` with the old
//! value's `ValueState` (also another type, a raw value, more than 16 KiB; a value over 1 MiB
//! is `TooLarge` and refused). The keys missing between the anchor (`Software`) and the step's
//! key each become a `CreateKey`, top-down and once for all steps. Every registry op goes after
//! every file op of the plan (the builder orders them; `plan::check` refuses anything else).
//!
//! Refused: a link or volatile key on the way (`ReparsePoint`, `Unsupported`), `HKLM`, the deny
//! list and every rule above, the same value in two steps, a plan without the game's main
//! executable (user decision E2); more than 128 ops by `Plan::encode`. There is no delete:
//! deleting is only ever a revert (ADR 0020).

use serde::{Deserialize, Deserializer, Serialize};

use super::{Builder, PlanCtx};
use crate::fold::fold;
use crate::plan::{NewValue, Op, PlanError, ValueState};
use crate::policy::registry::{AsciiName, AsciiSeg, GameKey, RegPolicy, RegPolicyError, RegSlot};
use crate::sys::SysErrorKind;

/// The prefix every `key` begins with, exactly.
pub const KEY_PREFIX: &str = r"HKCU\Software\";
/// Most values of one step.
pub const MAX_VALUES: usize = 32;

/// The `registry_set` step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistrySetSpec {
    /// `HKCU\Software\<Vendor>\<Product>[\…]`.
    pub key: String,
    /// The values, 1 to [`MAX_VALUES`].
    pub values: Vec<RegValueEntry>,
}

/// One value of a [`RegistrySetSpec`]: a name and exactly one of `dword`, `qword`, `sz`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegValueEntry {
    /// The value name (`""` is the default value).
    pub name: String,
    /// A `REG_DWORD`.
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub dword: Option<u32>,
    /// A `REG_QWORD` as a decimal string.
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub qword: Option<String>,
    /// A `REG_SZ`.
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub sz: Option<String>,
}

/// A field that is present must hold a value: `null` is refused (review N5), a missing field
/// is `None` through `default`.
fn present<'de, D: Deserializer<'de>, T: Deserialize<'de>>(d: D) -> Result<Option<T>, D::Error> {
    T::deserialize(d).map(Some)
}

fn refuse(what: impl Into<String>) -> PlanError {
    PlanError::Step(what.into())
}

fn policy(e: &RegPolicyError) -> PlanError {
    refuse(format!("registry_set: {e}"))
}

/// The key of a step for messages (ADR 0016).
fn shown(s: &str) -> String {
    crate::escape::path(s).to_string()
}

/// The game key of `key` (module docs).
fn game_key(key: &str) -> Result<GameKey, PlanError> {
    let Some(rest) = key.strip_prefix(KEY_PREFIX) else {
        if key
            .get(..5)
            .is_some_and(|p| p.eq_ignore_ascii_case(r"HKLM\"))
        {
            return Err(PlanError::NeedsHelper);
        }
        return Err(refuse(format!(
            r"registry_set: the key {} does not begin with HKCU\Software\",
            shown(key)
        )));
    };
    let segs = rest
        .split('\\')
        .map(AsciiSeg::parse)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| policy(&e))?;
    let mut it = segs.into_iter();
    let (Some(vendor), Some(product)) = (it.next(), it.next()) else {
        return Err(refuse(format!(
            r"registry_set: the key {} names no HKCU\Software\<Vendor>\<Product>",
            shown(key)
        )));
    };
    GameKey::new(vendor, product, it.collect()).map_err(|e| policy(&e))
}

/// The new value of an entry (exactly one of the three).
fn new_value(e: &RegValueEntry) -> Result<NewValue, PlanError> {
    let name = shown(&e.name);
    match (e.dword, &e.qword, &e.sz) {
        (Some(v), None, None) => Ok(NewValue::Dword(v)),
        (None, Some(q), None) => crate::wire::dec_u64::from_str(q)
            .map(NewValue::Qword)
            .ok_or_else(|| {
                refuse(format!(
                    "registry_set: value {name}: qword is a decimal string without leading zero"
                ))
            }),
        (None, None, Some(s)) => Ok(NewValue::Sz(s.clone())),
        _ => Err(refuse(format!(
            "registry_set: value {name} has exactly one of dword, qword, sz"
        ))),
    }
}

/// Plans `spec` into `b` (module docs).
pub(crate) fn plan_into(
    spec: &RegistrySetSpec,
    ctx: &PlanCtx<'_>,
    b: &mut Builder,
) -> Result<(), PlanError> {
    let key = game_key(&spec.key)?;
    if spec.values.is_empty() || spec.values.len() > MAX_VALUES {
        return Err(refuse(format!(
            "registry_set: {} has 1 to {MAX_VALUES} values",
            shown(&spec.key)
        )));
    }
    let roots = [ctx.game.path().clone()];
    let mut names: Vec<String> = Vec::with_capacity(spec.values.len());
    for e in &spec.values {
        let name = AsciiName::parse(&e.name).map_err(|x| policy(&x))?;
        let folded = fold(name.as_str());
        if names.contains(&folded) {
            return Err(refuse(format!(
                "registry_set: value {} twice",
                shown(&e.name)
            )));
        }
        names.push(folded.clone());
        let new = new_value(e)?;
        let slot = RegSlot::GameValue {
            key: key.clone(),
            name,
        };
        let av = RegPolicy.check(&slot, &roots).map_err(|x| policy(&x))?;
        RegPolicy
            .check_new(&av, &new.value())
            .map_err(|x| policy(&x))?;
        let object = (av.key().key().clone(), folded);
        if b.reg_values.contains(&object) {
            return Err(refuse(format!(
                "registry_set: value {} of {} in two steps",
                shown(&e.name),
                shown(&spec.key)
            )));
        }
        b.reg_values.push(object);
        let read_err = |x: crate::sys::SysError| match x.kind {
            SysErrorKind::ReparsePoint => refuse(format!(
                "registry_set: a symbolic-link key on the way to {}",
                shown(&spec.key)
            )),
            SysErrorKind::Unsupported => refuse(format!(
                "registry_set: a volatile key on the way to {}",
                shown(&spec.key)
            )),
            SysErrorKind::TooLarge => refuse(format!(
                "registry_set: the old value {} is larger than 1 MiB",
                shown(&e.name)
            )),
            _ => PlanError::Sys(x),
        };
        let current = match ctx.reg.get(&av) {
            Ok(v) => v,
            Err(x) if x.kind == SysErrorKind::NotFound => None,
            Err(x) => return Err(read_err(x)),
        };
        // Missing keys first (top-down, once over all steps), so the revert finds them empty.
        for k in ctx.reg.missing_keys(av.key()).map_err(read_err)? {
            if b.reg_keys.contains(&k) {
                continue;
            }
            let segs = u8::try_from(k.path.split('\\').count())
                .map_err(|_| refuse("registry_set: a key with too many segments"))?;
            b.reg_ops.push(Op::CreateKey {
                slot: slot.clone(),
                segs,
            });
            b.reg_keys.push(k);
        }
        if current.as_ref() == Some(&new.value()) {
            continue;
        }
        let old = match &current {
            None => None,
            Some(v) => Some(ValueState::of(v).ok_or_else(|| {
                refuse(format!(
                    "registry_set: the old value {} cannot be kept",
                    shown(&e.name)
                ))
            })?),
        };
        b.reg_ops.push(Op::SetValue { slot, old, new });
    }
    Ok(())
}
