//! `gpu_preference` (P4-11; ADR 0018 and ADR 0020, amendments P4-11): Windows' graphics
//! preference for an executable of the game folder, in
//! `HKCU\Software\Microsoft\DirectX\UserGpuPreferences` (what Settings > System > Display >
//! Graphics writes).
//!
//! The step `{"gpu_preference":{"exe":"bin\\game.exe","preference":"high_performance"}}`
//! (`deny_unknown_fields`; both fields required): `exe` a `RelPath` naming a plain `.exe` file
//! of the game folder below plain folders (`compat_layer::stored_exe`: the plan names it in the
//! stored spelling of every segment, so the value name is the canonical path as Settings
//! writes it); `preference` only `high_performance` in v1 (`GpuPreference=2;`).
//!
//! The planner reads the current value through `policy::registry` without following links:
//! missing → `old` none; a `REG_SZ` in the strict grammar of `policy::registry::gpu_pref` →
//! `old` with its bytes; anything else (another type, outside the grammar, over 1 KiB) is
//! refused ("an unusual value, Rerun leaves it alone"). `GpuPreference=2` already there → no op
//! (the Topo engine says so, N2); `GpuPreference=1` (the user chose "Power saving") → refused
//! with a pointer to Settings (user decision E-G3 a); `0` or no pair → one `GpuPref` op whose
//! new value `policy` forms (`gpu_pref::set`: only Rerun's pair changes, every other pair keeps
//! its bytes and place). The missing keys below `Software\Microsoft` (`DirectX`,
//! `UserGpuPreferences`) each become a `CreateKey`, top-down and once for all steps.
//!
//! Refused besides: a game folder reached by another path than its canonical one (a link, a
//! junctioned library, an 8.3 name; as `compat_layer` E3 a: how DirectX matches the value name
//! is not measured, so the conservative rule of the layer), a case-sensitive folder, a link or
//! volatile key on the way, two steps for the same executable, a plan without the game's main
//! executable (E2 of P2-10). While the executable runs neither apply nor revert run (D4,
//! `exec::roots::game_closed`).

use serde::{Deserialize, Serialize};

use super::compat_layer::stored_exe;
use super::{Builder, PlanCtx, Step};
use crate::fold::fold;
use crate::journal::TxnId;
use crate::path::RelPath;
use crate::plan::{Op, Plan, PlanError, RootIx, ValueState};
use crate::policy::registry::gpu_pref::{self, Current};
use crate::policy::registry::{AllowedValue, GpuPref, RegPolicy, RegSlot};
use crate::sys::SysErrorKind;
use crate::sys::registry::RegValue;

/// The `gpu_preference` step (a Topo step and a step file step alike).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GpuPreferenceSpec {
    /// The executable, relative to the game folder.
    pub exe: RelPath,
    /// The preference (v1: `high_performance`).
    pub preference: GpuPref,
}

fn refuse(what: impl Into<String>) -> PlanError {
    PlanError::Step(what.into())
}

/// A path for messages (ADR 0016).
fn shown(s: &str) -> String {
    crate::escape::path(s).to_string()
}

fn unusual(exe: &RelPath) -> PlanError {
    refuse(format!(
        "gpu_preference: the graphics preference value of {} is unusual (another type, another \
         form or longer than 511 characters); Rerun leaves it alone",
        shown(exe.as_str())
    ))
}

/// The slot and allowed value of `spec` on this game folder, with the old value as read
/// (`None`: missing). Every refusal of the planner before the merge.
fn read(
    spec: &GpuPreferenceSpec,
    ctx: &PlanCtx<'_>,
) -> Result<(RegSlot, AllowedValue, Option<String>), PlanError> {
    let game = ctx.game;
    if game.launch_path() != Some(game.path()) {
        return Err(refuse(format!(
            "gpu_preference: the game folder {} is reached through a link or another name ({}); \
             the value name is the canonical path, and the game would be started by another path",
            shown(&game.path().to_string()),
            game.launch_path().map_or_else(
                || "a path too long to compare".to_owned(),
                |l| shown(&l.to_string())
            ),
        )));
    }
    if game.info().case_sensitive {
        return Err(refuse("gpu_preference: the game folder is case-sensitive"));
    }
    let exe = stored_exe(game, &spec.exe, "gpu_preference")?;
    let slot = RegSlot::GpuPreference {
        root: RootIx(0),
        exe: exe.clone(),
    };
    let av = RegPolicy
        .check(&slot, &[game.path().clone()])
        .map_err(|e| refuse(format!("gpu_preference: {e}")))?;
    let old = match ctx.reg.get(&av) {
        Ok(None) => None,
        Err(x) if x.kind == SysErrorKind::NotFound => None,
        Ok(Some(RegValue::String(s))) if gpu_pref::parse(&s).is_ok() => Some(s),
        Ok(Some(_)) => return Err(unusual(&exe)),
        Err(x) => return Err(read_err(&exe, x)),
    };
    Ok((slot, av, old))
}

fn read_err(exe: &RelPath, x: crate::sys::SysError) -> PlanError {
    match x.kind {
        SysErrorKind::ReparsePoint => {
            refuse("gpu_preference: a symbolic-link key on the way to DirectX\\UserGpuPreferences")
        }
        SysErrorKind::Unsupported => {
            refuse("gpu_preference: a volatile key on the way to DirectX\\UserGpuPreferences")
        }
        SysErrorKind::TooLarge => unusual(exe),
        _ => PlanError::Sys(x),
    }
}

/// Plans `spec` into `b` (module docs).
pub(crate) fn plan_into(
    spec: &GpuPreferenceSpec,
    ctx: &PlanCtx<'_>,
    b: &mut Builder,
) -> Result<(), PlanError> {
    let (slot, av, old) = read(spec, ctx)?;
    let RegSlot::GpuPreference { exe, .. } = &slot else {
        return Err(refuse("gpu_preference: not a graphics preference slot"));
    };
    let exe = exe.clone();
    let object = (av.key().key().clone(), fold(av.name()));
    if b.reg_values.contains(&object) {
        return Err(refuse(format!(
            "gpu_preference: two steps for {}",
            shown(exe.as_str())
        )));
    }
    b.reg_values.push(object);
    if let Some(o) = &old {
        match gpu_pref::parse(o).map(|p| gpu_pref::current(&p)) {
            Ok(Current::Digit(d)) if d == spec.preference.digit() => return Ok(()),
            // E-G3 a: the user's deliberate choice is never overridden.
            Ok(Current::Digit(1)) => {
                return Err(refuse(format!(
                    "gpu_preference: the graphics preference of {} is \"Power saving\", chosen \
                     in Settings > System > Display > Graphics; Rerun does not override it. \
                     Change it there to \"Let Windows decide\" or remove it first",
                    shown(exe.as_str())
                )));
            }
            _ => {}
        }
    }
    let new = RegPolicy
        .check_pref(&av, old.as_deref(), spec.preference)
        .map_err(|e| refuse(format!("gpu_preference: {e}")))?;
    for k in ctx
        .reg
        .missing_keys(av.key())
        .map_err(|x| read_err(&exe, x))?
    {
        if b.reg_keys.contains(&k) {
            continue;
        }
        let segs = u8::try_from(k.path.split('\\').count())
            .map_err(|_| refuse("gpu_preference: a key with too many segments"))?;
        b.reg_ops.push(Op::CreateKey {
            slot: slot.clone(),
            segs,
        });
        b.reg_keys.push(k);
    }
    let old = match old {
        None => None,
        Some(o) => Some(ValueState::of(&RegValue::String(o)).ok_or_else(|| unusual(&exe))?),
    };
    b.reg_ops.push(Op::GpuPref {
        slot,
        old,
        pref: spec.preference,
        new,
    });
    Ok(())
}

/// The open Rerun transaction whose `GpuPref` set the value of `av` (for a message only:
/// anything unreadable is "none").
fn set_by_rerun(ctx: &PlanCtx<'_>, av: &AllowedValue) -> Option<TxnId> {
    super::open_txn_with(
        ctx,
        |p, k, op| matches!(op, Op::GpuPref { slot, .. } if super::same_value(p, slot, k, av)),
    )
}

/// A `gpu_preference` step of `steps` that `plan` leaves out because the preference is set
/// already (review N2): the executable, and the open Rerun transaction that set it, if one did
/// (reverting that one takes it back).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlreadySet {
    /// The executable, in the spelling of the step.
    pub exe: RelPath,
    /// The open transaction whose op set it.
    pub by: Option<TxnId>,
}

/// The `gpu_preference` steps of `steps` without an op in `plan` (module docs, N2): read again,
/// each one whose value holds the step's preference already. For the engine's warnings only.
pub fn already_set(steps: &[Step], plan: &Plan, ctx: &PlanCtx<'_>) -> Vec<AlreadySet> {
    let mut out = Vec::new();
    for s in steps {
        let Step::GpuPreference(spec) = s else {
            continue;
        };
        let Ok((_, av, Some(old))) = read(spec, ctx) else {
            continue;
        };
        let planned = plan.ops.iter().enumerate().any(|(k, op)| {
            matches!(op, Op::GpuPref { slot, .. } if super::same_value(plan, slot, k, &av))
        });
        let set = gpu_pref::parse(&old)
            .is_ok_and(|p| gpu_pref::current(&p) == Current::Digit(spec.preference.digit()));
        if set && !planned {
            out.push(AlreadySet {
                exe: spec.exe.clone(),
                by: set_by_rerun(ctx, &av),
            });
        }
    }
    out
}
