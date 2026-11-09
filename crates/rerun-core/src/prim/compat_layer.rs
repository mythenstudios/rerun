//! `compat_layer` (P2-11; ADR 0018 and ADR 0020, amendments P2-11): compatibility-layer tokens
//! for an executable of the game folder, in
//! `HKCU\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers`.
//!
//! The step `{"compat_layer":{"exe":"bin\\game.exe","layers":["…"]}}` (`deny_unknown_fields`;
//! `exe` is required, there is no default): `exe` a `RelPath` naming a plain file of the game
//! folder (not missing, no folder, no link or other reparse point, not restricted, every folder
//! on the way plain) ending in `.exe` (folded); the plan names it in the stored spelling of
//! every segment (A2-B1), so the value name is the canonical path as Windows writes it; 1 to 8
//! `layers`, each a `TokenName` on the add allowlist (`policy::registry::layers::LAYER_TOKENS`,
//! spelled as the compatibility tab writes it, P2-11b), unique.
//!
//! The planner reads the current value through `policy::registry` without following links:
//! missing → `old` none; a `REG_SZ` in the strict grammar → `old` with its bytes; anything else
//! (another type, outside the grammar, over 1 KiB) is refused ("an unusual value, Rerun leaves
//! it alone"). A token already in the value is left out (also one an earlier Rerun transaction
//! added: reverting that one removes it, the preview says so, review N3); all present → no op.
//! A token in the value in another case only is refused (review S4). A token of the same group
//! as one already there (another operating-system mode, DPI, colour or resolution setting) is
//! refused (user decision E5 a): with the transaction that added it if that was Rerun (review
//! N2), else with a pointer to the Properties dialog. Every other token stays as it is,
//! elevation tokens included. The missing keys below `CurrentVersion` (`AppCompatFlags`,
//! `Layers`) each become a `CreateKey`, top-down and once for all steps; one `TokenList` with
//! the tokens in byte order and the new value (`layers::merge`).
//!
//! The "all users" value (P3-6, ADR 0018 amendment P3-6): when there is something to add, the
//! planner reads the value of the same executable below `HKLM\…\AppCompatFlags\Layers`, read
//! only, in the native and the 32-bit view (`RegReader::machine_layers`). A word there of the
//! group of a token Rerun would add (folded, a joined `~` looked through, the token itself
//! excepted) is refused, as is a value outside the strict grammar or not a `REG_SZ` (its tokens
//! cannot be checked) and one that cannot be read for any reason but "missing" (fail closed).
//! Otherwise the op records the value of every view where it exists (`TokenList::machine`), and
//! the preview names it. Rerun never writes `HKLM` (core rule 6).
//!
//! Refused besides: a game folder reached by another path than its canonical one (a link, a
//! junctioned library, an 8.3 name; user decision E3 a, final after SB-L2: Windows applies a
//! layer only when the value name is the path the program is started by, and the value name is
//! the canonical path; 8.3 is not measured and refused the same way), a case-sensitive folder, a link or volatile key on the way, two steps for the same
//! executable, a plan without the game's main executable (user decision E2 of P2-10).

use serde::{Deserialize, Serialize};

use super::{Builder, PlanCtx};
use crate::fold::fold;
use crate::journal::{InstanceTag, Journal, TxnId, TxnState, VerifyBackups};
use crate::path::RelPath;
use crate::plan::{self, LayerView, MachineLayers, Op, PlanError, RootIx, ValueState};
use crate::policy::registry::{
    AllowedValue, RegPolicy, RegSlot, TokenName,
    layers::{self, MAX_ADD},
};
use crate::policy::root::GameDir;
use crate::sys::SysErrorKind;
use crate::sys::fs::EntryKind;
use crate::sys::registry::{RegValue, RegView};

/// The `compat_layer` step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompatLayerSpec {
    /// The executable, relative to the game folder.
    pub exe: RelPath,
    /// The tokens, 1 to 8.
    pub layers: Vec<String>,
}

fn refuse(what: impl Into<String>) -> PlanError {
    PlanError::Step(what.into())
}

/// A path for messages (ADR 0016).
fn shown(s: &str) -> String {
    crate::escape::path(s).to_string()
}

/// The tokens of the step: the form, the allowlist, unique; in byte order (review M1).
fn tokens(spec: &CompatLayerSpec) -> Result<Vec<TokenName>, PlanError> {
    if spec.layers.is_empty() || spec.layers.len() > MAX_ADD {
        return Err(refuse("compat_layer: 1 to 8 layers"));
    }
    let mut out: Vec<TokenName> = Vec::with_capacity(spec.layers.len());
    for l in &spec.layers {
        let t = TokenName::parse(l)
            .map_err(|_| refuse(format!("compat_layer: {} is not a token", shown(l))))?;
        if !layers::allowed(&t) {
            return Err(refuse(format!(
                "compat_layer: the token {t} is not on the allowlist"
            )));
        }
        if out.contains(&t) {
            return Err(refuse(format!("compat_layer: the token {t} twice")));
        }
        out.push(t);
    }
    out.sort();
    Ok(out)
}

/// `exe` in the stored spelling of every segment, if it is a plain `.exe` file of the game
/// folder below plain folders (module docs).
/// `step` names the step in messages (`compat_layer`, `launch_method`).
pub(crate) fn stored_exe(
    game: &GameDir<'_>,
    exe: &RelPath,
    step: &str,
) -> Result<RelPath, PlanError> {
    let bad = |why: &str| refuse(format!("{step}: {}: {why}", shown(exe.as_str())));
    if !fold(exe.file_name()).ends_with(&fold(".exe")) {
        return Err(bad("not an .exe file"));
    }
    let segs: Vec<&str> = exe.segments().collect();
    let mut asked: Option<RelPath> = None;
    let mut stored: Option<RelPath> = None;
    for (i, seg) in segs.iter().enumerate() {
        let next = match &asked {
            None => RelPath::from_segment(seg),
            Some(p) => p.child(seg),
        }
        .map_err(|e| bad(&e.to_string()))?;
        let last = i + 1 == segs.len();
        let meta = match game.dir().metadata(&next) {
            Ok(Some(m)) => m,
            Ok(None) => return Err(bad("missing")),
            Err(e) if e.kind == SysErrorKind::ReparsePoint => {
                return Err(bad("a link or other reparse point on the way"));
            }
            Err(e) => return Err(e.into()),
        };
        let want = if last {
            EntryKind::File
        } else {
            EntryKind::Dir
        };
        if meta.kind != want || meta.reparse.is_some() || meta.restricted {
            return Err(bad(if last {
                "not a plain file"
            } else {
                "a folder on the way is not a plain folder"
            }));
        }
        if !last
            && game
                .dir()
                .open_dir(&next)
                .and_then(|d| d.info())
                .map_err(|e| bad(&e.to_string()))?
                .case_sensitive
        {
            return Err(bad("a case-sensitive folder on the way"));
        }
        let name = game
            .dir()
            .stored_name(&next)
            .map_err(|e| bad(&e.to_string()))?
            .ok_or_else(|| bad("changed while it was planned"))?;
        stored = Some(
            match &stored {
                None => RelPath::from_segment(&name),
                Some(p) => p.child(&name),
            }
            .map_err(|e| bad(&e.to_string()))?,
        );
        asked = Some(next);
    }
    stored.ok_or_else(|| bad("empty"))
}

/// The open Rerun transaction whose `TokenList` on the value of `av` added `token` (review N2),
/// for the message only: anything unreadable is "none".
fn added_by_rerun(ctx: &PlanCtx<'_>, av: &AllowedValue, token: &str) -> Option<TxnId> {
    let j = Journal::new(ctx.app?, InstanceTag::new());
    let listing = j.list().ok()?;
    let name = fold(av.name());
    listing.txns.iter().rev().find_map(|l| {
        let v = l.view.as_ref().ok()?;
        if l.forgotten || matches!(v.state, TxnState::Closed(_) | TxnState::Empty) {
            return None;
        }
        let full = j.load(&l.id, VerifyBackups::Length).ok()?;
        let p = plan::decode_recorded(full.head.as_deref()?).ok()?;
        p.ops.iter().enumerate().find_map(|(k, op)| {
            let Op::TokenList { slot, add, .. } = op else {
                return None;
            };
            let other = plan::allowed(&p, slot, k).ok()?;
            (other.key().key() == av.key().key()
                && fold(other.name()) == name
                && add.iter().any(|t| t.as_str() == token))
            .then_some(l.id)
        })
    })
}

/// Plans `spec` into `b` (module docs).
pub(crate) fn plan_into(
    spec: &CompatLayerSpec,
    ctx: &PlanCtx<'_>,
    b: &mut Builder,
) -> Result<(), PlanError> {
    let game = ctx.game;
    // E3 a (final, SB-L2): the value name is the canonical path, and Windows applies a layer
    // only to a launch by exactly that path, so a game started through a link would not get it.
    // A launch path that is no `RootPath` (too long, review S-a) is refused the same way.
    if game.launch_path() != Some(game.path()) {
        return Err(refuse(format!(
            "compat_layer: the game folder {} is reached through a link or another name ({}); \
             Windows applies a compatibility layer only when a program is started by exactly \
             the path of the value name, and the game would be started by another path",
            shown(&game.path().to_string()),
            game.launch_path().map_or_else(
                || "a path too long to compare".to_owned(),
                |l| shown(&l.to_string())
            ),
        )));
    }
    if game.info().case_sensitive {
        return Err(refuse("compat_layer: the game folder is case-sensitive"));
    }
    let wanted = tokens(spec)?;
    let exe = stored_exe(game, &spec.exe, "compat_layer")?;
    let slot = RegSlot::CompatLayers {
        root: RootIx(0),
        exe: exe.clone(),
    };
    let roots = [game.path().clone()];
    let av = RegPolicy
        .check(&slot, &roots)
        .map_err(|e| refuse(format!("compat_layer: {e}")))?;
    let object = (av.key().key().clone(), fold(av.name()));
    if b.reg_values.contains(&object) {
        return Err(refuse(format!(
            "compat_layer: two steps for {}",
            shown(exe.as_str())
        )));
    }
    b.reg_values.push(object);
    let read_err = |x: crate::sys::SysError| match x.kind {
        SysErrorKind::ReparsePoint => {
            refuse("compat_layer: a symbolic-link key on the way to AppCompatFlags\\Layers")
        }
        SysErrorKind::Unsupported => {
            refuse("compat_layer: a volatile key on the way to AppCompatFlags\\Layers")
        }
        SysErrorKind::TooLarge => unusual(&exe),
        _ => PlanError::Sys(x),
    };
    let old = match ctx.reg.get(&av) {
        Ok(None) => None,
        Err(x) if x.kind == SysErrorKind::NotFound => None,
        Ok(Some(RegValue::String(s))) if layers::parse(&s).is_ok() => Some(s),
        Ok(Some(_)) => return Err(unusual(&exe)),
        Err(x) => return Err(read_err(x)),
    };
    let words: Vec<&str> = old
        .as_deref()
        .map_or_else(Vec::new, |o| o.split(' ').collect());
    let mut add = Vec::with_capacity(wanted.len());
    for t in wanted {
        if words.contains(&t.as_str()) {
            continue;
        }
        let f = fold(t.as_str());
        if words.iter().any(|w| fold(w) == f) {
            return Err(refuse(format!(
                "compat_layer: {} holds the token {t} in another case; Rerun leaves it alone",
                shown(exe.as_str())
            )));
        }
        // E5 a: a token of the same group already there is never replaced.
        if let Some(g) = layers::group_of(t.as_str())
            && let Some(w) = words.iter().find(|w| layers::group_of(w) == Some(g))
        {
            return Err(match added_by_rerun(ctx, &av, w) {
                Some(txn) => refuse(format!(
                    "compat_layer: {} already has {} from Rerun transaction {txn}; revert that \
                     transaction first",
                    shown(exe.as_str()),
                    shown(w)
                )),
                None => refuse(format!(
                    "compat_layer: {} already has {} of the same kind as {t}; remove it in the \
                     Compatibility tab of the executable's Properties first",
                    shown(exe.as_str()),
                    shown(w)
                )),
            });
        }
        add.push(t);
    }
    if add.is_empty() {
        return Ok(());
    }
    RegPolicy
        .check_tokens(&av, old.as_deref(), &add)
        .map_err(|e| refuse(format!("compat_layer: {e}")))?;
    let machine = machine_layers(ctx, &av, &exe, &add)?;
    for k in ctx.reg.missing_keys(av.key()).map_err(read_err)? {
        if b.reg_keys.contains(&k) {
            continue;
        }
        let segs = u8::try_from(k.path.split('\\').count())
            .map_err(|_| refuse("compat_layer: a key with too many segments"))?;
        b.reg_ops.push(Op::CreateKey {
            slot: slot.clone(),
            segs,
        });
        b.reg_keys.push(k);
    }
    let new = layers::merge(old.as_deref(), &add);
    let old = match old {
        None => None,
        Some(o) => Some(ValueState::of(&RegValue::String(o)).ok_or_else(|| unusual(&exe))?),
    };
    b.reg_ops.push(Op::TokenList {
        slot,
        old,
        add,
        new,
        machine,
    });
    Ok(())
}

/// The "all users" value of the executable (P3-6, ADR 0018 amendment P3-6), read only in both
/// views: refused when it holds a word of the group of a token of `add`, when it is unusual
/// (its tokens cannot be checked) or cannot be read (fail closed); otherwise every view where it
/// exists, for the preview. Rerun never writes `HKLM` (core rule 6).
fn machine_layers(
    ctx: &PlanCtx<'_>,
    av: &AllowedValue,
    exe: &RelPath,
    add: &[TokenName],
) -> Result<Vec<MachineLayers>, PlanError> {
    let mut out = Vec::new();
    for (view, rv, words) in [
        (LayerView::Native, RegView::Native, "64-bit view"),
        (LayerView::Wow32, RegView::Wow32, "32-bit view"),
    ] {
        let at = || {
            format!(
                "compat_layer: the all-users compatibility-layer value of {} (HKLM, {words})",
                shown(exe.as_str())
            )
        };
        let unusual = || {
            refuse(format!(
                "{} is unusual (another type, another form or longer than 511 characters); \
                 Rerun cannot check its tokens and adds none",
                at()
            ))
        };
        let value = match ctx.reg.machine_layers(av, rv) {
            Ok(None) => continue,
            Ok(Some(RegValue::String(s))) => s,
            Ok(Some(_)) => return Err(unusual()),
            Err(e) if e.kind == SysErrorKind::TooLarge => return Err(unusual()),
            Err(e) => {
                return Err(refuse(format!(
                    "{} cannot be read ({e}); Rerun adds no token it cannot check against it",
                    at()
                )));
            }
        };
        match layers::machine_conflict(&value, add) {
            Ok(None) => {}
            Ok(Some((w, t))) => {
                return Err(refuse(format!(
                    "{} holds {}, of the same kind as {t}; Rerun does not add {t} for the \
                     current user over it; change it in the Compatibility tab of the \
                     executable's Properties (Change settings for all users) first. The value: {}",
                    at(),
                    shown(w),
                    crate::escape::text(&value)
                )));
            }
            Err(_) => return Err(unusual()),
        }
        out.push(MachineLayers { view, value });
    }
    Ok(out)
}

fn unusual(exe: &RelPath) -> PlanError {
    refuse(format!(
        "compat_layer: the compatibility-layer value of {} is unusual (another type, another \
         form or longer than 511 characters); Rerun leaves it alone",
        shown(exe.as_str())
    ))
}
