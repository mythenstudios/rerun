//! The registry op kinds: apply, observe and revert (ADR 0020 amendment P2-10b; ADR 0018; user
//! decision 6a, senior-dev conditions S2, S3, S4, S6).
//!
//! Every key and value is reached through `policy::registry` (`RegWriter`), its location built
//! again from the head on every run (`RegPolicy::check` with the plan's roots: the journal is
//! untrusted), walked segment by segment without following a link (`sys::seq::reg`). Nothing
//! trusts a record alone.
//!
//! - `CreateKey` (`K` = the slot's key cut to `segs`): apply `intent` → `create_key` → `true`:
//!   `Done`; `false` (the key existed, someone else's): `Mismatch`, never deleted (6a); an
//!   error: observed. Observed: missing → `Before`; a link or volatile key on the way →
//!   `Foreign`; empty → `After` (by `Done`, by the call's result in the rollback, or without
//!   proof in a recovery: 6a, the rest risk of `docs/06-security.md` scenario 10), deleted with
//!   `delete_empty_key` (`NotEmpty` checked on the handle); `Existed` in the rollback, or not
//!   empty → `Foreign`. `verify` (newest op first, S3) counts a key holding only the keys and
//!   values of later ops that will be gone (observed `After` or `Before`) as empty, after
//!   `counts()` (S6: a key too large to list is `Foreign`). Only `verify` lists names, and it
//!   does so through the read side, which follows links below `K` (review N3): that listing
//!   only shapes the read-only preview; the rollback and the recovery decide on the walked
//!   handle's counts alone, and the delete runs on a handle with its own `NotEmpty` check.
//!   Rest risk (review nit 5, the class of 6a): `false` is never deleted in the same run, but
//!   a crash between it and the rollback's `RevertDone` leaves an intent without `Done`, and a
//!   recovery then deletes that key if it is still empty.
//! - `SetValue`: apply re-reads the value (`Mismatch` before the intent if it is not `old`),
//!   keeps the old bytes in the intent (`Before::Inline` up to 16 KiB, else `op-NNNN.bin`
//!   through `backup_bytes`), then `set(expected = the value read, new)`. Observed: exactly
//!   `new` (and not a refused write in this run) → `After`, restored to the old value from
//!   `before_bytes` (hashed before use) or deleted if there was none, with `new` expected; the
//!   old value (or missing) → `Before`; anything else (another type, a `REG_SZ` without its
//!   NUL, a link or volatile key) → `Foreign` (S4). Rest risk (review nit 5): a refused write
//!   (`NotWritten`) is left only by the rollback of the same run; after a crash before its
//!   `RevertDone`, a recovery cannot tell another program's write of exactly `new` from Rerun's
//!   and restores the old value over it (the class of 6a, `docs/06-security.md` scenario 10).
//! - `TokenList` (P2-11; user decisions E1 a, E2 b, E6 b, E8; senior-dev conditions S2, S3, S5,
//!   N1): apply like `SetValue` (the old bytes always inline, at most 1 KiB), but the write is
//!   `RegWriter::add_tokens(expected = the value read, add)`: `policy` forms the new value.
//!   Observed, in this order: a link, volatile key or a value too large on the way →
//!   `Foreign`; exactly `new` (and no `NotWritten`) → `After`, the old value restored exactly
//!   from the journal (or deleted); the old value (missing for none) → `Before`; with
//!   `NotWritten` anything else is `Foreign` (N1); missing although there was an old value →
//!   `Drifted`, nothing written (S3); a `REG_SZ` whose `layers::unmerge` keeps some of
//!   Rerun's tokens → `Drifted`, `RegWriter::remove_tokens(expected = the value seen, add)`
//!   (S5; deleted when only prefix words are left, S2); one with none of them → `Drifted`,
//!   nothing written (E2 b); anything else (another type, no NUL, the grammar, one of Rerun's
//!   tokens twice or in another case) → `Foreign`. No `from`/`to` in the `RevertIntent`
//!   (E8): a crash after `remove_tokens` leaves a value without Rerun's tokens, which the next
//!   run observes as `Before`, `Drifted` (none left) or `Drifted` (missing), never `Foreign`.
//! - `CreateKey` of a shared Windows key (`AppCompatFlags`, `Layers`; `AllowedValue::shared_keys`,
//!   E6 b, E7): a key that is not empty, or that existed (`Existed`), is `Drifted` and left, the
//!   transaction still closes; a game key keeps 6a (`Foreign`). `verify` counts a value of a
//!   later `TokenList` as gone when its revert deletes it (`After` or `Before` with no old
//!   value, `Drifted` with a rest of prefix words or already missing), not when it stays.

use std::collections::BTreeMap;

use super::file::Mode;
use super::{Acted, ExecError, Hint, Refusal};
use crate::fold::fold;
use crate::journal::{
    Before, BeforeArg, Digest, INLINE_MAX, Observed, OpLog, Reverting, TxnWriter,
};
use crate::plan::{self, Op, Plan, Target, ValueState};
use crate::policy::registry::{
    AllowedKey, AllowedValue, RegWriteError, RegWriter, TokenName, Unmerged, layers,
};
use crate::sys::registry::{KeyState, MAX_VALUE_BYTES, RegKey, RegValue};
use crate::sys::{SysError, SysErrorKind, System};

/// The result of `create_key` in this run, for the rollback (6a).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum KeyHint {
    /// `true`: this call created it.
    Created,
    /// `false`: it existed (someone else's).
    Existed,
    /// An error: it may exist.
    Unknown,
}

/// What a revert does to a registry op after its `RevertIntent`.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Action {
    /// Delete the empty key (by its walked handle).
    DeleteKey { key: RegKey, of: AllowedKey },
    /// Put the old value back (or delete the value), `expected` the new one.
    Restore {
        av: AllowedValue,
        expected: RegValue,
    },
    /// Remove Rerun's tokens from a value someone changed since the apply, `expected` the value
    /// seen (P2-11, S5).
    RemoveTokens {
        av: AllowedValue,
        expected: RegValue,
    },
}

/// What a registry op observes and what its revert does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Seen {
    pub(super) observed: Observed,
    action: Option<Box<Action>>,
    /// `verify` (S3): the key a `CreateKey` creates, and the value of a `SetValue` or
    /// `TokenList`.
    object: Object,
    /// A value that will be gone after the revert of this op (`verify` of a created key above
    /// it): observed `After` or `Before` (in a created key there is no old value), or a
    /// `Drifted` token list whose rest is deleted or which is missing already.
    gone: bool,
}

/// The object of a registry op, for the verify of a created key above it.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Object {
    Key(RegKey),
    Value(RegKey, String),
}

impl Seen {
    fn new(observed: Observed, object: Object) -> Self {
        Self {
            observed,
            action: None,
            object,
            gone: matches!(observed, Observed::After | Observed::Before),
        }
    }

    fn act(mut self, a: Action) -> Self {
        self.action = Some(Box::new(a));
        self
    }

    fn gone(mut self, gone: bool) -> Self {
        self.gone = gone;
        self
    }
}

fn op_err(k: u16) -> impl Fn(SysError) -> ExecError {
    move |source| ExecError::Op { op: k, source }
}

/// A plan rule broken at run time (never for a decoded plan: fail closed).
fn rule(k: u16, e: &crate::plan::PlanError) -> ExecError {
    ExecError::Op {
        op: k,
        source: SysError::new(SysErrorKind::InvalidPath, e.to_string()),
    }
}

/// The key a `CreateKey` creates and its allowed key.
fn key_of(plan: &Plan, k: u16, op: &Op) -> Result<(AllowedValue, RegKey), ExecError> {
    match op.target() {
        Target::Key { slot, segs } => {
            plan::created_key(plan, slot, segs, usize::from(k)).map_err(|e| rule(k, &e))
        }
        _ => Err(not_a_registry_op(k)),
    }
}

/// The value a `SetValue` sets.
fn value_of(plan: &Plan, k: u16, op: &Op) -> Result<AllowedValue, ExecError> {
    match op.target() {
        Target::Value { slot } => {
            plan::allowed(plan, slot, usize::from(k)).map_err(|e| rule(k, &e))
        }
        _ => Err(not_a_registry_op(k)),
    }
}

fn not_a_registry_op(k: u16) -> ExecError {
    ExecError::Op {
        op: k,
        source: SysError::new(SysErrorKind::Other, "not a registry op"),
    }
}

/// The current value; a missing key is a missing value.
fn current(w: &RegWriter<'_>, av: &AllowedValue) -> Result<Option<RegValue>, SysError> {
    match w.get(av) {
        Ok(v) => Ok(v),
        Err(e) if e.kind == SysErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// A link or volatile key on the way, or a value too large to read: not Rerun's.
fn not_ours(e: &SysError) -> bool {
    matches!(
        e.kind,
        SysErrorKind::ReparsePoint | SysErrorKind::Unsupported | SysErrorKind::TooLarge
    )
}

#[cfg(test)]
thread_local! {
    /// Control K-R7: `create_key == false` (the key existed) counts as created.
    pub(crate) static KNOB_EXISTED_AS_OWN: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

fn existed_as_own() -> bool {
    #[cfg(test)]
    return KNOB_EXISTED_AS_OWN.with(std::cell::Cell::get);
    #[cfg(not(test))]
    false
}

#[cfg(test)]
thread_local! {
    /// Control K-L2: every drift of a token list is `Foreign` (as `SetValue`).
    pub(crate) static KNOB_DRIFT_FOREIGN: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// Control K-L1: a token list without any of Rerun's tokens left is `Foreign` (E2 a).
    pub(crate) static KNOB_UNTOUCHED_FOREIGN: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// K-L2 (tests): a drift is `Foreign`.
fn drift_foreign() -> bool {
    #[cfg(test)]
    return KNOB_DRIFT_FOREIGN.with(std::cell::Cell::get);
    #[cfg(not(test))]
    false
}

/// K-L1 (tests): no token of Rerun's left is `Foreign`.
fn untouched_foreign() -> bool {
    #[cfg(test)]
    return KNOB_UNTOUCHED_FOREIGN.with(std::cell::Cell::get);
    #[cfg(not(test))]
    false
}

/// Step 5 of the apply for the registry ops, before anything is written: a created key is
/// still missing, a value still has its planned old state (`Mismatch`); a link, volatile key or
/// unreadable value on the way is `Refusal::Registry`.
pub(super) fn old_state(w: &RegWriter<'_>, plan: &Plan) -> Result<(), Refusal> {
    for (i, op) in plan.ops.iter().enumerate() {
        let k = super::op_ix(i);
        let reg = |source| Refusal::Registry { op: k, source };
        let to_refusal = |e: ExecError| match e {
            ExecError::Op { source, .. } => reg(source),
            _ => Refusal::Mismatch { op: k },
        };
        match op {
            Op::CreateKey { .. } => {
                let (av, key) = key_of(plan, k, op).map_err(to_refusal)?;
                match w.state_at(&key, av.key()) {
                    Ok(KeyState::Missing) => {}
                    Ok(KeyState::Present { .. }) => return Err(Refusal::Mismatch { op: k }),
                    Err(e) => return Err(reg(e)),
                }
            }
            Op::SetValue { old, .. } | Op::TokenList { old, .. } => {
                let av = value_of(plan, k, op).map_err(to_refusal)?;
                let cur = current(w, &av).map_err(reg)?;
                if !ValueState::is(old.as_ref(), cur.as_ref()) {
                    return Err(Refusal::Mismatch { op: k });
                }
            }
            Op::CreateDir { .. } | Op::CreateFile { .. } | Op::ReplaceFile { .. } => {}
        }
    }
    Ok(())
}

/// Applies registry op `k` (module docs).
pub(super) fn apply_op(
    w: &mut TxnWriter<'_>,
    reg: &RegWriter<'_>,
    plan: &Plan,
    k: u16,
    op: &Op,
    hints: &mut BTreeMap<u16, Hint>,
) -> Result<(), ExecError> {
    let e = op_err(k);
    match op {
        Op::CreateKey { .. } => {
            let (av, key) = key_of(plan, k, op)?;
            w.intent(k, None, None)?;
            match reg.create_key(&key, av.key()) {
                Ok(true) => {
                    hints.insert(k, Hint::Key(KeyHint::Created));
                    w.done(k, None, false)?;
                    Ok(())
                }
                Ok(false) if existed_as_own() => {
                    hints.insert(k, Hint::Key(KeyHint::Created));
                    w.done(k, None, false)?;
                    Ok(())
                }
                Ok(false) => {
                    // 6a: someone else's key; never deleted.
                    hints.insert(k, Hint::Key(KeyHint::Existed));
                    Err(e(SysError::new(
                        SysErrorKind::Mismatch,
                        format!("{key}: created by someone else since the check"),
                    )))
                }
                Err(x) => {
                    // P2-9 S5: past the create the key may exist; the rollback observes it.
                    hints.insert(k, Hint::Key(KeyHint::Unknown));
                    Err(e(x))
                }
            }
        }
        Op::SetValue { old, .. } | Op::TokenList { old, .. } => {
            let av = value_of(plan, k, op)?;
            let cur = current(reg, &av).map_err(&e)?;
            if !ValueState::is(old.as_ref(), cur.as_ref()) {
                return Err(e(SysError::new(
                    SysErrorKind::Mismatch,
                    format!(
                        "{} @ {:?}: changed since the preview",
                        av.key().key(),
                        av.name()
                    ),
                )));
            }
            let before = match &cur {
                None => None,
                Some(v) => {
                    let (_, data) = v.encode().ok_or_else(|| {
                        e(SysError::new(
                            SysErrorKind::Unsupported,
                            "an old value without encoding",
                        ))
                    })?;
                    Some(if data.len() <= INLINE_MAX {
                        BeforeArg::Inline(data)
                    } else {
                        BeforeArg::Backup(w.backup_bytes(&data)?)
                    })
                }
            };
            w.intent(k, None, before)?;
            let r = match op {
                Op::SetValue { new, .. } => reg.set(&av, cur.as_ref(), &new.value()),
                // `policy` forms the new value from the value read (P2-11, S5).
                Op::TokenList { add, .. } => reg.add_tokens(&av, cur.as_ref(), add),
                _ => return Err(not_a_registry_op(k)),
            };
            match r {
                Ok(()) => {
                    w.done(k, None, false)?;
                    Ok(())
                }
                Err(RegWriteError::Policy(p)) => {
                    hints.insert(k, Hint::NotWritten);
                    Err(e(SysError::new(SysErrorKind::Unsupported, p.to_string())))
                }
                Err(RegWriteError::Sys(x)) => {
                    // `Mismatch`: nothing was written. Anything else: the old or the new value
                    // is there; the rollback observes.
                    if x.kind == SysErrorKind::Mismatch {
                        hints.insert(k, Hint::NotWritten);
                    }
                    Err(e(x))
                }
            }
        }
        Op::CreateDir { .. } | Op::CreateFile { .. } | Op::ReplaceFile { .. } => {
            Err(not_a_registry_op(k))
        }
    }
}

/// The names in `key` that later registry ops of `plan` (after `k`) put there and that will be
/// gone when the revert reaches `k` (S3: observed `After` or `Before`): direct subkeys created
/// by a later `CreateKey`, values of a later `SetValue` or `TokenList` that will be gone
/// (`Seen::gone`; a drifted token list that stays is not, E7).
fn later_names(
    k: u16,
    key: &RegKey,
    later: &BTreeMap<u16, super::Seen>,
) -> (Vec<String>, Vec<String>) {
    let mut keys = Vec::new();
    let mut values = Vec::new();
    for s in later.range(k.saturating_add(1)..).map(|(_, s)| s) {
        let super::Seen::Reg(s) = s else {
            continue;
        };
        match &s.object {
            Object::Key(c)
                if c.parent().as_ref() == Some(key)
                    && matches!(s.observed, Observed::After | Observed::Before) =>
            {
                keys.push(fold(c.path.rsplit('\\').next().unwrap_or_default()));
            }
            Object::Value(v, name) if v == key && s.gone => values.push(name.clone()),
            Object::Key(_) | Object::Value(..) => {}
        }
    }
    (keys, values)
}

/// A key holding only what later ops will remove (S3, S6): `counts()` first, then the names
/// through the read side (the key itself was just walked without a link). Too large to list is
/// "not empty".
fn only_later(
    sys: &dyn System,
    key: &RegKey,
    counts: (u32, u32),
    names: &(Vec<String>, Vec<String>),
) -> Result<bool, SysError> {
    let (values, subkeys) = counts;
    if usize::try_from(subkeys).unwrap_or(usize::MAX) > names.0.len()
        || usize::try_from(values).unwrap_or(usize::MAX) > names.1.len()
    {
        return Ok(false);
    }
    let r = sys.registry();
    let subs = match r.subkeys(key) {
        Ok(s) => s,
        Err(e) if e.kind == SysErrorKind::TooLarge => return Ok(false),
        Err(e) => return Err(e),
    };
    if !subs.iter().all(|s| names.0.contains(&fold(s))) {
        return Ok(false);
    }
    let vals = match r.values(key) {
        Ok(v) => v,
        Err(e) if e.kind == SysErrorKind::TooLarge => return Ok(false),
        Err(e) => return Err(e),
    };
    Ok(vals.iter().all(|(n, _)| names.1.contains(&fold(n))))
}

/// Observes registry op `k` (module docs; read only).
#[expect(
    clippy::too_many_arguments,
    reason = "the observation of every registry op kind"
)]
pub(super) fn observe(
    reg: &RegWriter<'_>,
    sys: &dyn System,
    plan: &Plan,
    k: u16,
    op: &Op,
    log: &OpLog,
    mode: Mode,
    hint: Option<Hint>,
    later: &BTreeMap<u16, super::Seen>,
) -> Result<Seen, ExecError> {
    let e = op_err(k);
    match op {
        Op::CreateKey { .. } => {
            let (av, key) = key_of(plan, k, op)?;
            let object = Object::Key(key.clone());
            let delete = Action::DeleteKey {
                key: key.clone(),
                of: av.key().clone(),
            };
            if super::trusting_records() {
                return Ok(match log.done {
                    Some(_) => Seen::new(Observed::After, object).act(delete),
                    None => Seen::new(Observed::Before, object),
                });
            }
            let (values, subkeys) = match reg.state_at(&key, av.key()) {
                Ok(KeyState::Missing) => return Ok(Seen::new(Observed::Before, object)),
                Ok(KeyState::Present { values, subkeys }) => (values, subkeys),
                Err(x) if not_ours(&x) => return Ok(Seen::new(Observed::Foreign, object)),
                Err(x) => return Err(e(x)),
            };
            let empty = (values, subkeys) == (0, 0)
                || (mode == Mode::Verify
                    && only_later(sys, &key, (values, subkeys), &later_names(k, &key, later))
                        .map_err(&e)?);
            let ours = log.done.is_some() || hint != Some(Hint::Key(KeyHint::Existed));
            Ok(if empty && ours {
                Seen::new(Observed::After, object).act(delete)
            } else if av.shared_keys() {
                // E6 b: a shared Windows key holding other programs' values (or one that
                // existed) stays, and the transaction closes.
                Seen::new(Observed::Drifted, object)
            } else {
                Seen::new(Observed::Foreign, object)
            })
        }
        Op::SetValue { old, new, .. } => {
            let av = value_of(plan, k, op)?;
            let object = Object::Value(av.key().key().clone(), fold(av.name()));
            let new = new.value();
            let restore = Action::Restore {
                av: av.clone(),
                expected: new.clone(),
            };
            if super::trusting_records() {
                return Ok(match log.done {
                    Some(_) => Seen::new(Observed::After, object).act(restore),
                    None => Seen::new(Observed::Before, object),
                });
            }
            let cur = match current(reg, &av) {
                Ok(v) => v,
                Err(x) if not_ours(&x) => return Ok(Seen::new(Observed::Foreign, object)),
                Err(x) => return Err(e(x)),
            };
            Ok(
                if cur.as_ref() == Some(&new) && hint != Some(Hint::NotWritten) {
                    Seen::new(Observed::After, object).act(restore)
                } else if ValueState::is(old.as_ref(), cur.as_ref()) {
                    Seen::new(Observed::Before, object)
                } else {
                    Seen::new(Observed::Foreign, object)
                },
            )
        }
        Op::TokenList { old, add, new, .. } => {
            let av = value_of(plan, k, op)?;
            let object = Object::Value(av.key().key().clone(), fold(av.name()));
            let new = RegValue::String(new.clone());
            let restore = Action::Restore {
                av: av.clone(),
                expected: new.clone(),
            };
            if super::trusting_records() {
                return Ok(match log.done {
                    Some(_) => Seen::new(Observed::After, object).act(restore),
                    None => Seen::new(Observed::Before, object),
                });
            }
            let cur = match current(reg, &av) {
                Ok(v) => v,
                Err(x) if not_ours(&x) => return Ok(Seen::new(Observed::Foreign, object)),
                Err(x) => return Err(e(x)),
            };
            Ok(token_list_seen(
                &av,
                object,
                old.as_ref(),
                add,
                &new,
                cur,
                hint,
                restore,
            ))
        }
        Op::CreateDir { .. } | Op::CreateFile { .. } | Op::ReplaceFile { .. } => {
            Err(not_a_registry_op(k))
        }
    }
}

/// The observation of a `TokenList` from the current value `cur` (module docs).
#[expect(
    clippy::too_many_arguments,
    reason = "the fields of the op, the value seen and the action"
)]
fn token_list_seen(
    av: &AllowedValue,
    object: Object,
    old: Option<&ValueState>,
    add: &[TokenName],
    new: &RegValue,
    cur: Option<RegValue>,
    hint: Option<Hint>,
    restore: Action,
) -> Seen {
    let written = hint != Some(Hint::NotWritten);
    if cur.as_ref() == Some(new) && written {
        return Seen::new(Observed::After, object)
            .act(restore)
            .gone(old.is_none());
    }
    if ValueState::is(old, cur.as_ref()) {
        return Seen::new(Observed::Before, object).gone(old.is_none());
    }
    // N1: after a refused write in this run, nothing there is Rerun's to remove.
    if !written || drift_foreign() {
        return Seen::new(Observed::Foreign, object);
    }
    match cur {
        // S3: someone deleted the value; nothing of Rerun's is left.
        None => Seen::new(Observed::Drifted, object).gone(true),
        Some(RegValue::String(s)) => match layers::unmerge(&s, add) {
            Unmerged::Foreign => Seen::new(Observed::Foreign, object),
            Unmerged::Untouched if untouched_foreign() => Seen::new(Observed::Foreign, object),
            // E2 b: none of Rerun's tokens is left.
            Unmerged::Untouched => Seen::new(Observed::Drifted, object),
            Unmerged::Rest(rest) => Seen::new(Observed::Drifted, object)
                .act(Action::RemoveTokens {
                    av: av.clone(),
                    expected: RegValue::String(s.clone()),
                })
                .gone(rest.is_none()),
        },
        Some(_) => Seen::new(Observed::Foreign, object),
    }
}

/// Carries out what `seen` says for op `k`, after its `RevertIntent`.
pub(super) fn act<W: Reverting>(
    w: &W,
    reg: &RegWriter<'_>,
    k: u16,
    op: &Op,
    seen: &Seen,
) -> Result<Acted, ExecError> {
    let e = op_err(k);
    match seen.action.as_deref() {
        None => {}
        Some(Action::DeleteKey { key, of }) => reg.delete_empty_key(key, of).map_err(&e)?,
        Some(Action::RemoveTokens { av, expected }) => {
            let Op::TokenList { add, .. } = op else {
                return Err(not_a_registry_op(k));
            };
            reg.remove_tokens(av, expected, add).map_err(|x| match x {
                RegWriteError::Sys(s) => e(s),
                RegWriteError::Policy(p) => e(SysError::new(SysErrorKind::Mismatch, p.to_string())),
            })?;
        }
        Some(Action::Restore { av, expected }) => {
            let (Op::SetValue { old, .. } | Op::TokenList { old, .. }) = op else {
                return Err(not_a_registry_op(k));
            };
            let old = match old {
                None => None,
                Some(s) => {
                    // Read whole and hashed against the intent before use (no TOCTOU).
                    let max = u64::try_from(MAX_VALUE_BYTES).unwrap_or(u64::MAX);
                    let bytes = w.before_bytes(k, max)?;
                    Some(RegValue::decode(s.kind, &bytes))
                }
            };
            reg.restore(av, expected, old.as_ref()).map_err(&e)?;
        }
    }
    Ok(Acted::default())
}

/// The records of a registry op fit its kind (record form of P2-10a, checklist P2-10b): no
/// temp name anywhere, no file ID, no `.old` left, no `from`/`to` (also not for a `TokenList`,
/// E8: they stay reserved for P2-12); a `CreateKey` keeps no old state; a `SetValue` keeps
/// exactly its planned old value: inline up to 16 KiB with its length and hash, else the digest
/// of `op-NNNN.bin`; none for a new value; a `TokenList` its old value inline (at most 1 KiB),
/// never a `.bin`.
pub(super) fn records_fit(op: &Op, log: &OpLog) -> bool {
    let i = &log.intent;
    let plain = i.tmp.is_none()
        && log
            .reverts
            .iter()
            .all(|r| r.tmp.is_none() && r.from.is_none() && r.to.is_none())
        && log.done.is_none_or(|d| d.file_id.is_none() && !d.old_left)
        && log.reverted.is_none_or(|r| !r.old_left);
    plain
        && match op {
            Op::CreateKey { .. } => i.before.is_none(),
            Op::SetValue { old: None, .. } => i.before.is_none(),
            Op::SetValue { old: Some(s), .. } => {
                let len = usize::try_from(s.len).unwrap_or(usize::MAX);
                match &i.before {
                    Some(Before::Inline(v)) => {
                        len <= INLINE_MAX
                            && v.len() == len
                            && <[u8; 32]>::from(<sha2::Sha256 as sha2::Digest>::digest(v))
                                == s.sha256
                    }
                    Some(Before::Bin(d)) => {
                        len > INLINE_MAX
                            && *d
                                == Digest {
                                    sha256: s.sha256,
                                    len: u64::from(s.len),
                                }
                    }
                    None => false,
                }
            }
            Op::TokenList { old: None, .. } => i.before.is_none(),
            Op::TokenList { old: Some(s), .. } => {
                let len = usize::try_from(s.len).unwrap_or(usize::MAX);
                matches!(&i.before, Some(Before::Inline(v))
                    if len <= layers::MAX_LAYERS_BYTES
                        && v.len() == len
                        && <[u8; 32]>::from(<sha2::Sha256 as sha2::Digest>::digest(v))
                            == s.sha256)
            }
            Op::CreateDir { .. } | Op::CreateFile { .. } | Op::ReplaceFile { .. } => false,
        }
}
