//! `policy::registry::gpu_pref`: the pairs of a `UserGpuPreferences` value (P4-11, ADR 0018
//! amendment P4-11, ADR 0020 amendment P4-11).
//!
//! `HKCU\Software\Microsoft\DirectX\UserGpuPreferences` holds one `REG_SZ` per executable
//! (value name: its full path), written by Settings > System > Display > Graphics. The value is
//! a list of `Name=Value;` pairs: `GpuPreference` `0` (let Windows decide), `1` (power saving),
//! `2` (high performance), and others Windows stores for the same executable (`AutoHDREnable`,
//! `SwapEffectUpgradeEnable`, …). Rerun never owns the value: it changes only its own pair and
//! keeps every other pair byte for byte, in its place.
//!
//! - **Grammar** ([`parse`], strict): 1 to n pairs `Name=Value;`, each closed by `;`, nothing
//!   between them; `Name` `[A-Za-z][A-Za-z0-9_]{0,63}`; `Value` 1 to 64 printable ASCII
//!   characters without `;`, `=` and space; names unique (folded); at most [`MAX_PREF_BYTES`]
//!   as a `REG_SZ` with its NUL. A name that folds to [`PREF_KEY`] must be spelled exactly so
//!   and hold `0`, `1` or `2`. Anything else is unusual: the planner leaves it alone, a revert
//!   finds it `Foreign` (also a value of another type, or another `GpuPreference` value such as
//!   a specific adapter encoded in the value: its form is not measured; a specific adapter
//!   stored as a pair of its own would pass as a foreign pair, SB-G1 decides, ADR 0018
//!   amendment P4-11).
//! - **Merge** ([`set`]): no value gives `GpuPreference=2;`; an existing `GpuPreference=0;`
//!   changes in its place; a value without the pair gets it appended. `=2` already there is no
//!   op (the planner's call); `=1`, the user's "Power saving", is refused (user decision E-G3
//!   a, [`super::RegPolicy::check_pref`]).
//! - **Revert of a changed value** ([`unset`]): only when the value is in the grammar and holds
//!   Rerun's `GpuPreference=2` is the pair set back to the old digit (or removed when the old
//!   value had none); every other pair stays as it is now. A value without Rerun's pair (the
//!   user chose another preference since) is left: the user's choice wins.
//!
//! Sources: the values `0`, `1` and `2` and the `AutoHDREnable` pair from Microsoft Q&A and
//! Kapil Arya, "Set Graphics Preference for Apps in Windows 11" (`docs/03b-gpu-display.md`,
//! "Sources"); the raw values Settings writes are to be dumped in the Windows Sandbox (SB-G1,
//! `docs/09-testing.md`) before the step is reviewed.

use std::fmt;

use super::{RegPolicyError, denied};
use crate::fold::fold;

/// The pair Rerun changes.
pub const PREF_KEY: &str = "GpuPreference";
/// Largest `UserGpuPreferences` value Rerun reads or writes, old and new alike: bytes of the
/// `REG_SZ` as UTF-16 with its NUL (511 ASCII characters; review N3). A plan carries such an
/// old value inline.
pub const MAX_PREF_BYTES: usize = 1 << 10;
const _: () = assert!(MAX_PREF_BYTES <= crate::plan::OLD_INLINE);
/// Longest pair name.
pub const MAX_PAIR_NAME: usize = 64;
/// Longest pair value.
pub const MAX_PAIR_VALUE: usize = 64;

/// The preference a `gpu_preference` step sets. On the wire `snake_case`
/// (`"high_performance"`); `power_saving` may follow without a format break.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GpuPref {
    /// `GpuPreference=2;`: Windows uses the high-performance adapter.
    HighPerformance,
}

impl GpuPref {
    /// The digit Windows stores.
    pub fn digit(self) -> u8 {
        match self {
            Self::HighPerformance => 2,
        }
    }

    /// The pair's value as text.
    fn text(self) -> &'static str {
        match self {
            Self::HighPerformance => "2",
        }
    }

    /// The name on the wire and in the preview.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::HighPerformance => "high_performance",
        }
    }
}

impl fmt::Display for GpuPref {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The pairs of a value in the strict grammar, in their order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pairs<'a>(Vec<(&'a str, &'a str)>);

impl<'a> Pairs<'a> {
    /// The pairs, in their order.
    pub fn pairs(&self) -> &[(&'a str, &'a str)] {
        &self.0
    }

    /// The value they form (the same bytes as the parsed text: the grammar has one form).
    fn join(&self) -> String {
        self.0.iter().map(|(n, v)| format!("{n}={v};")).collect()
    }
}

/// `s` as a `REG_SZ` with its NUL fits [`MAX_PREF_BYTES`] (UTF-16 units, review N3).
pub fn fits(s: &str) -> bool {
    s.encode_utf16().count().saturating_add(1).saturating_mul(2) <= MAX_PREF_BYTES
}

fn name_ok(n: &str) -> bool {
    let b = n.as_bytes();
    !b.is_empty()
        && b.len() <= MAX_PAIR_NAME
        && b[0].is_ascii_alphabetic()
        && b.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'_')
}

fn value_ok(v: &str) -> bool {
    !v.is_empty()
        && v.len() <= MAX_PAIR_VALUE
        && v.bytes()
            .all(|c| (0x21..=0x7E).contains(&c) && c != b';' && c != b'=')
}

/// Parses `s` in the strict grammar (module docs), including the length.
pub fn parse(s: &str) -> Result<Pairs<'_>, RegPolicyError> {
    let bad = |why| Err(denied("a UserGpuPreferences value", why));
    if s.is_empty() {
        return bad("empty");
    }
    if !fits(s) {
        return bad("longer than 511 characters");
    }
    let Some(body) = s.strip_suffix(';') else {
        return bad("every pair ends with ;");
    };
    let mut out: Vec<(&str, &str)> = Vec::new();
    for p in body.split(';') {
        let Some((n, v)) = p.split_once('=') else {
            return bad("pairs of the form Name=Value;");
        };
        if !name_ok(n) || !value_ok(v) {
            return bad("pairs of the form Name=Value; in printable ASCII");
        }
        let f = fold(n);
        if out.iter().any(|(o, _)| fold(o) == f) {
            return bad("a pair name twice");
        }
        if f == fold(PREF_KEY) && (n != PREF_KEY || !matches!(v, "0" | "1" | "2")) {
            return bad("a GpuPreference pair of another form");
        }
        out.push((n, v));
    }
    Ok(Pairs(out))
}

/// The `GpuPreference` pair of a parsed value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Current {
    /// No such pair.
    Absent,
    /// `0`, `1` or `2`.
    Digit(u8),
}

/// The `GpuPreference` pair of `p`.
pub fn current(p: &Pairs<'_>) -> Current {
    p.0.iter()
        .find(|(n, _)| *n == PREF_KEY)
        .and_then(|(_, v)| v.parse::<u8>().ok())
        .map_or(Current::Absent, Current::Digit)
}

/// The value with Rerun's pair: `GpuPreference=<pref>;` alone without an old value, the pair
/// changed in its place, or appended at the end. The one place a new value is formed. `Err`
/// for an old value outside the grammar (the planner never gets there).
pub fn set(old: Option<&str>, pref: GpuPref) -> Result<String, RegPolicyError> {
    let Some(old) = old else {
        return Ok(format!("{PREF_KEY}={};", pref.text()));
    };
    let mut p = parse(old)?;
    match p.0.iter_mut().find(|(n, _)| *n == PREF_KEY) {
        Some(pair) => pair.1 = pref.text(),
        None => p.0.push((PREF_KEY, pref.text())),
    }
    Ok(p.join())
}

/// What [`unset`] finds in a current value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unset {
    /// The value without Rerun's preference: the pair back to the old digit, or removed;
    /// every other pair as it is now. `None`: no pair is left, the value is deleted.
    Rest(Option<String>),
    /// In the grammar, but Rerun's pair is not there (missing, or another digit): the user's
    /// choice since the apply, nothing to write.
    NotOurs,
    /// Outside the grammar: not a state Rerun left.
    Foreign,
}

/// The `GpuPreference` digit of a recorded old value, read without the grammar (review
/// follow-up: a grammar tightened since the plan must not turn a drifted value `Foreign`): the
/// first piece (split after each `;`) that starts with `GpuPreference=` and ends with `;`, the
/// same piece logic as `plan::pref_relation`. `None`: a pair whose value is not `0`, `1` or
/// `2` (nothing is guessed).
pub fn old_digit(old: &str) -> Option<Current> {
    let head = format!("{PREF_KEY}=");
    let Some(piece) = old
        .split_inclusive(';')
        .find(|p| p.starts_with(&head) && p.ends_with(';'))
    else {
        return Some(Current::Absent);
    };
    match &piece[head.len()..piece.len() - 1] {
        "0" => Some(Current::Digit(0)),
        "1" => Some(Current::Digit(1)),
        "2" => Some(Current::Digit(2)),
        _ => None,
    }
}

/// The current value `cur` with Rerun's `ours` taken back to what `old` held (module docs).
/// `cur` must be in the grammar (Rerun writes into it); `old`, the journal's value, is read
/// without the grammar ([`old_digit`]); an old pair of another value is `Foreign`.
pub fn unset(cur: &str, ours: GpuPref, old: Option<&str>) -> Unset {
    let Ok(mut p) = parse(cur) else {
        return Unset::Foreign;
    };
    if current(&p) != Current::Digit(ours.digit()) {
        return Unset::NotOurs;
    }
    let before = match old {
        None => Current::Absent,
        Some(o) => match old_digit(o) {
            Some(c) => c,
            None => return Unset::Foreign,
        },
    };
    match before {
        Current::Digit(d) => {
            let text = match d {
                0 => "0",
                1 => "1",
                _ => "2",
            };
            if let Some(pair) = p.0.iter_mut().find(|(n, _)| *n == PREF_KEY) {
                pair.1 = text;
            }
        }
        Current::Absent => p.0.retain(|(n, _)| *n != PREF_KEY),
    }
    if p.0.is_empty() {
        Unset::Rest(None)
    } else {
        Unset::Rest(Some(p.join()))
    }
}

/// The rules for setting `pref` on a value holding `old` (`None`: missing); see
/// [`super::RegPolicy::check_pref`]. Returns the new value.
pub(super) fn check(old: Option<&str>, pref: GpuPref) -> Result<String, RegPolicyError> {
    if let Some(o) = old {
        let p = parse(o).map_err(|_| {
            denied(
                "the UserGpuPreferences value",
                "an unusual value; Rerun leaves it alone",
            )
        })?;
        match current(&p) {
            Current::Digit(1) => {
                return Err(denied(
                    "the UserGpuPreferences value",
                    "the graphics preference is \"Power saving\", chosen in Settings > Display > \
                     Graphics; Rerun does not override it",
                ));
            }
            Current::Digit(d) if d == pref.digit() => {
                return Err(denied(
                    "the UserGpuPreferences value",
                    "the preference is set already",
                ));
            }
            _ => {}
        }
    }
    let new = set(old, pref)?;
    if !fits(&new) {
        return Err(denied(
            "the new UserGpuPreferences value",
            "longer than 511 characters",
        ));
    }
    Ok(new)
}

#[cfg(test)]
mod tests;
