//! `policy::registry::layers`: the tokens of an `AppCompatFlags\Layers` value (P2-11, ADR 0018
//! amendment P2-11, ADR 0020 amendment P2-11).
//!
//! The value is shared with Explorer's compatibility tab, the Program Compatibility Assistant
//! and the user, so Rerun never owns it: it appends allowlisted tokens to whatever is there
//! (the old bytes unchanged, [`merge`]) and a revert either restores the old value exactly
//! (nothing else changed it) or removes only the words Rerun added ([`unmerge`]).
//!
//! - **Grammar** ([`parse`], strict): printable ASCII without space (`0x21` to `0x7E`) in
//!   words separated by exactly one space, no space at either end, not empty, at most
//!   [`MAX_LAYERS_BYTES`] as a `REG_SZ` with its NUL. A value outside it is unusual: the
//!   planner leaves it alone, a revert finds it `Foreign`.
//! - **Tokens** ([`TokenName`]): `[A-Z0-9_]`, 1 to 40 characters; the form only. Whether a
//!   token may be added is [`allowed`]: exactly on the add allowlist [`LAYER_TOKENS`], never
//!   an elevation token (`RUNAS…`, ADR 0018 S6), whatever the list says.
//! - **Groups** ([`LAYER_GROUPS`], separate from the add allowlist, review N5): at most one
//!   token of an exclusive group (operating-system mode, DPI, colour, resolution) per value,
//!   compared folded (review S4), Rerun's and the value's together.
//! - **Revert** ([`unmerge`]): a word equal to one of Rerun's tokens only when folded, or one
//!   of Rerun's tokens twice, is not Rerun's state: `Foreign`. A rest without a word other
//!   than a prefix word ([`PREFIX_WORDS`]) deletes the value (review S2).
//!
//! **No token is allowlisted yet (review S8).** [`LAYER_TOKENS`] and [`LAYER_GROUPS`] stay
//! empty, so the planner refuses every token, until the Windows Sandbox probes SB-L1 and SB-L3
//! have shown how the compatibility tab spells each token and which prefix a value needs; the
//! commit that fills them names a source for every token (`docs/05-sources-policy.md`,
//! reference data). Tests use synthetic tokens (`ZZ_…`, `#[cfg(test)]`). [`PREFIX_NEW`] and
//! [`PREFIX_WORDS`] are provisional for the same reason: they decide nothing while no token
//! can be added.

use std::fmt;

use super::{RegPolicyError, denied};
use crate::fold::fold;

/// Longest token.
pub const MAX_TOKEN: usize = 40;
/// Most tokens one op adds.
pub const MAX_ADD: usize = 8;
/// Largest `Layers` value Rerun reads or writes, old and new alike: bytes of the `REG_SZ`
/// with its NUL (511 characters). A plan carries such an old value inline (review N6).
pub const MAX_LAYERS_BYTES: usize = 1 << 10;
const _: () = assert!(MAX_LAYERS_BYTES <= crate::plan::OLD_INLINE);

/// The add allowlist: the tokens a `compat_layer` step may add. Empty until SB-L1 and SB-L3
/// (module docs, review S8).
pub const LAYER_TOKENS: &[&str] = &[];

/// The group of every token that excludes others (review N5): a token not listed has no
/// group. Empty until SB-L1 (module docs).
pub const LAYER_GROUPS: &[(&str, Group)] = &[];

/// Prefix words a value may begin with (ADR 0018 names `~` and `$`); a value of nothing else is
/// empty. Provisional until SB-L1 (module docs).
pub const PREFIX_WORDS: &[&str] = &["~", "$"];

/// What a new value begins with, before the tokens. Provisional until SB-L3 (module docs).
pub const PREFIX_NEW: &str = "~ ";

/// Every token beginning with this is an elevation token and is never added (ADR 0018 S6).
const ELEVATION: &str = "RUNAS";

/// A group of tokens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Group {
    /// An operating-system mode.
    OsMode,
    /// A DPI setting.
    Dpi,
    /// A reduced colour mode.
    Color,
    /// A reduced resolution.
    Res,
    /// A flag: no exclusion.
    Flag,
}

impl Group {
    /// At most one token of this group per value.
    fn exclusive(self) -> bool {
        !matches!(self, Self::Flag)
    }
}

/// Synthetic tokens of the tests: no real token spelling is assumed (review S8).
#[cfg(test)]
pub(crate) const TEST_TOKENS: &[&str] = &[
    "ZZ_COLOR_A",
    "ZZ_DPI_A",
    "ZZ_FLAG_A",
    "ZZ_FLAG_B",
    "ZZ_FLAG_C",
    "ZZ_FLAG_D",
    "ZZ_FLAG_E",
    "ZZ_FLAG_F",
    "ZZ_FLAG_G",
    "ZZ_OS_A",
    "ZZ_OS_B",
    "ZZ_RES_A",
];

/// The groups of the synthetic tokens; `ZZ_OS_C` and `ZZ_DPI_B` stand for tokens of the
/// compatibility tab that Rerun does not add.
#[cfg(test)]
pub(crate) const TEST_GROUPS: &[(&str, Group)] = &[
    ("ZZ_OS_A", Group::OsMode),
    ("ZZ_OS_B", Group::OsMode),
    ("ZZ_OS_C", Group::OsMode),
    ("ZZ_DPI_A", Group::Dpi),
    ("ZZ_DPI_B", Group::Dpi),
    ("ZZ_COLOR_A", Group::Color),
    ("ZZ_RES_A", Group::Res),
    ("ZZ_FLAG_A", Group::Flag),
];

#[cfg(test)]
pub(crate) mod knob {
    //! Test knobs of this thread: the tables (synthetic by default), R-L8 and the controls
    //! K-L1 and K-L4.

    use std::cell::Cell;

    thread_local! {
        static PRODUCTION: Cell<bool> = const { Cell::new(false) };
        static DROPPED: Cell<Option<&'static str>> = const { Cell::new(None) };
        static REVERSED: Cell<bool> = const { Cell::new(false) };
        static NORMALISE_OLD: Cell<bool> = const { Cell::new(false) };
        static FIRST_ONLY: Cell<bool> = const { Cell::new(false) };
    }

    /// The production tables (empty) instead of the synthetic ones.
    pub(crate) fn production(on: bool) {
        PRODUCTION.with(|c| c.set(on));
    }
    pub(crate) fn is_production() -> bool {
        PRODUCTION.with(Cell::get)
    }
    /// R-L8: a token removed from the allowlist.
    pub(crate) fn drop_token(t: Option<&'static str>) {
        DROPPED.with(|c| c.set(t));
    }
    pub(crate) fn dropped() -> Option<&'static str> {
        DROPPED.with(Cell::get)
    }
    /// R-L8 (M1): the allowlist in reverse order.
    pub(crate) fn reverse(on: bool) {
        REVERSED.with(|c| c.set(on));
    }
    pub(crate) fn is_reversed() -> bool {
        REVERSED.with(Cell::get)
    }
    /// K-L4: `merge` sorts the words of the old value.
    pub(crate) fn normalise_old(on: bool) {
        NORMALISE_OLD.with(|c| c.set(on));
    }
    pub(crate) fn normalising_old() -> bool {
        NORMALISE_OLD.with(Cell::get)
    }
    /// K-L1: `unmerge` removes only the first of Rerun's tokens it meets.
    pub(crate) fn first_only(on: bool) {
        FIRST_ONLY.with(|c| c.set(on));
    }
    pub(crate) fn removing_first_only() -> bool {
        FIRST_ONLY.with(Cell::get)
    }
}

/// The add allowlist in force (synthetic in tests).
fn tokens() -> Vec<&'static str> {
    #[cfg(test)]
    {
        if knob::is_production() {
            return LAYER_TOKENS.to_vec();
        }
        let mut t: Vec<&'static str> = TEST_TOKENS
            .iter()
            .copied()
            .filter(|t| Some(*t) != knob::dropped())
            .collect();
        if knob::is_reversed() {
            t.reverse();
        }
        t
    }
    #[cfg(not(test))]
    LAYER_TOKENS.to_vec()
}

/// The group table in force (synthetic in tests).
fn groups() -> &'static [(&'static str, Group)] {
    #[cfg(test)]
    if !knob::is_production() {
        return TEST_GROUPS;
    }
    LAYER_GROUPS
}

/// A token's form: `[A-Z0-9_]`, 1 to [`MAX_TOKEN`] characters. On the wire a string, parsed
/// through [`TokenName::parse`] (the form, never the allowlist: a recorded head stays
/// readable when the allowlist changes, user decision E4). Ordered byte-wise (review M1).
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(try_from = "String", into = "String")]
pub struct TokenName(String);

impl TokenName {
    /// Checks the form.
    pub fn parse(s: &str) -> Result<Self, RegPolicyError> {
        if s.is_empty()
            || s.len() > MAX_TOKEN
            || !s
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
        {
            return Err(denied(
                format!("{s:?}"),
                "a token has 1 to 40 characters of A-Z, 0-9 and _",
            ));
        }
        Ok(Self(s.to_owned()))
    }

    /// The token.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for TokenName {
    type Error = RegPolicyError;

    fn try_from(s: String) -> Result<Self, RegPolicyError> {
        Self::parse(&s)
    }
}

impl From<TokenName> for String {
    fn from(t: TokenName) -> Self {
        t.0
    }
}

impl fmt::Display for TokenName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// `t` may be added: exactly on the add allowlist, and no elevation token.
pub fn allowed(t: &TokenName) -> bool {
    !t.as_str().starts_with(ELEVATION) && tokens().contains(&t.as_str())
}

/// The group of a word of a value, compared folded (review S4); `None` for a word without one.
pub fn group_of(word: &str) -> Option<Group> {
    let w = fold(word);
    groups().iter().find(|(t, _)| fold(t) == w).map(|(_, g)| *g)
}

/// The words of a value in the strict grammar (module docs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layers<'a> {
    words: Vec<&'a str>,
}

impl<'a> Layers<'a> {
    /// The words, in their order.
    pub fn words(&self) -> &[&'a str] {
        &self.words
    }
}

/// `s` as a `REG_SZ` with its NUL fits [`MAX_LAYERS_BYTES`] (ASCII: one UTF-16 unit per byte).
pub fn fits(s: &str) -> bool {
    s.len().saturating_add(1).saturating_mul(2) <= MAX_LAYERS_BYTES
}

/// Parses `s` in the strict grammar (module docs), including the length.
pub fn parse(s: &str) -> Result<Layers<'_>, RegPolicyError> {
    let bad = |why| Err(denied("a Layers value", why));
    if s.is_empty() {
        return bad("empty");
    }
    if !fits(s) {
        return bad("longer than 511 characters");
    }
    if !s.bytes().all(|b| b == b' ' || (0x21..=0x7E).contains(&b)) {
        return bad("only printable ASCII words");
    }
    let words: Vec<&str> = s.split(' ').collect();
    if words.iter().any(|w| w.is_empty()) {
        return bad("words separated by exactly one space, none at either end");
    }
    Ok(Layers { words })
}

/// The value with `add` appended: `old`, one space, the tokens (the bytes of `old` unchanged);
/// without an old value [`PREFIX_NEW`] and the tokens. The one place a new value is formed.
pub fn merge(old: Option<&str>, add: &[TokenName]) -> String {
    let tail: Vec<&str> = add.iter().map(TokenName::as_str).collect();
    let tail = tail.join(" ");
    match old {
        #[cfg(test)]
        Some(o) if knob::normalising_old() => {
            let mut w: Vec<&str> = o.split(' ').collect();
            w.sort_unstable();
            format!("{} {tail}", w.join(" "))
        }
        Some(o) => format!("{o} {tail}"),
        None => format!("{PREFIX_NEW}{tail}"),
    }
}

/// What [`unmerge`] finds in a current value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unmerged {
    /// Not a state Rerun left: the grammar or the length broken, one of Rerun's tokens twice, a
    /// word equal to one of them only when folded.
    Foreign,
    /// None of Rerun's tokens is there: nothing to remove.
    Untouched,
    /// The value without Rerun's tokens, the order of the other words kept; `None`: nothing
    /// but prefix words is left, the value is deleted (review S2).
    Rest(Option<String>),
}

/// The current value `cur` without the tokens `ours` (module docs).
pub fn unmerge(cur: &str, ours: &[TokenName]) -> Unmerged {
    let Ok(l) = parse(cur) else {
        return Unmerged::Foreign;
    };
    let mut seen = vec![0usize; ours.len()];
    for w in l.words() {
        match ours.iter().position(|t| t.as_str() == *w) {
            Some(i) => seen[i] += 1,
            None => {
                let f = fold(w);
                if ours.iter().any(|t| fold(t.as_str()) == f) {
                    return Unmerged::Foreign;
                }
            }
        }
    }
    if seen.iter().any(|n| *n > 1) {
        return Unmerged::Foreign;
    }
    if seen.iter().all(|n| *n == 0) {
        return Unmerged::Untouched;
    }
    #[cfg(test)]
    let first_only = knob::removing_first_only();
    #[cfg(not(test))]
    let first_only = false;
    let mut removed = false;
    let rest: Vec<&str> = l
        .words()
        .iter()
        .copied()
        .filter(|w| {
            let ours = ours.iter().any(|t| t.as_str() == *w);
            if ours && first_only && removed {
                return true;
            }
            removed |= ours;
            !ours
        })
        .collect();
    if rest.iter().all(|w| PREFIX_WORDS.contains(w)) {
        Unmerged::Rest(None)
    } else {
        Unmerged::Rest(Some(rest.join(" ")))
    }
}

/// The rules for adding `add` to a value holding `old` (`None`: missing); see
/// [`super::RegPolicy::check_tokens`].
pub(super) fn check(old: Option<&str>, add: &[TokenName]) -> Result<(), RegPolicyError> {
    if add.is_empty() || add.len() > MAX_ADD {
        return Err(denied("tokens", "1 to 8 tokens are added at once"));
    }
    if add.windows(2).any(|w| w[0] >= w[1]) {
        return Err(denied(
            "tokens",
            "the tokens are unique and in byte order (one form)",
        ));
    }
    if let Some(t) = add.iter().find(|t| !allowed(t)) {
        return Err(denied(t.as_str(), "this token is not on the allowlist"));
    }
    let old_words = match old {
        None => Vec::new(),
        Some(o) => parse(o)
            .map_err(|_| {
                denied(
                    "the Layers value",
                    "an unusual value; Rerun leaves it alone",
                )
            })?
            .words()
            .to_vec(),
    };
    for t in add {
        let f = fold(t.as_str());
        if old_words.iter().any(|w| fold(w) == f) {
            return Err(denied(t.as_str(), "the token is already in the value"));
        }
        if let Some(g) = group_of(t.as_str()).filter(|g| g.exclusive()) {
            let other = add
                .iter()
                .map(TokenName::as_str)
                .filter(|o| *o != t.as_str())
                .chain(old_words.iter().copied())
                .find(|o| group_of(o) == Some(g));
            if let Some(o) = other {
                return Err(RegPolicyError::Denied {
                    what: format!("{t} and {o}"),
                    why: "two tokens of one group (operating system, DPI, colour or resolution)",
                });
            }
        }
    }
    if !fits(&merge(old, add)) {
        return Err(denied("the new Layers value", "longer than 511 characters"));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
