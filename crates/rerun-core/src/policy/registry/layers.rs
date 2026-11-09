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
//! - **Groups** ([`LAYER_GROUPS`], separate from the add allowlist, review N5): Rerun adds no
//!   token of a group (operating-system mode, DPI, colour, resolution) that another added
//!   token or a word of the value already holds, compared folded (review S4). A word not
//!   listed has no group and excludes nothing.
//! - **Revert** ([`unmerge`]): a word equal to one of Rerun's tokens only when folded, or one
//!   of Rerun's tokens twice, is not Rerun's state: `Foreign`. A rest without a word other
//!   than a prefix word ([`PREFIX_WORDS`]) deletes the value (review S2). A value of nothing
//!   but prefix words holds none of Rerun's tokens: `Untouched`, a revert leaves it (P2-11b,
//!   user decision B4.2; the tab never writes a lone `~`, it deletes the value).
//!
//! **Source (P2-11b, ADR 0018 amendment P2-11b, `docs/05-sources-policy.md` "Reference
//! data").** Every word of [`LAYER_TOKENS`] and [`LAYER_GROUPS`] is spelled as Explorer's
//! compatibility tab wrote it in the Windows Sandbox (SB-L1, build 26100, 2026-11-07; the raw
//! values are the fixture `tests/fixtures/layers/sb-l1-2026-11-07.txt`, and a test binds
//! every listed word to it). A token is addable only if SB-L6 also saw it launch without Win32
//! 740 in a non-elevated session, on a 32-bit and a 64-bit image, with `__COMPAT_LAYER`
//! holding it: the elevation rule below sees only names. [`LAYER_TOKENS`] is the one place
//! the add allowlist lives; taking a token off never blocks a revert (R-L8).
//!
//! What is kept out, and how:
//! - `RUNAS…` (`RUNASADMIN`, `RUNASHIGHEST`, `RUNASINVOKER`): elevation tokens (ADR 0018 S6;
//!   an elevated game loads the DLLs Rerun puts in a user-writable folder). Refused by
//!   [`allowed`] by prefix, whatever the list says.
//! - `REGISTERAPPRESTART`: Windows starts the program again by itself after a restart (rule 1:
//!   nothing runs in the background, no autostart). Refused by [`allowed`] by name, whatever
//!   the list says.
//! - The operating-system modes (`WINXPSP3`, `WIN7RTM` and the ones not observed): `WINXPSP3`
//!   makes a 32-bit image need elevation in a non-elevated session (SB-L3) and has no effect on
//!   a 64-bit one; the others are not measured (P2-11b, user decision B5 a). Not on the list,
//!   and a compile-time check keeps every word of [`NEVER_ADD`] (these two included) off it;
//!   whether a mode may ever be added is a later decision with its own measurement. They are
//!   in the group table all the same, so a mode the user set is seen.
//! - Anything SB-L1 did not observe (never invent, `docs/05-sources-policy.md`): not on the
//!   list, held by a test against the SB-L1 fixture.
//!
//! The tab has three DPI options: Application `HIGHDPIAWARE`, System `DPIUNAWARE`, System
//! (Enhanced) the pair `GDIDPISCALING DPIUNAWARE`. Only `HIGHDPIAWARE` is addable: the model
//! is one word per token, so the pair cannot be added as one option, and a lone `DPIUNAWARE`
//! of Rerun's would become half of the pair when the user picks "System (Enhanced)" in the
//! tab (user decision B3 a). All three words are in the DPI group.
//!
//! The current rules ([`check`]) refuse an old value with a prefix character joined to a word
//! (`~X`, `$X`) or a lone `~` or `$` after another word (P2-11b, B4.3): Windows applies `~X`
//! like `X` (SB-L3), but it is another word for the duplicate and group checks. The grammar
//! and the revert take such a value as any other.
//!
//! The logic is tested with synthetic tokens (`ZZ_…`, `#[cfg(test)]`), the production tables
//! (`knob::production`) against the SB-L1 fixture.

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

/// The add allowlist: the tokens a `compat_layer` step may add, in byte order, each with the
/// compatibility tab's label and its SB-L1 dump (module docs). The one place the list lives:
/// a token that SB-L6 or a later probe contradicts is taken off here.
pub const LAYER_TOKENS: &[&str] = &[
    // "Disable fullscreen optimizations"; SB-L1 dump 06-nofso, build 26100, 2026-11-07.
    "DISABLEDXMAXIMIZEDWINDOWEDMODE",
    // "Override high DPI scaling behavior", scaling performed by "Application"; SB-L1 dump
    // 10-dpi-app, build 26100, 2026-11-07.
    "HIGHDPIAWARE",
];

/// The group of every observed word that excludes others (review N5), addable or not: a word
/// not listed has no group. Each as SB-L1 saw it (build 26100, 2026-11-07, dump named).
pub const LAYER_GROUPS: &[(&str, Group)] = &[
    // Reduced colour mode 16-bit (04-color16) and 8-bit (12-combined).
    ("16BITCOLOR", Group::Color),
    ("256COLOR", Group::Color),
    // Run in 640 x 480 (05-640x480), the only resolution the tab offers.
    ("640X480", Group::Res),
    // High DPI override: System (21-dpi-system), System (Enhanced) the pair `GDIDPISCALING
    // DPIUNAWARE` (22-dpi-sysenh), Application (10-dpi-app).
    ("DPIUNAWARE", Group::Dpi),
    ("GDIDPISCALING", Group::Dpi),
    ("HIGHDPIAWARE", Group::Dpi),
    // Compatibility mode Windows 7 (03-win7) and Windows XP (Service Pack 3) (02-xpsp3).
    // Incomplete: the other modes of the list are not observed (SB-L1b); none is addable.
    ("WIN7RTM", Group::OsMode),
    ("WINXPSP3", Group::OsMode),
];

/// Prefix words a value may begin with: `~`, what the tab writes (SB-L1); a rest of nothing
/// else is empty (review S2). `$` has no source and is an ordinary word (P2-11b, B4.1).
pub const PREFIX_WORDS: &[&str] = &["~"];

/// What a new value begins with, before the tokens: what the tab writes (SB-L1) and Windows
/// applies (SB-L3).
pub const PREFIX_NEW: &str = "~ ";

/// The SB-L1 fixture (module docs): the raw values the compatibility tab wrote.
#[cfg(test)]
const SB_L1_FIXTURE: &str =
    include_str!("../../../../../tests/fixtures/layers/sb-l1-2026-11-07.txt");

/// The values of the SB-L1 fixture as (label, hive, data), in the fixture's order; the fixture
/// is ours, so a malformed line is a test failure.
#[cfg(test)]
pub(crate) fn sb_l1_tab() -> Vec<(&'static str, &'static str, &'static str)> {
    SB_L1_FIXTURE
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| {
            let mut it = l.splitn(3, ' ');
            let (Some(label), Some(hive), Some(rest)) = (it.next(), it.next(), it.next()) else {
                panic!("SB-L1 fixture: {l:?}");
            };
            let data = rest
                .split_once("\" = \"")
                .and_then(|(_, d)| d.strip_suffix('"'))
                .unwrap_or_else(|| panic!("SB-L1 fixture: {l:?}"));
            (label, hive, data)
        })
        .collect()
}

/// Words never on the add allowlist (module docs); a compile-time check below holds
/// [`LAYER_TOKENS`] against it, in every build.
pub const NEVER_ADD: &[&str] = &[
    "RUNASADMIN",
    "RUNASHIGHEST",
    "RUNASINVOKER",
    "REGISTERAPPRESTART",
    "WINXPSP3",
    "WIN7RTM",
];

/// Every token beginning with this is an elevation token and is never added (ADR 0018 S6).
const ELEVATION: &str = "RUNAS";

/// The token that makes Windows restart the program by itself; never added (rule 1).
const RESTART: &str = "REGISTERAPPRESTART";

/// `a` equals `b` byte for byte (`const`).
const fn same(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

/// `a` begins with `p` (`const`).
const fn begins(a: &[u8], p: &[u8]) -> bool {
    if a.len() < p.len() {
        return false;
    }
    let mut i = 0;
    while i < p.len() {
        if a[i] != p[i] {
            return false;
        }
        i += 1;
    }
    true
}

// No word of the add allowlist is on the never-list, an elevation token or the restart token,
// in every build (review S2, N3).
const _: () = {
    let mut i = 0;
    while i < LAYER_TOKENS.len() {
        let t = LAYER_TOKENS[i].as_bytes();
        assert!(
            !begins(t, ELEVATION.as_bytes()),
            "an elevation token on LAYER_TOKENS"
        );
        assert!(
            !same(t, RESTART.as_bytes()),
            "REGISTERAPPRESTART on LAYER_TOKENS"
        );
        let mut j = 0;
        while j < NEVER_ADD.len() {
            assert!(
                !same(t, NEVER_ADD[j].as_bytes()),
                "a NEVER_ADD word on LAYER_TOKENS"
            );
            j += 1;
        }
        i += 1;
    }
};

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
/// compatibility tab that Rerun does not add; the `ZZ_FLAG_…` tokens have no group.
#[cfg(test)]
pub(crate) const TEST_GROUPS: &[(&str, Group)] = &[
    ("ZZ_OS_A", Group::OsMode),
    ("ZZ_OS_B", Group::OsMode),
    ("ZZ_OS_C", Group::OsMode),
    ("ZZ_DPI_A", Group::Dpi),
    ("ZZ_DPI_B", Group::Dpi),
    ("ZZ_COLOR_A", Group::Color),
    ("ZZ_RES_A", Group::Res),
];

#[cfg(test)]
pub(crate) mod knob {
    //! Test knobs of this thread: the tables (synthetic by default), R-L8 and the controls
    //! K-L1 and K-L4.

    use std::cell::Cell;

    thread_local! {
        static PRODUCTION: Cell<bool> = const { Cell::new(false) };
        static DROPPED: Cell<Option<&'static str>> = const { Cell::new(None) };
        static PLANTED: Cell<Option<&'static str>> = const { Cell::new(None) };
        static REVERSED: Cell<bool> = const { Cell::new(false) };
        static NORMALISE_OLD: Cell<bool> = const { Cell::new(false) };
        static FIRST_ONLY: Cell<bool> = const { Cell::new(false) };
    }

    /// The production tables instead of the synthetic ones.
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
    /// A token planted on the allowlist in force (the hard exclusions of `allowed`).
    pub(crate) fn plant(t: Option<&'static str>) {
        PLANTED.with(|c| c.set(t));
    }
    pub(crate) fn planted() -> Option<&'static str> {
        PLANTED.with(Cell::get)
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
        let base = if knob::is_production() {
            LAYER_TOKENS
        } else {
            TEST_TOKENS
        };
        let mut t: Vec<&'static str> = base
            .iter()
            .copied()
            .filter(|t| Some(*t) != knob::dropped())
            .chain(knob::planted())
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

/// `t` may be added: exactly on the add allowlist, no elevation token and not the restart
/// token (module docs).
pub fn allowed(t: &TokenName) -> bool {
    let s = t.as_str();
    !s.starts_with(ELEVATION) && s != RESTART && tokens().contains(&s)
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
    if let Some(w) = joined_prefix(&old_words) {
        return Err(denied(
            format!("the Layers word {w:?}"),
            "a prefix joined to a word or after a word is an unusual value; Rerun leaves it alone",
        ));
    }
    for t in add {
        let f = fold(t.as_str());
        if old_words.iter().any(|w| fold(w) == f) {
            return Err(denied(t.as_str(), "the token is already in the value"));
        }
        if let Some(g) = group_of(t.as_str()) {
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

/// The first conflict between the "all users" value `machine` (the `HKLM` value of the same
/// executable, P3-6, ADR 0018 amendment P3-6) and the tokens `add` Rerun would append to the
/// `HKCU` value: a word of `machine` in the group of one of `add` and not that token itself
/// (both folded), as (word, token). A prefix character joined to a word (`~X`, `$X`) is looked
/// through, since Windows applies `~X` like `X` (SB-L3). `Err` for a value outside the strict
/// grammar: its tokens cannot be checked. Rerun never writes `HKLM`; this only reads.
pub fn machine_conflict<'m>(
    machine: &'m str,
    add: &[TokenName],
) -> Result<Option<(&'m str, TokenName)>, RegPolicyError> {
    let l = parse(machine)?;
    for t in add {
        let Some(g) = group_of(t.as_str()) else {
            continue;
        };
        let f = fold(t.as_str());
        let hit = l.words().iter().copied().find(|w| {
            let bare = w.trim_start_matches(['~', '$']);
            fold(bare) != f && group_of(bare) == Some(g)
        });
        if let Some(w) = hit {
            return Ok(Some((w, t.clone())));
        }
    }
    Ok(None)
}

/// The first word of `words` that is a prefix character (`~`, `$`) joined to a word, or a lone
/// one after another word (P2-11b, B4.3; module docs). Lone ones at the start (`~`, `$ ~`)
/// are fine.
fn joined_prefix<'w>(words: &[&'w str]) -> Option<&'w str> {
    let mut leading = true;
    words.iter().copied().find(|w| {
        let prefix = w.starts_with(['~', '$']);
        if prefix && w.len() > 1 {
            return true;
        }
        if prefix {
            return !leading;
        }
        leading = false;
        false
    })
}

#[cfg(test)]
mod tests;
