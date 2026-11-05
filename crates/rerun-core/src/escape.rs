//! Display of untrusted text (ADR 0016): app names, library labels, adapter names, paths and
//! issue texts before they reach a terminal or another output.
//!
//! One explicit table of code points (Unicode 16, no Unicode crate) and two entry points:
//!
//! - [`text`]: the base set only. For names, labels and messages: printable confusables
//!   (full-width letters, `¥`, special spaces) are legitimate there and stay readable.
//! - [`path`]: the base set plus everything [`is_deceptive`] matches. For `RelPath`, `RootPath`
//!   and `SysError` targets, where a confusable changes what a path appears to be.
//!
//! The **base set**: `Cc`; every `Cf` (supplementary planes included); every
//! `Default_Ignorable_Code_Point` (tags, variation selectors, Hangul fillers, …); U+2028 and
//! U+2029; supplementary private use; noncharacters. A clean string comes back unchanged and
//! borrowed; otherwise the whole string is `{:?}`-quoted and every escapable character it still
//! holds is written as `\u{x}`. The result never holds an escapable character, so escaping is
//! idempotent. U+FFFD is kept.
//!
//! Strong right-to-left letters are no control characters and are not escaped; an output that
//! lays text out (the phase 5 app) still isolates untrusted text (`<bdi>`, `dir="auto"`).

use std::borrow::Cow;
use std::fmt;

use crate::path::is_deceptive;

/// Text that went through [`path`] or [`text`]. The field is private and there is no other
/// constructor, so a `Shown` always holds escaped (or clean) text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Shown<'a>(Cow<'a, str>);

impl fmt::Display for Shown<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Shown<'_> {
    /// The text as it is shown.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// `true` if the input had to be escaped (and was quoted); `false` for a clean input that
    /// is shown unchanged, without an allocation.
    pub fn is_escaped(&self) -> bool {
        matches!(self.0, Cow::Owned(_))
    }

    /// The same text, owned (for text computed by the caller, such as an error message).
    pub fn into_owned(self) -> Shown<'static> {
        Shown(Cow::Owned(self.0.into_owned()))
    }

    /// The escaped text, or `None` for a clean input.
    pub(crate) fn into_escaped(self) -> Option<String> {
        match self.0 {
            Cow::Owned(s) => Some(s),
            Cow::Borrowed(_) => None,
        }
    }
}

/// `s` for display as a path: the base set and every [`is_deceptive`] character escaped.
pub fn path(s: &str) -> Shown<'_> {
    shown(s, in_path_set)
}

/// `s` for display as a name, label or message: the base set escaped, printable confusables
/// kept.
pub fn text(s: &str) -> Shown<'_> {
    shown(s, in_base_set)
}

fn shown(s: &str, bad: fn(char) -> bool) -> Shown<'_> {
    if !s.chars().any(bad) {
        return Shown(Cow::Borrowed(s));
    }
    let quoted = format!("{s:?}");
    let mut out = String::with_capacity(quoted.len() + 16);
    for c in quoted.chars() {
        if bad(c) {
            out.push_str(&format!("\\u{{{:x}}}", u32::from(c)));
        } else {
            out.push(c);
        }
    }
    Shown(Cow::Owned(out))
}

/// The base set as sorted, non-overlapping, inclusive ranges (Unicode 16). Noncharacters at
/// the end of each plane (`U+xFFFE`, `U+xFFFF`) are checked separately in [`in_base_set`].
pub(crate) const BASE: &[(u32, u32)] = &[
    (0x0000, 0x001F),    // Cc: C0 controls
    (0x007F, 0x009F),    // Cc: DEL, C1 controls
    (0x00AD, 0x00AD),    // Cf: soft hyphen
    (0x034F, 0x034F),    // DI: combining grapheme joiner
    (0x0600, 0x0605),    // Cf: Arabic number signs
    (0x061C, 0x061C),    // Cf: Arabic letter mark
    (0x06DD, 0x06DD),    // Cf: Arabic end of ayah
    (0x070F, 0x070F),    // Cf: Syriac abbreviation mark
    (0x0890, 0x0891),    // Cf: Arabic pound and piastre mark above
    (0x08E2, 0x08E2),    // Cf: Arabic disputed end of ayah
    (0x115F, 0x1160),    // DI: Hangul choseong and jungseong fillers
    (0x17B4, 0x17B5),    // DI: Khmer inherent vowels
    (0x180B, 0x180F),    // DI: Mongolian free variation selectors, vowel separator (Cf)
    (0x200B, 0x200F),    // Cf: zero width space, ZWNJ, ZWJ, LRM, RLM
    (0x2028, 0x202E),    // Zl, Zp: line and paragraph separator; Cf: bidi embedding/override
    (0x2060, 0x206F),    // Cf: word joiner, invisible operators, bidi isolates; DI: U+2065
    (0x3164, 0x3164),    // DI: Hangul filler
    (0xFDD0, 0xFDEF),    // noncharacters
    (0xFE00, 0xFE0F),    // DI: variation selectors
    (0xFEFF, 0xFEFF),    // Cf: zero width no-break space (BOM)
    (0xFFA0, 0xFFA0),    // DI: halfwidth Hangul filler
    (0xFFF0, 0xFFFB),    // DI: reserved U+FFF0..U+FFF8; Cf: interlinear annotation
    (0x110BD, 0x110BD),  // Cf: Kaithi number sign
    (0x110CD, 0x110CD),  // Cf: Kaithi number sign above
    (0x13430, 0x1343F),  // Cf: Egyptian hieroglyph format controls
    (0x1BCA0, 0x1BCA3),  // Cf: shorthand format controls
    (0x1D173, 0x1D17A),  // Cf: musical symbol beam and phrase controls
    (0xE0000, 0xE0FFF),  // Cf/DI: tags, variation selectors supplement, reserved
    (0xF0000, 0x10FFFF), // Co: supplementary private use A and B (with their noncharacters)
];

/// In the base set: [`BASE`] or a noncharacter at the end of a plane.
pub(crate) fn in_base_set(c: char) -> bool {
    let cp = u32::from(c);
    if (0x20..0x7F).contains(&cp) {
        return false;
    }
    if cp & 0xFFFE == 0xFFFE {
        return true;
    }
    // The last range that starts at or before `cp`.
    let at = BASE.partition_point(|&(start, _)| start <= cp);
    at.checked_sub(1)
        .and_then(|i| BASE.get(i))
        .is_some_and(|&(_, end)| cp <= end)
}

/// In the set of [`path`]: the base set or [`is_deceptive`].
pub(crate) fn in_path_set(c: char) -> bool {
    in_base_set(c) || is_deceptive(c)
}

#[cfg(test)]
mod tests;
