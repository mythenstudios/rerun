//! Paths in the game folder: [`RelPath`] (relative, confined) and [`GameRoot`] (root).
//!
//! A `RelPath` can never leave the game folder lexically. The rules are the same as
//! `$defs/relPath` in `schema/topo.schema.json` and `schema/package.schema.json`; the
//! parity test in `tests/schema.rs` checks both against `tests/fixtures/paths.json`.
//!
//! Not allowed:
//! - empty, longer than [`RelPath::MAX_LEN`] characters
//! - absolute: leading separator, drive (`C:`), UNC, `\\?\`, `\\.\` (covered by "no
//!   `:`", "no `?`" and "no leading separator")
//! - empty segments (`a//b`), `.` and `..`
//! - characters `< > : " | ? *` and control characters (`:` also rules out alternate data streams)
//! - invisible and confusable Unicode characters ([`is_deceptive`]): bidi and format characters,
//!   zero-width, special spaces, line separators, private use, fullwidth ASCII
//!   (`．＼` → `.\` under ANSI best-fit), yen/won (backslash in old code pages), slash look-alikes
//! - reserved device names (`CON`, `PRN`, `AUX`, `NUL`, `CONIN$`, `CONOUT$`, `CLOCK$`,
//!   `COM0-9`, `LPT0-9`, also superscript `¹²³`), also with an extension (`nul.txt`)
//! - dot or space at the end of a segment, space at the start of a segment (Win32 strips them)
//! - `~` followed by a digit (8.3 short names like `PROGRA~1` could refer to other files;
//!   also blocks `Data~2024`)
//!
//! Comparisons ([`PartialEq`], [`Hash`], [`Ord`]) are case-insensitive like NTFS:
//! `D3D9.dll` and `d3d9.dll` are the same path.
//!
//! The check for reparse points (symlinks, junctions) in the real folder arrives in phase 2
//! (see ADR 0007).

use std::cmp::Ordering;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};

use crate::sys::fold::fold;

/// Error while checking a path.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid path {path:?}: {reason}")]
pub struct PathError {
    /// The checked path.
    pub path: String,
    /// Reason.
    pub reason: &'static str,
}

const FORBIDDEN_CHARS: &[char] = &['<', '>', ':', '"', '|', '?', '*'];
const RESERVED: &[&str] = &["CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$", "CLOCK$"];
const RESERVED_NUMBERED: &[&str] = &["COM", "LPT"];

/// Invisible or confusable characters. Same list as in the schema (`relPath`).
pub fn is_deceptive(c: char) -> bool {
    matches!(c,
        '\u{00A0}' | '\u{00AD}' | '\u{061C}' | '\u{1680}' | '\u{180E}'
        | '\u{2000}'..='\u{200F}'   // special spaces, zero-width, LRM/RLM
        | '\u{2028}'..='\u{202F}'   // line/paragraph separators, bidi embedding/override, NNBSP
        | '\u{205F}'..='\u{206F}'   // MMSP, word joiner, bidi isolates, invisible operators
        | '\u{3000}' | '\u{FEFF}'
        | '\u{FFF9}'..='\u{FFFB}'
        | '\u{E000}'..='\u{F8FF}'   // Private Use
        | '\u{FF01}'..='\u{FF5E}'   // fullwidth ASCII
        | '\u{00A5}' | '\u{20A9}'   // ¥ ₩ (backslash in Japanese/Korean code pages)
        | '\u{2215}' | '\u{2044}' | '\u{29F8}' // slash look-alikes
    )
}

/// Checks a single path segment (file or directory name).
fn check_segment(seg: &str) -> Result<(), &'static str> {
    if seg.is_empty() {
        return Err("empty segment (leading, trailing or double separator)");
    }
    if seg == "." || seg == ".." {
        return Err("'.' or '..' segment");
    }
    for c in seg.chars() {
        if c == ':' {
            return Err("contains ':' (drive or stream)");
        }
        if c.is_control() || FORBIDDEN_CHARS.contains(&c) {
            return Err("forbidden character");
        }
        if is_deceptive(c) {
            return Err("invisible or confusable character");
        }
    }
    if seg.ends_with('.') || seg.ends_with(' ') {
        return Err("segment ends with '.' or space");
    }
    if seg.starts_with(' ') {
        return Err("segment starts with space");
    }
    let mut chars = seg.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '~' && chars.peek().is_some_and(char::is_ascii_digit) {
            return Err("looks like an 8.3 short name ('~' followed by digit)");
        }
    }
    // Device name: part before the first dot, trailing spaces ignored.
    let stem = seg
        .split('.')
        .next()
        .unwrap_or(seg)
        .trim_end_matches(' ')
        .to_ascii_uppercase();
    if RESERVED.contains(&stem.as_str()) {
        return Err("reserved device name");
    }
    for prefix in RESERVED_NUMBERED {
        if let Some(rest) = stem.strip_prefix(prefix) {
            let mut rc = rest.chars();
            if let (Some(c), None) = (rc.next(), rc.next())
                && (c.is_ascii_digit() || matches!(c, '¹' | '²' | '³'))
            {
                return Err("reserved device name");
            }
        }
    }
    Ok(())
}

/// Relative, confined path. Internally separated by `\`, case unchanged;
/// comparisons are case-insensitive.
#[derive(Debug, Clone)]
pub struct RelPath {
    raw: String,
    folded: String,
}

impl RelPath {
    /// Maximum length in characters (Unicode code points, like `maxLength` in JSON Schema).
    pub const MAX_LEN: usize = 240;

    /// Checks and normalizes (`/` → `\`).
    pub fn parse(s: &str) -> Result<Self, PathError> {
        let fail = |reason| {
            Err(PathError {
                path: s.to_owned(),
                reason,
            })
        };
        if s.is_empty() {
            return fail("empty");
        }
        if s.chars().count() > Self::MAX_LEN {
            return fail("too long");
        }
        let raw = s.replace('/', "\\");
        for seg in raw.split('\\') {
            if let Err(reason) = check_segment(seg) {
                return fail(reason);
            }
        }
        let folded = fold(&raw);
        Ok(Self { raw, folded })
    }

    /// The path separated by `\`, in its original case.
    pub fn as_str(&self) -> &str {
        &self.raw
    }

    /// The segments.
    pub fn segments(&self) -> impl Iterator<Item = &str> {
        self.raw.split('\\')
    }
}

impl PartialEq for RelPath {
    fn eq(&self, other: &Self) -> bool {
        self.folded == other.folded
    }
}

impl Eq for RelPath {}

impl Hash for RelPath {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.folded.hash(state);
    }
}

impl PartialOrd for RelPath {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for RelPath {
    fn cmp(&self, other: &Self) -> Ordering {
        self.folded.cmp(&other.folded)
    }
}

impl fmt::Display for RelPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.raw)
    }
}

/// Absolute game folder (comes from `detect`, i.e. from user-writable files such as
/// `libraryfolders.vdf` – hence strictly checked).
///
/// Only `<drive>:\<segment>\…` with at least one segment is allowed, each segment under
/// the same rules as in [`RelPath`]. Not allowed: `.`/`..`, UNC, `\\?\`, `\\.\`
/// (devices, `GLOBALROOT`), a bare drive root, ADS, reserved names.
///
/// Phase 2 adds canonicalization via a handle and a ban on system folders
/// (ADR 0007).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GameRoot(PathBuf);

impl GameRoot {
    /// Checks and normalizes (`/` → `\`, trailing separator removed).
    pub fn new(path: impl AsRef<Path>) -> Result<Self, PathError> {
        let path = path.as_ref();
        let shown = path.display().to_string();
        let fail = |reason| {
            Err(PathError {
                path: shown.clone(),
                reason,
            })
        };
        let Some(s) = path.to_str() else {
            return fail("not valid Unicode");
        };
        let s = s.replace('/', "\\");
        let b = s.as_bytes();
        if !(b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && b[2] == b'\\') {
            return fail("game root must start with a drive letter, e.g. C:\\");
        }
        let rest = s[3..].strip_suffix('\\').unwrap_or(&s[3..]);
        if rest.is_empty() {
            return fail("game root must not be a drive root");
        }
        if rest.chars().count() > RelPath::MAX_LEN {
            return fail("too long");
        }
        let mut normalized = PathBuf::from(format!("{}\\", s[..2].to_ascii_uppercase()));
        for seg in rest.split('\\') {
            if let Err(reason) = check_segment(seg) {
                return fail(reason);
            }
            normalized.push(seg);
        }
        Ok(Self(normalized))
    }

    /// The folder.
    pub fn path(&self) -> &Path {
        &self.0
    }

    /// Appends a checked relative path. Always stays lexically inside the game folder, because
    /// neither the root nor the segments can contain `..`, prefixes or separators.
    pub fn join(&self, rel: &RelPath) -> PathBuf {
        let mut p = self.0.clone();
        for seg in rel.segments() {
            p.push(seg);
        }
        p
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_forward_slashes() {
        assert_eq!(
            RelPath::parse("scripts/EaglePatchAC1.asi")
                .unwrap()
                .as_str(),
            r"scripts\EaglePatchAC1.asi"
        );
    }

    #[test]
    fn comparison_is_case_insensitive_and_keeps_spelling() {
        let a = RelPath::parse("D3D9.dll").unwrap();
        let b = RelPath::parse("d3d9.DLL").unwrap();
        assert_eq!(a, b);
        assert_eq!(a.as_str(), "D3D9.dll");
        let set: std::collections::HashSet<_> = [a, b].into_iter().collect();
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn join_stays_inside_root() {
        let root = GameRoot::new(r"C:\Games\AC").unwrap();
        let rel = RelPath::parse("scripts/a.asi").unwrap();
        let joined = root.join(&rel);
        assert!(joined.starts_with(root.path()));
        assert_eq!(joined, PathBuf::from(r"C:\Games\AC\scripts\a.asi"));
    }

    #[test]
    fn game_root_accepts_plain_drive_paths() {
        for ok in [
            r"C:\Games\AC",
            r"d:/SteamLibrary/steamapps/common/Far Cry 2/",
            r"E:\Spiele\Über",
        ] {
            assert!(GameRoot::new(ok).is_ok(), "{ok}");
        }
        assert_eq!(GameRoot::new(r"d:/x/").unwrap().path(), Path::new(r"D:\x"));
    }

    /// Cases from the security review (phase 0).
    #[test]
    fn game_root_rejects_escapes_devices_and_unc() {
        for bad in [
            "Games",
            r"\Games",
            r"C:Games",
            r"C:\",
            r"C:\Games\..\Windows",
            r"C:\Games\.\CON",
            r"C:\G\x.exe:s",
            r"C:\G. ",
            r"C:\G\\x",
            r"\\.\PhysicalDrive0",
            r"\\.\GLOBALROOT\Device\HarddiskVolumeShadowCopy1",
            r"\\attacker\share\g",
            r"\\?\UNC\attacker\share\g",
            r"\\?\C:\G\..\x",
            "C:\\G\\a\u{202E}gnp",
            "C:\\G\\\u{FF0E}\u{FF0E}",
        ] {
            assert!(GameRoot::new(bad).is_err(), "{bad:?} accepted");
        }
    }

    #[test]
    fn reason_is_reported() {
        let e = RelPath::parse("../x").unwrap_err();
        assert_eq!(e.reason, "'.' or '..' segment");
        assert!(e.to_string().contains("../x"));
    }
}
