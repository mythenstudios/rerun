//! Paths: [`RelPath`] (relative, confined to a root) and [`RootPath`] (absolute root).
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
//! Files inside a root are only reached through a handle opened by `policy::root`
//! (ADR 0007).

use std::cmp::Ordering;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};

use crate::fold::fold;

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

/// A raw directory entry name that is not a valid [`RelPath`] segment (ADR 0007).
///
/// Anomalies are reported and never touched: `d3d9.dll.`, `CON`, `x `, `PROGRA~1`,
/// names with invalid UTF-16 (shown with U+FFFD) and entries of case-sensitive directories.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("anomalous name {name:?}: {reason}")]
pub struct Anomaly {
    /// The raw name as listed by `read_dir`.
    pub name: String,
    /// Reason.
    pub reason: &'static str,
}

/// Classifies one raw name from `read_dir`: a valid single segment or an [`Anomaly`].
/// `case_sensitive` is `RootInfo::case_sensitive` of the listed directory: every entry of a
/// case-sensitive directory is an anomaly (two names may fold to the same segment).
///
/// Stricter than [`RelPath::from_segment`] in one point: U+FFFD (the replacement for invalid
/// UTF-16) is an anomaly, because such a name cannot be turned back into the name on disk.
pub fn classify(name: &str, case_sensitive: bool) -> Result<RelPath, Anomaly> {
    if case_sensitive {
        return Err(Anomaly {
            name: name.to_owned(),
            reason: "entry of a case-sensitive directory",
        });
    }
    if name.contains('\u{FFFD}') {
        return Err(Anomaly {
            name: name.to_owned(),
            reason: "invalid UTF-16 (replacement character)",
        });
    }
    RelPath::from_segment(name).map_err(|e| Anomaly {
        name: name.to_owned(),
        reason: e.reason,
    })
}

/// Relative, confined path. Internally separated by `\`, case unchanged;
/// comparisons are case-insensitive: `==`, `Hash` and the order use the folded form, so two
/// spellings of one name are equal. Where the spelling itself matters (a name on disk against
/// the one in a plan, ADR 0020 "Name spelling") compare with [`Self::same_spelling`].
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

    /// The same path in exactly the same spelling (case included), unlike `==`, which folds.
    pub fn same_spelling(&self, other: &Self) -> bool {
        self.raw == other.raw
    }

    /// A path of exactly one segment (e.g. Steam's `installdir` or a name from `read_dir`).
    /// Separators are rejected.
    pub fn from_segment(seg: &str) -> Result<Self, PathError> {
        if seg.contains(['\\', '/']) {
            return Err(PathError {
                path: seg.to_owned(),
                reason: "must be a single path segment",
            });
        }
        Self::parse(seg)
    }

    /// This path with one more segment appended.
    pub fn child(&self, seg: &str) -> Result<Self, PathError> {
        let child = Self::from_segment(seg)?;
        Self::parse(&format!("{}\\{}", self.raw, child.raw))
    }

    /// The segments.
    pub fn segments(&self) -> impl Iterator<Item = &str> {
        self.raw.split('\\')
    }

    /// The last segment.
    pub fn file_name(&self) -> &str {
        self.raw.rsplit('\\').next().unwrap_or(&self.raw)
    }

    /// The parent path; `None` for a single segment.
    pub fn parent(&self) -> Option<Self> {
        let (parent, _) = self.raw.rsplit_once('\\')?;
        Some(Self {
            raw: parent.to_owned(),
            folded: fold(parent),
        })
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

/// Absolute root folder (game folder, Steam folder, Rerun's own folder). Game roots come from
/// `detect`, i.e. from user-writable files such as `libraryfolders.vdf`, hence the strict
/// lexical check.
///
/// Only `<drive>:\<segment>\…` with at least one segment is allowed, each segment under
/// the same rules as in [`RelPath`]. Not allowed: `.`/`..`, UNC, `\\?\`, `\\.\`
/// (devices, `GLOBALROOT`), a bare drive root, ADS, reserved names.
///
/// A `RootPath` is only a name. Files inside a root are reached exclusively through a
/// handle opened by `policy::root` (ADR 0007); there is deliberately no `join`.
/// Comparisons are case-insensitive like NTFS.
#[derive(Debug, Clone)]
pub struct RootPath {
    path: PathBuf,
    folded: String,
}

impl RootPath {
    /// Checks and normalizes (`/` → `\`, drive letter uppercase, trailing separator removed).
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
        let folded = fold(&normalized.display().to_string());
        Ok(Self {
            path: normalized,
            folded,
        })
    }

    /// From the result of `GetFinalPathNameByHandleW` (`\\?\X:\…`). Network paths
    /// (`\\?\UNC\…`) and volumes without a drive letter (`\\?\Volume{…}`) are rejected (v1).
    pub fn from_final_path(path: impl AsRef<Path>) -> Result<Self, PathError> {
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
        let rest = s.strip_prefix(r"\\?\").unwrap_or(s);
        // `get`, never a byte slice: the text after the prefix may start with a character that
        // is longer than one byte (a folder named `ü…` at a drive root).
        let starts = |p: &str| {
            rest.get(..p.len())
                .is_some_and(|h| h.eq_ignore_ascii_case(p))
        };
        if starts(r"UNC\") {
            return fail("network paths are not supported");
        }
        if starts("Volume{") {
            return fail("volume without a drive letter is not supported");
        }
        Self::new(rest)
    }

    /// The folder.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The folder one segment below, as a name (`policy::root` derives forbidden folders
    /// with it). Never used to reach a file: there is deliberately no `join`.
    pub(crate) fn child(&self, seg: &str) -> Result<Self, PathError> {
        // `Path::join` would split `a\b` and let an absolute segment replace the path.
        if seg.contains(['\\', '/']) {
            return Err(PathError {
                path: seg.to_owned(),
                reason: "more than one segment",
            });
        }
        check_segment(seg).map_err(|reason| PathError {
            path: seg.to_owned(),
            reason,
        })?;
        Self::new(self.path.join(seg))
    }

    /// The first segment below the drive (`Games` for `D:\Games\X`).
    pub(crate) fn first_segment(&self) -> &str {
        let s = self.path.to_str().unwrap_or_default();
        s.get(3..)
            .and_then(|rest| rest.split('\\').next())
            .unwrap_or_default()
    }

    /// `true` if `other` is this folder or lies inside it (segment-wise, case-insensitive).
    pub fn contains(&self, other: &RootPath) -> bool {
        other.folded == self.folded
            || other
                .folded
                .strip_prefix(&self.folded)
                .is_some_and(|rest| rest.starts_with('\\'))
    }
}

impl PartialEq for RootPath {
    fn eq(&self, other: &Self) -> bool {
        self.folded == other.folded
    }
}

impl Eq for RootPath {}

impl fmt::Display for RootPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.path.display())
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
    fn segments_children_and_parents() {
        let rel = RelPath::parse("scripts/a.asi").unwrap();
        assert_eq!(rel.file_name(), "a.asi");
        assert_eq!(rel.parent().unwrap().as_str(), "scripts");
        assert!(RelPath::parse("a").unwrap().parent().is_none());
        let child = RelPath::parse("scripts").unwrap().child("b.ini").unwrap();
        assert_eq!(child.as_str(), r"scripts\b.ini");
        for bad in [r"..\x", "a/b", "", "CON", ".."] {
            assert!(RelPath::from_segment(bad).is_err(), "{bad:?}");
            assert!(
                RelPath::parse("scripts").unwrap().child(bad).is_err(),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn root_contains_is_segment_wise_and_case_insensitive() {
        let pf = RootPath::new(r"C:\Program Files").unwrap();
        assert!(pf.contains(&RootPath::new(r"c:\program files\Steam").unwrap()));
        assert!(pf.contains(&RootPath::new(r"C:\PROGRAM FILES").unwrap()));
        assert!(!pf.contains(&RootPath::new(r"C:\Program Files (x86)\Steam").unwrap()));
        assert!(!pf.contains(&RootPath::new(r"C:\Program").unwrap()));
        assert_eq!(pf, RootPath::new(r"c:/program files/").unwrap());
    }

    #[test]
    fn root_from_final_path() {
        let r = RootPath::from_final_path(r"\\?\D:\SteamLibrary\steamapps\common\Game").unwrap();
        assert_eq!(
            r.path(),
            Path::new(r"D:\SteamLibrary\steamapps\common\Game")
        );
        assert!(RootPath::from_final_path(r"\\?\UNC\server\share\g").is_err());
        assert!(RootPath::from_final_path(r"\\?\Volume{1234}\g").is_err());
        assert!(RootPath::from_final_path(r"\\?\C:\").is_err());
        // A first segment that starts with a multi-byte character (P4-5b: this panicked on a
        // byte slice), and short texts after the prefix.
        for ok in [
            "\\\\?\\D:\\\u{fc}ber",
            "\\\\?\\D:\\\u{1D400}x",
            "D:\\\u{1D400}",
        ] {
            assert!(RootPath::from_final_path(ok).is_ok(), "{ok}");
        }
        assert!(RootPath::from_final_path("\\\\?\\\u{fc}").is_err());
        assert!(RootPath::from_final_path(r"\\?\U").is_err());
    }

    #[test]
    fn game_root_accepts_plain_drive_paths() {
        for ok in [
            r"C:\Games\AC",
            r"d:/SteamLibrary/steamapps/common/Far Cry 2/",
            r"E:\Spiele\Über",
        ] {
            assert!(RootPath::new(ok).is_ok(), "{ok}");
        }
        assert_eq!(RootPath::new(r"d:/x/").unwrap().path(), Path::new(r"D:\x"));
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
            assert!(RootPath::new(bad).is_err(), "{bad:?} accepted");
        }
    }

    #[test]
    fn classify_separates_segments_from_anomalies() {
        assert_eq!(classify("D3D9.dll", false).unwrap().as_str(), "D3D9.dll");
        assert!(classify("D3D9.dll", true).is_err());
        for bad in [
            "d3d9.dll.",
            "CON",
            "nul.txt",
            "x ",
            " x",
            "PROGRA~1",
            "a\u{FFFD}b",
            r"a\b",
            "a/b",
            "",
            "..",
            "a\u{202E}b",
        ] {
            let a = classify(bad, false).unwrap_err();
            assert_eq!(a.name, bad);
            assert!(!a.reason.is_empty());
        }
    }

    #[test]
    fn reason_is_reported() {
        let e = RelPath::parse("../x").unwrap_err();
        assert_eq!(e.reason, "'.' or '..' segment");
        assert!(e.to_string().contains("../x"));
    }
}
