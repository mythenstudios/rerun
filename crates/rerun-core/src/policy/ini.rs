//! `policy::ini`: the bounded INI editor (P2-12, ADR 0021). Pure: bytes in, bytes out; no
//! system access. INI files of a game folder are untrusted input.
//!
//! The editor never reformats: [`edit`] replaces only the value span of an existing key or
//! inserts whole lines, [`unedit`] puts exactly those bytes back, and every other byte (line
//! endings, whitespace, comments, the BOM, other sections, duplicates elsewhere) stays in its
//! order. Property I1: `unedit(edit(f)).bytes == f` for every `f` that `edit` accepts.
//!
//! **Dialect** (fail closed at Rerun's targets, tolerant elsewhere; nothing is guessed):
//! - **Encoding**: `EF BB BF` is a UTF-8 BOM, kept as a prefix; anything else without NUL is
//!   ASCII-compatible text (UTF-8 or an ANSI code page), handled byte by byte. Refused: a
//!   UTF-16 BOM (`FF FE`, `FE FF`; user decision E3 b: UTF-16 comes with phase 4), any NUL byte
//!   (BOM-less UTF-16 and UTF-32), more than [`MAX_INI_BYTES`].
//! - **Lines** end in CRLF or LF, mixed too; a CR without LF is refused. A file that ends with
//!   a line ending has no empty last line.
//! - **Kinds**, after optional spaces and tabs: blank; a comment (`;` or `#`); a header: `[`
//!   and a `]` later on the line (review S3: always a section boundary; its name is the text
//!   up to the first `]`); a key line (holds `=`: the key is the trimmed text before the
//!   first `=`, the value the trimmed rest, no inline comments, no quotes interpreted, as
//!   `GetPrivateProfileString`); anything else an "other" line. A line that starts with `[`
//!   without `]` is refused anywhere (the section boundaries are unclear).
//! - **Names** are compared ASCII case-insensitively; the file's spelling stays. Keys before
//!   the first header are allowed but never a target.
//! - **Refused at a target only**: its section twice; a header of its section that is not
//!   exactly `[Name]` (spaces inside the brackets, text after `]` other than spaces and a
//!   comment); its key twice in the section; an "other" line equal to its key; an old value
//!   that is not printable ASCII or longer than [`MAX_TEXT`] ([`IniError::Unusual`], the
//!   planner only).
//!
//! **Output of [`edit`] (frozen, review M2)**: an existing key gets the new value in its
//! trimmed value span (an empty old value: at the end of the line's content); a new key in an
//! existing section is the line `key=value` right after the header (inserted before the
//! header's line ending, with that line ending in front of it); a new section is `[Section]`
//! and its `key=value` lines after the content of the last line (no line ending in front in an
//! empty file). Inserted lines take the line ending of the line they follow, at the end of a
//! file without one the first line ending of the file, else CRLF. At one place, new keys of an
//! existing section come before new sections; edits are in their canonical order. The bytes
//! `edit` writes for an accepted input never change: a recorded head binds them (golden
//! vectors in the tests); a change needs a versioned `edit` for older heads (ADR 0021).
//!
//! **[`unedit`]** per edit by its [`KeyState`]: `New` (the value is exactly Rerun's) puts the
//! old value back into the span, or removes the line Rerun inserted (with its own line ending;
//! the last line without one takes the line ending of the line before it along); a section
//! Rerun created whose lines are all gone loses its header too. `Old` and `Changed` are left.

use serde::{Deserialize, Serialize};

/// Largest INI file Rerun reads or writes (old, new, a revert's `from` and `to`).
pub const MAX_INI_BYTES: usize = 1 << 20;
/// Most edits of one file in one op.
pub const MAX_EDITS: usize = 8;
/// Longest section or key name.
pub const MAX_NAME: usize = 64;
/// Longest value.
pub const MAX_TEXT: usize = 128;
/// The one file extension `ini_set` writes (folded; review S4: no `.cfg` yet).
pub const INI_EXTENSION: &str = "ini";

/// Why the editor refuses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum IniError {
    /// More than [`MAX_INI_BYTES`].
    #[error("the INI file is larger than 1 MiB")]
    TooLarge,
    /// A UTF-16 BOM (UTF-16 is not supported yet).
    #[error("the INI file is UTF-16 text, which Rerun does not edit yet")]
    Utf16,
    /// A NUL byte (UTF-16 or UTF-32 without BOM, or binary).
    #[error("the INI file holds a NUL byte (UTF-16, UTF-32 or binary)")]
    Nul,
    /// A carriage return without a line feed.
    #[error("the INI file holds a carriage return without a line feed")]
    LoneCr,
    /// A line that starts with `[` and has no `]`.
    #[error("the INI file has a line starting with [ without ]: its sections are unclear")]
    Unclear,
    /// The section or key of edit `edit` is not unique or not in its exact form.
    #[error("value {edit}: its section or key is ambiguous in the INI file")]
    Ambiguous {
        /// Edit index.
        edit: u8,
    },
    /// The current value of edit `edit` is not printable ASCII of at most 128 characters.
    #[error(
        "value {edit}: an unusual value (not printable ASCII or longer than 128 characters); Rerun leaves it alone"
    )]
    Unusual {
        /// Edit index.
        edit: u8,
    },
    /// The file does not hold the old state of edit `edit`.
    #[error("value {edit}: the INI file does not hold the planned old value")]
    NotOld {
        /// Edit index.
        edit: u8,
    },
    /// A new section in a file without any header (review S4: maybe no INI at all).
    #[error("a new section in a file without any section header")]
    NoHeader,
    /// The edits break a rule of their form.
    #[error("{0}")]
    Edits(&'static str),
    /// Not a section or key name.
    #[error(
        "not a section or key name (A-Z a-z 0-9 _ . - and space, 1 to 64, no space at either end)"
    )]
    Name,
    /// Not a value.
    #[error("not a value (printable ASCII, at most 128 characters, no space at either end)")]
    Text,
    /// A new value breaks a rule in force now.
    #[error("{0}")]
    Rule(&'static str),
}

/// `[A-Za-z0-9_. -]`.
fn name_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, b'_' | b'.' | b'-' | b' ')
}

/// A section or key name: `[A-Za-z0-9_. -]{1,64}`, no space at either end. Serde only
/// through [`Self::parse`].
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct IniName(String);

impl IniName {
    /// Parses the form.
    pub fn parse(s: &str) -> Result<Self, IniError> {
        let b = s.as_bytes();
        let ok = (1..=MAX_NAME).contains(&b.len())
            && b.iter().all(|c| name_char(*c))
            && b.first() != Some(&b' ')
            && b.last() != Some(&b' ');
        if ok {
            Ok(Self(s.to_owned()))
        } else {
            Err(IniError::Name)
        }
    }

    /// The name.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Folded (ASCII upper case), for comparisons and the canonical order.
    pub fn folded(&self) -> String {
        self.0.to_ascii_uppercase()
    }

    /// `b` is this name, ASCII case-insensitively.
    fn matches(&self, b: &[u8]) -> bool {
        self.0.as_bytes().eq_ignore_ascii_case(b)
    }
}

impl TryFrom<String> for IniName {
    type Error = IniError;
    fn try_from(s: String) -> Result<Self, IniError> {
        Self::parse(&s)
    }
}

impl From<IniName> for String {
    fn from(n: IniName) -> Self {
        n.0
    }
}

impl std::fmt::Display for IniName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A value: printable ASCII (`0x20` to `0x7E`), 0 to 128 characters, no space at either end.
/// Serde only through [`Self::parse`] (the form; [`Self::check_new`] is a rule in force now).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct IniText(String);

/// Characters a new value never holds (rules in force now): path and environment
/// characters, and comment characters a game may strip.
const NEW_FORBIDDEN: &[u8] = b"\\/:%;#";

impl IniText {
    /// Parses the form.
    pub fn parse(s: &str) -> Result<Self, IniError> {
        let b = s.as_bytes();
        let ok = b.len() <= MAX_TEXT
            && b.iter().all(|c| (0x20..=0x7e).contains(c))
            && b.first() != Some(&b' ')
            && b.last() != Some(&b' ');
        if ok {
            Ok(Self(s.to_owned()))
        } else {
            Err(IniError::Text)
        }
    }

    /// The value.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The rule for a value Rerun writes now (planning and apply, never a revert): none of
    /// `\ / : % ; #` and no `..` (no paths, no environment references, nothing a game may
    /// read as a comment). Syntactic only; what a value means is curation (`docs/06`).
    pub fn check_new(&self) -> Result<(), IniError> {
        if self.0.bytes().any(|c| NEW_FORBIDDEN.contains(&c)) || knob::forbidden(&self.0) {
            return Err(IniError::Rule(
                "a new INI value holds one of \\ / : % ; # (no paths, environment references or comments)",
            ));
        }
        if self.0.contains("..") {
            return Err(IniError::Rule("a new INI value holds .."));
        }
        Ok(())
    }
}

impl TryFrom<String> for IniText {
    type Error = IniError;
    fn try_from(s: String) -> Result<Self, IniError> {
        Self::parse(&s)
    }
}

impl From<IniText> for String {
    fn from(t: IniText) -> Self {
        t.0
    }
}

/// The old state of one key as planned (review nit: an enum, not an option and a flag).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Old {
    /// The key had this value.
    Value(IniText),
    /// The section existed, the key did not.
    NoKey,
    /// The section did not exist.
    NoSection,
}

/// One key Rerun sets in an INI file. On the wire `{"section":"Display","key":"Width",
/// "old":{"value":"1280"},"new":"1920"}` (`"old":"no_key"`, `"old":"no_section"`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IniEdit {
    /// The section.
    pub section: IniName,
    /// The key.
    pub key: IniName,
    /// Its old state.
    pub old: Old,
    /// The new value (not empty: an empty value has no span to find again).
    pub new: IniText,
}

impl IniEdit {
    /// The canonical order: folded section, then folded key, byte by byte.
    fn order(&self) -> (String, String) {
        (self.section.folded(), self.key.folded())
    }
}

/// The form rules of an edit list (both rule sets, `edit` and `unedit`): 1 to [`MAX_EDITS`],
/// in canonical order without a folded duplicate; a section spelled one way only, with all
/// its edits `NoSection` or none; every new value not empty and other than its old one.
pub fn check_edits(edits: &[IniEdit]) -> Result<(), IniError> {
    if edits.is_empty() || edits.len() > MAX_EDITS {
        return Err(IniError::Edits("1 to 8 INI values per file"));
    }
    if edits.windows(2).any(|w| w[0].order() >= w[1].order()) {
        return Err(IniError::Edits(
            "INI values unique and in order of section and key",
        ));
    }
    for (i, e) in edits.iter().enumerate() {
        if e.new.as_str().is_empty() {
            return Err(IniError::Edits("an empty new INI value"));
        }
        if e.old == Old::Value(e.new.clone()) {
            return Err(IniError::Edits("an INI value set to the value it has"));
        }
        for o in &edits[..i] {
            if o.section.folded() == e.section.folded()
                && (o.section != e.section
                    || (o.old == Old::NoSection) != (e.old == Old::NoSection))
            {
                return Err(IniError::Edits(
                    "a section spelled two ways, or both new and existing",
                ));
            }
        }
    }
    Ok(())
}

/// The encoding of a file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    /// ASCII-compatible text without BOM (UTF-8 or ANSI), byte by byte.
    Plain,
    /// The same with a UTF-8 BOM, kept as a prefix.
    Utf8Bom,
}

const BOM: &[u8] = b"\xEF\xBB\xBF";

/// The kind of a line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Blank,
    Comment,
    /// `name` the raw text between `[` and the first `]`; `exact`: no space at its ends and
    /// nothing after `]` but spaces and a comment.
    Header {
        name: (usize, usize),
        exact: bool,
    },
    /// The trimmed key and the trimmed value span (an empty value: the end of the content).
    Key {
        key: (usize, usize),
        value: (usize, usize),
    },
    /// The trimmed text.
    Other {
        text: (usize, usize),
    },
}

/// One line: its content `[start, content_end)` and line ending `[content_end, end)`.
#[derive(Debug, Clone, Copy)]
struct Line {
    start: usize,
    content_end: usize,
    end: usize,
    kind: Kind,
}

fn is_space(c: u8) -> bool {
    c == b' ' || c == b'\t'
}

/// `[s, e)` without spaces and tabs at either end.
fn trim(b: &[u8], mut s: usize, mut e: usize) -> (usize, usize) {
    while s < e && is_space(b[s]) {
        s += 1;
    }
    while e > s && is_space(b[e - 1]) {
        e -= 1;
    }
    (s, e)
}

/// A scanned INI file (module docs).
#[derive(Debug, Clone)]
pub struct Doc<'a> {
    bytes: &'a [u8],
    encoding: Encoding,
    lines: Vec<Line>,
}

/// What a file holds for one section and key (the planner).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Found<'a> {
    /// No section of that name.
    NoSection,
    /// The section, without the key.
    NoKey,
    /// The key with this value (printable ASCII, at most 128 characters).
    Value(&'a str),
}

/// Where one section and key are.
#[derive(Debug, Clone, Copy)]
enum Loc {
    NoSection,
    /// The header line and the lines of the section `[from, to)`; the key line.
    Section {
        header: usize,
        from: usize,
        to: usize,
        key: Option<usize>,
    },
}

/// Scans `b` (module docs): the encoding and every line, or why the file is refused.
pub fn scan(b: &[u8]) -> Result<Doc<'_>, IniError> {
    if b.len() > MAX_INI_BYTES {
        return Err(IniError::TooLarge);
    }
    if b.starts_with(b"\xFF\xFE") || b.starts_with(b"\xFE\xFF") {
        return Err(IniError::Utf16);
    }
    if b.contains(&0) {
        return Err(IniError::Nul);
    }
    let (encoding, body) = if b.starts_with(BOM) {
        (Encoding::Utf8Bom, BOM.len())
    } else {
        (Encoding::Plain, 0)
    };
    let mut lines = Vec::new();
    let mut start = body;
    let mut i = body;
    while i < b.len() {
        match b[i] {
            b'\r' if b.get(i + 1) != Some(&b'\n') => return Err(IniError::LoneCr),
            b'\n' => {
                let content_end = if i > start && b[i - 1] == b'\r' {
                    i - 1
                } else {
                    i
                };
                lines.push(line(b, start, content_end, i + 1)?);
                start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    if start < b.len() {
        lines.push(line(b, start, b.len(), b.len())?);
    }
    Ok(Doc {
        bytes: b,
        encoding,
        lines,
    })
}

/// Classifies one line.
fn line(b: &[u8], start: usize, content_end: usize, end: usize) -> Result<Line, IniError> {
    let (s, e) = trim(b, start, content_end);
    let kind = match b.get(s) {
        _ if s == e => Kind::Blank,
        Some(b';' | b'#') => Kind::Comment,
        Some(b'[') => {
            let Some(close) = b[s..e].iter().position(|c| *c == b']').map(|p| s + p) else {
                return Err(IniError::Unclear);
            };
            let name = (s + 1, close);
            let (ns, ne) = trim(b, name.0, name.1);
            let (rs, re) = trim(b, close + 1, e);
            let rest_ok = rs == re || matches!(b[rs], b';' | b'#');
            Kind::Header {
                name,
                exact: (ns, ne) == name && rest_ok,
            }
        }
        _ => match b[s..e].iter().position(|c| *c == b'=').map(|p| s + p) {
            Some(eq) => {
                let key = trim(b, s, eq);
                let value = trim(b, eq + 1, e);
                // An empty value: its span is the end of the content (module docs).
                let value = if value.0 == value.1 {
                    (content_end, content_end)
                } else {
                    value
                };
                Kind::Key { key, value }
            }
            None => Kind::Other { text: (s, e) },
        },
    };
    Ok(Line {
        start,
        content_end,
        end,
        kind,
    })
}

impl<'a> Doc<'a> {
    /// The encoding.
    pub fn encoding(&self) -> Encoding {
        self.encoding
    }

    /// The file has at least one header.
    pub fn has_header(&self) -> bool {
        self.lines
            .iter()
            .any(|l| matches!(l.kind, Kind::Header { .. }))
    }

    fn at(&self, (s, e): (usize, usize)) -> &'a [u8] {
        &self.bytes[s..e]
    }

    /// The first line ending of the file, else CRLF.
    fn first_eol(&self) -> &'a [u8] {
        self.lines
            .iter()
            .find(|l| l.end > l.content_end)
            .map_or(b"\r\n", |l| &self.bytes[l.content_end..l.end])
    }

    /// The line ending inserted lines after line `i` take (module docs).
    fn eol_after(&self, i: usize) -> &'a [u8] {
        match self.lines.get(i) {
            Some(l) if l.end > l.content_end => &self.bytes[l.content_end..l.end],
            _ => self.first_eol(),
        }
    }

    /// Where `section` and `key` are; `Ambiguous` by the rules at a target (module docs).
    fn locate(&self, edit: u8, section: &IniName, key: &IniName) -> Result<Loc, IniError> {
        let amb = IniError::Ambiguous { edit };
        let mut found: Option<usize> = None;
        for (i, l) in self.lines.iter().enumerate() {
            if let Kind::Header { name, exact } = l.kind
                && section.matches(self.at(trim(self.bytes, name.0, name.1)))
            {
                if found.is_some() || !exact {
                    return Err(amb);
                }
                found = Some(i);
            }
        }
        let Some(header) = found else {
            return Ok(Loc::NoSection);
        };
        let from = header + 1;
        let to = self.lines[from..]
            .iter()
            .position(|l| matches!(l.kind, Kind::Header { .. }))
            .map_or(self.lines.len(), |p| from + p);
        let mut at = None;
        for (i, l) in self.lines[from..to].iter().enumerate() {
            match l.kind {
                Kind::Key { key: k, .. } if key.matches(self.at(k)) => {
                    if at.is_some() {
                        return Err(amb);
                    }
                    at = Some(from + i);
                }
                Kind::Other { text } if key.matches(self.at(text)) => return Err(amb),
                _ => {}
            }
        }
        Ok(Loc::Section {
            header,
            from,
            to,
            key: at,
        })
    }

    /// The value span of key line `i`.
    fn value(&self, i: usize) -> (usize, usize) {
        match self.lines[i].kind {
            Kind::Key { value, .. } => value,
            _ => (self.lines[i].content_end, self.lines[i].content_end),
        }
    }

    /// What the file holds for `section` and `key` (the planner): `Ambiguous` or `Unusual`
    /// (as edit `edit`) by the rules at a target.
    pub fn get(&self, edit: u8, section: &IniName, key: &IniName) -> Result<Found<'a>, IniError> {
        match self.locate(edit, section, key)? {
            Loc::NoSection => Ok(Found::NoSection),
            Loc::Section { key: None, .. } => Ok(Found::NoKey),
            Loc::Section { key: Some(i), .. } => {
                let v = self.at(self.value(i));
                let usual = v.len() <= MAX_TEXT && v.iter().all(|c| (0x20..=0x7e).contains(c));
                match std::str::from_utf8(v) {
                    Ok(s) if usual => Ok(Found::Value(s)),
                    _ => Err(IniError::Unusual { edit }),
                }
            }
        }
    }
}

/// Edit index as `u8` (at most [`MAX_EDITS`]).
fn ix(i: usize) -> u8 {
    u8::try_from(i).unwrap_or(u8::MAX)
}

/// The bytes of `doc` with `inserts` after the content of a line, `replace` of a value span
/// and lines `removed`.
struct Rebuild<'d, 'a> {
    doc: &'d Doc<'a>,
    inserts: Vec<(usize, Vec<u8>)>,
    replace: Vec<(usize, Vec<u8>)>,
    removed: Vec<bool>,
}

impl<'d, 'a> Rebuild<'d, 'a> {
    fn new(doc: &'d Doc<'a>) -> Self {
        Self {
            doc,
            inserts: Vec::new(),
            replace: Vec::new(),
            removed: vec![false; doc.lines.len()],
        }
    }

    fn bytes(&self) -> Vec<u8> {
        let d = self.doc;
        let b = d.bytes;
        let mut out = Vec::with_capacity(b.len() + 256);
        if d.encoding == Encoding::Utf8Bom {
            out.extend_from_slice(BOM);
        }
        let mut last_kept_eol: Option<usize> = None;
        for (i, l) in d.lines.iter().enumerate() {
            if self.removed[i] {
                continue;
            }
            match self.replace.iter().find(|(j, _)| *j == i) {
                Some((_, v)) => {
                    let (s, e) = d.value(i);
                    out.extend_from_slice(&b[l.start..s]);
                    out.extend_from_slice(v);
                    out.extend_from_slice(&b[e..l.content_end]);
                }
                None => out.extend_from_slice(&b[l.start..l.content_end]),
            }
            for (_, ins) in self.inserts.iter().filter(|(j, _)| *j == i) {
                out.extend_from_slice(ins);
            }
            let eol = &b[l.content_end..l.end];
            last_kept_eol = Some(out.len());
            out.extend_from_slice(eol);
            if knob::normalising_eol() && eol == b"\r\n" {
                out.truncate(out.len() - 2);
                out.push(b'\n');
            }
        }
        // The last line removed and without a line ending: the line before it gives its
        // line ending up (module docs).
        let last_removed = d
            .lines
            .len()
            .checked_sub(1)
            .is_some_and(|i| self.removed[i]);
        let last_open = d.lines.last().is_some_and(|l| l.end == l.content_end);
        if last_removed
            && last_open
            && let Some(at) = last_kept_eol
        {
            out.truncate(at);
        }
        out
    }
}

/// Edits `old` (module docs): every edit's old state must be exactly what the file holds
/// (`NotOld`), its section and key unambiguous. The output for an accepted input is frozen
/// (review M2).
pub fn edit(old: &[u8], edits: &[IniEdit]) -> Result<Vec<u8>, IniError> {
    check_edits(edits)?;
    let doc = scan(old)?;
    let mut r = Rebuild::new(&doc);
    // New sections, grouped (the edits are in canonical order).
    let mut sections: Vec<(&IniName, Vec<&IniEdit>)> = Vec::new();
    for (i, e) in edits.iter().enumerate() {
        let loc = doc.locate(ix(i), &e.section, &e.key)?;
        let not_old = IniError::NotOld { edit: ix(i) };
        match (&e.old, loc) {
            (Old::Value(v), Loc::Section { key: Some(l), .. })
                if doc.at(doc.value(l)) == v.as_str().as_bytes() =>
            {
                r.replace.push((l, e.new.as_str().as_bytes().to_vec()));
            }
            (
                Old::NoKey,
                Loc::Section {
                    header, key: None, ..
                },
            ) => {
                let mut ins = doc.eol_after(header).to_vec();
                ins.extend_from_slice(format!("{}={}", e.key, e.new.as_str()).as_bytes());
                r.inserts.push((header, ins));
            }
            (Old::NoSection, Loc::NoSection) => match sections.last_mut() {
                Some((s, v)) if s.folded() == e.section.folded() => v.push(e),
                _ => sections.push((&e.section, vec![e])),
            },
            _ => return Err(not_old),
        }
    }
    if sections.is_empty() {
        return Ok(r.bytes());
    }
    if !doc.has_header() {
        return Err(IniError::NoHeader);
    }
    let last = doc.lines.len() - 1;
    let eol = doc.eol_after(last);
    let mut ins = Vec::new();
    for (s, es) in sections {
        ins.extend_from_slice(eol);
        ins.extend_from_slice(format!("[{s}]").as_bytes());
        for e in es {
            ins.extend_from_slice(eol);
            ins.extend_from_slice(format!("{}={}", e.key, e.new.as_str()).as_bytes());
        }
    }
    // After the new keys of an existing section ending at the same line.
    r.inserts.push((last, ins));
    Ok(r.bytes())
}

/// The state of one of Rerun's keys in a file (`unedit`, `verify`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyState {
    /// The value is exactly Rerun's: a revert puts the old state back.
    New,
    /// The value is the old one (or the key is missing, as it was).
    Old,
    /// Someone set another value or removed a key that had one: it stays (user decision E1 b).
    Changed,
}

/// What [`unedit`] makes of a file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unedit {
    /// The file with every `New` key put back (the input if there is none).
    pub bytes: Vec<u8>,
    /// The state of each edit, in order.
    pub keys: Vec<KeyState>,
}

impl Unedit {
    /// Some key is `New`: the revert writes [`Self::bytes`].
    pub fn writes(&self) -> bool {
        self.keys.contains(&KeyState::New)
    }
}

/// Puts the old state of every key that still holds Rerun's value back into `cur` (module
/// docs); refuses what [`scan`] refuses and an ambiguous target.
pub fn unedit(cur: &[u8], edits: &[IniEdit]) -> Result<Unedit, IniError> {
    check_edits(edits)?;
    let doc = scan(cur)?;
    let mut r = Rebuild::new(&doc);
    let mut keys = Vec::with_capacity(edits.len());
    let mut created: Vec<(usize, usize, usize)> = Vec::new();
    for (i, e) in edits.iter().enumerate() {
        let loc = doc.locate(ix(i), &e.section, &e.key)?;
        let (state, line) = match loc {
            Loc::Section { key: Some(l), .. } => {
                let v = doc.at(doc.value(l));
                if v == e.new.as_str().as_bytes() {
                    (KeyState::New, Some(l))
                } else if matches!(&e.old, Old::Value(o) if o.as_str().as_bytes() == v) {
                    (KeyState::Old, None)
                } else {
                    (KeyState::Changed, None)
                }
            }
            Loc::Section { key: None, .. } | Loc::NoSection => match e.old {
                Old::Value(_) => (KeyState::Changed, None),
                Old::NoKey | Old::NoSection => (KeyState::Old, None),
            },
        };
        if let Some(l) = line {
            match &e.old {
                Old::Value(o) => r.replace.push((l, o.as_str().as_bytes().to_vec())),
                Old::NoKey | Old::NoSection => r.removed[l] = true,
            }
        }
        if e.old == Old::NoSection
            && let Loc::Section {
                header, from, to, ..
            } = loc
            && !created.contains(&(header, from, to))
        {
            created.push((header, from, to));
        }
        keys.push(state);
    }
    // A section Rerun created loses its header once the revert removes all its lines (one
    // someone else left empty keeps it).
    for (header, from, to) in created {
        if to > from && r.removed[from..to].iter().all(|x| *x) {
            r.removed[header] = true;
        }
    }
    let bytes = if keys.contains(&KeyState::New) {
        r.bytes()
    } else {
        cur.to_vec()
    };
    Ok(Unedit { bytes, keys })
}

/// `p` is a file `ini_set` may edit: the extension `.ini` (folded), not `desktop.ini`
/// (Explorer's folder settings; review S4).
pub fn path_ok(p: &crate::path::RelPath) -> bool {
    let name = p.file_name().to_ascii_lowercase();
    name != "desktop.ini"
        && name
            .rsplit_once('.')
            .is_some_and(|(stem, ext)| !stem.is_empty() && ext == INI_EXTENSION)
}

#[cfg(test)]
pub(crate) mod knob {
    //! Test knobs of this thread: R-I8 (a character forbidden in new values since the apply)
    //! and the control K-I2 (`unedit` normalising line endings).

    use std::cell::Cell;

    thread_local! {
        static FORBID: Cell<Option<char>> = const { Cell::new(None) };
        static NORMALISE_EOL: Cell<bool> = const { Cell::new(false) };
    }

    /// R-I8: from now on a new value holding `c` breaks the rule.
    pub(crate) fn forbid(c: Option<char>) {
        FORBID.with(|f| f.set(c));
    }
    pub(super) fn forbidden(s: &str) -> bool {
        FORBID.with(|f| f.get().is_some_and(|c| s.contains(c)))
    }
    /// K-I2: the rebuild writes LF for every CRLF.
    pub(crate) fn normalise_eol(on: bool) {
        NORMALISE_EOL.with(|f| f.set(on));
    }
    pub(super) fn normalising_eol() -> bool {
        NORMALISE_EOL.with(Cell::get)
    }
}

#[cfg(not(test))]
mod knob {
    pub(super) fn forbidden(_: &str) -> bool {
        false
    }
    pub(super) fn normalising_eol() -> bool {
        false
    }
}

#[cfg(test)]
mod tests;
