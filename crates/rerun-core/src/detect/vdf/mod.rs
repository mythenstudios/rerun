//! Bounded parser for Valve KeyValues text files ("VDF"), ADR 0011.
//!
//! Steam's `libraryfolders.vdf` and `appmanifest_*.acf` live in folders every process of the
//! user can write, so their content is untrusted. [`parse`] accepts only the quoted subset
//! Steam writes:
//!
//! ```text
//! document = BOM? ws* (pair ws*)* EOF
//! pair     = string ws* (string | object)
//! object   = "{" ws* (pair ws*)* "}"
//! string   = '"' (char | escape)* '"'
//! char     = any character except '"', '\', CR, LF
//! escape   = '\' ( '"' | '\' | 'n' | 't' )
//! ws       = ' ' | '\t' | '\r' | '\n' | comment
//! comment  = "//" (any character except LF)*
//! ```
//!
//! - UTF-8 only; one leading UTF-8 BOM is skipped. A UTF-16 BOM, invalid UTF-8 and NUL bytes
//!   are errors. Checks run in the order size, UTF-16 BOM, UTF-8, NUL, grammar; the first
//!   failure is reported.
//! - Unquoted tokens, `#include`/`#base` (never followed), conditionals (`[`), unknown escapes
//!   and raw line breaks inside strings are errors with their own [`VdfErrorKind`].
//! - [`Limits`] bound the input size, the nesting depth, the number of pairs and the decoded
//!   length of every string. The parser is a single pass with an explicit stack and never
//!   recurses; the depth is additionally capped at [`HARD_MAX_DEPTH`].
//! - Keys keep their spelling, duplicates and order are preserved; lookups compare keys ASCII
//!   case-insensitively ([`Object::get_all`], [`Object::get_unique`]).
//! - Errors carry a byte offset and never file content (at most one character as `U+XXXX`).
//!
//! [`read_store_file`] is the only way to read such a file from disk: handle-relative to a
//! store root, with `Dir::read_limited` (more than `max_bytes` is refused, never truncated).

pub mod read;

use std::fmt;

pub use read::{VdfReadError, read_store_file};

/// UTF-8 byte order mark, skipped once at the start.
const UTF8_BOM: &[u8] = b"\xEF\xBB\xBF";

/// Depth cap applied whatever [`Limits::max_depth`] says: the derived `Drop`, `Clone`,
/// `PartialEq` and `Debug` of [`Object`] recurse, so the tree must stay shallow.
pub const HARD_MAX_DEPTH: usize = 64;

/// Bounds for one parse. A value of exactly the limit is accepted, one more is an error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Limits {
    /// Input size in bytes, a leading BOM included.
    pub max_bytes: usize,
    /// Number of objects open at the same time (capped at [`HARD_MAX_DEPTH`]).
    pub max_depth: usize,
    /// Number of pairs in the whole document, nested ones included.
    pub max_entries: usize,
    /// Decoded length of every key and value string, in bytes.
    pub max_string: usize,
}

impl Limits {
    /// `libraryfolders.vdf`: 4 MiB, depth 16, 200,000 pairs, 8 KiB strings.
    pub const LIBRARY_FOLDERS: Self = Self {
        max_bytes: 4 << 20,
        max_depth: 16,
        max_entries: 200_000,
        max_string: 8 << 10,
    };

    /// `appmanifest_<appid>.acf`: 1 MiB, depth 16, 20,000 pairs, 8 KiB strings.
    pub const APP_MANIFEST: Self = Self {
        max_bytes: 1 << 20,
        max_depth: 16,
        max_entries: 20_000,
        max_string: 8 << 10,
    };

    /// Depth limit that is applied: [`Self::max_depth`], at most [`HARD_MAX_DEPTH`].
    pub fn effective_depth(&self) -> usize {
        self.max_depth.min(HARD_MAX_DEPTH)
    }
}

/// A parsed document: the top-level pairs.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Document {
    root: Object,
}

impl Document {
    /// The top-level pairs.
    pub fn root(&self) -> &Object {
        &self.root
    }
}

/// An object: pairs in file order, duplicates kept.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Object {
    entries: Vec<Entry>,
}

impl Object {
    /// All pairs in file order.
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// Number of pairs.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// No pairs.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// All pairs whose key equals `key` ASCII case-insensitively (non-ASCII characters compare
    /// exactly), in file order.
    pub fn get_all<'a, 'k>(
        &'a self,
        key: &'k str,
    ) -> impl Iterator<Item = &'a Entry> + use<'a, 'k> {
        self.entries
            .iter()
            .filter(move |e| e.key.eq_ignore_ascii_case(key))
    }

    /// The one pair named `key` (see [`Self::get_all`]): `Ok(None)` if there is none,
    /// [`Duplicate`] if there are several.
    pub fn get_unique(&self, key: &str) -> Result<Option<&Entry>, Duplicate> {
        let mut all = self.get_all(key);
        match (all.next(), all.next()) {
            (Some(a), Some(b)) => Err(Duplicate {
                first: a.offset,
                second: b.offset,
            }),
            (first, _) => Ok(first),
        }
    }
}

/// A key that should be unique appears more than once.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("key appears more than once (bytes {first} and {second})")]
pub struct Duplicate {
    /// Offset of the first occurrence.
    pub first: usize,
    /// Offset of the second occurrence.
    pub second: usize,
}

/// One pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// Key as written (decoded).
    pub key: String,
    /// Value.
    pub value: Value,
    /// Byte offset of the key's opening quote in the input.
    pub offset: usize,
}

/// Value of a pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    /// A string (decoded).
    Str(String),
    /// An object.
    Obj(Object),
}

impl Value {
    /// The string, if this is one.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::Str(s) => Some(s),
            Self::Obj(_) => None,
        }
    }

    /// The object, if this is one.
    pub fn as_object(&self) -> Option<&Object> {
        match self {
            Self::Obj(o) => Some(o),
            Self::Str(_) => None,
        }
    }
}

/// Parse error: what and where. Never contains file content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("{kind} at byte {offset}")]
pub struct VdfError {
    /// What went wrong.
    pub kind: VdfErrorKind,
    /// Byte offset in the input as given (a BOM included).
    pub offset: usize,
}

impl VdfError {
    fn new(kind: VdfErrorKind, offset: usize) -> Self {
        Self { kind, offset }
    }

    /// Line and column of the error in `input` (the input that was parsed).
    pub fn line_col(&self, input: &[u8]) -> LineCol {
        LineCol::of(input, self.offset)
    }
}

/// 1-based line and column; the column counts characters, a leading BOM is not counted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LineCol {
    /// Line (LF ends a line, so CRLF does too).
    pub line: usize,
    /// Column in characters (UTF-8 continuation bytes are not counted).
    pub column: usize,
}

impl LineCol {
    /// Position of byte `offset` in `input`; an offset past the end is clamped.
    pub fn of(input: &[u8], offset: usize) -> Self {
        let end = offset.min(input.len());
        let start = if input.starts_with(UTF8_BOM) {
            UTF8_BOM.len().min(end)
        } else {
            0
        };
        let before = input.get(start..end).unwrap_or_default();
        let line_start = before
            .iter()
            .rposition(|&b| b == b'\n')
            .map_or(0, |p| p + 1);
        let line = 1 + before.iter().filter(|&&b| b == b'\n').count();
        let column = 1 + before
            .get(line_start..)
            .unwrap_or_default()
            .iter()
            .filter(|&&b| b & 0xC0 != 0x80)
            .count();
        Self { line, column }
    }
}

impl fmt::Display for LineCol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "line {}, column {}", self.line, self.column)
    }
}

/// A character shown as `U+XXXX`, never as itself (also in `Debug`).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct CodePoint(pub char);

impl fmt::Display for CodePoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "U+{:04X}", u32::from(self.0))
    }
}

impl fmt::Debug for CodePoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// Kind of a parse error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
#[non_exhaustive]
pub enum VdfErrorKind {
    /// The input is larger than [`Limits::max_bytes`] (offset: the limit).
    #[error("input larger than {limit} bytes")]
    TooLarge {
        /// The limit.
        limit: usize,
    },
    /// The input starts with a UTF-16 byte order mark.
    #[error("UTF-16 byte order mark (only UTF-8 is supported)")]
    Utf16Bom,
    /// The input is not valid UTF-8 (offset: the first invalid byte).
    #[error("invalid UTF-8")]
    InvalidUtf8,
    /// A NUL byte.
    #[error("NUL byte")]
    Nul,
    /// A string without a closing quote on its line (offset: the opening quote).
    #[error("unterminated string")]
    UnterminatedString,
    /// An escape other than `\"`, `\\`, `\n`, `\t` (offset: the backslash).
    #[error("unknown escape: backslash followed by {ch}")]
    UnknownEscape {
        /// The character after the backslash.
        ch: CodePoint,
    },
    /// A character that cannot start a token here.
    #[error("unexpected character {ch}")]
    UnexpectedChar {
        /// The character.
        ch: CodePoint,
    },
    /// An unquoted token (only quoted strings are accepted).
    #[error("unquoted token")]
    UnquotedToken,
    /// `#include` or `#base` (never followed).
    #[error("#include or #base directive (not supported, never followed)")]
    Directive,
    /// A conditional such as `[$WIN32]`.
    #[error("conditional (not supported)")]
    Conditional,
    /// A `}` without an open object.
    #[error("closing brace without an open object")]
    UnbalancedBrace,
    /// The input ends inside an object or after a key (offset: the end).
    #[error("unexpected end of input")]
    UnexpectedEnd,
    /// More objects open at once than [`Limits::max_depth`] (offset: the `{`).
    #[error("nesting deeper than {limit}")]
    TooDeep {
        /// The applied limit.
        limit: usize,
    },
    /// More pairs than [`Limits::max_entries`] (offset: the first key over the limit).
    #[error("more than {limit} entries")]
    TooManyEntries {
        /// The limit.
        limit: usize,
    },
    /// A decoded string longer than [`Limits::max_string`] (offset: the opening quote).
    #[error("string longer than {limit} bytes")]
    StringTooLong {
        /// The limit.
        limit: usize,
    },
}

/// Parses a VDF document within `limits`. Pure, no I/O.
pub fn parse(input: &[u8], limits: &Limits) -> Result<Document, VdfError> {
    if input.len() > limits.max_bytes {
        return Err(VdfError::new(
            VdfErrorKind::TooLarge {
                limit: limits.max_bytes,
            },
            limits.max_bytes,
        ));
    }
    if input.starts_with(b"\xFF\xFE") || input.starts_with(b"\xFE\xFF") {
        return Err(VdfError::new(VdfErrorKind::Utf16Bom, 0));
    }
    let text = std::str::from_utf8(input)
        .map_err(|e| VdfError::new(VdfErrorKind::InvalidUtf8, e.valid_up_to()))?;
    if let Some(at) = input.iter().position(|&b| b == 0) {
        return Err(VdfError::new(VdfErrorKind::Nul, at));
    }
    let start = if input.starts_with(UTF8_BOM) {
        UTF8_BOM.len()
    } else {
        0
    };
    Parser {
        text,
        bytes: input,
        pos: start,
        limits: *limits,
        depth_limit: limits.effective_depth(),
        entries: 0,
    }
    .run()
}

/// An open object on the explicit stack.
struct Frame {
    key: String,
    key_at: usize,
    entries: Vec<Entry>,
}

struct Parser<'a> {
    text: &'a str,
    bytes: &'a [u8],
    pos: usize,
    limits: Limits,
    depth_limit: usize,
    entries: usize,
}

impl Parser<'_> {
    fn run(mut self) -> Result<Document, VdfError> {
        let mut root: Vec<Entry> = Vec::new();
        let mut stack: Vec<Frame> = Vec::new();
        // `Some` after a key: a value is expected.
        let mut pending: Option<(String, usize)> = None;
        loop {
            self.skip_ws();
            let at = self.pos;
            let Some(&c) = self.bytes.get(at) else {
                if pending.is_some() || !stack.is_empty() {
                    return Err(VdfError::new(VdfErrorKind::UnexpectedEnd, at));
                }
                return Ok(Document {
                    root: Object { entries: root },
                });
            };
            pending = match (pending, c) {
                (None, b'"') => {
                    if self.entries >= self.limits.max_entries {
                        return Err(VdfError::new(
                            VdfErrorKind::TooManyEntries {
                                limit: self.limits.max_entries,
                            },
                            at,
                        ));
                    }
                    self.entries += 1;
                    Some((self.string()?, at))
                }
                (None, b'}') => {
                    let Some(frame) = stack.pop() else {
                        return Err(VdfError::new(VdfErrorKind::UnbalancedBrace, at));
                    };
                    self.pos += 1;
                    let entry = Entry {
                        key: frame.key,
                        value: Value::Obj(Object {
                            entries: frame.entries,
                        }),
                        offset: frame.key_at,
                    };
                    push(&mut stack, &mut root, entry);
                    None
                }
                (Some((key, key_at)), b'"') => {
                    let value = Value::Str(self.string()?);
                    push(
                        &mut stack,
                        &mut root,
                        Entry {
                            key,
                            value,
                            offset: key_at,
                        },
                    );
                    None
                }
                (Some((key, key_at)), b'{') => {
                    if stack.len() >= self.depth_limit {
                        return Err(VdfError::new(
                            VdfErrorKind::TooDeep {
                                limit: self.depth_limit,
                            },
                            at,
                        ));
                    }
                    self.pos += 1;
                    stack.push(Frame {
                        key,
                        key_at,
                        entries: Vec::new(),
                    });
                    None
                }
                (_, c) => return Err(VdfError::new(self.bad_token(at, c), at)),
            };
        }
    }

    /// Skips whitespace and `//` comments.
    fn skip_ws(&mut self) {
        while let Some(&c) = self.bytes.get(self.pos) {
            match c {
                b' ' | b'\t' | b'\r' | b'\n' => self.pos += 1,
                b'/' if self.bytes.get(self.pos + 1) == Some(&b'/') => {
                    self.pos = self
                        .bytes
                        .get(self.pos..)
                        .and_then(|rest| rest.iter().position(|&b| b == b'\n'))
                        .map_or(self.bytes.len(), |p| self.pos + p);
                }
                _ => break,
            }
        }
    }

    /// Reads the quoted string at `self.pos` (which is `"`), decoded.
    fn string(&mut self) -> Result<String, VdfError> {
        let open = self.pos;
        let unterminated = || VdfError::new(VdfErrorKind::UnterminatedString, open);
        let too_long = || {
            VdfError::new(
                VdfErrorKind::StringTooLong {
                    limit: self.limits.max_string,
                },
                open,
            )
        };
        let mut out = String::new();
        let mut i = open + 1;
        let mut run = i;
        loop {
            if out.len() + (i - run) > self.limits.max_string {
                return Err(too_long());
            }
            let Some(&c) = self.bytes.get(i) else {
                return Err(unterminated());
            };
            match c {
                b'"' => {
                    out.push_str(self.slice(run, i));
                    self.pos = i + 1;
                    return Ok(out);
                }
                b'\r' | b'\n' => return Err(unterminated()),
                b'\\' => {
                    out.push_str(self.slice(run, i));
                    let decoded = match self.bytes.get(i + 1) {
                        None | Some(b'\r' | b'\n') => return Err(unterminated()),
                        Some(b'"') => '"',
                        Some(b'\\') => '\\',
                        Some(b'n') => '\n',
                        Some(b't') => '\t',
                        Some(_) => {
                            return Err(VdfError::new(
                                VdfErrorKind::UnknownEscape {
                                    ch: self.char_at(i + 1),
                                },
                                i,
                            ));
                        }
                    };
                    out.push(decoded);
                    i += 2;
                    run = i;
                }
                _ => i += 1,
            }
        }
    }

    /// The error for byte `c` at `at` where a token was expected but none can start.
    fn bad_token(&self, at: usize, c: u8) -> VdfErrorKind {
        let starts_with = |word: &[u8]| {
            self.bytes
                .get(at..at + word.len())
                .is_some_and(|w| w.eq_ignore_ascii_case(word))
        };
        match c {
            b'[' => VdfErrorKind::Conditional,
            b'#' if starts_with(b"#include") || starts_with(b"#base") => VdfErrorKind::Directive,
            b'{' | b'}' => VdfErrorKind::UnexpectedChar {
                ch: CodePoint(char::from(c)),
            },
            0x21..=0x7E => VdfErrorKind::UnquotedToken,
            _ => VdfErrorKind::UnexpectedChar {
                ch: self.char_at(at),
            },
        }
    }

    /// The input between two ASCII positions (always char boundaries).
    fn slice(&self, from: usize, to: usize) -> &str {
        debug_assert!(
            self.text.is_char_boundary(from) && self.text.is_char_boundary(to),
            "slice off a char boundary"
        );
        self.text.get(from..to).unwrap_or_default()
    }

    /// The character starting at `at` (a char boundary: only ASCII bytes are ever skipped
    /// singly), U+FFFD if not.
    fn char_at(&self, at: usize) -> CodePoint {
        debug_assert!(
            self.text.is_char_boundary(at),
            "char_at off a char boundary"
        );
        CodePoint(
            self.text
                .get(at..)
                .and_then(|t| t.chars().next())
                .unwrap_or(char::REPLACEMENT_CHARACTER),
        )
    }
}

fn push(stack: &mut [Frame], root: &mut Vec<Entry>, entry: Entry) {
    match stack.last_mut() {
        Some(frame) => frame.entries.push(entry),
        None => root.push(entry),
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod structural;
