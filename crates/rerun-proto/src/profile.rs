//! Launch profile, format 1 (ADR 0022): what `rerun-launch` reads at a game start.
//!
//! One grammar for the writer (`rerun-core`, from a plan) and the reader (`rerun-launch`,
//! without serde, ADR 0006). The file is UTF-8 text of at most [`MAX_PROFILE_BYTES`], one
//! `key=value` per line, every line ending in LF, the keys in a fixed order:
//!
//! ```text
//! rerun-profile 1
//! method=direct                       direct | watch
//! start=C:\Games\Game\game.exe        the exe Steam starts (%command%), canonical
//! target=C:\Games\Game\game.exe       the exe whose affinity is set; = start for direct
//! bitness=x64                         x86 | x64 (of target)
//! priority=none                       none | normal | above_normal | high
//! watch_timeout_s=120                 1..=120
//! cpu=rule                            none | rule; with rule the six cpu.* lines follow
//! cpu.prefer=performance              performance | any
//! cpu.single_l3=true                  true | false
//! cpu.prefer_l3=none                  none | largest
//! cpu.smt=false                       true | false
//! cpu.mode=hard                       hard | soft
//! cpu.max_threads=8                   none | 1..=4096
//! ```
//!
//! The reader is strict: no other key, no repeated key, no other order, no empty line, no CR,
//! no control character, no leading zero, nothing after the last key. A profile decodes to
//! exactly one [`LaunchProfile`] and encodes back to the same bytes. Errors name the line
//! and the key, never the file's content (it is untrusted).

use std::fmt;

use crate::cpu::MAX_LOGICAL_CPUS;
use crate::cpu::rule::{Bitness, CpuRule, Mode, Prefer, PreferL3};

/// The format this module reads and writes.
pub const PROFILE_FORMAT: u32 = 1;

/// Largest profile file in bytes.
pub const MAX_PROFILE_BYTES: usize = 8 * 1024;

/// Most UTF-16 code units of `start` and `target`.
pub const MAX_PATH_UNITS: usize = 2048;

/// Longest `watch` search in seconds (docs/04).
pub const MAX_WATCH_TIMEOUT_S: u16 = 120;

const HEADER: &str = "rerun-profile ";

/// A profile's ID: 16 bytes, written as 32 lower-case hex digits in file names
/// (`<id>.profile`) and in the launch option (`--profile <id>`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ProfileId(pub [u8; 16]);

impl ProfileId {
    /// Parses exactly 32 lower-case hex digits.
    pub fn from_hex(s: &str) -> Option<Self> {
        let b = s.as_bytes();
        if b.len() != 32 {
            return None;
        }
        let mut out = [0u8; 16];
        let (pairs, _) = b.as_chunks::<2>();
        for (o, [hi, lo]) in out.iter_mut().zip(pairs) {
            *o = (hex_digit(*hi)? << 4) | hex_digit(*lo)?;
        }
        Some(Self(out))
    }
}

fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    }
}

impl fmt::Display for ProfileId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.iter().try_for_each(|b| write!(f, "{b:02x}"))
    }
}

/// How `rerun-launch` reaches the game (docs/04; `hold`, `ifeo` and `inproc` come later).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Method {
    /// Start Steam's command in a Job Object with the limit.
    Direct,
    /// Start Steam's command unchanged, find `target`, set the limit on it.
    Watch,
}

/// Priority class set at the start (ADR 0022, D6 a). Never realtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Priority {
    /// `NORMAL_PRIORITY_CLASS`.
    Normal,
    /// `ABOVE_NORMAL_PRIORITY_CLASS`.
    AboveNormal,
    /// `HIGH_PRIORITY_CLASS`.
    High,
}

/// A launch profile.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LaunchProfile {
    /// Launch method.
    pub method: Method,
    /// Canonical absolute path of the exe Steam passes (`%command%`), compared with Steam's
    /// first argument.
    pub start: String,
    /// The exe whose limit is set and checked; equal to `start` for [`Method::Direct`].
    pub target: String,
    /// Bitness of `target`.
    pub bitness: Bitness,
    /// Priority class, if any.
    pub priority: Option<Priority>,
    /// How long `watch` searches for `target`, `1..=120` seconds (kept for `direct` too).
    pub watch_timeout_s: u16,
    /// CPU rule, if any.
    pub cpu: Option<CpuRule>,
}

/// What is wrong with a profile file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProfileErrorKind {
    /// More than [`MAX_PROFILE_BYTES`].
    TooLarge,
    /// Not UTF-8.
    NotUtf8,
    /// The last line has no LF (also an empty file or a cut-off one).
    NoFinalNewline,
    /// A CR.
    CarriageReturn,
    /// A control character (C0, DEL or C1), including NUL and tab.
    ControlChar,
    /// An empty line.
    EmptyLine,
    /// The first line is not `rerun-profile <n>`.
    BadHeader,
    /// `rerun-profile <n>` with `n` other than [`PROFILE_FORMAT`].
    UnsupportedFormat(u32),
    /// A line without `=`.
    MissingEquals,
    /// A key this format does not know.
    UnknownKey,
    /// A key that appeared before.
    DuplicateKey,
    /// A known key at the wrong place; `expected` is the key that belongs there.
    UnexpectedKey {
        /// The key that belongs at this line.
        expected: &'static str,
    },
    /// The file ends before `expected`.
    Truncated {
        /// The first missing key.
        expected: &'static str,
    },
    /// A line after the last key.
    TrailingLine,
    /// The value of `key` is not one of its allowed values.
    BadValue {
        /// The key.
        key: &'static str,
    },
    /// `method=direct` with `target` other than `start`.
    TargetNotStart,
    /// [`encode`] only: the bytes would decode to another profile (never for a correct codec).
    NotCanonical,
}

/// A rejected profile: the 1-based line (0: the file as a whole) and why.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProfileError {
    /// 1-based line number, 0 for the whole file.
    pub line: usize,
    /// What is wrong.
    pub kind: ProfileErrorKind,
}

impl fmt::Display for ProfileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use ProfileErrorKind as K;
        if self.line > 0 {
            write!(f, "launch profile line {}: ", self.line)?;
        } else {
            write!(f, "launch profile: ")?;
        }
        match self.kind {
            K::TooLarge => write!(f, "larger than {MAX_PROFILE_BYTES} bytes"),
            K::NotUtf8 => write!(f, "not UTF-8"),
            K::NoFinalNewline => write!(f, "the last line does not end with LF"),
            K::CarriageReturn => write!(f, "carriage return"),
            K::ControlChar => write!(f, "control character"),
            K::EmptyLine => write!(f, "empty line"),
            K::BadHeader => write!(f, "not a launch profile"),
            K::UnsupportedFormat(n) => {
                write!(f, "format {n}, this version reads {PROFILE_FORMAT}")
            }
            K::MissingEquals => write!(f, "no '='"),
            K::UnknownKey => write!(f, "unknown key"),
            K::DuplicateKey => write!(f, "repeated key"),
            K::UnexpectedKey { expected } => write!(f, "expected key {expected}"),
            K::Truncated { expected } => write!(f, "ends before key {expected}"),
            K::TrailingLine => write!(f, "line after the last key"),
            K::BadValue { key } => write!(f, "invalid value of {key}"),
            K::TargetNotStart => write!(f, "method direct needs target equal to start"),
            K::NotCanonical => write!(f, "does not read back as written"),
        }
    }
}

impl std::error::Error for ProfileError {}

const KEYS: &[&str] = &[
    "method",
    "start",
    "target",
    "bitness",
    "priority",
    "watch_timeout_s",
    "cpu",
    "cpu.prefer",
    "cpu.single_l3",
    "cpu.prefer_l3",
    "cpu.smt",
    "cpu.mode",
    "cpu.max_threads",
];

/// Encodes `p`. The bytes are checked by [`decode`]: what the writer emits, the reader takes
/// (an invalid path, a timeout outside `1..=120`, `max_threads` 0 or `direct` with
/// `target != start` are errors here, never a file the shim would refuse).
pub fn encode(p: &LaunchProfile) -> Result<Vec<u8>, ProfileError> {
    let mut s = format!("{HEADER}{PROFILE_FORMAT}\n");
    let mut kv = |k: &str, v: &str| {
        s.push_str(k);
        s.push('=');
        s.push_str(v);
        s.push('\n');
    };
    kv(
        "method",
        match p.method {
            Method::Direct => "direct",
            Method::Watch => "watch",
        },
    );
    kv("start", &p.start);
    kv("target", &p.target);
    kv("bitness", bitness_str(p.bitness));
    kv(
        "priority",
        match p.priority {
            None => "none",
            Some(Priority::Normal) => "normal",
            Some(Priority::AboveNormal) => "above_normal",
            Some(Priority::High) => "high",
        },
    );
    kv("watch_timeout_s", &p.watch_timeout_s.to_string());
    match &p.cpu {
        None => kv("cpu", "none"),
        Some(r) => {
            kv("cpu", "rule");
            kv(
                "cpu.prefer",
                match r.prefer {
                    Prefer::Performance => "performance",
                    Prefer::Any => "any",
                },
            );
            kv("cpu.single_l3", bool_str(r.single_l3));
            kv(
                "cpu.prefer_l3",
                match r.prefer_l3 {
                    None => "none",
                    Some(PreferL3::Largest) => "largest",
                },
            );
            kv("cpu.smt", bool_str(r.smt));
            kv(
                "cpu.mode",
                match r.mode {
                    Mode::Hard => "hard",
                    Mode::Soft => "soft",
                },
            );
            let max = r.max_threads.map(|n| n.to_string());
            kv("cpu.max_threads", max.as_deref().unwrap_or("none"));
        }
    }
    let bytes = s.into_bytes();
    let back = decode(&bytes)?;
    if &back == p {
        Ok(bytes)
    } else {
        // Unreachable for a correct codec; never hand out bytes that read back differently.
        Err(ProfileError {
            line: 0,
            kind: ProfileErrorKind::NotCanonical,
        })
    }
}

fn bitness_str(b: Bitness) -> &'static str {
    match b {
        Bitness::X86 => "x86",
        Bitness::X64 => "x64",
    }
}

fn bool_str(b: bool) -> &'static str {
    if b { "true" } else { "false" }
}

/// Decodes a profile file. Bounded (at most [`MAX_PROFILE_BYTES`]) and strict, see the module
/// documentation.
pub fn decode(bytes: &[u8]) -> Result<LaunchProfile, ProfileError> {
    let whole = |kind| ProfileError { line: 0, kind };
    if bytes.len() > MAX_PROFILE_BYTES {
        return Err(whole(ProfileErrorKind::TooLarge));
    }
    let text = std::str::from_utf8(bytes).map_err(|_| whole(ProfileErrorKind::NotUtf8))?;
    let body = text
        .strip_suffix('\n')
        .ok_or(whole(ProfileErrorKind::NoFinalNewline))?;
    let mut lines = body.split('\n').enumerate().map(|(n, l)| (n + 1, l));

    // Every line first: CR, control characters, empty lines.
    for (n, l) in body.split('\n').enumerate() {
        let at = |kind| ProfileError { line: n + 1, kind };
        if l.contains('\r') {
            return Err(at(ProfileErrorKind::CarriageReturn));
        }
        if l.chars().any(char::is_control) {
            return Err(at(ProfileErrorKind::ControlChar));
        }
        if l.is_empty() {
            return Err(at(ProfileErrorKind::EmptyLine));
        }
    }

    let (_, header) = lines.next().ok_or(whole(ProfileErrorKind::BadHeader))?;
    let version = header
        .strip_prefix(HEADER)
        .and_then(canonical_number)
        .ok_or(ProfileError {
            line: 1,
            kind: ProfileErrorKind::BadHeader,
        })?;
    if version != u64::from(PROFILE_FORMAT) {
        let n = u32::try_from(version).unwrap_or(u32::MAX);
        return Err(ProfileError {
            line: 1,
            kind: ProfileErrorKind::UnsupportedFormat(n),
        });
    }

    let mut r = Reader {
        lines,
        seen: Vec::new(),
        last_line: 1,
    };
    let method = r.value("method", |v| match v {
        "direct" => Some(Method::Direct),
        "watch" => Some(Method::Watch),
        _ => None,
    })?;
    let start = r.value("start", path)?;
    let (target_line, target) = r.value_at("target", path)?;
    let bitness = r.value("bitness", |v| match v {
        "x86" => Some(Bitness::X86),
        "x64" => Some(Bitness::X64),
        _ => None,
    })?;
    let priority = r.value("priority", |v| match v {
        "none" => Some(None),
        "normal" => Some(Some(Priority::Normal)),
        "above_normal" => Some(Some(Priority::AboveNormal)),
        "high" => Some(Some(Priority::High)),
        _ => None,
    })?;
    let watch_timeout_s = r.value("watch_timeout_s", |v| {
        canonical_number(v)
            .filter(|n| (1..=u64::from(MAX_WATCH_TIMEOUT_S)).contains(n))
            .and_then(|n| u16::try_from(n).ok())
    })?;
    let has_rule = r.value("cpu", |v| match v {
        "none" => Some(false),
        "rule" => Some(true),
        _ => None,
    })?;
    let cpu = if has_rule {
        let prefer = r.value("cpu.prefer", |v| match v {
            "performance" => Some(Prefer::Performance),
            "any" => Some(Prefer::Any),
            _ => None,
        })?;
        let single_l3 = r.value("cpu.single_l3", boolean)?;
        let prefer_l3 = r.value("cpu.prefer_l3", |v| match v {
            "none" => Some(None),
            "largest" => Some(Some(PreferL3::Largest)),
            _ => None,
        })?;
        let smt = r.value("cpu.smt", boolean)?;
        let mode = r.value("cpu.mode", |v| match v {
            "hard" => Some(Mode::Hard),
            "soft" => Some(Mode::Soft),
            _ => None,
        })?;
        let max_threads = r.value("cpu.max_threads", |v| {
            if v == "none" {
                return Some(None);
            }
            canonical_number(v)
                .filter(|n| (1..=MAX_LOGICAL_CPUS as u64).contains(n))
                .and_then(|n| u16::try_from(n).ok())
                .map(Some)
        })?;
        Some(CpuRule {
            max_threads,
            prefer,
            single_l3,
            prefer_l3,
            smt,
            mode,
        })
    } else {
        None
    };
    if let Some((n, line)) = r.lines.next() {
        let kind = match line.split_once('=').map(|(k, _)| k) {
            Some(k) if r.seen.contains(&k) => ProfileErrorKind::DuplicateKey,
            Some(k) if KEYS.contains(&k) => ProfileErrorKind::TrailingLine,
            Some(_) => ProfileErrorKind::UnknownKey,
            None => ProfileErrorKind::MissingEquals,
        };
        return Err(ProfileError { line: n, kind });
    }
    if method == Method::Direct && target != start {
        return Err(ProfileError {
            line: target_line,
            kind: ProfileErrorKind::TargetNotStart,
        });
    }
    Ok(LaunchProfile {
        method,
        start,
        target,
        bitness,
        priority,
        watch_timeout_s,
        cpu,
    })
}

struct Reader<'a, I: Iterator<Item = (usize, &'a str)>> {
    lines: I,
    seen: Vec<&'a str>,
    last_line: usize,
}

impl<'a, I: Iterator<Item = (usize, &'a str)>> Reader<'a, I> {
    fn value<T>(
        &mut self,
        key: &'static str,
        parse: impl FnOnce(&str) -> Option<T>,
    ) -> Result<T, ProfileError> {
        self.value_at(key, parse).map(|(_, v)| v)
    }

    fn value_at<T>(
        &mut self,
        key: &'static str,
        parse: impl FnOnce(&str) -> Option<T>,
    ) -> Result<(usize, T), ProfileError> {
        let Some((n, line)) = self.lines.next() else {
            return Err(ProfileError {
                line: self.last_line + 1,
                kind: ProfileErrorKind::Truncated { expected: key },
            });
        };
        self.last_line = n;
        let at = |kind| ProfileError { line: n, kind };
        let (k, v) = line
            .split_once('=')
            .ok_or(at(ProfileErrorKind::MissingEquals))?;
        if k != key {
            return Err(at(if self.seen.contains(&k) {
                ProfileErrorKind::DuplicateKey
            } else if KEYS.contains(&k) {
                ProfileErrorKind::UnexpectedKey { expected: key }
            } else {
                ProfileErrorKind::UnknownKey
            }));
        }
        self.seen.push(k);
        parse(v)
            .map(|v| (n, v))
            .ok_or(at(ProfileErrorKind::BadValue { key }))
    }
}

fn boolean(v: &str) -> Option<bool> {
    match v {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    }
}

/// A decimal number without sign or leading zero (`0` alone is allowed), at most 9 digits.
fn canonical_number(v: &str) -> Option<u64> {
    let b = v.as_bytes();
    if b.is_empty() || b.len() > 9 || !b.iter().all(u8::is_ascii_digit) {
        return None;
    }
    if b.len() > 1 && b[0] == b'0' {
        return None;
    }
    v.parse().ok()
}

/// A canonical absolute drive path as `rerun-launch` compares it with Steam's first argument:
/// `X:\` and at least one component; components separated by one `\`, none empty, `.` or
/// `..`, none starting with a space or ending in a space or a dot, none a reserved device name
/// (`CON`, `NUL`, `COM1`, `nul.txt`, …, docs/06 #4); none of `< > : " / | ? *`, no format or
/// separator character (Unicode Cf, Zl, Zp: bidirectional controls, zero-width characters,
/// U+FEFF, U+2028/U+2029; docs/06 #6); at most [`MAX_PATH_UNITS`] UTF-16 units. Never `\\?\`,
/// UNC or relative.
fn path(v: &str) -> Option<String> {
    let b = v.as_bytes();
    if b.len() < 4 || !b[0].is_ascii_alphabetic() || b[1] != b':' || b[2] != b'\\' {
        return None;
    }
    if v.encode_utf16().count() > MAX_PATH_UNITS {
        return None;
    }
    let ok = v[3..].split('\\').all(|c| {
        !c.is_empty()
            && c != "."
            && c != ".."
            && !c.starts_with(' ')
            && !c.ends_with(' ')
            && !c.ends_with('.')
            && !c.contains(['<', '>', ':', '"', '/', '|', '?', '*'])
            && !c.chars().any(is_format_or_separator)
            && !is_device_name(c)
    });
    ok.then(|| v.to_owned())
}

/// Unicode general categories Cf (format), Zl (line separator) and Zp (paragraph separator),
/// as of Unicode 16. `std` has no category table; the list is short and stable.
fn is_format_or_separator(c: char) -> bool {
    matches!(c,
        '\u{00AD}' | '\u{0600}'..='\u{0605}' | '\u{061C}' | '\u{06DD}' | '\u{070F}'
        | '\u{0890}'..='\u{0891}' | '\u{08E2}' | '\u{180E}'
        | '\u{200B}'..='\u{200F}'   // zero-width characters, LRM/RLM
        | '\u{2028}'..='\u{202E}'   // line and paragraph separator, bidi embedding/override
        | '\u{2060}'..='\u{2064}' | '\u{2066}'..='\u{206F}' // word joiner, bidi isolates
        | '\u{FEFF}' | '\u{FFF9}'..='\u{FFFB}'
        | '\u{110BD}' | '\u{110CD}' | '\u{13430}'..='\u{1343F}' | '\u{1BCA0}'..='\u{1BCA3}'
        | '\u{1D173}'..='\u{1D17A}' | '\u{E0001}' | '\u{E0020}'..='\u{E007F}'
    )
}

/// A reserved DOS device name: the part before the first dot, trailing spaces ignored, is
/// `CON`, `PRN`, `AUX`, `NUL`, `CONIN$`, `CONOUT$`, `CLOCK$`, or `COM`/`LPT` with one digit or
/// superscript 1–3 (the rule of `rerun-core`'s `RelPath`).
fn is_device_name(component: &str) -> bool {
    let stem = component
        .split('.')
        .next()
        .unwrap_or(component)
        .trim_end_matches(' ')
        .to_ascii_uppercase();
    if ["CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$", "CLOCK$"].contains(&stem.as_str()) {
        return true;
    }
    ["COM", "LPT"].iter().any(|prefix| {
        stem.strip_prefix(prefix).is_some_and(|rest| {
            let mut rc = rest.chars();
            matches!((rc.next(), rc.next()), (Some(c), None)
                if c.is_ascii_digit() || matches!(c, '¹' | '²' | '³'))
        })
    })
}

#[cfg(test)]
mod tests;
