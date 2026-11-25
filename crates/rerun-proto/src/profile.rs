//! Launch profile, formats 1, 2 and 3 (ADR 0022, amendments P4-13 and P5-OE): what
//! `rerun-launch` reads at a game start.
//!
//! One grammar for the writer (`rerun-core`, from a plan) and the reader (`rerun-launch`,
//! without serde, ADR 0006). The file is UTF-8 text of at most [`MAX_PROFILE_BYTES`], one
//! `key=value` per line, every line ending in LF, the keys in a fixed order. Format 3, the one
//! [`encode`] writes for every profile:
//!
//! ```text
//! rerun-profile 3
//! method=direct                       direct | watch
//! start=C:\Games\Game\game.exe        the exe Steam starts (%command%), canonical
//! target=C:\Games\Game\game_dx9.exe   the exe whose limit is set: run, else start (direct)
//! bitness=x64                         x86 | x64 (x86 if a program of the chain is i386)
//! priority=none                       none | normal | above_normal | high
//! watch_timeout_s=120                 1..=120
//! cpu=rule                            none | rule; with rule the seven cpu.* lines follow
//! cpu.prefer=performance              performance | any
//! cpu.single_l3=true                  true | false
//! cpu.prefer_l3=none                  none | largest
//! cpu.smt=false                       true | false
//! cpu.mode=hard                       hard | soft
//! cpu.max_threads=8                   none | 1..=4096
//! cpu.exclude_first=none              none | thread | core
//! run=C:\Games\Game\game_dx9.exe      none | the exe the shim starts instead of start
//! args=-dx9 +fullscreen=1             none | 1..=8 arguments joined by one space
//! ```
//!
//! Format 1 (ADR 0022 D1) is format 3 without `cpu.exclude_first`, `run` and `args`; format 2
//! (amendment P4-13) is format 1 with `cpu=rule` required and `cpu.exclude_first`
//! (`thread`/`core`) after `cpu.max_threads`. The reader takes all three, so a revert can
//! restore a profile an earlier build wrote; the writer emits format 3 only.
//!
//! Format 3 rules beyond the key grammar (amendment P5-OE): `run` is a path like `start`,
//! ending in `.exe`, not `start`, in **the same folder** as `start` (both byte for byte equal
//! up to and including their last `\`), and requires `method=direct` and `target = run`.
//! `args` holds 1 to [`MAX_ARGS`] [`LaunchArg`]s joined by one space, at most
//! [`MAX_ARGS_BYTES`] bytes, and requires `method=direct`. Without `run`, `direct` still needs
//! `target = start`.
//!
//! The reader is strict: no other key, no repeated key, no other order, no empty line, no CR,
//! no control character, no leading zero, nothing after the last key. A profile decodes to
//! exactly one [`LaunchProfile`]; a format-3 file encodes back to the same bytes. Errors name
//! the line and the key, never the file's content (it is untrusted).

use std::fmt;

use crate::cpu::MAX_LOGICAL_CPUS;
use crate::cpu::rule::{Bitness, CpuRule, ExcludeFirst, Mode, Prefer, PreferL3};

/// The format [`encode`] writes, for every profile (ADR 0022 amendment P5-OE).
pub const PROFILE_FORMAT: u32 = 3;

/// Every format the reader accepts (1: ADR 0022 D1; 2: amendment P4-13; 3: amendment P5-OE).
pub const PROFILE_FORMATS: [u32; 3] = [1, 2, PROFILE_FORMAT];

/// Most arguments of `args`.
pub const MAX_ARGS: usize = 8;

/// Most characters (= bytes, the pattern is ASCII) of one [`LaunchArg`].
pub const MAX_ARG_CHARS: usize = 64;

/// Most bytes of the `args` value (the arguments joined by one space).
pub const MAX_ARGS_BYTES: usize = 512;

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

/// One launch argument of `args` (ADR 0032 amendment P5-OE): `^[-+][A-Za-z0-9_.=+-]+$`, at
/// most [`MAX_ARG_CHARS`] characters. No quote, space, `%`, `\`, `/` or anything else a command
/// line or Steam would read twice: the shim appends it to the command line as it is. The one
/// place of the pattern; the catalogue reuses it.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct LaunchArg(String);

impl LaunchArg {
    /// The argument if `s` matches the pattern.
    pub fn parse(s: &str) -> Option<Self> {
        let b = s.as_bytes();
        let ok = b.len() >= 2
            && b.len() <= MAX_ARG_CHARS
            && matches!(b[0], b'-' | b'+')
            && b[1..].iter().all(|c| {
                c.is_ascii_alphanumeric() || matches!(c, b'_' | b'.' | b'=' | b'+' | b'-')
            });
        ok.then(|| Self(s.to_owned()))
    }

    /// The argument.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for LaunchArg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The value of the `args` key: `none`, or the arguments joined by one space.
pub fn args_value(args: &[LaunchArg]) -> String {
    if args.is_empty() {
        return "none".to_owned();
    }
    let parts: Vec<&str> = args.iter().map(LaunchArg::as_str).collect();
    parts.join(" ")
}

/// How `rerun-launch` reaches the game (docs/04; `hold`, `ifeo` and `inproc` come later).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Method {
    /// Start Steam's command (or the profile's `run` in its place) in a Job Object with the
    /// limit.
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
    /// The exe whose limit is set and checked; for [`Method::Direct`] equal to `run` if the
    /// profile has one, else to `start`.
    pub target: String,
    /// `x86` if a process of the chain the rule reaches is i386 (`IMAGE_FILE_MACHINE_I386`):
    /// the planner reads `start` and the game's main executable (ADR 0022 D1, amendment P3-3).
    /// A .NET "AnyCPU" image is i386 on disk and may run as x64; it counts as x86, which costs
    /// only on a processor group of more than 32 logical processors (B6).
    pub bitness: Bitness,
    /// Priority class, if any.
    pub priority: Option<Priority>,
    /// How long `watch` searches for `target`, `1..=120` seconds (kept for `direct` too).
    pub watch_timeout_s: u16,
    /// CPU rule, if any.
    pub cpu: Option<CpuRule>,
    /// The exe the shim starts instead of `start` when Steam's first argument is `start`
    /// (format 3): canonical, `.exe`, in the folder of `start`, not `start`; `direct` only.
    pub run: Option<String>,
    /// Arguments the shim appends to the command line it starts (format 3); `direct` only.
    pub args: Vec<LaunchArg>,
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
    /// `rerun-profile <n>` with `n` not in [`PROFILE_FORMATS`] (1, 2 and 3).
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
    /// `method=direct` without `run`, and `target` other than `start`.
    TargetNotStart,
    /// `run` with `target` other than `run`.
    TargetNotRun,
    /// `run` with `method=watch` (the shim starts `run` only for `direct`).
    RunNeedsDirect,
    /// `run` names `start` itself (also in another case).
    RunIsStart,
    /// `run` is not in the folder of `start` (byte for byte up to the last `\`).
    RunNotInStartFolder,
    /// `args` with `method=watch` (the shim appends them only for `direct`).
    ArgsNeedDirect,
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
                write!(f, "format {n}, this version reads formats ")?;
                let last = PROFILE_FORMATS.len().saturating_sub(1);
                for (i, v) in PROFILE_FORMATS.iter().enumerate() {
                    let sep = match i {
                        0 => "",
                        _ if i == last => " and ",
                        _ => ", ",
                    };
                    write!(f, "{sep}{v}")?;
                }
                Ok(())
            }
            K::MissingEquals => write!(f, "no '='"),
            K::UnknownKey => write!(f, "unknown key"),
            K::DuplicateKey => write!(f, "repeated key"),
            K::UnexpectedKey { expected } => write!(f, "expected key {expected}"),
            K::Truncated { expected } => write!(f, "ends before key {expected}"),
            K::TrailingLine => write!(f, "line after the last key"),
            K::BadValue { key } => write!(f, "invalid value of {key}"),
            K::TargetNotStart => write!(f, "method direct needs target equal to start"),
            K::TargetNotRun => write!(f, "run needs target equal to run"),
            K::RunNeedsDirect => write!(f, "run needs method direct"),
            K::RunIsStart => write!(f, "run names the start program itself"),
            K::RunNotInStartFolder => write!(f, "run is not in the folder of start"),
            K::ArgsNeedDirect => write!(f, "args need method direct"),
            K::NotCanonical => write!(f, "does not read back as written"),
        }
    }
}

impl std::error::Error for ProfileError {}

/// The keys of format 1, in order.
const KEYS_1: &[&str] = &[
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

/// The keys of format 2, in order: format 1 plus `cpu.exclude_first`.
const KEYS_2: &[&str] = &[
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
    "cpu.exclude_first",
];

/// The keys of format 3, in order: format 2 plus `run` and `args` (`cpu=none` allowed again,
/// `cpu.exclude_first` with `none`).
const KEYS_3: &[&str] = &[
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
    "cpu.exclude_first",
    "run",
    "args",
];

/// Encodes `p` as format 3 ([`PROFILE_FORMAT`], every profile). The bytes are checked by
/// [`decode`]: what the writer emits, the reader takes (an invalid path, a timeout outside
/// `1..=120`, `max_threads` 0, `direct` with the wrong `target`, a `run` outside the folder of
/// `start` or an argument outside the pattern are errors here, never a file the shim would
/// refuse).
pub fn encode(p: &LaunchProfile) -> Result<Vec<u8>, ProfileError> {
    encode_format(p, PROFILE_FORMAT)
}

/// Encodes `p` as `format` (1, 2 or 3) and checks the bytes with [`decode`]. Formats 1 and 2
/// are written by tests only: a profile an earlier build wrote, to prove a revert restores it.
pub(crate) fn encode_format(p: &LaunchProfile, format: u32) -> Result<Vec<u8>, ProfileError> {
    let bytes = write(p, format).into_bytes();
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

/// The text of `p` in `format`, unchecked: format 1 never writes `exclude_first`, `run` or
/// `args`; format 2 writes `exclude_first` only for a rule that has it.
fn write(p: &LaunchProfile, format: u32) -> String {
    let v3 = format == PROFILE_FORMAT;
    let mut s = format!("{HEADER}{format}\n");
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
            match r.exclude_first {
                Some(e) if format >= 2 => kv("cpu.exclude_first", e.name()),
                None if v3 => kv("cpu.exclude_first", "none"),
                _ => {}
            }
        }
    }
    if v3 {
        kv("run", p.run.as_deref().unwrap_or("none"));
        kv("args", &args_value(&p.args));
    }
    s
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
    let format = u32::try_from(version).unwrap_or(u32::MAX);
    if !PROFILE_FORMATS.contains(&format) {
        return Err(ProfileError {
            line: 1,
            kind: ProfileErrorKind::UnsupportedFormat(format),
        });
    }
    let v2 = format == 2;
    let v3 = format == 3;

    let mut r = Reader {
        lines,
        keys: match format {
            1 => KEYS_1,
            2 => KEYS_2,
            _ => KEYS_3,
        },
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
    // Format 2 exists only for a rule with `exclude_first`: `cpu=none` is format 1 or 3.
    let has_rule = r.value("cpu", |v| match v {
        "none" if !v2 => Some(false),
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
        let exclude_first = if v2 || v3 {
            r.value("cpu.exclude_first", |v| match v {
                "none" if v3 => Some(None),
                "thread" => Some(Some(ExcludeFirst::Thread)),
                "core" => Some(Some(ExcludeFirst::Core)),
                _ => None,
            })?
        } else {
            None
        };
        Some(CpuRule {
            max_threads,
            prefer,
            single_l3,
            prefer_l3,
            smt,
            mode,
            exclude_first,
        })
    } else {
        None
    };
    let (run_line, run, args_line, args) = if v3 {
        let (run_line, run) = r.value_at("run", |v| match v {
            "none" => Some(None),
            _ => path(v).filter(|p| is_exe(p)).map(Some),
        })?;
        let (args_line, args) = r.value_at("args", parse_args)?;
        (run_line, run, args_line, args)
    } else {
        (0, None, 0, Vec::new())
    };
    if let Some((n, line)) = r.lines.next() {
        let kind = match line.split_once('=').map(|(k, _)| k) {
            Some(k) if r.seen.contains(&k) => ProfileErrorKind::DuplicateKey,
            Some(k) if r.keys.contains(&k) => ProfileErrorKind::TrailingLine,
            Some(_) => ProfileErrorKind::UnknownKey,
            None => ProfileErrorKind::MissingEquals,
        };
        return Err(ProfileError { line: n, kind });
    }
    let at = |line, kind| Err(ProfileError { line, kind });
    match &run {
        Some(_) if method != Method::Direct => {
            return at(run_line, ProfileErrorKind::RunNeedsDirect);
        }
        Some(run) if same_name(run, &start) => return at(run_line, ProfileErrorKind::RunIsStart),
        Some(run) if folder(run) != folder(&start) => {
            return at(run_line, ProfileErrorKind::RunNotInStartFolder);
        }
        Some(run) if &target != run => return at(target_line, ProfileErrorKind::TargetNotRun),
        None if method == Method::Direct && target != start => {
            return at(target_line, ProfileErrorKind::TargetNotStart);
        }
        _ => {}
    }
    if !args.is_empty() && method != Method::Direct {
        return at(args_line, ProfileErrorKind::ArgsNeedDirect);
    }
    Ok(LaunchProfile {
        method,
        start,
        target,
        bitness,
        priority,
        watch_timeout_s,
        cpu,
        run,
        args,
    })
}

/// The value of `args`: `none`, or 1 to [`MAX_ARGS`] [`LaunchArg`]s joined by one space, at
/// most [`MAX_ARGS_BYTES`] bytes.
fn parse_args(v: &str) -> Option<Vec<LaunchArg>> {
    if v == "none" {
        return Some(Vec::new());
    }
    if v.len() > MAX_ARGS_BYTES {
        return None;
    }
    let args: Vec<LaunchArg> = v.split(' ').map(LaunchArg::parse).collect::<Option<_>>()?;
    (args.len() <= MAX_ARGS).then_some(args)
}

/// The path ends in `.exe`, ASCII case-insensitively.
fn is_exe(p: &str) -> bool {
    p.len() > 4 && p.is_char_boundary(p.len() - 4) && p[p.len() - 4..].eq_ignore_ascii_case(".exe")
}

/// The folder of a canonical path: everything up to and including its last `\` (there is one
/// at index 2 at least).
fn folder(p: &str) -> &str {
    p.rfind('\\').map_or(p, |i| &p[..=i])
}

/// The same path in another case (simple Unicode case mapping both ways; the planner compares
/// with the file system's own folding, this is the codec's fail-closed check).
fn same_name(a: &str, b: &str) -> bool {
    a == b || a.to_lowercase() == b.to_lowercase() || a.to_uppercase() == b.to_uppercase()
}

struct Reader<'a, I: Iterator<Item = (usize, &'a str)>> {
    lines: I,
    /// The keys of the file's format, in order.
    keys: &'static [&'static str],
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
            } else if self.keys.contains(&k) {
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
    v[3..].split('\\').all(component).then(|| v.to_owned())
}

/// One component of a canonical path (the rules of [`path`] for a single name; no `\`): not
/// empty, `.` or `..`, not starting with a space or ending in a space or a dot, none of
/// `< > : " / | ? *`, no format or separator character, not a reserved device name. Control
/// characters are refused by both readers before any value is parsed.
pub(crate) fn component(c: &str) -> bool {
    !c.is_empty()
        && c != "."
        && c != ".."
        && !c.starts_with(' ')
        && !c.ends_with(' ')
        && !c.ends_with('.')
        && !c.contains(['<', '>', ':', '"', '/', '|', '?', '*', '\\'])
        && !c.chars().any(is_format_or_separator)
        && !is_device_name(c)
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
