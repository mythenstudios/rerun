//! Launch result, format 1 (ADR 0022, D5 and amendment P3-2): what `rerun-launch` records about
//! its last start of a profile in `<LocalAppData>\Rerun\launch\<id>.result`, and what
//! `rerun status` reads back.
//!
//! One grammar for the writer (`rerun-launch`, without serde, ADR 0006) and the reader
//! (`rerun-core`, untrusted input). UTF-8 text of at most [`MAX_RESULT_BYTES`], nine lines in a
//! fixed order, each `key=value` ending in LF, every key always present:
//!
//! ```text
//! rerun-result 1
//! profile=0123456789abcdef0123456789abcdef   the profile ID (= the file name)
//! time=1762600000                            seconds since 1970-01-01 UTC
//! rule=applied                               applied | skipped:<reason>[:<code>]
//! cpu=hard:8:32                              none | hard:<threads>:<of> | soft:<threads>:<of>
//! priority=none                              none | normal | above_normal | high
//! check=ok                                   none | ok | reset:<what> | exited_early | failed:<code>
//! start=created                              created | shell | shell_no_process | not_exe | failed:<code>
//! ended=none                                 none | ended | failed:<code> | not_confirmed:<code>
//! ```
//!
//! `rule=applied` carries `cpu`, `priority` and `check` and always `start=created`,
//! `ended=none`; `rule=skipped:…` carries `start` and `ended` and always `cpu=none`,
//! `priority=none`, `check=none`. `<code>` is a Win32 error code (or an `HRESULT` as an
//! unsigned number where Windows gave one) in canonical decimal. The reader is strict like the
//! profile reader: no other key, order or spelling, no leading zero, no empty line, no CR, no
//! control character; a file decodes to one [`LaunchResult`] and encodes back to the same
//! bytes. Errors name the line and the key, never the content.

use std::fmt;

use crate::cpu::MAX_LOGICAL_CPUS;
use crate::cpu::rule::Mode;
use crate::profile::{Priority, ProfileId};

/// The format this module reads and writes.
pub const RESULT_FORMAT: u32 = 1;

/// Largest result file in bytes (a valid one has fewer than 300).
pub const MAX_RESULT_BYTES: usize = 1024;

const HEADER: &str = "rerun-result ";

/// The record of one start.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LaunchResult {
    /// The profile (the file is `<profile>.result`).
    pub profile: ProfileId,
    /// When the shim wrote it, seconds since 1970-01-01 UTC.
    pub unix_s: u64,
    /// What happened.
    pub outcome: Outcome,
}

/// What became of the profile's rule.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Outcome {
    /// The rule was applied to the started process (always started with `CreateProcessW`).
    Applied {
        /// The CPU limit, if the profile has a rule.
        cpu: Option<AppliedCpu>,
        /// The priority class, if the profile sets one.
        priority: Option<Priority>,
        /// The post-launch check.
        check: Check,
    },
    /// The rule was not applied: Steam's command was started unchanged (or not at all).
    Skipped {
        /// Why.
        reason: SkipReason,
        /// How the command was started.
        start: Start,
        /// A child created with the rule that had to be ended first.
        ended: Option<Ended>,
    },
}

/// A CPU limit as applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AppliedCpu {
    /// Hard (job) or soft (CPU Sets).
    pub mode: Mode,
    /// Selected logical processors, `1..=of`.
    pub threads: u16,
    /// Logical processors of the machine, `1..=4096`.
    pub of: u16,
}

/// The post-launch check, about 5 s after the start (docs/04).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Check {
    /// Affinity (or CPU Sets) and priority class are as set.
    Ok,
    /// Something differs from what was set (no culprit is named: the shim cannot tell who
    /// changed it). At least one of the two is `true`.
    Reset {
        /// The affinity, the job's group affinity or the CPU Sets differ.
        cpu: bool,
        /// The priority class differs.
        priority: bool,
    },
    /// The started process ended before the check (a launcher stub hands over: `watch`).
    ExitedEarly,
    /// The check itself failed with this code.
    Failed {
        /// Win32 error code.
        code: u32,
    },
}

/// Why the rule was not applied. The names are those of docs/04.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SkipReason {
    /// `profile_missing`: no profile file (or no `profiles` folder).
    ProfileMissing,
    /// `profile_unreadable:<code>`: the profile could not be read.
    ProfileUnreadable {
        /// Win32 error code or `HRESULT`.
        code: u32,
    },
    /// `profile_reparse_point`: the profile is a link (refused, D2).
    ProfileReparsePoint,
    /// `profile_not_a_file`.
    ProfileNotAFile,
    /// `profile_invalid`: too large, or it does not decode.
    ProfileInvalid,
    /// `method_unsupported`: `watch` before P3-4.
    MethodUnsupported,
    /// `path_mismatch`: Steam's first argument is not the profile's `start`.
    PathMismatch,
    /// `topology_unavailable`: the live topology could not be read.
    TopologyUnavailable,
    /// `topology_invalid`: the topology from Windows failed validation.
    TopologyInvalid,
    /// `selection_empty`: the rule selects nothing on this machine.
    SelectionEmpty,
    /// `mask_too_wide`: the selection does not fit this build's affinity mask.
    MaskTooWide,
    /// `spawn_failed:<code>`: the job or the suspended child could not be created.
    SpawnFailed {
        /// Win32 error code.
        code: u32,
    },
    /// `job_failed:<code>`: the job's group affinity could not be set.
    JobFailed {
        /// Win32 error code.
        code: u32,
    },
    /// `read_back_failed:<code>`.
    ReadBackFailed {
        /// Win32 error code.
        code: u32,
    },
    /// `mismatch`: the read-back before the resume differed from the selection.
    Mismatch,
    /// `cpu_sets_failed:<code>`.
    CpuSetsFailed {
        /// Win32 error code.
        code: u32,
    },
    /// `resume_failed:<code>`.
    ResumeFailed {
        /// Win32 error code.
        code: u32,
    },
    /// `elevation_required`: error 740, started through `ShellExecuteExW` without a rule.
    ElevationRequired,
}

/// How Steam's command was started on a skipped rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Start {
    /// `created`: `CreateProcessW`.
    Created,
    /// `shell`: `ShellExecuteExW` after 740.
    Shell,
    /// `shell_no_process`: `ShellExecuteExW` without a process handle.
    ShellNoProcess,
    /// `not_exe`: 740, but `argv[0]` is no `.exe`; nothing started.
    NotExe,
    /// `failed:<code>`: nothing started.
    Failed {
        /// Win32 error code.
        code: u32,
    },
}

/// How a child created with the rule was ended before the unchanged start.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Ended {
    /// `ended`.
    Ended,
    /// `failed:<code>`: `TerminateProcess` failed.
    Failed {
        /// Win32 error code.
        code: u32,
    },
    /// `not_confirmed:<code>`: terminated, but not seen ending.
    NotConfirmed {
        /// Win32 error code (258 for the timeout).
        code: u32,
    },
}

/// What is wrong with a result file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ResultErrorKind {
    /// More than [`MAX_RESULT_BYTES`].
    TooLarge,
    /// Not UTF-8.
    NotUtf8,
    /// The last line has no LF (also an empty file).
    NoFinalNewline,
    /// A CR.
    CarriageReturn,
    /// A control character other than LF.
    ControlChar,
    /// An empty line.
    EmptyLine,
    /// The first line is not `rerun-result <n>`.
    BadHeader,
    /// `rerun-result <n>` with `n` other than [`RESULT_FORMAT`].
    UnsupportedFormat(u32),
    /// The line is not `<expected>=…`.
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
    /// The values contradict each other (e.g. `rule=skipped:…` with `cpu=hard:…`).
    Inconsistent,
}

/// A rejected result file: the 1-based line (0: the file as a whole) and why.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResultError {
    /// 1-based line number, 0 for the whole file.
    pub line: usize,
    /// What is wrong.
    pub kind: ResultErrorKind,
}

impl fmt::Display for ResultError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use ResultErrorKind as K;
        if self.line > 0 {
            write!(f, "launch result line {}: ", self.line)?;
        } else {
            write!(f, "launch result: ")?;
        }
        match self.kind {
            K::TooLarge => write!(f, "larger than {MAX_RESULT_BYTES} bytes"),
            K::NotUtf8 => write!(f, "not UTF-8"),
            K::NoFinalNewline => write!(f, "the last line does not end with LF"),
            K::CarriageReturn => write!(f, "carriage return"),
            K::ControlChar => write!(f, "control character"),
            K::EmptyLine => write!(f, "empty line"),
            K::BadHeader => write!(f, "not a launch result"),
            K::UnsupportedFormat(n) => write!(f, "format {n}, this version reads {RESULT_FORMAT}"),
            K::UnexpectedKey { expected } => write!(f, "expected key {expected}"),
            K::Truncated { expected } => write!(f, "ends before key {expected}"),
            K::TrailingLine => write!(f, "line after the last key"),
            K::BadValue { key } => write!(f, "invalid value of {key}"),
            K::Inconsistent => write!(f, "the values contradict each other"),
        }
    }
}

impl std::error::Error for ResultError {}

const KEYS: [&str; 8] = [
    "profile", "time", "rule", "cpu", "priority", "check", "start", "ended",
];

impl SkipReason {
    /// The name in the file and in `rerun status` (without the code).
    pub fn name(self) -> &'static str {
        match self {
            Self::ProfileMissing => "profile_missing",
            Self::ProfileUnreadable { .. } => "profile_unreadable",
            Self::ProfileReparsePoint => "profile_reparse_point",
            Self::ProfileNotAFile => "profile_not_a_file",
            Self::ProfileInvalid => "profile_invalid",
            Self::MethodUnsupported => "method_unsupported",
            Self::PathMismatch => "path_mismatch",
            Self::TopologyUnavailable => "topology_unavailable",
            Self::TopologyInvalid => "topology_invalid",
            Self::SelectionEmpty => "selection_empty",
            Self::MaskTooWide => "mask_too_wide",
            Self::SpawnFailed { .. } => "spawn_failed",
            Self::JobFailed { .. } => "job_failed",
            Self::ReadBackFailed { .. } => "read_back_failed",
            Self::Mismatch => "mismatch",
            Self::CpuSetsFailed { .. } => "cpu_sets_failed",
            Self::ResumeFailed { .. } => "resume_failed",
            Self::ElevationRequired => "elevation_required",
        }
    }

    /// The code of the reasons that carry one.
    pub fn code(self) -> Option<u32> {
        match self {
            Self::ProfileUnreadable { code }
            | Self::SpawnFailed { code }
            | Self::JobFailed { code }
            | Self::ReadBackFailed { code }
            | Self::CpuSetsFailed { code }
            | Self::ResumeFailed { code } => Some(code),
            _ => None,
        }
    }

    fn parse(name: &str, code: Option<u32>) -> Option<Self> {
        let plain = match name {
            "profile_missing" => Some(Self::ProfileMissing),
            "profile_reparse_point" => Some(Self::ProfileReparsePoint),
            "profile_not_a_file" => Some(Self::ProfileNotAFile),
            "profile_invalid" => Some(Self::ProfileInvalid),
            "method_unsupported" => Some(Self::MethodUnsupported),
            "path_mismatch" => Some(Self::PathMismatch),
            "topology_unavailable" => Some(Self::TopologyUnavailable),
            "topology_invalid" => Some(Self::TopologyInvalid),
            "selection_empty" => Some(Self::SelectionEmpty),
            "mask_too_wide" => Some(Self::MaskTooWide),
            "mismatch" => Some(Self::Mismatch),
            "elevation_required" => Some(Self::ElevationRequired),
            _ => None,
        };
        if let Some(r) = plain {
            return code.is_none().then_some(r);
        }
        let code = code?;
        Some(match name {
            "profile_unreadable" => Self::ProfileUnreadable { code },
            "spawn_failed" => Self::SpawnFailed { code },
            "job_failed" => Self::JobFailed { code },
            "read_back_failed" => Self::ReadBackFailed { code },
            "cpu_sets_failed" => Self::CpuSetsFailed { code },
            "resume_failed" => Self::ResumeFailed { code },
            _ => return None,
        })
    }
}

impl fmt::Display for SkipReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.code() {
            Some(c) => write!(f, "{}:{c}", self.name()),
            None => f.write_str(self.name()),
        }
    }
}

fn priority_str(p: Option<Priority>) -> &'static str {
    match p {
        None => "none",
        Some(Priority::Normal) => "normal",
        Some(Priority::AboveNormal) => "above_normal",
        Some(Priority::High) => "high",
    }
}

fn cpu_str(c: Option<AppliedCpu>) -> String {
    match c {
        None => "none".to_owned(),
        Some(c) => {
            let mode = match c.mode {
                Mode::Hard => "hard",
                Mode::Soft => "soft",
            };
            format!("{mode}:{}:{}", c.threads, c.of)
        }
    }
}

fn check_str(c: Option<Check>) -> String {
    match c {
        None => "none".to_owned(),
        Some(Check::Ok) => "ok".to_owned(),
        Some(Check::Reset { cpu, priority }) => match (cpu, priority) {
            (true, true) => "reset:cpu_priority".to_owned(),
            (true, false) => "reset:cpu".to_owned(),
            // `(false, false)` is refused by `valid` before it is written.
            (false, _) => "reset:priority".to_owned(),
        },
        Some(Check::ExitedEarly) => "exited_early".to_owned(),
        Some(Check::Failed { code }) => format!("failed:{code}"),
    }
}

fn start_str(s: Start) -> String {
    match s {
        Start::Created => "created".to_owned(),
        Start::Shell => "shell".to_owned(),
        Start::ShellNoProcess => "shell_no_process".to_owned(),
        Start::NotExe => "not_exe".to_owned(),
        Start::Failed { code } => format!("failed:{code}"),
    }
}

fn ended_str(e: Option<Ended>) -> String {
    match e {
        None => "none".to_owned(),
        Some(Ended::Ended) => "ended".to_owned(),
        Some(Ended::Failed { code }) => format!("failed:{code}"),
        Some(Ended::NotConfirmed { code }) => format!("not_confirmed:{code}"),
    }
}

/// The values a file of `r` holds, in key order.
fn values(r: &LaunchResult) -> [String; 8] {
    let (rule, cpu, priority, check, start, ended) = match &r.outcome {
        Outcome::Applied {
            cpu,
            priority,
            check,
        } => (
            "applied".to_owned(),
            cpu_str(*cpu),
            priority_str(*priority),
            check_str(Some(*check)),
            start_str(Start::Created),
            ended_str(None),
        ),
        Outcome::Skipped {
            reason,
            start,
            ended,
        } => (
            format!("skipped:{reason}"),
            cpu_str(None),
            priority_str(None),
            check_str(None),
            start_str(*start),
            ended_str(*ended),
        ),
    };
    [
        r.profile.to_string(),
        r.unix_s.to_string(),
        rule,
        cpu,
        priority.to_owned(),
        check,
        start,
        ended,
    ]
}

/// The invariants a value must meet: `1 <= threads <= of <= 4096`; a reset names at least one
/// thing and only things that were set.
fn valid(r: &LaunchResult) -> bool {
    match &r.outcome {
        Outcome::Applied {
            cpu,
            priority,
            check,
        } => {
            let cpu_ok = cpu.is_none_or(|c| {
                c.threads >= 1 && c.threads <= c.of && usize::from(c.of) <= MAX_LOGICAL_CPUS
            });
            let check_ok = match check {
                Check::Reset {
                    cpu: c,
                    priority: p,
                } => (*c || *p) && (!*c || cpu.is_some()) && (!*p || priority.is_some()),
                _ => true,
            };
            cpu_ok && check_ok
        }
        Outcome::Skipped { .. } => true,
    }
}

/// Encodes `r`. Fails (`Inconsistent`) for a value no file may hold (threads 0 or above `of`,
/// a reset of nothing or of something not set), and checks its output with [`decode`].
pub fn encode(r: &LaunchResult) -> Result<Vec<u8>, ResultError> {
    if !valid(r) {
        return Err(ResultError {
            line: 0,
            kind: ResultErrorKind::Inconsistent,
        });
    }
    let mut s = format!("{HEADER}{RESULT_FORMAT}\n");
    for (k, v) in KEYS.iter().zip(values(r)) {
        s.push_str(k);
        s.push('=');
        s.push_str(&v);
        s.push('\n');
    }
    let bytes = s.into_bytes();
    let back = decode(&bytes)?;
    if &back == r {
        Ok(bytes)
    } else {
        // Unreachable for a correct codec; never hand out bytes that read back differently.
        Err(ResultError {
            line: 0,
            kind: ResultErrorKind::Inconsistent,
        })
    }
}

/// Decodes a result file. Bounded and strict, see the module documentation.
pub fn decode(bytes: &[u8]) -> Result<LaunchResult, ResultError> {
    let whole = |kind| ResultError { line: 0, kind };
    if bytes.len() > MAX_RESULT_BYTES {
        return Err(whole(ResultErrorKind::TooLarge));
    }
    let text = std::str::from_utf8(bytes).map_err(|_| whole(ResultErrorKind::NotUtf8))?;
    let body = text
        .strip_suffix('\n')
        .ok_or(whole(ResultErrorKind::NoFinalNewline))?;
    let lines: Vec<&str> = body.split('\n').collect();
    for (n, l) in lines.iter().enumerate() {
        let at = |kind| ResultError { line: n + 1, kind };
        if l.contains('\r') {
            return Err(at(ResultErrorKind::CarriageReturn));
        }
        if l.chars().any(char::is_control) {
            return Err(at(ResultErrorKind::ControlChar));
        }
        if l.is_empty() {
            return Err(at(ResultErrorKind::EmptyLine));
        }
    }
    let header = lines.first().copied().unwrap_or_default();
    let version = header
        .strip_prefix(HEADER)
        .and_then(|v| number(v, 9))
        .ok_or(ResultError {
            line: 1,
            kind: ResultErrorKind::BadHeader,
        })?;
    if version != u64::from(RESULT_FORMAT) {
        return Err(ResultError {
            line: 1,
            kind: ResultErrorKind::UnsupportedFormat(u32::try_from(version).unwrap_or(u32::MAX)),
        });
    }
    let mut v: [&str; 8] = [""; 8];
    for (i, key) in KEYS.iter().enumerate() {
        let n = i + 2;
        let line = lines.get(i + 1).ok_or(ResultError {
            line: n,
            kind: ResultErrorKind::Truncated { expected: key },
        })?;
        v[i] = line
            .strip_prefix(key)
            .and_then(|r| r.strip_prefix('='))
            .ok_or(ResultError {
                line: n,
                kind: ResultErrorKind::UnexpectedKey { expected: key },
            })?;
    }
    if lines.len() > KEYS.len() + 1 {
        return Err(ResultError {
            line: KEYS.len() + 2,
            kind: ResultErrorKind::TrailingLine,
        });
    }
    let bad = |i: usize| ResultError {
        line: i + 2,
        kind: ResultErrorKind::BadValue { key: KEYS[i] },
    };
    let profile = ProfileId::from_hex(v[0]).ok_or(bad(0))?;
    let unix_s = number(v[1], 20).ok_or(bad(1))?;
    let rule = parse_rule(v[2]).ok_or(bad(2))?;
    let cpu = parse_cpu(v[3]).ok_or(bad(3))?;
    let priority = parse_priority(v[4]).ok_or(bad(4))?;
    let check = parse_check(v[5]).ok_or(bad(5))?;
    let start = parse_start(v[6]).ok_or(bad(6))?;
    let ended = parse_ended(v[7]).ok_or(bad(7))?;
    let outcome = match rule {
        None => Outcome::Applied {
            cpu,
            priority,
            check: check.ok_or(whole(ResultErrorKind::Inconsistent))?,
        },
        Some(reason) => Outcome::Skipped {
            reason,
            start,
            ended,
        },
    };
    let r = LaunchResult {
        profile,
        unix_s,
        outcome,
    };
    // Every value parsed; the combination must be one a writer emits: the same bytes back.
    if !valid(&r) || values(&r) != v.map(str::to_owned) {
        return Err(whole(ResultErrorKind::Inconsistent));
    }
    Ok(r)
}

/// A canonical decimal number: digits only, no sign, no leading zero (`0` alone is allowed),
/// at most `max_digits` digits, fitting `u64`.
fn number(v: &str, max_digits: usize) -> Option<u64> {
    let b = v.as_bytes();
    if b.is_empty() || b.len() > max_digits || !b.iter().all(u8::is_ascii_digit) {
        return None;
    }
    if b.len() > 1 && b[0] == b'0' {
        return None;
    }
    v.parse().ok()
}

/// A Win32 code: a canonical `u32`.
fn code(v: &str) -> Option<u32> {
    number(v, 10).and_then(|n| u32::try_from(n).ok())
}

/// `applied` → `None`; `skipped:<reason>[:<code>]` → the reason.
fn parse_rule(v: &str) -> Option<Option<SkipReason>> {
    if v == "applied" {
        return Some(None);
    }
    let rest = v.strip_prefix("skipped:")?;
    let (name, c) = match rest.split_once(':') {
        Some((name, c)) => (name, Some(code(c)?)),
        None => (rest, None),
    };
    SkipReason::parse(name, c).map(Some)
}

fn parse_cpu(v: &str) -> Option<Option<AppliedCpu>> {
    if v == "none" {
        return Some(None);
    }
    let mut parts = v.split(':');
    let mode = match parts.next()? {
        "hard" => Mode::Hard,
        "soft" => Mode::Soft,
        _ => return None,
    };
    let threads = u16::try_from(number(parts.next()?, 4)?).ok()?;
    let of = u16::try_from(number(parts.next()?, 4)?).ok()?;
    if parts.next().is_some() {
        return None;
    }
    Some(Some(AppliedCpu { mode, threads, of }))
}

fn parse_priority(v: &str) -> Option<Option<Priority>> {
    match v {
        "none" => Some(None),
        "normal" => Some(Some(Priority::Normal)),
        "above_normal" => Some(Some(Priority::AboveNormal)),
        "high" => Some(Some(Priority::High)),
        _ => None,
    }
}

fn parse_check(v: &str) -> Option<Option<Check>> {
    Some(Some(match v {
        "none" => return Some(None),
        "ok" => Check::Ok,
        "reset:cpu" => Check::Reset {
            cpu: true,
            priority: false,
        },
        "reset:priority" => Check::Reset {
            cpu: false,
            priority: true,
        },
        "reset:cpu_priority" => Check::Reset {
            cpu: true,
            priority: true,
        },
        "exited_early" => Check::ExitedEarly,
        _ => Check::Failed {
            code: code(v.strip_prefix("failed:")?)?,
        },
    }))
}

fn parse_start(v: &str) -> Option<Start> {
    Some(match v {
        "created" => Start::Created,
        "shell" => Start::Shell,
        "shell_no_process" => Start::ShellNoProcess,
        "not_exe" => Start::NotExe,
        _ => Start::Failed {
            code: code(v.strip_prefix("failed:")?)?,
        },
    })
}

fn parse_ended(v: &str) -> Option<Option<Ended>> {
    Some(Some(match v {
        "none" => return Some(None),
        "ended" => Ended::Ended,
        _ => {
            if let Some(c) = v.strip_prefix("failed:") {
                Ended::Failed { code: code(c)? }
            } else {
                Ended::NotConfirmed {
                    code: code(v.strip_prefix("not_confirmed:")?)?,
                }
            }
        }
    }))
}

#[cfg(test)]
mod tests;
