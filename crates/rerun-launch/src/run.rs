//! What the shim does with its command line (ADR 0022): decide whether the profile's rule
//! applies, start Steam's command with or without it, wait for it, pass the exit code on.
//!
//! - Fail closed for the rule, fail open for the start (D3): every problem on the way to the
//!   rule ends in one start of Steam's command **unchanged** (no job, no limit, no priority).
//! - `lpApplicationName` is always Steam's `argv[0]`, `lpCommandLine` always the raw tail (M2).
//! - An elevated shim reads nothing and sets nothing (M1).
//! - Error 740 starts the command through `ShellExecuteExW`, without a rule (B2).
//!
//! The [`Report`] is what the result file (P3-2) will record; nothing is written yet.

use rerun_proto::cpu::rule::{Mode, SelectError, select};
use rerun_proto::profile::{
    LaunchProfile, MAX_PROFILE_BYTES, Method, Priority, ProfileError, ProfileId, decode,
};

use crate::cmdline::{self, Command, Usage};
use crate::os::{GroupAffinity, Os, OsError, Spawn, Terminated};

/// winerror.h `ERROR_ELEVATION_REQUIRED`.
pub(crate) const ERROR_ELEVATION_REQUIRED: u32 = 740;

/// Exit code: the DLL search restriction failed (ADR 0008, fail closed; set in `main`).
pub(crate) const EXIT_HARDENING: u32 = 1;
/// Exit code: the shim's own command line is unusable, nothing started (B1, M2).
pub(crate) const EXIT_USAGE: u32 = 2;
/// Exit code: Steam's command could not be started, or its exit code could not be read.
pub(crate) const EXIT_NOT_STARTED: u32 = 3;

/// Why the rule was not applied. Never carries the profile's content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Skip {
    /// The shim counts as elevated (M1): the profile was not read.
    Elevated,
    /// The token after `--profile` is not 32 lower-case hex digits.
    ProfileId,
    /// The profile could not be read (missing, reparse point, access denied, …).
    ProfileUnreadable(OsError),
    /// The profile is too large or does not decode.
    ProfileInvalid(Option<ProfileError>),
    /// The profile's method is not `direct` (`watch` arrives in P3-4).
    Method(Method),
    /// Steam's `argv[0]` is not the profile's `start` (`path_mismatch`).
    PathMismatch,
    /// The live topology could not be read.
    Topology(OsError),
    /// The rule selects nothing on this machine, or the topology is invalid.
    Select(SelectError),
    /// The selection's mask does not fit this build's `KAFFINITY`.
    MaskWidth,
    /// Creating the job or the suspended child failed.
    Spawn(u32),
    /// `JobObjectGroupInformationEx` could not be set.
    Job(u32),
    /// The job or the thread could not be read back.
    ReadBack(u32),
    /// The read-back differs from the selection.
    Mismatch,
    /// `SetProcessDefaultCpuSets` failed.
    CpuSets(u32),
    /// `ResumeThread` failed.
    Resume(u32),
    /// `CreateProcessW` reported 740 (`elevation_required`).
    ElevationRequired,
}

/// What became of the profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Rule {
    /// Applied to the started process.
    Applied {
        /// The CPU limit, if the profile has a rule.
        cpu: Option<Applied>,
        /// The priority class, if the profile sets one.
        priority: Option<Priority>,
    },
    /// Not applied: Steam's command was started unchanged.
    Skipped(Skip),
}

/// A CPU limit that was set (and, for `hard`, read back).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Applied {
    /// Hard (job) or soft (CPU Sets).
    pub(crate) mode: Mode,
    /// Selected logical processors.
    pub(crate) threads: u16,
    /// Logical processors of the machine.
    pub(crate) of: u16,
}

/// How Steam's command was started.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Start {
    /// `CreateProcessW`; the exit code is the child's.
    Created,
    /// `ShellExecuteExW` after 740; the exit code is the child's.
    ShellExecuted,
    /// `ShellExecuteExW` succeeded without a process handle; exit code 0.
    ShellWithoutProcess,
    /// 740, but `argv[0]` is not an `.exe`: nothing started.
    NotExe,
    /// The start failed with this Win32 error code.
    Failed(u32),
    /// Started, but waiting or reading the exit code failed with this Win32 error code.
    WaitFailed(u32),
}

/// The outcome of one run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Report {
    /// The command line is unusable; nothing started (exit code 2).
    Usage(Usage),
    /// Steam's command was handled.
    Ran {
        /// The profile ID from the command line, if the token is one (the name of the result
        /// file, P3-2; also when the shim is elevated, which writes nothing, B13).
        profile: Option<ProfileId>,
        /// What became of the profile.
        rule: Rule,
        /// How the command was started.
        start: Start,
        /// The shim's exit code.
        exit: u32,
        /// A child created with the rule that had to be ended before the unchanged start.
        terminated: Option<Terminated>,
    },
}

/// A `Report::Ran` without profile ID and termination (filled in by [`run`]).
fn ran(rule: Rule, start: Start, exit: u32) -> Report {
    Report::Ran {
        profile: None,
        rule,
        start,
        exit,
        terminated: None,
    }
}

impl Report {
    /// The shim's exit code.
    pub(crate) fn exit_code(&self) -> u32 {
        match self {
            Self::Usage(_) => EXIT_USAGE,
            Self::Ran { exit, .. } => *exit,
        }
    }
}

/// The plan for the start, decided before any process exists.
enum Plan {
    /// Start with these settings.
    Rule {
        limit: Option<(Limit, Applied)>,
        priority: Option<Priority>,
    },
    /// Start unchanged.
    Unchanged(Skip),
}

/// The CPU limit of a plan.
enum Limit {
    Hard(GroupAffinity),
    Soft(Vec<u32>),
}

/// The shim's whole run on `os`.
pub(crate) fn run<O: Os>(os: &O) -> Report {
    let line = os.command_line();
    let cmd = match cmdline::parse(&line) {
        Ok(c) => c,
        Err(u) => return Report::Usage(u),
    };
    let id = String::from_utf16(cmd.token)
        .ok()
        .and_then(|t| ProfileId::from_hex(&t));
    let plan = if os.elevated() {
        Plan::Unchanged(Skip::Elevated)
    } else {
        decide(os, &cmd, id)
    };
    let mut report = match plan {
        Plan::Unchanged(skip) => unchanged(os, &cmd, skip),
        Plan::Rule { limit, priority } => with_rule(os, &cmd, limit, priority),
    };
    if let Report::Ran { profile, .. } = &mut report {
        *profile = id;
    }
    report
}

/// Reads the profile and the topology and selects the processors (non-elevated only).
fn decide<O: Os>(os: &O, cmd: &Command<'_>, id: Option<ProfileId>) -> Plan {
    let Some(id) = id else {
        return Plan::Unchanged(Skip::ProfileId);
    };
    let bytes = match os.read_profile(&id) {
        Ok(b) => b,
        Err(e) => return Plan::Unchanged(Skip::ProfileUnreadable(e)),
    };
    if bytes.len() > MAX_PROFILE_BYTES {
        return Plan::Unchanged(Skip::ProfileInvalid(None));
    }
    let profile = match decode(&bytes) {
        Ok(p) => p,
        Err(e) => return Plan::Unchanged(Skip::ProfileInvalid(Some(e))),
    };
    if profile.method != Method::Direct {
        return Plan::Unchanged(Skip::Method(profile.method));
    }
    if !os.same_path(cmd.app, &profile.start) {
        return Plan::Unchanged(Skip::PathMismatch);
    }
    match limit_of(os, &profile) {
        Ok(limit) => Plan::Rule {
            limit,
            priority: profile.priority,
        },
        Err(skip) => Plan::Unchanged(skip),
    }
}

/// The CPU limit of the profile on this machine.
fn limit_of<O: Os>(os: &O, profile: &LaunchProfile) -> Result<Option<(Limit, Applied)>, Skip> {
    let Some(rule) = profile.cpu else {
        return Ok(None);
    };
    let topology = os.topology().map_err(Skip::Topology)?;
    let sel = select(&topology, &rule, profile.bitness).map_err(Skip::Select)?;
    let applied = Applied {
        mode: rule.mode,
        threads: sel.threads,
        of: sel.of,
    };
    let limit = match rule.mode {
        Mode::Hard => {
            // A 32-bit build's KAFFINITY has 32 bits (its topology is unsupported anyway).
            if usize::try_from(sel.mask).is_err() {
                return Err(Skip::MaskWidth);
            }
            Limit::Hard(GroupAffinity {
                group: sel.group,
                mask: sel.mask,
            })
        }
        Mode::Soft => Limit::Soft(sel.cpu_set_ids),
    };
    Ok(Some((limit, applied)))
}

/// Starts with the profile's settings; any failure ends in one unchanged start.
fn with_rule<O: Os>(
    os: &O,
    cmd: &Command<'_>,
    limit: Option<(Limit, Applied)>,
    priority: Option<Priority>,
) -> Report {
    let (spawn, applied) = match &limit {
        None => (
            Spawn {
                in_job: false,
                suspended: false,
                priority,
            },
            None,
        ),
        Some((Limit::Hard(_), a)) => (
            Spawn {
                in_job: true,
                suspended: true,
                priority,
            },
            Some(*a),
        ),
        Some((Limit::Soft(_), a)) => (
            Spawn {
                in_job: false,
                suspended: true,
                priority,
            },
            Some(*a),
        ),
    };
    let child = match os.spawn(cmd.app, cmd.tail, &spawn) {
        Ok(c) => c,
        Err(ERROR_ELEVATION_REQUIRED) => {
            return shell(os, cmd, Rule::Skipped(Skip::ElevationRequired));
        }
        Err(code) => return unchanged(os, cmd, Skip::Spawn(code)),
    };
    let prepared = match &limit {
        None => Ok(()),
        Some((Limit::Hard(ga), _)) => hard(os, &child, *ga),
        Some((Limit::Soft(ids), _)) => os.set_cpu_sets(&child, ids).map_err(Skip::CpuSets),
    };
    let resumed = prepared.and_then(|()| {
        if spawn.suspended {
            os.resume(&child).map_err(Skip::Resume)
        } else {
            Ok(())
        }
    });
    if let Err(skip) = resumed {
        let ended = os.terminate(child);
        let mut report = unchanged(os, cmd, skip);
        if let Report::Ran { terminated, .. } = &mut report {
            *terminated = Some(ended);
        }
        return report;
    }
    let rule = Rule::Applied {
        cpu: applied,
        priority,
    };
    wait(os, child, rule, Start::Created)
}

/// Steps 3 and 4 of B-2 on the suspended child in its job.
fn hard<O: Os>(os: &O, child: &O::Child, ga: GroupAffinity) -> Result<(), Skip> {
    os.limit_job(child, ga).map_err(Skip::Job)?;
    let back = os.read_back(child).map_err(Skip::ReadBack)?;
    if back.job != [ga] || back.thread != ga {
        return Err(Skip::Mismatch);
    }
    Ok(())
}

/// Steam's command, unchanged; 740 goes to `ShellExecuteExW`.
fn unchanged<O: Os>(os: &O, cmd: &Command<'_>, skip: Skip) -> Report {
    match os.spawn(cmd.app, cmd.tail, &Spawn::UNCHANGED) {
        Ok(child) => wait(os, child, Rule::Skipped(skip), Start::Created),
        Err(ERROR_ELEVATION_REQUIRED) => shell(os, cmd, Rule::Skipped(skip)),
        Err(code) => ran(Rule::Skipped(skip), Start::Failed(code), EXIT_NOT_STARTED),
    }
}

/// B2: the same `argv[0]` and the raw parameters through `ShellExecuteExW`, `.exe` only.
fn shell<O: Os>(os: &O, cmd: &Command<'_>, rule: Rule) -> Report {
    if !cmdline::ends_with_exe(cmd.app) {
        return ran(rule, Start::NotExe, EXIT_NOT_STARTED);
    }
    match os.shell_execute(cmd.app, cmd.parameters) {
        Ok(Some(child)) => wait(os, child, rule, Start::ShellExecuted),
        Ok(None) => ran(rule, Start::ShellWithoutProcess, 0),
        Err(code) => ran(rule, Start::Failed(code), EXIT_NOT_STARTED),
    }
}

/// B3: wait for the direct child, pass its exit code on.
fn wait<O: Os>(os: &O, child: O::Child, rule: Rule, start: Start) -> Report {
    match os.wait(child) {
        Ok(exit) => ran(rule, start, exit),
        Err(code) => ran(rule, Start::WaitFailed(code), EXIT_NOT_STARTED),
    }
}

#[cfg(test)]
mod tests;
