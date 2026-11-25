//! What the shim does with its command line (ADR 0022): decide whether the profile's rule
//! applies, start Steam's command with or without it, check the rule, record the outcome, wait
//! for the command, pass its exit code on.
//!
//! - Fail closed for the rule, fail open for the start (D3): every problem on the way to the
//!   rule ends in one start of Steam's command **unchanged** (no job, no limit, no priority, no
//!   `run`, no `args`).
//! - `lpApplicationName` is Steam's `argv[0]`, `lpCommandLine` the raw tail (M2), with exactly
//!   one exception (ADR 0022 amendment P5-OE): when `argv[0]` is the profile's `start` and the
//!   profile has `run`, the shim starts `run` with the rule instead: `lpApplicationName` is
//!   `run`, `lpCommandLine` is `"<run>"` followed by the raw tail after `argv[0]`, byte for
//!   byte ([`with_run`]). The profile's `args` are appended to that command line after one
//!   space. A `run` that cannot be started records `run_failed:<code>` and starts Steam's
//!   command unchanged. Nothing else starts `run`: no profile, an invalid one, `path_mismatch`
//!   (which records the file name of `argv[0]`, `steam_start`), an elevated shim and every
//!   other D3 fallback start Steam's command exactly as before.
//! - An elevated shim reads nothing, sets nothing and writes nothing (M1, B13).
//! - Error 740 starts the program the rule was for (Steam's `argv[0]`, or `run`, with `args`)
//!   through `ShellExecuteExW`, without a rule (B2).
//! - Post-launch check (P3-2, docs/04): with the rule applied, the shim waits up to
//!   [`CHECK_DELAY_MS`] on the running child and then reads what Windows reports: the job's
//!   group affinity and the process's affinity (hard), the default CPU Sets (soft), the
//!   priority class (D6 addition).
//! - Result file (P3-2, D5): exactly one record per start that has a profile ID, written
//!   **before** the long wait for the game, on every path: after the check, after an unchanged
//!   start, after a failed start. With the rule applied it is written after the check, so
//!   ending the shim (Steam's "Stop") within the first 5 s loses it; later it is on disk. A
//!   failed write changes nothing else: not the start, not the exit code.
//! - `watch` (P3-4, [`watch`]): Steam's command starts unchanged; the rule is set on the game
//!   process found after it, checked there, and recorded once before the wait for the command.

use std::borrow::Borrow;

use rerun_proto::cpu::rule::{Mode, SelectError, select};
use rerun_proto::launch::{self, AppliedCpu, Check, Ended, LaunchResult, Outcome, SkipReason};
use rerun_proto::profile::{
    LaunchArg, LaunchProfile, MAX_PROFILE_BYTES, Method, Priority, ProfileError, ProfileId,
    args_value, decode,
};

use crate::cmdline::{self, Command, Usage};
use crate::os::{GroupAffinity, Os, OsError, Spawn, Terminated, priority_class};

/// winerror.h `ERROR_ELEVATION_REQUIRED`.
pub(crate) const ERROR_ELEVATION_REQUIRED: u32 = 740;
/// winerror.h `ERROR_FILE_NOT_FOUND` and `ERROR_PATH_NOT_FOUND`: the profile is missing.
const ERROR_FILE_NOT_FOUND: u32 = 2;
const ERROR_PATH_NOT_FOUND: u32 = 3;

/// Exit code: the DLL search restriction failed (ADR 0008, fail closed; set in `main`).
pub(crate) const EXIT_HARDENING: u32 = 1;
/// Exit code: the shim's own command line is unusable, nothing started (B1, M2).
pub(crate) const EXIT_USAGE: u32 = 2;
/// Exit code: Steam's command could not be started, or its exit code could not be read.
pub(crate) const EXIT_NOT_STARTED: u32 = 3;

/// How long the post-launch check waits on the started process (docs/04: "about 5 s").
pub(crate) const CHECK_DELAY_MS: u32 = 5_000;

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
    /// The profile's `run` could not be started (the job or `CreateProcessW` failed other than
    /// with 740); Steam's command was started unchanged.
    RunFailed(u32),
    /// `watch`: no new process of the target appeared before the timeout.
    TargetNotFound,
    /// `watch`: the target runs at a higher integrity level than the shim (M1).
    TargetElevated,
    /// `watch`: the target could not be opened with the rights to set the rule or read back,
    /// or (search end) the only candidates could not be opened or read.
    TargetDenied(u32),
    /// `watch`: no process snapshot during the whole search, or the shim's own facts could
    /// not be read before the start.
    SearchFailed(u32),
    /// `watch`: the target's priority class could not be read or set; nothing was set.
    Priority(u32),
    /// `watch`: the target joined the job, but its process affinity right after is not the
    /// selection (a job it already was in keeps another limit). The membership stays.
    JobIneffective,
}

impl Skip {
    /// The reason in the result file; `None` for the two skips that write none (elevated: B13;
    /// no profile ID: no file name).
    fn reason(&self) -> Option<SkipReason> {
        Some(match self {
            Self::Elevated | Self::ProfileId => return None,
            Self::ProfileUnreadable(e) => match e {
                OsError::Win32(ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND) => {
                    SkipReason::ProfileMissing
                }
                OsError::Win32(code) => SkipReason::ProfileUnreadable { code: *code },
                OsError::HResult(hr) => SkipReason::ProfileUnreadable {
                    code: hr.cast_unsigned(),
                },
                OsError::ReparsePoint => SkipReason::ProfileReparsePoint,
                OsError::NotAFile => SkipReason::ProfileNotAFile,
                _ => SkipReason::ProfileUnreadable { code: 0 },
            },
            Self::ProfileInvalid(_) => SkipReason::ProfileInvalid,
            Self::PathMismatch => SkipReason::PathMismatch,
            Self::Topology(_) => SkipReason::TopologyUnavailable,
            Self::Select(SelectError::Invalid(_)) => SkipReason::TopologyInvalid,
            Self::Select(SelectError::Empty { .. }) => SkipReason::SelectionEmpty,
            Self::MaskWidth => SkipReason::MaskTooWide,
            Self::Spawn(code) => SkipReason::SpawnFailed { code: *code },
            Self::Job(code) => SkipReason::JobFailed { code: *code },
            Self::ReadBack(code) => SkipReason::ReadBackFailed { code: *code },
            Self::Mismatch => SkipReason::Mismatch,
            Self::CpuSets(code) => SkipReason::CpuSetsFailed { code: *code },
            Self::Resume(code) => SkipReason::ResumeFailed { code: *code },
            Self::ElevationRequired => SkipReason::ElevationRequired,
            Self::RunFailed(code) => SkipReason::RunFailed { code: *code },
            Self::TargetNotFound => SkipReason::TargetNotFound,
            Self::TargetElevated => SkipReason::TargetElevated,
            Self::TargetDenied(code) => SkipReason::TargetDenied { code: *code },
            Self::SearchFailed(code) => SkipReason::SearchFailed { code: *code },
            Self::Priority(code) => SkipReason::PriorityFailed { code: *code },
            Self::JobIneffective => SkipReason::JobIneffective,
        })
    }
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

impl Start {
    /// The start in the result file (written before the wait, so never `WaitFailed` there).
    fn recorded(self) -> launch::Start {
        match self {
            Self::Created | Self::WaitFailed(_) => launch::Start::Created,
            Self::ShellExecuted => launch::Start::Shell,
            Self::ShellWithoutProcess => launch::Start::ShellNoProcess,
            Self::NotExe => launch::Start::NotExe,
            Self::Failed(code) => launch::Start::Failed { code },
        }
    }
}

fn ended(t: Terminated) -> Ended {
    match t {
        Terminated::Ended => Ended::Ended,
        Terminated::Failed(code) => Ended::Failed { code },
        Terminated::NotConfirmed(code) => Ended::NotConfirmed { code },
    }
}

/// What happened to the result file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Written {
    /// Not attempted: elevated (B13), or no profile ID (no file name).
    No,
    /// Written.
    Yes,
    /// The write failed (nothing else changes).
    Failed(OsError),
}

/// The outcome of one run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Report {
    /// The command line is unusable; nothing started (exit code 2).
    Usage(Usage),
    /// Steam's command was handled.
    Ran {
        /// The profile ID from the command line, if the token is one (the name of the result
        /// file; also when the shim is elevated, which writes nothing, B13).
        profile: Option<ProfileId>,
        /// What became of the profile.
        rule: Rule,
        /// How the command was started.
        start: Start,
        /// The shim's exit code.
        exit: u32,
        /// A child created with the rule that had to be ended before the unchanged start.
        terminated: Option<Terminated>,
        /// The post-launch check (only with the rule applied).
        check: Option<Check>,
        /// `watch`: putting the target's priority class back failed with this code (A4).
        priority_restore: Option<u32>,
        /// The result file.
        written: Written,
    },
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
pub(crate) enum Plan {
    /// Start `launch` with these settings.
    Rule {
        limit: Option<(Limit, Applied)>,
        priority: Option<Priority>,
        launch: OwnedCommand,
    },
    /// `watch`: start unchanged, then find the target and set the rule there.
    Watch(watch::Watch),
    /// Start unchanged.
    Unchanged(Skip),
}

/// What the shim starts with the rule (ADR 0022 amendment P5-OE): Steam's command, or the
/// profile's `run` in its place, with the profile's `args` appended. Built by [`with_run`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OwnedCommand {
    /// `lpApplicationName`: Steam's `argv[0]`, or `run`.
    pub(crate) app: Vec<u16>,
    /// `lpCommandLine`.
    pub(crate) line: Vec<u16>,
    /// `lpParameters` of the `ShellExecuteExW` fallback (B2).
    pub(crate) parameters: Option<Vec<u16>>,
    /// `app` is the profile's `run`.
    pub(crate) run: bool,
}

/// The command the rule is for (pure): with `run`, `lpApplicationName` is `run` and the command
/// line `"<run>"` followed by the raw tail after Steam's `argv[0]` (from right after its closing
/// quote, or from the blank that ended it), byte for byte; without, Steam's command as it is.
/// `args` (no quote, space or `%`, `rerun_proto::profile::LaunchArg`) follow after one space,
/// on the command line and on the parameters of the 740 fallback.
pub(crate) fn with_run(cmd: &Command<'_>, run: Option<&str>, args: &[LaunchArg]) -> OwnedCommand {
    let (app, mut line) = match run {
        Some(run) => {
            let run: Vec<u16> = run.encode_utf16().collect();
            let (_, rest) = cmdline::split_argv0(cmd.tail);
            let mut line = Vec::with_capacity(run.len() + 2 + rest.len());
            line.push(u16::from(b'"'));
            line.extend_from_slice(&run);
            line.push(u16::from(b'"'));
            line.extend_from_slice(rest);
            (run, line)
        }
        None => (cmd.app.to_vec(), cmd.tail.to_vec()),
    };
    let mut parameters = cmd.parameters.map(<[u16]>::to_vec);
    if !args.is_empty() {
        let args: Vec<u16> = args_value(args).encode_utf16().collect();
        line.push(u16::from(b' '));
        line.extend_from_slice(&args);
        parameters = Some(match parameters {
            Some(mut p) => {
                p.push(u16::from(b' '));
                p.extend_from_slice(&args);
                p
            }
            None => args,
        });
    }
    OwnedCommand {
        app,
        line,
        parameters,
        run: run.is_some(),
    }
}

/// The CPU limit of a plan.
pub(crate) enum Limit {
    Hard(GroupAffinity),
    Soft(Vec<u32>),
}

/// Who may write the result file of this run.
struct Ctx {
    /// The profile ID, if the token is one.
    id: Option<ProfileId>,
    /// The shim counts as elevated (M1): no result file (B13).
    elevated: bool,
    /// The profile's method, once the profile decoded (the result's `method=` line).
    method: Option<Method>,
    /// `path_mismatch` only: the file name of Steam's `argv[0]` (S5), if it is a valid one.
    steam_start: Option<String>,
}

/// What one run started and recorded, before the wait.
struct Done<C> {
    rule: Rule,
    start: Start,
    terminated: Option<Terminated>,
    check: Option<Check>,
    /// The child to wait for; `None` if nothing (waitable) was started.
    child: Option<C>,
    /// The exit code without a child.
    exit: u32,
    /// `watch`: putting the target's priority class back failed with this code (A4).
    restore: Option<u32>,
    /// The started program is the profile's `run` (the result's `run=yes`).
    run: bool,
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
    let elevated = os.elevated();
    let (plan, method) = if elevated {
        (Plan::Unchanged(Skip::Elevated), None)
    } else {
        match profile(os, id) {
            Ok(p) => (decide(os, &cmd, &p), Some(p.method)),
            Err(skip) => (Plan::Unchanged(skip), None),
        }
    };
    // S5: what Steam started instead, as a file name only (the folder never leaves the shim).
    let steam_start = match &plan {
        Plan::Unchanged(Skip::PathMismatch) => String::from_utf16(cmd.app)
            .ok()
            .and_then(|a| launch::steam_start_name(&a)),
        _ => None,
    };
    let ctx = Ctx {
        id,
        elevated,
        method,
        steam_start,
    };
    let done = match plan {
        Plan::Unchanged(skip) => unchanged(os, &cmd, skip, None),
        Plan::Rule {
            limit,
            priority,
            launch,
        } => with_rule(os, &cmd, &launch, limit, priority),
        Plan::Watch(w) => watch::start(os, &cmd, &w),
    };
    finish(os, &ctx, done)
}

/// Records the run (B13: never when elevated), then waits for the child (B3).
fn finish<O: Os>(os: &O, ctx: &Ctx, done: Done<O::Child>) -> Report {
    let written = record(os, ctx, &done);
    let (start, exit) = match done.child {
        None => (done.start, done.exit),
        Some(child) => match os.wait(child) {
            Ok(exit) => (done.start, exit),
            Err(code) => (Start::WaitFailed(code), EXIT_NOT_STARTED),
        },
    };
    Report::Ran {
        profile: ctx.id,
        rule: done.rule,
        start,
        exit,
        terminated: done.terminated,
        check: done.check,
        priority_restore: done.restore,
        written,
    }
}

/// Writes the result file of `done`, if this run may write one.
fn record<O: Os, C>(os: &O, ctx: &Ctx, done: &Done<C>) -> Written {
    if ctx.elevated {
        return Written::No;
    }
    let Some(id) = ctx.id else {
        return Written::No;
    };
    let outcome = match &done.rule {
        Rule::Applied { cpu, priority } => Outcome::Applied {
            cpu: cpu.map(|a| AppliedCpu {
                mode: a.mode,
                threads: a.threads,
                of: a.of,
            }),
            priority: *priority,
            // `with_rule` always sets the check; a missing one is never shown as verified.
            check: done.check.unwrap_or(Check::Failed { code: 0 }),
        },
        Rule::Skipped(skip) => {
            let Some(reason) = skip.reason() else {
                return Written::No;
            };
            Outcome::Skipped {
                reason,
                start: done.start.recorded(),
                ended: done.terminated.map(ended),
                priority_restore: done.restore,
            }
        }
    };
    let result = LaunchResult {
        profile: id,
        unix_s: os.now_unix_s(),
        outcome,
        method: ctx.method,
        run: done.run,
        steam_start: ctx.steam_start.clone(),
    };
    let Ok(bytes) = launch::encode(&result) else {
        return Written::Failed(OsError::Encode);
    };
    match os.write_result(&id, &bytes) {
        Ok(()) => Written::Yes,
        Err(e) => Written::Failed(e),
    }
}

/// Reads and decodes the profile (non-elevated only).
fn profile<O: Os>(os: &O, id: Option<ProfileId>) -> Result<LaunchProfile, Skip> {
    let Some(id) = id else {
        return Err(Skip::ProfileId);
    };
    let bytes = os.read_profile(&id).map_err(Skip::ProfileUnreadable)?;
    if bytes.len() > MAX_PROFILE_BYTES {
        return Err(Skip::ProfileInvalid(None));
    }
    decode(&bytes).map_err(|e| Skip::ProfileInvalid(Some(e)))
}

/// Checks the start path, reads the topology and selects the processors. The gate of `run` is
/// the gate of the rule: `argv[0]` equals `start` (ADR 0022 amendment P5-OE); a profile with
/// `run` or `args` is `direct` (the codec refuses them with `watch`).
pub(crate) fn decide<O: Os>(os: &O, cmd: &Command<'_>, profile: &LaunchProfile) -> Plan {
    if !os.same_path(cmd.app, &profile.start) {
        return Plan::Unchanged(Skip::PathMismatch);
    }
    let limit = match limit_of(os, profile) {
        Ok(limit) => limit,
        Err(skip) => return Plan::Unchanged(skip),
    };
    match profile.method {
        Method::Direct => Plan::Rule {
            limit,
            priority: profile.priority,
            launch: with_run(cmd, profile.run.as_deref(), &profile.args),
        },
        Method::Watch => Plan::Watch(watch::Watch::new(profile, limit)),
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

/// Starts `launch` with the profile's settings and checks them; any failure before the resume
/// ends in one unchanged start of Steam's command `cmd` (also when `launch` is `run`).
fn with_rule<O: Os>(
    os: &O,
    cmd: &Command<'_>,
    launch: &OwnedCommand,
    limit: Option<(Limit, Applied)>,
    priority: Option<Priority>,
) -> Done<O::Child> {
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
    let child = match os.spawn(&launch.app, &launch.line, &spawn) {
        Ok(c) => c,
        Err(ERROR_ELEVATION_REQUIRED) => {
            let mut done = shell_with(
                os,
                &launch.app,
                launch.parameters.as_deref(),
                Rule::Skipped(Skip::ElevationRequired),
                None,
            );
            done.run = launch.run;
            return done;
        }
        // A `run` that cannot be started: Steam's command, unchanged (no rule, no `args`).
        Err(code) if launch.run => return unchanged(os, cmd, Skip::RunFailed(code), None),
        Err(code) => return unchanged(os, cmd, Skip::Spawn(code), None),
    };
    let prepared = match &limit {
        None => Ok(()),
        Some((Limit::Hard(ga), _)) => hard(os, &child, *ga),
        Some((Limit::Soft(ids), _)) => os.set_cpu_sets(child.borrow(), ids).map_err(Skip::CpuSets),
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
        return unchanged(os, cmd, skip, Some(ended));
    }
    let check = check(os, child.borrow(), limit.as_ref().map(|(l, _)| l), priority);
    Done {
        rule: Rule::Applied {
            cpu: applied,
            priority,
        },
        start: Start::Created,
        terminated: None,
        check: Some(check),
        child: Some(child),
        exit: 0,
        restore: None,
        run: launch.run,
    }
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

/// The post-launch check (P3-2): wait up to [`CHECK_DELAY_MS`] on the running child, then
/// compare what Windows reports with what was set. A difference is `Reset` (no culprit is
/// named, docs/04); a failed read is `Failed`.
fn check<O: Os>(
    os: &O,
    child: &O::Proc,
    limit: Option<&Limit>,
    priority: Option<Priority>,
) -> Check {
    match os.wait_for(child, CHECK_DELAY_MS) {
        Ok(true) => return Check::ExitedEarly,
        Ok(false) => {}
        Err(code) => return Check::Failed { code },
    }
    let cpu = match limit {
        None => Ok(Cpu::Same),
        Some(Limit::Hard(ga)) => os.job_affinity(child).and_then(|job| {
            // The job keeps exactly the one entry; the process's mask (of its primary group,
            // which the read-back made the selected one) is the selection, or a non-empty
            // proper subset of it that the game set itself within the rule (`narrowed`). 0
            // (threads in several groups) or bits outside the job's mask are a reset.
            let mask = os.process_affinity(child)?;
            Ok(if job != [*ga] {
                Cpu::Changed
            } else if mask == ga.mask {
                Cpu::Same
            } else if mask != 0 && mask & !ga.mask == 0 {
                Cpu::Narrowed
            } else {
                Cpu::Changed
            })
        }),
        Some(Limit::Soft(ids)) => os.cpu_sets(child).map(|mut now| {
            let mut set = ids.clone();
            now.sort_unstable();
            set.sort_unstable();
            if now == set { Cpu::Same } else { Cpu::Changed }
        }),
    };
    let cpu = match cpu {
        Ok(c) => c,
        Err(code) => return Check::Failed { code },
    };
    let prio = match priority {
        None => false,
        Some(p) => match os.priority_class(child) {
            Ok(class) => class != priority_class(p),
            Err(code) => return Check::Failed { code },
        },
    };
    match (cpu, prio) {
        (Cpu::Changed, _) | (_, true) => Check::Reset {
            cpu: cpu == Cpu::Changed,
            priority: prio,
        },
        (Cpu::Narrowed, false) => Check::Narrowed,
        (Cpu::Same, false) => Check::Ok,
    }
}

/// The CPU part of the check.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Cpu {
    /// As set.
    Same,
    /// Hard limit: the process narrowed itself within the job's mask.
    Narrowed,
    /// Differs from what was set.
    Changed,
}

/// Steam's command, unchanged; 740 goes to `ShellExecuteExW`.
fn unchanged<O: Os>(
    os: &O,
    cmd: &Command<'_>,
    skip: Skip,
    terminated: Option<Terminated>,
) -> Done<O::Child> {
    let rule = Rule::Skipped(skip);
    match os.spawn(cmd.app, cmd.tail, &Spawn::UNCHANGED) {
        Ok(child) => Done {
            rule,
            start: Start::Created,
            terminated,
            check: None,
            child: Some(child),
            exit: 0,
            restore: None,
            run: false,
        },
        Err(ERROR_ELEVATION_REQUIRED) => shell(os, cmd, rule, terminated),
        Err(code) => Done {
            rule,
            start: Start::Failed(code),
            terminated,
            check: None,
            child: None,
            exit: EXIT_NOT_STARTED,
            restore: None,
            run: false,
        },
    }
}

/// B2: the same `argv[0]` and the raw parameters through `ShellExecuteExW`, `.exe` only.
fn shell<O: Os>(
    os: &O,
    cmd: &Command<'_>,
    rule: Rule,
    terminated: Option<Terminated>,
) -> Done<O::Child> {
    shell_with(os, cmd.app, cmd.parameters, rule, terminated)
}

/// B2 for `file` with `parameters`: Steam's, or the command the rule was for (`run`, `args`).
fn shell_with<O: Os>(
    os: &O,
    file: &[u16],
    parameters: Option<&[u16]>,
    rule: Rule,
    terminated: Option<Terminated>,
) -> Done<O::Child> {
    let (start, child, exit) = if cmdline::ends_with_exe(file) {
        match os.shell_execute(file, parameters) {
            Ok(Some(child)) => (Start::ShellExecuted, Some(child), 0),
            Ok(None) => (Start::ShellWithoutProcess, None, 0),
            Err(code) => (Start::Failed(code), None, EXIT_NOT_STARTED),
        }
    } else {
        (Start::NotExe, None, EXIT_NOT_STARTED)
    };
    Done {
        rule,
        start,
        terminated,
        check: None,
        child,
        exit,
        restore: None,
        run: false,
    }
}

pub(crate) mod watch;

#[cfg(test)]
mod check_tests;
#[cfg(test)]
mod run_tests;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod watch_tests;
