//! The shim's system layer (ADR 0022): everything `run` asks of Windows goes through [`Os`].
//! `win::WinOs` is the real one; `fake::FakeOs` (tests) scripts every answer, so each decision
//! of `run` is tested without starting a process.
//!
//! The steps of a hard limit are separate calls so that `run`, not the system layer, decides
//! what a failure or a difference means (B-2): [`Os::spawn`] creates the job and the suspended
//! child inside it, [`Os::limit_job`] sets the job's group affinity, [`Os::read_back`] reads
//! the job and the initial thread back, [`Os::resume`] lets the child run.
//!
//! The post-launch check (P3-2) waits on the child without consuming it ([`Os::wait_for`]) and
//! reads what Windows reports now ([`Os::job_affinity`], [`Os::process_affinity`],
//! [`Os::cpu_sets`], [`Os::priority_class`]); [`Os::write_result`] records the outcome.

use std::fmt;

use rerun_proto::cpu::{CpuTopology, TopologyError};
use rerun_proto::profile::{Priority, ProfileId};

/// One `GROUP_AFFINITY` (`Reserved` is always zero when Rerun passes it).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct GroupAffinity {
    /// Processor group.
    pub(crate) group: u16,
    /// Processors of the group.
    pub(crate) mask: u64,
}

/// How [`Os::spawn`] creates the child.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct Spawn {
    /// Create a job first (`JOB_OBJECT_LIMIT_BREAKAWAY_OK`, B4) and the child inside it
    /// (`PROC_THREAD_ATTRIBUTE_JOB_LIST` only; the group affinity follows with
    /// [`Os::limit_job`], ADR 0022 amendment P3-1b). Implies suspended.
    pub(crate) in_job: bool,
    /// `CREATE_SUSPENDED`.
    pub(crate) suspended: bool,
    /// Priority class creation flag; none = the default.
    pub(crate) priority: Option<Priority>,
}

impl Spawn {
    /// Steam's command as Steam would start it: no job, not suspended, default priority.
    pub(crate) const UNCHANGED: Self = Self {
        in_job: false,
        suspended: false,
        priority: None,
    };
}

/// How [`Os::terminate`] went (for the result file, P3-2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Terminated {
    /// The child ended within the wait.
    Ended,
    /// `TerminateProcess` failed with this Win32 error code.
    Failed(u32),
    /// `TerminateProcess` succeeded, but the child had not ended after the wait (or the wait
    /// failed with this Win32 error code; `WAIT_TIMEOUT` = 258 for the timeout).
    NotConfirmed(u32),
}

/// What [`Os::read_back`] found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReadBack {
    /// The job's `JobObjectGroupInformationEx`, every entry.
    pub(crate) job: Vec<GroupAffinity>,
    /// The initial thread's `GetThreadGroupAffinity`.
    pub(crate) thread: GroupAffinity,
}

/// A failed system call of the shim. A Win32 error code where Windows gave one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum OsError {
    /// The call failed with this Win32 error code.
    Win32(u32),
    /// The call failed with this `HRESULT`.
    HResult(i32),
    /// The profile, or for the result file `Rerun`, `launch` or the file itself, is a reparse
    /// point (refused, D2, P3-2).
    ReparsePoint,
    /// The profile is not a regular file (for the result file: `Rerun` or `launch` is not a
    /// folder, or the file is not a file).
    NotAFile,
    /// The topology from Windows is inconsistent or malformed (ADR 0010, fail closed).
    #[cfg_attr(
        not(target_pointer_width = "64"),
        expect(dead_code, reason = "a 32-bit shim reads no topology (ADR 0010)")
    )]
    Topology(TopologyError),
    /// Not available in this build (the topology in a 32-bit shim, ADR 0010).
    Unsupported,
    /// The new result file is not in the `launch` folder that was checked (P3-2).
    Escaped,
    /// The result could not be encoded (never for a correct codec).
    Encode,
    /// An elevated shim writes nothing (B13).
    Elevated,
}

impl fmt::Display for OsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Win32(code) => write!(f, "Win32 error {code}"),
            Self::HResult(hr) => write!(f, "HRESULT 0x{:08X}", hr.cast_unsigned()),
            Self::ReparsePoint => f.write_str("the profile is a reparse point"),
            Self::NotAFile => f.write_str("the profile is not a file"),
            Self::Topology(e) => write!(f, "topology: {e}"),
            Self::Unsupported => f.write_str("not supported in this build"),
            Self::Escaped => f.write_str("the result file is not in the launch folder"),
            Self::Encode => f.write_str("the result could not be encoded"),
            Self::Elevated => f.write_str("an elevated shim writes nothing"),
        }
    }
}

impl std::error::Error for OsError {}

/// The shim's system layer.
pub(crate) trait Os {
    /// A started process. Owns its handles (process, initial thread, job); dropping it closes
    /// them. The job handle stays open as long as the child value lives (B3).
    type Child;

    /// The raw command line of this process (`GetCommandLineW`), without the NUL.
    fn command_line(&self) -> Vec<u16>;

    /// The shim counts as elevated (M1): the token is elevated, UAC is off for a member of
    /// Administrators, or the answer cannot be determined (fail closed).
    fn elevated(&self) -> bool;

    /// The profile file `<LocalAppData>\Rerun\profiles\<id>.profile`, at most
    /// `MAX_PROFILE_BYTES + 1` bytes (the codec refuses more). A reparse point is refused.
    fn read_profile(&self, id: &ProfileId) -> Result<Vec<u8>, OsError>;

    /// The live CPU topology (ADR 0010).
    fn topology(&self) -> Result<CpuTopology, OsError>;

    /// `CreateProcessW(app, command_line, …)`; never inherits handles; environment and current
    /// directory are the shim's. The Win32 error code on failure.
    fn spawn(&self, app: &[u16], command_line: &[u16], spawn: &Spawn) -> Result<Self::Child, u32>;

    /// `SetInformationJobObject(JobObjectGroupInformationEx)` with exactly this one entry.
    fn limit_job(&self, child: &Self::Child, affinity: GroupAffinity) -> Result<(), u32>;

    /// The job's group affinity and the initial thread's.
    fn read_back(&self, child: &Self::Child) -> Result<ReadBack, u32>;

    /// `SetProcessDefaultCpuSets` on the (suspended) child.
    fn set_cpu_sets(&self, child: &Self::Child, ids: &[u32]) -> Result<(), u32>;

    /// `ResumeThread` on the initial thread.
    fn resume(&self, child: &Self::Child) -> Result<(), u32>;

    /// Ends a child that never ran (`TerminateProcess`, then a bounded wait for its end) and
    /// closes its handles. The outcome is reported, never acted on (the start stays fail open).
    fn terminate(&self, child: Self::Child) -> Terminated;

    /// Steam's `argv[0]` equals the profile's `start`: `CompareStringOrdinal(…, TRUE)`, the
    /// comparison Windows uses for file names (ADR 0022 amendment P3-1b review).
    fn same_path(&self, app: &[u16], start: &str) -> bool;

    /// `ShellExecuteExW` (B2): default verb, `file`, `parameters`, no directory, with COM
    /// initialised around the call. `None` if Windows started no process it could hand back.
    fn shell_execute(
        &self,
        file: &[u16],
        parameters: Option<&[u16]>,
    ) -> Result<Option<Self::Child>, u32>;

    /// Waits for the child to exit and returns its exit code.
    fn wait(&self, child: Self::Child) -> Result<u32, u32>;

    /// Waits up to `ms` milliseconds for the child to end, without consuming it: `true` if it
    /// ended (the post-launch check, P3-2).
    fn wait_for(&self, child: &Self::Child, ms: u32) -> Result<bool, u32>;

    /// The job's `JobObjectGroupInformationEx` now, every entry (hard limit only).
    fn job_affinity(&self, child: &Self::Child) -> Result<Vec<GroupAffinity>, u32>;

    /// The process's affinity mask now (`GetProcessAffinityMask`: its primary group's; 0 when
    /// its threads span more than one group).
    fn process_affinity(&self, child: &Self::Child) -> Result<u64, u32>;

    /// The process's default CPU Sets now (`GetProcessDefaultCpuSets`), in any order.
    fn cpu_sets(&self, child: &Self::Child) -> Result<Vec<u32>, u32>;

    /// The process's priority class now (`GetPriorityClass`).
    fn priority_class(&self, child: &Self::Child) -> Result<u32, u32>;

    /// Seconds since 1970-01-01 UTC (0 if the clock is before it).
    fn now_unix_s(&self) -> u64;

    /// Writes `<LocalAppData>\Rerun\launch\<id>.result` (P3-2): `Rerun` must exist, `launch`
    /// is created if missing, a reparse point at `Rerun`, `launch` or the file is refused,
    /// temp file + rename inside `launch`. Refused when elevated (B13; `run` never asks then).
    fn write_result(&self, id: &ProfileId, bytes: &[u8]) -> Result<(), OsError>;
}

/// The priority class `GetPriorityClass` reports for a class Rerun sets (winbase.h
/// `NORMAL_PRIORITY_CLASS`, `ABOVE_NORMAL_PRIORITY_CLASS`, `HIGH_PRIORITY_CLASS`: the same
/// values as the creation flags; checked against `windows-sys` in `win::launch`).
pub(crate) fn priority_class(p: Priority) -> u32 {
    match p {
        Priority::Normal => 0x0000_0020,
        Priority::AboveNormal => 0x0000_8000,
        Priority::High => 0x0000_0080,
    }
}
