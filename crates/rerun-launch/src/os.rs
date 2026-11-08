//! The shim's system layer (ADR 0022): everything `run` asks of Windows goes through [`Os`].
//! `win::WinOs` is the real one; `fake::FakeOs` (tests) scripts every answer, so each decision
//! of `run` is tested without starting a process.
//!
//! The steps of a hard limit are separate calls so that `run`, not the system layer, decides
//! what a failure or a difference means (B-2): [`Os::spawn`] creates the job and the suspended
//! child inside it, [`Os::limit_job`] sets the job's group affinity, [`Os::read_back`] reads
//! the job and the initial thread back, [`Os::resume`] lets the child run.

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
    /// (`PROC_THREAD_ATTRIBUTE_JOB_LIST`), with this group affinity for its initial thread
    /// (`PROC_THREAD_ATTRIBUTE_GROUP_AFFINITY`, so it is the primary group). Implies suspended.
    pub(crate) job: Option<GroupAffinity>,
    /// `CREATE_SUSPENDED`.
    pub(crate) suspended: bool,
    /// Priority class creation flag; none = the default.
    pub(crate) priority: Option<Priority>,
}

impl Spawn {
    /// Steam's command as Steam would start it: no job, not suspended, default priority.
    pub(crate) const UNCHANGED: Self = Self {
        job: None,
        suspended: false,
        priority: None,
    };
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
    /// The profile is a reparse point (refused, D2).
    ReparsePoint,
    /// The profile is not a regular file.
    NotAFile,
    /// The topology from Windows is inconsistent or malformed (ADR 0010, fail closed).
    #[cfg_attr(
        not(target_pointer_width = "64"),
        expect(dead_code, reason = "a 32-bit shim reads no topology (ADR 0010)")
    )]
    Topology(TopologyError),
    /// Not available in this build (the topology in a 32-bit shim, ADR 0010).
    Unsupported,
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

    /// Ends a child that never ran (`TerminateProcess`) and closes its handles.
    fn terminate(&self, child: Self::Child);

    /// `ShellExecuteExW` (B2): default verb, `file`, `parameters`, no directory, with COM
    /// initialised around the call. `None` if Windows started no process it could hand back.
    fn shell_execute(
        &self,
        file: &[u16],
        parameters: Option<&[u16]>,
    ) -> Result<Option<Self::Child>, u32>;

    /// Waits for the child to exit and returns its exit code.
    fn wait(&self, child: Self::Child) -> Result<u32, u32>;
}
