//! `FakeOs`: a scripted [`Os`] for the decision tests of `run` (ADR 0022, [F]). Every call is
//! recorded in order; every answer is set by the test. A child is its spawn number (1, 2, …).

use std::cell::RefCell;
use std::collections::VecDeque;

use rerun_proto::cpu::CpuTopology;
use rerun_proto::profile::{Priority, ProfileId};

use crate::os::{GroupAffinity, Os, OsError, ReadBack, Spawn, Terminated, priority_class};

/// One recorded call. Paths and command lines as `String` (the tests use valid UTF-16).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Call {
    ReadProfile(ProfileId),
    Topology,
    Spawn {
        app: String,
        line: String,
        spawn: Spawn,
    },
    LimitJob(u32, GroupAffinity),
    ReadBack(u32),
    CpuSets(u32, Vec<u32>),
    Resume(u32),
    Terminate(u32),
    Shell {
        file: String,
        parameters: Option<String>,
    },
    Wait(u32),
    WaitFor(u32, u32),
    JobAffinity(u32),
    ProcessAffinity(u32),
    ReadCpuSets(u32),
    PriorityClass(u32),
    /// The bytes are in [`FakeOs::written`].
    WriteResult(ProfileId),
}

pub(crate) struct FakeOs {
    pub(crate) line: Vec<u16>,
    pub(crate) elevated: bool,
    pub(crate) profile: Result<Vec<u8>, OsError>,
    pub(crate) topology: Result<CpuTopology, OsError>,
    /// Answers of the spawn calls in order; `Ok` once they run out.
    pub(crate) spawns: RefCell<VecDeque<Result<(), u32>>>,
    pub(crate) limit_job: Result<(), u32>,
    /// `None`: echo the affinity of the last `limit_job` for job and thread.
    pub(crate) read_back: Option<Result<ReadBack, u32>>,
    pub(crate) cpu_sets: Result<(), u32>,
    pub(crate) resume: Result<(), u32>,
    /// `Ok(true)`: a process handle; `Ok(false)`: none.
    pub(crate) shell: Result<bool, u32>,
    pub(crate) wait: Result<u32, u32>,
    pub(crate) terminated: Terminated,
    /// The post-launch check's wait: `Ok(false)` = still running after the delay.
    pub(crate) wait_for: Result<bool, u32>,
    /// `None`: what `limit_job` set (one entry, or none without a call).
    pub(crate) job_affinity: Option<Result<Vec<GroupAffinity>, u32>>,
    /// `None`: the mask `limit_job` set (all 32 bits without a call).
    pub(crate) process_affinity: Option<Result<u64, u32>>,
    /// `None`: what `set_cpu_sets` set (none without a call).
    pub(crate) read_cpu_sets: Option<Result<Vec<u32>, u32>>,
    /// `None`: the class of the last spawn's priority (normal without one).
    pub(crate) priority_class: Option<Result<u32, u32>>,
    pub(crate) now: u64,
    pub(crate) write: Result<(), OsError>,
    /// Every result file written, in order.
    pub(crate) written: RefCell<Vec<Vec<u8>>>,
    pub(crate) calls: RefCell<Vec<Call>>,
    next: RefCell<u32>,
    last_limit: RefCell<Option<GroupAffinity>>,
    last_sets: RefCell<Vec<u32>>,
    last_priority: RefCell<Option<Priority>>,
}

fn s(u: &[u16]) -> String {
    String::from_utf16_lossy(u)
}

impl FakeOs {
    /// A non-elevated machine with the given command line, no profile file
    /// (`ERROR_FILE_NOT_FOUND`), no topology (`Unsupported`), every other call succeeding,
    /// the child still running at the check and exiting with 42, the clock at 1,762,600,000.
    pub(crate) fn new(line: &str) -> Self {
        Self {
            line: line.encode_utf16().collect(),
            elevated: false,
            profile: Err(OsError::Win32(2)),
            topology: Err(OsError::Unsupported),
            spawns: RefCell::new(VecDeque::new()),
            limit_job: Ok(()),
            read_back: None,
            cpu_sets: Ok(()),
            resume: Ok(()),
            shell: Ok(true),
            wait: Ok(42),
            terminated: Terminated::Ended,
            wait_for: Ok(false),
            job_affinity: None,
            process_affinity: None,
            read_cpu_sets: None,
            priority_class: None,
            now: 1_762_600_000,
            write: Ok(()),
            written: RefCell::new(Vec::new()),
            calls: RefCell::new(Vec::new()),
            next: RefCell::new(0),
            last_limit: RefCell::new(None),
            last_sets: RefCell::new(Vec::new()),
            last_priority: RefCell::new(None),
        }
    }

    pub(crate) fn calls(&self) -> Vec<Call> {
        self.calls.borrow().clone()
    }

    fn record(&self, c: Call) {
        self.calls.borrow_mut().push(c);
    }
}

impl Os for FakeOs {
    type Child = u32;

    fn command_line(&self) -> Vec<u16> {
        self.line.clone()
    }

    fn elevated(&self) -> bool {
        self.elevated
    }

    fn read_profile(&self, id: &ProfileId) -> Result<Vec<u8>, OsError> {
        self.record(Call::ReadProfile(*id));
        self.profile.clone()
    }

    fn topology(&self) -> Result<CpuTopology, OsError> {
        self.record(Call::Topology);
        self.topology.clone()
    }

    fn spawn(&self, app: &[u16], command_line: &[u16], spawn: &Spawn) -> Result<u32, u32> {
        self.record(Call::Spawn {
            app: s(app),
            line: s(command_line),
            spawn: *spawn,
        });
        self.spawns.borrow_mut().pop_front().unwrap_or(Ok(()))?;
        *self.last_priority.borrow_mut() = spawn.priority;
        let mut n = self.next.borrow_mut();
        *n += 1;
        Ok(*n)
    }

    fn limit_job(&self, child: &u32, affinity: GroupAffinity) -> Result<(), u32> {
        self.record(Call::LimitJob(*child, affinity));
        *self.last_limit.borrow_mut() = Some(affinity);
        self.limit_job
    }

    fn read_back(&self, child: &u32) -> Result<ReadBack, u32> {
        self.record(Call::ReadBack(*child));
        match &self.read_back {
            Some(r) => r.clone(),
            None => {
                let ga = self
                    .last_limit
                    .borrow()
                    .unwrap_or(GroupAffinity { group: 0, mask: 0 });
                Ok(ReadBack {
                    job: vec![ga],
                    thread: ga,
                })
            }
        }
    }

    fn set_cpu_sets(&self, child: &u32, ids: &[u32]) -> Result<(), u32> {
        self.record(Call::CpuSets(*child, ids.to_vec()));
        *self.last_sets.borrow_mut() = ids.to_vec();
        self.cpu_sets
    }

    fn resume(&self, child: &u32) -> Result<(), u32> {
        self.record(Call::Resume(*child));
        self.resume
    }

    fn terminate(&self, child: u32) -> Terminated {
        self.record(Call::Terminate(child));
        self.terminated
    }

    /// ASCII case-insensitive only: the tests use ASCII paths; the real comparison
    /// (`CompareStringOrdinal`) is tested in `win::tests`.
    fn same_path(&self, app: &[u16], start: &str) -> bool {
        String::from_utf16(app).is_ok_and(|a| a.eq_ignore_ascii_case(start))
    }

    fn shell_execute(&self, file: &[u16], parameters: Option<&[u16]>) -> Result<Option<u32>, u32> {
        self.record(Call::Shell {
            file: s(file),
            parameters: parameters.map(s),
        });
        if self.shell? {
            let mut n = self.next.borrow_mut();
            *n += 1;
            Ok(Some(*n))
        } else {
            Ok(None)
        }
    }

    fn wait(&self, child: u32) -> Result<u32, u32> {
        self.record(Call::Wait(child));
        self.wait
    }

    fn wait_for(&self, child: &u32, ms: u32) -> Result<bool, u32> {
        self.record(Call::WaitFor(*child, ms));
        self.wait_for
    }

    fn job_affinity(&self, child: &u32) -> Result<Vec<GroupAffinity>, u32> {
        self.record(Call::JobAffinity(*child));
        match &self.job_affinity {
            Some(r) => r.clone(),
            None => Ok(self.last_limit.borrow().iter().copied().collect()),
        }
    }

    fn process_affinity(&self, child: &u32) -> Result<u64, u32> {
        self.record(Call::ProcessAffinity(*child));
        match self.process_affinity {
            Some(r) => r,
            None => Ok(self.last_limit.borrow().map_or(0xFFFF_FFFF, |ga| ga.mask)),
        }
    }

    fn cpu_sets(&self, child: &u32) -> Result<Vec<u32>, u32> {
        self.record(Call::ReadCpuSets(*child));
        match &self.read_cpu_sets {
            Some(r) => r.clone(),
            None => Ok(self.last_sets.borrow().clone()),
        }
    }

    fn priority_class(&self, child: &u32) -> Result<u32, u32> {
        self.record(Call::PriorityClass(*child));
        match self.priority_class {
            Some(r) => r,
            None => Ok(priority_class(
                self.last_priority.borrow().unwrap_or(Priority::Normal),
            )),
        }
    }

    fn now_unix_s(&self) -> u64 {
        self.now
    }

    fn write_result(&self, id: &ProfileId, bytes: &[u8]) -> Result<(), OsError> {
        self.record(Call::WriteResult(*id));
        self.written.borrow_mut().push(bytes.to_vec());
        self.write.clone()
    }
}
