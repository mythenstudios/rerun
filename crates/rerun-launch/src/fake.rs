//! `FakeOs`: a scripted [`Os`] for the decision tests of `run` (ADR 0022, [F]). Every call is
//! recorded in order; every answer is set by the test. A child is its spawn number (1, 2, …).

use std::cell::RefCell;
use std::collections::VecDeque;

use rerun_proto::cpu::CpuTopology;
use rerun_proto::profile::ProfileId;

use crate::os::{GroupAffinity, Os, OsError, ReadBack, Spawn, Terminated};

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
    pub(crate) calls: RefCell<Vec<Call>>,
    next: RefCell<u32>,
    last_limit: RefCell<Option<GroupAffinity>>,
}

fn s(u: &[u16]) -> String {
    String::from_utf16_lossy(u)
}

impl FakeOs {
    /// A non-elevated machine with the given command line, no profile file
    /// (`ERROR_FILE_NOT_FOUND`), no topology (`Unsupported`), every other call succeeding and
    /// the child exiting with 42.
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
            calls: RefCell::new(Vec::new()),
            next: RefCell::new(0),
            last_limit: RefCell::new(None),
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
}
