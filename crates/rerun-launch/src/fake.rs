//! `FakeOs`: a scripted [`Os`] for the decision tests of `run` (ADR 0022, [F]). Every call is
//! recorded in order; every answer is set by the test. A child is its spawn number (1, 2, …);
//! a target opened by `watch` takes the next number of the same counter.
//!
//! `watch` (P3-4) runs on a virtual clock: `now_ms` starts at 0, `wait_for` and `sleep_ms`
//! move it on. The process table is a script of snapshots ([`FakeOs::table`], the last one
//! repeats); `open_process` opens what the last successful snapshot lists, so a PID that
//! changed between snapshots models PID reuse, and each [`FakeProc`] sets its own open and
//! facts answers.

use std::borrow::Borrow;
use std::cell::{Cell, RefCell};
use std::collections::VecDeque;

use rerun_proto::cpu::CpuTopology;
use rerun_proto::profile::{Priority, ProfileId};

use crate::os::{
    Access, Facts, GroupAffinity, Listed, Os, OsError, Own, ReadBack, Spawn, Terminated, Token,
    priority_class,
};

/// The shim's token in the fake: user `S-1-5-21-…-1001` as bytes, session 1, medium.
pub(crate) fn own_token() -> Token {
    Token {
        user: vec![1, 5, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 0xe9, 3, 0, 0],
        session: 1,
        integrity: 0x2000,
    }
}

/// The shim's creation time in the fake (FILETIME units).
pub(crate) const OWN_CREATED: u64 = 1_000_000;

/// The started child's PID in the fake.
pub(crate) const CHILD_PID: u32 = 4_000;

/// A process of the fake table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FakeProc {
    pub(crate) pid: u32,
    /// `szExeFile`.
    pub(crate) name: String,
    /// The answer of an open with query rights only.
    pub(crate) open: Result<(), u32>,
    /// The answer of an open with set rights.
    pub(crate) open_set: Result<(), u32>,
    /// What a handle reports.
    pub(crate) facts: Result<Facts, u32>,
    /// What a handle with set rights reports; `None`: [`FakeProc::facts`].
    pub(crate) facts_set: Option<Result<Facts, u32>>,
    /// Ends this long into a wait on it (the check); `None`: runs on.
    pub(crate) exits_after_ms: Option<u32>,
    /// Its priority class before anything is set.
    pub(crate) class: u32,
}

impl FakeProc {
    /// A process of the shim's user and session, opened and read without error, created
    /// `after` units after the shim, running on, normal priority.
    pub(crate) fn new(pid: u32, image: &str, after: i64) -> Self {
        let name = image.rsplit('\\').next().unwrap_or_default().to_owned();
        Self {
            pid,
            name,
            open: Ok(()),
            open_set: Ok(()),
            facts: Ok(Facts {
                image: image.encode_utf16().collect(),
                created: OWN_CREATED.saturating_add_signed(after),
                token: own_token(),
            }),
            facts_set: None,
            exits_after_ms: None,
            class: priority_class(Priority::Normal),
        }
    }

    /// The facts a handle reports, for changing one field.
    pub(crate) fn facts_mut(&mut self) -> &mut Facts {
        self.facts.as_mut().unwrap()
    }
}

/// A target handle of the fake: its number. Not `Copy`, not convertible to a child.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct FakeTarget(u32);

impl Borrow<u32> for FakeTarget {
    fn borrow(&self) -> &u32 {
        &self.0
    }
}

/// An opened target handle.
#[derive(Debug, Clone)]
struct Opened {
    id: u32,
    proc: FakeProc,
    /// Opened with set rights.
    set: bool,
}

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
    /// `processes`.
    Snapshot,
    /// `open_process`.
    Open {
        pid: u32,
        access: Access,
    },
    /// `facts` of a target handle.
    Facts(u32),
    /// `attach_job` on a target handle: affinity and the job's limit flags (A1).
    AttachJob(u32, GroupAffinity, u32),
    /// `set_priority` on a target handle.
    SetPriority(u32, u32),
    /// `sleep_ms`.
    Sleep(u32),
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
    /// The virtual clock at each result file written.
    pub(crate) written_at: RefCell<Vec<u64>>,
    pub(crate) calls: RefCell<Vec<Call>>,
    /// `watch`: the shim's own facts.
    pub(crate) own: Result<Own, u32>,
    /// `watch`: the started child ends at this virtual time (`None`: it runs on, or what
    /// [`FakeOs::wait_for`] says).
    pub(crate) child_ends_at: Option<u64>,
    /// `watch`: one entry per snapshot; the last one repeats (none: an empty table).
    pub(crate) table: RefCell<VecDeque<Result<Vec<FakeProc>, u32>>>,
    /// `watch`: answers of `set_priority` in order; `Ok` once they run out.
    pub(crate) set_priority: RefCell<VecDeque<Result<(), u32>>>,
    /// `watch`: the answer of `attach_job`.
    pub(crate) attach_job: Result<(), u32>,
    /// The virtual clock in milliseconds.
    pub(crate) clock: Cell<u64>,
    /// The table of the last successful snapshot: what `open_process` finds.
    current: RefCell<Vec<FakeProc>>,
    /// Every target handle opened.
    opened: RefCell<Vec<Opened>>,
    /// Priority classes set on targets, per PID.
    classes: RefCell<Vec<(u32, u32)>>,
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
            written_at: RefCell::new(Vec::new()),
            calls: RefCell::new(Vec::new()),
            own: Ok(Own {
                created: OWN_CREATED,
                token: own_token(),
            }),
            child_ends_at: None,
            table: RefCell::new(VecDeque::new()),
            set_priority: RefCell::new(VecDeque::new()),
            attach_job: Ok(()),
            clock: Cell::new(0),
            current: RefCell::new(Vec::new()),
            opened: RefCell::new(Vec::new()),
            classes: RefCell::new(Vec::new()),
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

    /// The numbers of the target handles opened with set rights, in order.
    pub(crate) fn set_handles(&self) -> Vec<u32> {
        self.opened
            .borrow()
            .iter()
            .filter(|o| o.set)
            .map(|o| o.id)
            .collect()
    }

    /// The opened target `id`, if it is one.
    fn target(&self, id: u32) -> Option<Opened> {
        self.opened.borrow().iter().find(|o| o.id == id).cloned()
    }

    fn advance(&self, ms: u64) {
        self.clock.set(self.clock.get() + ms);
    }

    fn next_id(&self) -> u32 {
        let mut n = self.next.borrow_mut();
        *n += 1;
        *n
    }
}

impl Os for FakeOs {
    type Proc = u32;
    type Child = u32;
    type Target = FakeTarget;

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
        Ok(self.next_id())
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
            Ok(Some(self.next_id()))
        } else {
            Ok(None)
        }
    }

    fn wait(&self, child: u32) -> Result<u32, u32> {
        self.record(Call::Wait(child));
        self.wait
    }

    /// A target: ends after its `exits_after_ms`, otherwise the whole wait passes. A child:
    /// ends at [`FakeOs::child_ends_at`], otherwise [`FakeOs::wait_for`] answers (the whole wait
    /// passes for `Ok(false)`).
    fn wait_for(&self, child: &u32, ms: u32) -> Result<bool, u32> {
        self.record(Call::WaitFor(*child, ms));
        if let Some(t) = self.target(*child) {
            return Ok(match t.proc.exits_after_ms {
                Some(e) if e <= ms => {
                    self.advance(u64::from(e));
                    true
                }
                _ => {
                    self.advance(u64::from(ms));
                    false
                }
            });
        }
        let now = self.clock.get();
        if let Some(end) = self.child_ends_at
            && now + u64::from(ms) >= end
        {
            self.clock.set(now.max(end));
            return Ok(true);
        }
        if self.wait_for == Ok(false) {
            self.advance(u64::from(ms));
        }
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
        if let Some(r) = self.priority_class {
            return r;
        }
        if let Some(t) = self.target(*child) {
            let set = self
                .classes
                .borrow()
                .iter()
                .rev()
                .find(|(pid, _)| *pid == t.proc.pid)
                .map(|(_, c)| *c);
            return Ok(set.unwrap_or(t.proc.class));
        }
        Ok(priority_class(
            self.last_priority.borrow().unwrap_or(Priority::Normal),
        ))
    }

    fn now_unix_s(&self) -> u64 {
        self.now
    }

    fn write_result(&self, id: &ProfileId, bytes: &[u8]) -> Result<(), OsError> {
        self.record(Call::WriteResult(*id));
        self.written.borrow_mut().push(bytes.to_vec());
        self.written_at.borrow_mut().push(self.clock.get());
        self.write.clone()
    }

    fn own(&self) -> Result<Own, u32> {
        self.own.clone()
    }

    fn pid(&self, _child: &u32) -> u32 {
        CHILD_PID
    }

    fn processes(&self) -> Result<Vec<Listed>, u32> {
        self.record(Call::Snapshot);
        let mut table = self.table.borrow_mut();
        let now = if table.len() > 1 {
            table.pop_front().unwrap_or(Ok(Vec::new()))
        } else {
            table.front().cloned().unwrap_or(Ok(Vec::new()))
        };
        let procs = now?;
        let listed = procs
            .iter()
            .map(|p| Listed {
                pid: p.pid,
                name: p.name.encode_utf16().collect(),
            })
            .collect();
        *self.current.borrow_mut() = procs;
        Ok(listed)
    }

    /// `ERROR_INVALID_PARAMETER` (87) for a PID the last snapshot does not list (it ended).
    fn open_process(&self, pid: u32, access: Access) -> Result<FakeTarget, u32> {
        self.record(Call::Open { pid, access });
        let proc = self
            .current
            .borrow()
            .iter()
            .find(|p| p.pid == pid)
            .cloned()
            .ok_or(87u32)?;
        let set = access != Access::default();
        if set { proc.open_set } else { proc.open }?;
        let id = self.next_id();
        self.opened.borrow_mut().push(Opened { id, proc, set });
        Ok(FakeTarget(id))
    }

    fn facts(&self, t: &FakeTarget) -> Result<Facts, u32> {
        self.record(Call::Facts(t.0));
        let o = self.target(t.0).ok_or(6u32)?;
        match (o.set, o.proc.facts_set) {
            (true, Some(f)) => f,
            _ => o.proc.facts,
        }
    }

    fn attach_job(
        &self,
        t: &mut FakeTarget,
        affinity: GroupAffinity,
        limit_flags: u32,
    ) -> Result<(), u32> {
        self.record(Call::AttachJob(t.0, affinity, limit_flags));
        self.attach_job?;
        *self.last_limit.borrow_mut() = Some(affinity);
        Ok(())
    }

    fn set_priority(&self, t: &FakeTarget, class: u32) -> Result<(), u32> {
        self.record(Call::SetPriority(t.0, class));
        self.set_priority
            .borrow_mut()
            .pop_front()
            .unwrap_or(Ok(()))?;
        if let Some(o) = self.target(t.0) {
            self.classes.borrow_mut().push((o.proc.pid, class));
        }
        Ok(())
    }

    fn now_ms(&self) -> u64 {
        self.clock.get()
    }

    fn sleep_ms(&self, ms: u32) {
        self.record(Call::Sleep(ms));
        self.advance(u64::from(ms));
    }
}
