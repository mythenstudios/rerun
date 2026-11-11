//! `WinOs` on real Windows. Nothing on the system changes: the only process started is
//! `System32\cmd.exe` (`/c exit <n>`, never resumed, or `/c ping -n <n> 127.0.0.1 >nul` for a
//! child that runs a few seconds; ending that `cmd` leaves its `ping` to finish on its own),
//! and the only limits, priorities and jobs set are on such a child of this test process; each
//! is held by a [`Kid`], which ends it also when a test panics. Every process the tests open
//! with set rights is such a child. Two tests reopen the PID of a child that has ended; that
//! PID may belong to another process by then, so they open it with query rights only, read
//! only its facts and a zero wait, and stop without a verdict as soon as it is not the child
//! (SEC-S2 of the review of P3-4a).

use std::borrow::Borrow;
use std::os::windows::ffi::OsStrExt;
use std::path::PathBuf;

use rerun_proto::cpu::rule::{
    Bitness, CpuRule, ExcludeFirst, Mode, Prefer, SelectError, SelectStep, Selection, select,
};
use rerun_proto::profile::Priority;

use super::launch;
use crate::os::{Access, GroupAffinity, JOB_LIMIT_BREAKAWAY_OK, Os, Spawn, priority_class};
use crate::run::watch::{Trust, trust};
use crate::win::WinOs;

fn w(s: &str) -> Vec<u16> {
    s.encode_utf16().collect()
}

/// `System32\cmd.exe`, from the Windows directory (test code only).
fn cmd_exe() -> Vec<u16> {
    #[expect(
        clippy::disallowed_methods,
        reason = "test: the Windows directory for a harmless system binary"
    )]
    let root = std::env::var_os("SystemRoot").unwrap();
    let p = PathBuf::from(root).join("System32").join("cmd.exe");
    p.as_os_str().encode_wide().collect()
}

#[test]
fn command_line_is_this_process() {
    let line = String::from_utf16(&WinOs.command_line()).unwrap();
    assert!(!line.is_empty());
}

#[test]
fn elevation_is_answered() {
    // Either answer is fine; the call must not panic. CI runners are elevated.
    let _ = WinOs.elevated();
}

#[test]
fn a_missing_profile_is_an_error() {
    // An ID nobody uses: the read fails (ERROR_FILE_NOT_FOUND or PATH_NOT_FOUND), never panics.
    let id = rerun_proto::profile::ProfileId([0xfe; 16]);
    assert!(WinOs.read_profile(&id).is_err());
}

#[test]
fn unchanged_spawn_passes_the_exit_code() {
    let app = cmd_exe();
    let mut line = vec![u16::from(b'"')];
    line.extend_from_slice(&app);
    line.extend(w("\" /c exit 7"));
    let child = WinOs.spawn(&app, &line, &Spawn::UNCHANGED).unwrap();
    assert_eq!(WinOs.wait(child), Ok(7));
}

#[test]
fn a_missing_program_is_a_win32_error() {
    let app = w(r"C:\Program");
    assert_eq!(
        WinOs
            .spawn(&app, &w(r"C:\Program Files\x.exe"), &Spawn::UNCHANGED)
            .err(),
        Some(2)
    );
}

/// The B-2 order on this machine: a job with one `GROUP_AFFINITY`, read back equal, then the
/// child runs and exits. One processor of the selection of `max_threads: 1`.
#[test]
fn hard_limit_round_trip_on_a_child_cmd() {
    let topology = WinOs.topology().unwrap();
    let rule = CpuRule {
        max_threads: Some(1),
        prefer: Prefer::Performance,
        single_l3: true,
        prefer_l3: None,
        smt: false,
        mode: Mode::Hard,
        exclude_first: None,
    };
    let sel = select(&topology, &rule, Bitness::X64).unwrap();
    let ga = GroupAffinity {
        group: sel.group,
        mask: sel.mask,
    };
    let app = cmd_exe();
    let mut line = vec![u16::from(b'"')];
    line.extend_from_slice(&app);
    line.extend(w("\" /c exit 3"));
    let spawn = Spawn {
        in_job: true,
        suspended: true,
        priority: None,
    };
    let child = Kid::new(WinOs.spawn(&app, &line, &spawn).unwrap());
    if let Err(e) = WinOs.limit_job(child.child(), ga) {
        panic!(
            "JobObjectGroupInformationEx failed with {e}; this test process in a job: {:?}",
            in_job()
        );
    }
    let back = WinOs.read_back(child.child()).unwrap();
    assert_eq!(back.job, [ga]);
    assert_eq!(back.thread, ga);
    WinOs.resume(child.child()).unwrap();
    assert_eq!(WinOs.wait(child.take()), Ok(3));
}

/// Puts `sel` on a `cmd /c exit 3` child in a job (B-2 order), reads it back equal, then lets
/// the child run and exit.
fn job_round_trip(sel: &Selection) {
    let ga = GroupAffinity {
        group: sel.group,
        mask: sel.mask,
    };
    let app = cmd_exe();
    let mut line = vec![u16::from(b'"')];
    line.extend_from_slice(&app);
    line.extend(w("\" /c exit 3"));
    let spawn = Spawn {
        in_job: true,
        suspended: true,
        priority: None,
    };
    let child = Kid::new(WinOs.spawn(&app, &line, &spawn).unwrap());
    if let Err(e) = WinOs.limit_job(child.child(), ga) {
        panic!(
            "JobObjectGroupInformationEx failed with {e}; this test process in a job: {:?}",
            in_job()
        );
    }
    let back = WinOs.read_back(child.child()).unwrap();
    assert_eq!(back.job, [ga]);
    assert_eq!(back.thread, ga);
    WinOs.resume(child.child()).unwrap();
    assert_eq!(WinOs.wait(child.take()), Ok(3));
}

/// A rule of `exclude_first` alone (every other field at its default).
fn exclude_first(e: ExcludeFirst, max_threads: Option<u16>) -> CpuRule {
    CpuRule {
        max_threads,
        prefer: Prefer::Any,
        single_l3: false,
        prefer_l3: None,
        smt: true,
        mode: Mode::Hard,
        exclude_first: Some(e),
    }
}

/// The selection of `rule` on this machine, `None` only when `exclude_first` empties it (a
/// one-processor machine); any other error fails the test.
fn selected(topology: &rerun_proto::cpu::CpuTopology, rule: &CpuRule) -> Option<Selection> {
    match select(topology, rule, Bitness::X64) {
        Ok(sel) => Some(sel),
        Err(SelectError::Empty {
            after: SelectStep::ExcludeFirst,
        }) => None,
        Err(e) => panic!("{e}"),
    }
}

/// The full mask of the processors of `group` on this machine.
fn group_mask(topology: &rerun_proto::cpu::CpuTopology, group: u16) -> u64 {
    topology
        .cpus
        .iter()
        .filter(|c| c.group == group)
        .fold(0, |m, c| m | (1 << c.index))
}

/// `exclude_first: thread, max_threads: 1` (amendment P4-13): the one processor is CPU 1, which
/// stands in for core 0; a job mask without bit 0 is set and read back equal.
#[test]
fn exclude_first_thread_max_1_is_cpu_1_in_a_job() {
    let topology = WinOs.topology().unwrap();
    let Some(sel) = selected(&topology, &exclude_first(ExcludeFirst::Thread, Some(1))) else {
        return; // a one-processor machine: nothing to put in a job
    };
    if sel.group == 0 {
        assert_eq!(sel.mask, 0x2);
    }
    job_round_trip(&sel);
}

/// `exclude_first: thread` alone on the real topology: the whole group without CPU 0.
#[test]
fn exclude_first_thread_alone_in_a_job() {
    let topology = WinOs.topology().unwrap();
    let Some(sel) = selected(&topology, &exclude_first(ExcludeFirst::Thread, None)) else {
        return; // a one-processor machine: nothing to put in a job
    };
    let full = group_mask(&topology, sel.group);
    if sel.group == 0 {
        assert_eq!(sel.mask, full & !1);
    } else {
        assert_eq!(sel.mask, full);
    }
    job_round_trip(&sel);
}

/// `exclude_first: core` alone on the real topology: the whole group without the core of
/// CPU 0 (CPU 0 and its SMT sibling).
#[test]
fn exclude_first_core_alone_in_a_job() {
    let topology = WinOs.topology().unwrap();
    let Some(sel) = selected(&topology, &exclude_first(ExcludeFirst::Core, None)) else {
        return; // a one-processor machine: nothing to put in a job
    };
    let full = group_mask(&topology, sel.group);
    let cpu0 = topology.cpus.iter().find(|c| (c.group, c.index) == (0, 0));
    if let Some(cpu0) = cpu0.filter(|c| c.group == sel.group) {
        let core0 = cpu0.core;
        let gone = topology
            .cpus
            .iter()
            .filter(|c| c.core == core0)
            .fold(0u64, |m, c| m | (1 << c.index));
        assert_eq!(gone & 1, 1);
        assert_eq!(sel.mask, full & !gone);
    }
    job_round_trip(&sel);
}

#[test]
fn soft_limit_and_terminate_on_a_suspended_child() {
    let topology = WinOs.topology().unwrap();
    let ids = [topology.cpus[0].cpu_set_id];
    let app = cmd_exe();
    let spawn = Spawn {
        in_job: false,
        suspended: true,
        priority: None,
    };
    let child = Kid::new(WinOs.spawn(&app, &app, &spawn).unwrap());
    WinOs.set_cpu_sets(child.proc(), &ids).unwrap();
    // Never resumed: it never ran.
    assert_eq!(WinOs.terminate(child.take()), crate::os::Terminated::Ended);
}

/// The read-back has teeth: without step 3 the job and the thread report the whole group, not
/// the selection of `max_threads: 1`.
#[test]
fn read_back_without_the_limit_differs() {
    let topology = WinOs.topology().unwrap();
    let rule = CpuRule {
        max_threads: Some(1),
        prefer: Prefer::Performance,
        single_l3: true,
        prefer_l3: None,
        smt: false,
        mode: Mode::Hard,
        exclude_first: None,
    };
    let sel = select(&topology, &rule, Bitness::X64).unwrap();
    if sel.of < 2 {
        return;
    }
    let ga = GroupAffinity {
        group: sel.group,
        mask: sel.mask,
    };
    let app = cmd_exe();
    let spawn = Spawn {
        in_job: true,
        suspended: true,
        priority: None,
    };
    let child = Kid::new(WinOs.spawn(&app, &app, &spawn).unwrap());
    let back = WinOs.read_back(child.child()).unwrap();
    drop(child);
    assert_ne!(back.thread, ga);
    assert_ne!(back.job, [ga]);
}

/// `IsProcessInJob` of this test process (for the failure message: a CI runner may hold the
/// tests in a job of its own).
fn in_job() -> Result<bool, u32> {
    use windows_sys::Win32::System::JobObjects::IsProcessInJob;
    use windows_sys::Win32::System::Threading::GetCurrentProcess;
    let mut result = 0;
    // SAFETY: no arguments; the pseudo handle needs no closing.
    let me = unsafe { GetCurrentProcess() };
    // SAFETY: `me` is the current-process pseudo handle; a null job asks for any job; `result`
    // is valid for a write.
    let ok = unsafe { IsProcessInJob(me, std::ptr::null_mut(), &mut result) };
    if ok == 0 {
        return Err(super::last_error());
    }
    Ok(result != 0)
}

/// The start path rule is `CompareStringOrdinal(…, TRUE)`: case-insensitive for `Ä`/`ä`,
/// one unit for one unit, so `Straße` and `STRASSE` differ (two names on NTFS).
#[test]
fn same_path_is_ordinal_ignore_case() {
    let os = WinOs;
    assert!(os.same_path(&w(r"c:\games\GAME.EXE"), r"C:\Games\game.exe"));
    assert!(os.same_path(&w(r"C:\Spiele\Ä\game.exe"), r"C:\Spiele\ä\game.exe"));
    assert!(!os.same_path(&w(r"C:\Straße\game.exe"), r"C:\STRASSE\game.exe"));
    assert!(os.same_path(&w(r"C:\Straße\game.exe"), r"C:\STRAßE\game.exe"));
    assert!(!os.same_path(&w(r"C:\Games\game.exe"), r"C:\Games\game.exe "));
    assert!(!os.same_path(&w(r"C:\Games\game.exe"), r"C:\Games\gamé.exe"));
    // A lone surrogate is a unit like any other: never equal to valid text.
    assert!(!os.same_path(&[u16::from(b'C'), 0xD800], "C\u{FFFD}"));
}

/// An own child of this test process, ended with `terminate` when dropped, also when a test
/// panics before its end (SEC-N1 of the review of P3-4a): no suspended or running `cmd.exe`
/// outlives a failed test.
pub(crate) struct Kid(Option<launch::Child>);

impl Kid {
    pub(crate) fn new(child: launch::Child) -> Self {
        Self(Some(child))
    }

    pub(crate) fn child(&self) -> &launch::Child {
        self.0.as_ref().unwrap()
    }

    pub(crate) fn proc(&self) -> &launch::Proc {
        self.child().borrow()
    }

    pub(crate) fn pid(&self) -> u32 {
        WinOs.pid(self.child())
    }

    /// The child itself, for a call that consumes it (`wait`, `terminate`).
    pub(crate) fn take(mut self) -> launch::Child {
        self.0.take().unwrap()
    }
}

impl Drop for Kid {
    fn drop(&mut self) {
        if let Some(child) = self.0.take() {
            launch::terminate(child);
        }
    }
}

/// A `cmd.exe` child, suspended (it never runs).
pub(crate) fn suspended_cmd() -> Kid {
    let app = cmd_exe();
    let spawn = Spawn {
        in_job: false,
        suspended: true,
        priority: None,
    };
    Kid::new(WinOs.spawn(&app, &app, &spawn).unwrap())
}

/// A `cmd.exe` child that runs for about `seconds` (waiting on a `ping` of its own).
fn running_cmd(seconds: u32) -> Kid {
    let app = cmd_exe();
    let mut line = vec![u16::from(b'"')];
    line.extend_from_slice(&app);
    line.extend(w(&format!(
        "\" /d /q /c ping -n {} 127.0.0.1 >nul",
        seconds + 1
    )));
    Kid::new(WinOs.spawn(&app, &line, &Spawn::UNCHANGED).unwrap())
}

/// The selection of `max_threads: 1` on this machine: one logical processor.
fn one_processor() -> GroupAffinity {
    let topology = WinOs.topology().unwrap();
    let rule = CpuRule {
        max_threads: Some(1),
        prefer: Prefer::Performance,
        single_l3: true,
        prefer_l3: None,
        smt: false,
        mode: Mode::Hard,
        exclude_first: None,
    };
    let sel = select(&topology, &rule, Bitness::X64).unwrap();
    GroupAffinity {
        group: sel.group,
        mask: sel.mask,
    }
}

/// The snapshot lists an own child by PID and file name (plan P3-4 §7.3).
#[test]
fn snapshot_lists_an_own_child() {
    let child = suspended_cmd();
    let pid = child.pid();
    let list = WinOs.processes();
    drop(child);
    assert_ne!(pid, 0);
    let list = list.unwrap();
    assert!(list.len() <= crate::os::MAX_LISTED);
    let entry = list.iter().find(|l| l.pid == pid).unwrap();
    assert!(
        WinOs.same_path(&entry.name, "cmd.exe"),
        "{}",
        String::from_utf16_lossy(&entry.name)
    );
}

/// The facts of an own child: its image path, created after this process, and the same token
/// facts as this process (user SID, session, integrity RID), so `trust` is `Same` (A3).
#[test]
fn facts_of_an_own_child_are_the_same_trust() {
    let own = WinOs.own().unwrap();
    let child = suspended_cmd();
    let facts = WinOs
        .open_process(child.pid(), Access::default())
        .and_then(|t| WinOs.facts(&t));
    drop(child);
    let facts = facts.unwrap();
    let cmd = String::from_utf16(&cmd_exe()).unwrap();
    assert!(
        WinOs.same_path(&facts.image, &cmd),
        "{}",
        String::from_utf16_lossy(&facts.image)
    );
    assert!(facts.created >= own.created);
    assert_eq!(facts.token, own.token);
    assert_eq!(trust(&own.token, &facts.token), Trust::Same);
    // A SID (revision 1, S-1-5-… for a user) and an integrity RID of at least low (0x1000).
    assert_eq!(own.token.user.first(), Some(&1));
    assert!(own.token.user.len() >= 12);
    assert!(own.token.integrity >= 0x1000, "{:#x}", own.token.integrity);
}

/// What opening the PID of an own child that has ended finds.
#[derive(Debug, PartialEq, Eq)]
enum Reopen {
    /// `OpenProcess` fails with 87: no process has the PID.
    Gone,
    /// It opens, its facts fail with 31 and a zero wait reports it ended: the ended child
    /// (its process object still kept by some handle).
    Ended,
    /// It opens and reports the child's creation time and image: still the child, readable.
    Same,
    /// Anything else (another creation time or image, 5, another failure): the PID may belong
    /// to another process by now. Inconclusive; nothing more is read from it.
    Reused(String),
}

/// One query-rights open of `pid` (SEC-S2 of the review of P3-4a): the only reads are the
/// facts and a zero wait, both with `PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE`.
fn reopen(pid: u32, created: u64, image: &[u16]) -> Reopen {
    let t = match WinOs.open_process(pid, Access::default()) {
        Err(87) => return Reopen::Gone,
        Err(code) => return Reopen::Reused(format!("open {code}")),
        Ok(t) => t,
    };
    match WinOs.facts(&t) {
        Ok(f) if f.created == created && f.image == image => Reopen::Same,
        Ok(_) => Reopen::Reused("other facts".to_owned()),
        Err(31) if WinOs.wait_for(t.borrow(), 0) == Ok(true) => Reopen::Ended,
        Err(code) => Reopen::Reused(format!("facts {code}")),
    }
}

/// An own suspended child, its facts read while it exists, then ended (its last handle here
/// closed): its PID, creation time and image.
fn ended_child() -> (u32, u64, Vec<u16>) {
    let child = suspended_cmd();
    let pid = child.pid();
    let facts = super::process::facts(child.proc()).unwrap();
    assert_eq!(
        launch::terminate(child.take()),
        crate::os::Terminated::Ended
    );
    (pid, facts.created, facts.image)
}

/// `OpenProcess` on the PID of a child that ended (its last handle here closed) ends in
/// `ERROR_INVALID_PARAMETER`, the code `run::watch` reads as "gone, not refused" (B1 of the
/// review of P3-4). For 20 to 40 ms after the end the open still succeeds (measured on the
/// developer machine; another holder of a handle, e.g. a scanner, keeps the process object):
/// retried, every answer is reported. A PID that another process got meanwhile is
/// inconclusive: the test stops without a verdict and reads nothing more from it.
#[test]
fn open_of_an_exited_pid_fails_with_87() {
    let (pid, created, image) = ended_child();
    let mut seen = Vec::new();
    for _ in 0..50 {
        let r = reopen(pid, created, &image);
        let stop = matches!(r, Reopen::Gone | Reopen::Reused(_));
        seen.push(r);
        if stop {
            break;
        }
        WinOs.sleep_ms(20);
    }
    eprintln!("B1: OpenProcess of an ended child's PID, in order: {seen:?}");
    if let Some(Reopen::Reused(why)) = seen.last() {
        eprintln!("B1: PID {pid} reused ({why}): inconclusive");
        return;
    }
    assert_eq!(seen.last(), Some(&Reopen::Gone), "{seen:?}");
}

/// What `run::watch::pick` relies on for a candidate that ended between the snapshot and the
/// open: right after the end it can often still be opened, but its facts fail (31) and a zero
/// wait reports it ended; or the open already fails with 87. Either way gone, not refused;
/// never readable as the process it was. A reused PID is inconclusive.
#[test]
fn an_ended_process_is_gone_whether_or_not_it_opens() {
    let (pid, created, image) = ended_child();
    let r = reopen(pid, created, &image);
    eprintln!("B1: an ended child's PID reopened at once: {r:?}");
    assert!(
        matches!(r, Reopen::Gone | Reopen::Ended | Reopen::Reused(_)),
        "{r:?}"
    );
}

/// A target opened with query rights only cannot be changed (W7: the rights are the bound).
#[test]
fn a_query_only_target_cannot_be_set() {
    let child = suspended_cmd();
    let mut t = WinOs.open_process(child.pid(), Access::default()).unwrap();
    let prio = WinOs.set_priority(&t, priority_class(Priority::High));
    let job = WinOs.attach_job(&mut t, one_processor(), JOB_LIMIT_BREAKAWAY_OK);
    drop(t);
    drop(child);
    assert_eq!(prio, Err(5));
    assert_eq!(job, Err(5));
}

/// `KILL_ON_JOB_CLOSE` is refused before anything is created (A1).
#[test]
fn attach_job_refuses_kill_on_job_close() {
    let child = suspended_cmd();
    let access = Access {
        job: true,
        ..Access::default()
    };
    let mut t = WinOs.open_process(child.pid(), access).unwrap();
    let r = WinOs.attach_job(&mut t, one_processor(), JOB_LIMIT_BREAKAWAY_OK | 0x2000);
    let kept = WinOs.job_affinity(t.borrow());
    drop(t);
    drop(child);
    assert_eq!(r, Err(87));
    // No job was kept in the target (ERROR_INVALID_HANDLE).
    assert_eq!(kept, Err(6));
}

/// A1 (review of P3-4): a running child (not suspended, in no job of the shim) joins a new job
/// with one processor; the job and the process report it. Closing the job handle (dropping the
/// target) leaves the child running and still limited: the limit lasts as long as the
/// process, and nothing ends it (no `KILL_ON_JOB_CLOSE`).
#[test]
fn attach_job_to_a_running_child_outlives_the_job_handle() {
    let ga = one_processor();
    let child = running_cmd(20);
    let access = Access {
        job: true,
        ..Access::default()
    };
    let mut t = WinOs.open_process(child.pid(), access).unwrap();
    let attached = WinOs.attach_job(&mut t, ga, JOB_LIMIT_BREAKAWAY_OK);
    let job = WinOs.job_affinity(t.borrow());
    let mask = WinOs.process_affinity(t.borrow());
    drop(t);
    let alive = WinOs.wait_for(child.proc(), 500);
    let after = WinOs.process_affinity(child.proc());
    drop(child);
    attached.unwrap();
    assert_eq!(job, Ok(vec![ga]));
    assert_eq!(mask, Ok(ga.mask));
    assert_eq!(
        alive,
        Ok(false),
        "the child ended when the job handle closed"
    );
    assert_eq!(after, Ok(ga.mask));
}

/// The priority class and the default CPU Sets on a running child, read back, the class put
/// back (plan P3-4 §7.3).
#[test]
fn priority_and_cpu_sets_on_a_running_child() {
    let topology = WinOs.topology().unwrap();
    let id = topology.cpus[0].cpu_set_id;
    let child = running_cmd(10);
    let access = Access {
        cpu_sets: true,
        priority: true,
        ..Access::default()
    };
    let t = WinOs.open_process(child.pid(), access).unwrap();
    let old = WinOs.priority_class(t.borrow());
    let high = priority_class(Priority::High);
    let set = WinOs.set_priority(&t, high);
    let now = WinOs.priority_class(t.borrow());
    let sets = WinOs.set_cpu_sets(t.borrow(), &[id]);
    let read = WinOs.cpu_sets(t.borrow());
    let back = old.map(|class| WinOs.set_priority(&t, class));
    let again = WinOs.priority_class(t.borrow());
    drop(t);
    drop(child);
    let old = old.unwrap();
    assert_eq!(set, Ok(()));
    assert_eq!(now, Ok(high));
    assert_eq!(sets, Ok(()));
    assert_eq!(read, Ok(vec![id]));
    assert_eq!(back, Ok(Ok(())));
    assert_eq!(again, Ok(old));
}

/// A6 (review of P3-4): CPU time of one Toolhelp32 process snapshot on this machine, from
/// `GetThreadTimes` of this thread over 50 snapshots. Printed (`--nocapture`); the bound only
/// catches a gross regression.
#[test]
fn snapshot_cpu_time() {
    const N: u32 = 50;
    let before = thread_cpu_100ns();
    let start = std::time::Instant::now();
    let mut entries = 0;
    for _ in 0..N {
        entries = WinOs.processes().unwrap().len();
    }
    let wall = start.elapsed() / N;
    let spent = thread_cpu_100ns() - before;
    let per_us = spent / u64::from(N) / 10;
    eprintln!(
        "A6: one Toolhelp32 snapshot: {per_us} us CPU, {wall:?} wall ({entries} processes, \
         {N} snapshots; thread time ticks at ~15.6 ms)"
    );
    assert!(per_us < 50_000, "{per_us} us per snapshot");
}

/// Kernel plus user time of this thread, in 100 ns units.
fn thread_cpu_100ns() -> u64 {
    use windows_sys::Win32::Foundation::FILETIME;
    use windows_sys::Win32::System::Threading::{GetCurrentThread, GetThreadTimes};
    let mut t = [FILETIME::default(); 4];
    let [c, e, k, u] = &mut t;
    // SAFETY: no arguments; the pseudo handle needs no closing.
    let me = unsafe { GetCurrentThread() };
    // SAFETY: `me` is the current-thread pseudo handle; the four FILETIMEs are valid for a
    // write.
    let ok = unsafe { GetThreadTimes(me, c, e, k, u) };
    assert_ne!(ok, 0);
    let v = |f: &FILETIME| (u64::from(f.dwHighDateTime) << 32) | u64::from(f.dwLowDateTime);
    v(k) + v(u)
}
