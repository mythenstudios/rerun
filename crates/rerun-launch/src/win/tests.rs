//! `WinOs` on real Windows. Nothing on the system changes: the only process started is
//! `System32\cmd.exe` (`/c exit <n>`, never resumed, or `/c ping -n <n> 127.0.0.1 >nul` for a
//! child that runs a few seconds; ending that `cmd` leaves its `ping` to finish on its own),
//! and the only limits, priorities and jobs set are on such a child of this test process.
//! `watch` opens only these children (plan P3-4 §7.3), never another process.

use std::borrow::Borrow;
use std::os::windows::ffi::OsStrExt;
use std::path::PathBuf;

use rerun_proto::cpu::rule::{Bitness, CpuRule, Mode, Prefer, select};
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
    let child = WinOs.spawn(&app, &line, &spawn).unwrap();
    if let Err(e) = WinOs.limit_job(&child, ga) {
        launch::terminate(child);
        panic!(
            "JobObjectGroupInformationEx failed with {e}; this test process in a job: {:?}",
            in_job()
        );
    }
    let back = WinOs.read_back(&child).unwrap();
    assert_eq!(back.job, [ga]);
    assert_eq!(back.thread, ga);
    WinOs.resume(&child).unwrap();
    assert_eq!(WinOs.wait(child), Ok(3));
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
    let child = WinOs.spawn(&app, &app, &spawn).unwrap();
    WinOs.set_cpu_sets(child.borrow(), &ids).unwrap();
    // Never resumed: it never ran.
    assert_eq!(WinOs.terminate(child), crate::os::Terminated::Ended);
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
    let child = WinOs.spawn(&app, &app, &spawn).unwrap();
    let back = WinOs.read_back(&child).unwrap();
    assert_ne!(back.thread, ga);
    assert_ne!(back.job, [ga]);
    launch::terminate(child);
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

/// A `cmd.exe` child, suspended (it never runs; ended with `terminate`).
pub(crate) fn suspended_cmd() -> launch::Child {
    let app = cmd_exe();
    let spawn = Spawn {
        in_job: false,
        suspended: true,
        priority: None,
    };
    WinOs.spawn(&app, &app, &spawn).unwrap()
}

/// A `cmd.exe` child that runs for about `seconds` (waiting on a `ping` of its own).
fn running_cmd(seconds: u32) -> launch::Child {
    let app = cmd_exe();
    let mut line = vec![u16::from(b'"')];
    line.extend_from_slice(&app);
    line.extend(w(&format!(
        "\" /d /q /c ping -n {} 127.0.0.1 >nul",
        seconds + 1
    )));
    WinOs.spawn(&app, &line, &Spawn::UNCHANGED).unwrap()
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
    let pid = WinOs.pid(&child);
    let list = WinOs.processes();
    WinOs.terminate(child);
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
    let pid = WinOs.pid(&child);
    let facts = WinOs
        .open_process(pid, Access::default())
        .and_then(|t| WinOs.facts(&t));
    WinOs.terminate(child);
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

/// `OpenProcess` on the PID of a child that exited (its last handle here closed) fails with
/// `ERROR_INVALID_PARAMETER`, the code `run::watch` reads as "gone, not refused" (B1 of the
/// review of P3-4). For 20 to 40 ms after the end the open still succeeds (measured on the
/// developer machine; another holder of a handle, e.g. a scanner, keeps the process object):
/// retried, every code seen is reported.
#[test]
fn open_of_an_exited_pid_fails_with_87() {
    let app = cmd_exe();
    let mut line = vec![u16::from(b'"')];
    line.extend_from_slice(&app);
    line.extend(w("\" /c exit 0"));
    let child = WinOs.spawn(&app, &line, &Spawn::UNCHANGED).unwrap();
    let pid = WinOs.pid(&child);
    assert_eq!(WinOs.wait(child), Ok(0));
    let mut codes = Vec::new();
    for _ in 0..50 {
        match WinOs.open_process(pid, Access::default()) {
            Err(code) => {
                codes.push(code);
                if code == 87 {
                    break;
                }
            }
            Ok(_) => codes.push(0),
        }
        WinOs.sleep_ms(20);
    }
    eprintln!("B1: OpenProcess of an exited PID, codes in order (0 = opened): {codes:?}");
    assert_eq!(
        codes.last(),
        Some(&87),
        "codes seen (0 = opened): {codes:?}"
    );
}

/// A target opened with query rights only cannot be changed (W7: the rights are the bound).
#[test]
fn a_query_only_target_cannot_be_set() {
    let child = suspended_cmd();
    let mut t = WinOs
        .open_process(WinOs.pid(&child), Access::default())
        .unwrap();
    let prio = WinOs.set_priority(&t, priority_class(Priority::High));
    let job = WinOs.attach_job(&mut t, one_processor(), JOB_LIMIT_BREAKAWAY_OK);
    drop(t);
    WinOs.terminate(child);
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
    let mut t = WinOs.open_process(WinOs.pid(&child), access).unwrap();
    let r = WinOs.attach_job(&mut t, one_processor(), JOB_LIMIT_BREAKAWAY_OK | 0x2000);
    let kept = WinOs.job_affinity(t.borrow());
    drop(t);
    WinOs.terminate(child);
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
    let mut t = WinOs.open_process(WinOs.pid(&child), access).unwrap();
    let attached = WinOs.attach_job(&mut t, ga, JOB_LIMIT_BREAKAWAY_OK);
    let job = WinOs.job_affinity(t.borrow());
    let mask = WinOs.process_affinity(t.borrow());
    drop(t);
    let alive = WinOs.wait_for(child.borrow(), 500);
    let after = WinOs.process_affinity(child.borrow());
    WinOs.terminate(child);
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
    let t = WinOs.open_process(WinOs.pid(&child), access).unwrap();
    let old = WinOs.priority_class(t.borrow());
    let high = priority_class(Priority::High);
    let set = WinOs.set_priority(&t, high);
    let now = WinOs.priority_class(t.borrow());
    let sets = WinOs.set_cpu_sets(t.borrow(), &[id]);
    let read = WinOs.cpu_sets(t.borrow());
    let back = old.map(|class| WinOs.set_priority(&t, class));
    let again = WinOs.priority_class(t.borrow());
    drop(t);
    WinOs.terminate(child);
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

/// What `run::watch::pick` relies on for a candidate that ended between the snapshot and the
/// open: right after the end it can often still be opened (measured: for 20 to 40 ms after
/// the last handle here closed), but its facts fail and a zero wait reports it ended; or the
/// open already fails with 87. Either way it is gone, not refused.
#[test]
fn an_ended_process_is_gone_whether_or_not_it_opens() {
    let app = cmd_exe();
    let mut line = vec![u16::from(b'"')];
    line.extend_from_slice(&app);
    line.extend(w("\" /c exit 0"));
    let child = WinOs.spawn(&app, &line, &Spawn::UNCHANGED).unwrap();
    let pid = WinOs.pid(&child);
    assert_eq!(WinOs.wait(child), Ok(0));
    match WinOs.open_process(pid, Access::default()) {
        Err(code) => assert_eq!(code, 87),
        Ok(t) => {
            let facts = WinOs.facts(&t);
            let ended = WinOs.wait_for(t.borrow(), 0);
            eprintln!(
                "B1: an ended process opened; facts {:?}, ended {ended:?}",
                facts.as_ref().map(|_| ())
            );
            assert!(facts.is_err());
            assert_eq!(ended, Ok(true));
        }
    }
}
