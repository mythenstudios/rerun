//! `WinOs` on real Windows. Nothing on the system changes: the only process started is
//! `System32\cmd.exe` (`/c exit <n>`, or never resumed), and the only limits set are on that
//! child and its own job.

use std::os::windows::ffi::OsStrExt;
use std::path::PathBuf;

use rerun_proto::cpu::rule::{Bitness, CpuRule, Mode, Prefer, select};

use super::launch;
use crate::os::{GroupAffinity, Os, Spawn};
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
    WinOs.set_cpu_sets(&child, &ids).unwrap();
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
