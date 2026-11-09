//! A7 of the review of P3-4: W3 to W5 of `watch` ([`set`]) on real Windows, on a target that
//! already is in a job (as under a launcher or a CI runner that holds its processes in one).
//! The target is a suspended `System32\cmd.exe` child of this test process, created inside a
//! parent job of its own by `WinOs::spawn`; it never runs and is ended at the end. Nothing
//! else is opened.

use std::borrow::Borrow;
use std::os::windows::ffi::OsStrExt;
use std::path::PathBuf;

use rerun_proto::cpu::rule::Mode;
use rerun_proto::launch::Check;
use rerun_proto::profile::Priority;

use super::{Candidate, Watch, set};
use crate::os::{Access, GroupAffinity, Os, Spawn, priority_class};
use crate::run::{Applied, Limit, Rule, Skip};
use crate::win::WinOs;
use crate::win::launch::{Child, Target};

fn cmd_exe() -> Vec<u16> {
    #[expect(
        clippy::disallowed_methods,
        reason = "test: the Windows directory for a harmless system binary"
    )]
    let root = std::env::var_os("SystemRoot").unwrap();
    let p = PathBuf::from(root).join("System32").join("cmd.exe");
    p.as_os_str().encode_wide().collect()
}

/// A suspended `cmd.exe` in a parent job (`JOB_OBJECT_LIMIT_BREAKAWAY_OK`), with `parent` as
/// the parent job's group affinity if given.
fn child_in_a_job(parent: Option<GroupAffinity>) -> Child {
    let app = cmd_exe();
    let spawn = Spawn {
        in_job: true,
        suspended: true,
        priority: None,
    };
    let child = WinOs.spawn(&app, &app, &spawn).unwrap();
    if let Some(ga) = parent {
        WinOs.limit_job(&child, ga).unwrap();
    }
    child
}

/// The child as `pick` hands it to `set`: opened with query rights, facts read.
fn candidate(child: &Child) -> Candidate<Target> {
    let pid = WinOs.pid(child);
    let handle = WinOs.open_process(pid, Access::default()).unwrap();
    let facts = WinOs.facts(&handle).unwrap();
    Candidate { pid, facts, handle }
}

/// A hard rule with priority `high` on `ga`.
fn watch(ga: GroupAffinity) -> Watch {
    let target = String::from_utf16(&cmd_exe()).unwrap();
    Watch {
        name: "cmd.exe".to_owned(),
        target,
        limit: Some((
            Limit::Hard(ga),
            Applied {
                mode: Mode::Hard,
                threads: 1,
                of: 1,
            },
        )),
        priority: Some(Priority::High),
        timeout_ms: 0,
    }
}

/// Two logical processors of one group, or `None` on a machine with fewer.
fn two_processors() -> Option<(GroupAffinity, GroupAffinity)> {
    let topology = WinOs.topology().unwrap();
    let first = topology.cpus.first()?;
    let second = topology
        .cpus
        .iter()
        .find(|c| c.group == first.group && c.index != first.index)?;
    let ga = |index: u8| GroupAffinity {
        group: first.group,
        mask: 1u64 << index,
    };
    Some((ga(first.index), ga(second.index)))
}

/// A7: a target in a parent job without a group limit joins the new job (a nested job): `applied`,
/// and the check about 5 s later reads `ok` (the new job's one entry, the process mask equal).
#[test]
fn a_target_in_a_job_without_a_limit_is_applied() {
    let Some((ga, _)) = two_processors() else {
        return;
    };
    let child = child_in_a_job(None);
    let c = candidate(&child);
    let mut held = Vec::new();
    let found = set(&WinOs, &watch(ga), c, &mut held);
    let class = WinOs.priority_class(child.borrow());
    drop(held);
    WinOs.terminate(child);
    assert_eq!(
        found.rule,
        Rule::Applied {
            cpu: Some(Applied {
                mode: Mode::Hard,
                threads: 1,
                of: 1
            }),
            priority: Some(Priority::High),
        }
    );
    assert_eq!(found.check, Some(Check::Ok));
    assert_eq!(found.restore, None);
    assert_eq!(class, Ok(priority_class(Priority::High)));
}

/// A target in a parent job limited to another processor (measured, Windows 11 build 26300):
/// joining a new job whose selection is disjoint from the parent's **succeeds**, but the
/// process keeps the parent's mask. The read-back right after the join sees it: `set` reports
/// `job_ineffective` and puts the priority class back; no check. The membership in the new
/// job stays (it cannot be undone) and has no effect.
#[test]
fn a_target_in_a_job_with_a_disjoint_mask_is_job_ineffective_with_the_priority_back() {
    let Some((parent, ga)) = two_processors() else {
        return;
    };
    let child = child_in_a_job(Some(parent));
    let before = WinOs.priority_class(child.borrow());
    let c = candidate(&child);
    let mut held = Vec::new();
    let found = set(&WinOs, &watch(ga), c, &mut held);
    let class = WinOs.priority_class(child.borrow());
    let mask = WinOs.process_affinity(child.borrow());
    drop(held);
    WinOs.terminate(child);
    eprintln!(
        "A7: disjoint nested job: {:?}, process mask {mask:?} (parent {:#x}, new {:#x})",
        found.rule, parent.mask, ga.mask
    );
    assert_eq!(found.rule, Rule::Skipped(Skip::JobIneffective));
    assert_eq!(found.check, None);
    assert_eq!(found.restore, None);
    assert_eq!(class, before);
    assert_eq!(class, Ok(priority_class(Priority::Normal)));
    // The parent's limit stays in force.
    assert_eq!(mask, Ok(parent.mask));
}

/// W4 on real Windows: a CPU step that fails (here the job refuses a group that does not
/// exist) is `job_failed:<code>`, and the priority class set before is put back.
#[test]
fn a_failed_job_puts_the_priority_back() {
    let child = child_in_a_job(None);
    let before = WinOs.priority_class(child.borrow());
    let c = candidate(&child);
    let mut held = Vec::new();
    let nowhere = GroupAffinity {
        group: u16::MAX,
        mask: 1,
    };
    let found = set(&WinOs, &watch(nowhere), c, &mut held);
    let after = WinOs.priority_class(child.borrow());
    drop(held);
    WinOs.terminate(child);
    eprintln!("W4: job refused: {:?}", found.rule);
    assert!(
        matches!(found.rule, Rule::Skipped(Skip::Job(_))),
        "{:?}",
        found.rule
    );
    assert_eq!(found.check, None);
    assert_eq!(found.restore, None);
    assert_eq!(after, before);
    assert_eq!(after, Ok(priority_class(Priority::Normal)));
}
