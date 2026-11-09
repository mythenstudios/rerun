//! `watch` (P3-4, docs/04): start Steam's command unchanged, find the game process that
//! appears after it, set the rule there, check it about 5 s later.
//!
//! - **Start (W1):** the shim reads its own creation time and token, then starts Steam's
//!   command with [`Spawn::UNCHANGED`]. 740 goes to `ShellExecuteExW` without a search (B2);
//!   any other start error is `spawn_failed:<code>` with nothing started (A9).
//! - **Search (W2, B1, A5, A6):** every [`POLL_MS`] for the first [`FAST_POLL_FOR_MS`], every
//!   [`SLOW_POLL_MS`] until [`SLOW_POLL_FOR_MS`], then every [`LATE_POLL_MS`], until the
//!   deadline (start + `watch_timeout_s`; 360 snapshots for 120 s), one process
//!   snapshot. Its entries are a name pre-filter only. The started child is excluded by PID
//!   before anything is opened. A new PID whose name matches is opened with query rights only
//!   (at most [`MAX_OPENS_PER_POLL`] per snapshot); a failed open or read skips it for this
//!   poll and remembers the code (except 87 on the open, or a failed read of a process that
//!   has ended: it is gone, not refused).
//!   Its handle reports the image path, the creation time and the token: a candidate has the
//!   target's path, was created at or after the shim, and runs as the same user in the same
//!   session ([`trust`], A3). Every other opened process stays
//!   held until the search ends and its PID is skipped without opening again (a held handle
//!   keeps the PID from being reused). Of several candidates the earliest created wins (then
//!   the smallest PID); the others stay untouched.
//! - **Target (W3):** a target at a higher integrity level ends the search untouched
//!   (`target_elevated`). Otherwise it is opened a second time with exactly the rights the
//!   profile needs while the first handle is held; the second handle must report the same
//!   facts. A failure here is `target_denied:<code>`.
//! - **Set (W4):** the priority class first (read the old one, set the new one; a failure is
//!   `priority_failed:<code>`, nothing set), then the CPU limit: hard = a new job with the
//!   selection on the still empty job, then the assignment ([`Os::attach_job`], never
//!   `KILL_ON_JOB_CLOSE`, A1), then a read-back: the job's entry and the process affinity must
//!   be the selection, else `job_ineffective` (A7: a job the target already was in keeps its
//!   limit; the membership stays) or `read_back_failed:<code>`; soft = default CPU Sets. A CPU failure puts the old priority
//!   class back (a failure of that is recorded, A4): skipped means nothing stays set, except a
//!   priority restore that failed and says so.
//! - **Check and search on (W5):** the check of `direct` on the target. A target that ends
//!   within the check (a stub handing over) lets the search go on, at most [`MAX_TARGETS`]
//!   targets and only before the deadline. The last target handled gives the result; without
//!   one, `target_denied:<last code>` if a candidate was refused, `search_failed:<last code>`
//!   if no snapshot ever succeeded, `target_not_found` otherwise.
//! - **Lifetime (W6, rule 1):** the search waits on the started child while it runs (and
//!   notices its end), then sleeps. Search plus check end at most one check after the
//!   deadline; `run` writes the result once, then waits for the started child.
//! - A target is never ended: there is no call from a target to `terminate` (A2).

use std::borrow::Borrow;

use rerun_proto::launch::Check;
use rerun_proto::profile::{LaunchProfile, Priority};

use super::{
    Applied, Done, ERROR_ELEVATION_REQUIRED, EXIT_NOT_STARTED, Limit, Rule, Skip, Start, check,
    shell, unchanged,
};
use crate::cmdline::Command;
use crate::os::{
    Access, Facts, GroupAffinity, JOB_LIMIT_BREAKAWAY_OK, Os, Own, Spawn, Token, priority_class,
};

/// The poll interval of the first [`FAST_POLL_FOR_MS`] of the search (W2).
pub(crate) const POLL_MS: u32 = 100;
/// The poll interval after that (A6: a snapshot costs about 3.5 ms CPU with 240 processes,
/// measured; most games appear early).
pub(crate) const SLOW_POLL_MS: u32 = 250;
/// The poll interval from [`SLOW_POLL_FOR_MS`] on (A6: a full search about 1.3 s CPU).
pub(crate) const LATE_POLL_MS: u32 = 500;
/// How long the search polls every [`POLL_MS`].
pub(crate) const FAST_POLL_FOR_MS: u64 = 10_000;
/// Until when (from the start of the search) it polls every [`SLOW_POLL_MS`].
pub(crate) const SLOW_POLL_FOR_MS: u64 = 30_000;
/// Targets handled per start (a target that ends within the check lets the search go on).
pub(crate) const MAX_TARGETS: u8 = 4;
/// New PIDs opened per snapshot (A5: held PIDs are skipped without opening and do not count).
pub(crate) const MAX_OPENS_PER_POLL: usize = 8;
/// winerror.h `ERROR_INVALID_DATA`: the second handle of a target reports other facts than
/// the first (cannot happen while the first is held; refused if it does).
pub(crate) const ERROR_INVALID_DATA: u32 = 13;
/// winerror.h `ERROR_INVALID_PARAMETER`: what `OpenProcess` reports for a PID that no longer
/// exists (the candidate ended after the snapshot; not a refusal).
const ERROR_INVALID_PARAMETER: u32 = 87;

/// A `watch` profile on this machine.
pub(crate) struct Watch {
    /// The profile's `target`: the game's image path.
    pub(crate) target: String,
    /// Its last component, the snapshot pre-filter.
    pub(crate) name: String,
    /// The CPU limit, as for `direct`.
    pub(crate) limit: Option<(Limit, Applied)>,
    /// The priority class.
    pub(crate) priority: Option<Priority>,
    /// The search's length (`watch_timeout_s`).
    pub(crate) timeout_ms: u64,
}

impl Watch {
    pub(super) fn new(profile: &LaunchProfile, limit: Option<(Limit, Applied)>) -> Self {
        let name = profile
            .target
            .rsplit(['\\', '/'])
            .next()
            .unwrap_or_default()
            .to_owned();
        Self {
            target: profile.target.clone(),
            name,
            limit,
            priority: profile.priority,
            timeout_ms: u64::from(profile.watch_timeout_s) * 1_000,
        }
    }

    /// The rights the rule needs on the target (W7).
    fn access(&self) -> Access {
        Access {
            job: matches!(self.limit, Some((Limit::Hard(_), _))),
            cpu_sets: matches!(self.limit, Some((Limit::Soft(_), _))),
            priority: self.priority.is_some(),
        }
    }
}

/// A process's token compared with the shim's (ADR 0022 M1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Trust {
    /// Same user, same session, integrity level at most the shim's.
    Same,
    /// Same user and session, higher integrity level (an elevated game or launcher).
    Elevated,
    /// Another user or another session: never a candidate.
    Foreign,
}

/// The trust of `target` from the shim's point of view (A3; pure).
pub(crate) fn trust(own: &Token, target: &Token) -> Trust {
    if own.user != target.user || own.session != target.session {
        Trust::Foreign
    } else if target.integrity > own.integrity {
        Trust::Elevated
    } else {
        Trust::Same
    }
}

/// What the search ends with.
struct Found {
    rule: Rule,
    check: Option<Check>,
    restore: Option<u32>,
}

impl Found {
    fn skipped(skip: Skip) -> Self {
        Self {
            rule: Rule::Skipped(skip),
            check: None,
            restore: None,
        }
    }
}

/// A candidate of one snapshot: opened with query rights, facts read.
struct Candidate<T> {
    pid: u32,
    facts: Facts,
    handle: T,
}

/// Starts Steam's command unchanged and searches; see the module documentation.
pub(super) fn start<O: Os>(os: &O, cmd: &Command<'_>, w: &Watch) -> Done<O::Child> {
    let own = match os.own() {
        Ok(o) => o,
        Err(code) => return unchanged(os, cmd, Skip::SearchFailed(code), None),
    };
    let child = match os.spawn(cmd.app, cmd.tail, &Spawn::UNCHANGED) {
        Ok(c) => c,
        Err(ERROR_ELEVATION_REQUIRED) => {
            return shell(os, cmd, Rule::Skipped(Skip::ElevationRequired), None);
        }
        // A9: this was the unchanged start already; nothing to fall back to.
        Err(code) => {
            return Done {
                rule: Rule::Skipped(Skip::Spawn(code)),
                start: Start::Failed(code),
                terminated: None,
                check: None,
                child: None,
                exit: EXIT_NOT_STARTED,
                restore: None,
            };
        }
    };
    let found = search(os, w, &own, &child);
    Done {
        rule: found.rule,
        start: Start::Created,
        terminated: None,
        check: found.check,
        child: Some(child),
        exit: 0,
        restore: found.restore,
    }
}

/// The search loop (W2–W6).
fn search<O: Os>(os: &O, w: &Watch, own: &Own, child: &O::Child) -> Found {
    let child_pid = os.pid(child);
    let begin = os.now_ms();
    let deadline = begin.saturating_add(w.timeout_ms);
    // Rejected and handled processes: held until the search ends, their PIDs skipped (A5).
    let mut held: Vec<(u32, O::Target)> = Vec::new();
    let mut child_running = true;
    let mut listed_once = false;
    let mut snapshot_error = None;
    let mut denied = None;
    let mut targets = 0u8;
    let mut last: Option<Found> = None;
    while os.now_ms() < deadline {
        match os.processes() {
            Err(code) => snapshot_error = Some(code),
            Ok(list) => {
                listed_once = true;
                if let Some(c) = pick(os, w, own, child_pid, &list, &mut held, &mut denied) {
                    targets += 1;
                    let found = if trust(&own.token, &c.facts.token) == Trust::Elevated {
                        held.push((c.pid, c.handle));
                        Found::skipped(Skip::TargetElevated)
                    } else {
                        set(os, w, c, &mut held)
                    };
                    let again = found.check == Some(Check::ExitedEarly) && targets < MAX_TARGETS;
                    last = Some(found);
                    if !again {
                        break;
                    }
                }
            }
        }
        let since = os.now_ms().saturating_sub(begin);
        let ms = if since < FAST_POLL_FOR_MS {
            POLL_MS
        } else if since < SLOW_POLL_FOR_MS {
            SLOW_POLL_MS
        } else {
            LATE_POLL_MS
        };
        if child_running {
            match os.wait_for(child.borrow(), ms) {
                Ok(false) => {}
                // The child ended (or cannot be waited on): pace by sleeping from now on.
                Ok(true) | Err(_) => {
                    child_running = false;
                    os.sleep_ms(ms);
                }
            }
        } else {
            os.sleep_ms(ms);
        }
    }
    drop(held);
    if let Some(found) = last {
        return found;
    }
    Found::skipped(if !listed_once {
        Skip::SearchFailed(snapshot_error.unwrap_or_default())
    } else if let Some(code) = denied {
        Skip::TargetDenied(code)
    } else {
        Skip::TargetNotFound
    })
}

/// The candidates of one snapshot (B1, A5): see the module documentation.
fn pick<O: Os>(
    os: &O,
    w: &Watch,
    own: &Own,
    child_pid: u32,
    list: &[crate::os::Listed],
    held: &mut Vec<(u32, O::Target)>,
    denied: &mut Option<u32>,
) -> Option<Candidate<O::Target>> {
    let mut opened = 0;
    let mut found: Vec<Candidate<O::Target>> = Vec::new();
    for l in list {
        if l.pid == child_pid
            || held.iter().any(|(pid, _)| *pid == l.pid)
            || !os.same_path(&l.name, &w.name)
        {
            continue;
        }
        if opened == MAX_OPENS_PER_POLL {
            break;
        }
        opened += 1;
        let handle = match os.open_process(l.pid, Access::default()) {
            Ok(h) => h,
            // The process ended after the snapshot: gone, not refused.
            Err(ERROR_INVALID_PARAMETER) => continue,
            Err(code) => {
                *denied = Some(code);
                continue;
            }
        };
        let facts = match os.facts(&handle) {
            Ok(f) => f,
            Err(code) => {
                // A process that ended can still be opened for a moment (until the last
                // handle to it closes) but no longer read (measured: ERROR_GEN_FAILURE, 31):
                // gone like 87, not refused.
                if os.wait_for(handle.borrow(), 0) != Ok(true) {
                    *denied = Some(code);
                }
                held.push((l.pid, handle));
                continue;
            }
        };
        let fits = os.same_path(&facts.image, &w.target)
            && facts.created >= own.created
            && trust(&own.token, &facts.token) != Trust::Foreign;
        if fits {
            found.push(Candidate {
                pid: l.pid,
                facts,
                handle,
            });
        } else {
            held.push((l.pid, handle));
        }
    }
    found.sort_by_key(|c| (c.facts.created, c.pid));
    // The others are dropped untouched: they may be the next target after this one.
    found.into_iter().next()
}

/// The read-back right after the join (A7): the job holds exactly the selection and the
/// process affinity is the selection. A target that already was in a job with another limit
/// joins without effect (measured: the parent's mask stays), which is `job_ineffective`; the
/// membership cannot be undone, the caller puts the priority class back. A failed read is
/// `read_back_failed:<code>`.
fn joined<O: Os>(os: &O, t: &O::Proc, ga: GroupAffinity) -> Result<(), Skip> {
    let job = os.job_affinity(t).map_err(Skip::ReadBack)?;
    let mask = os.process_affinity(t).map_err(Skip::ReadBack)?;
    if job == [ga] && mask == ga.mask {
        Ok(())
    } else {
        Err(Skip::JobIneffective)
    }
}

/// W3–W5 on a candidate of the same user and session.
fn set<O: Os>(
    os: &O,
    w: &Watch,
    c: Candidate<O::Target>,
    held: &mut Vec<(u32, O::Target)>,
) -> Found {
    let Candidate { pid, facts, handle } = c;
    // The query handle stays held: the PID cannot be reused while the second one is opened,
    // and it is skipped for the rest of the search.
    held.push((pid, handle));
    let mut t = match os.open_process(pid, w.access()) {
        Ok(t) => t,
        Err(code) => return Found::skipped(Skip::TargetDenied(code)),
    };
    match os.facts(&t) {
        Ok(f) if f == facts => {}
        Ok(_) => return Found::skipped(Skip::TargetDenied(ERROR_INVALID_DATA)),
        Err(code) => return Found::skipped(Skip::TargetDenied(code)),
    }
    // (1) The priority class: reversible, so first.
    let old = match w.priority {
        None => None,
        Some(p) => {
            let old = match os.priority_class(t.borrow()) {
                Ok(class) => class,
                Err(code) => return Found::skipped(Skip::Priority(code)),
            };
            if let Err(code) = os.set_priority(&t, priority_class(p)) {
                return Found::skipped(Skip::Priority(code));
            }
            Some(old)
        }
    };
    // (2) The CPU limit: joining a job lasts as long as the process, so last.
    let cpu = match &w.limit {
        None => Ok(()),
        Some((Limit::Hard(ga), _)) => os
            .attach_job(&mut t, *ga, JOB_LIMIT_BREAKAWAY_OK)
            .map_err(Skip::Job)
            .and_then(|()| joined(os, t.borrow(), *ga)),
        Some((Limit::Soft(ids), _)) => os.set_cpu_sets(t.borrow(), ids).map_err(Skip::CpuSets),
    };
    if let Err(skip) = cpu {
        let restore = old.and_then(|class| os.set_priority(&t, class).err());
        return Found {
            rule: Rule::Skipped(skip),
            check: None,
            restore,
        };
    }
    let check = check(os, t.borrow(), w.limit.as_ref().map(|(l, _)| l), w.priority);
    Found {
        rule: Rule::Applied {
            cpu: w.limit.as_ref().map(|(_, a)| *a),
            priority: w.priority,
        },
        check: Some(check),
        restore: None,
    }
}

#[cfg(test)]
#[cfg(windows)]
#[path = "watch_win_tests.rs"]
mod win_tests;
