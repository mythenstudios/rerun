//! The lines of the launch results in `rerun status` (ADR 0022 amendment P3-2, ADR 0016). One
//! [`LaunchMsg`] is one line. Every field is typed and shown by Rerun's own words, except the
//! reason a file is unreadable and the target of a `watch` profile, which are [`Shown`] and
//! stand last on their line.
//!
//! `watch` (P3-4c, plan `P3-4` §3.5 and the review of P3-4a): every reason only `watch` writes
//! is explained on its line; otherwise the method is the result file's own `method=` line (a
//! journal head may be newer than the result, so it never decides the method), and with
//! `watch` `exited_early`, a soft `ok`, `read_back_failed` and the start of a skipped rule get
//! `watch` words, and a line names the target when the transaction that holds the profile has a
//! `watch` head too (the path comes from it). Without the line the shared words stay.

use std::fmt;

use rerun_core::escape::Shown;
use rerun_core::exec::launch_result::{
    AppliedCpu, Check, Ended, Mode, Priority, ProfileId, SkipReason, Start,
};

use rerun_core::journal::TxnId;

use super::Count;

/// Seconds since 1970-01-01 UTC, shown as `YYYY-MM-DD hh:mm:ss UTC`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Utc(pub u64);

/// The last second `Utc` shows as a date (9999-12-31 23:59:59); later is shown in seconds.
const MAX_SHOWN: u64 = 253_402_300_799;

impl fmt::Display for Utc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0 > MAX_SHOWN {
            return write!(f, "{} s after 1970", self.0);
        }
        let days = self.0 / 86_400;
        let secs = self.0 % 86_400;
        let (y, m, d) = civil(days);
        write!(
            f,
            "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02} UTC",
            secs / 3600,
            secs / 60 % 60,
            secs % 60
        )
    }
}

/// The proleptic Gregorian date of a day count since 1970-01-01 (H. Hinnant,
/// `civil_from_days`, for days >= 0).
fn civil(days: u64) -> (u64, u64, u64) {
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + u64::from(m <= 2);
    (y, m, d)
}

/// One line of the launch results.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LaunchMsg<'a> {
    /// The heading.
    Heading,
    /// The rule was applied to the last start.
    Applied {
        /// Profile.
        id: ProfileId,
        /// When.
        at: Utc,
        /// The CPU limit.
        cpu: Option<AppliedCpu>,
        /// The priority class.
        priority: Option<Priority>,
        /// The post-launch check.
        check: Check,
        /// The result says `method=watch`: the check covered the game
        /// process found after the start.
        watch: bool,
    },
    /// The rule was not applied to the last start.
    Skipped {
        /// Profile.
        id: ProfileId,
        /// When.
        at: Utc,
        /// Why.
        reason: SkipReason,
        /// How the game was started.
        start: Start,
        /// How a child created with the rule was ended.
        ended: Option<Ended>,
        /// `watch`: the priority class set on the game could not be put back (Win32 error).
        restore: Option<u32>,
        /// `method=watch`, a reason only `watch` writes, or a priority restore line.
        watch: bool,
    },
    /// `watch` (A4): the priority class set on the game could not be put back.
    PriorityNotRestored {
        /// Win32 error code.
        code: u32,
    },
    /// `method=watch` and a `watch` head holds the profile: what the rule was for (its path).
    Watched {
        /// The target.
        target: Shown<'a>,
    },
    /// The file cannot be read or decoded.
    Unreadable {
        /// Profile (of the file name).
        id: ProfileId,
        /// Why (escaped).
        why: Shown<'a>,
    },
    /// Entries of the folder that are not Rerun's.
    Other {
        /// How many.
        n: usize,
    },
    /// A start without a profile (`profile_missing`): the launch option is still set (A7, X12).
    OptionStillSet {
        /// Profile.
        id: ProfileId,
        /// A transaction not reverted holds a profile with this ID (the result may be older).
        held: Option<TxnId>,
    },
    /// A start without a profile although a forgotten transaction left one of this ID (it is
    /// missing now): the option should go (review L-b: a forgotten transaction cannot be
    /// reverted).
    OptionStillSetForgotten {
        /// Profile.
        id: ProfileId,
    },
    /// The check covered a launcher, not the game (A6: `method=direct`, the launcher from the
    /// journal head).
    CheckedLauncher {
        /// The launcher.
        start: Shown<'a>,
    },
    /// The folder cannot be read.
    FolderUnreadable {
        /// The error (escaped).
        error: Shown<'a>,
    },
}

fn priority(p: Priority) -> &'static str {
    match p {
        Priority::Normal => "normal",
        Priority::AboveNormal => "above normal",
        Priority::High => "high",
    }
}

/// `8 of 32 threads (hard), priority high`, or what is set.
struct Set(Option<AppliedCpu>, Option<Priority>);

impl fmt::Display for Set {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(c) = self.0 {
            let mode = match c.mode {
                Mode::Hard => "hard",
                Mode::Soft => "soft",
            };
            write!(f, "{} of {} threads ({mode})", c.threads, c.of)?;
        }
        match (self.0, self.1) {
            (Some(_), Some(p)) => write!(f, ", priority {}", priority(p)),
            (None, Some(p)) => write!(f, "priority {}", priority(p)),
            (Some(_), None) => Ok(()),
            (None, None) => f.write_str("no CPU rule, no priority"),
        }
    }
}

/// What a reason only `watch` writes means (`None` for the others: their name says it), and
/// `read_back_failed` of a known `watch` profile (review S2: the game stayed in the new job).
fn why(reason: SkipReason, restore: Option<u32>, watch: bool) -> Option<String> {
    // Review S1: without a failed restore, either the class was put back or none was set.
    let put_back = if restore.is_none() {
        "; any priority class set on it was put back"
    } else {
        ""
    };
    Some(match reason {
        SkipReason::TargetNotFound => "no new game process appeared within the 120 s search (a launcher waiting for a login or an update: start the game again; a game that is itself the program Steam starts and does not start itself again: use method direct)".to_owned(),
        SkipReason::TargetElevated => "the game process runs as administrator, or was started by a launcher that does; rerun-launch leaves it alone".to_owned(),
        SkipReason::TargetDenied { code } => format!("a process of the game's name could not be opened or read (Win32 error {code}: protected or anti-cheat, another account, or possibly running as administrator); nothing was set (if the game itself never appeared, e.g. a launcher waiting for a login or an update: start the game again)"),
        SkipReason::SearchFailed { code } => format!("no game process could be looked for (Win32 error {code}: the process list, or rerun-launch's own process information before the search, could not be read, or the program Steam started could not be identified); nothing was set"),
        SkipReason::PriorityFailed { code } => format!("the priority class of the game process could not be read or set (Win32 error {code}); nothing was set"),
        SkipReason::JobIneffective => format!("the game process joined the job but kept another limit (a job it was already in, e.g. a launcher's); the job stays without effect until the game exits{put_back}"),
        SkipReason::ReadBackFailed { code } if watch => format!("the game process joined a job with the selection, but it could not be read back (Win32 error {code}); the limit may apply until the game exits{put_back}"),
        SkipReason::MethodUnsupported => "written by an older rerun-launch without method watch".to_owned(),
        _ => return None,
    })
}

fn start(s: Start, watch: bool) -> String {
    match s {
        Start::Created if watch => "Steam's command started unchanged".to_owned(),
        Start::Created => "the game started unchanged".to_owned(),
        Start::Shell | Start::ShellNoProcess => {
            "the game started unchanged through the shell (administrator prompt)".to_owned()
        }
        Start::NotExe => "nothing started (not an .exe)".to_owned(),
        Start::Failed { code } => format!("nothing started (Win32 error {code})"),
    }
}

fn ended(e: Ended) -> String {
    match e {
        Ended::Ended => "the suspended child with the rule was ended first".to_owned(),
        Ended::Failed { code } => {
            format!("the suspended child with the rule could not be ended (Win32 error {code})")
        }
        Ended::NotConfirmed { code } => {
            format!("the suspended child with the rule was not seen ending (Win32 error {code})")
        }
    }
}

impl fmt::Display for LaunchMsg<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Heading => f.write_str("last start per launch profile (rerun-launch):"),
            Self::Applied {
                id,
                at,
                cpu,
                priority,
                check,
                watch,
            } => {
                let set = Set(*cpu, *priority);
                write!(f, "  {id}, {at}: ")?;
                match check {
                    Check::Ok => {
                        write!(f, "ok, verified: {set}")?;
                        if cpu.is_some_and(|c| c.mode == Mode::Soft) {
                            f.write_str(if *watch {
                                " (CPU Sets of the game process only; whether threads already running follow them is unproven)"
                            } else {
                                " (CPU Sets of the started process only)"
                            })?;
                        }
                        Ok(())
                    }
                    Check::Narrowed => write!(
                        f,
                        "narrowed, the game limited itself to fewer threads within the rule (set: {set}; not an error, the rule holds)"
                    ),
                    Check::Reset {
                        cpu: c,
                        priority: p,
                    } => {
                        let what = match (c, p) {
                            (true, true) => "affinity and priority",
                            (true, false) => "affinity",
                            _ => "priority",
                        };
                        write!(f, "reset, the {what} changed after the start (set: {set})")
                    }
                    Check::ExitedEarly if *watch => write!(
                        f,
                        "exited_early, the game process found ended within 5 s, before the check, and no other one followed in time (at most 4 within 120 s) (set: {set}; it crashed, or it hands over to a process of another path)"
                    ),
                    Check::ExitedEarly => write!(
                        f,
                        "exited_early, the started process ended within 5 s, before the check (set: {set}; it crashed, or it is a launcher that starts the game as another process)"
                    ),
                    Check::Failed { code } => {
                        write!(f, "check failed (Win32 error {code}), set: {set}")
                    }
                }
            }
            Self::Skipped {
                id,
                at,
                reason,
                start: s,
                ended: e,
                restore,
                watch,
            } => {
                write!(f, "  {id}, {at}: rule_skipped: {reason}, ")?;
                match why(*reason, *restore, *watch) {
                    // Review S2: the game was found and joined the job; it did not start
                    // unchanged.
                    Some(why) if matches!(reason, SkipReason::ReadBackFailed { .. }) => {
                        f.write_str(&why)?;
                    }
                    Some(why) => write!(f, "{why}; {}", start(*s, *watch))?,
                    None => f.write_str(&start(*s, *watch))?,
                }
                match e {
                    Some(e) => write!(f, "; {}", ended(*e)),
                    None => Ok(()),
                }
            }
            Self::Unreadable { id, why } => write!(f, "  {id}: unreadable: {why}"),
            Self::Other { n } => write!(
                f,
                "  {} in the launch folder not Rerun's (not read)",
                Count(*n, "other entry", "other entries")
            ),
            Self::OptionStillSet { id, held: None } => write!(
                f,
                "    the launch option with --profile {id} was still set in Steam at that start; remove it (the game starts unchanged through it)"
            ),
            Self::OptionStillSet { id, held: Some(t) } => write!(
                f,
                "    the launch option with --profile {id} was still set in Steam at that start; transaction {t} holds this profile now (rerun revert {t} --dry-run shows its state)"
            ),
            Self::OptionStillSetForgotten { id } => write!(
                f,
                "    the launch option with --profile {id} was still set in Steam at that start; a forgotten transaction left a profile of this ID and it was missing then: remove the launch option"
            ),
            Self::PriorityNotRestored { code } => write!(
                f,
                "    the priority class set on the game process could not be put back (Win32 error {code}); it stays until the game exits"
            ),
            Self::Watched { target } => write!(
                f,
                "    method watch: the rule is for the game process found after the start, not the program Steam starts: {target}"
            ),
            Self::CheckedLauncher { start } => write!(
                f,
                "    Steam starts a launcher here: the check covered the launcher, not the game: {start}"
            ),
            Self::FolderUnreadable { error } => {
                write!(f, "launch results cannot be read: {error}")
            }
        }
    }
}
