//! The lines of the launch results in `rerun status` (ADR 0022 amendment P3-2, ADR 0016). One
//! [`LaunchMsg`] is one line. Every field is typed and shown by Rerun's own words, except the
//! reason a file is unreadable, which is [`Shown`] and stands last on its line.

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
    /// The check covered a launcher, not the game (A6, from the journal head).
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

fn start(s: Start) -> String {
    match s {
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
            } => {
                let set = Set(*cpu, *priority);
                write!(f, "  {id}, {at}: ")?;
                match check {
                    Check::Ok => {
                        write!(f, "ok, verified: {set}")?;
                        if cpu.is_some_and(|c| c.mode == Mode::Soft) {
                            f.write_str(" (CPU Sets of the started process only)")?;
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
            } => {
                write!(f, "  {id}, {at}: rule_skipped: {reason}, {}", start(*s))?;
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
