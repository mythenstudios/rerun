//! The lines of a launch profile (P3-3d, ADR 0016 amendment P3-3, plan `P3-3` §5 and X12): the
//! profile in a plan's preview, the selection on this computer, the hints, the launch option to
//! copy, and what a revert or `forget` leaves in Steam. A `watch` profile (P3-4c, plan `P3-4`
//! §3.5) adds its target and says what is set on the game process found after the start. One
//! [`ProfileMsg`] is one line. Every field is Rerun's own words or numbers, except paths and the
//! launch option, which are [`Shown`] and stand last on their line.

use std::fmt;

use rerun_core::escape::Shown;
use rerun_core::exec::launch_result::ProfileId;
use rerun_core::prim::launch_method::{RuleMode as Mode, SelectStep};

/// One line about a launch profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProfileMsg<'a> {
    /// After the root line of the profiles root.
    ProfilesRoot,
    /// The content of a profile op: carried by the plan, not a package.
    InlineSource,
    /// The profile an op writes.
    Profile {
        /// Its ID (32 lower-case hex digits, from the file name).
        id: &'a str,
        /// `direct` or `watch`.
        method: &'static str,
        /// `x86` or `x64`.
        bitness: &'static str,
    },
    /// The CPU rule in the words of `docs/02-topo-format.md` (Rerun's words).
    Rule {
        /// The rule.
        words: &'a str,
    },
    /// The priority class.
    Priority {
        /// The class.
        class: &'static str,
    },
    /// The program Steam must start.
    Start {
        /// Its path.
        path: Shown<'a>,
    },
    /// `watch`: the program whose new process gets the rule.
    Target {
        /// Its path.
        path: Shown<'a>,
    },
    /// The profile's bytes are no profile of this version (a recorded head).
    Unreadable {
        /// Why (no content).
        why: Shown<'a>,
    },
    /// The heading of the selection on this computer.
    MachineHeading,
    /// What the rule selects here now.
    Selection {
        /// Selected logical processors.
        threads: u16,
        /// Of all.
        of: u16,
        /// Group.
        group: u16,
        /// Mask in the group.
        mask: u64,
        /// The cores, as ranges (`0-7`, Rerun's numbers).
        cores: String,
        /// The one LLC (number, level, bytes).
        llc: Option<(u32, u8, u64)>,
    },
    /// How the selection is applied.
    Mode {
        /// Hard or soft.
        mode: Mode,
    },
    /// How the selection is applied by `watch` (on the game process found).
    WatchMode {
        /// Hard or soft.
        mode: Mode,
    },
    /// The topology cannot be read here.
    MachineUnknown {
        /// Why (escaped).
        why: Shown<'a>,
    },
    /// The rule selects nothing here.
    MachineEmpty {
        /// The step that emptied it.
        after: SelectStep,
    },
    /// No CPU rule (priority only).
    MachineNoRule,
    /// More than one processor group and a hard rule.
    MultiGroup,
    /// A 32-bit game on a group of more than 32 logical processors.
    X86Capped,
    /// Steam starts a launcher, not the game: the program.
    LauncherStarts {
        /// The launcher.
        start: Shown<'a>,
    },
    /// The game the launcher starts.
    LauncherGame {
        /// The main executable (relative to the game folder).
        main: Shown<'a>,
    },
    /// The priority class note (D6 addition).
    PriorityNote {
        /// The class.
        class: &'static str,
    },
    /// The priority class note of `watch`.
    WatchPriorityNote {
        /// The class.
        class: &'static str,
    },
    /// `watch` with the game as the start: a stub that must start the game again.
    WatchStub,
    /// `watch`: an elevated game is left alone; a game that does not appear runs unchanged.
    WatchLeftAlone,
    /// The heading of the launch option.
    OptionHeading,
    /// The launch option, to copy.
    Option {
        /// The option.
        option: Shown<'a>,
    },
    /// Where to paste it.
    OptionWhere,
    /// Rerun does not change Steam's settings.
    OptionByHand,
    /// Existing launch options and other wrappers.
    OptionCombine,
    /// The shim must stay where it is.
    OptionShimStays,
    /// Rerun's install folder is unknown: no option offered.
    InstallUnknown,
    /// The path of the install folder cannot be shown as it is: no option offered.
    OptionNotShowable,
    /// `rerun-launch.exe` is not in Rerun's install folder.
    ShimMissing {
        /// The path checked.
        path: Shown<'a>,
    },
    /// Whether `rerun-launch.exe` is there could not be checked.
    ShimUnchecked {
        /// Why (escaped).
        why: Shown<'a>,
    },
    /// After an apply: paste the option now.
    PasteNow,
    /// After an apply whose option could not be offered or whose shim is missing.
    PasteNotYet,
    /// X12 (revert preview): what follows holds once the revert completes.
    AfterRevert,
    /// X12 (the profile is gone): remove the launch option by hand.
    OptionRemove {
        /// The option as it would be built now.
        option: Shown<'a>,
    },
    /// X12 (the profile stays): removing the option stops it.
    OptionToStop {
        /// The option as it would be built now.
        option: Shown<'a>,
    },
    /// X12: the profile from before this transaction is back (a replace reverted).
    ProfilePreviousBack {
        /// The profile.
        id: ProfileId,
    },
    /// X12: the profile stays (not reverted, changed by someone else, a halt before it, forget).
    ProfileStays {
        /// The profile.
        id: ProfileId,
    },
    /// X12: an earlier revert left the profile as found; whether it is still there is unknown.
    ProfileLeft {
        /// The profile.
        id: ProfileId,
    },
    /// X12: any option with this profile ID.
    OptionAny {
        /// The profile.
        id: ProfileId,
    },
    /// X12: what happens until it is removed.
    OptionUntilRemoved,
    /// The profiles folder is at another path than the plan names (A1): the path named.
    ProfilesMovedFrom {
        /// The plan's path.
        planned: Shown<'a>,
    },
    /// ... and the path now.
    ProfilesMovedTo {
        /// The path now.
        now: Shown<'a>,
    },
    /// A halt at the profile op: the profiles folder is missing.
    ProfilesHalt,
}

fn step(s: SelectStep) -> &'static str {
    match s {
        SelectStep::Group => "the group",
        SelectStep::Bitness => "the 32-bit limit (processors 0 to 31)",
        SelectStep::Performance => "prefer: performance",
        SelectStep::L3 => "single_l3 / prefer_l3",
        SelectStep::ExcludeFirst => "exclude_first",
        SelectStep::Smt => "smt: false",
        SelectStep::MaxThreads => "max_threads",
    }
}

/// `32 MiB` or `512 KiB`.
pub(crate) fn size(b: u64) -> String {
    if b >= 1 << 20 && b.is_multiple_of(1 << 20) {
        format!("{} MiB", b >> 20)
    } else {
        format!("{} KiB", b >> 10)
    }
}

impl fmt::Display for ProfileMsg<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ProfilesRoot => f.write_str(
                "  Rerun's launch profiles: written by apply, read by rerun-launch at a game start",
            ),
            Self::InlineSource => {
                f.write_str("  content: the launch profile, carried by the plan (no package)")
            }
            Self::Profile {
                id,
                method,
                bitness,
            } => write!(f, "     launch profile {id}: method {method}, {bitness}"),
            Self::Rule { words } => write!(f, "     cpu {words}"),
            Self::Priority { class } => write!(f, "     priority {class}"),
            Self::Start { path } => write!(f, "     start {path}"),
            Self::Target { path } => write!(f, "     target {path}"),
            Self::Unreadable { why } => {
                write!(f, "     not a launch profile of this version: {why}")
            }
            Self::MachineHeading => f.write_str("on this computer now (not part of the plan; rerun-launch selects again at every start):"),
            Self::Selection {
                threads,
                of,
                group,
                mask,
                cores,
                llc,
            } => {
                write!(
                    f,
                    "  {threads} of {of} logical processors, group {group}, mask {mask:#018x}, cores {cores}"
                )?;
                match llc {
                    Some((n, level, bytes)) => write!(f, ", L{level} #{n} ({})", size(*bytes)),
                    None => Ok(()),
                }
            }
            Self::Mode { mode } => f.write_str(match mode {
                Mode::Hard => "  hard: job affinity, inherited by the programs the started program starts",
                Mode::Soft => "  soft: default CPU Sets of the started program only, not of its children; Windows may override them",
            }),
            Self::WatchMode { mode } => f.write_str(match mode {
                Mode::Hard => "  hard: a new job with the selection on the game process once found; the game cannot widen it, programs it starts inherit it, and it stays until the game exits (a job the game is already in keeps its own limit: job_ineffective)",
                Mode::Soft => "  soft: default CPU Sets of the game process once found, not of programs it starts; Windows may override them, and whether threads already running follow them is unproven (the check reads only that they are set)",
            }),
            Self::MachineUnknown { why } => write!(
                f,
                "  unknown here, rerun-launch decides at every start; the topology: {why}"
            ),
            Self::MachineEmpty { after } => write!(
                f,
                "  the rule selects nothing here (emptied by {}); the game would start unchanged",
                step(*after)
            ),
            Self::MachineNoRule => f.write_str("  no CPU rule (priority only)"),
            Self::MultiGroup => f.write_str(
                "  hint: this computer has more than one processor group; a hard rule may start the game unchanged here (ADR 0022, multi-group case unmeasured)",
            ),
            Self::X86Capped => f.write_str(
                "  hint: a 32-bit game gets processors 0 to 31 of its group only",
            ),
            Self::LauncherStarts { start } => write!(
                f,
                "  hint: Steam starts a launcher, not the game; the game inherits the limit through the job unless it leaves it, and the check after about 5 s covers the launcher (a launcher that exits sooner shows exited_early); the launcher: {start}"
            ),
            Self::LauncherGame { main } => write!(f, "  the game: {main}"),
            Self::PriorityNote { class } => write!(
                f,
                "  priority {class} is set only when Steam starts the game through the launch option (not from a shortcut or the exe), and only on the start program; the check reads it"
            ),
            Self::WatchPriorityNote { class } => write!(
                f,
                "  priority {class} is set on the game process once found, only when Steam starts the game through the launch option (not from a shortcut or the exe); the check reads it, and it is put back if the CPU rule cannot be set"
            ),
            Self::WatchStub => f.write_str(
                "  hint: Steam starts the game's own program: watch looks for a second process of it (a stub that hands over to a launcher such as Ubisoft Connect, which starts the game again); if the game does not start itself again, it runs unchanged (target_not_found): use method direct",
            ),
            Self::WatchLeftAlone => f.write_str(
                "  hint: a game running as administrator, or started by a launcher that runs as administrator, is left alone (target_elevated); a game that does not appear within 120 s (a login or an update in the launcher) runs unchanged (target_not_found): start it again",
            ),
            Self::OptionHeading => f.write_str("launch option for Steam (copy it):"),
            Self::Option { option } => write!(f, "  {option}"),
            Self::OptionWhere => f.write_str(
                "  paste it in Steam: the game > Properties > General > Launch options",
            ),
            Self::OptionByHand => f.write_str(
                "  Rerun does not change Steam's settings: remove the option by hand after a revert",
            ),
            Self::OptionCombine => f.write_str(
                "  existing launch options of the game go after %command%; an option that already holds %command% (another wrapper) cannot be combined",
            ),
            Self::OptionShimStays => f.write_str(
                "  moving or deleting rerun-launch.exe breaks the start through Steam until the option is removed",
            ),
            Self::InstallUnknown => f.write_str(
                "  no launch option shown: Rerun's install folder is unknown",
            ),
            Self::OptionNotShowable => f.write_str(
                "  no launch option shown: the path of Rerun's install folder holds characters that cannot be shown as they are; move Rerun to a path without them",
            ),
            Self::ShimUnchecked { why } => write!(
                f,
                "  warning: whether rerun-launch.exe is in Rerun's install folder could not be checked: {why}"
            ),
            Self::PasteNotYet => f.write_str(
                "the launch option could not be offered or would not start the game (see the preview); fix that before you set a launch option in Steam",
            ),
            Self::AfterRevert => f.write_str("once the revert completes:"),
            Self::OptionToStop { option } => write!(
                f,
                "  to stop it, remove this launch option of the game in Steam by hand (Rerun does not change Steam's settings): {option}"
            ),
            Self::ProfilePreviousBack { id } => write!(
                f,
                "launch option: the launch profile {id} from before this transaction is back and keeps applying through the launch option; leave the option set for it"
            ),
            Self::ProfileLeft { id } => write!(
                f,
                "launch option: the launch profile {id} was left as found by an earlier revert (changed by someone else); if it is still in Rerun's profiles folder it keeps applying through the launch option until the option is removed, if it is gone the game starts unchanged through the option"
            ),
            Self::ProfileStays { id } => write!(
                f,
                "launch option: the launch profile {id} stays and keeps applying through the launch option until the option is removed"
            ),
            Self::ShimMissing { path } => write!(
                f,
                "  warning: rerun-launch.exe is not in Rerun's install folder; the option would not start the game: {path}"
            ),
            Self::PasteNow => f.write_str(
                "now paste the launch option shown in the preview into Steam (the game > Properties > General > Launch options)",
            ),
            Self::OptionRemove { option } => write!(
                f,
                "launch option: Rerun does not change Steam's settings; remove this launch option of the game in Steam by hand: {option}"
            ),
            Self::OptionAny { id } => write!(
                f,
                "  (and any launch option with --profile {id})"
            ),
            Self::OptionUntilRemoved => f.write_str(
                "  until it is removed, Steam starts the game through rerun-launch, which finds no profile and starts it unchanged (rerun status: profile_missing); if rerun-launch.exe is moved or deleted, the game does not start through Steam",
            ),
            Self::ProfilesMovedFrom { planned } => write!(
                f,
                "Rerun's profiles folder is at another path than the transaction names (its hashes decide): named {planned}"
            ),
            Self::ProfilesMovedTo { now } => write!(f, "  now {now}"),
            Self::ProfilesHalt => f.write_str(
                "  Rerun's profiles folder is missing: the revert stops at the launch profile after everything else is reverted; forget closes the transaction then",
            ),
        }
    }
}

/// Ascending numbers as ranges: `0-7, 16, 18-19` (`system::ranges`, review N5).
pub fn ranges(v: &[u32]) -> String {
    crate::system::ranges(v.iter().copied())
        .into_iter()
        .map(|(a, b)| {
            if a == b {
                a.to_string()
            } else {
                format!("{a}-{b}")
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}
