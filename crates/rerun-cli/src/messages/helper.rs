//! The lines about Rerun's elevated helper and its firewall rules (ADR 0023 §6, §10; P4-2d):
//! a rule of a preview, the administrator prompt a plan will bring (rule 5: the user knows before
//! the confirmation whether Windows will ask again), and the `status` lines about Rerun rules
//! that no transaction of this account owns (A4 N6). Rule names and programs come as [`Shown`]
//! and stand last on their lines.

use std::fmt;

use rerun_core::escape::Shown;

/// One line about the helper or a firewall rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HelperMsg<'a> {
    /// The rule a `block in firewall` op adds: its name (the transaction left open), group and
    /// direction.
    Rule {
        /// `outbound`.
        direction: &'static str,
        /// `Rerun`.
        group: &'static str,
        /// `Rerun - <topo> - <transaction>-NNN`.
        name: Shown<'a>,
    },
    /// The program a rule blocks, as the rule names it.
    Program {
        /// The full path.
        program: Shown<'a>,
    },
    /// Windows will show its administrator prompt (UAC) once for this run.
    PromptDialog {
        /// Credentials (an administrator's password) rather than a yes/no question.
        credentials: bool,
    },
    /// The prompt appears on the normal desktop (`PromptOnSecureDesktop = 0`, A4 N7).
    PromptNotSecure,
    /// Windows will not ask (`ConsentPromptBehaviorAdmin = 0`, or unreadable): the confirmation
    /// here is the only one (ADR 0023 §10, R11).
    NoDialog,
    /// Only signed programs are elevated here (`ValidateAdminCodeSignatures = 1`): the unsigned
    /// helper of this version will not start.
    SignedOnly,
    /// Heading of the `status` list of Rerun rules no transaction of this account owns (N6).
    OrphansHeading,
    /// One such rule.
    Orphan {
        /// Its program.
        program: Shown<'a>,
        /// Its name.
        name: Shown<'a>,
    },
    /// What the list means and how to remove such a rule (N6).
    OrphansHint,
    /// The installed helper fails the pre-check (ADR 0023 §2): a warning at `plan`, the apply
    /// is refused until it passes.
    NotInstalled {
        /// Why.
        error: Shown<'a>,
    },
    /// The firewall could not be read for the list.
    OrphansUnreadable {
        /// Why.
        error: Shown<'a>,
    },
    /// The journal could not be read for the list (security review N1 of P4-2d).
    OrphansNoJournal {
        /// Why.
        error: Shown<'a>,
    },
}

impl fmt::Display for HelperMsg<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rule {
                direction,
                group,
                name,
            } => write!(
                f,
                "  firewall rule: {direction}, block, group {group}, name {name}"
            ),
            Self::Program { program } => write!(f, "  program: {program}"),
            Self::PromptDialog { credentials: false } => f.write_str(
                "administrator: Windows asks once for administrator approval (UAC) when Rerun's \
                 helper changes the firewall rules",
            ),
            Self::PromptDialog { credentials: true } => f.write_str(
                "administrator: Windows asks once for an administrator's password (UAC) when \
                 Rerun's helper changes the firewall rules",
            ),
            Self::PromptNotSecure => f.write_str(
                "administrator: the Windows prompt appears on your normal desktop, not the \
                 secure desktop (PromptOnSecureDesktop is 0): other programs could reach it",
            ),
            Self::NoDialog => f.write_str(
                "administrator: Windows will not ask for administrator approval on this PC: your \
                 confirmation here is the only one",
            ),
            Self::SignedOnly => f.write_str(
                "administrator: Windows elevates only signed programs on this PC \
                 (ValidateAdminCodeSignatures is 1): Rerun's helper of this version is not \
                 signed and will not start; the apply is then rolled back",
            ),
            Self::OrphansHeading => {
                f.write_str("Rerun firewall rules that no transaction of this account owns:")
            }
            Self::Orphan { program, name } => write!(f, "  {name}: program {program}"),
            Self::OrphansHint => f.write_str(
                "  Rules of other Windows accounts on this PC appear here too. Remove a rule you \
                 no longer need in Windows Defender Firewall with Advanced Security (outbound or \
                 inbound rules, group Rerun); a non-elevated Rerun never removes it.",
            ),
            Self::NotInstalled { error } => write!(
                f,
                "warning: Rerun's helper is not installed safely, so this plan cannot be applied \
                 yet: {error}"
            ),
            Self::OrphansUnreadable { error } => write!(f, "Rerun firewall rules: {error}"),
            Self::OrphansNoJournal { error } => write!(
                f,
                "Rerun firewall rules: which belong to this account cannot be told: {error}"
            ),
        }
    }
}
