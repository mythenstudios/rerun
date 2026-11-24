//! The lines of `rerun uninstall-check` (P5-13b, ADR 0030): the verdict, the games Steam may
//! still start through `rerun-launch.exe`, forgotten transactions and Rerun's folder. Paths come
//! through `escape::path`, errors through `escape::text`; every untrusted field stands last.

use std::fmt;

use rerun_core::escape::Shown;
use rerun_core::exec::launch_result::ProfileId;
use rerun_core::journal::TxnId;

use super::{Count, Utc};

/// One line of `rerun uninstall-check`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UninstallMsg<'a> {
    /// Nothing is open.
    Clean,
    /// Transactions are not settled (they are listed above, as `rerun status` lists them).
    Open {
        /// How many.
        n: usize,
    },
    /// Forgotten transactions keep their backups in Rerun's folder.
    Forgotten {
        /// How many.
        n: usize,
    },
    /// The heading of the launch options, with the shim's path (`None`: the install folder is
    /// unknown).
    LaunchHeading {
        /// `<install>\rerun-launch.exe`.
        shim: Option<Shown<'a>>,
    },
    /// A game Steam may still start through the shim.
    LaunchLeft {
        /// The profile.
        id: ProfileId,
        /// The Steam app, if known.
        app: Option<u32>,
    },
    /// A transaction holds the profile.
    LaunchHeld {
        /// The transaction.
        txn: TxnId,
        /// It is forgotten.
        forgotten: bool,
    },
    /// The last recorded start through the shim.
    LaunchStarted {
        /// When.
        at: Utc,
    },
    /// The result of the last start cannot be read.
    LaunchResultUnreadable {
        /// Why (escaped).
        why: Shown<'a>,
    },
    /// What to do about the launch options.
    LaunchHint,
    /// The launch results cannot be read.
    LaunchUnreadable {
        /// The error (escaped).
        error: Shown<'a>,
    },
    /// Rerun's folder.
    DataFolder {
        /// It exists.
        exists: bool,
        /// Its path (escaped).
        path: Shown<'a>,
    },
    /// Rerun's folder cannot be determined.
    DataUnknown {
        /// The error (escaped).
        error: Shown<'a>,
    },
}

impl fmt::Display for UninstallMsg<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Clean => f.write_str("uninstall check: no change of Rerun is open"),
            Self::Open { n } => write!(
                f,
                "uninstall check: {} still open; undo each in Rerun first (or forget it), then uninstall again",
                Count(*n, "transaction is", "transactions are")
            ),
            Self::Forgotten { n } => write!(
                f,
                "note: {} backups in Rerun's folder; removing that folder deletes them",
                Count(
                    *n,
                    "forgotten transaction keeps its",
                    "forgotten transactions keep their"
                )
            ),
            Self::LaunchHeading { shim: Some(p) } => write!(
                f,
                "warning: Steam may still start these games through rerun-launch.exe; once it is removed they do not start until you remove their launch option in Steam: {p}"
            ),
            Self::LaunchHeading { shim: None } => f.write_str(
                "warning: Steam may still start these games through rerun-launch.exe; once it is removed they do not start until you remove their launch option in Steam",
            ),
            Self::LaunchLeft { id, app: Some(a) } => {
                write!(f, "  Steam app {a}: launch option with --profile {id}")
            }
            Self::LaunchLeft { id, app: None } => {
                write!(f, "  unknown game: launch option with --profile {id}")
            }
            Self::LaunchHeld {
                txn,
                forgotten: false,
            } => write!(f, "    transaction {txn} holds its profile"),
            Self::LaunchHeld {
                txn,
                forgotten: true,
            } => write!(f, "    the forgotten transaction {txn} left its profile"),
            Self::LaunchStarted { at } => write!(f, "    last start through rerun-launch: {at}"),
            Self::LaunchResultUnreadable { why } => {
                write!(f, "    the result of its last start cannot be read: {why}")
            }
            Self::LaunchHint => f.write_str(
                "  Rerun does not read Steam's settings: check each game's Properties > General > Launch options",
            ),
            Self::LaunchUnreadable { error } => write!(
                f,
                "warning: the launch results cannot be read, so games Steam starts through rerun-launch.exe may be missing here; check their launch options in Steam: {error}"
            ),
            Self::DataFolder { exists: true, path } => write!(f, "Rerun's folder: {path}"),
            Self::DataFolder {
                exists: false,
                path,
            } => write!(f, "Rerun's folder (does not exist): {path}"),
            Self::DataUnknown { error } => {
                write!(f, "Rerun's folder cannot be determined: {error}")
            }
        }
    }
}
