//! The lines of `rerun package list | remove | prune` (P5-8b-2, ADR 0025 amendment P5-8b): the
//! store, the removal preview (every file, rule 5), what stays and why, the result. Package IDs,
//! versions and names come through `escape::text`, paths through `escape::path` (in
//! `rerun_core::flow::store`); every error is a [`Shown`] and stands last.

use std::fmt;

use rerun_core::escape::Shown;
use rerun_core::flow::StoredState;
use rerun_core::journal::TxnId;
use rerun_core::pkg::store::StoreKeep;

use super::{Count, TxnText};

/// Why a package stays, as shown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StaysWhy {
    /// A transaction that is not settled uses it (its lines follow).
    InUse,
    /// These transactions cannot be read.
    UnknownUse(Vec<TxnId>),
    /// What its folder holds.
    Store(StoreKeep),
    /// Only its archive, which a package that stays needs too.
    SharedArchive,
}

/// One line about Rerun's package store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreMsg<'a> {
    /// Nothing in the store.
    Empty,
    /// `Packages:`.
    PackagesHeader,
    /// One package of the store.
    Package {
        /// The ID.
        id: Shown<'a>,
        /// The version.
        version: Shown<'a>,
        /// Its name in the current index (`None`: not in it).
        name: Option<Shown<'a>>,
        /// Its state.
        state: StoredState,
        /// Its files.
        files: u32,
        /// Its files and archives in bytes.
        bytes: u64,
    },
    /// A file of a package (below its version folder).
    File {
        /// The path.
        path: Shown<'a>,
    },
    /// An archive of a package in the cache.
    Archive {
        /// Its name (the SHA-256).
        name: Shown<'a>,
    },
    /// A transaction that uses the package.
    UsedBy {
        /// The transaction.
        txn: TxnId,
        /// The Steam app of its head.
        app: Option<u32>,
        /// Its state.
        state: TxnText<'a>,
    },
    /// Why the package stays.
    Stays {
        /// Why.
        why: StaysWhy,
    },
    /// `Archives without a package:`.
    LooseHeader,
    /// An archive no package of the index names.
    Loose {
        /// Its name.
        name: Shown<'a>,
        /// Its length.
        bytes: u64,
    },
    /// Leftovers of interrupted runs.
    Leftovers {
        /// How many.
        n: usize,
        /// Their bytes.
        bytes: u64,
    },
    /// `Not Rerun's (never touched):`.
    ForeignHeader,
    /// An entry Rerun never touches.
    Foreign {
        /// Its path below `AppDir` (escaped by the core).
        path: Shown<'a>,
        /// Why.
        why: StoreKeep,
    },
    /// `Removed from Rerun's package store:`.
    GoesHeader,
    /// `Stays:`.
    StaysHeader,
    /// A package that stays, with its reason.
    PackageStays {
        /// The ID.
        id: Shown<'a>,
        /// The version.
        version: Shown<'a>,
        /// Why.
        why: StaysWhy,
    },
    /// The sentence under a preview.
    Unchanged,
    /// Nothing to remove.
    Nothing,
    /// The question.
    Ask {
        /// Packages.
        packages: usize,
        /// Archives without a package.
        archives: usize,
        /// Leftovers.
        leftovers: usize,
        /// Bytes freed.
        bytes: u64,
    },
    /// Done.
    Removed {
        /// Packages removed.
        packages: usize,
        /// Archives removed.
        archives: usize,
        /// Leftovers removed.
        leftovers: usize,
        /// Bytes freed.
        bytes: u64,
    },
    /// Something shown stopped while it was removed (it shows again in the next listing).
    Stopped {
        /// `<id>@<version>` or a cache name.
        name: Shown<'a>,
        /// Why.
        why: StoreKeep,
    },
    /// The package asked for is not in the store.
    NotFound {
        /// `<id>@<version>`.
        package: Shown<'a>,
    },
    /// The store changed since the preview: nothing removed.
    Changed,
    /// The store or the journal cannot be read, or the removal failed.
    Error {
        /// Why.
        error: Shown<'a>,
    },
}

/// What a [`StoreKeep`] means, in words.
fn store_why(k: StoreKeep) -> &'static str {
    match k {
        StoreKeep::Reparse => "it holds a link (a junction or a symbolic link)",
        StoreKeep::Linked => "it holds a file with more than one hard link",
        StoreKeep::Attributes => {
            "it holds a read-only, hidden or system entry, or one Rerun cannot open"
        }
        StoreKeep::TooMany => "it holds too many entries",
        StoreKeep::BadName => "a name that is not Rerun's",
        StoreKeep::Busy => "in use right now (a scanner, say); try again later",
        StoreKeep::Changed => "it changed while it was removed; look at the store again",
        StoreKeep::Unsupported => "the drive does not allow it to be removed (FAT or exFAT)",
        _ => "Rerun does not remove it",
    }
}

impl fmt::Display for StaysWhy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InUse => {
                f.write_str("used by a transaction that is not settled; revert it first")
            }
            Self::UnknownUse(ts) => {
                f.write_str("transaction")?;
                if ts.len() > 1 {
                    f.write_str("s")?;
                }
                for (i, t) in ts.iter().enumerate() {
                    f.write_str(if i == 0 { " " } else { ", " })?;
                    write!(f, "{t}")?;
                }
                f.write_str(" cannot be read, so any package may be in use; rerun status shows it")
            }
            Self::Store(k) => f.write_str(store_why(*k)),
            Self::SharedArchive => {
                f.write_str("it is only its archive, which a package that stays needs too")
            }
        }
    }
}

impl fmt::Display for StoreMsg<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("Rerun's package store is empty"),
            Self::PackagesHeader => f.write_str("Packages:"),
            Self::Package {
                id,
                version,
                name,
                state,
                files,
                bytes,
            } => {
                write!(f, "  {id} {version}  ")?;
                match name {
                    Some(n) => write!(f, "{n}")?,
                    None => f.write_str("not in the signed index (cannot be downloaded again)")?,
                }
                let state = match state {
                    StoredState::Unpacked => "unpacked",
                    StoredState::Incomplete => "incomplete (rerun package fetch completes it)",
                    StoredState::ArchiveOnly => "only its archive",
                };
                write!(
                    f,
                    "  {state}, {}, {bytes} bytes",
                    Count(
                        usize::try_from(*files).unwrap_or(usize::MAX),
                        "file",
                        "files"
                    )
                )
            }
            Self::File { path } => write!(f, "    {path}"),
            Self::Archive { name } => write!(f, "    archive {name}"),
            Self::UsedBy { txn, app, state } => {
                write!(f, "    used by {txn}")?;
                if let Some(a) = app {
                    write!(f, "  Steam app {a}")?;
                }
                write!(f, "  {state}")
            }
            Self::Stays { why } => write!(f, "    stays: {why}"),
            Self::LooseHeader => f.write_str("Archives without a package:"),
            Self::Loose { name, bytes } => write!(f, "  {name}  {bytes} bytes"),
            Self::Leftovers { n, bytes } => write!(
                f,
                "{} of interrupted runs, {bytes} bytes",
                Count(*n, "leftover", "leftovers")
            ),
            Self::ForeignHeader => f.write_str("Not Rerun's (never touched):"),
            Self::Foreign { path, why } => write!(f, "  {path}: {}", store_why(*why)),
            Self::GoesHeader => f.write_str("Removed from Rerun's package store:"),
            Self::StaysHeader => f.write_str("Stays:"),
            Self::PackageStays { id, version, why } => write!(f, "  {id} {version}: {why}"),
            Self::Unchanged => f.write_str(
                "Game folders, the registry and the firewall stay unchanged. Undoing a fix never \
                 needs a package.",
            ),
            Self::Nothing => f.write_str("nothing to remove"),
            Self::Ask {
                packages,
                archives,
                leftovers,
                bytes,
            } => write!(
                f,
                "Remove {}, {} and {} ({bytes} bytes)? [y/N]",
                Count(*packages, "package", "packages"),
                Count(
                    *archives,
                    "archive without a package",
                    "archives without a package"
                ),
                Count(*leftovers, "leftover", "leftovers")
            ),
            Self::Removed {
                packages,
                archives,
                leftovers,
                bytes,
            } => write!(
                f,
                "{}, {} and {} removed, {bytes} bytes freed",
                Count(*packages, "package", "packages"),
                Count(*archives, "archive", "archives"),
                Count(*leftovers, "leftover", "leftovers")
            ),
            Self::Stopped { name, why } => write!(f, "  {name}: {}", store_why(*why)),
            Self::NotFound { package } => {
                write!(
                    f,
                    "rerun: package {package} is not in Rerun's package store"
                )
            }
            Self::Changed => f.write_str(
                "rerun: Rerun's package store changed since the list was shown; nothing was \
                 removed; run the command again",
            ),
            Self::Error { error } => write!(f, "rerun: {error}"),
        }
    }
}
