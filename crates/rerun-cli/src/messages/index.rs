//! The lines of `rerun index import` and `rerun index show` (ADR 0024). Numbers, hashes and key
//! IDs are Rerun's own text; the issue date and every error come as [`Shown`] and stand last.

use std::fmt;

use rerun_core::escape::Shown;

/// One line about the signed index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IndexMsg<'a> {
    /// An index was accepted and is now the current one.
    Imported {
        /// Its sequence number.
        seq: u64,
        /// The one it replaced.
        previous: Option<u64>,
    },
    /// The same index was already the current one.
    AlreadyCurrent {
        /// Its sequence number.
        seq: u64,
    },
    /// The facts of an index: number, entries, key, hash.
    Facts {
        /// Its sequence number.
        seq: u64,
        /// Topos.
        topos: usize,
        /// Packages.
        packages: usize,
        /// The key ID (16 hex digits).
        key: String,
        /// SHA-256 of its bytes (64 hex digits).
        sha256: String,
    },
    /// When it was issued.
    Issued {
        /// The date.
        issued: Shown<'a>,
    },
    /// No index was imported yet.
    NoneYet,
    /// A file of the command could not be read.
    File {
        /// `index` or `signature`.
        which: &'static str,
        /// Why.
        error: Shown<'a>,
    },
    /// The index was refused or the stored one cannot be used.
    Refused {
        /// Why.
        error: Shown<'a>,
    },
}

impl fmt::Display for IndexMsg<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Imported {
                seq,
                previous: Some(p),
            } => write!(f, "index {seq} imported (replaces index {p})"),
            Self::Imported {
                seq,
                previous: None,
            } => write!(f, "index {seq} imported"),
            Self::AlreadyCurrent { seq } => write!(f, "index {seq} is already the current index"),
            Self::Facts {
                seq,
                topos,
                packages,
                key,
                sha256,
            } => write!(
                f,
                "index {seq}: {topos} topos, {packages} packages, key {key}, sha256 {sha256}"
            ),
            Self::Issued { issued } => write!(f, "  issued: {issued}"),
            Self::NoneYet => f.write_str(
                "no signed index has been imported yet (rerun index import <index.json> <index.json.sig>)",
            ),
            Self::File { which, error } => {
                write!(f, "rerun: cannot read the {which} file: {error}")
            }
            Self::Refused { error } => write!(f, "rerun: index refused: {error}"),
        }
    }
}
