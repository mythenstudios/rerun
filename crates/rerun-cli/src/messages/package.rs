//! The lines of `rerun package fetch` (ADR 0025): downloads, then unpacked files. Package IDs,
//! versions and hashes are checked before they reach a line (the ID and version rules of
//! docs/02), a file name is shown escaped; every error comes as [`Shown`] and stands last.

use std::fmt;

use rerun_core::escape::Shown;

/// How a download got into the cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FetchedHow {
    /// It was there already (hashed again).
    Cached,
    /// Downloaded now.
    Downloaded {
        /// Redirects followed.
        redirects: usize,
        /// A cache entry with other content was replaced.
        replaced: bool,
    },
}

/// How a file got into the version folder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnpackedHow {
    /// It was there with its pinned hash (hashed again).
    Present,
    /// Unpacked now.
    Unpacked,
    /// Unpacked now over a file with other content.
    Replaced,
    /// A file with other content was removed; the run failed before it was unpacked again.
    Removed,
}

/// One line about a package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PackageMsg<'a> {
    /// A download of the package is in the cache with its pinned hash.
    Fetched {
        /// The package ID.
        id: Shown<'a>,
        /// Its version.
        version: Shown<'a>,
        /// The architecture of a per-architecture asset.
        arch: Option<&'static str>,
        /// How.
        how: FetchedHow,
        /// Its length in bytes.
        len: u64,
        /// Its SHA-256 (64 hex digits).
        sha256: String,
    },
    /// A file of the package is in its version folder with its pinned hash.
    Unpacked {
        /// The package ID.
        id: Shown<'a>,
        /// Its version.
        version: Shown<'a>,
        /// The file below the version folder.
        file: Shown<'a>,
        /// How.
        how: UnpackedHow,
        /// Its length in bytes.
        len: u64,
    },
    /// No signed index has been imported.
    NoIndex,
    /// The current index has no package of this ID.
    Unknown {
        /// The ID asked for.
        id: Shown<'a>,
    },
    /// The current index holds the package, but this build sets it aside (ADR 0024 amendment
    /// "Forward compatibility" §10).
    Aside {
        /// The ID.
        id: Shown<'a>,
        /// A newer Rerun can use it.
        newer: bool,
        /// Why this version cannot use it (`None` when `newer`).
        why: Option<Shown<'a>>,
    },
    /// The current index has the package at another version (one package is one version).
    OtherVersion {
        /// The ID.
        id: Shown<'a>,
        /// The version in the index.
        version: Shown<'a>,
    },
    /// The fetch was refused or failed.
    Failed {
        /// Why.
        error: Shown<'a>,
    },
    /// Unpacking was refused or failed.
    NotUnpacked {
        /// Why.
        error: Shown<'a>,
    },
}

impl fmt::Display for PackageMsg<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Fetched {
                id,
                version,
                arch,
                how,
                len,
                sha256,
            } => {
                write!(f, "{id} {version}")?;
                if let Some(a) = arch {
                    write!(f, " ({a})")?;
                }
                match how {
                    FetchedHow::Cached => f.write_str(": already in the cache")?,
                    FetchedHow::Downloaded {
                        redirects,
                        replaced,
                    } => {
                        write!(f, ": downloaded (redirects: {redirects}")?;
                        if *replaced {
                            f.write_str(", a damaged cache entry replaced")?;
                        }
                        f.write_str(")")?;
                    }
                }
                write!(f, ", {len} bytes, sha256 {sha256}")
            }
            Self::Unpacked {
                id,
                version,
                file,
                how,
                len,
            } => {
                write!(f, "{id} {version}: {file} ")?;
                f.write_str(match how {
                    UnpackedHow::Present => "already unpacked",
                    UnpackedHow::Unpacked => "unpacked",
                    UnpackedHow::Replaced => "unpacked (a changed file replaced)",
                    UnpackedHow::Removed => "removed (it had changed; not unpacked again)",
                })?;
                write!(f, ", {len} bytes")
            }
            Self::NoIndex => f.write_str(
                "rerun: no signed index has been imported yet (rerun index import <index.json> <index.json.sig>)",
            ),
            Self::Unknown { id } => {
                write!(f, "rerun: the current index has no package {id}")
            }
            Self::Aside { id, newer: true, .. } => write!(
                f,
                "rerun: package {id} needs a newer version of Rerun: nothing fetched"
            ),
            Self::Aside {
                id,
                newer: false,
                why,
            } => {
                write!(
                    f,
                    "rerun: package {id} cannot be used by this version of Rerun"
                )?;
                if let Some(w) = why {
                    write!(f, " ({w})")?;
                }
                f.write_str(": nothing fetched")
            }
            Self::OtherVersion { id, version } => write!(
                f,
                "rerun: the current index has package {id} at version {version} only"
            ),
            Self::Failed { error } => write!(f, "rerun: package not fetched: {error}"),
            Self::NotUnpacked { error } => write!(f, "rerun: package not unpacked: {error}"),
        }
    }
}
