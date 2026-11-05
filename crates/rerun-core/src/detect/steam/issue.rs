//! Issues of the Steam scan (ADR 0012). The scan never fails as a whole: every problem is an
//! [`Issue`] with a [`Location`], and the scan goes on with what is left.
//!
//! Issues never contain file or registry content other than paths and names the user has to
//! see: raw ones only escaped (`{:?}`, as `PathError` and `Anomaly` do), paths that passed
//! `RootPath` or `RelPath` as they are. Output layers sanitize further.

use std::fmt;

use super::root::RootSource;
use crate::detect::steam::files::ViewError;
use crate::detect::vdf::VdfReadError;
use crate::path::{Anomaly, RelPath, RootPath};
use crate::policy::root::RootError;
use crate::sys::SysError;
use crate::sys::fs::EntryKind;

/// One problem found by the scan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Issue {
    /// Where.
    pub at: Location,
    /// What.
    pub kind: IssueKind,
}

impl fmt::Display for Issue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.at, self.kind)
    }
}

/// Where an issue was found.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Location {
    /// A registry candidate for the Steam root.
    Registry(RootSource),
    /// The library file of the Steam root.
    LibraryFile {
        /// The Steam root.
        root: RootPath,
        /// The file, relative to the root.
        file: RelPath,
    },
    /// One library listed in the library file.
    LibraryEntry {
        /// The Steam root.
        root: RootPath,
        /// The file, relative to the root.
        file: RelPath,
        /// Position in the file, from 0, in file order.
        index: usize,
    },
    /// A library (the Steam root is library 0).
    Library(RootPath),
    /// An entry of a library's `steamapps` folder.
    Manifest {
        /// The library.
        library: RootPath,
        /// The raw entry name as listed (shown escaped).
        name: String,
    },
}

impl fmt::Display for Location {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Registry(source) => write!(f, "{source}"),
            Self::LibraryFile { root, file } => write!(f, r"{root}\{file}"),
            Self::LibraryEntry { root, file, index } => {
                write!(f, r"{root}\{file}, library entry {index}")
            }
            Self::Library(path) => write!(f, "library {path}"),
            Self::Manifest { library, name } => {
                write!(f, "library {library}, steamapps entry {name:?}")
            }
        }
    }
}

/// Why a registry value is not used as a path. Never contains the value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum BadValue {
    /// The string is empty.
    Empty,
    /// `REG_EXPAND_SZ` with `%`: Rerun never expands it.
    Unexpanded,
    /// Not a string type.
    NotAString {
        /// The registry type number.
        kind: u32,
    },
    /// A string type whose bytes are not UTF-16LE text (odd length, NUL inside, lone
    /// surrogate).
    InvalidString,
}

impl fmt::Display for BadValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("empty value"),
            Self::Unexpanded => f.write_str("REG_EXPAND_SZ with '%' (never expanded)"),
            Self::NotAString { kind } => write!(f, "registry type {kind}, not a string"),
            Self::InvalidString => f.write_str("not valid UTF-16 text"),
        }
    }
}

/// What went wrong.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum IssueKind {
    /// Error of the system layer (reading a registry value, opening or listing a folder).
    #[error(transparent)]
    Sys(SysError),
    /// A root (Steam folder, library) was refused. Boxed: by far the largest error.
    #[error(transparent)]
    Root(Box<RootError>),
    /// A registry value is not usable as a path.
    #[error("{0}")]
    RegistryValue(BadValue),
    /// Reading a Steam file failed (open, read, parse).
    #[error(transparent)]
    VdfRead(VdfReadError),
    /// A Steam file does not have the expected shape.
    #[error(transparent)]
    View(ViewError),
    /// An install folder name or a manifest entry name is not a valid single segment.
    #[error(transparent)]
    Anomaly(Anomaly),
    /// A later registry candidate opens a different folder than the Steam root. Not scanned.
    #[error("opens {other}, not the Steam root {root} (from {winner}); not scanned")]
    RootsDisagree {
        /// The candidate that became the root.
        winner: RootSource,
        /// The Steam root.
        root: RootPath,
        /// The folder this candidate opens.
        other: RootPath,
    },
    /// The library file lists more libraries than allowed; only the Steam root is scanned.
    #[error("lists {count} libraries, more than {max}; only the Steam root is scanned")]
    TooManyLibraries {
        /// Libraries listed.
        count: usize,
        /// The limit.
        max: usize,
    },
    /// `steamapps` is case-sensitive; two manifests could fold to one name. No apps read.
    #[error("steamapps is case-sensitive; no apps read")]
    CaseSensitiveSteamapps,
    /// More manifest entries than allowed. No apps read (never a partial list).
    #[error("{count} app manifest entries, more than {max}; no apps read")]
    TooManyManifests {
        /// Entries named `appmanifest_*.acf`.
        count: usize,
        /// The limit.
        max: usize,
    },
    /// `appmanifest_<id>.acf` whose `<id>` is not a valid app ID. Not read.
    #[error("app manifest name without a valid app ID; not read")]
    ManifestName,
    /// A manifest entry that is not a plain file. Never opened.
    #[error("app manifest is not a plain file ({kind:?}, restricted: {restricted}); not read")]
    ManifestEntry {
        /// Kind of the entry.
        kind: EntryKind,
        /// The entry denies the current user every open.
        restricted: bool,
    },
    /// The app ID in the file name differs from `appid` in the file. The app is dropped.
    #[error("file name says app {file}, the manifest says app {manifest}; app dropped")]
    AppIdMismatch {
        /// From the file name.
        file: u32,
        /// From the manifest.
        manifest: u32,
    },
    /// The same app ID is also in another library. Every copy is kept and reported; no
    /// winner is picked.
    #[error("app {app_id} is also in library {other}{}", and_more(*.more))]
    DuplicateApp {
        /// The app ID.
        app_id: u32,
        /// The first other library that holds it.
        other: RootPath,
        /// How many more libraries hold it.
        more: usize,
    },
}

/// ` and N more libraries`, or nothing.
fn and_more(more: usize) -> String {
    match more {
        0 => String::new(),
        1 => " and 1 more library".to_owned(),
        n => format!(" and {n} more libraries"),
    }
}
