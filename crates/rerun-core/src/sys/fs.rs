//! File system traits: one absolute [`Fs::open_dir`], everything else relative to a [`Dir`]
//! handle (ADR 0007).
//!
//! Semantics (identical for `win` and `fake`, checked in `sys::contract`):
//! - Names are case-insensitive, the original case is preserved. Folding is 1:1 per
//!   character like the NTFS upcase table (`Straße` and `STRASSE` are two names).
//! - [`Fs::open_dir`] is the only absolute operation. It follows reparse points in the given
//!   path (above the root), e.g. a Steam library that was moved and linked back.
//! - Below a root, every component is opened relative to its parent. Name surrogates
//!   (junction, mount point, symlink, LX symlink) and entries with an unknown reparse tag are
//!   reported as [`EntryKind::Reparse`] and never traversed; operations through them return
//!   `ReparsePoint`. Deleting such an entry itself is allowed.
//! - Entries with an allowlisted data tag ([`tag::is_allowed_data_tag`]: WOF, dedup, cloud
//!   files) behave like normal files and directories and carry the tag in
//!   [`Metadata::reparse`] as far as Windows reports it: while the `wof.sys` filter is
//!   attached (every normal boot) it hides its own reparse point, so a WOF-compressed file
//!   (CompactGUI, `compact /exe`) looks like a plain file without a tag and reads its
//!   uncompressed content (contract `fs_read_contract`, WOF case).
//! - A handle refers to an object, not a name: it stays valid when the directory or one of
//!   its parents is renamed. [`Dir::info`] computes the path at call time.
//! - Writes into a case-sensitive directory return `Unsupported`.
//! - If a parent directory is missing, writing operations return `NotFound`.
//! - `read_dir` returns raw names as on disk; they may be invalid as a [`RelPath`]
//!   (`d3d9.dll.`, `CON`). `policy::path::classify` separates them.
//! - **Restricted entries.** An entry whose own security descriptor denies the current user
//!   even an attribute-only open (e.g. `%LOCALAPPDATA%\ElevatedDiagnostics`,
//!   `C:\ProgramData\ntuser.pol`) is neither an error nor dropped: `read_dir` and `metadata`
//!   describe it from the directory listing with [`Metadata::restricted`] set. Kind, length,
//!   attributes, file ID and reparse tag come from the listing; the link count is unknown
//!   (`links: None`, never "single-link") and so is a link target (`None`). `open_read`,
//!   `read`, `open_dir`, `read_dir(Some(_))` on it and any walk through it stay
//!   `AccessDenied`; nothing ever opens it (snapshot and policy record it as metadata only).
//!   `sys::win`: listing with `FileIdExtdDirectoryInformation`; on a file system without that
//!   class (FAT) the listing has no file ID and a denied entry stays an `AccessDenied` error
//!   (fail closed; FAT has no ACLs, so this does not happen in practice).
//! - `sys::win` implements only the reading methods in phase 1; the writing ones return
//!   `Unsupported`.

use std::io::{Read, Seek};
use std::path::{Path, PathBuf};

use super::{SysError, SysErrorKind, SysResult};
use crate::path::RelPath;

/// Reparse tags known to Rerun.
pub mod tag {
    /// Junction / mount point (name surrogate).
    pub const MOUNT_POINT: u32 = 0xA000_0003;
    /// Symbolic link (name surrogate).
    pub const SYMLINK: u32 = 0xA000_000C;
    /// WSL symbolic link (name surrogate).
    pub const LX_SYMLINK: u32 = 0xA000_001D;
    /// Windows Overlay Filter, e.g. CompactGUI compression (data tag, allowed).
    pub const WOF: u32 = 0x8000_0017;
    /// Data deduplication (data tag, allowed).
    pub const DEDUP: u32 = 0x8000_0013;
    /// Cloud files placeholder, e.g. OneDrive (data tag, allowed; also `0x9000_x01A`).
    pub const CLOUD: u32 = 0x9000_001A;
    /// App execution alias (rejected).
    pub const APPEXECLINK: u32 = 0x8000_001B;
    /// Projected file system (rejected).
    pub const PROJFS: u32 = 0x9000_001C;

    /// Name-surrogate bit of a reparse tag: the entry stands for another name.
    pub const fn is_surrogate(tag: u32) -> bool {
        tag & 0x2000_0000 != 0
    }

    /// Data tags that are treated as normal files and directories: WOF, dedup and the cloud
    /// files family (`0x9000_001A`, `0x9000_101A` … `0x9000_F01A`).
    pub const fn is_allowed_data_tag(tag: u32) -> bool {
        tag == WOF || tag == DEDUP || tag & 0xFFFF_0FFF == CLOUD
    }
}

/// `Read + Seek + Send`, as returned by [`Dir::open_read`] (PE parsing needs `Seek`).
pub trait ReadSeek: Read + Seek + Send {}

impl<T: Read + Seek + Send> ReadSeek for T {}

/// Kind of an entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EntryKind {
    /// Regular file (possibly with an allowlisted data tag).
    File,
    /// Directory (possibly with an allowlisted data tag).
    Dir,
    /// Name surrogate (junction, symlink …) or an entry with an unknown reparse tag.
    /// Never followed, never opened for data.
    Reparse,
}

/// File attributes that matter for Rerun.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Attrs {
    /// `FILE_ATTRIBUTE_READONLY`.
    pub readonly: bool,
    /// `FILE_ATTRIBUTE_HIDDEN`.
    pub hidden: bool,
    /// `FILE_ATTRIBUTE_SYSTEM`.
    pub system: bool,
}

/// Reparse data of an entry.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ReparseInfo {
    /// Reparse tag (see [`tag`]).
    pub tag: u32,
    /// Name surrogate (junction, symlink).
    pub surrogate: bool,
    /// Link target as stored (print name), for name surrogates.
    pub target: Option<String>,
}

/// Metadata of an entry, without following reparse points. Timestamps are deliberately
/// absent (see `snapshot`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Metadata {
    /// Kind of the entry.
    pub kind: EntryKind,
    /// Size in bytes (0 for directories and reparse points).
    pub len: u64,
    /// Attributes.
    pub attrs: Attrs,
    /// Number of hard links: `Some(1)` for directories and reparse points, `None` = unknown
    /// ([`Self::restricted`] entries). Unknown never counts as a single link: ask
    /// [`Self::is_single_link`] (or compare with `== Some(1)`), never `links > Some(1)`
    /// (`None` orders below `Some`, so that comparison would treat unknown as single-link).
    pub links: Option<u32>,
    /// 128-bit file ID (`FILE_ID_INFO`), unique per volume.
    pub file_id: u128,
    /// Reparse data: `Some` for [`EntryKind::Reparse`] and for allowlisted data tags.
    pub reparse: Option<ReparseInfo>,
    /// The entry cannot be opened by the current user, not even for its attributes (its own
    /// DACL denies it). Described from the directory listing only: `links` is `None`, a link
    /// target is `None`. Never opened, hashed or traversed (see the module docs).
    pub restricted: bool,
}

impl Metadata {
    /// Exactly one hard link is known. `false` for an unknown link count (restricted entry),
    /// so the hard-link rule (ADR 0007: never change a linked file in place) fails closed.
    pub fn is_single_link(&self) -> bool {
        self.links == Some(1)
    }
}

/// Entry of a directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirEntry {
    /// Raw name as on disk. May be invalid as a [`RelPath`] (see `policy::path::classify`).
    pub name: String,
    /// Metadata.
    pub meta: Metadata,
}

/// Identity and properties of an opened directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootInfo {
    /// Canonical path at call time (`GetFinalPathNameByHandleW`, `\\?\X:\…`).
    pub final_path: PathBuf,
    /// Volume serial number.
    pub volume_serial: u64,
    /// 128-bit file ID of the directory.
    pub file_id: u128,
    /// The current (non-elevated) user can write into the directory.
    pub user_writable: bool,
    /// The directory is case-sensitive (`FILE_CASE_SENSITIVE_DIR`); writes are refused.
    pub case_sensitive: bool,
    /// Path of the directory relative to the root of its volume, `\`-separated, without a
    /// leading or trailing `\`, raw names (unpaired surrogates as U+FFFD). Empty for the root
    /// of a volume: a drive root or a volume mounted in a folder (`sys::win`:
    /// `FileNormalizedNameInformation` of the handle). A fact, not a rule: `policy::root`
    /// refuses volume roots and applies the per-volume folder rule to the first segment.
    ///
    /// `sys::win` takes it only from `FileNormalizedNameInformation` on the same handle (long
    /// names, relative to the handle's own volume) with exactly one leading `\` stripped. If
    /// that query fails, `info()` fails: never a fallback to `FileNameInformation` (8.3 names
    /// would slip past `WINDOWSAPPS`), never derived from `final_path` (drive-relative, misses
    /// folder-mounted volumes), never `""` as a stand-in.
    pub volume_path: String,
    /// File system of the volume.
    pub fs_kind: FsKind,
    /// The volume supports POSIX rename semantics (`FILE_RENAME_FLAG_POSIX_SEMANTICS`).
    pub supports_posix_rename: bool,
}

impl RootInfo {
    /// The directory is the root of a volume (drive root or a volume mounted in a folder).
    pub fn is_volume_root(&self) -> bool {
        self.volume_path.is_empty()
    }

    /// First segment of [`Self::volume_path`]; `None` for a volume root.
    pub fn volume_first_segment(&self) -> Option<&str> {
        self.volume_path
            .split('\\')
            .next()
            .filter(|s| !s.is_empty())
    }
}

/// File system of a volume (`GetVolumeInformationByHandleW`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum FsKind {
    /// NTFS.
    Ntfs,
    /// ReFS.
    Refs,
    /// FAT12/16/32.
    Fat,
    /// exFAT.
    ExFat,
    /// Anything else.
    Other,
}

/// File system: the only absolute operation.
pub trait Fs: Send + Sync {
    /// Opens a directory by absolute path. Follows reparse points in `abs` (they lie above
    /// the root). Missing yields `NotFound`, a file `InvalidPath`.
    ///
    /// Input: drive-absolute only, `X:\…` or `\\?\X:\…` (`/` is treated as `\`, empty
    /// segments are ignored). Relative paths, `.` and `..`, UNC and volume GUID paths and
    /// segments with control characters or `<>:"|?*` yield `InvalidPath` (same in `win` and
    /// `fake`). A non-allowlisted reparse tag on the opened directory itself yields
    /// `ReparsePoint`.
    ///
    /// Only `policy::root` and `sys::snapshot` call this (ADR 0007).
    fn open_dir(&self, abs: &Path) -> SysResult<Box<dyn Dir + '_>>;
}

/// An opened directory. All paths are relative to it and never follow reparse points.
pub trait Dir: Send + Sync + std::fmt::Debug {
    /// Identity of this directory, computed at call time. `NotFound` if it was deleted.
    ///
    /// `sys::win` resolves `final_path` and `volume_path` component by component; while an
    /// ancestor is being renamed at that moment the query can fail. It is retried a bounded
    /// number of times; if the race persists, `info` returns `NotFound` (callers fail closed,
    /// an identity is never guessed).
    fn info(&self) -> SysResult<RootInfo>;

    /// Opens a subdirectory relative to this handle. Never follows reparse points.
    fn open_dir(&self, p: &RelPath) -> SysResult<Box<dyn Dir + '_>>;

    /// Metadata without following reparse points (lstat-like). `Ok(None)` = does not exist
    /// (also: a parent is missing or is a file). A reparse point in the parents is an error,
    /// a restricted parent `AccessDenied`. A restricted entry itself is described from the
    /// listing of its parent ([`Metadata::restricted`]), exactly as `read_dir` reports it.
    fn metadata(&self, p: &RelPath) -> SysResult<Option<Metadata>>;

    /// Opens a file for reading. A directory or a restricted entry yields `AccessDenied`.
    fn open_read(&self, p: &RelPath) -> SysResult<Box<dyn ReadSeek + '_>>;

    /// Reads a whole file.
    fn read(&self, p: &RelPath) -> SysResult<Vec<u8>> {
        let mut reader = self.open_read(p)?;
        let mut buf = Vec::new();
        reader
            .read_to_end(&mut buf)
            .map_err(|_| SysError::new(SysErrorKind::Other, p.as_str()))?;
        Ok(buf)
    }

    /// Lists a directory (`None` = this one). Raw names, order unspecified. Names with
    /// unpaired UTF-16 surrogates are converted with U+FFFD and such entries are never
    /// dropped (`policy::path::classify` turns them into anomalies).
    /// Restricted entries are listed with [`Metadata::restricted`], never dropped.
    fn read_dir(&self, p: Option<&RelPath>) -> SysResult<Vec<DirEntry>>;

    /// Creates a new file (`FILE_CREATE`): an existing entry of any kind yields
    /// `AlreadyExists` and is not touched.
    fn create_new(&self, p: &RelPath, data: &[u8]) -> SysResult<()>;

    /// Replaces an existing file (ADR 0007 "Replace"). `tmp` is a single segment supplied by
    /// the journal; `<tmp>` is created next to the target with create-new semantics, then the
    /// old file is renamed to `<tmp>.old`, `<tmp>` is renamed onto the target name and
    /// `<tmp>.old` is deleted. The stored spelling of the target name is kept.
    ///
    /// Errors: missing target `NotFound`, directory or read-only file `AccessDenied`,
    /// reparse point `ReparsePoint`, `<tmp>` or `<tmp>.old` already present `AlreadyExists`
    /// (target unchanged). Other links of a hard-linked target keep the old content. If the
    /// final rename fails, `<tmp>` and `<tmp>.old` stay for the journal to recover.
    /// `tmp` or `<tmp>.old` equal to the target name (case-insensitively) yields `InvalidPath`.
    ///
    /// If the target is renamed or moved by someone else between the phases, the operation
    /// aborts with `Busy`: `<tmp>` is removed and the target is left where it is, never
    /// pulled back. `sys::win` checks this with `FileNameInformation` on the held handle
    /// before each rename.
    fn replace(&self, p: &RelPath, data: &[u8], tmp: &str) -> SysResult<()>;

    /// Creates exactly one directory. Deliberately no `create_dir_all`: every created
    /// directory must be journaled individually.
    fn create_dir(&self, p: &RelPath) -> SysResult<()>;

    /// Deletes a file, or a reparse point itself (never its target). A read-only file yields
    /// `AccessDenied`, a directory `AccessDenied`. Other hard links stay.
    fn remove_file(&self, p: &RelPath) -> SysResult<()>;

    /// Deletes an empty directory (or a directory reparse point itself). Not empty yields
    /// `NotEmpty`, a file `InvalidPath`.
    fn remove_dir(&self, p: &RelPath) -> SysResult<()>;

    /// Renames or moves within this handle's tree. Never overwrites (`AlreadyExists`);
    /// a case-only change is allowed. "Case-only" is decided by file identity (the
    /// destination resolves to the same file ID as the source), never by comparing folded
    /// names. Moving a directory into its own subtree yields `InvalidPath`; a destination
    /// through a reparse point `ReparsePoint`.
    fn rename(&self, from: &RelPath, to: &RelPath) -> SysResult<()>;

    /// Sets or clears the read-only attribute. A file with more than one link yields
    /// `Linked` (in-place change), a reparse point `ReparsePoint`.
    fn set_readonly(&self, p: &RelPath, ro: bool) -> SysResult<()>;
}

#[cfg(test)]
mod tests {
    use super::{Dir, Fs, tag};

    // Compile test: both traits must be usable as trait objects.
    fn _object_safe(_: &dyn Fs, _: &dyn Dir) {}

    #[test]
    fn tag_classes() {
        for t in [tag::MOUNT_POINT, tag::SYMLINK, tag::LX_SYMLINK] {
            assert!(
                tag::is_surrogate(t) && !tag::is_allowed_data_tag(t),
                "{t:#x}"
            );
        }
        for t in [tag::WOF, tag::DEDUP, tag::CLOUD, 0x9000_101A, 0x9000_F01A] {
            assert!(
                !tag::is_surrogate(t) && tag::is_allowed_data_tag(t),
                "{t:#x}"
            );
        }
        for t in [tag::APPEXECLINK, tag::PROJFS, 0x9000_001B] {
            assert!(
                !tag::is_surrogate(t) && !tag::is_allowed_data_tag(t),
                "{t:#x}"
            );
        }
    }
}
