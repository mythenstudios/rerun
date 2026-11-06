//! File system traits: one absolute [`Fs::open_dir`], everything else relative to a [`Dir`]
//! handle (ADR 0007). Capabilities are split (ADR 0017): [`Dir`] reads, [`DirWrite`] writes
//! the direct children of its handle, [`FileGuard`] holds one existing file for a check and
//! an act on the same handle.
//!
//! Semantics (identical for `win` and `fake`, checked in `sys::contract`):
//! - Names are case-insensitive, the original case is preserved. Folding is 1:1 per
//!   character like the NTFS upcase table (`Straße` and `STRASSE` are two names).
//! - [`Fs::open_dir`] is the only absolute operation. It follows reparse points in the given
//!   path (above the root), e.g. a Steam library that was moved and linked back.
//! - Below a root, every component is opened relative to its parent. Name surrogates
//!   (junction, mount point, symlink, LX symlink) and entries with an unknown reparse tag are
//!   reported as [`EntryKind::Reparse`] and never traversed; operations through them return
//!   `ReparsePoint`.
//! - Entries with an allowlisted data tag ([`tag::is_allowed_data_tag`]: WOF, dedup, cloud
//!   files) behave like normal files and directories and carry the tag in
//!   [`Metadata::reparse`] as far as Windows reports it: while the `wof.sys` filter is
//!   attached (every normal boot) it hides its own reparse point, so a WOF-compressed file
//!   (CompactGUI, `compact /exe`) looks like a plain file without a tag and reads its
//!   uncompressed content (contract `fs_read_contract`, WOF case).
//! - A handle refers to an object, not a name: it stays valid when the directory or one of
//!   its parents is renamed. [`Dir::info`] computes the path at call time. Renaming a parent
//!   while any handle below it is open is refused (`AccessDenied`, observed on Windows for
//!   every kind of handle, modelled by the fake, ADR 0017 A5); renaming the directory itself
//!   is allowed.
//! - **Delete-pending entries** (ADR 0017, A6): a name in legacy delete-pending state (deleted
//!   by another program while a second handle is still open) cannot be opened at all:
//!   `metadata`, `open_read`, `read`, `users`, `open_dir`, `guard`, `lock` and the existence
//!   check of `create_new` are `Busy`, and `read_dir` skips it like an entry that vanished
//!   between the listing and its reopen. The fake models it; `sys::win` maps
//!   `STATUS_DELETE_PENDING` to `Busy` and skips such an entry in a listing.
//! - **Share modes.** A handle that reads data shares read only (`open_read`), a [`Dir`]
//!   handle shares everything; an open that conflicts with another program's handle is
//!   `Busy`. Attribute-only opens (`metadata`, `users`, the components of a walk) are never
//!   blocked, so a walk passes through a folder held exclusively by someone else.
//! - Writes into a case-sensitive directory return `Unsupported`.
//! - `read_dir` returns raw names as on disk; they may be invalid as a [`RelPath`]
//!   (`d3d9.dll.`, `CON`). `policy::path::classify` separates them.
//! - **Bounded reads** (ADR 0011, ADR 0012). Input that someone else can make large is read
//!   with a bound: [`Dir::read_limited`] (a file of at most `max_len` bytes) and
//!   [`Dir::read_dir_limited`] (a listing of at most `max_entries` entries). Beyond the bound
//!   both refuse with `TooLarge`; neither ever returns a truncated file or a partial list.
//! - **Restricted entries.** An entry whose own security descriptor denies the current user
//!   even an attribute-only open (e.g. `%LOCALAPPDATA%\ElevatedDiagnostics`,
//!   `C:\ProgramData\ntuser.pol`) is neither an error nor dropped: `read_dir` and `metadata`
//!   describe it from the directory listing with [`Metadata::restricted`] set. Kind, length,
//!   attributes, file ID and reparse tag come from the listing; the link count is unknown
//!   (`links: None`, never "single-link") and so is a link target (`None`). `open_read`,
//!   `read`, `open_dir`, `read_dir(Some(_))` on it and any walk through it stay
//!   `AccessDenied`; nothing ever opens it (the snapshot of the round-trip tests and policy
//!   record it as metadata only).
//!   `sys::win`: listing with `FileIdExtdDirectoryInformation`; on a file system without that
//!   class (FAT) the listing has no file ID and a denied entry stays an `AccessDenied` error
//!   (fail closed; FAT has no ACLs, so this does not happen in practice).
//! - **Error targets.** `SysError.target` only ever contains validated paths (`RelPath`,
//!   `RootPath`, input that passed the rules above), fixed placeholders, or names from the
//!   system escaped (`{:?}`). `sys::win` formats every listed entry name escaped
//!   (`<dir>: entry "<name>"`), and [`SysError::new`] escapes any target that still holds a
//!   control or an invisible/confusable character ([`crate::sys::shown_target`]), in `win`
//!   and `fake` alike.
//! - Implementation status: both `sys::fake` and `sys::win` implement the read side and the
//!   write side. The write sequences live once in `sys::seq` (ADR 0017, A1) and
//!   [`FileGuard`] has one implementation there; both implement only the primitives, and the
//!   write contracts run unchanged against both. [`Dir::users`] is real in both (the fake
//!   from its share model).

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
    /// The current (non-elevated) user can change the directory itself: `AccessCheck` grants
    /// any of `FILE_ADD_FILE`, `FILE_ADD_SUBDIRECTORY`, `FILE_DELETE_CHILD`, `DELETE`,
    /// `WRITE_DAC`, `WRITE_OWNER`, `FILE_WRITE_ATTRIBUTES`, `FILE_WRITE_EA` (the owner always
    /// counts, through its implicit `WRITE_DAC`). Applies to this directory only; entries
    /// below it may have their own DACLs.
    ///
    /// In the elevated helper this is informational only and never a security decision:
    /// under over-the-shoulder elevation the linked token is the administrator's filtered
    /// token, not the interactive user's. The helper's own security-descriptor check
    /// (ADR 0007, "Elevation") is the boundary.
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
    /// Read side only ([`Dir`]). Only `policy::root` calls this (ADR 0007); test code opts
    /// out of the `clippy.toml` ban per module.
    fn open_dir(&self, abs: &Path) -> SysResult<Box<dyn Dir + '_>>;

    /// Opens a directory by absolute path with the write capability ([`DirWrite`]). Same
    /// input rules, walk and errors as [`Self::open_dir`]. Requires a [`WriteCap`], which only
    /// this crate can create: outside `rerun-core` (CLI, app) no write handle can be obtained
    /// at all. Only `policy::root` calls this (`clippy.toml`, ADR 0017).
    fn open_dir_write(&self, abs: &Path, cap: &WriteCap) -> SysResult<Box<dyn DirWrite + '_>>;
}

/// Proof of the write capability for [`Fs::open_dir_write`] (ADR 0017). Zero-sized; its
/// constructor is crate-internal and is only called in `policy::root` (and in tests of this
/// crate), so the type system keeps write handles inside `rerun-core` and the reviewed
/// paths. It carries no data and checks nothing itself.
#[derive(Debug)]
pub struct WriteCap(());

impl WriteCap {
    /// The token. Crate-internal; product code calls it only in `policy::root`.
    pub(crate) fn new() -> Self {
        Self(())
    }
}

/// An opened directory, read side. All paths are relative to it and never follow reparse
/// points.
pub trait Dir: Send + Sync + std::fmt::Debug {
    /// Identity of this directory, computed at call time. `NotFound` if it was deleted.
    ///
    /// `sys::win` resolves `final_path` and `volume_path` component by component; while an
    /// ancestor is being renamed at that moment a query can fail, or the two can see
    /// different moments. Both are taken in one attempt that must agree (`final_path` ends
    /// with `volume_path`); a failed or disagreeing attempt is retried a bounded number of
    /// times, and if the race persists `info` returns `NotFound` (callers fail closed, an
    /// identity is never guessed).
    fn info(&self) -> SysResult<RootInfo>;

    /// Opens a subdirectory relative to this handle, read side only. Never follows reparse
    /// points.
    fn open_dir(&self, p: &RelPath) -> SysResult<Box<dyn Dir + '_>>;

    /// Metadata without following reparse points (lstat-like). `Ok(None)` = does not exist
    /// (also: a parent is missing or is a file). A reparse point in the parents is an error,
    /// a restricted parent `AccessDenied`. A restricted entry itself is described from the
    /// listing of its parent ([`Metadata::restricted`]), exactly as `read_dir` reports it.
    fn metadata(&self, p: &RelPath) -> SysResult<Option<Metadata>>;

    /// The stored spelling of the last segment of `p`: the name as its directory holds it
    /// (`p` may spell it in another case), the one a [`FileGuard`] renames onto. `Ok(None)` =
    /// does not exist (as [`Self::metadata`]); in `sys::win` also an 8.3 short name (the L1
    /// check of the open refuses it as `NotFound`). Never follows a reparse point: a link is
    /// named itself. `Busy` if the entry opened has another folding than the name asked (it
    /// was renamed in between). A restricted entry is not described (an error); callers
    /// refuse restricted entries from [`Self::metadata`] first. `sys::win` asks
    /// `FileNameInformation` on an attribute-only handle opened relative to the parent, as
    /// the guard does.
    ///
    /// The default refuses (`Unsupported`): a test double that does not model names makes a
    /// planner fail closed rather than guess a spelling.
    fn stored_name(&self, p: &RelPath) -> SysResult<Option<String>> {
        Err(SysError::new(SysErrorKind::Unsupported, p.as_str()))
    }

    /// Opens a file for reading. A directory or a restricted entry yields `AccessDenied`.
    fn open_read(&self, p: &RelPath) -> SysResult<Box<dyn ReadSeek + '_>>;

    /// Reads a whole file. Unbounded: input that someone else can make large goes through
    /// [`Self::read_limited`] instead.
    fn read(&self, p: &RelPath) -> SysResult<Vec<u8>> {
        let mut reader = self.open_read(p)?;
        let mut buf = Vec::new();
        reader
            .read_to_end(&mut buf)
            .map_err(|e| SysError::io(&e, p.as_str()))?;
        Ok(buf)
    }

    /// Reads a whole file of at most `max_len` bytes (ADR 0011). A longer file is `TooLarge`
    /// and nothing is returned, never a truncated read. The length from metadata is never
    /// trusted: at most `max_len + 1` bytes are read from the handle, so a file that grows
    /// while it is read is refused as well, and a file of exactly `max_len` bytes is read.
    /// Errors of the open as in [`Self::open_read`]; read errors keep their code
    /// ([`SysError::io`]).
    fn read_limited(&self, p: &RelPath, max_len: u64) -> SysResult<Vec<u8>> {
        let reader = self.open_read(p)?;
        let mut buf = Vec::new();
        reader
            .take(max_len.saturating_add(1))
            .read_to_end(&mut buf)
            .map_err(|e| SysError::io(&e, p.as_str()))?;
        if u64::try_from(buf.len()).map_or(true, |n| n > max_len) {
            return Err(SysError::too_large(p.as_str(), max_len));
        }
        Ok(buf)
    }

    /// Lists a directory (`None` = this one) without a bound on the number of entries; see
    /// [`Self::read_dir_limited`].
    fn read_dir(&self, p: Option<&RelPath>) -> SysResult<Vec<DirEntry>> {
        self.read_dir_limited(p, usize::MAX)
    }

    /// Lists a directory (`None` = this one) of at most `max_entries` entries (ADR 0012). Raw
    /// names, order unspecified. Names with unpaired UTF-16 surrogates are converted with
    /// U+FFFD and such entries are never dropped (`policy::path::classify` turns them into
    /// anomalies). Restricted entries are listed with [`Metadata::restricted`], never
    /// dropped.
    ///
    /// The bound counts the names in the listing (without `.` and `..`) **before** any entry
    /// is opened: more than `max_entries` is `TooLarge` and nothing is returned, never a
    /// partial list. `sys::win` stops listing at the first batch that crosses the bound, so
    /// it holds at most `max_entries` names plus one 64 KiB batch and opens none of them. An
    /// entry that vanishes between the listing and its reopen is skipped (the result may
    /// have fewer entries than were counted).
    fn read_dir_limited(&self, p: Option<&RelPath>, max_entries: usize)
    -> SysResult<Vec<DirEntry>>;

    /// Process IDs that use the file `p` at this moment: open handles, image sections and
    /// mapped views, the running process of an executable (ADR 0017, "users()"). A check at
    /// a moment, not a lock. The current process counts only through handles other than the
    /// one used for the query. Order unspecified, no duplicates.
    ///
    /// Only plain files (an allowlisted data tag counts as plain): a directory or a
    /// restricted entry yields `AccessDenied`, a reparse point `ReparsePoint`, a missing
    /// entry `NotFound`. `sys::win` queries `FileProcessIdsUsingFileInformation` on an
    /// attribute-only handle opened relative to the parent (never following a reparse point),
    /// which no share mode blocks. `sys::fake` reports every handle its share model records
    /// on the file (`Dir::open_read` readers, fixture holds), with their process IDs.
    fn users(&self, p: &RelPath) -> SysResult<Vec<u32>>;
}

/// An opened directory that can write its direct children (ADR 0017). `policy::root` hands
/// it out only for game folders (and later Rerun's own folder), never for a store.
///
/// Every write names a direct child of this handle (`name` is exactly one segment, else
/// `InvalidPath`): the parent is the handle that is checked, renamed into and flushed, never
/// a path resolved again. Writes into a case-sensitive directory and on a volume without
/// POSIX delete and rename semantics are `Unsupported`.
///
/// The writing methods run the sequences of `sys::seq` (ADR 0017, A1) over the primitives of
/// an implementation (`sys::fake`, `sys::win`).
pub trait DirWrite: Dir {
    /// Opens a subdirectory relative to this handle with the write capability. Same walk
    /// and errors as [`Dir::open_dir`].
    fn open_dir_write(&self, p: &RelPath) -> SysResult<Box<dyn DirWrite + '_>>;

    /// Holds the existing file `name` on one handle that shares read only, so it can be
    /// hashed, backed up, replaced or deleted with nothing changing in between
    /// ([`FileGuard`]). Refuses a directory (`AccessDenied`), a reparse point
    /// (`ReparsePoint`), a case-sensitive parent (`Unsupported`) and a link count other than
    /// 1 (`Linked`).
    fn guard(&self, name: &RelPath) -> SysResult<Box<dyn FileGuard + '_>>;

    /// Creates the file `name` from `src` through the temp file `new.tmp` and a rename
    /// without replace, so a crash never leaves a torn file under `name`. At most
    /// `new.max_len` bytes; a hash other than `new.sha256` deletes the temp file and is
    /// `Mismatch`. An existing `name` is `AlreadyExists`, a collision only at the rename
    /// `Busy`. The attributes `new.attrs` are set after the last write.
    fn create_new(&self, name: &RelPath, src: &mut dyn Read, new: &NewFile) -> SysResult<Written>;

    /// Creates exactly one directory and returns its file ID. Deliberately no
    /// `create_dir_all`: every created directory is journaled individually.
    fn create_dir(&self, name: &RelPath) -> SysResult<u128>;

    /// Deletes the empty directory `name` by handle if its file ID is `expected_id`
    /// (`Mismatch` otherwise, nothing changed). Not empty yields `NotEmpty`.
    fn remove_dir(&self, name: &RelPath, expected_id: u128) -> SysResult<()>;

    /// Flushes this directory (the renames into it), best effort (ADR 0019).
    fn flush(&self) -> SysResult<()>;

    /// Opens or creates the plain file `name` under its final name (it stays empty; its
    /// content never matters) with share 0 and keeps it open until the [`FileLock`] drops: any
    /// other open of it, by Rerun or anyone, is `Busy` meanwhile; the kernel releases it when
    /// the process ends (ADR 0017, A7; the journal lock of ADR 0019). Never follows a reparse
    /// point (`ReparsePoint`); a directory is `AccessDenied`, a link count other than 1
    /// `Linked`.
    fn lock(&self, name: &RelPath) -> SysResult<Box<dyn FileLock + '_>>;
}

/// A held lock file ([`DirWrite::lock`]); dropping it releases the lock.
pub trait FileLock: Send + std::fmt::Debug {}

/// One handle on an existing file that shares read only (ADR 0017, "FileGuard"): while it is
/// held nobody else can write, rename or delete the file, so the hash taken on it is the hash
/// of what [`Self::replace`] and [`Self::delete`] act on.
pub trait FileGuard: Send + std::fmt::Debug {
    /// The stored spelling of the name it was opened by (one segment, as its directory
    /// holds it when the guard was opened): the name a replace renames onto. Compare it
    /// with [`RelPath::same_spelling`]: `==` on a [`RelPath`] folds.
    fn name(&self) -> &RelPath;

    /// Metadata, queried on the guard handle.
    fn metadata(&self) -> SysResult<Metadata>;

    /// SHA-256 of the content, streamed once, then cached.
    fn sha256(&mut self) -> SysResult<[u8; 32]>;

    /// The content from offset 0, for backups.
    fn reader(&mut self) -> SysResult<Box<dyn Read + '_>>;

    /// Process IDs using the file, queried on the guard handle itself (see [`Dir::users`]).
    fn users(&self) -> SysResult<Vec<u32>>;

    /// Replaces the file if its hash is `expected` (`Mismatch` otherwise, nothing touched):
    /// temp file, rename to `<tmp>.old`, rename onto the stored spelling of the name, POSIX
    /// delete of `<tmp>.old` (ADR 0017, "Replace sequence"). `new.sha256 == expected` is
    /// `Unsupported`. Before each rename and the delete the guard re-checks its name (`Busy`),
    /// its link count (`Linked`) and R/H/S (`Mismatch`); a failed step 7 renames the guard
    /// back on the same handle; a failed step 8 is success with `old_left` (amendment A2, A4).
    fn replace(
        self: Box<Self>,
        expected: &[u8; 32],
        src: &mut dyn Read,
        new: &NewFile,
    ) -> SysResult<Replaced>;

    /// Deletes the file (POSIX semantics, also read-only) if its hash is `expected`
    /// (`Mismatch` otherwise) and the re-checks of [`Self::replace`] pass; the name is free
    /// when this returns.
    fn delete(self: Box<Self>, expected: &[u8; 32]) -> SysResult<()>;

    /// Renames the file to `name` in the same directory, never replacing. Recovery only.
    fn rename_to(self: Box<Self>, name: &RelPath) -> SysResult<()>;
}

/// What a new file must be: its temp name, attributes, content hash and maximum length.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewFile {
    /// Temp name next to the target, journaled before the write (ADR 0019).
    pub tmp: TmpName,
    /// Read-only, hidden and system, set after the last write.
    pub attrs: Attrs,
    /// Expected SHA-256 of the content streamed from the source.
    pub sha256: [u8; 32],
    /// Most bytes the source may yield.
    pub max_len: u64,
}

/// A file written by [`DirWrite::create_new`] or [`FileGuard::replace`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Written {
    /// SHA-256 of what was written.
    pub sha256: [u8; 32],
    /// Length in bytes.
    pub len: u64,
    /// 128-bit file ID of the new file.
    pub file_id: u128,
}

/// Result of [`FileGuard::replace`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Replaced {
    /// The new file.
    pub new: Written,
    /// `Some(tmp)` if [`TmpName::old`] of `tmp` (the old content) is still present because it
    /// is mapped as an image: success with pending cleanup, recorded by the journal
    /// (ADR 0019).
    pub old_left: Option<TmpName>,
}

/// Prefix of every [`TmpName`].
const TMP_PREFIX: &str = ".rerun-";
/// Suffix of every [`TmpName`].
const TMP_SUFFIX: &str = ".tmp";

/// A temp file name `.rerun-<tag>-<n>.tmp` (ADR 0019): `<tag>` the instance tag as exactly 16
/// lowercase hex digits, `<n>` a decimal counter (a `u64`, no leading zero). Always a single
/// valid segment; chosen and journaled before any write. [`Self::new`] and [`Self::parse`]
/// are a bijection: every accepted string is the one `new` writes for its tag and counter.
///
/// Recovery (ADR 0019) works from the name in the journal: it compares that name with what
/// is on disk folded, like every name, and never adopts a temp name it merely finds in a
/// listing (a `.rerun-…` file planted by someone else is not ours).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TmpName {
    name: String,
    tag: u64,
}

impl TmpName {
    /// The temp name for instance `tag` and counter `n`.
    pub fn new(tag: u64, n: u64) -> Self {
        Self {
            name: format!("{TMP_PREFIX}{tag:016x}-{n}{TMP_SUFFIX}"),
            tag,
        }
    }

    /// Parses a name read back from the journal; `None` unless it is exactly what
    /// [`Self::new`] writes.
    pub fn parse(s: &str) -> Option<Self> {
        let body = s.strip_prefix(TMP_PREFIX)?.strip_suffix(TMP_SUFFIX)?;
        let (tag, n) = body.split_once('-')?;
        let hex = |c: char| c.is_ascii_digit() || ('a'..='f').contains(&c);
        if tag.len() != 16 || !tag.chars().all(hex) {
            return None;
        }
        if !n.chars().all(|c| c.is_ascii_digit()) || (n != "0" && n.starts_with('0')) {
            return None;
        }
        let made = Self::new(u64::from_str_radix(tag, 16).ok()?, n.parse().ok()?);
        (made.name == s).then_some(made)
    }

    /// The instance tag (ADR 0019).
    pub fn tag(&self) -> u64 {
        self.tag
    }

    /// The name.
    pub fn as_str(&self) -> &str {
        &self.name
    }

    /// The name as a single-segment path.
    pub fn to_rel(&self) -> RelPath {
        segment(&self.name)
    }

    /// `<tmp>.old`: the name of the old file during a replace (ADR 0017).
    pub fn old(&self) -> RelPath {
        segment(&format!("{}.old", self.name))
    }
}

impl std::fmt::Display for TmpName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.name)
    }
}

/// A name of the [`TmpName`] shape (ASCII letters, digits, `.`, `-`, no trailing dot) is
/// always a valid single segment.
fn segment(s: &str) -> RelPath {
    match RelPath::from_segment(s) {
        Ok(p) => p,
        Err(e) => unreachable!("{s:?} has the TmpName shape and is a segment: {e}"),
    }
}

#[cfg(test)]
mod tests {
    use super::{Dir, DirWrite, FileGuard, FileLock, Fs, TmpName, tag};

    // Compile test: every trait must be usable as a trait object, and a write handle is a
    // read handle.
    fn _object_safe(
        _: &dyn Fs,
        _: &dyn Dir,
        w: &dyn DirWrite,
        _: &dyn FileGuard,
        _: &dyn FileLock,
    ) {
        let _: &dyn Dir = w;
    }

    #[test]
    fn tmp_names_have_one_shape_and_are_segments() {
        for (tag, n) in [(0, 0), (0x1234_abcd, 7), (u64::MAX, u64::MAX)] {
            let t = TmpName::new(tag, n);
            assert_eq!(TmpName::parse(t.as_str()), Some(t.clone()));
            assert_eq!(t.to_rel().as_str(), t.as_str());
            assert_eq!(t.old().as_str(), format!("{t}.old"));
        }
        assert_eq!(
            TmpName::new(0xab, 12).as_str(),
            ".rerun-00000000000000ab-12.tmp"
        );
        for (ok, tag) in [
            (".rerun-000000000000000a-0.tmp", 0xa),
            (".rerun-ffffffffffffffff-18446744073709551615.tmp", u64::MAX),
        ] {
            assert_eq!(TmpName::parse(ok).map(|t| t.tag()), Some(tag), "{ok}");
        }
        assert_eq!(TmpName::new(0x1234, 9).tag(), 0x1234);
        for bad in [
            "",
            ".rerun-a-0.tmp",
            ".rerun-000000000000000-1.tmp",
            ".rerun-00000000000000000-1.tmp",
            ".rerun-000000000000000A-1.tmp",
            ".rerun--1.tmp",
            ".rerun-a-.tmp",
            ".rerun-A-1.tmp",
            ".rerun-g-1.tmp",
            ".rerun-a-01.tmp",
            ".rerun-a-1-2.tmp",
            ".rerun-a-+1.tmp",
            ".rerun-11111111111111111-1.tmp",
            ".rerun-a-18446744073709551616.tmp",
            ".rerun-a-1.tmp.old",
            "rerun-a-1.tmp",
            r"x\.rerun-a-1.tmp",
            ".rerun-a-1.TMP",
        ] {
            assert!(TmpName::parse(bad).is_none(), "{bad}");
        }
    }

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
