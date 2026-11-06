//! In-memory file system with handle semantics (ADR 0007).
//!
//! The file system is a node arena. A [`Dir`] handle is a node ID plus a reference to the
//! shared state, so a handle stays valid when its directory or a parent is renamed, like on
//! NTFS. Every relative operation walks component by component; between two components an
//! optional test hook ([`FakeFs::on_step`]) runs **without** the state lock, so a test can
//! swap a directory for a junction in the middle of an operation (TOCTOU tests).
//!
//! Deliberate deviations from real Windows (not checked by the contract tests). Setup that
//! the contracts cannot do themselves goes through the `FsFixture` implementation in
//! `fake/mod.rs`; the fixture methods the fake cannot model (`subst`, `short_name`,
//! `wof_compress`) report "not available", so the contracts skip those cases.
//! - [`Fs::open_dir`] only accepts drive-absolute paths (`C:\…`, `\\?\C:\…`); no UNC, no
//!   volume GUID paths. `.` and `..` are rejected (`InvalidPath`) instead of resolved.
//! - Drive roots exist implicitly. The volume serial is derived from the drive letter, file
//!   IDs come from a counter and are never reused.
//! - No 8.3 short names, no stripping of trailing dots or spaces: raw names (see
//!   [`FakeFs::put_raw_file`]) are stored exactly as given.
//! - **Share model** (ADR 0017, contract `fs_read_contract`): every handle that stays open is
//!   recorded with its access, share mode, process ID and origin (Rerun or a fixture): a
//!   [`Dir`] handle (list, shares read, write and delete), an `open_read` reader (read, shares
//!   read), a fixture hold ([`FakeFs::hold_open_as`]). A new open with data access is checked
//!   against the open handles of the same object (a file's inode, shared by its hard links; a
//!   directory's node) with [`share_conflict`], like `IoCheckShareAccess`; a conflict is
//!   `Busy`. Attribute-only opens (`metadata`, `users`, every component of a walk, which
//!   `sys::win` opens with `FILE_READ_ATTRIBUTES` only) are neither checked nor recorded.
//!   Fixture moves are checked the same way: overwriting a file asks for write, renaming or
//!   removing an entry for delete, renaming into a directory for write on that directory;
//!   renaming a directory while any recorded handle (of any kind, also an attribute-only
//!   hold) is open strictly below it is `AccessDenied`, as observed on Windows (ADR 0017, A5).
//!   Adding a hard link and changing attributes are never checked (observed allowed while a
//!   guard is held). [`FakeFs::rename_ignoring_shares`] renames without any of these checks,
//!   which Windows cannot do; it exists for defence-in-depth tests only. [`Dir::users`]
//!   reports the process ID of every recorded handle on the file. A handle closes when its
//!   owner drops: the drop queues the close and the next access to the state applies it (never
//!   re-entrant, also when a handle drops while the state is locked). A handle to a deleted
//!   directory returns `NotFound`. Image sections ([`FakeFs::map_image_as`]) and legacy
//!   delete-pending entries ([`FakeFs::delete_pending`]) are records of their own kind, see
//!   there.
//! - **Write side** ([`DirWrite`], ADR 0017): the sequences live once in `sys::seq`; the fake
//!   implements only their primitives (`fs/prim.rs`). Each primitive fires the step hook with
//!   `FsOp::Write` and its [`Prim`] before it acts. `<tmp>` is created with write and delete
//!   access and share 0, a lock file with read access and share 0, a directory is opened for
//!   deleting with share read and write; a rename into a directory needs every handle on it
//!   to share write and refuses an existing name (`Busy`); a POSIX delete removes the name
//!   when its handle closes (a directory only if it is still empty), keeping the content for
//!   other open handles. A guard opens with read and delete access and shares read. Tests
//!   change the tree through the setup and attacker helpers of [`FakeFs`].
//! - No ACLs and no elevation: `user_writable` ([`FakeFs::set_user_writable`]) is reported
//!   in [`RootInfo`] but not enforced.
//! - No alternate data streams.
//! - Hard links share content and attributes (like NTFS); the file ID of a file is the ID of
//!   its shared content.
//! - `open_read` returns a reader over a copy of the content; later writes are not visible
//!   through it.
//! - Link targets are stored strings. `Fs::open_dir` resolves absolute and relative targets
//!   lexically (at most 32 levels) and follows directory and file links alike.
//! - Allowlisted data tags (WOF, dedup, cloud) only mark the entry: content is read directly,
//!   there is no hydration and no reopen without `FILE_OPEN_REPARSE_POINT`. A WOF-tagged file
//!   shows its tag; on Windows `wof.sys` hides it (the contract accepts both).
//! - A volume mounted in a folder ([`FakeFs::set_volume_root`]) is a mount point seen from
//!   above, like on Windows: below a root it is a name surrogate (`Dir::metadata` reports
//!   `Reparse` with the `MOUNT_POINT` tag, operations through it return `ReparsePoint`), and
//!   `Fs::open_dir` by absolute path follows into it. Opened that way it reports an empty
//!   `volume_path` and its own volume serial. Deviation: the mount point is the volume root
//!   itself (no separate directory underneath), the file system and file IDs stay those of
//!   the drive, and the setup helpers walk through it without refusing.
//! - Restricted entries ([`FakeFs::set_restricted`]) are a flag, not an ACL: every open of
//!   one and every walk through it is `AccessDenied`, including `Fs::open_dir`. The setup
//!   helpers ignore the flag (they act like an administrator).
//! - Volumes: the file system is NTFS unless set with [`FakeFs::set_fs_kind`]; it only
//!   changes what [`RootInfo`] reports, not the behaviour.
//! - **Faults and crashes** (ADR 0019 amendment): every call of Rerun (a write primitive, a
//!   read-side call, `Fs::open_dir`) is counted and can be failed or crashed after
//!   ([`FakeFs::fault`], [`Fault`]); after a crash every call of Rerun fails until
//!   [`FakeFs::restart`], which closes Rerun's handles by origin, and no step hook fires.
//!   Fixture and attacker helpers are never counted, faulted or blocked, and neither is a
//!   call made from inside a step hook (it plays another program).
//! - **Power loss** (ADR 0019 amendment, `fs/durable.rs`): one ordered log of Rerun's
//!   metadata changes per volume, made durable by flushes; [`FakeFs::power_loss`] keeps any
//!   prefix of the unflushed part per volume and resets content to the last flushed. A
//!   fixture change makes its volume's log durable (another program that flushed).
//!   Deviation: a volume mounted in a folder shares the log of its drive.
//! - Hooks fire for [`Dir`] operations, the write primitives and once before `Fs::open_dir`
//!   resolves its path ([`FsOp::OpenAbs`]), never for the setup helpers, and never
//!   reentrantly (a hook that calls into the fake does not trigger itself).

use std::cell::Cell;
use std::collections::BTreeMap;
use std::fmt;
use std::io::{Cursor, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use crate::fold::fold;
use crate::path::RelPath;
use crate::sys::contract::{Access, Share, share_conflict};
use crate::sys::fs::{
    Attrs, Dir, DirEntry, DirWrite, EntryKind, FileGuard, FileLock, Fs, FsKind, Metadata, NewFile,
    ReadSeek, ReparseInfo, RootInfo, WriteCap, Written, tag,
};
use crate::sys::{SysError, SysErrorKind, SysResult, seq};

mod durable;
mod prim;

pub use prim::FakeFile;

use durable::VolLog;

type NodeId = u64;

/// Maximum number of reparse levels `Fs::open_dir` follows.
const MAX_FOLLOW: u32 = 32;

/// Operation during which a [`StepEvent`] fires.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum FsOp {
    /// `Dir::open_dir`.
    OpenDir,
    /// `Dir::metadata`.
    Metadata,
    /// `Dir::open_read`.
    OpenRead,
    /// `Dir::read_dir`.
    ReadDir,
    /// `Dir::users`.
    Users,
    /// `DirWrite::open_dir_write`.
    OpenDirWrite,
    /// A primitive call of the write side (`sys::seq`); [`StepEvent::call`] names it.
    Write,
    /// `Dir::info` (only as a fault unit, [`Prim::ReadSide`]; no walk, no hook).
    Info,
    /// `Fs::open_dir` and `Fs::open_dir_write`: a hook only (`name` is the absolute path as
    /// given), fired once before the path is resolved; the fault unit stays
    /// `Prim::ReadSide(FsOp::OpenDir)`.
    OpenAbs,
}

/// A primitive call of the write side (ADR 0017, A1), the unit of the fake's write hooks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Prim {
    /// `PrimDir::support` (case sensitivity, POSIX support; before every write).
    Support,
    /// `PrimDir::volume_name` (the guard's name re-check).
    VolumeName,
    /// `PrimDir::open_guard` (step 1).
    OpenGuard,
    /// `PrimDir::lookup` (attribute-only metadata of a child).
    Lookup,
    /// `PrimDir::create_tmp` (step 2).
    CreateTmp,
    /// `PrimDir::open_lock`.
    OpenLock,
    /// `PrimDir::create_dir`.
    CreateDir,
    /// `PrimDir::open_dir_delete`.
    OpenDirDelete,
    /// `PrimDir::rename` (steps 6 and 7, the undo, `rename_to`, `create_new`).
    Rename,
    /// `PrimDir::flush`.
    FlushDir,
    /// `PrimFile::state`.
    State,
    /// `PrimFile::name` (the guard's name re-check).
    Name,
    /// `PrimFile::read_at` (one chunk of the guard's hash or reader).
    ReadAt,
    /// `PrimFile::users`.
    Users,
    /// `PrimFile::write` (one chunk of step 3).
    Write,
    /// `PrimFile::set_attrs` (step 4).
    SetAttrs,
    /// `PrimFile::flush` (step 5).
    FlushFile,
    /// `PrimFile::posix_delete` (step 8, `delete`, `remove_dir`, the cleanup of `<tmp>`).
    PosixDelete,
    /// A read-side operation of a `Dir` handle or `Fs::open_dir` (`FsOp::OpenDir`): a fault
    /// unit only, its hooks are the walk steps.
    ReadSide(FsOp),
}

/// What an armed fault does when its call comes ([`FakeFs::fault`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fault {
    /// The call fails with this kind before it acts.
    Fail(SysErrorKind),
    /// The call acts, then the process crashes (ADR 0019 amendment): this and every later
    /// call of Rerun fails with `Other` ("fake: process crashed"), so no rollback runs, until
    /// [`FakeFs::restart`]. A read-side call crashes before it acts.
    CrashAfter,
}

/// Fault injection state of the file system (not shared with `FakeRegistry`).
#[derive(Debug, Default)]
struct Faults {
    /// Armed faults: call, its 1-based occurrence, what happens.
    armed: Vec<(Prim, usize, Fault)>,
    /// Calls seen since the faults were last cleared, per call.
    seen: Vec<(Prim, usize)>,
    fired: bool,
    record: bool,
    calls: Vec<Prim>,
    crashed: bool,
}

thread_local! {
    /// The current thread runs a step hook ([`FakeFs::on_step`]).
    static IN_HOOK: Cell<bool> = const { Cell::new(false) };
}

fn crashed_err() -> SysError {
    err(SysErrorKind::Other, "fake: process crashed")
}

/// A step of an operation: fires before component `index` (0-based) of the relative path is
/// looked up, and before each primitive call of the write side (`op` is [`FsOp::Write`],
/// `call` names the primitive, `name` is its name argument or empty).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StepEvent {
    /// Operation.
    pub op: FsOp,
    /// Index of the component that is looked up next (0 for a primitive call).
    pub index: usize,
    /// Name of that component.
    pub name: String,
    /// The primitive about to run (`None` for a step of a read-side walk).
    pub call: Option<Prim>,
}

/// Test hook, see [`FakeFs::on_step`].
pub type StepHook = Box<dyn FnMut(&FakeFs, &StepEvent) + Send>;

#[derive(Debug, Clone)]
struct DirData {
    /// Child key (folded, or exact in a case-sensitive directory) → node.
    children: BTreeMap<String, NodeId>,
    attrs: Attrs,
    case_sensitive: bool,
    user_writable: bool,
    /// Root directory of a volume (drive root or a volume mounted in a folder).
    volume_root: bool,
    /// Non-surrogate reparse tag (e.g. a cloud files folder).
    tag: Option<u32>,
    /// Its DACL denies the current user every open ([`FakeFs::set_restricted`]).
    restricted: bool,
}

impl DirData {
    fn new(user_writable: bool) -> Self {
        Self {
            children: BTreeMap::new(),
            attrs: Attrs::default(),
            case_sensitive: false,
            user_writable,
            volume_root: false,
            tag: None,
            restricted: false,
        }
    }

    /// No tag or an allowlisted data tag: a plain, traversable directory.
    fn plain(&self) -> bool {
        self.tag.is_none_or(tag::is_allowed_data_tag)
    }

    fn key(&self, name: &str) -> String {
        if self.case_sensitive {
            name.to_owned()
        } else {
            fold(name)
        }
    }
}

/// File content shared by all hard links.
#[derive(Debug, Clone)]
struct Inode {
    data: Vec<u8>,
    /// Content as of the last flush (ADR 0019 amendment): what a power loss leaves.
    durable: Vec<u8>,
    attrs: Attrs,
    tag: Option<u32>,
    links: u32,
    /// Its DACL denies the current user every open (shared by all hard links, like the
    /// security descriptor on NTFS).
    restricted: bool,
}

#[derive(Debug, Clone)]
struct LinkData {
    tag: u32,
    target: String,
    restricted: bool,
    /// Read-only, hidden and system of the link itself.
    attrs: Attrs,
}

#[derive(Debug, Clone)]
enum Body {
    Dir(DirData),
    /// Directory entry of a file; the value is the inode.
    File(NodeId),
    /// Name surrogate (junction, symlink).
    Link(LinkData),
}

#[derive(Debug, Clone)]
struct Node {
    parent: Option<NodeId>,
    /// Name in its original case; `X:` for a drive root.
    name: String,
    body: Body,
}

/// Identifier of a recorded open handle; never reused.
type OpenId = u64;

/// The object an open handle refers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Obj {
    /// A file, opened through the directory entry `node`; share state is per inode.
    File { node: NodeId, ino: NodeId },
    /// A directory or another non-file entry.
    Node(NodeId),
}

impl Obj {
    fn node(self) -> NodeId {
        match self {
            Self::File { node, .. } | Self::Node(node) => node,
        }
    }

    /// Both refer to the same object for the share check (hard links share an inode).
    fn same(self, other: Self) -> bool {
        match (self, other) {
            (Self::File { ino: a, .. }, Self::File { ino: b, .. }) => a == b,
            (Self::Node(a), Self::Node(b)) => a == b,
            _ => false,
        }
    }
}

/// Who opened a handle: a restart closes Rerun's handles only (ADR 0019 amendment).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Origin {
    Rerun,
    Fixture,
}

/// An open handle.
#[derive(Debug)]
struct OpenRec {
    obj: Obj,
    kind: RecKind,
    access: Access,
    share: Share,
    pid: u32,
    origin: Origin,
    /// A POSIX delete was set on the handle: the name goes when it closes.
    delete_on_close: bool,
}

/// What a record stands for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RecKind {
    /// An open handle (share-checked).
    Handle,
    /// An image section without a handle ([`FakeFs::map_image_as`]): never share-checked,
    /// but an open for write and every delete of the file are `Busy`; renames work.
    Image,
    /// A file in legacy delete-pending state ([`FakeFs::delete_pending`]): every open of it,
    /// also attribute-only, is `Busy`, listings skip it; the name goes when this closes.
    Pending,
    /// A writable data section without a handle ([`FakeFs::map_data_as`]): share-checked
    /// like an open with write access that shares everything, so every open with data
    /// access that does not share write is `Busy` (observed); renames and deletes work and
    /// it never counts for the ancestor rule (observed).
    DataMap,
}

#[derive(Debug, Default)]
struct State {
    next_id: NodeId,
    nodes: BTreeMap<NodeId, Node>,
    inodes: BTreeMap<NodeId, Inode>,
    drives: BTreeMap<char, NodeId>,
    fs_kinds: BTreeMap<char, FsKind>,
    next_open: OpenId,
    opens: BTreeMap<OpenId, OpenRec>,
    faults: Faults,
    /// Per-volume logs of Rerun's metadata changes (power-loss model, `fs/durable.rs`).
    logs: BTreeMap<char, VolLog>,
}

fn err(kind: SysErrorKind, target: &str) -> SysError {
    SysError::new(kind, target)
}

fn volume_serial(drive: char) -> u64 {
    0x5EED_0000 + u64::from(u32::from(drive))
}

/// Serial of a volume mounted in a folder: its own, distinct from every drive serial.
fn mounted_serial(root: NodeId) -> u64 {
    0x5EED_0001_0000_0000 + root
}

/// Parses `X:\a\b` or `\\?\X:\a\b` (also with `/`) into drive and segments.
fn parse_abs_str(s: &str, shown: &str) -> SysResult<(char, Vec<String>)> {
    let invalid = || err(SysErrorKind::InvalidPath, shown);
    let s = s.replace('/', "\\");
    let t = s.strip_prefix(r"\\?\").unwrap_or(&s);
    let b = t.as_bytes();
    if !(b.len() >= 2
        && b[0].is_ascii_alphabetic()
        && b[1] == b':'
        && (b.len() == 2 || b[2] == b'\\'))
    {
        return Err(invalid());
    }
    let drive = char::from(b[0]).to_ascii_uppercase();
    let mut segs = Vec::new();
    for seg in t[2..].split('\\') {
        match seg {
            "" => {}
            "." | ".." => return Err(invalid()),
            _ if seg.chars().any(|c| {
                c.is_control() || matches!(c, '<' | '>' | ':' | '"' | '|' | '?' | '*')
            }) =>
            {
                return Err(invalid());
            }
            _ => segs.push(seg.to_owned()),
        }
    }
    Ok((drive, segs))
}

fn parse_abs(p: &Path) -> SysResult<(char, Vec<String>)> {
    let shown = p.display().to_string();
    let s = p
        .to_str()
        .ok_or_else(|| err(SysErrorKind::InvalidPath, &shown))?;
    parse_abs_str(s, &shown)
}

/// Like [`parse_abs`], split into parent segments and the last name.
fn parse_abs_child(p: &Path) -> SysResult<(char, Vec<String>, String)> {
    let (drive, mut segs) = parse_abs(p)?;
    let name = segs
        .pop()
        .ok_or_else(|| SysError::path(SysErrorKind::InvalidPath, p))?;
    Ok((drive, segs, name))
}

impl State {
    fn alloc(&mut self) -> NodeId {
        self.next_id += 1;
        self.next_id
    }

    fn drive_root(&mut self, drive: char) -> NodeId {
        if let Some(&id) = self.drives.get(&drive) {
            return id;
        }
        let id = self.alloc();
        let mut root = DirData::new(true);
        root.volume_root = true;
        self.nodes.insert(
            id,
            Node {
                parent: None,
                name: format!("{drive}:"),
                body: Body::Dir(root),
            },
        );
        self.drives.insert(drive, id);
        id
    }

    fn node(&self, id: NodeId, target: &str) -> SysResult<&Node> {
        self.nodes
            .get(&id)
            .ok_or_else(|| err(SysErrorKind::NotFound, target))
    }

    fn inode(&self, ino: NodeId, target: &str) -> SysResult<&Inode> {
        self.inodes
            .get(&ino)
            .ok_or_else(|| err(SysErrorKind::NotFound, target))
    }

    fn tag_allowed(&self, ino: NodeId) -> bool {
        self.inodes
            .get(&ino)
            .is_none_or(|i| i.tag.is_none_or(tag::is_allowed_data_tag))
    }

    fn dir(&self, id: NodeId, target: &str) -> SysResult<&DirData> {
        match &self.node(id, target)?.body {
            Body::Dir(d) => Ok(d),
            _ => Err(err(SysErrorKind::InvalidPath, target)),
        }
    }

    fn dir_mut(&mut self, id: NodeId, target: &str) -> SysResult<&mut DirData> {
        match self.nodes.get_mut(&id).map(|n| &mut n.body) {
            Some(Body::Dir(d)) => Ok(d),
            Some(_) => Err(err(SysErrorKind::InvalidPath, target)),
            None => Err(err(SysErrorKind::NotFound, target)),
        }
    }

    fn lookup(&self, dir: NodeId, name: &str, target: &str) -> SysResult<Option<NodeId>> {
        let d = self.dir(dir, target)?;
        Ok(d.children.get(&d.key(name)).copied())
    }

    fn kind(&self, id: NodeId) -> EntryKind {
        match self.nodes.get(&id).map(|n| &n.body) {
            Some(Body::Dir(d)) if d.plain() => EntryKind::Dir,
            Some(Body::File(ino)) if self.tag_allowed(*ino) => EntryKind::File,
            _ => EntryKind::Reparse,
        }
    }

    /// A volume mounted in a folder, seen from above: below a root it is a name surrogate
    /// (`IO_REPARSE_TAG_MOUNT_POINT`), like on Windows.
    fn is_mount(&self, id: NodeId) -> bool {
        self.nodes
            .get(&id)
            .is_some_and(|n| n.parent.is_some() && matches!(&n.body, Body::Dir(d) if d.volume_root))
    }

    /// Kind as seen by relative operations (a mounted volume is a reparse point).
    fn rel_kind(&self, id: NodeId) -> EntryKind {
        if self.is_mount(id) {
            EntryKind::Reparse
        } else {
            self.kind(id)
        }
    }

    /// The current user cannot open the entry at all (see [`FakeFs::set_restricted`]).
    fn is_restricted(&self, id: NodeId) -> bool {
        match self.nodes.get(&id).map(|n| &n.body) {
            Some(Body::Dir(d)) => d.restricted,
            Some(Body::File(ino)) => self.inodes.get(ino).is_some_and(|i| i.restricted),
            Some(Body::Link(l)) => l.restricted,
            None => false,
        }
    }

    /// `AccessDenied` for a restricted entry: every open of it fails, like on Windows.
    /// `Busy` for an entry in delete-pending state (ADR 0017, A6).
    fn openable(&self, id: NodeId, target: &str) -> SysResult<()> {
        if self.is_restricted(id) {
            return Err(err(SysErrorKind::AccessDenied, target));
        }
        self.not_pending(id, target)
    }

    /// `Busy` if the entry is in legacy delete-pending state (A6).
    fn not_pending(&self, id: NodeId, target: &str) -> SysResult<()> {
        let pending = self
            .opens
            .values()
            .any(|o| o.kind == RecKind::Pending && o.obj.node() == id);
        if pending {
            return Err(err(SysErrorKind::Busy, target));
        }
        Ok(())
    }

    /// `Busy` if the inode is mapped as an image (`STATUS_CANNOT_DELETE` for a delete, a
    /// sharing violation for an open for write).
    fn not_mapped(&self, obj: Obj, target: &str) -> SysResult<()> {
        let mapped = self
            .opens
            .values()
            .any(|o| o.kind == RecKind::Image && o.obj.same(obj));
        if mapped {
            return Err(err(SysErrorKind::Busy, target));
        }
        Ok(())
    }

    /// Metadata of an entry. A restricted entry is described the way `sys::win` describes it
    /// from the directory listing: link count and link target unknown.
    fn meta(&self, id: NodeId, target: &str) -> SysResult<Metadata> {
        let mut m = self.full_meta(id, target)?;
        if self.is_restricted(id) {
            m.restricted = true;
            m.links = None;
            if let Some(r) = m.reparse.as_mut() {
                r.target = None;
            }
        }
        Ok(m)
    }

    fn full_meta(&self, id: NodeId, target: &str) -> SysResult<Metadata> {
        Ok(match &self.node(id, target)?.body {
            Body::Dir(d) => Metadata {
                kind: self.rel_kind(id),
                len: 0,
                attrs: d.attrs,
                links: Some(1),
                file_id: u128::from(id),
                reparse: if self.is_mount(id) {
                    Some(ReparseInfo {
                        tag: tag::MOUNT_POINT,
                        surrogate: true,
                        target: None,
                    })
                } else {
                    d.tag.map(|t| ReparseInfo {
                        tag: t,
                        surrogate: tag::is_surrogate(t),
                        target: None,
                    })
                },
                restricted: false,
            },
            Body::File(ino) => {
                let i = self.inode(*ino, target)?;
                let kind = self.kind(id);
                Metadata {
                    kind,
                    len: if kind == EntryKind::File {
                        i.data.len() as u64
                    } else {
                        0
                    },
                    attrs: i.attrs,
                    links: Some(i.links),
                    file_id: u128::from(*ino),
                    reparse: i.tag.map(|t| ReparseInfo {
                        tag: t,
                        surrogate: tag::is_surrogate(t),
                        target: None,
                    }),
                    restricted: false,
                }
            }
            Body::Link(l) => Metadata {
                kind: EntryKind::Reparse,
                len: 0,
                attrs: l.attrs,
                links: Some(1),
                file_id: u128::from(id),
                reparse: Some(ReparseInfo {
                    tag: l.tag,
                    surrogate: tag::is_surrogate(l.tag),
                    target: Some(l.target.clone()),
                }),
                restricted: false,
            },
        })
    }

    /// One component of a relative walk: only plain directories are traversed.
    fn traverse(&self, cur: NodeId, name: &str, target: &str) -> SysResult<NodeId> {
        let child = self
            .lookup(cur, name, target)?
            .ok_or_else(|| err(SysErrorKind::NotFound, target))?;
        self.openable(child, target)?;
        match &self.node(child, target)?.body {
            Body::Dir(d) if d.plain() && !d.volume_root => Ok(child),
            Body::Dir(_) => Err(err(SysErrorKind::ReparsePoint, target)),
            Body::File(ino) if self.tag_allowed(*ino) => {
                Err(err(SysErrorKind::InvalidPath, target))
            }
            Body::File(_) | Body::Link(_) => Err(err(SysErrorKind::ReparsePoint, target)),
        }
    }

    fn insert(
        &mut self,
        parent: NodeId,
        name: &str,
        body: Body,
        target: &str,
    ) -> SysResult<NodeId> {
        let key = self.dir(parent, target)?.key(name);
        self.insert_keyed(parent, key, name, body, target)
    }

    /// [`Self::insert`] under an explicit child key (a raw UTF-16 name that the listing shows
    /// with U+FFFD, [`FakeFs::put_utf16_file`]).
    fn insert_keyed(
        &mut self,
        parent: NodeId,
        key: String,
        name: &str,
        body: Body,
        target: &str,
    ) -> SysResult<NodeId> {
        if self.dir(parent, target)?.children.contains_key(&key) {
            return Err(err(SysErrorKind::AlreadyExists, target));
        }
        let id = self.alloc();
        self.nodes.insert(
            id,
            Node {
                parent: Some(parent),
                name: name.to_owned(),
                body,
            },
        );
        self.dir_mut(parent, target)?.children.insert(key, id);
        Ok(id)
    }

    fn new_file(
        &mut self,
        parent: NodeId,
        name: &str,
        data: &[u8],
        target: &str,
    ) -> SysResult<NodeId> {
        if self.lookup(parent, name, target)?.is_some() {
            return Err(err(SysErrorKind::AlreadyExists, target));
        }
        let ino = self.alloc();
        self.inodes.insert(
            ino,
            Inode {
                data: data.to_vec(),
                durable: data.to_vec(),
                attrs: Attrs::default(),
                tag: None,
                links: 1,
                restricted: false,
            },
        );
        self.insert(parent, name, Body::File(ino), target)
    }

    fn detach(&mut self, id: NodeId) {
        let Some((Some(parent), name)) = self.nodes.get(&id).map(|n| (n.parent, n.name.clone()))
        else {
            return;
        };
        if let Some(Node {
            body: Body::Dir(d), ..
        }) = self.nodes.get_mut(&parent)
        {
            let key = d.key(&name);
            if d.children.get(&key) == Some(&id) {
                d.children.remove(&key);
            } else {
                // A raw UTF-16 name lives under its own key (`put_utf16_file`).
                d.children.retain(|_, child| *child != id);
            }
        }
    }

    /// Moves `id` to `parent\name`. Never overwrites another entry.
    fn move_node(&mut self, id: NodeId, parent: NodeId, name: &str, target: &str) -> SysResult<()> {
        let key = self.dir(parent, target)?.key(name);
        match self.dir(parent, target)?.children.get(&key) {
            Some(&other) if other != id => return Err(err(SysErrorKind::AlreadyExists, target)),
            _ => {}
        }
        self.detach(id);
        self.dir_mut(parent, target)?.children.insert(key, id);
        if let Some(node) = self.nodes.get_mut(&id) {
            node.parent = Some(parent);
            node.name = name.to_owned();
        }
        Ok(())
    }

    /// Removes a directory entry; the content goes when its last link goes.
    fn unlink(&mut self, id: NodeId) {
        self.detach(id);
        if let Some(Node {
            body: Body::File(ino),
            ..
        }) = self.nodes.remove(&id)
            && let Some(i) = self.inodes.get_mut(&ino)
        {
            i.links = i.links.saturating_sub(1);
            self.drop_orphan(ino);
        }
    }

    /// Frees an inode without links once no handle holds it open.
    fn drop_orphan(&mut self, ino: NodeId) {
        let open = self
            .opens
            .values()
            .any(|o| matches!(o.obj, Obj::File { ino: i, .. } if i == ino));
        if !open && self.inodes.get(&ino).is_some_and(|i| i.links == 0) {
            self.inodes.remove(&ino);
        }
    }

    // ---------- Share model ----------

    fn obj_of(&self, id: NodeId) -> Obj {
        match self.nodes.get(&id).map(|n| &n.body) {
            Some(Body::File(ino)) => Obj::File {
                node: id,
                ino: *ino,
            },
            _ => Obj::Node(id),
        }
    }

    /// `Busy` if an open of `obj` with `access` and `share` conflicts with an open handle, or
    /// asks for write on a mapped image.
    fn check_share(&self, obj: Obj, access: Access, share: Share, target: &str) -> SysResult<()> {
        let conflict = self.opens.values().any(|o| {
            o.kind != RecKind::Image
                && o.obj.same(obj)
                && share_conflict(access, share, o.access, o.share)
        });
        if conflict {
            return Err(err(SysErrorKind::Busy, target));
        }
        if access.write {
            self.not_mapped(obj, target)?;
        }
        Ok(())
    }

    fn register(
        &mut self,
        obj: Obj,
        access: Access,
        share: Share,
        pid: u32,
        origin: Origin,
    ) -> OpenId {
        self.register_kind(obj, RecKind::Handle, access, share, pid, origin)
    }

    fn register_kind(
        &mut self,
        obj: Obj,
        kind: RecKind,
        access: Access,
        share: Share,
        pid: u32,
        origin: Origin,
    ) -> OpenId {
        self.next_open += 1;
        self.opens.insert(
            self.next_open,
            OpenRec {
                obj,
                kind,
                access,
                share,
                pid,
                origin,
                delete_on_close: kind == RecKind::Pending,
            },
        );
        self.next_open
    }

    /// Closes a handle (applied from the close queue, see [`FakeFs::lock`]). A POSIX delete
    /// set on it removes its name now: the entry it was opened through (followed across
    /// renames), a directory only if it is still empty.
    /// While the process is crashed, its own handles stay open until [`FakeFs::restart`]
    /// (a dropped Rust value does not close a handle of a dead process early).
    fn close(&mut self, id: OpenId) {
        if self.faults.crashed
            && self
                .opens
                .get(&id)
                .is_some_and(|o| o.origin == Origin::Rerun)
        {
            return;
        }
        let Some(rec) = self.opens.remove(&id) else {
            return;
        };
        if rec.delete_on_close {
            let node = rec.obj.node();
            let still = match (rec.obj, self.nodes.get(&node)) {
                (_, Some(Node { parent: None, .. }) | None) => false,
                (Obj::File { ino, .. }, Some(n)) => matches!(n.body, Body::File(i) if i == ino),
                (Obj::Node(_), Some(n)) => match &n.body {
                    Body::Dir(d) => d.children.is_empty(),
                    Body::Link(_) => true,
                    Body::File(_) => false,
                },
            };
            if still {
                let drive = self.path_of(node, "").ok().map(|(d, _)| d);
                if rec.origin == Origin::Rerun {
                    self.log_unlink(node);
                }
                self.unlink(node);
                if rec.origin == Origin::Fixture
                    && let Some(d) = drive
                {
                    self.fixture_flushed(d);
                }
            }
        }
        if let Obj::File { ino, .. } = rec.obj {
            self.drop_orphan(ino);
        }
    }

    /// A recorded handle (of any kind) is open on an entry strictly below `anc`: Windows
    /// refuses to rename `anc` (`ACCESS_DENIED`, observed, ADR 0017 A5).
    /// An image or data section without a handle does not count (observed 2026-11-05: the
    /// ancestor renames; pinned by W19 and W24).
    fn open_below(&self, anc: NodeId) -> bool {
        self.opens.values().any(|o| {
            let n = o.obj.node();
            !matches!(o.kind, RecKind::Image | RecKind::DataMap)
                && n != anc
                && self.nodes.contains_key(&n)
                && self.is_ancestor_or_self(anc, n)
        })
    }

    /// Process IDs of the handles and image sections on the inode `ino`, without `except`;
    /// sorted, unique.
    fn users_of(&self, ino: NodeId, except: Option<OpenId>) -> Vec<u32> {
        let mut pids: Vec<u32> = self
            .opens
            .iter()
            .filter(|(id, o)| {
                Some(**id) != except && matches!(o.obj, Obj::File { ino: i, .. } if i == ino)
            })
            .map(|(_, o)| o.pid)
            .collect();
        pids.sort_unstable();
        pids.dedup();
        pids
    }

    /// Enters a call of Rerun: fails after a crash; counts it, records it, and applies an
    /// armed fault. `Ok(true)`: crash after the call acts.
    /// A call made from inside a step hook (the hook plays another program or the test) is
    /// neither counted, recorded nor faulted; it still fails after a crash.
    fn enter(&mut self, call: Prim) -> SysResult<bool> {
        let f = &mut self.faults;
        if f.crashed {
            return Err(crashed_err());
        }
        if IN_HOOK.with(Cell::get) {
            return Ok(false);
        }
        let n = match f.seen.iter_mut().find(|(c, _)| *c == call) {
            Some((_, n)) => {
                *n += 1;
                *n
            }
            None => {
                f.seen.push((call, 1));
                1
            }
        };
        if f.record {
            f.calls.push(call);
        }
        let Some(pos) = f.armed.iter().position(|(c, k, _)| *c == call && *k == n) else {
            return Ok(false);
        };
        let (_, _, fault) = f.armed.remove(pos);
        f.fired = true;
        match fault {
            Fault::Fail(kind) => Err(err(kind, &format!("fake: injected fault at {call:?} #{n}"))),
            Fault::CrashAfter => Ok(true),
        }
    }

    /// A read-side call: like [`Self::enter`]; a crash happens before it acts.
    fn enter_read(&mut self, op: FsOp) -> SysResult<()> {
        if self.enter(Prim::ReadSide(op))? {
            self.faults.crashed = true;
            return Err(crashed_err());
        }
        Ok(())
    }

    /// `Other` for a handle closed by a restart (stale).
    fn alive(&self, id: OpenId) -> SysResult<()> {
        if self.opens.contains_key(&id) {
            Ok(())
        } else {
            Err(err(SysErrorKind::Other, "fake: handle closed by a restart"))
        }
    }

    /// Identity of the directory `node` ([`Dir::info`]).
    fn root_info(&self, node: NodeId, target: &str) -> SysResult<RootInfo> {
        let d = self.dir(node, target)?;
        let (drive, _) = self.path_of(node, target)?;
        let fs_kind = self.fs_kinds.get(&drive).copied().unwrap_or(FsKind::Ntfs);
        let (vol, vol_segs) = self.volume_of(node, target)?;
        let serial = if self.drives.get(&drive) == Some(&vol) {
            volume_serial(drive)
        } else {
            mounted_serial(vol)
        };
        Ok(RootInfo {
            final_path: self.final_path(node, target)?,
            volume_serial: serial,
            file_id: u128::from(node),
            user_writable: d.user_writable,
            case_sensitive: d.case_sensitive,
            volume_path: vol_segs.join("\\"),
            fs_kind,
            supports_posix_rename: matches!(fs_kind, FsKind::Ntfs | FsKind::Refs),
        })
    }

    /// A rename by another program (`MoveFileExW`): the source is opened for delete, the
    /// target directory for write (both share-checked, `Busy`), and a directory with a handle
    /// open below it is not renamed (`AccessDenied`). Never overwrites.
    fn checked_move(
        &mut self,
        src: NodeId,
        parent: NodeId,
        name: &str,
        target: &str,
    ) -> SysResult<()> {
        self.check_share(self.obj_of(src), Access::DELETE, Share::RWD, target)?;
        self.check_share(Obj::Node(parent), Access::WRITE, Share::RWD, target)?;
        if self.open_below(src) {
            return Err(err(SysErrorKind::AccessDenied, target));
        }
        self.move_node(src, parent, name, target)
    }

    /// Drive and segments of a node, computed from the parent chain.
    fn path_of(&self, id: NodeId, target: &str) -> SysResult<(char, Vec<String>)> {
        let mut segs = Vec::new();
        let mut cur = self.node(id, target)?;
        while let Some(parent) = cur.parent {
            segs.push(cur.name.clone());
            cur = self.node(parent, target)?;
        }
        segs.reverse();
        let drive = cur
            .name
            .chars()
            .next()
            .ok_or_else(|| err(SysErrorKind::Other, target))?;
        Ok((drive, segs))
    }

    /// Nearest volume root at or above `id` and the path of `id` below it (segments).
    fn volume_of(&self, id: NodeId, target: &str) -> SysResult<(NodeId, Vec<String>)> {
        let mut segs = Vec::new();
        let mut cur_id = id;
        loop {
            let cur = self.node(cur_id, target)?;
            if matches!(&cur.body, Body::Dir(d) if d.volume_root) {
                segs.reverse();
                return Ok((cur_id, segs));
            }
            let Some(parent) = cur.parent else {
                return Err(err(SysErrorKind::Other, target));
            };
            segs.push(cur.name.clone());
            cur_id = parent;
        }
    }

    fn final_path(&self, id: NodeId, target: &str) -> SysResult<PathBuf> {
        let (drive, segs) = self.path_of(id, target)?;
        Ok(PathBuf::from(format!(r"\\?\{drive}:\{}", segs.join("\\"))))
    }

    fn is_ancestor_or_self(&self, anc: NodeId, mut id: NodeId) -> bool {
        loop {
            if id == anc {
                return true;
            }
            match self.nodes.get(&id).and_then(|n| n.parent) {
                Some(p) => id = p,
                None => return false,
            }
        }
    }

    /// Absolute target of a link (absolute, drive-relative or relative to the link's parent).
    fn link_target(&self, link: NodeId, t: &str, target: &str) -> SysResult<(char, Vec<String>)> {
        let t = t.replace('/', "\\");
        let stripped = t
            .strip_prefix(r"\\?\")
            .or_else(|| t.strip_prefix(r"\??\"))
            .unwrap_or(&t);
        let b = stripped.as_bytes();
        if b.len() >= 2 && b[0].is_ascii_alphabetic() && b[1] == b':' {
            return parse_abs_str(stripped, target);
        }
        let parent = self
            .node(link, target)?
            .parent
            .ok_or_else(|| err(SysErrorKind::InvalidPath, target))?;
        let (drive, mut segs) = self.path_of(parent, target)?;
        if stripped.starts_with('\\') {
            segs.clear();
        }
        for seg in stripped.split('\\') {
            match seg {
                "" | "." => {}
                ".." => {
                    segs.pop();
                }
                s => segs.push(s.to_owned()),
            }
        }
        Ok((drive, segs))
    }

    /// Absolute walk that follows links (only for `Fs::open_dir`).
    fn resolve_follow(
        &mut self,
        drive: char,
        segs: &[String],
        depth: u32,
        target: &str,
    ) -> SysResult<NodeId> {
        if depth > MAX_FOLLOW {
            return Err(err(SysErrorKind::Other, target));
        }
        let mut cur = self.drive_root(drive);
        for seg in segs {
            let child = self
                .lookup(cur, seg, target)?
                .ok_or_else(|| err(SysErrorKind::NotFound, target))?;
            self.openable(child, target)?;
            cur = match &self.node(child, target)?.body {
                Body::Dir(d) if d.plain() => child,
                Body::Dir(_) => return Err(err(SysErrorKind::ReparsePoint, target)),
                Body::File(ino) if self.tag_allowed(*ino) => {
                    return Err(err(SysErrorKind::InvalidPath, target));
                }
                Body::File(_) => return Err(err(SysErrorKind::ReparsePoint, target)),
                Body::Link(l) => {
                    let t = l.target.clone();
                    let (d2, s2) = self.link_target(child, &t, target)?;
                    self.resolve_follow(d2, &s2, depth + 1, target)?
                }
            };
        }
        Ok(cur)
    }

    /// Absolute walk without following links (setup helpers). `Ok(None)` = missing.
    fn lookup_abs(
        &mut self,
        drive: char,
        segs: &[String],
        target: &str,
    ) -> SysResult<Option<NodeId>> {
        let mut cur = self.drive_root(drive);
        for (i, seg) in segs.iter().enumerate() {
            let Some(child) = self.lookup(cur, seg, target)? else {
                return Ok(None);
            };
            if i + 1 == segs.len() {
                return Ok(Some(child));
            }
            match self.kind(child) {
                EntryKind::Dir => cur = child,
                EntryKind::Reparse => return Err(err(SysErrorKind::ReparsePoint, target)),
                EntryKind::File => return Ok(None),
            }
        }
        Ok(Some(cur))
    }

    /// Creates missing directories (setup helpers).
    fn mkdir_all(&mut self, drive: char, segs: &[String], target: &str) -> SysResult<NodeId> {
        let mut cur = self.drive_root(drive);
        for seg in segs {
            cur = match self.lookup(cur, seg, target)? {
                Some(child) => match self.kind(child) {
                    EntryKind::Dir => child,
                    EntryKind::Reparse => return Err(err(SysErrorKind::ReparsePoint, target)),
                    EntryKind::File => return Err(err(SysErrorKind::AlreadyExists, target)),
                },
                None => {
                    let uw = self.dir(cur, target)?.user_writable;
                    self.insert(cur, seg, Body::Dir(DirData::new(uw)), target)?
                }
            };
        }
        Ok(cur)
    }

    fn require_abs(&mut self, p: &Path) -> SysResult<NodeId> {
        let shown = p.display().to_string();
        let (drive, segs) = parse_abs(p)?;
        self.lookup_abs(drive, &segs, &shown)?
            .ok_or_else(|| err(SysErrorKind::NotFound, &shown))
    }
}

#[derive(Default)]
struct Shared {
    state: Mutex<State>,
    /// Handles closed by a drop, applied at the next [`FakeFs::lock`].
    closed: Mutex<Vec<OpenId>>,
    hook: Mutex<Option<StepHook>>,
    /// Bytes served by every reader `open_read` handed out ([`FakeFs::bytes_served`]).
    served: Arc<AtomicU64>,
}

/// A recorded open handle; dropping it closes the handle. The drop only queues the close (it
/// may happen while the state is locked); the next [`FakeFs::lock`] applies it.
struct OpenToken {
    shared: Arc<Shared>,
    id: OpenId,
}

impl fmt::Debug for OpenToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<open {}>", self.id)
    }
}

impl Drop for OpenToken {
    fn drop(&mut self) {
        self.shared
            .closed
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(self.id);
    }
}

/// A handle held by a fixture ([`FakeFs::hold_open_as`]); dropping it closes the handle.
#[derive(Debug)]
pub struct FakeHold {
    _open: OpenToken,
}

/// A reader over a copy of a file that counts the bytes it serves into its [`FakeFs`]. It
/// holds its handle open (read, shares read) until it drops.
struct Counted {
    data: Cursor<Vec<u8>>,
    served: Arc<AtomicU64>,
    _open: OpenToken,
}

impl Read for Counted {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.data.read(buf)?;
        self.served
            .fetch_add(u64::try_from(n).unwrap_or(u64::MAX), Ordering::SeqCst);
        Ok(n)
    }
}

impl Seek for Counted {
    fn seek(&mut self, to: SeekFrom) -> std::io::Result<u64> {
        self.data.seek(to)
    }
}

/// Marks the log of a volume durable when dropped (see [`FakeFs::fixture_scope`]); declared
/// before any state lock of the helper, so it drops after it.
struct FixtureFlush<'a>(&'a FakeFs, Option<char>);

impl Drop for FixtureFlush<'_> {
    fn drop(&mut self) {
        if let Some(drive) = self.1 {
            self.0.lock().fixture_flushed(drive);
        }
    }
}

/// In-memory file system. Cheap to clone; clones share the same state.
#[derive(Clone, Default)]
pub struct FakeFs {
    shared: Arc<Shared>,
}

impl fmt::Debug for FakeFs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let st = self.lock();
        f.debug_struct("FakeFs")
            .field("nodes", &st.nodes.len())
            .field("inodes", &st.inodes.len())
            .finish_non_exhaustive()
    }
}

impl FakeFs {
    /// The state, after applying the closes that drops have queued since the last call.
    fn lock(&self) -> MutexGuard<'_, State> {
        let mut st = self
            .shared
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let closed = std::mem::take(
            &mut *self
                .shared
                .closed
                .lock()
                .unwrap_or_else(PoisonError::into_inner),
        );
        for id in closed {
            st.close(id);
        }
        st
    }

    fn token(&self, id: OpenId) -> OpenToken {
        OpenToken {
            shared: Arc::clone(&self.shared),
            id,
        }
    }

    fn hook_slot(&self) -> MutexGuard<'_, Option<StepHook>> {
        self.shared
            .hook
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Runs the hook for a step of a read-side walk.
    fn fire(&self, op: FsOp, index: usize, name: &str) {
        self.fire_event(op, index, name, None);
    }

    /// Runs the hook before a primitive call of the write side.
    fn fire_call(&self, call: Prim, name: &str) {
        self.fire_event(FsOp::Write, 0, name, Some(call));
    }

    /// Runs the hook without holding the state lock. The hook is taken out while it runs, so
    /// operations it performs do not trigger it again.
    fn fire_event(&self, op: FsOp, index: usize, name: &str, call: Option<Prim>) {
        let hook = self.hook_slot().take();
        if let Some(mut hook) = hook {
            IN_HOOK.with(|h| h.set(true));
            hook(
                self,
                &StepEvent {
                    op,
                    index,
                    name: name.to_owned(),
                    call,
                },
            );
            IN_HOOK.with(|h| h.set(false));
            let mut slot = self.hook_slot();
            if slot.is_none() {
                *slot = Some(hook);
            }
        }
    }

    /// Bytes served so far by every reader that `open_read` (and `read`) handed out, for
    /// tests that bound how much a caller reads.
    pub fn bytes_served(&self) -> u64 {
        self.shared.served.load(Ordering::SeqCst)
    }

    /// Installs a test hook that runs before each component of a relative operation is looked
    /// up and before each primitive call of the write side ([`StepEvent`]). Replaces an
    /// earlier hook.
    pub fn on_step(&self, hook: impl FnMut(&FakeFs, &StepEvent) + Send + 'static) {
        *self.hook_slot() = Some(Box::new(hook));
    }

    /// Removes the test hook (not from inside the hook itself).
    pub fn clear_on_step(&self) {
        *self.hook_slot() = None;
    }

    // ---------- Faults and crashes (ADR 0019 amendment) ----------

    /// Arms `fault` for the `nth` (1-based) call of `call` counted from the last
    /// [`Self::clear_faults`] or [`Self::restart`]. Fixture and attacker helpers are never
    /// counted or faulted.
    pub fn fault(&self, call: Prim, nth: usize, fault: Fault) {
        self.lock().faults.armed.push((call, nth, fault));
    }

    /// `fault(call, nth, Fault::Fail(kind))`.
    pub fn fail_at(&self, call: Prim, nth: usize, kind: SysErrorKind) {
        self.fault(call, nth, Fault::Fail(kind));
    }

    /// Disarms every fault and resets the call counts (not the crash flag).
    pub fn clear_faults(&self) {
        let mut st = self.lock();
        st.faults.armed.clear();
        st.faults.seen.clear();
        st.faults.fired = false;
    }

    /// An armed fault has fired since the last [`Self::clear_faults`].
    pub fn fault_fired(&self) -> bool {
        self.lock().faults.fired
    }

    /// Records every call of Rerun (primitives and read-side calls) from now on, or stops.
    pub fn record_calls(&self, on: bool) {
        self.lock().faults.record = on;
    }

    /// The calls recorded so far; clears the record.
    pub fn take_calls(&self) -> Vec<Prim> {
        std::mem::take(&mut self.lock().faults.calls)
    }

    /// The process crashed ([`Fault::CrashAfter`]) and was not restarted yet.
    pub fn crashed(&self) -> bool {
        self.lock().faults.crashed
    }

    /// Restarts after a crash (or at any time): closes every handle Rerun held, by origin,
    /// not by process ID (pending POSIX deletes on them complete, a lock is released, the old
    /// [`Dir`] handles and guards become stale), keeps the handles and image sections of
    /// other programs (fixture holds), clears the crash flag, the armed faults and the call
    /// counts.
    pub fn restart(&self) {
        let mut st = self.lock();
        st.faults.crashed = false;
        let ours: Vec<OpenId> = st
            .opens
            .iter()
            .filter(|(_, o)| o.origin == Origin::Rerun)
            .map(|(id, _)| *id)
            .collect();
        for id in ours {
            st.close(id);
        }
        st.faults.armed.clear();
        st.faults.seen.clear();
        st.faults.fired = false;
    }

    // ---------- Setup and attacker helpers (absolute, never follow links) ----------

    /// Creates a directory including missing parents.
    pub fn mkdir_all(&self, abs: &Path) -> SysResult<()> {
        let _flushed = self.fixture_scope(abs);
        let shown = abs.display().to_string();
        let (drive, segs) = parse_abs(abs)?;
        self.lock().mkdir_all(drive, &segs, &shown).map(|_| ())
    }

    /// Creates or overwrites a file including missing parents (overwrite keeps the inode,
    /// i.e. all hard links see the new content). Overwriting opens the file for write
    /// (share-checked, `Busy`).
    pub fn put_file(&self, abs: &Path, data: &[u8]) -> SysResult<()> {
        let _flushed = self.fixture_scope(abs);
        let shown = abs.display().to_string();
        let (drive, segs, name) = parse_abs_child(abs)?;
        let mut st = self.lock();
        let parent = st.mkdir_all(drive, &segs, &shown)?;
        match st.lookup(parent, &name, &shown)? {
            None => st.new_file(parent, &name, data, &shown).map(|_| ()),
            Some(id) => match st.nodes.get(&id).map(|n| &n.body) {
                Some(Body::File(ino)) => {
                    let ino = *ino;
                    st.not_pending(id, &shown)?;
                    st.check_share(st.obj_of(id), Access::WRITE, Share::RWD, &shown)?;
                    if let Some(i) = st.inodes.get_mut(&ino) {
                        i.data = data.to_vec();
                        i.durable = data.to_vec();
                    }
                    Ok(())
                }
                _ => Err(err(SysErrorKind::AlreadyExists, &shown)),
            },
        }
    }

    /// Creates a file with a raw name that need not be a valid segment (`d3d9.dll.`, `CON`),
    /// like a file created through `\\?\`. Only empty names, separators and NUL are refused.
    pub fn put_raw_file(&self, parent_abs: &Path, raw_name: &str, data: &[u8]) -> SysResult<()> {
        let _flushed = self.fixture_scope(parent_abs);
        let shown = format!("{}\\{raw_name}", parent_abs.display());
        if raw_name.is_empty() || raw_name.contains(['\\', '/', '\0']) {
            return Err(err(SysErrorKind::InvalidPath, &shown));
        }
        let (drive, segs) = parse_abs(parent_abs)?;
        let mut st = self.lock();
        let parent = st.mkdir_all(drive, &segs, &shown)?;
        st.new_file(parent, raw_name, data, &shown).map(|_| ())
    }

    /// Creates or overwrites the file whose name is the raw UTF-16 `units` in `parent_abs`,
    /// like a file created through `\\?\` with `CreateFileW`: the units may hold unpaired
    /// surrogates. The listing shows the name converted with U+FFFD, as `sys::win` does, and
    /// two names that differ only in their unpaired surrogates stay two entries; a lookup by
    /// the converted name finds neither (on Windows it names other units). Empty names,
    /// separators and NUL are refused.
    pub fn put_utf16_file(&self, parent_abs: &Path, units: &[u16], data: &[u8]) -> SysResult<()> {
        let _flushed = self.fixture_scope(parent_abs);
        let name = String::from_utf16_lossy(units);
        let shown = format!("{}\\{name:?}", parent_abs.display());
        if name.is_empty() || name.contains(['\\', '/', '\0']) {
            return Err(err(SysErrorKind::InvalidPath, &shown));
        }
        let (drive, segs) = parse_abs(parent_abs)?;
        let mut st = self.lock();
        let parent = st.mkdir_all(drive, &segs, &shown)?;
        let mut key = st.dir(parent, &shown)?.key(&name);
        if String::from_utf16(units).is_err() {
            // NUL never occurs in a name: the suffix keeps raw keys apart from every other.
            key.push('\0');
            for u in units {
                key.push_str(&format!("{u:04x}"));
            }
        }
        let existing = st.dir(parent, &shown)?.children.get(&key).copied();
        match existing {
            None => {
                let ino = st.alloc();
                st.inodes.insert(
                    ino,
                    Inode {
                        data: data.to_vec(),
                        durable: data.to_vec(),
                        attrs: Attrs::default(),
                        tag: None,
                        links: 1,
                        restricted: false,
                    },
                );
                st.insert_keyed(parent, key, &name, Body::File(ino), &shown)
                    .map(|_| ())
            }
            Some(id) => match st.nodes.get(&id).map(|n| &n.body) {
                Some(Body::File(ino)) => {
                    let ino = *ino;
                    st.check_share(st.obj_of(id), Access::WRITE, Share::RWD, &shown)?;
                    if let Some(i) = st.inodes.get_mut(&ino) {
                        i.data = data.to_vec();
                        i.durable = data.to_vec();
                    }
                    Ok(())
                }
                _ => Err(err(SysErrorKind::AlreadyExists, &shown)),
            },
        }
    }

    /// Creates a file with a reparse tag. Name-surrogate tags are refused (use
    /// [`FakeFs::put_link`]).
    pub fn put_tagged_file(&self, abs: &Path, data: &[u8], reparse_tag: u32) -> SysResult<()> {
        if tag::is_surrogate(reparse_tag) {
            return Err(SysError::path(SysErrorKind::InvalidPath, abs));
        }
        self.put_file(abs, data)?;
        let mut st = self.lock();
        let id = st.require_abs(abs)?;
        if let Some(Node {
            body: Body::File(ino),
            ..
        }) = st.nodes.get(&id)
        {
            let ino = *ino;
            if let Some(i) = st.inodes.get_mut(&ino) {
                i.tag = Some(reparse_tag);
            }
        }
        Ok(())
    }

    /// Creates a name surrogate (junction, symlink) with a target. The target need not exist.
    /// Directory and file links behave alike (see the module docs).
    pub fn put_link(&self, abs: &Path, reparse_tag: u32, target: &str) -> SysResult<()> {
        let _flushed = self.fixture_scope(abs);
        let shown = abs.display().to_string();
        if !tag::is_surrogate(reparse_tag) {
            return Err(err(SysErrorKind::InvalidPath, &shown));
        }
        let (drive, segs, name) = parse_abs_child(abs)?;
        let mut st = self.lock();
        let parent = st.mkdir_all(drive, &segs, &shown)?;
        let body = Body::Link(LinkData {
            tag: reparse_tag,
            target: target.to_owned(),
            restricted: false,
            attrs: Attrs::default(),
        });
        st.insert(parent, &name, body, &shown).map(|_| ())
    }

    /// Adds a hard link `new_abs` to the existing file `existing_abs` (same drive).
    pub fn put_hardlink(&self, existing_abs: &Path, new_abs: &Path) -> SysResult<()> {
        let _flushed = self.fixture_scope(new_abs);
        let shown = new_abs.display().to_string();
        let (drive, segs, name) = parse_abs_child(new_abs)?;
        let mut st = self.lock();
        let src = st.require_abs(existing_abs)?;
        let ino = match st.nodes.get(&src).map(|n| &n.body) {
            Some(Body::File(ino)) => *ino,
            _ => return Err(SysError::path(SysErrorKind::AccessDenied, existing_abs)),
        };
        if st.path_of(src, &shown)?.0 != drive {
            return Err(err(SysErrorKind::Unsupported, &shown));
        }
        let parent = st.mkdir_all(drive, &segs, &shown)?;
        st.insert(parent, &name, Body::File(ino), &shown)?;
        if let Some(i) = st.inodes.get_mut(&ino) {
            i.links += 1;
        }
        Ok(())
    }

    /// Sets the attributes of a file (shared by its hard links), a directory or a link itself.
    pub fn set_attrs(&self, abs: &Path, attrs: Attrs) -> SysResult<()> {
        let _flushed = self.fixture_scope(abs);
        let mut st = self.lock();
        let id = st.require_abs(abs)?;
        let ino = match st.nodes.get_mut(&id).map(|n| &mut n.body) {
            Some(Body::Dir(d)) => {
                d.attrs = attrs;
                return Ok(());
            }
            Some(Body::File(ino)) => *ino,
            Some(Body::Link(l)) => {
                l.attrs = attrs;
                return Ok(());
            }
            None => return Err(SysError::path(SysErrorKind::NotFound, abs)),
        };
        if let Some(i) = st.inodes.get_mut(&ino) {
            i.attrs = attrs;
        }
        Ok(())
    }

    /// Makes an existing, empty directory case-sensitive (or not), like
    /// `fsutil file setCaseSensitiveInfo`.
    pub fn set_case_sensitive(&self, abs: &Path, on: bool) -> SysResult<()> {
        let _flushed = self.fixture_scope(abs);
        let shown = abs.display().to_string();
        let mut st = self.lock();
        let id = st.require_abs(abs)?;
        let d = st.dir_mut(id, &shown)?;
        if !d.children.is_empty() {
            return Err(err(SysErrorKind::NotEmpty, &shown));
        }
        d.case_sensitive = on;
        Ok(())
    }

    /// Gives an existing directory a non-surrogate reparse tag (e.g. [`tag::CLOUD`] for a
    /// OneDrive folder, allowed, or [`tag::PROJFS`], rejected).
    pub fn set_dir_tag(&self, abs: &Path, reparse_tag: u32) -> SysResult<()> {
        let _flushed = self.fixture_scope(abs);
        let shown = abs.display().to_string();
        if tag::is_surrogate(reparse_tag) {
            return Err(err(SysErrorKind::InvalidPath, &shown));
        }
        let mut st = self.lock();
        let id = st.require_abs(abs)?;
        st.dir_mut(id, &shown)?.tag = Some(reparse_tag);
        Ok(())
    }

    /// Sets the file system reported for a drive (default NTFS).
    pub fn set_fs_kind(&self, drive: char, kind: FsKind) {
        self.lock()
            .fs_kinds
            .insert(drive.to_ascii_uppercase(), kind);
    }

    /// Sets whether the current user can write the directory (reported only, not enforced).
    pub fn set_user_writable(&self, abs: &Path, on: bool) -> SysResult<()> {
        let shown = abs.display().to_string();
        let mut st = self.lock();
        let id = st.require_abs(abs)?;
        st.dir_mut(id, &shown)?.user_writable = on;
        Ok(())
    }

    /// Makes an existing entry restricted (or not): its DACL denies the current user every
    /// open, even for attributes (`ElevatedDiagnostics`, `ntuser.pol`). `read_dir` and
    /// `metadata` still describe it ([`Metadata::restricted`]); every open of it and every
    /// walk through it is `AccessDenied`. For a file the flag is shared by its hard links.
    pub fn set_restricted(&self, abs: &Path, on: bool) -> SysResult<()> {
        let _flushed = self.fixture_scope(abs);
        let mut st = self.lock();
        let id = st.require_abs(abs)?;
        let ino = match st.nodes.get_mut(&id).map(|n| &mut n.body) {
            Some(Body::Dir(d)) => {
                d.restricted = on;
                return Ok(());
            }
            Some(Body::Link(l)) => {
                l.restricted = on;
                return Ok(());
            }
            Some(Body::File(ino)) => *ino,
            None => return Err(SysError::path(SysErrorKind::NotFound, abs)),
        };
        if let Some(i) = st.inodes.get_mut(&ino) {
            i.restricted = on;
        }
        Ok(())
    }

    /// Marks an existing directory as the root of a volume mounted in a folder. It gets its
    /// own volume serial; the file system stays that of the drive.
    pub fn set_volume_root(&self, abs: &Path) -> SysResult<()> {
        let _flushed = self.fixture_scope(abs);
        let shown = abs.display().to_string();
        let mut st = self.lock();
        let id = st.require_abs(abs)?;
        st.dir_mut(id, &shown)?.volume_root = true;
        Ok(())
    }

    /// Attacker: atomically renames the entry at `abs` to a hidden sibling name and puts a
    /// junction to `target` in its place. Returns the hidden name. The rename is checked like
    /// [`Self::rename_abs`].
    pub fn swap_with_junction(&self, abs: &Path, target: &str) -> SysResult<String> {
        let _flushed = self.fixture_scope(abs);
        let shown = abs.display().to_string();
        let mut st = self.lock();
        let id = st.require_abs(abs)?;
        let (parent, name) = match st.nodes.get(&id) {
            Some(Node {
                parent: Some(p),
                name,
                ..
            }) => (*p, name.clone()),
            _ => return Err(err(SysErrorKind::AccessDenied, &shown)),
        };
        let hidden = format!("{name}.swapped-{id}");
        st.checked_move(id, parent, &hidden, &shown)?;
        let body = Body::Link(LinkData {
            tag: tag::MOUNT_POINT,
            target: target.to_owned(),
            restricted: false,
            attrs: Attrs::default(),
        });
        st.insert(parent, &name, body, &shown)?;
        Ok(hidden)
    }

    /// Attacker: renames or moves an entry by absolute path (same drive, never overwrites),
    /// like `MoveFileExW`: checked against the share model (`Busy`) and refused for a
    /// directory with a handle open below it (`AccessDenied`), see the module docs.
    pub fn rename_abs(&self, from: &Path, to: &Path) -> SysResult<()> {
        self.rename_impl(from, to, true)
    }

    /// Renames like [`Self::rename_abs`] but ignores every share mode and the open-handle
    /// rule for ancestors. Windows cannot do this; it exists only for defence-in-depth tests
    /// (a handle's name re-check, a swap below an open handle).
    pub fn rename_ignoring_shares(&self, from: &Path, to: &Path) -> SysResult<()> {
        self.rename_impl(from, to, false)
    }

    fn rename_impl(&self, from: &Path, to: &Path, checked: bool) -> SysResult<()> {
        let _flushed = self.fixture_scope(to);
        let shown = to.display().to_string();
        let (drive, segs, name) = parse_abs_child(to)?;
        let mut st = self.lock();
        let src = st.require_abs(from)?;
        if st.path_of(src, &shown)?.0 != drive {
            return Err(err(SysErrorKind::Unsupported, &shown));
        }
        let parent = st
            .lookup_abs(drive, &segs, &shown)?
            .ok_or_else(|| err(SysErrorKind::NotFound, &shown))?;
        if st.kind(parent) != EntryKind::Dir {
            return Err(err(SysErrorKind::NotFound, &shown));
        }
        if st.is_ancestor_or_self(src, parent) {
            return Err(err(SysErrorKind::InvalidPath, &shown));
        }
        if checked {
            st.checked_move(src, parent, &name, &shown)
        } else {
            st.move_node(src, parent, &name, &shown)
        }
    }

    /// Attacker or setup: deletes the entry at `abs` by absolute path: a file (one hard link
    /// of it), a link itself (never its target) or an empty directory. A directory with
    /// entries is `NotEmpty`, a drive root `AccessDenied`, an entry held open without
    /// share-delete `Busy`. Handles to a deleted directory return `NotFound` afterwards.
    pub fn remove_abs(&self, abs: &Path) -> SysResult<()> {
        let _flushed = self.fixture_scope(abs);
        let shown = abs.display().to_string();
        let mut st = self.lock();
        let id = st.require_abs(abs)?;
        st.not_pending(id, &shown)?;
        st.check_share(st.obj_of(id), Access::DELETE, Share::RWD, &shown)?;
        st.not_mapped(st.obj_of(id), &shown)?;
        match st.nodes.get(&id) {
            Some(Node { parent: None, .. }) => {
                return Err(SysError::path(SysErrorKind::AccessDenied, abs));
            }
            Some(Node {
                body: Body::Dir(d), ..
            }) if !d.children.is_empty() => {
                return Err(SysError::path(SysErrorKind::NotEmpty, abs));
            }
            _ => {}
        }
        st.unlink(id);
        Ok(())
    }

    /// Changes the target of an existing link.
    pub fn retarget(&self, abs: &Path, target: &str) -> SysResult<()> {
        let _flushed = self.fixture_scope(abs);
        let mut st = self.lock();
        let id = st.require_abs(abs)?;
        match st.nodes.get_mut(&id).map(|n| &mut n.body) {
            Some(Body::Link(l)) => {
                l.target = target.to_owned();
                Ok(())
            }
            _ => Err(SysError::path(SysErrorKind::InvalidPath, abs)),
        }
    }

    /// A fixture change is another program that flushed: when the returned value drops, the
    /// log of the volume of `abs` is durable up to now (power-loss model, `fs/durable.rs`).
    fn fixture_scope(&self, abs: &Path) -> FixtureFlush<'_> {
        FixtureFlush(self, parse_abs(abs).ok().map(|(d, _)| d))
    }

    /// Fixture: opens the existing file or directory `abs` itself (not a link) as process
    /// `pid` with `access` and `share`, share-checked like every open (`Busy`), and keeps it
    /// open until the returned [`FakeHold`] drops. `FsFixture::hold_open` uses the ID of this
    /// process, like a handle of the test itself on Windows.
    pub fn hold_open_as(
        &self,
        pid: u32,
        abs: &Path,
        access: Access,
        share: Share,
    ) -> SysResult<FakeHold> {
        let shown = abs.display().to_string();
        let id = {
            let mut st = self.lock();
            let node = st.require_abs(abs)?;
            if matches!(st.nodes.get(&node).map(|n| &n.body), Some(Body::Link(_))) {
                return Err(err(SysErrorKind::ReparsePoint, &shown));
            }
            let obj = st.obj_of(node);
            st.check_share(obj, access, share, &shown)?;
            st.register(obj, access, share, pid, Origin::Fixture)
        };
        Ok(FakeHold {
            _open: self.token(id),
        })
    }

    /// Fixture: maps the existing file `abs` as an image section of process `pid` (a running
    /// exe or a loaded DLL without an open handle) until the returned [`FakeHold`] drops.
    /// `users` reports it; renames of the file and of a folder above it work, a delete (also
    /// the POSIX delete of step 8) and an open for write are `Busy` (ADR 0017, observed). A
    /// restart keeps it; a power loss drops it.
    pub fn map_image_as(&self, pid: u32, abs: &Path) -> SysResult<FakeHold> {
        let shown = abs.display().to_string();
        let id = {
            let mut st = self.lock();
            let node = st.require_abs(abs)?;
            let obj = st.obj_of(node);
            if !matches!(obj, Obj::File { .. }) {
                return Err(err(SysErrorKind::AccessDenied, &shown));
            }
            st.register_kind(
                obj,
                RecKind::Image,
                Access::ATTRS,
                Share::RWD,
                pid,
                Origin::Fixture,
            )
        };
        Ok(FakeHold {
            _open: self.token(id),
        })
    }

    /// Fixture: maps the existing file `abs` read-write as a data section of process `pid`
    /// (a writable view, no handle) until the returned [`FakeHold`] drops: `users` reports
    /// it, an open with data access that does not share write is `Busy`, renames and deletes
    /// work, an ancestor renames (observed on Windows 11 build 26300, ADR 0017).
    pub fn map_data_as(&self, pid: u32, abs: &Path) -> SysResult<FakeHold> {
        let shown = abs.display().to_string();
        let id = {
            let mut st = self.lock();
            let node = st.require_abs(abs)?;
            let obj = st.obj_of(node);
            if !matches!(obj, Obj::File { .. }) {
                return Err(err(SysErrorKind::AccessDenied, &shown));
            }
            st.register_kind(
                obj,
                RecKind::DataMap,
                Access::WRITE,
                Share::RWD,
                pid,
                Origin::Fixture,
            )
        };
        Ok(FakeHold {
            _open: self.token(id),
        })
    }

    /// Fixture: puts the existing file `abs` in legacy delete-pending state (a delete while
    /// another handle is open) until the returned [`FakeHold`] (that handle) drops; then the
    /// name goes. Meanwhile every open of it is `Busy` and listings skip it (ADR 0017, A6).
    pub fn delete_pending(&self, abs: &Path) -> SysResult<FakeHold> {
        let shown = abs.display().to_string();
        let id = {
            let mut st = self.lock();
            let node = st.require_abs(abs)?;
            let obj = st.obj_of(node);
            if !matches!(obj, Obj::File { .. }) {
                return Err(err(SysErrorKind::AccessDenied, &shown));
            }
            st.check_share(obj, Access::DELETE, Share::RWD, &shown)?;
            st.register_kind(
                obj,
                RecKind::Pending,
                Access::ATTRS,
                Share::RWD,
                std::process::id(),
                Origin::Fixture,
            )
        };
        Ok(FakeHold {
            _open: self.token(id),
        })
    }

    /// Target of a link (only for checks in tests; `Dir` never follows links).
    pub fn reparse_target(&self, abs: &Path) -> SysResult<Option<String>> {
        let mut st = self.lock();
        let id = st.require_abs(abs)?;
        Ok(match st.nodes.get(&id).map(|n| &n.body) {
            Some(Body::Link(l)) => Some(l.target.clone()),
            _ => None,
        })
    }
}

impl FakeFs {
    /// The absolute open behind both [`Fs`] methods.
    fn open_abs(&self, abs: &Path) -> SysResult<FakeDir> {
        let shown = abs.display().to_string();
        let (drive, segs) = parse_abs(abs)?;
        self.lock().enter_read(FsOp::OpenDir)?;
        // A test can change the tree before the path is resolved (`FsOp::OpenAbs`).
        self.fire(FsOp::OpenAbs, 0, &shown);
        let node = self.lock().resolve_follow(drive, &segs, 0, &shown)?;
        self.dir_handle(node, &shown)
    }

    /// Opens a [`Dir`] handle on `node`: list access, shares read, write and delete,
    /// share-checked (`Busy`) and recorded until the handle drops.
    fn dir_handle(&self, node: NodeId, target: &str) -> SysResult<FakeDir> {
        let id = {
            let mut st = self.lock();
            st.dir(node, target)?;
            st.check_share(Obj::Node(node), Access::READ, Share::RWD, target)?;
            st.register(
                Obj::Node(node),
                Access::READ,
                Share::RWD,
                std::process::id(),
                Origin::Rerun,
            )
        };
        Ok(FakeDir {
            fs: self.clone(),
            node,
            _open: self.token(id),
        })
    }
}

impl Fs for FakeFs {
    fn open_dir(&self, abs: &Path) -> SysResult<Box<dyn Dir + '_>> {
        Ok(Box::new(self.open_abs(abs)?))
    }

    fn open_dir_write(&self, abs: &Path, _: &WriteCap) -> SysResult<Box<dyn DirWrite + '_>> {
        Ok(Box::new(self.open_abs(abs)?))
    }
}

/// Handle to a directory of a [`FakeFs`]: a node ID, valid across renames.
#[derive(Debug)]
pub struct FakeDir {
    fs: FakeFs,
    node: NodeId,
    _open: OpenToken,
}

impl FakeDir {
    fn handle_target(&self) -> String {
        format!("<handle {}>", self.node)
    }

    /// Enters a read-side call on this handle: crash, fault, stale handle.
    fn check(&self, op: FsOp) -> SysResult<()> {
        let mut st = self.fs.lock();
        st.enter_read(op)?;
        st.alive(self._open.id)
    }

    /// Walks `segs` from this handle, firing the hook before each component.
    fn walk(&self, op: FsOp, segs: &[&str], target: &str) -> SysResult<NodeId> {
        let mut cur = self.node;
        self.fs.lock().dir(cur, target)?;
        for (i, seg) in segs.iter().enumerate() {
            self.fs.fire(op, i, seg);
            cur = self.fs.lock().traverse(cur, seg, target)?;
        }
        Ok(cur)
    }

    /// Walks to the parent of `p`; returns the parent node and the last name.
    fn split<'p>(&self, op: FsOp, p: &'p RelPath) -> SysResult<(NodeId, &'p str)> {
        let segs: Vec<&'p str> = p.segments().collect();
        let Some((last, parents)) = segs.split_last() else {
            return Err(err(SysErrorKind::InvalidPath, p.as_str()));
        };
        let parent = self.walk(op, parents, p.as_str())?;
        self.fs.fire(op, parents.len(), last);
        Ok((parent, last))
    }

    fn require(st: &State, parent: NodeId, name: &str, target: &str) -> SysResult<NodeId> {
        st.lookup(parent, name, target)?
            .ok_or_else(|| err(SysErrorKind::NotFound, target))
    }
}

impl Dir for FakeDir {
    fn info(&self) -> SysResult<RootInfo> {
        self.check(FsOp::Info)?;
        self.fs.lock().root_info(self.node, &self.handle_target())
    }

    fn open_dir(&self, p: &RelPath) -> SysResult<Box<dyn Dir + '_>> {
        self.check(FsOp::OpenDir)?;
        let segs: Vec<&str> = p.segments().collect();
        let node = self.walk(FsOp::OpenDir, &segs, p.as_str())?;
        Ok(Box::new(self.fs.dir_handle(node, p.as_str())?))
    }

    fn metadata(&self, p: &RelPath) -> SysResult<Option<Metadata>> {
        self.check(FsOp::Metadata)?;
        let t = p.as_str();
        // A deleted handle is an error, not a missing entry.
        self.fs.lock().dir(self.node, &self.handle_target())?;
        let (parent, name) = match self.split(FsOp::Metadata, p) {
            Ok(x) => x,
            Err(e) if matches!(e.kind, SysErrorKind::NotFound | SysErrorKind::InvalidPath) => {
                return Ok(None);
            }
            Err(e) => return Err(e),
        };
        let st = self.fs.lock();
        match st.lookup(parent, name, t)? {
            Some(id) => {
                st.not_pending(id, t)?;
                st.meta(id, t).map(Some)
            }
            None => Ok(None),
        }
    }

    fn stored_name(&self, p: &RelPath) -> SysResult<Option<String>> {
        self.check(FsOp::Metadata)?;
        let t = p.as_str();
        self.fs.lock().dir(self.node, &self.handle_target())?;
        let (parent, name) = match self.split(FsOp::Metadata, p) {
            Ok(x) => x,
            Err(e) if matches!(e.kind, SysErrorKind::NotFound | SysErrorKind::InvalidPath) => {
                return Ok(None);
            }
            Err(e) => return Err(e),
        };
        let st = self.fs.lock();
        let Some(id) = st.lookup(parent, name, t)? else {
            return Ok(None);
        };
        st.not_pending(id, t)?;
        if st.is_restricted(id) {
            return Err(err(SysErrorKind::AccessDenied, t));
        }
        Ok(Some(st.node(id, t)?.name.clone()))
    }

    fn open_read(&self, p: &RelPath) -> SysResult<Box<dyn ReadSeek + '_>> {
        self.check(FsOp::OpenRead)?;
        let t = p.as_str();
        let (parent, name) = self.split(FsOp::OpenRead, p)?;
        let mut st = self.fs.lock();
        let id = Self::require(&st, parent, name, t)?;
        st.openable(id, t)?;
        match (st.rel_kind(id), st.nodes.get(&id).map(|n| &n.body)) {
            (EntryKind::File, Some(Body::File(ino))) => {
                let data = st.inode(*ino, t)?.data.clone();
                let obj = st.obj_of(id);
                st.check_share(obj, Access::READ, Share::R, t)?;
                let open = st.register(
                    obj,
                    Access::READ,
                    Share::R,
                    std::process::id(),
                    Origin::Rerun,
                );
                drop(st);
                Ok(Box::new(Counted {
                    data: Cursor::new(data),
                    served: Arc::clone(&self.fs.shared.served),
                    _open: self.fs.token(open),
                }))
            }
            (EntryKind::Dir, _) => Err(err(SysErrorKind::AccessDenied, t)),
            _ => Err(err(SysErrorKind::ReparsePoint, t)),
        }
    }

    fn read_dir_limited(
        &self,
        p: Option<&RelPath>,
        max_entries: usize,
    ) -> SysResult<Vec<DirEntry>> {
        self.check(FsOp::ReadDir)?;
        let (node, t) = match p {
            None => (self.node, self.handle_target()),
            Some(p) => {
                let segs: Vec<&str> = p.segments().collect();
                (self.walk(FsOp::ReadDir, &segs, p.as_str())?, p.to_string())
            }
        };
        let st = self.fs.lock();
        st.dir(node, &t)?;
        if p.is_some() {
            // Listing another directory opens it like a `Dir` handle (list access).
            st.check_share(Obj::Node(node), Access::READ, Share::RWD, &t)?;
        }
        let children = &st.dir(node, &t)?.children;
        if children.len() > max_entries {
            return Err(SysError::too_large(
                t,
                u64::try_from(max_entries).unwrap_or(u64::MAX),
            ));
        }
        // An entry in delete-pending state cannot be reopened: skipped like one that
        // vanished between the listing and its reopen (A6).
        children
            .values()
            .filter(|&&id| st.not_pending(id, &t).is_ok())
            .map(|&id| {
                Ok(DirEntry {
                    name: st.node(id, &t)?.name.clone(),
                    meta: st.meta(id, &t)?,
                })
            })
            .collect()
    }

    fn users(&self, p: &RelPath) -> SysResult<Vec<u32>> {
        self.check(FsOp::Users)?;
        let t = p.as_str();
        let (parent, name) = self.split(FsOp::Users, p)?;
        let st = self.fs.lock();
        let id = Self::require(&st, parent, name, t)?;
        st.openable(id, t)?;
        match (st.rel_kind(id), st.nodes.get(&id).map(|n| &n.body)) {
            (EntryKind::File, Some(Body::File(ino))) => Ok(st.users_of(*ino, None)),
            (EntryKind::File | EntryKind::Reparse, _) => Err(err(SysErrorKind::ReparsePoint, t)),
            (EntryKind::Dir, _) => Err(err(SysErrorKind::AccessDenied, t)),
        }
    }
}

impl DirWrite for FakeDir {
    fn open_dir_write(&self, p: &RelPath) -> SysResult<Box<dyn DirWrite + '_>> {
        self.check(FsOp::OpenDirWrite)?;
        let segs: Vec<&str> = p.segments().collect();
        let node = self.walk(FsOp::OpenDirWrite, &segs, p.as_str())?;
        Ok(Box::new(self.fs.dir_handle(node, p.as_str())?))
    }

    fn guard(&self, name: &RelPath) -> SysResult<Box<dyn FileGuard + '_>> {
        Ok(Box::new(seq::guard(self, name)?))
    }

    fn create_new(&self, name: &RelPath, src: &mut dyn Read, new: &NewFile) -> SysResult<Written> {
        seq::create_new(self, name, src, new)
    }

    fn create_dir(&self, name: &RelPath) -> SysResult<u128> {
        seq::create_dir(self, name)
    }

    fn remove_dir(&self, name: &RelPath, expected_id: u128) -> SysResult<()> {
        seq::remove_dir(self, name, expected_id)
    }

    fn flush(&self) -> SysResult<()> {
        seq::flush(self)
    }

    fn lock(&self, name: &RelPath) -> SysResult<Box<dyn FileLock + '_>> {
        Ok(Box::new(seq::lock(self, name)?))
    }
}
