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
//! - No share modes and no sharing violations (`Busy`): open handles never block a rename
//!   or delete. A handle to a deleted directory returns `NotFound`.
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
//!   there is no hydration and no reopen without `FILE_OPEN_REPARSE_POINT`.
//! - A volume mounted in a folder ([`FakeFs::set_volume_root`]) is a mount point seen from
//!   above, like on Windows: below a root it is a name surrogate (`Dir::metadata` reports
//!   `Reparse` with the `MOUNT_POINT` tag, operations through it return `ReparsePoint`), and
//!   `Fs::open_dir` by absolute path follows into it. Opened that way it reports an empty
//!   `volume_path` and its own volume serial. Deviation: the mount point is the volume root
//!   itself (no separate directory underneath), the file system and file IDs stay those of
//!   the drive, and the setup helpers walk through it without refusing.
//! - Restricted entries ([`FakeFs::set_restricted`]) are a flag, not an ACL: every open of
//!   one, every walk through it and every write to it (`replace`, `remove_*`, `rename`,
//!   `set_readonly`) is `AccessDenied`, including `Fs::open_dir`. On Windows, deleting such an
//!   entry can still succeed through the parent's `FILE_DELETE_CHILD`; the fake refuses
//!   (only stricter). The setup helpers ignore the flag (they act like an administrator).
//! - Volumes: the file system is NTFS unless set with [`FakeFs::set_fs_kind`]; it only
//!   changes what [`RootInfo`] reports, not the behaviour.
//! - `remove_file` removes any reparse point (file or directory link, like a handle-based
//!   delete), `remove_dir` only directory links.
//! - Hooks fire only for [`Dir`] operations, never for `Fs::open_dir` or the setup helpers,
//!   and never reentrantly (a hook that calls into the fake does not trigger itself).
//! - `replace` runs its phases (create temp, rename old, rename temp, delete old) as separate
//!   lock sections with hook events in between; the checks are the same as on Windows.

use std::collections::BTreeMap;
use std::fmt;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use crate::fold::fold;
use crate::path::RelPath;
use crate::sys::fs::{
    Attrs, Dir, DirEntry, EntryKind, Fs, FsKind, Metadata, ReadSeek, ReparseInfo, RootInfo, tag,
};
use crate::sys::{SysError, SysErrorKind, SysResult};

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
    /// `Dir::create_new`.
    CreateNew,
    /// `Dir::replace`, walk to the target.
    Replace,
    /// `Dir::replace`, before renaming the old file to `<tmp>.old`.
    ReplaceRenameOld,
    /// `Dir::replace`, before renaming `<tmp>` onto the target.
    ReplaceRenameTmp,
    /// `Dir::replace`, before deleting `<tmp>.old`.
    ReplaceDeleteOld,
    /// `Dir::create_dir`.
    CreateDir,
    /// `Dir::remove_file`.
    RemoveFile,
    /// `Dir::remove_dir`.
    RemoveDir,
    /// `Dir::rename`, walk to the source.
    Rename,
    /// `Dir::rename`, walk to the destination.
    RenameTarget,
    /// `Dir::set_readonly`.
    SetReadonly,
}

/// A step of an operation: fires before component `index` (0-based) of the relative path is
/// looked up. For the `Replace*` phases, `index` is 0 and `name` is the affected entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StepEvent {
    /// Operation.
    pub op: FsOp,
    /// Index of the component that is looked up next.
    pub index: usize,
    /// Name of that component.
    pub name: String,
}

/// Test hook, see [`FakeFs::on_step`].
pub type StepHook = Box<dyn FnMut(&FakeFs, &StepEvent) + Send>;

#[derive(Debug)]
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
#[derive(Debug)]
struct Inode {
    data: Vec<u8>,
    attrs: Attrs,
    tag: Option<u32>,
    links: u32,
    /// Its DACL denies the current user every open (shared by all hard links, like the
    /// security descriptor on NTFS).
    restricted: bool,
}

#[derive(Debug)]
struct LinkData {
    tag: u32,
    target: String,
    is_dir: bool,
    restricted: bool,
}

#[derive(Debug)]
enum Body {
    Dir(DirData),
    /// Directory entry of a file; the value is the inode.
    File(NodeId),
    /// Name surrogate (junction, symlink).
    Link(LinkData),
}

#[derive(Debug)]
struct Node {
    parent: Option<NodeId>,
    /// Name in its original case; `X:` for a drive root.
    name: String,
    body: Body,
}

#[derive(Debug, Default)]
struct State {
    next_id: NodeId,
    nodes: BTreeMap<NodeId, Node>,
    inodes: BTreeMap<NodeId, Inode>,
    drives: BTreeMap<char, NodeId>,
    fs_kinds: BTreeMap<char, FsKind>,
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

    /// The parent of an entry that is about to be written: a live, case-insensitive directory.
    fn writable_dir(&self, id: NodeId, target: &str) -> SysResult<&DirData> {
        let d = self.dir(id, target)?;
        if d.case_sensitive {
            return Err(err(SysErrorKind::Unsupported, target));
        }
        Ok(d)
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
    fn openable(&self, id: NodeId, target: &str) -> SysResult<()> {
        if self.is_restricted(id) {
            Err(err(SysErrorKind::AccessDenied, target))
        } else {
            Ok(())
        }
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
                attrs: Attrs::default(),
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

    /// The current name of `id` if it still is the entry `folded` in `parent`.
    fn entry_at(&self, id: NodeId, parent: NodeId, folded: &str) -> Option<String> {
        let n = self.nodes.get(&id)?;
        (n.parent == Some(parent) && fold(&n.name) == folded).then(|| n.name.clone())
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
            if i.links == 0 {
                self.inodes.remove(&ino);
            }
        }
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
    hook: Mutex<Option<StepHook>>,
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
    fn lock(&self) -> MutexGuard<'_, State> {
        self.shared
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    fn hook_slot(&self) -> MutexGuard<'_, Option<StepHook>> {
        self.shared
            .hook
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Runs the hook without holding the state lock. The hook is taken out while it runs, so
    /// operations it performs do not trigger it again.
    fn fire(&self, op: FsOp, index: usize, name: &str) {
        let hook = self.hook_slot().take();
        if let Some(mut hook) = hook {
            hook(
                self,
                &StepEvent {
                    op,
                    index,
                    name: name.to_owned(),
                },
            );
            let mut slot = self.hook_slot();
            if slot.is_none() {
                *slot = Some(hook);
            }
        }
    }

    /// Installs a test hook that runs before each component of a relative operation is looked
    /// up (and between the phases of `replace`). Replaces an earlier hook.
    pub fn on_step(&self, hook: impl FnMut(&FakeFs, &StepEvent) + Send + 'static) {
        *self.hook_slot() = Some(Box::new(hook));
    }

    /// Removes the test hook (not from inside the hook itself).
    pub fn clear_on_step(&self) {
        *self.hook_slot() = None;
    }

    // ---------- Setup and attacker helpers (absolute, never follow links) ----------

    /// Creates a directory including missing parents.
    pub fn mkdir_all(&self, abs: &Path) -> SysResult<()> {
        let shown = abs.display().to_string();
        let (drive, segs) = parse_abs(abs)?;
        self.lock().mkdir_all(drive, &segs, &shown).map(|_| ())
    }

    /// Creates or overwrites a file including missing parents (overwrite keeps the inode,
    /// i.e. all hard links see the new content).
    pub fn put_file(&self, abs: &Path, data: &[u8]) -> SysResult<()> {
        let shown = abs.display().to_string();
        let (drive, segs, name) = parse_abs_child(abs)?;
        let mut st = self.lock();
        let parent = st.mkdir_all(drive, &segs, &shown)?;
        match st.lookup(parent, &name, &shown)? {
            None => st.new_file(parent, &name, data, &shown).map(|_| ()),
            Some(id) => match st.nodes.get(&id).map(|n| &n.body) {
                Some(Body::File(ino)) => {
                    let ino = *ino;
                    if let Some(i) = st.inodes.get_mut(&ino) {
                        i.data = data.to_vec();
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
        let shown = format!("{}\\{raw_name}", parent_abs.display());
        if raw_name.is_empty() || raw_name.contains(['\\', '/', '\0']) {
            return Err(err(SysErrorKind::InvalidPath, &shown));
        }
        let (drive, segs) = parse_abs(parent_abs)?;
        let mut st = self.lock();
        let parent = st.mkdir_all(drive, &segs, &shown)?;
        st.new_file(parent, raw_name, data, &shown).map(|_| ())
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
    pub fn put_link(
        &self,
        abs: &Path,
        reparse_tag: u32,
        target: &str,
        is_dir: bool,
    ) -> SysResult<()> {
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
            is_dir,
            restricted: false,
        });
        st.insert(parent, &name, body, &shown).map(|_| ())
    }

    /// Adds a hard link `new_abs` to the existing file `existing_abs` (same drive).
    pub fn put_hardlink(&self, existing_abs: &Path, new_abs: &Path) -> SysResult<()> {
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

    /// Sets the attributes of a file (shared by its hard links) or directory.
    pub fn set_attrs(&self, abs: &Path, attrs: Attrs) -> SysResult<()> {
        let mut st = self.lock();
        let id = st.require_abs(abs)?;
        let ino = match st.nodes.get_mut(&id).map(|n| &mut n.body) {
            Some(Body::Dir(d)) => {
                d.attrs = attrs;
                return Ok(());
            }
            Some(Body::File(ino)) => *ino,
            _ => return Err(SysError::path(SysErrorKind::ReparsePoint, abs)),
        };
        if let Some(i) = st.inodes.get_mut(&ino) {
            i.attrs = attrs;
        }
        Ok(())
    }

    /// Makes an existing, empty directory case-sensitive (or not), like
    /// `fsutil file setCaseSensitiveInfo`.
    pub fn set_case_sensitive(&self, abs: &Path, on: bool) -> SysResult<()> {
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
        let shown = abs.display().to_string();
        let mut st = self.lock();
        let id = st.require_abs(abs)?;
        st.dir_mut(id, &shown)?.volume_root = true;
        Ok(())
    }

    /// Attacker: atomically renames the entry at `abs` to a hidden sibling name and puts a
    /// junction to `target` in its place. Returns the hidden name.
    pub fn swap_with_junction(&self, abs: &Path, target: &str) -> SysResult<String> {
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
        st.move_node(id, parent, &hidden, &shown)?;
        let body = Body::Link(LinkData {
            tag: tag::MOUNT_POINT,
            target: target.to_owned(),
            is_dir: true,
            restricted: false,
        });
        st.insert(parent, &name, body, &shown)?;
        Ok(hidden)
    }

    /// Attacker: renames or moves an entry by absolute path (same drive, never overwrites).
    pub fn rename_abs(&self, from: &Path, to: &Path) -> SysResult<()> {
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
        st.move_node(src, parent, &name, &shown)
    }

    /// Changes the target of an existing link.
    pub fn retarget(&self, abs: &Path, target: &str) -> SysResult<()> {
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

impl Fs for FakeFs {
    fn open_dir(&self, abs: &Path) -> SysResult<Box<dyn Dir + '_>> {
        let shown = abs.display().to_string();
        let (drive, segs) = parse_abs(abs)?;
        let node = self.lock().resolve_follow(drive, &segs, 0, &shown)?;
        Ok(Box::new(FakeDir {
            fs: self.clone(),
            node,
        }))
    }
}

/// Handle to a directory of a [`FakeFs`]: a node ID, valid across renames.
#[derive(Debug)]
pub struct FakeDir {
    fs: FakeFs,
    node: NodeId,
}

impl FakeDir {
    fn handle_target(&self) -> String {
        format!("<handle {}>", self.node)
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
        let target = self.handle_target();
        let st = self.fs.lock();
        let d = st.dir(self.node, &target)?;
        let (drive, _) = st.path_of(self.node, &target)?;
        let fs_kind = st.fs_kinds.get(&drive).copied().unwrap_or(FsKind::Ntfs);
        let (vol, vol_segs) = st.volume_of(self.node, &target)?;
        let serial = if st.drives.get(&drive) == Some(&vol) {
            volume_serial(drive)
        } else {
            mounted_serial(vol)
        };
        Ok(RootInfo {
            final_path: st.final_path(self.node, &target)?,
            volume_serial: serial,
            file_id: u128::from(self.node),
            user_writable: d.user_writable,
            case_sensitive: d.case_sensitive,
            volume_path: vol_segs.join("\\"),
            fs_kind,
            supports_posix_rename: matches!(fs_kind, FsKind::Ntfs | FsKind::Refs),
        })
    }

    fn open_dir(&self, p: &RelPath) -> SysResult<Box<dyn Dir + '_>> {
        let segs: Vec<&str> = p.segments().collect();
        let node = self.walk(FsOp::OpenDir, &segs, p.as_str())?;
        Ok(Box::new(FakeDir {
            fs: self.fs.clone(),
            node,
        }))
    }

    fn metadata(&self, p: &RelPath) -> SysResult<Option<Metadata>> {
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
            Some(id) => st.meta(id, t).map(Some),
            None => Ok(None),
        }
    }

    fn open_read(&self, p: &RelPath) -> SysResult<Box<dyn ReadSeek + '_>> {
        let t = p.as_str();
        let (parent, name) = self.split(FsOp::OpenRead, p)?;
        let st = self.fs.lock();
        let id = Self::require(&st, parent, name, t)?;
        st.openable(id, t)?;
        match (st.rel_kind(id), st.nodes.get(&id).map(|n| &n.body)) {
            (EntryKind::File, Some(Body::File(ino))) => {
                Ok(Box::new(Cursor::new(st.inode(*ino, t)?.data.clone())))
            }
            (EntryKind::Dir, _) => Err(err(SysErrorKind::AccessDenied, t)),
            _ => Err(err(SysErrorKind::ReparsePoint, t)),
        }
    }

    fn read_dir(&self, p: Option<&RelPath>) -> SysResult<Vec<DirEntry>> {
        let (node, t) = match p {
            None => (self.node, self.handle_target()),
            Some(p) => {
                let segs: Vec<&str> = p.segments().collect();
                (self.walk(FsOp::ReadDir, &segs, p.as_str())?, p.to_string())
            }
        };
        let st = self.fs.lock();
        st.dir(node, &t)?
            .children
            .values()
            .map(|&id| {
                Ok(DirEntry {
                    name: st.node(id, &t)?.name.clone(),
                    meta: st.meta(id, &t)?,
                })
            })
            .collect()
    }

    fn create_new(&self, p: &RelPath, data: &[u8]) -> SysResult<()> {
        let t = p.as_str();
        let (parent, name) = self.split(FsOp::CreateNew, p)?;
        let mut st = self.fs.lock();
        st.writable_dir(parent, t)?;
        st.new_file(parent, name, data, t).map(|_| ())
    }

    fn replace(&self, p: &RelPath, data: &[u8], tmp: &str) -> SysResult<()> {
        let t = p.as_str();
        let old = format!("{tmp}.old");
        if RelPath::from_segment(tmp).is_err() || RelPath::from_segment(&old).is_err() {
            return Err(err(SysErrorKind::InvalidPath, tmp));
        }
        let (parent, name) = self.split(FsOp::Replace, p)?;
        let folded = fold(name);
        if fold(tmp) == folded || fold(&old) == folded {
            return Err(err(SysErrorKind::InvalidPath, tmp));
        }

        // Phase 1: check the target, create the temp file (FILE_CREATE).
        let (target, tmp_id) = {
            let mut st = self.fs.lock();
            st.writable_dir(parent, t)?;
            let target = Self::require(&st, parent, name, t)?;
            st.openable(target, t)?;
            match st.nodes.get(&target).map(|n| &n.body) {
                Some(Body::Dir(_)) => return Err(err(SysErrorKind::AccessDenied, t)),
                Some(Body::File(ino)) if st.tag_allowed(*ino) => {
                    if st.inode(*ino, t)?.attrs.readonly {
                        return Err(err(SysErrorKind::AccessDenied, t));
                    }
                }
                _ => return Err(err(SysErrorKind::ReparsePoint, t)),
            }
            let tmp_id = st.new_file(parent, tmp, data, tmp)?;
            (target, tmp_id)
        };

        // Phase 2: old file → `<tmp>.old` (by handle, into the parent).
        self.fs.fire(FsOp::ReplaceRenameOld, 0, &old);
        let target_name = {
            let mut st = self.fs.lock();
            let (Some(target_name), Some(_)) = (
                st.entry_at(target, parent, &folded),
                st.entry_at(tmp_id, parent, &fold(tmp)),
            ) else {
                // Renamed or moved by someone else: never pull it back.
                st.unlink(tmp_id);
                return Err(err(SysErrorKind::Busy, t));
            };
            if let Err(e) = st.move_node(target, parent, &old, &old) {
                st.unlink(tmp_id);
                return Err(e);
            }
            target_name
        };

        // Phase 3: `<tmp>` → target name, never overwriting.
        self.fs.fire(FsOp::ReplaceRenameTmp, 0, &target_name);
        {
            let mut st = self.fs.lock();
            if st.entry_at(target, parent, &fold(&old)).is_none()
                || st.entry_at(tmp_id, parent, &fold(tmp)).is_none()
            {
                st.unlink(tmp_id);
                return Err(err(SysErrorKind::Busy, t));
            }
            st.move_node(tmp_id, parent, &target_name, t)?;
        }

        // Phase 4: delete `<tmp>.old` by handle.
        self.fs.fire(FsOp::ReplaceDeleteOld, 0, &old);
        let mut st = self.fs.lock();
        let ino = match st.nodes.get(&target).map(|n| &n.body) {
            Some(Body::File(ino)) => *ino,
            _ => return Ok(()),
        };
        if st.inode(ino, &old)?.attrs.readonly {
            return Err(err(SysErrorKind::AccessDenied, &old));
        }
        st.unlink(target);
        Ok(())
    }

    fn create_dir(&self, p: &RelPath) -> SysResult<()> {
        let t = p.as_str();
        let (parent, name) = self.split(FsOp::CreateDir, p)?;
        let mut st = self.fs.lock();
        let uw = st.writable_dir(parent, t)?.user_writable;
        st.insert(parent, name, Body::Dir(DirData::new(uw)), t)
            .map(|_| ())
    }

    fn remove_file(&self, p: &RelPath) -> SysResult<()> {
        let t = p.as_str();
        let (parent, name) = self.split(FsOp::RemoveFile, p)?;
        let mut st = self.fs.lock();
        st.writable_dir(parent, t)?;
        let id = Self::require(&st, parent, name, t)?;
        st.openable(id, t)?;
        match (st.kind(id), st.nodes.get(&id).map(|n| &n.body)) {
            (_, Some(Body::Dir(_))) => return Err(err(SysErrorKind::AccessDenied, t)),
            (EntryKind::File, Some(Body::File(ino))) if st.inode(*ino, t)?.attrs.readonly => {
                return Err(err(SysErrorKind::AccessDenied, t));
            }
            _ => {}
        }
        st.unlink(id);
        Ok(())
    }

    fn remove_dir(&self, p: &RelPath) -> SysResult<()> {
        let t = p.as_str();
        let (parent, name) = self.split(FsOp::RemoveDir, p)?;
        let mut st = self.fs.lock();
        st.writable_dir(parent, t)?;
        let id = Self::require(&st, parent, name, t)?;
        st.openable(id, t)?;
        match st.nodes.get(&id).map(|n| &n.body) {
            Some(Body::Dir(d)) if !d.children.is_empty() => {
                return Err(err(SysErrorKind::NotEmpty, t));
            }
            Some(Body::Dir(d)) if d.attrs.readonly => {
                return Err(err(SysErrorKind::AccessDenied, t));
            }
            Some(Body::Dir(_) | Body::Link(LinkData { is_dir: true, .. })) => {}
            _ => return Err(err(SysErrorKind::InvalidPath, t)),
        }
        st.unlink(id);
        Ok(())
    }

    fn rename(&self, from: &RelPath, to: &RelPath) -> SysResult<()> {
        let (fp, fname) = self.split(FsOp::Rename, from)?;
        let (tp, tname) = self.split(FsOp::RenameTarget, to)?;
        let (tf, tt) = (from.as_str(), to.as_str());
        let mut st = self.fs.lock();
        st.writable_dir(fp, tf)?;
        st.writable_dir(tp, tt)?;
        let src = Self::require(&st, fp, fname, tf)?;
        st.openable(src, tf)?;
        if let Some(existing) = st.lookup(tp, tname, tt)? {
            if existing != src {
                return Err(err(SysErrorKind::AlreadyExists, tt));
            }
        } else if matches!(st.nodes.get(&src).map(|n| &n.body), Some(Body::Dir(_)))
            && st.is_ancestor_or_self(src, tp)
        {
            return Err(err(SysErrorKind::InvalidPath, tt));
        }
        st.move_node(src, tp, tname, tt)
    }

    fn set_readonly(&self, p: &RelPath, ro: bool) -> SysResult<()> {
        let t = p.as_str();
        let (parent, name) = self.split(FsOp::SetReadonly, p)?;
        let mut st = self.fs.lock();
        st.writable_dir(parent, t)?;
        let id = Self::require(&st, parent, name, t)?;
        st.openable(id, t)?;
        let kind = st.kind(id);
        let ino = match st.nodes.get_mut(&id).map(|n| &mut n.body) {
            Some(Body::Dir(d)) if d.plain() && !d.volume_root => {
                d.attrs.readonly = ro;
                return Ok(());
            }
            Some(Body::File(ino)) if kind == EntryKind::File => *ino,
            _ => return Err(err(SysErrorKind::ReparsePoint, t)),
        };
        let i = st
            .inodes
            .get_mut(&ino)
            .ok_or_else(|| err(SysErrorKind::NotFound, t))?;
        if i.links > 1 {
            return Err(err(SysErrorKind::Linked, t));
        }
        i.attrs.readonly = ro;
        Ok(())
    }
}
