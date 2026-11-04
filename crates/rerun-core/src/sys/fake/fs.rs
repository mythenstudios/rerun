//! In-memory file system with Win32 semantics.
//!
//! Deviations from real Windows (deliberate, not checked by the contract tests):
//! - Only drive-absolute paths (`C:\…`), no UNC, no `\\?\`.
//! - `.` and `..` are rejected instead of resolved (`InvalidPath`).
//! - Trailing dots and spaces in names are not stripped, no 8.3 names.
//! - No sharing violations (`Busy`); they arrive with fault injection in phase 3.
//! - No alternate data streams: `:` in a name yields `InvalidPath`.
//! - `rename` across drives yields `Unsupported` (Win32: `ERROR_NOT_SAME_DEVICE`).
//! - Reparse points have no file/directory type; `remove_file` and `remove_dir` both remove
//!   them (Win32: directory junctions only via `RemoveDirectory`).
//! - `write` replaces atomically in memory; the temp file of the real implementation must be
//!   journaled.

use std::collections::BTreeMap;
use std::io::Cursor;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, PoisonError};

use crate::sys::fold::fold;
use crate::sys::fs::{DirEntry, EntryKind, Fs, Metadata};
use crate::sys::{SysError, SysErrorKind, SysResult};

#[derive(Debug, Clone)]
enum Node {
    File {
        name: String,
        data: Vec<u8>,
        readonly: bool,
    },
    Dir {
        name: String,
        readonly: bool,
    },
    Reparse {
        name: String,
        target: PathBuf,
    },
}

impl Node {
    fn name(&self) -> &str {
        match self {
            Self::File { name, .. } | Self::Dir { name, .. } | Self::Reparse { name, .. } => name,
        }
    }

    fn set_name(&mut self, new: String) {
        match self {
            Self::File { name, .. } | Self::Dir { name, .. } | Self::Reparse { name, .. } => {
                *name = new;
            }
        }
    }

    fn meta(&self) -> Metadata {
        match self {
            Self::File { data, readonly, .. } => Metadata {
                kind: EntryKind::File,
                len: data.len() as u64,
                readonly: *readonly,
            },
            Self::Dir { readonly, .. } => Metadata {
                kind: EntryKind::Dir,
                len: 0,
                readonly: *readonly,
            },
            Self::Reparse { .. } => Metadata {
                kind: EntryKind::Reparse,
                len: 0,
                readonly: false,
            },
        }
    }
}

/// Split, normalized path.
#[derive(Debug, Clone)]
struct FakePath {
    /// Drive in upper case, e.g. `C:`.
    drive: String,
    /// Segments in their original case.
    segments: Vec<String>,
}

impl FakePath {
    fn parse(p: &Path) -> SysResult<Self> {
        let invalid = || SysError::path(SysErrorKind::InvalidPath, p);
        let s = p.to_str().ok_or_else(invalid)?.replace('/', "\\");
        let bytes = s.as_bytes();
        let is_drive_abs = bytes.len() >= 3
            && bytes[0].is_ascii_alphabetic()
            && bytes[1] == b':'
            && bytes[2] == b'\\';
        if !is_drive_abs {
            return Err(invalid());
        }
        let drive = s[..2].to_ascii_uppercase();
        let mut segments = Vec::new();
        for seg in s[3..].split('\\') {
            match seg {
                "" => {}
                "." | ".." => return Err(invalid()),
                _ if seg.chars().any(|c| {
                    (c as u32) < 0x20 || matches!(c, '<' | '>' | ':' | '"' | '|' | '?' | '*')
                }) =>
                {
                    return Err(invalid());
                }
                _ => segments.push(seg.to_owned()),
            }
        }
        Ok(Self { drive, segments })
    }

    fn is_root(&self) -> bool {
        self.segments.is_empty()
    }

    /// Folded key for the first `n` segments.
    fn key_n(&self, n: usize) -> String {
        let mut k = self.drive.clone();
        for seg in &self.segments[..n] {
            k.push('\\');
            k.push_str(&fold(seg));
        }
        k
    }

    fn key(&self) -> String {
        self.key_n(self.segments.len())
    }

    fn name(&self) -> String {
        self.segments
            .last()
            .cloned()
            .unwrap_or_else(|| self.drive.clone())
    }
}

/// In-memory file system. Drive roots (`C:\`, `D:\` …) always exist.
#[derive(Debug, Default)]
pub struct FakeFs {
    nodes: Mutex<BTreeMap<String, Node>>,
}

type Nodes = BTreeMap<String, Node>;

impl FakeFs {
    fn lock(&self) -> MutexGuard<'_, Nodes> {
        self.nodes.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Checks the ancestors of `fp` (excluding `fp` itself).
    /// `Ok(true)` = all exist as directories, `Ok(false)` = one is missing or is a file.
    fn ancestors_ok(nodes: &Nodes, fp: &FakePath, p: &Path) -> SysResult<bool> {
        for n in 1..fp.segments.len() {
            match nodes.get(&fp.key_n(n)) {
                Some(Node::Dir { .. }) => {}
                Some(Node::Reparse { .. }) => {
                    return Err(SysError::path(SysErrorKind::ReparsePoint, p));
                }
                Some(Node::File { .. }) | None => return Ok(false),
            }
        }
        Ok(true)
    }

    /// Like `ancestors_ok`, but missing parents are an error (`NotFound`).
    fn require_parent(nodes: &Nodes, fp: &FakePath, p: &Path) -> SysResult<()> {
        if Self::ancestors_ok(nodes, fp, p)? {
            Ok(())
        } else {
            Err(SysError::path(SysErrorKind::NotFound, p))
        }
    }

    fn children<'a>(nodes: &'a Nodes, key: &str) -> impl Iterator<Item = (&'a String, &'a Node)> {
        let prefix = format!("{key}\\");
        nodes
            .range(prefix.clone()..)
            .take_while(move |(k, _)| k.starts_with(&prefix))
            .filter(move |(k, _)| !k[key.len() + 1..].contains('\\'))
    }

    fn has_children(nodes: &Nodes, key: &str) -> bool {
        let prefix = format!("{key}\\");
        nodes
            .range(prefix.clone()..)
            .next()
            .is_some_and(|(k, _)| k.starts_with(&prefix))
    }

    /// Builder only: creates a directory including missing parents.
    pub(super) fn create_dir_all(&self, p: &Path) -> SysResult<()> {
        let fp = FakePath::parse(p)?;
        for n in 1..=fp.segments.len() {
            let mut prefix = PathBuf::from(format!("{}\\", fp.drive));
            for seg in &fp.segments[..n] {
                prefix.push(seg);
            }
            match self.metadata(&prefix)? {
                None => self.create_dir(&prefix)?,
                Some(m) if m.kind == EntryKind::Dir => {}
                Some(_) => return Err(SysError::path(SysErrorKind::AlreadyExists, &prefix)),
            }
        }
        Ok(())
    }

    /// Target of a reparse point (only for checks in tests; `Fs` never follows reparse points).
    pub fn reparse_target(&self, p: &Path) -> SysResult<Option<PathBuf>> {
        let fp = FakePath::parse(p)?;
        Ok(match self.lock().get(&fp.key()) {
            Some(Node::Reparse { target, .. }) => Some(target.clone()),
            _ => None,
        })
    }

    /// Builder only: creates a reparse point.
    pub(super) fn add_reparse(&self, p: &Path, target: PathBuf) -> SysResult<()> {
        let fp = FakePath::parse(p)?;
        let mut nodes = self.lock();
        Self::require_parent(&nodes, &fp, p)?;
        if fp.is_root() || nodes.contains_key(&fp.key()) {
            return Err(SysError::path(SysErrorKind::AlreadyExists, p));
        }
        nodes.insert(
            fp.key(),
            Node::Reparse {
                name: fp.name(),
                target,
            },
        );
        Ok(())
    }
}

impl Fs for FakeFs {
    fn metadata(&self, p: &Path) -> SysResult<Option<Metadata>> {
        let fp = FakePath::parse(p)?;
        if fp.is_root() {
            return Ok(Some(Metadata {
                kind: EntryKind::Dir,
                len: 0,
                readonly: false,
            }));
        }
        let nodes = self.lock();
        if !Self::ancestors_ok(&nodes, &fp, p)? {
            return Ok(None);
        }
        Ok(nodes.get(&fp.key()).map(Node::meta))
    }

    fn open_read<'a>(&'a self, p: &Path) -> SysResult<Box<dyn Read + Send + 'a>> {
        let fp = FakePath::parse(p)?;
        let nodes = self.lock();
        Self::require_parent(&nodes, &fp, p)?;
        match nodes.get(&fp.key()) {
            Some(Node::File { data, .. }) => Ok(Box::new(Cursor::new(data.clone()))),
            Some(Node::Reparse { .. }) => Err(SysError::path(SysErrorKind::ReparsePoint, p)),
            Some(Node::Dir { .. }) => Err(SysError::path(SysErrorKind::AccessDenied, p)),
            None if fp.is_root() => Err(SysError::path(SysErrorKind::AccessDenied, p)),
            None => Err(SysError::path(SysErrorKind::NotFound, p)),
        }
    }

    fn read_dir(&self, p: &Path) -> SysResult<Vec<DirEntry>> {
        let fp = FakePath::parse(p)?;
        let nodes = self.lock();
        Self::require_parent(&nodes, &fp, p)?;
        if !fp.is_root() {
            match nodes.get(&fp.key()) {
                Some(Node::Dir { .. }) => {}
                Some(Node::Reparse { .. }) => {
                    return Err(SysError::path(SysErrorKind::ReparsePoint, p));
                }
                Some(Node::File { .. }) => {
                    return Err(SysError::path(SysErrorKind::InvalidPath, p));
                }
                None => return Err(SysError::path(SysErrorKind::NotFound, p)),
            }
        }
        Ok(Self::children(&nodes, &fp.key())
            .map(|(_, n)| DirEntry {
                name: n.name().to_owned(),
                meta: n.meta(),
            })
            .collect())
    }

    fn write(&self, p: &Path, data: &[u8]) -> SysResult<()> {
        let fp = FakePath::parse(p)?;
        if fp.is_root() {
            return Err(SysError::path(SysErrorKind::AccessDenied, p));
        }
        let mut nodes = self.lock();
        Self::require_parent(&nodes, &fp, p)?;
        match nodes.get_mut(&fp.key()) {
            Some(Node::File { readonly: true, .. }) | Some(Node::Dir { .. }) => {
                Err(SysError::path(SysErrorKind::AccessDenied, p))
            }
            Some(Node::Reparse { .. }) => Err(SysError::path(SysErrorKind::ReparsePoint, p)),
            Some(Node::File { data: existing, .. }) => {
                // The case of the existing name is kept (like Win32).
                *existing = data.to_vec();
                Ok(())
            }
            None => {
                nodes.insert(
                    fp.key(),
                    Node::File {
                        name: fp.name(),
                        data: data.to_vec(),
                        readonly: false,
                    },
                );
                Ok(())
            }
        }
    }

    fn create_dir(&self, p: &Path) -> SysResult<()> {
        let fp = FakePath::parse(p)?;
        let mut nodes = self.lock();
        Self::require_parent(&nodes, &fp, p)?;
        if fp.is_root() || nodes.contains_key(&fp.key()) {
            return Err(SysError::path(SysErrorKind::AlreadyExists, p));
        }
        nodes.insert(
            fp.key(),
            Node::Dir {
                name: fp.name(),
                readonly: false,
            },
        );
        Ok(())
    }

    fn remove_file(&self, p: &Path) -> SysResult<()> {
        let fp = FakePath::parse(p)?;
        let mut nodes = self.lock();
        Self::require_parent(&nodes, &fp, p)?;
        match nodes.get(&fp.key()) {
            Some(Node::File { readonly: true, .. }) | Some(Node::Dir { .. }) => {
                Err(SysError::path(SysErrorKind::AccessDenied, p))
            }
            Some(Node::File { .. }) | Some(Node::Reparse { .. }) => {
                nodes.remove(&fp.key());
                Ok(())
            }
            None if fp.is_root() => Err(SysError::path(SysErrorKind::AccessDenied, p)),
            None => Err(SysError::path(SysErrorKind::NotFound, p)),
        }
    }

    fn remove_dir(&self, p: &Path) -> SysResult<()> {
        let fp = FakePath::parse(p)?;
        if fp.is_root() {
            return Err(SysError::path(SysErrorKind::AccessDenied, p));
        }
        let mut nodes = self.lock();
        Self::require_parent(&nodes, &fp, p)?;
        let key = fp.key();
        match nodes.get(&key) {
            Some(Node::Dir { .. }) if Self::has_children(&nodes, &key) => {
                Err(SysError::path(SysErrorKind::NotEmpty, p))
            }
            Some(Node::Dir { .. }) | Some(Node::Reparse { .. }) => {
                nodes.remove(&key);
                Ok(())
            }
            Some(Node::File { .. }) => Err(SysError::path(SysErrorKind::InvalidPath, p)),
            None => Err(SysError::path(SysErrorKind::NotFound, p)),
        }
    }

    fn rename(&self, from: &Path, to: &Path) -> SysResult<()> {
        let ffrom = FakePath::parse(from)?;
        let fto = FakePath::parse(to)?;
        if ffrom.is_root() || fto.is_root() {
            return Err(SysError::path(SysErrorKind::AccessDenied, from));
        }
        let mut nodes = self.lock();
        Self::require_parent(&nodes, &ffrom, from)?;
        Self::require_parent(&nodes, &fto, to)?;
        if ffrom.drive != fto.drive {
            return Err(SysError::path(SysErrorKind::Unsupported, to));
        }
        let (kfrom, kto) = (ffrom.key(), fto.key());
        if !nodes.contains_key(&kfrom) {
            return Err(SysError::path(SysErrorKind::NotFound, from));
        }
        if kfrom == kto {
            // Only the case changes.
            if let Some(node) = nodes.get_mut(&kfrom) {
                node.set_name(fto.name());
            }
            return Ok(());
        }
        if nodes.contains_key(&kto) {
            return Err(SysError::path(SysErrorKind::AlreadyExists, to));
        }
        if kto.starts_with(&format!("{kfrom}\\")) {
            return Err(SysError::path(SysErrorKind::InvalidPath, to));
        }
        // Move the entry itself and all descendants.
        let prefix = format!("{kfrom}\\");
        let moved: Vec<String> = nodes
            .range(prefix.clone()..)
            .take_while(|(k, _)| k.starts_with(&prefix))
            .map(|(k, _)| k.clone())
            .collect();
        if let Some(mut node) = nodes.remove(&kfrom) {
            node.set_name(fto.name());
            nodes.insert(kto.clone(), node);
        }
        for old in moved {
            if let Some(node) = nodes.remove(&old) {
                nodes.insert(format!("{kto}{}", &old[kfrom.len()..]), node);
            }
        }
        Ok(())
    }

    fn set_readonly(&self, p: &Path, ro: bool) -> SysResult<()> {
        let fp = FakePath::parse(p)?;
        let mut nodes = self.lock();
        Self::require_parent(&nodes, &fp, p)?;
        match nodes.get_mut(&fp.key()) {
            Some(Node::File { readonly, .. }) | Some(Node::Dir { readonly, .. }) => {
                *readonly = ro;
                Ok(())
            }
            Some(Node::Reparse { .. }) => Err(SysError::path(SysErrorKind::ReparsePoint, p)),
            None => Err(SysError::path(SysErrorKind::NotFound, p)),
        }
    }
}
