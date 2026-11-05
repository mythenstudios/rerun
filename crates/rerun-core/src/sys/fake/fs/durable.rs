//! The fake's power-loss model (ADR 0019 amendment, user decision D-1): one ordered log of
//! metadata changes per volume, made durable by flushes, cut at any point by a power loss.
//!
//! - Logged are the metadata changes Rerun makes through the write primitives: a created
//!   file or directory, a rename, a POSIX delete completing when its handle closes, an
//!   attribute change. A fixture or attacker change is another program that flushed: it is
//!   durable itself and makes its volume's log durable up to that moment, so an undo never
//!   meets a change it did not log; an undo that collides anyway panics (a model error).
//! - Deviation: a volume mounted in a folder shares the log of the drive it is mounted on.
//! - File content is not in the log: each inode keeps its last flushed content. A fixture
//!   write is flushed at once; a file Rerun creates starts empty and durable as empty.
//! - `PrimFile::flush` makes the file's content durable and every volume's log durable up to
//!   the last entry touching that file; `PrimDir::flush` up to the last entry touching the
//!   directory or an entry in it. Because a log is ordered, every earlier entry of that
//!   volume becomes durable with it.
//! - [`FakeFs::power_loss`] keeps, per volume, the durable part plus `keep` more entries (cut
//!   0 drops every unflushed change), undoes the rest newest first, resets every file to its
//!   last flushed content and drops every handle and image section without completing a
//!   pending delete; afterwards the process is fresh (not crashed, no faults).

use std::collections::BTreeMap;

use super::{Body, FakeFs, Inode, Node, NodeId, Obj, State};
use crate::sys::fs::Attrs;

/// How to undo one logged change.
#[derive(Debug)]
pub(super) enum Undo {
    /// A file or directory was created: remove it again.
    Created { node: NodeId },
    /// An entry was renamed or moved: move it back.
    Moved {
        node: NodeId,
        from_parent: NodeId,
        from_name: String,
    },
    /// An entry was unlinked (POSIX delete completed): put it back, with a copy of its inode.
    Unlinked {
        node: NodeId,
        saved: Node,
        inode: Option<(NodeId, Inode)>,
    },
    /// R/H/S changed: set the old ones.
    Attrs { obj: Obj, old: Attrs },
}

/// One logged change and what it touched (for the flush rules).
#[derive(Debug)]
pub(super) struct Entry {
    undo: Undo,
    /// Nodes it touched: the entry itself and every directory it changed.
    nodes: Vec<NodeId>,
    /// Inode it touched, if a file.
    ino: Option<NodeId>,
}

/// The ordered log of one volume.
#[derive(Debug, Default)]
pub(super) struct VolLog {
    entries: Vec<Entry>,
    /// Entries `..durable` are durable.
    durable: usize,
}

impl State {
    fn drive_of(&self, node: NodeId) -> Option<char> {
        self.path_of(node, "").ok().map(|(d, _)| d)
    }

    /// Appends a change to the log of the volume of `on`.
    pub(super) fn log(&mut self, on: NodeId, undo: Undo, nodes: Vec<NodeId>, ino: Option<NodeId>) {
        if let Some(drive) = self.drive_of(on) {
            self.logs
                .entry(drive)
                .or_default()
                .entries
                .push(Entry { undo, nodes, ino });
        }
    }

    /// Logs a file or directory `node` just created in `parent`.
    pub(super) fn log_created(&mut self, node: NodeId, parent: NodeId) {
        let ino = match self.obj_of(node) {
            Obj::File { ino, .. } => Some(ino),
            Obj::Node(_) => None,
        };
        self.log(parent, Undo::Created { node }, vec![node, parent], ino);
    }

    /// Logs the unlink of `node` (before it happens): a copy of the entry and of its inode.
    pub(super) fn log_unlink(&mut self, node: NodeId) {
        let Some(saved) = self.nodes.get(&node).cloned() else {
            return;
        };
        let Some(parent) = saved.parent else {
            return;
        };
        let inode = match saved.body {
            Body::File(ino) => self.inodes.get(&ino).cloned().map(|i| (ino, i)),
            _ => None,
        };
        let ino = inode.as_ref().map(|(i, _)| *i);
        self.log(
            parent,
            Undo::Unlinked { node, saved, inode },
            vec![node, parent],
            ino,
        );
    }

    /// A fixture change on `drive`: another program that flushed, so the volume's log is
    /// durable up to now (the ordered log stays consistent with changes nobody logs).
    pub(super) fn fixture_flushed(&mut self, drive: char) {
        if let Some(log) = self.logs.get_mut(&drive) {
            log.durable = log.entries.len();
        }
    }

    /// Makes every volume's log durable up to the last entry that `touches`.
    fn durable_up_to(&mut self, touches: impl Fn(&Entry) -> bool) {
        for log in self.logs.values_mut() {
            if let Some(last) = log.entries.iter().rposition(&touches) {
                log.durable = log.durable.max(last + 1);
            }
        }
    }

    /// `PrimFile::flush` of a file: its content and the log up to its last change.
    pub(super) fn flush_file(&mut self, obj: Obj) {
        let node = obj.node();
        if let Obj::File { ino, .. } = obj
            && let Some(i) = self.inodes.get_mut(&ino)
        {
            i.durable = i.data.clone();
        }
        let ino = match obj {
            Obj::File { ino, .. } => Some(ino),
            Obj::Node(_) => None,
        };
        self.durable_up_to(|e| e.nodes.contains(&node) || (ino.is_some() && e.ino == ino));
    }

    /// `PrimDir::flush`: the log up to the last change of the directory or an entry in it.
    pub(super) fn flush_dir(&mut self, dir: NodeId) {
        self.durable_up_to(|e| e.nodes.contains(&dir));
    }

    fn undo(&mut self, u: Undo) {
        match u {
            Undo::Created { node } => {
                assert!(
                    self.nodes.contains_key(&node),
                    "fake power loss: created entry {node} is gone before its undo"
                );
                self.unlink(node);
            }
            Undo::Moved {
                node,
                from_parent,
                from_name,
            } => {
                if let Err(e) = self.move_node(node, from_parent, &from_name, "<undo>") {
                    panic!("fake power loss: undo of a rename of {node} collides: {e}");
                }
            }
            Undo::Unlinked { node, saved, inode } => {
                let (Some(parent), name) = (saved.parent, saved.name.clone()) else {
                    return;
                };
                assert!(
                    !self.nodes.contains_key(&node) && self.nodes.contains_key(&parent),
                    "fake power loss: undo of the unlink of {node} collides"
                );
                if let Body::File(ino) = saved.body {
                    match self.inodes.get_mut(&ino) {
                        Some(i) => i.links += 1,
                        None => {
                            if let Some((_, mut copy)) = inode {
                                copy.links = 1;
                                self.inodes.insert(ino, copy);
                            }
                        }
                    }
                }
                let key = match self.dir(parent, "<undo>") {
                    Ok(d) if !d.children.contains_key(&d.key(&name)) => d.key(&name),
                    _ => panic!("fake power loss: undo of the unlink of {node} collides"),
                };
                self.nodes.insert(node, saved);
                if let Ok(d) = self.dir_mut(parent, "<undo>") {
                    d.children.insert(key, node);
                }
            }
            Undo::Attrs { obj, old } => match obj {
                Obj::File { ino, .. } => {
                    if let Some(i) = self.inodes.get_mut(&ino) {
                        i.attrs = old;
                    }
                }
                Obj::Node(node) => {
                    if let Ok(d) = self.dir_mut(node, "<undo>") {
                        d.attrs = old;
                    }
                }
            },
        }
    }
}

impl FakeFs {
    /// Makes every change so far durable on every volume (content and log), like a clean
    /// shutdown. Test setup usually ends with it.
    pub fn sync_all(&self) {
        let mut st = self.lock();
        for log in st.logs.values_mut() {
            log.durable = log.entries.len();
        }
        for i in st.inodes.values_mut() {
            i.durable = i.data.clone();
        }
    }

    /// Changes of the volume `drive` that a power loss could drop (logged, not durable).
    pub fn pending(&self, drive: char) -> usize {
        self.lock()
            .logs
            .get(&drive.to_ascii_uppercase())
            .map_or(0, |l| l.entries.len() - l.durable)
    }

    /// A power loss: per volume, the durable changes plus `keep[volume]` (default 0) more
    /// survive, the rest is undone newest first; every file reads its last flushed content;
    /// every handle and image section is gone (no pending delete completes); the process
    /// starts fresh (see the module docs).
    pub fn power_loss(&self, keep: &BTreeMap<char, usize>) {
        let mut st = self.lock();
        st.opens.clear();
        st.faults.crashed = false;
        st.faults.armed.clear();
        st.faults.seen.clear();
        st.faults.fired = false;
        let logs = std::mem::take(&mut st.logs);
        for (drive, mut log) in logs {
            let kept =
                (log.durable + keep.get(&drive).copied().unwrap_or(0)).min(log.entries.len());
            while log.entries.len() > kept {
                if let Some(e) = log.entries.pop() {
                    st.undo(e.undo);
                }
            }
        }
        for i in st.inodes.values_mut() {
            i.data = i.durable.clone();
        }
        let orphans: Vec<NodeId> = st
            .inodes
            .iter()
            .filter(|(_, i)| i.links == 0)
            .map(|(id, _)| *id)
            .collect();
        for ino in orphans {
            st.inodes.remove(&ino);
        }
    }
}
