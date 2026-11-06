//! The fake's write primitives ([`PrimDir`], [`PrimFile`], ADR 0017 A1): the sequences
//! themselves live in `sys::seq`. Each primitive call first fires the step hook with
//! `FsOp::Write` and its [`Prim`] (without the state lock, so a hook can act as a racing
//! program), then acts on the state under one lock acquisition.

use super::durable::Undo;
use super::{
    Body, DirData, FakeDir, FakeFs, NodeId, Obj, OpenId, OpenToken, Origin, Prim, State,
    crashed_err, err,
};
use crate::sys::contract::{Access, Share};
use crate::sys::fs::{Attrs, EntryKind, Metadata, tag};
use crate::sys::seq::{HeldState, PrimDir, PrimFile, Seg, Support};
use crate::sys::{SysErrorKind, SysResult};

/// Access of a `<tmp>` handle: write and delete (and attributes).
const TMP_ACCESS: Access = Access {
    read: false,
    write: true,
    delete: true,
};

/// Access of a guard: read data and delete (and attributes).
const GUARD_ACCESS: Access = Access {
    read: true,
    write: false,
    delete: true,
};

/// A held handle of the fake's write side.
#[derive(Debug)]
pub struct FakeFile {
    fs: FakeFs,
    open: OpenToken,
}

impl FakeFile {
    fn id(&self) -> OpenId {
        self.open.id
    }
}

impl State {
    /// The record of an open handle; a closed one (restart) is an error.
    fn rec_obj(&self, id: OpenId, target: &str) -> SysResult<Obj> {
        self.opens
            .get(&id)
            .map(|r| r.obj)
            .ok_or_else(|| err(SysErrorKind::Other, &format!("{target}: handle is closed")))
    }

    /// What a handle reports about its object (also after its name is gone).
    fn held_state(&self, obj: Obj, target: &str) -> SysResult<HeldState> {
        match obj {
            Obj::File { ino, .. } => {
                let i = self.inode(ino, target)?;
                let plain = i.tag.is_none_or(tag::is_allowed_data_tag);
                Ok(HeldState {
                    kind: if plain {
                        EntryKind::File
                    } else {
                        EntryKind::Reparse
                    },
                    links: i.links,
                    attrs: i.attrs,
                    len: if plain { i.data.len() as u64 } else { 0 },
                    file_id: u128::from(ino),
                    reparse_tag: i.tag,
                })
            }
            Obj::Node(node) => {
                let m = self.full_meta(node, target)?;
                Ok(HeldState {
                    kind: m.kind,
                    links: 1,
                    attrs: m.attrs,
                    len: 0,
                    file_id: m.file_id,
                    reparse_tag: m.reparse.map(|r| r.tag),
                })
            }
        }
    }

    /// `FileNameInformation` of a node: its path below its volume root with a leading `\`.
    /// A name that is gone (POSIX-deleted, still open) reports a path below `$Extend`.
    fn volume_name_of(&self, node: NodeId, target: &str) -> SysResult<String> {
        if !self.nodes.contains_key(&node) {
            return Ok(format!(r"\$Extend\$Deleted\{node:016X}"));
        }
        let (_, segs) = self.volume_of(node, target)?;
        Ok(format!(r"\{}", segs.join("\\")))
    }

    /// Opens an existing child for a primitive: restricted entries are `AccessDenied`.
    fn child(&self, dir: NodeId, name: &str) -> SysResult<NodeId> {
        let id = self
            .lookup(dir, name, name)?
            .ok_or_else(|| err(SysErrorKind::NotFound, name))?;
        self.openable(id, name)?;
        Ok(id)
    }
}

impl FakeFs {
    /// Runs one primitive: fires the hook (`FsOp::Write`, `call`) without the state lock,
    /// then, under it, enters the call (crash, armed fault) and runs `f`. A
    /// [`Fault::CrashAfter`](super::Fault) lets `f` act and then crashes.
    fn prim<T>(
        &self,
        call: Prim,
        name: &str,
        f: impl FnOnce(&mut State) -> SysResult<T>,
    ) -> SysResult<T> {
        // After a crash no hook fires: the call fails before anything happens.
        if !self.lock().hub.crashed() {
            self.fire_call(call, name);
        }
        let mut st = self.lock();
        let crash = st.enter(call)?;
        let r = f(&mut st);
        if crash {
            st.hub.crash();
            return Err(crashed_err());
        }
        r
    }

    /// Registers an open of `obj` by Rerun after a share check (`Busy`).
    fn open_rerun(
        st: &mut State,
        obj: Obj,
        access: Access,
        share: Share,
        target: &str,
    ) -> SysResult<OpenId> {
        st.check_share(obj, access, share, target)?;
        Ok(st.register(obj, access, share, std::process::id(), Origin::Rerun))
    }

    fn file(&self, id: OpenId) -> FakeFile {
        FakeFile {
            fs: self.clone(),
            open: self.token(id),
        }
    }
}

impl FakeDir {
    /// A primitive on this directory handle: also `Other` once a restart closed it.
    fn prim<T>(
        &self,
        call: Prim,
        name: &str,
        f: impl FnOnce(&mut State) -> SysResult<T>,
    ) -> SysResult<T> {
        let id = self._open.id;
        self.fs.prim(call, name, |st| {
            st.alive(id)?;
            f(st)
        })
    }
}

impl PrimDir for FakeDir {
    type File = FakeFile;

    fn support(&self) -> SysResult<Support> {
        let t = self.handle_target();
        self.prim(Prim::Support, "", |st| {
            let info = st.root_info(self.node, &t)?;
            Ok(Support {
                case_sensitive: info.case_sensitive,
                posix: info.supports_posix_rename,
            })
        })
    }

    fn volume_name(&self) -> SysResult<String> {
        let t = self.handle_target();
        self.prim(Prim::VolumeName, "", |st| {
            st.dir(self.node, &t)?;
            st.volume_name_of(self.node, &t)
        })
    }

    fn open_guard(&self, name: Seg<'_>) -> SysResult<FakeFile> {
        let name = name.as_str();
        let id = self.prim(Prim::OpenGuard, name, |st| {
            let node = st.child(self.node, name)?;
            let obj = st.obj_of(node);
            FakeFs::open_rerun(st, obj, GUARD_ACCESS, Share::R, name)
        })?;
        Ok(self.fs.file(id))
    }

    fn lookup(&self, name: Seg<'_>) -> SysResult<Option<Metadata>> {
        let name = name.as_str();
        self.prim(Prim::Lookup, name, |st| {
            st.dir(self.node, name)?;
            match st.lookup(self.node, name, name)? {
                Some(id) => {
                    st.not_pending(id, name)?;
                    st.meta(id, name).map(Some)
                }
                None => Ok(None),
            }
        })
    }

    fn create_tmp(&self, name: Seg<'_>) -> SysResult<FakeFile> {
        let name = name.as_str();
        let id = self.prim(Prim::CreateTmp, name, |st| {
            let node = st.new_file(self.node, name, &[], name)?;
            let obj = st.obj_of(node);
            st.log_created(node, self.node);
            FakeFs::open_rerun(st, obj, TMP_ACCESS, Share::NONE, name)
        })?;
        Ok(self.fs.file(id))
    }

    fn open_lock(&self, name: Seg<'_>) -> SysResult<FakeFile> {
        let name = name.as_str();
        let id = self.prim(Prim::OpenLock, name, |st| {
            let node = match st.lookup(self.node, name, name)? {
                Some(n) => {
                    st.openable(n, name)?;
                    n
                }
                None => {
                    let n = st.new_file(self.node, name, &[], name)?;
                    st.log_created(n, self.node);
                    n
                }
            };
            let obj = st.obj_of(node);
            FakeFs::open_rerun(st, obj, Access::READ, Share::NONE, name)
        })?;
        Ok(self.fs.file(id))
    }

    fn create_dir(&self, name: Seg<'_>) -> SysResult<u128> {
        let name = name.as_str();
        self.prim(Prim::CreateDir, name, |st| {
            let user_writable = st.dir(self.node, name)?.user_writable;
            let node = st.insert(
                self.node,
                name,
                Body::Dir(DirData::new(user_writable)),
                name,
            )?;
            st.log_created(node, self.node);
            Ok(u128::from(node))
        })
    }

    fn open_dir_delete(&self, name: Seg<'_>) -> SysResult<FakeFile> {
        let name = name.as_str();
        let id = self.prim(Prim::OpenDirDelete, name, |st| {
            let node = st.child(self.node, name)?;
            if matches!(st.nodes.get(&node).map(|n| &n.body), Some(Body::File(_))) {
                return Err(err(SysErrorKind::InvalidPath, name));
            }
            FakeFs::open_rerun(st, Obj::Node(node), Access::DELETE, Share::RW, name)
        })?;
        Ok(self.fs.file(id))
    }

    fn rename(&self, f: &FakeFile, name: Seg<'_>) -> SysResult<()> {
        let name = name.as_str();
        self.prim(Prim::Rename, name, |st| {
            let rec = st
                .opens
                .get(&f.id())
                .ok_or_else(|| err(SysErrorKind::Other, &format!("{name}: handle is closed")))?;
            // A rename needs `DELETE` on the renamed handle.
            if !rec.access.delete {
                return Err(err(SysErrorKind::AccessDenied, name));
            }
            let node = rec.obj.node();
            if st.nodes.get(&node).is_none_or(|n| n.parent.is_none()) {
                return Err(err(SysErrorKind::NotFound, name));
            }
            st.dir(self.node, name)?;
            // The target directory is opened for write: every handle on it must share write.
            st.check_share(Obj::Node(self.node), Access::WRITE, Share::RWD, name)?;
            if st.open_below(node) {
                return Err(err(SysErrorKind::AccessDenied, name));
            }
            if matches!(st.lookup(self.node, name, name)?, Some(other) if other != node) {
                return Err(err(SysErrorKind::Busy, name));
            }
            let (from_parent, from_name) = match st.nodes.get(&node) {
                Some(n) => (n.parent.unwrap_or(self.node), n.name.clone()),
                None => return Err(err(SysErrorKind::NotFound, name)),
            };
            st.move_node(node, self.node, name, name)?;
            let ino = match st.obj_of(node) {
                Obj::File { ino, .. } => Some(ino),
                Obj::Node(_) => None,
            };
            st.log(
                self.node,
                Undo::Moved {
                    node,
                    from_parent,
                    from_name,
                },
                vec![node, from_parent, self.node],
                ino,
            );
            Ok(())
        })
    }

    fn flush(&self) -> SysResult<()> {
        let t = self.handle_target();
        self.prim(Prim::FlushDir, "", |st| {
            st.dir(self.node, &t)?;
            st.flush_dir(self.node);
            Ok(())
        })
    }
}

impl PrimFile for FakeFile {
    fn state(&self) -> SysResult<HeldState> {
        self.fs.prim(Prim::State, "", |st| {
            let obj = st.rec_obj(self.id(), "<held>")?;
            st.held_state(obj, "<held>")
        })
    }

    fn name(&self) -> SysResult<String> {
        self.fs.prim(Prim::Name, "", |st| {
            let node = st.rec_obj(self.id(), "<held>")?.node();
            st.volume_name_of(node, "<held>")
        })
    }

    fn read_at(&mut self, off: u64, buf: &mut [u8]) -> SysResult<usize> {
        self.fs.prim(Prim::ReadAt, "", |st| {
            let t = "<held>";
            let rec = st
                .opens
                .get(&self.id())
                .ok_or_else(|| err(SysErrorKind::Other, t))?;
            let (Obj::File { ino, .. }, true) = (rec.obj, rec.access.read) else {
                return Err(err(SysErrorKind::AccessDenied, t));
            };
            let data = &st.inode(ino, t)?.data;
            let start = usize::try_from(off).unwrap_or(usize::MAX).min(data.len());
            let n = buf.len().min(data.len() - start);
            buf[..n].copy_from_slice(&data[start..start + n]);
            Ok(n)
        })
    }

    fn users(&self) -> SysResult<Vec<u32>> {
        self.fs.prim(Prim::Users, "", |st| {
            match st.rec_obj(self.id(), "<held>")? {
                Obj::File { ino, .. } => Ok(st.users_of(ino, Some(self.id()))),
                Obj::Node(_) => Err(err(SysErrorKind::AccessDenied, "<held>")),
            }
        })
    }

    fn write(&mut self, buf: &[u8]) -> SysResult<()> {
        self.fs.prim(Prim::Write, "", |st| {
            let t = "<held>";
            let rec = st
                .opens
                .get(&self.id())
                .ok_or_else(|| err(SysErrorKind::Other, t))?;
            let (Obj::File { ino, .. }, true) = (rec.obj, rec.access.write) else {
                return Err(err(SysErrorKind::AccessDenied, t));
            };
            st.inodes
                .get_mut(&ino)
                .ok_or_else(|| err(SysErrorKind::NotFound, t))?
                .data
                .extend_from_slice(buf);
            Ok(())
        })
    }

    fn set_attrs(&self, attrs: Attrs) -> SysResult<()> {
        self.fs.prim(Prim::SetAttrs, "", |st| {
            let t = "<held>";
            let obj = st.rec_obj(self.id(), t)?;
            let old = match obj {
                Obj::File { ino, .. } => {
                    let i = st
                        .inodes
                        .get_mut(&ino)
                        .ok_or_else(|| err(SysErrorKind::NotFound, t))?;
                    std::mem::replace(&mut i.attrs, attrs)
                }
                Obj::Node(node) => std::mem::replace(&mut st.dir_mut(node, t)?.attrs, attrs),
            };
            let node = obj.node();
            let ino = match obj {
                Obj::File { ino, .. } => Some(ino),
                Obj::Node(_) => None,
            };
            // The entry and its folder: a flush of either covers the change.
            let mut nodes = vec![node];
            nodes.extend(st.nodes.get(&node).and_then(|n| n.parent));
            st.log(node, Undo::Attrs { obj, old }, nodes, ino);
            Ok(())
        })
    }

    fn flush(&self) -> SysResult<()> {
        self.fs.prim(Prim::FlushFile, "", |st| {
            let obj = st.rec_obj(self.id(), "<held>")?;
            st.flush_file(obj);
            Ok(())
        })
    }

    fn posix_delete(&self) -> SysResult<()> {
        self.fs.prim(Prim::PosixDelete, "", |st| {
            let t = "<held>";
            let rec = st
                .opens
                .get(&self.id())
                .ok_or_else(|| err(SysErrorKind::Other, t))?;
            if !rec.access.delete {
                return Err(err(SysErrorKind::AccessDenied, t));
            }
            // An image section refuses every delete (`STATUS_CANNOT_DELETE`, observed).
            st.not_mapped(rec.obj, t)?;
            if let Obj::Node(node) = rec.obj
                && st
                    .nodes
                    .get(&node)
                    .is_some_and(|n| matches!(&n.body, Body::Dir(d) if !d.children.is_empty()))
            {
                return Err(err(SysErrorKind::NotEmpty, t));
            }
            if let Some(rec) = st.opens.get_mut(&self.id()) {
                rec.delete_on_close = true;
            }
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::FakeFs;
    use crate::path::RelPath;
    use crate::sys::SysErrorKind;
    use crate::sys::seq::{PrimDir, Seg};

    #[test]
    fn a_rename_needs_delete_access_on_the_handle() {
        let fs = FakeFs::default();
        fs.mkdir_all(Path::new(r"C:\G")).unwrap();
        let d = fs.open_abs(Path::new(r"C:\G")).unwrap();
        let (a, b) = (
            RelPath::parse("a.lock").unwrap(),
            RelPath::parse("b.lock").unwrap(),
        );
        // A lock handle has read access only.
        let lock = d.open_lock(Seg::new(&a).unwrap()).unwrap();
        let e = d.rename(&lock, Seg::new(&b).unwrap()).unwrap_err();
        assert_eq!(e.kind, SysErrorKind::AccessDenied);
        // `<tmp>` has delete access.
        let t = RelPath::parse("t.tmp").unwrap();
        let tmp = d.create_tmp(Seg::new(&t).unwrap()).unwrap();
        d.rename(&tmp, Seg::new(&b).unwrap()).unwrap();
    }

    #[test]
    fn a_segment_is_exactly_one_valid_path_segment() {
        let two = RelPath::parse(r"a\b").unwrap();
        assert_eq!(Seg::new(&two).unwrap_err().kind, SysErrorKind::InvalidPath);
        // Streams, dot segments and device names never become a `RelPath`.
        for bad in [":x", "x:s", ".", "..", "CON", "nul.txt", "a."] {
            assert!(RelPath::from_segment(bad).is_err(), "{bad}");
        }
    }
}
