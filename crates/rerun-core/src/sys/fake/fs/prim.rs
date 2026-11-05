//! The fake's write primitives ([`PrimDir`], [`PrimFile`], ADR 0017 A1): the sequences
//! themselves live in `sys::seq`. Each primitive call first fires the step hook with
//! `FsOp::Write` and its [`Prim`] (without the state lock, so a hook can act as a racing
//! program), then acts on the state under one lock acquisition.

use super::{
    Body, DirData, FakeDir, FakeFs, NodeId, Obj, OpenId, OpenToken, Origin, Prim, State, err,
};
use crate::sys::contract::{Access, Share};
use crate::sys::fs::{Attrs, Dir, EntryKind, Metadata, RootInfo, tag};
use crate::sys::seq::{HeldState, PrimDir, PrimFile};
use crate::sys::{SysErrorKind, SysResult};

/// Access of a `<tmp>` handle: write and delete (and attributes).
const TMP_ACCESS: Access = Access {
    read: false,
    write: true,
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

/// A primitive takes exactly one segment (re-asserted like `sys::win` does).
fn single(name: &str) -> SysResult<()> {
    if name.is_empty() || name.contains(['\\', '/', '\0']) {
        return Err(err(SysErrorKind::InvalidPath, name));
    }
    Ok(())
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
    /// then `f` under it.
    fn prim<T>(
        &self,
        call: Prim,
        name: &str,
        f: impl FnOnce(&mut State) -> SysResult<T>,
    ) -> SysResult<T> {
        self.fire_call(call, name);
        let mut st = self.lock();
        f(&mut st)
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

impl PrimDir for FakeDir {
    type File = FakeFile;

    fn info(&self) -> SysResult<RootInfo> {
        self.fs.fire_call(Prim::Info, "");
        Dir::info(self)
    }

    fn lookup(&self, name: &str) -> SysResult<Option<Metadata>> {
        self.fs.prim(Prim::Lookup, name, |st| {
            single(name)?;
            st.dir(self.node, name)?;
            match st.lookup(self.node, name, name)? {
                Some(id) => st.meta(id, name).map(Some),
                None => Ok(None),
            }
        })
    }

    fn create_tmp(&self, name: &str) -> SysResult<FakeFile> {
        let id = self.fs.prim(Prim::CreateTmp, name, |st| {
            single(name)?;
            let node = st.new_file(self.node, name, &[], name)?;
            let obj = st.obj_of(node);
            FakeFs::open_rerun(st, obj, TMP_ACCESS, Share::NONE, name)
        })?;
        Ok(self.fs.file(id))
    }

    fn open_lock(&self, name: &str) -> SysResult<FakeFile> {
        let id = self.fs.prim(Prim::OpenLock, name, |st| {
            single(name)?;
            let node = match st.lookup(self.node, name, name)? {
                Some(n) => {
                    st.openable(n, name)?;
                    n
                }
                None => st.new_file(self.node, name, &[], name)?,
            };
            let obj = st.obj_of(node);
            FakeFs::open_rerun(st, obj, Access::READ, Share::NONE, name)
        })?;
        Ok(self.fs.file(id))
    }

    fn create_dir(&self, name: &str) -> SysResult<u128> {
        self.fs.prim(Prim::CreateDir, name, |st| {
            single(name)?;
            let user_writable = st.dir(self.node, name)?.user_writable;
            st.insert(
                self.node,
                name,
                Body::Dir(DirData::new(user_writable)),
                name,
            )
            .map(u128::from)
        })
    }

    fn open_dir_delete(&self, name: &str) -> SysResult<FakeFile> {
        let id = self.fs.prim(Prim::OpenDirDelete, name, |st| {
            single(name)?;
            let node = st.child(self.node, name)?;
            if matches!(st.nodes.get(&node).map(|n| &n.body), Some(Body::File(_))) {
                return Err(err(SysErrorKind::InvalidPath, name));
            }
            FakeFs::open_rerun(st, Obj::Node(node), Access::DELETE, Share::RW, name)
        })?;
        Ok(self.fs.file(id))
    }

    fn rename(&self, f: &FakeFile, name: &str) -> SysResult<()> {
        self.fs.prim(Prim::Rename, name, |st| {
            single(name)?;
            let node = st.rec_obj(f.id(), name)?.node();
            if st.nodes.get(&node).is_none_or(|n| n.parent.is_none()) {
                return Err(err(SysErrorKind::NotFound, name));
            }
            st.dir(self.node, name)?;
            // The target directory is opened for write: every handle on it must share write.
            st.check_share(Obj::Node(self.node), Access::WRITE, Share::RWD, name)?;
            if st.open_below(node) {
                return Err(err(SysErrorKind::AccessDenied, name));
            }
            match st.lookup(self.node, name, name)? {
                Some(other) if other != node => Err(err(SysErrorKind::Busy, name)),
                _ => st.move_node(node, self.node, name, name),
            }
        })
    }

    fn flush(&self) -> SysResult<()> {
        let t = self.handle_target();
        self.fs
            .prim(Prim::FlushDir, "", |st| st.dir(self.node, &t).map(|_| ()))
    }
}

impl PrimFile for FakeFile {
    fn state(&self) -> SysResult<HeldState> {
        self.fs.prim(Prim::State, "", |st| {
            let obj = st.rec_obj(self.id(), "<held>")?;
            st.held_state(obj, "<held>")
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
            match st.rec_obj(self.id(), t)? {
                Obj::File { ino, .. } => {
                    st.inodes
                        .get_mut(&ino)
                        .ok_or_else(|| err(SysErrorKind::NotFound, t))?
                        .attrs = attrs;
                }
                Obj::Node(node) => st.dir_mut(node, t)?.attrs = attrs,
            }
            Ok(())
        })
    }

    fn flush(&self) -> SysResult<()> {
        self.fs.prim(Prim::FlushFile, "", |st| {
            st.rec_obj(self.id(), "<held>").map(|_| ())
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
