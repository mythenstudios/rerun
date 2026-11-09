//! Contract of the elevated helper's file system reads (ADR 0023 §2, §4; A4 S1, N1, N2):
//! [`Fs::open_by_id`] and [`Dir::sd_facts`](super::super::fs::Dir::sd_facts), against the fake
//! and `sys::win` (NTFS under `target/`).
//!
//! - **I1** a directory opened by `{volume GUID, file ID}` is the same object (file ID, final
//!   path) and follows the object across a rename of its parent.
//! - **I2** a junction is `ReparsePoint`, a file `InvalidPath`, an ID that names nothing and a
//!   volume GUID of no volume are errors; nothing is ever followed.
//! - **I3** `sd_facts` of the handle and of entries: an owner and a DACL on a volume with
//!   persistent ACLs; kind and link count of the object itself (a hard link counts, a junction
//!   is described as `Reparse`, never followed); a missing entry is `NotFound`, a walk through a
//!   junction `ReparsePoint`.
//!
//! The 16-byte IDs of ReFS (A4 N2) are a unit test of the name bytes in `sys::win::nt` plus
//! `win_open_by_id_on_refs` when a ReFS folder is named (`docs/09-testing.md`); the fake models
//! 8-byte-sized IDs only.

use std::path::Path;

use super::{FsContractResult, FsFixture, Skipped, ensure, ok};
use crate::path::RelPath;
use crate::sys::fs::{EntryKind, Fs, VolumeGuid};
use crate::sys::{SysErrorKind, SysResult};

fn rel(s: &str) -> RelPath {
    match RelPath::parse(s) {
        Ok(p) => p,
        Err(e) => unreachable!("{s}: {e}"),
    }
}

fn kind_of<T>(r: SysResult<T>) -> Option<SysErrorKind> {
    r.err().map(|e| e.kind)
}

/// I1 to I3 (module docs) in the empty directory `work`.
pub fn fs_identity_contract(fs: &dyn Fs, fx: &dyn FsFixture, work: &Path) -> FsContractResult {
    let skips = Skipped::new();
    ok(fx.dir(&work.join("a").join("b")), "fixture dir")?;
    ok(fx.file(&work.join("f.txt"), b"f"), "fixture file")?;
    ok(
        fx.junction(&work.join("j"), &work.join("a")),
        "fixture junction",
    )?;

    let w = ok(fs.open_dir(work), "open work")?;
    let b = ok(w.open_dir(&rel(r"a\b")), "open a\\b")?;
    let bi = ok(b.info(), "info a\\b")?;
    let Some(guid) = bi.volume_guid else {
        return Err("I1: no volume GUID for a folder on a local volume".to_owned());
    };
    ensure(
        bi.supports_open_by_id && bi.persistent_acls,
        "I1: the work volume opens by ID and keeps ACLs",
    )?;
    ensure(
        VolumeGuid::parse(&guid.to_string()) == Some(guid),
        "I1: the GUID's text form parses back",
    )?;
    drop(b);

    // I1.
    let by_id = ok(fs.open_by_id(&guid, bi.file_id), "I1 open by id")?;
    let ii = ok(by_id.info(), "I1 info by id")?;
    ensure(
        ii.file_id == bi.file_id && ii.final_path == bi.final_path,
        "I1: the same object",
    )?;
    ensure(
        ii.volume_serial == bi.volume_serial,
        "I1: the same volume serial",
    )?;
    drop((by_id, w));
    ok(
        fx.rename(&work.join("a"), &work.join("a2")),
        "fixture rename",
    )?;
    let moved = ok(
        fs.open_by_id(&guid, bi.file_id),
        "I1 open by id after rename",
    )?;
    let mi = ok(moved.info(), "I1 info after rename")?;
    ensure(
        mi.final_path.ends_with(Path::new("a2").join("b")),
        "I1: found by identity after its parent was renamed",
    )?;
    drop(moved);

    // I2.
    let w = ok(fs.open_dir(work), "reopen work")?;
    let meta = |p: &str| -> Result<u128, String> {
        match ok(w.metadata(&rel(p)), p)? {
            Some(m) => Ok(m.file_id),
            None => Err(format!("{p} missing")),
        }
    };
    let j = meta("j")?;
    let f = meta("f.txt")?;
    ensure(
        kind_of(fs.open_by_id(&guid, j)) == Some(SysErrorKind::ReparsePoint),
        "I2: a junction opened by ID is ReparsePoint",
    )?;
    ensure(
        kind_of(fs.open_by_id(&guid, f)) == Some(SysErrorKind::InvalidPath),
        "I2: a file opened by ID is InvalidPath",
    )?;
    ensure(
        fs.open_by_id(&guid, 0x7FFF_FFFF_FFFF_FFF0).is_err(),
        "I2: an ID that names nothing is an error",
    )?;
    let nowhere = VolumeGuid::from_u128(0x0123_4567_89ab_cdef_0123_4567_89ab_cdef);
    ensure(
        fs.open_by_id(&nowhere, bi.file_id).is_err(),
        "I2: a GUID of no volume is an error",
    )?;

    // I3.
    let own = ok(w.sd_facts(None), "I3 sd of the handle")?;
    ensure(
        own.kind == EntryKind::Dir && own.links == 1,
        "I3: the handle is a directory",
    )?;
    ensure(
        own.owner.is_some() && own.dacl.as_ref().is_some_and(|d| !d.is_empty()),
        "I3: a folder below target has an owner and a non-empty DACL",
    )?;
    ensure(own.persistent_acls, "I3: persistent ACLs")?;
    let file = ok(w.sd_facts(Some(&rel("f.txt"))), "I3 sd of f.txt")?;
    ensure(
        file.kind == EntryKind::File && file.links == 1 && file.owner.is_some(),
        "I3: a plain file, one link",
    )?;
    ok(
        fx.hardlink(&work.join("f.txt"), &work.join("g.txt")),
        "fixture hardlink",
    )?;
    let linked = ok(w.sd_facts(Some(&rel("f.txt"))), "I3 sd of a linked file")?;
    ensure(linked.links == 2, "I3: a hard link counts")?;
    let junction = ok(w.sd_facts(Some(&rel("j"))), "I3 sd of the junction")?;
    ensure(
        junction.kind == EntryKind::Reparse,
        "I3: a junction is described itself",
    )?;
    ensure(
        kind_of(w.sd_facts(Some(&rel("missing")))) == Some(SysErrorKind::NotFound),
        "I3: a missing entry is NotFound",
    )?;
    ensure(
        kind_of(w.sd_facts(Some(&rel(r"j\b")))) == Some(SysErrorKind::ReparsePoint),
        "I3: never through a junction",
    )?;
    Ok(skips)
}
