//! File system contract, writing side (ADR 0017 and its amendment): `DirWrite` and
//! `FileGuard` against the fake and, from P2-4, `sys::win` in a `TestRoot`. Setup and every
//! move of another program go through the [`FsFixture`]; the case names (W1 …, K1, S8b) are
//! those of `docs/09-testing.md`.

use std::io::{self, Read};
use std::path::Path;

use sha2::{Digest, Sha256};

use super::{
    Access, ContractResult, FsContractResult, FsFixture, Share, Skipped, ensure, err_kind, names,
    ok, open_write, read_is, rel, skip,
};
use crate::sys::SysErrorKind;
use crate::sys::fs::{Attrs, Dir, DirWrite, EntryKind, Fs, NewFile, TmpName};

/// Instance tag of every temp name the contract uses.
const TAG: u64 = 0x00c0_ffee;

fn sha(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// What `create_new` or `replace` must write: `data` with temp name `n`.
fn new_file(n: u64, attrs: Attrs, data: &[u8], max_len: u64) -> NewFile {
    NewFile {
        tmp: TmpName::new(TAG, n),
        attrs,
        sha256: sha(data),
        max_len,
    }
}

fn len_of(data: &[u8]) -> u64 {
    u64::try_from(data.len()).unwrap_or(u64::MAX)
}

/// No temp file (`.rerun-…`) is left in `d`.
fn no_tmp(d: &dyn Dir, what: &str) -> ContractResult {
    let left: Vec<String> = names(d, None, what)?
        .into_iter()
        .filter(|n| n.starts_with(".rerun-"))
        .collect();
    ensure(
        left.is_empty(),
        &format!("{what}: no temp file is left ({left:?})"),
    )
}

/// The entry `p` does not exist.
fn absent(d: &dyn Dir, p: &str, what: &str) -> ContractResult {
    ensure(
        ok(d.metadata(&rel(p)?), what)?.is_none(),
        &format!("{what}: {p} does not exist"),
    )
}

/// Every combination of read-only, hidden and system.
fn all_attrs() -> Vec<Attrs> {
    (0..8u8)
        .map(|b| Attrs {
            readonly: b & 1 != 0,
            hidden: b & 2 != 0,
            system: b & 4 != 0,
        })
        .collect()
}

/// A fresh case directory `work\case`, opened with the write capability.
fn case_dir<'f>(
    fs: &'f dyn Fs,
    fx: &dyn FsFixture,
    work: &Path,
    case: &str,
) -> Result<Box<dyn DirWrite + 'f>, String> {
    ok(fx.dir(&work.join(case)), "fixture case dir")?;
    open_write(fs, &work.join(case), "open case dir")
}

/// A source that fails after its first bytes.
struct Failing(bool);

impl Read for Failing {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if std::mem::replace(&mut self.0, true) {
            return Err(io::Error::other("source failed"));
        }
        let n = buf.len().min(3);
        buf.iter_mut().take(n).for_each(|b| *b = b'x');
        Ok(n)
    }
}

/// File system contract, writing side. `work` must be an existing, empty directory. Setup
/// through `fx`; cases the fixture cannot set up are skipped (`case_sensitive_dir`).
pub fn fs_write_contract(fs: &dyn Fs, fx: &dyn FsFixture, work: &Path) -> FsContractResult {
    let mut skips = Skipped::new();
    let root = ok(fs.open_dir(work), "open work dir")?;
    ensure(
        names(&*root, None, "read_dir work")?.is_empty(),
        "work dir is empty (each contract needs a fresh empty work dir)",
    )?;
    drop(root);
    w1_create_new(fs, fx, work)?;
    w2_existing(fs, fx, work)?;
    w3_refused_sources(fs, fx, work)?;
    w4_planted_tmp(fs, fx, work)?;
    w5_one_segment(fs, fx, work)?;
    w6_spelling(fs, fx, work)?;
    w7_directories(fs, fx, work)?;
    w8_flush(fs, fx, work)?;
    w21_case_sensitive(fs, fx, work, &mut skips)?;
    k1_lock(fs, fx, work)?;
    s8b_remove_dir_held(fs, fx, work)?;
    Ok(skips)
}

/// W1: `create_new` writes what `Written` says, with exactly the requested R/H/S, and leaves
/// no temp file; an empty file and a file of exactly `max_len` bytes.
fn w1_create_new(fs: &dyn Fs, fx: &dyn FsFixture, work: &Path) -> ContractResult {
    let d = case_dir(fs, fx, work, "w1")?;
    for (i, attrs) in all_attrs().into_iter().enumerate() {
        let n = u64::try_from(i).unwrap_or(0);
        let name = format!("f{i}.bin");
        let data = format!("content {i}").into_bytes();
        let what = format!("W1 create_new {name} with {attrs:?}");
        let new = new_file(n, attrs, &data, len_of(&data) + 10);
        let w = ok(d.create_new(&rel(&name)?, &mut &data[..], &new), &what)?;
        let m = ok(d.metadata(&rel(&name)?), &what)?
            .ok_or(format!("contract violated: {what}: file missing"))?;
        ensure(
            w.sha256 == sha(&data) && w.len == len_of(&data) && w.file_id == m.file_id,
            &format!("{what}: Written matches the file"),
        )?;
        ensure(
            m.kind == EntryKind::File
                && m.len == len_of(&data)
                && m.attrs == attrs
                && m.links == Some(1),
            &format!("{what}: metadata (kind, length, R/H/S, one link)"),
        )?;
        read_is(&*d, &name, &data, &what)?;
    }
    let empty = ok(
        d.create_new(
            &rel("empty.bin")?,
            &mut &b""[..],
            &new_file(100, Attrs::default(), b"", 0),
        ),
        "W1 empty file with max_len 0",
    )?;
    ensure(empty.len == 0, "W1 an empty file has length 0")?;
    read_is(&*d, "empty.bin", b"", "W1 empty file")?;
    let full = [7u8; 100];
    ok(
        d.create_new(
            &rel("full.bin")?,
            &mut &full[..],
            &new_file(101, Attrs::default(), &full, 100),
        ),
        "W1 a file of exactly max_len bytes",
    )?;
    read_is(&*d, "full.bin", &full, "W1 file of exactly max_len")?;
    no_tmp(&*d, "W1")
}

/// W2: an existing file or directory (in any case spelling) is `AlreadyExists`; nothing
/// changes, no temp file.
fn w2_existing(fs: &dyn Fs, fx: &dyn FsFixture, work: &Path) -> ContractResult {
    let d = case_dir(fs, fx, work, "w2")?;
    ok(fx.file(&work.join(r"w2\existing.bin"), b"old"), "fixture")?;
    ok(fx.dir(&work.join(r"w2\sub")), "fixture")?;
    for (i, name) in ["existing.bin", "EXISTING.BIN", "sub"]
        .into_iter()
        .enumerate()
    {
        let n = u64::try_from(i).unwrap_or(0);
        err_kind(
            d.create_new(
                &rel(name)?,
                &mut &b"new"[..],
                &new_file(n, Attrs::default(), b"new", 3),
            ),
            SysErrorKind::AlreadyExists,
            &format!("W2 create_new over {name}"),
        )?;
    }
    read_is(
        &*d,
        "existing.bin",
        b"old",
        "W2 the existing file is unchanged",
    )?;
    ensure(
        ok(d.metadata(&rel("sub")?), "W2 metadata sub")?.is_some_and(|m| m.kind == EntryKind::Dir),
        "W2 the existing directory is unchanged",
    )?;
    no_tmp(&*d, "W2")
}

/// W3: a source with another hash is `Mismatch`, one longer than `max_len` `TooLarge` with the
/// bound, a failing source returns its error; the name stays absent, no temp file.
fn w3_refused_sources(fs: &dyn Fs, fx: &dyn FsFixture, work: &Path) -> ContractResult {
    let d = case_dir(fs, fx, work, "w3")?;
    let target = rel("t.bin")?;
    let mut wrong = new_file(1, Attrs::default(), b"expected", 100);
    wrong.sha256 = sha(b"something else");
    err_kind(
        d.create_new(&target, &mut &b"expected"[..], &wrong),
        SysErrorKind::Mismatch,
        "W3 a source with another hash",
    )?;
    absent(&*d, "t.bin", "W3 after Mismatch")?;
    let long = [1u8; 11];
    match d.create_new(
        &target,
        &mut &long[..],
        &new_file(2, Attrs::default(), &long, 10),
    ) {
        Err(e) if e.kind == SysErrorKind::TooLarge && e.limit == Some(10) => {}
        other => {
            return Err(format!(
                "contract violated: W3 a source over max_len: expected TooLarge with limit 10, \
                 got {other:?}"
            ));
        }
    }
    absent(&*d, "t.bin", "W3 after TooLarge")?;
    ensure(
        d.create_new(
            &target,
            &mut Failing(false),
            &new_file(3, Attrs::default(), b"xxx", 100),
        )
        .is_err(),
        "W3 a failing source is an error",
    )?;
    absent(&*d, "t.bin", "W3 after a failing source")?;
    no_tmp(&*d, "W3")
}

/// W4: a file planted under the temp name makes `create_new` `AlreadyExists`; the planted
/// file is unchanged and the name stays absent.
fn w4_planted_tmp(fs: &dyn Fs, fx: &dyn FsFixture, work: &Path) -> ContractResult {
    let d = case_dir(fs, fx, work, "w4")?;
    let new = new_file(7, Attrs::default(), b"data", 4);
    let planted = work.join("w4").join(new.tmp.as_str());
    ok(fx.file(&planted, b"planted"), "fixture planted tmp")?;
    err_kind(
        d.create_new(&rel("t.bin")?, &mut &b"data"[..], &new),
        SysErrorKind::AlreadyExists,
        "W4 create_new with a planted temp name",
    )?;
    absent(&*d, "t.bin", "W4")?;
    read_is(
        &*d,
        new.tmp.as_str(),
        b"planted",
        "W4 the planted file is unchanged",
    )
}

/// W5: every write method takes exactly one segment (`InvalidPath`), also when the path
/// below would exist.
fn w5_one_segment(fs: &dyn Fs, fx: &dyn FsFixture, work: &Path) -> ContractResult {
    let d = case_dir(fs, fx, work, "w5")?;
    ok(fx.file(&work.join(r"w5\a\b.txt"), b"b"), "fixture")?;
    let two = rel(r"a\b.txt")?;
    let ip = SysErrorKind::InvalidPath;
    err_kind(
        d.create_new(
            &two,
            &mut &b"x"[..],
            &new_file(1, Attrs::default(), b"x", 1),
        ),
        ip,
        "W5 create_new",
    )?;
    err_kind(d.create_dir(&two), ip, "W5 create_dir")?;
    err_kind(d.remove_dir(&rel(r"a\c")?, 0), ip, "W5 remove_dir")?;
    err_kind(d.lock(&two), ip, "W5 lock")?;
    read_is(&*d, r"a\b.txt", b"b", "W5 nothing changed")?;
    no_tmp(&*d, "W5")
}

/// W6: names are folded 1:1 per character: `Straße.txt` and `STRASSE.txt` are two files,
/// each keeps its spelling; another case spelling of an existing one is `AlreadyExists`.
fn w6_spelling(fs: &dyn Fs, fx: &dyn FsFixture, work: &Path) -> ContractResult {
    let d = case_dir(fs, fx, work, "w6")?;
    for (i, (name, data)) in [("Straße.txt", b"1"), ("STRASSE.txt", b"2")]
        .into_iter()
        .enumerate()
    {
        let n = u64::try_from(i).unwrap_or(0);
        ok(
            d.create_new(
                &rel(name)?,
                &mut &data[..],
                &new_file(n, Attrs::default(), data, 1),
            ),
            &format!("W6 create_new {name}"),
        )?;
    }
    let mut expected = vec!["STRASSE.txt".to_owned(), "Straße.txt".to_owned()];
    expected.sort();
    ensure(
        names(&*d, None, "W6 listing")? == expected,
        "W6 both names are listed exactly as spelled",
    )?;
    read_is(&*d, "straße.TXT", b"1", "W6 Straße")?;
    read_is(&*d, "strasse.txt", b"2", "W6 STRASSE")?;
    err_kind(
        d.create_new(
            &rel("STRAßE.TXT")?,
            &mut &b"3"[..],
            &new_file(5, Attrs::default(), b"3", 1),
        ),
        SysErrorKind::AlreadyExists,
        "W6 another spelling of Straße.txt",
    )
}

/// W7: `create_dir` returns the ID `metadata` reports and refuses an existing name;
/// `remove_dir` refuses another ID (`Mismatch`), a non-empty directory (`NotEmpty`) and a
/// file (`InvalidPath`), removes by the right ID, and a missing name is `NotFound`.
fn w7_directories(fs: &dyn Fs, fx: &dyn FsFixture, work: &Path) -> ContractResult {
    let d = case_dir(fs, fx, work, "w7")?;
    let made = rel("NewDir")?;
    let id = ok(d.create_dir(&made), "W7 create_dir")?;
    let m = ok(d.metadata(&made), "W7 metadata")?.ok_or("contract violated: W7 dir missing")?;
    ensure(
        m.kind == EntryKind::Dir && m.file_id == id,
        "W7 create_dir returns the directory's file ID",
    )?;
    ensure(
        names(&*d, None, "W7 listing")? == ["NewDir"],
        "W7 the directory keeps its spelling",
    )?;
    err_kind(
        d.create_dir(&rel("newdir")?),
        SysErrorKind::AlreadyExists,
        "W7 create_dir of an existing name",
    )?;
    let other = ok(d.create_dir(&rel("Other")?), "W7 create_dir Other")?;
    err_kind(
        d.remove_dir(&made, other),
        SysErrorKind::Mismatch,
        "W7 remove_dir with another directory's ID",
    )?;
    let full = rel("Full")?;
    let full_id = ok(d.create_dir(&full), "W7 create_dir Full")?;
    ok(fx.file(&work.join(r"w7\Full\x.txt"), b"x"), "fixture")?;
    err_kind(
        d.remove_dir(&full, full_id),
        SysErrorKind::NotEmpty,
        "W7 remove_dir of a non-empty directory",
    )?;
    ok(fx.file(&work.join(r"w7\f.txt"), b"f"), "fixture")?;
    err_kind(
        d.remove_dir(&rel("f.txt")?, 0),
        SysErrorKind::InvalidPath,
        "W7 remove_dir of a file",
    )?;
    ok(d.remove_dir(&rel("NEWDIR")?, id), "W7 remove_dir")?;
    absent(&*d, "NewDir", "W7 after remove_dir")?;
    err_kind(
        d.remove_dir(&made, id),
        SysErrorKind::NotFound,
        "W7 remove_dir of a missing directory",
    )?;
    read_is(&*d, r"Full\x.txt", b"x", "W7 the non-empty directory stays")
}

/// W8: `flush` works on a handle and on a sub handle.
fn w8_flush(fs: &dyn Fs, fx: &dyn FsFixture, work: &Path) -> ContractResult {
    let d = case_dir(fs, fx, work, "w8")?;
    ok(fx.dir(&work.join(r"w8\sub")), "fixture")?;
    ok(d.flush(), "W8 flush")?;
    let sub = ok(d.open_dir_write(&rel("sub")?), "W8 open sub")?;
    ok(sub.flush(), "W8 flush of a sub handle")
}

/// W21: in a case-sensitive directory every write is `Unsupported` and nothing is created,
/// while opening it with the write capability works.
fn w21_case_sensitive(
    fs: &dyn Fs,
    fx: &dyn FsFixture,
    work: &Path,
    skips: &mut Skipped,
) -> ContractResult {
    let cs = work.join("w21");
    if !ok(fx.case_sensitive_dir(&cs), "fixture case-sensitive dir")? {
        skip(skips, "case_sensitive_dir");
        return Ok(());
    }
    let d = open_write(fs, &cs, "W21 open_dir_write of a case-sensitive directory")?;
    let n = rel("x.txt")?;
    let un = SysErrorKind::Unsupported;
    err_kind(
        d.create_new(&n, &mut &b"x"[..], &new_file(1, Attrs::default(), b"x", 1)),
        un,
        "W21 create_new",
    )?;
    err_kind(d.create_dir(&n), un, "W21 create_dir")?;
    err_kind(d.remove_dir(&n, 0), un, "W21 remove_dir")?;
    err_kind(d.flush(), un, "W21 flush")?;
    err_kind(d.lock(&n), un, "W21 lock")?;
    ensure(
        names(&*d, None, "W21 listing")?.is_empty(),
        "W21 nothing was created",
    )
}

/// K1 (ADR 0017, A7): a lock file is opened or created empty under its final name and held
/// with share 0: a second lock, a read and a fixture hold with data access are `Busy`, an
/// attribute-only hold is not; it can be taken again once dropped. An existing file keeps its
/// content. A junction is `ReparsePoint` (nothing created behind it), a directory
/// `AccessDenied`, a file with two links `Linked`.
fn k1_lock(fs: &dyn Fs, fx: &dyn FsFixture, work: &Path) -> ContractResult {
    let d = case_dir(fs, fx, work, "k1")?;
    let name = rel("journal.lock")?;
    let abs = work.join(r"k1\journal.lock");
    let held = ok(d.lock(&name), "K1 lock")?;
    ensure(
        ok(d.metadata(&name), "K1 metadata")?
            .is_some_and(|m| m.kind == EntryKind::File && m.len == 0),
        "K1 the lock file exists and is empty",
    )?;
    err_kind(d.lock(&name), SysErrorKind::Busy, "K1 a second lock")?;
    err_kind(
        d.read(&name),
        SysErrorKind::Busy,
        "K1 a read of the lock file",
    )?;
    err_kind(
        fx.hold_open(&abs, Access::READ, Share::RWD).map(|_| ()),
        SysErrorKind::Busy,
        "K1 another program opening the lock file",
    )?;
    drop(ok(
        fx.hold_open(&abs, Access::ATTRS, Share::RWD),
        "K1 an attribute-only open is never blocked",
    )?);
    drop(held);
    let again = ok(d.lock(&name), "K1 the lock is free once dropped")?;
    drop(again);

    ok(fx.file(&work.join(r"k1\kept.lock"), b"kept"), "fixture")?;
    drop(ok(
        d.lock(&rel("kept.lock")?),
        "K1 lock of an existing file",
    )?);
    read_is(
        &*d,
        "kept.lock",
        b"kept",
        "K1 an existing file keeps its content",
    )?;

    ok(fx.dir(&work.join("k1-target")), "fixture")?;
    ok(
        fx.junction(&work.join(r"k1\link.lock"), &work.join("k1-target")),
        "fixture junction",
    )?;
    err_kind(
        d.lock(&rel("link.lock")?).map(|_| ()),
        SysErrorKind::ReparsePoint,
        "K1 lock of a junction",
    )?;
    let root = ok(fs.open_dir(work), "open work")?;
    ensure(
        names(&*root, Some(&rel("k1-target")?), "K1 junction target")?.is_empty(),
        "K1 nothing is created behind a junction",
    )?;
    ok(fx.dir(&work.join(r"k1\dir.lock")), "fixture")?;
    err_kind(
        d.lock(&rel("dir.lock")?).map(|_| ()),
        SysErrorKind::AccessDenied,
        "K1 lock of a directory",
    )?;
    ok(fx.file(&work.join(r"k1\a.lock"), b""), "fixture")?;
    ok(
        fx.hardlink(&work.join(r"k1\a.lock"), &work.join(r"k1\b.lock")),
        "fixture hard link",
    )?;
    err_kind(
        d.lock(&rel("a.lock")?).map(|_| ()),
        SysErrorKind::Linked,
        "K1 lock of a file with two links",
    )
}

/// S8b: `remove_dir` is `Busy` while another program holds the directory without
/// share-delete, and works once it is closed.
fn s8b_remove_dir_held(fs: &dyn Fs, fx: &dyn FsFixture, work: &Path) -> ContractResult {
    let d = case_dir(fs, fx, work, "s8b")?;
    let name = rel("held")?;
    let id = ok(d.create_dir(&name), "S8b create_dir")?;
    let hold = ok(
        fx.hold_open(&work.join(r"s8b\held"), Access::READ, Share::RW),
        "S8b hold without share-delete",
    )?;
    err_kind(
        d.remove_dir(&name, id),
        SysErrorKind::Busy,
        "S8b remove_dir of a held directory",
    )?;
    drop(hold);
    ok(
        d.remove_dir(&name, id),
        "S8b remove_dir once the hold is closed",
    )?;
    absent(&*d, "held", "S8b")
}
