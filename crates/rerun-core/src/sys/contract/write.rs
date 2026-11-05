//! File system contract, writing side (ADR 0017 and its amendment): `DirWrite` and
//! `FileGuard` against the fake and `sys::win` in a `TestRoot`. Setup and every
//! move of another program go through the [`FsFixture`]; the case names (W1 …, K1, S8b) are
//! those of `docs/09-testing.md`.

use std::io::{self, Read};
use std::path::Path;
use std::time::{Duration, Instant};

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
    w9_guard_refusals(fs, fx, work, &mut skips)?;
    w10_guard_reads(fs, fx, work)?;
    w11_replace_refused(fs, fx, work)?;
    w12_replace(fs, fx, work)?;
    w13_planted_old(fs, fx, work)?;
    w14_delete(fs, fx, work)?;
    w15_rename_to(fs, fx, work)?;
    w16_guard_holds(fs, fx, work)?;
    w17_guard_and_readers(fs, fx, work)?;
    w18_folder_held(fs, fx, work)?;
    w18b_folder_held_for_delete(fs, fx, work)?;
    w22_guard_blocks_ancestor(fs, fx, work)?;
    w23_handle_follows(fs, fx, work)?;
    s2_changes_under_a_guard(fs, fx, work)?;
    s8a_delete_in_held_folder(fs, fx, work)?;
    w19_mapped_image(fs, fx, work, &mut skips)?;
    w20_delete_pending(fs, fx, work, &mut skips)?;
    Ok(skips)
}

/// W19: an image-mapped file (no handle) is reported by `users`; `replace` succeeds with the
/// old content left as `<tmp>.old` (`old_left`, step 8 refused); deleting `.old` stays `Busy`
/// until the mapping is gone, then works. An image section without a handle does not block
/// renaming a folder above it (observed on Windows 11 build 26300, unlike a handle, A5).
fn w19_mapped_image(
    fs: &dyn Fs,
    fx: &dyn FsFixture,
    work: &Path,
    skips: &mut Skipped,
) -> ContractResult {
    let d = case_dir(fs, fx, work, "w19")?;
    let Some(map) = ok(
        fx.mapped_image(&work.join(r"w19\game.exe")),
        "fixture image",
    )?
    else {
        skip(skips, "mapped_image");
        return Ok(());
    };
    let exe = rel("game.exe")?;
    ensure(
        !ok(d.users(&exe), "W19 users")?.is_empty(),
        "W19 users reports an image-mapped file",
    )?;
    let mut g = ok(d.guard(&exe), "W19 guard")?;
    let h0 = ok(g.sha256(), "W19 sha256")?;
    let new = new_file(1, Attrs::default(), b"new exe", 7);
    let r = ok(
        g.replace(&h0, &mut &b"new exe"[..], &new),
        "W19 replace of a mapped image",
    )?;
    ensure(
        r.old_left.as_ref() == Some(&new.tmp),
        "W19 the old image is left as pending cleanup",
    )?;
    read_is(
        &*d,
        "game.exe",
        b"new exe",
        "W19 the new content is in place",
    )?;
    let old = new.tmp.old();
    let mut g = ok(d.guard(&old), "W19 guard .old")?;
    ensure(ok(g.sha256(), "W19 .old hash")? == h0, "W19 .old holds h0")?;
    err_kind(
        g.delete(&h0),
        SysErrorKind::Busy,
        "W19 delete of .old while it is mapped",
    )?;
    drop(map);
    let g = ok(d.guard(&old), "W19 guard .old after the mapping")?;
    ok(g.delete(&h0), "W19 delete of .old once the mapping is gone")?;
    ensure(
        names(&*d, None, "W19 listing")? == ["game.exe"],
        "W19 nothing is left",
    )?;
    let lib = ok(
        fx.mapped_image(&work.join(r"w19-anc\sub\lib.dll")),
        "fixture image below a folder",
    )?
    .ok_or("contract violated: W19 the fixture maps one image but not a second")?;
    ok(
        rename_settled(fx, &work.join("w19-anc"), &work.join("w19-anc2")),
        "W19 renaming an ancestor of an image-mapped file",
    )?;
    drop(lib);
    Ok(())
}

/// How long [`rename_settled`] retries.
const SETTLE: Duration = Duration::from_secs(10);

/// A fixture rename of a folder above a freshly written file, retried while it is
/// `AccessDenied` or `Busy` for at most [`SETTLE`]: a virus scanner reading the new file holds
/// a handle below the folder for a moment, and any handle blocks the rename (A5). What the
/// caller asserts (a mapping it still holds does not block) is unaffected: a blocking mapping
/// would block until it is gone, so the rename would never succeed within the retries.
fn rename_settled(fx: &dyn FsFixture, from: &Path, to: &Path) -> crate::sys::SysResult<()> {
    let started = Instant::now();
    loop {
        match fx.rename(from, to) {
            Err(e)
                if matches!(e.kind, SysErrorKind::AccessDenied | SysErrorKind::Busy)
                    && started.elapsed() < SETTLE =>
            {
                std::thread::sleep(Duration::from_millis(20));
            }
            r => return r,
        }
    }
}

/// W20 and A6: a name in legacy delete-pending state cannot be opened at all: `metadata`,
/// `read`, `open_read`, `users`, `guard`, `lock` and `create_new` are `Busy`, `read_dir` skips
/// it. Once the other handle closes, the name is free.
fn w20_delete_pending(
    fs: &dyn Fs,
    fx: &dyn FsFixture,
    work: &Path,
    skips: &mut Skipped,
) -> ContractResult {
    let d = case_dir(fs, fx, work, "w20")?;
    ok(fx.file(&work.join(r"w20\keep.bin"), b"keep"), "fixture")?;
    let Some(pending) = ok(
        fx.delete_pending(&work.join(r"w20\gone.bin")),
        "fixture delete pending",
    )?
    else {
        skip(skips, "delete_pending");
        return Ok(());
    };
    let p = rel("gone.bin")?;
    let busy = SysErrorKind::Busy;
    err_kind(d.metadata(&p), busy, "A6 metadata")?;
    err_kind(d.read(&p), busy, "A6 read")?;
    err_kind(d.open_read(&p).map(|_| ()), busy, "A6 open_read")?;
    err_kind(d.users(&p), busy, "A6 users")?;
    err_kind(d.guard(&p).map(|_| ()), busy, "W20 guard")?;
    err_kind(d.lock(&p).map(|_| ()), busy, "A6 lock")?;
    err_kind(
        d.create_new(&p, &mut &b"x"[..], &new_file(1, Attrs::default(), b"x", 1)),
        busy,
        "W20 create_new",
    )?;
    ensure(
        names(&*d, None, "A6 listing")? == ["keep.bin"],
        "A6 read_dir skips a delete-pending entry",
    )?;
    drop(pending);
    absent(&*d, "gone.bin", "W20 once the other handle is closed")?;
    ok(
        d.create_new(&p, &mut &b"x"[..], &new_file(2, Attrs::default(), b"x", 1)),
        "W20 create_new once the name is free",
    )?;
    no_tmp(&*d, "W20")
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
    err_kind(d.guard(&two).map(|_| ()), ip, "W5 guard")?;
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
    )?;
    // The guard finds a name only by its 1:1 folding and replaces under the stored spelling.
    let g6 = case_dir(fs, fx, work, "w6g")?;
    ok(fx.file(&work.join(r"w6g\Straße.txt"), b"old"), "fixture")?;
    err_kind(
        g6.guard(&rel("STRASSE.txt")?).map(|_| ()),
        SysErrorKind::NotFound,
        "W6 guard of STRASSE.txt when only Straße.txt exists",
    )?;
    let g = ok(g6.guard(&rel("straße.TXT")?), "W6 guard in another case")?;
    ok(
        g.replace(
            &sha(b"old"),
            &mut &b"new"[..],
            &new_file(6, Attrs::default(), b"new", 3),
        ),
        "W6 replace through another case",
    )?;
    ensure(
        names(&*g6, None, "W6 listing")? == ["Straße.txt"],
        "W6 replace keeps the stored spelling",
    )?;
    read_is(&*g6, "Straße.txt", b"new", "W6 replaced")
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
    err_kind(d.guard(&n).map(|_| ()), un, "W21 guard")?;
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

/// W9: the guard refuses a directory (`AccessDenied`), a missing name (`NotFound`), a
/// restricted file (`AccessDenied`) and a file with two links (`Linked`, both unchanged); once
/// the second link is gone, it opens.
fn w9_guard_refusals(
    fs: &dyn Fs,
    fx: &dyn FsFixture,
    work: &Path,
    skips: &mut Skipped,
) -> ContractResult {
    let d = case_dir(fs, fx, work, "w9")?;
    ok(fx.dir(&work.join(r"w9\dir")), "fixture")?;
    err_kind(
        d.guard(&rel("dir")?).map(|_| ()),
        SysErrorKind::AccessDenied,
        "W9 guard of a directory",
    )?;
    err_kind(
        d.guard(&rel("missing")?).map(|_| ()),
        SysErrorKind::NotFound,
        "W9 guard of a missing file",
    )?;
    ok(fx.file(&work.join(r"w9\a.bin"), b"a"), "fixture")?;
    ok(
        fx.hardlink(&work.join(r"w9\a.bin"), &work.join(r"w9\b.bin")),
        "fixture hard link",
    )?;
    for n in ["a.bin", "b.bin"] {
        err_kind(
            d.guard(&rel(n)?).map(|_| ()),
            SysErrorKind::Linked,
            &format!("W9 guard of {n} with two links"),
        )?;
        read_is(&*d, n, b"a", "W9 a linked file is unchanged")?;
    }
    ok(fx.remove(&work.join(r"w9\b.bin")), "fixture remove link")?;
    drop(ok(
        d.guard(&rel("a.bin")?),
        "W9 guard once the second link is gone",
    )?);
    let r_abs = work.join(r"w9\r.bin");
    ok(fx.file(&r_abs, b"r"), "fixture")?;
    if ok(fx.restricted(&r_abs), "fixture restricted")? {
        err_kind(
            d.guard(&rel("r.bin")?).map(|_| ()),
            SysErrorKind::AccessDenied,
            "W9 guard of a restricted file",
        )?;
    } else {
        skip(skips, "restricted");
    }
    Ok(())
}

/// W10: the guard's metadata is `Dir::metadata`; its hash is right and stable; its reader
/// starts at offset 0, also after hashing.
fn w10_guard_reads(fs: &dyn Fs, fx: &dyn FsFixture, work: &Path) -> ContractResult {
    let d = case_dir(fs, fx, work, "w10")?;
    let data = b"guarded content";
    let abs = work.join(r"w10\g.bin");
    ok(fx.file(&abs, data), "fixture")?;
    let hidden = Attrs {
        hidden: true,
        ..Attrs::default()
    };
    ok(fx.set_attrs(&abs, hidden), "fixture attrs")?;
    let mut g = ok(d.guard(&rel("G.BIN")?), "W10 guard")?;
    let dm = ok(d.metadata(&rel("g.bin")?), "W10 metadata")?
        .ok_or("contract violated: W10 file missing")?;
    ensure(
        ok(g.metadata(), "W10 guard metadata")? == dm,
        "W10 the guard's metadata equals Dir::metadata",
    )?;
    ensure(
        ok(g.sha256(), "W10 sha256")? == sha(data)
            && ok(g.sha256(), "W10 sha256 again")? == sha(data),
        "W10 the guard's hash is right and stable",
    )?;
    for round in 0..2 {
        let mut got = Vec::new();
        ok(g.reader(), "W10 reader")?
            .read_to_end(&mut got)
            .map_err(|e| format!("contract violated: W10 reader: {e}"))?;
        ensure(
            got == data,
            &format!("W10 the reader starts at offset 0 (round {round})"),
        )?;
    }
    Ok(())
}

/// W11: `replace` with another expected hash, a source with another hash, a source over
/// `max_len` and an unchanged content (A2: `Unsupported`) changes nothing; no temp file and
/// no `.old` are left.
fn w11_replace_refused(fs: &dyn Fs, fx: &dyn FsFixture, work: &Path) -> ContractResult {
    let d = case_dir(fs, fx, work, "w11")?;
    ok(fx.file(&work.join(r"w11\t.bin"), b"old"), "fixture")?;
    let t = rel("t.bin")?;
    let id0 = ok(d.metadata(&t), "W11 metadata")?
        .ok_or("contract violated: W11 missing")?
        .file_id;
    let g = ok(d.guard(&t), "W11 guard")?;
    err_kind(
        g.replace(
            &sha(b"other"),
            &mut &b"new"[..],
            &new_file(1, Attrs::default(), b"new", 3),
        ),
        SysErrorKind::Mismatch,
        "W11 replace with another expected hash",
    )?;
    let g = ok(d.guard(&t), "W11 guard")?;
    let mut wrong = new_file(2, Attrs::default(), b"new", 3);
    wrong.sha256 = sha(b"else");
    err_kind(
        g.replace(&sha(b"old"), &mut &b"new"[..], &wrong),
        SysErrorKind::Mismatch,
        "W11 replace with a source of another hash",
    )?;
    let g = ok(d.guard(&t), "W11 guard")?;
    let long = [1u8; 11];
    err_kind(
        g.replace(
            &sha(b"old"),
            &mut &long[..],
            &new_file(3, Attrs::default(), &long, 10),
        ),
        SysErrorKind::TooLarge,
        "W11 replace with a source over max_len",
    )?;
    let g = ok(d.guard(&t), "W11 guard")?;
    err_kind(
        g.replace(
            &sha(b"old"),
            &mut &b"old"[..],
            &new_file(4, Attrs::default(), b"old", 3),
        ),
        SysErrorKind::Unsupported,
        "W11 replace with the same content (A2)",
    )?;
    read_is(&*d, "t.bin", b"old", "W11 unchanged")?;
    ensure(
        ok(d.metadata(&t), "W11 metadata after")?.is_some_and(|m| m.file_id == id0),
        "W11 the file is the same object",
    )?;
    ensure(
        names(&*d, None, "W11 listing")? == ["t.bin"],
        "W11 no temp file and no .old left",
    )
}

/// W12: `replace` writes the new content with exactly the requested R/H/S as a new file whose
/// ID `Written` reports, also over a read-only target; nothing is left pending.
fn w12_replace(fs: &dyn Fs, fx: &dyn FsFixture, work: &Path) -> ContractResult {
    let d = case_dir(fs, fx, work, "w12")?;
    let mut expected = Vec::new();
    for (i, attrs) in all_attrs().into_iter().enumerate() {
        let n = u64::try_from(i).unwrap_or(0);
        let name = format!("t{i}.bin");
        let abs = work.join("w12").join(&name);
        ok(fx.file(&abs, b"old"), "fixture")?;
        let read_only = i % 2 == 1;
        if read_only {
            let ro = Attrs {
                readonly: true,
                ..Attrs::default()
            };
            ok(fx.set_attrs(&abs, ro), "fixture read-only target")?;
        }
        let what = format!("W12 replace {name} (target read-only: {read_only}) with {attrs:?}");
        let id0 = ok(d.metadata(&rel(&name)?), &what)?
            .ok_or(format!("contract violated: {what}: missing"))?
            .file_id;
        let data = format!("new {i}").into_bytes();
        let g = ok(d.guard(&rel(&name)?), &what)?;
        let r = ok(
            g.replace(
                &sha(b"old"),
                &mut &data[..],
                &new_file(10 + n, attrs, &data, 100),
            ),
            &what,
        )?;
        let m = ok(d.metadata(&rel(&name)?), &what)?
            .ok_or(format!("contract violated: {what}: missing after"))?;
        ensure(
            r.old_left.is_none() && r.new.sha256 == sha(&data) && r.new.len == len_of(&data),
            &format!("{what}: Replaced reports the new file, nothing pending"),
        )?;
        ensure(
            m.file_id == r.new.file_id && m.file_id != id0 && m.attrs == attrs,
            &format!("{what}: a new file with the requested R/H/S"),
        )?;
        read_is(&*d, &name, &data, &what)?;
        expected.push(name);
    }
    expected.sort();
    ensure(
        names(&*d, None, "W12 listing")? == expected,
        "W12 no temp file and no .old left",
    )
}

/// No temp file is left in `d` except `allowed`.
fn no_tmp_but(d: &dyn Dir, allowed: &[&str], what: &str) -> ContractResult {
    let left: Vec<String> = names(d, None, what)?
        .into_iter()
        .filter(|n| n.starts_with(".rerun-") && !allowed.contains(&n.as_str()))
        .collect();
    ensure(
        left.is_empty(),
        &format!("{what}: no temp file is left ({left:?})"),
    )
}

/// W13: a file planted at `<tmp>.old` makes `replace` `Busy` at step 6: the target (ID, hash)
/// and the planted file are unchanged, no temp file is left.
fn w13_planted_old(fs: &dyn Fs, fx: &dyn FsFixture, work: &Path) -> ContractResult {
    let d = case_dir(fs, fx, work, "w13")?;
    ok(fx.file(&work.join(r"w13\t.bin"), b"old"), "fixture")?;
    let new = new_file(1, Attrs::default(), b"new", 3);
    let old = new.tmp.old();
    ok(
        fx.file(&work.join("w13").join(old.as_str()), b"planted"),
        "fixture planted .old",
    )?;
    let t = rel("t.bin")?;
    let id0 = ok(d.metadata(&t), "W13")?
        .ok_or("contract violated: W13 missing")?
        .file_id;
    let g = ok(d.guard(&t), "W13 guard")?;
    err_kind(
        g.replace(&sha(b"old"), &mut &b"new"[..], &new),
        SysErrorKind::Busy,
        "W13 replace with a planted .old",
    )?;
    read_is(&*d, "t.bin", b"old", "W13 target unchanged")?;
    ensure(
        ok(d.metadata(&t), "W13 after")?.is_some_and(|m| m.file_id == id0),
        "W13 the target is the same object",
    )?;
    read_is(
        &*d,
        old.as_str(),
        b"planted",
        "W13 the planted file is unchanged",
    )?;
    no_tmp_but(&*d, &[old.as_str()], "W13")
}

/// W14: `delete` with another hash is `Mismatch`; with the right one the name is free at
/// once, also while another program still holds the file (sharing delete), and a read-only
/// file is deleted too.
fn w14_delete(fs: &dyn Fs, fx: &dyn FsFixture, work: &Path) -> ContractResult {
    let d = case_dir(fs, fx, work, "w14")?;
    let abs = work.join(r"w14\t.bin");
    ok(fx.file(&abs, b"old"), "fixture")?;
    let t = rel("t.bin")?;
    let g = ok(d.guard(&t), "W14 guard")?;
    err_kind(
        g.delete(&sha(b"other")),
        SysErrorKind::Mismatch,
        "W14 delete with another hash",
    )?;
    read_is(&*d, "t.bin", b"old", "W14 unchanged after Mismatch")?;
    let hold = ok(
        fx.hold_open(&abs, Access::READ, Share::RWD),
        "W14 another program holds the file",
    )?;
    let g = ok(d.guard(&t), "W14 guard while held")?;
    ok(g.delete(&sha(b"old")), "W14 delete")?;
    absent(&*d, "t.bin", "W14 the name is free at once")?;
    ok(
        d.create_new(
            &t,
            &mut &b"fresh"[..],
            &new_file(1, Attrs::default(), b"fresh", 5),
        ),
        "W14 create_new of the freed name while the old file is still held",
    )?;
    drop(hold);
    read_is(&*d, "t.bin", b"fresh", "W14 the new file")?;
    let ro_abs = work.join(r"w14\ro.bin");
    ok(fx.file(&ro_abs, b"ro"), "fixture")?;
    let ro = Attrs {
        readonly: true,
        ..Attrs::default()
    };
    ok(fx.set_attrs(&ro_abs, ro), "fixture read-only")?;
    let g = ok(d.guard(&rel("ro.bin")?), "W14 guard read-only")?;
    ok(g.delete(&sha(b"ro")), "W14 delete of a read-only file")?;
    absent(&*d, "ro.bin", "W14 the read-only file is gone")?;
    no_tmp(&*d, "W14")
}

/// W15: `rename_to` moves the held file to a free name (same object); onto an existing name
/// (any spelling) it is `Busy` and nothing changes; two segments are `InvalidPath`.
fn w15_rename_to(fs: &dyn Fs, fx: &dyn FsFixture, work: &Path) -> ContractResult {
    let d = case_dir(fs, fx, work, "w15")?;
    ok(fx.file(&work.join(r"w15\a.bin"), b"a"), "fixture")?;
    ok(fx.file(&work.join(r"w15\b.bin"), b"b"), "fixture")?;
    let a = rel("a.bin")?;
    let id = ok(d.metadata(&a), "W15")?
        .ok_or("contract violated: W15 missing")?
        .file_id;
    let g = ok(d.guard(&a), "W15 guard")?;
    err_kind(
        g.rename_to(&rel("B.BIN")?),
        SysErrorKind::Busy,
        "W15 rename_to an existing name",
    )?;
    read_is(&*d, "a.bin", b"a", "W15 a unchanged")?;
    read_is(&*d, "b.bin", b"b", "W15 b unchanged")?;
    let g = ok(d.guard(&a), "W15 guard")?;
    err_kind(
        g.rename_to(&rel(r"sub\c.bin")?),
        SysErrorKind::InvalidPath,
        "W15 rename_to two segments",
    )?;
    let g = ok(d.guard(&a), "W15 guard")?;
    ok(g.rename_to(&rel("c.bin")?), "W15 rename_to")?;
    absent(&*d, "a.bin", "W15 the old name is gone")?;
    ensure(
        ok(d.metadata(&rel("c.bin")?), "W15 metadata c")?.is_some_and(|m| m.file_id == id),
        "W15 the same object under the new name",
    )?;
    read_is(&*d, "c.bin", b"a", "W15 content")
}

/// W16: while a guard is held, another program can neither overwrite, rename nor remove the
/// file, nor open it for read without share-delete (`Busy`); a read sharing delete and
/// `metadata` work; our own `open_read` (sharing read only) is `Busy`. `Dir::users` reports
/// the guard, `FileGuard::users` does not count the guard itself.
fn w16_guard_holds(fs: &dyn Fs, fx: &dyn FsFixture, work: &Path) -> ContractResult {
    let d = case_dir(fs, fx, work, "w16")?;
    let abs = work.join(r"w16\t.bin");
    ok(fx.file(&abs, b"held"), "fixture")?;
    let t = rel("t.bin")?;
    let me = std::process::id();
    let g = ok(d.guard(&t), "W16 guard")?;
    let busy = SysErrorKind::Busy;
    err_kind(fx.file(&abs, b"x"), busy, "W16 overwrite while guarded")?;
    err_kind(
        fx.rename(&abs, &work.join(r"w16\u.bin")),
        busy,
        "W16 rename while guarded",
    )?;
    err_kind(fx.remove(&abs), busy, "W16 remove while guarded")?;
    err_kind(
        fx.hold_open(&abs, Access::READ, Share::R).map(|_| ()),
        busy,
        "W16 a read without share-delete while guarded",
    )?;
    let rd = ok(
        fx.hold_open(&abs, Access::READ, Share::RD),
        "W16 a read sharing delete while guarded",
    )?;
    drop(rd);
    err_kind(
        d.open_read(&t).map(|_| ()),
        busy,
        "W16 open_read (shares read only) while guarded",
    )?;
    ensure(
        ok(d.metadata(&t), "W16 metadata")?.is_some_and(|m| m.len == 4),
        "W16 metadata while guarded",
    )?;
    ensure(
        ok(d.users(&t), "W16 Dir::users")?.contains(&me),
        "W16 Dir::users reports the guard",
    )?;
    ensure(
        !ok(g.users(), "W16 FileGuard::users")?.contains(&me),
        "W16 FileGuard::users does not count the guard itself",
    )?;
    drop(g);
    read_is(&*d, "t.bin", b"held", "W16 nothing changed")?;
    ensure(
        names(&*d, None, "W16 listing")? == ["t.bin"],
        "W16 nothing was renamed or added",
    )
}

/// W17: our own `open_read` reader makes the guard `Busy`; another program's read sharing
/// delete does not, and `replace` works while it stays open.
fn w17_guard_and_readers(fs: &dyn Fs, fx: &dyn FsFixture, work: &Path) -> ContractResult {
    let d = case_dir(fs, fx, work, "w17")?;
    let abs = work.join(r"w17\t.bin");
    ok(fx.file(&abs, b"old"), "fixture")?;
    let t = rel("t.bin")?;
    let reader = ok(d.open_read(&t), "W17 open_read")?;
    err_kind(
        d.guard(&t).map(|_| ()),
        SysErrorKind::Busy,
        "W17 guard while our reader is open",
    )?;
    drop(reader);
    let hold = ok(
        fx.hold_open(&abs, Access::READ, Share::RD),
        "W17 another program reads, sharing delete",
    )?;
    let g = ok(d.guard(&t), "W17 guard while the read is open")?;
    let r = ok(
        g.replace(
            &sha(b"old"),
            &mut &b"new"[..],
            &new_file(1, Attrs::default(), b"new", 3),
        ),
        "W17 replace while the read is open",
    )?;
    ensure(r.old_left.is_none(), "W17 nothing pending")?;
    read_is(&*d, "t.bin", b"new", "W17 replaced")?;
    drop(hold);
    ensure(
        names(&*d, None, "W17 listing")? == ["t.bin"],
        "W17 no temp file and no .old left",
    )
}

/// W18: while another program holds the folder without share-write, renames into it are
/// `Busy`: `replace` changes nothing, `create_new` leaves the name absent, no temp file.
fn w18_folder_held(fs: &dyn Fs, fx: &dyn FsFixture, work: &Path) -> ContractResult {
    let d = case_dir(fs, fx, work, "w18")?;
    ok(fx.file(&work.join(r"w18\t.bin"), b"old"), "fixture")?;
    let t = rel("t.bin")?;
    let id0 = ok(d.metadata(&t), "W18")?
        .ok_or("contract violated: W18 missing")?
        .file_id;
    let hold = ok(
        fx.hold_open(&work.join("w18"), Access::READ, Share::RD),
        "W18 another program holds the folder without share-write",
    )?;
    let g = ok(d.guard(&t), "W18 guard")?;
    err_kind(
        g.replace(
            &sha(b"old"),
            &mut &b"new"[..],
            &new_file(1, Attrs::default(), b"new", 3),
        ),
        SysErrorKind::Busy,
        "W18 replace in a held folder",
    )?;
    read_is(&*d, "t.bin", b"old", "W18 unchanged")?;
    ensure(
        ok(d.metadata(&t), "W18 after")?.is_some_and(|m| m.file_id == id0),
        "W18 the same object",
    )?;
    err_kind(
        d.create_new(
            &rel("n.bin")?,
            &mut &b"n"[..],
            &new_file(2, Attrs::default(), b"n", 1),
        ),
        SysErrorKind::Busy,
        "W18 create_new in a held folder",
    )?;
    absent(&*d, "n.bin", "W18")?;
    no_tmp(&*d, "W18 while held")?;
    drop(hold);
    no_tmp(&*d, "W18")
}

/// W18b: a folder held by another program with delete access (sharing everything, or read
/// and write only) does not block renames into it: `create_new` and `replace` work (observed
/// on Windows 11 build 26300: the target-directory open of a rename does not ask for delete).
fn w18b_folder_held_for_delete(fs: &dyn Fs, fx: &dyn FsFixture, work: &Path) -> ContractResult {
    let d = case_dir(fs, fx, work, "w18b")?;
    for (i, share) in [Share::RWD, Share::RW].into_iter().enumerate() {
        let n = u64::try_from(i).unwrap_or(0) * 2;
        let name = format!("t{i}.bin");
        ok(fx.file(&work.join("w18b").join(&name), b"old"), "fixture")?;
        let what = format!("W18b folder held for delete, {share:?}");
        let hold = ok(
            fx.hold_open(&work.join("w18b"), Access::DELETE, share),
            &what,
        )?;
        ok(
            d.create_new(
                &rel(&format!("n{i}.bin"))?,
                &mut &b"n"[..],
                &new_file(n, Attrs::default(), b"n", 1),
            ),
            &format!("{what}: create_new"),
        )?;
        let g = ok(d.guard(&rel(&name)?), &what)?;
        ok(
            g.replace(
                &sha(b"old"),
                &mut &b"new"[..],
                &new_file(n + 1, Attrs::default(), b"new", 3),
            ),
            &format!("{what}: replace"),
        )?;
        drop(hold);
        read_is(&*d, &name, b"new", &what)?;
    }
    no_tmp(&*d, "W18b")
}

/// W22: an ancestor of a guarded file cannot be renamed (`AccessDenied`, A5) while the guard
/// is held; afterwards it can.
fn w22_guard_blocks_ancestor(fs: &dyn Fs, fx: &dyn FsFixture, work: &Path) -> ContractResult {
    let d = case_dir(fs, fx, work, "w22")?;
    ok(fx.file(&work.join(r"w22\sub\t.bin"), b"t"), "fixture")?;
    let sub = ok(d.open_dir_write(&rel("sub")?), "W22 open sub")?;
    let g = ok(sub.guard(&rel("t.bin")?), "W22 guard")?;
    err_kind(
        fx.rename(&work.join(r"w22\sub"), &work.join(r"w22\sub2")),
        SysErrorKind::AccessDenied,
        "W22 renaming the folder of a guarded file",
    )?;
    drop(g);
    ok(
        fx.rename(&work.join(r"w22\sub"), &work.join(r"w22\sub2")),
        "W22 rename once the guard is closed",
    )?;
    read_is(&*sub, "t.bin", b"t", "W22 the handle follows its folder")
}

/// W23: a write handle stays on its folder: renamed, with a new folder planted at the old
/// name, `create_new` lands in the renamed folder.
fn w23_handle_follows(fs: &dyn Fs, fx: &dyn FsFixture, work: &Path) -> ContractResult {
    let d = case_dir(fs, fx, work, "w23")?;
    ok(fx.dir(&work.join(r"w23\sub")), "fixture")?;
    let sub = ok(d.open_dir_write(&rel("sub")?), "W23 open sub")?;
    ok(
        fx.rename(&work.join(r"w23\sub"), &work.join(r"w23\sub-moved")),
        "W23 rename the handle's own folder",
    )?;
    ok(fx.dir(&work.join(r"w23\sub")), "W23 plant a new folder")?;
    ok(
        sub.create_new(
            &rel("x.bin")?,
            &mut &b"x"[..],
            &new_file(1, Attrs::default(), b"x", 1),
        ),
        "W23 create_new through the handle",
    )?;
    read_is(
        &*d,
        r"sub-moved\x.bin",
        b"x",
        "W23 lands in the renamed folder",
    )?;
    absent(&*d, r"sub\x.bin", "W23 nothing in the planted folder")
}

/// S2 (A4): another program may change R/H/S of a guarded file and add a hard link to it
/// (both observed allowed on Windows); `replace` then refuses at its re-check (`Mismatch`,
/// `Linked`) and nothing is renamed; `delete` after an attribute change is `Mismatch`.
fn s2_changes_under_a_guard(fs: &dyn Fs, fx: &dyn FsFixture, work: &Path) -> ContractResult {
    let d = case_dir(fs, fx, work, "s2")?;
    let abs = work.join(r"s2\t.bin");
    ok(fx.file(&abs, b"old"), "fixture")?;
    let t = rel("t.bin")?;
    let hidden = Attrs {
        hidden: true,
        ..Attrs::default()
    };
    let g = ok(d.guard(&t), "S2 guard")?;
    ok(
        fx.set_attrs(&abs, hidden),
        "S2 another program sets attributes of a guarded file",
    )?;
    err_kind(
        g.replace(
            &sha(b"old"),
            &mut &b"new"[..],
            &new_file(1, Attrs::default(), b"new", 3),
        ),
        SysErrorKind::Mismatch,
        "S2 replace after an attribute change",
    )?;
    read_is(&*d, "t.bin", b"old", "S2 unchanged after Mismatch")?;
    ensure(
        names(&*d, None, "S2 listing")? == ["t.bin"],
        "S2 nothing renamed, no temp file",
    )?;
    let g = ok(d.guard(&t), "S2 guard again")?;
    ok(
        fx.hardlink(&abs, &work.join(r"s2\link.bin")),
        "S2 another program adds a hard link to a guarded file",
    )?;
    err_kind(
        g.replace(
            &sha(b"old"),
            &mut &b"new"[..],
            &new_file(2, Attrs::default(), b"new", 3),
        ),
        SysErrorKind::Linked,
        "S2 replace after a hard link was added",
    )?;
    read_is(&*d, "t.bin", b"old", "S2 unchanged after Linked")?;
    read_is(&*d, "link.bin", b"old", "S2 the new link is unchanged")?;
    let d_abs = work.join(r"s2\d.bin");
    ok(fx.file(&d_abs, b"d"), "fixture")?;
    let g = ok(d.guard(&rel("d.bin")?), "S2 guard d")?;
    ok(fx.set_attrs(&d_abs, hidden), "S2 attributes of d")?;
    err_kind(
        g.delete(&sha(b"d")),
        SysErrorKind::Mismatch,
        "S2 delete after an attribute change",
    )?;
    read_is(&*d, "d.bin", b"d", "S2 d is still there")?;
    no_tmp(&*d, "S2")
}

/// S8a: `FileGuard::delete` needs nothing from the folder: it works while another program
/// holds the folder without share-write.
fn s8a_delete_in_held_folder(fs: &dyn Fs, fx: &dyn FsFixture, work: &Path) -> ContractResult {
    let d = case_dir(fs, fx, work, "s8a")?;
    ok(fx.file(&work.join(r"s8a\t.bin"), b"t"), "fixture")?;
    let hold = ok(
        fx.hold_open(&work.join("s8a"), Access::READ, Share::RD),
        "S8a hold the folder without share-write",
    )?;
    let g = ok(d.guard(&rel("t.bin")?), "S8a guard")?;
    ok(g.delete(&sha(b"t")), "S8a delete in a held folder")?;
    absent(&*d, "t.bin", "S8a")?;
    drop(hold);
    Ok(())
}

/// File system contract for links on the writing side: nothing is ever written through a
/// junction or symlink, and a write handle stays on its folder when it is swapped for a
/// junction. `work` must be an existing, empty directory. Cases the fixture cannot set up are
/// skipped (`dir_symlink`, `file_symlink`).
pub fn fs_link_write_contract(fs: &dyn Fs, fx: &dyn FsFixture, work: &Path) -> FsContractResult {
    const CANARY: &[u8] = b"canary";
    let mut skips = Skipped::new();
    let root_abs = work.join("root");
    let outside_abs = work.join("outside");
    ok(fx.dir(&root_abs), "fixture root")?;
    ok(
        fx.file(&outside_abs.join("canary.txt"), CANARY),
        "fixture canary",
    )?;
    let w = ok(fs.open_dir(work), "open work dir")?;
    let canary_intact = |what: &str| -> ContractResult {
        ensure(
            names(&*w, Some(&rel("outside")?), what)? == ["canary.txt"],
            &format!("{what}: nothing appeared outside"),
        )?;
        read_is(
            &*w,
            r"outside\canary.txt",
            CANARY,
            &format!("{what}: canary unchanged"),
        )
    };
    let d = open_write(fs, &root_abs, "open root")?;

    // L1, L2: a link at the name.
    let mut links = vec!["junction", "dangling"];
    ok(
        fx.junction(&root_abs.join("junction"), &outside_abs),
        "fixture junction",
    )?;
    ok(
        fx.junction(&root_abs.join("dangling"), &work.join("nowhere")),
        "fixture dangling junction",
    )?;
    if ok(
        fx.dir_symlink(&root_abs.join("dsym"), &outside_abs),
        "fixture dir symlink",
    )? {
        links.push("dsym");
    } else {
        skip(&mut skips, "dir_symlink");
    }
    if ok(
        fx.file_symlink(&root_abs.join("fsym"), &outside_abs.join("canary.txt")),
        "fixture file symlink",
    )? {
        links.push("fsym");
    } else {
        skip(&mut skips, "file_symlink");
    }
    for (i, link) in links.iter().enumerate() {
        let n = u64::try_from(i).unwrap_or(0);
        let p = rel(link)?;
        err_kind(
            d.create_new(&p, &mut &b"x"[..], &new_file(n, Attrs::default(), b"x", 1)),
            SysErrorKind::AlreadyExists,
            &format!("L1 create_new over {link}"),
        )?;
        err_kind(
            d.create_dir(&p),
            SysErrorKind::AlreadyExists,
            &format!("L1 create_dir over {link}"),
        )?;
        err_kind(
            d.guard(&p).map(|_| ()),
            SysErrorKind::ReparsePoint,
            &format!("L2 guard of {link}"),
        )?;
        err_kind(
            d.lock(&p).map(|_| ()),
            SysErrorKind::ReparsePoint,
            &format!("L2 lock of {link}"),
        )?;
        ensure(
            ok(d.metadata(&p), "L1 metadata")?.is_some_and(|m| m.kind == EntryKind::Reparse),
            &format!("L1 {link} is still a link"),
        )?;
        canary_intact(&format!("L1 after {link}"))?;
    }
    let jid = ok(d.metadata(&rel("junction")?), "L2 metadata junction")?
        .ok_or("contract violated: L2 junction missing")?
        .file_id;
    err_kind(
        d.remove_dir(&rel("junction")?, jid),
        SysErrorKind::ReparsePoint,
        "L2 remove_dir of a junction",
    )?;
    ensure(
        ok(d.metadata(&rel("junction")?), "L2 junction after")?
            .is_some_and(|m| m.kind == EntryKind::Reparse),
        "L2 the junction stays",
    )?;
    ensure(
        ok(w.metadata(&rel("nowhere")?), "L1 dangling target")?.is_none(),
        "L1 nothing was created at a dangling target",
    )?;
    canary_intact("L2")?;

    // L3: swap after open.
    ok(
        fx.file(&root_abs.join(r"sub\data.txt"), b"orig"),
        "fixture sub",
    )?;
    let sub = ok(d.open_dir_write(&rel("sub")?), "L3 open sub")?;
    ok(
        fx.rename(&root_abs.join("sub"), &root_abs.join("sub-moved")),
        "L3 rename sub",
    )?;
    ok(
        fx.junction(&root_abs.join("sub"), &outside_abs),
        "L3 junction in its place",
    )?;
    ok(
        sub.create_new(
            &rel("new.bin")?,
            &mut &b"new"[..],
            &new_file(50, Attrs::default(), b"new", 3),
        ),
        "L3 create_new through the held handle",
    )?;
    let g = ok(
        sub.guard(&rel("data.txt")?),
        "L3 guard through the held handle",
    )?;
    ok(
        g.replace(
            &sha(b"orig"),
            &mut &b"changed"[..],
            &new_file(51, Attrs::default(), b"changed", 7),
        ),
        "L3 replace through the held handle",
    )?;
    read_is(
        &*d,
        r"sub-moved\new.bin",
        b"new",
        "L3 create_new landed in sub-moved",
    )?;
    read_is(
        &*d,
        r"sub-moved\data.txt",
        b"changed",
        "L3 replace landed in sub-moved",
    )?;
    canary_intact("L3")?;
    Ok(skips)
}
