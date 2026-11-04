//! Contract tests of the system layer: the same checks for `fake` and `win`.
//!
//! Today they run against `sys::fake`. From phase 1/2 they also run against `sys::win`:
//! the file system contracts in a fresh directory under `target/`, registry contracts in
//! Windows Sandbox (`docs/09-testing.md`). That keeps the fake honest.
//!
//! Each function expects an **empty** working directory or key and cleans up at the end.
//! The file system contracts receive the working directory as an absolute path and open it
//! with [`Fs::open_dir`](super::fs::Fs::open_dir), the one absolute operation.

use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use super::fs::{Attrs, Dir, EntryKind, tag};
use super::registry::{RegKey, RegValue};
use super::{SysErrorKind, SysResult, System};
use crate::path::{RelPath, RootPath};

/// Failed contract with a description.
pub type ContractResult = Result<(), String>;

/// Setup that the API under test deliberately cannot do (junctions, hard links, renames by
/// absolute path as an attacker would, case-sensitive directories). For `sys::fake` it is
/// implemented by `FakeFs`; for `sys::win` by test code (junctions need no admin).
pub trait FsFixture {
    /// Creates a directory junction `link` pointing to `target`.
    fn junction(&self, link: &Path, target: &Path) -> SysResult<()>;
    /// Creates a hard link `new` to the existing file `existing`.
    fn hardlink(&self, existing: &Path, new: &Path) -> SysResult<()>;
    /// Creates a file symbolic link. `Ok(false)` = not available (no Developer Mode or
    /// privilege); the case is skipped.
    fn file_symlink(&self, link: &Path, target: &Path) -> SysResult<bool>;
    /// Renames by absolute path (the attacker's move in a swap).
    fn rename(&self, from: &Path, to: &Path) -> SysResult<()>;
    /// Creates an empty case-sensitive directory. `Ok(false)` = not available on this
    /// machine; the case is skipped.
    fn case_sensitive_dir(&self, p: &Path) -> SysResult<bool>;
}

fn ensure(cond: bool, what: &str) -> ContractResult {
    if cond {
        Ok(())
    } else {
        Err(format!("contract violated: {what}"))
    }
}

fn ok<T>(r: SysResult<T>, what: &str) -> Result<T, String> {
    r.map_err(|e| format!("contract violated: {what}: unexpected error {e}"))
}

fn err_kind<T>(r: SysResult<T>, kind: SysErrorKind, what: &str) -> ContractResult {
    match r {
        Err(e) if e.kind == kind => Ok(()),
        Err(e) => Err(format!(
            "contract violated: {what}: expected {kind}, got error {e}"
        )),
        Ok(_) => Err(format!(
            "contract violated: {what}: expected {kind}, got success"
        )),
    }
}

fn rel(s: &str) -> Result<RelPath, String> {
    RelPath::parse(s).map_err(|e| format!("contract setup: {e}"))
}

/// Sorted raw names of a directory.
fn names(dir: &dyn Dir, p: Option<&RelPath>, what: &str) -> Result<Vec<String>, String> {
    let mut names: Vec<String> = ok(dir.read_dir(p), what)?
        .into_iter()
        .map(|e| e.name)
        .collect();
    names.sort();
    Ok(names)
}

fn read_is(dir: &dyn Dir, p: &str, expected: &[u8], what: &str) -> ContractResult {
    ensure(ok(dir.read(&rel(p)?), what)? == expected, what)
}

/// File system contract, reading side: identity, lookups, metadata, error kinds.
/// `work` must be an existing, empty directory.
pub fn fs_read_contract(sys: &dyn System, work: &Path) -> ContractResult {
    let root = ok(sys.fs().open_dir(work), "open work dir")?;
    let info = ok(root.info(), "info")?;
    ensure(
        RootPath::from_final_path(&info.final_path).is_ok(),
        "final_path is a drive-letter path",
    )?;
    ensure(!info.case_sensitive, "work dir is case-insensitive")?;
    let again = ok(
        ok(sys.fs().open_dir(work), "open work dir again")?.info(),
        "info again",
    )?;
    ensure(
        again.file_id == info.file_id && again.volume_serial == info.volume_serial,
        "identity of a directory is stable",
    )?;
    ensure(
        names(&*root, None, "read_dir work")?.is_empty(),
        "work dir is empty",
    )?;

    let game = rel("Game")?;
    let file = rel(r"Game\Data.bin")?;
    ok(root.create_dir(&game), "create_dir")?;
    ok(root.create_new(&file, b"hello"), "create_new")?;
    read_is(
        &*root,
        r"Game\Data.bin",
        b"hello",
        "read returns written data",
    )?;

    // Seekable reader (PE parsing).
    let mut reader = ok(root.open_read(&file), "open_read")?;
    let mut tail = Vec::new();
    reader
        .seek(SeekFrom::Start(1))
        .and_then(|_| reader.read_to_end(&mut tail))
        .map_err(|e| format!("contract violated: seek and read: {e}"))?;
    ensure(tail == b"ello", "seek then read")?;
    drop(reader);

    // Case-insensitive, original case is preserved.
    read_is(&*root, r"GAME\DATA.BIN", b"hello", "case-insensitive read")?;
    ensure(
        names(&*root, None, "read_dir")? == ["Game"],
        "read_dir keeps original case",
    )?;

    // Metadata.
    let m = ok(root.metadata(&file), "metadata")?.ok_or("contract violated: file missing")?;
    ensure(
        m.kind == EntryKind::File
            && m.len == 5
            && m.attrs == Attrs::default()
            && m.links == 1
            && m.reparse.is_none(),
        "metadata of a plain file",
    )?;
    let dm = ok(root.metadata(&game), "metadata dir")?.ok_or("contract violated: dir missing")?;
    ensure(dm.kind == EntryKind::Dir, "metadata of a directory")?;
    ensure(m.file_id != dm.file_id, "file ids differ")?;
    ensure(
        ok(root.metadata(&file), "metadata again")?.is_some_and(|m2| m2.file_id == m.file_id),
        "file id is stable",
    )?;
    for missing in [r"Game\missing", r"Game\missing\deeper", r"Game\Data.bin\x"] {
        ensure(
            ok(root.metadata(&rel(missing)?), "metadata missing")?.is_none(),
            "missing entry, missing parent or file as parent = None",
        )?;
    }

    // Kinds.
    err_kind(
        root.open_dir(&file),
        SysErrorKind::InvalidPath,
        "open_dir on a file",
    )?;
    err_kind(
        root.open_dir(&rel(r"Game\missing")?),
        SysErrorKind::NotFound,
        "open_dir missing",
    )?;
    err_kind(
        root.open_read(&game),
        SysErrorKind::AccessDenied,
        "open_read on a dir",
    )?;
    err_kind(
        root.open_read(&rel(r"Game\missing")?),
        SysErrorKind::NotFound,
        "open_read missing",
    )?;
    err_kind(
        root.read_dir(Some(&file)),
        SysErrorKind::InvalidPath,
        "read_dir on a file",
    )?;

    // A sub handle.
    let sub = ok(root.open_dir(&game), "open_dir relative")?;
    ensure(
        names(&*sub, None, "read_dir sub")? == ["Data.bin"],
        "read_dir of a sub handle",
    )?;
    read_is(&*sub, "data.bin", b"hello", "read through a sub handle")?;
    let sinfo = ok(sub.info(), "sub info")?;
    ensure(
        sinfo.final_path == info.final_path.join("Game"),
        "final_path of a sub handle",
    )?;
    ensure(
        sinfo.volume_serial == info.volume_serial && sinfo.file_id == dm.file_id,
        "sub handle identity equals its metadata",
    )?;
    let abs = ok(sys.fs().open_dir(&work.join("game")), "open sub absolute")?;
    ensure(
        ok(abs.info(), "abs info")?.file_id == sinfo.file_id,
        "absolute and relative open reach the same directory",
    )?;
    drop(abs);
    drop(sub);

    // Clean up.
    ok(root.remove_file(&file), "remove file")?;
    ok(root.remove_dir(&game), "remove dir")?;
    ensure(
        names(&*root, None, "read_dir after cleanup")?.is_empty(),
        "work dir empty after cleanup",
    )
}

/// File system contract, writing side: create, replace, remove, rename, read-only, handles
/// across renames, name spelling. `work` must be an existing, empty directory.
pub fn fs_write_contract(sys: &dyn System, work: &Path) -> ContractResult {
    let root = ok(sys.fs().open_dir(work), "open work dir")?;
    let info = ok(root.info(), "info")?;
    let game = rel("Game")?;
    let file = rel(r"Game\Data.bin")?;

    // Create.
    ok(root.create_dir(&game), "create_dir")?;
    err_kind(
        root.create_dir(&game),
        SysErrorKind::AlreadyExists,
        "create_dir twice",
    )?;
    err_kind(
        root.create_dir(&rel(r"nope\deeper")?),
        SysErrorKind::NotFound,
        "create_dir with missing parent",
    )?;
    ok(root.create_new(&file, b"hello"), "create_new")?;
    err_kind(
        root.create_new(&file, b"other"),
        SysErrorKind::AlreadyExists,
        "create_new twice",
    )?;
    read_is(
        &*root,
        r"Game\Data.bin",
        b"hello",
        "create_new twice leaves content",
    )?;
    err_kind(
        root.create_new(&game, b"x"),
        SysErrorKind::AlreadyExists,
        "create_new over a directory",
    )?;
    err_kind(
        root.create_new(&rel(r"nope\x.txt")?, b"x"),
        SysErrorKind::NotFound,
        "create_new with missing parent",
    )?;

    // Remove: kinds.
    err_kind(
        root.remove_dir(&game),
        SysErrorKind::NotEmpty,
        "remove_dir non-empty",
    )?;
    err_kind(
        root.remove_dir(&file),
        SysErrorKind::InvalidPath,
        "remove_dir on a file",
    )?;
    err_kind(
        root.remove_file(&game),
        SysErrorKind::AccessDenied,
        "remove_file on a dir",
    )?;

    // Read-only attribute.
    ok(root.set_readonly(&file, true), "set_readonly")?;
    ensure(
        ok(root.metadata(&file), "metadata readonly")?.is_some_and(|m| m.attrs.readonly),
        "readonly visible in metadata",
    )?;
    err_kind(
        root.replace(&file, b"x", "Data.bin.rerun-tmp"),
        SysErrorKind::AccessDenied,
        "replace read-only",
    )?;
    err_kind(
        root.remove_file(&file),
        SysErrorKind::AccessDenied,
        "remove read-only",
    )?;
    ok(root.set_readonly(&file, false), "clear readonly")?;

    // Replace: works through another case, keeps the stored spelling, leaves no temp files.
    ok(
        root.replace(&rel(r"GAME\DATA.BIN")?, b"world", "Data.bin.rerun-tmp"),
        "replace",
    )?;
    read_is(
        &*root,
        r"Game\Data.bin",
        b"world",
        "replace writes new content",
    )?;
    ensure(
        names(&*root, Some(&game), "read_dir after replace")? == ["Data.bin"],
        "replace keeps the spelling and leaves no temp or .old file",
    )?;
    err_kind(
        root.replace(&rel(r"Game\missing.bin")?, b"x", "missing.tmp"),
        SysErrorKind::NotFound,
        "replace missing",
    )?;
    err_kind(
        root.replace(&game, b"x", "Game.tmp"),
        SysErrorKind::AccessDenied,
        "replace a directory",
    )?;

    // Replace with a planted temp or .old name fails and leaves everything as it was.
    ok(
        root.create_new(&rel(r"Game\planted.tmp")?, b"attacker"),
        "plant tmp",
    )?;
    err_kind(
        root.replace(&file, b"evil", "planted.tmp"),
        SysErrorKind::AlreadyExists,
        "replace with planted tmp",
    )?;
    read_is(
        &*root,
        r"Game\Data.bin",
        b"world",
        "target unchanged after planted tmp",
    )?;
    read_is(
        &*root,
        r"Game\planted.tmp",
        b"attacker",
        "planted tmp unchanged",
    )?;
    ok(
        root.create_new(&rel(r"Game\t2.old")?, b"attacker2"),
        "plant .old",
    )?;
    err_kind(
        root.replace(&file, b"evil", "t2"),
        SysErrorKind::AlreadyExists,
        "replace with planted .old",
    )?;
    read_is(
        &*root,
        r"Game\Data.bin",
        b"world",
        "target unchanged after planted .old",
    )?;
    ensure(
        names(&*root, Some(&game), "read_dir after planted .old")?
            == ["Data.bin", "planted.tmp", "t2.old"],
        "failed replace removes its own temp file",
    )?;
    ok(
        root.remove_file(&rel(r"Game\planted.tmp")?),
        "remove planted",
    )?;
    ok(
        root.remove_file(&rel(r"Game\t2.old")?),
        "remove planted .old",
    )?;
    for bad in ["", r"a\b", "a/b", "..", "CON", "x.", " x"] {
        err_kind(
            root.replace(&file, b"evil", bad),
            SysErrorKind::InvalidPath,
            "replace with an invalid temp name",
        )?;
    }
    read_is(
        &*root,
        r"Game\Data.bin",
        b"world",
        "target unchanged after invalid temp",
    )?;

    // Rename never overwrites, a case-only change is allowed.
    let other = rel(r"Game\Other.bin")?;
    ok(root.create_new(&other, b"other"), "create other")?;
    err_kind(
        root.rename(&file, &other),
        SysErrorKind::AlreadyExists,
        "rename onto existing",
    )?;
    err_kind(
        root.rename(&file, &rel(r"Game\OTHER.BIN")?),
        SysErrorKind::AlreadyExists,
        "rename onto another entry that differs only in case",
    )?;
    let recased = rel(r"Game\DATA.bin")?;
    ok(root.rename(&file, &recased), "rename case only")?;
    ensure(
        names(&*root, Some(&game), "read_dir after recase")? == ["DATA.bin", "Other.bin"],
        "case-only rename changes the stored name",
    )?;
    err_kind(
        root.rename(&rel(r"Game\missing")?, &rel(r"Game\x")?),
        SysErrorKind::NotFound,
        "rename missing",
    )?;
    err_kind(
        root.rename(&other, &rel(r"Game\nope\x")?),
        SysErrorKind::NotFound,
        "rename into missing dir",
    )?;
    let sub = rel(r"Game\sub")?;
    let moved = rel(r"Game\sub\Other.bin")?;
    ok(root.create_dir(&sub), "create sub")?;
    ok(root.rename(&other, &moved), "move into subdir")?;
    read_is(&*root, r"Game\sub\Other.bin", b"other", "moved file")?;
    ok(root.rename(&moved, &other), "move back")?;
    err_kind(
        root.rename(&game, &rel(r"Game\sub\Game2")?),
        SysErrorKind::InvalidPath,
        "move a directory into its own subtree",
    )?;

    // A handle to a deleted directory reports NotFound, not a missing entry.
    ok(root.create_dir(&rel("D")?), "create D")?;
    let doomed = ok(root.open_dir(&rel("D")?), "open D")?;
    ok(root.remove_dir(&rel("D")?), "remove D")?;
    err_kind(
        doomed.metadata(&rel("x")?),
        SysErrorKind::NotFound,
        "metadata via a deleted handle",
    )?;
    drop(doomed);

    // A handle stays valid when its parent is renamed.
    ok(root.create_dir(&rel("A")?), "create A")?;
    ok(root.create_dir(&rel(r"A\B")?), "create A\\B")?;
    ok(root.create_new(&rel(r"A\B\f.txt")?, b"f"), "create f")?;
    let held = ok(root.open_dir(&rel(r"A\B")?), "open A\\B")?;
    ok(root.rename(&rel("A")?, &rel("A2")?), "rename parent")?;
    read_is(
        &*held,
        "f.txt",
        b"f",
        "read through handle after parent rename",
    )?;
    ok(
        held.create_new(&rel("g.txt")?, b"g"),
        "write through handle",
    )?;
    read_is(
        &*root,
        r"A2\B\g.txt",
        b"g",
        "write landed in the renamed tree",
    )?;
    ensure(
        ok(held.info(), "held info")?.final_path == info.final_path.join("A2").join("B"),
        "final_path follows the rename",
    )?;
    ensure(
        ok(root.metadata(&rel("A")?), "metadata old name")?.is_none(),
        "old name is gone",
    )?;
    drop(held);
    for f in [r"A2\B\f.txt", r"A2\B\g.txt"] {
        ok(root.remove_file(&rel(f)?), "remove in A2")?;
    }
    ok(root.remove_dir(&rel(r"A2\B")?), "remove A2\\B")?;
    ok(root.remove_dir(&rel("A2")?), "remove A2")?;

    // Spelling of valid but unusual names round-trips; folding is 1:1 per character.
    let spelled = [
        "a..b",
        ".hidden",
        "$data.bin",
        "Über.txt",
        "my file.txt",
        "Straße.ini",
        "STRASSE.ini",
    ];
    for n in spelled {
        ok(
            root.create_new(&sub.child(n).map_err(|e| e.to_string())?, n.as_bytes()),
            n,
        )?;
    }
    let mut expected: Vec<String> = spelled.iter().map(|s| (*s).to_owned()).collect();
    expected.sort();
    ensure(
        names(&*root, Some(&sub), "read_dir names")? == expected,
        "names keep their exact spelling (Straße and STRASSE are different)",
    )?;
    err_kind(
        root.create_new(&rel(r"Game\sub\über.TXT")?, b"x"),
        SysErrorKind::AlreadyExists,
        "case-insensitive beyond ASCII",
    )?;
    err_kind(
        root.rename(
            &rel(r"Game\sub\Straße.ini")?,
            &rel(r"Game\sub\STRASSE.ini")?,
        ),
        SysErrorKind::AlreadyExists,
        "rename onto a different entry (Straße to STRASSE)",
    )?;
    for n in spelled {
        ok(
            root.remove_file(&sub.child(n).map_err(|e| e.to_string())?),
            n,
        )?;
    }

    // Clean up.
    ok(root.remove_dir(&sub), "remove sub")?;
    ok(root.remove_file(&recased), "remove file")?;
    ok(root.remove_file(&other), "remove other")?;
    err_kind(
        root.remove_file(&other),
        SysErrorKind::NotFound,
        "remove missing file",
    )?;
    err_kind(
        root.remove_dir(&sub),
        SysErrorKind::NotFound,
        "remove missing dir",
    )?;
    ok(root.remove_dir(&game), "remove_dir")?;
    ensure(
        names(&*root, None, "read_dir after cleanup")?.is_empty(),
        "work dir empty after cleanup",
    )
}

/// File system contract with links (ADR 0007): junctions below a root are never followed,
/// handles survive a swap, hard links and case-sensitive directories are handled.
/// `work` must be an existing, empty directory; `fx` creates what the API cannot.
pub fn fs_link_contract(sys: &dyn System, fx: &dyn FsFixture, work: &Path) -> ContractResult {
    const CANARY: &[u8] = b"canary";
    let root_abs = work.join("root");
    let outside_abs = work.join("outside");
    let w = ok(sys.fs().open_dir(work), "open work dir")?;
    let outside = rel("outside")?;
    ok(w.create_dir(&outside), "create outside")?;
    ok(
        w.create_new(&rel(r"outside\canary.txt")?, CANARY),
        "create canary",
    )?;
    ok(w.create_dir(&rel("root")?), "create root")?;
    let canary_intact = |what: &str| -> ContractResult {
        ensure(
            names(&*w, Some(&outside), what)? == ["canary.txt"],
            &format!("{what}: outside unchanged"),
        )?;
        read_is(
            &*w,
            r"outside\canary.txt",
            CANARY,
            &format!("{what}: canary unchanged"),
        )
    };

    ok(
        fx.junction(&root_abs.join("link"), &outside_abs),
        "fixture junction",
    )?;
    let root = ok(sys.fs().open_dir(&root_abs), "open root")?;
    let root_info = ok(root.info(), "root info")?;
    let link = rel("link")?;
    let m = ok(root.metadata(&link), "metadata link")?.ok_or("contract violated: link missing")?;
    ensure(
        m.kind == EntryKind::Reparse
            && m.reparse
                .as_ref()
                .is_some_and(|r| r.surrogate && r.tag == tag::MOUNT_POINT),
        "junction is reported as a surrogate reparse point",
    )?;

    // Nothing goes through a junction below the root.
    let through = rel(r"link\canary.txt")?;
    let rp = SysErrorKind::ReparsePoint;
    err_kind(root.read(&through), rp, "read through junction")?;
    err_kind(root.metadata(&through), rp, "metadata through junction")?;
    err_kind(root.open_dir(&link), rp, "open_dir on junction")?;
    err_kind(root.read_dir(Some(&link)), rp, "read_dir on junction")?;
    err_kind(root.open_read(&link), rp, "open_read on junction")?;
    err_kind(
        root.create_new(&rel(r"link\new.txt")?, b"x"),
        rp,
        "create_new through junction",
    )?;
    err_kind(
        root.create_dir(&rel(r"link\d")?),
        rp,
        "create_dir through junction",
    )?;
    err_kind(
        root.replace(&through, b"x", "canary.tmp"),
        rp,
        "replace through junction",
    )?;
    err_kind(
        root.replace(&link, b"x", "link.tmp"),
        rp,
        "replace the junction",
    )?;
    err_kind(
        root.remove_file(&through),
        rp,
        "remove_file through junction",
    )?;
    err_kind(
        root.set_readonly(&through, true),
        rp,
        "set_readonly through junction",
    )?;
    err_kind(
        root.set_readonly(&link, true),
        rp,
        "set_readonly on junction",
    )?;
    err_kind(
        root.rename(&through, &rel("stolen.txt")?),
        rp,
        "rename out of junction",
    )?;
    canary_intact("after operations through the junction")?;

    // `Fs::open_dir` follows reparse points above the root.
    let via = ok(
        sys.fs().open_dir(&root_abs.join("link")),
        "open via junction",
    )?;
    let out = ok(sys.fs().open_dir(&outside_abs), "open outside")?;
    let (via_info, out_info) = (ok(via.info(), "via info")?, ok(out.info(), "out info")?);
    ensure(
        via_info.file_id == out_info.file_id && via_info.final_path == out_info.final_path,
        "absolute open follows the junction to its target",
    )?;
    drop(via);
    drop(out);

    // Deleting the junction itself leaves the target alone.
    ok(root.remove_file(&link), "remove junction")?;
    ensure(
        ok(root.metadata(&link), "metadata removed link")?.is_none(),
        "junction gone",
    )?;
    canary_intact("after removing the junction")?;

    // A junction name is occupied: create_new and create_dir never go through it, live or
    // dangling.
    ok(
        fx.junction(&root_abs.join("live"), &outside_abs),
        "fixture live junction",
    )?;
    ok(
        fx.junction(&root_abs.join("dangling"), &work.join("nowhere")),
        "fixture dangling junction",
    )?;
    for name in ["live", "dangling"] {
        let l = rel(name)?;
        let ae = SysErrorKind::AlreadyExists;
        err_kind(
            root.create_new(&l, b"x"),
            ae,
            "create_new on a junction name",
        )?;
        err_kind(root.create_dir(&l), ae, "create_dir on a junction name")?;
    }
    ensure(
        ok(w.metadata(&rel("nowhere")?), "metadata dangling target")?.is_none(),
        "dangling target not created",
    )?;
    canary_intact("after create on junction names")?;

    // Rename never moves anything through a junction, also deeper down.
    ok(root.create_new(&rel("x.txt")?, b"x"), "create x")?;
    ok(root.create_dir(&rel("d1")?), "create d1")?;
    ok(root.create_dir(&rel(r"d1\d2")?), "create d1\\d2")?;
    ok(
        fx.junction(&root_abs.join("d1").join("d2").join("deep"), &outside_abs),
        "fixture deep junction",
    )?;
    err_kind(
        root.rename(&rel("x.txt")?, &rel(r"live\x.txt")?),
        rp,
        "rename into junction",
    )?;
    err_kind(
        root.rename(&rel("x.txt")?, &rel(r"d1\d2\deep\x.txt")?),
        rp,
        "rename into deep junction",
    )?;
    read_is(&*root, "x.txt", b"x", "source of refused rename unchanged")?;
    canary_intact("after renames into junctions")?;
    ok(root.remove_file(&rel("x.txt")?), "remove x")?;
    ok(
        root.remove_file(&rel(r"d1\d2\deep")?),
        "remove deep junction",
    )?;
    ok(root.remove_dir(&rel(r"d1\d2")?), "remove d1\\d2")?;
    ok(root.remove_dir(&rel("d1")?), "remove d1")?;
    ok(root.remove_file(&rel("live")?), "remove live junction")?;
    ok(
        root.remove_file(&rel("dangling")?),
        "remove dangling junction",
    )?;

    // remove_dir on a junction to an empty directory removes only the link.
    ok(w.create_dir(&rel("empty")?), "create empty")?;
    ok(
        fx.junction(&root_abs.join("elink"), &work.join("empty")),
        "fixture junction to empty",
    )?;
    ok(root.remove_dir(&rel("elink")?), "remove_dir on junction")?;
    ensure(
        ok(root.metadata(&rel("elink")?), "metadata elink")?.is_none(),
        "junction to empty dir removed",
    )?;
    ensure(
        ok(w.metadata(&rel("empty")?), "metadata empty")?.is_some_and(|m| m.kind == EntryKind::Dir),
        "target of the junction still exists",
    )?;
    ok(w.remove_dir(&rel("empty")?), "remove empty")?;

    // File symbolic link: never read, replaced or changed through; deleting removes the link.
    if ok(
        fx.file_symlink(&root_abs.join("flink.dll"), &outside_abs.join("canary.txt")),
        "fixture file symlink",
    )? {
        let fl = rel("flink.dll")?;
        let m =
            ok(root.metadata(&fl), "metadata flink")?.ok_or("contract violated: flink missing")?;
        ensure(
            m.kind == EntryKind::Reparse
                && m.reparse
                    .as_ref()
                    .is_some_and(|r| r.surrogate && r.tag == tag::SYMLINK),
            "file symlink is reported as a surrogate",
        )?;
        err_kind(root.open_read(&fl), rp, "open_read file symlink")?;
        err_kind(
            root.replace(&fl, b"evil", "flink.tmp"),
            rp,
            "replace file symlink",
        )?;
        err_kind(
            root.set_readonly(&fl, true),
            rp,
            "set_readonly file symlink",
        )?;
        err_kind(
            root.read(&rel(r"flink.dll\x")?),
            rp,
            "read through file symlink",
        )?;
        ok(root.remove_file(&fl), "remove file symlink")?;
        ensure(
            ok(root.metadata(&fl), "metadata removed flink")?.is_none(),
            "file symlink gone",
        )?;
        canary_intact("after the file symlink")?;
    }

    // Swap after open: the old handle keeps the original directory, a fresh walk hits the
    // junction.
    ok(root.create_dir(&rel("sub")?), "create sub")?;
    ok(
        root.create_new(&rel(r"sub\data.txt")?, b"orig"),
        "create data",
    )?;
    let held = ok(root.open_dir(&rel("sub")?), "open sub")?;
    ok(
        fx.rename(&root_abs.join("sub"), &root_abs.join("sub-moved")),
        "fixture rename",
    )?;
    ok(
        fx.junction(&root_abs.join("sub"), &outside_abs),
        "fixture swap junction",
    )?;
    read_is(&*held, "data.txt", b"orig", "old handle reads the original")?;
    ok(
        held.create_new(&rel("held.txt")?, b"h"),
        "write through old handle",
    )?;
    read_is(
        &*root,
        r"sub-moved\held.txt",
        b"h",
        "write landed in the original",
    )?;
    ensure(
        ok(held.info(), "held info")?.final_path == root_info.final_path.join("sub-moved"),
        "old handle reports the moved path",
    )?;
    err_kind(
        root.create_new(&rel(r"sub\fresh.txt")?, b"x"),
        rp,
        "fresh walk after swap",
    )?;
    err_kind(
        root.read(&rel(r"sub\data.txt")?),
        rp,
        "fresh read after swap",
    )?;
    canary_intact("after the swap")?;
    drop(held);
    ok(root.remove_file(&rel("sub")?), "remove swap junction")?;
    for f in [r"sub-moved\held.txt", r"sub-moved\data.txt"] {
        ok(root.remove_file(&rel(f)?), "remove in sub-moved")?;
    }
    ok(root.remove_dir(&rel("sub-moved")?), "remove sub-moved")?;

    // Hard links: no in-place change, unlink and replace of the entry are allowed.
    let a = rel("a.bin")?;
    let b = rel("b.bin")?;
    ok(root.create_new(&a, b"shared"), "create a")?;
    ok(
        fx.hardlink(&root_abs.join("a.bin"), &root_abs.join("b.bin")),
        "fixture hardlink",
    )?;
    let ma = ok(root.metadata(&a), "metadata a")?.ok_or("contract violated: a missing")?;
    let mb = ok(root.metadata(&b), "metadata b")?.ok_or("contract violated: b missing")?;
    ensure(
        ma.links == 2 && mb.links == 2 && ma.file_id == mb.file_id,
        "both links report two links and the same file id",
    )?;
    err_kind(
        root.set_readonly(&a, true),
        SysErrorKind::Linked,
        "set_readonly on a linked file",
    )?;
    ok(
        root.replace(&a, b"new", "a.bin.rerun-tmp"),
        "replace a linked file",
    )?;
    read_is(&*root, "a.bin", b"new", "replaced link has new content")?;
    read_is(&*root, "b.bin", b"shared", "other link keeps old content")?;
    ensure(
        ok(root.metadata(&a), "metadata a after")?.is_some_and(|m| m.links == 1)
            && ok(root.metadata(&b), "metadata b after")?.is_some_and(|m| m.links == 1),
        "replace splits the links",
    )?;
    ok(
        fx.hardlink(&root_abs.join("b.bin"), &root_abs.join("c.bin")),
        "fixture hardlink c",
    )?;
    ok(root.remove_file(&rel("c.bin")?), "remove one of two links")?;
    read_is(&*root, "b.bin", b"shared", "remaining link intact")?;
    ensure(
        ok(root.metadata(&b), "metadata b last")?.is_some_and(|m| m.links == 1),
        "link count drops",
    )?;
    ok(root.set_readonly(&b, true), "set_readonly single link")?;
    ok(root.set_readonly(&b, false), "clear readonly single link")?;
    ok(root.remove_file(&a), "remove a")?;
    ok(root.remove_file(&b), "remove b")?;

    // Case-sensitive directory: writes are refused.
    if ok(
        fx.case_sensitive_dir(&root_abs.join("cs")),
        "fixture case-sensitive dir",
    )? {
        let cs = rel("cs")?;
        let h = ok(root.open_dir(&cs), "open cs")?;
        ensure(
            ok(h.info(), "cs info")?.case_sensitive,
            "case_sensitive reported",
        )?;
        let us = SysErrorKind::Unsupported;
        err_kind(
            root.create_new(&rel(r"cs\x.txt")?, b"x"),
            us,
            "create_new in cs dir",
        )?;
        err_kind(
            h.create_new(&rel("x.txt")?, b"x"),
            us,
            "create_new via cs handle",
        )?;
        err_kind(root.create_dir(&rel(r"cs\d")?), us, "create_dir in cs dir")?;
        // Refused before the entry is looked up, so the directory can stay empty.
        err_kind(
            root.replace(&rel(r"cs\x.txt")?, b"x", "x.tmp"),
            us,
            "replace in cs dir",
        )?;
        err_kind(
            root.remove_file(&rel(r"cs\x.txt")?),
            us,
            "remove_file in cs dir",
        )?;
        err_kind(root.remove_dir(&rel(r"cs\d")?), us, "remove_dir in cs dir")?;
        err_kind(
            root.set_readonly(&rel(r"cs\x.txt")?, true),
            us,
            "set_readonly in cs dir",
        )?;
        ok(root.create_new(&rel("in.txt")?, b"in"), "create in.txt")?;
        err_kind(
            root.rename(&rel("in.txt")?, &rel(r"cs\in.txt")?),
            us,
            "rename into cs dir",
        )?;
        err_kind(
            root.rename(&rel(r"cs\x.txt")?, &rel("out.txt")?),
            us,
            "rename out of cs dir",
        )?;
        read_is(
            &*root,
            "in.txt",
            b"in",
            "source of refused rename unchanged",
        )?;
        ok(root.remove_file(&rel("in.txt")?), "remove in.txt")?;
        drop(h);
        ok(root.remove_dir(&cs), "remove cs dir")?;
    }

    // Clean up.
    ensure(
        names(&*root, None, "read_dir root after")?.is_empty(),
        "root empty after cleanup",
    )?;
    drop(root);
    ok(w.remove_dir(&rel("root")?), "remove root")?;
    ok(w.remove_file(&rel(r"outside\canary.txt")?), "remove canary")?;
    ok(w.remove_dir(&outside), "remove outside")?;
    ensure(
        names(&*w, None, "read_dir work after")?.is_empty(),
        "work dir empty after cleanup",
    )
}

/// Registry contract. `root` must be an existing key without values and subkeys.
pub fn registry_contract(sys: &dyn System, root: &RegKey) -> ContractResult {
    let reg = sys.registry();
    let a = root.join("Alpha");

    ensure(
        ok(reg.create_key(&a), "create_key")?,
        "create_key reports new key",
    )?;
    ensure(
        !ok(reg.create_key(&a), "create_key again")?,
        "create_key reports existing key",
    )?;
    err_kind(
        reg.create_key(&root.join("Missing").join("Child")),
        SysErrorKind::NotFound,
        "create_key with missing parent",
    )?;

    // NUL would truncate the path in the Win32 call and must be rejected.
    err_kind(
        reg.create_key(&root.join("Bad\0Name")),
        SysErrorKind::InvalidPath,
        "create_key with NUL",
    )?;
    err_kind(
        reg.set(&a, "Bad\0Name", &RegValue::Dword(1)),
        SysErrorKind::InvalidPath,
        "set value name with NUL",
    )?;

    // Empty key ≠ missing key.
    ensure(ok(reg.key_exists(&a), "key_exists")?, "empty key exists")?;
    ensure(
        ok(reg.get(&a, "Nope"), "get missing value")?.is_none(),
        "missing value = None",
    )?;
    err_kind(
        reg.get(&root.join("Missing"), "x"),
        SysErrorKind::NotFound,
        "get on missing key",
    )?;

    // Value type is preserved, names are case-insensitive.
    ok(reg.set(&a, "Flag", &RegValue::Dword(1)), "set dword")?;
    let v = ok(reg.get(&a, "FLAG"), "get other case")?;
    ensure(
        v == Some(RegValue::Dword(1)),
        "dword round-trip, case-insensitive name",
    )?;
    ensure(
        v != Some(RegValue::String("1".into())),
        "dword differs from string",
    )?;
    let names: Vec<String> = ok(reg.values(&a), "values")?
        .into_iter()
        .map(|(n, _)| n)
        .collect();
    ensure(names == ["Flag"], "value name keeps original case")?;

    // Default value.
    ok(
        reg.set(&a, "", &RegValue::String("default".into())),
        "set default",
    )?;
    ensure(
        ok(reg.get(&a, ""), "get default")? == Some(RegValue::String("default".into())),
        "default value",
    )?;

    // A key with subkeys cannot be deleted.
    let child = a.join("Child");
    ok(reg.create_key(&child), "create child")?;
    let subs = ok(reg.subkeys(&root.join("ALPHA")), "subkeys other case")?;
    ensure(subs == ["Child"], "subkeys keep original case")?;
    err_kind(
        reg.delete_key(&a),
        SysErrorKind::NotEmpty,
        "delete_key with subkeys",
    )?;
    err_kind(
        reg.delete_value(&a, "Nope"),
        SysErrorKind::NotFound,
        "delete missing value",
    )?;

    // Clean up.
    ok(reg.delete_key(&child), "delete child")?;
    ok(reg.delete_value(&a, "Flag"), "delete value")?;
    ok(reg.delete_value(&a, ""), "delete default")?;
    ok(reg.delete_key(&a), "delete key")?;
    ensure(
        !ok(reg.key_exists(&a), "key_exists after delete")?,
        "key gone",
    )?;
    err_kind(
        reg.delete_key(&a),
        SysErrorKind::NotFound,
        "delete missing key",
    )
}

/// Topology contract: self-consistent data.
pub fn topology_contract(sys: &dyn System) -> ContractResult {
    let t = ok(sys.topology().read(), "topology read")?;
    ensure(t.logical_count() > 0, "at least one logical cpu")?;
    ensure(t.core_count() <= t.logical_count(), "cores <= logical cpus")?;
    ensure(
        t.cpus.iter().all(|c| t.llc_sizes.contains_key(&c.llc)),
        "every llc has a size",
    )?;
    let mut seen = std::collections::BTreeSet::new();
    ensure(
        t.cpus.iter().all(|c| seen.insert((c.group, c.index))),
        "(group, index) unique",
    )
}
