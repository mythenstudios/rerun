//! Contract tests of the system layer: the same checks for `fake` and `win`.
//!
//! Today they run against `sys::fake`. From phase 1/2 they also run against `sys::win`:
//! the file system contracts in a fresh directory under `target/`, registry contracts in
//! Windows Sandbox (`docs/09-testing.md`). That keeps the fake honest.
//!
//! The file system contracts are split by side:
//!
//! - **Read side** ([`fs_read_contract`], [`fs_link_read_contract`], [`fs_volume_contract`],
//!   [`fs_race_contract`]) use only [`Fs::open_dir`] and the reading methods of
//!   [`Dir`](super::fs::Dir) (`info`, `open_dir`, `metadata`, `open_read`, `read`,
//!   `read_dir`). Everything they need on disk, and every attacker move, is done by an
//!   [`FsFixture`] (plain `std::fs` and raw calls in test code). They therefore run against
//!   `sys::win`, which is read-only in phase 1.
//! - **Write side** ([`fs_write_contract`], [`fs_link_write_contract`]) exercise the writing
//!   methods. They run against the fake only until `sys::win` can write (phase 2).
//!
//! Each file system contract needs a fresh, **empty** working directory. The runner owns
//! cleanup: the read contracts never delete anything, and the write contracts remove what they
//! create only because that exercises the remove operations, not as a promise.
//!
//! A case that the fixture cannot set up on this machine (no symlink privilege, no second
//! volume, 8.3 names disabled) is skipped, not failed. The file system contracts return the
//! names of the skipped cases as [`Skipped`], so the runner can tell "passed" from "passed
//! because it skipped" and decide whether a skip is acceptable (the fake: fixed list; on
//! GitHub runners: only a few are).
//!
//! The file system contracts receive the working directory as an absolute path and open it
//! with [`Fs::open_dir`], the one absolute operation.

#![expect(
    clippy::disallowed_methods,
    reason = "contract tests open their work directory by absolute path"
)]

use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use super::fs::{Attrs, Dir, EntryKind, Fs, tag};
use super::gpu::MAX_NAME_UTF16;
use super::registry::{RegKey, RegValue};
use super::{KnownFolder, SysErrorKind, SysResult, System};
use crate::path::{RelPath, RootPath};

/// Failed contract with a description.
pub type ContractResult = Result<(), String>;

/// Names of the cases a file system contract skipped because the fixture reported "not
/// available" (`"dir_symlink"`, `"file_symlink"`, `"case_sensitive_dir"`, `"mount_volume"`,
/// `"subst"`, `"short_name"`, `"wof_compress"`). Without duplicates.
pub type Skipped = Vec<&'static str>;

/// Result of a file system contract: the skipped cases on success.
pub type FsContractResult = Result<Skipped, String>;

fn skip(skips: &mut Skipped, case: &'static str) {
    if !skips.contains(&case) {
        skips.push(case);
    }
}

/// Setup that the API under test deliberately cannot do (creating anything, junctions, hard
/// links, renames by absolute path as an attacker would, case-sensitive directories, mounted
/// volumes, drive substitution, 8.3 names, compression). For `sys::fake` it is implemented by
/// `FakeFs`; for `sys::win` by test code (junctions need no admin).
///
/// All paths are absolute. Every method creates missing parent directories of the path it
/// creates. Methods that may be unavailable on a machine return `Ok(false)` / `Ok(None)`
/// ("not available"): the contract skips that case and reports it in [`Skipped`]. A fixture
/// that creates something outside the work directory (a mount, a substituted drive) must undo
/// it when the test ends, even on panic (drop guard).
pub trait FsFixture: Sync {
    /// Creates the directory `p` including missing parents.
    fn dir(&self, p: &Path) -> SysResult<()>;
    /// Creates the file `p` with `data` (overwriting an existing file).
    fn file(&self, p: &Path, data: &[u8]) -> SysResult<()>;
    /// Creates a directory junction `link` pointing to `target`. The target need not exist.
    fn junction(&self, link: &Path, target: &Path) -> SysResult<()>;
    /// Creates a directory symbolic link. `Ok(false)` = not available (no Developer Mode or
    /// privilege).
    fn dir_symlink(&self, link: &Path, target: &Path) -> SysResult<bool>;
    /// Creates a file symbolic link. `Ok(false)` = not available (no Developer Mode or
    /// privilege).
    fn file_symlink(&self, link: &Path, target: &Path) -> SysResult<bool>;
    /// Creates a hard link `new` to the existing file `existing`.
    fn hardlink(&self, existing: &Path, new: &Path) -> SysResult<()>;
    /// Renames by absolute path (the attacker's move in a swap). Never overwrites.
    fn rename(&self, from: &Path, to: &Path) -> SysResult<()>;
    /// Creates an empty case-sensitive directory. `Ok(false)` = not available on this
    /// machine.
    fn case_sensitive_dir(&self, p: &Path) -> SysResult<bool>;
    /// Mounts another, empty volume (own volume serial) in the folder `at`, which is created
    /// if missing. Files can then be created below it. `Ok(false)` = no second volume.
    fn mount_volume(&self, at: &Path) -> SysResult<bool>;
    /// Substitutes a drive letter for the existing directory `target` (`subst`) and returns
    /// its root, e.g. `S:\`. `None` = not available.
    fn subst(&self, target: &Path) -> SysResult<Option<PathBuf>>;
    /// Gives the existing file or directory `p` the 8.3 short name `short`, e.g. `ALIAS.TXT`.
    /// `Ok(false)` = not available (8.3 names disabled, not NTFS).
    fn short_name(&self, p: &Path, short: &str) -> SysResult<bool>;
    /// Compresses the existing file `p` with the Windows Overlay Filter (like CompactGUI), so
    /// it carries the WOF reparse tag. `Ok(false)` = not available.
    fn wof_compress(&self, p: &Path) -> SysResult<bool>;
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

/// The entry `p` is a name surrogate with the given tag (`Dir::metadata` does not follow it).
fn is_surrogate_with(dir: &dyn Dir, p: &str, expected: u32, what: &str) -> ContractResult {
    let m =
        ok(dir.metadata(&rel(p)?), what)?.ok_or(format!("contract violated: {what}: missing"))?;
    ensure(
        m.kind == EntryKind::Reparse
            && m.reparse
                .as_ref()
                .is_some_and(|r| r.surrogate && r.tag == expected),
        what,
    )
}

/// Every operation of the read side through `p` (a path whose parent is a reparse point)
/// returns `ReparsePoint`.
fn refused_through(dir: &dyn Dir, p: &str, what: &str) -> ContractResult {
    let rp = SysErrorKind::ReparsePoint;
    let p = rel(p)?;
    err_kind(dir.read(&p), rp, &format!("{what}: read"))?;
    err_kind(dir.open_read(&p), rp, &format!("{what}: open_read"))?;
    err_kind(dir.metadata(&p), rp, &format!("{what}: metadata"))?;
    err_kind(dir.open_dir(&p), rp, &format!("{what}: open_dir"))?;
    err_kind(dir.read_dir(Some(&p)), rp, &format!("{what}: read_dir"))
}

/// Operations on a reparse point itself that must not follow it.
fn refused_at(dir: &dyn Dir, p: &str, what: &str) -> ContractResult {
    let rp = SysErrorKind::ReparsePoint;
    let p = rel(p)?;
    err_kind(dir.open_dir(&p), rp, &format!("{what}: open_dir"))?;
    err_kind(dir.read_dir(Some(&p)), rp, &format!("{what}: read_dir"))?;
    err_kind(dir.open_read(&p), rp, &format!("{what}: open_read"))
}

/// File system contract, reading side: identity, lookups, metadata, error kinds, the input
/// rules of `Fs::open_dir`, long-name lookups. `work` must be an existing, empty directory.
/// Uses only the read API; setup through `fx`.
pub fn fs_read_contract(fs: &dyn Fs, fx: &dyn FsFixture, work: &Path) -> FsContractResult {
    let mut skips = Skipped::new();
    let root = ok(fs.open_dir(work), "open work dir")?;
    let info = ok(root.info(), "info")?;
    ensure(
        RootPath::from_final_path(&info.final_path).is_ok(),
        "final_path is a drive-letter path",
    )?;
    ensure(!info.case_sensitive, "work dir is case-insensitive")?;
    ensure(!info.is_volume_root(), "work dir is not a volume root")?;
    // The work dir lies on a drive-letter volume (no folder mount above it), so its
    // volume-relative path is the final path without `\\?\X:\`: long names, no device prefix.
    let final_str = info.final_path.to_string_lossy();
    let below_drive = final_str.get(r"\\?\X:\".len()..).unwrap_or_default();
    ensure(
        info.volume_path == below_drive
            && !info.volume_path.starts_with('\\')
            && !info.volume_path.ends_with('\\')
            && info.volume_path.split('\\').all(|s| !s.is_empty()),
        "volume_path is the final path below the drive root",
    )?;
    if let Some(drive_root) = work.ancestors().last() {
        let d = ok(fs.open_dir(drive_root), "open drive root")?;
        ensure(
            ok(d.info(), "drive root info")?.is_volume_root(),
            "drive root is a volume root",
        )?;
    }
    let again = ok(
        ok(fs.open_dir(work), "open work dir again")?.info(),
        "info again",
    )?;
    ensure(
        again.file_id == info.file_id && again.volume_serial == info.volume_serial,
        "identity of a directory is stable",
    )?;
    ensure(
        names(&*root, None, "read_dir work")?.is_empty(),
        "work dir is empty (each contract needs a fresh empty work dir)",
    )?;

    let game_abs = work.join("Game");
    ok(fx.dir(&game_abs), "fixture dir")?;
    ok(
        fx.file(&game_abs.join("Data.bin"), b"hello"),
        "fixture file",
    )?;
    let game = rel("Game")?;
    let file = rel(r"Game\Data.bin")?;
    read_is(
        &*root,
        r"Game\Data.bin",
        b"hello",
        "read returns the file content",
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
    err_kind(
        fs.open_dir(&game_abs.join("Data.bin")),
        SysErrorKind::InvalidPath,
        "Fs::open_dir on a file",
    )?;
    err_kind(
        fs.open_dir(&game_abs.join("missing")),
        SysErrorKind::NotFound,
        "Fs::open_dir missing",
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
    let abs = ok(fs.open_dir(&work.join("game")), "open sub absolute")?;
    ensure(
        ok(abs.info(), "abs info")?.file_id == sinfo.file_id,
        "absolute and relative open reach the same directory",
    )?;
    drop(abs);
    drop(sub);

    open_dir_input_rules(fs, work, info.file_id)?;
    long_name_lookups(fx, &*root, work, &mut skips)?;
    wof_files(fx, &*root, work, &mut skips)?;
    Ok(skips)
}

/// `Fs::open_dir` accepts only drive-absolute input (`X:\…`, `\\?\X:\…`; `/` counts as `\`).
/// `.`, `..`, UNC, device and volume-GUID paths, relative and stream paths are `InvalidPath`.
fn open_dir_input_rules(fs: &dyn Fs, work: &Path, work_id: u128) -> ContractResult {
    let ws = work
        .to_str()
        .ok_or("contract setup: work dir is not Unicode")?;
    let accepted = [
        (PathBuf::from(ws.replace('\\', "/")), "forward slashes"),
        (PathBuf::from(format!(r"\\?\{ws}")), r"\\?\ prefix"),
        (PathBuf::from(ws.to_lowercase()), "other case"),
        (PathBuf::from(format!(r"{ws}\")), "trailing separator"),
    ];
    for (p, what) in accepted {
        let d = ok(fs.open_dir(&p), what)?;
        ensure(
            ok(d.info(), what)?.file_id == work_id,
            &format!("open_dir input accepted: {what}"),
        )?;
    }
    let game = work.join("Game");
    let rejected = [
        (work.join("."), "dot segment"),
        (game.join(".."), "dot-dot segment"),
        (
            game.join("..").join("Game"),
            "dot-dot segment in the middle",
        ),
        (PathBuf::from(r"\\server\share\x"), "UNC path"),
        (PathBuf::from(r"\\?\UNC\server\share\x"), r"\\?\UNC path"),
        (
            PathBuf::from(r"\\?\Volume{00000000-0000-0000-0000-000000000000}\"),
            "volume GUID path",
        ),
        (PathBuf::from(r"\\.\C:\"), "device path"),
        (PathBuf::new(), "empty path"),
        (PathBuf::from("Game"), "relative path"),
        (PathBuf::from(r"\Game"), "rooted path without a drive"),
        (PathBuf::from("C:Game"), "drive-relative path"),
        (game.join("Data.bin:stream"), "alternate data stream"),
        (game.join("Data.bin::$DATA"), "default data stream"),
        (game.join(":stream"), "stream of the directory"),
    ];
    for (p, what) in rejected {
        err_kind(
            fs.open_dir(&p),
            SysErrorKind::InvalidPath,
            &format!("open_dir input rejected: {what}"),
        )?;
    }
    Ok(())
}

/// L1: the last segment of the normalized name must equal the requested segment. An 8.3 short
/// name (`ALIAS.TXT` for `Long File Name.txt`) is not a way to reach the entry.
fn long_name_lookups(
    fx: &dyn FsFixture,
    root: &dyn Dir,
    work: &Path,
    skips: &mut Skipped,
) -> ContractResult {
    let file_abs = work.join("names").join("Long File Name.txt");
    let dir_abs = work.join("names").join("Long Dir Name");
    ok(fx.file(&file_abs, b"long"), "fixture file")?;
    ok(fx.file(&dir_abs.join("inner.txt"), b"inner"), "fixture dir")?;
    let both = ok(fx.short_name(&file_abs, "ALIAS.TXT"), "fixture short name")?
        && ok(fx.short_name(&dir_abs, "ALIASD"), "fixture short name dir")?;
    if !both {
        skip(skips, "short_name");
        return Ok(());
    }
    let nf = SysErrorKind::NotFound;
    read_is(
        root,
        r"names\Long File Name.txt",
        b"long",
        "long name works",
    )?;
    ensure(
        ok(
            root.metadata(&rel(r"names\ALIAS.TXT")?),
            "metadata short name",
        )?
        .is_none(),
        "metadata by short name = None",
    )?;
    err_kind(
        root.open_read(&rel(r"names\ALIAS.TXT")?),
        nf,
        "open_read by short name",
    )?;
    err_kind(
        root.read(&rel(r"names\alias.txt")?),
        nf,
        "read by short name",
    )?;
    err_kind(
        root.open_dir(&rel(r"names\ALIASD")?),
        nf,
        "open_dir by short name",
    )?;
    ensure(
        ok(
            root.metadata(&rel(r"names\ALIASD\inner.txt")?),
            "metadata below a short dir name",
        )?
        .is_none(),
        "metadata below a short directory name = None",
    )?;
    err_kind(
        root.read(&rel(r"names\ALIASD\inner.txt")?),
        nf,
        "read below a short directory name",
    )?;
    ensure(
        names(root, Some(&rel("names")?), "read_dir names")?
            == ["Long Dir Name", "Long File Name.txt"],
        "read_dir lists long names only",
    )
}

/// WOF-compressed files (CompactGUI) read like plain files with unchanged content and carry
/// the WOF tag.
fn wof_files(
    fx: &dyn FsFixture,
    root: &dyn Dir,
    work: &Path,
    skips: &mut Skipped,
) -> ContractResult {
    let data: Vec<u8> = (0..256 * 1024u32)
        .map(|i| u8::try_from(i % 251).unwrap_or(0))
        .collect();
    let abs = work.join("wof").join("big.bin");
    ok(fx.file(&abs, &data), "fixture file")?;
    if !ok(fx.wof_compress(&abs), "fixture wof")? {
        skip(skips, "wof_compress");
        return Ok(());
    }
    let p = rel(r"wof\big.bin")?;
    ensure(
        ok(root.read(&p), "read wof file")? == data,
        "content of a WOF file is unchanged",
    )?;
    let m = ok(root.metadata(&p), "metadata wof")?.ok_or("contract violated: wof file missing")?;
    ensure(
        m.kind == EntryKind::File
            && m.len == data.len() as u64
            && m.reparse.as_ref().is_some_and(|r| r.tag == tag::WOF),
        "a WOF file is a plain file with the WOF tag",
    )
}

/// File system contract with links, reading side (ADR 0007): reparse points below a root are
/// never followed, handles survive a swap, hard links and case-sensitive directories are
/// reported. Includes the matrix of link kinds × positions (I2) and the file-symlink-as-
/// directory case. `work` must be an existing, empty directory; `fx` creates everything.
pub fn fs_link_read_contract(fs: &dyn Fs, fx: &dyn FsFixture, work: &Path) -> FsContractResult {
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
    let outside = rel("outside")?;
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

    // Junction.
    ok(
        fx.junction(&root_abs.join("link"), &outside_abs),
        "fixture junction",
    )?;
    let root = ok(fs.open_dir(&root_abs), "open root")?;
    let root_info = ok(root.info(), "root info")?;
    is_surrogate_with(
        &*root,
        "link",
        tag::MOUNT_POINT,
        "junction is reported as a surrogate reparse point",
    )?;
    refused_at(&*root, "link", "the junction itself")?;
    refused_through(&*root, r"link\canary.txt", "through a junction")?;
    canary_intact("after reads through the junction")?;

    // `Fs::open_dir` follows reparse points above the root.
    let via = ok(fs.open_dir(&root_abs.join("link")), "open via junction")?;
    let out = ok(fs.open_dir(&outside_abs), "open outside")?;
    let (via_info, out_info) = (ok(via.info(), "via info")?, ok(out.info(), "out info")?);
    ensure(
        via_info.file_id == out_info.file_id && via_info.final_path == out_info.final_path,
        "absolute open follows the junction to its target",
    )?;
    drop(via);
    drop(out);

    // A dangling junction is still a surrogate and refused.
    ok(
        fx.junction(&root_abs.join("dangling"), &work.join("nowhere")),
        "fixture dangling junction",
    )?;
    is_surrogate_with(
        &*root,
        "dangling",
        tag::MOUNT_POINT,
        "dangling junction is a surrogate",
    )?;
    refused_at(&*root, "dangling", "a dangling junction")?;
    refused_through(&*root, r"dangling\x", "through a dangling junction")?;
    ensure(
        ok(w.metadata(&rel("nowhere")?), "metadata dangling target")?.is_none(),
        "dangling target does not exist",
    )?;

    // File symbolic link: reported as a surrogate, never opened.
    if ok(
        fx.file_symlink(&root_abs.join("flink.dll"), &outside_abs.join("canary.txt")),
        "fixture file symlink",
    )? {
        is_surrogate_with(
            &*root,
            "flink.dll",
            tag::SYMLINK,
            "file symlink is reported as a surrogate",
        )?;
        refused_at(&*root, "flink.dll", "a file symlink")?;
        refused_through(&*root, r"flink.dll\x", "through a file symlink")?;
        canary_intact("after the file symlink")?;
    } else {
        skip(&mut skips, "file_symlink");
    }

    // Swap after open: the old handle keeps the original directory, a fresh walk hits the
    // junction.
    ok(
        fx.file(&root_abs.join("sub").join("data.txt"), b"orig"),
        "fixture sub",
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
    ensure(
        ok(held.info(), "held info")?.final_path == root_info.final_path.join("sub-moved"),
        "old handle reports the moved path",
    )?;
    refused_through(&*root, r"sub\data.txt", "fresh walk after the swap")?;
    refused_through(&*root, r"sub\canary.txt", "fresh walk to the canary")?;
    read_is(
        &*root,
        r"sub-moved\data.txt",
        b"orig",
        "the original is under its new name",
    )?;
    canary_intact("after the swap")?;
    drop(held);

    // Hard links: both names report two links, the same file ID and the same content.
    ok(fx.file(&root_abs.join("a.bin"), b"shared"), "fixture a")?;
    ok(
        fx.hardlink(&root_abs.join("a.bin"), &root_abs.join("b.bin")),
        "fixture hardlink",
    )?;
    let ma =
        ok(root.metadata(&rel("a.bin")?), "metadata a")?.ok_or("contract violated: a missing")?;
    let mb =
        ok(root.metadata(&rel("b.bin")?), "metadata b")?.ok_or("contract violated: b missing")?;
    ensure(
        ma.links == 2 && mb.links == 2 && ma.file_id == mb.file_id,
        "both links report two links and the same file id",
    )?;
    read_is(&*root, "b.bin", b"shared", "read through the second link")?;

    // Case-sensitive directory: reported.
    if ok(
        fx.case_sensitive_dir(&root_abs.join("cs")),
        "fixture case-sensitive dir",
    )? {
        let h = ok(root.open_dir(&rel("cs")?), "open cs")?;
        ensure(
            ok(h.info(), "cs info")?.case_sensitive,
            "case_sensitive reported",
        )?;
        ensure(
            !ok(root.info(), "root info again")?.case_sensitive,
            "the parent stays case-insensitive",
        )?;
        ensure(
            names(&*h, None, "read_dir cs")?.is_empty(),
            "a new case-sensitive directory is empty",
        )?;
    } else {
        skip(&mut skips, "case_sensitive_dir");
    }

    link_matrix(fs, fx, work, &mut skips)?;
    Ok(skips)
}

/// I2: every kind of link replaces `steamapps`, `common` and `Game` of a store in turn. Each
/// one is a surrogate with the right tag, and nothing goes through it, including a file
/// symlink where a directory is expected (`open_dir` gives `ReparsePoint`, not `InvalidPath`).
fn link_matrix(
    fs: &dyn Fs,
    fx: &dyn FsFixture,
    work: &Path,
    skips: &mut Skipped,
) -> ContractResult {
    const DIRS: [&str; 3] = ["steamapps", "common", "Game"];
    const CANARY: &[u8] = b"canary";
    #[derive(Clone, Copy, PartialEq)]
    enum Kind {
        Junction,
        DirSymlink,
        FileSymlink,
        Mount,
    }
    let kinds = [
        (Kind::Junction, "junction"),
        (Kind::DirSymlink, "dir symlink"),
        (Kind::FileSymlink, "file symlink"),
        (Kind::Mount, "mount point"),
    ];
    for (ki, (kind, kind_name)) in kinds.into_iter().enumerate() {
        for level in 0..DIRS.len() {
            let case = work.join(format!("i2-{ki}-{level}"));
            let (store, out) = (case.join("store"), case.join("out"));
            // The target holds the rest of the path at every level, so a followed link would
            // read the canary.
            for p in [r"common\Game\game.exe", r"Game\game.exe", "game.exe"] {
                ok(fx.file(&out.join(p), CANARY), "fixture out")?;
            }
            ok(fx.dir(&store), "fixture store")?;
            let link_rel = DIRS[..=level].join("\\");
            if level > 0 {
                ok(
                    fx.dir(&store.join(DIRS[..level].join("\\"))),
                    "fixture parents",
                )?;
            }
            let link_abs = store.join(&link_rel);
            let (made, link_tag, skip_name) = match kind {
                Kind::Junction => {
                    ok(fx.junction(&link_abs, &out), "fixture junction")?;
                    (true, tag::MOUNT_POINT, "")
                }
                Kind::DirSymlink => (
                    ok(fx.dir_symlink(&link_abs, &out), "fixture dir symlink")?,
                    tag::SYMLINK,
                    "dir_symlink",
                ),
                Kind::FileSymlink => (
                    ok(
                        fx.file_symlink(&link_abs, &out.join("game.exe")),
                        "fixture file symlink",
                    )?,
                    tag::SYMLINK,
                    "file_symlink",
                ),
                Kind::Mount => (
                    ok(fx.mount_volume(&link_abs), "fixture mount")?,
                    tag::MOUNT_POINT,
                    "mount_volume",
                ),
            };
            if !made {
                skip(skips, skip_name);
                continue;
            }
            let mut through: Vec<&str> = DIRS[level + 1..].to_vec();
            through.push("game.exe");
            let through_rel = format!("{link_rel}\\{}", through.join("\\"));
            if kind == Kind::Mount {
                ok(
                    fx.file(&store.join(&through_rel), b"inside"),
                    "fixture below mount",
                )?;
            }
            let what = format!("{kind_name} at {}", DIRS[level]);
            let sd = ok(fs.open_dir(&store), "open store")?;
            is_surrogate_with(&*sd, &link_rel, link_tag, &format!("{what}: surrogate"))?;
            refused_at(&*sd, &link_rel, &what)?;
            refused_through(&*sd, &through_rel, &what)?;
            if let Some(next) = DIRS.get(level + 1) {
                refused_through(&*sd, &format!("{link_rel}\\{next}"), &what)?;
            }
            // The canary outside is unchanged.
            let od = ok(fs.open_dir(&out), "open out")?;
            for p in [r"common\Game\game.exe", r"Game\game.exe", "game.exe"] {
                read_is(&*od, p, CANARY, &format!("{what}: canary"))?;
            }
        }
    }
    Ok(())
}

/// File system contract for volumes: a folder-mounted volume (I3) and a substituted drive
/// (I4). `work` must be an existing, empty directory. Cases the fixture cannot set up are
/// skipped (`mount_volume`, `subst`).
pub fn fs_volume_contract(fs: &dyn Fs, fx: &dyn FsFixture, work: &Path) -> FsContractResult {
    let mut skips = Skipped::new();
    let w = ok(fs.open_dir(work), "open work dir")?;
    let winfo = ok(w.info(), "work info")?;

    // I3: a volume mounted in a folder. Opened by absolute path it is a volume root with its
    // own serial; seen from above it is a name surrogate that is never traversed.
    let mnt = work.join("mnt");
    if ok(fx.mount_volume(&mnt), "fixture mount")? {
        ok(
            fx.file(&mnt.join("sub").join("x.txt"), b"x"),
            "fixture file on the mounted volume",
        )?;
        let m = ok(fs.open_dir(&mnt), "open mount point absolute")?;
        let mi = ok(m.info(), "mount info")?;
        ensure(
            mi.is_volume_root() && mi.volume_path.is_empty(),
            "a folder-mounted volume opened by absolute path is a volume root",
        )?;
        ensure(
            mi.volume_serial != winfo.volume_serial,
            "a mounted volume has its own serial",
        )?;
        let si = ok(
            ok(fs.open_dir(&mnt.join("sub")), "open below the mount")?.info(),
            "sub info",
        )?;
        ensure(
            si.volume_path == "sub" && si.volume_serial == mi.volume_serial,
            "volume_path counts from the mounted volume's root",
        )?;
        is_surrogate_with(
            &*w,
            "mnt",
            tag::MOUNT_POINT,
            "a mount point below a root is a surrogate",
        )?;
        refused_at(&*w, "mnt", "the mount point")?;
        refused_through(&*w, r"mnt\sub\x.txt", "through the mount point")?;
    } else {
        skip(&mut skips, "mount_volume");
    }

    // I4: a substituted drive. The canonical path shows the real location.
    ok(
        fx.dir(&work.join("target").join("sub")),
        "fixture subst target",
    )?;
    let target_abs = work.join("target");
    match ok(fx.subst(&target_abs), "fixture subst")? {
        Some(drive) => {
            let direct = ok(
                ok(fs.open_dir(&target_abs), "open target directly")?.info(),
                "target info",
            )?;
            let via = ok(
                ok(fs.open_dir(&drive), "open the substituted drive")?.info(),
                "subst info",
            )?;
            ensure(
                via.final_path == direct.final_path,
                "final_path of a substituted drive shows the target",
            )?;
            ensure(
                via.file_id == direct.file_id
                    && via.volume_serial == direct.volume_serial
                    && via.volume_path == direct.volume_path,
                "identity through a substituted drive equals the direct one",
            )?;
            let sub = ok(
                ok(fs.open_dir(&drive.join("sub")), "open below the drive")?.info(),
                "subst sub info",
            )?;
            ensure(
                sub.final_path == direct.final_path.join("sub"),
                "final_path below a substituted drive shows the target",
            )?;
        }
        None => skip(&mut skips, "subst"),
    }
    Ok(skips)
}

/// What a probe of the race contract must never see.
struct Forbidden {
    file_ids: Vec<u128>,
}

impl Forbidden {
    fn id(&self, id: u128, what: &str) -> ContractResult {
        ensure(
            !self.file_ids.contains(&id),
            &format!("race: {what} exposed the file ID of the outside canary"),
        )
    }
}

/// `Ok(Some(v))`, or `Ok(None)` for the outcomes a swap legitimately causes (`ReparsePoint`,
/// `NotFound` in the gap between two renames). Any other error fails the contract.
fn racing<T>(r: SysResult<T>, what: &str) -> Result<Option<T>, String> {
    match r {
        Ok(v) => Ok(Some(v)),
        Err(e) if matches!(e.kind, SysErrorKind::ReparsePoint | SysErrorKind::NotFound) => Ok(None),
        Err(e) => Err(format!(
            "contract violated: race: {what}: unexpected error {e}"
        )),
    }
}

/// File system contract, stress race (M-b): while a flipper thread swaps directories for
/// junctions to an outside folder by path (first, middle and last directory level of a three
/// level path), the main thread probes through the root handle. No result that comes back `Ok`
/// may ever contain the outside canary's content, file ID or name. Allowed: `ReparsePoint`,
/// `NotFound` (gap between two renames) and the content of the real file.
///
/// Runs for `budget`. `work` must be an existing, empty directory. Against `sys::win` the
/// runner also runs a naive implementation (check, then open by full path) which this harness
/// must catch, so a passing run means something.
pub fn fs_race_contract(
    fs: &dyn Fs,
    fx: &dyn FsFixture,
    work: &Path,
    budget: Duration,
) -> FsContractResult {
    const CANARY: &[u8] = b"CANARY";
    const NAME: &str = "canary-only.txt";
    const CHAIN: [&str; 3] = ["l0", "l1", "l2"];
    let root_abs = work.join("root");
    let outside_abs = work.join("outside");

    // Real tree: root\l0\l1\l2\data.txt. Outside: for each level k a tree holding the rest of
    // the path below it, so a followed junction at level k reaches `canary-only.txt`.
    let real_dir = |upto: usize| -> PathBuf {
        CHAIN[..upto]
            .iter()
            .fold(root_abs.clone(), |p, seg| p.join(seg))
    };
    ok(
        fx.file(&real_dir(3).join("data.txt"), b"inside"),
        "fixture data",
    )?;
    for level in 0..CHAIN.len() {
        let target = CHAIN[level + 1..]
            .iter()
            .fold(outside_abs.join(format!("k{level}")), |p, seg| p.join(seg));
        ok(fx.file(&target.join(NAME), CANARY), "fixture canary")?;
        ok(
            fx.junction(
                &real_dir(level).join(format!("{}.link", CHAIN[level])),
                &outside_abs.join(format!("k{level}")),
            ),
            "fixture junction",
        )?;
    }

    // File IDs of the canary files and the directories above them.
    let mut forbidden = Forbidden {
        file_ids: Vec::new(),
    };
    let out_handle = ok(fs.open_dir(&outside_abs), "open outside")?;
    for level in 0..CHAIN.len() {
        let mut dir = format!("k{level}");
        for seg in &CHAIN[level + 1..] {
            dir = format!("{dir}\\{seg}");
        }
        let d = ok(out_handle.open_dir(&rel(&dir)?), "open outside tree")?;
        forbidden
            .file_ids
            .push(ok(d.info(), "outside dir info")?.file_id);
        let m = ok(d.metadata(&rel(NAME)?), "outside canary metadata")?
            .ok_or("contract violated: outside canary missing")?;
        forbidden.file_ids.push(m.file_id);
    }
    drop(out_handle);

    let root = ok(fs.open_dir(&root_abs), "open root")?;
    let (dir_p, data_p, canary_p) = (
        rel(r"l0\l1\l2")?,
        rel(r"l0\l1\l2\data.txt")?,
        rel(&format!(r"l0\l1\l2\{NAME}"))?,
    );
    let name_p = rel(NAME)?;

    let stop = AtomicBool::new(false);
    let probe: ContractResult = thread::scope(|scope| {
        let flipper = scope.spawn(|| -> Result<u64, String> {
            let mut flips = 0u64;
            let mut level = 0;
            while !stop.load(Ordering::Relaxed) {
                let at = real_dir(level);
                let (real, aside, link) = (
                    at.join(CHAIN[level]),
                    at.join(format!("{}.real", CHAIN[level])),
                    at.join(format!("{}.link", CHAIN[level])),
                );
                // Real -> junction: the name now leads outside, with a gap in between.
                ok(
                    fx.rename(&real, &aside),
                    "flip: move the real directory away",
                )?;
                thread::yield_now();
                ok(
                    fx.rename(&link, &real),
                    "flip: put the junction in its place",
                )?;
                thread::yield_now();
                thread::yield_now();
                // And back.
                ok(fx.rename(&real, &link), "flip: take the junction away")?;
                ok(
                    fx.rename(&aside, &real),
                    "flip: put the real directory back",
                )?;
                flips += 1;
                level = (level + 1) % CHAIN.len();
            }
            Ok(flips)
        });

        let started = Instant::now();
        let mut probes = 0u64;
        let result = (|| -> ContractResult {
            while probes == 0 || started.elapsed() < budget {
                probes += 1;
                if let Some(bytes) = racing(root.read(&data_p), "read data")? {
                    ensure(
                        bytes == b"inside",
                        "race: read of data.txt returned foreign content (outside canary?)",
                    )?;
                }
                ensure(
                    racing(root.read(&canary_p), "read canary")?.is_none(),
                    "race: read of canary-only.txt succeeded (it exists only outside)",
                )?;
                if let Some(Some(m)) = racing(root.metadata(&data_p), "metadata data")? {
                    forbidden.id(m.file_id, "metadata of data.txt")?;
                }
                ensure(
                    racing(root.metadata(&canary_p), "metadata canary")?
                        .flatten()
                        .is_none(),
                    "race: metadata of canary-only.txt found an entry (it exists only outside)",
                )?;
                ensure(
                    racing(root.open_read(&canary_p), "open_read canary")?.is_none(),
                    "race: open_read of canary-only.txt succeeded",
                )?;
                if let Some(entries) = racing(root.read_dir(Some(&dir_p)), "read_dir")? {
                    for e in &entries {
                        ensure(
                            e.name != NAME,
                            "race: read_dir exposed the name canary-only.txt",
                        )?;
                        forbidden.id(e.meta.file_id, "read_dir entry")?;
                    }
                }
                if let Some(h) = racing(root.open_dir(&dir_p), "open_dir")? {
                    forbidden.id(ok(h.info(), "info through the handle")?.file_id, "open_dir")?;
                    if let Some(entries) = racing(h.read_dir(None), "read_dir through handle")? {
                        ensure(
                            entries.iter().all(|e| e.name != NAME),
                            "race: read_dir through the handle exposed canary-only.txt",
                        )?;
                    }
                    ensure(
                        racing(h.read(&name_p), "read canary through handle")?.is_none(),
                        "race: read of canary-only.txt through the handle succeeded",
                    )?;
                    if let Some(bytes) =
                        racing(h.read(&rel("data.txt")?), "read data through handle")?
                    {
                        ensure(
                            bytes == b"inside",
                            "race: read through the handle returned foreign content",
                        )?;
                    }
                }
            }
            Ok(())
        })();
        stop.store(true, Ordering::Relaxed);
        let flips = flipper
            .join()
            .map_err(|_| "contract violated: race: flipper thread panicked".to_owned())
            .and_then(|r| r);
        result?;
        let flips = flips?;
        ensure(
            flips > 0,
            "race: the flipper never completed a flip (the harness did not run)",
        )?;
        Ok(())
    });
    probe?;
    Ok(Skipped::new())
}

/// File system contract, writing side: create, replace, remove, rename, read-only, handles
/// across renames, name spelling. `work` must be an existing, empty directory (fresh for every
/// run). Fake only until `sys::win` can write (phase 2). The removals at the end exercise the
/// remove operations; the runner must not rely on them for cleanup.
pub fn fs_write_contract(fs: &dyn Fs, work: &Path) -> FsContractResult {
    let root = ok(fs.open_dir(work), "open work dir")?;
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
    )?;
    Ok(Skipped::new())
}

/// File system contract with links, writing side (ADR 0007): nothing is created, replaced,
/// removed, renamed or changed through a reparse point below a root, handles survive a swap,
/// hard links and case-sensitive directories are handled. The read side is
/// [`fs_link_read_contract`]. `work` must be an existing, empty directory (fresh for every
/// run); `fx` creates what the API cannot. Fake only until `sys::win` can write (phase 2).
pub fn fs_link_write_contract(fs: &dyn Fs, fx: &dyn FsFixture, work: &Path) -> FsContractResult {
    let mut skips = Skipped::new();
    const CANARY: &[u8] = b"canary";
    let root_abs = work.join("root");
    let outside_abs = work.join("outside");
    let w = ok(fs.open_dir(work), "open work dir")?;
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
    let root = ok(fs.open_dir(&root_abs), "open root")?;
    let root_info = ok(root.info(), "root info")?;
    let link = rel("link")?;

    // Nothing is written through a junction below the root (the read side is checked by
    // `fs_link_read_contract`).
    let through = rel(r"link\canary.txt")?;
    let rp = SysErrorKind::ReparsePoint;
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
    } else {
        skip(&mut skips, "file_symlink");
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
    } else {
        skip(&mut skips, "case_sensitive_dir");
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
    )?;
    Ok(skips)
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

/// Known-folders contract: every folder resolves, stays the same, is a usable absolute path
/// and opens as a directory; no two folders are the same.
///
/// Deliberately **not** part of the contract: that folders nest (`Common Files` inside
/// `Program Files`, the profile inside `Users`). All of them can be relocated, so policy
/// must not rely on it.
pub fn known_folders_contract(sys: &dyn System) -> ContractResult {
    let kf = sys.known_folders();
    let mut seen: Vec<(KnownFolder, RootPath)> = Vec::new();
    for f in KnownFolder::ALL {
        let what = format!("known folder {f}");
        let p = ok(kf.get(f), &what)?;
        ensure(
            ok(kf.get(f), &what)? == p,
            &format!("{what} is stable across calls"),
        )?;
        let s = p
            .to_str()
            .ok_or(format!("contract violated: {what} is not Unicode"))?;
        // Folder redirection may move Roaming to a share; that is never a game root.
        if f == KnownFolder::RoamingAppData && s.starts_with(r"\\") {
            ensure(
                !s.starts_with(r"\\?\") && !s.starts_with(r"\\.\"),
                &format!("{what} is a plain UNC path, not a device path"),
            )?;
            continue;
        }
        let root = RootPath::new(&p)
            .map_err(|e| format!("contract violated: {what} is a drive-letter path: {e}"))?;
        if let Some((other, _)) = seen.iter().find(|(_, r)| *r == root) {
            return Err(format!(
                "contract violated: {what} differs from known folder {other}"
            ));
        }
        let dir = ok(sys.fs().open_dir(&p), &format!("open {what}"))?;
        let info = ok(dir.info(), &format!("info {what}"))?;
        ensure(
            RootPath::from_final_path(&info.final_path).is_ok(),
            &format!("{what} has a drive-letter final path"),
        )?;
        seen.push((f, root));
    }
    Ok(())
}

/// GPU contract: at least one adapter (Windows always lists the Microsoft Basic Render
/// Driver), stable across calls, names fit the DXGI field, LUIDs are unique.
pub fn gpu_contract(sys: &dyn System) -> ContractResult {
    let adapters = ok(sys.gpu().adapters(), "gpu adapters")?;
    ensure(!adapters.is_empty(), "at least one adapter")?;
    ensure(
        ok(sys.gpu().adapters(), "gpu adapters again")? == adapters,
        "adapter list is stable across calls",
    )?;
    let mut luids = std::collections::BTreeSet::new();
    for a in &adapters {
        ensure(!a.name.is_empty(), "adapter name is not empty")?;
        ensure(
            a.name.encode_utf16().count() < MAX_NAME_UTF16,
            "adapter name fits the DXGI field",
        )?;
        ensure(
            !a.name.chars().any(char::is_control),
            "adapter name has no control characters",
        )?;
        ensure(luids.insert(a.luid), "adapter LUIDs are unique")?;
    }
    Ok(())
}
