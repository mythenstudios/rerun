//! Contract tests of the system layer: the same checks for `fake` and `win`.
//!
//! Today they run against `sys::fake`. From phase 1/2 they also run against `sys::win`:
//! the file system contracts in a fresh directory under `target/`, the registry contracts in a
//! private app hive under `target/` and on stable system keys, the rest in Windows Sandbox
//! (`docs/09-testing.md`). That keeps the fake honest.
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
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use super::fs::{Attrs, Dir, EntryKind, Fs, tag};
use super::gpu::MAX_NAME_UTF16;
use super::registry::{
    Hive, MAX_SUBKEYS, MAX_VALUE_BYTES, MAX_VALUES, MAX_VALUES_TOTAL_BYTES, RegKey, RegValue,
    RegView, Registry, reg_type,
};
use super::{KnownFolder, KnownFolders, SysErrorKind, SysResult, System};
use crate::fold::fold;
use crate::path::{RelPath, RootPath};

/// Failed contract with a description.
pub type ContractResult = Result<(), String>;

/// Names of the cases a file system contract skipped because the fixture reported "not
/// available" (`"dir_symlink"`, `"file_symlink"`, `"case_sensitive_dir"`, `"mount_volume"`,
/// `"subst"`, `"short_name"`, `"wof_compress"`, `"restricted"`). Without duplicates.
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
    /// Mounts another volume (own volume serial) in the folder `at`, which is created if
    /// missing. On Windows this is an existing volume of the machine: the contracts never
    /// create anything below `at` and never list it. `Ok(false)` = no second volume.
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
    /// Gives the existing file or directory `p` a DACL that denies the current user every
    /// access, even `FILE_READ_ATTRIBUTES` and `SYNCHRONIZE` (like `ElevatedDiagnostics` or
    /// `ntuser.pol` for a standard user). The runner must still be able to remove it (e.g.
    /// owner keeps `WRITE_DAC`, the fixture restores the DACL before cleanup).
    /// `Ok(false)` = not available.
    fn restricted(&self, p: &Path) -> SysResult<bool>;
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
            && m.links == Some(1)
            && !m.restricted
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
    restricted_entries(fs, fx, &*root, work, &mut skips)?;
    Ok(skips)
}

/// Entries whose own DACL denies the current user every open are neither an error nor
/// dropped: `read_dir` and `metadata` describe them from the listing (`restricted`, link count
/// unknown), and nothing opens them or walks through them (`AccessDenied`).
fn restricted_entries(
    fs: &dyn Fs,
    fx: &dyn FsFixture,
    root: &dyn Dir,
    work: &Path,
    skips: &mut Skipped,
) -> ContractResult {
    let base = work.join("rs");
    let (file_abs, dir_abs) = (base.join("secret.bin"), base.join("locked"));
    ok(fx.file(&file_abs, b"secret"), "fixture secret file")?;
    ok(
        fx.file(&dir_abs.join("inner.txt"), b"inner"),
        "fixture locked dir",
    )?;
    ok(fx.file(&base.join("plain.txt"), b"plain"), "fixture plain")?;
    let both = ok(fx.restricted(&file_abs), "fixture restrict file")?
        && ok(fx.restricted(&dir_abs), "fixture restrict dir")?;
    if !both {
        skip(skips, "restricted");
        return Ok(());
    }
    let ad = SysErrorKind::AccessDenied;
    let listed = ok(root.read_dir(Some(&rel("rs")?)), "read_dir rs")?;
    let entry = |name: &str| {
        listed
            .iter()
            .find(|e| e.name == name)
            .map(|e| e.meta.clone())
            .ok_or(format!(
                "contract violated: read_dir lists a restricted entry ({name} missing)"
            ))
    };
    ensure(listed.len() == 3, "read_dir lists restricted entries")?;
    let (secret, locked, plain) = (entry("secret.bin")?, entry("locked")?, entry("plain.txt")?);
    ensure(
        secret.restricted
            && secret.kind == EntryKind::File
            && secret.len == 6
            && secret.attrs == Attrs::default()
            && secret.links.is_none()
            && !secret.is_single_link()
            && secret.reparse.is_none(),
        "a restricted file: kind, length and attributes from the listing, link count unknown",
    )?;
    ensure(
        locked.restricted && locked.kind == EntryKind::Dir && locked.links.is_none(),
        "a restricted directory is listed as a restricted directory",
    )?;
    ensure(
        !plain.restricted && plain.links == Some(1),
        "a plain sibling is not restricted",
    )?;
    ensure(
        secret.file_id != 0
            && locked.file_id != 0
            && secret.file_id != locked.file_id
            && secret.file_id != plain.file_id
            && locked.file_id != plain.file_id,
        "restricted entries carry their own file IDs",
    )?;
    for (p, listed_meta) in [
        (r"rs\secret.bin", &secret),
        (r"RS\SECRET.BIN", &secret),
        (r"rs\locked", &locked),
    ] {
        ensure(
            ok(root.metadata(&rel(p)?), "metadata restricted")?.as_ref() == Some(listed_meta),
            "metadata of a restricted entry equals its listing entry",
        )?;
    }
    let sub = ok(root.open_dir(&rel("rs")?), "open rs")?;
    ensure(
        ok(sub.metadata(&rel("secret.bin")?), "metadata via sub")?.as_ref() == Some(&secret)
            && ok(sub.read_dir(None), "read_dir via sub")?
                .iter()
                .any(|e| e.name == "locked" && e.meta == locked),
        "a sub handle reports restricted entries the same way",
    )?;
    drop(sub);
    err_kind(
        root.open_read(&rel(r"rs\secret.bin")?),
        ad,
        "open_read restricted",
    )?;
    err_kind(root.read(&rel(r"rs\secret.bin")?), ad, "read restricted")?;
    err_kind(
        root.open_dir(&rel(r"rs\secret.bin")?),
        ad,
        "open_dir on a restricted file",
    )?;
    err_kind(
        root.open_dir(&rel(r"rs\locked")?),
        ad,
        "open_dir restricted",
    )?;
    err_kind(
        root.read_dir(Some(&rel(r"rs\locked")?)),
        ad,
        "read_dir restricted",
    )?;
    err_kind(
        root.open_read(&rel(r"rs\locked")?),
        ad,
        "open_read on a restricted directory",
    )?;
    err_kind(
        root.metadata(&rel(r"rs\locked\inner.txt")?),
        ad,
        "metadata through a restricted directory",
    )?;
    err_kind(
        root.read(&rel(r"rs\locked\inner.txt")?),
        ad,
        "read through a restricted directory",
    )?;
    err_kind(
        fs.open_dir(&dir_abs),
        ad,
        "Fs::open_dir of a restricted directory",
    )?;
    ensure(
        ok(
            root.metadata(&rel(r"rs\nothing")?),
            "metadata missing sibling",
        )?
        .is_none(),
        "a missing sibling of restricted entries is still None",
    )?;
    read_is(root, r"rs\plain.txt", b"plain", "a plain sibling reads")
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
    // While the wof.sys filter is attached (every Windows 10/11 boot) it hides its own
    // reparse point: no FILE_ATTRIBUTE_REPARSE_POINT, no tag in FileAttributeTagInformation
    // or the listing, FSCTL_GET_REPARSE_POINT reports ERROR_NOT_A_REPARSE_POINT. The tag is
    // only seen without the filter, and then it must be WOF.
    ensure(
        m.kind == EntryKind::File
            && m.len == data.len() as u64
            && !m.restricted
            && m.reparse.as_ref().is_none_or(|r| r.tag == tag::WOF),
        "a WOF file is a plain file (with the WOF tag only if the filter does not hide it)",
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
        ma.links == Some(2) && mb.links == Some(2) && ma.file_id == mb.file_id,
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
            // Nothing is created below a mount point (another volume): the walk must stop at
            // the link with `ReparsePoint` whether or not the rest of the path exists there.
            let mut through: Vec<&str> = DIRS[level + 1..].to_vec();
            through.push("game.exe");
            let through_rel = format!("{link_rel}\\{}", through.join("\\"));
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
    // own serial; seen from above it is a name surrogate that is never traversed. Nothing is
    // created on the mounted volume and its root is not listed (on Windows it is an existing
    // volume; a volume root holds in-use system files such as `pagefile.sys`). That
    // `volume_path` counts from the mounted volume's root below it is a fake unit test
    // (`volume_roots_are_reported`).
    let mnt = work.join("mnt");
    if ok(fx.mount_volume(&mnt), "fixture mount")? {
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
        drop(m);
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

/// Upper bound the race contract waits beyond its budget for the first completed flip.
pub const RACE_FIRST_FLIP_GRACE: Duration = Duration::from_secs(30);

/// File system contract, stress race (M-b): while a flipper thread swaps directories for
/// junctions to an outside folder by path (first, middle and last directory level of a three
/// level path), the main thread probes through the root handle. No result that comes back `Ok`
/// may ever contain the outside canary's content, file ID or name. Allowed: `ReparsePoint`,
/// `NotFound` (gap between two renames) and the content of the real file.
///
/// Probes for at least `budget` and until the flipper has completed one flip (at most
/// [`RACE_FIRST_FLIP_GRACE`] longer, so a slow, loaded machine still gets a real race).
/// `work` must be an existing, empty directory. Against `sys::win` the
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

    // A rename by path, retried while it is refused because of the probe: on Windows a
    // directory cannot be renamed while a handle below it was opened without
    // `FILE_SHARE_DELETE` (`open_read` shares read only), which yields `AccessDenied` or
    // `Busy`. Retrying keeps every flip complete; the probe stops before the flipper, so
    // the retries end.
    let flip = |from: &Path, to: &Path, what: &str| -> ContractResult {
        let since = Instant::now();
        loop {
            match fx.rename(from, to) {
                Ok(()) => return Ok(()),
                Err(e)
                    if matches!(e.kind, SysErrorKind::AccessDenied | SysErrorKind::Busy)
                        && since.elapsed() < Duration::from_secs(10) =>
                {
                    thread::yield_now();
                }
                Err(e) => {
                    return Err(format!("contract violated: {what}: unexpected error {e}"));
                }
            }
        }
    };
    let stop = AtomicBool::new(false);
    let flips_done = AtomicU64::new(0);
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
                flip(&real, &aside, "flip: move the real directory away")?;
                thread::yield_now();
                flip(&link, &real, "flip: put the junction in its place")?;
                thread::yield_now();
                thread::yield_now();
                // And back.
                flip(&real, &link, "flip: take the junction away")?;
                flip(&aside, &real, "flip: put the real directory back")?;
                flips += 1;
                flips_done.store(flips, Ordering::Relaxed);
                level = (level + 1) % CHAIN.len();
            }
            Ok(flips)
        });

        let started = Instant::now();
        let mut probes = 0u64;
        let result = (|| -> ContractResult {
            let more = |probes: u64| {
                let t = started.elapsed();
                probes == 0
                    || t < budget
                    || (flips_done.load(Ordering::Relaxed) == 0
                        && t < budget + RACE_FIRST_FLIP_GRACE)
            };
            while more(probes) {
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
                    // `info` resolves the current path of the handle; while an ancestor is
                    // renamed that can fail with `NotFound` (sys::win retries a bounded number
                    // of times). Never a wrong identity.
                    if let Some(i) = racing(h.info(), "info through the handle")? {
                        forbidden.id(i.file_id, "open_dir")?;
                    }
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
        ma.links == Some(2) && mb.links == Some(2) && ma.file_id == mb.file_id,
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
        ok(root.metadata(&a), "metadata a after")?.is_some_and(|m| m.is_single_link())
            && ok(root.metadata(&b), "metadata b after")?.is_some_and(|m| m.is_single_link()),
        "replace splits the links",
    )?;
    ok(
        fx.hardlink(&root_abs.join("b.bin"), &root_abs.join("c.bin")),
        "fixture hardlink c",
    )?;
    ok(root.remove_file(&rel("c.bin")?), "remove one of two links")?;
    read_is(&*root, "b.bin", b"shared", "remaining link intact")?;
    ensure(
        ok(root.metadata(&b), "metadata b last")?.is_some_and(|m| m.is_single_link()),
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

/// Setup that the registry API under test deliberately cannot do while it is read-only: create
/// keys, write values with any type number and bytes, delete a value, create a symbolic-link
/// key. For `sys::fake` it is implemented by `FakeRegistry`; for `sys::win` by test code in a
/// private app hive (ADR 0009).
///
/// The fixture writes exactly what it is told: `raw` stores the type number and bytes as given,
/// without any decoding. Methods that may be unavailable return `Ok(false)` ("not available"):
/// the contract skips that case and reports it in [`Skipped`].
pub trait RegFixture: Sync {
    /// Creates the key `k` including missing parents.
    fn key(&self, k: &RegKey) -> SysResult<()>;
    /// Stores the value `name` of the existing key `k` with type number `kind` and `data`
    /// (overwriting a value of that name).
    fn raw(&self, k: &RegKey, name: &str, kind: u32, data: &[u8]) -> SysResult<()>;
    /// Deletes a value of the existing key `k`.
    fn delete_value(&self, k: &RegKey, name: &str) -> SysResult<()>;
    /// Creates `link` as a symbolic-link key to the existing key `target` (same hive and
    /// view). `Ok(false)` = not available.
    fn link(&self, link: &RegKey, target: &RegKey) -> SysResult<bool>;
    /// Stores the value `name` of the existing key `k` as `REG_BINARY` of `len` bytes (each
    /// `7`). `Ok(false)` = the registry cannot hold one value that large (Windows refuses more
    /// than 1,048,572 bytes, below [`MAX_VALUE_BYTES`]).
    fn large(&self, k: &RegKey, name: &str, len: usize) -> SysResult<bool>;
}

fn sz_bytes(s: &str) -> Vec<u8> {
    s.encode_utf16()
        .chain([0])
        .flat_map(u16::to_le_bytes)
        .collect()
}

fn units_bytes(units: &[u16]) -> Vec<u8> {
    units.iter().flat_map(|u| u.to_le_bytes()).collect()
}

fn multi_bytes(parts: &[&str]) -> Vec<u8> {
    let mut units: Vec<u16> = Vec::new();
    for p in parts {
        units.extend(p.encode_utf16());
        units.push(0);
    }
    units.push(0);
    units_bytes(&units)
}

/// Value names of `values` (original case), sorted.
fn value_names(reg: &dyn Registry, k: &RegKey, what: &str) -> Result<Vec<String>, String> {
    let mut v: Vec<String> = ok(reg.values(k), what)?
        .into_iter()
        .map(|(n, _)| n)
        .collect();
    v.sort();
    Ok(v)
}

fn subkey_names(reg: &dyn Registry, k: &RegKey, what: &str) -> Result<Vec<String>, String> {
    let mut v = ok(reg.subkeys(k), what)?;
    v.sort();
    Ok(v)
}

fn other_view(k: &RegKey) -> RegKey {
    RegKey {
        view: match k.view {
            RegView::Native => RegView::Wow32,
            RegView::Wow32 => RegView::Native,
        },
        ..k.clone()
    }
}

/// The type numbers and bytes of the decoding cases: `(value name, type, bytes, typed value
/// the registry must hand out, or `None` for [`RegValue::Raw`])`.
type DecodeCase = (&'static str, u32, Vec<u8>, Option<RegValue>);

fn decode_cases() -> Vec<DecodeCase> {
    use reg_type::*;
    let sz = |s: &str| Some(RegValue::String(s.to_owned()));
    vec![
        ("sz", REG_SZ, sz_bytes("Steam"), sz("Steam")),
        ("sz_empty", REG_SZ, sz_bytes(""), sz("")),
        (
            "sz_astral",
            REG_SZ,
            sz_bytes("a\u{1F3AE}"),
            sz("a\u{1F3AE}"),
        ),
        ("sz_zero_length", REG_SZ, vec![], None),
        ("sz_odd_length", REG_SZ, vec![b'a', 0, 0], None),
        // RegQueryValueExW zeroes the last byte of this one (ADR 0009).
        ("sz_odd_tail", REG_SZ, vec![b'a', 0, b'b'], None),
        ("sz_no_nul", REG_SZ, units_bytes(&[0x61, 0x62]), None),
        ("sz_two_nuls", REG_SZ, units_bytes(&[0x61, 0, 0]), None),
        (
            "sz_nul_inside",
            REG_SZ,
            units_bytes(&[0x61, 0, 0x62, 0]),
            None,
        ),
        ("sz_lone_surrogate", REG_SZ, units_bytes(&[0xD800, 0]), None),
        (
            "expand",
            REG_EXPAND_SZ,
            sz_bytes(r"%SystemRoot%\system32"),
            Some(RegValue::ExpandString(r"%SystemRoot%\system32".to_owned())),
        ),
        (
            "expand_no_nul",
            REG_EXPAND_SZ,
            units_bytes(&[0x25, 0x25]),
            None,
        ),
        (
            "multi",
            REG_MULTI_SZ,
            multi_bytes(&["a", "bc"]),
            Some(RegValue::MultiString(vec!["a".into(), "bc".into()])),
        ),
        (
            "multi_empty_list",
            REG_MULTI_SZ,
            vec![0, 0],
            Some(RegValue::MultiString(vec![])),
        ),
        ("multi_two_nuls", REG_MULTI_SZ, vec![0, 0, 0, 0], None),
        (
            "multi_empty_element",
            REG_MULTI_SZ,
            units_bytes(&[0x61, 0, 0, 0x62, 0, 0]),
            None,
        ),
        (
            "multi_no_final_nul",
            REG_MULTI_SZ,
            units_bytes(&[0x61, 0]),
            None,
        ),
        (
            "dword",
            REG_DWORD,
            vec![1, 0, 0, 0],
            Some(RegValue::Dword(1)),
        ),
        (
            "dword_high",
            REG_DWORD,
            0xA1B2_C3D4_u32.to_le_bytes().to_vec(),
            Some(RegValue::Dword(0xA1B2_C3D4)),
        ),
        ("dword_3_bytes", REG_DWORD, vec![1, 0, 0], None),
        (
            "dword_8_bytes",
            REG_DWORD,
            vec![1, 0, 0, 0, 0, 0, 0, 0],
            None,
        ),
        (
            "qword",
            REG_QWORD,
            u64::MAX.to_le_bytes().to_vec(),
            Some(RegValue::Qword(u64::MAX)),
        ),
        ("qword_4_bytes", REG_QWORD, vec![1, 0, 0, 0], None),
        (
            "binary_empty",
            REG_BINARY,
            vec![],
            Some(RegValue::Binary(vec![])),
        ),
        (
            "binary",
            REG_BINARY,
            vec![0, 1, 2, 0],
            Some(RegValue::Binary(vec![0, 1, 2, 0])),
        ),
        ("none", REG_NONE, vec![1, 2, 3], None),
        ("none_empty", REG_NONE, vec![], None),
        (
            "dword_big_endian",
            REG_DWORD_BIG_ENDIAN,
            vec![0, 0, 0, 1],
            None,
        ),
        ("link_type", REG_LINK, units_bytes(&[0x61]), None),
        ("resource_list", REG_RESOURCE_LIST, vec![9, 9], None),
        ("unknown_12", 12, vec![1], None),
        ("unknown_big", 0x1234, vec![1, 2], None),
    ]
}

/// Registry read contract: key and value semantics, canonical decoding, input rules, limits
/// for untrusted data and (where the fixture can make one) symbolic-link keys. Only reads go
/// through `reg`; every key and value it needs is made by `fx`.
///
/// `root` must be an existing key without values and subkeys and **outside**
/// `HKLM\SOFTWARE`, where the 32-bit view is not redirected: the runner calls the contract
/// once per view, with different roots (the contract deletes nothing), and the contract checks
/// that the other view sees the same data. The redirection itself is pinned by
/// [`registry_system_contract`].
///
/// Skipped cases: `"key_link"` (no symbolic-link keys), `"value_at_limit"` and
/// `"value_over_limit"` (the registry cannot hold one value of [`MAX_VALUE_BYTES`] or more;
/// Windows stops at 1,048,572 bytes).
pub fn registry_read_contract(
    reg: &dyn Registry,
    fx: &dyn RegFixture,
    root: &RegKey,
) -> Result<Skipped, String> {
    let mut skips = Skipped::new();
    ensure(ok(reg.key_exists(root), "root exists")?, "root exists")?;
    ensure(
        value_names(reg, root, "values of root")?.is_empty()
            && subkey_names(reg, root, "subkeys of root")?.is_empty(),
        "root is empty",
    )?;
    ensure(
        ok(
            reg.key_exists(&RegKey::new(root.hive, root.view, "")),
            "hive root exists",
        )?,
        "the hive root exists",
    )?;

    // Missing key.
    let a = root.join("Alpha");
    ensure(
        !ok(reg.key_exists(&a), "key_exists missing")?,
        "missing key does not exist",
    )?;
    err_kind(
        reg.get(&a, "x"),
        SysErrorKind::NotFound,
        "get on missing key",
    )?;
    err_kind(
        reg.values(&a),
        SysErrorKind::NotFound,
        "values of missing key",
    )?;
    err_kind(
        reg.subkeys(&a),
        SysErrorKind::NotFound,
        "subkeys of missing key",
    )?;

    // An empty key is not a missing key.
    ok(fx.key(&a), "fixture: key")?;
    ensure(ok(reg.key_exists(&a), "key_exists")?, "empty key exists")?;
    ensure(
        ok(reg.get(&a, "Nope"), "get missing value")?.is_none(),
        "missing value = None",
    )?;
    ensure(
        value_names(reg, &a, "values of empty key")?.is_empty()
            && subkey_names(reg, &a, "subkeys of empty key")?.is_empty(),
        "empty key has no values and no subkeys",
    )?;
    ensure(
        subkey_names(reg, root, "subkeys of root")? == ["Alpha"],
        "subkeys keep the original case",
    )?;

    // Names are case-insensitive and keep their case; the default value is "".
    ok(fx.key(&a.join("Child")), "fixture: child")?;
    ok(
        fx.raw(&a, "Flag", reg_type::REG_DWORD, &[1, 0, 0, 0]),
        "fixture: Flag",
    )?;
    ok(
        fx.raw(&a, "", reg_type::REG_SZ, &sz_bytes("default")),
        "fixture: default",
    )?;
    ensure(
        ok(reg.get(&root.join("ALPHA"), "FLAG"), "get other case")? == Some(RegValue::Dword(1)),
        "dword round-trip, case-insensitive key and value name",
    )?;
    ensure(
        ok(reg.get(&a, "Flag"), "get")? != Some(RegValue::String("1".into())),
        "dword differs from string",
    )?;
    ensure(
        ok(reg.get(&a, ""), "get default")? == Some(RegValue::String("default".into())),
        "default value",
    )?;
    ensure(
        value_names(reg, &a, "values")? == ["", "Flag"],
        "value names keep their case, the default value is \"\"",
    )?;
    ensure(
        subkey_names(reg, &root.join("alpha"), "subkeys other case")? == ["Child"],
        "subkeys of a key found by another case",
    )?;
    ensure(
        ok(
            reg.key_exists(&root.join("aLpHa").join("CHILD")),
            "key_exists case",
        )?,
        "key_exists is case-insensitive",
    )?;
    // Non-ASCII names.
    let green = root.join("Gr\u{fc}n");
    ok(fx.key(&green), "fixture: Grün")?;
    ok(
        fx.raw(&green, "Ünï\u{1F3AE}", reg_type::REG_DWORD, &[2, 0, 0, 0]),
        "fixture: unicode value",
    )?;
    ensure(
        ok(reg.key_exists(&root.join("GR\u{dc}N")), "key_exists Ü")?,
        "non-ASCII key names fold",
    )?;
    ensure(
        ok(reg.get(&green, "Ünï\u{1F3AE}"), "get unicode value")? == Some(RegValue::Dword(2)),
        "non-ASCII value name",
    )?;
    ensure(
        value_names(reg, &green, "values")? == ["Ünï\u{1F3AE}"],
        "non-ASCII value name keeps its case",
    )?;
    // A value name may contain a backslash.
    ok(
        fx.raw(&green, r"a\b", reg_type::REG_DWORD, &[3, 0, 0, 0]),
        "fixture: a\\b",
    )?;
    ensure(
        ok(reg.get(&green, r"a\b"), "get a\\b")? == Some(RegValue::Dword(3)),
        "value name with a backslash",
    )?;

    // The other view sees the same data below a root outside SOFTWARE.
    let other = other_view(&a);
    ensure(
        ok(reg.get(&other, "Flag"), "get through the other view")? == Some(RegValue::Dword(1)),
        "keys outside HKLM\\SOFTWARE are shared between the views",
    )?;
    ensure(
        subkey_names(reg, &other, "subkeys through the other view")? == ["Child"],
        "subkeys through the other view",
    )?;

    // Every decoding case: the exact stored type and bytes come back, typed only when canonical.
    let types = root.join("Types");
    ok(fx.key(&types), "fixture: Types")?;
    let cases = decode_cases();
    for (name, kind, data, _) in &cases {
        ok(
            fx.raw(&types, name, *kind, data),
            &format!("fixture: {name}"),
        )?;
    }
    for (name, kind, data, typed) in &cases {
        let what = format!("decoding case {name}");
        let got = ok(reg.get(&types, name), &what)?
            .ok_or(format!("contract violated: {what}: missing"))?;
        ensure(
            got.encode() == Some((*kind, data.clone())),
            &format!("{what}: exact type and bytes"),
        )?;
        match typed {
            Some(v) => ensure(got == *v, &format!("{what}: typed value"))?,
            None => ensure(
                matches!(got, RegValue::Raw(_)),
                &format!("{what}: raw value"),
            )?,
        }
        ensure(
            got == RegValue::decode(*kind, data),
            &format!("{what}: same as RegValue::decode"),
        )?;
    }
    let all = ok(reg.values(&types), "values of Types")?;
    ensure(all.len() == cases.len(), "values lists every value")?;
    for (name, value) in &all {
        let one = ok(reg.get(&types, name), "get")?;
        ensure(
            one.as_ref() == Some(value),
            &format!("values and get agree on {name}"),
        )?;
    }

    // Input rules: InvalidPath before anything touches the registry.
    let bad_keys = [
        (
            "NUL in key",
            RegKey {
                path: format!("{}\\Bad\0Name", root.path),
                ..root.clone()
            },
        ),
        (
            "empty segment",
            RegKey {
                path: format!("{}\\\\Alpha", root.path),
                ..root.clone()
            },
        ),
        (
            "leading backslash",
            RegKey {
                path: format!("\\{}", root.path),
                ..root.clone()
            },
        ),
        (
            "trailing backslash",
            RegKey {
                path: format!("{}\\", root.path),
                ..root.clone()
            },
        ),
        ("segment of 256 units", root.join(&"s".repeat(256))),
        (
            "segment of 128 astral characters",
            root.join(&"\u{1F3AE}".repeat(128)),
        ),
        (
            "path over 32,767 units",
            RegKey {
                path: vec!["p".repeat(255); 130].join("\\"),
                ..root.clone()
            },
        ),
    ];
    for (what, k) in &bad_keys {
        err_kind(
            reg.key_exists(k),
            SysErrorKind::InvalidPath,
            &format!("key_exists: {what}"),
        )?;
        err_kind(
            reg.get(k, "x"),
            SysErrorKind::InvalidPath,
            &format!("get: {what}"),
        )?;
        err_kind(
            reg.values(k),
            SysErrorKind::InvalidPath,
            &format!("values: {what}"),
        )?;
        err_kind(
            reg.subkeys(k),
            SysErrorKind::InvalidPath,
            &format!("subkeys: {what}"),
        )?;
    }
    for (what, name) in [
        ("NUL in value name", "Bad\0Name".to_owned()),
        ("value name of 16,384 units", "n".repeat(16_384)),
        (
            "value name of 8,192 astral characters",
            "\u{1F3AE}".repeat(8_192),
        ),
    ] {
        err_kind(
            reg.get(&a, &name),
            SysErrorKind::InvalidPath,
            &format!("get: {what}"),
        )?;
    }
    // Exactly at the limits is valid.
    let long_key = root.join(&"s".repeat(255));
    ok(fx.key(&long_key), "fixture: segment of 255 units")?;
    ensure(
        ok(reg.key_exists(&long_key), "key_exists long segment")?,
        "a segment of 255 units is valid",
    )?;
    let long_name = "n".repeat(16_383);
    ok(
        fx.raw(&a, &long_name, reg_type::REG_DWORD, &[4, 0, 0, 0]),
        "fixture: value name of 16,383 units",
    )?;
    ensure(
        ok(reg.get(&a, &long_name), "get long name")? == Some(RegValue::Dword(4)),
        "a value name of 16,383 units is valid",
    )?;

    // Limits for untrusted data: Unsupported, never a partial result.
    let blob = |n: usize| vec![7_u8; n];
    let big = root.join("Big");
    ok(fx.key(&big), "fixture: Big")?;
    // Half the limit: far above any first buffer, so reads must grow theirs.
    let half = MAX_VALUE_BYTES / 2;
    ok(
        fx.raw(&big, "half", reg_type::REG_BINARY, &blob(half)),
        "fixture: half of the value limit",
    )?;
    ensure(
        ok(reg.get(&big, "half"), "get half")? == Some(RegValue::Binary(blob(half))),
        "a value of half the limit is returned exactly",
    )?;
    if ok(
        fx.large(&big, "at", MAX_VALUE_BYTES),
        "fixture: value at the limit",
    )? {
        ensure(
            ok(reg.get(&big, "at"), "get at the limit")?.is_some(),
            "a value at the limit is returned",
        )?;
        ensure(
            ok(reg.values(&big), "values with a value at the limit")?.len() == 2,
            "values with a value at the limit",
        )?;
    } else {
        skip(&mut skips, "value_at_limit");
    }
    if ok(
        fx.large(&big, "over", MAX_VALUE_BYTES + 1),
        "fixture: value over the limit",
    )? {
        err_kind(
            reg.get(&big, "over"),
            SysErrorKind::Unsupported,
            "get of a value over the limit",
        )?;
        err_kind(
            reg.values(&big),
            SysErrorKind::Unsupported,
            "values with a value over the limit",
        )?;
        ensure(
            ok(reg.get(&big, "half"), "get after refusal")?.is_some(),
            "other values stay readable",
        )?;
        ok(fx.delete_value(&big, "over"), "fixture: delete over")?;
        ensure(
            ok(reg.values(&big), "values after the large value is gone")?
                .iter()
                .all(|(n, _)| n != "over"),
            "values works again",
        )?;
    } else {
        skip(&mut skips, "value_over_limit");
    }

    // The total: values of half the value limit (which every registry can hold) up to exactly
    // the limit, then one byte more.
    let total = root.join("Total");
    ok(fx.key(&total), "fixture: Total")?;
    let parts = MAX_VALUES_TOTAL_BYTES / half;
    for i in 0..parts {
        ok(
            fx.raw(&total, &format!("v{i}"), reg_type::REG_BINARY, &blob(half)),
            "fixture: the total limit",
        )?;
    }
    ensure(
        ok(reg.values(&total), "values at the total limit")?.len() == parts,
        "values with exactly the total limit",
    )?;
    ok(
        fx.raw(&total, "one more", reg_type::REG_BINARY, &[1]),
        "fixture: one byte more",
    )?;
    err_kind(
        reg.values(&total),
        SysErrorKind::Unsupported,
        "values over the total limit",
    )?;

    let many = root.join("Many");
    ok(fx.key(&many), "fixture: Many")?;
    for i in 0..MAX_VALUES {
        ok(
            fx.raw(&many, &format!("v{i}"), reg_type::REG_DWORD, &[1, 0, 0, 0]),
            "fixture: 16,384 values",
        )?;
    }
    ensure(
        ok(reg.values(&many), "values with 16,384")?.len() == MAX_VALUES,
        "values with 16,384 values",
    )?;
    ok(
        fx.raw(&many, "one more", reg_type::REG_DWORD, &[1, 0, 0, 0]),
        "fixture: one value more",
    )?;
    err_kind(
        reg.values(&many),
        SysErrorKind::Unsupported,
        "values over 16,384 values",
    )?;

    let subs = root.join("Subs");
    ok(fx.key(&subs), "fixture: Subs")?;
    for i in 0..MAX_SUBKEYS {
        ok(
            fx.key(&subs.join(&format!("k{i}"))),
            "fixture: 65,536 subkeys",
        )?;
    }
    ensure(
        ok(reg.subkeys(&subs), "subkeys with 65,536")?.len() == MAX_SUBKEYS,
        "subkeys with 65,536 names",
    )?;
    ok(fx.key(&subs.join("one more")), "fixture: one subkey more")?;
    err_kind(
        reg.subkeys(&subs),
        SysErrorKind::Unsupported,
        "subkeys over 65,536 names",
    )?;

    // Symbolic-link keys are followed on reads.
    let link = root.join("Link");
    if ok(fx.link(&link, &a), "fixture: link")? {
        ensure(
            ok(reg.key_exists(&link), "key_exists link")?,
            "a link key exists",
        )?;
        ensure(
            ok(reg.get(&link, "Flag"), "get through link")? == Some(RegValue::Dword(1)),
            "a value is read through a link",
        )?;
        ensure(
            subkey_names(reg, &link, "subkeys through link")? == ["Child"],
            "subkeys are read through a link",
        )?;
        ensure(
            ok(reg.values(&link), "values through link")? == ok(reg.values(&a), "values")?,
            "values are read through a link",
        )?;
        ensure(
            ok(reg.key_exists(&link.join("Child")), "key_exists below link")?,
            "a key below a link exists",
        )?;
    } else {
        skip(&mut skips, "key_link");
    }
    Ok(skips)
}

/// Value of `name` of `k` as text (a `REG_SZ`, or a `REG_EXPAND_SZ` that is not expanded).
fn text_value(reg: &dyn Registry, k: &RegKey, name: &str) -> Result<String, String> {
    match ok(reg.get(k, name), &format!("get {k} @ {name}"))? {
        Some(RegValue::String(s) | RegValue::ExpandString(s)) => Ok(s),
        other => Err(format!(
            "contract violated: {k} @ {name} is not text: {other:?}"
        )),
    }
}

/// Registry system contract: read-only checks on keys that every Windows has, so that the
/// WOW64 views, links and access errors are pinned on the real system and on a seeded fake
/// (the fake must hold `ProgramFilesDir` and `CommonFilesDir` below `HKLM\SOFTWARE` and
/// `HKLM\SOFTWARE\WOW6432Node`, `HKLM\SYSTEM\CurrentControlSet\Control`, and `HKLM\SECURITY`
/// denied):
///
/// - `ProgramFilesDir` and `CommonFilesDir` of `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion`
///   in the native view are the known folders `ProgramFiles` and `ProgramFilesCommon`, in the
///   32-bit view `ProgramFilesX86` and `ProgramFilesCommonX86` (case-insensitive).
/// - The 32-bit view of `HKLM\SOFTWARE\X` is `HKLM\SOFTWARE\WOW6432Node\X` of the native view
///   (`WOW6432Node` is the alias; the logical path never names it).
/// - `HKLM\SYSTEM\CurrentControlSet` (a link on Windows) has a `Control` subkey.
/// - `HKLM\SECURITY` is `AccessDenied` for `key_exists`, also for an administrator.
///
/// Whether an explicit `WOW6432Node` in the 32-bit view names the same key is deliberately
/// not part of the contract (ADR 0009). Skipped case: `"security_denied"` (the process can
/// open `HKLM\SECURITY`, e.g. it runs as SYSTEM).
pub fn registry_system_contract(
    reg: &dyn Registry,
    kf: &dyn KnownFolders,
) -> Result<Skipped, String> {
    let mut skips = Skipped::new();
    let cv = r"SOFTWARE\Microsoft\Windows\CurrentVersion";
    let native = RegKey::new(Hive::LocalMachine, RegView::Native, cv);
    let wow = RegKey::new(Hive::LocalMachine, RegView::Wow32, cv);
    let alias = RegKey::new(
        Hive::LocalMachine,
        RegView::Native,
        r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion",
    );

    let same = |value: String, folder: KnownFolder, what: &str| -> ContractResult {
        let p = ok(kf.get(folder), &format!("known folder {folder}"))?;
        ensure(
            fold(&value) == fold(&p.display().to_string()),
            &format!(
                "{what} is the known folder {folder}: {value:?} vs {}",
                p.display()
            ),
        )
    };
    same(
        text_value(reg, &native, "ProgramFilesDir")?,
        KnownFolder::ProgramFiles,
        "native ProgramFilesDir",
    )?;
    same(
        text_value(reg, &native, "CommonFilesDir")?,
        KnownFolder::ProgramFilesCommon,
        "native CommonFilesDir",
    )?;
    same(
        text_value(reg, &wow, "ProgramFilesDir")?,
        KnownFolder::ProgramFilesX86,
        "32-bit ProgramFilesDir",
    )?;
    same(
        text_value(reg, &wow, "CommonFilesDir")?,
        KnownFolder::ProgramFilesCommonX86,
        "32-bit CommonFilesDir",
    )?;
    for name in ["ProgramFilesDir", "CommonFilesDir"] {
        ensure(
            text_value(reg, &wow, name)? == text_value(reg, &alias, name)?,
            &format!(
                "the 32-bit view of SOFTWARE\\X is SOFTWARE\\WOW6432Node\\X of the native view ({name})"
            ),
        )?;
    }
    ensure(
        ok(
            reg.key_exists(&RegKey::new(
                Hive::LocalMachine,
                RegView::Native,
                "SOFTWARE",
            )),
            "SOFTWARE",
        )? && ok(
            reg.key_exists(&RegKey::new(Hive::LocalMachine, RegView::Wow32, "SOFTWARE")),
            "SOFTWARE (32-bit)",
        )?,
        "HKLM\\SOFTWARE itself exists in both views",
    )?;

    // Links: CurrentControlSet points to a ControlSet00x.
    ensure(
        ok(
            reg.key_exists(&RegKey::new(
                Hive::LocalMachine,
                RegView::Native,
                r"SYSTEM\CurrentControlSet\Control",
            )),
            "CurrentControlSet\\Control",
        )?,
        "HKLM\\SYSTEM\\CurrentControlSet\\Control exists",
    )?;

    // Access errors.
    match reg.key_exists(&RegKey::new(
        Hive::LocalMachine,
        RegView::Native,
        "SECURITY",
    )) {
        Err(e) if e.kind == SysErrorKind::AccessDenied => {}
        Err(e) => {
            return Err(format!(
                "contract violated: HKLM\\SECURITY: expected access denied, got error {e}"
            ));
        }
        Ok(_) => skip(&mut skips, "security_denied"),
    }
    Ok(skips)
}

/// Registry write contract. `root` must be an existing key without values and subkeys.
/// Runs against the fake only until `sys::win` can write (phase 2); then in a private app hive
/// (ADR 0009).
pub fn registry_write_contract(reg: &dyn Registry, root: &RegKey) -> ContractResult {
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

    // Raw values are stored exactly; a typed value without a canonical encoding is refused.
    let raw = RegValue::decode(reg_type::REG_NONE, &[1, 2, 3]);
    ok(reg.set(&a, "Raw", &raw), "set raw")?;
    ensure(
        ok(reg.get(&a, "Raw"), "get raw")? == Some(raw),
        "raw value round-trip",
    )?;
    err_kind(
        reg.set(&a, "Bad", &RegValue::String("a\0b".into())),
        SysErrorKind::Unsupported,
        "set string with NUL",
    )?;
    ensure(
        ok(reg.get(&a, "Bad"), "get refused value")?.is_none(),
        "a refused value is not stored",
    )?;
    ok(reg.delete_value(&a, "Raw"), "delete raw")?;

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
pub fn known_folders_contract(kf: &dyn KnownFolders, fs: &dyn Fs) -> ContractResult {
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
        let dir = ok(fs.open_dir(&p), &format!("open {what}"))?;
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
