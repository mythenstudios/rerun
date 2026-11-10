//! Package files from the verified archive into `<AppDir>\packages\<id>\<version>` (ADR 0025
//! part 2, P4-7).
//!
//! [`extract`] runs in this order and skips nothing:
//! 1. **Standard user only**, like the download (`exec::standard_user`).
//! 2. **The layout** ([`layout`]): where each `files[]` entry lies below the version folder. A
//!    package with one download keeps the archive's names (`from`); a package with one
//!    download per architecture (`assets`) puts each architecture's files below a folder of
//!    its name (`x86\…`, `x64\…`), because the same `from` (Ultimate ASI Loader's
//!    `dinput8.dll`) is another file in each build. An entry without `arch` comes from every
//!    asset; one with `arch` only from those. One place never gets two hashes.
//! 3. **The packages folder** `<AppDir>\packages` is opened (created) handle-relative, never
//!    through a reparse point, and `packages\.lock` is held (share 0) for the whole run; the
//!    version folder and every folder below it are created one level at a time, the version
//!    folder only right before the first file is written.
//! 4. **Per download:** if every file it provides is there with its pinned SHA-256 (hashed on a
//!    guard), the archive is not read at all. Otherwise the cached archive `cache\<sha256>` is
//!    read whole (at most the download limit) and hashed again; another hash is refused
//!    ("fetch it again"), a missing one too ("fetch it first"). Its format comes from the
//!    download's file name (`.zip`, `.tar.gz`, `.tgz`; anything else is refused) and
//!    [`Archive::open`] checks its whole structure.
//! 5. **Only named entries:** each file is looked up by its `from`, exactly (after the
//!    archive's `/` became `\`, case included); nothing else is ever written. Its content
//!    streams from the archive reader (size and CRC-32 checked) through
//!    `DirWrite::create_new` (temp file, hashed, renamed without replace): a hash other than
//!    `files[].sha256`, a damaged entry or any write error leaves nothing under the name. A file
//!    already there with other content is deleted on its guard first; temp files an
//!    interrupted run left in a folder are deleted before it is written (under the lock none
//!    can be in use).
//!
//! The packages folder is Rerun's store, not the game: nothing here is journaled, and
//! `file_install` hashes every source again when it plans and while it copies.

use sha2::{Digest, Sha256};

use crate::catalog::model::{Arch, Package};
use crate::journal::InstanceTag;
use crate::path::RelPath;
use crate::policy::root::{AppDir, AppSub, Create, RootError};
use crate::sys::fs::{Attrs, EntryKind, NewFile, TmpName};
use crate::sys::{DirWrite, SysError, SysErrorKind, System};

use super::archive::{Archive, ArchiveError, Entry, EntryReader, Extraction, Format, Limits};
use super::download::{Download, FetchError, MAX_DOWNLOAD_BYTES, cache_name, downloads};

/// The lock file of the packages folder (not a package ID: those never start with `.`).
const LOCK: &str = ".lock";
/// Most entries of a folder listed when temp files are swept.
const MAX_SWEEP_ENTRIES: usize = 4096;

/// One file of a package at its place below the version folder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Placed {
    /// The asset it comes from (`None`: the package's one download).
    pub arch: Option<Arch>,
    /// Its name in the archive.
    pub from: RelPath,
    /// Its place below the version folder.
    pub dest: RelPath,
    /// Its pinned SHA-256.
    pub sha256: [u8; 32],
}

/// Every file of `p` at its place (module docs, step 2; `Package::place`, the rule the loader
/// and the planner share), each place once.
pub fn layout(p: &Package) -> Result<Vec<Placed>, ExtractError> {
    let bad = |why: String| ExtractError::Layout {
        id: p.id.to_string(),
        why,
    };
    let mut out: Vec<Placed> = Vec::new();
    for f in &p.files {
        let sha256 = *f
            .sha256
            .bytes()
            .ok_or_else(|| bad(format!("{}: its SHA-256 is TODO", f.from)))?;
        for arch in p.file_archs(f) {
            let dest = p.place(f, arch).ok_or_else(|| {
                bad(format!(
                    "{}: no asset for {}",
                    crate::escape::path(f.from.as_str()),
                    arch.map_or("its architecture", Arch::as_str)
                ))
            })?;
            if let Some(o) = out.iter().find(|o| o.dest == dest) {
                if o.sha256 != sha256 {
                    return Err(bad(format!(
                        "{} has two SHA-256 values",
                        crate::escape::path(dest.as_str())
                    )));
                }
                continue;
            }
            out.push(Placed {
                arch,
                from: f.from.clone(),
                dest,
                sha256,
            });
        }
    }
    Ok(out)
}

/// How one file came to be in the version folder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum How {
    /// It was there with its pinned SHA-256 (hashed again).
    Present,
    /// Extracted now.
    Extracted,
    /// Extracted now over a file with other content, which was deleted.
    Replaced,
    /// A file with other content was deleted, and the run failed before its replacement was
    /// written (a change all the same: `package fetch` reports it).
    Removed,
}

/// One file of the version folder after [`extract`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unpacked {
    /// Its place below the version folder.
    pub dest: RelPath,
    /// Its length.
    pub len: u64,
    /// How it got there.
    pub how: How,
}

/// Why an extraction failed. Names from the archive are shown only escaped.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ExtractError {
    /// The process is elevated (or its elevation is unknown).
    #[error(
        "extraction is refused in an elevated process (or one whose elevation cannot be determined)"
    )]
    Elevated,
    /// The package's downloads (none, a TODO, a URL outside the rules).
    #[error(transparent)]
    Download(#[from] FetchError),
    /// The package's files cannot be placed.
    #[error("package {id}: {why}")]
    Layout {
        /// The package.
        id: String,
        /// Why.
        why: String,
    },
    /// The download's file name names no format Rerun reads.
    #[error("package {id}: {url} is not a .zip, .tar.gz or .tgz archive")]
    Format {
        /// The package.
        id: String,
        /// The URL.
        url: String,
    },
    /// The archive is not in the cache.
    #[error("package {id}: the archive is not in the cache; run rerun package fetch first")]
    NotCached {
        /// The package.
        id: String,
    },
    /// The cached archive does not hash to its pin.
    #[error("package {id}: the cached archive has changed; run rerun package fetch again")]
    CacheChanged {
        /// The package.
        id: String,
    },
    /// The archive or an entry is refused.
    #[error("package {id}: {error}")]
    Archive {
        /// The package.
        id: String,
        /// Why.
        error: ArchiveError,
    },
    /// An extracted file does not have its pinned SHA-256; nothing was kept.
    #[error("package {id}: {} does not have its pinned SHA-256; nothing was kept", crate::escape::path(.file))]
    Mismatch {
        /// The package.
        id: String,
        /// The file below the version folder.
        file: String,
    },
    /// A file or folder of the packages folder Rerun never uses (a link, a reparse point, a
    /// folder where a file belongs, or the other way round).
    #[error("{} in Rerun's packages folder cannot be used ({error}); remove it", crate::escape::path(.name))]
    Entry {
        /// Its path below the version folder.
        name: String,
        /// Why.
        error: SysError,
    },
    /// A file of the packages folder that cannot be used now (in use); try again.
    #[error("{} in Rerun's packages folder cannot be used now ({error}); try again", crate::escape::path(.name))]
    Busy {
        /// Its path below the version folder.
        name: String,
        /// Why.
        error: SysError,
    },
    /// Rerun's folder, `packages` or `cache`.
    #[error(transparent)]
    Root(Box<RootError>),
    /// The file system.
    #[error(transparent)]
    Sys(SysError),
}

impl ExtractError {
    /// Passing or in the environment (try again), as `FetchError::transient`.
    pub fn transient(&self) -> bool {
        match self {
            Self::Busy { .. } | Self::Root(_) | Self::Sys(_) => true,
            Self::Download(e) => e.transient(),
            _ => false,
        }
    }
}

impl From<RootError> for ExtractError {
    fn from(e: RootError) -> Self {
        Self::Root(Box::new(e))
    }
}

impl From<SysError> for ExtractError {
    fn from(e: SysError) -> Self {
        Self::Sys(e)
    }
}

fn seg(s: &str) -> Result<RelPath, ExtractError> {
    RelPath::from_segment(s)
        .map_err(|_| ExtractError::Sys(SysError::new(SysErrorKind::InvalidPath, s)))
}

/// A guard, open or create error at `name`: a link, reparse point, folder where a file belongs
/// (or the other way round) or a bad name is never used (remove it); anything else is passing.
fn entry_error(name: &RelPath, error: SysError) -> ExtractError {
    let name = name.as_str().to_owned();
    match error.kind {
        SysErrorKind::Linked
        | SysErrorKind::ReparsePoint
        | SysErrorKind::AccessDenied
        | SysErrorKind::InvalidPath
        | SysErrorKind::AlreadyExists => ExtractError::Entry { name, error },
        _ => ExtractError::Busy { name, error },
    }
}

/// The subfolder `p` of `base` with the write capability (`None`: `base` itself).
fn sub<'d>(
    base: &'d dyn DirWrite,
    p: Option<&RelPath>,
) -> Result<Option<Box<dyn DirWrite + 'd>>, ExtractError> {
    p.map(|p| base.open_dir_write(p).map_err(|e| entry_error(p, e)))
        .transpose()
}

/// Makes sure the folder `rel` exists below `base`: each missing level created on its own, an
/// existing one must be a plain folder (a reparse point anywhere is refused by the walk).
fn ensure_dirs(base: &dyn DirWrite, rel: &RelPath) -> Result<(), ExtractError> {
    let mut prefix: Option<RelPath> = None;
    for s in rel.segments() {
        let name = seg(s)?;
        let here = match &prefix {
            None => name.clone(),
            Some(p) => p
                .child(s)
                .map_err(|_| ExtractError::Sys(SysError::new(SysErrorKind::InvalidPath, s)))?,
        };
        match base.metadata(&here).map_err(|e| entry_error(&here, e))? {
            Some(m) if m.kind == EntryKind::Dir && m.reparse.is_none() && !m.restricted => {}
            Some(_) => {
                return Err(entry_error(
                    &here,
                    SysError::new(SysErrorKind::AlreadyExists, here.as_str()),
                ));
            }
            None => {
                let parent = sub(base, prefix.as_ref())?;
                let dir: &dyn DirWrite = parent.as_deref().unwrap_or(base);
                dir.create_dir(&name).map_err(|e| entry_error(&here, e))?;
            }
        }
        prefix = Some(here);
    }
    Ok(())
}

/// Deletes the temp files an interrupted run left in `dir` (best effort, under the lock).
fn sweep(dir: &dyn DirWrite) {
    let Ok(entries) = dir.read_dir_limited(None, MAX_SWEEP_ENTRIES) else {
        return;
    };
    for e in entries {
        if e.meta.kind != EntryKind::File || TmpName::parse(&e.name).is_none() {
            continue;
        }
        let Ok(name) = RelPath::from_segment(&e.name) else {
            continue;
        };
        if let Ok(mut g) = dir.guard(&name)
            && let Ok(sha) = g.sha256()
        {
            let _ = g.delete(&sha);
        }
    }
}

/// Whether `dest` is there with `sha256`: `Some(len)` yes; `None` no file, or one with other
/// content, which is deleted (`replaced` set).
fn check_present(
    version: &dyn DirWrite,
    dest: &RelPath,
    sha256: &[u8; 32],
    replaced: &mut bool,
) -> Result<Option<u64>, ExtractError> {
    match version.metadata(dest) {
        Ok(None) => return Ok(None),
        // A missing folder on the way.
        Err(e) if e.kind == SysErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(entry_error(dest, e)),
        Ok(Some(m)) if m.kind != EntryKind::File || m.reparse.is_some() => {
            return Err(entry_error(
                dest,
                SysError::new(SysErrorKind::AccessDenied, dest.as_str()),
            ));
        }
        Ok(Some(_)) => {}
    }
    let parent = sub(version, dest.parent().as_ref())?;
    let dir: &dyn DirWrite = parent.as_deref().unwrap_or(version);
    let name = seg(dest.file_name())?;
    let entry = |e| entry_error(dest, e);
    let mut g = dir.guard(&name).map_err(entry)?;
    let have = g.sha256().map_err(entry)?;
    if &have == sha256 {
        return Ok(Some(g.metadata().map_err(entry)?.len));
    }
    g.delete(&have).map_err(entry)?;
    *replaced = true;
    Ok(None)
}

/// The archive of `d`, read whole from the cache and hashed again.
fn read_cached(app: &AppDir<'_>, id: &str, d: &Download) -> Result<Vec<u8>, ExtractError> {
    let not_cached = || ExtractError::NotCached { id: id.to_owned() };
    let cache = app.sub(AppSub::Cache)?.ok_or_else(not_cached)?;
    let name = seg(&cache_name(d.sha256()))?;
    let bytes = match cache.read_limited(&name, MAX_DOWNLOAD_BYTES) {
        Ok(b) => b,
        Err(e) if e.kind == SysErrorKind::NotFound => return Err(not_cached()),
        Err(e) if e.kind == SysErrorKind::TooLarge => {
            return Err(ExtractError::CacheChanged { id: id.to_owned() });
        }
        Err(e) => return Err(entry_error(&name, e)),
    };
    let have: [u8; 32] = Sha256::digest(&bytes).into();
    if &have != d.sha256() {
        return Err(ExtractError::CacheChanged { id: id.to_owned() });
    }
    Ok(bytes)
}

/// The format named by the last segment of the download's path (its query aside).
fn format_of(id: &str, d: &Download) -> Result<Format, ExtractError> {
    let path = d.url().path();
    let path = path.split_once('?').map_or(path, |(p, _)| p);
    let file = path.rsplit('/').next().unwrap_or_default();
    Format::of_file_name(file).ok_or_else(|| ExtractError::Format {
        id: id.to_owned(),
        url: d.url().to_string(),
    })
}

/// Why the write of one file stopped.
enum WriteStop {
    /// The content is not the pinned one (nothing was kept).
    Mismatch(String),
    Other(ExtractError),
}

/// Extracts the files of `p` into `<AppDir>\packages\<id>\<version>` (module docs). The
/// package's archives must be in the cache (`download::fetch`).
pub fn extract(
    sys: &dyn System,
    app: &AppDir<'_>,
    p: &Package,
) -> Result<Vec<Unpacked>, ExtractError> {
    let mut done = Vec::new();
    extract_with(sys, app, p, &Limits::DEFAULT, &mut done)?;
    Ok(done)
}

/// [`extract`] that collects into `done` what it did, also when it fails afterwards: `package
/// fetch` then reports progress instead of "nothing changed" (ADR 0025, exit codes).
pub fn extract_noting(
    sys: &dyn System,
    app: &AppDir<'_>,
    p: &Package,
    done: &mut Vec<Unpacked>,
) -> Result<(), ExtractError> {
    extract_with(sys, app, p, &Limits::DEFAULT, done)
}

/// [`extract_noting`] with other archive limits (tests).
pub(crate) fn extract_with(
    sys: &dyn System,
    app: &AppDir<'_>,
    p: &Package,
    limits: &Limits,
    done: &mut Vec<Unpacked>,
) -> Result<(), ExtractError> {
    crate::exec::standard_user(sys).map_err(|_| ExtractError::Elevated)?;
    let id = p.id.as_str();
    let dls = downloads(p)?;
    let placed = layout(p)?;
    // A package without files has nothing to unpack: nothing is created.
    if placed.is_empty() {
        return Ok(());
    }
    let packages = app
        .sub_write(AppSub::Packages, Create::IfMissing)?
        .ok_or_else(|| SysError::new(SysErrorKind::NotFound, "packages"))?;
    let _lock = packages.lock(&seg(LOCK)?)?;
    let version_rel = seg(id)?
        .child(&p.version)
        .map_err(|_| ExtractError::Layout {
            id: id.to_owned(),
            why: "not a valid version folder".to_owned(),
        })?;
    // The version folder is created only right before the first file is written (a refused
    // archive leaves none, and the planner's refusal then names `package fetch`).
    let mut version: Option<Box<dyn DirWrite + '_>> = match packages.open_dir_write(&version_rel) {
        Ok(d) => Some(d),
        Err(e) if e.kind == SysErrorKind::NotFound => None,
        Err(e) => return Err(entry_error(&version_rel, e)),
    };
    let tag = InstanceTag::new().get();
    let mut n = 0u64;
    for d in &dls {
        let mut todo: Vec<(&Placed, bool)> = Vec::new();
        for x in placed.iter().filter(|x| x.arch == d.arch()) {
            let Some(v) = version.as_deref() else {
                todo.push((x, false));
                continue;
            };
            let mut replaced = false;
            match check_present(v, &x.dest, &x.sha256, &mut replaced)? {
                Some(len) => done.push(Unpacked {
                    dest: x.dest.clone(),
                    len,
                    how: How::Present,
                }),
                None => {
                    if replaced {
                        done.push(Unpacked {
                            dest: x.dest.clone(),
                            len: 0,
                            how: How::Removed,
                        });
                    }
                    todo.push((x, replaced));
                }
            }
        }
        if todo.is_empty() {
            continue;
        }
        let format = format_of(id, d)?;
        let bytes = read_cached(app, id, d)?;
        let archive_err = |error| ExtractError::Archive {
            id: id.to_owned(),
            error,
        };
        let archive = Archive::open(&bytes, format, limits).map_err(archive_err)?;
        let mut wanted = Vec::with_capacity(todo.len());
        for (x, _) in &todo {
            wanted.push(archive.find(&x.from).map_err(archive_err)?);
        }
        if version.is_none() {
            ensure_dirs(&*packages, &version_rel)?;
            version = Some(
                packages
                    .open_dir_write(&version_rel)
                    .map_err(|e| entry_error(&version_rel, e))?,
            );
        }
        let version: &dyn DirWrite = version
            .as_deref()
            .ok_or_else(|| SysError::new(SysErrorKind::NotFound, version_rel.as_str()))?;
        let mut sink = |e: &Entry, r: &mut EntryReader<'_>| -> Result<(), WriteStop> {
            let other = WriteStop::Other;
            let Some((x, replaced)) = todo
                .iter()
                .find(|(x, _)| x.from.same_spelling(&e.name))
                .copied()
            else {
                return Err(other(ExtractError::Sys(SysError::new(
                    SysErrorKind::Other,
                    "an archive entry that was not asked for",
                ))));
            };
            if let Some(parent) = x.dest.parent() {
                ensure_dirs(version, &parent).map_err(other)?;
            }
            let parent = sub(version, x.dest.parent().as_ref()).map_err(other)?;
            let dir: &dyn DirWrite = parent.as_deref().unwrap_or(version);
            sweep(dir);
            let name = seg(x.dest.file_name()).map_err(other)?;
            n += 1;
            let new = NewFile {
                tmp: TmpName::new(tag, n),
                attrs: Attrs::default(),
                sha256: x.sha256,
                max_len: e.size,
            };
            let written = match dir.create_new(&name, r, &new) {
                Ok(w) => w,
                Err(err) if err.kind == SysErrorKind::Mismatch => {
                    return Err(WriteStop::Mismatch(x.dest.as_str().to_owned()));
                }
                Err(err) => return Err(other(entry_error(&x.dest, err))),
            };
            dir.flush().map_err(|e| other(e.into()))?;
            let now = Unpacked {
                dest: x.dest.clone(),
                len: written.len,
                how: if replaced {
                    How::Replaced
                } else {
                    How::Extracted
                },
            };
            match done
                .iter_mut()
                .find(|u| u.how == How::Removed && u.dest == x.dest)
            {
                Some(u) => *u = now,
                None => done.push(now),
            }
            Ok(())
        };
        match archive.extract(&wanted, &mut sink) {
            Ok(()) => {}
            Err(Extraction::Archive(error)) => return Err(archive_err(error)),
            Err(Extraction::Sink(WriteStop::Other(e))) => return Err(e),
            Err(Extraction::Sink(WriteStop::Mismatch(file))) => {
                return Err(ExtractError::Mismatch {
                    id: id.to_owned(),
                    file,
                });
            }
        }
    }
    Ok(())
}
