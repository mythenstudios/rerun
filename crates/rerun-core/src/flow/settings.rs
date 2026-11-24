//! The app's settings file `<AppDir>\app\settings.json` (P5-10b, ADR 0027 amendment P5-10): Rerun's
//! own state like the index store, not a change to the system, so it is not journaled. The core
//! moves **opaque bytes** of at most [`SETTINGS_MAX`]; what they mean is the app's
//! (`rerun-app::settings`), which never names a path, a font or a URL in them.
//!
//! - [`read_settings`] never creates anything and never fails: no folder, no `app`, no file is
//!   [`SettingsRead::Absent`]; a link, a hard link, a folder in its place, an `app` that is a
//!   junction or a file over the bound is [`SettingsRead::Unusable`] (the app then uses the
//!   defaults and never writes over it). What it read is remembered as a [`Seen`]: the SHA-256 of
//!   the bytes, `Absent`, or `Unknown` (nothing may be written over it).
//! - [`write_settings`] is a compare-and-swap against that [`Seen`]: `Absent` creates the file
//!   with `create_new` (temp file and rename without replace), a hash replaces it through a
//!   [`FileGuard`](crate::sys::fs::FileGuard) only while it still has that hash (a file over
//!   [`SETTINGS_MAX`] there now is another file and is never hashed); anything else is
//!   [`SettingsError::Changed`] and nothing is written. Rerun's folder and `app` are created only
//!   here, right before the first write (review S6 of P2-13: opening and closing the app never
//!   creates them). A crash at any step leaves the old or the new file, never a torn one, except
//!   between the two renames of a replace: then there is no file and the next start takes the
//!   defaults. A crash or a failed last step of a replace may leave a temp file or a `<tmp>.old`
//!   in `app` (harmless, never read, not cleaned up: nothing is journaled here).
//!
//! Both take a [`Guarded`], so an elevated process reads and writes nothing (rule 6).

use sha2::{Digest, Sha256};

use super::Guarded;
use crate::journal::InstanceTag;
use crate::path::RelPath;
use crate::policy::root::{AppDir, AppSub, Create, RootError};
use crate::sys::fs::{Attrs, EntryKind, NewFile, TmpName};
use crate::sys::{DirWrite, SysErrorKind};

/// Most bytes of the settings file (ADR 0027 open point, closed with P5-10).
pub const SETTINGS_MAX: u64 = 4096;

/// The file's name in `<AppDir>\app`.
pub const SETTINGS_FILE: &str = "settings.json";

/// What the last read or write saw in the file's place: what the next write expects there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Seen {
    /// No file (no folder, no `app`, no `settings.json`).
    Absent,
    /// A plain file with this SHA-256.
    Hash([u8; 32]),
    /// Something that is never written over (a link, a folder, a file over the bound, an
    /// error): every write is refused.
    Unknown,
}

/// Why the file cannot be used.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Unusable {
    /// Larger than [`SETTINGS_MAX`].
    TooLarge,
    /// A symbolic link, a junction or a hard link (more than one name).
    Link,
    /// A folder or another kind of entry in its place.
    NotAFile,
    /// The folder `app` cannot be opened (a junction, access denied).
    Folder(Box<RootError>),
    /// The file system.
    Io(SysErrorKind),
}

/// What [`read_settings`] found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SettingsRead {
    /// No file: the defaults, and the first change creates it.
    Absent,
    /// The bytes (at most [`SETTINGS_MAX`]) and their hash.
    Bytes {
        /// The file's content.
        bytes: Vec<u8>,
        /// [`Seen::Hash`] of exactly these bytes.
        seen: Seen,
    },
    /// The file cannot be used: the defaults.
    Unusable {
        /// Why.
        why: Unusable,
        /// Always [`Seen::Unknown`]: an unusable file is never written over.
        seen: Seen,
    },
}

impl SettingsRead {
    /// What the next write expects in the file's place.
    pub fn seen(&self) -> Seen {
        match self {
            Self::Absent => Seen::Absent,
            Self::Bytes { seen, .. } | Self::Unusable { seen, .. } => seen.clone(),
        }
    }
}

fn name() -> RelPath {
    match RelPath::from_segment(SETTINGS_FILE) {
        Ok(p) => p,
        Err(e) => unreachable!("{SETTINGS_FILE} is a fixed valid segment: {e}"),
    }
}

/// Reads `<AppDir>\app\settings.json` (module docs). Creates nothing, never fails.
pub fn read_settings(g: &Guarded<'_>) -> SettingsRead {
    let Some(app) = g.app() else {
        return SettingsRead::Absent;
    };
    let unusable = |why| SettingsRead::Unusable {
        why,
        seen: Seen::Unknown,
    };
    let dir = match app.sub(AppSub::App) {
        Ok(Some(d)) => d,
        Ok(None) => return SettingsRead::Absent,
        Err(e) => return unusable(Unusable::Folder(Box::new(e))),
    };
    let name = name();
    let meta = match dir.metadata(&name) {
        Ok(Some(m)) => m,
        Ok(None) => return SettingsRead::Absent,
        Err(e) => return unusable(Unusable::Io(e.kind)),
    };
    match meta.kind {
        EntryKind::File if meta.restricted => {
            return unusable(Unusable::Io(SysErrorKind::AccessDenied));
        }
        EntryKind::File if !meta.is_single_link() => return unusable(Unusable::Link),
        EntryKind::File => {}
        EntryKind::Reparse => return unusable(Unusable::Link),
        EntryKind::Dir => return unusable(Unusable::NotAFile),
    }
    match dir.read_limited(&name, SETTINGS_MAX) {
        Ok(bytes) => {
            let seen = Seen::Hash(Sha256::digest(&bytes).into());
            SettingsRead::Bytes { bytes, seen }
        }
        Err(e) if e.kind == SysErrorKind::NotFound => SettingsRead::Absent,
        Err(e) if e.kind == SysErrorKind::TooLarge => unusable(Unusable::TooLarge),
        Err(e) if e.kind == SysErrorKind::ReparsePoint => unusable(Unusable::Link),
        Err(e) => unusable(Unusable::Io(e.kind)),
    }
}

/// Why the settings were not written. Nothing was written in every case.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SettingsError {
    /// More than [`SETTINGS_MAX`] bytes to write.
    TooLarge,
    /// The file is not what the last read saw (another Rerun wrote it): read again first.
    Changed,
    /// The place cannot be written (a link, a folder, [`Seen::Unknown`], the file system).
    Unwritable(Unusable),
    /// Rerun's folder was neither found nor created.
    NoAppDir,
    /// Rerun's folder cannot be opened or created.
    AppDir(Box<RootError>),
}

/// Writes `bytes` as `<AppDir>\app\settings.json` if the file is still what `seen` says (module
/// docs); returns what is there now. Rerun's folder and `app` are created here if missing, and
/// the folder is kept in `g` like `flow::store` does. The same bytes as `seen` write nothing.
pub fn write_settings(
    g: &mut Guarded<'_>,
    bytes: &[u8],
    seen: &Seen,
) -> Result<Seen, SettingsError> {
    let len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    if len > SETTINGS_MAX {
        return Err(SettingsError::TooLarge);
    }
    let sha: [u8; 32] = Sha256::digest(bytes).into();
    match seen {
        Seen::Unknown => {
            return Err(SettingsError::Unwritable(Unusable::Io(
                SysErrorKind::Mismatch,
            )));
        }
        Seen::Hash(h) if *h == sha => return Ok(Seen::Hash(sha)),
        Seen::Absent | Seen::Hash(_) => {}
    }
    let sys = g.env().sys;
    // Review S6: Rerun's folder is created only now, right before the first write.
    let app = match g.app.take() {
        Some(a) => a,
        None => match AppDir::open(sys, Create::IfMissing) {
            Ok(Some(a)) => a,
            Ok(None) => return Err(SettingsError::NoAppDir),
            Err(e) => return Err(SettingsError::AppDir(Box::new(e))),
        },
    };
    let app = g.app.insert(app);
    let dir = match app.sub_write(AppSub::App, Create::IfMissing) {
        Ok(Some(d)) => d,
        Ok(None) => return Err(SettingsError::NoAppDir),
        Err(e) => return Err(SettingsError::Unwritable(Unusable::Folder(Box::new(e)))),
    };
    let new = NewFile {
        tmp: TmpName::new(InstanceTag::new().get(), 0),
        attrs: Attrs::default(),
        sha256: sha,
        max_len: len,
    };
    let name = name();
    let r = match seen {
        Seen::Absent => match dir.create_new(&name, &mut &bytes[..], &new) {
            Ok(_) => Ok(()),
            Err(e) if e.kind == SysErrorKind::AlreadyExists => Err(SettingsError::Changed),
            Err(e) => Err(unwritable(e.kind)),
        },
        Seen::Hash(expected) => replace(&*dir, &name, expected, bytes, &new),
        Seen::Unknown => unreachable!("refused above"),
    };
    r?;
    // Best effort, as for the index store: the renames are done either way.
    let _ = dir.flush();
    Ok(Seen::Hash(sha))
}

/// Replaces `name` if it still hashes to `expected`.
fn replace(
    dir: &dyn DirWrite,
    name: &RelPath,
    expected: &[u8; 32],
    bytes: &[u8],
    new: &NewFile,
) -> Result<(), SettingsError> {
    let mut guard = match dir.guard(name) {
        Ok(g) => g,
        Err(e) if e.kind == SysErrorKind::NotFound => return Err(SettingsError::Changed),
        Err(e) => return Err(unwritable(e.kind)),
    };
    // The expected hash is of a file of at most `SETTINGS_MAX` bytes: a larger one is another
    // file, and it is never hashed (a huge or sparse file would keep the worker for minutes).
    let len = guard.metadata().map_err(|e| unwritable(e.kind))?.len;
    if len > SETTINGS_MAX {
        return Err(SettingsError::Changed);
    }
    let have = guard.sha256().map_err(|e| unwritable(e.kind))?;
    if have != *expected {
        return Err(SettingsError::Changed);
    }
    match guard.replace(expected, &mut &bytes[..], new) {
        Ok(_) => Ok(()),
        Err(e) if e.kind == SysErrorKind::Mismatch => Err(SettingsError::Changed),
        Err(e) => Err(unwritable(e.kind)),
    }
}

/// A file system error of a write, by kind: a link or a folder in the file's place is what it is.
fn unwritable(kind: SysErrorKind) -> SettingsError {
    SettingsError::Unwritable(match kind {
        SysErrorKind::ReparsePoint | SysErrorKind::Linked => Unusable::Link,
        SysErrorKind::TooLarge => Unusable::TooLarge,
        k => Unusable::Io(k),
    })
}

#[cfg(test)]
#[path = "settings_tests.rs"]
mod tests;
