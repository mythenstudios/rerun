//! The accepted indexes under `<AppDir>\index` (ADR 0024):
//!
//! - `<sha256>.json` and `<sha256>.sig`: the bytes and the signature of every index accepted,
//!   named by the SHA-256 of the bytes (64 lower-case hex digits). Kept: a transaction applied
//!   with an index names it by this hash, and its revert reads exactly these bytes again
//!   ([`by_hash`]: signature only, also by a retired key, no `seq` floor; P4 condition R1).
//!   Rerun deletes none of them in phase 4.
//! - `current.json`: `{"format":1,"seq":<n>,"sha256":"<hex>"}`, the last accepted index. Its
//!   `seq` is the floor of [`import`]: lower is a rollback, equal with other bytes a second
//!   index under one number; both refused. Before comparing, [`import`] checks the pointer and
//!   the index it names like [`by_hash`]; anything wrong there is [`StoreError::Damaged`] naming
//!   the file to remove.
//! - `lock`: held by [`import`] (share 0), so two imports never interleave.
//!
//! Everything below `<AppDir>` is user-writable (`docs/06-security.md` #14): what is read back is
//! untrusted. [`current`] and [`by_hash`] read bounded, check the hash against the name, verify
//! the signature and parse again; a pointer that disagrees with its index is
//! [`StoreError::Damaged`]. The floor protects against a replayed old index from outside, not
//! against a process of the user that rewrites `current.json` (it could change anything there).

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{Catalog, IndexError, MAX_INDEX_BYTES, PublicKey, SIG_BYTES, key, verify};
use crate::journal::InstanceTag;
use crate::path::RelPath;
use crate::policy::root::{AppDir, AppSub, Create, RootError};
use crate::sys::fs::{Attrs, NewFile, TmpName};
use crate::sys::{DirWrite, SysError, SysErrorKind};
use crate::wire::hex32;

/// The pointer file.
pub const CURRENT: &str = "current.json";
/// The lock file of [`import`].
const LOCK: &str = "lock";
/// Most bytes of `current.json`.
const MAX_CURRENT_BYTES: u64 = 1024;

/// Why an import or a read of the stored index failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StoreError {
    /// The offered or stored index is refused.
    #[error(transparent)]
    Index(#[from] IndexError),
    /// Its `seq` is lower than the last accepted one.
    #[error(
        "index {offered} is older than the index already accepted ({current}): a rollback is refused"
    )]
    Rollback {
        /// The last accepted `seq`.
        current: u64,
        /// The offered `seq`.
        offered: u64,
    },
    /// The same `seq` as the last accepted index, with other bytes.
    #[error("another index with the same number {seq} was already accepted: refused")]
    SameSeq {
        /// The `seq`.
        seq: u64,
    },
    /// What is stored does not fit together (pointer, name, bytes, signature).
    #[error("the stored index is damaged: {0}")]
    Damaged(String),
    /// Rerun's folder.
    #[error(transparent)]
    Root(Box<RootError>),
    /// The file system.
    #[error(transparent)]
    Sys(#[from] SysError),
}

impl From<RootError> for StoreError {
    fn from(e: RootError) -> Self {
        Self::Root(Box::new(e))
    }
}

/// What [`import`] did.
#[derive(Debug)]
pub enum Imported {
    /// The index is now the current one; `previous` is the `seq` it replaced.
    New {
        /// The catalogue.
        catalog: Catalog,
        /// The last accepted `seq` before, if any.
        previous: Option<u64>,
    },
    /// The same index was already the current one.
    AlreadyCurrent(Catalog),
}

/// The pointer `current.json`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Current {
    format: u32,
    seq: u64,
    #[serde(with = "hex32")]
    sha256: [u8; 32],
}

fn seg(s: &str) -> RelPath {
    match RelPath::from_segment(s) {
        Ok(p) => p,
        Err(e) => unreachable!("{s} is a fixed valid segment: {e}"),
    }
}

/// `<sha>.json` and `<sha>.sig`.
fn names(sha: &[u8; 32]) -> (RelPath, RelPath) {
    let h = hex32::to_string(sha);
    (seg(&format!("{h}.json")), seg(&format!("{h}.sig")))
}

/// Writes `bytes` as `name`: created if missing, replaced if it holds other bytes (a damaged
/// copy of a content-addressed file), left if it holds them already.
fn put(
    dir: &dyn DirWrite,
    name: &RelPath,
    bytes: &[u8],
    tag: u64,
    n: u64,
) -> Result<(), StoreError> {
    let sha: [u8; 32] = Sha256::digest(bytes).into();
    let new = NewFile {
        tmp: TmpName::new(tag, n),
        attrs: Attrs::default(),
        sha256: sha,
        max_len: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
    };
    match dir.create_new(name, &mut &bytes[..], &new) {
        Ok(_) => Ok(()),
        Err(e) if e.kind == SysErrorKind::AlreadyExists => {
            let mut g = dir.guard(name)?;
            let have = g.sha256()?;
            if have != sha {
                g.replace(&have, &mut &bytes[..], &new)?;
            }
            Ok(())
        }
        Err(e) => Err(e.into()),
    }
}

fn read_current(dir: &dyn crate::sys::Dir) -> Result<Option<Current>, StoreError> {
    let bytes = match dir.read_limited(&seg(CURRENT), MAX_CURRENT_BYTES) {
        Ok(b) => b,
        Err(e) if e.kind == SysErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let c: Current = serde_json::from_slice(&bytes)
        .map_err(|_| StoreError::Damaged(format!("{CURRENT} is not a pointer of format 1")))?;
    if c.format != 1 {
        return Err(StoreError::Damaged(format!(
            "{CURRENT} is not a pointer of format 1"
        )));
    }
    Ok(Some(c))
}

/// Reads the index stored under `sha`, checks its name, signature and form.
pub(crate) fn load(
    dir: &dyn crate::sys::Dir,
    sha: &[u8; 32],
    keys: &[PublicKey],
) -> Result<Catalog, StoreError> {
    load_with(dir, sha, keys, key::REVOKED_KEYS)
}

/// [`load`] against an explicit revocation list (the elevated helper's tests, ADR 0023 §14).
pub(crate) fn load_with(
    dir: &dyn crate::sys::Dir,
    sha: &[u8; 32],
    keys: &[PublicKey],
    revoked: &[[u8; 32]],
) -> Result<Catalog, StoreError> {
    let (json, sig) = names(sha);
    let read = |name: &RelPath, max: usize| match dir.read_limited(name, max as u64) {
        Err(e) if e.kind == SysErrorKind::TooLarge => {
            Err(StoreError::Damaged(format!("{name} is too large")))
        }
        r => r.map_err(StoreError::from),
    };
    let bytes = read(&json, MAX_INDEX_BYTES)?;
    let have: [u8; 32] = Sha256::digest(&bytes).into();
    if &have != sha {
        return Err(StoreError::Damaged(format!(
            "{json} does not hash to its name"
        )));
    }
    let sig = read(&sig, SIG_BYTES)?;
    let v = super::verify_with(&bytes, &sig, keys, revoked)?;
    Ok(Catalog::from_verified(&v)?)
}

/// `keys` and the retired keys, without revoked ones: what an already accepted index may be
/// signed with (a rotation does not invalidate it).
fn with_retired(keys: &[PublicKey]) -> Vec<PublicKey> {
    let mut all = keys.to_vec();
    all.extend(key::RETIRED_KEYS.iter().map(|k| PublicKey::new(*k)));
    all.retain(|k| !key::revoked(k));
    all
}

/// The pointer and the index it names, checked like [`by_hash`] (a retired key still counts:
/// the index was accepted before the rotation) and carrying the pointer's `seq`. Any failure
/// is [`StoreError::Damaged`] naming the file to remove.
fn floor(
    app: &AppDir<'_>,
    dir: &dyn crate::sys::Dir,
    keys: &[PublicKey],
) -> Result<Option<Current>, StoreError> {
    let at = || format!(r"{}\index\{CURRENT}", app.path());
    let c = match read_current(dir) {
        Ok(c) => c,
        Err(StoreError::Damaged(why)) => {
            return Err(StoreError::Damaged(format!(
                "{why}; remove {} to import again",
                at()
            )));
        }
        Err(e) => return Err(e),
    };
    let Some(c) = c else { return Ok(None) };
    match load(dir, &c.sha256, &with_retired(keys)) {
        Ok(cat) if cat.seq() == c.seq => Ok(Some(c)),
        Ok(cat) => Err(StoreError::Damaged(format!(
            "{} names index {} but the index there is {}; remove it to import again",
            at(),
            c.seq,
            cat.seq()
        ))),
        Err(StoreError::Root(e)) => Err(StoreError::Root(e)),
        Err(StoreError::Sys(e)) if e.kind != SysErrorKind::NotFound => Err(StoreError::Sys(e)),
        Err(e) => Err(StoreError::Damaged(format!(
            "{} names an index that cannot be used ({e}); remove it to import again",
            at()
        ))),
    }
}

/// Verifies and parses `index` with `sig` (nothing is parsed before the signature checked
/// out), applies the rollback rule against `current.json` and stores both under
/// `<AppDir>\index` (created if missing), then moves the pointer.
pub fn import(
    app: &AppDir<'_>,
    index: &[u8],
    sig: &[u8],
    keys: &[PublicKey],
) -> Result<Imported, StoreError> {
    let v = verify(index, sig, keys)?;
    let catalog = Catalog::from_verified(&v)?;
    let dir = app
        .sub_write(AppSub::Index, Create::IfMissing)?
        .ok_or_else(|| SysError::new(SysErrorKind::NotFound, "index"))?;
    let _lock = dir.lock(&seg(LOCK))?;
    let cur = floor(app, &*dir, keys)?;
    let same = match cur {
        Some(c) if catalog.seq() < c.seq => {
            return Err(StoreError::Rollback {
                current: c.seq,
                offered: catalog.seq(),
            });
        }
        Some(c) if catalog.seq() == c.seq && &c.sha256 != catalog.sha256() => {
            return Err(StoreError::SameSeq { seq: c.seq });
        }
        Some(c) => catalog.seq() == c.seq,
        None => false,
    };
    let tag = InstanceTag::new().get();
    let (json, signame) = names(catalog.sha256());
    put(&*dir, &json, index, tag, 0)?;
    put(&*dir, &signame, sig, tag, 1)?;
    dir.flush()?;
    if same {
        return Ok(Imported::AlreadyCurrent(catalog));
    }
    let pointer = Current {
        format: 1,
        seq: catalog.seq(),
        sha256: *catalog.sha256(),
    };
    let bytes = serde_json::to_vec(&pointer)
        .map_err(|e| StoreError::Damaged(format!("pointer not encodable: {e}")))?;
    put(&*dir, &seg(CURRENT), &bytes, tag, 2)?;
    dir.flush()?;
    Ok(Imported::New {
        catalog,
        previous: cur.map(|c| c.seq),
    })
}

/// The current index: `None` if none was accepted yet (or Rerun's folder or `index` is
/// missing). The stored bytes are checked again like an import (signature under `keys`, form),
/// and must carry the pointer's `seq`.
pub fn current(app: &AppDir<'_>, keys: &[PublicKey]) -> Result<Option<Catalog>, StoreError> {
    let Some(dir) = app.sub(AppSub::Index)? else {
        return Ok(None);
    };
    let Some(c) = read_current(&*dir)? else {
        return Ok(None);
    };
    let catalog = load(&*dir, &c.sha256, keys)?;
    if catalog.seq() != c.seq {
        return Err(StoreError::Damaged(format!(
            "{CURRENT} names index {} but the index there is {}",
            c.seq,
            catalog.seq()
        )));
    }
    Ok(Some(catalog))
}

/// The accepted index with this hash, whatever the current one is (a revert reads the index
/// its transaction was applied with; P4 condition R1): bounded, hash against name, signature
/// under [`key::revert_keys`] (the trusted and the retired keys, never a revoked one), form;
/// no `seq` floor. The only reader that accepts a retired key.
pub fn by_hash(app: &AppDir<'_>, sha: &[u8; 32]) -> Result<Catalog, StoreError> {
    by_hash_with(app, sha, &key::revert_keys())
}

/// [`by_hash`] with explicit keys (tests sign with the test key).
pub(crate) fn by_hash_with(
    app: &AppDir<'_>,
    sha: &[u8; 32],
    keys: &[PublicKey],
) -> Result<Catalog, StoreError> {
    let dir = app
        .sub(AppSub::Index)?
        .ok_or_else(|| SysError::new(SysErrorKind::NotFound, "index"))?;
    load(&*dir, sha, keys)
}
