//! The elevated helper's image and opens by identity (ADR 0023 §2, §4, §5 step 4; A4 S1, N1,
//! N2).
//!
//! - [`admin_only`]: the rule of ADR 0007 "Elevation" on the facts of one object
//!   ([`SdFacts`]): the volume keeps ACLs, the owner is Administrators, SYSTEM or
//!   TrustedInstaller, the DACL is present and no ACE that applies to the object grants any
//!   right of [`WRITE_MASK`] to another SID. Inherit-only ACEs are skipped (they apply to
//!   children only, e.g. `CREATOR OWNER` in `Program Files`); deny ACEs only take rights away;
//!   an allow ACE of any other type (callback, object, unknown) fails closed, because its
//!   effect cannot be judged here.
//! - [`helper_image`]: the CLI's pre-check before any UAC prompt (§2): `Program Files` from
//!   the known folder (never the environment), then `Rerun` and `rerun-helper.exe`
//!   handle-relative below it, neither a reparse point, the file a plain single-link file, and
//!   all three admin-only. Returns the canonical image path the start and `elevate::judge`
//!   use.
//! - [`helper_for_this_build`]: [`helper_image`] for the CLI's start (security N5 of P4-2c): a
//!   helper built with the published index test key is refused unless the CLI is such a test
//!   build itself.
//! - [`dir_by_id`]: the only caller of [`crate::sys::Fs::open_by_id`] (`clippy.toml`): a
//!   directory by `{volume GUID, file ID}`, never by path (the helper's `elevate` and `index`
//!   folders and its root, from P4-2c).

use super::{RootError, open_abs, raced};
use crate::path::{RelPath, RootPath};
use crate::sys::fs::{EntryKind, SdFacts, VolumeGuid, ace};
use crate::sys::{Dir, KnownFolder, SysErrorKind, System};

/// The helper's folder below `Program Files` (§2).
pub const HELPER_FOLDER: &str = "Rerun";
/// The helper's file name (§2).
pub const HELPER_EXE: &str = "rerun-helper.exe";

/// The SIDs an admin-only object may be owned by and grant write rights to: Administrators,
/// SYSTEM, TrustedInstaller (`NT SERVICE\TrustedInstaller`).
pub const ADMIN_SIDS: [&str; 3] = [
    "S-1-5-32-544",
    "S-1-5-18",
    "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
];

/// Rights no other SID may hold on an admin-only object (A4 N1): `FILE_WRITE_DATA` /
/// `FILE_ADD_FILE`, `FILE_APPEND_DATA` / `FILE_ADD_SUBDIRECTORY`, `FILE_WRITE_EA`,
/// `FILE_DELETE_CHILD`, `FILE_WRITE_ATTRIBUTES`, `DELETE`, `WRITE_DAC`, `WRITE_OWNER`,
/// `GENERIC_ALL`, `GENERIC_WRITE`.
pub const WRITE_MASK: u32 = 0x0000_0002
    | 0x0000_0004
    | 0x0000_0010
    | 0x0000_0040
    | 0x0000_0100
    | 0x0001_0000
    | 0x0004_0000
    | 0x0008_0000
    | 0x1000_0000
    | 0x4000_0000;

/// The pre-checked helper (§2): what the CLI starts and what `elevate::judge` compares the
/// started process with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelperImage {
    /// The canonical Win32 path, passed to `ShellExecuteExW`.
    pub path: RootPath,
    /// The file's NT name (`\Device\HarddiskVolumeN\…`), read on the same handle as its
    /// security descriptor: the started process must report exactly this image (folded).
    pub nt_name: String,
}

/// Why an object is not admin-only.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NotAdminOnly {
    /// The volume keeps no ACLs (FAT, exFAT).
    #[error("the volume keeps no ACLs (FILE_PERSISTENT_ACLS)")]
    NoAcls,
    /// The descriptor has no owner.
    #[error("no owner")]
    NoOwner,
    /// Owned by another SID.
    #[error("owner {0} is not Administrators, SYSTEM or TrustedInstaller")]
    Owner(String),
    /// No DACL: everyone has every right.
    #[error("NULL DACL (everyone has every right)")]
    NullDacl,
    /// An allow ACE grants a write right to another SID.
    #[error("{sid} may write (access mask {mask:#010x})")]
    Writer {
        /// The SID.
        sid: String,
        /// Its mask.
        mask: u32,
    },
    /// An allow ACE whose effect cannot be judged (callback, object or unknown type).
    #[error("ACE of type {ace_type:#04x} cannot be judged")]
    Unjudgeable {
        /// `AceType`.
        ace_type: u8,
    },
}

/// The admin-only rule on the facts of one object (module docs).
///
/// # Errors
/// The first reason the object is not admin-only.
pub fn admin_only(f: &SdFacts) -> Result<(), NotAdminOnly> {
    if !f.persistent_acls {
        return Err(NotAdminOnly::NoAcls);
    }
    let owner = f.owner.as_deref().ok_or(NotAdminOnly::NoOwner)?;
    if !ADMIN_SIDS.contains(&owner) {
        return Err(NotAdminOnly::Owner(owner.to_owned()));
    }
    let dacl = f.dacl.as_ref().ok_or(NotAdminOnly::NullDacl)?;
    for a in dacl {
        if a.flags & ace::INHERIT_ONLY != 0 {
            continue;
        }
        match a.ace_type {
            ace::DENIED
            | ace::DENIED_OBJECT
            | ace::DENIED_CALLBACK
            | ace::DENIED_CALLBACK_OBJECT => {}
            ace::ALLOWED => {
                let Some(sid) = a.sid.as_deref() else {
                    return Err(NotAdminOnly::Unjudgeable {
                        ace_type: a.ace_type,
                    });
                };
                if a.mask & WRITE_MASK != 0 && !ADMIN_SIDS.contains(&sid) {
                    return Err(NotAdminOnly::Writer {
                        sid: sid.to_owned(),
                        mask: a.mask,
                    });
                }
            }
            other => return Err(NotAdminOnly::Unjudgeable { ace_type: other }),
        }
    }
    Ok(())
}

fn unsafe_at(path: &RootPath, reason: impl ToString) -> RootError {
    RootError::HelperUnsafe {
        path: path.clone(),
        reason: reason.to_string(),
    }
}

/// `admin_only` of `f`, or [`RootError::HelperUnsafe`] for `path`.
fn require(path: &RootPath, f: &SdFacts) -> Result<(), RootError> {
    admin_only(f).map_err(|e| unsafe_at(path, format!("not admin-only: {e}")))
}

/// The CLI's pre-check of the installed helper (ADR 0023 §2, module docs). Ok: the canonical
/// path of `rerun-helper.exe` and its NT name. A missing folder or file is `HelperUnsafe` "not
/// installed" (after `Program Files` itself passed).
///
/// # Errors
/// [`RootError::HelperUnsafe`] naming the object and the reason (an SID for a foreign owner or
/// writer, A4 N1); `Sys` for a system error other than a missing entry.
pub fn helper_image(sys: &dyn System) -> Result<HelperImage, RootError> {
    let pf_path = sys
        .known_folders()
        .get(KnownFolder::ProgramFiles)
        .map_err(RootError::Sys)?;
    let pf_root = RootPath::new(&pf_path)?;
    let pf = open_abs(sys, pf_root.path())?;
    let pf_canon = RootPath::from_final_path(&pf.info().map_err(raced)?.final_path)?;
    require(&pf_canon, &pf.sd_facts(None)?)?;

    let folder = RelPath::from_segment(HELPER_FOLDER)?;
    let folder_path = pf_canon.child(HELPER_FOLDER)?;
    let not_installed = |p: &RootPath| unsafe_at(p, "not installed");
    let rerun = match pf.open_dir(&folder) {
        Ok(d) => d,
        Err(e) if e.kind == SysErrorKind::NotFound => return Err(not_installed(&folder_path)),
        Err(e) if e.kind == SysErrorKind::ReparsePoint => {
            return Err(unsafe_at(
                &folder_path,
                "a reparse point (link or junction)",
            ));
        }
        Err(e) if e.kind == SysErrorKind::InvalidPath => {
            return Err(unsafe_at(&folder_path, "not a folder"));
        }
        Err(e) => return Err(RootError::Sys(e)),
    };
    let rerun_canon = RootPath::from_final_path(&rerun.info().map_err(raced)?.final_path)?;
    if rerun_canon != folder_path {
        return Err(unsafe_at(&folder_path, format!("opened as {rerun_canon}")));
    }
    require(&rerun_canon, &rerun.sd_facts(None)?)?;

    let exe = RelPath::from_segment(HELPER_EXE)?;
    let image = rerun_canon.child(HELPER_EXE)?;
    let facts = match rerun.sd_facts(Some(&exe)) {
        Ok(f) => f,
        Err(e) if e.kind == SysErrorKind::NotFound => return Err(not_installed(&image)),
        Err(e) => return Err(RootError::Sys(e)),
    };
    match facts.kind {
        EntryKind::File => {}
        EntryKind::Reparse => return Err(unsafe_at(&image, "a reparse point (link)")),
        EntryKind::Dir => return Err(unsafe_at(&image, "not a file")),
    }
    if facts.links != 1 {
        return Err(unsafe_at(
            &image,
            format!("{} hard links (one expected)", facts.links),
        ));
    }
    require(&image, &facts)?;
    let nt_name = facts
        .nt_name
        .ok_or_else(|| unsafe_at(&image, "its NT name cannot be read"))?;
    Ok(HelperImage {
        path: image,
        nt_name,
    })
}

/// The largest helper image [`helper_for_this_build`] reads (a debug test-key build is some
/// tens of MiB; a release helper a few).
pub const MAX_HELPER_BYTES: u64 = 256 << 20;

/// The seed of the published index test key as hex text (`catalog::key::test_key::SEED_HEX`),
/// each byte XOR `0xA5`: a release CLI must find the seed in a helper without holding it itself
/// (the release byte check `holds_test_key` searches every shipped binary for it). Unmasked at
/// run time behind `black_box`; a test pins it to the seed.
const MASKED_TEST_SEED: [u8; 64] = [
    0x97, 0xc3, 0xc4, 0x91, 0x94, 0x96, 0x94, 0xc7, 0x96, 0x94, 0x96, 0xc7, 0x93, 0x90, 0x90, 0xc0,
    0xc6, 0x90, 0xc7, 0xc1, 0x95, 0x93, 0xc7, 0x94, 0x9d, 0x9c, 0x96, 0x9d, 0xc6, 0x95, 0x96, 0xc6,
    0x97, 0xc3, 0x91, 0xc7, 0xc4, 0x97, 0x95, 0x97, 0xc1, 0xc6, 0x96, 0x9d, 0x9c, 0xc4, 0xc7, 0xc7,
    0x96, 0x9d, 0x94, 0xc1, 0xc1, 0x9d, 0x93, 0x92, 0x94, 0x95, 0x95, 0xc4, 0xc7, 0xc4, 0x95, 0x90,
];

/// The seed text of the published test key, unmasked (see [`MASKED_TEST_SEED`]).
fn test_seed() -> [u8; 64] {
    let mut seed = std::hint::black_box(MASKED_TEST_SEED);
    for b in &mut seed {
        *b ^= 0xA5;
    }
    seed
}

/// Whether `image` (the bytes of a helper) holds the published index test key's seed: a
/// `test-key` build, which trusts that key for an add (ADR 0023 §2, A4 S3).
pub fn holds_test_key(image: &[u8]) -> bool {
    let seed = test_seed();
    image.windows(seed.len()).any(|w| w == seed)
}

/// [`helper_image`] for a start by this CLI (security N5 of P4-2c): also refused when the
/// installed helper is a `test-key` build and this CLI is not. Whoever holds the published test
/// key could otherwise have a Rerun block rule added through a forgotten test helper with a
/// release CLI's prompt. A `test-key` CLI (a test build itself, [SB] and [DEV]) accepts it. The
/// image is read bounded through its folder's handle (at most [`MAX_HELPER_BYTES`]); the helper's
/// own image check does not use this (it cannot judge itself).
///
/// # Errors
/// The errors of [`helper_image`]; [`RootError::HelperUnsafe`] for a test-key helper or an image
/// larger than the bound.
pub fn helper_for_this_build(sys: &dyn System) -> Result<HelperImage, RootError> {
    let image = helper_image(sys)?;
    check_test_key(sys, &image, cfg!(feature = "test-key"))?;
    Ok(image)
}

/// The test-key part of [`helper_for_this_build`], with the build's answer as `allow`.
pub(crate) fn check_test_key(
    sys: &dyn System,
    image: &HelperImage,
    allow: bool,
) -> Result<(), RootError> {
    if allow {
        return Ok(());
    }
    let folder = image
        .path
        .path()
        .parent()
        .ok_or_else(|| unsafe_at(&image.path, "no folder"))?;
    let dir = open_abs(sys, folder)?;
    let exe = RelPath::from_segment(HELPER_EXE)?;
    let bytes = match dir.read_limited(&exe, MAX_HELPER_BYTES) {
        Ok(b) => b,
        Err(e) if e.kind == SysErrorKind::TooLarge => {
            return Err(unsafe_at(
                &image.path,
                format!("larger than {MAX_HELPER_BYTES} bytes"),
            ));
        }
        Err(e) => return Err(RootError::Sys(e)),
    };
    if holds_test_key(&bytes) {
        return Err(unsafe_at(
            &image.path,
            "a test build that trusts the published index test key; remove it",
        ));
    }
    Ok(())
}

/// Opens a directory by `{volume GUID, file ID}` (module docs), read side only. A volume
/// without open by ID (FAT, exFAT) is `Sys(Unsupported)`, a reparse point `Sys(ReparsePoint)`.
///
/// # Errors
/// The system error of the open.
#[expect(
    clippy::disallowed_methods,
    reason = "ADR 0023 (A4 S1): policy::root is the only place that opens by identity"
)]
pub fn dir_by_id<'s>(
    sys: &'s dyn System,
    volume: &VolumeGuid,
    file_id: u128,
) -> Result<Box<dyn Dir + 's>, RootError> {
    Ok(sys.fs().open_by_id(volume, file_id)?)
}

/// A game folder the elevated helper opened by identity (ADR 0023 §5 step 4): read side only,
/// nothing is ever written into it.
#[derive(Debug)]
pub struct RootById<'s> {
    dir: Box<dyn Dir + 's>,
    path: RootPath,
    info: crate::sys::fs::RootInfo,
}

impl RootById<'_> {
    /// The handle, read side.
    pub fn dir(&self) -> &dyn Dir {
        &*self.dir
    }

    /// The canonical path read on the handle.
    pub fn path(&self) -> &RootPath {
        &self.path
    }

    /// Properties as of opening.
    pub fn info(&self) -> &crate::sys::fs::RootInfo {
        &self.info
    }
}

/// Opens the game folder the request names by `{volume GUID, file ID}` (ADR 0023 §5 step 4,
/// R4, N2): through [`dir_by_id`] (no path walked, no link followed, a reparse point refused),
/// then on the handle: the volume serial and file ID as expected, the canonical path equal to
/// `expected` (folded) and allowed by `fr` (the helper's own forbidden list, with the
/// per-volume rule and no volume root). The folder need not be admin-only: nothing is written
/// there.
///
/// # Errors
/// The open; [`RootError::IdentityMismatch`] for another serial or file ID;
/// [`RootError::Escaped`] for another canonical path; [`RootError::Forbidden`].
pub fn root_by_id<'s>(
    sys: &'s dyn System,
    fr: &super::ForbiddenRoots,
    volume: &VolumeGuid,
    file_id: u128,
    serial: u64,
    expected: &RootPath,
) -> Result<RootById<'s>, RootError> {
    let dir = dir_by_id(sys, volume, file_id)?;
    let info = dir.info().map_err(raced)?;
    let want = super::RootId {
        volume_serial: serial,
        file_id,
    };
    let path = RootPath::from_final_path(&info.final_path)?;
    super::ensure(&path, &info, want)?;
    if &path != expected {
        return Err(RootError::Escaped {
            store: expected.clone(),
            child: path,
        });
    }
    super::check_canonical(fr, &path, &info)?;
    Ok(RootById { dir, path, info })
}

#[cfg(test)]
mod tests;
