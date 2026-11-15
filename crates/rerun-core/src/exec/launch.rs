//! The result files of `rerun-launch` for `rerun status` (ADR 0022 amendment P3-2): the last
//! start of each profile, from `<AppDir>\launch\<id>.result`.
//!
//! Untrusted input (any process of the user can write the folder, docs/06 #17): the folder is
//! opened handle-relative through [`AppDir`] (a reparse point at `launch` refused), listed with
//! a bound, each file read bounded and decoded strictly by `rerun_proto::launch`. A file that
//! cannot be read or decoded, names another profile than its file name, or is a link or a
//! folder is listed as unreadable with the reason (escaped), never acted on. The shim's temp
//! files (`<id>.<…>.tmp`) are skipped; any other name is only counted. Nothing is written,
//! except by [`purge_results`] ("clear history", P5-6d-1b, ADR 0022 amendment P5-6d): a result
//! file only with exactly the bytes a preview read.

use rerun_proto::launch::{MAX_RESULT_BYTES, decode};

/// The result types, for front ends (`rerun-cli` depends on `rerun-core` only).
pub use rerun_proto::cpu::rule::Mode;
pub use rerun_proto::launch::{AppliedCpu, Check, Ended, LaunchResult, Outcome, SkipReason, Start};
pub use rerun_proto::profile::{Priority, ProfileId};

use crate::escape::{self, Shown};
use crate::path::RelPath;
use crate::policy::root::{AppDir, AppSub, RootError};
use crate::sys::fs::{DirEntry, EntryKind};
use crate::sys::{Dir, SysErrorKind};

/// Most entries `launch` may hold (one per profile; more is refused as a whole).
pub const MAX_LAUNCH_ENTRIES: usize = 4096;

const SUFFIX: &str = ".result";

/// The result files of `launch`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchResults {
    /// One per `<id>.result`, by ID.
    pub entries: Vec<LaunchEntry>,
    /// Entries that are neither a result file nor a temp file of the shim.
    pub other: usize,
}

/// One result file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchEntry {
    /// The profile ID of the file name.
    pub id: ProfileId,
    /// The last start, or why it cannot be shown (escaped).
    pub result: Result<LaunchResult, Shown<'static>>,
}

/// Reads `<AppDir>\launch`. `Ok(None)` if the folder does not exist.
pub fn launch_results(app: &AppDir<'_>) -> Result<Option<LaunchResults>, RootError> {
    Ok(launch_results_hashed(app)?.map(|(r, _)| r))
}

/// The SHA-256 of each readable result file, by profile.
pub(crate) type ResultHashes = Vec<(ProfileId, [u8; 32])>;

/// [`launch_results`], with the SHA-256 of the bytes each readable result was decoded from (the
/// bytes a "clear history" preview binds its deletion to, P5-6d-1b).
pub(crate) fn launch_results_hashed(
    app: &AppDir<'_>,
) -> Result<Option<(LaunchResults, ResultHashes)>, RootError> {
    let Some(dir) = app.sub(AppSub::Launch)? else {
        return Ok(None);
    };
    let listing = dir
        .read_dir_limited(None, MAX_LAUNCH_ENTRIES)
        .map_err(RootError::Sys)?;
    let mut entries = Vec::new();
    let mut hashes = Vec::new();
    let mut other = 0;
    for e in listing {
        match classify(&e.name) {
            Name::Result(id) => {
                let result = read(&*dir, &e, id).map(|(r, sha)| {
                    hashes.push((id, sha));
                    r
                });
                entries.push(LaunchEntry { id, result });
            }
            Name::Temp => {}
            Name::Other => other += 1,
        }
    }
    entries.sort_by_key(|e| e.id);
    hashes.sort_by_key(|(id, _)| *id);
    Ok(Some((LaunchResults { entries, other }, hashes)))
}

/// Deletes the result files `seen` names ("clear history", P5-6d-1b; ADR 0022 amendment P5-6d),
/// each only if it still holds exactly the bytes the preview read: `guard` and
/// `delete(expected)`, a real comparison here, because the shim may have written a new start
/// since (then it stays: a new start, no error). A file that is gone, a link, a folder, in use or
/// otherwise not deletable stays too; the folder itself, the shim's temp files and any other
/// name are never touched. Takes no journal lock (the shim takes none). Returns how many went.
///
/// # Errors
/// `launch` cannot be opened (a reparse point is refused).
pub(crate) fn purge_results(
    app: &AppDir<'_>,
    seen: &[(ProfileId, [u8; 32])],
) -> Result<usize, RootError> {
    if seen.is_empty() {
        return Ok(0);
    }
    let Some(dir) = app.sub_write(AppSub::Launch, crate::policy::root::Create::Never)? else {
        return Ok(0);
    };
    let mut n = 0;
    for (id, sha) in seen {
        let Ok(name) = RelPath::from_segment(&format!("{id}{SUFFIX}")) else {
            continue;
        };
        let Ok(g) = dir.guard(&name) else { continue };
        if g.delete(sha).is_ok() {
            n += 1;
        }
    }
    if n > 0 {
        // Best effort, as every flush of Rerun's own folders: the deletions are done.
        let _durable = dir.flush();
    }
    Ok(n)
}

enum Name {
    Result(ProfileId),
    Temp,
    Other,
}

/// `<32 hex>.result` exactly; `<32 hex>.<anything>.tmp` is the shim's temp file.
fn classify(name: &str) -> Name {
    if let Some(id) = name.strip_suffix(SUFFIX).and_then(ProfileId::from_hex) {
        return Name::Result(id);
    }
    let temp = name.len() > 33
        && name.ends_with(".tmp")
        && name.is_char_boundary(32)
        && ProfileId::from_hex(&name[..32]).is_some()
        && name.as_bytes()[32] == b'.';
    if temp { Name::Temp } else { Name::Other }
}

fn text(s: &str) -> Shown<'static> {
    escape::text(s).into_owned()
}

/// One result file, read bounded and decoded, with the SHA-256 of its bytes; any problem as
/// text.
fn read(
    dir: &dyn Dir,
    e: &DirEntry,
    id: ProfileId,
) -> Result<(LaunchResult, [u8; 32]), Shown<'static>> {
    if e.meta.restricted {
        return Err(text("access denied"));
    }
    match e.meta.kind {
        EntryKind::File => {}
        EntryKind::Dir => return Err(text("a folder, not a file")),
        EntryKind::Reparse => return Err(text("a link (not followed)")),
    }
    // P5-6d-1b (security nit 3): a result with a second hard link is not the shim's own file;
    // it is never acted on (a "clear history" would otherwise delete one name of it).
    if !e.meta.is_single_link() {
        return Err(text("a file with more than one link"));
    }
    let rel = RelPath::from_segment(&e.name).map_err(|err| text(&err.to_string()))?;
    let max = u64::try_from(MAX_RESULT_BYTES).unwrap_or(u64::MAX);
    let bytes = dir.read_limited(&rel, max).map_err(|err| match err.kind {
        SysErrorKind::TooLarge => text(&format!("larger than {MAX_RESULT_BYTES} bytes")),
        _ => text(&err.to_string()),
    })?;
    let r = decode(&bytes).map_err(|err| text(&err.to_string()))?;
    if r.profile != id {
        return Err(text("it names another profile than its file name"));
    }
    let sha: [u8; 32] =
        sha2::Digest::finalize(<sha2::Sha256 as sha2::Digest>::new_with_prefix(&bytes)).into();
    Ok((r, sha))
}

#[cfg(test)]
mod tests;
