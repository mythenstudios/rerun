//! The result files of `rerun-launch` for `rerun status` (ADR 0022 amendment P3-2): the last
//! start of each profile, from `<AppDir>\launch\<id>.result`.
//!
//! Untrusted input (any process of the user can write the folder, docs/06 #17): the folder is
//! opened handle-relative through [`AppDir`] (a reparse point at `launch` refused), listed with
//! a bound, each file read bounded and decoded strictly by `rerun_proto::launch`. A file that
//! cannot be read or decoded, names another profile than its file name, or is a link or a
//! folder is listed as unreadable with the reason (escaped), never acted on. The shim's temp
//! files (`<id>.<…>.tmp`) are skipped; any other name is only counted. Nothing is written.

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
    let Some(dir) = app.sub(AppSub::Launch)? else {
        return Ok(None);
    };
    let listing = dir
        .read_dir_limited(None, MAX_LAUNCH_ENTRIES)
        .map_err(RootError::Sys)?;
    let mut entries = Vec::new();
    let mut other = 0;
    for e in listing {
        match classify(&e.name) {
            Name::Result(id) => entries.push(LaunchEntry {
                id,
                result: read(&*dir, &e, id),
            }),
            Name::Temp => {}
            Name::Other => other += 1,
        }
    }
    entries.sort_by_key(|e| e.id);
    Ok(Some(LaunchResults { entries, other }))
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

/// One result file, read bounded and decoded; any problem as text.
fn read(dir: &dyn Dir, e: &DirEntry, id: ProfileId) -> Result<LaunchResult, Shown<'static>> {
    if e.meta.restricted {
        return Err(text("access denied"));
    }
    match e.meta.kind {
        EntryKind::File => {}
        EntryKind::Dir => return Err(text("a folder, not a file")),
        EntryKind::Reparse => return Err(text("a link (not followed)")),
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
    Ok(r)
}

#[cfg(test)]
mod tests;
