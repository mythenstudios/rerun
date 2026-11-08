//! [`read_input`]: a file the user names on the command line (the phase 2 step file, P2-13).
//!
//! The file is the user's own input, read once and never written: its folder is opened by
//! absolute path, read side only, like a store root (a link above it is followed), and must be
//! a plain drive-letter folder, also canonically (no network share, no volume without a drive
//! letter, not a drive root). The file itself is one segment below it, opened handle-relative:
//! a plain file (not a link or other reparse point, not restricted), read with `read_limited`.
//! No forbidden-root check: nothing is written there, and the folder is the user's choice.

use std::path::Path;

use super::{RootError, open_abs, raced};
use crate::path::{PathError, RelPath, RootPath, classify};
use crate::sys::fs::EntryKind;
use crate::sys::{SysError, SysErrorKind, System};

/// Reads the input file `abs` (an absolute path; module docs): at most `max` bytes, more is
/// `TooLarge` and nothing is returned.
pub fn read_input(sys: &dyn System, abs: &Path, max: u64) -> Result<Vec<u8>, RootError> {
    let shown = abs.display().to_string();
    let bad = |reason| {
        RootError::InvalidPath(PathError {
            path: shown.clone(),
            reason,
        })
    };
    // A share (`\\server\share`, `\\?\UNC\…`): say so, not just "no drive letter".
    let raw = abs.to_string_lossy();
    let share = raw
        .get(..8)
        .is_some_and(|p| p.eq_ignore_ascii_case(r"\\?\UNC\"))
        || ((raw.starts_with(r"\\") || raw.starts_with("//"))
            && !raw.starts_with(r"\\?\")
            && !raw.starts_with(r"\\.\"));
    if share {
        return Err(bad(
            "an input file on a network share is not read; copy it to a local folder",
        ));
    }
    let (Some(parent), Some(name)) = (abs.parent(), abs.file_name()) else {
        return Err(bad("not a file path"));
    };
    let name = name.to_str().ok_or_else(|| bad("not valid Unicode"))?;
    // A drive root has no parent of its own; say what is wrong with the input, not that a
    // "game root" must not be a drive root (review nit).
    if parent.parent().is_none() {
        return Err(bad(
            "an input file directly on a drive root is not read; move it into a folder",
        ));
    }
    let folder = RootPath::new(parent)?;
    let dir = open_abs(sys, folder.path())?;
    let info = dir.info().map_err(raced)?;
    // Canonically too: a drive letter mapped to a share, a folder mounted elsewhere.
    RootPath::from_final_path(&info.final_path)?;
    if info.volume_first_segment().is_none() {
        return Err(bad(
            "an input file directly on a drive root is not read; move it into a folder",
        ));
    }
    let file: RelPath = classify(name, false)?;
    match dir.metadata(&file)? {
        Some(m) if m.kind == EntryKind::File && m.reparse.is_none() && !m.restricted => {}
        Some(_) => {
            return Err(RootError::Sys(SysError::new(
                SysErrorKind::InvalidPath,
                format!("{file} (not a plain file)"),
            )));
        }
        None => {
            return Err(RootError::Sys(SysError::new(
                SysErrorKind::NotFound,
                file.as_str(),
            )));
        }
    }
    Ok(dir.read_limited(&file, max)?)
}

/// Whether `<install>\<name>` is a plain file (P3-3d: the shim the launch option names), read
/// side only: `install` opened by absolute path like [`read_input`]'s folder (a drive root
/// too), the file one segment below it, never followed through a link. `Ok(false)` if it is
/// missing, a folder, a link or restricted.
pub fn file_present(sys: &dyn System, install: &Path, name: &str) -> Result<bool, RootError> {
    let dir = open_abs(sys, install)?;
    let file: RelPath = classify(name, false)?;
    Ok(matches!(
        dir.metadata(&file)?,
        Some(m) if m.kind == EntryKind::File && m.reparse.is_none() && !m.restricted
    ))
}
