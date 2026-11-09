//! The UAC VirtualStore lookup (P3-7, ADR 0007 amendment P3-7). Read only.
//!
//! A game without a manifest that writes into `%ProgramFiles%`, `%ProgramFiles(x86)%` or
//! `%ProgramData%` as a standard user has its writes redirected to
//! `<LocalAppData>\VirtualStore\<path without drive>`, and from then on reads that copy, not the
//! file in the game folder. A file Rerun manages there may then have no effect. For each plan
//! root inside one of those three folders, [`shadows`] looks for such a copy of every file the
//! plan manages and reports it ([`Shadow::Copy`]).
//!
//! - The three folders come from [`KnownFolders`](crate::sys::KnownFolders), never from the
//!   environment, and are compared lexically with the root's canonical path (no file-system
//!   call). A root outside them is not looked up at all; a root without file ops neither.
//! - `LocalAppData` is opened by absolute path, read side only, like
//!   [`AppDir::path_of`](super::AppDir::path_of); `VirtualStore\<path without drive>` and each
//!   file below it handle-relative. A reparse point on that way (a junction, a symbolic link)
//!   is never followed: [`Shadow::Link`]. `VirtualStore` stays on the forbidden list: it is
//!   never a root and never written.
//! - The lookup never fails a preview or `verify`: whatever keeps it from running (`LocalAppData`
//!   unknown, an access error) is [`Shadow::Unchecked`], so "no copy" and "not looked" are never
//!   shown alike.

use std::collections::BTreeSet;

use super::open_abs;
use crate::escape::{self, Shown};
use crate::path::{RelPath, RootPath};
use crate::plan::{Plan, PlanBytes, PlanError, RootKind, Target};
use crate::sys::fs::EntryKind;
use crate::sys::{KnownFolder, SysErrorKind, System};

/// The folder below `LocalAppData` that UAC file virtualization writes to.
pub const VIRTUAL_STORE: &str = "VirtualStore";

/// The known folders whose writes UAC file virtualization redirects (the ones a game folder can
/// lie in; `%windir%` is forbidden as a root anyway).
const VIRTUALIZED: [KnownFolder; 3] = [
    KnownFolder::ProgramFiles,
    KnownFolder::ProgramFilesX86,
    KnownFolder::ProgramData,
];

/// What the lookup found for a plan root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Shadow {
    /// A copy of a managed file exists in the VirtualStore: the game probably reads it, not the
    /// managed file.
    Copy {
        /// Root index in the plan.
        root: usize,
        /// The managed file, relative to the root.
        file: RelPath,
        /// The copy's full path (`escape::path`).
        copy: Shown<'static>,
    },
    /// A reparse point on the way to (or at) a copy: not followed, not looked behind.
    Link {
        /// Root index in the plan.
        root: usize,
        /// The path that was looked up (`escape::path`).
        at: Shown<'static>,
    },
    /// The lookup could not run for this root.
    Unchecked {
        /// Root index in the plan.
        root: usize,
        /// Why (`escape::text`).
        why: Shown<'static>,
    },
}

/// `true` if `root` lies inside one of the three virtualized known folders (lexical, folded). A
/// folder that cannot be resolved is not compared: without it policy hands out no root at all
/// (`ForbiddenRoots` fails closed), so no plan root can lie in it.
fn virtualized(sys: &dyn System, root: &RootPath) -> bool {
    VIRTUALIZED.iter().any(|f| {
        sys.known_folders()
            .get(*f)
            .ok()
            .and_then(|p| RootPath::new(p).ok())
            .is_some_and(|k| k.contains(root))
    })
}

/// The lookup for root `root` at `path` and the managed files `files` (module docs).
pub fn check_root<'a>(
    sys: &dyn System,
    root: usize,
    path: &RootPath,
    files: impl IntoIterator<Item = &'a RelPath>,
) -> Vec<Shadow> {
    if !virtualized(sys, path) {
        return Vec::new();
    }
    let unchecked = |why: &str| {
        vec![Shadow::Unchecked {
            root,
            why: escape::text(why).into_owned(),
        }]
    };
    // `Program Files (x86)\G`: the canonical path below its drive letter.
    let rest = path.to_string();
    let below = match RelPath::parse(&format!(r"{VIRTUAL_STORE}\{}", rest.get(3..).unwrap_or(""))) {
        Ok(b) => b,
        Err(e) => return unchecked(&e.to_string()),
    };
    let lad = match sys.known_folders().get(KnownFolder::LocalAppData) {
        Ok(p) => p,
        Err(e) => return unchecked(&format!("LocalAppData is unknown: {e}")),
    };
    let base = match RootPath::new(&lad) {
        Ok(b) => b,
        Err(e) => return unchecked(&format!("LocalAppData: {e}")),
    };
    let dir = match open_abs(sys, base.path()) {
        Ok(d) => d,
        Err(e) => return unchecked(&format!("LocalAppData: {e}")),
    };
    // Shown with the canonical path of the folder that was actually opened.
    let canon = match dir
        .info()
        .map_err(|e| e.to_string())
        .and_then(|i| RootPath::from_final_path(&i.final_path).map_err(|e| e.to_string()))
    {
        Ok(c) => c,
        Err(e) => return unchecked(&format!("LocalAppData: {e}")),
    };
    let shown = |rel: &str| escape::path(&format!(r"{canon}\{rel}")).into_owned();
    let store = match dir.open_dir(&below) {
        Ok(s) => s,
        Err(e) if e.kind == SysErrorKind::NotFound => return Vec::new(),
        Err(e) if e.kind == SysErrorKind::ReparsePoint => {
            return vec![Shadow::Link {
                root,
                at: shown(below.as_str()),
            }];
        }
        Err(e) => return unchecked(&e.to_string()),
    };
    let mut out = Vec::new();
    for file in files {
        let at = format!(r"{below}\{file}");
        match store.metadata(file) {
            Ok(Some(m)) if m.kind == EntryKind::File => out.push(Shadow::Copy {
                root,
                file: file.clone(),
                copy: shown(&at),
            }),
            Ok(Some(m)) if m.kind == EntryKind::Reparse => out.push(Shadow::Link {
                root,
                at: shown(&at),
            }),
            // Missing, or a folder of that name (no copy of a file).
            Ok(_) => {}
            Err(e) if e.kind == SysErrorKind::NotFound => {}
            Err(e) if e.kind == SysErrorKind::ReparsePoint => out.push(Shadow::Link {
                root,
                at: shown(&at),
            }),
            Err(e) => out.push(Shadow::Unchecked {
                root,
                why: escape::text(&e.to_string()).into_owned(),
            }),
        }
    }
    out
}

/// The lookup for every game root of `p`, at `paths` (the plan's root paths for a preview, the
/// bound ones for `verify`), for the files its file ops manage (folders not counted).
pub fn shadows(sys: &dyn System, p: &Plan, paths: &[&RootPath]) -> Vec<Shadow> {
    let mut out = Vec::new();
    for (i, (r, path)) in p.roots.iter().zip(paths).enumerate() {
        if r.kind != RootKind::Game {
            continue;
        }
        let files: BTreeSet<&RelPath> = p
            .ops
            .iter()
            .filter_map(|o| match o.target() {
                Target::File {
                    root,
                    path,
                    dir: false,
                } if usize::from(root.0) == i => Some(path),
                _ => None,
            })
            .collect();
        if !files.is_empty() {
            out.extend(check_root(sys, i, path, files));
        }
    }
    out
}

/// [`shadows`] of stored plan bytes at the plan's own root paths (the preview of `rerun plan`
/// and `rerun apply`), decoded like [`crate::plan::preview_stored`].
pub fn shadows_stored(sys: &dyn System, b: &PlanBytes) -> Result<Vec<Shadow>, PlanError> {
    let p = crate::plan::decode(b.bytes())?;
    let paths: Vec<&RootPath> = p.roots.iter().map(|r| &r.path).collect();
    Ok(shadows(sys, &p, &paths))
}

#[cfg(test)]
mod tests;
