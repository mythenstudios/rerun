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
//!   shown alike. A path in its reason is shown as a path (`escape::path`), apart from the text.
//! - A file (not a folder) at a component of `VirtualStore\<path without drive>\<file>` means
//!   that no copy can exist there: virtualization would need a folder at that place, and the
//!   game cannot read a copy through a file. Nothing is reported, for the root part exactly as
//!   for the part below it ([`Dir::metadata`](crate::sys::Dir::metadata) is `Ok(None)` for a
//!   path whose parent is a file).

use std::collections::BTreeSet;

use super::open_abs;
use crate::escape::{self, Shown};
use crate::path::{PathError, RelPath, RootPath};
use crate::plan::{Plan, PlanBytes, PlanError, Preview, RootKind, Target};
use crate::sys::fs::{EntryKind, Metadata};
use crate::sys::{KnownFolder, SysError, SysErrorKind, SysResult, System};

/// The literal of [`VIRTUAL_STORE`], for `concat!` in the const tables of the forbidden list
/// (`forbidden.rs`): one spelling, so the list and the lookup cannot drift apart.
macro_rules! virtual_store {
    () => {
        "VirtualStore"
    };
}
pub(super) use virtual_store;

/// The folder below `LocalAppData` that UAC file virtualization writes to.
pub const VIRTUAL_STORE: &str = virtual_store!();

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
        /// Why, without the path it is about (`escape::text`).
        why: Shown<'static>,
        /// The path the reason is about, if any (`escape::path`): a raw `LocalAppData` value,
        /// the path an access error names.
        at: Option<Shown<'static>>,
    },
}

/// [`Shadow::Unchecked`] with the reason as text and the path, if any, as a path.
fn unchecked(root: usize, why: &str, at: Option<&str>) -> Shadow {
    Shadow::Unchecked {
        root,
        why: escape::text(why).into_owned(),
        at: at.map(|a| escape::path(a).into_owned()),
    }
}

/// [`unchecked`] for a system error: kind (and limit) as the reason, its target as the path.
fn unchecked_sys(root: usize, ctx: &str, e: &SysError) -> Shadow {
    let limit = e.limit.map(|n| format!(" (limit {n})")).unwrap_or_default();
    let at = (!e.target.is_empty()).then_some(e.target.as_str());
    unchecked(root, &format!("{ctx}{}{limit}", e.kind), at)
}

/// [`unchecked`] for a path error: its reason as the reason, the checked path as the path.
fn unchecked_path(root: usize, ctx: &str, e: &PathError) -> Shadow {
    unchecked(
        root,
        &format!("{ctx}invalid path: {}", e.reason),
        Some(&e.path),
    )
}

/// What one `metadata` answer on the way to a copy means. `None`: nothing to report (missing,
/// a folder of the file's name, or a file at a component of the way: module docs). `file`:
/// the managed file a found file is a copy of (`None` for the root part, where a file is a
/// component of the way, never a copy).
fn classify(
    root: usize,
    m: SysResult<Option<Metadata>>,
    shown: impl Fn() -> Shown<'static>,
    file: Option<&RelPath>,
) -> Option<Shadow> {
    match m {
        Ok(Some(m)) if m.kind == EntryKind::Reparse => Some(Shadow::Link { root, at: shown() }),
        Ok(Some(m)) if m.kind == EntryKind::File => file.map(|f| Shadow::Copy {
            root,
            file: f.clone(),
            copy: shown(),
        }),
        Ok(_) => None,
        Err(e) if e.kind == SysErrorKind::NotFound => None,
        Err(e) if e.kind == SysErrorKind::ReparsePoint => Some(Shadow::Link { root, at: shown() }),
        Err(e) => Some(unchecked_sys(root, "", &e)),
    }
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
    let one = |s: Shadow| vec![s];
    // `Program Files (x86)\G`: the canonical path below its drive letter.
    let rest = path.to_string();
    let below = match RelPath::parse(&format!(r"{VIRTUAL_STORE}\{}", rest.get(3..).unwrap_or(""))) {
        Ok(b) => b,
        Err(e) => return one(unchecked_path(root, "", &e)),
    };
    let lad = match sys.known_folders().get(KnownFolder::LocalAppData) {
        Ok(p) => p,
        Err(e) => return one(unchecked_sys(root, "LocalAppData is unknown: ", &e)),
    };
    let base = match RootPath::new(&lad) {
        Ok(b) => b,
        Err(e) => return one(unchecked_path(root, "LocalAppData: ", &e)),
    };
    let dir = match open_abs(sys, base.path()) {
        Ok(d) => d,
        Err(e) => return one(unchecked_sys(root, "LocalAppData: ", &e)),
    };
    // Shown with the canonical path of the folder that was actually opened.
    let info = match dir.info() {
        Ok(i) => i,
        Err(e) => return one(unchecked_sys(root, "LocalAppData: ", &e)),
    };
    let canon = match RootPath::from_final_path(&info.final_path) {
        Ok(c) => c,
        Err(e) => return one(unchecked_path(root, "LocalAppData: ", &e)),
    };
    let shown = |rel: &str| escape::path(&format!(r"{canon}\{rel}")).into_owned();
    let store = match dir.open_dir(&below) {
        Ok(s) => s,
        Err(e) if e.kind == SysErrorKind::NotFound => return Vec::new(),
        Err(e) if e.kind == SysErrorKind::ReparsePoint => {
            return one(Shadow::Link {
                root,
                at: shown(below.as_str()),
            });
        }
        // Not a folder somewhere on the way: asked like the walk below asks a file, so a file
        // at a component says nothing here exactly as there (module docs). A folder after all
        // (it changed in between) is the open's error.
        Err(e) if e.kind == SysErrorKind::InvalidPath => {
            return match dir.metadata(&below) {
                Ok(Some(m)) if m.kind == EntryKind::Dir => one(unchecked_sys(root, "", &e)),
                m => classify(root, m, || shown(below.as_str()), None)
                    .into_iter()
                    .collect(),
            };
        }
        Err(e) => return one(unchecked_sys(root, "", &e)),
    };
    files
        .into_iter()
        .filter_map(|file| {
            let at = format!(r"{below}\{file}");
            classify(root, store.metadata(file), || shown(&at), Some(file))
        })
        .collect()
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

/// [`crate::plan::preview_stored`] of stored plan bytes together with their [`shadows`] at the
/// plan's own root paths (the preview of `rerun plan` and `rerun apply`): one decode for both,
/// so a decode error fails the preview and is never a silent "no copy".
pub fn preview_with_shadows(
    sys: &dyn System,
    b: &PlanBytes,
) -> Result<(Preview, Vec<Shadow>), PlanError> {
    let p = crate::plan::decode(b.bytes())?;
    let paths: Vec<&RootPath> = p.roots.iter().map(|r| &r.path).collect();
    Ok((crate::plan::preview(&p), shadows(sys, &p, &paths)))
}

#[cfg(test)]
mod tests;
