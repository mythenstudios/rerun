//! `draft --hashes-from <game folder>` (P4-14): the main executables of a local copy of the
//! game with their real hashes, by exactly the logic of `rerun scan --hashes` (ADR 0014,
//! ADR 0016): the folder opened like a manually added game folder (`GameDir::open_manual`, the
//! forbidden roots from the workbench's own folder), `detect::exe::scan_game` with hashes and the
//! default bounds (at most 8 files, 2 GiB each), read only. Refused in an elevated process, like
//! every command of `rerun` that reads game folders for a plan.
//!
//! Taken are the candidates of the main executable (`Main::One`, or every one of `Main::Tied`:
//! a DX9 and a DX10 build) that were hashed, with the API of their imports if a Topo can name it
//! (`GraphicsApi::topo_name`); one without such an API is left out with a comment. The draft
//! names paths relative to the folder only, never the folder itself (it holds the user name).

use std::path::Path;

use rerun_core::catalog::model::{Api, Sha1, Sha256};
use rerun_core::detect::exe::{
    ApiVerdict, ExeLimits, GraphicsApi, HashOutcome, Main, Options, scan_game,
};
use rerun_core::exec::standard_user;
use rerun_core::path::RelPath;
use rerun_core::policy::root::{ForbiddenRoots, GameDir};
use rerun_core::sys::System;

/// One executable of the local copy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalExe {
    /// Relative to the game folder.
    pub path: RelPath,
    /// Its SHA-1.
    pub sha1: Sha1,
    /// Its SHA-256.
    pub sha256: Sha256,
    /// The API of its imports.
    pub api: Api,
}

/// The executables and the comments about those left out.
pub type Local = (Vec<LocalExe>, Vec<String>);

/// The Topo's name of a detected API, if it has one.
fn topo_api(a: GraphicsApi) -> Option<Api> {
    a.topo_name()?;
    Some(match a {
        GraphicsApi::Ddraw => Api::Ddraw,
        GraphicsApi::D3d8 => Api::D3d8,
        GraphicsApi::D3d9 => Api::D3d9,
        GraphicsApi::D3d10 => Api::D3d10,
        GraphicsApi::D3d11 => Api::D3d11,
        GraphicsApi::Opengl => Api::Opengl,
        _ => return None,
    })
}

/// A path for a comment: printable ASCII, anything else `?`.
fn shown(p: &RelPath) -> String {
    p.as_str()
        .chars()
        .map(|c| {
            if c.is_ascii_graphic() || c == ' ' {
                c
            } else {
                '?'
            }
        })
        .collect()
}

/// The main executables of `folder` (module docs). `install`: the workbench's own folder, for
/// the forbidden roots.
pub fn exes_from(sys: &dyn System, install: &Path, folder: &Path) -> Result<Local, String> {
    standard_user(sys).map_err(|_| {
        "--hashes-from: refused in an elevated process (run the workbench as a standard user)"
            .to_owned()
    })?;
    let fr = ForbiddenRoots::resolve(sys, install).map_err(|e| {
        format!(
            "the forbidden roots: {}",
            rerun_core::escape::text(&e.to_string())
        )
    })?;
    let game = GameDir::open_manual(sys, &fr, folder).map_err(|e| {
        format!(
            "--hashes-from: the game folder: {}",
            rerun_core::escape::text(&e.to_string())
        )
    })?;
    let name_hint = folder
        .file_name()
        .and_then(|n| n.to_str())
        .and_then(|n| RelPath::parse(n).ok());
    let exes = scan_game(
        &game,
        &Options {
            name_hint,
            hashes: true,
            limits: ExeLimits::DEFAULT,
        },
    );
    drop(game);
    let main = match &exes.main {
        Main::One(i) => vec![*i],
        Main::Tied(v) => v.clone(),
        Main::None => Vec::new(),
    };
    let mut out = Vec::new();
    let mut notes = Vec::new();
    for c in main.iter().filter_map(|i| exes.candidates.get(*i)) {
        let Ok(facts) = &c.facts else { continue };
        let HashOutcome::Done(h) = &facts.hashes else {
            notes.push(format!("{} left out: not hashed", shown(&c.path)));
            continue;
        };
        let api = match &facts.api.verdict {
            ApiVerdict::One { api, .. } => topo_api(*api).ok_or_else(|| api.to_string()),
            _ => Err("no single API".to_owned()),
        };
        let api = match api {
            Ok(a) => a,
            Err(what) => {
                notes.push(format!(
                    "{} left out: its graphics API ({what}) is not one a Topo can name (ADR 0014)",
                    shown(&c.path)
                ));
                continue;
            }
        };
        let (Some(sha1), Some(sha256)) = (
            Sha1::parse(&h.sha1.to_ascii_uppercase()),
            Sha256::parse(&h.sha256.to_ascii_uppercase()),
        ) else {
            notes.push(format!(
                "{} left out: hashes of another form",
                shown(&c.path)
            ));
            continue;
        };
        out.push(LocalExe {
            path: c.path.clone(),
            sha1,
            sha256,
            api,
        });
    }
    if out.is_empty() {
        let mut why = String::from(
            "--hashes-from: no main executable with hashes and a graphics API a Topo can name",
        );
        for n in &notes {
            why.push_str("; ");
            why.push_str(n);
        }
        return Err(format!("{why}: write match.exes by hand"));
    }
    Ok((out, notes))
}

#[cfg(test)]
mod tests;
