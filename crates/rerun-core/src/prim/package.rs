//! `package` (ADR 0020 amendment P4-7, ADR 0025 part 2): a Topo's `package: <id>` step as the
//! `file_install` step of exactly the package's files that are for this game.
//!
//! A pure function of the package (from the signed index) and the game's build: no I/O. The
//! `file_install` planner then does what it does for every step (sources hashed below
//! `<AppDir>\packages\<id>\<version>`, targets in the game folder), so a Topo plan has the bytes
//! of a step file with the same `file_install` step.
//!
//! - **Architecture** of the game's main executable, from its PE header (`detect`): the
//!   package's `arch` must name it; a file with `arch` only for it. Unknown (ARM64, another
//!   machine) is refused.
//! - **Graphics API** of the main executable as the Topo states it: the `api` of exactly the
//!   `match.exes` entry whose hashes matched (two entries may name one path with different
//!   builds; detection can only guess the API, ADR 0014). A package with `apis` must name it; a
//!   file with `api` only for it.
//! - **Source** below the version folder: `from`, or `<arch>\<from>` for a package with one
//!   asset per architecture (`Package::place`, the rule the loader and the extraction share).
//! - Refused: a community package (the user downloads it; that way is not built), a `TODO`
//!   hash, a package of which nothing is for this game.

use super::{FileEntry, FileInstallSpec};
use crate::catalog::model::{Api, Arch, ArchList, Package, Tier};

/// What the planner knows of the game's build.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GameBuild {
    /// The main executable's architecture (`None`: not x86 or x64, or not read).
    pub arch: Option<Arch>,
    /// The main executable's graphics API (the `api` of the `match.exes` entry that matched).
    pub api: Api,
}

/// Why a package cannot be planned for this game.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PackageRefusal {
    /// The game's architecture is not x86 or x64.
    #[error("the game's main executable is neither x86 nor x64")]
    UnknownArch,
    /// The package is not built for the game's architecture.
    #[error("the package is not built for {0}")]
    Arch(&'static str),
    /// The package does not wrap the game's API.
    #[error("the package does not support {0}")]
    Api(&'static str),
    /// A community package.
    #[error("a community package is downloaded by the user; Rerun does not install it yet")]
    Community,
    /// A hash or the architecture list is `TODO` (never in a signed index).
    #[error("the package is a draft (TODO)")]
    Draft,
    /// None of its files is for this game.
    #[error("none of the package's files is for this game")]
    Empty,
}

fn api_name(a: Api) -> &'static str {
    match a {
        Api::Ddraw => "ddraw",
        Api::D3d8 => "d3d8",
        Api::D3d9 => "d3d9",
        Api::D3d10 => "d3d10",
        Api::D3d11 => "d3d11",
        Api::Opengl => "opengl",
    }
}

/// The `file_install` step of `p` for a game of `build` (module docs).
pub fn file_install(p: &Package, build: &GameBuild) -> Result<FileInstallSpec, PackageRefusal> {
    if p.tier == Tier::Community {
        return Err(PackageRefusal::Community);
    }
    let arch = build.arch.ok_or(PackageRefusal::UnknownArch)?;
    match &p.arch {
        ArchList::List(a) if a.contains(&arch) => {}
        ArchList::List(_) => return Err(PackageRefusal::Arch(arch.as_str())),
        ArchList::Todo(_) => return Err(PackageRefusal::Draft),
    }
    if let Some(apis) = &p.apis
        && !apis.contains(&build.api)
    {
        return Err(PackageRefusal::Api(api_name(build.api)));
    }
    let mut files = Vec::new();
    for f in &p.files {
        if f.arch.as_ref().is_some_and(|a| !a.contains(&arch))
            || f.api.as_ref().is_some_and(|a| !a.contains(&build.api))
        {
            continue;
        }
        let Some(from) = p.place(f, Some(arch)) else {
            continue;
        };
        let sha256 = *f.sha256.bytes().ok_or(PackageRefusal::Draft)?;
        files.push(FileEntry {
            from,
            to: f.to.clone(),
            sha256,
            config: f.config,
        });
    }
    if files.is_empty() {
        return Err(PackageRefusal::Empty);
    }
    Ok(FileInstallSpec {
        package: p.id.to_string(),
        version: p.version.clone(),
        files,
    })
}
