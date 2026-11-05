//! Test fixtures for `detect::steam`: a fake Windows layout with Rerun's install folder (as in
//! the `policy::root` tests) and builders for the registry values and Steam files. Every path,
//! name and ID is invented (`docs/09-testing.md`, VDF fixtures).

use std::path::Path;

use super::root::RootSource;
use crate::policy::root::ForbiddenRoots;
use crate::sys::fake::{FakeSystem, FakeSystemBuilder};
use crate::sys::registry::RegValue;

/// Rerun's install folder in the fake layout.
pub(super) const INSTALL: &str = r"C:\Users\Player\AppData\Local\Programs\Rerun";

/// The usual Steam folder.
pub(super) const STEAM: &str = r"C:\Program Files (x86)\Steam";

/// The fake Windows layout with the install folder.
pub(super) fn base() -> FakeSystemBuilder {
    FakeSystem::builder().windows_layout().dir(INSTALL)
}

/// The resolved forbidden list of `sys`.
pub(super) fn fr(sys: &FakeSystem) -> ForbiddenRoots {
    ForbiddenRoots::resolve(sys, Path::new(INSTALL)).unwrap_or_else(|e| panic!("{e}"))
}

/// `s` as a quoted VDF string.
pub(super) fn q(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', r"\\").replace('"', "\\\""))
}

/// `libraryfolders.vdf` in the current format: `(path, label)` per library, keys from 0.
pub(super) fn library_folders(libs: &[(&str, &str)]) -> String {
    let mut out = String::from("\"libraryfolders\"\n{\n\t\"contentstatsid\"\t\t\"-1\"\n");
    for (i, (path, label)) in libs.iter().enumerate() {
        out.push_str(&format!(
            "\t\"{i}\"\n\t{{\n\t\t\"path\"\t\t{}\n\t\t\"label\"\t\t{}\n\t\t\"apps\"\n\t\t{{\n\t\t\t\"1000001\"\t\t\"1024\"\n\t\t}}\n\t}}\n",
            q(path),
            q(label)
        ));
    }
    out.push_str("}\n");
    out
}

/// `libraryfolders.vdf` in the format before 2021 (the root not listed), keys from 1.
pub(super) fn legacy_folders(paths: &[&str]) -> String {
    let mut out = String::from("\"LibraryFolders\"\n{\n\t\"TimeNextStatsReport\"\t\t\"1\"\n");
    for (i, path) in paths.iter().enumerate() {
        out.push_str(&format!("\t\"{}\"\t\t{}\n", i + 1, q(path)));
    }
    out.push_str("}\n");
    out
}

/// `appmanifest_<id>.acf`.
pub(super) fn acf(app_id: u32, name: &str, install_dir: &str, flags: u32) -> String {
    format!(
        "\"AppState\"\n{{\n\t\"appid\"\t\t\"{app_id}\"\n\t\"universe\"\t\t\"1\"\n\t\"name\"\t\t{}\n\t\"StateFlags\"\t\t\"{flags}\"\n\t\"installdir\"\t\t{}\n\t\"SizeOnDisk\"\t\t\"1\"\n}}\n",
        q(name),
        q(install_dir)
    )
}

/// Extension of the builder for Steam fixtures.
pub(super) trait SteamFixture: Sized {
    /// Sets the value of a registry candidate.
    fn candidate(self, source: RootSource, value: RegValue) -> Self;

    /// A file below a folder (relative path with `\`).
    fn file_in(self, folder: &str, rel: &str, content: &str) -> Self;

    /// Sets a registry candidate to a `REG_SZ` path.
    fn candidate_path(self, source: RootSource, path: &str) -> Self {
        self.candidate(source, RegValue::String(path.to_owned()))
    }

    /// `steamapps\libraryfolders.vdf` of `root`.
    fn library_file(self, root: &str, content: &str) -> Self {
        self.file_in(root, r"steamapps\libraryfolders.vdf", content)
    }

    /// `steamapps\appmanifest_<id>.acf` of `library` with state `FullyInstalled`, and its game
    /// folder `steamapps\common\<install_dir>`.
    fn app(self, library: &str, app_id: u32, name: &str, install_dir: &str) -> Self {
        self.file_in(
            library,
            &format!(r"steamapps\appmanifest_{app_id}.acf"),
            &acf(app_id, name, install_dir, 4),
        )
        .file_in(
            library,
            &format!(r"steamapps\common\{install_dir}\game.exe"),
            "MZ",
        )
    }
}

impl SteamFixture for FakeSystemBuilder {
    fn candidate(self, source: RootSource, value: RegValue) -> Self {
        self.value(source.key(), source.value_name(), value)
    }

    fn file_in(self, folder: &str, rel: &str, content: &str) -> Self {
        self.file(Path::new(folder).join(rel), content.as_bytes().to_vec())
    }
}
