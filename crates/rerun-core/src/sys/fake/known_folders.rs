//! Fake known folders: a standard Windows 11 layout for the user `Player`.

use std::collections::BTreeMap;
use std::path::PathBuf;

use crate::sys::{KnownFolder, KnownFolders, SysError, SysErrorKind, SysResult};

/// Known folders from a table. The default is a standard layout on `C:`; the directories
/// themselves only exist in the fake file system after
/// [`FakeSystemBuilder::windows_layout`](super::FakeSystemBuilder::windows_layout).
#[derive(Debug, Clone)]
pub struct FakeKnownFolders {
    folders: BTreeMap<KnownFolder, PathBuf>,
}

impl Default for FakeKnownFolders {
    fn default() -> Self {
        let folders = KnownFolder::ALL
            .into_iter()
            .map(|f| (f, PathBuf::from(Self::standard(f))))
            .collect();
        Self { folders }
    }
}

impl FakeKnownFolders {
    /// Path of `folder` in the standard layout.
    pub fn standard(folder: KnownFolder) -> &'static str {
        match folder {
            KnownFolder::Windows => r"C:\Windows",
            KnownFolder::ProgramFiles => r"C:\Program Files",
            KnownFolder::ProgramFilesX86 => r"C:\Program Files (x86)",
            KnownFolder::ProgramFilesCommon => r"C:\Program Files\Common Files",
            KnownFolder::ProgramFilesCommonX86 => r"C:\Program Files (x86)\Common Files",
            KnownFolder::ProgramData => r"C:\ProgramData",
            KnownFolder::UserProfiles => r"C:\Users",
            KnownFolder::Profile => r"C:\Users\Player",
            KnownFolder::LocalAppData => r"C:\Users\Player\AppData\Local",
            KnownFolder::RoamingAppData => r"C:\Users\Player\AppData\Roaming",
        }
    }

    /// Sets `folder` to `path`.
    pub fn set(&mut self, folder: KnownFolder, path: impl Into<PathBuf>) {
        self.folders.insert(folder, path.into());
    }

    /// Removes `folder`; [`KnownFolders::get`] then reports `NotFound`.
    pub fn remove(&mut self, folder: KnownFolder) {
        self.folders.remove(&folder);
    }

    /// All configured folders.
    pub fn paths(&self) -> impl Iterator<Item = (KnownFolder, &PathBuf)> {
        self.folders.iter().map(|(f, p)| (*f, p))
    }
}

impl KnownFolders for FakeKnownFolders {
    fn get(&self, folder: KnownFolder) -> SysResult<PathBuf> {
        self.folders
            .get(&folder)
            .cloned()
            .ok_or_else(|| SysError::new(SysErrorKind::NotFound, format!("known folder {folder}")))
    }
}
