//! Known folders: the machine and user folders that `policy::root` keeps off limits.
//!
//! The real implementation (`sys::win`) resolves them with `GetSystemWindowsDirectoryW`
//! (not `GetWindowsDirectoryW`, which is per session) and `SHGetKnownFolderPath`. **Never
//! from environment variables**: `windir`, `ProgramFiles` and friends can be overridden per
//! user and are inherited by the elevated helper (ADR 0007, review finding H3).
//!
//! The paths are raw, as the system reports them. Canonicalizing (open + final path) and
//! comparing is the job of `policy::root`.

use std::fmt;
use std::path::PathBuf;

use super::SysResult;

/// A known folder. Only the folders `policy::root` needs (ADR 0007, forbidden roots).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum KnownFolder {
    /// `C:\Windows` (`GetSystemWindowsDirectoryW`).
    Windows,
    /// `C:\Program Files` (`FOLDERID_ProgramFiles`).
    ProgramFiles,
    /// `C:\Program Files (x86)` (`FOLDERID_ProgramFilesX86`).
    ProgramFilesX86,
    /// `C:\Program Files\Common Files` (`FOLDERID_ProgramFilesCommon`).
    ProgramFilesCommon,
    /// `C:\Program Files (x86)\Common Files` (`FOLDERID_ProgramFilesCommonX86`).
    ProgramFilesCommonX86,
    /// `C:\ProgramData` (`FOLDERID_ProgramData`).
    ProgramData,
    /// `C:\Users`, the folder with all profiles (`FOLDERID_UserProfiles`).
    UserProfiles,
    /// The own profile, `C:\Users\<name>` (`FOLDERID_Profile`).
    Profile,
    /// `…\AppData\Local` of the own profile (`FOLDERID_LocalAppData`).
    LocalAppData,
    /// `…\AppData\Roaming` of the own profile (`FOLDERID_RoamingAppData`). The only folder
    /// that may be redirected to a network path (folder redirection).
    RoamingAppData,
}

impl KnownFolder {
    /// All known folders, in declaration order.
    pub const ALL: [Self; 10] = [
        Self::Windows,
        Self::ProgramFiles,
        Self::ProgramFilesX86,
        Self::ProgramFilesCommon,
        Self::ProgramFilesCommonX86,
        Self::ProgramData,
        Self::UserProfiles,
        Self::Profile,
        Self::LocalAppData,
        Self::RoamingAppData,
    ];
}

impl fmt::Display for KnownFolder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Windows => "Windows",
            Self::ProgramFiles => "ProgramFiles",
            Self::ProgramFilesX86 => "ProgramFilesX86",
            Self::ProgramFilesCommon => "ProgramFilesCommon",
            Self::ProgramFilesCommonX86 => "ProgramFilesCommonX86",
            Self::ProgramData => "ProgramData",
            Self::UserProfiles => "UserProfiles",
            Self::Profile => "Profile",
            Self::LocalAppData => "LocalAppData",
            Self::RoamingAppData => "RoamingAppData",
        })
    }
}

/// Resolves known folders.
pub trait KnownFolders: Send + Sync {
    /// Absolute path of `folder` as reported by the system. `NotFound` if the system has no
    /// such folder.
    fn get(&self, folder: KnownFolder) -> SysResult<PathBuf>;
}
