//! Compile-time check of the `windows-sys` entries in `clippy.toml` (review L4).
//!
//! `allow-invalid = true` makes clippy silently ignore a ban whose path does not resolve, so a
//! typo would leave an API unbanned. Every banned `windows-sys` item is referenced here once,
//! never called, each under its own `#[expect(clippy::disallowed_methods)]`: a dead entry turns
//! into an unfulfilled expectation, which `clippy -D warnings` rejects.
//! [`every_banned_item_is_listed_here`] keeps this list and `clippy.toml` in sync. The
//! `std::env` bans (ADR 0009) are checked the same way ([`banned_std_env_items_resolve`],
//! [`every_banned_std_env_item_is_listed_here`]).

#[test]
fn banned_windows_sys_items_resolve() {
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: CreateFileW must be banned"
    )]
    let _ = windows_sys::Win32::Storage::FileSystem::CreateFileW;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: CreateFileA must be banned"
    )]
    let _ = windows_sys::Win32::Storage::FileSystem::CreateFileA;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: CreateFile2 must be banned"
    )]
    let _ = windows_sys::Win32::Storage::FileSystem::CreateFile2;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: OpenFileById must be banned"
    )]
    let _ = windows_sys::Win32::Storage::FileSystem::OpenFileById;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: FindFirstFileW must be banned"
    )]
    let _ = windows_sys::Win32::Storage::FileSystem::FindFirstFileW;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: FindFirstFileExW must be banned"
    )]
    let _ = windows_sys::Win32::Storage::FileSystem::FindFirstFileExW;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: GetFileAttributesW must be banned"
    )]
    let _ = windows_sys::Win32::Storage::FileSystem::GetFileAttributesW;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: GetFileAttributesExW must be banned"
    )]
    let _ = windows_sys::Win32::Storage::FileSystem::GetFileAttributesExW;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: SetFileAttributesW must be banned"
    )]
    let _ = windows_sys::Win32::Storage::FileSystem::SetFileAttributesW;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: DeleteFileW must be banned"
    )]
    let _ = windows_sys::Win32::Storage::FileSystem::DeleteFileW;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: RemoveDirectoryW must be banned"
    )]
    let _ = windows_sys::Win32::Storage::FileSystem::RemoveDirectoryW;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: CreateDirectoryW must be banned"
    )]
    let _ = windows_sys::Win32::Storage::FileSystem::CreateDirectoryW;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: CreateDirectoryExW must be banned"
    )]
    let _ = windows_sys::Win32::Storage::FileSystem::CreateDirectoryExW;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: MoveFileW must be banned"
    )]
    let _ = windows_sys::Win32::Storage::FileSystem::MoveFileW;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: MoveFileExW must be banned"
    )]
    let _ = windows_sys::Win32::Storage::FileSystem::MoveFileExW;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: MoveFileWithProgressW must be banned"
    )]
    let _ = windows_sys::Win32::Storage::FileSystem::MoveFileWithProgressW;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: ReplaceFileW must be banned"
    )]
    let _ = windows_sys::Win32::Storage::FileSystem::ReplaceFileW;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: CopyFileW must be banned"
    )]
    let _ = windows_sys::Win32::Storage::FileSystem::CopyFileW;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: CopyFileExW must be banned"
    )]
    let _ = windows_sys::Win32::Storage::FileSystem::CopyFileExW;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: CopyFile2 must be banned"
    )]
    let _ = windows_sys::Win32::Storage::FileSystem::CopyFile2;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: CreateHardLinkW must be banned"
    )]
    let _ = windows_sys::Win32::Storage::FileSystem::CreateHardLinkW;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: CreateSymbolicLinkW must be banned"
    )]
    let _ = windows_sys::Win32::Storage::FileSystem::CreateSymbolicLinkW;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: GetFullPathNameW must be banned"
    )]
    let _ = windows_sys::Win32::Storage::FileSystem::GetFullPathNameW;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: GetLongPathNameW must be banned"
    )]
    let _ = windows_sys::Win32::Storage::FileSystem::GetLongPathNameW;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: GetShortPathNameW must be banned"
    )]
    let _ = windows_sys::Win32::Storage::FileSystem::GetShortPathNameW;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: GetVolumeInformationW must be banned"
    )]
    let _ = windows_sys::Win32::Storage::FileSystem::GetVolumeInformationW;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: GetCompressedFileSizeW must be banned"
    )]
    let _ = windows_sys::Win32::Storage::FileSystem::GetCompressedFileSizeW;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: GetFileSecurityW must be banned"
    )]
    let _ = windows_sys::Win32::Security::GetFileSecurityW;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: SetFileSecurityW must be banned"
    )]
    let _ = windows_sys::Win32::Security::SetFileSecurityW;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: GetNamedSecurityInfoW must be banned"
    )]
    let _ = windows_sys::Win32::Security::Authorization::GetNamedSecurityInfoW;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: SetNamedSecurityInfoW must be banned"
    )]
    let _ = windows_sys::Win32::Security::Authorization::SetNamedSecurityInfoW;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: SetVolumeMountPointW must be banned"
    )]
    let _ = windows_sys::Win32::Storage::FileSystem::SetVolumeMountPointW;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: DeleteVolumeMountPointW must be banned"
    )]
    let _ = windows_sys::Win32::Storage::FileSystem::DeleteVolumeMountPointW;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: DefineDosDeviceW must be banned"
    )]
    let _ = windows_sys::Win32::Storage::FileSystem::DefineDosDeviceW;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: SetCurrentDirectoryW must be banned"
    )]
    let _ = windows_sys::Win32::System::Environment::SetCurrentDirectoryW;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: CreateFileFromAppW must be banned"
    )]
    let _ = windows_sys::Win32::Storage::FileSystem::CreateFileFromAppW;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: DeleteFileFromAppW must be banned"
    )]
    let _ = windows_sys::Win32::Storage::FileSystem::DeleteFileFromAppW;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: CreateFileTransactedW must be banned"
    )]
    let _ = windows_sys::Win32::Storage::FileSystem::CreateFileTransactedW;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: OpenFile must be banned"
    )]
    let _ = windows_sys::Win32::Storage::FileSystem::OpenFile;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: DeleteFileA must be banned"
    )]
    let _ = windows_sys::Win32::Storage::FileSystem::DeleteFileA;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: MoveFileExA must be banned"
    )]
    let _ = windows_sys::Win32::Storage::FileSystem::MoveFileExA;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: MoveFileA must be banned"
    )]
    let _ = windows_sys::Win32::Storage::FileSystem::MoveFileA;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: CopyFileA must be banned"
    )]
    let _ = windows_sys::Win32::Storage::FileSystem::CopyFileA;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: CreateDirectoryA must be banned"
    )]
    let _ = windows_sys::Win32::Storage::FileSystem::CreateDirectoryA;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: RemoveDirectoryA must be banned"
    )]
    let _ = windows_sys::Win32::Storage::FileSystem::RemoveDirectoryA;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: GetFileAttributesA must be banned"
    )]
    let _ = windows_sys::Win32::Storage::FileSystem::GetFileAttributesA;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: FindFirstFileA must be banned"
    )]
    let _ = windows_sys::Win32::Storage::FileSystem::FindFirstFileA;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: CreateHardLinkA must be banned"
    )]
    let _ = windows_sys::Win32::Storage::FileSystem::CreateHardLinkA;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: CreateSymbolicLinkA must be banned"
    )]
    let _ = windows_sys::Win32::Storage::FileSystem::CreateSymbolicLinkA;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: NtDeleteFile must be banned"
    )]
    let _ = windows_sys::Wdk::Storage::FileSystem::NtDeleteFile;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: ZwDeleteFile must be banned"
    )]
    let _ = windows_sys::Wdk::Storage::FileSystem::ZwDeleteFile;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: NtQueryFullAttributesFile must be banned"
    )]
    let _ = windows_sys::Wdk::Storage::FileSystem::NtQueryFullAttributesFile;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: ZwQueryFullAttributesFile must be banned"
    )]
    let _ = windows_sys::Wdk::Storage::FileSystem::ZwQueryFullAttributesFile;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: NtQueryInformationByName must be banned"
    )]
    let _ = windows_sys::Wdk::Storage::FileSystem::NtQueryInformationByName;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: ZwCreateFile must be banned"
    )]
    let _ = windows_sys::Wdk::System::SystemServices::ZwCreateFile;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: ZwOpenFile must be banned"
    )]
    let _ = windows_sys::Wdk::System::SystemServices::ZwOpenFile;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: NtSetInformationFile must be banned"
    )]
    let _ = windows_sys::Wdk::Storage::FileSystem::NtSetInformationFile;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: CreateProcessW must be banned"
    )]
    let _ = windows_sys::Win32::System::Threading::CreateProcessW;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: CreateProcessA must be banned"
    )]
    let _ = windows_sys::Win32::System::Threading::CreateProcessA;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: CreateProcessAsUserW must be banned"
    )]
    let _ = windows_sys::Win32::System::Threading::CreateProcessAsUserW;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: NtCreateFile must be banned"
    )]
    let _ = windows_sys::Wdk::Storage::FileSystem::NtCreateFile;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: NtOpenFile must be banned"
    )]
    let _ = windows_sys::Wdk::Storage::FileSystem::NtOpenFile;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: SHGetKnownFolderPath must be banned"
    )]
    let _ = windows_sys::Win32::UI::Shell::SHGetKnownFolderPath;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: GetSystemWindowsDirectoryW must be banned"
    )]
    let _ = windows_sys::Win32::System::SystemInformation::GetSystemWindowsDirectoryW;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: GetSystemWindowsDirectoryA must be banned"
    )]
    let _ = windows_sys::Win32::System::SystemInformation::GetSystemWindowsDirectoryA;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: GetWindowsDirectoryW must be banned"
    )]
    let _ = windows_sys::Win32::System::SystemInformation::GetWindowsDirectoryW;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: GetWindowsDirectoryA must be banned"
    )]
    let _ = windows_sys::Win32::System::SystemInformation::GetWindowsDirectoryA;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: SHGetFolderPathW must be banned"
    )]
    let _ = windows_sys::Win32::UI::Shell::SHGetFolderPathW;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: SHGetFolderPathA must be banned"
    )]
    let _ = windows_sys::Win32::UI::Shell::SHGetFolderPathA;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: SHGetFolderPathAndSubDirW must be banned"
    )]
    let _ = windows_sys::Win32::UI::Shell::SHGetFolderPathAndSubDirW;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: SHGetFolderPathAndSubDirA must be banned"
    )]
    let _ = windows_sys::Win32::UI::Shell::SHGetFolderPathAndSubDirA;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: SHGetSpecialFolderPathW must be banned"
    )]
    let _ = windows_sys::Win32::UI::Shell::SHGetSpecialFolderPathW;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: SHGetSpecialFolderPathA must be banned"
    )]
    let _ = windows_sys::Win32::UI::Shell::SHGetSpecialFolderPathA;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: SHSetKnownFolderPath must be banned"
    )]
    let _ = windows_sys::Win32::UI::Shell::SHSetKnownFolderPath;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: SHSetFolderPathW must be banned"
    )]
    let _ = windows_sys::Win32::UI::Shell::SHSetFolderPathW;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: SHSetFolderPathA must be banned"
    )]
    let _ = windows_sys::Win32::UI::Shell::SHSetFolderPathA;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: GetProfilesDirectoryW must be banned"
    )]
    let _ = windows_sys::Win32::UI::Shell::GetProfilesDirectoryW;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: GetProfilesDirectoryA must be banned"
    )]
    let _ = windows_sys::Win32::UI::Shell::GetProfilesDirectoryA;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: GetAllUsersProfileDirectoryW must be banned"
    )]
    let _ = windows_sys::Win32::UI::Shell::GetAllUsersProfileDirectoryW;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: GetAllUsersProfileDirectoryA must be banned"
    )]
    let _ = windows_sys::Win32::UI::Shell::GetAllUsersProfileDirectoryA;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: DoEnvironmentSubstW must be banned"
    )]
    let _ = windows_sys::Win32::UI::Shell::DoEnvironmentSubstW;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: DoEnvironmentSubstA must be banned"
    )]
    let _ = windows_sys::Win32::UI::Shell::DoEnvironmentSubstA;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: GetEnvironmentVariableW must be banned"
    )]
    let _ = windows_sys::Win32::System::Environment::GetEnvironmentVariableW;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: GetEnvironmentVariableA must be banned"
    )]
    let _ = windows_sys::Win32::System::Environment::GetEnvironmentVariableA;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: GetEnvironmentStrings must be banned"
    )]
    let _ = windows_sys::Win32::System::Environment::GetEnvironmentStrings;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: GetEnvironmentStringsW must be banned"
    )]
    let _ = windows_sys::Win32::System::Environment::GetEnvironmentStringsW;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: ExpandEnvironmentStringsW must be banned"
    )]
    let _ = windows_sys::Win32::System::Environment::ExpandEnvironmentStringsW;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: ExpandEnvironmentStringsA must be banned"
    )]
    let _ = windows_sys::Win32::System::Environment::ExpandEnvironmentStringsA;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: ExpandEnvironmentStringsForUserW must be banned"
    )]
    let _ = windows_sys::Win32::System::Environment::ExpandEnvironmentStringsForUserW;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: ExpandEnvironmentStringsForUserA must be banned"
    )]
    let _ = windows_sys::Win32::System::Environment::ExpandEnvironmentStringsForUserA;
}

/// The `std::env` bans (ADR 0009) the same way: a ban that stops matching (a renamed or
/// moved item) becomes an unfulfilled expectation.
#[test]
fn banned_std_env_items_resolve() {
    #[expect(clippy::disallowed_methods, reason = "ban check: var must be banned")]
    let _ = std::env::var::<&str>;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: var_os must be banned"
    )]
    let _ = std::env::var_os::<&str>;
    #[expect(clippy::disallowed_methods, reason = "ban check: vars must be banned")]
    let _ = std::env::vars;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: vars_os must be banned"
    )]
    let _ = std::env::vars_os;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: home_dir must be banned"
    )]
    let _ = std::env::home_dir;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: temp_dir must be banned"
    )]
    let _ = std::env::temp_dir;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: set_current_dir must be banned"
    )]
    let _ = std::env::set_current_dir::<&str>;
}

/// Every `std::env::` path in `clippy.toml` is referenced by the test above.
#[test]
fn every_banned_std_env_item_is_listed_here() {
    let toml = include_str!("../../../../../clippy.toml");
    let this = include_str!("bans.rs");
    let mut n = 0;
    for line in toml.lines() {
        let Some(rest) = line.split("path = \"std::env::").nth(1) else {
            continue;
        };
        let path = rest.split('"').next().unwrap_or_default();
        assert!(
            this.contains(&format!("let _ = std::env::{path};"))
                || this.contains(&format!("let _ = std::env::{path}::<")),
            "clippy.toml bans std::env::{path}, but bans.rs does not check it"
        );
        n += 1;
    }
    assert_eq!(n, 7, "parsed {n} std::env bans");
}

/// Every `windows_sys::` path in `clippy.toml` is referenced by `banned_windows_sys_items_resolve`.
#[test]
fn every_banned_item_is_listed_here() {
    let toml = include_str!("../../../../../clippy.toml");
    let this = include_str!("bans.rs");
    let mut n = 0;
    for line in toml.lines() {
        let Some(rest) = line.split("path = \"windows_sys::").nth(1) else {
            continue;
        };
        let path = rest.split('"').next().unwrap_or_default();
        assert!(
            this.contains(&format!("let _ = windows_sys::{path};")),
            "clippy.toml bans windows_sys::{path}, but bans.rs does not check it"
        );
        n += 1;
    }
    assert!(n > 40, "parsed only {n} windows_sys bans");
}
