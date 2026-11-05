//! Compile-time check of the `windows-sys` entries in `clippy.toml` (review L4).
//!
//! `allow-invalid = true` makes clippy silently ignore a ban whose path does not resolve, so a
//! typo would leave an API unbanned. Every banned `windows-sys` item is referenced here once,
//! never called, each under its own `#[expect(clippy::disallowed_methods)]`: a dead entry turns
//! into an unfulfilled expectation, which `clippy -D warnings` rejects.
//! [`every_banned_item_is_listed_here`] keeps this list and `clippy.toml` in sync. The
//! `std::env` bans (ADR 0009) and the `std::thread` ban (ADR 0010) are checked the same way
//! ([`banned_std_env_items_resolve`], [`banned_std_thread_items_resolve`],
//! [`every_banned_std_env_item_is_listed_here`], [`every_banned_std_thread_item_is_listed_here`]).

#[test]
fn banned_windows_sys_items_resolve() {
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: NtSetInformationThread must be banned"
    )]
    let _ = windows_sys::Wdk::System::Threading::NtSetInformationThread;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: ZwSetInformationThread must be banned"
    )]
    let _ = windows_sys::Wdk::System::Threading::ZwSetInformationThread;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: UpdateProcThreadAttribute must be banned"
    )]
    let _ = windows_sys::Win32::System::Threading::UpdateProcThreadAttribute;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: SetProcessAffinityUpdateMode must be banned"
    )]
    let _ = windows_sys::Win32::System::Threading::SetProcessAffinityUpdateMode;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: ReleaseExclusiveCpuSets must be banned"
    )]
    let _ = windows_sys::Win32::Gaming::ReleaseExclusiveCpuSets;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: GetProcessAffinityMask must be banned"
    )]
    let _ = windows_sys::Win32::System::Threading::GetProcessAffinityMask;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: GetProcessGroupAffinity must be banned"
    )]
    let _ = windows_sys::Win32::System::Threading::GetProcessGroupAffinity;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: GetThreadGroupAffinity must be banned"
    )]
    let _ = windows_sys::Win32::System::Threading::GetThreadGroupAffinity;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: GetProcessDefaultCpuSets must be banned"
    )]
    let _ = windows_sys::Win32::System::Threading::GetProcessDefaultCpuSets;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: GetProcessDefaultCpuSetMasks must be banned"
    )]
    let _ = windows_sys::Win32::System::Threading::GetProcessDefaultCpuSetMasks;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: GetThreadSelectedCpuSets must be banned"
    )]
    let _ = windows_sys::Win32::System::Threading::GetThreadSelectedCpuSets;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: GetThreadSelectedCpuSetMasks must be banned"
    )]
    let _ = windows_sys::Win32::System::Threading::GetThreadSelectedCpuSetMasks;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: GetNumaNodeProcessorMask must be banned"
    )]
    let _ = windows_sys::Win32::System::Threading::GetNumaNodeProcessorMask;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: GetNumaNodeProcessorMaskEx must be banned"
    )]
    let _ = windows_sys::Win32::System::Threading::GetNumaNodeProcessorMaskEx;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: GetNumaProcessorNode must be banned"
    )]
    let _ = windows_sys::Win32::System::Threading::GetNumaProcessorNode;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: GetNumaProcessorNodeEx must be banned"
    )]
    let _ = windows_sys::Win32::System::Threading::GetNumaProcessorNodeEx;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: CreateProcessAsUserA must be banned"
    )]
    let _ = windows_sys::Win32::System::Threading::CreateProcessAsUserA;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: CreateProcessWithLogonW must be banned"
    )]
    let _ = windows_sys::Win32::System::Threading::CreateProcessWithLogonW;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: CreateProcessWithTokenW must be banned"
    )]
    let _ = windows_sys::Win32::System::Threading::CreateProcessWithTokenW;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: ShellExecuteA must be banned"
    )]
    let _ = windows_sys::Win32::UI::Shell::ShellExecuteA;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: ShellExecuteW must be banned"
    )]
    let _ = windows_sys::Win32::UI::Shell::ShellExecuteW;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: ShellExecuteExA must be banned"
    )]
    let _ = windows_sys::Win32::UI::Shell::ShellExecuteExA;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: ShellExecuteExW must be banned"
    )]
    let _ = windows_sys::Win32::UI::Shell::ShellExecuteExW;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: GetSystemCpuSetInformation must be banned"
    )]
    let _ = windows_sys::Win32::System::SystemInformation::GetSystemCpuSetInformation;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: GetLogicalProcessorInformationEx must be banned"
    )]
    let _ = windows_sys::Win32::System::SystemInformation::GetLogicalProcessorInformationEx;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: GetLogicalProcessorInformation must be banned"
    )]
    let _ = windows_sys::Win32::System::SystemInformation::GetLogicalProcessorInformation;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: GetSystemInfo must be banned"
    )]
    let _ = windows_sys::Win32::System::SystemInformation::GetSystemInfo;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: GetNativeSystemInfo must be banned"
    )]
    let _ = windows_sys::Win32::System::SystemInformation::GetNativeSystemInfo;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: GetActiveProcessorCount must be banned"
    )]
    let _ = windows_sys::Win32::System::Threading::GetActiveProcessorCount;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: GetMaximumProcessorCount must be banned"
    )]
    let _ = windows_sys::Win32::System::Threading::GetMaximumProcessorCount;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: GetActiveProcessorGroupCount must be banned"
    )]
    let _ = windows_sys::Win32::System::Threading::GetActiveProcessorGroupCount;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: GetMaximumProcessorGroupCount must be banned"
    )]
    let _ = windows_sys::Win32::System::Threading::GetMaximumProcessorGroupCount;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: NtQuerySystemInformation must be banned"
    )]
    let _ = windows_sys::Wdk::System::SystemInformation::NtQuerySystemInformation;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: ZwQuerySystemInformation must be banned"
    )]
    let _ = windows_sys::Wdk::System::SystemInformation::ZwQuerySystemInformation;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: SetProcessAffinityMask must be banned"
    )]
    let _ = windows_sys::Win32::System::Threading::SetProcessAffinityMask;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: SetThreadAffinityMask must be banned"
    )]
    let _ = windows_sys::Win32::System::Threading::SetThreadAffinityMask;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: SetThreadGroupAffinity must be banned"
    )]
    let _ = windows_sys::Win32::System::Threading::SetThreadGroupAffinity;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: SetProcessDefaultCpuSets must be banned"
    )]
    let _ = windows_sys::Win32::System::Threading::SetProcessDefaultCpuSets;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: SetProcessDefaultCpuSetMasks must be banned"
    )]
    let _ = windows_sys::Win32::System::Threading::SetProcessDefaultCpuSetMasks;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: SetThreadSelectedCpuSets must be banned"
    )]
    let _ = windows_sys::Win32::System::Threading::SetThreadSelectedCpuSets;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: SetThreadSelectedCpuSetMasks must be banned"
    )]
    let _ = windows_sys::Win32::System::Threading::SetThreadSelectedCpuSetMasks;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: SetThreadIdealProcessor must be banned"
    )]
    let _ = windows_sys::Win32::System::Threading::SetThreadIdealProcessor;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: SetThreadIdealProcessorEx must be banned"
    )]
    let _ = windows_sys::Win32::System::Threading::SetThreadIdealProcessorEx;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: SetInformationJobObject must be banned"
    )]
    let _ = windows_sys::Win32::System::JobObjects::SetInformationJobObject;
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

/// The registry bans (ADR 0009) the same way.
#[test]
fn banned_registry_items_resolve() {
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: RegOpenCurrentUser must be banned"
    )]
    let _ = windows_sys::Win32::System::Registry::RegOpenCurrentUser;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: RegOpenKeyExW must be banned"
    )]
    let _ = windows_sys::Win32::System::Registry::RegOpenKeyExW;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: RegEnumKeyExW must be banned"
    )]
    let _ = windows_sys::Win32::System::Registry::RegEnumKeyExW;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: RegQueryInfoKeyW must be banned"
    )]
    let _ = windows_sys::Win32::System::Registry::RegQueryInfoKeyW;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: NtQueryValueKey must be banned"
    )]
    let _ = windows_sys::Wdk::System::Registry::NtQueryValueKey;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: NtEnumerateValueKey must be banned"
    )]
    let _ = windows_sys::Wdk::System::Registry::NtEnumerateValueKey;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: ZwQueryValueKey must be banned"
    )]
    let _ = windows_sys::Wdk::System::Registry::ZwQueryValueKey;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: ZwEnumerateValueKey must be banned"
    )]
    let _ = windows_sys::Wdk::System::Registry::ZwEnumerateValueKey;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: RegQueryValueExW must be banned"
    )]
    let _ = windows_sys::Win32::System::Registry::RegQueryValueExW;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: RegEnumValueW must be banned"
    )]
    let _ = windows_sys::Win32::System::Registry::RegEnumValueW;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: RegGetValueW must be banned"
    )]
    let _ = windows_sys::Win32::System::Registry::RegGetValueW;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: RegQueryMultipleValuesW must be banned"
    )]
    let _ = windows_sys::Win32::System::Registry::RegQueryMultipleValuesW;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: RegGetValueA must be banned"
    )]
    let _ = windows_sys::Win32::System::Registry::RegGetValueA;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: RegOpenKeyW must be banned"
    )]
    let _ = windows_sys::Win32::System::Registry::RegOpenKeyW;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: RegOpenKeyA must be banned"
    )]
    let _ = windows_sys::Win32::System::Registry::RegOpenKeyA;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: RegOpenKeyExA must be banned"
    )]
    let _ = windows_sys::Win32::System::Registry::RegOpenKeyExA;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: RegQueryValueW must be banned"
    )]
    let _ = windows_sys::Win32::System::Registry::RegQueryValueW;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: RegQueryValueA must be banned"
    )]
    let _ = windows_sys::Win32::System::Registry::RegQueryValueA;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: RegQueryValueExA must be banned"
    )]
    let _ = windows_sys::Win32::System::Registry::RegQueryValueExA;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: RegEnumKeyW must be banned"
    )]
    let _ = windows_sys::Win32::System::Registry::RegEnumKeyW;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: RegEnumKeyA must be banned"
    )]
    let _ = windows_sys::Win32::System::Registry::RegEnumKeyA;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: RegEnumKeyExA must be banned"
    )]
    let _ = windows_sys::Win32::System::Registry::RegEnumKeyExA;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: RegEnumValueA must be banned"
    )]
    let _ = windows_sys::Win32::System::Registry::RegEnumValueA;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: RegQueryInfoKeyA must be banned"
    )]
    let _ = windows_sys::Win32::System::Registry::RegQueryInfoKeyA;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: RegQueryMultipleValuesA must be banned"
    )]
    let _ = windows_sys::Win32::System::Registry::RegQueryMultipleValuesA;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: RegLoadMUIStringW must be banned"
    )]
    let _ = windows_sys::Win32::System::Registry::RegLoadMUIStringW;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: RegLoadMUIStringA must be banned"
    )]
    let _ = windows_sys::Win32::System::Registry::RegLoadMUIStringA;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: RegCreateKeyW must be banned"
    )]
    let _ = windows_sys::Win32::System::Registry::RegCreateKeyW;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: RegCreateKeyA must be banned"
    )]
    let _ = windows_sys::Win32::System::Registry::RegCreateKeyA;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: RegCreateKeyExW must be banned"
    )]
    let _ = windows_sys::Win32::System::Registry::RegCreateKeyExW;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: RegCreateKeyExA must be banned"
    )]
    let _ = windows_sys::Win32::System::Registry::RegCreateKeyExA;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: RegSetValueW must be banned"
    )]
    let _ = windows_sys::Win32::System::Registry::RegSetValueW;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: RegSetValueA must be banned"
    )]
    let _ = windows_sys::Win32::System::Registry::RegSetValueA;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: RegSetValueExW must be banned"
    )]
    let _ = windows_sys::Win32::System::Registry::RegSetValueExW;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: RegSetValueExA must be banned"
    )]
    let _ = windows_sys::Win32::System::Registry::RegSetValueExA;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: RegSetKeyValueW must be banned"
    )]
    let _ = windows_sys::Win32::System::Registry::RegSetKeyValueW;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: RegSetKeyValueA must be banned"
    )]
    let _ = windows_sys::Win32::System::Registry::RegSetKeyValueA;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: RegDeleteKeyW must be banned"
    )]
    let _ = windows_sys::Win32::System::Registry::RegDeleteKeyW;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: RegDeleteKeyA must be banned"
    )]
    let _ = windows_sys::Win32::System::Registry::RegDeleteKeyA;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: RegDeleteKeyExW must be banned"
    )]
    let _ = windows_sys::Win32::System::Registry::RegDeleteKeyExW;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: RegDeleteKeyExA must be banned"
    )]
    let _ = windows_sys::Win32::System::Registry::RegDeleteKeyExA;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: RegDeleteValueW must be banned"
    )]
    let _ = windows_sys::Win32::System::Registry::RegDeleteValueW;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: RegDeleteValueA must be banned"
    )]
    let _ = windows_sys::Win32::System::Registry::RegDeleteValueA;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: RegDeleteKeyValueW must be banned"
    )]
    let _ = windows_sys::Win32::System::Registry::RegDeleteKeyValueW;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: RegDeleteKeyValueA must be banned"
    )]
    let _ = windows_sys::Win32::System::Registry::RegDeleteKeyValueA;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: RegDeleteTreeW must be banned"
    )]
    let _ = windows_sys::Win32::System::Registry::RegDeleteTreeW;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: RegDeleteTreeA must be banned"
    )]
    let _ = windows_sys::Win32::System::Registry::RegDeleteTreeA;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: RegCopyTreeW must be banned"
    )]
    let _ = windows_sys::Win32::System::Registry::RegCopyTreeW;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: RegCopyTreeA must be banned"
    )]
    let _ = windows_sys::Win32::System::Registry::RegCopyTreeA;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: RegRenameKey must be banned"
    )]
    let _ = windows_sys::Win32::System::Registry::RegRenameKey;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: RegSetKeySecurity must be banned"
    )]
    let _ = windows_sys::Win32::System::Registry::RegSetKeySecurity;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: NtCreateKey must be banned"
    )]
    let _ = windows_sys::Wdk::System::Registry::NtCreateKey;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: ZwCreateKey must be banned"
    )]
    let _ = windows_sys::Wdk::System::Registry::ZwCreateKey;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: NtSetValueKey must be banned"
    )]
    let _ = windows_sys::Wdk::System::Registry::NtSetValueKey;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: ZwSetValueKey must be banned"
    )]
    let _ = windows_sys::Wdk::System::Registry::ZwSetValueKey;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: NtDeleteKey must be banned"
    )]
    let _ = windows_sys::Wdk::System::Registry::NtDeleteKey;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: ZwDeleteKey must be banned"
    )]
    let _ = windows_sys::Wdk::System::Registry::ZwDeleteKey;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: NtDeleteValueKey must be banned"
    )]
    let _ = windows_sys::Wdk::System::Registry::NtDeleteValueKey;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: ZwDeleteValueKey must be banned"
    )]
    let _ = windows_sys::Wdk::System::Registry::ZwDeleteValueKey;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: NtRenameKey must be banned"
    )]
    let _ = windows_sys::Wdk::System::Registry::NtRenameKey;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: ZwRenameKey must be banned"
    )]
    let _ = windows_sys::Wdk::System::Registry::ZwRenameKey;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: NtSetInformationKey must be banned"
    )]
    let _ = windows_sys::Wdk::System::Registry::NtSetInformationKey;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: ZwSetInformationKey must be banned"
    )]
    let _ = windows_sys::Wdk::System::Registry::ZwSetInformationKey;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: RegOverridePredefKey must be banned"
    )]
    let _ = windows_sys::Win32::System::Registry::RegOverridePredefKey;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: RegDisablePredefinedCache must be banned"
    )]
    let _ = windows_sys::Win32::System::Registry::RegDisablePredefinedCache;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: RegDisablePredefinedCacheEx must be banned"
    )]
    let _ = windows_sys::Win32::System::Registry::RegDisablePredefinedCacheEx;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: RegConnectRegistryW must be banned"
    )]
    let _ = windows_sys::Win32::System::Registry::RegConnectRegistryW;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: RegConnectRegistryA must be banned"
    )]
    let _ = windows_sys::Win32::System::Registry::RegConnectRegistryA;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: RegConnectRegistryExW must be banned"
    )]
    let _ = windows_sys::Win32::System::Registry::RegConnectRegistryExW;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: RegConnectRegistryExA must be banned"
    )]
    let _ = windows_sys::Win32::System::Registry::RegConnectRegistryExA;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: RegLoadKeyW must be banned"
    )]
    let _ = windows_sys::Win32::System::Registry::RegLoadKeyW;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: RegLoadKeyA must be banned"
    )]
    let _ = windows_sys::Win32::System::Registry::RegLoadKeyA;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: RegUnLoadKeyW must be banned"
    )]
    let _ = windows_sys::Win32::System::Registry::RegUnLoadKeyW;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: RegUnLoadKeyA must be banned"
    )]
    let _ = windows_sys::Win32::System::Registry::RegUnLoadKeyA;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: RegLoadAppKeyW must be banned"
    )]
    let _ = windows_sys::Win32::System::Registry::RegLoadAppKeyW;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: RegLoadAppKeyA must be banned"
    )]
    let _ = windows_sys::Win32::System::Registry::RegLoadAppKeyA;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: RegSaveKeyW must be banned"
    )]
    let _ = windows_sys::Win32::System::Registry::RegSaveKeyW;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: RegSaveKeyA must be banned"
    )]
    let _ = windows_sys::Win32::System::Registry::RegSaveKeyA;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: RegSaveKeyExW must be banned"
    )]
    let _ = windows_sys::Win32::System::Registry::RegSaveKeyExW;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: RegSaveKeyExA must be banned"
    )]
    let _ = windows_sys::Win32::System::Registry::RegSaveKeyExA;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: RegRestoreKeyW must be banned"
    )]
    let _ = windows_sys::Win32::System::Registry::RegRestoreKeyW;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: RegRestoreKeyA must be banned"
    )]
    let _ = windows_sys::Win32::System::Registry::RegRestoreKeyA;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: RegReplaceKeyW must be banned"
    )]
    let _ = windows_sys::Win32::System::Registry::RegReplaceKeyW;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: RegReplaceKeyA must be banned"
    )]
    let _ = windows_sys::Win32::System::Registry::RegReplaceKeyA;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: RegDisableReflectionKey must be banned"
    )]
    let _ = windows_sys::Win32::System::Registry::RegDisableReflectionKey;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: RegEnableReflectionKey must be banned"
    )]
    let _ = windows_sys::Win32::System::Registry::RegEnableReflectionKey;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: RegCreateKeyTransactedW must be banned"
    )]
    let _ = windows_sys::Win32::System::Registry::RegCreateKeyTransactedW;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: RegCreateKeyTransactedA must be banned"
    )]
    let _ = windows_sys::Win32::System::Registry::RegCreateKeyTransactedA;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: RegOpenKeyTransactedW must be banned"
    )]
    let _ = windows_sys::Win32::System::Registry::RegOpenKeyTransactedW;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: RegOpenKeyTransactedA must be banned"
    )]
    let _ = windows_sys::Win32::System::Registry::RegOpenKeyTransactedA;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: RegDeleteKeyTransactedW must be banned"
    )]
    let _ = windows_sys::Win32::System::Registry::RegDeleteKeyTransactedW;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: RegDeleteKeyTransactedA must be banned"
    )]
    let _ = windows_sys::Win32::System::Registry::RegDeleteKeyTransactedA;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: NtCreateKeyTransacted must be banned"
    )]
    let _ = windows_sys::Wdk::System::Registry::NtCreateKeyTransacted;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: ZwCreateKeyTransacted must be banned"
    )]
    let _ = windows_sys::Wdk::System::Registry::ZwCreateKeyTransacted;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: NtOpenKeyTransacted must be banned"
    )]
    let _ = windows_sys::Wdk::System::Registry::NtOpenKeyTransacted;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: ZwOpenKeyTransacted must be banned"
    )]
    let _ = windows_sys::Wdk::System::Registry::ZwOpenKeyTransacted;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: NtOpenKeyTransactedEx must be banned"
    )]
    let _ = windows_sys::Wdk::System::Registry::NtOpenKeyTransactedEx;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: ZwOpenKeyTransactedEx must be banned"
    )]
    let _ = windows_sys::Wdk::System::Registry::ZwOpenKeyTransactedEx;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: NtCreateRegistryTransaction must be banned"
    )]
    let _ = windows_sys::Wdk::System::Registry::NtCreateRegistryTransaction;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: ZwCreateRegistryTransaction must be banned"
    )]
    let _ = windows_sys::Wdk::System::Registry::ZwCreateRegistryTransaction;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: NtCommitRegistryTransaction must be banned"
    )]
    let _ = windows_sys::Wdk::System::Registry::NtCommitRegistryTransaction;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: ZwCommitRegistryTransaction must be banned"
    )]
    let _ = windows_sys::Wdk::System::Registry::ZwCommitRegistryTransaction;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: NtRollbackRegistryTransaction must be banned"
    )]
    let _ = windows_sys::Wdk::System::Registry::NtRollbackRegistryTransaction;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: ZwRollbackRegistryTransaction must be banned"
    )]
    let _ = windows_sys::Wdk::System::Registry::ZwRollbackRegistryTransaction;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: NtOpenRegistryTransaction must be banned"
    )]
    let _ = windows_sys::Wdk::System::Registry::NtOpenRegistryTransaction;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: ZwOpenRegistryTransaction must be banned"
    )]
    let _ = windows_sys::Wdk::System::Registry::ZwOpenRegistryTransaction;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: NtRestoreKey must be banned"
    )]
    let _ = windows_sys::Wdk::System::Registry::NtRestoreKey;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: ZwRestoreKey must be banned"
    )]
    let _ = windows_sys::Wdk::System::Registry::ZwRestoreKey;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: NtSaveKey must be banned"
    )]
    let _ = windows_sys::Wdk::System::Registry::NtSaveKey;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: ZwSaveKey must be banned"
    )]
    let _ = windows_sys::Wdk::System::Registry::ZwSaveKey;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: NtSaveKeyEx must be banned"
    )]
    let _ = windows_sys::Wdk::System::Registry::NtSaveKeyEx;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: ZwSaveKeyEx must be banned"
    )]
    let _ = windows_sys::Wdk::System::Registry::ZwSaveKeyEx;
}

/// The DLL loading and search path bans (ADR 0008 amendment, 2026-11-05).
#[test]
fn banned_loader_items_resolve() {
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: LoadLibraryA must be banned"
    )]
    let _ = windows_sys::Win32::System::LibraryLoader::LoadLibraryA;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: LoadLibraryW must be banned"
    )]
    let _ = windows_sys::Win32::System::LibraryLoader::LoadLibraryW;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: LoadLibraryExA must be banned"
    )]
    let _ = windows_sys::Win32::System::LibraryLoader::LoadLibraryExA;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: LoadLibraryExW must be banned"
    )]
    let _ = windows_sys::Win32::System::LibraryLoader::LoadLibraryExW;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: LoadPackagedLibrary must be banned"
    )]
    let _ = windows_sys::Win32::System::LibraryLoader::LoadPackagedLibrary;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: GetProcAddress must be banned"
    )]
    let _ = windows_sys::Win32::System::LibraryLoader::GetProcAddress;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: SetDefaultDllDirectories must be banned"
    )]
    let _ = windows_sys::Win32::System::LibraryLoader::SetDefaultDllDirectories;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: SetDllDirectoryW must be banned"
    )]
    let _ = windows_sys::Win32::System::LibraryLoader::SetDllDirectoryW;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: SetDllDirectoryA must be banned"
    )]
    let _ = windows_sys::Win32::System::LibraryLoader::SetDllDirectoryA;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: AddDllDirectory must be banned"
    )]
    let _ = windows_sys::Win32::System::LibraryLoader::AddDllDirectory;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: RemoveDllDirectory must be banned"
    )]
    let _ = windows_sys::Win32::System::LibraryLoader::RemoveDllDirectory;
}

/// The GPU and COM activation bans (ADR 0008 amendment, 2026-11-05).
#[test]
fn banned_gpu_and_com_items_resolve() {
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: D3DKMTEnumAdapters must be banned"
    )]
    let _ = windows_sys::Wdk::Graphics::Direct3D::D3DKMTEnumAdapters;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: D3DKMTEnumAdapters2 must be banned"
    )]
    let _ = windows_sys::Wdk::Graphics::Direct3D::D3DKMTEnumAdapters2;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: D3DKMTEnumAdapters3 must be banned"
    )]
    let _ = windows_sys::Wdk::Graphics::Direct3D::D3DKMTEnumAdapters3;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: D3DKMTQueryAdapterInfo must be banned"
    )]
    let _ = windows_sys::Wdk::Graphics::Direct3D::D3DKMTQueryAdapterInfo;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: D3DKMTOpenAdapterFromLuid must be banned"
    )]
    let _ = windows_sys::Wdk::Graphics::Direct3D::D3DKMTOpenAdapterFromLuid;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: CoCreateInstance must be banned"
    )]
    let _ = windows_sys::Win32::System::Com::CoCreateInstance;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: CoCreateInstanceEx must be banned"
    )]
    let _ = windows_sys::Win32::System::Com::CoCreateInstanceEx;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: CoGetClassObject must be banned"
    )]
    let _ = windows_sys::Win32::System::Com::CoGetClassObject;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: CoInitialize must be banned"
    )]
    let _ = windows_sys::Win32::System::Com::CoInitialize;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: CoInitializeEx must be banned"
    )]
    let _ = windows_sys::Win32::System::Com::CoInitializeEx;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: CoGetObject must be banned"
    )]
    let _ = windows_sys::Win32::System::Com::CoGetObject;
}

/// The bans of the step 10 security review (2026-11-05).
#[test]
fn banned_step10_review_items_resolve() {
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: LoadModule must be banned"
    )]
    let _ = windows_sys::Win32::System::LibraryLoader::LoadModule;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: QueryOptionalDelayLoadedAPI must be banned"
    )]
    let _ = windows_sys::Win32::System::LibraryLoader::QueryOptionalDelayLoadedAPI;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: LoadLibraryShim must be banned"
    )]
    let _ = windows_sys::Win32::System::ClrHosting::LoadLibraryShim;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: CoCreateInstanceFromApp must be banned"
    )]
    let _ = windows_sys::Win32::System::Com::CoCreateInstanceFromApp;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: BindMoniker must be banned"
    )]
    let _ = windows_sys::Win32::System::Com::BindMoniker;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: CoRegisterClassObject must be banned"
    )]
    let _ = windows_sys::Win32::System::Com::CoRegisterClassObject;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: CoInitializeSecurity must be banned"
    )]
    let _ = windows_sys::Win32::System::Com::CoInitializeSecurity;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: CoGetInstanceFromFile must be banned"
    )]
    let _ = windows_sys::Win32::System::Com::StructuredStorage::CoGetInstanceFromFile;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: CoGetClassObjectFromURL must be banned"
    )]
    let _ = windows_sys::Win32::System::Com::Urlmon::CoGetClassObjectFromURL;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: OleInitialize must be banned"
    )]
    let _ = windows_sys::Win32::System::Ole::OleInitialize;
}

/// The version API bans of ADR 0015: the OS build comes from the registry only (`hw::os`).
#[test]
fn banned_version_items_resolve() {
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: GetVersion must be banned"
    )]
    let _ = windows_sys::Win32::System::SystemInformation::GetVersion;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: GetVersionExA must be banned"
    )]
    let _ = windows_sys::Win32::System::SystemInformation::GetVersionExA;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: GetVersionExW must be banned"
    )]
    let _ = windows_sys::Win32::System::SystemInformation::GetVersionExW;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: VerifyVersionInfoA must be banned"
    )]
    let _ = windows_sys::Win32::System::SystemInformation::VerifyVersionInfoA;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: VerifyVersionInfoW must be banned"
    )]
    let _ = windows_sys::Win32::System::SystemInformation::VerifyVersionInfoW;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: VerSetConditionMask must be banned"
    )]
    let _ = windows_sys::Win32::System::SystemInformation::VerSetConditionMask;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: RtlGetVersion must be banned"
    )]
    let _ = windows_sys::Wdk::System::SystemServices::RtlGetVersion;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: RtlVerifyVersionInfo must be banned"
    )]
    let _ = windows_sys::Wdk::System::SystemServices::RtlVerifyVersionInfo;
}

/// The bans of the step 8 security review the same way.
#[test]
fn banned_review_items_resolve() {
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: SHSetValueW must be banned"
    )]
    let _ = windows_sys::Win32::UI::Shell::SHSetValueW;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: SHSetValueA must be banned"
    )]
    let _ = windows_sys::Win32::UI::Shell::SHSetValueA;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: SHDeleteKeyW must be banned"
    )]
    let _ = windows_sys::Win32::UI::Shell::SHDeleteKeyW;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: SHDeleteKeyA must be banned"
    )]
    let _ = windows_sys::Win32::UI::Shell::SHDeleteKeyA;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: SHDeleteValueW must be banned"
    )]
    let _ = windows_sys::Win32::UI::Shell::SHDeleteValueW;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: SHDeleteValueA must be banned"
    )]
    let _ = windows_sys::Win32::UI::Shell::SHDeleteValueA;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: SHDeleteEmptyKeyW must be banned"
    )]
    let _ = windows_sys::Win32::UI::Shell::SHDeleteEmptyKeyW;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: SHDeleteEmptyKeyA must be banned"
    )]
    let _ = windows_sys::Win32::UI::Shell::SHDeleteEmptyKeyA;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: SHCopyKeyW must be banned"
    )]
    let _ = windows_sys::Win32::UI::Shell::SHCopyKeyW;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: SHCopyKeyA must be banned"
    )]
    let _ = windows_sys::Win32::UI::Shell::SHCopyKeyA;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: SHRegSetUSValueW must be banned"
    )]
    let _ = windows_sys::Win32::UI::Shell::SHRegSetUSValueW;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: SHRegSetUSValueA must be banned"
    )]
    let _ = windows_sys::Win32::UI::Shell::SHRegSetUSValueA;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: SHRegWriteUSValueW must be banned"
    )]
    let _ = windows_sys::Win32::UI::Shell::SHRegWriteUSValueW;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: SHRegWriteUSValueA must be banned"
    )]
    let _ = windows_sys::Win32::UI::Shell::SHRegWriteUSValueA;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: SHRegCreateUSKeyW must be banned"
    )]
    let _ = windows_sys::Win32::UI::Shell::SHRegCreateUSKeyW;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: SHRegCreateUSKeyA must be banned"
    )]
    let _ = windows_sys::Win32::UI::Shell::SHRegCreateUSKeyA;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: SHRegDeleteUSValueW must be banned"
    )]
    let _ = windows_sys::Win32::UI::Shell::SHRegDeleteUSValueW;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: SHRegDeleteUSValueA must be banned"
    )]
    let _ = windows_sys::Win32::UI::Shell::SHRegDeleteUSValueA;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: SHRegDeleteEmptyUSKeyW must be banned"
    )]
    let _ = windows_sys::Win32::UI::Shell::SHRegDeleteEmptyUSKeyW;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: SHRegDeleteEmptyUSKeyA must be banned"
    )]
    let _ = windows_sys::Win32::UI::Shell::SHRegDeleteEmptyUSKeyA;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: SHRegSetPathW must be banned"
    )]
    let _ = windows_sys::Win32::UI::Shell::SHRegSetPathW;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: SHRegSetPathA must be banned"
    )]
    let _ = windows_sys::Win32::UI::Shell::SHRegSetPathA;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: SHOpenRegStreamW must be banned"
    )]
    let _ = windows_sys::Win32::UI::Shell::SHOpenRegStreamW;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: SHOpenRegStreamA must be banned"
    )]
    let _ = windows_sys::Win32::UI::Shell::SHOpenRegStreamA;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: SHOpenRegStream2W must be banned"
    )]
    let _ = windows_sys::Win32::UI::Shell::SHOpenRegStream2W;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: SHOpenRegStream2A must be banned"
    )]
    let _ = windows_sys::Win32::UI::Shell::SHOpenRegStream2A;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: SHGetValueW must be banned"
    )]
    let _ = windows_sys::Win32::UI::Shell::SHGetValueW;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: SHGetValueA must be banned"
    )]
    let _ = windows_sys::Win32::UI::Shell::SHGetValueA;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: SHQueryValueExW must be banned"
    )]
    let _ = windows_sys::Win32::UI::Shell::SHQueryValueExW;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: SHQueryValueExA must be banned"
    )]
    let _ = windows_sys::Win32::UI::Shell::SHQueryValueExA;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: SHRegGetValueW must be banned"
    )]
    let _ = windows_sys::Win32::UI::Shell::SHRegGetValueW;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: SHRegGetValueA must be banned"
    )]
    let _ = windows_sys::Win32::UI::Shell::SHRegGetValueA;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: SHRegGetPathW must be banned"
    )]
    let _ = windows_sys::Win32::UI::Shell::SHRegGetPathW;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: SHRegGetPathA must be banned"
    )]
    let _ = windows_sys::Win32::UI::Shell::SHRegGetPathA;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: SHRegQueryUSValueW must be banned"
    )]
    let _ = windows_sys::Win32::UI::Shell::SHRegQueryUSValueW;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: SHRegQueryUSValueA must be banned"
    )]
    let _ = windows_sys::Win32::UI::Shell::SHRegQueryUSValueA;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: SHEnumValueW must be banned"
    )]
    let _ = windows_sys::Win32::UI::Shell::SHEnumValueW;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: SHEnumValueA must be banned"
    )]
    let _ = windows_sys::Win32::UI::Shell::SHEnumValueA;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: SHRegGetValueFromHKCUHKLM must be banned"
    )]
    let _ = windows_sys::Win32::UI::Shell::SHRegGetValueFromHKCUHKLM;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: NtOpenKey must be banned"
    )]
    let _ = windows_sys::Wdk::System::Registry::NtOpenKey;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: NtOpenKeyEx must be banned"
    )]
    let _ = windows_sys::Wdk::System::Registry::NtOpenKeyEx;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: ZwOpenKey must be banned"
    )]
    let _ = windows_sys::Wdk::System::Registry::ZwOpenKey;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: ZwOpenKeyEx must be banned"
    )]
    let _ = windows_sys::Wdk::System::Registry::ZwOpenKeyEx;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: NtEnumerateKey must be banned"
    )]
    let _ = windows_sys::Wdk::System::Registry::NtEnumerateKey;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: NtQueryMultipleValueKey must be banned"
    )]
    let _ = windows_sys::Wdk::System::Registry::NtQueryMultipleValueKey;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: NtQueryKey must be banned"
    )]
    let _ = windows_sys::Wdk::System::Registry::NtQueryKey;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: NtFlushKey must be banned"
    )]
    let _ = windows_sys::Wdk::System::Registry::NtFlushKey;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: NtNotifyChangeKey must be banned"
    )]
    let _ = windows_sys::Wdk::Storage::FileSystem::NtNotifyChangeKey;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: RegOpenUserClassesRoot must be banned"
    )]
    let _ = windows_sys::Win32::System::Registry::RegOpenUserClassesRoot;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: SetSecurityInfo must be banned"
    )]
    let _ = windows_sys::Win32::Security::Authorization::SetSecurityInfo;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: SetKernelObjectSecurity must be banned"
    )]
    let _ = windows_sys::Win32::Security::SetKernelObjectSecurity;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: NtSetSecurityObject must be banned"
    )]
    let _ = windows_sys::Wdk::Storage::FileSystem::NtSetSecurityObject;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: GetTempPathW must be banned"
    )]
    let _ = windows_sys::Win32::Storage::FileSystem::GetTempPathW;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: GetTempPathA must be banned"
    )]
    let _ = windows_sys::Win32::Storage::FileSystem::GetTempPathA;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: GetTempPath2W must be banned"
    )]
    let _ = windows_sys::Win32::Storage::FileSystem::GetTempPath2W;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: GetTempPath2A must be banned"
    )]
    let _ = windows_sys::Win32::Storage::FileSystem::GetTempPath2A;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: SHGetKnownFolderIDList must be banned"
    )]
    let _ = windows_sys::Win32::UI::Shell::SHGetKnownFolderIDList;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: SHGetKnownFolderItem must be banned"
    )]
    let _ = windows_sys::Win32::UI::Shell::SHGetKnownFolderItem;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: SHGetFolderLocation must be banned"
    )]
    let _ = windows_sys::Win32::UI::Shell::SHGetFolderLocation;
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: SHGetSpecialFolderLocation must be banned"
    )]
    let _ = windows_sys::Win32::UI::Shell::SHGetSpecialFolderLocation;
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

/// The `std::thread` ban (ADR 0010) resolves.
#[test]
fn banned_std_thread_items_resolve() {
    #[expect(
        clippy::disallowed_methods,
        reason = "ban check: available_parallelism must be banned"
    )]
    let _ = std::thread::available_parallelism;
}

/// Every `std::<module>::` path in `clippy.toml` is referenced by a test above; returns the
/// number of such bans.
fn std_bans_listed(module: &str) -> usize {
    let toml = include_str!("../../../../../clippy.toml");
    let this = include_str!("bans.rs");
    let mut n = 0;
    for line in toml.lines() {
        let Some(rest) = line.split(&format!("path = \"std::{module}::")).nth(1) else {
            continue;
        };
        let path = rest.split('"').next().unwrap_or_default();
        assert!(
            this.contains(&format!("let _ = std::{module}::{path};"))
                || this.contains(&format!("let _ = std::{module}::{path}::<")),
            "clippy.toml bans std::{module}::{path}, but bans.rs does not check it"
        );
        n += 1;
    }
    n
}

/// Every `std::env::` path in `clippy.toml` is referenced by the test above.
#[test]
fn every_banned_std_env_item_is_listed_here() {
    assert_eq!(std_bans_listed("env"), 7, "std::env bans");
}

/// Every `std::thread::` path in `clippy.toml` is referenced by the test above.
#[test]
fn every_banned_std_thread_item_is_listed_here() {
    assert_eq!(std_bans_listed("thread"), 1, "std::thread bans");
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
