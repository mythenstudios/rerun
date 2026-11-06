//! Test fixtures for the file system contracts against real Windows (`docs/09-testing.md`).
//!
//! - [`TestRoot`]: a fresh directory `target/rerun-fs-contract/<pid>-<nanos>-<case>` with the
//!   safeguards of `09-testing.md` (inside the canonical `target/`, local fixed drive, no
//!   reparse point or cloud attribute on any ancestor, skipped locally when elevated). Drop
//!   undoes what the fixture changed outside the tree (mount points, drive substitutions,
//!   restricted DACLs), re-checks the safeguards and only then removes the tree.
//! - [`WinFixture`]: the [`FsFixture`] for `sys::win`, made of `std::fs` and raw Win32 calls
//!   (junctions via `FSCTL_SET_REPARSE_POINT`, no admin, no `cmd`). Fixtures that change the
//!   machine beyond the test root (mount point, `subst`, 8.3 short names) run only on
//!   GitHub-hosted runners with the explicit opt-in ([`hosted_ci`]) and report "not
//!   available" everywhere else. Every writing method is bound to its [`TestRoot`]: the path
//!   must lie inside the root, without `.`/`..`, below no reparse point and no mount point.
//! - [`NaiveFs`]: a deliberately unsafe check-then-use-by-path `Fs` (check each prefix with
//!   `symlink_metadata`, yield, then act on the full path). The race contract must catch it.
//! - [`AppHive`]: a private registry hive (`RegLoadAppKeyW`) in a file inside a [`TestRoot`],
//!   the [`RegFixture`] of the registry read contract; [`HiveRoot`] bundles it with its root
//!   and a [`WinRegistry`] on it. Raw writes go only to that hive, never to `HKCU` or `HKLM`.
//! - [`module_path`]: where Windows loaded a module from (`GetModuleFileNameW`).
//!
//! Path-based Win32 and `std::fs` calls are the point of this module (they set the scene the
//! handle-based `sys::win` has to survive), hence the module-wide `disallowed_methods`
//! exception. Test code only (`cfg(all(test, windows))`).

#![expect(
    clippy::disallowed_methods,
    reason = "test fixture: sets up and removes the contract tree under target/ by path \
              (std::fs, MoveFileExW, CreateSymbolicLinkW, SetVolumeMountPointW, \
              DefineDosDeviceW), NaiveFs is a path-based control implementation, and the app \
              hive is loaded (RegLoadAppKeyW) and written (RegCreateKeyExW, NtSetValueKey, \
              RegDeleteValueW) only here"
)]
#![allow(
    unsafe_code,
    reason = "test-only FFI (junction buffer, DACLs, mount points, subst, short names, \
              file IDs, app hive); every block has a SAFETY comment"
)]

use std::ffi::OsString;
use std::ffi::c_void;
use std::fs::{File, OpenOptions};
use std::io::Write as _;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::{Component, Path, PathBuf};
use std::sync::{Mutex, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};
use std::{ptr, thread};

use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows_sys::Wdk::Storage::FileSystem::{FILE_OPEN, FILE_OPEN_REPARSE_POINT, NtCreateFile};
use windows_sys::Wdk::System::Registry::NtSetValueKey;
use windows_sys::Win32::Foundation::{
    ERROR_NOT_ALL_ASSIGNED, GENERIC_EXECUTE, GENERIC_READ, GENERIC_WRITE, HANDLE,
    INVALID_HANDLE_VALUE, LUID,
};
use windows_sys::Win32::Foundation::{OBJ_CASE_INSENSITIVE, UNICODE_STRING};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACL, ACL_REVISION, AddAccessAllowedAce, AddAccessDeniedAce,
    AdjustTokenPrivileges, DACL_SECURITY_INFORMATION, GetLengthSid, GetTokenInformation,
    ImpersonateSelf, InitializeAcl, InitializeSecurityDescriptor, LUID_AND_ATTRIBUTES,
    LookupPrivilegeValueW, PROTECTED_DACL_SECURITY_INFORMATION, RevertToSelf, SE_BACKUP_NAME,
    SE_DACL_PROTECTED, SE_PRIVILEGE_ENABLED, SE_RESTORE_NAME, SECURITY_DESCRIPTOR,
    SecurityImpersonation, SetKernelObjectSecurity, SetSecurityDescriptorControl,
    SetSecurityDescriptorDacl, TOKEN_ADJUST_PRIVILEGES, TOKEN_ELEVATION, TOKEN_PRIVILEGES,
    TOKEN_QUERY, TOKEN_USER, TokenElevation, TokenPrivileges, TokenUser,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateSymbolicLinkW, DDD_EXACT_MATCH_ON_REMOVE, DDD_REMOVE_DEFINITION, DELETE,
    DefineDosDeviceW, DeleteVolumeMountPointW, FILE_ALL_ACCESS, FILE_ATTRIBUTE_DIRECTORY,
    FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_OFFLINE, FILE_ATTRIBUTE_PINNED,
    FILE_ATTRIBUTE_READONLY, FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS, FILE_ATTRIBUTE_RECALL_ON_OPEN,
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_SYSTEM, FILE_ATTRIBUTE_UNPINNED, FILE_BASIC_INFO,
    FILE_CASE_SENSITIVE_INFO, FILE_DISPOSITION_INFO, FILE_FLAG_BACKUP_SEMANTICS,
    FILE_FLAG_OPEN_REPARSE_POINT, FILE_ID_INFO, FILE_READ_ATTRIBUTES, FILE_READ_DATA,
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA,
    FileBasicInfo, FileCaseSensitiveInfo, FileDispositionInfo, FileIdInfo, FindFirstVolumeW,
    FindNextVolumeW, FindVolumeClose, GetDriveTypeW, GetFileInformationByHandleEx,
    GetLogicalDrives, GetVolumeInformationW, GetVolumeNameForVolumeMountPointW,
    GetVolumePathNamesForVolumeNameW, MoveFileExW, READ_CONTROL,
    SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE, SYMBOLIC_LINK_FLAG_DIRECTORY, SYNCHRONIZE,
    SetFileInformationByHandle, SetFileShortNameW, SetVolumeMountPointW, WRITE_DAC,
};
use windows_sys::Win32::System::IO::DeviceIoControl;
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;
use windows_sys::Win32::System::Ioctl::{FSCTL_SET_EXTERNAL_BACKING, FSCTL_SET_REPARSE_POINT};
use windows_sys::Win32::System::Memory::{
    CreateFileMappingW, FILE_MAP_READ, FILE_MAP_WRITE, MEMORY_MAPPED_VIEW_ADDRESS, MapViewOfFile,
    PAGE_READONLY, PAGE_READWRITE, SEC_IMAGE, UnmapViewOfFile,
};
use windows_sys::Win32::System::Registry::{
    HKEY, KEY_ALL_ACCESS, KEY_CREATE_LINK, KEY_CREATE_SUB_KEY, KEY_READ, KEY_SET_VALUE, REG_BINARY,
    REG_CREATED_NEW_KEY, REG_LINK, REG_OPTION_CREATE_LINK, REG_OPTION_OPEN_LINK,
    REG_PROCESS_APPKEY, RegCreateKeyExW, RegDeleteValueW, RegLoadAppKeyW, RegOpenKeyExW,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentThread, GetExitCodeProcess, OpenProcess, OpenProcessToken,
    OpenThreadToken, PROCESS_QUERY_LIMITED_INFORMATION,
};

use super::WinRegistry;
use super::reg::{self, OwnedKey};
use super::status::kind_of_win32;
use crate::path::RelPath;
use crate::sys::contract::{Access, FsFixture, Held, RegFixture, Share};
use crate::sys::fs::{
    Attrs, Dir, DirEntry, DirWrite, EntryKind, FileGuard, FileLock, Fs, FsKind, Metadata, NewFile,
    ReadSeek, ReparseInfo, Replaced, RootInfo, WriteCap, Written, tag,
};
use crate::sys::registry::{Hive, RegKey};
use crate::sys::{SysError, SysErrorKind, SysResult};

/// winbase.h `DRIVE_FIXED`.
const DRIVE_FIXED: u32 = 3;
/// winnt.h `SECURITY_DESCRIPTOR_REVISION`.
const SECURITY_DESCRIPTOR_REVISION: u32 = 1;
/// winerror.h `ERROR_PRIVILEGE_NOT_HELD`.
const ERROR_PRIVILEGE_NOT_HELD: u32 = 1314;
/// winioctl.h `WOF_CURRENT_VERSION`, `WOF_PROVIDER_FILE`, `FILE_PROVIDER_CURRENT_VERSION`,
/// `FILE_PROVIDER_COMPRESSION_XPRESS4K`.
const WOF_CURRENT_VERSION: u32 = 1;
const WOF_PROVIDER_FILE: u32 = 2;
const FILE_PROVIDER_CURRENT_VERSION: u32 = 1;
const FILE_PROVIDER_COMPRESSION_XPRESS4K: u32 = 0;
/// Attributes that disqualify an ancestor of the test root: a reparse point (junction,
/// symlink, mount point) or a cloud placeholder.
const UNSAFE_ANCESTOR_ATTRS: u32 = FILE_ATTRIBUTE_REPARSE_POINT
    | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS
    | FILE_ATTRIBUTE_RECALL_ON_OPEN
    | FILE_ATTRIBUTE_OFFLINE
    | FILE_ATTRIBUTE_PINNED
    | FILE_ATTRIBUTE_UNPINNED;

/// winbase.h `STILL_ACTIVE` (exit code of a running process).
const STILL_ACTIVE: u32 = 259;

/// A GitHub-hosted runner (ephemeral VM, admin) **and** the explicit opt-in of the workflow:
/// `GITHUB_ACTIONS=true`, `RUNNER_ENVIRONMENT=github-hosted` and
/// `RERUN_FS_MACHINE_FIXTURES=1` (set in `.github/workflows/ci.yml` for the test step only).
/// Gates the machine-wide fixtures, the elevated run and the strict skip policy. A
/// self-hosted runner or a developer shell that merely sets `GITHUB_ACTIONS` gets none of it.
pub(super) fn hosted_ci() -> bool {
    #[expect(
        clippy::disallowed_methods,
        reason = "test gate: the CI opt-in is an environment variable by design, not a path"
    )]
    let is = |k: &str, v: &str| std::env::var(k).is_ok_and(|x| x == v);
    is("GITHUB_ACTIONS", "true")
        && is("RUNNER_ENVIRONMENT", "github-hosted")
        && is("RERUN_FS_MACHINE_FIXTURES", "1")
}

/// A note that `cargo test` does not capture (written to the real stderr, not via `eprintln!`),
/// so skips stay visible in a passing run.
pub(super) fn note(msg: &str) {
    let _ = writeln!(std::io::stderr(), "{msg}");
}

/// A GitHub workflow command (`::warning::…`) on the real stdout, past the test capture.
pub(super) fn workflow_warning(msg: &str) {
    let _ = writeln!(std::io::stdout(), "::warning::{msg}");
}

fn last_error() -> u32 {
    std::io::Error::last_os_error()
        .raw_os_error()
        .map_or(0, i32::cast_unsigned)
}

/// NUL-terminated UTF-16.
fn wide(s: impl AsRef<std::ffi::OsStr>) -> Vec<u16> {
    s.as_ref().encode_wide().chain([0]).collect()
}

fn win32_err(code: u32, what: &str) -> SysError {
    SysError::new(kind_of_win32(code), what).with_win32(code)
}

fn io_err(e: &std::io::Error, p: &Path) -> SysError {
    let code = e.raw_os_error().map_or(0, i32::cast_unsigned);
    win32_err(code, &p.display().to_string())
}

/// `X:\…` without a `\\?\` prefix (the contracts take plain drive paths).
fn plain(p: &Path) -> PathBuf {
    let s = p.to_string_lossy();
    PathBuf::from(s.strip_prefix(r"\\?\").unwrap_or(&s).to_owned())
}

/// Opens `p` itself (never following a final reparse point), file or directory.
fn open_entry(p: &Path, access: u32) -> SysResult<File> {
    OpenOptions::new()
        .access_mode(access)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(p)
        .map_err(|e| io_err(&e, p))
}

// ---------- Token ----------

fn process_token(access: u32) -> Result<OwnedHandle, u32> {
    let mut raw: HANDLE = ptr::null_mut();
    // SAFETY: GetCurrentProcess returns the current-process pseudo handle (always valid, never
    // closed).
    let process = unsafe { GetCurrentProcess() };
    // SAFETY: `process` is a valid pseudo handle; `raw` is valid for a write.
    if unsafe { OpenProcessToken(process, access, &mut raw) } == 0 {
        return Err(last_error());
    }
    // SAFETY: OpenProcessToken succeeded and wrote a new handle that nothing else owns.
    Ok(unsafe { OwnedHandle::from_raw_handle(raw) })
}

/// The process runs elevated (`TokenElevation`).
fn is_elevated() -> bool {
    let Ok(token) = process_token(TOKEN_QUERY) else {
        return false;
    };
    let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
    let mut returned = 0u32;
    // SAFETY: `token` is a live token handle with TOKEN_QUERY; `elevation` is a correctly sized
    // output buffer for TokenElevation (one u32); `returned` is valid for a write.
    let ok = unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenElevation,
            ptr::from_mut(&mut elevation).cast::<c_void>(),
            u32::try_from(size_of::<TOKEN_ELEVATION>()).unwrap_or(0),
            &mut returned,
        )
    };
    ok != 0 && elevation.TokenIsElevated != 0
}

/// `TOKEN_USER` of the process token as an 8-byte aligned buffer (the SID lives inside).
struct UserSid(Vec<u64>);

impl UserSid {
    fn current() -> Result<Self, u32> {
        let token = process_token(TOKEN_QUERY)?;
        let mut needed = 0u32;
        // SAFETY: size query: null buffer with length 0 is allowed; `needed` is valid for a
        // write. Fails with ERROR_INSUFFICIENT_BUFFER and reports the size.
        unsafe {
            GetTokenInformation(
                token.as_raw_handle(),
                TokenUser,
                ptr::null_mut(),
                0,
                &mut needed,
            )
        };
        let mut buf = vec![0u64; (needed as usize).div_ceil(8).max(1)];
        let len = u32::try_from(buf.len() * 8).map_err(|_| 122u32)?;
        // SAFETY: `buf` is valid for writes of `len` bytes and 8-byte aligned (TOKEN_USER
        // holds a pointer); `needed` is valid for a write.
        let ok = unsafe {
            GetTokenInformation(
                token.as_raw_handle(),
                TokenUser,
                buf.as_mut_ptr().cast::<c_void>(),
                len,
                &mut needed,
            )
        };
        if ok == 0 {
            return Err(last_error());
        }
        Ok(Self(buf))
    }

    /// The SID pointer (into `self.0`, valid as long as `self`).
    fn sid(&self) -> *mut c_void {
        // SAFETY: GetTokenInformation(TokenUser) filled `self.0` with a TOKEN_USER at offset 0,
        // the buffer is 8-byte aligned and at least size_of::<TOKEN_USER>() bytes.
        unsafe { (*self.0.as_ptr().cast::<TOKEN_USER>()).User.Sid }
    }
}

/// A DACL with a single ACE for the current user (`deny = true`: access-denied ACE).
fn single_ace_acl(user: &UserSid, mask: u32, deny: bool) -> Result<Vec<u64>, u32> {
    // SAFETY: the SID pointer comes from a successful TokenUser query and is valid.
    let sid_len = unsafe { GetLengthSid(user.sid()) };
    // ACL header + ACE (ACCESS_ALLOWED_ACE and ACCESS_DENIED_ACE have the same size) minus the
    // SidStart placeholder + SID.
    let len = size_of::<ACL>() + size_of::<ACCESS_ALLOWED_ACE>() - 4 + sid_len as usize;
    let mut buf = vec![0u64; len.div_ceil(8)];
    let len32 = u32::try_from(buf.len() * 8).map_err(|_| 122u32)?;
    let acl = buf.as_mut_ptr().cast::<ACL>();
    // SAFETY: `acl` points to `len32` writable, 8-byte aligned bytes owned by `buf`.
    if unsafe { InitializeAcl(acl, len32, ACL_REVISION) } == 0 {
        return Err(last_error());
    }
    let ok = if deny {
        // SAFETY: `acl` was initialized above with room for one ACE with this SID; the SID is
        // valid.
        unsafe { AddAccessDeniedAce(acl, ACL_REVISION, mask, user.sid()) }
    } else {
        // SAFETY: as above.
        unsafe { AddAccessAllowedAce(acl, ACL_REVISION, mask, user.sid()) }
    };
    if ok == 0 {
        return Err(last_error());
    }
    Ok(buf)
}

/// Replaces the DACL of the entry behind `f` (a handle with `WRITE_DAC`) by a protected DACL
/// with one ACE for the current user. `SetKernelObjectSecurity` writes the descriptor as given
/// (no inheritance propagation to children, unlike `SetSecurityInfo`).
fn set_dacl(f: &File, what: &str, mask: u32, deny: bool) -> SysResult<()> {
    let user = UserSid::current().map_err(|c| win32_err(c, what))?;
    let mut acl = single_ace_acl(&user, mask, deny).map_err(|c| win32_err(c, what))?;
    // SAFETY: SECURITY_DESCRIPTOR is plain data; all-zero is a valid starting value that
    // InitializeSecurityDescriptor overwrites.
    let mut sd: SECURITY_DESCRIPTOR = unsafe { std::mem::zeroed() };
    let psd = ptr::from_mut(&mut sd).cast::<c_void>();
    // SAFETY: `psd` points to a writable SECURITY_DESCRIPTOR.
    if unsafe { InitializeSecurityDescriptor(psd, SECURITY_DESCRIPTOR_REVISION) } == 0 {
        return Err(win32_err(last_error(), what));
    }
    // SAFETY: `psd` is initialized; `acl` is a valid ACL that outlives every use of `sd`
    // (both live until the end of this function).
    if unsafe { SetSecurityDescriptorDacl(psd, 1, acl.as_mut_ptr().cast::<ACL>(), 0) } == 0 {
        return Err(win32_err(last_error(), what));
    }
    // SAFETY: `psd` is an initialized absolute security descriptor.
    if unsafe { SetSecurityDescriptorControl(psd, SE_DACL_PROTECTED, SE_DACL_PROTECTED) } == 0 {
        return Err(win32_err(last_error(), what));
    }
    // SAFETY: `f` is a live handle opened with WRITE_DAC; `psd` is a valid absolute security
    // descriptor whose DACL (`acl`) is alive for the call.
    let ok = unsafe {
        SetKernelObjectSecurity(
            f.as_raw_handle(),
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            psd,
        )
    };
    if ok == 0 {
        return Err(win32_err(last_error(), what));
    }
    Ok(())
}

/// Enables `SeRestorePrivilege` on a thread impersonation token for the lifetime of the
/// guard; `RevertToSelf` on drop. The process token is never changed.
struct RestorePrivilege;

impl RestorePrivilege {
    /// `Ok(None)` = the privilege is not held (not an administrator).
    fn enable() -> Result<Option<Self>, u32> {
        // SAFETY: no pointers; impersonates the process token on this thread.
        if unsafe { ImpersonateSelf(SecurityImpersonation) } == 0 {
            return Err(last_error());
        }
        let guard = Self;
        let mut raw: HANDLE = ptr::null_mut();
        // SAFETY: GetCurrentThread returns the current-thread pseudo handle.
        let thread = unsafe { GetCurrentThread() };
        // SAFETY: `thread` is valid; `raw` is valid for a write; OpenAsSelf = TRUE.
        let ok =
            unsafe { OpenThreadToken(thread, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, 1, &mut raw) };
        if ok == 0 {
            return Err(last_error());
        }
        // SAFETY: OpenThreadToken succeeded and wrote a new handle that nothing else owns.
        let token = unsafe { OwnedHandle::from_raw_handle(raw) };
        let mut luid = LUID {
            LowPart: 0,
            HighPart: 0,
        };
        // SAFETY: SE_RESTORE_NAME is a static NUL-terminated string; `luid` is valid for a
        // write; null system name = local system.
        if unsafe { LookupPrivilegeValueW(ptr::null(), SE_RESTORE_NAME, &mut luid) } == 0 {
            return Err(last_error());
        }
        let tp = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };
        // SAFETY: `token` is a live token with TOKEN_ADJUST_PRIVILEGES; `tp` is a valid
        // TOKEN_PRIVILEGES with one entry; no previous-state buffer (null, 0).
        let ok = unsafe {
            AdjustTokenPrivileges(
                token.as_raw_handle(),
                0,
                &tp,
                0,
                ptr::null_mut(),
                ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(last_error());
        }
        if last_error() == ERROR_NOT_ALL_ASSIGNED {
            return Ok(None);
        }
        Ok(Some(guard))
    }
}

impl Drop for RestorePrivilege {
    fn drop(&mut self) {
        // SAFETY: no pointers; ends the impersonation started in `enable`.
        unsafe { RevertToSelf() };
    }
}

// ---------- Safeguards ----------

/// The cargo target directory: the ancestor of the test executable that contains
/// `CACHEDIR.TAG`. Panics if there is none (never guess a location).
pub(super) fn target_dir() -> PathBuf {
    let exe = std::env::current_exe().unwrap_or_else(|e| panic!("current_exe: {e}"));
    exe.ancestors()
        .find(|a| a.join("CACHEDIR.TAG").is_file())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| panic!("no ancestor of {} contains CACHEDIR.TAG", exe.display()))
}

/// Safeguard 1 of `09-testing.md` for `path`: canonical, strictly inside the canonical
/// `target`, on a local fixed drive, no ancestor is a reparse point or a cloud file.
fn check_safe(target: &Path, path: &Path) -> Result<PathBuf, String> {
    let canon = std::fs::canonicalize(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if canon == target || !canon.starts_with(target) {
        return Err(format!(
            "{} is not inside {}",
            canon.display(),
            target.display()
        ));
    }
    let shown = plain(&canon);
    let drive: String = shown.to_string_lossy().chars().take(3).collect();
    if drive.len() != 3 || !drive.ends_with(":\\") {
        return Err(format!("{} is not on a drive letter", canon.display()));
    }
    let drive_w = wide(&drive);
    // SAFETY: `drive_w` is a NUL-terminated `X:\` that outlives the call.
    let drive_type = unsafe { GetDriveTypeW(drive_w.as_ptr()) };
    if drive_type != DRIVE_FIXED {
        return Err(format!("{drive} is not a fixed drive (type {drive_type})"));
    }
    for a in canon.ancestors() {
        let m = std::fs::symlink_metadata(a).map_err(|e| format!("{}: {e}", a.display()))?;
        let bad = m.file_attributes() & UNSAFE_ANCESTOR_ATTRS;
        if bad != 0 {
            return Err(format!(
                "{} has attributes {bad:#x} (reparse point or cloud file)",
                a.display()
            ));
        }
    }
    Ok(canon)
}

// ---------- TestRoot ----------

/// A fresh, unique directory under `target/rerun-fs-contract/` for one contract run.
pub(super) struct TestRoot {
    /// Plain drive path (`X:\…`), as the contracts take it.
    path: PathBuf,
    /// Canonical target directory.
    target: PathBuf,
    fx: WinFixture,
}

impl TestRoot {
    /// `None` (with a note) when the process is elevated outside [`hosted_ci`] (safeguard 4).
    /// Removes stale roots of dead test processes first ([`clean_stale`]). Panics if a
    /// safeguard fails.
    pub(super) fn new(case: &str) -> Option<Self> {
        if is_elevated() && !hosted_ci() {
            note(&format!(
                "skipped {case}: the process is elevated; the file system contracts run \
                 elevated only on GitHub runners (docs/09-testing.md, safeguard 4)"
            ));
            return None;
        }
        let target_raw = target_dir();
        let target = std::fs::canonicalize(&target_raw)
            .unwrap_or_else(|e| panic!("canonicalize {}: {e}", target_raw.display()));
        let base = target.join("rerun-fs-contract");
        std::fs::create_dir_all(&base).unwrap_or_else(|e| panic!("{}: {e}", base.display()));
        clean_stale(&target, &base);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let dir = base.join(format!("{}-{nanos}-{case}", std::process::id()));
        // create_dir (not _all): fails if it exists, so the root is always new.
        std::fs::create_dir(&dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display()));
        let canon = check_safe(&target, &dir).unwrap_or_else(|e| {
            let _ = std::fs::remove_dir(&dir);
            panic!("unsafe test root: {e}")
        });
        let path = plain(&canon);
        Some(Self {
            fx: WinFixture::new(path.clone(), plain(&base)),
            path,
            target,
        })
    }

    /// The root (plain drive path).
    pub(super) fn path(&self) -> &Path {
        &self.path
    }

    /// The fixture whose machine-wide changes this root undoes.
    pub(super) fn fx(&self) -> &WinFixture {
        &self.fx
    }

    /// A fresh, empty work directory `name` below the root.
    pub(super) fn work(&self, name: &str) -> PathBuf {
        let p = self.path.join(name);
        std::fs::create_dir(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()));
        p
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        // Never panic here (a panic during unwinding aborts); report and keep the tree.
        if !self.fx.undo_all() {
            note(&format!(
                "kept {}: undoing a fixture change failed",
                self.path.display()
            ));
            return;
        }
        if let Err(e) = check_safe(&self.target, &self.path) {
            note(&format!("kept {}: {e}", self.path.display()));
            return;
        }
        // std's remove_dir_all is handle-based and deletes reparse points without following
        // them since the CVE-2022-21658 fix (Rust 1.58.1); checked by
        // `cleanup_never_follows_a_junction`.
        if let Err(e) = std::fs::remove_dir_all(&self.path) {
            note(&format!("could not remove {}: {e}", self.path.display()));
        }
    }
}

// ---------- Stale roots ----------

/// The process `pid` may still run (running, or not inspectable: assume alive).
fn pid_alive(pid: u32) -> bool {
    // SAFETY: no pointers; returns a new handle or null.
    let raw = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if raw.is_null() {
        // ERROR_INVALID_PARAMETER: no such process. Anything else (access denied): alive.
        return last_error() != 87;
    }
    // SAFETY: OpenProcess succeeded and returned a new handle that nothing else owns.
    let process = unsafe { OwnedHandle::from_raw_handle(raw) };
    let mut code = 0u32;
    // SAFETY: `process` is a live process handle with PROCESS_QUERY_LIMITED_INFORMATION;
    // `code` is valid for a write.
    let ok = unsafe { GetExitCodeProcess(process.as_raw_handle(), &mut code) };
    ok == 0 || code == STILL_ACTIVE
}

/// Opens `p` itself with `WRITE_DAC` only (`NtCreateFile`, no `SYNCHRONIZE`, no
/// `FILE_READ_ATTRIBUTES`, `FILE_OPEN_REPARSE_POINT`), so the owner can reset a DACL that
/// denies everything else. `CreateFileW` cannot: it always adds those two rights.
fn open_write_dac(p: &Path) -> SysResult<File> {
    let what = p.display().to_string();
    let mut nt: Vec<u16> = r"\??\".encode_utf16().collect();
    nt.extend(plain(p).as_os_str().encode_wide());
    let len =
        u16::try_from(nt.len() * 2).map_err(|_| SysError::path(SysErrorKind::InvalidPath, p))?;
    let name = UNICODE_STRING {
        Length: len,
        MaximumLength: len,
        Buffer: nt.as_mut_ptr(),
    };
    let oa = OBJECT_ATTRIBUTES {
        Length: u32::try_from(size_of::<OBJECT_ATTRIBUTES>()).unwrap_or(0),
        RootDirectory: ptr::null_mut(),
        ObjectName: &name,
        Attributes: OBJ_CASE_INSENSITIVE,
        SecurityDescriptor: ptr::null(),
        SecurityQualityOfService: ptr::null(),
    };
    let mut iosb = IO_STATUS_BLOCK::default();
    let mut raw: HANDLE = ptr::null_mut();
    // SAFETY: `raw` and `iosb` are valid for writes; `oa` points to `name`, whose buffer `nt`
    // outlives the call; no allocation size and no EA buffer. No I/O is done on the handle,
    // so it needs no synchronous mode.
    let status = unsafe {
        NtCreateFile(
            &mut raw,
            WRITE_DAC,
            &oa,
            &mut iosb,
            ptr::null(),
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_OPEN,
            FILE_OPEN_REPARSE_POINT,
            ptr::null(),
            0,
        )
    };
    if status < 0 || raw.is_null() {
        return Err(SysError::new(SysErrorKind::Other, &what).with_ntstatus(status));
    }
    // SAFETY: NtCreateFile succeeded and wrote a new handle that nothing else owns.
    Ok(File::from(unsafe { OwnedHandle::from_raw_handle(raw) }))
}

/// Gives every entry of a stale tree a DACL granting the current user full access (the owner
/// may always do that), entries before their children, never following a link: directory
/// entries come from the listing (`DirEntry::metadata` uses the find data, no open), and
/// reparse points are reset but not descended into.
fn reset_tree(dir: &Path) -> SysResult<()> {
    let what = dir.display().to_string();
    set_dacl(&open_write_dac(dir)?, &what, FILE_ALL_ACCESS, false)?;
    for e in std::fs::read_dir(dir).map_err(|e| io_err(&e, dir))? {
        let e = e.map_err(|err| io_err(&err, dir))?;
        let m = e.metadata().map_err(|err| io_err(&err, &e.path()))?;
        let path = e.path();
        if m.is_dir() && m.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0 {
            reset_tree(&path)?;
        } else {
            let shown = path.display().to_string();
            set_dacl(&open_write_dac(&path)?, &shown, FILE_ALL_ACCESS, false)?;
        }
    }
    Ok(())
}

/// Review L7: removes roots `<pid>-<nanos>-<case>` in `base` whose process is gone (a test
/// that aborted or was killed before its drop ran). Each one must be a plain directory (not a
/// reparse point, from the listing) that passes the safeguards; its DACLs are reset through
/// the owner right ([`reset_tree`]), the safeguards are checked again, then it is removed
/// with the link-safe `remove_dir_all`. Roots of the current or a possibly live process are
/// never touched. Failures are notes, never panics. One cleaner at a time per process: tests
/// create roots in parallel, and two cleaners on the same stale root would race (one sees the
/// root half removed by the other).
fn clean_stale(target: &Path, base: &Path) {
    static CLEANING: Mutex<()> = Mutex::new(());
    let _one = CLEANING.lock().unwrap_or_else(PoisonError::into_inner);
    let Ok(list) = std::fs::read_dir(base) else {
        return;
    };
    let me = std::process::id();
    for e in list.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        let Some(pid) = name.split('-').next().and_then(|s| s.parse::<u32>().ok()) else {
            continue;
        };
        if pid == me || pid_alive(pid) {
            continue;
        }
        let path = e.path();
        let plain_dir = e
            .metadata()
            .is_ok_and(|m| m.is_dir() && m.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0);
        if !plain_dir {
            note(&format!(
                "kept stale {}: not a plain directory",
                path.display()
            ));
            continue;
        }
        let checked = check_safe(target, &path)
            .and_then(|_| reset_tree(&path).map_err(|e| e.to_string()))
            .and_then(|()| check_safe(target, &path));
        match checked {
            Err(why) => note(&format!("kept stale {}: {why}", path.display())),
            Ok(_) => match std::fs::remove_dir_all(&path) {
                Ok(()) => note(&format!("removed stale test root {}", path.display())),
                Err(err) => note(&format!("could not remove stale {}: {err}", path.display())),
            },
        }
    }
}

// ---------- WinFixture ----------

/// A machine-wide change the fixture made; undone in reverse order by [`TestRoot`]'s drop.
#[derive(Debug)]
enum Undo {
    /// A volume mount point (path with a trailing `\`).
    Mount(PathBuf),
    /// A substituted drive (`X:`) and its target.
    Subst(String, PathBuf),
    /// A restricted DACL on an entry of the test tree, with the `WRITE_DAC` handle opened
    /// before the change (a new open would need `SYNCHRONIZE` and `FILE_READ_ATTRIBUTES`,
    /// which `CreateFileW` always adds and the restricted DACL denies).
    Dacl(PathBuf, File),
}

/// [`FsFixture`] for `sys::win`, bound to one [`TestRoot`]. See the module docs.
#[derive(Debug)]
pub(super) struct WinFixture {
    /// The test root (plain, canonical): every written path lies inside it.
    root: PathBuf,
    /// `target/rerun-fs-contract` (plain, canonical): link targets lie inside it.
    base: PathBuf,
    undo: Mutex<Vec<Undo>>,
}

/// What the last component of a guarded path may be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Last {
    /// Must not be a reparse point if it exists (data is written to or through it).
    Plain,
    /// May be a reparse point (a link renamed as itself).
    Link,
}

impl WinFixture {
    fn new(root: PathBuf, base: PathBuf) -> Self {
        Self {
            root,
            base,
            undo: Mutex::new(Vec::new()),
        }
    }

    /// Review L5: `p` lies inside the root (component-wise), has no `.` or `..`, is not below
    /// a mount point of this fixture, and no existing component below the root is a reparse
    /// point (the last one only if `last` is [`Last::Link`]). An unreadable component refuses
    /// too (fail closed).
    fn guard(&self, p: &Path, last: Last) -> SysResult<()> {
        let refuse = |kind| Err(SysError::path(kind, p));
        if p.components()
            .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
        {
            return refuse(SysErrorKind::InvalidPath);
        }
        let Ok(rel) = p.strip_prefix(&self.root) else {
            return refuse(SysErrorKind::InvalidPath);
        };
        self.refuse_mounted(p)?;
        let comps: Vec<Component<'_>> = rel.components().collect();
        let mut cur = self.root.clone();
        for (i, c) in comps.iter().enumerate() {
            cur.push(c);
            match std::fs::symlink_metadata(&cur) {
                Ok(m) => {
                    let link = m.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0;
                    if link && !(i + 1 == comps.len() && last == Last::Link) {
                        return refuse(SysErrorKind::ReparsePoint);
                    }
                }
                // Nothing below a missing component exists either.
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => break,
                Err(_) => return refuse(SysErrorKind::AccessDenied),
            }
        }
        Ok(())
    }

    /// Link targets stay inside `target/rerun-fs-contract` (safeguard 2; the cleanup test
    /// links one test root to a sibling root).
    fn guard_target(&self, target: &Path) -> SysResult<()> {
        let t = plain(target);
        if t.components()
            .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
            || !t.starts_with(&self.base)
        {
            return Err(SysError::path(SysErrorKind::InvalidPath, target));
        }
        Ok(())
    }

    fn push_undo(&self, u: Undo) {
        self.undo
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(u);
    }

    /// Undoes every recorded change, newest first. `false` if one of them failed.
    fn undo_all(&self) -> bool {
        let mut list =
            std::mem::take(&mut *self.undo.lock().unwrap_or_else(PoisonError::into_inner));
        let mut all_ok = true;
        while let Some(u) = list.pop() {
            let r = match &u {
                Undo::Mount(at) => {
                    // SAFETY: `w` is a NUL-terminated mount point path with a trailing `\`.
                    let ok = unsafe { DeleteVolumeMountPointW(wide(at).as_ptr()) };
                    if ok == 0 { Err(last_error()) } else { Ok(()) }
                }
                Undo::Subst(letter, target) => {
                    // SAFETY: both strings are NUL-terminated; exact-match removal of the
                    // definition this fixture created.
                    let ok = unsafe {
                        DefineDosDeviceW(
                            DDD_REMOVE_DEFINITION | DDD_EXACT_MATCH_ON_REMOVE,
                            wide(letter).as_ptr(),
                            wide(target).as_ptr(),
                        )
                    };
                    if ok == 0 { Err(last_error()) } else { Ok(()) }
                }
                Undo::Dacl(p, f) => set_dacl(f, &p.display().to_string(), FILE_ALL_ACCESS, false)
                    .map_err(|e| e.win32.unwrap_or(0)),
            };
            if let Err(code) = r {
                note(&format!("fixture undo of {u:?} failed: Win32 error {code}"));
                all_ok = false;
            }
        }
        all_ok
    }

    /// The fixture never writes below a mount point (that would be another volume of the
    /// machine).
    fn refuse_mounted(&self, p: &Path) -> SysResult<()> {
        let list = self.undo.lock().unwrap_or_else(PoisonError::into_inner);
        let below = list.iter().any(|u| match u {
            Undo::Mount(at) => p.starts_with(plain(at)),
            _ => false,
        });
        if below {
            return Err(SysError::path(SysErrorKind::Unsupported, p));
        }
        Ok(())
    }

    fn parents(&self, p: &Path, last: Last) -> SysResult<()> {
        self.guard(p, last)?;
        match p.parent() {
            Some(parent) => std::fs::create_dir_all(parent).map_err(|e| io_err(&e, parent)),
            None => Ok(()),
        }
    }

    fn symlink(&self, link: &Path, target: &Path, flags: u32) -> SysResult<bool> {
        self.parents(link, Last::Plain)?;
        self.guard_target(target)?;
        let flags = flags | SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE;
        // SAFETY: both paths are NUL-terminated wide strings that outlive the call.
        let ok = unsafe { CreateSymbolicLinkW(wide(link).as_ptr(), wide(target).as_ptr(), flags) };
        if ok {
            return Ok(true);
        }
        match last_error() {
            ERROR_PRIVILEGE_NOT_HELD => Ok(false),
            code => Err(win32_err(code, &link.display().to_string())),
        }
    }

    /// Another NTFS volume of this machine that is already mounted at a drive letter and is
    /// not the volume of `near`: its volume GUID path (`\\?\Volume{…}\`). Already-mounted only,
    /// so adding a mount point never makes Windows mount (and write to) a dormant volume.
    fn other_volume(near: &Path) -> Option<Vec<u16>> {
        let drive: String = plain(near).to_string_lossy().chars().take(3).collect();
        let own = volume_name_of(&drive)?;
        let mut name = vec![0u16; 64];
        // SAFETY: `name` is valid for writes of its length in UTF-16 units.
        let find = unsafe { FindFirstVolumeW(name.as_mut_ptr(), 64) };
        if find.is_null() || find == INVALID_HANDLE_VALUE {
            return None;
        }
        let mut found = None;
        loop {
            let vol = trim_nul(&name);
            if vol != own && is_ntfs(&vol) && mounted_at_letter(&vol) {
                found = Some(vol);
                break;
            }
            // SAFETY: `find` is the live search handle; `name` is valid for writes.
            if unsafe { FindNextVolumeW(find, name.as_mut_ptr(), 64) } == 0 {
                break;
            }
        }
        // SAFETY: `find` is the live search handle from FindFirstVolumeW, closed once.
        unsafe { FindVolumeClose(find) };
        found
    }
}

fn trim_nul(buf: &[u16]) -> Vec<u16> {
    let end = buf.iter().position(|&u| u == 0).unwrap_or(buf.len());
    buf[..end].to_vec()
}

/// Volume GUID path of the volume mounted at `root` (`X:\`).
fn volume_name_of(root: &str) -> Option<Vec<u16>> {
    let mut name = vec![0u16; 64];
    // SAFETY: `root` is NUL-terminated; `name` is valid for writes of 64 units.
    let ok =
        unsafe { GetVolumeNameForVolumeMountPointW(wide(root).as_ptr(), name.as_mut_ptr(), 64) };
    (ok != 0).then(|| trim_nul(&name))
}

fn is_ntfs(vol: &[u16]) -> bool {
    let mut fs_name = vec![0u16; 64];
    let mut v = vol.to_vec();
    v.push(0);
    // SAFETY: `v` is a NUL-terminated volume GUID path with a trailing `\`; `fs_name` is valid
    // for writes of 64 units; the other outputs are null (optional).
    let ok = unsafe {
        GetVolumeInformationW(
            v.as_ptr(),
            ptr::null_mut(),
            0,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            fs_name.as_mut_ptr(),
            64,
        )
    };
    ok != 0 && String::from_utf16_lossy(&trim_nul(&fs_name)) == "NTFS"
}

/// The volume has at least one drive-letter mount path (`X:\`).
fn mounted_at_letter(vol: &[u16]) -> bool {
    let mut v = vol.to_vec();
    v.push(0);
    let mut buf = vec![0u16; 1024];
    let mut needed = 0u32;
    // SAFETY: `v` is NUL-terminated; `buf` is valid for writes of 1024 units; `needed` is
    // valid for a write.
    let ok = unsafe {
        GetVolumePathNamesForVolumeNameW(v.as_ptr(), buf.as_mut_ptr(), 1024, &mut needed)
    };
    if ok == 0 {
        return false;
    }
    buf.split(|&u| u == 0)
        .take_while(|s| !s.is_empty())
        .any(|s| s.len() == 3 && s[1] == u16::from(b':') && s[2] == u16::from(b'\\'))
}

impl FsFixture for WinFixture {
    fn dir(&self, p: &Path) -> SysResult<()> {
        self.guard(p, Last::Plain)?;
        std::fs::create_dir_all(p).map_err(|e| io_err(&e, p))
    }

    fn file(&self, p: &Path, data: &[u8]) -> SysResult<()> {
        self.parents(p, Last::Plain)?;
        std::fs::write(p, data).map_err(|e| io_err(&e, p))
    }

    /// `FSCTL_SET_REPARSE_POINT` with a mount point buffer on a new empty directory: no admin
    /// and no `mklink` needed.
    fn junction(&self, link: &Path, target: &Path) -> SysResult<()> {
        self.parents(link, Last::Plain)?;
        self.guard_target(target)?;
        std::fs::create_dir(link).map_err(|e| io_err(&e, link))?;
        let target = plain(target);
        let print: Vec<u16> = target.as_os_str().encode_wide().collect();
        let mut subst: Vec<u16> = r"\??\".encode_utf16().collect();
        subst.extend_from_slice(&print);
        let bytes = |n: usize| {
            u16::try_from(n * 2).map_err(|_| SysError::path(SysErrorKind::InvalidPath, link))
        };
        let (sub_len, print_len) = (bytes(subst.len())?, bytes(print.len())?);
        // PathBuffer: substitute name, NUL, print name, NUL.
        let mut path_buf = subst;
        path_buf.push(0);
        path_buf.extend_from_slice(&print);
        path_buf.push(0);
        let data_len = bytes(path_buf.len())?
            .checked_add(8)
            .ok_or_else(|| SysError::path(SysErrorKind::InvalidPath, link))?;
        let mut buf = Vec::new();
        buf.extend_from_slice(&tag::MOUNT_POINT.to_le_bytes());
        buf.extend_from_slice(&data_len.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.extend_from_slice(&sub_len.to_le_bytes());
        buf.extend_from_slice(&(sub_len + 2).to_le_bytes());
        buf.extend_from_slice(&print_len.to_le_bytes());
        buf.extend(path_buf.iter().flat_map(|u| u.to_le_bytes()));
        let f = open_entry(link, FILE_WRITE_ATTRIBUTES | FILE_WRITE_DATA)?;
        let len = u32::try_from(buf.len())
            .map_err(|_| SysError::path(SysErrorKind::InvalidPath, link))?;
        let mut returned = 0u32;
        // SAFETY: `f` is a live directory handle opened with write access and
        // FILE_FLAG_OPEN_REPARSE_POINT; `buf` is a complete REPARSE_DATA_BUFFER of `len`
        // bytes; no output buffer; `returned` is valid for a write; synchronous handle.
        let ok = unsafe {
            DeviceIoControl(
                f.as_raw_handle(),
                FSCTL_SET_REPARSE_POINT,
                buf.as_ptr().cast::<c_void>(),
                len,
                ptr::null_mut(),
                0,
                &mut returned,
                ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(win32_err(last_error(), &link.display().to_string()));
        }
        Ok(())
    }

    fn dir_symlink(&self, link: &Path, target: &Path) -> SysResult<bool> {
        self.symlink(link, target, SYMBOLIC_LINK_FLAG_DIRECTORY)
    }

    fn file_symlink(&self, link: &Path, target: &Path) -> SysResult<bool> {
        self.symlink(link, target, 0)
    }

    fn hardlink(&self, existing: &Path, new: &Path) -> SysResult<()> {
        self.guard(existing, Last::Plain)?;
        self.parents(new, Last::Plain)?;
        std::fs::hard_link(existing, new).map_err(|e| io_err(&e, new))
    }

    /// `MoveFileExW` without `MOVEFILE_REPLACE_EXISTING`: never overwrites; renames a link
    /// itself, never its target.
    fn rename(&self, from: &Path, to: &Path) -> SysResult<()> {
        self.guard(from, Last::Link)?;
        self.guard(to, Last::Link)?;
        // SAFETY: both paths are NUL-terminated wide strings that outlive the call.
        let ok = unsafe { MoveFileExW(wide(from).as_ptr(), wide(to).as_ptr(), 0) };
        if ok == 0 {
            return Err(win32_err(last_error(), &from.display().to_string()));
        }
        Ok(())
    }

    /// `SetFileInformationByHandle(FileCaseSensitiveInfo)` on a new empty directory.
    fn case_sensitive_dir(&self, p: &Path) -> SysResult<bool> {
        self.dir(p)?;
        let f = open_entry(p, FILE_WRITE_ATTRIBUTES | FILE_READ_ATTRIBUTES)?;
        let info = FILE_CASE_SENSITIVE_INFO { Flags: 1 };
        // SAFETY: `f` is a live directory handle with FILE_WRITE_ATTRIBUTES; `info` is a
        // FILE_CASE_SENSITIVE_INFO of the size passed.
        let ok = unsafe {
            SetFileInformationByHandle(
                f.as_raw_handle(),
                FileCaseSensitiveInfo,
                ptr::from_ref(&info).cast::<c_void>(),
                u32::try_from(size_of::<FILE_CASE_SENSITIVE_INFO>()).unwrap_or(0),
            )
        };
        if ok != 0 {
            return Ok(true);
        }
        match last_error() {
            // Not supported by the file system or the OS configuration, or not permitted.
            1 | 5 | 50 | 87 | ERROR_PRIVILEGE_NOT_HELD => Ok(false),
            code => Err(win32_err(code, &p.display().to_string())),
        }
    }

    /// GitHub runners only: mounts another, already mounted NTFS volume of the machine in
    /// `at` (`SetVolumeMountPointW`), undone with `DeleteVolumeMountPointW`. Nothing is ever
    /// written below it.
    fn mount_volume(&self, at: &Path) -> SysResult<bool> {
        if !hosted_ci() {
            return Ok(false);
        }
        self.guard(at, Last::Plain)?;
        let Some(vol) = Self::other_volume(at) else {
            return Ok(false);
        };
        self.dir(at)?;
        let mut point = plain(at).into_os_string();
        point.push("\\");
        let point = PathBuf::from(point);
        let mut v = vol.clone();
        v.push(0);
        // SAFETY: both strings are NUL-terminated (mount point with a trailing `\`, volume
        // GUID path with a trailing `\`).
        let ok = unsafe { SetVolumeMountPointW(wide(&point).as_ptr(), v.as_ptr()) };
        if ok == 0 {
            return Err(win32_err(last_error(), &at.display().to_string()));
        }
        self.push_undo(Undo::Mount(point));
        Ok(true)
    }

    /// GitHub runners only: `DefineDosDeviceW` on a free drive letter, undone with an exact
    /// removal.
    fn subst(&self, target: &Path) -> SysResult<Option<PathBuf>> {
        if !hosted_ci() {
            return Ok(None);
        }
        self.guard(target, Last::Plain)?;
        // SAFETY: no arguments.
        let used = unsafe { GetLogicalDrives() };
        let Some(letter) = (b'G'..=b'Z')
            .rev()
            .find(|l| used & (1 << (l - b'A')) == 0)
            .map(char::from)
        else {
            return Ok(None);
        };
        let device = format!("{letter}:");
        let target = plain(target);
        // SAFETY: both strings are NUL-terminated and outlive the call.
        let ok = unsafe { DefineDosDeviceW(0, wide(&device).as_ptr(), wide(&target).as_ptr()) };
        if ok == 0 {
            return Err(win32_err(last_error(), &device));
        }
        self.push_undo(Undo::Subst(device, target));
        Ok(Some(PathBuf::from(format!("{letter}:\\"))))
    }

    /// GitHub runners only: `SetFileShortNameW` with `SeRestorePrivilege` enabled on a thread
    /// impersonation token (never on the process token). The short name lives in the test
    /// tree and goes with it.
    fn short_name(&self, p: &Path, short: &str) -> SysResult<bool> {
        if !hosted_ci() {
            return Ok(false);
        }
        self.guard(p, Last::Plain)?;
        let what = p.display().to_string();
        let Some(_privilege) = RestorePrivilege::enable().map_err(|c| win32_err(c, &what))? else {
            return Ok(false);
        };
        // GENERIC_WRITE | DELETE: the documented access for SetFileShortNameW.
        let f = open_entry(p, GENERIC_WRITE | DELETE)?;
        // SAFETY: `f` is a live handle with GENERIC_WRITE | DELETE opened with backup
        // semantics; the short name is NUL-terminated.
        let ok = unsafe { SetFileShortNameW(f.as_raw_handle(), wide(short).as_ptr()) };
        if ok != 0 {
            return Ok(true);
        }
        match last_error() {
            // 8.3 names disabled on the volume, or not NTFS.
            1 | 50 | 87 => Ok(false),
            code => Err(win32_err(code, &what)),
        }
    }

    /// `FSCTL_SET_EXTERNAL_BACKING` with the WOF file provider (XPRESS4K), like CompactGUI.
    fn wof_compress(&self, p: &Path) -> SysResult<bool> {
        self.guard(p, Last::Plain)?;
        let f = OpenOptions::new()
            .read(true)
            .write(true)
            .open(p)
            .map_err(|e| io_err(&e, p))?;
        let mut input = Vec::new();
        for v in [
            WOF_CURRENT_VERSION,
            WOF_PROVIDER_FILE,
            FILE_PROVIDER_CURRENT_VERSION,
            FILE_PROVIDER_COMPRESSION_XPRESS4K,
            0,
        ] {
            input.extend_from_slice(&v.to_le_bytes());
        }
        let mut returned = 0u32;
        // SAFETY: `f` is a live file handle with read/write access; `input` is a
        // WOF_EXTERNAL_INFO followed by a FILE_PROVIDER_EXTERNAL_INFO_V1 (20 bytes); no output
        // buffer; `returned` is valid for a write; synchronous handle.
        let ok = unsafe {
            DeviceIoControl(
                f.as_raw_handle(),
                FSCTL_SET_EXTERNAL_BACKING,
                input.as_ptr().cast::<c_void>(),
                20,
                ptr::null_mut(),
                0,
                &mut returned,
                ptr::null_mut(),
            )
        };
        if ok != 0 {
            return Ok(true);
        }
        match last_error() {
            // No WOF on this volume or OS.
            1 | 50 | 87 => Ok(false),
            code => Err(win32_err(code, &p.display().to_string())),
        }
    }

    /// A protected DACL with one access-denied ACE for the current user covering everything
    /// except `READ_CONTROL` and `WRITE_DAC`. The `WRITE_DAC` handle is opened before the
    /// change and kept with the undo record (a DACL granting the user full access), which is
    /// recorded whether or not the change succeeded, so the runner can always restore and
    /// remove the entry. A new open after the change would fail: `CreateFileW` always adds
    /// `SYNCHRONIZE | FILE_READ_ATTRIBUTES`, which the DACL denies (found on real Windows).
    fn restricted(&self, p: &Path) -> SysResult<bool> {
        self.guard(p, Last::Plain)?;
        let f = open_entry(p, WRITE_DAC | READ_CONTROL)?;
        let what = p.display().to_string();
        let r = set_dacl(
            &f,
            &what,
            FILE_ALL_ACCESS & !(READ_CONTROL | WRITE_DAC),
            true,
        );
        self.push_undo(Undo::Dacl(p.to_path_buf(), f));
        r.map(|()| true)
    }

    /// `RemoveDirectoryW` for a plain directory, `DeleteFileW` for anything else (a link is
    /// removed itself).
    fn remove(&self, p: &Path) -> SysResult<()> {
        self.guard(p, Last::Link)?;
        // `symlink_metadata` does not follow; a junction or directory symlink carries
        // FILE_ATTRIBUTE_DIRECTORY and `RemoveDirectoryW` removes the link itself.
        let m = std::fs::symlink_metadata(p).map_err(|e| io_err(&e, p))?;
        if m.file_attributes() & FILE_ATTRIBUTE_DIRECTORY != 0 {
            std::fs::remove_dir(p).map_err(|e| io_err(&e, p))
        } else {
            std::fs::remove_file(p).map_err(|e| io_err(&e, p))
        }
    }

    /// `SetFileInformationByHandle(FileBasicInfo)` on a handle with `FILE_WRITE_ATTRIBUTES`;
    /// times 0 stay unchanged, attributes other than R/H/S are kept.
    fn set_attrs(&self, p: &Path, attrs: Attrs) -> SysResult<()> {
        self.guard(p, Last::Plain)?;
        let f = open_entry(p, FILE_WRITE_ATTRIBUTES | FILE_READ_ATTRIBUTES)?;
        let current = f.metadata().map_err(|e| io_err(&e, p))?.file_attributes();
        let mut bits =
            current & !(FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
        for (on, bit) in [
            (attrs.readonly, FILE_ATTRIBUTE_READONLY),
            (attrs.hidden, FILE_ATTRIBUTE_HIDDEN),
            (attrs.system, FILE_ATTRIBUTE_SYSTEM),
        ] {
            if on {
                bits |= bit;
            }
        }
        if bits == 0 {
            bits = FILE_ATTRIBUTE_NORMAL;
        }
        let info = FILE_BASIC_INFO {
            CreationTime: 0,
            LastAccessTime: 0,
            LastWriteTime: 0,
            ChangeTime: 0,
            FileAttributes: bits,
        };
        // SAFETY: `f` is a live handle with FILE_WRITE_ATTRIBUTES; `info` is a
        // FILE_BASIC_INFO of the size passed that outlives the call.
        let ok = unsafe {
            SetFileInformationByHandle(
                f.as_raw_handle(),
                FileBasicInfo,
                ptr::from_ref(&info).cast::<c_void>(),
                u32::try_from(size_of::<FILE_BASIC_INFO>()).unwrap_or(0),
            )
        };
        if ok == 0 {
            return Err(win32_err(last_error(), &p.display().to_string()));
        }
        Ok(())
    }

    /// A copy of `System32\version.dll` (a valid PE produced at runtime from the machine's
    /// own system file; no binary in the repo), mapped as an image section with
    /// `CreateFileMappingW(SEC_IMAGE)` and `MapViewOfFile`: the loader is never involved (no
    /// `LoadLibrary`, no `DllMain`, no DLL search), and the file and section handles are
    /// closed at once, so only the view keeps the image section, like a running exe or a
    /// loaded DLL. Unmapped on drop.
    fn mapped_image(&self, p: &Path) -> SysResult<Option<Held<'_>>> {
        self.parents(p, Last::Plain)?;
        let src = system32().join("version.dll");
        let bytes = std::fs::read(&src).map_err(|e| io_err(&e, &src))?;
        std::fs::write(p, bytes).map_err(|e| io_err(&e, p))?;
        let f = OpenOptions::new()
            .access_mode(GENERIC_READ | GENERIC_EXECUTE)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_DELETE)
            .open(p)
            .map_err(|e| io_err(&e, p))?;
        let view = map_view(&f, PAGE_READONLY | SEC_IMAGE, FILE_MAP_READ, p)?;
        drop(f);
        Ok(Some(Box::new(view)))
    }

    /// A legacy delete (`SetFileInformationByHandle(FileDispositionInfo)`, not POSIX) on one
    /// handle while a second one (read, sharing everything) stays open: the name stays in
    /// delete-pending state until the returned second handle drops.
    fn delete_pending(&self, p: &Path) -> SysResult<Option<Held<'_>>> {
        self.parents(p, Last::Plain)?;
        std::fs::write(p, b"pending").map_err(|e| io_err(&e, p))?;
        let open = |access: u32| {
            OpenOptions::new()
                .access_mode(access | SYNCHRONIZE)
                .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
                .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
                .open(p)
                .map_err(|e| io_err(&e, p))
        };
        let keep = open(FILE_READ_DATA)?;
        let del = open(DELETE)?;
        let info = FILE_DISPOSITION_INFO { DeleteFile: true };
        // SAFETY: `del` is a live handle with DELETE; `info` is a FILE_DISPOSITION_INFO of the
        // size passed that outlives the call.
        let ok = unsafe {
            SetFileInformationByHandle(
                del.as_raw_handle(),
                FileDispositionInfo,
                ptr::from_ref(&info).cast::<c_void>(),
                u32::try_from(size_of::<FILE_DISPOSITION_INFO>()).unwrap_or(0),
            )
        };
        if ok == 0 {
            return Err(win32_err(last_error(), &p.display().to_string()));
        }
        drop(del);
        Ok(Some(Box::new(keep)))
    }

    /// The file `p` mapped read-write as a data section (`PAGE_READWRITE`, a writable view),
    /// with the file and section handles closed at once: only the view stays, until the
    /// returned value drops.
    fn mapped_data(&self, p: &Path) -> SysResult<Option<Held<'_>>> {
        self.parents(p, Last::Plain)?;
        std::fs::write(p, b"mapped data").map_err(|e| io_err(&e, p))?;
        let f = OpenOptions::new()
            .read(true)
            .write(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .open(p)
            .map_err(|e| io_err(&e, p))?;
        let view = map_view(&f, PAGE_READWRITE, FILE_MAP_WRITE, p)?;
        drop(f);
        Ok(Some(Box::new(view)))
    }

    /// The file `p` with a writable data section (`PAGE_READWRITE`) and no view; the file
    /// handle is closed at once, the section handle is the returned value.
    fn data_section(&self, p: &Path) -> SysResult<Option<Held<'_>>> {
        self.parents(p, Last::Plain)?;
        std::fs::write(p, b"data section").map_err(|e| io_err(&e, p))?;
        let f = OpenOptions::new()
            .read(true)
            .write(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .open(p)
            .map_err(|e| io_err(&e, p))?;
        let section = create_section(&f, PAGE_READWRITE, p)?;
        drop(f);
        Ok(Some(Box::new(section)))
    }

    /// `CreateFileW` with `FILE_READ_DATA`/`FILE_WRITE_DATA`/`DELETE` (or
    /// `FILE_READ_ATTRIBUTES` alone), `SYNCHRONIZE` and the share mode, opening `p` itself
    /// (`FILE_FLAG_OPEN_REPARSE_POINT`). `FILE_FLAG_BACKUP_SEMANTICS` (backup intent) only for
    /// a directory, which cannot be opened without it: an ordinary program opens a file
    /// without it, and on the elevated GitHub runner a file opened with it passed a share-0
    /// lock (K1, CI run 42130639073), so the hold would not test the share mode there.
    fn hold_open(&self, p: &Path, access: Access, share: Share) -> SysResult<Held<'_>> {
        self.guard(p, Last::Plain)?;
        ci_token_note();
        let dir = std::fs::symlink_metadata(p)
            .map_err(|e| io_err(&e, p))?
            .file_attributes()
            & FILE_ATTRIBUTE_DIRECTORY
            != 0;
        let mut mask = SYNCHRONIZE;
        for (on, bit) in [
            (access.read, FILE_READ_DATA),
            (access.write, FILE_WRITE_DATA),
            (access.delete, DELETE),
        ] {
            if on {
                mask |= bit;
            }
        }
        if !access.any() {
            mask |= FILE_READ_ATTRIBUTES;
        }
        let mut sh = 0;
        for (on, bit) in [
            (share.read, FILE_SHARE_READ),
            (share.write, FILE_SHARE_WRITE),
            (share.delete, FILE_SHARE_DELETE),
        ] {
            if on {
                sh |= bit;
            }
        }
        let f = OpenOptions::new()
            .access_mode(mask)
            .share_mode(sh)
            .custom_flags(if dir {
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT
            } else {
                FILE_FLAG_OPEN_REPARSE_POINT
            })
            .open(p)
            .map_err(|e| io_err(&e, p))?;
        Ok(Box::new(f))
    }
}

/// Diagnostic on GitHub runners, once per process: whether the token is elevated and whether
/// `SeBackupPrivilege` and `SeRestorePrivilege` are enabled (they decide what an open with
/// backup intent may do; K1 failed there with a fixture open by backup semantics).
fn ci_token_note() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    if !hosted_ci() {
        return;
    }
    ONCE.call_once(|| {
        note(&format!(
            "note: CI token: elevated {}, SeBackupPrivilege {}, SeRestorePrivilege {}",
            is_elevated(),
            privilege_state(SE_BACKUP_NAME),
            privilege_state(SE_RESTORE_NAME),
        ));
    });
}

/// `SeBackupPrivilege` and `SeRestorePrivilege` of the process token, each `enabled`,
/// `disabled`, `absent` or `unknown`.
pub(super) fn backup_restore_privileges() -> (&'static str, &'static str) {
    (
        privilege_state(SE_BACKUP_NAME),
        privilege_state(SE_RESTORE_NAME),
    )
}

/// `enabled`, `disabled` (held, not enabled), `absent` or `unknown` for a privilege of the
/// process token (`TokenPrivileges`).
fn privilege_state(name: windows_sys::core::PCWSTR) -> &'static str {
    let mut luid = LUID {
        LowPart: 0,
        HighPart: 0,
    };
    // SAFETY: `name` is a static NUL-terminated privilege name; `luid` is valid for a write;
    // null system name = local system.
    if unsafe { LookupPrivilegeValueW(ptr::null(), name, &mut luid) } == 0 {
        return "unknown";
    }
    let Ok(token) = process_token(TOKEN_QUERY) else {
        return "unknown";
    };
    let mut buf = vec![0u64; 512];
    let len = u32::try_from(buf.len() * 8).unwrap_or(0);
    let mut needed = 0u32;
    // SAFETY: `token` is a live token with TOKEN_QUERY; `buf` is valid for writes of `len`
    // bytes and 8-byte aligned; `needed` is valid for a write.
    let ok = unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenPrivileges,
            buf.as_mut_ptr().cast::<c_void>(),
            len,
            &mut needed,
        )
    };
    if ok == 0 {
        return "unknown";
    }
    // TOKEN_PRIVILEGES: a u32 count, then LUID_AND_ATTRIBUTES entries of 12 bytes (LUID low
    // u32, high i32, attributes u32) from offset 4; read as bytes, never through a pointer.
    let bytes: Vec<u8> = buf.iter().flat_map(|w| w.to_le_bytes()).collect();
    let word = |at: usize| {
        bytes
            .get(at..at + 4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    };
    let count = word(0).unwrap_or(0) as usize;
    for i in 0..count {
        let at = 4 + 12 * i;
        let (Some(low), Some(high), Some(attrs)) = (word(at), word(at + 4), word(at + 8)) else {
            return "unknown";
        };
        if low == luid.LowPart && high.cast_signed() == luid.HighPart {
            return if attrs & SE_PRIVILEGE_ENABLED != 0 {
                "enabled"
            } else {
                "disabled"
            };
        }
    }
    "absent"
}

/// `<Windows>\System32` from the real known folders.
fn system32() -> PathBuf {
    use super::WinKnownFolders;
    use crate::sys::{KnownFolder, KnownFolders};
    let reg = WinRegistry::new().unwrap_or_else(|e| panic!("registry: {e}"));
    WinKnownFolders::new(std::sync::Arc::new(reg))
        .get(KnownFolder::Windows)
        .unwrap_or_else(|e| panic!("known folder Windows: {e}"))
        .join("System32")
}

/// A mapped view (its base address in this process) without any handle: the section lives
/// as long as the view. Unmapped on drop.
#[derive(Debug)]
struct View(usize);

impl Drop for View {
    fn drop(&mut self) {
        // SAFETY: `self.0` is the base address MapViewOfFile returned, unmapped exactly once
        // here; the mapped memory is never read or borrowed.
        unsafe {
            UnmapViewOfFile(MEMORY_MAPPED_VIEW_ADDRESS {
                Value: self.0 as *mut c_void,
            })
        };
    }
}

/// A section of `f` (its whole size) with `protect`.
fn create_section(f: &File, protect: u32, p: &Path) -> SysResult<OwnedHandle> {
    // SAFETY: `f` is a live file handle with the access `protect` needs; no security
    // attributes and no name (null); size 0 = the size of the file.
    let raw =
        unsafe { CreateFileMappingW(f.as_raw_handle(), ptr::null(), protect, 0, 0, ptr::null()) };
    if raw.is_null() {
        return Err(win32_err(last_error(), &p.display().to_string()));
    }
    // SAFETY: CreateFileMappingW succeeded and returned a new handle that nothing else owns.
    Ok(unsafe { OwnedHandle::from_raw_handle(raw) })
}

/// Creates a section of `f` with `protect` and maps all of it with `access`; the section
/// handle is closed before returning (the view keeps the section).
fn map_view(f: &File, protect: u32, access: u32, p: &Path) -> SysResult<View> {
    let what = p.display().to_string();
    let section = create_section(f, protect, p)?;
    // SAFETY: `section` is a live section handle; offset 0 and size 0 map the whole section.
    let addr = unsafe { MapViewOfFile(section.as_raw_handle(), access, 0, 0, 0) };
    if addr.Value.is_null() {
        return Err(win32_err(last_error(), &what));
    }
    Ok(View(addr.Value as usize))
}

// ---------- App hive ----------

/// NT name prefix of every private app hive (`RegLoadAppKeyW`).
const APP_HIVE_PREFIX: &str = r"\REGISTRY\A\";
/// ntstatus.h `STATUS_INSUFFICIENT_RESOURCES`: what `NtSetValueKey` returns for a value over
/// 1,048,572 bytes (`RegSetValueExW`: `ERROR_NO_SYSTEM_RESOURCES`).
const STATUS_INSUFFICIENT_RESOURCES: i32 = 0xC000_009A_u32.cast_signed();

/// A private registry hive in a file inside a [`TestRoot`] (ADR 0009, `docs/09-testing.md`):
/// `RegLoadAppKeyW(…, REG_PROCESS_APPKEY)` needs no admin, is not visible in the global
/// namespace and is unloaded when its last handle closes (also when the process dies).
///
/// It is the [`RegFixture`] of the registry read contract: every write goes through
/// `RegCreateKeyExW` **relative to the hive key** (never `HKEY_CURRENT_USER` or
/// `HKEY_LOCAL_MACHINE`), and every handle a write uses must, by its kernel name
/// (`NtQueryKey(KeyNameInformation)`), lie below the hive key; otherwise the write is refused
/// before any value is set. `Hive::CurrentUser` is the hive's key `HKCU`, `Hive::LocalMachine`
/// its key `HKLM`; app hives apply no WOW64 redirection, so both views name the same key.
pub(super) struct AppHive {
    hive: OwnedKey,
    /// Kernel name of the hive key (`\REGISTRY\A\{…}`).
    name: String,
    /// `None` if a symbolic-link key in this hive can be created and followed, else why not
    /// (probed once at load, outside `HKCU` and `HKLM`).
    no_links: Option<String>,
}

/// Kernel name of an open key, as a fixture error.
fn key_name(key: &OwnedKey, what: &str) -> SysResult<String> {
    reg::key_name(key).map_err(|st| SysError::new(SysErrorKind::Other, what).with_ntstatus(st))
}

impl AppHive {
    /// Loads (creating) the hive file `file`, which must lie inside a [`TestRoot`].
    pub(super) fn load(file: &Path) -> SysResult<Self> {
        let what = format!("app hive {}", file.display());
        let w = wide(file);
        let mut raw: HKEY = ptr::null_mut();
        // SAFETY: `w` is NUL-terminated and outlives the call; `raw` is valid for a write and on
        // success receives a new key handle that `OwnedKey` takes over below.
        let rc =
            unsafe { RegLoadAppKeyW(w.as_ptr(), &mut raw, KEY_ALL_ACCESS, REG_PROCESS_APPKEY, 0) };
        if rc != 0 || raw.is_null() {
            return Err(win32_err(rc, &what));
        }
        // SAFETY: `raw` was just returned by a successful RegLoadAppKeyW; nothing else owns or
        // closes it.
        let hive = unsafe { OwnedKey::from_raw(raw) };
        let name = key_name(&hive, &what)?;
        assert!(
            name.len() > APP_HIVE_PREFIX.len()
                && name.to_ascii_uppercase().starts_with(APP_HIVE_PREFIX),
            "{what}: not an app hive: {name}"
        );
        let mut hive = Self {
            hive,
            name,
            no_links: None,
        };
        hive.create("HKCU", KEY_READ, false)?;
        hive.create("HKLM", KEY_READ, false)?;
        hive.no_links = hive.probe_links().err();
        Ok(hive)
    }

    /// Creates the link `LinkProbe\Link` → `LinkProbe\Target` and opens it (which follows it).
    fn probe_links(&self) -> Result<(), String> {
        let target = r"LinkProbe\Target";
        self.create(target, KEY_READ, false)
            .map_err(|e| format!("probe target: {e} ({:?})", e.win32))?;
        self.make_link(r"LinkProbe\Link", target)
            .map_err(|e| format!("create: {e} ({:?})", e.win32))?;
        self.open_following(r"LinkProbe\Link")
            .map(drop)
            .map_err(|e| format!("follow: {e} ({:?})", e.win32))
    }

    /// Creates `link` (a new key) as a symbolic link to the hive path `target`.
    fn make_link(&self, link: &str, target: &str) -> SysResult<()> {
        let what = format!("app hive link {link} -> {target}");
        let key = self.create(link, KEY_SET_VALUE, true)?;
        // REG_LINK: the target's kernel name, UTF-16 without a terminating NUL.
        let dest = format!(r"{}\{target}", self.name);
        let data: Vec<u8> = dest.encode_utf16().flat_map(u16::to_le_bytes).collect();
        Self::set_raw(&key, "SymbolicLinkValue", REG_LINK, &data, &what)
    }

    /// A [`WinRegistry`] whose hives are this hive's keys `HKCU` and `HKLM` (read handles).
    pub(super) fn registry(&self) -> SysResult<WinRegistry> {
        Ok(WinRegistry::with_roots(
            self.create("HKCU", KEY_READ, false)?,
            self.create("HKLM", KEY_READ, false)?,
        ))
    }

    /// Path of `k` inside the hive.
    fn path_of(k: &RegKey) -> String {
        let hive = match k.hive {
            Hive::CurrentUser => "HKCU",
            Hive::LocalMachine => "HKLM",
        };
        if k.path.is_empty() {
            hive.to_owned()
        } else {
            format!(r"{hive}\{}", k.path)
        }
    }

    /// `key` lies below the hive key (by its kernel name), else an error.
    fn guard(&self, key: &OwnedKey, what: &str) -> SysResult<()> {
        let name = key_name(key, what)?;
        let inside = name
            .get(..self.name.len())
            .is_some_and(|p| p.eq_ignore_ascii_case(&self.name))
            && name[self.name.len()..].starts_with('\\');
        if inside {
            Ok(())
        } else {
            Err(SysError::new(
                SysErrorKind::Other,
                format!(
                    "{what}: handle {name} is outside the app hive {}",
                    self.name
                ),
            ))
        }
    }

    /// Opens or creates the hive path `path` **segment by segment**, each segment relative to
    /// the handle of the previous one (the first relative to the hive key) with
    /// `REG_OPTION_OPEN_LINK`: a symbolic-link key on the way is opened itself, never
    /// followed, so no key is ever created outside the hive (review, 2026-11-04). The final
    /// handle is guarded by its kernel name as well. `link`: the last segment must be new and
    /// becomes a symbolic-link key.
    fn create(&self, path: &str, access: u32, link: bool) -> SysResult<OwnedKey> {
        let what = format!("app hive key {path}");
        let segs: Vec<&str> = path.split('\\').collect();
        let mut parent: Option<OwnedKey> = None;
        for (i, seg) in segs.iter().enumerate() {
            let last = i + 1 == segs.len();
            let (options, rights) = match (last, link) {
                (true, true) => (REG_OPTION_CREATE_LINK, access | KEY_CREATE_LINK),
                (true, false) => (REG_OPTION_OPEN_LINK, access),
                (false, _) => (REG_OPTION_OPEN_LINK, KEY_CREATE_SUB_KEY),
            };
            let base = parent.as_ref().map_or(self.hive.raw(), OwnedKey::raw);
            let w = wide(seg);
            let mut raw: HKEY = ptr::null_mut();
            let mut disposition: u32 = 0;
            // SAFETY: `base` is the hive key or the previous segment's key, both kept alive
            // (`self`, `parent`) until after the call; `w` is NUL-terminated and outlives the
            // call; class and security attributes are null; `raw` and `disposition` are valid
            // for writes, and on success `raw` is a new key handle that `OwnedKey` takes over
            // below.
            let rc = unsafe {
                RegCreateKeyExW(
                    base,
                    w.as_ptr(),
                    0,
                    ptr::null(),
                    options,
                    rights,
                    ptr::null(),
                    &mut raw,
                    &mut disposition,
                )
            };
            if rc != 0 || raw.is_null() {
                return Err(win32_err(rc, &what));
            }
            // SAFETY: `raw` was just returned by a successful RegCreateKeyExW; nothing else
            // owns or closes it.
            let key = unsafe { OwnedKey::from_raw(raw) };
            if last && link && disposition != REG_CREATED_NEW_KEY {
                return Err(SysError::new(
                    SysErrorKind::AlreadyExists,
                    format!("{what}: a link must be a new key"),
                ));
            }
            parent = Some(key);
        }
        let key = parent.ok_or_else(|| SysError::new(SysErrorKind::InvalidPath, &what))?;
        self.guard(&key, &what)?;
        Ok(key)
    }

    /// Opens `path` (relative to the hive key) **following** links, read-only; only for the
    /// link probe.
    fn open_following(&self, path: &str) -> SysResult<OwnedKey> {
        let w = wide(path);
        let mut raw: HKEY = ptr::null_mut();
        // SAFETY: `self.hive` is the open hive key, kept alive by the borrow; `w` is
        // NUL-terminated and outlives the call; `raw` is valid for a write and on success a new
        // key handle that `OwnedKey` takes over below.
        let rc = unsafe { RegOpenKeyExW(self.hive.raw(), w.as_ptr(), 0, KEY_READ, &mut raw) };
        if rc != 0 || raw.is_null() {
            return Err(win32_err(rc, &format!("app hive key {path}")));
        }
        // SAFETY: `raw` was just returned by a successful RegOpenKeyExW; nothing else owns or
        // closes it.
        Ok(unsafe { OwnedKey::from_raw(raw) })
    }

    /// `NtSetValueKey` on a guarded key: stores exactly `kind` and `data`. Not
    /// `RegSetValueExW`, which may extend a string-typed value by a NUL that follows the
    /// caller's buffer in memory (found on Windows 11, 2026-11-04).
    fn set_raw(key: &OwnedKey, name: &str, kind: u32, data: &[u8], what: &str) -> SysResult<()> {
        let units: Vec<u16> = name.encode_utf16().collect();
        let bytes = u16::try_from(units.len() * 2)
            .map_err(|_| SysError::new(SysErrorKind::InvalidPath, what))?;
        let us = UNICODE_STRING {
            Length: bytes,
            MaximumLength: bytes,
            Buffer: units.as_ptr().cast_mut(),
        };
        let len = u32::try_from(data.len())
            .map_err(|_| SysError::new(SysErrorKind::Unsupported, what))?;
        // SAFETY: `key` is an open key with KEY_SET_VALUE, kept alive by the borrow; `us`
        // describes `units` (exactly `bytes` bytes, read only) and `data` is readable for `len`
        // bytes, both outlive the call.
        let status = unsafe { NtSetValueKey(key.raw(), &us, 0, kind, data.as_ptr().cast(), len) };
        if status == 0 {
            Ok(())
        } else {
            Err(SysError::new(SysErrorKind::Other, what).with_ntstatus(status))
        }
    }
}

impl RegFixture for AppHive {
    fn key(&self, k: &RegKey) -> SysResult<()> {
        self.create(&Self::path_of(k), KEY_READ, false).map(drop)
    }

    fn raw(&self, k: &RegKey, name: &str, kind: u32, data: &[u8]) -> SysResult<()> {
        let what = format!("app hive {k} @ {name:?}");
        let key = self.create(&Self::path_of(k), KEY_SET_VALUE, false)?;
        Self::set_raw(&key, name, kind, data, &what)
    }

    fn delete_value(&self, k: &RegKey, name: &str) -> SysResult<()> {
        let what = format!("app hive {k} @ {name:?}");
        let key = self.create(&Self::path_of(k), KEY_SET_VALUE, false)?;
        let w = wide(name);
        // SAFETY: `key` is an open key with KEY_SET_VALUE, kept alive by the borrow; `w` is
        // NUL-terminated and outlives the call.
        let rc = unsafe { RegDeleteValueW(key.raw(), w.as_ptr()) };
        if rc == 0 {
            Ok(())
        } else {
            Err(win32_err(rc, &what))
        }
    }

    fn link(&self, link: &RegKey, target: &RegKey) -> SysResult<bool> {
        if let Some(why) = &self.no_links {
            note(&format!(
                "note: app hive link {link} -> {target}: not available ({why})"
            ));
            return Ok(false);
        }
        self.make_link(&Self::path_of(link), &Self::path_of(target))?;
        Ok(true)
    }

    fn large(&self, k: &RegKey, name: &str, len: usize) -> SysResult<bool> {
        let what = format!("app hive {k} @ {name:?} ({len} bytes)");
        let key = self.create(&Self::path_of(k), KEY_SET_VALUE, false)?;
        match Self::set_raw(&key, name, REG_BINARY, &vec![7; len], &what) {
            Ok(()) => Ok(true),
            // Windows refuses a value over 1,048,572 bytes (found 2026-11-04).
            Err(e) if e.ntstatus == Some(STATUS_INSUFFICIENT_RESOURCES) => Ok(false),
            Err(e) => Err(e),
        }
    }
}

/// A [`TestRoot`] with an [`AppHive`] in it and a [`WinRegistry`] on that hive. Fields drop in
/// declaration order: the registry's and the fixture's handles close (the hive unloads) before
/// the test root removes the hive file.
pub(super) struct HiveRoot {
    pub(super) registry: WinRegistry,
    pub(super) hive: AppHive,
    #[expect(dead_code, reason = "held for its drop, which removes the hive file")]
    root: TestRoot,
}

impl HiveRoot {
    /// `None` when [`TestRoot::new`] skips. Panics if the hive cannot be loaded.
    pub(super) fn new(case: &str) -> Option<Self> {
        let root = TestRoot::new(case)?;
        let file = root.path().join("hive.dat");
        let hive = AppHive::load(&file).unwrap_or_else(|e| panic!("{e}"));
        let registry = hive.registry().unwrap_or_else(|e| panic!("{e}"));
        Some(Self {
            registry,
            hive,
            root,
        })
    }
}

// ---------- OS version ----------

/// The build number `RtlGetVersion` reports: the cross-check of `hw::os`, which reads
/// `CurrentBuildNumber` from the registry (ADR 0015). Banned everywhere else.
pub(super) fn rtl_build_number() -> u32 {
    use windows_sys::Win32::System::SystemInformation::OSVERSIONINFOW;
    let mut info = OSVERSIONINFOW {
        dwOSVersionInfoSize: u32::try_from(size_of::<OSVERSIONINFOW>()).unwrap(),
        ..OSVERSIONINFOW::default()
    };
    #[expect(
        clippy::disallowed_methods,
        reason = "test-only cross-check of hw::os against RtlGetVersion (ADR 0015)"
    )]
    // SAFETY: `info` is a writable, initialised `OSVERSIONINFOW` that lives across the call, and
    // its `dwOSVersionInfoSize` is its own size, so `RtlGetVersion` fills the plain
    // `OSVERSIONINFOW` layout and writes nothing beyond it.
    let status = unsafe { windows_sys::Wdk::System::SystemServices::RtlGetVersion(&raw mut info) };
    assert_eq!(status, 0, "RtlGetVersion: {status:#x}");
    info.dwBuildNumber
}

// ---------- Loaded modules ----------

/// The full path Windows reports for a loaded module (`GetModuleFileNameW`).
pub(super) fn module_path(module: windows_sys::Win32::Foundation::HMODULE) -> PathBuf {
    let mut buf = vec![0u16; 32_768];
    let cap = u32::try_from(buf.len()).unwrap();
    // SAFETY: `module` is a loaded module that is never freed; `buf` is writable for `cap` UTF-16
    // units and lives across the call.
    let n = unsafe {
        windows_sys::Win32::System::LibraryLoader::GetModuleFileNameW(module, buf.as_mut_ptr(), cap)
    };
    let n = usize::try_from(n).unwrap();
    assert!(
        n > 0 && n < buf.len(),
        "GetModuleFileNameW: {}",
        last_error()
    );
    PathBuf::from(OsString::from_wide(&buf[..n]))
}

// ---------- NaiveFs ----------

/// Check-then-use-by-path control implementation (never use outside this test): checks each
/// prefix with `symlink_metadata`, yields, then acts on the full path, which Windows resolves
/// again and follows every junction in it. Every error is reported as `NotFound` (on the write
/// side also `Mismatch` and `AlreadyExists` from its own checks), so the race contracts can
/// only catch it by a leak. Its write side hashes a guarded file by path when the guard opens,
/// writes a temp file by path and renames it with replace (`std::fs::rename`), and deletes by
/// path, each after the pause: the writing race contract must catch it.
#[derive(Debug, Default)]
pub(super) struct NaiveFs;

/// Pause between check and use in [`NaiveFs`], on top of `yield_now`. A flip of the race
/// contract is two renames by path (hundreds of microseconds each on NTFS), so a bare yield
/// leaves a window far shorter than a flip and the harness could never land a swap in it
/// (measured: not caught in 30 s). One millisecond stands for an ordinary preemption between
/// check and use; the harness must catch a window of that size.
const NAIVE_PAUSE: std::time::Duration = std::time::Duration::from_millis(1);

#[derive(Debug)]
struct NaiveDir {
    base: PathBuf,
    /// Volume serial and file ID of `base` when it was opened (a path has no identity later).
    id: (u64, u128),
}

fn naive_err(p: &Path) -> SysError {
    SysError::path(SysErrorKind::NotFound, p)
}

/// Volume serial and file ID of `p` itself (by path, not following a final link).
fn naive_id(p: &Path) -> SysResult<(u64, u128)> {
    let f = open_entry(p, FILE_READ_ATTRIBUTES).map_err(|_| naive_err(p))?;
    // SAFETY: FILE_ID_INFO is plain data; all-zero is a valid value the call overwrites.
    let mut info: FILE_ID_INFO = unsafe { std::mem::zeroed() };
    // SAFETY: `f` is a live handle with FILE_READ_ATTRIBUTES; `info` is a FILE_ID_INFO of the
    // size passed.
    let ok = unsafe {
        GetFileInformationByHandleEx(
            f.as_raw_handle(),
            FileIdInfo,
            ptr::from_mut(&mut info).cast::<c_void>(),
            u32::try_from(size_of::<FILE_ID_INFO>()).unwrap_or(0),
        )
    };
    if ok == 0 {
        return Err(naive_err(p));
    }
    Ok((
        info.VolumeSerialNumber,
        u128::from_le_bytes(info.FileId.Identifier),
    ))
}

fn naive_meta(p: &Path) -> SysResult<Metadata> {
    let m = std::fs::symlink_metadata(p).map_err(|_| naive_err(p))?;
    let a = m.file_attributes();
    let kind = if a & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        EntryKind::Reparse
    } else if m.is_dir() {
        EntryKind::Dir
    } else {
        EntryKind::File
    };
    Ok(Metadata {
        kind,
        len: if kind == EntryKind::File { m.len() } else { 0 },
        attrs: Attrs::default(),
        links: Some(1),
        file_id: naive_id(p)?.1,
        reparse: (kind == EntryKind::Reparse).then_some(ReparseInfo {
            tag: tag::MOUNT_POINT,
            surrogate: true,
            target: None,
        }),
        restricted: false,
    })
}

impl NaiveDir {
    /// The naive check: no prefix is a reparse point *right now*; then yield.
    fn check(&self, p: Option<&RelPath>) -> SysResult<PathBuf> {
        let mut cur = self.base.clone();
        for seg in p.into_iter().flat_map(RelPath::segments) {
            cur.push(seg);
            let m = std::fs::symlink_metadata(&cur).map_err(|_| naive_err(&cur))?;
            if m.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                return Err(SysError::path(SysErrorKind::ReparsePoint, &cur));
            }
        }
        thread::yield_now();
        thread::sleep(NAIVE_PAUSE);
        Ok(cur)
    }
}

impl Fs for NaiveFs {
    fn open_dir(&self, abs: &Path) -> SysResult<Box<dyn Dir + '_>> {
        if !std::fs::metadata(abs).map_err(|_| naive_err(abs))?.is_dir() {
            return Err(SysError::path(SysErrorKind::InvalidPath, abs));
        }
        Ok(Box::new(NaiveDir {
            base: abs.to_path_buf(),
            id: naive_id(abs)?,
        }))
    }
    /// Same as `open_dir`: the writing race contract writes through it.
    fn open_dir_write(&self, abs: &Path, _: &WriteCap) -> SysResult<Box<dyn DirWrite + '_>> {
        if !std::fs::metadata(abs).map_err(|_| naive_err(abs))?.is_dir() {
            return Err(SysError::path(SysErrorKind::InvalidPath, abs));
        }
        Ok(Box::new(NaiveDir {
            base: abs.to_path_buf(),
            id: naive_id(abs)?,
        }))
    }
}

/// The naive pause between a check and the act (see [`NAIVE_PAUSE`]).
fn naive_pause() {
    thread::yield_now();
    thread::sleep(NAIVE_PAUSE);
}

fn naive_sha(data: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    sha2::Sha256::digest(data).into()
}

fn naive_mismatch(p: &Path) -> SysError {
    SysError::path(SysErrorKind::Mismatch, p)
}

/// Reads `src` and checks it against `new` (hash and bound), like the real sequence does.
fn naive_source(src: &mut dyn std::io::Read, new: &NewFile, p: &Path) -> SysResult<Vec<u8>> {
    let mut data = Vec::new();
    src.read_to_end(&mut data).map_err(|_| naive_err(p))?;
    if u64::try_from(data.len()).unwrap_or(u64::MAX) > new.max_len {
        return Err(SysError::too_large(p.display().to_string(), new.max_len));
    }
    if naive_sha(&data) != new.sha256 {
        return Err(naive_mismatch(p));
    }
    Ok(data)
}

/// The naive write: the temp file next to the target by path, then `std::fs::rename`, which
/// replaces an existing target (`MOVEFILE_REPLACE_EXISTING`).
fn naive_put(path: &Path, tmp: &str, data: &[u8]) -> SysResult<Written> {
    let tmp = path.with_file_name(tmp);
    std::fs::write(&tmp, data).map_err(|_| naive_err(&tmp))?;
    std::fs::rename(&tmp, path).map_err(|_| naive_err(path))?;
    Ok(Written {
        sha256: naive_sha(data),
        len: u64::try_from(data.len()).unwrap_or(u64::MAX),
        file_id: naive_id(path)?.1,
    })
}

/// The naive guard: the hash is taken by path when it is opened; `replace` and `delete` act
/// by path after the pause, on whatever is at the name then.
#[derive(Debug)]
struct NaiveGuard {
    path: PathBuf,
    hash: [u8; 32],
}

impl FileGuard for NaiveGuard {
    fn metadata(&self) -> SysResult<Metadata> {
        naive_meta(&self.path)
    }

    fn sha256(&mut self) -> SysResult<[u8; 32]> {
        Ok(self.hash)
    }

    fn reader(&mut self) -> SysResult<Box<dyn std::io::Read + '_>> {
        Ok(Box::new(
            File::open(&self.path).map_err(|_| naive_err(&self.path))?,
        ))
    }

    fn users(&self) -> SysResult<Vec<u32>> {
        Err(SysError::path(SysErrorKind::Unsupported, &self.path))
    }

    fn replace(
        self: Box<Self>,
        expected: &[u8; 32],
        src: &mut dyn std::io::Read,
        new: &NewFile,
    ) -> SysResult<Replaced> {
        if self.hash != *expected {
            return Err(naive_mismatch(&self.path));
        }
        let data = naive_source(src, new, &self.path)?;
        naive_pause();
        Ok(Replaced {
            new: naive_put(&self.path, new.tmp.as_str(), &data)?,
            old_left: None,
        })
    }

    fn delete(self: Box<Self>, expected: &[u8; 32]) -> SysResult<()> {
        if self.hash != *expected {
            return Err(naive_mismatch(&self.path));
        }
        naive_pause();
        std::fs::remove_file(&self.path).map_err(|_| naive_err(&self.path))
    }

    fn rename_to(self: Box<Self>, name: &RelPath) -> SysResult<()> {
        naive_pause();
        let to = self.path.with_file_name(name.as_str());
        std::fs::rename(&self.path, &to).map_err(|_| naive_err(&to))
    }
}

/// A naive lock: a file opened (or created) by path with share 0.
#[derive(Debug)]
struct NaiveLock(#[expect(dead_code, reason = "held for its drop")] File);

impl FileLock for NaiveLock {}

impl DirWrite for NaiveDir {
    fn open_dir_write(&self, p: &RelPath) -> SysResult<Box<dyn DirWrite + '_>> {
        let full = self.check(Some(p))?;
        let id = naive_id(&full)?;
        Ok(Box::new(NaiveDir { base: full, id }))
    }

    fn guard(&self, name: &RelPath) -> SysResult<Box<dyn FileGuard + '_>> {
        let path = self.check(Some(name))?;
        let data = std::fs::read(&path).map_err(|_| naive_err(&path))?;
        Ok(Box::new(NaiveGuard {
            hash: naive_sha(&data),
            path,
        }))
    }

    fn create_new(
        &self,
        name: &RelPath,
        src: &mut dyn std::io::Read,
        new: &NewFile,
    ) -> SysResult<Written> {
        let path = self.base.join(name.as_str());
        if std::fs::symlink_metadata(&path).is_ok() {
            return Err(SysError::path(SysErrorKind::AlreadyExists, &path));
        }
        let data = naive_source(src, new, &path)?;
        naive_pause();
        naive_put(&path, new.tmp.as_str(), &data)
    }

    fn create_dir(&self, name: &RelPath) -> SysResult<u128> {
        let path = self.base.join(name.as_str());
        naive_pause();
        std::fs::create_dir(&path).map_err(|_| naive_err(&path))?;
        Ok(naive_id(&path)?.1)
    }

    fn remove_dir(&self, name: &RelPath, _expected_id: u128) -> SysResult<()> {
        let path = self.check(Some(name))?;
        std::fs::remove_dir(&path).map_err(|_| naive_err(&path))
    }

    fn flush(&self) -> SysResult<()> {
        Ok(())
    }

    fn lock(&self, name: &RelPath) -> SysResult<Box<dyn FileLock + '_>> {
        let path = self.base.join(name.as_str());
        naive_pause();
        let f = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .share_mode(0)
            .open(&path)
            .map_err(|_| naive_err(&path))?;
        Ok(Box::new(NaiveLock(f)))
    }
}

impl Dir for NaiveDir {
    fn info(&self) -> SysResult<RootInfo> {
        let (volume_serial, file_id) = self.id;
        Ok(RootInfo {
            final_path: self.base.clone(),
            volume_serial,
            file_id,
            user_writable: true,
            case_sensitive: false,
            volume_path: String::new(),
            fs_kind: FsKind::Ntfs,
            supports_posix_rename: true,
        })
    }

    fn open_dir(&self, p: &RelPath) -> SysResult<Box<dyn Dir + '_>> {
        let full = self.check(Some(p))?;
        let id = naive_id(&full)?;
        Ok(Box::new(NaiveDir { base: full, id }))
    }

    fn metadata(&self, p: &RelPath) -> SysResult<Option<Metadata>> {
        match self.check(Some(p)) {
            Ok(full) => Ok(naive_meta(&full).ok()),
            Err(e) if e.kind == SysErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn open_read(&self, p: &RelPath) -> SysResult<Box<dyn ReadSeek + '_>> {
        let full = self.check(Some(p))?;
        Ok(Box::new(File::open(&full).map_err(|_| naive_err(&full))?))
    }

    fn read_dir_limited(&self, p: Option<&RelPath>, max: usize) -> SysResult<Vec<DirEntry>> {
        let full = self.check(p)?;
        let mut out = Vec::new();
        for e in std::fs::read_dir(&full).map_err(|_| naive_err(&full))? {
            let e = e.map_err(|_| naive_err(&full))?;
            if out.len() == max {
                return Err(SysError::path(SysErrorKind::TooLarge, &full));
            }
            let path = e.path();
            out.push(DirEntry {
                name: e.file_name().to_string_lossy().into_owned(),
                meta: naive_meta(&path)?,
            });
        }
        Ok(out)
    }

    fn users(&self, p: &RelPath) -> SysResult<Vec<u32>> {
        Err(SysError::new(SysErrorKind::Unsupported, p.as_str()))
    }
}

/// Review L7: a root left behind by a dead process, with a restricted file and a restricted
/// directory in it, is reset and removed by the next `TestRoot::new`; a root of the current
/// process is not.
#[test]
fn stale_roots_of_dead_processes_are_removed() {
    // Same gate as every TestRoot (safeguard 4).
    let Some(own) = TestRoot::new("stale-own") else {
        return;
    };
    let target = std::fs::canonicalize(target_dir()).unwrap();
    let base = target.join("rerun-fs-contract");
    // Populate under a name clean_stale ignores, then give it a dead PID.
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let building = base.join(format!("building-{nanos}"));
    std::fs::create_dir(&building).unwrap();
    let fx = WinFixture::new(plain(&building), plain(&base));
    fx.file(&plain(&building).join("locked.txt"), b"x").unwrap();
    fx.file(&plain(&building).join(r"dir\inner.txt"), b"y")
        .unwrap();
    fx.junction(&plain(&building).join("j"), own.path())
        .unwrap();
    assert!(fx.restricted(&plain(&building).join("locked.txt")).unwrap());
    assert!(fx.restricted(&plain(&building).join("dir")).unwrap());
    // Drop the undo records without restoring: the tree stays restricted, like after a crash.
    std::mem::take(&mut *fx.undo.lock().unwrap());
    // 0xFFFF_FFF0 is never a valid PID (PIDs are multiples of 4 below that).
    let stale = base.join(format!("4294967280-{nanos}-stale"));
    std::fs::rename(&building, &stale).unwrap();
    clean_stale(&target, &base);
    assert!(!stale.exists(), "{} was not removed", stale.display());
    assert!(own.path().exists(), "the own root was removed");
}
