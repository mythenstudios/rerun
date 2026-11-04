//! Test fixtures for the file system contracts against real Windows (`docs/09-testing.md`).
//!
//! - [`TestRoot`]: a fresh directory `target/rerun-fs-contract/<pid>-<nanos>-<case>` with the
//!   safeguards of `09-testing.md` (inside the canonical `target/`, local fixed drive, no
//!   reparse point or cloud attribute on any ancestor, skipped locally when elevated). Drop
//!   undoes what the fixture changed outside the tree (mount points, drive substitutions,
//!   restricted DACLs), re-checks the safeguards and only then removes the tree.
//! - [`WinFixture`]: the [`FsFixture`] for `sys::win`, made of `std::fs` and raw Win32 calls
//!   (junctions via `FSCTL_SET_REPARSE_POINT`, no admin, no `cmd`). Fixtures that change the
//!   machine beyond the test root (mount point, `subst`, 8.3 short names) run only on GitHub
//!   runners (`GITHUB_ACTIONS=true`) and report "not available" everywhere else.
//! - [`NaiveFs`]: a deliberately unsafe check-then-use-by-path `Fs` (check each prefix with
//!   `symlink_metadata`, yield, then act on the full path). The race contract must catch it.
//!
//! Path-based Win32 and `std::fs` calls are the point of this module (they set the scene the
//! handle-based `sys::win` has to survive), hence the module-wide `disallowed_methods`
//! exception. Test code only (`cfg(all(test, windows))`).

#![expect(
    clippy::disallowed_methods,
    reason = "test fixture: sets up and removes the contract tree under target/ by path \
              (std::fs, MoveFileExW, CreateSymbolicLinkW, SetVolumeMountPointW, \
              DefineDosDeviceW), and NaiveFs is a path-based control implementation"
)]
#![allow(
    unsafe_code,
    reason = "test-only FFI (junction buffer, DACLs, mount points, subst, short names, \
              file IDs); every block has a SAFETY comment"
)]

use std::ffi::c_void;
use std::fs::{File, OpenOptions};
use std::io::Write as _;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};
use std::{ptr, thread};

use windows_sys::Win32::Foundation::{
    ERROR_NOT_ALL_ASSIGNED, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE, LUID,
};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACL, ACL_REVISION, AddAccessAllowedAce, AddAccessDeniedAce,
    AdjustTokenPrivileges, DACL_SECURITY_INFORMATION, GetLengthSid, GetTokenInformation,
    ImpersonateSelf, InitializeAcl, InitializeSecurityDescriptor, LUID_AND_ATTRIBUTES,
    LookupPrivilegeValueW, PROTECTED_DACL_SECURITY_INFORMATION, RevertToSelf, SE_DACL_PROTECTED,
    SE_PRIVILEGE_ENABLED, SE_RESTORE_NAME, SECURITY_DESCRIPTOR, SecurityImpersonation,
    SetKernelObjectSecurity, SetSecurityDescriptorControl, SetSecurityDescriptorDacl,
    TOKEN_ADJUST_PRIVILEGES, TOKEN_ELEVATION, TOKEN_PRIVILEGES, TOKEN_QUERY, TOKEN_USER,
    TokenElevation, TokenUser,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateSymbolicLinkW, DDD_EXACT_MATCH_ON_REMOVE, DDD_REMOVE_DEFINITION, DELETE,
    DefineDosDeviceW, DeleteVolumeMountPointW, FILE_ALL_ACCESS, FILE_ATTRIBUTE_OFFLINE,
    FILE_ATTRIBUTE_PINNED, FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS, FILE_ATTRIBUTE_RECALL_ON_OPEN,
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_UNPINNED, FILE_CASE_SENSITIVE_INFO,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_ID_INFO, FILE_READ_ATTRIBUTES,
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA,
    FileCaseSensitiveInfo, FileIdInfo, FindFirstVolumeW, FindNextVolumeW, FindVolumeClose,
    GetDriveTypeW, GetFileInformationByHandleEx, GetLogicalDrives, GetVolumeInformationW,
    GetVolumeNameForVolumeMountPointW, GetVolumePathNamesForVolumeNameW, MoveFileExW, READ_CONTROL,
    SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE, SYMBOLIC_LINK_FLAG_DIRECTORY,
    SetFileInformationByHandle, SetFileShortNameW, SetVolumeMountPointW, WRITE_DAC,
};
use windows_sys::Win32::System::IO::DeviceIoControl;
use windows_sys::Win32::System::Ioctl::{FSCTL_SET_EXTERNAL_BACKING, FSCTL_SET_REPARSE_POINT};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentThread, OpenProcessToken, OpenThreadToken,
};

use super::status::kind_of_win32;
use crate::path::RelPath;
use crate::sys::contract::FsFixture;
use crate::sys::fs::{
    Attrs, Dir, DirEntry, EntryKind, Fs, FsKind, Metadata, ReadSeek, ReparseInfo, RootInfo, tag,
};
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

/// Running on a GitHub-hosted runner (ephemeral VM, admin).
pub(super) fn ci() -> bool {
    std::env::var("GITHUB_ACTIONS").is_ok_and(|v| v == "true")
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
fn target_dir() -> PathBuf {
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
    /// `None` (with a note) when the process is elevated outside GitHub Actions (safeguard 4).
    /// Panics if a safeguard fails.
    pub(super) fn new(case: &str) -> Option<Self> {
        if is_elevated() && !ci() {
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
        Some(Self {
            path: plain(&canon),
            target,
            fx: WinFixture::new(),
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

/// [`FsFixture`] for `sys::win`. See the module docs.
#[derive(Debug, Default)]
pub(super) struct WinFixture {
    undo: Mutex<Vec<Undo>>,
}

impl WinFixture {
    fn new() -> Self {
        Self::default()
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

    fn parents(&self, p: &Path) -> SysResult<()> {
        self.refuse_mounted(p)?;
        match p.parent() {
            Some(parent) => std::fs::create_dir_all(parent).map_err(|e| io_err(&e, parent)),
            None => Ok(()),
        }
    }

    fn symlink(&self, link: &Path, target: &Path, flags: u32) -> SysResult<bool> {
        self.parents(link)?;
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
        self.refuse_mounted(p)?;
        std::fs::create_dir_all(p).map_err(|e| io_err(&e, p))
    }

    fn file(&self, p: &Path, data: &[u8]) -> SysResult<()> {
        self.parents(p)?;
        std::fs::write(p, data).map_err(|e| io_err(&e, p))
    }

    /// `FSCTL_SET_REPARSE_POINT` with a mount point buffer on a new empty directory: no admin
    /// and no `mklink` needed.
    fn junction(&self, link: &Path, target: &Path) -> SysResult<()> {
        self.parents(link)?;
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
        self.parents(new)?;
        std::fs::hard_link(existing, new).map_err(|e| io_err(&e, new))
    }

    /// `MoveFileExW` without `MOVEFILE_REPLACE_EXISTING`: never overwrites; renames a link
    /// itself, never its target.
    fn rename(&self, from: &Path, to: &Path) -> SysResult<()> {
        self.refuse_mounted(to)?;
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
        if !ci() {
            return Ok(false);
        }
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
        if !ci() {
            return Ok(None);
        }
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
        if !ci() {
            return Ok(false);
        }
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
        self.refuse_mounted(p)?;
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
}

// ---------- NaiveFs ----------

/// Check-then-use-by-path control implementation (never use outside this test): checks each
/// prefix with `symlink_metadata`, yields, then acts on the full path, which Windows resolves
/// again and follows every junction in it. Every error is reported as `NotFound`, so the race
/// contract can only catch it by a leak.
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

    fn read_dir(&self, p: Option<&RelPath>) -> SysResult<Vec<DirEntry>> {
        let full = self.check(p)?;
        let mut out = Vec::new();
        for e in std::fs::read_dir(&full).map_err(|_| naive_err(&full))? {
            let e = e.map_err(|_| naive_err(&full))?;
            let path = e.path();
            out.push(DirEntry {
                name: e.file_name().to_string_lossy().into_owned(),
                meta: naive_meta(&path)?,
            });
        }
        Ok(out)
    }

    fn create_new(&self, p: &RelPath, _: &[u8]) -> SysResult<()> {
        Err(SysError::new(SysErrorKind::Unsupported, p.as_str()))
    }
    fn replace(&self, p: &RelPath, _: &[u8], _: &str) -> SysResult<()> {
        Err(SysError::new(SysErrorKind::Unsupported, p.as_str()))
    }
    fn create_dir(&self, p: &RelPath) -> SysResult<()> {
        Err(SysError::new(SysErrorKind::Unsupported, p.as_str()))
    }
    fn remove_file(&self, p: &RelPath) -> SysResult<()> {
        Err(SysError::new(SysErrorKind::Unsupported, p.as_str()))
    }
    fn remove_dir(&self, p: &RelPath) -> SysResult<()> {
        Err(SysError::new(SysErrorKind::Unsupported, p.as_str()))
    }
    fn rename(&self, p: &RelPath, _: &RelPath) -> SysResult<()> {
        Err(SysError::new(SysErrorKind::Unsupported, p.as_str()))
    }
    fn set_readonly(&self, p: &RelPath, _: bool) -> SysResult<()> {
        Err(SysError::new(SysErrorKind::Unsupported, p.as_str()))
    }
}
