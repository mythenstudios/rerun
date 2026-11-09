//! The private key file gets a protected DACL with one ACE: full access for the current user
//! (ADR 0024). Nothing is inherited from the folder, so a key generated into a shared folder is
//! not readable by other accounts or groups. Set on the handle of the new, still empty file,
//! before the key is written, then read back.

#![allow(
    unsafe_code,
    reason = "Win32 security calls on one file handle of the curator tool (ADR 0024)"
)]

use std::ffi::c_void;
use std::fs::File;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::ptr;

use windows_sys::Win32::Foundation::{GetLastError, HANDLE, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    GetSecurityInfo, SE_FILE_OBJECT, SetSecurityInfo,
};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACL, ACL_REVISION, ACL_SIZE_INFORMATION, AclSizeInformation,
    AddAccessAllowedAce, DACL_SECURITY_INFORMATION, GetAclInformation, GetLengthSid,
    GetSecurityDescriptorControl, GetTokenInformation, PROTECTED_DACL_SECURITY_INFORMATION,
    SE_DACL_PROTECTED, TOKEN_QUERY, TOKEN_USER, TokenUser,
};
use windows_sys::Win32::Storage::FileSystem::FILE_ALL_ACCESS;
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

/// The access a key file is opened with: write, change the DACL, read it back.
pub const KEY_FILE_ACCESS: u32 = 0x4000_0000 /* GENERIC_WRITE */
    | 0x0004_0000 /* WRITE_DAC */
    | 0x0002_0000 /* READ_CONTROL */;

fn last(what: &str) -> String {
    // SAFETY: reads the calling thread's last-error value; no preconditions.
    let code = unsafe { GetLastError() };
    format!("{what} failed (Win32 error {code})")
}

/// `TOKEN_USER` of the process token in an 8-byte aligned buffer (the SID lives inside).
fn token_user() -> Result<Vec<u64>, String> {
    let mut raw: HANDLE = ptr::null_mut();
    // SAFETY: no preconditions; returns the pseudo handle of this process.
    let process = unsafe { GetCurrentProcess() };
    // SAFETY: `process` is the current process's pseudo handle; `raw` is valid for a write.
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut raw) } == 0 {
        return Err(last("OpenProcessToken"));
    }
    // SAFETY: `raw` was just returned by a successful OpenProcessToken and is owned here only.
    let token = unsafe { OwnedHandle::from_raw_handle(raw) };
    let mut needed = 0u32;
    // SAFETY: size query: a null buffer with length 0 is allowed; `needed` is valid for a write.
    unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            ptr::null_mut(),
            0,
            &mut needed,
        )
    };
    let mut buf = vec![0u64; (needed as usize).div_ceil(8).max(8)];
    let len = u32::try_from(buf.len() * 8).map_err(|e| e.to_string())?;
    // SAFETY: `buf` is valid for writes of `len` bytes and 8-byte aligned (TOKEN_USER holds a
    // pointer); `needed` is valid for a write.
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
        return Err(last("GetTokenInformation"));
    }
    Ok(buf)
}

/// Replaces the DACL of `f` (opened with [`KEY_FILE_ACCESS`]) by a protected DACL with one
/// ACE granting the current user full access, then checks that it is so.
pub fn owner_only(f: &File) -> Result<(), String> {
    let user = token_user()?;
    // SAFETY: GetTokenInformation(TokenUser) filled `user` with a TOKEN_USER at offset 0; the
    // buffer is 8-byte aligned and at least size_of::<TOKEN_USER>() bytes.
    let sid = unsafe { (*user.as_ptr().cast::<TOKEN_USER>()).User.Sid };
    // SAFETY: `sid` points into `user`, a valid SID from the token query.
    let sid_len = unsafe { GetLengthSid(sid) } as usize;
    let len = size_of::<ACL>() + size_of::<ACCESS_ALLOWED_ACE>() - 4 + sid_len;
    let mut acl_buf = vec![0u64; len.div_ceil(8)];
    let len32 = u32::try_from(acl_buf.len() * 8).map_err(|e| e.to_string())?;
    let acl = acl_buf.as_mut_ptr().cast::<ACL>();
    // SAFETY: `acl` points to `len32` writable, 8-byte aligned bytes owned by `acl_buf`.
    if unsafe { windows_sys::Win32::Security::InitializeAcl(acl, len32, ACL_REVISION) } == 0 {
        return Err(last("InitializeAcl"));
    }
    // SAFETY: `acl` was initialized above with room for one ACE with this SID; `sid` is valid.
    if unsafe { AddAccessAllowedAce(acl, ACL_REVISION, FILE_ALL_ACCESS, sid) } == 0 {
        return Err(last("AddAccessAllowedAce"));
    }
    // SAFETY: `f` is a live handle opened with WRITE_DAC; `acl` is a valid ACL alive for the
    // call; owner, group and SACL are not changed (null).
    let rc = unsafe {
        SetSecurityInfo(
            f.as_raw_handle(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            acl,
            ptr::null(),
        )
    };
    if rc != 0 {
        return Err(format!("SetSecurityInfo failed (Win32 error {rc})"));
    }
    check(f)
}

/// The DACL of `f` is protected and holds exactly one ACE.
fn check(f: &File) -> Result<(), String> {
    let mut dacl: *mut ACL = ptr::null_mut();
    let mut sd: *mut c_void = ptr::null_mut();
    // SAFETY: `f` is a live handle opened with READ_CONTROL; the out pointers are valid for
    // writes; the descriptor is freed with LocalFree below.
    let rc = unsafe {
        GetSecurityInfo(
            f.as_raw_handle(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            &mut dacl,
            ptr::null_mut(),
            &mut sd,
        )
    };
    if rc != 0 {
        return Err(format!("GetSecurityInfo failed (Win32 error {rc})"));
    }
    let mut control = 0u16;
    let mut revision = 0u32;
    // SAFETY: `sd` is the descriptor GetSecurityInfo returned; the out values are valid.
    let ok_control = unsafe { GetSecurityDescriptorControl(sd, &mut control, &mut revision) } != 0;
    let mut info = ACL_SIZE_INFORMATION {
        AceCount: 0,
        AclBytesInUse: 0,
        AclBytesFree: 0,
    };
    let ok_info = !dacl.is_null()
        // SAFETY: `dacl` points into `sd` (alive until LocalFree); `info` is a writable
        // ACL_SIZE_INFORMATION of the size passed.
        && unsafe {
            GetAclInformation(
                dacl,
                ptr::from_mut(&mut info).cast::<c_void>(),
                u32::try_from(size_of::<ACL_SIZE_INFORMATION>()).unwrap_or(0),
                AclSizeInformation,
            )
        } != 0;
    // SAFETY: `sd` was allocated by GetSecurityInfo with LocalAlloc and is not used afterwards.
    unsafe { LocalFree(sd) };
    if ok_control && ok_info && control & SE_DACL_PROTECTED != 0 && info.AceCount == 1 {
        Ok(())
    } else {
        Err("the key file's DACL is not owner-only after setting it".into())
    }
}

#[cfg(test)]
mod tests {
    use std::os::windows::fs::OpenOptionsExt;

    use super::{KEY_FILE_ACCESS, check, owner_only};

    /// A temp file (not a system change): its inherited DACL is not protected; after
    /// `owner_only` it is protected with one ACE.
    #[test]
    fn a_new_file_gets_an_owner_only_dacl() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("rerun-workbench-acl-{}.tmp", std::process::id()));
        let f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .access_mode(KEY_FILE_ACCESS)
            .open(&path)
            .unwrap();
        let before = check(&f);
        let after = owner_only(&f);
        drop(f);
        let _ = std::fs::remove_file(&path);
        assert!(before.is_err(), "an inherited DACL counted as owner-only");
        after.unwrap();
    }
}
