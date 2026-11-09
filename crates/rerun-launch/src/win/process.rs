//! What `watch` (P3-4) reads about processes: the Toolhelp32 snapshot (names only, a
//! pre-filter), `OpenProcess` (its one call site in Rerun's production code, banned elsewhere
//! in `clippy.toml`), and what an opened handle reports: the image path, the creation time
//! and the raw token facts (user SID, session, integrity RID; `run::watch::trust` compares
//! them, A3). Nothing here changes a process; the setters are in `win::launch`.
//!
//! Rights (W7): every open asks for `PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE` and only
//! what the profile sets besides ([`rights`]); handles are never inheritable.

use std::os::windows::io::{AsRawHandle, BorrowedHandle, OwnedHandle};
use std::ptr;

use windows_sys::Win32::Foundation::{
    ERROR_BUFFER_OVERFLOW, ERROR_INSUFFICIENT_BUFFER, ERROR_NO_MORE_FILES, FILETIME, HANDLE,
    INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Security::{
    GetTokenInformation, SID_AND_ATTRIBUTES, TOKEN_INFORMATION_CLASS, TOKEN_QUERY,
    TokenIntegrityLevel, TokenSessionId, TokenUser,
};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetProcessTimes, OpenProcess, OpenProcessToken, PROCESS_NAME_WIN32,
    PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SET_INFORMATION, PROCESS_SET_LIMITED_INFORMATION,
    PROCESS_SET_QUOTA, PROCESS_SYNCHRONIZE, PROCESS_TERMINATE, QueryFullProcessImageNameW,
};

use super::launch::{self, Proc, Target};
use super::{last_error, token_info};
use crate::os::{Access, Facts, Listed, MAX_LISTED, Own, Token};

/// winerror.h `ERROR_INVALID_DATA`: a token answer that does not hold the SID it should.
const ERROR_INVALID_DATA: u32 = 13;
/// Buffer of `QueryFullProcessImageNameW` in UTF-16 units (the longest Win32 path plus NUL).
const IMAGE_UNITS: usize = 32_768;
/// Largest `TokenUser` / `TokenIntegrityLevel` answer accepted (a SID is at most 68 bytes).
const MAX_TOKEN_BYTES: usize = 1_024;
/// winnt.h `SID_MAX_SUB_AUTHORITIES`.
const SID_MAX_SUB_AUTHORITIES: u8 = 15;

/// The access mask of [`open`] (W7): query and wait always; job membership needs
/// `PROCESS_SET_QUOTA | PROCESS_TERMINATE` (`AssignProcessToJobObject`; `TerminateProcess` is
/// never called on a target, A2), default CPU Sets `PROCESS_SET_LIMITED_INFORMATION`, the
/// priority class `PROCESS_SET_INFORMATION`.
pub(crate) fn rights(access: Access) -> u32 {
    let mut r = PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE;
    if access.job {
        r |= PROCESS_SET_QUOTA | PROCESS_TERMINATE;
    }
    if access.cpu_sets {
        r |= PROCESS_SET_LIMITED_INFORMATION;
    }
    if access.priority {
        r |= PROCESS_SET_INFORMATION;
    }
    r
}

/// `OpenProcess(rights(access), FALSE, pid)`: a [`Target`] that owns the handle. The Win32
/// error otherwise (87 for a PID no process has, 5 for a process that refuses the rights).
pub(crate) fn open(pid: u32, access: Access) -> Result<Target, u32> {
    #[expect(
        clippy::disallowed_methods,
        reason = "rerun-launch's one OpenProcess call site: watch opens a candidate (ADR 0022 \
                  amendment P3-4, W7)"
    )]
    // SAFETY: no pointers; `bInheritHandle` FALSE; the call returns a new handle or null.
    let raw = unsafe { OpenProcess(rights(access), 0, pid) };
    // SAFETY: `raw` was just returned by OpenProcess (null on failure); nothing else owns it.
    let process = unsafe { launch::own(raw) }.ok_or_else(last_error)?;
    Ok(Target::opened(process))
}

/// One Toolhelp32 snapshot of the processes: PID and `szExeFile` (up to its NUL) of each, at
/// most [`MAX_LISTED`] (more: `ERROR_BUFFER_OVERFLOW` for this poll).
pub(crate) fn snapshot() -> Result<Vec<Listed>, u32> {
    // SAFETY: documented flags; the process ID is ignored for TH32CS_SNAPPROCESS; no pointers.
    let raw = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if raw == INVALID_HANDLE_VALUE {
        return Err(last_error());
    }
    // SAFETY: `raw` is not INVALID_HANDLE_VALUE, so it is a new snapshot handle (or null, which
    // `own` turns into `None`); nothing else owns it.
    let snap = unsafe { launch::own(raw) }.ok_or_else(last_error)?;
    let mut entry = PROCESSENTRY32W {
        dwSize: u32::try_from(size_of::<PROCESSENTRY32W>()).unwrap_or(0),
        ..PROCESSENTRY32W::default()
    };
    let mut list = Vec::new();
    // SAFETY: `snap` is a live snapshot handle; `entry` is a writable PROCESSENTRY32W whose
    // `dwSize` is its size.
    let mut ok = unsafe { Process32FirstW(snap.as_raw_handle(), &mut entry) };
    while ok != 0 {
        if list.len() == MAX_LISTED {
            return Err(ERROR_BUFFER_OVERFLOW);
        }
        let name = &entry.szExeFile;
        let len = name.iter().position(|&u| u == 0).unwrap_or(name.len());
        list.push(Listed {
            pid: entry.th32ProcessID,
            name: name.get(..len).unwrap_or_default().to_vec(),
        });
        // SAFETY: as for Process32FirstW.
        ok = unsafe { Process32NextW(snap.as_raw_handle(), &mut entry) };
    }
    let code = last_error();
    if code != ERROR_NO_MORE_FILES {
        return Err(code);
    }
    Ok(list)
}

/// This process, as a borrowed pseudo handle.
fn current_process() -> BorrowedHandle<'static> {
    // SAFETY: no arguments; returns the current-process pseudo handle.
    let raw = unsafe { GetCurrentProcess() };
    // SAFETY: the pseudo handle (-1) is valid for the whole life of the process and needs no
    // closing; `BorrowedHandle` allows -1 ("sometimes a valid handle value").
    unsafe { BorrowedHandle::borrow_raw(raw) }
}

/// `GetProcessTimes`: the creation time (FILETIME as a `u64`).
fn created(process: BorrowedHandle<'_>) -> Result<u64, u32> {
    let mut times = [FILETIME::default(); 4];
    let [creation, exit, kernel, user] = &mut times;
    // SAFETY: `process` is a live process handle with PROCESS_QUERY_LIMITED_INFORMATION (or
    // the pseudo handle), kept alive by the borrow; the four FILETIMEs are valid for a write.
    let ok = unsafe { GetProcessTimes(process.as_raw_handle(), creation, exit, kernel, user) };
    if ok == 0 {
        return Err(last_error());
    }
    Ok((u64::from(creation.dwHighDateTime) << 32) | u64::from(creation.dwLowDateTime))
}

/// `QueryFullProcessImageNameW(PROCESS_NAME_WIN32)`: the image's Win32 path.
fn image(process: BorrowedHandle<'_>) -> Result<Vec<u16>, u32> {
    let mut buf = vec![0u16; IMAGE_UNITS];
    let mut size = u32::try_from(IMAGE_UNITS).unwrap_or(0);
    #[expect(
        clippy::disallowed_methods,
        reason = "rerun-launch's one QueryFullProcessImageNameW call site: the watch target's \
                  image (ADR 0022 amendment P3-4)"
    )]
    // SAFETY: `process` is a live process handle with PROCESS_QUERY_LIMITED_INFORMATION, kept
    // alive by the borrow; `buf` is a writable buffer of `size` units; `size` is valid for a
    // read and a write.
    let ok = unsafe {
        QueryFullProcessImageNameW(
            process.as_raw_handle(),
            PROCESS_NAME_WIN32,
            buf.as_mut_ptr(),
            &mut size,
        )
    };
    if ok == 0 {
        return Err(last_error());
    }
    // On success `size` is the length without the NUL, below the buffer's.
    buf.truncate(usize::try_from(size).unwrap_or(0).min(IMAGE_UNITS - 1));
    Ok(buf)
}

/// `OpenProcessToken(process, TOKEN_QUERY)`.
fn token_of(process: BorrowedHandle<'_>) -> Result<OwnedHandle, u32> {
    let mut raw: HANDLE = ptr::null_mut();
    // SAFETY: `process` is a live process handle with PROCESS_QUERY_LIMITED_INFORMATION (or
    // the pseudo handle), kept alive by the borrow; `raw` is valid for a write.
    let ok = unsafe { OpenProcessToken(process.as_raw_handle(), TOKEN_QUERY, &mut raw) };
    if ok == 0 {
        return Err(last_error());
    }
    // SAFETY: `raw` was just returned by a successful OpenProcessToken; nothing else owns it.
    unsafe { launch::own(raw) }.ok_or_else(last_error)
}

/// The SID a variable-size token class carries in its leading `SID_AND_ATTRIBUTES`
/// (`TokenUser`, `TokenIntegrityLevel`), copied as bytes. The SID must lie inside the answer.
fn token_sid(token: &OwnedHandle, class: TOKEN_INFORMATION_CLASS) -> Result<Vec<u8>, u32> {
    let mut needed: u32 = 0;
    // SAFETY: the documented size query: a null buffer of length 0; `token` is a live token
    // handle with TOKEN_QUERY; `needed` is valid for a write.
    let ok = unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            class,
            ptr::null_mut(),
            0,
            &mut needed,
        )
    };
    if ok != 0 {
        return Err(ERROR_INVALID_DATA);
    }
    let code = last_error();
    if code != ERROR_INSUFFICIENT_BUFFER {
        return Err(code);
    }
    let needed = usize::try_from(needed).unwrap_or(usize::MAX);
    if !(size_of::<SID_AND_ATTRIBUTES>()..=MAX_TOKEN_BYTES).contains(&needed) {
        return Err(ERROR_INVALID_DATA);
    }
    // u64 storage: 8-aligned, enough for the pointer in SID_AND_ATTRIBUTES.
    let mut buf = vec![0u64; needed.div_ceil(8)];
    let cap = buf.len() * 8;
    let mut returned: u32 = 0;
    // SAFETY: `buf` is a writable, 8-aligned buffer of `cap` bytes (≤ MAX_TOKEN_BYTES + 7, so
    // the cast fits) alive for the call; `token` as above; `returned` is valid for a write.
    let ok = unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            class,
            buf.as_mut_ptr().cast(),
            u32::try_from(cap).unwrap_or(0),
            &mut returned,
        )
    };
    if ok == 0 {
        return Err(last_error());
    }
    let filled = usize::try_from(returned).unwrap_or(0).min(cap);
    if filled < size_of::<SID_AND_ATTRIBUTES>() {
        return Err(ERROR_INVALID_DATA);
    }
    // SAFETY: `buf` is 8-aligned and its first `filled` ≥ size_of::<SID_AND_ATTRIBUTES>()
    // bytes were written by Windows; SID_AND_ATTRIBUTES is a raw pointer and a u32, valid for
    // every bit pattern. The pointer is only compared below, never dereferenced.
    let head = unsafe { buf.as_ptr().cast::<SID_AND_ATTRIBUTES>().read() };
    // SAFETY: the `cap` bytes of `buf` are initialized (a zeroed vector, partly overwritten);
    // u8 has no alignment or validity requirement; the slice lives no longer than `buf`.
    let bytes = unsafe { std::slice::from_raw_parts(buf.as_ptr().cast::<u8>(), cap) };
    let offset = head
        .Sid
        .addr()
        .checked_sub(buf.as_ptr().addr())
        .ok_or(ERROR_INVALID_DATA)?;
    let sid = bytes
        .get(..filled)
        .and_then(|b| sid_at(b, offset))
        .ok_or(ERROR_INVALID_DATA)?;
    Ok(sid.to_vec())
}

/// The SID at `offset` in `bytes` (winnt.h `SID`: revision 1, a sub-authority count of 1 to
/// 15, a 6-byte authority, the sub-authorities), if it lies wholly inside.
fn sid_at(bytes: &[u8], offset: usize) -> Option<&[u8]> {
    let head = bytes.get(offset..offset.checked_add(8)?)?;
    let (revision, count) = (*head.first()?, *head.get(1)?);
    if revision != 1 || count == 0 || count > SID_MAX_SUB_AUTHORITIES {
        return None;
    }
    let len = 8 + 4 * usize::from(count);
    bytes.get(offset..offset.checked_add(len)?)
}

/// The last sub-authority of a SID [`sid_at`] accepted: for the integrity label the RID.
fn last_sub_authority(sid: &[u8]) -> Option<u32> {
    let count = usize::from(*sid.get(1)?);
    let at = 8 + 4 * count.checked_sub(1)?;
    let unit: [u8; 4] = sid.get(at..at + 4)?.try_into().ok()?;
    Some(u32::from_le_bytes(unit))
}

/// The raw token facts (A3).
fn token_facts(token: &OwnedHandle) -> Result<Token, u32> {
    let user = token_sid(token, TokenUser)?;
    // SAFETY: TokenSessionId writes a DWORD (a u32, any value valid).
    let session: u32 = unsafe { token_info(token, TokenSessionId) }?;
    let label = token_sid(token, TokenIntegrityLevel)?;
    let integrity = last_sub_authority(&label).ok_or(ERROR_INVALID_DATA)?;
    Ok(Token {
        user,
        session,
        integrity,
    })
}

/// The shim's own creation time and token facts (read once before the unchanged start).
pub(crate) fn own() -> Result<Own, u32> {
    let me = current_process();
    let created = created(me)?;
    let token = token_of(me)?;
    Ok(Own {
        created,
        token: token_facts(&token)?,
    })
}

/// What an opened process is: image path, creation time, token facts. Its token is opened
/// with `TOKEN_QUERY` through the process handle (`PROCESS_QUERY_LIMITED_INFORMATION`).
pub(crate) fn facts(p: &Proc) -> Result<Facts, u32> {
    let h = p.handle();
    let image = image(h)?;
    let created = created(h)?;
    let token = token_of(h)?;
    Ok(Facts {
        image,
        created,
        token: token_facts(&token)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rights_are_only_what_the_profile_sets() {
        let base = PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE;
        assert_eq!(rights(Access::default()), base);
        let job = Access {
            job: true,
            ..Access::default()
        };
        assert_eq!(rights(job), base | PROCESS_SET_QUOTA | PROCESS_TERMINATE);
        let sets = Access {
            cpu_sets: true,
            ..Access::default()
        };
        assert_eq!(rights(sets), base | PROCESS_SET_LIMITED_INFORMATION);
        let prio = Access {
            priority: true,
            ..Access::default()
        };
        assert_eq!(rights(prio), base | PROCESS_SET_INFORMATION);
        // Never PROCESS_VM_*, PROCESS_CREATE_THREAD, PROCESS_DUP_HANDLE or PROCESS_ALL_ACCESS.
        let all = Access {
            job: true,
            cpu_sets: true,
            priority: true,
        };
        assert_eq!(rights(all) & 0x0000_007A, 0);
        assert_eq!(rights(all) & !0x0010_3301, 0);
    }

    #[test]
    fn sid_bounds() {
        // S-1-16-12288 (high integrity): revision 1, one sub-authority, authority 16.
        let label = [1u8, 1, 0, 0, 0, 0, 0, 16, 0x00, 0x30, 0, 0];
        assert_eq!(sid_at(&label, 0), Some(&label[..]));
        assert_eq!(last_sub_authority(&label), Some(0x3000));
        // Cut short, another revision, no or too many sub-authorities, an offset outside.
        assert_eq!(sid_at(&label[..11], 0), None);
        let mut bad = label;
        bad[0] = 2;
        assert_eq!(sid_at(&bad, 0), None);
        bad = label;
        bad[1] = 0;
        assert_eq!(sid_at(&bad, 0), None);
        bad[1] = 16;
        assert_eq!(sid_at(&bad, 0), None);
        assert_eq!(sid_at(&label, 1), None);
        assert_eq!(sid_at(&label, usize::MAX), None);
        // With room before it.
        let mut padded = vec![0u8; 4];
        padded.extend_from_slice(&label);
        assert_eq!(sid_at(&padded, 4), Some(&label[..]));
    }
}
