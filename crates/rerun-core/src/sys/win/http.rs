//! [`WinHttp`]: HTTPS GET through WinHTTP (ADR 0025, P4-6), the only network code of Rerun.
//!
//! One request per [`Http::get`]: a fresh session, connection and request, closed when the
//! returned body drops (field order of [`Body`]). Fixed for every request, none of it a
//! parameter:
//! - TLS only (`WINHTTP_FLAG_SECURE`, port 443), TLS 1.2 or 1.3 (`WINHTTP_OPTION_SECURE_PROTOCOLS`);
//!   the certificate is validated by Schannel as WinHTTP does by default. No
//!   `WINHTTP_OPTION_SECURITY_FLAGS` is ever set (a source rule test checks that no
//!   `SECURITY_FLAG_IGNORE_*` appears in the workspace).
//! - No redirect is followed (`WINHTTP_OPTION_REDIRECT_POLICY_NEVER` on the session,
//!   `WINHTTP_DISABLE_REDIRECTS` on the request): `pkg::download` checks every hop itself.
//! - No cookie, no authentication (`WINHTTP_DISABLE_COOKIES`, `WINHTTP_DISABLE_AUTHENTICATION`),
//!   no automatic logon with the user's credentials (`WINHTTP_AUTOLOGON_SECURITY_LEVEL_HIGH`); no
//!   request header of Rerun's own but the user agent `Rerun/<version>` (no personal data).
//! - The system proxy (`WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY`); synchronous; 30 s per resolve,
//!   connect, send and receive; response headers at most 64 KiB.
//! - The path is sent exactly as given (`WINHTTP_FLAG_ESCAPE_DISABLE`, `…_QUERY`); the input rule
//!   [`check_request`] runs before anything is opened.
//!
//! Refuses (`Unsupported`) unless the process restricted its DLL search path first
//! (`loader::restrict_dll_search`, ADR 0008): WinHTTP loads further system DLLs at run time.
//! Errors carry the WinHTTP code (`ERROR_WINHTTP_*`, 12000–12199) in `SysError::win32`; a read
//! error of the body is an `io::Error` with that code as its raw OS error.

#![allow(
    unsafe_code,
    reason = "FFI to WinHTTP (ADR 0025, ADR 0008); every block has a SAFETY comment"
)]
#![expect(
    clippy::disallowed_methods,
    reason = "the one WinHttpOpen and WinHttpSetOption call site (ADR 0025)"
)]

use std::ffi::c_void;
use std::io::{self, Read};
use std::ptr;

use windows_sys::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, GetLastError};
use windows_sys::Win32::Networking::WinHttp::{
    ERROR_WINHTTP_CANNOT_CONNECT, ERROR_WINHTTP_CONNECTION_ERROR, ERROR_WINHTTP_HEADER_NOT_FOUND,
    ERROR_WINHTTP_INVALID_SERVER_RESPONSE, ERROR_WINHTTP_NAME_NOT_RESOLVED,
    ERROR_WINHTTP_SECURE_FAILURE, ERROR_WINHTTP_SECURE_FAILURE_PROXY, ERROR_WINHTTP_TIMEOUT,
    INTERNET_DEFAULT_HTTPS_PORT, WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
    WINHTTP_AUTOLOGON_SECURITY_LEVEL_HIGH, WINHTTP_DISABLE_AUTHENTICATION, WINHTTP_DISABLE_COOKIES,
    WINHTTP_DISABLE_REDIRECTS, WINHTTP_FLAG_ESCAPE_DISABLE, WINHTTP_FLAG_ESCAPE_DISABLE_QUERY,
    WINHTTP_FLAG_SECURE, WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2, WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3,
    WINHTTP_OPTION_AUTOLOGON_POLICY, WINHTTP_OPTION_DISABLE_FEATURE,
    WINHTTP_OPTION_MAX_RESPONSE_HEADER_SIZE, WINHTTP_OPTION_REDIRECT_POLICY,
    WINHTTP_OPTION_REDIRECT_POLICY_NEVER, WINHTTP_OPTION_SECURE_PROTOCOLS,
    WINHTTP_QUERY_CONTENT_LENGTH, WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_QUERY_FLAG_NUMBER64,
    WINHTTP_QUERY_LOCATION, WINHTTP_QUERY_STATUS_CODE, WinHttpCloseHandle, WinHttpConnect,
    WinHttpOpen, WinHttpOpenRequest, WinHttpQueryHeaders, WinHttpReadData, WinHttpReceiveResponse,
    WinHttpSendRequest, WinHttpSetOption, WinHttpSetTimeouts,
};

use super::loader;
use super::status::kind_of_win32;
use crate::sys::http::{MAX_LOCATION, check_request};
use crate::sys::{Http, Response, SysError, SysErrorKind, SysResult};

/// The user agent: Rerun and its version, nothing about the user or the machine.
const USER_AGENT: &str = concat!("Rerun/", env!("CARGO_PKG_VERSION"));
/// Each of the resolve, connect, send and receive timeouts, in milliseconds.
const TIMEOUT_MS: i32 = 30_000;
/// Most bytes of the response headers WinHTTP accepts.
const MAX_HEADER_BYTES: u32 = 64 * 1024;

/// HTTPS GET through WinHTTP (module docs).
#[derive(Debug, Default, Clone, Copy)]
pub struct WinHttp;

impl WinHttp {
    /// The real HTTP side; opens nothing until [`Http::get`].
    pub fn new() -> Self {
        Self
    }
}

/// An `HINTERNET` (session, connection or request), closed on drop.
struct Handle(*mut c_void);

// SAFETY: a WinHTTP handle is not bound to the thread that opened it; `Handle` owns it alone
// and is never shared (no `Sync`), so moving it to another thread is sound.
unsafe impl Send for Handle {}

impl Drop for Handle {
    fn drop(&mut self) {
        // SAFETY: `self.0` is a non-null handle returned by WinHTTP (checked in `opened`),
        // owned by this value and closed exactly once, here. A request handle is dropped
        // before its connection and session (`Body` field order).
        unsafe {
            WinHttpCloseHandle(self.0);
        }
    }
}

/// The thread's last Win32 error.
fn last_error() -> u32 {
    // SAFETY: no preconditions.
    unsafe { GetLastError() }
}

/// A short reason for the common WinHTTP codes, for the message only (the code is kept).
fn reason(code: u32) -> &'static str {
    match code {
        ERROR_WINHTTP_TIMEOUT => "timed out",
        ERROR_WINHTTP_NAME_NOT_RESOLVED => "the host name could not be resolved",
        ERROR_WINHTTP_CANNOT_CONNECT => "cannot connect",
        ERROR_WINHTTP_CONNECTION_ERROR => "the connection was reset or aborted",
        ERROR_WINHTTP_SECURE_FAILURE => "TLS failed (certificate or handshake)",
        ERROR_WINHTTP_SECURE_FAILURE_PROXY => "TLS to the proxy failed",
        ERROR_WINHTTP_INVALID_SERVER_RESPONSE => "invalid server response",
        _ => "WinHTTP error",
    }
}

/// The error of a failed call, with its code.
fn fail(call: &str, host: &str, code: u32) -> SysError {
    SysError::new(
        kind_of_win32(code),
        format!("https://{host}: {call}: {} (code {code})", reason(code)),
    )
    .with_win32(code)
}

/// A handle from a call that returns NULL on failure.
fn opened(raw: *mut c_void, call: &str, host: &str) -> SysResult<Handle> {
    if raw.is_null() {
        return Err(fail(call, host, last_error()));
    }
    Ok(Handle(raw))
}

/// A NUL-terminated UTF-16 copy of `s` (ASCII without NUL by [`check_request`] and the fixed
/// strings).
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// `WinHttpSetOption` with a `DWORD` value.
fn set_u32(h: &Handle, option: u32, value: u32, host: &str) -> SysResult<()> {
    let len = u32::try_from(size_of::<u32>()).unwrap_or(4);
    // SAFETY: `h.0` is an open handle; the buffer is a `u32` of `len` bytes that lives across
    // the call; WinHTTP copies the value.
    let ok = unsafe { WinHttpSetOption(h.0, option, (&raw const value).cast(), len) };
    if ok == 0 {
        return Err(fail(
            &format!("WinHttpSetOption({option})"),
            host,
            last_error(),
        ));
    }
    Ok(())
}

/// A numeric header (`WINHTTP_QUERY_FLAG_NUMBER` or `…NUMBER64`) into `T`; `Ok(None)` if the
/// header is absent.
fn query_number<T: Copy + Default>(req: &Handle, level: u32, host: &str) -> SysResult<Option<T>> {
    let mut v = T::default();
    let mut len = u32::try_from(size_of::<T>()).unwrap_or(0);
    // SAFETY: `req.0` is a request whose response was received; the buffer is a `T` of `len`
    // bytes that lives across the call; NULL name (a standard header by level) and NULL index.
    let ok = unsafe {
        WinHttpQueryHeaders(
            req.0,
            level,
            ptr::null(),
            (&raw mut v).cast(),
            &mut len,
            ptr::null_mut(),
        )
    };
    if ok != 0 {
        return Ok(Some(v));
    }
    match last_error() {
        ERROR_WINHTTP_HEADER_NOT_FOUND => Ok(None),
        code => Err(fail("WinHttpQueryHeaders", host, code)),
    }
}

/// The `Location` header: at most [`MAX_LOCATION`] bytes, ASCII only; `Ok(None)` if absent.
fn query_location(req: &Handle, host: &str) -> SysResult<Option<String>> {
    let mut len = 0u32;
    // SAFETY: a size query: NULL buffer with `len` 0; WinHTTP writes the needed size in bytes
    // to `len` and fails with ERROR_INSUFFICIENT_BUFFER.
    let ok = unsafe {
        WinHttpQueryHeaders(
            req.0,
            WINHTTP_QUERY_LOCATION,
            ptr::null(),
            ptr::null_mut(),
            &mut len,
            ptr::null_mut(),
        )
    };
    if ok != 0 {
        return Ok(Some(String::new()));
    }
    match last_error() {
        ERROR_WINHTTP_HEADER_NOT_FOUND => return Ok(None),
        ERROR_INSUFFICIENT_BUFFER => {}
        code => return Err(fail("WinHttpQueryHeaders(Location)", host, code)),
    }
    let units = usize::try_from(len).unwrap_or(usize::MAX) / 2 + 1;
    if units > MAX_LOCATION + 1 {
        return Err(SysError::too_large(
            format!("https://{host}: the Location header"),
            u64::try_from(MAX_LOCATION).unwrap_or(u64::MAX),
        ));
    }
    let mut buf = vec![0u16; units];
    let mut len = u32::try_from(units * 2).unwrap_or(0);
    // SAFETY: `buf` is writable for `len` bytes and lives across the call; on success `len`
    // receives the bytes written without the NUL.
    let ok = unsafe {
        WinHttpQueryHeaders(
            req.0,
            WINHTTP_QUERY_LOCATION,
            ptr::null(),
            buf.as_mut_ptr().cast(),
            &mut len,
            ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(fail("WinHttpQueryHeaders(Location)", host, last_error()));
    }
    let n = (usize::try_from(len).unwrap_or(usize::MAX) / 2).min(buf.len());
    let text = buf.get(..n).unwrap_or_default();
    if text.len() > MAX_LOCATION || !text.iter().all(|&c| (0x20..0x7F).contains(&c)) {
        return Err(SysError::new(
            SysErrorKind::InvalidPath,
            format!("https://{host}: a Location header that is not printable ASCII"),
        ));
    }
    Ok(Some(
        text.iter()
            .filter_map(|&c| u8::try_from(c).ok())
            .map(char::from)
            .collect(),
    ))
}

/// The body of one response; owns its request, connection and session (dropped in this order).
struct Body {
    req: Handle,
    _conn: Handle,
    _session: Handle,
}

impl Read for Body {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let want = u32::try_from(buf.len()).unwrap_or(u32::MAX);
        let mut got = 0u32;
        // SAFETY: `self.req.0` is a request whose response was received; `buf` is writable for
        // `want` bytes (`want <= buf.len()`) and lives across the call; `got` receives the
        // count, which WinHTTP keeps at or below `want`.
        let ok = unsafe { WinHttpReadData(self.req.0, buf.as_mut_ptr().cast(), want, &mut got) };
        if ok == 0 {
            let code = last_error();
            return Err(io::Error::from_raw_os_error(
                i32::try_from(code).unwrap_or(i32::MAX),
            ));
        }
        Ok(usize::try_from(got).unwrap_or(0).min(buf.len()))
    }
}

impl Http for WinHttp {
    fn get(&self, host: &str, path: &str) -> SysResult<Response<'_>> {
        check_request(host, path)?;
        if !loader::dll_search_restricted() {
            return Err(SysError::new(
                SysErrorKind::Unsupported,
                format!(
                    "https://{host}: the DLL search path is not restricted to System32 (ADR 0008)"
                ),
            ));
        }
        let agent = wide(USER_AGENT);
        // SAFETY: `agent` is NUL-terminated and lives across the call; NULL proxy name and
        // bypass list, as WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY requires; flags 0 = synchronous.
        let raw = unsafe {
            WinHttpOpen(
                agent.as_ptr(),
                WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                ptr::null(),
                ptr::null(),
                0,
            )
        };
        let session = opened(raw, "WinHttpOpen", host)?;
        set_u32(
            &session,
            WINHTTP_OPTION_SECURE_PROTOCOLS,
            WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2 | WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3,
            host,
        )?;
        set_u32(
            &session,
            WINHTTP_OPTION_REDIRECT_POLICY,
            WINHTTP_OPTION_REDIRECT_POLICY_NEVER,
            host,
        )?;
        // SAFETY: `session.0` is an open session handle; the four timeouts are plain values.
        let ok = unsafe {
            WinHttpSetTimeouts(session.0, TIMEOUT_MS, TIMEOUT_MS, TIMEOUT_MS, TIMEOUT_MS)
        };
        if ok == 0 {
            return Err(fail("WinHttpSetTimeouts", host, last_error()));
        }
        let whost = wide(host);
        // SAFETY: `session.0` is an open session; `whost` is NUL-terminated and lives across the
        // call; the port is the fixed HTTPS port; reserved 0.
        let raw =
            unsafe { WinHttpConnect(session.0, whost.as_ptr(), INTERNET_DEFAULT_HTTPS_PORT, 0) };
        let conn = opened(raw, "WinHttpConnect", host)?;
        let verb = wide("GET");
        let wpath = wide(path);
        // SAFETY: `conn.0` is an open connection; `verb` and `wpath` are NUL-terminated and live
        // across the call; NULL version (HTTP/1.1), NULL referrer, NULL accept types (none sent).
        let raw = unsafe {
            WinHttpOpenRequest(
                conn.0,
                verb.as_ptr(),
                wpath.as_ptr(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
                WINHTTP_FLAG_SECURE
                    | WINHTTP_FLAG_ESCAPE_DISABLE
                    | WINHTTP_FLAG_ESCAPE_DISABLE_QUERY,
            )
        };
        let req = opened(raw, "WinHttpOpenRequest", host)?;
        set_u32(
            &req,
            WINHTTP_OPTION_DISABLE_FEATURE,
            WINHTTP_DISABLE_COOKIES | WINHTTP_DISABLE_REDIRECTS | WINHTTP_DISABLE_AUTHENTICATION,
            host,
        )?;
        set_u32(
            &req,
            WINHTTP_OPTION_AUTOLOGON_POLICY,
            WINHTTP_AUTOLOGON_SECURITY_LEVEL_HIGH,
            host,
        )?;
        set_u32(
            &req,
            WINHTTP_OPTION_MAX_RESPONSE_HEADER_SIZE,
            MAX_HEADER_BYTES,
            host,
        )?;
        // SAFETY: `req.0` is an open request; no additional headers (NULL, 0), no body (NULL,
        // 0, total 0), context 0.
        let ok = unsafe { WinHttpSendRequest(req.0, ptr::null(), 0, ptr::null(), 0, 0, 0) };
        if ok == 0 {
            return Err(fail("WinHttpSendRequest", host, last_error()));
        }
        // SAFETY: `req.0` is a request that was sent; the reserved argument is NULL.
        let ok = unsafe { WinHttpReceiveResponse(req.0, ptr::null_mut()) };
        if ok == 0 {
            return Err(fail("WinHttpReceiveResponse", host, last_error()));
        }
        let status = query_number::<u32>(
            &req,
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            host,
        )?
        .and_then(|s| u16::try_from(s).ok())
        .ok_or_else(|| {
            SysError::new(
                SysErrorKind::Other,
                format!("https://{host}: no valid status code"),
            )
            .with_win32(ERROR_WINHTTP_INVALID_SERVER_RESPONSE)
        })?;
        // Advisory only: a malformed length is no length.
        let length = query_number::<u64>(
            &req,
            WINHTTP_QUERY_CONTENT_LENGTH | WINHTTP_QUERY_FLAG_NUMBER64,
            host,
        )
        .ok()
        .flatten();
        // Only a redirect's Location is read (the fake does the same).
        let location = if (300..400).contains(&status) {
            query_location(&req, host)?
        } else {
            None
        };
        Ok(Response {
            status,
            location,
            length,
            body: Box::new(Body {
                req,
                _conn: conn,
                _session: session,
            }),
        })
    }
}
