//! HTTPS GET, the network's only way in (ADR 0025, P4-6).
//!
//! `sys` is dumb and honest here too: [`Http::get`] makes exactly one request to one host and
//! path over TLS on port 443 and reports what came back (status, `Location`, `Content-Length`,
//! the body as a stream). It follows no redirect, sends no cookie and no credential, and knows
//! no allowlist: which hosts and paths may be asked, which redirect may be followed and how many
//! bytes are read decide `policy::url` and `pkg::download` above it, the same for the fake and
//! the real one.
//!
//! The real one is `sys::win::WinHttp` (WinHTTP over Schannel with the system proxy), the fake
//! one `sys::fake::FakeHttp` (scripted replies). [`NoHttp`] refuses every request.
//!
//! `Http` is deliberately **not** part of [`System`](super::System): the elevated helper's
//! system can never reach it (ADR 0023 §11), and the curator tool uses it without a system.

use std::io::Read;

use super::{SysError, SysErrorKind, SysResult};

/// Most bytes of a host name [`Http::get`] accepts (RFC 1035).
pub const MAX_HOST: usize = 253;
/// Most bytes of a request path with its query. Signed redirect targets of release hosts carry
/// long query strings (a few KiB); anything longer is refused before a request is made.
pub const MAX_PATH: usize = 8192;
/// Most bytes of a `Location` header that are read; a longer one is an error, never cut.
pub const MAX_LOCATION: usize = MAX_PATH + 512;

/// What one request returned.
pub struct Response<'a> {
    /// The HTTP status code.
    pub status: u16,
    /// The `Location` header of a 3xx response as sent (at most [`MAX_LOCATION`] bytes, ASCII
    /// only; anything else is an error of the request), if there was one; never read for another
    /// status.
    pub location: Option<String>,
    /// `Content-Length`, if the server sent a valid one. Advisory: the body may end earlier or
    /// run longer; the reader decides by what it reads.
    pub length: Option<u64>,
    /// The body. A transport error while reading is an `io::Error` with the Win32 code as its
    /// raw OS error (`SysError::io` keeps it).
    pub body: Box<dyn Read + Send + 'a>,
}

impl std::fmt::Debug for Response<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Response")
            .field("status", &self.status)
            .field("location", &self.location)
            .field("length", &self.length)
            .finish_non_exhaustive()
    }
}

/// HTTPS GET.
pub trait Http: Send + Sync {
    /// One `GET https://<host><path>` on port 443, TLS with the system's certificate
    /// validation, no redirect followed, no cookie, no credential. `host` is a plain DNS name,
    /// `path` starts with `/` and is sent as given (no escaping), both printable ASCII without
    /// spaces (`InvalidPath` otherwise, before any request). Errors carry the Win32 code.
    fn get(&self, host: &str, path: &str) -> SysResult<Response<'_>>;
}

/// The input rule of [`Http::get`], shared by every implementation: a host of letters, digits,
/// `-` and `.`, a path that starts with `/`, both within their bounds and printable ASCII
/// without spaces, `\` or `#`. A fact check, not the policy (`policy::url` is stricter).
pub fn check_request(host: &str, path: &str) -> SysResult<()> {
    let host_ok = !host.is_empty()
        && host.len() <= MAX_HOST
        && host
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'.');
    if host_ok && path_ok(path) {
        Ok(())
    } else {
        Err(SysError::new(
            SysErrorKind::InvalidPath,
            "an HTTPS request with an invalid host or path",
        ))
    }
}

/// The path rule of [`check_request`], also `policy::url`'s for every URL it admits: starts with
/// `/`, at most [`MAX_PATH`] bytes of printable ASCII without `\`, `#` or a space.
pub fn path_ok(path: &str) -> bool {
    path.starts_with('/')
        && path.len() <= MAX_PATH
        && path
            .bytes()
            .all(|c| c.is_ascii_graphic() && c != b'\\' && c != b'#')
}

/// No network: every request is refused (`Unsupported`). For systems and tests that must
/// never download.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoHttp;

impl Http for NoHttp {
    fn get(&self, host: &str, _path: &str) -> SysResult<Response<'_>> {
        Err(SysError::new(
            SysErrorKind::Unsupported,
            format!("https://{host}: no network in this system"),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_request_rule_refuses_before_any_request() {
        assert!(check_request("github.com", "/a/b?x=1&y=%2F").is_ok());
        for (h, p) in [
            ("", "/"),
            ("github.com", ""),
            ("github.com", "a"),
            ("git hub.com", "/"),
            ("github.com:444", "/"),
            ("user@github.com", "/"),
            ("github.com", "/a b"),
            ("github.com", "/a\\b"),
            ("github.com", "/a#b"),
            ("github.com", "/\u{e9}"),
            ("github.com", "/\r\nX: y"),
        ] {
            assert!(check_request(h, p).is_err(), "{h:?} {p:?}");
        }
        assert!(check_request(&"a".repeat(MAX_HOST + 1), "/").is_err());
        assert!(check_request("a.com", &format!("/{}", "a".repeat(MAX_PATH))).is_err());
    }

    #[test]
    fn no_http_refuses() {
        let e = NoHttp.get("github.com", "/").unwrap_err();
        assert_eq!(e.kind, SysErrorKind::Unsupported);
    }
}
