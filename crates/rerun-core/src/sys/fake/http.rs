//! Fake HTTPS (ADR 0025, P4-6): scripted replies per `https://<host><path>`.
//!
//! A URL without a reply is a connection failure (`ERROR_WINHTTP_CANNOT_CONNECT`), so a test that
//! forgot to script a host can never pass by accident. Every request is recorded in order
//! ([`FakeHttp::requests`]): a test shows which hosts were asked, and that a refused redirect
//! was never requested. A reply can end its body early with a transport error
//! ([`FakeReply::cut_after`]), the abort in the middle of a download.

use std::collections::BTreeMap;
use std::io::{self, Read};
use std::sync::{Mutex, PoisonError};

use crate::sys::http::check_request;
use crate::sys::{Http, Response, SysError, SysErrorKind, SysResult};

/// `ERROR_WINHTTP_CANNOT_CONNECT`.
pub const CANNOT_CONNECT: u32 = 12029;
/// `ERROR_WINHTTP_CONNECTION_ERROR`: what a reset in the middle of a body reports.
pub const CONNECTION_ERROR: u32 = 12030;

/// One scripted reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FakeReply {
    /// The status code.
    pub status: u16,
    /// The `Location` header.
    pub location: Option<String>,
    /// The `Content-Length` header (advisory, may lie).
    pub length: Option<u64>,
    /// The body.
    pub body: Vec<u8>,
    /// After this many body bytes the read fails with [`CONNECTION_ERROR`].
    pub cut_after: Option<usize>,
    /// The request itself fails with this Win32 code (nothing else of the reply counts).
    pub fail: Option<u32>,
}

impl FakeReply {
    /// `200` with `body` and its true length.
    pub fn ok(body: &[u8]) -> Self {
        Self {
            status: 200,
            location: None,
            length: Some(body.len() as u64),
            body: body.to_vec(),
            cut_after: None,
            fail: None,
        }
    }

    /// A redirect with `status` to `location`.
    pub fn redirect(status: u16, location: &str) -> Self {
        Self {
            status,
            location: Some(location.to_owned()),
            length: Some(0),
            body: Vec::new(),
            cut_after: None,
            fail: None,
        }
    }

    /// A reply with `status` and an empty body.
    pub fn status(status: u16) -> Self {
        Self {
            status,
            ..Self::ok(b"")
        }
    }

    /// The request fails with `code` (a WinHTTP code).
    pub fn fail(code: u32) -> Self {
        Self {
            fail: Some(code),
            ..Self::ok(b"")
        }
    }
}

/// The fake HTTP side.
#[derive(Debug, Default)]
pub struct FakeHttp {
    replies: Mutex<BTreeMap<String, FakeReply>>,
    requests: Mutex<Vec<String>>,
}

impl FakeHttp {
    /// Scripts the reply for `url` (`https://<host><path>`), replacing an earlier one.
    pub fn reply(&self, url: &str, r: FakeReply) {
        self.replies
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(url.to_owned(), r);
    }

    /// Every request so far, in order, as `https://<host><path>`.
    pub fn requests(&self) -> Vec<String> {
        self.requests
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Forgets the recorded requests.
    pub fn clear_requests(&self) {
        self.requests
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clear();
    }
}

/// A body that may fail after a number of bytes.
struct Body {
    data: Vec<u8>,
    at: usize,
    cut_after: Option<usize>,
}

impl Read for Body {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let end = self.cut_after.unwrap_or(usize::MAX).min(self.data.len());
        if self.at >= end && self.cut_after.is_some_and(|c| c < self.data.len()) {
            return Err(io::Error::from_raw_os_error(CONNECTION_ERROR as i32));
        }
        let rest = self.data.get(self.at..end).unwrap_or_default();
        let n = rest.len().min(buf.len());
        buf[..n].copy_from_slice(&rest[..n]);
        self.at += n;
        Ok(n)
    }
}

impl Http for FakeHttp {
    fn get(&self, host: &str, path: &str) -> SysResult<Response<'_>> {
        check_request(host, path)?;
        let url = format!("https://{host}{path}");
        self.requests
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(url.clone());
        let reply = self
            .replies
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&url)
            .cloned()
            .unwrap_or_else(|| FakeReply::fail(CANNOT_CONNECT));
        if let Some(code) = reply.fail {
            return Err(SysError::new(
                SysErrorKind::Other,
                format!("https://{host}: fake failure"),
            )
            .with_win32(code));
        }
        Ok(Response {
            status: reply.status,
            location: reply.location,
            length: reply.length,
            body: Box::new(Body {
                data: reply.body,
                at: 0,
                cut_after: reply.cut_after,
            }),
        })
    }
}
