//! Package downloads into `<AppDir>\cache` (ADR 0025 part 1, P4-6).
//!
//! [`fetch`] runs in this order and skips nothing:
//! 1. **Standard user only.** An elevated process (or one whose elevation cannot be determined)
//!    is refused before anything is opened, like every command that changes something
//!    (`exec::standard_user`, user decision E3 of P2-13).
//! 2. **The cache.** `<AppDir>\cache` is opened (created) handle-relative through `AppDir`, never
//!    through a reparse point, and `cache\lock` is held (share 0) for the whole fetch, so two
//!    fetches never interleave. Temp files of an earlier, interrupted fetch (`.rerun-<tag>-<n>.tmp`,
//!    `TmpName`) are deleted first: under the lock none can be in use.
//! 3. **A cache hit is hashed.** The cache is user-writable and untrusted (`docs/06-security.md`
//!    #14): an entry `<sha256>` is hashed on a guard and used only if it hashes to its name;
//!    otherwise it is deleted (on that guard) and downloaded again. An entry that cannot be
//!    guarded (a link, a directory, a reparse point) is an error naming the file to remove.
//! 4. **The request chain.** The package URL ([`Download::url`], re-checked by
//!    `HttpsUrl::download`) is requested; a redirect (301, 302, 303, 307, 308) is followed only as
//!    `HttpsUrl::redirect` allows (fixed host list, https, no port, userinfo or IP literal), at
//!    most [`MAX_REDIRECTS`] times; any other status than 200 is an error. A refused redirect is
//!    never requested.
//! 5. **The body.** `Content-Length` above [`MAX_DOWNLOAD_BYTES`] is refused before reading;
//!    otherwise the length is advisory and the limit is enforced on the bytes read. A body that
//!    ends before or runs past its `Content-Length` is refused. The body streams through
//!    `DirWrite::create_new` into a temp file next to the target, hashed on the way: a hash other
//!    than the pinned one, a transport error, the limit or any write error deletes the temp
//!    file, so nothing is ever kept under the name unless it is exactly the pinned content. On
//!    success the temp file is renamed (without replace) to `<sha256>` and the folder flushed.
//!
//! **Progress and cancellation** (P5-5b, [`fetch_watched`]): the body reports how many bytes were
//! read and the announced `Content-Length` (every [`PROGRESS_STEP`] bytes), and a flag is checked
//! before every request and every read. A cancel stops at the next read (a blocked read ends at
//! WinHTTP's 30 s receive timeout at the latest) and takes the same road as any other failure of
//! the body: the temp file is deleted, so a cancelled download keeps nothing under any name.
//!
//! A cached file is still untrusted: whoever uses it (extraction, P4-7) hashes it again on its
//! own handle.

use std::io::{self, Read};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crate::catalog::model::{Arch, Package, Sha256, Tier};
use crate::journal::InstanceTag;
use crate::path::RelPath;
use crate::policy::root::{AppDir, AppSub, Create, RootError};
use crate::policy::url::{HttpsUrl, UrlError, belongs};
use crate::sys::fs::{Attrs, EntryKind, NewFile, TmpName};
use crate::sys::{DirWrite, Http, SysError, SysErrorKind, System};
use crate::wire::hex32;

/// Most bytes of one download (every package archive Rerun knows is far below; DXVK 2.5.3 is
/// about 10 MB). Enforced on the bytes read, never only on `Content-Length`.
pub const MAX_DOWNLOAD_BYTES: u64 = 64 * 1024 * 1024;
/// Most redirects followed for one download (GitHub needs one).
pub const MAX_REDIRECTS: usize = 3;
/// Most time one download may take, from its first request to its last byte (ADR 0025). Generous:
/// 64 MiB in 10 minutes is about 110 KB/s. WinHTTP's 30 s timeouts bound each step; this bounds
/// a server that keeps sending slowly.
pub const MAX_DOWNLOAD_TIME: Duration = Duration::from_secs(600);
/// Most entries of `cache` listed when temp files are swept; a larger folder is not swept.
const MAX_CACHE_ENTRIES: usize = 4096;
/// The lock file of the cache.
const LOCK: &str = "lock";

/// One download of a package: an archive at a URL with its pinned SHA-256. Built only by
/// [`downloads`] (from a package of the signed index, form and provenance checked).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Download {
    arch: Option<Arch>,
    url: HttpsUrl,
    sha256: [u8; 32],
}

impl Download {
    /// The architecture of a per-architecture asset (`assets[]`), `None` for `source.release`.
    pub fn arch(&self) -> Option<Arch> {
        self.arch
    }

    /// Where it is fetched from.
    pub fn url(&self) -> &HttpsUrl {
        &self.url
    }

    /// What it must hash to.
    pub fn sha256(&self) -> &[u8; 32] {
        &self.sha256
    }

    /// A download without a package (tests only: the fake and the [SB] test).
    #[cfg(test)]
    pub(crate) fn for_test(arch: Option<Arch>, url: HttpsUrl, sha256: [u8; 32]) -> Self {
        Self { arch, url, sha256 }
    }
}

/// How a fetch ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum How {
    /// The cache held it already (hashed again).
    Cached,
    /// Downloaded now, after this many redirects.
    Downloaded {
        /// Redirects followed.
        redirects: usize,
        /// A cache entry with other content was deleted first.
        replaced: bool,
    },
}

/// A package archive in the cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fetched {
    /// Its SHA-256 (= its name in `cache`).
    pub sha256: [u8; 32],
    /// Its length in bytes.
    pub len: u64,
    /// How it got there.
    pub how: How,
}

/// Why a fetch failed. Hosts are named only after they passed the host rule; nothing a server
/// sent is quoted.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FetchError {
    /// The process is elevated (or its elevation is unknown).
    #[error(
        "downloads are refused in an elevated process (or one whose elevation cannot be determined)"
    )]
    Elevated,
    /// The package has no download Rerun may fetch.
    #[error("package {id} has no direct download: {why}")]
    NoDownload {
        /// The package ID.
        id: String,
        /// Why.
        why: &'static str,
    },
    /// A URL outside the rules (the package's own or a redirect).
    #[error(transparent)]
    Url(#[from] UrlError),
    /// A download URL that does not belong to the package's source (docs/02 "Provenance").
    #[error("a download of package {id} is not from its original source")]
    Provenance {
        /// The package ID.
        id: String,
    },
    /// More redirects than [`MAX_REDIRECTS`].
    #[error("https://{host}: more than {MAX_REDIRECTS} redirects")]
    TooManyRedirects {
        /// The last host asked.
        host: String,
    },
    /// A redirect status without a `Location`.
    #[error("https://{host}: a redirect without a Location header")]
    NoLocation {
        /// The host.
        host: String,
    },
    /// Any other status than 200 or a redirect.
    #[error("https://{host}: HTTP status {status}")]
    Status {
        /// The host.
        host: String,
        /// The status.
        status: u16,
    },
    /// Larger than the limit ([`MAX_DOWNLOAD_BYTES`]).
    #[error("https://{host}: the download is larger than {limit} bytes")]
    TooLarge {
        /// The host.
        host: String,
        /// The limit.
        limit: u64,
    },
    /// The caller cancelled; nothing was kept of the download that was running.
    #[error("the download was cancelled; nothing was kept")]
    Cancelled,
    /// The download took longer than [`MAX_DOWNLOAD_TIME`].
    #[error("https://{host}: the download took longer than {secs} s")]
    TimedOut {
        /// The host asked last.
        host: String,
        /// The limit in seconds.
        secs: u64,
    },
    /// The body ended before or ran past its `Content-Length`.
    #[error("https://{host}: the download does not match its Content-Length of {expected} bytes")]
    Length {
        /// The host.
        host: String,
        /// `Content-Length`.
        expected: u64,
    },
    /// The content is not the pinned one; nothing was kept.
    #[error("the download does not have the pinned SHA-256 {expected}; nothing was kept")]
    Mismatch {
        /// The pinned hash, as hex.
        expected: String,
    },
    /// The network or WinHTTP (the error carries the Win32 code).
    #[error("network: {0}")]
    Network(SysError),
    /// A cache entry Rerun never uses (a hard link, a directory, a reparse point).
    #[error("the cache entry {name} cannot be used ({error}); remove it from the cache folder")]
    CacheEntry {
        /// Its name below `cache`.
        name: String,
        /// Why.
        error: SysError,
    },
    /// A cache entry that cannot be read or removed now (in use, or another passing error).
    #[error("the cache entry {name} cannot be used now ({error}); try again")]
    CacheBusy {
        /// Its name below `cache`.
        name: String,
        /// Why.
        error: SysError,
    },
    /// Rerun's folder or `cache`.
    #[error(transparent)]
    Root(Box<RootError>),
    /// The file system of the cache.
    #[error(transparent)]
    Sys(SysError),
}

impl FetchError {
    /// Whether the failure is passing or lies in the environment (ADR 0025, exit 1 of `package
    /// fetch`): the network, HTTP 5xx and 429, a body that does not match its `Content-Length`,
    /// the overall deadline, a cache entry in use, the file system. Everything else is a refusal
    /// by policy or integrity (exit 3 when nothing was changed).
    pub fn transient(&self) -> bool {
        match self {
            Self::Network(_)
            | Self::Length { .. }
            | Self::TimedOut { .. }
            | Self::CacheBusy { .. }
            | Self::Root(_)
            | Self::Sys(_) => true,
            Self::Status { status, .. } => *status >= 500 || *status == 429,
            _ => false,
        }
    }
}

impl From<RootError> for FetchError {
    fn from(e: RootError) -> Self {
        Self::Root(Box::new(e))
    }
}

impl From<SysError> for FetchError {
    fn from(e: SysError) -> Self {
        Self::Sys(e)
    }
}

fn seg(s: &str) -> RelPath {
    match RelPath::from_segment(s) {
        Ok(p) => p,
        Err(e) => unreachable!("{s} is a fixed valid segment: {e}"),
    }
}

/// The name of an archive in `cache`: its SHA-256 as 64 lower-case hex digits.
pub fn cache_name(sha256: &[u8; 32]) -> String {
    hex32::to_string(sha256)
}

/// The downloads of a package of the signed index: `source.release` with `sha256`, or one per
/// `assets[]` entry. A community package has none (the user downloads it from its page), nor
/// has a draft value (`TODO`). Every URL is checked again against the form and the provenance
/// rule (the loader checked both; the downloader does not rely on it).
pub fn downloads(p: &Package) -> Result<Vec<Download>, FetchError> {
    let id = p.id.as_str();
    let none = |why| FetchError::NoDownload {
        id: id.to_owned(),
        why,
    };
    if p.tier == Tier::Community {
        return Err(none(
            "a community package is downloaded by the user from its original page",
        ));
    }
    let one = |arch: Option<Arch>, url: &str, sha: &Sha256| -> Result<Download, FetchError> {
        let sha256 = *sha.bytes().ok_or_else(|| none("its SHA-256 is TODO"))?;
        if url == crate::catalog::model::TODO {
            return Err(none("its URL is TODO"));
        }
        let url_ok = HttpsUrl::download(url)?;
        if !belongs(url, p.source.repo.as_deref(), p.source.page.as_deref()) {
            return Err(FetchError::Provenance { id: id.to_owned() });
        }
        Ok(Download {
            arch,
            url: url_ok,
            sha256,
        })
    };
    match (&p.source.release, &p.sha256, &p.assets) {
        (Some(url), Some(sha), None) => Ok(vec![one(None, url, sha)?]),
        (None, None, Some(assets)) if !assets.is_empty() => assets
            .iter()
            .map(|a| one(Some(a.arch), &a.url, &a.sha256))
            .collect(),
        _ => Err(none("neither source.release with sha256 nor assets")),
    }
}

/// A progress report is made every this many bytes (and at the first and the last read).
pub const PROGRESS_STEP: u64 = 64 * 1024;

/// How far the body of a download has come (P5-5b).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reading {
    /// Bytes read so far.
    pub read: u64,
    /// The announced `Content-Length` (advisory), if the server sent one.
    pub announced: Option<u64>,
}

/// The body of the last response, counted against `Content-Length` and the limit; remembers why
/// it failed, so a failure inside `create_new` is reported as what it was.
struct Tap<'a> {
    body: Box<dyn Read + Send + 'a>,
    host: String,
    read: u64,
    expected: Option<u64>,
    limits: Limits,
    started: Instant,
    failed: Option<FetchError>,
    cancel: Option<&'a AtomicBool>,
    on_read: &'a mut dyn FnMut(Reading),
    /// Bytes read at the last report (`None`: none yet).
    reported: Option<u64>,
}

impl Tap<'_> {
    fn stop(&mut self, why: FetchError) -> io::Error {
        self.failed = Some(why);
        io::Error::other("download stopped")
    }
}

impl Read for Tap<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if cancelled(self.cancel) {
            return Err(self.stop(FetchError::Cancelled));
        }
        if let Some(why) = self.limits.past(self.started, &self.host) {
            return Err(self.stop(why));
        }
        let n = match self.body.read(buf) {
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => return Err(e),
            Err(e) => {
                let why = FetchError::Network(SysError::io(&e, format!("https://{}", self.host)));
                return Err(self.stop(why));
            }
        };
        self.read = self
            .read
            .saturating_add(u64::try_from(n).unwrap_or(u64::MAX));
        let host = self.host.clone();
        if self.read > self.limits.bytes {
            let limit = self.limits.bytes;
            return Err(self.stop(FetchError::TooLarge { host, limit }));
        }
        if let Some(expected) = self.expected
            && ((n == 0 && self.read != expected) || self.read > expected)
        {
            return Err(self.stop(FetchError::Length { host, expected }));
        }
        if self
            .reported
            .is_none_or(|r| n == 0 || self.read.saturating_sub(r) >= PROGRESS_STEP)
        {
            self.reported = Some(self.read);
            (self.on_read)(Reading {
                read: self.read,
                announced: self.expected,
            });
        }
        Ok(n)
    }
}

fn cancelled(flag: Option<&AtomicBool>) -> bool {
    flag.is_some_and(|f| f.load(Ordering::SeqCst))
}

/// The bounds of one download.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Limits {
    /// Most bytes ([`MAX_DOWNLOAD_BYTES`]).
    pub(crate) bytes: u64,
    /// Most time from the first request ([`MAX_DOWNLOAD_TIME`]).
    pub(crate) time: Duration,
}

impl Limits {
    const PRODUCT: Self = Self {
        bytes: MAX_DOWNLOAD_BYTES,
        time: MAX_DOWNLOAD_TIME,
    };

    /// `TimedOut` once `time` has passed since `started`.
    fn past(&self, started: Instant, host: &str) -> Option<FetchError> {
        (started.elapsed() >= self.time).then(|| FetchError::TimedOut {
            host: host.to_owned(),
            secs: self.time.as_secs(),
        })
    }
}

/// A guard error at a cache entry: a link, a directory or a reparse point is never used
/// ([`FetchError::CacheEntry`], remove it); anything else is passing ([`FetchError::CacheBusy`]).
fn entry_error(name: &RelPath, error: SysError) -> FetchError {
    let name = name.to_string();
    match error.kind {
        SysErrorKind::Linked
        | SysErrorKind::ReparsePoint
        | SysErrorKind::AccessDenied
        | SysErrorKind::InvalidPath => FetchError::CacheEntry { name, error },
        _ => FetchError::CacheBusy { name, error },
    }
}

/// Deletes the temp files an interrupted fetch left in `cache` (module docs, step 2). Best
/// effort: a file that cannot be guarded or deleted stays.
fn sweep(dir: &dyn DirWrite) {
    let Ok(entries) = dir.read_dir_limited(None, MAX_CACHE_ENTRIES) else {
        return;
    };
    for e in entries {
        if e.meta.kind != EntryKind::File || TmpName::parse(&e.name).is_none() {
            continue;
        }
        let name = seg(&e.name);
        if let Ok(mut g) = dir.guard(&name)
            && let Ok(sha) = g.sha256()
        {
            let _ = g.delete(&sha);
        }
    }
}

/// Whether `cache\<name>` holds `sha256`: `Ok(Some(len))` yes; `Ok(None)` no entry, or one with
/// other content, which is deleted (`replaced` set).
fn check_cached(
    dir: &dyn DirWrite,
    name: &RelPath,
    sha256: &[u8; 32],
    replaced: &mut bool,
) -> Result<Option<u64>, FetchError> {
    let entry = |error: SysError| entry_error(name, error);
    let mut g = match dir.guard(name) {
        Ok(g) => g,
        Err(e) if e.kind == SysErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(entry(e)),
    };
    let have = g.sha256().map_err(entry)?;
    if &have == sha256 {
        return Ok(Some(g.metadata().map_err(entry)?.len));
    }
    g.delete(&have).map_err(entry)?;
    *replaced = true;
    Ok(None)
}

/// Fetches `d` into `<AppDir>\cache\<sha256>` (module docs).
pub fn fetch(
    sys: &dyn System,
    http: &dyn Http,
    app: &AppDir<'_>,
    d: &Download,
) -> Result<Fetched, FetchError> {
    fetch_noting(sys, http, app, d, &mut false)
}

/// [`fetch`] that sets `changed` once it stored or deleted anything in the cache (a new archive,
/// a damaged entry removed), also when it fails afterwards: `package fetch` then reports progress
/// instead of "nothing changed" (ADR 0025, exit codes).
pub fn fetch_noting(
    sys: &dyn System,
    http: &dyn Http,
    app: &AppDir<'_>,
    d: &Download,
    changed: &mut bool,
) -> Result<Fetched, FetchError> {
    fetch_with(sys, http, app, d, Limits::PRODUCT, changed)
}

/// [`fetch_noting`] that reports the progress of the body and stops when `cancel` is set (P5-5b,
/// module docs). A cancel before anything started touches nothing; a cancel during the body
/// leaves no archive and no temp file ([`FetchError::Cancelled`]).
pub fn fetch_watched(
    sys: &dyn System,
    http: &dyn Http,
    app: &AppDir<'_>,
    d: &Download,
    changed: &mut bool,
    on_read: &mut dyn FnMut(Reading),
    cancel: &AtomicBool,
) -> Result<Fetched, FetchError> {
    fetch_watching(
        sys,
        http,
        app,
        d,
        Limits::PRODUCT,
        changed,
        on_read,
        Some(cancel),
    )
}

/// [`fetch`] with other limits (tests: a small byte limit, a zero deadline).
pub(crate) fn fetch_with(
    sys: &dyn System,
    http: &dyn Http,
    app: &AppDir<'_>,
    d: &Download,
    limits: Limits,
    changed: &mut bool,
) -> Result<Fetched, FetchError> {
    fetch_watching(sys, http, app, d, limits, changed, &mut |_| {}, None)
}

/// [`fetch_with`] that reports progress and listens to `cancel`.
#[expect(
    clippy::too_many_arguments,
    reason = "one body for the public fetches and the tests; each argument is one thing"
)]
pub(crate) fn fetch_watching(
    sys: &dyn System,
    http: &dyn Http,
    app: &AppDir<'_>,
    d: &Download,
    limits: Limits,
    changed: &mut bool,
    on_read: &mut dyn FnMut(Reading),
    cancel: Option<&AtomicBool>,
) -> Result<Fetched, FetchError> {
    // Before anything is opened or created.
    if cancelled(cancel) {
        return Err(FetchError::Cancelled);
    }
    crate::exec::standard_user(sys).map_err(|_| FetchError::Elevated)?;
    let dir = app
        .sub_write(AppSub::Cache, Create::IfMissing)?
        .ok_or_else(|| SysError::new(SysErrorKind::NotFound, "cache"))?;
    let _lock = dir.lock(&seg(LOCK))?;
    sweep(&*dir);
    let name = seg(&cache_name(&d.sha256));
    let mut replaced = false;
    let hit = check_cached(&*dir, &name, &d.sha256, &mut replaced);
    *changed |= replaced;
    if let Some(len) = hit? {
        return Ok(Fetched {
            sha256: d.sha256,
            len,
            how: How::Cached,
        });
    }
    let started = Instant::now();
    let mut url = d.url.clone();
    let mut redirects = 0;
    let resp = loop {
        if let Some(why) = limits.past(started, url.host()) {
            return Err(why);
        }
        if cancelled(cancel) {
            return Err(FetchError::Cancelled);
        }
        let resp = http
            .get(url.host(), url.path())
            .map_err(FetchError::Network)?;
        match resp.status {
            200 => break resp,
            301 | 302 | 303 | 307 | 308 => {
                let host = url.host().to_owned();
                let loc = resp
                    .location
                    .as_deref()
                    .ok_or_else(|| FetchError::NoLocation { host: host.clone() })?;
                let next = url.redirect(loc)?;
                drop(resp);
                redirects += 1;
                if redirects > MAX_REDIRECTS {
                    return Err(FetchError::TooManyRedirects { host });
                }
                url = next;
            }
            status => {
                return Err(FetchError::Status {
                    host: url.host().to_owned(),
                    status,
                });
            }
        }
    };
    let host = url.host().to_owned();
    if resp.length.is_some_and(|n| n > limits.bytes) {
        return Err(FetchError::TooLarge {
            host,
            limit: limits.bytes,
        });
    }
    let mut tap = Tap {
        body: resp.body,
        host,
        read: 0,
        expected: resp.length,
        limits,
        started,
        failed: None,
        cancel,
        on_read,
        reported: None,
    };
    let new = NewFile {
        tmp: TmpName::new(InstanceTag::new().get(), 0),
        attrs: Attrs::default(),
        sha256: d.sha256,
        max_len: limits.bytes,
    };
    let written = dir.create_new(&name, &mut tap, &new);
    if let Some(why) = tap.failed.take() {
        return Err(why);
    }
    let written = match written {
        Ok(w) => w,
        Err(e) if e.kind == SysErrorKind::Mismatch => {
            return Err(FetchError::Mismatch {
                expected: cache_name(&d.sha256).to_ascii_uppercase(),
            });
        }
        Err(e) if e.kind == SysErrorKind::TooLarge => {
            return Err(FetchError::TooLarge {
                host: tap.host,
                limit: limits.bytes,
            });
        }
        Err(e) => return Err(FetchError::Sys(e)),
    };
    *changed = true;
    dir.flush()?;
    Ok(Fetched {
        sha256: written.sha256,
        len: written.len,
        how: How::Downloaded {
            redirects,
            replaced,
        },
    })
}
