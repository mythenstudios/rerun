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
//! A cached file is still untrusted: whoever uses it (extraction, P4-7) hashes it again on its
//! own handle.

use std::io::{self, Read};

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
/// Most entries of `cache` listed when temp files are swept; a larger folder is not swept.
const MAX_CACHE_ENTRIES: usize = 4096;
/// The lock file of the cache.
const LOCK: &str = "lock";

/// One download of a package: an archive at a URL with its pinned SHA-256.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Download {
    /// The architecture of a per-architecture asset (`assets[]`), `None` for `source.release`.
    pub arch: Option<Arch>,
    /// Where it is fetched from.
    pub url: HttpsUrl,
    /// What it must hash to.
    pub sha256: [u8; 32],
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
    /// A cache entry that cannot be checked or removed (a link, a directory, a reparse point).
    #[error("the cache entry {name} cannot be used ({error}); remove it from the cache folder")]
    CacheEntry {
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

/// The body of the last response, counted against `Content-Length` and the limit; remembers why
/// it failed, so a failure inside `create_new` is reported as what it was.
struct Tap<'a> {
    body: Box<dyn Read + Send + 'a>,
    host: String,
    read: u64,
    expected: Option<u64>,
    limit: u64,
    failed: Option<FetchError>,
}

impl Tap<'_> {
    fn stop(&mut self, why: FetchError) -> io::Error {
        self.failed = Some(why);
        io::Error::other("download stopped")
    }
}

impl Read for Tap<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
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
        if self.read > self.limit {
            let limit = self.limit;
            return Err(self.stop(FetchError::TooLarge { host, limit }));
        }
        if let Some(expected) = self.expected
            && ((n == 0 && self.read != expected) || self.read > expected)
        {
            return Err(self.stop(FetchError::Length { host, expected }));
        }
        Ok(n)
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
    let entry = |error: SysError| FetchError::CacheEntry {
        name: name.to_string(),
        error,
    };
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
    fetch_limited(sys, http, app, d, MAX_DOWNLOAD_BYTES)
}

/// [`fetch`] with another limit than [`MAX_DOWNLOAD_BYTES`] (tests: a small limit instead of a
/// 64 MiB body).
pub(crate) fn fetch_limited(
    sys: &dyn System,
    http: &dyn Http,
    app: &AppDir<'_>,
    d: &Download,
    limit: u64,
) -> Result<Fetched, FetchError> {
    crate::exec::standard_user(sys).map_err(|_| FetchError::Elevated)?;
    let dir = app
        .sub_write(AppSub::Cache, Create::IfMissing)?
        .ok_or_else(|| SysError::new(SysErrorKind::NotFound, "cache"))?;
    let _lock = dir.lock(&seg(LOCK))?;
    sweep(&*dir);
    let name = seg(&cache_name(&d.sha256));
    let mut replaced = false;
    if let Some(len) = check_cached(&*dir, &name, &d.sha256, &mut replaced)? {
        return Ok(Fetched {
            sha256: d.sha256,
            len,
            how: How::Cached,
        });
    }
    let mut url = d.url.clone();
    let mut redirects = 0;
    let resp = loop {
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
    if resp.length.is_some_and(|n| n > limit) {
        return Err(FetchError::TooLarge { host, limit });
    }
    let mut tap = Tap {
        body: resp.body,
        host,
        read: 0,
        expected: resp.length,
        limit,
        failed: None,
    };
    let new = NewFile {
        tmp: TmpName::new(InstanceTag::new().get(), 0),
        attrs: Attrs::default(),
        sha256: d.sha256,
        max_len: limit,
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
                limit,
            });
        }
        Err(e) => return Err(FetchError::Sys(e)),
    };
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
