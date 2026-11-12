//! Package downloads for a front end (P5-5b, ADR 0027 amendment P5-5b): what a fix needs
//! ([`PackageNeed`], the list the user consents to), and [`fetch`], which downloads, verifies and
//! unpacks it with progress and cancellation.
//!
//! - **The need is the consent.** A [`PackageNeed`] holds exactly what the user is shown before a
//!   byte is requested: name, version, licence, the source repository, and per download its URL,
//!   host and pinned SHA-256. [`fetch`] looks the package up in the current signed index again and
//!   refuses with [`FetchError::Changed`] when any of it differs from the need it was given, so a
//!   download is only ever made for the list that was shown. The size is not in the index; it is
//!   the `Content-Length` the server announces during the download ([`Progress::Download`]).
//! - **Nothing new is trusted.** Every check of ADR 0025 stays in `pkg::download` and
//!   `pkg::extract` (form and provenance of the URL, the redirect host list, the byte limit, the
//!   pinned hash before a file gets its name, zip-slip and the archive limits, only the named
//!   files); this module orders those calls as `rerun package fetch` does.
//! - **A cancel leaves nothing of the download that was running** (`pkg::download`: the temp file
//!   is deleted like after any failed body). A download that was finished before the cancel stays
//!   in the cache: it is complete and hash-pinned, and a retry takes it as a cache hit.
//! - **Reads nothing it does not need, creates nothing before it downloads.** [`need`] only reads
//!   (Rerun's folder is never created); [`fetch`] needs the folder to exist, which it does once an
//!   index is stored.

use std::sync::atomic::{AtomicBool, Ordering};

use crate::catalog::model::{Arch, Package, Tier};
use crate::catalog::{Catalog, EntryKind};
use crate::escape;
use crate::pkg::download::{self, Reading};
use crate::pkg::extract::{self, ExtractError, Unpacked};
use crate::policy::root::AppDir;

use super::{Guarded, IndexState, index_state};

/// One download of a package as the user is shown it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DownloadNeed {
    /// The architecture of a per-architecture asset, `None` for the package's one download.
    pub arch: Option<Arch>,
    /// The full `https` URL of the release asset (the first request).
    pub url: String,
    /// Its host (a redirect may continue on one of the fixed storage hosts, ADR 0025).
    pub host: String,
    /// The pinned SHA-256, 64 lower-case hex digits; checked after the download.
    pub sha256: String,
}

/// Whether a package is in Rerun's packages folder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NeedState {
    /// Every file is there with its pinned SHA-256: nothing to download.
    Unpacked,
    /// A download and unpacking is needed and possible.
    Missing,
    /// Rerun cannot download it (a community package, a draft value, a URL outside the rules, not
    /// in the index, set aside by this build); the text is the core's reason in English, not
    /// localised, and display text already escaped (`escape::text`): it may name parts of the
    /// signed entry.
    Unobtainable(String),
}

/// One package a fix names, with what the consent dialog shows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageNeed {
    /// The package ID.
    pub id: String,
    /// Its name.
    pub name: String,
    /// The pinned version.
    pub version: String,
    /// Its licence (an SPDX expression).
    pub license: String,
    /// The source tier.
    pub tier: Tier,
    /// The forge repository it comes from.
    pub repo: Option<String>,
    /// The original page (shown as the source when there is no repository).
    pub page: Option<String>,
    /// Its downloads (empty when [`NeedState::Unobtainable`]).
    pub downloads: Vec<DownloadNeed>,
    /// Where it stands.
    pub state: NeedState,
}

impl PackageNeed {
    /// What the consent covers: everything but the state (a package unpacked meanwhile is still
    /// the package that was shown).
    fn same_as(&self, o: &Self) -> bool {
        self.id == o.id
            && self.name == o.name
            && self.version == o.version
            && self.license == o.license
            && self.tier == o.tier
            && self.repo == o.repo
            && self.page == o.page
            && self.downloads == o.downloads
    }

    /// Whether [`fetch`] can be asked for it (a download is needed and allowed).
    pub fn fetchable(&self) -> bool {
        self.state == NeedState::Missing
    }
}

/// The need of the package `id` of `catalog`; `app` is Rerun's folder if it exists (never
/// created). Read only.
pub fn need(catalog: &Catalog, app: Option<&AppDir<'_>>, id: &str) -> PackageNeed {
    match catalog.package(id) {
        Some(p) => need_of(p, app),
        None => PackageNeed {
            id: id.to_owned(),
            name: id.to_owned(),
            version: String::new(),
            license: String::new(),
            tier: Tier::Community,
            repo: None,
            page: None,
            downloads: Vec::new(),
            // A set-aside package is never fetched (ADR 0024 amendment "Forward compatibility"
            // §10): the same answer as `rerun package fetch`.
            state: NeedState::Unobtainable(match catalog.aside_entry(EntryKind::Package, id) {
                Some(a) if a.why.needs_newer() => {
                    "the package needs a newer version of Rerun".to_owned()
                }
                Some(a) => format!(
                    "the package cannot be used by this version of Rerun ({})",
                    escape::text(&a.why.to_string())
                ),
                None => "the package is not in the signed index".to_owned(),
            }),
        },
    }
}

fn need_of(p: &Package, app: Option<&AppDir<'_>>) -> PackageNeed {
    let (downloads, state) = match download::downloads(p) {
        Err(e) => (
            Vec::new(),
            NeedState::Unobtainable(escape::text(&e.to_string()).to_string()),
        ),
        Ok(ds) => {
            let downloads = ds
                .iter()
                .map(|d| DownloadNeed {
                    arch: d.arch(),
                    url: d.url().to_string(),
                    host: d.url().host().to_owned(),
                    sha256: download::cache_name(d.sha256()),
                })
                .collect();
            let state = if extract::is_unpacked(app, p) {
                NeedState::Unpacked
            } else {
                NeedState::Missing
            };
            (downloads, state)
        }
    };
    PackageNeed {
        id: p.id.to_string(),
        name: p.name.clone(),
        version: p.version.clone(),
        license: p.license.clone(),
        tier: p.tier,
        repo: p.source.repo.clone(),
        page: p.source.page.clone(),
        downloads,
        state,
    }
}

/// How far a [`fetch`] has come.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Progress {
    /// The body of download `index` (of `of`) is being read.
    Download {
        /// Which download, from 0.
        index: usize,
        /// How many the package has.
        of: usize,
        /// Bytes read so far.
        read: u64,
        /// The announced `Content-Length`, if the server sent one (advisory).
        announced: Option<u64>,
    },
    /// Download `index` was in the cache already (hashed again), nothing is requested.
    Cached {
        /// Which download, from 0.
        index: usize,
        /// How many the package has.
        of: usize,
    },
    /// Every download is in the cache: the named files are unpacked.
    Unpacking,
}

/// What a finished [`fetch`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fetched {
    /// One entry per download, in the package's order.
    pub downloads: Vec<download::Fetched>,
    /// The files of the version folder.
    pub unpacked: Vec<Unpacked>,
}

/// Why a [`fetch`] failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FetchError {
    /// The caller cancelled; the download that was running left nothing in the cache.
    #[error("the download was cancelled; nothing was kept")]
    Cancelled,
    /// Rerun's folder does not exist or holds no current index.
    #[error("there is no current signed index")]
    NoIndex,
    /// The package is another one than the user was shown (the index changed in between).
    #[error("package {id} is not the one that was shown; look at it again")]
    Changed {
        /// The package ID.
        id: String,
    },
    /// The package cannot be downloaded by Rerun.
    #[error("package {id} cannot be downloaded: {why}")]
    Unobtainable {
        /// The package ID.
        id: String,
        /// Why.
        why: String,
    },
    /// The download failed or was refused.
    #[error(transparent)]
    Download(download::FetchError),
    /// The unpacking failed or was refused.
    #[error(transparent)]
    Unpack(#[from] ExtractError),
}

impl From<download::FetchError> for FetchError {
    fn from(e: download::FetchError) -> Self {
        match e {
            download::FetchError::Cancelled => Self::Cancelled,
            e => Self::Download(e),
        }
    }
}

/// The kind of a failure, for a front end's own words.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FetchKind {
    /// The caller cancelled.
    Cancelled,
    /// No network: the host cannot be resolved or reached.
    Offline,
    /// Too slow: a WinHTTP timeout or the overall deadline.
    TimedOut,
    /// The connection broke or the body did not match its length.
    Interrupted,
    /// A redirect to a host, scheme or form the rules refuse, or too many redirects.
    RedirectRefused,
    /// The server answered with another status than 200.
    Status,
    /// The content does not have the pinned SHA-256 (nothing was kept).
    WrongHash,
    /// More than the byte limit.
    TooLarge,
    /// The archive or a file in it was refused.
    ExtractionRefused,
    /// The package is not the one that was shown, or the index is gone.
    Changed,
    /// Rerun cannot download the package.
    Unobtainable,
    /// Anything else (the cache or the file system, elevation): the core's text is the detail.
    Other,
}

/// WinHTTP: the name does not resolve.
const NAME_NOT_RESOLVED: u32 = 12007;
/// WinHTTP: the server cannot be reached.
const CANNOT_CONNECT: u32 = 12029;
/// WinHTTP: a timeout.
const WINHTTP_TIMEOUT: u32 = 12002;

impl FetchError {
    /// The kind of failure.
    pub fn kind(&self) -> FetchKind {
        use download::FetchError as D;
        match self {
            Self::Cancelled => FetchKind::Cancelled,
            Self::NoIndex | Self::Changed { .. } => FetchKind::Changed,
            Self::Unobtainable { .. } => FetchKind::Unobtainable,
            // A passing I/O failure of the unpacking is not a refusal of the archive.
            Self::Unpack(e) if e.transient() => FetchKind::Other,
            Self::Unpack(_) => FetchKind::ExtractionRefused,
            Self::Download(d) => match d {
                D::Network(e) => match e.win32 {
                    Some(NAME_NOT_RESOLVED | CANNOT_CONNECT) => FetchKind::Offline,
                    Some(WINHTTP_TIMEOUT) => FetchKind::TimedOut,
                    _ => FetchKind::Interrupted,
                },
                D::TimedOut { .. } => FetchKind::TimedOut,
                D::Length { .. } => FetchKind::Interrupted,
                D::Url(_) | D::TooManyRedirects { .. } | D::NoLocation { .. } => {
                    FetchKind::RedirectRefused
                }
                D::Status { .. } => FetchKind::Status,
                D::Mismatch { .. } => FetchKind::WrongHash,
                D::TooLarge { .. } => FetchKind::TooLarge,
                D::NoDownload { .. } | D::Provenance { .. } => FetchKind::Unobtainable,
                _ => FetchKind::Other,
            },
        }
    }

    /// Whether trying again may help (a passing failure, `FetchError::transient`).
    pub fn transient(&self) -> bool {
        match self {
            Self::Download(d) => d.transient(),
            Self::Unpack(e) => e.transient(),
            Self::Cancelled | Self::NoIndex | Self::Changed { .. } | Self::Unobtainable { .. } => {
                false
            }
        }
    }
}

/// The hosts a download of the package's host may be handed over to (ADR 0025, the fixed
/// redirect list): where the bytes may come from besides the URL's own host.
pub fn redirect_hosts(host: &str) -> Vec<&'static str> {
    crate::policy::url::REDIRECTS
        .iter()
        .filter(|(from, _)| *from == host)
        .flat_map(|(_, to)| to.iter().copied())
        .collect()
}

/// Downloads, verifies and unpacks the package `need` (module docs): every download into the
/// cache under its pinned SHA-256, then the files the package names into
/// `<AppDir>\packages\<id>\<version>`. `on` hears the progress of the bodies; `cancel` is checked
/// before every request and every read. Writes only Rerun's own folders (the cache and the
/// packages folder), never the game.
pub fn fetch(
    g: &Guarded<'_>,
    need: &PackageNeed,
    on: &mut dyn FnMut(Progress),
    cancel: &AtomicBool,
) -> Result<Fetched, FetchError> {
    let cancelled = || cancel.load(Ordering::SeqCst);
    if cancelled() {
        return Err(FetchError::Cancelled);
    }
    let app = g.app().ok_or(FetchError::NoIndex)?;
    let catalog = match index_state(Some(app)) {
        IndexState::Current(c) => c,
        IndexState::None | IndexState::Refused(_) => return Err(FetchError::NoIndex),
    };
    let id = need.id.clone();
    let p = catalog
        .package(&need.id)
        .ok_or_else(|| FetchError::Changed { id: id.clone() })?;
    // The consent is for the list that was shown: the same package, version, licence, source,
    // URLs and hashes.
    let now = need_of(p, Some(app));
    if !need.same_as(&now) {
        return Err(FetchError::Changed { id });
    }
    let downloads = download::downloads(p)?;
    if downloads.is_empty() {
        return Err(FetchError::Unobtainable {
            id,
            why: "it has no download".to_owned(),
        });
    }
    let env = g.env();
    let of = downloads.len();
    let mut done = Vec::with_capacity(of);
    let mut changed = false;
    for (index, d) in downloads.iter().enumerate() {
        let mut report = |r: Reading| {
            on(Progress::Download {
                index,
                of,
                read: r.read,
                announced: r.announced,
            });
        };
        let got =
            download::fetch_watched(env.sys, env.http, app, d, &mut changed, &mut report, cancel)?;
        if got.how == download::How::Cached {
            on(Progress::Cached { index, of });
        }
        done.push(got);
    }
    if cancelled() {
        // Finished downloads stay (module docs); nothing is unpacked after a cancel.
        return Err(FetchError::Cancelled);
    }
    on(Progress::Unpacking);
    let mut unpacked = Vec::new();
    extract::extract_noting(env.sys, app, p, &mut unpacked)?;
    Ok(Fetched {
        downloads: done,
        unpacked,
    })
}

// The fetch reads the index through `catalog::trusted_keys()`, which holds the published test
// key only with the feature `test-key`: without it every index is refused (`NoKeys`), so the
// tests run with it (`cargo test -p rerun-core --features fake,test-key`, and the workspace run).
#[cfg(test)]
#[cfg(feature = "test-key")]
#[path = "packages_tests.rs"]
mod tests;
