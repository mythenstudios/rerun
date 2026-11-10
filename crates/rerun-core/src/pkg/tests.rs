//! The package download (ADR 0025, P4-6) against the fake: the cache holds an archive only
//! under its pinned hash, every redirect is checked before it is requested, limits are enforced
//! on the bytes read, and nothing is left behind by a failure.

use std::path::Path;
use std::time::Duration;

use sha2::{Digest, Sha256};

use super::download::{
    Download, FetchError, Fetched, How, Limits, MAX_DOWNLOAD_BYTES, MAX_DOWNLOAD_TIME, cache_name,
    downloads, fetch, fetch_noting, fetch_with,
};
use crate::catalog::model::{Arch, ArchList, Asset, Hex, Id, Package, PackageSource, Status, Tier};
use crate::path::RelPath;
use crate::policy::root::{AppDir, AppSub, Create};
use crate::policy::url::{HttpsUrl, UrlError};
use crate::sys::fake::{FakeHttp, FakeReply, FakeSystem, Fault, Prim};
use crate::sys::{SysErrorKind, System};

const LAD: &str = r"C:\Users\Player\AppData\Local";
const CACHE: &str = r"C:\Users\Player\AppData\Local\Rerun\cache";
const ASSET: &str = "https://github.com/owner/fix-pack/releases/download/v1.0/fix-pack.zip";
const STORE: &str = "https://release-assets.githubusercontent.com/github-production-release-asset/1/2?sp=r&sig=a%2Bb%3D";
const BODY: &[u8] = b"PK\x03\x04 a small archive";

fn sha(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}

fn sys() -> FakeSystem {
    FakeSystem::builder().dir(LAD).build().unwrap()
}

fn app(sys: &FakeSystem) -> AppDir<'_> {
    AppDir::open(sys, Create::IfMissing).unwrap().unwrap()
}

fn download(content: &[u8]) -> Download {
    Download::for_test(None, HttpsUrl::download(ASSET).unwrap(), sha(content))
}

/// [`fetch`] with a byte limit of `bytes`.
fn fetch_limited(
    sys: &FakeSystem,
    http: &FakeHttp,
    app: &AppDir<'_>,
    d: &Download,
    bytes: u64,
) -> Result<Fetched, FetchError> {
    let limits = Limits {
        bytes,
        time: MAX_DOWNLOAD_TIME,
    };
    fetch_with(sys, http, app, d, limits, &mut false)
}

/// GitHub's answer: a redirect to its asset storage, which serves `body`.
fn github(body: FakeReply) -> FakeHttp {
    let http = FakeHttp::default();
    http.reply(ASSET, FakeReply::redirect(302, STORE));
    http.reply(STORE, body);
    http
}

/// The names in `cache` (without the lock file), sorted.
fn cached(sys: &FakeSystem) -> Vec<String> {
    let a = AppDir::open(sys, Create::Never).unwrap().unwrap();
    let Some(dir) = a.sub(AppSub::Cache).unwrap() else {
        return Vec::new();
    };
    let mut names: Vec<String> = dir
        .read_dir(None)
        .unwrap()
        .into_iter()
        .map(|e| e.name)
        .filter(|n| n != "lock")
        .collect();
    names.sort();
    names
}

/// What the cache holds under the name of `content`.
fn stored(sys: &FakeSystem, content: &[u8]) -> Vec<u8> {
    let a = AppDir::open(sys, Create::Never).unwrap().unwrap();
    let dir = a.sub(AppSub::Cache).unwrap().unwrap();
    dir.read(&RelPath::from_segment(&cache_name(&sha(content))).unwrap())
        .unwrap()
}

fn cache_file(content: &[u8]) -> String {
    format!(r"{CACHE}\{}", cache_name(&sha(content)))
}

#[test]
fn a_download_follows_the_github_redirect_and_lands_under_its_hash() {
    let sys = sys();
    let http = github(FakeReply::ok(BODY));
    let got = fetch(&sys, &http, &app(&sys), &download(BODY)).unwrap();
    assert_eq!(got.sha256, sha(BODY));
    assert_eq!(got.len, BODY.len() as u64);
    assert_eq!(
        got.how,
        How::Downloaded {
            redirects: 1,
            replaced: false
        }
    );
    assert_eq!(http.requests(), [ASSET, STORE]);
    assert_eq!(cached(&sys), [cache_name(&sha(BODY))]);
    assert_eq!(stored(&sys, BODY), BODY);

    // Again: a cache hit, hashed, no request.
    http.clear_requests();
    let again = fetch(&sys, &http, &app(&sys), &download(BODY)).unwrap();
    assert_eq!(again.how, How::Cached);
    assert_eq!(again.len, BODY.len() as u64);
    assert!(http.requests().is_empty());
}

#[test]
fn a_wrong_hash_keeps_nothing() {
    let sys = sys();
    let http = github(FakeReply::ok(b"PK another archive"));
    let e = fetch(&sys, &http, &app(&sys), &download(BODY)).unwrap_err();
    assert!(matches!(e, FetchError::Mismatch { .. }), "{e:?}");
    assert_eq!(cached(&sys), Vec::<String>::new());
}

#[test]
fn a_refused_redirect_is_never_requested() {
    for (location, want) in [
        ("https://evil.example/fix-pack.zip", None),
        (
            "https://github.com/other/repo/releases/download/v1/a.zip",
            None,
        ),
        (
            "http://release-assets.githubusercontent.com/a",
            Some(UrlError::NotHttps),
        ),
        (
            "https://release-assets.githubusercontent.com:8443/a",
            Some(UrlError::Port),
        ),
        ("https://185.199.108.133/a", Some(UrlError::IpLiteral)),
        (
            "https://user@release-assets.githubusercontent.com/a",
            Some(UrlError::Userinfo),
        ),
        ("/owner/fix-pack/other.zip", Some(UrlError::Relative)),
    ] {
        let sys = sys();
        let http = FakeHttp::default();
        http.reply(ASSET, FakeReply::redirect(302, location));
        http.reply(location, FakeReply::ok(BODY));
        let e = fetch(&sys, &http, &app(&sys), &download(BODY)).unwrap_err();
        match (&e, want) {
            (FetchError::Url(UrlError::NotAllowed { .. }), None) => {}
            (FetchError::Url(got), Some(want)) if *got == want => {}
            _ => panic!("{location}: {e:?}"),
        }
        assert_eq!(http.requests(), [ASSET], "{location}");
        assert_eq!(cached(&sys), Vec::<String>::new(), "{location}");
    }
}

#[test]
fn statuses_other_than_200_and_redirects_fail() {
    let sys = sys();
    let http = FakeHttp::default();
    http.reply(ASSET, FakeReply::status(404));
    assert!(matches!(
        fetch(&sys, &http, &app(&sys), &download(BODY)),
        Err(FetchError::Status { status: 404, .. })
    ));
    let mut no_location = FakeReply::redirect(302, "");
    no_location.location = None;
    http.reply(ASSET, no_location);
    assert!(matches!(
        fetch(&sys, &http, &app(&sys), &download(BODY)),
        Err(FetchError::NoLocation { .. })
    ));
    // A host nobody answers for: a connection error with its WinHTTP code.
    let e = fetch(&sys, &FakeHttp::default(), &app(&sys), &download(BODY)).unwrap_err();
    match e {
        FetchError::Network(s) => assert_eq!(s.win32, Some(12029)),
        other => panic!("{other:?}"),
    }
    assert_eq!(cached(&sys), Vec::<String>::new());
}

#[test]
fn the_limit_counts_the_bytes_read_not_the_header() {
    let body = vec![0x5A; 100];
    let sys = sys();
    // An honest Content-Length above the limit: refused before reading (the body would fail at
    // its first byte, so without the pre-check this is a network error).
    let mut honest = FakeReply::ok(&body);
    honest.cut_after = Some(0);
    let http = github(honest);
    let e = fetch_limited(&sys, &http, &app(&sys), &download(&body), 99).unwrap_err();
    assert!(matches!(e, FetchError::TooLarge { limit: 99, .. }), "{e:?}");
    // No Content-Length: the bytes read count.
    let mut silent = FakeReply::ok(&body);
    silent.length = None;
    let http = github(silent);
    let e = fetch_limited(&sys, &http, &app(&sys), &download(&body), 99).unwrap_err();
    assert!(matches!(e, FetchError::TooLarge { limit: 99, .. }), "{e:?}");
    // A Content-Length that lies low.
    let mut liar = FakeReply::ok(&body);
    liar.length = Some(10);
    let http = github(liar);
    let e = fetch_limited(&sys, &http, &app(&sys), &download(&body), 1000).unwrap_err();
    assert!(
        matches!(e, FetchError::Length { expected: 10, .. }),
        "{e:?}"
    );
    // One that promises more than comes.
    let mut short = FakeReply::ok(&body);
    short.length = Some(200);
    let http = github(short);
    let e = fetch_limited(&sys, &http, &app(&sys), &download(&body), 1000).unwrap_err();
    assert!(
        matches!(e, FetchError::Length { expected: 200, .. }),
        "{e:?}"
    );
    assert_eq!(cached(&sys), Vec::<String>::new());
    // Exactly the limit is fine.
    let http = github(FakeReply::ok(&body));
    fetch_limited(&sys, &http, &app(&sys), &download(&body), 100).unwrap();
    const { assert!(MAX_DOWNLOAD_BYTES == 64 * 1024 * 1024) };
}

#[test]
fn an_abort_in_the_middle_keeps_nothing() {
    let sys = sys();
    let mut cut = FakeReply::ok(BODY);
    cut.cut_after = Some(5);
    let http = github(cut);
    let e = fetch(&sys, &http, &app(&sys), &download(BODY)).unwrap_err();
    match e {
        FetchError::Network(s) => assert_eq!(s.win32, Some(12030)),
        other => panic!("{other:?}"),
    }
    assert_eq!(cached(&sys), Vec::<String>::new());
}

#[test]
fn a_damaged_cache_entry_is_downloaded_again() {
    let sys = sys();
    let http = github(FakeReply::ok(BODY));
    fetch(&sys, &http, &app(&sys), &download(BODY)).unwrap();
    // Another process of the user swaps the content under the name.
    sys.fake_fs()
        .put_file(Path::new(&cache_file(BODY)), b"PK tampered")
        .unwrap();
    http.clear_requests();
    let got = fetch(&sys, &http, &app(&sys), &download(BODY)).unwrap();
    assert_eq!(
        got.how,
        How::Downloaded {
            redirects: 1,
            replaced: true
        }
    );
    assert_eq!(http.requests(), [ASSET, STORE]);
    assert_eq!(stored(&sys, BODY), BODY);
}

#[test]
fn a_linked_or_reparse_cache_entry_is_named_not_used() {
    let sys = sys();
    let http = github(FakeReply::ok(BODY));
    fetch(&sys, &http, &app(&sys), &download(BODY)).unwrap();
    // A hard link to the cache entry from elsewhere: never trusted, never deleted through.
    sys.fake_fs()
        .put_hardlink(
            Path::new(&cache_file(BODY)),
            Path::new(r"C:\Users\Player\elsewhere.zip"),
        )
        .unwrap();
    let e = fetch(&sys, &http, &app(&sys), &download(BODY)).unwrap_err();
    match &e {
        FetchError::CacheEntry { error, .. } => assert_eq!(error.kind, SysErrorKind::Linked),
        other => panic!("{other:?}"),
    }
    // A junction planted at another entry's name.
    let other = b"PK other";
    sys.fake_fs()
        .put_link(
            Path::new(&cache_file(other)),
            crate::sys::fs::tag::MOUNT_POINT,
            r"C:\Windows",
        )
        .unwrap();
    let e = fetch(&sys, &http, &app(&sys), &download(other)).unwrap_err();
    assert!(matches!(e, FetchError::CacheEntry { .. }), "{e:?}");
}

#[test]
fn a_crash_in_the_middle_leaves_a_temp_file_the_next_fetch_removes() {
    let sys = sys();
    let http = github(FakeReply::ok(BODY));
    let app_dir = app(&sys);
    sys.fake_fs().fault(Prim::Write, 1, Fault::CrashAfter);
    assert!(fetch(&sys, &http, &app_dir, &download(BODY)).is_err());
    drop(app_dir);
    sys.fake_fs().restart();
    sys.fake_fs().clear_faults();
    let left = cached(&sys);
    assert_eq!(left.len(), 1, "{left:?}");
    assert!(left[0].starts_with(".rerun-") && left[0].ends_with(".tmp"));
    fetch(&sys, &http, &app(&sys), &download(BODY)).unwrap();
    assert_eq!(cached(&sys), [cache_name(&sha(BODY))]);
}

#[test]
fn an_elevated_process_downloads_nothing() {
    let sys = sys();
    let a = app(&sys);
    sys.fake_registry().set_elevated(true);
    let http = github(FakeReply::ok(BODY));
    assert_eq!(
        fetch(&sys, &http, &a, &download(BODY)),
        Err(FetchError::Elevated)
    );
    assert!(http.requests().is_empty());
    assert!(a.sub(AppSub::Cache).unwrap().is_none());
    let _: &dyn System = &sys;
}

fn package() -> Package {
    Package {
        format: 1,
        id: Id::parse("fix-pack").unwrap(),
        name: "Fix pack".into(),
        status: Status::Active,
        tier: Tier::Established,
        source: PackageSource {
            repo: Some("https://github.com/owner/fix-pack".into()),
            page: None,
            release: Some(ASSET.into()),
        },
        version: "1.0".into(),
        sha256: Some(Hex::new([0xAB; 32])),
        assets: None,
        license: "MIT".into(),
        arch: ArchList::List(vec![Arch::X86]),
        apis: None,
        slots: vec![],
        slots_by_api: None,
        requires: vec![],
        requires_gpu: vec![],
        supports_exe_sha1: vec![],
        files: vec![],
        options: Default::default(),
    }
}

#[test]
fn a_package_names_its_downloads() {
    let p = package();
    let d = downloads(&p).unwrap();
    assert_eq!(d.len(), 1);
    assert_eq!((d[0].arch(), *d[0].sha256()), (None, [0xAB; 32]));
    assert_eq!(d[0].url().to_string(), ASSET);

    let mut per_arch = package();
    per_arch.source.release = None;
    per_arch.sha256 = None;
    per_arch.assets = Some(vec![
        Asset {
            arch: Arch::X86,
            url: "https://github.com/owner/fix-pack/releases/download/v1.0/x86.zip".into(),
            sha256: Hex::new([1; 32]),
        },
        Asset {
            arch: Arch::X64,
            url: "https://github.com/owner/fix-pack/releases/download/v1.0/x64.zip".into(),
            sha256: Hex::new([2; 32]),
        },
    ]);
    let d = downloads(&per_arch).unwrap();
    assert_eq!(
        d.iter()
            .map(|d| (d.arch(), d.sha256()[0]))
            .collect::<Vec<_>>(),
        [(Some(Arch::X86), 1), (Some(Arch::X64), 2)]
    );
}

#[test]
fn a_package_without_a_direct_download_has_none() {
    let mut community = package();
    community.tier = Tier::Community;
    assert!(matches!(
        downloads(&community),
        Err(FetchError::NoDownload { .. })
    ));
    let mut todo = package();
    todo.sha256 = Some(Hex::parse("TODO").unwrap());
    assert!(matches!(
        downloads(&todo),
        Err(FetchError::NoDownload { .. })
    ));
    let mut todo_url = package();
    todo_url.source.release = Some("TODO".into());
    assert!(matches!(
        downloads(&todo_url),
        Err(FetchError::NoDownload { .. })
    ));
    // Another repository's release: the downloader checks provenance itself.
    let mut foreign = package();
    foreign.source.release =
        Some("https://github.com/other/fix-pack/releases/download/v1.0/fix-pack.zip".into());
    assert_eq!(
        downloads(&foreign),
        Err(FetchError::Provenance {
            id: "fix-pack".into()
        })
    );
    let mut port = package();
    port.source.release =
        Some("https://github.com:444/owner/fix-pack/releases/download/v1/a".into());
    assert_eq!(downloads(&port), Err(FetchError::Url(UrlError::Form)));
}

#[test]
fn the_overall_deadline_ends_a_download() {
    let sys = sys();
    let http = github(FakeReply::ok(BODY));
    let limits = Limits {
        bytes: MAX_DOWNLOAD_BYTES,
        time: Duration::ZERO,
    };
    let e = fetch_with(&sys, &http, &app(&sys), &download(BODY), limits, &mut false).unwrap_err();
    assert!(matches!(e, FetchError::TimedOut { secs: 0, .. }), "{e:?}");
    assert!(e.transient());
    assert_eq!(cached(&sys), Vec::<String>::new());
    const { assert!(MAX_DOWNLOAD_TIME.as_secs() == 600) };
}

#[test]
fn a_held_cache_lock_refuses_and_sweeps_nothing() {
    let sys = sys();
    let a = app(&sys);
    let tmp = format!(r"{CACHE}\.rerun-00000000000000aa-0.tmp");
    sys.fake_fs().put_file(Path::new(&tmp), b"left").unwrap();
    let dir = a.sub_write(AppSub::Cache, Create::Never).unwrap().unwrap();
    let _held = dir.lock(&RelPath::from_segment("lock").unwrap()).unwrap();
    let http = github(FakeReply::ok(BODY));
    let e = fetch(&sys, &http, &a, &download(BODY)).unwrap_err();
    match &e {
        FetchError::Sys(s) => assert_eq!(s.kind, SysErrorKind::Busy),
        other => panic!("{other:?}"),
    }
    assert!(e.transient());
    assert!(http.requests().is_empty());
    assert_eq!(cached(&sys), [".rerun-00000000000000aa-0.tmp"]);
}

#[test]
fn changed_reports_what_a_failed_fetch_did_to_the_cache() {
    let sys = sys();
    // Nothing stored, nothing replaced: a wrong hash leaves `changed` false.
    let http = github(FakeReply::ok(b"PK other"));
    let mut changed = false;
    assert!(fetch_noting(&sys, &http, &app(&sys), &download(BODY), &mut changed).is_err());
    assert!(!changed);
    // A damaged entry is removed, then the download fails: `changed`.
    sys.fake_fs()
        .put_file(Path::new(&cache_file(BODY)), b"PK tampered")
        .unwrap();
    let mut cut = FakeReply::ok(BODY);
    cut.cut_after = Some(3);
    let http = github(cut);
    let e = fetch_noting(&sys, &http, &app(&sys), &download(BODY), &mut changed).unwrap_err();
    assert!(matches!(e, FetchError::Network(_)), "{e:?}");
    assert!(changed);
    // A stored archive: `changed`.
    let http = github(FakeReply::ok(BODY));
    let mut changed = false;
    fetch_noting(&sys, &http, &app(&sys), &download(BODY), &mut changed).unwrap();
    assert!(changed);
    // A cache hit changes nothing.
    let mut changed = false;
    fetch_noting(&sys, &http, &app(&sys), &download(BODY), &mut changed).unwrap();
    assert!(!changed);
}

#[test]
fn failures_are_refusals_or_transient() {
    let host = || "github.com".to_owned();
    for (e, transient) in [
        (
            FetchError::Status {
                host: host(),
                status: 503,
            },
            true,
        ),
        (
            FetchError::Status {
                host: host(),
                status: 429,
            },
            true,
        ),
        (
            FetchError::Status {
                host: host(),
                status: 404,
            },
            false,
        ),
        (
            FetchError::Status {
                host: host(),
                status: 403,
            },
            false,
        ),
        (
            FetchError::Length {
                host: host(),
                expected: 1,
            },
            true,
        ),
        (
            FetchError::TimedOut {
                host: host(),
                secs: 1,
            },
            true,
        ),
        (
            FetchError::TooLarge {
                host: host(),
                limit: 1,
            },
            false,
        ),
        (
            FetchError::Mismatch {
                expected: String::new(),
            },
            false,
        ),
        (FetchError::Url(UrlError::Port), false),
        (FetchError::Elevated, false),
    ] {
        assert_eq!(e.transient(), transient, "{e:?}");
    }
}
