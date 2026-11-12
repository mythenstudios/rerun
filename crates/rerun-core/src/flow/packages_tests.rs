//! Tests of the package flow (P5-5b, ADR 0027 amendment P5-5b) against the fake world and the
//! fake HTTPS side; no network. Every ID, URL and file is invented.
//! - FP1 what a fix needs: the list a consent shows (name, version, licence, source, URL, host,
//!   SHA-256), unpacked or missing, never created by looking; a community package cannot be
//!   downloaded.
//! - FP2 a fetch downloads, verifies and unpacks, reports its progress in order, and a second
//!   one finds everything in place.
//! - FP3 the consent is the list that was shown: a package that differs (a changed hash, URL or
//!   version) is refused before any request.
//! - FP4 a cancel in the middle of the body leaves no archive and no temp file in the cache and
//!   no packages folder; the next fetch works.
//! - FP5 every failure is typed and keeps nothing: offline, a wrong hash, a redirect to a foreign
//!   host, a status, a refused archive.

use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;

use sha2::{Digest, Sha256};

use crate::catalog::key::test_key;
use crate::catalog::{self};
use crate::pkg::archive::testfx::{ZipEntry, zip};
use crate::policy::root::{AppDir, AppSub, Create};
use crate::sys::fake::{FakeHttp, FakeReply, FakeSystem, Prim, Trip};

use super::{FetchError, FetchKind, NeedState, PackageNeed, Progress, fetch, need};
use crate::flow::{Env, Guarded, guard};

const INSTALL: &str = r"C:\Users\Player\AppData\Local\Programs\Rerun";
const ASSET: &str = "https://github.com/owner/fix-pack/releases/download/v1.0/fix-pack.zip";
const STORE: &str =
    "https://release-assets.githubusercontent.com/github-production-release-asset/1/2?sp=r";
const DLL: &[u8] = b"the fix dll";
const INI: &[u8] = b"[Fix]\r\nOn=1\r\n";

fn upper(b: &[u8]) -> String {
    Sha256::digest(b)
        .iter()
        .map(|x| format!("{x:02X}"))
        .collect()
}

fn lower(b: &[u8]) -> String {
    upper(b).to_ascii_lowercase()
}

/// Bytes that do not compress (a plain LCG), so the archive is as large as its content.
fn noise(n: usize) -> Vec<u8> {
    let mut x: u32 = 0x9E37_79B9;
    (0..n)
        .map(|_| {
            x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            x.to_be_bytes()[0]
        })
        .collect()
}

fn archive() -> Vec<u8> {
    // Padding makes the body larger than one progress step.
    zip(&[
        ZipEntry::file("bin/fix.dll", DLL),
        ZipEntry::file("fix.ini", INI),
        ZipEntry::file("README.txt", &noise(200 * 1024)),
    ])
}

fn package(archive: &[u8], tier: &str) -> String {
    // A community package has no direct download (the loader's rule): the user fetches it.
    let sha = format!(r#""sha256":"{}","#, upper(archive));
    let release = if tier == "community" {
        String::new()
    } else {
        format!(r#","release":"{ASSET}""#)
    };
    format!(
        r#"{{"format":1,"id":"fix-pack","name":"Fix pack","status":"active","tier":"{tier}","source":{{"repo":"https://github.com/owner/fix-pack","page":"https://github.com/owner/fix-pack"{release}}},"version":"1.0",{sha}"license":"MIT","arch":["x86"],"slots":["fix.dll"],"files":[{{"from":"bin/fix.dll","to":"fix.dll","sha256":"{d}"}},{{"from":"fix.ini","to":"fix.ini","sha256":"{i}","config":true}}]}}"#,
        d = upper(DLL),
        i = upper(INI),
    )
}

/// A world with the signed index holding `package`.
fn world(package: &str) -> FakeSystem {
    let sys = FakeSystem::builder()
        .windows_layout()
        .dir(INSTALL)
        .build()
        .unwrap();
    let ix = format!(
        r#"{{"format":1,"seq":1,"issued":"2026-11-10T12:00:00Z","topos":[],"packages":[{package}]}}"#
    );
    let app = AppDir::open(&sys, Create::IfMissing).unwrap().unwrap();
    catalog::store::import(
        &app,
        ix.as_bytes(),
        &test_key::sign(ix.as_bytes()),
        &catalog::trusted_keys(),
    )
    .unwrap_or_else(|e| panic!("{e}"));
    drop(app);
    sys.fake_fs().sync_all();
    sys
}

fn github(body: FakeReply) -> FakeHttp {
    let http = FakeHttp::default();
    http.reply(ASSET, FakeReply::redirect(302, STORE));
    http.reply(STORE, body);
    http
}

fn with_guard<R>(sys: &FakeSystem, http: &FakeHttp, f: impl FnOnce(&Guarded<'_>) -> R) -> R {
    let ok: Result<PathBuf, String> = Ok(PathBuf::from(INSTALL));
    let g = guard(Env {
        sys,
        http,
        install: &ok,
    })
    .unwrap_or_else(|e| panic!("{e:?}"));
    f(&g)
}

/// The need of `fix-pack` as the page of a game would hold it.
fn need_of(sys: &FakeSystem, http: &FakeHttp) -> PackageNeed {
    with_guard(sys, http, |g| {
        let state = super::index_state(g.app());
        let super::IndexState::Current(c) = state else {
            panic!("no index");
        };
        need(&c, g.app(), "fix-pack")
    })
}

/// What `cache` and `packages` hold (without the lock files), as sorted names.
fn listed(sys: &FakeSystem, sub: AppSub) -> Option<Vec<String>> {
    let a = AppDir::open(sys, Create::Never).unwrap().unwrap();
    let dir = a.sub(sub).unwrap()?;
    let mut names: Vec<String> = dir
        .read_dir(None)
        .unwrap()
        .into_iter()
        .map(|e| e.name)
        .filter(|n| n != "lock" && n != ".lock")
        .collect();
    names.sort();
    Some(names)
}

fn run(
    sys: &FakeSystem,
    http: &FakeHttp,
    n: &PackageNeed,
    cancel: &AtomicBool,
) -> (Result<super::Fetched, FetchError>, Vec<Progress>) {
    let mut seen = Vec::new();
    let r = with_guard(sys, http, |g| fetch(g, n, &mut |p| seen.push(p), cancel));
    (r, seen)
}

#[test]
fn fp1_what_a_fix_needs_is_the_list_a_consent_shows() {
    let a = archive();
    let sys = world(&package(&a, "established"));
    let http = FakeHttp::default();
    sys.fake_fs().record_calls(true);
    let n = need_of(&sys, &http);
    let calls = sys.fake_fs().take_calls();
    assert!(!calls.is_empty(), "the record bites");
    assert!(
        !calls.iter().any(|c| matches!(
            c,
            Prim::CreateTmp | Prim::CreateDir | Prim::Rename | Prim::Write | Prim::OpenLock
        )),
        "looking writes nothing: {calls:?}"
    );
    assert_eq!(
        (n.id.as_str(), n.name.as_str(), n.version.as_str()),
        ("fix-pack", "Fix pack", "1.0")
    );
    assert_eq!(n.license, "MIT");
    assert_eq!(n.repo.as_deref(), Some("https://github.com/owner/fix-pack"));
    assert_eq!(n.state, NeedState::Missing);
    assert!(n.fetchable());
    assert_eq!(n.downloads.len(), 1);
    let d = &n.downloads[0];
    assert_eq!(d.url, ASSET);
    assert_eq!(d.host, "github.com");
    assert_eq!(d.sha256, lower(&a));
    assert_eq!(d.arch, None);
    assert_eq!(listed(&sys, AppSub::Cache), None, "no cache folder made");
    assert_eq!(listed(&sys, AppSub::Packages), None);

    // A community package is the user's to download: not obtainable here.
    let sys = world(&package(&a, "community"));
    let n = need_of(&sys, &http);
    assert!(matches!(n.state, NeedState::Unobtainable(_)), "{n:?}");
    assert!(n.downloads.is_empty() && !n.fetchable());
    let (r, _) = run(&sys, &http, &n, &AtomicBool::new(false));
    assert_eq!(r.unwrap_err().kind(), FetchKind::Unobtainable);
    assert!(http.requests().is_empty());
}

#[test]
fn fp2_a_fetch_downloads_verifies_and_unpacks() {
    let a = archive();
    let sys = world(&package(&a, "established"));
    let http = github(FakeReply::ok(&a).chunked(16 * 1024));
    let n = need_of(&sys, &http);
    let (r, seen) = run(&sys, &http, &n, &AtomicBool::new(false));
    let done = r.unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(http.requests(), [ASSET, STORE]);
    assert_eq!(done.downloads.len(), 1);
    assert_eq!(done.unpacked.len(), 2, "{:?}", done.unpacked);
    // Progress: bodies with the announced length, then the unpacking last.
    assert!(matches!(seen.last(), Some(Progress::Unpacking)), "{seen:?}");
    let reads: Vec<(u64, Option<u64>)> = seen
        .iter()
        .filter_map(|p| match p {
            Progress::Download {
                index: 0,
                of: 1,
                read,
                announced,
            } => Some((*read, *announced)),
            _ => None,
        })
        .collect();
    assert!(reads.len() > 2, "{seen:?}");
    assert!(reads.iter().all(|(_, ann)| *ann == Some(a_len(&a))));
    assert_eq!(reads.last().map(|r| r.0), Some(a_len(&a)));
    // Now it is unpacked, the cache holds the archive under its hash, and a second fetch asks
    // nobody.
    assert_eq!(need_of(&sys, &http).state, NeedState::Unpacked);
    assert_eq!(listed(&sys, AppSub::Cache), Some(vec![lower(&a)]));
    assert_eq!(
        listed(&sys, AppSub::Packages),
        Some(vec!["fix-pack".to_owned()])
    );
    http.clear_requests();
    let (r, seen) = run(&sys, &http, &n, &AtomicBool::new(false));
    r.unwrap_or_else(|e| panic!("{e}"));
    assert!(http.requests().is_empty());
    assert!(
        matches!(seen[0], Progress::Cached { index: 0, of: 1 }),
        "{seen:?}"
    );

    // A tampered unpacked file is missing again.
    let dll = r"C:\Users\Player\AppData\Local\Rerun\packages\fix-pack\1.0\bin\fix.dll";
    sys.fake_fs().remove_abs(Path::new(dll)).unwrap();
    sys.fake_fs().put_file(Path::new(dll), b"swapped").unwrap();
    sys.fake_fs().sync_all();
    assert_eq!(need_of(&sys, &http).state, NeedState::Missing);
}

fn a_len(a: &[u8]) -> u64 {
    a.len() as u64
}

#[test]
fn fp3_the_consent_is_the_list_that_was_shown() {
    let a = archive();
    let sys = world(&package(&a, "established"));
    let http = github(FakeReply::ok(&a));
    let shown = need_of(&sys, &http);
    let never = AtomicBool::new(false);
    for change in [
        |n: &mut PackageNeed| n.downloads[0].sha256 = lower(b"another archive"),
        |n: &mut PackageNeed| n.downloads[0].url = ASSET.replace("v1.0", "v1.1"),
        |n: &mut PackageNeed| n.downloads[0].host = "evil.example".to_owned(),
        |n: &mut PackageNeed| n.version = "2.0".to_owned(),
        |n: &mut PackageNeed| n.license = "GPL-3.0-only".to_owned(),
        |n: &mut PackageNeed| n.id = "other".to_owned(),
    ] {
        let mut n = shown.clone();
        change(&mut n);
        let (r, seen) = run(&sys, &http, &n, &never);
        let e = r.unwrap_err();
        assert!(matches!(e, FetchError::Changed { .. }), "{e:?}");
        assert_eq!(e.kind(), FetchKind::Changed);
        assert!(seen.is_empty());
    }
    assert!(http.requests().is_empty(), "nothing was asked for");
    assert_eq!(listed(&sys, AppSub::Cache), None);
    // The state does not belong to the consent: a need read before another process unpacked
    // the package is still the package that was shown.
    let mut n = shown.clone();
    n.state = NeedState::Unpacked;
    assert!(run(&sys, &http, &n, &never).0.is_ok());
}

/// FP4: a cancel in the middle of the body leaves no archive and no temp file in the cache and
/// no packages folder, and the next fetch works.
#[test]
fn fp4_a_cancel_in_the_middle_leaves_nothing() {
    let a = archive();
    let sys = world(&package(&a, "established"));
    let trip = Trip::new();
    let http = github(
        FakeReply::ok(&a)
            .chunked(16 * 1024)
            .trip_after(100 * 1024, &trip),
    );
    let n = need_of(&sys, &http);
    let (r, seen) = run(&sys, &http, &n, trip.flag());
    let e = r.unwrap_err();
    assert_eq!(e, FetchError::Cancelled);
    assert_eq!(e.kind(), FetchKind::Cancelled);
    assert!(!e.transient());
    // It was in the middle of the body, and never got to unpacking.
    assert!(
        seen.iter()
            .any(|p| matches!(p, Progress::Download { read, .. } if *read > 0))
    );
    assert!(!seen.iter().any(|p| matches!(p, Progress::Unpacking)));
    assert_eq!(
        listed(&sys, AppSub::Cache),
        Some(Vec::new()),
        "no archive, no temp file"
    );
    assert_eq!(listed(&sys, AppSub::Packages), None, "nothing unpacked");
    assert_eq!(need_of(&sys, &http).state, NeedState::Missing);
    // Again, not cancelled.
    http.reply(STORE, FakeReply::ok(&a));
    let (r, _) = run(&sys, &http, &n, &AtomicBool::new(false));
    r.unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(need_of(&sys, &http).state, NeedState::Unpacked);

    // A cancel that is set before the job runs asks nobody and creates nothing.
    let sys = world(&package(&a, "established"));
    let http = github(FakeReply::ok(&a));
    let (r, seen) = run(&sys, &http, &need_of(&sys, &http), &AtomicBool::new(true));
    assert_eq!(r.unwrap_err(), FetchError::Cancelled);
    assert!(seen.is_empty() && http.requests().is_empty());
    assert_eq!(listed(&sys, AppSub::Cache), None);
}

/// FP5: every failure is typed, passes or not as the core says, and keeps nothing.
#[test]
fn fp5_every_failure_is_typed_and_keeps_nothing() {
    let a = archive();
    let sys = world(&package(&a, "established"));
    let n = need_of(&sys, &FakeHttp::default());
    let never = AtomicBool::new(false);
    let foreign = FakeHttp::default();
    foreign.reply(
        ASSET,
        FakeReply::redirect(302, "https://evil.example/fix-pack.zip"),
    );
    let mut cut = FakeReply::ok(&a);
    cut.cut_after = Some(1000);
    let cases: Vec<(FakeHttp, FetchKind, bool)> = vec![
        // Nobody answers: offline.
        (FakeHttp::default(), FetchKind::Offline, true),
        // Another archive under the pinned URL: the hash is the answer.
        (
            github(FakeReply::ok(b"PK another archive")),
            FetchKind::WrongHash,
            false,
        ),
        (foreign, FetchKind::RedirectRefused, false),
        (
            {
                let h = FakeHttp::default();
                h.reply(ASSET, FakeReply::status(404));
                h
            },
            FetchKind::Status,
            false,
        ),
        (
            {
                let h = FakeHttp::default();
                h.reply(ASSET, FakeReply::status(503));
                h
            },
            FetchKind::Status,
            true,
        ),
        (github(cut), FetchKind::Interrupted, true),
        (
            {
                let h = FakeHttp::default();
                h.reply(ASSET, FakeReply::fail(12002));
                h
            },
            FetchKind::TimedOut,
            true,
        ),
    ];
    for (i, (http, kind, transient)) in cases.iter().enumerate() {
        let (r, _) = run(&sys, http, &n, &never);
        let e = r.unwrap_err();
        assert_eq!((e.kind(), e.transient()), (*kind, *transient), "{i}: {e:?}");
        assert_eq!(
            listed(&sys, AppSub::Cache).unwrap_or_default(),
            Vec::<String>::new(),
            "{i}: nothing in the cache"
        );
        assert_eq!(listed(&sys, AppSub::Packages), None, "{i}");
    }

    // An archive with the pinned hash that does not hold the files the package names is
    // refused when it is unpacked; no file appears.
    let bad = zip(&[ZipEntry::file("other.txt", b"x")]);
    let sys = world(&package(&bad, "established"));
    let http = github(FakeReply::ok(&bad));
    let n = need_of(&sys, &http);
    let (r, seen) = run(&sys, &http, &n, &never);
    let e = r.unwrap_err();
    assert_eq!(e.kind(), FetchKind::ExtractionRefused, "{e:?}");
    assert!(matches!(seen.last(), Some(Progress::Unpacking)));
    assert_eq!(need_of(&sys, &http).state, NeedState::Missing);
    // The archive had its pinned hash: it stays in the cache (a refusal of its content is not a
    // failed download); nothing was unpacked.
    assert_eq!(listed(&sys, AppSub::Cache), Some(vec![lower(&bad)]));
    let files = listed(&sys, AppSub::Packages).unwrap_or_default();
    assert!(
        files.iter().all(|f| f != "fix-pack") || files.is_empty(),
        "{files:?}"
    );
}

/// FP6: a package with one download per architecture. A cancel during the second body keeps
/// the first archive (complete, under its pinned hash) and nothing of the second; the retry takes
/// the first as a cache hit and finishes.
#[test]
fn fp6_a_cancel_during_the_second_asset_keeps_the_first_complete() {
    const ASSET64: &str =
        "https://github.com/owner/fix-pack/releases/download/v1.0/fix-pack-x64.zip";
    const STORE64: &str =
        "https://release-assets.githubusercontent.com/github-production-release-asset/1/3?sp=r";
    let a86 = zip(&[
        ZipEntry::file("bin/fix.dll", DLL),
        ZipEntry::file("fix.ini", INI),
    ]);
    let a64 = zip(&[
        ZipEntry::file("bin/fix.dll", DLL),
        ZipEntry::file("fix.ini", INI),
        ZipEntry::file("README.txt", &noise(300 * 1024)),
    ]);
    let pkg = format!(
        r#"{{"format":1,"id":"fix-pack","name":"Fix pack","status":"active","tier":"established","source":{{"repo":"https://github.com/owner/fix-pack","page":"https://github.com/owner/fix-pack"}},"version":"1.0","assets":[{{"arch":"x86","url":"{ASSET}","sha256":"{x}"}},{{"arch":"x64","url":"{ASSET64}","sha256":"{y}"}}],"license":"MIT","arch":["x86","x64"],"slots":["fix.dll"],"files":[{{"from":"bin/fix.dll","to":"fix.dll","sha256":"{d}"}},{{"from":"fix.ini","to":"fix.ini","sha256":"{i}","config":true}}]}}"#,
        x = upper(&a86),
        y = upper(&a64),
        d = upper(DLL),
        i = upper(INI),
    );
    let sys = world(&pkg);
    let trip = Trip::new();
    let http = FakeHttp::default();
    http.reply(ASSET, FakeReply::redirect(302, STORE));
    http.reply(STORE, FakeReply::ok(&a86));
    http.reply(ASSET64, FakeReply::redirect(302, STORE64));
    http.reply(
        STORE64,
        FakeReply::ok(&a64)
            .chunked(16 * 1024)
            .trip_after(100 * 1024, &trip),
    );
    let n = need_of(&sys, &http);
    assert_eq!(n.downloads.len(), 2);
    let (r, seen) = run(&sys, &http, &n, trip.flag());
    assert_eq!(r.unwrap_err(), FetchError::Cancelled);
    assert!(seen.iter().any(|p| matches!(
        p,
        Progress::Download {
            index: 1,
            of: 2,
            ..
        }
    )));
    assert_eq!(listed(&sys, AppSub::Cache), Some(vec![lower(&a86)]));
    assert_eq!(listed(&sys, AppSub::Packages), None);
    // Retry: the first is a hit, the second is downloaded whole.
    http.reply(STORE64, FakeReply::ok(&a64));
    http.clear_requests();
    let (r, seen) = run(&sys, &http, &n, &AtomicBool::new(false));
    r.unwrap_or_else(|e| panic!("{e}"));
    assert!(
        seen.iter()
            .any(|p| matches!(p, Progress::Cached { index: 0, of: 2 }))
    );
    assert_eq!(http.requests(), [ASSET64, STORE64]);
    let mut want = vec![lower(&a86), lower(&a64)];
    want.sort();
    assert_eq!(listed(&sys, AppSub::Cache), Some(want));
    assert_eq!(need_of(&sys, &http).state, NeedState::Unpacked);
}

/// FX11: a package the index holds but this build sets aside is never offered for download,
/// with the same words as `rerun package fetch`; an unknown one keeps its own.
#[test]
fn fx11_a_set_aside_package_is_unobtainable() {
    let b = br#"{"format":1,"seq":1,"issued":"2026-11-12T12:00:00Z","topos":[],"packages":[{"format":2,"id":"future-pack"},{"format":1,"id":"odd-pack","future":1}]}"#;
    let sig = test_key::sign(b);
    let v = catalog::verify(b, &sig, &[test_key::public()]).unwrap();
    let c = catalog::Catalog::from_verified(&v).unwrap();
    let state = |id: &str| need(&c, None, id).state;
    assert_eq!(
        state("future-pack"),
        NeedState::Unobtainable("the package needs a newer version of Rerun".to_owned())
    );
    let NeedState::Unobtainable(why) = state("odd-pack") else {
        panic!("odd-pack is offered");
    };
    assert!(
        why.starts_with("the package cannot be used by this version of Rerun (not readable"),
        "{why}"
    );
    assert_eq!(
        state("other-pack"),
        NeedState::Unobtainable("the package is not in the signed index".to_owned())
    );
}
