//! HTTPS through WinHTTP (ADR 0025, P4-6). The normal tests make no request. The [SB] test
//! (`#[ignore]`, `sandbox_guard` first; run by `scripts/sandbox-run.ps1` in pass 1 of
//! `scripts/ci-sandbox.ps1` as the standard user; skipped in the local Windows Sandbox, which has
//! no network) downloads one small real GitHub release asset through the product path, measures
//! it independently and leaves the cache as it found it.
//!
//! The asset: `EaglePatchAC1.zip` of release `v1.1` of `Sergeanur/EaglePatch` (the author of the
//! EaglePatchAC1 package in `packages/`), 44,574 bytes. Its SHA-256 below is the `digest` GitHub
//! reports for the asset in its release API (read 2026-11-10); the test also hashes the bytes
//! itself and prints the result (`MEASURED`), so a changed asset shows what it became.

use std::io::Read;

use sha2::{Digest, Sha256};

use super::super::WinHttp;
use super::super::WinSystem;
use super::super::testfx::{note, sandbox_guard};
use crate::catalog::model::Hex;
use crate::pkg::download::{Download, FetchError, How, cache_name, fetch};
use crate::policy::root::{AppDir, AppSub, Create};
use crate::policy::url::HttpsUrl;
use crate::sys::{Http, NoHttp, SysErrorKind};

const ASSET: &str =
    "https://github.com/Sergeanur/EaglePatch/releases/download/v1.1/EaglePatchAC1.zip";
const ASSET_LEN: u64 = 44_574;
const ASSET_SHA256: &str = "6DC496AC6B298B92FB70C3F90A34E323F77AC88E6EA97544F84E52435038AEEA";

#[test]
fn win_http_refuses_a_bad_request_before_any_network() {
    for (h, p) in [
        ("github.com:444", "/"),
        ("user@github.com", "/"),
        ("github.com", "no-slash"),
        ("github.com", "/a b"),
        ("github.com", "/a#b"),
    ] {
        let e = WinHttp::new().get(h, p).unwrap_err();
        assert_eq!(e.kind, SysErrorKind::InvalidPath, "{h} {p}");
    }
}

/// The body behind `url`, following redirects as `pkg::download` does; the hosts on the way.
fn measure(url: &HttpsUrl) -> (Vec<u8>, Vec<String>) {
    let mut url = url.clone();
    let mut hosts = vec![url.host().to_owned()];
    let http = WinHttp::new();
    for _ in 0..4 {
        let mut r = http
            .get(url.host(), url.path())
            .unwrap_or_else(|e| panic!("{url}: {e}"));
        match r.status {
            200 => {
                let mut body = Vec::new();
                r.body.read_to_end(&mut body).unwrap();
                return (body, hosts);
            }
            301 | 302 | 303 | 307 | 308 => {
                let loc = r.location.clone().unwrap_or_default();
                url = url
                    .redirect(&loc)
                    .unwrap_or_else(|e| panic!("redirect from {} refused: {e}", url.host()));
                hosts.push(url.host().to_owned());
            }
            s => panic!("{url}: status {s}"),
        }
    }
    panic!("too many redirects")
}

#[test]
#[ignore = "network and the real LocalAppData: Windows Sandbox or the CI sandbox job only"]
fn sandbox_package_download_of_a_github_release_asset() {
    sandbox_guard();
    // The local Windows Sandbox has no network (`scripts/sandbox-test.wsb`): only the CI job runs
    // this test (`RERUN_CI_SANDBOX=1`, set by `sandbox-run.ps1 -Ci`); `ci-sandbox.ps1` fails pass 1
    // if its MEASURED line is missing.
    #[expect(
        clippy::disallowed_methods,
        reason = "test gate: the CI opt-in is an environment variable by design, not a path"
    )]
    let ci = std::env::var("RERUN_CI_SANDBOX").is_ok_and(|v| v == "1");
    if !ci {
        note(
            "sandbox_package_download_of_a_github_release_asset: skipped (no network outside the CI job)",
        );
        return;
    }
    super::super::restrict_dll_search().unwrap();
    let url = HttpsUrl::download(ASSET).unwrap();

    // 1. Measured independently of the cache: hosts on the way, length, SHA-256.
    let (body, hosts) = measure(&url);
    let sha: [u8; 32] = Sha256::digest(&body).into();
    let measured = cache_name(&sha).to_ascii_uppercase();
    note(&format!(
        "MEASURED download {ASSET}: hosts {}, {} bytes, sha256 {measured} (pinned {ASSET_SHA256})",
        hosts.join(" -> "),
        body.len()
    ));
    assert_eq!(body.len() as u64, ASSET_LEN);
    assert_eq!(measured, ASSET_SHA256);

    // 2. The product path into the real cache.
    let sys = WinSystem::new().unwrap();
    let app = AppDir::open(&sys, Create::IfMissing).unwrap().unwrap();
    let pinned = *Hex::<32>::parse(ASSET_SHA256).unwrap().bytes().unwrap();
    let d = Download {
        arch: None,
        url: url.clone(),
        sha256: pinned,
    };
    let cache = app
        .sub_write(AppSub::Cache, Create::IfMissing)
        .unwrap()
        .unwrap();
    let name = crate::path::RelPath::from_segment(&cache_name(&pinned)).unwrap();
    if let Ok(mut g) = cache.guard(&name) {
        let have = g.sha256().unwrap();
        g.delete(&have).unwrap();
    }
    let got = fetch(&sys, &WinHttp::new(), &app, &d).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(got.len, ASSET_LEN);
    assert!(
        matches!(
            got.how,
            How::Downloaded {
                redirects: 1,
                replaced: false
            }
        ),
        "{got:?}"
    );
    assert_eq!(cache.read(&name).unwrap(), body);

    // 3. A cache hit needs no network.
    let again = fetch(&sys, &NoHttp, &app, &d).unwrap();
    assert_eq!(again.how, How::Cached);

    // 4. A wrong pin downloads, refuses and keeps nothing.
    let wrong = Download {
        sha256: [0; 32],
        ..d.clone()
    };
    let e = fetch(&sys, &WinHttp::new(), &app, &wrong).unwrap_err();
    assert!(matches!(e, FetchError::Mismatch { .. }), "{e:?}");
    let left: Vec<String> = cache
        .read_dir(None)
        .unwrap()
        .into_iter()
        .map(|e| e.name)
        .filter(|n| n != "lock" && *n != cache_name(&pinned))
        .collect();
    assert!(left.is_empty(), "left in the cache: {left:?}");

    // Leave the cache as found.
    let mut g = cache.guard(&name).unwrap();
    let have = g.sha256().unwrap();
    g.delete(&have).unwrap();
    note("sandbox_package_download_of_a_github_release_asset: passed, cache entry removed");
}
