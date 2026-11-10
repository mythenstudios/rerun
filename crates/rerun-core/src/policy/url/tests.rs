//! The URL rules of the downloader (ADR 0025): package URLs, redirects, provenance.

use super::*;

const ASSET: &str = "https://github.com/owner/fix-pack/releases/download/v1.0/fix-pack.zip";

fn gh() -> HttpsUrl {
    HttpsUrl::download(ASSET).unwrap()
}

#[test]
fn a_package_url_splits_into_host_and_path() {
    let u = gh();
    assert_eq!(u.host(), "github.com");
    assert_eq!(
        u.path(),
        "/owner/fix-pack/releases/download/v1.0/fix-pack.zip"
    );
    assert_eq!(u.to_string(), ASSET);
    // A page download (the loader's provenance decides whether it belongs).
    let p = HttpsUrl::download("https://dege.example.org/files/dgVoodoo2_86.zip?x=1").unwrap();
    assert_eq!(p.path(), "/files/dgVoodoo2_86.zip?x=1");
}

#[test]
fn a_package_url_outside_the_form_is_refused() {
    for u in [
        "http://github.com/o/r/releases/download/v1/a.zip",
        "https://github.com",
        "https://github.com:443/o/r/releases/download/v1/a.zip",
        "https://user@github.com/o/r/releases/download/v1/a.zip",
        "https://127.0.0.1/a.zip",
        "https://GitHub.com/o/r/releases/download/v1/a.zip",
        "https://github.com/o/r/releases/download/v1/../a.zip",
        "https://github.com/o/r/releases/download/v1/a.zip?x",
        "https://github.com/o/r/releases/download/v1/a%2Fb.zip",
        "https://example.org/a b.zip",
        "https://example.org/a\\b.zip",
        "https://example.org/a.zip#frag",
        "https://example.org/caf\u{e9}.zip",
        "TODO",
    ] {
        assert_eq!(HttpsUrl::download(u), Err(UrlError::Form), "{u}");
    }
}

#[test]
fn github_redirects_only_to_its_asset_hosts() {
    for to in [
        "https://objects.githubusercontent.com/github-production-release-asset-2e65be/1/2?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Signature=ab%3D",
        "https://release-assets.githubusercontent.com/github-production-release-asset/1/2?sp=r&sig=x%2By%3D&jwt=a.b.c",
    ] {
        let r = gh().redirect(to).unwrap();
        assert_eq!(r.to_string(), to);
    }
}

#[test]
fn every_other_redirect_is_refused() {
    let cases: &[(&str, UrlError)] = &[
        ("http://objects.githubusercontent.com/a", UrlError::NotHttps),
        ("ftp://objects.githubusercontent.com/a", UrlError::NotHttps),
        ("/owner/fix-pack/a.zip", UrlError::Relative),
        ("//objects.githubusercontent.com/a", UrlError::Relative),
        ("objects.githubusercontent.com/a", UrlError::Relative),
        (
            "https://user:pw@objects.githubusercontent.com/a",
            UrlError::Userinfo,
        ),
        (
            "https://objects.githubusercontent.com@evil.example/a",
            UrlError::Userinfo,
        ),
        (
            "https://objects.githubusercontent.com:443/a",
            UrlError::Port,
        ),
        ("https://140.82.121.4/a", UrlError::IpLiteral),
        ("https://[::1]/a", UrlError::IpLiteral),
        ("https://Objects.GitHubUserContent.com/a", UrlError::Host),
        ("https://objects.githubusercontent.com./a", UrlError::Host),
        ("https://xn--github-.com/a", UrlError::Host),
        ("https:///a", UrlError::Host),
        ("https://objects.githubusercontent.com", UrlError::Path),
        ("https://objects.githubusercontent.com?a=1", UrlError::Path),
        ("https://objects.githubusercontent.com/a#b", UrlError::Path),
        ("https://objects.githubusercontent.com/a b", UrlError::Path),
        ("https://objects.githubusercontent.com\\a", UrlError::Path),
        (
            "https://objects.githubusercontent.com/caf\u{e9}",
            UrlError::Path,
        ),
    ];
    for (to, want) in cases {
        assert_eq!(gh().redirect(to).as_ref(), Err(want), "{to}");
    }
    // Same host (could leave the checked repository), a foreign host, a look-alike.
    for to in [
        "https://github.com/other/repo/releases/download/v1/a.zip",
        "https://evil.example/a.zip",
        "https://objects.githubusercontent.com.evil.example/a",
        "https://githubusercontent.com/a",
    ] {
        assert!(
            matches!(gh().redirect(to), Err(UrlError::NotAllowed { .. })),
            "{to}"
        );
    }
    // An asset host does not redirect any further, nor does a host without an entry.
    let asset = gh()
        .redirect("https://objects.githubusercontent.com/a")
        .unwrap();
    assert!(matches!(
        asset.redirect("https://release-assets.githubusercontent.com/a"),
        Err(UrlError::NotAllowed { .. })
    ));
    let page = HttpsUrl::download("https://example.org/a.zip").unwrap();
    assert!(matches!(
        page.redirect("https://example.org/b.zip"),
        Err(UrlError::NotAllowed { .. })
    ));
    // Too long.
    let long = format!(
        "https://objects.githubusercontent.com/{}",
        "a".repeat(MAX_PATH)
    );
    assert_eq!(gh().redirect(&long), Err(UrlError::Path));
}

#[test]
fn provenance_binds_a_release_to_its_repository() {
    let repo = Some("https://github.com/owner/fix-pack");
    assert!(belongs(ASSET, repo, None));
    assert!(!belongs(
        "https://github.com/other/repo/releases/download/v1.0/a.zip",
        repo,
        None
    ));
    // A page on github.com never admits a release download of another repository.
    assert!(!belongs(
        "https://github.com/other/repo/releases/download/v1.0/a.zip",
        None,
        Some("https://github.com/other")
    ));
    assert!(belongs(
        "https://example.org/files/a.zip",
        None,
        Some("https://example.org/page")
    ));
    assert!(!belongs(
        "https://evil.example/files/a.zip",
        None,
        Some("https://example.org/page")
    ));
}
