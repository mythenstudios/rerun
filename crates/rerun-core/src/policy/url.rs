//! The URL rules (docs/02 "General rules", "Download"; ADR 0024, ADR 0025): one grammar for the
//! loader (`catalog::check`) and the downloader (`pkg::download`).
//!
//! - **Form** ([`https_url`], [`repo_url`], [`release_download`]): `https://`, a host of ASCII
//!   lower-case labels with a letter TLD (so no port, no userinfo, no IP literal, no
//!   backslash), a path without spaces; a release download exactly
//!   `https://<forge>/<owner>/<repo>/releases/download/<tag>/<file>`.
//! - **Provenance** ([`belongs`]): a download belongs to the releases of `source.repo`, or, if it
//!   names no release download, to the host of `source.page`. The loader checks it for every
//!   package of the signed index.
//! - **What is fetched** ([`HttpsUrl`]): [`HttpsUrl::download`] admits a package URL that passes
//!   the form rule and is printable ASCII without `#`; [`HttpsUrl::redirect`] admits a
//!   `Location` only to a host listed for the host that sent it in [`REDIRECTS`] (fixed in
//!   code; a forge that changes its download hosts fails closed until the list is changed), as
//!   an absolute `https` URL without port, userinfo or IP literal. Nothing else is ever
//!   requested: no redirect to the same host (it could leave the repository the provenance rule
//!   checked), no `http`, no relative `Location`.

use crate::sys::http::MAX_PATH;

/// `\s` of ECMA-262 (the schemas' pattern language).
pub(crate) fn space(c: char) -> bool {
    c.is_whitespace() || c == '\u{FEFF}'
}

/// One host label: `[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?`.
fn label(l: &str) -> bool {
    let b = l.as_bytes();
    let inner = |c: &u8| c.is_ascii_lowercase() || c.is_ascii_digit();
    (1..=63).contains(&b.len())
        && b.first().is_some_and(inner)
        && b.last().is_some_and(inner)
        && b.iter().all(|c| inner(c) || *c == b'-')
}

/// A host of `$defs/httpsUrl`: labels, then a TLD of 2 to 63 letters.
pub(crate) fn host(h: &str) -> bool {
    let mut parts: Vec<&str> = h.split('.').collect();
    let Some(tld) = parts.pop() else { return false };
    !parts.is_empty()
        && (2..=63).contains(&tld.len())
        && tld.bytes().all(|c| c.is_ascii_lowercase())
        && parts.iter().all(|l| label(l))
}

/// Splits `https://<host><rest>`; `rest` is empty or starts with `/`.
pub(crate) fn split_https(u: &str) -> Option<(&str, &str)> {
    let r = u.strip_prefix("https://")?;
    let end = r.find('/').unwrap_or(r.len());
    Some((&r[..end], &r[end..]))
}

/// `$defs/httpsUrl`: `https://`, a plain host, an optional path without spaces or `\`.
pub fn https_url(u: &str) -> bool {
    u.chars().count() <= 2048
        && split_https(u)
            .is_some_and(|(h, rest)| host(h) && rest.chars().all(|c| !space(c) && c != '\\'))
}

/// `owner/repo` segments `[A-Za-z0-9_.-]+`.
fn repo_seg(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'.' | b'-'))
}

/// The forges a `source.repo` may name.
pub const FORGES: [&str; 3] = ["github.com", "gitlab.com", "codeberg.org"];

/// `https://<forge>/<owner>/<repo>` and the rest after it.
pub(crate) fn forge(u: &str) -> Option<(&str, &str, &str)> {
    let (h, rest) = split_https(u)?;
    if !FORGES.contains(&h) {
        return None;
    }
    let rest = rest.strip_prefix('/')?;
    let (owner, rest) = rest.split_once('/')?;
    let end = rest.find('/').unwrap_or(rest.len());
    let (repo, tail) = (&rest[..end], &rest[end..]);
    (repo_seg(owner) && repo_seg(repo)).then_some((owner, repo, tail))
}

/// `$defs/repoUrl`: `https://<forge>/<owner>/<repo>` with an optional `/`.
pub fn repo_url(u: &str) -> bool {
    forge(u).is_some_and(|(_, _, tail)| tail.is_empty() || tail == "/")
}

/// The path part of a forge release download.
pub(crate) const RELEASES: &str = "/releases/download/";

/// After [`RELEASES`]: exactly `<tag>/<file>`, each of `[A-Za-z0-9._+-]`, neither `.` nor `..`
/// (so no `%`, `?`, `#`, no further `/`).
fn tag_and_file(rest: &str) -> bool {
    let seg = |s: &str| {
        !s.is_empty()
            && s != "."
            && s != ".."
            && s.bytes()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'+' | b'-'))
    };
    rest.split_once('/')
        .is_some_and(|(tag, file)| seg(tag) && seg(file))
}

/// A download URL that names a release download must be exactly
/// `https://<forge>/<owner>/<repo>/releases/download/<tag>/<file>` (schema
/// `$defs/downloadUrl`); any other https URL is left to [`belongs`].
pub fn release_download(u: &str) -> bool {
    let Some(at) = u.find(RELEASES) else {
        return true;
    };
    repo_url(&u[..at]) && tag_and_file(&u[at + RELEASES.len()..])
}

/// docs/02 "Provenance": `u` is a release download of `repo` (`<repo>/releases/download/<tag>/
/// <file>`), or it names no release download and lies on the host of `page`. A release
/// download counts only for its own repository, never by the host of a page (a page on
/// `github.com` would otherwise admit any repository there).
pub fn belongs(u: &str, repo: Option<&str>, page: Option<&str>) -> bool {
    let from_repo = repo.is_some_and(|r| {
        u.strip_prefix(r.trim_end_matches('/'))
            .and_then(|rest| rest.strip_prefix(RELEASES))
            .is_some_and(tag_and_file)
    });
    let page_host = page.and_then(split_https).map(|(h, _)| h);
    let from_page = !u.contains(RELEASES)
        && page_host.is_some_and(|h| split_https(u).is_some_and(|(uh, _)| uh == h));
    from_repo || from_page
}

/// Where a host may redirect a download to (ADR 0025): exact host names, no wildcard. GitHub
/// answers a release download with a redirect to its asset storage.
pub const REDIRECTS: &[(&str, &[&str])] = &[(
    "github.com",
    &[
        "objects.githubusercontent.com",
        "release-assets.githubusercontent.com",
    ],
)];

/// Why a URL is not fetched. Never carries the URL's text (it may come from a server), only a
/// host that passed the host rule.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum UrlError {
    /// Not the form of a package download (docs/02).
    #[error("not a download URL of the package form (https, a plain host, printable ASCII)")]
    Form,
    /// A redirect to `http://` or another scheme.
    #[error("a redirect that is not https")]
    NotHttps,
    /// A relative `Location`.
    #[error("a redirect without a scheme and host")]
    Relative,
    /// User information before the host.
    #[error("a redirect with user information before the host")]
    Userinfo,
    /// An explicit port.
    #[error("a redirect with a port")]
    Port,
    /// An IP address instead of a host name.
    #[error("a redirect to an IP address")]
    IpLiteral,
    /// Not a plain host name.
    #[error("a redirect to a host that is not a plain lower-case host name")]
    Host,
    /// A host that is not listed for the host that redirected.
    #[error("a redirect from {from} to {to}, a host not allowed for it")]
    NotAllowed {
        /// The host that sent the redirect.
        from: String,
        /// The host it named (passed the host rule).
        to: String,
    },
    /// A path that is not printable ASCII, has a fragment or is too long.
    #[error("a redirect whose path is not printable ASCII, has a fragment or is too long")]
    Path,
}

/// An https URL Rerun may request: a host and a path (with its query), both printable ASCII.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpsUrl {
    host: String,
    path: String,
}

/// A request path: starts with `/`, at most [`MAX_PATH`] bytes of printable ASCII without
/// `\` and `#` (a fragment is never sent).
fn wire_path(p: &str) -> bool {
    p.starts_with('/')
        && p.len() <= MAX_PATH
        && p.bytes()
            .all(|c| c.is_ascii_graphic() && c != b'\\' && c != b'#')
}

impl HttpsUrl {
    /// A package download URL (`source.release`, `assets[].url`): the form rule
    /// ([`https_url`], [`release_download`]), a path, printable ASCII without `#`. Provenance
    /// is the loader's ([`belongs`]); this is the downloader's own re-check.
    pub fn download(u: &str) -> Result<Self, UrlError> {
        let (h, rest) = split_https(u).ok_or(UrlError::Form)?;
        if !(https_url(u) && release_download(u) && wire_path(rest)) {
            return Err(UrlError::Form);
        }
        Ok(Self {
            host: h.to_owned(),
            path: rest.to_owned(),
        })
    }

    /// The URL a redirect from `self` names in `location`, if it may be followed (module docs).
    pub fn redirect(&self, location: &str) -> Result<Self, UrlError> {
        let Some(rest) = location.strip_prefix("https://") else {
            let scheme = location
                .split_once(':')
                .is_some_and(|(s, _)| !s.is_empty() && !s.contains('/'));
            return Err(if scheme {
                UrlError::NotHttps
            } else {
                UrlError::Relative
            });
        };
        let end = rest.find(['/', '?', '#', '\\']).unwrap_or(rest.len());
        let (auth, path) = rest.split_at(end);
        if auth.contains('@') {
            return Err(UrlError::Userinfo);
        }
        let numeric = |a: &str| {
            a.split('.')
                .all(|l| !l.is_empty() && l.bytes().all(|c| c.is_ascii_digit()))
        };
        if auth.starts_with('[') || numeric(auth) {
            return Err(UrlError::IpLiteral);
        }
        if auth.contains(':') {
            return Err(UrlError::Port);
        }
        if !host(auth) {
            return Err(UrlError::Host);
        }
        let allowed = REDIRECTS
            .iter()
            .find(|(from, _)| *from == self.host)
            .is_some_and(|(_, to)| to.contains(&auth));
        if !allowed {
            return Err(UrlError::NotAllowed {
                from: self.host.clone(),
                to: auth.to_owned(),
            });
        }
        if !wire_path(path) {
            return Err(UrlError::Path);
        }
        Ok(Self {
            host: auth.to_owned(),
            path: path.to_owned(),
        })
    }

    /// The host.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The path with its query, as sent.
    pub fn path(&self) -> &str {
        &self.path
    }
}

impl std::fmt::Display for HttpsUrl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "https://{}{}", self.host, self.path)
    }
}

#[cfg(test)]
mod tests;
