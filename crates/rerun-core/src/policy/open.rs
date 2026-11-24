//! What Rerun may hand to the shell (ADR 0027 amendment P5-10a): the one decision behind
//! "open a link" and "open the data folder". `sys::Shell` only executes; `flow::open` connects.
//!
//! - **URLs** ([`OpenUrl`]): built only here, from three sources: a source URL of the current
//!   signed index (`flow::source_url`, crate-internal [`OpenUrl::from_index`]), Rerun's own
//!   constants ([`OwnLink`]) and the prefilled issue of "report a problem" ([`OpenUrl::issue`]).
//!   Never from window input: the app sends a reference, the core looks the URL up.
//! - **The grammar** ([`admit`]), stricter than the index loader's `https_url` because the
//!   string reaches `ShellExecuteExW` and from there a browser's command line: `https://`, a host
//!   of [`super::url::host`] (lower-case labels and a letter TLD, so no port, no user
//!   information, no IP literal, no IDN in Unicode form), then nothing or a part that starts
//!   with `/`, of printable ASCII without a space and without `" < > \ ^ `` ` `` { | }`; a `%`
//!   only before two hex digits, at most one `#`. A character beyond ASCII is percent-encoded
//!   (UTF-8) unless it is one `escape::path` would escape (a control, format, bidi or invisible
//!   character, a confusable): then the URL is refused. At most [`MAX_OPEN_URL`] bytes after the
//!   encoding.
//! - **The folder** ([`OpenFolder`]): Rerun's own folder only, from an [`AppDir`] that is open
//!   (so it exists, was opened handle-relative without following a reparse point, and its
//!   final path was checked); never created for this.

use crate::escape::in_path_set;
use crate::path::RootPath;
use crate::policy::root::AppDir;

use super::url::{host, split_https};

/// Most bytes of a URL handed to the shell, after the encoding.
pub const MAX_OPEN_URL: usize = 2048;

/// Rerun's repository (the workspace's `repository`).
pub const RERUN_REPO: &str = "https://github.com/mythenstudios/rerun";

/// Why nothing is opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum OpenRefusal {
    /// The URL is not of the form Rerun opens (module docs).
    #[error("not a link Rerun opens (https, a plain host, printable characters only)")]
    Form,
    /// The URL is longer than [`MAX_OPEN_URL`] bytes after the encoding.
    #[error("the link is longer than Rerun opens")]
    TooLong,
    /// The current index has no such source.
    #[error("the current index has no such link")]
    NotInIndex,
    /// There is no current signed index.
    #[error("there is no signed index")]
    NoIndex,
    /// Rerun's folder does not exist.
    #[error("Rerun's folder does not exist yet")]
    NoAppDir,
}

/// One of Rerun's own links (compiled in).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnLink {
    /// The repository.
    Repository,
    /// The source code of this build: `…/tree/<commit>` when the build ID names a commit (7 to 40
    /// lower-case hex digits), else the repository.
    SourceOfThisBuild,
    /// A new, empty issue.
    NewIssue,
}

/// An https URL Rerun may hand to the shell. Built only in this module (private field).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenUrl {
    url: String,
}

/// ASCII characters a URL handed to the shell never holds (besides controls and the space).
const REFUSED_ASCII: &[u8] = b"\"<>\\^`{|}";

/// The URL `u` in the form Rerun opens (module docs), or why not.
pub fn admit(u: &str) -> Result<String, OpenRefusal> {
    let (h, rest) = split_https(u).ok_or(OpenRefusal::Form)?;
    // `split_https` ends the host at the first `/`: a `?`, `#`, `:` or `@` in it fails the host
    // rule, so do ports, user information and IP literals.
    if !host(h) || !(rest.is_empty() || rest.starts_with('/')) {
        return Err(OpenRefusal::Form);
    }
    let mut out = String::with_capacity(u.len());
    out.push_str("https://");
    out.push_str(h);
    let bytes = rest.as_bytes();
    let mut fragments = 0;
    let mut i = 0;
    for c in rest.chars() {
        let at = i;
        i += c.len_utf8();
        if c.is_ascii() {
            let b = c as u8;
            if !b.is_ascii_graphic() || REFUSED_ASCII.contains(&b) {
                return Err(OpenRefusal::Form);
            }
            if b == b'%' {
                let hex = |k: usize| bytes.get(at + k).is_some_and(u8::is_ascii_hexdigit);
                if !(hex(1) && hex(2)) {
                    return Err(OpenRefusal::Form);
                }
            }
            if b == b'#' {
                fragments += 1;
                if fragments > 1 {
                    return Err(OpenRefusal::Form);
                }
            }
            out.push(c);
        } else if in_path_set(c) {
            return Err(OpenRefusal::Form);
        } else {
            let mut buf = [0u8; 4];
            for b in c.encode_utf8(&mut buf).bytes() {
                push_pct(&mut out, b);
            }
        }
        if out.len() > MAX_OPEN_URL {
            return Err(OpenRefusal::TooLong);
        }
    }
    Ok(out)
}

/// Whether `u` passes [`admit`]: a front end shows an open button only then (the core decides
/// again when it is clicked).
pub fn openable(u: &str) -> bool {
    admit(u).is_ok()
}

/// `%XX` with upper-case hex digits.
fn push_pct(out: &mut String, b: u8) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    out.push('%');
    out.push(char::from(HEX[usize::from(b >> 4)]));
    out.push(char::from(HEX[usize::from(b & 0xF)]));
}

/// `s` as a query value: every byte but the unreserved ones (`A-Z a-z 0-9 - . _ ~`) encoded.
fn query_value(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 3);
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(b));
        } else {
            push_pct(&mut out, b);
        }
    }
    out
}

/// The commit of the build ID `id` (`<version>+<commit>`), if it names one: 7 to 40 lower-case hex
/// digits.
fn commit_of(id: &str) -> Option<&str> {
    let (_, c) = id.split_once('+')?;
    ((7..=40).contains(&c.len())
        && c.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
    .then_some(c)
}

impl OpenUrl {
    /// A source URL read from the current signed index (only `flow`, with the URL it looked up).
    pub(crate) fn from_index(u: &str) -> Result<Self, OpenRefusal> {
        admit(u).map(|url| Self { url })
    }

    /// One of Rerun's own links.
    pub fn own(l: OwnLink) -> Self {
        Self::own_for(l, crate::BUILD_ID)
    }

    /// [`Self::own`] for the build ID `id` (tests).
    fn own_for(l: OwnLink, id: &str) -> Self {
        let url = match l {
            OwnLink::Repository => RERUN_REPO.to_owned(),
            OwnLink::SourceOfThisBuild => match commit_of(id) {
                Some(c) => format!("{RERUN_REPO}/tree/{c}"),
                None => RERUN_REPO.to_owned(),
            },
            OwnLink::NewIssue => format!("{RERUN_REPO}/issues/new"),
        };
        Self { url }
    }

    /// The new issue of Rerun's repository with `title` and `body` filled in (every byte but the
    /// unreserved ones percent-encoded), at most [`MAX_OPEN_URL`] bytes.
    pub(crate) fn issue(title: &str, body: &str) -> Result<Self, OpenRefusal> {
        let url = format!(
            "{RERUN_REPO}/issues/new?title={}&body={}",
            query_value(title),
            query_value(body)
        );
        if url.len() > MAX_OPEN_URL {
            return Err(OpenRefusal::TooLong);
        }
        // Belt and braces: the encoded URL passes the grammar unchanged.
        admit(&url).map(|url| Self { url })
    }

    /// The URL, shown next to the link and handed to the shell.
    pub fn as_str(&self) -> &str {
        &self.url
    }
}

/// Rerun's own folder, the only folder Rerun shows in Explorer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenFolder {
    path: RootPath,
}

impl OpenFolder {
    /// The folder of `app`, which is open (so it exists and its final path was checked).
    pub(crate) fn app_dir(app: &AppDir<'_>) -> Self {
        Self {
            path: app.path().clone(),
        }
    }

    /// Its canonical path.
    pub fn path(&self) -> &RootPath {
        &self.path
    }

    /// A folder at `path`, for the tests of the shell's call (never opened).
    #[cfg(test)]
    pub(crate) fn for_test(path: RootPath) -> Self {
        Self { path }
    }
}

#[cfg(test)]
mod tests;
