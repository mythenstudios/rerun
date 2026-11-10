//! The PCGamingWiki side of `draft` (P4-14; user decisions D2 a, D4 a): at most two HTTPS GETs
//! to [`HOST`], the facts of one page read from its wikitext by a fixed list of template
//! parameters, and the anchors of its fix sections.
//!
//! - **Requests** (only through `sys::Http`, never another host): for a Steam app ID first
//!   `/api/appid.php?appid=<n>`, of whose reply only the redirect's `Location` is read, never
//!   followed; it must be exactly `https://www.pcgamingwiki.com/wiki/<page>`. Then
//!   `/w/api.php?action=parse&…&prop=wikitext|sections&page=<page>`, which must answer 200
//!   (a redirect is an error, never followed). Every query is built here and percent-encoded;
//!   at most [`MAX_REQUESTS`] per run, [`MAX_REPLY`] bytes per reply (a larger
//!   `Content-Length` is refused before reading), a fixed spacing between the two and one
//!   deadline for the whole exchange; no retry, no cache, no cookie, the wrapper's generic user
//!   agent.
//! - **Input:** a page name is at most [`MAX_PAGE`] bytes of UTF-8 without control, format or
//!   bidi characters and without the characters MediaWiki forbids in titles or that could
//!   leave the query (`" \ # < > [ ] { } |`); checked before any request.
//! - **The reply** is JSON into typed structs (serde_json's recursion limit stays on); only
//!   `parse.title`, `parse.wikitext`, `parse.sections[].level` and `.anchor` and `error.code`
//!   are read. The title must name the page asked for. The wikitext goes through
//!   [`crate::wikitext`]; of each read parameter only whitelisted values count (`true`,
//!   `false`, `hackable`, app IDs, version numbers), anything else is "not known". No text of
//!   the page reaches the draft: only the page name, numbers we parsed and anchors, which are
//!   percent-encoded to printable ASCII. A template the wiki renames makes the page fail
//!   (`Shape`), never a draft with wrong facts.

use std::io::Read;
use std::time::{Duration, Instant};

use serde::Deserialize;

use rerun_core::escape;
use rerun_core::sys::{Http, SysError};

use crate::wikitext::{self, OPAQUE, Wanted};

/// The only host asked.
pub const HOST: &str = "www.pcgamingwiki.com";
/// Most bytes of one reply.
pub const MAX_REPLY: usize = 1 << 20;
/// Most requests of one run.
pub const MAX_REQUESTS: usize = 2;
/// Most bytes of a page name (MediaWiki's own limit).
pub const MAX_PAGE: usize = 255;
/// Most sections of a page.
pub const MAX_SECTIONS: usize = 512;
/// Most bytes of a section anchor as the wiki sends it.
pub const MAX_ANCHOR: usize = 256;
/// Most items of a parameter's list (app IDs, versions).
pub const MAX_ITEMS: usize = 32;
/// The page URL prefix (also of a `pcgw` source, docs/02).
pub const WIKI: &str = "https://www.pcgamingwiki.com/wiki/";

/// What `draft` asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    /// A Steam app ID.
    SteamApp(u32),
    /// A page.
    Page(PageName),
}

/// A checked page name in its space form (module docs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PageName(String);

impl PageName {
    /// Checks `s` (`_` or spaces, runs of them become one space, none at either end).
    pub fn parse(s: &str) -> Result<Self, PcgwError> {
        let mut out = String::with_capacity(s.len());
        for part in s.split(['_', ' ']).filter(|p| !p.is_empty()) {
            if !out.is_empty() {
                out.push(' ');
            }
            out.push_str(part);
        }
        let bad = |c: char| {
            matches!(
                c,
                '"' | '\\' | '#' | '<' | '>' | '[' | ']' | '{' | '}' | '|' | OPAQUE
            ) || c.is_whitespace() && c != ' '
        };
        if out.is_empty() || out.len() > MAX_PAGE {
            return Err(PcgwError::Input("a page name of 1 to 255 bytes"));
        }
        if out.chars().any(bad) || escape::text(&out).as_str() != out {
            return Err(PcgwError::Input(
                "a page name without control, format or bidi characters and without \" \\ # < > [ ] { } |",
            ));
        }
        Ok(Self(out))
    }

    /// The name with spaces (the page title).
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The name with `_` (`links.pcgw`, URLs).
    pub fn wiki(&self) -> String {
        self.0.replace(' ', "_")
    }

    /// The page's URL, printable ASCII.
    pub fn url(&self) -> String {
        format!("{WIKI}{}", encode(&self.wiki(), b"'(),!:*"))
    }

    /// The same page as `other` (MediaWiki ignores the first letter's case).
    fn same(&self, other: &Self) -> bool {
        let (mut a, mut b) = (self.0.chars(), other.0.chars());
        match (a.next(), b.next()) {
            (Some(x), Some(y)) => x.to_uppercase().eq(y.to_uppercase()) && a.eq(b),
            _ => false,
        }
    }
}

/// A section anchor, percent-encoded to printable ASCII (`#` and space never in it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Anchor(String);

impl Anchor {
    fn parse(s: &str) -> Option<Self> {
        let ok = !s.is_empty() && s.len() <= MAX_ANCHOR && escape::text(s).as_str() == s;
        ok.then(|| Self(encode(s, b"'(),!:*")))
    }

    /// The encoded anchor.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Percent-encodes every byte but `A-Za-z0-9-._~` and `keep`.
pub fn encode(s: &str, keep: &[u8]) -> String {
    let mut out = String::with_capacity(s.len());
    for &c in s.as_bytes() {
        if c.is_ascii_alphanumeric() || b"-._~".contains(&c) || keep.contains(&c) {
            out.push(char::from(c));
        } else {
            out.push_str(&format!("%{c:02X}"));
        }
    }
    out
}

/// Decodes `%XX` (bounded by the input); `None` for a broken escape or non-UTF-8.
fn decode(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let hex = std::str::from_utf8(b.get(i + 1..i + 3)?).ok()?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// The graphics APIs a page names.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ApiFacts {
    /// Direct3D major versions, sorted, unique.
    pub d3d: Vec<u8>,
    /// DirectDraw.
    pub ddraw: bool,
    /// OpenGL.
    pub opengl: bool,
    /// Vulkan.
    pub vulkan: bool,
    /// Glide.
    pub glide: bool,
}

/// What a page says about the game, read from its wikitext.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GameFacts {
    /// The page (the title the wiki answered with).
    pub page: PageName,
    /// The Steam app IDs of `{{Infobox game}}`.
    pub steam: Vec<u32>,
    /// `{{API}}`; `None` without the template.
    pub api: Option<ApiFacts>,
    /// `windows 32-bit exe`, `windows 64-bit exe` (`None`: not known).
    pub bits: (Option<bool>, Option<bool>),
    /// Our labels of the `{{Video}}`/`{{Input}}` features marked `hackable`, with the section.
    pub hackable: Vec<(&'static str, &'static str)>,
    /// Templates not on the page (`Video`, …).
    pub missing: Vec<&'static str>,
}

/// The anchors of the fix sections (subsections of the level-2 sections named).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Fixes {
    /// `Essential_improvements`.
    pub essential: Vec<Anchor>,
    /// `Issues_fixed`.
    pub fixed: Vec<Anchor>,
    /// `Issues_unresolved`.
    pub unresolved: Vec<Anchor>,
}

/// Why `draft` got no facts.
#[derive(Debug)]
#[non_exhaustive]
pub enum PcgwError {
    /// The input, before any request.
    Input(&'static str),
    /// The request failed.
    Transport(SysError),
    /// A status other than the expected one.
    Status(u16),
    /// A redirect where none is expected (never followed).
    Redirect(u16),
    /// The app ID lookup's `Location` is not a page of the wiki.
    Location,
    /// A reply larger than [`MAX_REPLY`].
    TooLarge,
    /// The deadline passed.
    Deadline,
    /// More than [`MAX_REQUESTS`].
    Budget,
    /// Not JSON (an HTML page: a Cloudflare check?).
    NotJson,
    /// JSON of another form, or a page the reader does not understand.
    Shape(String),
    /// A MediaWiki error; its code if it is of the plain form.
    Api(Option<String>),
    /// No such page or app ID.
    NotFound,
}

impl std::fmt::Display for PcgwError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Input(what) => write!(f, "expected {what}"),
            Self::Transport(e) => write!(f, "{HOST}: {e}"),
            Self::Status(s @ (403 | 429 | 503)) => write!(
                f,
                "PCGamingWiki refused (status {s}; rate limit or Cloudflare check): try later"
            ),
            Self::Status(s) => write!(f, "PCGamingWiki answered status {s}"),
            Self::Redirect(s) => write!(f, "PCGamingWiki answered a redirect ({s}), not followed"),
            Self::Location => f.write_str("the app ID lookup did not name a page of the wiki"),
            Self::TooLarge => write!(f, "a reply larger than {MAX_REPLY} bytes"),
            Self::Deadline => f.write_str("PCGamingWiki took too long"),
            Self::Budget => write!(f, "more than {MAX_REQUESTS} requests"),
            Self::NotJson => f.write_str("the reply is not JSON (a Cloudflare check?): try later"),
            Self::Shape(what) => write!(f, "unexpected reply: {what}"),
            Self::Api(Some(code)) => write!(f, "PCGamingWiki error {code}"),
            Self::Api(None) => f.write_str("PCGamingWiki error (unknown code)"),
            Self::NotFound => f.write_str("no such page on PCGamingWiki"),
        }
    }
}

fn shape(what: impl Into<String>) -> PcgwError {
    PcgwError::Shape(what.into())
}

/// The path of the app ID lookup.
pub fn appid_path(n: u32) -> String {
    format!("/api/appid.php?appid={n}")
}

/// The path of the page request.
pub fn parse_path(page: &PageName) -> String {
    format!(
        "/w/api.php?action=parse&format=json&formatversion=2&prop=wikitext%7Csections&page={}",
        encode(&page.wiki(), b"")
    )
}

/// The page a lookup's `Location` names: exactly `https://www.pcgamingwiki.com/wiki/<page>`.
pub fn page_of_location(loc: &str) -> Result<PageName, PcgwError> {
    let rest = loc.strip_prefix(WIKI).ok_or(PcgwError::Location)?;
    if rest.is_empty() || rest.len() > 3 * MAX_PAGE || rest.contains(['?', '#']) {
        return Err(PcgwError::Location);
    }
    let page = decode(rest).ok_or(PcgwError::Location)?;
    PageName::parse(&page).map_err(|_| PcgwError::Location)
}

// ---------- the reply ----------

#[derive(Deserialize)]
struct Reply {
    parse: Option<Parsed>,
    error: Option<ApiError>,
}

#[derive(Deserialize)]
struct ApiError {
    code: String,
}

#[derive(Deserialize)]
struct Parsed {
    title: String,
    wikitext: String,
    sections: Vec<Section>,
}

#[derive(Deserialize)]
struct Section {
    level: String,
    anchor: String,
}

const INFOBOX: Wanted = Wanted {
    template: "Infobox game",
    keys: &["steam appid"],
};
const API: Wanted = Wanted {
    template: "API",
    keys: &[
        "direct3d versions",
        "directdraw versions",
        "opengl versions",
        "glide versions",
        "vulkan versions",
        "windows 32-bit exe",
        "windows 64-bit exe",
    ],
};
const VIDEO: Wanted = Wanted {
    template: "Video",
    keys: &[
        "widescreen resolution",
        "ultrawidescreen",
        "4k ultra hd",
        "fov",
        "windowed",
        "borderless windowed",
        "60 fps",
        "120 fps",
    ],
};
const INPUT: Wanted = Wanted {
    template: "Input",
    keys: &["controller support", "controller hotplug"],
};
/// Our label of each key of `VIDEO` and `INPUT` (same order).
const VIDEO_LABELS: [&str; 8] = [
    "widescreen",
    "ultrawide",
    "4K",
    "field of view",
    "windowed",
    "borderless windowed",
    "60 FPS",
    "120 FPS",
];
const INPUT_LABELS: [&str; 2] = ["controller support", "controller hotplug"];

/// The comma-separated items of a value, at most [`MAX_ITEMS`].
fn items(v: &str) -> Result<Vec<&str>, PcgwError> {
    let v: Vec<&str> = v
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    if v.len() > MAX_ITEMS {
        return Err(shape(format!("a list of more than {MAX_ITEMS} items")));
    }
    Ok(v)
}

/// `steam appid`: app IDs, 1 to `u32::MAX`; anything else is an error.
fn steam_ids(v: &str) -> Result<Vec<u32>, PcgwError> {
    let mut out = Vec::new();
    for s in items(v)? {
        let n = (s.len() <= 10 && s.bytes().all(|c| c.is_ascii_digit()))
            .then(|| s.parse::<u32>().ok())
            .flatten()
            .filter(|n| *n >= 1)
            .ok_or_else(|| shape("{{Infobox game}}: a steam appid that is not an app ID"))?;
        if !out.contains(&n) {
            out.push(n);
        }
    }
    Ok(out)
}

/// A version item (`9`, `9.0c`, `10.1`): its major version.
fn major(s: &str) -> Option<u8> {
    let (num, rest) = s.split_at(s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len()));
    let minor_ok = rest.is_empty()
        || rest.strip_prefix('.').is_some_and(|m| {
            let digits = m.trim_end_matches(|c: char| c.is_ascii_lowercase());
            (1..=2).contains(&digits.len())
                && digits.bytes().all(|c| c.is_ascii_digit())
                && m.len() - digits.len() <= 1
        });
    ((1..=2).contains(&num.len()) && minor_ok)
        .then(|| num.parse().ok())
        .flatten()
}

/// The Direct3D majors of a value; items that are no version are not counted.
fn d3d(v: &str) -> Result<Vec<u8>, PcgwError> {
    let mut out: Vec<u8> = items(v)?.into_iter().filter_map(major).collect();
    out.sort_unstable();
    out.dedup();
    Ok(out)
}

/// A version list that names at least one version (or `true`).
fn listed(v: &str) -> Result<bool, PcgwError> {
    Ok(items(v)?
        .into_iter()
        .any(|s| s == "true" || major(s).is_some()))
}

fn flag(v: Option<&str>) -> Option<bool> {
    match v {
        Some("true") => Some(true),
        Some("false") => Some(false),
        _ => None,
    }
}

/// Facts and fix anchors of a parse reply for `asked` (module docs).
pub fn parse_page(body: &[u8], asked: &PageName) -> Result<(GameFacts, Fixes), PcgwError> {
    if body.iter().find(|c| !c.is_ascii_whitespace()) != Some(&b'{') {
        return Err(PcgwError::NotJson);
    }
    let r: Reply = serde_json::from_slice(body).map_err(|_| shape("not a MediaWiki reply"))?;
    if let Some(e) = r.error {
        let plain = (1..=64).contains(&e.code.len())
            && e.code
                .bytes()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-');
        return Err(match e.code.as_str() {
            "missingtitle" | "invalidtitle" => PcgwError::NotFound,
            _ => PcgwError::Api(plain.then_some(e.code)),
        });
    }
    let p = r.parse.ok_or_else(|| shape("no parse result"))?;
    let page = PageName::parse(&p.title).map_err(|_| shape("a page title of another form"))?;
    if !page.same(asked) {
        return Err(shape("the reply names another page"));
    }
    let head = p.wikitext.trim_start().get(..9).unwrap_or_default();
    if head.eq_ignore_ascii_case("#redirect") {
        return Err(shape("the page is a redirect: pass its target with --page"));
    }
    let fixes = fixes(&p.sections)?;
    let found = wikitext::read(&p.wikitext, &[INFOBOX, API, VIDEO, INPUT])
        .map_err(|e| shape(e.to_string()))?;
    let [infobox, api, video, input]: [wikitext::Found; 4] = found
        .try_into()
        .map_err(|_| shape("the scanner's result"))?;
    let infobox = infobox.ok_or_else(|| {
        shape("no {{Infobox game}} on the page (not a game page, or the template was renamed)")
    })?;
    let steam = steam_ids(infobox[0].as_deref().unwrap_or(""))?;
    let mut missing = Vec::new();
    let (api, bits) = match api {
        None => {
            missing.push("API");
            (None, (None, None))
        }
        Some(v) => {
            let get = |i: usize| v[i].as_deref().unwrap_or("");
            (
                Some(ApiFacts {
                    d3d: d3d(get(0))?,
                    ddraw: listed(get(1))?,
                    opengl: listed(get(2))?,
                    glide: listed(get(3))?,
                    vulkan: listed(get(4))?,
                }),
                (flag(v[5].as_deref()), flag(v[6].as_deref())),
            )
        }
    };
    let mut hackable = Vec::new();
    for (found, labels, section, name) in [
        (video, &VIDEO_LABELS[..], "Video", "Video"),
        (input, &INPUT_LABELS[..], "Input", "Input"),
    ] {
        match found {
            None => missing.push(name),
            Some(v) => {
                for (value, label) in v.iter().zip(labels) {
                    if value
                        .as_deref()
                        .is_some_and(|s| s.eq_ignore_ascii_case("hackable"))
                    {
                        hackable.push((*label, section));
                    }
                }
            }
        }
    }
    Ok((
        GameFacts {
            page,
            steam,
            api,
            bits,
            hackable,
            missing,
        },
        fixes,
    ))
}

fn fixes(sections: &[Section]) -> Result<Fixes, PcgwError> {
    if sections.len() > MAX_SECTIONS {
        return Err(shape(format!("more than {MAX_SECTIONS} sections")));
    }
    let mut f = Fixes::default();
    let mut under: Option<usize> = None;
    for s in sections {
        let level: u8 = match s.level.as_str() {
            l @ ("1" | "2" | "3" | "4" | "5" | "6") => l.parse().unwrap_or(0),
            _ => return Err(shape("a section level of another form")),
        };
        let a =
            Anchor::parse(&s.anchor).ok_or_else(|| shape("a section anchor of another form"))?;
        if level <= 2 {
            under = match a.as_str() {
                "Essential_improvements" => Some(0),
                "Issues_fixed" => Some(1),
                "Issues_unresolved" => Some(2),
                _ => None,
            };
            continue;
        }
        match under {
            Some(0) => f.essential.push(a),
            Some(1) => f.fixed.push(a),
            Some(2) => f.unresolved.push(a),
            _ => {}
        }
    }
    Ok(f)
}

// ---------- the client ----------

/// The requests of one run (module docs).
pub struct Client<'h> {
    http: &'h dyn Http,
    sent: usize,
    started: Instant,
    last: Option<Instant>,
    spacing: Duration,
    deadline: Duration,
}

/// A reply: status, `Location`, and the body (empty unless read).
struct Got {
    status: u16,
    location: Option<String>,
    body: Vec<u8>,
}

impl<'h> Client<'h> {
    /// A client; the deadline counts from now.
    pub fn new(http: &'h dyn Http, spacing: Duration, deadline: Duration) -> Self {
        Self {
            http,
            sent: 0,
            started: Instant::now(),
            last: None,
            spacing,
            deadline,
        }
    }

    fn late(&self) -> Result<(), PcgwError> {
        if self.started.elapsed() > self.deadline {
            Err(PcgwError::Deadline)
        } else {
            Ok(())
        }
    }

    /// One request; the body is read only for 200 and only with `read`.
    fn get(&mut self, path: &str, read: bool) -> Result<Got, PcgwError> {
        if self.sent >= MAX_REQUESTS {
            return Err(PcgwError::Budget);
        }
        if let Some(last) = self.last {
            let wait = self.spacing.saturating_sub(last.elapsed());
            if self.started.elapsed() + wait > self.deadline {
                return Err(PcgwError::Deadline);
            }
            std::thread::sleep(wait);
        }
        self.late()?;
        self.sent += 1;
        self.last = Some(Instant::now());
        let r = self.http.get(HOST, path).map_err(PcgwError::Transport)?;
        let mut body = Vec::new();
        if read && r.status == 200 {
            if r.length.is_some_and(|n| n > MAX_REPLY as u64) {
                return Err(PcgwError::TooLarge);
            }
            let mut reader = r.body.take(MAX_REPLY as u64 + 1);
            let mut buf = [0u8; 16 * 1024];
            loop {
                let n = reader.read(&mut buf).map_err(|e| {
                    PcgwError::Transport(SysError::io(&e, format!("https://{HOST}")))
                })?;
                if n == 0 {
                    break;
                }
                body.extend_from_slice(&buf[..n]);
                if body.len() > MAX_REPLY {
                    return Err(PcgwError::TooLarge);
                }
                self.late()?;
            }
        }
        Ok(Got {
            status: r.status,
            location: r.location,
            body,
        })
    }

    /// The page of `t`: a page as given, an app ID through the lookup (one request).
    pub fn page(&mut self, t: &Target) -> Result<PageName, PcgwError> {
        match t {
            Target::Page(p) => Ok(p.clone()),
            Target::SteamApp(n) => {
                let g = self.get(&appid_path(*n), false)?;
                match g.status {
                    301 | 302 | 303 | 307 | 308 => {
                        page_of_location(g.location.as_deref().ok_or(PcgwError::Location)?)
                    }
                    // The lookup answers an unknown app ID with a page of its own.
                    200 | 404 => Err(PcgwError::NotFound),
                    s => Err(PcgwError::Status(s)),
                }
            }
        }
    }

    /// The facts and fix anchors of `page` (one request).
    pub fn facts(&mut self, page: &PageName) -> Result<(GameFacts, Fixes), PcgwError> {
        let g = self.get(&parse_path(page), true)?;
        match g.status {
            200 => parse_page(&g.body, page),
            s @ 300..=399 => Err(PcgwError::Redirect(s)),
            404 => Err(PcgwError::NotFound),
            s => Err(PcgwError::Status(s)),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests;
