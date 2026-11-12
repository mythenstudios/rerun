//! `draft`: a Topo draft from a PCGamingWiki page (P4-14, docs/02 "Drafts from PCGamingWiki").
//!
//! The draft holds facts and links only: `status: draft`, `TODO` hashes, `issues: []`, no
//! launch, no step. What a curator has to look at is a `# TODO` comment: the launch, each fix
//! section of the page (`# TODO issue: <link>`), each `{{Video}}`/`{{Input}}` feature PCGW marks
//! `hackable`. Comments hold only text built here (fixed words, numbers, percent-encoded URLs
//! of the wiki), never text of the page and never a local path.
//!
//! The YAML is written by a small emitter with a fixed template (comments need it; there is no
//! serialiser): every string double-quoted with `"` and `\` escaped; a control, format or bidi
//! character in a value is refused before (`escape::text`). Before anything is printed or
//! written the text goes the loader's way: `load_yaml` → `Topo` → `check::topo(Rules::Source)` →
//! `status: draft` → equal to the Topo intended ([`self_check`]); otherwise nothing comes out.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use rerun_core::catalog::Topo;
use rerun_core::catalog::check::{self, Rules};
use rerun_core::catalog::model::{Api, Exe, Id, Links, Match, Sha256, Status};
use rerun_core::escape;
use rerun_core::path::RelPath;
use rerun_core::sys::Http;

use crate::bundle::load_yaml;
use crate::local::{Local, LocalExe};
use crate::pcgw::{ApiFacts, Client, Fixes, GameFacts, PageName, Target};

/// The spacing between the two requests.
pub const SPACING: Duration = Duration::from_secs(1);
/// The deadline of the whole exchange.
pub const DEADLINE: Duration = Duration::from_secs(60);

/// What the curator asked for.
#[derive(Debug, Clone)]
pub struct Request {
    /// The app ID or page.
    pub target: Target,
    /// `--id`.
    pub id: Option<Id>,
    /// `--title`.
    pub title: Option<String>,
    /// `--hashes-from`: the local copy's executables, scanned before any request.
    pub local: Option<Local>,
}

/// The executables of the draft.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Exes {
    /// One placeholder `{ path: TODO, sha256: TODO, api }` (user decision D1 a).
    Stub(Api),
    /// The main executables of a local copy with their real hashes (`--hashes-from`).
    Local(Vec<LocalExe>),
}

/// A draft before it is rendered.
#[derive(Debug, Clone)]
pub struct Draft {
    /// The ID.
    pub id: Id,
    /// The title.
    pub title: String,
    /// `match.steam_appid`.
    pub steam_appid: Option<u32>,
    /// `links.pcgw`.
    pub pcgw: Option<String>,
    /// The page's URL.
    pub url: String,
    /// The executables.
    pub exes: Exes,
    /// Comments after `match` (ASCII, built here).
    pub notes: Vec<String>,
    /// `# TODO issue:` links.
    pub issue_links: Vec<String>,
}

/// The ID from a page name: ASCII lower-case letters and digits, `'` dropped, anything else a
/// hyphen, runs joined, at most 64. `None` for a name with a non-ASCII character or nothing left.
pub fn derive_id(page: &PageName) -> Option<Id> {
    let s = page.as_str();
    if !s.is_ascii() {
        return None;
    }
    let mut out = String::new();
    for c in s.chars().filter(|c| *c != '\'') {
        if c.is_ascii_alphanumeric() {
            out.push(c.to_ascii_lowercase());
        } else if !out.is_empty() && !out.ends_with('-') {
            out.push('-');
        }
    }
    out.truncate(Id::MAX_LEN);
    Id::parse(out.trim_end_matches('-'))
}

/// A title as given, if it is 1 to 200 characters that `escape::text` leaves as they are.
pub fn check_title(s: &str) -> Option<String> {
    let ok =
        (1..=200).contains(&s.chars().count()) && escape::text(s).as_str() == s && s.trim() == s;
    ok.then(|| s.to_owned())
}

/// The APIs a Topo can name, and the names of those it cannot (ADR 0014: `d3d12`, `vulkan`,
/// `glide` are reserved). Direct3D 7 and older count as DirectDraw, as detection does.
pub fn apis(a: &ApiFacts) -> (BTreeSet<Api>, Vec<String>) {
    let mut set = BTreeSet::new();
    let mut other = Vec::new();
    for v in &a.d3d {
        match v {
            0..=7 => set.insert(Api::Ddraw),
            8 => set.insert(Api::D3d8),
            9 => set.insert(Api::D3d9),
            10 => set.insert(Api::D3d10),
            11 => set.insert(Api::D3d11),
            v => {
                other.push(format!("Direct3D {v}"));
                false
            }
        };
    }
    if a.ddraw {
        set.insert(Api::Ddraw);
    }
    if a.opengl {
        set.insert(Api::Opengl);
    }
    if a.vulkan {
        other.push("Vulkan".into());
    }
    if a.glide {
        other.push("Glide".into());
    }
    (set, other)
}

/// The API of the placeholder: exactly one API on the page, one a Topo can name, and every
/// version list of the page read.
pub fn stub_api(a: &ApiFacts) -> Option<Api> {
    let (set, other) = apis(a);
    match (set.len(), other.is_empty() && a.unclear.is_empty()) {
        (1, true) => set.into_iter().next(),
        _ => None,
    }
}

fn api_name(a: Api) -> &'static str {
    match a {
        Api::Ddraw => "ddraw",
        Api::D3d8 => "d3d8",
        Api::D3d9 => "d3d9",
        Api::D3d10 => "d3d10",
        Api::D3d11 => "d3d11",
        Api::Opengl => "opengl",
    }
}

/// A YAML double-quoted scalar (the value holds no control character, [`check_title`]).
fn yq(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

/// A comment line: printable ASCII only (anything else becomes `?`; nothing else is ever
/// passed, the guard keeps it so).
fn comment(out: &mut String, s: &str) {
    let s: String = s
        .chars()
        .map(|c| {
            if c == ' ' || c.is_ascii_graphic() {
                c
            } else {
                '?'
            }
        })
        .collect();
    let _ = writeln!(out, "# {s}");
}

/// The YAML of `d` (module docs).
pub fn render(d: &Draft) -> String {
    let mut o = String::new();
    comment(
        &mut o,
        "Draft from PCGamingWiki (rerun-workbench draft): facts and links only.",
    );
    comment(
        &mut o,
        "Curate it (docs/02-topo-format.md) before it leaves status draft.",
    );
    comment(&mut o, &format!("Page: {}", d.url));
    o.push_str("format: 1\n");
    let _ = writeln!(o, "id: {}", yq(d.id.as_str()));
    let _ = writeln!(o, "title: {}", yq(&d.title));
    o.push_str("status: \"draft\"\nrev: 1\nmatch:\n");
    if let Some(n) = d.steam_appid {
        let _ = writeln!(o, "  steam_appid: {n}");
    }
    o.push_str("  exes:\n");
    match &d.exes {
        Exes::Stub(api) => {
            o.push_str(
                "    # TODO: the executable's path and hash (computed from the game files)\n",
            );
            let _ = writeln!(
                o,
                "    - {{ path: \"TODO\", sha256: \"TODO\", api: {} }}",
                yq(api_name(*api))
            );
        }
        Exes::Local(v) => {
            o.push_str(
                "    # hashes from a local copy of the game: verify its files in Steam first\n",
            );
            for e in v {
                let _ = writeln!(
                    o,
                    "    - {{ path: {}, sha1: {}, sha256: {}, api: {} }}",
                    yq(e.path.as_str()),
                    yq(&e.sha1.to_string()),
                    yq(&e.sha256.to_string()),
                    yq(api_name(e.api))
                );
            }
        }
    }
    for n in &d.notes {
        comment(&mut o, n);
    }
    comment(
        &mut o,
        "TODO launch: chain, method and start (docs/02-topo-format.md, launch.start); never guessed.",
    );
    o.push_str("issues: []\n");
    for l in &d.issue_links {
        comment(&mut o, &format!("TODO issue: {l}"));
    }
    if let Some(p) = &d.pcgw {
        let _ = writeln!(o, "links:\n  pcgw: {}", yq(p));
    }
    o
}

/// The Topo `d` stands for.
fn intended(d: &Draft) -> Result<Topo, String> {
    let todo = Sha256::parse("TODO").ok_or("TODO")?;
    let exes = match &d.exes {
        Exes::Stub(api) => vec![Exe {
            path: RelPath::parse("TODO").map_err(|e| e.to_string())?,
            sha1: None,
            sha256: Some(todo),
            api: *api,
        }],
        Exes::Local(v) => v
            .iter()
            .map(|e| Exe {
                path: e.path.clone(),
                sha1: Some(e.sha1.clone()),
                sha256: Some(e.sha256.clone()),
                api: e.api,
            })
            .collect(),
    };
    Ok(Topo {
        // Facts and links only: format 1 (ADR 0024 amendment "Forward compatibility" §6).
        format: 1,
        id: d.id.clone(),
        title: d.title.clone(),
        status: Status::Draft,
        rev: 1,
        tested_on: Vec::new(),
        matches: Match {
            steam_appid: d.steam_appid,
            exes,
        },
        launch: None,
        anti_cheat: None,
        user_data: None,
        issues: Vec::new(),
        tips: None,
        links: d.pcgw.clone().map(|p| Links { pcgw: Some(p) }),
    })
}

/// The loader's way (module docs); the Topo it read.
pub fn self_check(text: &str, d: &Draft) -> Result<Topo, String> {
    let v = load_yaml(text).map_err(|e| format!("the draft does not load: {e}"))?;
    let t: Topo = serde_json::from_value(v).map_err(|e| format!("the draft does not load: {e}"))?;
    check::topo(&t, Rules::Source).map_err(|e| format!("the draft breaks a rule: {e}"))?;
    if t.status != Status::Draft {
        return Err("the draft is not status: draft".into());
    }
    if t != intended(d)? {
        return Err("the draft reads back as another Topo".into());
    }
    if text
        .lines()
        .any(|l| l.trim_start().starts_with('#') && !l.is_ascii())
    {
        return Err("a comment of the draft is not ASCII".into());
    }
    Ok(t)
}

fn api_facts_line(a: &ApiFacts, bits: (Option<bool>, Option<bool>)) -> String {
    let mut parts = Vec::new();
    let unclear = |name: &str| a.unclear.contains(&name);
    if unclear("Direct3D") {
        parts.push("Direct3D (version not read)".to_owned());
    } else if !a.d3d.is_empty() {
        let v: Vec<String> = a.d3d.iter().map(u8::to_string).collect();
        parts.push(format!("Direct3D {}", v.join(", ")));
    }
    for (on, name) in [
        (a.ddraw, "DirectDraw"),
        (a.opengl, "OpenGL"),
        (a.vulkan, "Vulkan"),
        (a.glide, "Glide"),
    ] {
        if unclear(name) {
            parts.push(format!("{name} (version not read)"));
        } else if on {
            parts.push(name.into());
        }
    }
    if parts.is_empty() {
        parts.push("no graphics API".into());
    }
    let b = |x: Option<bool>| x.map_or("unknown", |v| if v { "yes" } else { "no" });
    format!(
        "PCGW API: {}; 32-bit exe {}, 64-bit exe {}",
        parts.join("; "),
        b(bits.0),
        b(bits.1)
    )
}

/// The draft of `facts` (no request).
pub fn build(req: &Request, facts: &GameFacts, fixes: &Fixes) -> Result<Draft, String> {
    let page = &facts.page;
    let url = page.url();
    let mut notes = Vec::new();
    let steam_appid = match (&req.target, facts.steam.as_slice()) {
        (Target::SteamApp(n), ids) => {
            if !ids.contains(n) {
                return Err(format!(
                    "{url} does not name Steam app {n} (the app ID lookup led elsewhere): pass the page with --page"
                ));
            }
            Some(*n)
        }
        (Target::Page(_), [one]) => Some(*one),
        (Target::Page(_), []) => None,
        (Target::Page(_), ids) => {
            let v: Vec<String> = ids.iter().map(u32::to_string).collect();
            notes.push(format!(
                "TODO match.steam_appid: PCGW names several app IDs: {}",
                v.join(", ")
            ));
            None
        }
    };
    let id = match &req.id {
        Some(id) => id.clone(),
        None => derive_id(page).ok_or("no ID from the page name: pass --id")?,
    };
    let title = match &req.title {
        Some(t) => check_title(t).ok_or(
            "--title: 1 to 200 characters, none of them control, format or bidi characters",
        )?,
        None => check_title(page.as_str()).ok_or("no title from the page name: pass --title")?,
    };
    let api = facts.api.clone().unwrap_or_default();
    let (named, other) = apis(&api);
    let exes = match (&req.local, stub_api(&api)) {
        (Some((v, left_out)), _) => {
            notes.push(
                "hashes from a local copy: a modified copy (mods, patches) gives wrong hashes"
                    .into(),
            );
            notes.extend(left_out.iter().cloned());
            if facts.api.is_some() {
                for e in v.iter().filter(|e| !named.contains(&e.api)) {
                    notes.push(format!(
                        "TODO: the local executable uses {}, PCGW does not name it",
                        api_name(e.api)
                    ));
                }
            }
            Exes::Local(v.clone())
        }
        (None, Some(a)) => Exes::Stub(a),
        (None, None) => {
            return Err(format!(
                "PCGamingWiki names no single graphics API a Topo can hold ({}): pass --hashes-from <game folder>",
                api_facts_line(&api, facts.bits)
            ));
        }
    };
    if facts.api.is_some() {
        notes.push(api_facts_line(&api, facts.bits));
    }
    if !other.is_empty() {
        notes.push(format!(
            "PCGW also names {}: a Topo cannot name it yet (ADR 0014)",
            other.join(", ")
        ));
    }
    for m in &facts.missing {
        notes.push(format!("PCGW: no {{{{{m}}}}} template on the page"));
    }
    for (label, section) in &facts.hackable {
        notes.push(format!("TODO: PCGW: {label} hackable - {url}#{section}"));
    }
    let wiki = page.wiki();
    let pcgw = if wiki.contains(['/', '?', '#']) {
        notes.push("links.pcgw left out: the page name holds / ? or #".into());
        None
    } else {
        Some(wiki)
    };
    let issue_links = [&fixes.essential, &fixes.fixed, &fixes.unresolved]
        .into_iter()
        .flatten()
        .map(|a| format!("{url}#{}", a.as_str()))
        .collect();
    Ok(Draft {
        id,
        title,
        steam_appid,
        pcgw,
        url,
        exes,
        notes,
        issue_links,
    })
}

/// Asks PCGamingWiki and makes the draft and its checked YAML.
pub fn make(
    http: &dyn Http,
    req: &Request,
    spacing: Duration,
    deadline: Duration,
) -> Result<(Draft, String), String> {
    let mut client = Client::new(http, spacing, deadline);
    let page = client.page(&req.target).map_err(|e| e.to_string())?;
    let (facts, fixes) = client.facts(&page).map_err(|e| e.to_string())?;
    let d = build(req, &facts, &fixes)?;
    let text = render(&d);
    self_check(&text, &d)?;
    Ok((d, text))
}

/// The `*.yaml` files of `dir` whose `match.steam_appid` is `n` (a warning, `--into`).
pub fn same_app(dir: &Path, n: u32) -> Vec<String> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    for e in entries.flatten() {
        let p = e.path();
        if p.extension().is_none_or(|x| x != "yaml") {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&p) else {
            continue;
        };
        let names = load_yaml(&text).ok().is_some_and(|v| {
            v.get("match")
                .and_then(|m| m.get("steam_appid"))
                .and_then(serde_json::Value::as_u64)
                == Some(u64::from(n))
        });
        if names {
            out.push(e.file_name().to_string_lossy().into_owned());
        }
    }
    out.sort();
    out
}

/// Writes `<dir>\<id>.yaml`, never over a file.
pub fn write_into(dir: &Path, d: &Draft, text: &str) -> Result<PathBuf, String> {
    let path = dir.join(format!("{}.yaml", d.id));
    crate::create_new(&path, text, false)?;
    Ok(path)
}

#[cfg(test)]
pub(crate) mod tests;
