//! The form rules of the typed Topo and package that their types do not carry: the rules of
//! `schema/topo.schema.json` and `schema/package.schema.json` (parity test against the same
//! fixtures, ADR 0005) plus a few loader rules the schema cannot express (unique issue and
//! variant IDs, the registry vendor deny list, unique value names, the qword range, download
//! provenance). The rules in force now of the planners (token allowlist, INI value rule, the
//! game folder itself) stay the planners'.
//!
//! [`Rules::Source`] is a file of `topos/` or `packages/`: `TODO` only in a draft.
//! [`Rules::Release`] is an entry of the signed index: no draft, no `TODO` anywhere.

use std::collections::BTreeSet;

use super::model::{
    ArchList, Compare, FirewallRuleSpec, Id, Launch, Method, Package, PackageOption, Source,
    SourceType, Status, TODO, Tier, Topo, TopoStep, When,
};
use crate::fold::fold;
use crate::policy::ini::IniName;
use crate::policy::registry::{AsciiName, AsciiSeg, GameKey};
use crate::prim::registry_set::{KEY_PREFIX, MAX_VALUES};
use crate::prim::{CompatLayerSpec, CpuRuleSpec, IniSetSpec, RegistrySetSpec};

/// Whether a Topo outside a draft may release an anti-cheat system as dead (`anti_cheat`,
/// P4-4). `false` until the field is reviewed: the signed index then holds none, and the
/// engine enforces the anti-cheat rule for every system it finds.
pub const ANTI_CHEAT_RELEASE_REVIEWED: bool = false;

/// Whether a Topo outside a draft may hold a `firewall_rule` step (P4-5a). `true` since the
/// step was reviewed with the helper chain: the [DEV] round trip through the real prompt and the
/// installed helper passed on 2026-11-10 (P4-5b, ADR 0023 §15), the agreed condition. Setting it
/// back to `false` makes the step draft only again (the signed index then holds none).
pub const FIREWALL_RULE_REVIEWED: bool = true;

/// Most executables of `match.exes` (P4-4: each is hashed when the engine reads a game).
pub const MAX_EXES: usize = 8;

/// Which entries are allowed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rules {
    /// A source file: `TODO` only with `status: draft`.
    Source,
    /// An entry of the signed index: never a draft, never `TODO`.
    Release,
}

/// A broken rule: where (a field path) and what.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{at}: {what}")]
pub struct RuleError {
    /// The field, e.g. `issues[0].variants[1].steps[0]`.
    pub at: String,
    /// The rule.
    pub what: String,
}

type R = Result<(), RuleError>;

fn err(at: &str, what: impl Into<String>) -> RuleError {
    RuleError {
        at: at.to_owned(),
        what: what.into(),
    }
}

fn ensure(ok: bool, at: &str, what: &str) -> R {
    if ok { Ok(()) } else { Err(err(at, what)) }
}

/// Characters a text, a path or a default must not hold: the class of `$defs/relPath`
/// (control, format, invisible and confusable characters, private use).
fn deceptive(c: char) -> bool {
    matches!(c,
        '\u{00}'..='\u{1F}' | '\u{7F}'..='\u{9F}' | '\u{A0}' | '\u{AD}' | '\u{61C}' | '\u{1680}'
        | '\u{180E}' | '\u{2000}'..='\u{200F}' | '\u{2028}'..='\u{202F}' | '\u{205F}'..='\u{206F}'
        | '\u{3000}' | '\u{FEFF}' | '\u{FFF9}'..='\u{FFFB}' | '\u{E000}'..='\u{F8FF}'
        | '\u{FF01}'..='\u{FF5E}' | '\u{A5}' | '\u{20A9}' | '\u{2215}' | '\u{2044}' | '\u{29F8}')
}

fn chars_between(s: &str, min: usize, max: usize) -> bool {
    (min..=max).contains(&s.chars().count())
}

fn unique<T: Ord>(items: impl IntoIterator<Item = T>) -> bool {
    let mut seen = BTreeSet::new();
    items.into_iter().all(|x| seen.insert(x))
}

/// Whether any string in the serialised entry is exactly `TODO`.
fn has_todo<T: serde::Serialize>(entry: &T) -> bool {
    fn any(v: &serde_json::Value) -> bool {
        match v {
            serde_json::Value::String(s) => s == TODO,
            serde_json::Value::Array(a) => a.iter().any(any),
            serde_json::Value::Object(o) => o.values().any(any),
            _ => false,
        }
    }
    serde_json::to_value(entry).is_ok_and(|v| any(&v))
}

fn status_rule<T: serde::Serialize>(entry: &T, status: Status, rules: Rules) -> R {
    let todo = has_todo(entry);
    match rules {
        Rules::Source => ensure(
            !todo || status == Status::Draft,
            "status",
            "an entry with TODO must be status: draft",
        ),
        Rules::Release => {
            ensure(
                status != Status::Draft,
                "status",
                "a draft is never released",
            )?;
            ensure(!todo, "", "a released entry has no TODO")
        }
    }
}

// ---------- URLs ----------

// The URL grammar lives in `policy::url` (one rule for the loader and the downloader, ADR 0025).
use crate::policy::url::{belongs, forge, space, split_https};
pub use crate::policy::url::{https_url, release_download, repo_url};

fn digits(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|c| c.is_ascii_digit())
}

/// The URL rule of a source type (`$defs/source`).
pub fn source_url(kind: SourceType, u: &str) -> bool {
    if u.chars().count() > 2048 {
        return false;
    }
    match kind {
        SourceType::Repo => forge(u).is_some_and(|(_, _, tail)| !tail.chars().any(space)),
        SourceType::SteamGuide => u
            .strip_prefix("https://steamcommunity.com/sharedfiles/filedetails/?id=")
            .is_some_and(digits),
        SourceType::SteamThread => {
            let Some(r) = u.strip_prefix("https://steamcommunity.com/") else {
                return false;
            };
            let r = r.strip_suffix('/').unwrap_or(r);
            let p: Vec<&str> = r.split('/').collect();
            let who = match p.first() {
                Some(&"app") => p.get(1).is_some_and(|n| digits(n)),
                Some(&"groups") => p.get(1).is_some_and(|n| {
                    !n.is_empty()
                        && n.bytes()
                            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-'))
                }),
                _ => false,
            };
            who && p.len() == 5 && p[2] == "discussions" && digits(p[3]) && digits(p[4])
        }
        SourceType::Pcgw => u
            .strip_prefix("https://www.pcgamingwiki.com/wiki/")
            .is_some_and(|r| {
                let (page, frag) = match r.split_once('#') {
                    Some((p, f)) => (p, Some(f)),
                    None => (r, None),
                };
                !page.is_empty()
                    && !page.chars().any(space)
                    && frag.is_none_or(|f| !f.is_empty() && !f.chars().any(space))
            }),
        SourceType::Official => {
            https_url(u) && split_https(u).is_some_and(|(_, rest)| rest.len() > 1)
        }
    }
}

fn source(s: &Source, at: &str) -> R {
    ensure(
        source_url(s.kind, &s.url),
        &format!("{at}.url"),
        "not a link of this source type (direct, https, the documented form)",
    )
}

// ---------- Topo ----------

/// Checks a Topo.
pub fn topo(t: &Topo, rules: Rules) -> Result<(), RuleError> {
    ensure(
        t.format == super::model::FORMAT,
        "format",
        "format must be 1",
    )?;
    ensure(
        chars_between(&t.title, 1, 200),
        "title",
        "1 to 200 characters",
    )?;
    ensure(t.rev >= 1, "rev", "at least 1")?;
    ensure(
        unique(t.tested_on.iter().map(|p| *p as u8)),
        "tested_on",
        "unique items",
    )?;
    ensure(
        t.matches.steam_appid != Some(0),
        "match.steam_appid",
        "1 to 4294967295",
    )?;
    ensure(
        !t.matches.exes.is_empty(),
        "match.exes",
        "at least one executable",
    )?;
    ensure(
        t.matches.exes.len() <= MAX_EXES,
        "match.exes",
        "at most 8 executables",
    )?;
    for (i, e) in t.matches.exes.iter().enumerate() {
        ensure(
            e.sha1.is_some() || e.sha256.is_some(),
            &format!("match.exes[{i}]"),
            "sha1 or sha256 required",
        )?;
    }
    if let Some(l) = &t.launch {
        launch(l)?;
    }
    if let Some(a) = &t.anti_cheat {
        ensure(
            !a.dead.is_empty() && unique(a.dead.iter()),
            "anti_cheat.dead",
            "at least one system, unique",
        )?;
        source(&a.source, "anti_cheat.source")?;
        // P4-4: a new release of the anti-cheat rule; draft only until it is reviewed.
        ensure(
            ANTI_CHEAT_RELEASE_REVIEWED || t.status == Status::Draft,
            "anti_cheat",
            "draft only until the anti-cheat release is reviewed (P4-4)",
        )?;
    }
    ensure(
        unique(t.issues.iter().map(|i| &i.id)),
        "issues",
        "issue IDs are unique",
    )?;
    for (i, issue) in t.issues.iter().enumerate() {
        let at = format!("issues[{i}]");
        ensure(
            chars_between(&issue.title, 1, 200),
            &format!("{at}.title"),
            "1 to 200 characters",
        )?;
        if let Some(w) = &issue.when {
            when(w, &format!("{at}.when"))?;
        }
        ensure(
            unique(issue.variants.iter().map(|v| &v.id)),
            &format!("{at}.variants"),
            "variant IDs are unique",
        )?;
        for (j, v) in issue.variants.iter().enumerate() {
            let at = format!("{at}.variants[{j}]");
            ensure(
                !v.steps.is_empty(),
                &format!("{at}.steps"),
                "at least one step",
            )?;
            for (k, s) in v.steps.iter().enumerate() {
                let at = format!("{at}.steps[{k}]");
                step(s, &at)?;
                if let TopoStep::FirewallRule(f) = s {
                    firewall_rule(t, f, &format!("{at}.firewall_rule"))?;
                }
            }
            for (k, x) in v.tradeoffs.iter().enumerate() {
                ensure(!x.is_empty(), &format!("{at}.tradeoffs[{k}]"), "not empty")?;
            }
            for (k, s) in v.sources.iter().enumerate() {
                source(s, &format!("{at}.sources[{k}]"))?;
            }
        }
    }
    if let Some(tips) = &t.tips {
        for (i, o) in tips.launch_options.iter().enumerate() {
            let b = o.as_bytes();
            let ok = b.len() >= 2
                && b.len() <= 64
                && matches!(b[0], b'-' | b'+')
                && b[1..].iter().all(|c| {
                    c.is_ascii_alphanumeric() || matches!(c, b'_' | b'.' | b'=' | b'+' | b'-')
                });
            ensure(
                ok,
                &format!("tips.launch_options[{i}]"),
                "one game argument: - or + then A-Z a-z 0-9 _ . = + -, at most 64",
            )?;
        }
        for (i, n) in tips.notes.iter().enumerate() {
            ensure(
                !n.text.is_empty(),
                &format!("tips.notes[{i}].text"),
                "not empty",
            )?;
            if let Some(s) = &n.source {
                source(s, &format!("tips.notes[{i}].source"))?;
            }
        }
    }
    if let Some(p) = t.links.as_ref().and_then(|l| l.pcgw.as_ref()) {
        ensure(
            !p.is_empty() && !p.chars().any(|c| space(c) || matches!(c, '/' | '?' | '#')),
            "links.pcgw",
            "a page name, not a URL",
        )?;
    }
    status_rule(t, t.status, rules)
}

fn launch(l: &Launch) -> R {
    ensure(
        unique(l.chain.iter().map(|c| *c as u8)),
        "launch.chain",
        "unique items",
    )?;
    if let Some(c) = &l.cpu {
        cpu_rule(c, "launch.cpu")?;
        ensure(
            c.report_cores.is_none() || l.method == Some(Method::Inproc),
            "launch.cpu.report_cores",
            "only with method: inproc",
        )?;
        ensure(
            c.report_cores.is_none_or(|n| (1..=1024).contains(&n)),
            "launch.cpu.report_cores",
            "1 to 1024",
        )?;
    }
    if let Some(s) = &l.start {
        ensure(
            s.as_str() == TODO || ends_with_ci(s.as_str(), ".exe"),
            "launch.start",
            "a .exe (or TODO in a draft)",
        )?;
    }
    // P4-4: the engine needs Steam's launch entry for these methods (`auto` resolves to
    // `direct` or `watch`); never guessed, unknown is `TODO` in a draft.
    ensure(
        !matches!(
            l.method,
            Some(Method::Auto | Method::Direct | Method::Watch)
        ) || l.start.is_some(),
        "launch.start",
        "required for method auto, direct and watch",
    )?;
    Ok(())
}

fn ends_with_ci(s: &str, ext: &str) -> bool {
    s.len() >= ext.len()
        && s.is_char_boundary(s.len() - ext.len())
        && s[s.len() - ext.len()..].eq_ignore_ascii_case(ext)
}

fn cpu_rule(c: &CpuRuleSpec, at: &str) -> R {
    let given = c.max_threads.is_some()
        || c.prefer.is_some()
        || c.single_l3.is_some()
        || c.prefer_l3.is_some()
        || c.smt.is_some()
        || c.mode.is_some()
        || c.report_cores.is_some();
    ensure(given, at, "at least one field")?;
    ensure(
        c.max_threads.is_none_or(|n| (1..=1024).contains(&n)),
        &format!("{at}.max_threads"),
        "1 to 1024",
    )
}

fn compare(c: &Compare, at: &str) -> R {
    let any = [c.gt, c.gte, c.lt, c.lte, c.eq].iter().any(Option::is_some);
    ensure(any, at, "at least one of gt, gte, lt, lte, eq")
}

fn when(w: &When, at: &str) -> R {
    if let Some(a) = &w.gpu_arch {
        ensure(
            !a.is_empty() && unique(a.iter()),
            &format!("{at}.gpu.arch"),
            "at least one identifier, unique",
        )?;
    }
    if let Some(c) = &w.cpu_threads {
        compare(c, &format!("{at}.cpu.threads"))?;
    }
    if let Some(c) = &w.os_build {
        compare(c, &format!("{at}.os.build"))?;
    }
    Ok(())
}

fn step(s: &TopoStep, at: &str) -> R {
    match s {
        TopoStep::Package(_) | TopoStep::SteamInput(_) => Ok(()),
        TopoStep::Cpu(c) => {
            cpu_rule(c, &format!("{at}.cpu"))?;
            ensure(
                c.report_cores.is_none(),
                &format!("{at}.cpu.report_cores"),
                "only in launch.cpu",
            )
        }
        TopoStep::RegistrySet(r) => registry_set(r, &format!("{at}.registry_set")),
        TopoStep::CompatLayer(c) => compat_layer(c, &format!("{at}.compat_layer")),
        TopoStep::IniSet(i) => ini_set(i, &format!("{at}.ini_set")),
        TopoStep::FirewallRule(f) => ensure(
            fold(f.exe.as_str()).ends_with(".EXE"),
            &format!("{at}.firewall_rule.exe"),
            "an .exe",
        ),
    }
}

/// `firewall_rule` against its Topo: draft only while not reviewed ([`FIREWALL_RULE_REVIEWED`]),
/// and the executable is an entry
/// of `match.exes` in exactly its spelling, with a `sha256` (ADR 0024 "sha256 for elevated anchors", P4 R6: `sha1` alone
/// never anchors anything elevated; a `TODO` only in a draft, like every `TODO`).
fn firewall_rule(t: &Topo, f: &FirewallRuleSpec, at: &str) -> R {
    ensure(
        FIREWALL_RULE_REVIEWED || t.status == Status::Draft,
        at,
        "draft only until firewall_rule is reviewed (P4-5a)",
    )?;
    // The exact spelling: `RelPath` equality folds Unicode (U+0131 equals `I`), which NTFS does
    // not; the program of the rule is derived from this entry (P4-2d), never from the step.
    let anchor = t.matches.exes.iter().find(|e| e.path.same_spelling(&f.exe));
    ensure(
        anchor.is_some(),
        &format!("{at}.exe"),
        "an executable of match.exes",
    )?;
    ensure(
        anchor.is_some_and(|e| e.sha256.is_some()),
        &format!("{at}.exe"),
        "its match.exes entry needs a sha256 (an elevated anchor, ADR 0024)",
    )
}

/// Printable ASCII without `\ / : %`.
fn reg_text_char(c: u8) -> bool {
    (0x20..=0x7E).contains(&c) && !matches!(c, b'\\' | b'/' | b':' | b'%')
}

fn registry_set(r: &RegistrySetSpec, at: &str) -> R {
    let key_at = format!("{at}.key");
    let rest = r
        .key
        .strip_prefix(KEY_PREFIX)
        .ok_or_else(|| err(&key_at, "begins with HKCU\\Software\\"))?;
    let segs = rest
        .split('\\')
        .map(AsciiSeg::parse)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| err(&key_at, e.to_string()))?;
    let mut it = segs.into_iter();
    let (Some(vendor), Some(product)) = (it.next(), it.next()) else {
        return Err(err(&key_at, "<Vendor>\\<Product> required"));
    };
    GameKey::new(vendor, product, it.collect()).map_err(|e| err(&key_at, e.to_string()))?;
    ensure(
        (1..=MAX_VALUES).contains(&r.values.len()),
        &format!("{at}.values"),
        "1 to 32 values",
    )?;
    ensure(
        unique(r.values.iter().map(|v| fold(&v.name))),
        &format!("{at}.values"),
        "value names are unique (case-insensitive)",
    )?;
    for (i, v) in r.values.iter().enumerate() {
        let at = format!("{at}.values[{i}]");
        AsciiName::parse(&v.name).map_err(|e| err(&format!("{at}.name"), e.to_string()))?;
        let n = usize::from(v.dword.is_some())
            + usize::from(v.qword.is_some())
            + usize::from(v.sz.is_some());
        ensure(n == 1, &at, "exactly one of dword, qword, sz")?;
        if let Some(q) = &v.qword {
            let ok = (q == "0" || (!q.starts_with('0') && digits(q))) && q.parse::<u64>().is_ok();
            ensure(
                ok,
                &format!("{at}.qword"),
                "a decimal string from 0 to 18446744073709551615",
            )?;
        }
        if let Some(s) = &v.sz {
            ensure(
                s.len() <= 1024 && s.bytes().all(reg_text_char),
                &format!("{at}.sz"),
                "at most 1,024 printable ASCII characters without \\ / : %",
            )?;
        }
    }
    Ok(())
}

fn compat_layer(c: &CompatLayerSpec, at: &str) -> R {
    ensure(
        ends_with_ci(c.exe.as_str(), ".exe"),
        &format!("{at}.exe"),
        "a .exe",
    )?;
    ensure(
        (1..=8).contains(&c.layers.len()) && unique(c.layers.iter()),
        &format!("{at}.layers"),
        "1 to 8 unique tokens",
    )?;
    for (i, t) in c.layers.iter().enumerate() {
        let ok = (1..=40).contains(&t.len())
            && t.bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_');
        ensure(
            ok,
            &format!("{at}.layers[{i}]"),
            "1 to 40 characters of A-Z, 0-9 and _",
        )?;
    }
    Ok(())
}

fn ini_set(s: &IniSetSpec, at: &str) -> R {
    ensure(
        ends_with_ci(s.file.as_str(), ".ini"),
        &format!("{at}.file"),
        "a .ini file",
    )?;
    ensure(
        (1..=8).contains(&s.values.len()),
        &format!("{at}.values"),
        "1 to 8 values",
    )?;
    ensure(
        unique(s.values.iter().map(|v| (fold(&v.section), fold(&v.key)))),
        &format!("{at}.values"),
        "section and key unique (case-insensitive)",
    )?;
    for (i, v) in s.values.iter().enumerate() {
        let at = format!("{at}.values[{i}]");
        IniName::parse(&v.section).map_err(|_| err(&format!("{at}.section"), "an INI name"))?;
        IniName::parse(&v.key).map_err(|_| err(&format!("{at}.key"), "an INI name"))?;
        let b = v.value.as_bytes();
        let ok = (1..=128).contains(&b.len())
            && b.iter().all(|c| (0x20..=0x7E).contains(c))
            && b.first() != Some(&b' ')
            && b.last() != Some(&b' ');
        ensure(
            ok,
            &format!("{at}.value"),
            "1 to 128 printable ASCII characters, no space at either end",
        )?;
    }
    Ok(())
}

// ---------- Package ----------

/// A DLL name of `$defs/dllName`: `[A-Za-z0-9_.-]+\.dll` and the path rules.
fn dll_name(s: &str) -> bool {
    ends_with_ci(s, ".dll")
        && s.len() > 4
        && s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'.' | b'-'))
        && crate::path::RelPath::parse(s).is_ok()
}

/// `^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$` without `..`.
pub fn version(s: &str) -> bool {
    let b = s.as_bytes();
    (1..=64).contains(&b.len())
        && b[0].is_ascii_alphanumeric()
        && b.iter()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'+' | b'-'))
        && !s.contains("..")
}

/// An SPDX expression of the schema: words `[A-Za-z0-9.+-]+` joined by ` OR `, ` AND `,
/// ` WITH `.
fn license(s: &str) -> bool {
    let word = |w: &str| {
        !w.is_empty()
            && w.bytes()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'+' | b'-'))
    };
    let parts: Vec<&str> = s.split(' ').collect();
    parts.len() % 2 == 1
        && parts.iter().enumerate().all(|(i, p)| {
            if i % 2 == 0 {
                word(p)
            } else {
                matches!(*p, "OR" | "AND" | "WITH")
            }
        })
}

/// `TODO`, or an https URL that, if it names a release download, has exactly that form.
fn url_or_todo(u: &str) -> bool {
    u == TODO || (https_url(u) && release_download(u))
}

/// Checks a package.
pub fn package(p: &Package, rules: Rules) -> Result<(), RuleError> {
    ensure(
        p.format == super::model::FORMAT,
        "format",
        "format must be 1",
    )?;
    ensure(
        chars_between(&p.name, 1, 200),
        "name",
        "1 to 200 characters",
    )?;
    let src = &p.source;
    ensure(
        src.repo.is_some() || src.page.is_some() || src.release.is_some(),
        "source",
        "at least one of repo, page, release",
    )?;
    if let Some(r) = &src.repo {
        ensure(
            repo_url(r),
            "source.repo",
            "https://github.com|gitlab.com|codeberg.org/<owner>/<repo>",
        )?;
    }
    if let Some(r) = &src.page {
        ensure(https_url(r), "source.page", "an https URL")?;
    }
    if let Some(r) = &src.release {
        ensure(url_or_todo(r), "source.release", "an https URL or TODO")?;
    }
    ensure(
        version(&p.version),
        "version",
        "A-Z a-z 0-9 . _ + -, at most 64, no ..",
    )?;
    ensure(license(&p.license), "license", "an SPDX expression or TODO")?;
    if let ArchList::List(a) = &p.arch {
        ensure(
            !a.is_empty() && unique(a.iter()),
            "arch",
            "at least one, unique",
        )?;
    }
    if let Some(assets) = &p.assets {
        ensure(!assets.is_empty(), "assets", "at least one")?;
        for (i, a) in assets.iter().enumerate() {
            ensure(
                url_or_todo(&a.url),
                &format!("assets[{i}].url"),
                "an https URL or TODO",
            )?;
        }
    }
    // The download forms (schema allOf).
    if p.tier == Tier::Community {
        ensure(
            p.sha256.is_some(),
            "sha256",
            "required for a community package",
        )?;
        ensure(
            src.page.is_some(),
            "source.page",
            "required for a community package",
        )?;
        ensure(
            src.release.is_none() && p.assets.is_none(),
            "source",
            "a community package has no direct download (no release, no assets)",
        )?;
    } else {
        let one = p.sha256.is_some() && src.release.is_some() && p.assets.is_none();
        let per_arch = p.assets.is_some() && p.sha256.is_none() && src.release.is_none();
        ensure(
            one || per_arch,
            "source",
            "exactly one download form: source.release + sha256, or assets",
        )?;
    }
    provenance(p)?;
    if let Some(a) = &p.apis {
        ensure(
            !a.is_empty() && unique(a.iter()),
            "apis",
            "at least one, unique",
        )?;
    }
    ensure(
        unique(p.slots.iter().map(|s| fold(s))),
        "slots",
        "unique items",
    )?;
    for (i, s) in p.slots.iter().enumerate() {
        ensure(dll_name(s), &format!("slots[{i}]"), "a DLL file name")?;
    }
    if let Some(m) = &p.slots_by_api {
        for (api, slots) in m {
            let at = format!(
                "slots_by_api.{}",
                serde_json::to_string(api).unwrap_or_default()
            );
            ensure(
                !slots.is_empty() && unique(slots.iter().map(|s| fold(s))),
                &at,
                "at least one, unique",
            )?;
            ensure(slots.iter().all(|s| dll_name(s)), &at, "DLL file names")?;
        }
    }
    ensure(unique(p.requires.iter()), "requires", "unique items")?;
    ensure(
        unique(p.requires_gpu.iter().map(|g| *g as u8)),
        "requires_gpu",
        "unique items",
    )?;
    ensure(
        unique(p.supports_exe_sha1.iter()),
        "supports_exe_sha1",
        "unique items",
    )?;
    ensure(
        p.supports_exe_sha1.iter().all(|h| !h.is_todo()),
        "supports_exe_sha1",
        "known hashes only (no TODO)",
    )?;
    for (i, f) in p.files.iter().enumerate() {
        let at = format!("files[{i}]");
        if let Some(a) = &f.arch {
            ensure(
                !a.is_empty() && unique(a.iter()),
                &format!("{at}.arch"),
                "at least one, unique",
            )?;
        }
        if let Some(a) = &f.api {
            ensure(
                !a.is_empty() && unique(a.iter()),
                &format!("{at}.api"),
                "at least one, unique",
            )?;
        }
        if let (Some(a), ArchList::List(of_package)) = (&f.arch, &p.arch) {
            ensure(
                a.iter().all(|x| of_package.contains(x)),
                &format!("{at}.arch"),
                "only architectures of the package's arch",
            )?;
        }
        if let (Some(a), Some(assets)) = (&f.arch, &p.assets) {
            ensure(
                a.iter().all(|x| assets.iter().any(|s| s.arch == *x)),
                &format!("{at}.arch"),
                "an architecture without an asset",
            )?;
        }
    }
    files_placed_once(p)?;
    // By position until the name is checked: an error never carries an unchecked map key.
    for (i, (name, o)) in p.options.iter().enumerate() {
        let ok = !name.is_empty()
            && name
                .bytes()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_');
        ensure(
            ok,
            &format!("options[{i}]"),
            "an option name of a-z, 0-9 and _",
        )?;
        option(o, &format!("options.{name}"))?;
    }
    status_rule(p, p.status, rules)
}

/// One place below the version folder holds one file (ADR 0025 part 2): with one download a
/// file's place is its `from`; with `assets` it is `<arch>\<from>` for each architecture the
/// file is for (its `arch`, or every asset's). Two entries of one place must pin the same
/// SHA-256 (a `TODO` counts as its own value).
fn files_placed_once(p: &Package) -> R {
    let archs = |f: &super::model::PackageFile| -> Vec<Option<super::model::Arch>> {
        match (&p.assets, &f.arch) {
            (None, _) => vec![None],
            (Some(_), Some(a)) => a.iter().copied().map(Some).collect(),
            (Some(assets), None) => assets.iter().map(|a| Some(a.arch)).collect(),
        }
    };
    let mut placed: Vec<(Option<super::model::Arch>, String, &super::model::Sha256)> = Vec::new();
    for (i, f) in p.files.iter().enumerate() {
        for a in archs(f) {
            let key = fold(f.from.as_str());
            if let Some((_, _, sha)) = placed.iter().find(|(x, k, _)| *x == a && *k == key) {
                ensure(
                    *sha == &f.sha256,
                    &format!("files[{i}].from"),
                    "a file of the package twice with another sha256",
                )?;
            } else {
                placed.push((a, key, &f.sha256));
            }
        }
    }
    Ok(())
}

fn option(o: &PackageOption, at: &str) -> R {
    let name = |s: &str| {
        !s.is_empty()
            && s.len() <= 128
            && s.bytes()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'.' | b' ' | b'-'))
    };
    ensure(
        name(&o.ini.section),
        &format!("{at}.ini.section"),
        "A-Z a-z 0-9 _ . space -",
    )?;
    ensure(
        name(&o.ini.key),
        &format!("{at}.ini.key"),
        "A-Z a-z 0-9 _ . space -",
    )?;
    if let super::model::OptionValue::Text(s) = &o.default {
        let b = s.as_bytes();
        let drive = b.len() >= 2 && b[0].is_ascii_alphabetic() && b[1] == b':';
        let ok = s.chars().count() <= 256
            && !s.chars().any(deceptive)
            && !drive
            && !s.starts_with(['\\', '/'])
            && !s.contains("..");
        ensure(
            ok,
            &format!("{at}.default"),
            "no control characters, absolute paths or ..",
        )?;
    }
    Ok(())
}

/// docs/02 "Provenance": a download belongs to the releases of `source.repo` or to the host of
/// `source.page` ([`belongs`]).
fn provenance(p: &Package) -> R {
    let mut urls: Vec<&str> = p.source.release.iter().map(String::as_str).collect();
    urls.extend(p.assets.iter().flatten().map(|a| a.url.as_str()));
    for u in urls.into_iter().filter(|u| *u != TODO) {
        ensure(
            belongs(u, p.source.repo.as_deref(), p.source.page.as_deref()),
            "source",
            "a download is not from the original source (releases of source.repo or the host of source.page)",
        )?;
    }
    Ok(())
}

/// The IDs of the packages a Topo names in its steps.
pub fn package_refs(t: &Topo) -> impl Iterator<Item = &Id> {
    t.issues
        .iter()
        .flat_map(|i| &i.variants)
        .flat_map(|v| &v.steps)
        .filter_map(|s| match s {
            TopoStep::Package(id) => Some(id),
            _ => None,
        })
}

/// Two Topos claim the same build: the same `match.steam_appid` and a hash in common (a SHA-256
/// or a SHA-1 of any of their executables, `TODO` never counts).
pub fn overlap(a: &Topo, b: &Topo) -> bool {
    if a.matches.steam_appid != b.matches.steam_appid {
        return false;
    }
    let hashes = |t: &Topo| -> Vec<Vec<u8>> {
        t.matches
            .exes
            .iter()
            .flat_map(|e| {
                let s256 = e
                    .sha256
                    .as_ref()
                    .and_then(|h| h.bytes())
                    .map(|b| b.to_vec());
                let s1 = e.sha1.as_ref().and_then(|h| h.bytes()).map(|b| b.to_vec());
                [s256, s1]
            })
            .flatten()
            .collect()
    };
    let hb = hashes(b);
    hashes(a).iter().any(|h| hb.contains(h))
}
