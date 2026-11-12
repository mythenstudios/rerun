//! Known or set aside (ADR 0024 amendment "Forward compatibility" §1 to §3): the verified bytes
//! of an index into its known entries and the ones this build sets aside.
//!
//! The envelope stays strict: `format` is read alone first ([`super::INDEX_FORMAT`] or the
//! whole index is refused as "needs newer"), then the envelope with `deny_unknown_fields`, each
//! entry kept as its raw text. Each entry's frozen head (`format`, `id`, for a Topo
//! `match.steam_appid`) is read leniently; a head that does not parse, or IDs not sorted and
//! unique over all heads, refuse the whole index. Then per entry, in order:
//!
//! 1. `format` above [`ENTRY_FORMAT`]: [`AsideWhy::Newer`], nothing more is parsed;
//! 2. the strict types (`deny_unknown_fields` at every level): [`AsideWhy::Unreadable`];
//! 3. the rules of `check` with [`Rules::Release`], the floor rule included:
//!    [`AsideWhy::Refused`];
//! 4. the cross-entry rules over what passed: packages on a set-aside package (repeated until
//!    nothing changes), Topos on a set-aside or missing package, `supports_exe_sha1`, the
//!    graphics API rule, and last the overlap of two Topos still known (both refused).
//!
//! A set-aside entry is kept for display only; nothing is ever planned, downloaded or derived
//! from it.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::marker::PhantomData;
use std::num::NonZeroU32;

use serde::de::{Deserializer, MapAccess, Visitor, value::MapAccessDeserializer};
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;

use super::check::{self, RuleError, Rules};
use super::model::{self, ENTRY_FORMAT, Id, Index, Package, Topo, TopoStep};
use super::{INDEX_FORMAT, IndexError, MAX_INDEX_BYTES, issued_ok, parse_class};

/// Which list an entry is in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum EntryKind {
    /// `topos`.
    Topo,
    /// `packages`.
    Package,
}

impl fmt::Display for EntryKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Topo => "topo",
            Self::Package => "package",
        })
    }
}

/// An entry this build does not use, with why (display only).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Aside {
    /// Its list.
    pub kind: EntryKind,
    /// Its ID (from the head).
    pub id: Id,
    /// Its entry format (from the head).
    pub format: u32,
    /// The Steam app ID of a Topo's head (never for a package).
    pub steam_appid: Option<u32>,
    /// Why.
    pub why: AsideWhy,
}

impl fmt::Display for Aside {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}: {}", self.kind, self.id, self.why)
    }
}

/// Why an entry is set aside.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AsideWhy {
    /// Its `format` is above [`ENTRY_FORMAT`].
    Newer {
        /// The entry's format.
        format: u32,
    },
    /// A known format that does not parse (the position within the entry, never its text).
    Unreadable {
        /// `syntax`, `data`, `eof`.
        class: &'static str,
        /// 1-based line within the entry.
        line: usize,
        /// 1-based column.
        column: usize,
    },
    /// A known format that breaks a rule of this build.
    Refused(RuleError),
    /// It names a package that is set aside.
    Package {
        /// The package.
        id: Id,
        /// That package needs a newer Rerun.
        newer: bool,
    },
}

impl AsideWhy {
    /// A newer Rerun can use the entry: [`Self::Newer`], or a set-aside package that needs one.
    pub fn needs_newer(&self) -> bool {
        match self {
            Self::Newer { .. } => true,
            Self::Package { newer, .. } => *newer,
            Self::Unreadable { .. } | Self::Refused(_) => false,
        }
    }
}

impl fmt::Display for AsideWhy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Newer { format } => write!(
                f,
                "entry format {format} needs a newer version of Rerun (this build reads up to {ENTRY_FORMAT})"
            ),
            Self::Unreadable {
                class,
                line,
                column,
            } => write!(
                f,
                "not readable by this build ({class} at line {line}, column {column} of the entry)"
            ),
            Self::Refused(e) => write!(f, "breaks a rule of this build: {e}"),
            Self::Package { id, newer: true } => {
                write!(
                    f,
                    "names package {id}, which needs a newer version of Rerun"
                )
            }
            Self::Package { id, newer: false } => {
                write!(f, "names package {id}, which this build cannot use")
            }
        }
    }
}

/// Deserialises `T` from a JSON object only (a struct derive alone also takes an array).
struct ObjectOnly<T>(T);

impl<'de, T: Deserialize<'de>> Deserialize<'de> for ObjectOnly<T> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V<T>(PhantomData<T>);
        impl<'de, T: Deserialize<'de>> Visitor<'de> for V<T> {
            type Value = T;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("an object")
            }
            fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<T, A::Error> {
                T::deserialize(MapAccessDeserializer::new(map))
            }
        }
        d.deserialize_map(V(PhantomData)).map(ObjectOnly)
    }
}

/// A present key holds a value (`null` refused), as in the model.
fn present<'de, D: Deserializer<'de>, T: Deserialize<'de>>(d: D) -> Result<Option<T>, D::Error> {
    T::deserialize(d).map(Some)
}

/// The `format` field alone, read before the rest.
#[derive(Deserialize)]
struct FormatOnly {
    format: u32,
}

/// The envelope: strict, entries raw.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope<'a> {
    format: u32,
    seq: u64,
    issued: String,
    #[serde(borrow)]
    topos: Vec<&'a RawValue>,
    #[serde(borrow)]
    packages: Vec<&'a RawValue>,
}

/// The frozen head of a Topo: lenient (every other key ignored), authorises nothing.
#[derive(Deserialize)]
struct TopoHead {
    format: u32,
    id: Id,
    #[serde(rename = "match", default, deserialize_with = "present")]
    matches: Option<ObjectOnly<TopoHeadMatch>>,
}

/// `match` of a Topo head: only `steam_appid` (1 to 4294967295; `0` refuses the index).
#[derive(Deserialize)]
struct TopoHeadMatch {
    #[serde(default, deserialize_with = "present")]
    steam_appid: Option<NonZeroU32>,
}

/// The frozen head of a package: no `match`.
#[derive(Deserialize)]
struct PackageHead {
    format: u32,
    id: Id,
}

/// One entry's head, whatever its list.
struct Head {
    format: u32,
    id: Id,
    steam_appid: Option<u32>,
}

/// The known entries of an index and the ones set aside.
pub(crate) struct Classified {
    /// The envelope with the known entries only.
    pub index: Index,
    /// Sorted by kind, then ID.
    pub aside: Vec<Aside>,
}

fn head_error(list: &'static str, pos: usize, e: &serde_json::Error) -> IndexError {
    IndexError::Head {
        list,
        pos,
        class: parse_class(e),
        line: e.line(),
        column: e.column(),
    }
}

fn topo_head(raw: &RawValue, pos: usize) -> Result<Head, IndexError> {
    let ObjectOnly(h) = serde_json::from_str::<ObjectOnly<TopoHead>>(raw.get())
        .map_err(|e| head_error("topos", pos, &e))?;
    Ok(Head {
        format: h.format,
        id: h.id,
        steam_appid: h
            .matches
            .and_then(|ObjectOnly(m)| m.steam_appid)
            .map(NonZeroU32::get),
    })
}

fn package_head(raw: &RawValue, pos: usize) -> Result<Head, IndexError> {
    let ObjectOnly(h) = serde_json::from_str::<ObjectOnly<PackageHead>>(raw.get())
        .map_err(|e| head_error("packages", pos, &e))?;
    Ok(Head {
        format: h.format,
        id: h.id,
        steam_appid: None,
    })
}

fn sorted(heads: &[Head], what: &str) -> Result<(), IndexError> {
    if heads.windows(2).all(|w| w[0].id < w[1].id) {
        Ok(())
    } else {
        Err(IndexError::Rule(format!(
            "{what} are not sorted by ID without duplicates"
        )))
    }
}

/// Stages 1 to 3 of one entry: the strict type and its own rules, or why it is set aside.
fn entry<'a, T: Deserialize<'a>>(
    raw: &'a RawValue,
    head: &Head,
    rules: impl Fn(&T) -> Result<(), RuleError>,
) -> Result<T, AsideWhy> {
    if head.format > ENTRY_FORMAT {
        return Err(AsideWhy::Newer {
            format: head.format,
        });
    }
    let t: T = serde_json::from_str(raw.get()).map_err(|e| AsideWhy::Unreadable {
        class: parse_class(&e),
        line: e.line(),
        column: e.column(),
    })?;
    rules(&t).map_err(AsideWhy::Refused)?;
    Ok(t)
}

fn rule(at: impl Into<String>, what: impl Into<String>) -> AsideWhy {
    AsideWhy::Refused(RuleError {
        at: at.into(),
        what: what.into(),
    })
}

fn set_aside(aside: &mut Vec<Aside>, kind: EntryKind, h: &Head, why: AsideWhy) {
    aside.push(Aside {
        kind,
        id: h.id.clone(),
        format: h.format,
        steam_appid: h.steam_appid,
        why,
    });
}

/// The bytes of an index (already verified, or the workbench's own) into known and set aside.
pub(crate) fn classify(bytes: &[u8]) -> Result<Classified, IndexError> {
    let ObjectOnly(f) =
        serde_json::from_slice::<ObjectOnly<FormatOnly>>(bytes).map_err(|e| parse_error(&e))?;
    if f.format != INDEX_FORMAT {
        return Err(IndexError::Format(f.format));
    }
    let ObjectOnly(env) =
        serde_json::from_slice::<ObjectOnly<Envelope<'_>>>(bytes).map_err(|e| parse_error(&e))?;
    if env.seq == 0 {
        return Err(IndexError::Rule("seq starts at 1".into()));
    }
    if !issued_ok(&env.issued) {
        return Err(IndexError::Rule(
            "issued is not YYYY-MM-DDTHH:MM:SSZ".into(),
        ));
    }
    let topo_heads = env
        .topos
        .iter()
        .enumerate()
        .map(|(i, r)| topo_head(r, i))
        .collect::<Result<Vec<_>, _>>()?;
    let package_heads = env
        .packages
        .iter()
        .enumerate()
        .map(|(i, r)| package_head(r, i))
        .collect::<Result<Vec<_>, _>>()?;
    sorted(&topo_heads, "topos")?;
    sorted(&package_heads, "packages")?;

    let mut aside: Vec<Aside> = Vec::new();

    // Stages 1 to 3, per entry.
    let mut packages: Vec<(Package, &Head)> = Vec::new();
    for (raw, h) in env.packages.iter().zip(&package_heads) {
        match entry::<Package>(raw, h, |p| check::package(p, Rules::Release)) {
            Ok(p) => packages.push((p, h)),
            Err(why) => set_aside(&mut aside, EntryKind::Package, h, why),
        }
    }
    let mut topos: Vec<(Topo, &Head)> = Vec::new();
    for (raw, h) in env.topos.iter().zip(&topo_heads) {
        match entry::<Topo>(raw, h, |t| check::topo(t, Rules::Release)) {
            Ok(t) => topos.push((t, h)),
            Err(why) => set_aside(&mut aside, EntryKind::Topo, h, why),
        }
    }

    // 4.1 Packages on a set-aside or missing package, until a pass sets nothing aside: each
    // pass removes at least one package or ends the loop.
    let held: BTreeSet<&Id> = package_heads.iter().map(|h| &h.id).collect();
    let mut package_aside: BTreeMap<Id, bool> = aside
        .iter()
        .filter(|a| a.kind == EntryKind::Package)
        .map(|a| (a.id.clone(), a.why.needs_newer()))
        .collect();
    loop {
        let mut changed = false;
        let mut i = 0;
        while i < packages.len() {
            let p = &packages[i].0;
            let why = p.requires.iter().enumerate().find_map(|(k, r)| {
                if let Some(newer) = package_aside.get(r) {
                    Some(AsideWhy::Package {
                        id: r.clone(),
                        newer: *newer,
                    })
                } else if !held.contains(r) {
                    Some(rule(
                        format!("requires[{k}]"),
                        format!("requires {r}, which is not in the index"),
                    ))
                } else {
                    None
                }
            });
            if let Some(why) = why {
                let (p, h) = packages.remove(i);
                package_aside.insert(p.id, why.needs_newer());
                set_aside(&mut aside, EntryKind::Package, h, why);
                changed = true;
            } else {
                i += 1;
            }
        }
        if !changed {
            break;
        }
    }
    let known_packages: BTreeMap<&str, &Package> =
        packages.iter().map(|(p, _)| (p.id.as_str(), p)).collect();

    // 4.2 Topos and their packages.
    let mut kept: Vec<(Topo, &Head)> = Vec::new();
    for (t, h) in topos {
        match topo_packages(&t, &known_packages, &package_aside, &held) {
            Ok(()) => kept.push((t, h)),
            Err(why) => set_aside(&mut aside, EntryKind::Topo, h, why),
        }
    }

    // 4.3 Overlap, last, over the Topos still known: both of a pair are refused.
    let live: Vec<usize> = (0..kept.len())
        .filter(|i| kept[*i].0.status != model::Status::Retired)
        .collect();
    let mut overlaps: BTreeMap<usize, &Id> = BTreeMap::new();
    for (n, &a) in live.iter().enumerate() {
        for &b in &live[..n] {
            if check::overlap(&kept[a].0, &kept[b].0) {
                overlaps.entry(a).or_insert(&kept[b].0.id);
                overlaps.entry(b).or_insert(&kept[a].0.id);
            }
        }
    }
    let overlaps: BTreeMap<usize, Id> = overlaps.into_iter().map(|(k, v)| (k, v.clone())).collect();
    let mut known_topos = Vec::with_capacity(kept.len());
    for (i, (t, h)) in kept.into_iter().enumerate() {
        if let Some(other) = overlaps.get(&i) {
            let why = rule(
                "match",
                format!("claims the same app and executable hash as topo {other}"),
            );
            set_aside(&mut aside, EntryKind::Topo, h, why);
        } else {
            known_topos.push(t);
        }
    }

    aside.sort_by(|a, b| (a.kind, &a.id).cmp(&(b.kind, &b.id)));
    Ok(Classified {
        index: Index {
            format: env.format,
            seq: env.seq,
            issued: env.issued,
            topos: known_topos,
            packages: packages.into_iter().map(|(p, _)| p).collect(),
        },
        aside,
    })
}

/// 4.2 for one Topo: a set-aside package ([`AsideWhy::Package`]), a missing one, the
/// `supports_exe_sha1` rule (P4-8) and the graphics API rule (P5-5c review).
fn topo_packages(
    t: &Topo,
    known: &BTreeMap<&str, &Package>,
    package_aside: &BTreeMap<Id, bool>,
    held: &BTreeSet<&Id>,
) -> Result<(), AsideWhy> {
    for (i, issue) in t.issues.iter().enumerate() {
        for (j, v) in issue.variants.iter().enumerate() {
            for (k, s) in v.steps.iter().enumerate() {
                let TopoStep::Package(id) = s else { continue };
                if let Some(newer) = package_aside.get(id) {
                    return Err(AsideWhy::Package {
                        id: id.clone(),
                        newer: *newer,
                    });
                }
                if !held.contains(id) {
                    return Err(rule(
                        format!("issues[{i}].variants[{j}].steps[{k}].package"),
                        format!("package {id} is not in the index"),
                    ));
                }
            }
        }
    }
    // P4-8 (ADR 0025 open point): a package that names the builds it supports
    // (`supports_exe_sha1`) supports every build a Topo that installs it names by SHA-1; the
    // engine checks the matched build itself as well (an entry may name only a SHA-256).
    for id in check::package_refs(t) {
        let Some(p) = known.get(id.as_str()) else {
            continue;
        };
        if p.supports_exe_sha1.is_empty() {
            continue;
        }
        if let Some((n, e)) = t.matches.exes.iter().enumerate().find(|(_, e)| {
            e.sha1
                .as_ref()
                .is_some_and(|h| !p.supports_exe_sha1.contains(h))
        }) {
            return Err(rule(
                format!("match.exes[{n}].sha1"),
                format!(
                    "package {id} does not list the SHA-1 of {} in supports_exe_sha1",
                    e.path
                ),
            ));
        }
    }
    // P5-5c review: until the game options of ADR 0032 name the executable the game runs, a
    // variant that installs a package whose files depend on the graphics API (or one it
    // requires) is refused for a Topo whose executables name more than one API. The engine would
    // refuse its plan (`EngineError::PackageApiOpen`, which stays its guard), and the app would
    // offer a download for a fix it cannot apply.
    let mut apis = t.matches.exes.iter().map(|e| e.api);
    let first = apis.next();
    if !first.is_some_and(|f| apis.any(|a| a != f)) {
        return Ok(());
    }
    for (i, issue) in t.issues.iter().enumerate() {
        for (j, v) in issue.variants.iter().enumerate() {
            for s in &v.steps {
                let TopoStep::Package(id) = s else { continue };
                if let Some(p) = with_requires(known, id)
                    .into_iter()
                    .find(|p| p.depends_on_api())
                {
                    return Err(rule(
                        format!("issues[{i}].variants[{j}]"),
                        format!(
                            "variant {} installs package {}, whose files depend on the graphics \
                             API, but its match.exes name more than one api (the game options of \
                             ADR 0032 are not there yet)",
                            v.id, p.id
                        ),
                    ));
                }
            }
        }
    }
    Ok(())
}

/// The package `id` and every package it requires, transitively (each once; all known after
/// 4.1).
fn with_requires<'p>(known: &BTreeMap<&str, &'p Package>, id: &Id) -> Vec<&'p Package> {
    let mut out: Vec<&Package> = Vec::new();
    let mut todo = vec![id];
    while let Some(next) = todo.pop() {
        let Some(p) = known.get(next.as_str()).copied() else {
            continue;
        };
        if out.iter().any(|q| q.id == p.id) {
            continue;
        }
        out.push(p);
        todo.extend(p.requires.iter());
    }
    out
}

fn parse_error(e: &serde_json::Error) -> IndexError {
    IndexError::Parse {
        class: parse_class(e),
        line: e.line(),
        column: e.column(),
    }
}

/// The client's classification without a signature, for the workbench (ADR 0024 amendment §6):
/// the envelope, the heads and the rules of every entry; only the set-aside list, never a
/// catalogue anything could be planned from.
pub fn check_bundle(bytes: &[u8]) -> Result<Vec<Aside>, IndexError> {
    if bytes.len() > MAX_INDEX_BYTES {
        return Err(IndexError::TooLarge {
            limit: MAX_INDEX_BYTES,
        });
    }
    classify(bytes).map(|c| c.aside)
}
