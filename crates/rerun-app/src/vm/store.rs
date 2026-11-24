//! Settings > Packages and its removal dialog (P5-8b-3, ADR 0027 amendment P5-8b-3). Rule 5: the
//! dialog lists every package that goes and, in an expander, every file; what stays has its
//! reason. The words are the app's, the values are `flow`'s ([`flow::package_store`],
//! [`flow::remove_preview`]); nothing here reads or writes the system.

use rerun_core::escape::{self, Shown};
use rerun_core::flow::{
    PackageKeep, RemovePreview, StoreGate, StoreView, StoredPackage, StoredState,
};
use rerun_core::pkg::store::{Removed, StoreKeep};

use super::clear::state_word;
use super::history::game_value;
use super::write::{DialogKind, DialogVm, ListVm, ResultVm, Tone, result, with_detail};
use super::{Badge, DetailVm, Names, shown_error};
use crate::text::{Lang, Msg, Sym, t};

fn tx(lang: Lang, m: Msg) -> String {
    t(lang, m).into_owned()
}

/// One package of the settings page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreRowVm {
    /// The package ID, as the store lists it (the removal asks for it by this).
    pub id: String,
    /// The version.
    pub version: String,
    /// The name in the index, or the ID.
    pub title: Shown<'static>,
    /// `<id> <version>`.
    pub ident: Shown<'static>,
    /// "Not in the index: it can't be downloaded again", for a package the index no longer lists.
    pub note: Option<String>,
    /// Whether its files are there (symbol and word).
    pub state: Badge,
    /// Size, files and archives.
    pub facts: String,
    /// "Used by <game> . No. 12 . Applied" per change that uses it, or "Not used".
    pub used: Vec<String>,
    /// Why it stays (`None`: it can be removed).
    pub keep: Option<String>,
    /// The row's button works (nothing keeps the package).
    pub can_remove: bool,
}

/// The settings page's packages group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreVm {
    /// The packages, by ID and version.
    pub rows: Vec<StoreRowVm>,
    /// Downloads without a package, and leftovers, one line each.
    pub extra: Vec<String>,
    /// The heading of the entries Rerun never touches (empty when there are none).
    pub foreign_heading: Option<String>,
    /// Those entries, `<path>: <reason>` (escaped by the core).
    pub foreign: Vec<String>,
    /// Nothing in the store, or the store cannot be shown: the first sentence.
    pub empty_title: Option<String>,
    /// The second sentence.
    pub empty_sub: Option<String>,
    /// The core's text for a store that cannot be read.
    pub detail: Option<Shown<'static>>,
    /// The button that removes every unused package; absent when there is no store.
    pub remove_all: Option<String>,
    /// The button works: something can go.
    pub can_remove_all: bool,
    /// The button of a row.
    pub remove: String,
}

/// Why an entry of the store stays.
fn store_keep(k: StoreKeep) -> Msg {
    match k {
        StoreKeep::Reparse => Msg::PkKeepReparse,
        StoreKeep::Linked => Msg::PkKeepLinked,
        StoreKeep::Attributes => Msg::PkKeepAttributes,
        StoreKeep::TooMany => Msg::PkKeepTooMany,
        StoreKeep::BadName => Msg::PkKeepBadName,
        StoreKeep::Busy => Msg::PkKeepBusy,
        StoreKeep::Changed => Msg::PkKeepChanged,
        StoreKeep::Unsupported => Msg::PkKeepUnsupported,
        // A reason a later version adds.
        _ => Msg::PkKeepOther,
    }
}

/// Why a package stays, in one sentence.
fn keep_text(k: &PackageKeep, lang: Lang) -> String {
    match k {
        PackageKeep::InUse => tx(lang, Msg::PkKeepInUse),
        PackageKeep::UnknownUse(ts) => tx(lang, Msg::PkKeepUnknownUse { n: ts.len() }),
        PackageKeep::Store(s) => tx(lang, store_keep(*s)),
        PackageKeep::SharedArchive => tx(lang, Msg::PkKeepShared),
    }
}

/// A change that uses a package: "Used by <game> . No. 12 . Applied".
fn used_line(u: &rerun_core::flow::UsedBy, names: &Names, lang: Lang) -> String {
    let mut parts = Vec::new();
    if let Some(a) = u.app {
        parts.push(game_value(a, names, lang).as_str().to_owned());
    }
    parts.push(tx(lang, Msg::ClearNumber { n: u.txn.seq() }));
    parts.push(tx(lang, state_word(&u.line, false)));
    format!("{} {}", tx(lang, Msg::PkUsedBy), parts.join(" \u{b7} "))
}

fn title_of(p: &StoredPackage) -> Shown<'static> {
    escape::text(p.name.as_deref().unwrap_or(&p.id)).into_owned()
}

fn ident_of(p: &StoredPackage) -> Shown<'static> {
    escape::text(&format!("{} {}", p.id, p.version)).into_owned()
}

fn state_badge(s: StoredState, lang: Lang) -> Badge {
    match s {
        StoredState::Unpacked => Badge::new(Sym::None, lang, Msg::PkStateUnpacked, false),
        StoredState::Incomplete => Badge::new(Sym::Attention, lang, Msg::PkStateIncomplete, true),
        StoredState::ArchiveOnly => {
            Badge::new(Sym::Unconfirmed, lang, Msg::PkStateArchiveOnly, true)
        }
    }
}

fn facts_of(p: &StoredPackage, lang: Lang) -> String {
    tx(
        lang,
        Msg::PkFacts {
            bytes: p.bytes,
            files: p.files,
            archives: p.archives.len(),
        },
    )
}

fn row(p: &StoredPackage, names: &Names, lang: Lang) -> StoreRowVm {
    StoreRowVm {
        id: p.id.clone(),
        version: p.version.clone(),
        title: title_of(p),
        ident: ident_of(p),
        note: (!p.in_index).then(|| tx(lang, Msg::PkNotInIndex)),
        state: state_badge(p.state, lang),
        facts: facts_of(p, lang),
        used: if p.used_by.is_empty() {
            vec![tx(lang, Msg::PkNotUsed)]
        } else {
            p.used_by
                .iter()
                .map(|u| used_line(u, names, lang))
                .collect()
        },
        keep: p.keep.as_ref().map(|k| keep_text(k, lang)),
        can_remove: p.keep.is_none(),
    }
}

/// The packages group for the store the worker read.
pub fn store(v: &StoreView, names: &Names, lang: Lang) -> StoreVm {
    let rows: Vec<StoreRowVm> = v.packages.iter().map(|p| row(p, names, lang)).collect();
    let mut extra = Vec::new();
    if !v.loose_archives.is_empty() {
        extra.push(tx(
            lang,
            Msg::PkLoose {
                n: v.loose_archives.len(),
                bytes: v.loose_archives.iter().map(|(_, b)| *b).sum(),
            },
        ));
    }
    if v.leftovers.0 > 0 {
        extra.push(tx(
            lang,
            Msg::PkLeftovers {
                n: v.leftovers.0,
                bytes: v.leftovers.1,
            },
        ));
    }
    let empty = rows.is_empty() && extra.is_empty() && v.foreign.is_empty();
    let can_remove_all = v.packages.iter().any(|p| p.keep.is_none())
        || !v.loose_archives.is_empty()
        || v.leftovers.0 > 0;
    StoreVm {
        remove_all: (!empty).then(|| tx(lang, Msg::PkRemoveAllBtn)),
        can_remove_all,
        rows,
        extra,
        foreign_heading: (!v.foreign.is_empty())
            .then(|| tx(lang, Msg::PkForeignHeading { n: v.foreign.len() })),
        foreign: v
            .foreign
            .iter()
            .map(|(path, k)| format!("{path}: {}", tx(lang, store_keep(*k))))
            .collect(),
        empty_title: empty.then(|| tx(lang, Msg::PkEmpty)),
        empty_sub: None,
        detail: None,
        remove: tx(lang, Msg::PkRemoveBtn),
    }
}

/// The packages group when the store cannot be shown: no store (the calm empty line) or a
/// store or journal that cannot be read (what it means, and the core's words under it).
pub fn store_unavailable(g: &StoreGate, lang: Lang) -> StoreVm {
    let (title, sub, detail) = match g {
        StoreGate::NoAppDir | StoreGate::NotFound => (tx(lang, Msg::PkEmpty), None, None),
        StoreGate::Journal(e) => (
            tx(lang, Msg::PkUnreadableTitle),
            Some(tx(lang, Msg::PkUnreadableBody)),
            Some(shown_error(e)),
        ),
        StoreGate::Store(e) => (
            tx(lang, Msg::PkUnreadableTitle),
            Some(tx(lang, Msg::PkUnreadableBody)),
            Some(shown_error(e)),
        ),
    };
    StoreVm {
        rows: Vec::new(),
        extra: Vec::new(),
        foreign_heading: None,
        foreign: Vec::new(),
        empty_title: Some(title),
        empty_sub: sub,
        detail,
        remove_all: None,
        can_remove_all: false,
        remove: tx(lang, Msg::PkRemoveBtn),
    }
}

/// One package as a line of a dialog list: name, ID and version, size, and that it cannot be
/// downloaded again.
fn package_line(p: &StoredPackage, lang: Lang) -> String {
    let mut line = format!(
        "{} \u{b7} {} \u{b7} {}",
        title_of(p).as_str(),
        ident_of(p).as_str(),
        facts_of(p, lang)
    );
    if !p.in_index {
        line.push_str(". ");
        line.push_str(&tx(lang, Msg::PkNotInIndex));
    }
    line
}

/// The files of a package (and its archives), as paths below Rerun's folder.
fn file_lines(p: &StoredPackage) -> Vec<String> {
    let dir = escape::text(&format!("{}\\{}", p.id, p.version)).into_owned();
    p.paths
        .iter()
        .map(|f| format!("packages\\{}\\{f}", dir.as_str()))
        .chain(
            p.archives
                .iter()
                .map(|a| format!("cache\\{}", escape::text(a).as_str())),
        )
        .collect()
}

/// The removal dialog for a preview (rule 5): every package that goes with its files behind an
/// expander, downloads without a package, leftovers, what stays with its reason, and that game
/// folders, registry and firewall are not touched. Nothing to remove: it says so and has no
/// confirm. `changed`: the store or the use of a package changed since the dialog the user looked
/// at.
pub fn store_dialog(
    p: &RemovePreview,
    names: &Names,
    changed: bool,
    nonce: u64,
    lang: Lang,
) -> DialogVm {
    let nothing = p.remove.is_empty() && p.loose_archives.is_empty() && p.leftovers.0 == 0;
    let mut lists = Vec::new();
    if !p.remove.is_empty() {
        lists.push(ListVm {
            heading: tx(lang, Msg::PkDlgGoesHeading { n: p.remove.len() }),
            lines: p.remove.iter().map(|x| package_line(x, lang)).collect(),
            fold: None,
        });
        // The files of each package behind a button: collapsed, but every one is listed.
        for x in &p.remove {
            let files = file_lines(x);
            if files.is_empty() {
                continue;
            }
            lists.push(ListVm {
                heading: format!("{} {}", title_of(x).as_str(), x.version),
                fold: Some((
                    tx(lang, Msg::PkDlgFilesShow { n: files.len() }),
                    tx(lang, Msg::PkDlgFilesHide),
                )),
                lines: files,
            });
        }
    }
    if !p.loose_archives.is_empty() {
        lists.push(ListVm {
            heading: tx(
                lang,
                Msg::PkDlgLooseHeading {
                    n: p.loose_archives.len(),
                },
            ),
            lines: p
                .loose_archives
                .iter()
                .map(|(name, _)| format!("cache\\{}", escape::text(name).as_str()))
                .collect(),
            fold: None,
        });
    }
    if !p.stays.is_empty() {
        let mut lines = Vec::new();
        for x in &p.stays {
            let why = x
                .keep
                .as_ref()
                .map(|k| keep_text(k, lang))
                .unwrap_or_default();
            lines.push(format!(
                "{} \u{b7} {}. {why}",
                title_of(x).as_str(),
                ident_of(x).as_str()
            ));
            lines.extend(
                x.used_by
                    .iter()
                    .map(|u| format!("    {}", used_line(u, names, lang))),
            );
        }
        lists.push(ListVm {
            heading: tx(lang, Msg::ClearStaysHeading { n: p.stays.len() }),
            lines,
            fold: None,
        });
    }
    let mut notes = Vec::new();
    if p.leftovers.0 > 0 {
        notes.push(tx(
            lang,
            Msg::PkDlgLeftovers {
                n: p.leftovers.0,
                bytes: p.leftovers.1,
            },
        ));
    }
    if !nothing {
        notes.push(tx(lang, Msg::PkDlgFreed { bytes: p.bytes }));
    }
    notes.push(tx(lang, Msg::PkDlgUnchanged));
    DialogVm {
        kind: DialogKind::Packages,
        nonce,
        txn: None,
        title: tx(lang, Msg::PkDlgTitle),
        intro: tx(
            lang,
            if nothing {
                Msg::PkDlgNothing
            } else {
                Msg::PkDlgIntro
            },
        ),
        changed: changed.then(|| tx(lang, Msg::PkDlgChanged)),
        ops: Vec::new(),
        notes,
        details: Vec::new(),
        launch: None,
        confirm: tx(lang, Msg::PkDlgTitle),
        can_confirm: !nothing,
        blocked: None,
        secondary: None,
        lists,
    }
}

/// Why the removal dialog is not shown.
pub fn store_gate(g: &StoreGate, lang: Lang) -> ResultVm {
    match g {
        StoreGate::NoAppDir => result(
            Tone::Calm,
            lang,
            Msg::RefNothingTitle,
            Msg::RefNothingBody,
            false,
        ),
        StoreGate::NotFound => result(Tone::Calm, lang, Msg::PkGoneTitle, Msg::PkGoneBody, false),
        StoreGate::Journal(e) => with_detail(unexpected(lang), shown_error(e)),
        StoreGate::Store(e) => with_detail(unexpected(lang), shown_error(e)),
    }
}

fn unexpected(lang: Lang) -> ResultVm {
    result(
        Tone::Attention,
        lang,
        Msg::RefUnexpectedTitle,
        Msg::RefUnexpectedBody,
        false,
    )
}

/// What a removal came to: how many packages, archives and leftovers went and how much room it
/// gave back; under "Stays" each thing that stopped at delete time with its reason (a file a
/// scanner holds). The core checked everything again under the locks.
pub fn store_done(r: &Removed, lang: Lang) -> ResultVm {
    let none = r.packages.is_empty() && r.archives == 0 && r.leftovers == 0;
    let tone = if r.stopped.is_empty() {
        Tone::Done
    } else {
        Tone::Calm
    };
    let mut out = if none {
        result(tone, lang, Msg::PkDoneTitle, Msg::PkDoneNothing, false)
    } else {
        result(
            tone,
            lang,
            Msg::PkDoneTitle,
            Msg::PkDoneBody {
                packages: r.packages.len(),
                archives: r.archives,
                leftovers: r.leftovers,
                bytes: r.bytes,
            },
            false,
        )
    };
    if !r.stopped.is_empty() {
        let text = |s: String| escape::text(&s).into_owned();
        out.notice.details.push(DetailVm::of(text(tx(
            lang,
            Msg::ClearStaysHeading { n: r.stopped.len() },
        ))));
        for (name, keep) in &r.stopped {
            out.notice.details.push(DetailVm {
                who: Some(text(name.clone())),
                what: text(tx(lang, store_keep(*keep))),
            });
        }
    }
    out
}
