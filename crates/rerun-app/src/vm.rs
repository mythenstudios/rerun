//! View models (ADR 0027): pure functions from `flow` results and a [`Lang`] to plain structs
//! with every string localized. Framework-free: `ui` only lays them out, and the tests run them
//! without a window.
//!
//! Untrusted text (Steam names, paths, Topo texts, the core's error texts) is carried only as
//! [`Shown`] (ADR 0016) and never concatenated into a sentence: `ui` draws each such field in
//! its own element (ADR 0026), so its direction cannot reorder the text around it.

use rerun_core::catalog::model::{Api, Kind, Status, VariantStatus};
use rerun_core::catalog::store::StoreError;
use rerun_core::catalog::{IndexError, Topo};
use rerun_core::detect::exe::{ApiVerdict, GraphicsApi, Main};
use rerun_core::detect::steam::{AppState, SteamApp, SteamScan};
use rerun_core::escape::{self, Shown};
use rerun_core::flow::{
    Fix, Found, GameOpen, GameRefusal, GameView, IndexState, LibraryFacts, Lookup, MatchView,
    RowScan, SteamWhy, failed_games,
};
use rerun_core::hw::{GpuArch, SacState, SystemProfile};
use rerun_core::journal::JournalError;
use rerun_core::topo::{AntiCheatState, Refusal, Tri};

mod write;
pub use write::*;

use crate::text::{Lang, Msg, Sym, t};

/// The most problem details the library lists.
pub const MAX_PROBLEMS: usize = 50;

/// A status: glyph and word, always together (`docs/07-ui.md`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Badge {
    /// The glyph.
    pub sym: Sym,
    /// The word.
    pub word: String,
    /// Shown with a dashed (or strong) outline: not confirmed, not ready.
    pub quiet: bool,
}

impl Badge {
    fn new(sym: Sym, lang: Lang, m: Msg, quiet: bool) -> Self {
        Self {
            sym,
            word: t(lang, m).into_owned(),
            quiet,
        }
    }
}

/// A value that is either Rerun's own text or untrusted text, drawn alike but never mixed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    /// Rerun's own text.
    Text(String),
    /// Untrusted text, escaped.
    Shown(Shown<'static>),
}

impl Value {
    /// The text to draw.
    pub fn as_str(&self) -> &str {
        match self {
            Self::Text(s) => s,
            Self::Shown(s) => s.as_str(),
        }
    }
}

/// One detail: what it is about (a game's name) and the core's text, both escaped and drawn
/// in their own elements.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetailVm {
    /// What it is about, if not Rerun itself.
    pub who: Option<Shown<'static>>,
    /// The core's text.
    pub what: Shown<'static>,
}

impl DetailVm {
    /// A detail about nothing in particular.
    pub fn of(what: Shown<'static>) -> Self {
        Self { who: None, what }
    }
}

/// An explanation with optional details (the core's texts, escaped).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notice {
    /// The first sentence.
    pub title: String,
    /// The explanation.
    pub body: String,
    /// Details, untrusted.
    pub details: Vec<DetailVm>,
}

fn notice(lang: Lang, title: Msg, body: Msg) -> Notice {
    Notice {
        title: t(lang, title).into_owned(),
        body: t(lang, body).into_owned(),
        details: Vec::new(),
    }
}

/// An error's text through the text rule.
pub fn shown_error(e: &impl std::fmt::Display) -> Shown<'static> {
    escape::text(&e.to_string()).into_owned()
}

// ---------- the guards ----------

/// Why the app reads nothing (a guard stopped the job).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockedVm {
    /// The process is elevated (or that cannot be determined): the whole window is blocked.
    pub elevated: bool,
    /// The explanation.
    pub notice: Notice,
}

/// The blocking page for a gate of `flow::guard`.
pub fn blocked(gate: &rerun_core::flow::Gate, lang: Lang) -> BlockedVm {
    use rerun_core::flow::Gate;
    match gate {
        Gate::Elevated(_) => BlockedVm {
            elevated: true,
            notice: Notice {
                title: t(lang, Msg::ElevatedTitle).into_owned(),
                body: format!(
                    "{} {}",
                    t(lang, Msg::ElevatedBody),
                    t(lang, Msg::ElevatedHow)
                ),
                details: Vec::new(),
            },
        },
        Gate::InstallUnknown(e) => guard_failed(lang, escape::text(e).into_owned()),
        Gate::Forbidden(e) => guard_failed(lang, shown_error(e)),
        Gate::AppDir(e) => guard_failed(lang, shown_error(e)),
    }
}

fn guard_failed(lang: Lang, detail: Shown<'static>) -> BlockedVm {
    let mut n = notice(lang, Msg::GuardTitle, Msg::GuardBody);
    n.details.push(DetailVm::of(detail));
    BlockedVm {
        elevated: false,
        notice: n,
    }
}

// ---------- the library ----------

/// The section of the library a game is listed in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Group {
    /// The index names a Topo for the app.
    Topo,
    /// No Topo (or no index).
    NoTopo,
    /// Updating, not installed, or its folder not read.
    NotReady,
}

impl Group {
    /// The groups, in display order.
    pub const ALL: [Self; 3] = [Self::Topo, Self::NoTopo, Self::NotReady];

    fn title(self) -> Msg {
        match self {
            Self::Topo => Msg::GroupTopo,
            Self::NoTopo => Msg::GroupNoTopo,
            Self::NotReady => Msg::GroupNotReady,
        }
    }
}

/// Whether the index names a Topo for an app.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TopoKnown {
    /// No usable index.
    NoIndex,
    /// The index names one or more Topos for it.
    Yes,
    /// It names none.
    No,
}

/// One game of the library.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RowVm {
    /// The Steam app.
    pub app_id: u32,
    /// Its name as Steam lists it, escaped.
    pub name: Shown<'static>,
    /// The second line: the graphics API or the state (Rerun's text).
    pub detail: String,
    /// The main executable, escaped as a path (its own element).
    pub exe: Option<Shown<'static>>,
    /// Its section.
    pub group: Group,
    /// Its status.
    pub badge: Badge,
    /// The name, lower case, for the search.
    key: String,
}

/// The display name of a graphics API (the same in every language).
pub fn api_name(api: GraphicsApi) -> &'static str {
    match api {
        GraphicsApi::Ddraw => "DirectDraw",
        GraphicsApi::D3d8 => "Direct3D 8",
        GraphicsApi::D3d9 => "Direct3D 9",
        GraphicsApi::D3d10 => "Direct3D 10",
        GraphicsApi::D3d11 => "Direct3D 11",
        GraphicsApi::D3d12 => "Direct3D 12",
        GraphicsApi::Opengl => "OpenGL",
        GraphicsApi::Vulkan => "Vulkan",
        GraphicsApi::Glide => "Glide",
    }
}

/// The display name of a Topo's API.
pub fn topo_api_name(api: Api) -> &'static str {
    match api {
        Api::Ddraw => "DirectDraw",
        Api::D3d8 => "Direct3D 8",
        Api::D3d9 => "Direct3D 9",
        Api::D3d10 => "Direct3D 10",
        Api::D3d11 => "Direct3D 11",
        Api::Opengl => "OpenGL",
    }
}

/// The row of one listed app.
pub fn row(app: &SteamApp, scan: &RowScan, topo: TopoKnown, lang: Lang) -> RowVm {
    let name = app.name.escaped().into_owned();
    let key = name.as_str().to_lowercase();
    let state = app.state();
    let (detail, exe, ready) = match scan {
        RowScan::NotOpened => {
            let m = match state {
                AppState::UpdatePending => Msg::RowUpdating,
                _ => Msg::RowNotInstalled,
            };
            (t(lang, m).into_owned(), None, false)
        }
        RowScan::Unopened(_) => (t(lang, Msg::RowNotOpened).into_owned(), None, false),
        RowScan::Scanned(exes) => match &exes.main {
            Main::One(i) => match exes.candidates.get(*i) {
                Some(c) => {
                    let api = c.facts.as_ref().ok().and_then(|f| match &f.api.verdict {
                        ApiVerdict::One { api, .. } => Some(api_name(*api)),
                        _ => None,
                    });
                    let detail = match api {
                        Some(a) => a.to_owned(),
                        None => t(lang, Msg::RowApiUnknown).into_owned(),
                    };
                    let exe = escape::path(c.path.file_name()).into_owned();
                    (detail, Some(exe), true)
                }
                None => (t(lang, Msg::RowNoMainExe).into_owned(), None, true),
            },
            Main::Tied(_) => (t(lang, Msg::RowSeveralExes).into_owned(), None, true),
            Main::None => (t(lang, Msg::RowNoMainExe).into_owned(), None, true),
        },
    };
    let (group, badge) = if !ready {
        let badge = match (scan, state) {
            (RowScan::Unopened(_), _) => Badge::new(Sym::Attention, lang, Msg::BadgeNotRead, true),
            (_, AppState::UpdatePending) => {
                Badge::new(Sym::Attention, lang, Msg::BadgeUpdating, true)
            }
            _ => Badge::new(Sym::NotHere, lang, Msg::BadgeNotInstalled, true),
        };
        (Group::NotReady, badge)
    } else {
        match topo {
            TopoKnown::Yes => (
                Group::Topo,
                Badge::new(Sym::Open, lang, Msg::BadgeTopo, false),
            ),
            TopoKnown::No => (
                Group::NoTopo,
                Badge::new(Sym::None, lang, Msg::BadgeNoTopo, false),
            ),
            TopoKnown::NoIndex => (
                Group::NoTopo,
                Badge::new(Sym::None, lang, Msg::BadgeNoIndex, false),
            ),
        }
    };
    RowVm {
        app_id: app.app_id,
        name,
        detail,
        exe,
        group,
        badge,
        key,
    }
}

/// The problem details of one row (a folder that did not open, a walk problem, an executable
/// that failed), for the library's problem list.
pub fn row_problems(app: &SteamApp, scan: &RowScan) -> Vec<DetailVm> {
    let who = || Some(app.name.escaped().into_owned());
    match scan {
        RowScan::NotOpened => Vec::new(),
        RowScan::Unopened(e) => vec![DetailVm {
            who: who(),
            what: shown_error(e),
        }],
        RowScan::Scanned(exes) => exes
            .issues
            .iter()
            .map(shown_error)
            .chain(failed_games(exes).filter_map(|c| c.facts.as_ref().err().map(shown_error)))
            .map(|what| DetailVm { who: who(), what })
            .collect(),
    }
}

/// A section of the library: its title and the rows in it (indices into the rows).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SectionVm {
    /// The heading.
    pub title: String,
    /// Indices into the rows, sorted by name.
    pub rows: Vec<usize>,
}

/// Whether `row` matches the search `query` (case-insensitive, part of the name).
pub fn matches(row: &RowVm, query: &str) -> bool {
    let q = query.trim().to_lowercase();
    q.is_empty() || row.key.contains(&q)
}

/// The sections of the library: the rows that match `query`, by status if `group` (empty
/// groups left out), else in one section; sorted by name within a section.
pub fn sections(rows: &[RowVm], query: &str, group: bool, lang: Lang) -> Vec<SectionVm> {
    let mut hits: Vec<usize> = (0..rows.len())
        .filter(|i| matches(&rows[*i], query))
        .collect();
    hits.sort_by(|a, b| {
        rows[*a]
            .key
            .cmp(&rows[*b].key)
            .then(rows[*a].app_id.cmp(&rows[*b].app_id))
    });
    if !group {
        if hits.is_empty() {
            return Vec::new();
        }
        return vec![SectionVm {
            title: t(lang, Msg::GroupAll).into_owned(),
            rows: hits,
        }];
    }
    Group::ALL
        .iter()
        .map(|g| SectionVm {
            title: t(lang, g.title()).into_owned(),
            rows: hits
                .iter()
                .copied()
                .filter(|i| rows[*i].group == *g)
                .collect(),
        })
        .filter(|s| !s.rows.is_empty())
        .collect()
}

/// The index for the status bar and the library.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexVm {
    /// The index part of the status bar.
    pub status: String,
    /// The signature part of the status bar.
    pub signature: String,
    /// The library's notice, if the index is missing or refused.
    pub notice: Option<Notice>,
}

/// The index state for display.
pub fn index(state: &IndexState, lang: Lang) -> IndexVm {
    match state {
        IndexState::Current(c) => IndexVm {
            status: t(lang, Msg::StatusIndex { seq: c.seq() }).into_owned(),
            signature: t(lang, Msg::StatusSignatureChecked).into_owned(),
            notice: None,
        },
        IndexState::None => IndexVm {
            status: t(lang, Msg::StatusIndexNone).into_owned(),
            signature: t(lang, Msg::StatusSignatureNone).into_owned(),
            notice: Some(notice(lang, Msg::IndexNoneTitle, Msg::IndexNoneBody)),
        },
        IndexState::Refused(e) => {
            let n = if matches!(e, StoreError::Index(IndexError::NoKeys)) {
                notice(lang, Msg::IndexNoKeysTitle, Msg::IndexNoKeysBody)
            } else {
                let mut n = notice(lang, Msg::IndexRefusedTitle, Msg::IndexRefusedBody);
                n.details.push(DetailVm::of(shown_error(e)));
                n
            };
            IndexVm {
                status: t(lang, Msg::StatusIndexRefused).into_owned(),
                signature: t(lang, Msg::StatusSignatureNone).into_owned(),
                notice: Some(n),
            }
        }
    }
}

/// What the Steam scan found before the first row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SteamVm {
    /// Steam was found.
    pub found: bool,
    /// The Steam scan's problems, escaped.
    pub problems: Vec<DetailVm>,
}

/// The Steam part of the scan.
pub fn steam(s: &SteamScan<'_>) -> SteamVm {
    SteamVm {
        found: s.root.is_some(),
        problems: s
            .issues
            .iter()
            .map(|i| DetailVm::of(shown_error(i)))
            .collect(),
    }
}

/// The library after the scan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LibraryVm {
    /// The line under the title.
    pub summary: String,
    /// What to show above the list, in order (index, Steam, no games, problems).
    pub notices: Vec<Notice>,
    /// The index.
    pub index: IndexVm,
}

/// The library's facts after the scan. `problems`: every problem detail found (Steam and per
/// game); the count names them all, at most [`MAX_PROBLEMS`] are listed.
pub fn library_done(
    facts: &LibraryFacts,
    steam: &SteamVm,
    problems: &[DetailVm],
    index: IndexVm,
    lang: Lang,
) -> LibraryVm {
    let c = &facts.counts;
    let mut notices = Vec::new();
    if let Some(n) = &index.notice {
        notices.push(n.clone());
    }
    if !steam.found {
        notices.push(notice(lang, Msg::NoSteamTitle, Msg::NoSteamBody));
    } else if c.installed == 0 {
        notices.push(notice(lang, Msg::NoGamesTitle, Msg::NoGamesBody));
    }
    let count = problems.len();
    if count > 0 {
        notices.push(Notice {
            title: t(lang, Msg::ScanProblemsTitle { count }).into_owned(),
            body: t(lang, Msg::ScanProblemsBody).into_owned(),
            details: problems.iter().take(MAX_PROBLEMS).cloned().collect(),
        });
    }
    LibraryVm {
        summary: t(
            lang,
            Msg::LibrarySummary {
                games: c.apps,
                libraries: c.libraries,
            },
        )
        .into_owned(),
        notices,
        index,
    }
}

// ---------- the game page ----------

/// The hero header's status sentence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeroVm {
    /// Its glyph.
    pub sym: Sym,
    /// The sentence.
    pub line: String,
    /// A quieter second line.
    pub sub: Option<String>,
}

/// One quiet fact under the hero.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FactVm {
    /// The label.
    pub label: String,
    /// The value.
    pub value: Value,
    /// Set in the monospaced font.
    pub mono: bool,
}

/// One problem of the Topo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProblemVm {
    /// The issue's title (Topo text, escaped).
    pub title: Shown<'static>,
    /// Whether it affects this PC.
    pub when: Badge,
    /// The fixes for it (variant IDs, escaped).
    pub fixes: Vec<Shown<'static>>,
    /// It does not affect this PC: listed collapsed.
    pub quiet: bool,
}

/// One issue a fix solves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SolvedVm {
    /// The issue's title (Topo text, escaped).
    pub issue: Shown<'static>,
    /// Whether it affects this PC.
    pub when: Badge,
    /// The evidence for this issue.
    pub status: Badge,
    /// The side effects this issue's copy of the fix names (Topo text, escaped).
    pub tradeoffs: Vec<Shown<'static>>,
    /// Where the fix comes from for this issue: type and link (escaped).
    pub sources: Vec<Shown<'static>>,
}

/// One fix (one variant ID, ADR 0027 U2 a).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixVm {
    /// The variant ID (escaped).
    pub id: Shown<'static>,
    /// Fix or enhancement.
    pub kind: String,
    /// Offered or not.
    pub state: Badge,
    /// Why it is not offered.
    pub refused: Option<String>,
    /// The core's reason (escaped), for a launch refusal.
    pub refused_detail: Option<Shown<'static>>,
    /// The anti-cheat rule warns.
    pub warned: Option<String>,
    /// Every issue it solves.
    pub solves: Vec<SolvedVm>,
    /// The variant ID as the Topo spells it (the pick; never drawn as text of its own).
    pub key: String,
    /// Whether and why the app can apply it (P5-5a).
    pub offer: Offer,
    /// Why it cannot be applied here yet (needs the helper or a download).
    pub note: Option<String>,
    /// Preselected: verified for a problem that affects this PC.
    pub preselect: bool,
    /// Why it is preselected.
    pub preselect_note: Option<String>,
    /// The fixes it cannot be combined with (indices into the page's fixes).
    pub conflicts: Vec<usize>,
    /// The same fixes' IDs (escaped), drawn under the label.
    pub exclusive: Vec<Shown<'static>>,
    /// The problem the pick names it for.
    pub pick_issue: String,
    /// Every problem it solves with its `when`, for the attribution.
    pub(crate) issues: Vec<(String, Tri)>,
    /// A solved problem is verified and affects this PC.
    pub(crate) solves_verified_here: bool,
}

/// Whether the app can apply a fix on this page (P5-5a).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Offer {
    /// It can be selected and applied.
    Selectable,
    /// The core refuses it here (anti-cheat, the launch): shown with the reason.
    Refused,
    /// A step needs Rerun's elevated helper: P5-5c.
    NeedsHelper,
    /// A step needs a package download: P5-5b.
    NeedsDownload,
}

/// The game page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GameVm {
    /// The Steam app.
    pub app_id: u32,
    /// The title (Steam's name, escaped).
    pub title: Shown<'static>,
    /// The status sentence.
    pub hero: HeroVm,
    /// The quiet facts.
    pub facts: Vec<FactVm>,
    /// Notes under the hero (anti-cheat, several adapters, retest).
    pub notes: Vec<String>,
    /// The core's text for a refused lookup (escaped).
    pub detail: Option<Shown<'static>>,
    /// The problems, those that affect this PC first.
    pub problems: Vec<ProblemVm>,
    /// The fixes, in the Topo's order of first appearance.
    pub fixes: Vec<FixVm>,
    /// What is applied to this game now, one card per transaction (P5-5a).
    pub applied: Vec<TxnCardVm>,
}

fn hero(sym: Sym, lang: Lang, m: Msg) -> HeroVm {
    HeroVm {
        sym,
        line: t(lang, m).into_owned(),
        sub: None,
    }
}

fn when_badge(w: Tri, lang: Lang) -> Badge {
    match w {
        Tri::Yes => Badge::new(Sym::Affects, lang, Msg::WhenYes, false),
        Tri::Unknown => Badge::new(Sym::Unknown, lang, Msg::WhenUnknown, true),
        Tri::No => Badge::new(Sym::NotHere, lang, Msg::WhenNo, true),
    }
}

fn status_badge(s: VariantStatus, lang: Lang) -> Badge {
    match s {
        VariantStatus::Verified => Badge::new(Sym::Verified, lang, Msg::StatusVerified, false),
        VariantStatus::Reported => Badge::new(Sym::Affects, lang, Msg::StatusReported, false),
        VariantStatus::Unverified => {
            Badge::new(Sym::Unconfirmed, lang, Msg::StatusUnverified, true)
        }
    }
}

fn base(app_id: u32, title: Shown<'static>, hero: HeroVm, lang: Lang) -> GameVm {
    GameVm {
        app_id,
        title,
        hero,
        facts: vec![FactVm {
            label: t(lang, Msg::FactSteamApp).into_owned(),
            value: Value::Text(app_id.to_string()),
            mono: true,
        }],
        notes: Vec::new(),
        detail: None,
        problems: Vec::new(),
        fixes: Vec::new(),
        applied: Vec::new(),
    }
}

/// The title of a game: Steam's name, or "Steam app <id>" when it lists none.
pub fn title_of(app_id: u32, name: Option<&Shown<'static>>, lang: Lang) -> Shown<'static> {
    match name {
        Some(n) if !n.as_str().is_empty() => n.clone(),
        _ => escape::text(&t(lang, Msg::UnnamedGame { app_id })).into_owned(),
    }
}

/// The game page while the worker still reads the game folder (P5-3b): what the library row
/// already says, at once. The title, the row's status as the hero line (its glyph and word) and
/// the row's second line under it; the fact of the Steam app. No problems, no fixes: the
/// page shows its reading text there until [`game`] replaces this one. Without the row (the
/// library has not listed the game) the hero says that the folder is being read.
pub fn game_loading(
    app_id: u32,
    name: Option<&Shown<'static>>,
    row: Option<&RowVm>,
    lang: Lang,
) -> GameVm {
    let title = title_of(app_id, name.or(row.map(|r| &r.name)), lang);
    let hero = match row {
        Some(r) => HeroVm {
            sym: r.badge.sym,
            line: r.badge.word.clone(),
            sub: Some(r.detail.clone()),
        },
        None => hero(Sym::None, lang, Msg::GameReading),
    };
    base(app_id, title, hero, lang)
}

/// The game page of a lookup.
pub fn game(view: &GameView, name: Option<&Shown<'static>>, lang: Lang) -> GameVm {
    let title = title_of(view.app_id, name, lang);
    let none = |m| base(view.app_id, title.clone(), hero(Sym::None, lang, m), lang);
    match &view.lookup {
        Lookup::NoIndex => none(Msg::HeroNoIndex),
        Lookup::NoTopo { .. } => none(Msg::HeroNoTopo),
        Lookup::Read { retired, found } => match found {
            Found::NoMatch(live) if live.is_empty() && !retired.is_empty() => {
                none(Msg::HeroRetired)
            }
            Found::NoMatch(_) => {
                let mut h = hero(Sym::Unknown, lang, Msg::HeroNoMatch);
                h.sub = Some(t(lang, Msg::HeroNoMatchSub).into_owned());
                base(view.app_id, title, h, lang)
            }
            Found::Several(_) => base(
                view.app_id,
                title,
                hero(Sym::Attention, lang, Msg::HeroSeveral),
                lang,
            ),
            Found::One(m) => matched(view.app_id, title, m, lang),
        },
    }
}

/// The game page of a refused lookup.
pub fn game_refused(
    app_id: u32,
    name: Option<&Shown<'static>>,
    e: &GameRefusal,
    lang: Lang,
) -> GameVm {
    let title = title_of(app_id, name, lang);
    let (sym, m, detail) = match e {
        GameRefusal::Index(e) => (Sym::Attention, Msg::HeroIndexRefused, Some(shown_error(e))),
        GameRefusal::Engine(e) => (Sym::Attention, Msg::HeroEngine, Some(shown_error(e))),
        GameRefusal::Game(GameOpen::Folder(e)) => {
            (Sym::Attention, Msg::HeroFolder, Some(shown_error(e)))
        }
        GameRefusal::Game(GameOpen::Steam { why, .. }) => {
            let m = match why {
                SteamWhy::NoSteam => Msg::HeroNoSteam,
                SteamWhy::NotListed => Msg::HeroNotListed,
                SteamWhy::Twice => Msg::HeroTwice,
                SteamWhy::Updating => Msg::HeroUpdating,
                SteamWhy::NotInstalled => Msg::HeroNotInstalled,
            };
            let sym = match why {
                SteamWhy::Updating | SteamWhy::Twice => Sym::Attention,
                _ => Sym::NotHere,
            };
            (sym, m, None)
        }
    };
    let mut g = base(app_id, title, hero(sym, lang, m), lang);
    g.detail = detail;
    g
}

fn topo_status(s: Status) -> Msg {
    match s {
        Status::Active => Msg::TopoActive,
        Status::NeedsRetest => Msg::TopoNeedsRetest,
        Status::Retired => Msg::TopoRetired,
        Status::Draft => Msg::TopoDraft,
    }
}

fn graphics_of(topo: &Topo, m: &MatchView) -> Option<&'static str> {
    let main = m.report.main_exe.as_ref()?;
    topo.matches
        .exes
        .iter()
        .find(|e| e.path.same_spelling(main))
        .map(|e| topo_api_name(e.api))
}

fn matched(app_id: u32, title: Shown<'static>, m: &MatchView, lang: Lang) -> GameVm {
    let r = &m.report;
    let topo = &r.topo;
    let issue_title = |id: &str| -> Shown<'static> {
        r.issues
            .iter()
            .find(|i| i.issue.id.as_str() == id)
            .map_or_else(
                || escape::text(id).into_owned(),
                |i| escape::text(&i.issue.title).into_owned(),
            )
    };
    // Problems: those that affect this PC first, then the open ones, then the others.
    let rank = |w: Tri| match w {
        Tri::Yes => 0,
        Tri::Unknown => 1,
        Tri::No => 2,
    };
    let mut issues: Vec<_> = r.issues.iter().collect();
    issues.sort_by_key(|i| rank(i.when));
    let problems: Vec<ProblemVm> = issues
        .iter()
        .map(|i| ProblemVm {
            title: escape::text(&i.issue.title).into_owned(),
            when: when_badge(i.when, lang),
            fixes: i
                .variants
                .iter()
                .map(|v| escape::text(v.variant.id.as_str()).into_owned())
                .collect(),
            quiet: i.when == Tri::No,
        })
        .collect();
    let mut fixes: Vec<FixVm> = m.fixes.iter().map(|f| fix(f, &issue_title, lang)).collect();
    write::link(&mut fixes);
    for f in &mut fixes {
        if f.preselect {
            f.preselect_note = Some(t(lang, Msg::FixPreselected).into_owned());
        }
    }

    let with_fix = |w: Tri| {
        r.issues
            .iter()
            .filter(|i| i.when == w && !i.variants.is_empty())
            .count()
    };
    let affects = with_fix(Tri::Yes);
    let may = with_fix(Tri::Unknown);
    let offered = m
        .fixes
        .iter()
        .filter(|f| f.refused.is_none() && f.solves.iter().any(|s| s.when != Tri::No))
        .count();
    let mut h = if affects + may == 0 {
        hero(Sym::None, lang, Msg::HeroNothingHere)
    } else if offered == 0 {
        hero(Sym::Attention, lang, Msg::HeroNoFixHere)
    } else if affects > 0 {
        hero(
            Sym::Affects,
            lang,
            Msg::HeroAffects {
                problems: affects,
                fixes: offered,
            },
        )
    } else {
        hero(
            Sym::Open,
            lang,
            Msg::HeroMayOccur {
                problems: may,
                fixes: offered,
            },
        )
    };
    if offered > 0 {
        h.sub = Some(t(lang, Msg::HeroReadOnly).into_owned());
    }

    let mut g = base(app_id, title, h, lang);
    if let Some(main) = &r.main_exe {
        g.facts.push(FactVm {
            label: t(lang, Msg::FactProgram).into_owned(),
            value: Value::Shown(escape::path(main.as_str()).into_owned()),
            mono: true,
        });
    }
    if let Some(api) = graphics_of(topo, m) {
        g.facts.push(FactVm {
            label: t(lang, Msg::FactGraphics).into_owned(),
            value: Value::Text(api.to_owned()),
            mono: false,
        });
    }
    g.facts.push(FactVm {
        label: t(lang, Msg::FactTopo).into_owned(),
        value: Value::Text(format!(
            "{} \u{00B7} {}",
            t(lang, Msg::TopoRevision { rev: topo.rev }),
            t(lang, topo_status(topo.status))
        )),
        mono: false,
    });
    match &r.anti_cheat {
        AntiCheatState::Clear => {}
        AntiCheatState::Enforced { unreadable, .. } => {
            g.notes.push(t(lang, Msg::NoteAntiCheat).into_owned());
            if *unreadable {
                g.notes
                    .push(t(lang, Msg::NoteAntiCheatUnreadable).into_owned());
            }
        }
        AntiCheatState::Released { .. } => {
            g.notes
                .push(t(lang, Msg::NoteAntiCheatReleased).into_owned());
        }
    }
    if r.several_gpus {
        g.notes.push(t(lang, Msg::NoteSeveralGpus).into_owned());
    }
    if topo.status == Status::NeedsRetest {
        g.notes.push(t(lang, Msg::NoteNeedsRetest).into_owned());
    }
    g.problems = problems;
    g.fixes = fixes;
    g
}

fn fix(f: &Fix, issue_title: &dyn Fn(&str) -> Shown<'static>, lang: Lang) -> FixVm {
    let (refused, refused_detail) = match &f.refused {
        None => (None, None),
        Some(Refusal::AntiCheat(_)) => (Some(t(lang, Msg::FixRefusedAntiCheat).into_owned()), None),
        Some(Refusal::Launch(p)) => (
            Some(t(lang, Msg::FixRefusedLaunch).into_owned()),
            Some(shown_error(p)),
        ),
    };
    let state = if refused.is_some() {
        Badge::new(Sym::NotHere, lang, Msg::FixNotOffered, true)
    } else {
        Badge::new(Sym::Open, lang, Msg::FixOffered, false)
    };
    let offer = if refused.is_some() {
        Offer::Refused
    } else if f.needs_helper {
        Offer::NeedsHelper
    } else if !f.packages.is_empty() {
        Offer::NeedsDownload
    } else {
        Offer::Selectable
    };
    let note = match offer {
        Offer::NeedsHelper => Some(t(lang, Msg::FixNeedsHelper).into_owned()),
        Offer::NeedsDownload => Some(t(lang, Msg::FixNeedsDownload).into_owned()),
        Offer::Selectable | Offer::Refused => None,
    };
    FixVm {
        key: f.variant.clone(),
        offer,
        note,
        preselect: false,
        preselect_note: None,
        conflicts: Vec::new(),
        exclusive: Vec::new(),
        pick_issue: String::new(),
        issues: f.solves.iter().map(|s| (s.issue.clone(), s.when)).collect(),
        solves_verified_here: f
            .solves
            .iter()
            .any(|s| write::verified_here(s.when, s.status)),
        id: escape::text(&f.variant).into_owned(),
        kind: t(
            lang,
            match f.kind {
                Kind::Fix => Msg::KindFix,
                Kind::Enhancement => Msg::KindEnhancement,
            },
        )
        .into_owned(),
        state,
        refused,
        refused_detail,
        warned: (!f.warned.is_empty() && f.refused.is_none())
            .then(|| t(lang, Msg::FixWarned).into_owned()),
        solves: f
            .solves
            .iter()
            .map(|s| SolvedVm {
                issue: issue_title(&s.issue),
                when: when_badge(s.when, lang),
                status: status_badge(s.status, lang),
                tradeoffs: s
                    .tradeoffs
                    .iter()
                    .map(|x| escape::text(x).into_owned())
                    .collect(),
                sources: s
                    .sources
                    .iter()
                    .map(|x| write::source_text(x.kind, &x.url, lang))
                    .collect(),
            })
            .collect(),
    }
}

// ---------- applied ----------

/// The applied page in P5-3: how many transactions are open.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliedVm {
    /// Open transactions (not closed, not forgotten, not empty).
    pub open: usize,
    /// The heading of the card.
    pub title: String,
    /// Its second line.
    pub sub: String,
    /// The core's text if the journal could not be read (escaped).
    pub detail: Option<Shown<'static>>,
    /// One card per open transaction (P5-5a, user decision U1).
    pub cards: Vec<TxnCardVm>,
}

/// The applied page from the status; `None`: Rerun's folder does not exist.
pub fn applied(
    status: Option<Result<&rerun_core::exec::Status, &JournalError>>,
    names: &Names,
    lang: Lang,
) -> AppliedVm {
    let empty = || AppliedVm {
        open: 0,
        title: t(lang, Msg::AppliedEmpty).into_owned(),
        sub: t(lang, Msg::AppliedEmptySub).into_owned(),
        detail: None,
        cards: Vec::new(),
    };
    match status {
        None => empty(),
        Some(Err(e)) => AppliedVm {
            open: 0,
            title: t(lang, Msg::AppliedUnreadable).into_owned(),
            sub: String::new(),
            detail: Some(shown_error(e)),
            cards: Vec::new(),
        },
        Some(Ok(v)) => {
            let open = v.txns.iter().filter(|s| !s.is_settled()).count();
            if open == 0 {
                empty()
            } else {
                AppliedVm {
                    open,
                    title: t(lang, Msg::AppliedSome { count: open }).into_owned(),
                    sub: t(lang, Msg::AppliedSomeSub).into_owned(),
                    detail: None,
                    cards: cards(v, names, lang),
                }
            }
        }
    }
}

// ---------- system ----------

/// One line of the system page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SysLineVm {
    /// The label.
    pub label: String,
    /// The values, one per line.
    pub values: Vec<Value>,
}

/// The system page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemVm {
    /// The lines.
    pub lines: Vec<SysLineVm>,
}

/// The system page of a profile and the Steam scan's outcome (`steam`: libraries found, or
/// `None` without Steam).
pub fn system(p: &SystemProfile, steam: Option<usize>, lang: Lang) -> SystemVm {
    let text = |m| Value::Text(t(lang, m).into_owned());
    let mut gpu = Vec::new();
    match &p.gpu {
        Err(e) => {
            gpu.push(text(Msg::SysUnreadable));
            gpu.push(Value::Shown(shown_error(e)));
        }
        Ok(g) if g.adapters.is_empty() => gpu.push(text(Msg::SysNoAdapter)),
        Ok(g) => {
            for a in &g.adapters {
                gpu.push(Value::Shown(escape::text(&a.adapter.name).into_owned()));
                let mut facts = vec![t(lang, Msg::SysVram { mb: a.vram_mb() }).into_owned()];
                if let GpuArch::Known(id) = &a.arch {
                    facts.push(id.as_str().to_owned());
                }
                if a.integrated == Some(true) {
                    facts.push(t(lang, Msg::SysIntegrated).into_owned());
                }
                gpu.push(Value::Text(facts.join(" \u{00B7} ")));
            }
        }
    }
    let cpu = match &p.cpu {
        Err(e) => vec![text(Msg::SysUnreadable), Value::Shown(shown_error(e))],
        Ok(c) => {
            let mut cores: Vec<(u16, u32)> = c.cpus.iter().map(|l| (l.group, l.core)).collect();
            cores.sort_unstable();
            cores.dedup();
            vec![text(Msg::SysCpu {
                threads: c.cpus.len(),
                cores: cores.len(),
                groups: c.llcs.len(),
            })]
        }
    };
    let os = match &p.os {
        Err(e) => vec![text(Msg::SysUnreadable), Value::Shown(shown_error(e))],
        Ok(b) => vec![match b.ubr {
            Some(ubr) => text(Msg::SysBuildUbr {
                build: b.build,
                ubr,
            }),
            None => text(Msg::SysBuild { build: b.build }),
        }],
    };
    let sac = text(match p.sac {
        SacState::Off => Msg::SacOff,
        SacState::Enforce => Msg::SacOn,
        SacState::Evaluation => Msg::SacEvaluation,
        SacState::Unknown => Msg::SacUnknown,
    });
    let steam = text(match steam {
        Some(libraries) => Msg::SteamFound { libraries },
        None => Msg::SteamNotFound,
    });
    let line = |m, values| SysLineVm {
        label: t(lang, m).into_owned(),
        values,
    };
    SystemVm {
        lines: vec![
            line(Msg::SysGraphics, gpu),
            line(Msg::SysProcessor, cpu),
            line(Msg::SysWindows, os),
            line(Msg::SysSac, vec![sac]),
            line(Msg::SysSteam, vec![steam]),
        ],
    }
}

#[cfg(test)]
mod tests;
