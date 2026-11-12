//! One game (ADR 0027; `rerun plan <app-id>` without `--pick`): the Topo of the app on the
//! current signed index, the engine's report, and its fixes grouped by variant ID.
//!
//! Order ([`with_topo`]): the current index (signature and form checked again), the Topos that
//! name the app, the path of Rerun's folder (never created), the system profile (`hw::read`
//! with the built-in architecture table, the table the Topo is checked against), the game
//! folder (exactly one installed app in the Steam libraries), per Topo the executables hashed
//! on their parsed handles (an executable a live `laa_patch` changed still counts as its build,
//! P4-10) and the anti-cheat markers. Retired Topos are listed, never chosen; exactly one of the
//! others must match. `appinfo.vdf` is never read (L9). Nothing is stored, nothing created.
//!
//! A long-lived caller (the app's worker) may pass a [`GameCache`] to [`game_cached`]: it keeps
//! what was read from a game's executables (the hashes, the expensive part) for as long as the
//! files keep their identity, in memory for the session only (P5-3b). Planning and applying
//! never use it: they read the files fresh.

use crate::catalog::model::{Issue, Kind, Source, Variant, VariantStatus};
use crate::catalog::store::StoreError;
use crate::catalog::{Catalog, Topo};
use crate::exec::PatchedExe;
use crate::hw::{self, GpuArchTable, SystemProfile};
use crate::path::{RelPath, RootPath};
use crate::policy::root::{AppDir, GameDir, RootId};
use crate::prim::GameRef;
use crate::sys::fs::Metadata;
use crate::topo::when::Tri;
use crate::topo::{
    self, AntiCheatState, EngineError, ExeCheck, Facts, GameFacts, LaunchPlan, LaunchProblem,
    Refusal, Report, Selection, StepKind,
};

use super::{GameOpen, Guarded, IndexState, index_state, with_game};

/// What a Topo lookup for one app found.
#[derive(Debug)]
pub enum Lookup<R> {
    /// No signed index (or no Rerun folder).
    NoIndex,
    /// The index names no Topo for the app.
    NoTopo {
        /// The index's `seq`.
        seq: u64,
    },
    /// The game folder was read for every Topo of the app.
    Read {
        /// Retired Topos of the app: listed, never chosen.
        retired: Vec<Topo>,
        /// Among the others.
        found: Found<R>,
    },
}

/// Which Topo of the app matches the game folder.
#[derive(Debug)]
pub enum Found<R> {
    /// None: every Topo that is not retired with what was read for it.
    NoMatch(Vec<(Topo, GameFacts)>),
    /// Several (a damaged or foreign index): their IDs.
    Several(Vec<String>),
    /// Exactly one: what the caller made of it.
    One(R),
}

/// The one Topo that matches, with what the engine works with.
pub struct Matched<'x> {
    /// The game folder.
    pub game: &'x GameDir<'x>,
    /// The Steam app ID.
    pub steam_app: Option<u32>,
    /// The Topo.
    pub topo: &'x Topo,
    /// What was read for it.
    pub read: &'x GameFacts,
    /// The system profile.
    pub profile: &'x SystemProfile,
    /// The architecture table the profile was read with.
    pub table: Option<&'static GpuArchTable>,
    /// The index the Topo comes from.
    pub catalog: &'x Catalog,
    /// The path of Rerun's folder, if known (never created).
    pub app_path: Option<&'x RootPath>,
}

impl Matched<'_> {
    /// The engine's facts.
    pub fn facts(&self) -> Facts<'_> {
        Facts {
            profile: self.profile,
            table: self.table,
            game: self.read,
            packages: self.catalog.packages(),
        }
    }
}

/// Why a game lookup stopped.
#[derive(Debug)]
pub enum GameRefusal {
    /// The stored index is refused.
    Index(StoreError),
    /// The game folder did not open.
    Game(GameOpen),
    /// The engine refuses the Topo.
    Engine(EngineError),
}

/// What a [`GameCache`] holds for one Topo of one game.
#[derive(Debug)]
struct CacheEntry {
    app_id: u32,
    topo: String,
    /// The index the Topo comes from (its SHA-256: a re-import with the same `seq` differs).
    index: [u8; 32],
    game: RootId,
    patched: Vec<PatchedExe>,
    /// Identity of every `match.exes` file when it was read (`None`: the file does not exist).
    files: Vec<Option<Metadata>>,
    exes: Vec<ExeCheck>,
}

/// Session cache of what was read from the executables of a game folder (P5-3b, ADR 0027
/// amendment): per app and Topo the [`ExeCheck`]s, valid while the index (its SHA-256), the game folder, the
/// live patches and every executable's identity (length, file ID, attributes, link count; the
/// layer reports no timestamps) are the same. Held in memory by the caller for the session,
/// never written anywhere; [`Self::clear`] on a rescan. It only spares the display a re-hash:
/// a file changed in place without a change of length and file ID shows as before until the
/// next rescan, and planning and applying read the files fresh (`flow::plan` takes no cache).
#[derive(Debug, Default)]
pub struct GameCache {
    entries: Vec<CacheEntry>,
    hits: u32,
    reads: u32,
}

impl GameCache {
    /// Forgets everything (a rescan).
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// How often the executables were served from the cache.
    pub fn hits(&self) -> u32 {
        self.hits
    }

    /// How often the executables were read from the game folder (a first look, or a changed
    /// identity).
    pub fn reads(&self) -> u32 {
        self.reads
    }

    pub(crate) fn facts(
        &mut self,
        game: &GameDir<'_>,
        app_id: u32,
        index: [u8; 32],
        topo: &Topo,
        patched: &[PatchedExe],
    ) -> GameFacts {
        let files: Option<Vec<Option<Metadata>>> = topo
            .matches
            .exes
            .iter()
            .map(|e| game.dir().metadata(&e.path).ok())
            .collect();
        // Not describable: read fresh and keep nothing.
        let Some(files) = files else {
            self.reads += 1;
            return topo::read_game_with(game, topo, patched);
        };
        let id = game.id();
        let at = self
            .entries
            .iter()
            .position(|c| c.app_id == app_id && c.topo == topo.id.as_str());
        if let Some(i) = at {
            let c = &self.entries[i];
            if c.index == index && c.game == id && c.files == files && c.patched == patched {
                self.hits += 1;
                return GameFacts {
                    exes: c.exes.clone(),
                    anti_cheat: topo::read_anti_cheat(game, topo),
                };
            }
        }
        self.reads += 1;
        let exes = topo::read_exes_with(game, topo, patched);
        let entry = CacheEntry {
            app_id,
            topo: topo.id.to_string(),
            index,
            game: id,
            patched: patched.to_vec(),
            files,
            exes: exes.clone(),
        };
        match at {
            Some(i) => self.entries[i] = entry,
            None => self.entries.push(entry),
        }
        GameFacts {
            exes,
            anti_cheat: topo::read_anti_cheat(game, topo),
        }
    }
}

/// Looks up the Topo of `app_id` (module docs) and runs `f` on it if exactly one matches.
/// Crate-internal behind [`super::game`] and `flow::plan` (P5-2a).
pub(crate) fn with_topo<R>(
    g: &Guarded<'_>,
    app_id: u32,
    cache: Option<&mut GameCache>,
    f: impl FnOnce(Matched<'_>) -> R,
) -> Result<Lookup<R>, GameRefusal> {
    let sys = g.env().sys;
    // No Rerun folder, no index.
    let Some(dir) = g.app() else {
        return Ok(Lookup::NoIndex);
    };
    let catalog = match index_state(Some(dir)) {
        IndexState::None => return Ok(Lookup::NoIndex),
        IndexState::Refused(e) => return Err(GameRefusal::Index(e)),
        IndexState::Current(c) => c,
    };
    let topos = topo::topos_for(&catalog, app_id);
    if topos.is_empty() {
        return Ok(Lookup::NoTopo { seq: catalog.seq() });
    }
    let app_path = AppDir::path_of(sys).ok();
    let table = GpuArchTable::builtin().ok();
    let profile = hw::read(sys, table);
    with_game(sys, g.fr(), &GameRef::Steam(app_id), |game, steam_app| {
        // P4-10 (R5): an executable a live laa_patch changed still counts as its build.
        let patched = crate::exec::patched_now(dir, game.id());
        let mut cache = cache;
        let read: Vec<(&Topo, GameFacts)> = topos
            .iter()
            .map(|t| {
                let facts = match cache.as_deref_mut() {
                    Some(c) => c.facts(game, app_id, *catalog.sha256(), t, &patched),
                    None => topo::read_game_with(game, t, &patched),
                };
                (*t, facts)
            })
            .collect();
        // Review follow-up 4: retired Topos are listed, never chosen.
        let (retired, selection) = topo::select(read);
        let retired = retired.into_iter().cloned().collect();
        let found = match selection {
            Selection::NoMatch(live) => {
                Found::NoMatch(live.into_iter().map(|(t, r)| (t.clone(), r)).collect())
            }
            Selection::Several(several) => {
                Found::Several(several.iter().map(|t| t.id.to_string()).collect())
            }
            Selection::One(t, r) => Found::One(f(Matched {
                game,
                steam_app,
                topo: t,
                read: &r,
                profile: &profile,
                table,
                catalog: &catalog,
                app_path: app_path.as_ref(),
            })),
        };
        Lookup::Read { retired, found }
    })
    .map_err(GameRefusal::Game)
}

/// What the engine says about one variant, owned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VariantView {
    /// The variant.
    pub variant: Variant,
    /// Why it cannot be planned here (the first refused step).
    pub refused: Option<Refusal>,
    /// Step kinds the anti-cheat rule warns about.
    pub warned: Vec<StepKind>,
}

/// What the engine says about one issue, owned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssueView {
    /// The issue.
    pub issue: Issue,
    /// Its `when` on this system.
    pub when: Tri,
    /// Its variants.
    pub variants: Vec<VariantView>,
}

/// The engine's report ([`topo::Report`]), owned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedReport {
    /// The Topo.
    pub topo: Topo,
    /// The executable that identifies the game.
    pub main_exe: Option<RelPath>,
    /// The launch, resolved.
    pub launch: Result<LaunchPlan, LaunchProblem>,
    /// The anti-cheat rule.
    pub anti_cheat: AntiCheatState,
    /// Every issue, in the Topo's order.
    pub issues: Vec<IssueView>,
    /// GPU conditions are unknown where several adapters differ (P4-11).
    pub several_gpus: bool,
}

impl From<Report<'_>> for OwnedReport {
    fn from(r: Report<'_>) -> Self {
        Self {
            topo: r.topo.clone(),
            main_exe: r.main_exe,
            launch: r.launch,
            anti_cheat: r.anti_cheat,
            issues: r
                .issues
                .into_iter()
                .map(|i| IssueView {
                    issue: i.issue.clone(),
                    when: i.when,
                    variants: i
                        .variants
                        .into_iter()
                        .map(|v| VariantView {
                            variant: v.variant.clone(),
                            refused: v.refused,
                            warned: v.warned,
                        })
                        .collect(),
                })
                .collect(),
            several_gpus: r.several_gpus,
        }
    }
}

/// One issue a [`Fix`] solves, with the evidence of that issue's variant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Solved {
    /// The issue.
    pub issue: String,
    /// Its `when` here: `No` refuses this issue only, not the fix.
    pub when: Tri,
    /// How well the variant is tested for this issue.
    pub status: VariantStatus,
    /// Where it comes from, for this issue.
    pub sources: Vec<Source>,
    /// Its side effects as this issue's copy names them (rule 5: shown before the apply).
    pub tradeoffs: Vec<String>,
}

/// One fix = one variant ID of the Topo, with every issue that names it (plan P5 §3, option B).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fix {
    /// The variant ID.
    pub variant: String,
    /// `fix` or `enhancement` (the same in every copy, P5-4).
    pub kind: Kind,
    /// Every issue that names the ID, in the Topo's order.
    pub solves: Vec<Solved>,
    /// Why the variant cannot be planned here (anti-cheat, the launch). Per variant: the engine
    /// assesses a variant by its steps only, and every copy has the same steps (P5-4). A refusal
    /// of one issue (`when`) is [`Solved::when`].
    pub refused: Option<Refusal>,
    /// Step kinds the anti-cheat rule warns about (per variant, as `refused`).
    pub warned: Vec<StepKind>,
}

/// The fixes of a report, grouped by variant ID in the order of first appearance. The loader
/// makes every copy of an ID identical in `kind` and `steps` (P5-4, `catalog::check`), so the
/// first copy speaks for the fix and later copies add only the issue they solve.
pub fn fixes(r: &OwnedReport) -> Vec<Fix> {
    let mut out: Vec<Fix> = Vec::new();
    for i in &r.issues {
        for v in &i.variants {
            let id = v.variant.id.to_string();
            let solved = Solved {
                issue: i.issue.id.to_string(),
                when: i.when,
                status: v.variant.status,
                sources: v.variant.sources.clone(),
                tradeoffs: v.variant.tradeoffs.clone(),
            };
            match out.iter_mut().find(|f| f.variant == id) {
                Some(f) => {
                    debug_assert!(
                        f.kind == v.variant.kind && f.refused == v.refused && f.warned == v.warned,
                        "the loader makes every copy of {id} the same fix (P5-4)"
                    );
                    f.solves.push(solved);
                }
                None => out.push(Fix {
                    variant: id,
                    kind: v.variant.kind,
                    solves: vec![solved],
                    refused: v.refused,
                    warned: v.warned.clone(),
                }),
            }
        }
    }
    out
}

/// The one Topo that matched, with the engine's report and its fixes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchView {
    /// The engine's report.
    pub report: OwnedReport,
    /// What was read from the game folder for the Topo.
    pub read: GameFacts,
    /// The fixes, grouped by variant ID.
    pub fixes: Vec<Fix>,
}

/// One game: what the Topo lookup found.
#[derive(Debug)]
pub struct GameView {
    /// The Steam app.
    pub app_id: u32,
    /// The lookup.
    pub lookup: Lookup<Box<MatchView>>,
}

/// The game `app_id` (module docs).
pub fn game(g: &Guarded<'_>, app_id: u32) -> Result<GameView, GameRefusal> {
    game_cached(g, app_id, None)
}

/// [`game`], with the executables served from `cache` while their files keep their identity
/// (and put into it otherwise).
pub fn game_cached(
    g: &Guarded<'_>,
    app_id: u32,
    cache: Option<&mut GameCache>,
) -> Result<GameView, GameRefusal> {
    let lookup = with_topo(g, app_id, cache, |m| {
        topo::report(m.topo, &m.facts()).map(|r| {
            let report = OwnedReport::from(r);
            let fixes = fixes(&report);
            Box::new(MatchView {
                report,
                read: m.read.clone(),
                fixes,
            })
        })
    })?;
    let lookup = match lookup {
        Lookup::NoIndex => Lookup::NoIndex,
        Lookup::NoTopo { seq } => Lookup::NoTopo { seq },
        Lookup::Read { retired, found } => Lookup::Read {
            retired,
            found: match found {
                Found::NoMatch(v) => Found::NoMatch(v),
                Found::Several(v) => Found::Several(v),
                Found::One(r) => Found::One(r.map_err(GameRefusal::Engine)?),
            },
        },
    };
    Ok(GameView { app_id, lookup })
}
