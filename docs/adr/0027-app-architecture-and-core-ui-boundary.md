# ADR 0027 · App architecture and the core–UI boundary

**Status:** Proposed · 2026-11-11 · extends ADR 0003, ADR 0016, ADR 0019, ADR 0020, ADR 0023, ADR 0024 · phase 5, steps P5-1 to P5-6 and P5-10 · the UI framework is ADR 0026 (Slint); this ADR names none

## Context
Phase 5 adds a Rust-native Windows app (`docs/07-ui.md`, layout C) that shows the library, a game, the applied fixes, the history, the system and the settings against the real core, and leads every change through preview → apply → revert (with a preview). Plan P5 found:

- **The CLI holds flow logic, not only output.** The order of the guards, the index state, the Topo choice and the engine call (`topo.rs`), "Rerun's folder only when the plan is stored" and `AppDirMoved` (`plan.rs`), the revert gates (`Forgotten`, `Closed`, `Empty`, `Damaged`), `revert_check` before `verify`, the cleanup question, the closing line, the profile holders and the X12 fates (`txn.rs`), the launch view and the prompt lines (`preview.rs`). An app that rebuilds this drifts from the CLI on exactly the paths rules 2, 5 and 6 depend on.
- **Revert is per transaction, the mockup per fix.** One "Apply" with two fixes is one plan and one transaction; the core cannot take one fix of it back alone (user decision U1).
- **The UAC dialog needs an owner window.** `WinElevation::run_helper` takes `GetConsoleWindow()` as the owner (`sys/win/elevation.rs`); from a GUI the dialog would have none and can open behind the window.
- **Core errors are English `Display` texts only** (the accepted localisation leftover of ADR 0016); a German UI needs typed refusals.
- **One fix, several issues.** A Topo may list the same variant under two issues (EaglePatch for Assassin's Creed: `controller/eaglepatch` and `online-services/eaglepatch`, identical steps). The engine already plans a package picked twice once (test `tk_twice_once_and_requires_in_the_plan`), and `elevate::derive` refuses a doubled executable (fail closed); the UI must not offer the fix twice.
- **The framework is ADR 0026** (Slint since 2026-11-11). Everything above the framework stays decidable and testable without it, so that a later switch replaces only the `ui` layer.

## Decision

### Crates and ownership
```
crates/
  rerun-core/   + flow       typed flows shared by the CLI and the app; no text, never asks
  rerun-cli/    a renderer over flow: messages, Out, confirm, the exit mapping and the flags stay here
  rerun-app/    planned, binary rerun-app.exe: worker, vm, text, theme, settings, ui
  rerun-launch/ rerun-helper/ rerun-cpu/ rerun-proto/ rerun-workbench/   unchanged
app/            the Tauri skeleton, removed in P5-3 (ADR 0026 decided)
```
- Dependencies: `rerun-app → rerun-core` (and `rerun-proto`), never back. Only `rerun-app::ui` names the framework (source rule test). `rerun-helper` never names `flow` (its source rule grows by one name, also as a whole word after `rerun_core`).
- `flow` is a **module of `rerun-core`**, not a crate: it has two users today, and a crate boundary would add nothing but a second public API to keep stable.

### `rerun_core::flow`
`flow` returns typed results, holds no user-facing text and never asks. It decides nothing the core does not already decide: it orders the existing calls (`exec`, `plan`, `topo`, `catalog`, `pkg`) as the CLI orders them today, and every check runs again under the journal lock as before. Signatures are a sketch; names may change in the step, the behaviour may not.

```rust
pub struct Env<'a> { pub sys: &'a dyn System, pub http: &'a dyn Http, pub install: &'a Result<PathBuf, String> }

/// The guards every command runs first, in the CLI's order: elevation (E3), forbidden roots,
/// Rerun's folder opened if it exists, never created.
pub struct Guarded<'a> { env: Env<'a>, fr: ForbiddenRoots, app: Option<AppDir<'a>> } // getters; only `guard` builds one
pub enum Gate { Elevated(Refusal), InstallUnknown(String), Forbidden(RootError), AppDir(RootError) }
pub fn guard<'a>(env: Env<'a>) -> Result<Guarded<'a>, Gate>;
/// Read-only parts of `guard` without the elevation check (amendment P5-1): only for the CLI's
/// elevated read commands (`scan`; `status`, `index show`).
pub fn forbidden_roots(sys: &dyn System, install: &Result<PathBuf, String>) -> Result<ForbiddenRoots, Gate>;
pub fn open_app(sys: &dyn System) -> Result<Option<AppDir<'_>>, Gate>;

// ---- read side
pub enum IndexState { None, Current(CatalogFacts), Refused(IndexError) }
pub struct GameRow { pub app_id: u32, pub name: Shown<'static>, pub state: AppState,
                     pub api: Option<GraphicsApi>, pub topo: TopoMatch, pub live: Vec<TxnId> }
pub enum TopoMatch { NoIndex, NoTopo, NoMatch(Vec<ExeLine>), Several(Vec<Id>), Matched(MatchFacts) }
pub fn library(g: &Guarded, on_row: &mut dyn FnMut(GameRow)) -> LibraryFacts; // streamed, never fails as a whole

pub struct GameView { pub row: GameRow, pub report: Option<OwnedReport>, pub fixes: Vec<Fix>,
                      pub last_launch: Option<LaunchResult>, pub live: Vec<TxnSummary>, pub warnings: Vec<Warning> }
/// One fix = one variant ID of the Topo, with every issue that names it.
pub struct Fix { pub variant: Id, pub kind: Kind, pub solves: Vec<Solved>, pub packages: Vec<PackageNeed>,
                 pub refused: Option<VariantRefusal>, // per variant: anti-cheat, package, admin-only folder
                 pub warned: Vec<StepKind>, pub needs_helper: bool }
pub struct Solved { pub issue: Id, pub when: When3,   // per issue: `when = no` refuses this issue only
                    pub status: VariantStatus, pub sources: Vec<Source> }
pub fn game(g: &Guarded, app_id: u32) -> Result<GameView, GameRefusal>;

pub struct StatusView { pub txns: Vec<TxnStatus>, pub holders: Vec<Holder>, pub launch: Vec<LaunchResultEntry>,
                        pub orphans: Result<Vec<OrphanRule>, OrphansError> }
pub fn status(g: &Guarded) -> Result<StatusView, JournalError>;

// ---- write side: plan (reads only) → the caller shows → store → apply
pub struct Planned { bytes: PlanBytes, pub hash: PlanHash, pub preview: Preview, pub shadows: Vec<Shadow>,
                     pub prompt: Option<PromptState>, pub launch: Option<LaunchView>, pub warnings: Vec<Warning> }
pub fn plan(g: &Guarded, app_id: u32, picks: &[Pick]) -> Result<Planned, PlanRefusal>; // stores nothing
/// Naming convention, not a guarantee: the bytes whose preview the caller rendered.
pub struct Previewed { bytes: PlanBytes, hash: PlanHash }
pub fn shown(p: Planned) -> Previewed;                                          // called after rendering p.preview
pub fn store(g: &Guarded, p: &Previewed) -> Result<PlanHash, StoreError>;       // creates Rerun's folder; AppDirMoved
pub fn load_stored(g: &Guarded, h: &PlanHash) -> Result<Planned, PlanRefusal>; // the CLI's `apply <hash>`
pub fn check(g: &Guarded, p: &Previewed) -> Result<usize, Refusal>;            // exec::check
pub fn apply(g: &Guarded, p: Previewed) -> Result<Outcome, ApplyError>;        // stores if needed, then exec::apply

pub enum RevertGate { Forgotten, Closed(Closing), Empty, Blocked, Refused(Refusal) }
pub struct RevertPreview { pub txn: TxnId, pub status: TxnStatus, pub verified: Verified, pub fates: Vec<Fate>,
                           pub launch_option: Option<X12>, pub prompt: Option<PromptState>, pub cleanup: CleanupAsk }
/// The transaction and a digest of the `Verified` fates that were shown.
pub struct RevertShown { txn: TxnId, fates: [u8; 32] }   // likewise RebindShown, ForgetShown
pub fn revert_preview(g: &Guarded, t: &TxnId) -> Result<(RevertPreview, RevertShown), RevertGate>;
pub fn revert(g: &Guarded, s: RevertShown) -> Result<RevertOutcome, ExecError>;
pub fn rebind_preview(g: &Guarded, t: &TxnId) -> Result<(RebindPreview, RebindShown), RevertGate>;
pub fn rebind(g: &Guarded, s: RebindShown) -> Result<RevertOutcome, ExecError>;
pub fn forget_preview(g: &Guarded, t: &TxnId) -> Result<(ForgetPreview, ForgetShown), RevertGate>;
pub fn forget(g: &Guarded, s: ForgetShown) -> Result<(), ExecError>;

// ---- packages and the index
pub struct PackageNeed { pub id: Id, pub version: String, pub tier: Tier, pub license: String,
                         pub downloads: Vec<Download>, pub unpacked: bool }
pub struct Progress { pub url_ix: usize, pub read: u64, pub announced: Option<u64> }
pub fn fetch(g: &Guarded, need: &PackageNeed, on: &mut dyn FnMut(Progress), cancel: &AtomicBool)
    -> Result<Vec<Unpacked>, FetchError>;                                      // download + extract (P5-5b)
pub fn index_import(g: &Guarded, index: &Path, sig: &Path) -> Result<CatalogFacts, IndexError>;
pub fn index_import_bytes(g: &Guarded, index: &[u8], sig: &[u8]) -> Result<CatalogFacts, IndexError>; // the shipped index
```

- **No text, no question.** `flow` returns values; the CLI turns them into `messages` and asks through `confirm`, the app into view models and dialogs. Refusals the user meets often are typed (the game runs, Steam is updating, anti-cheat, an admin-only folder, the helper missing or unsafe, a slot taken, a file held, a foreign change, the index refused, offline); anything else is shown as a generic localized message with the core's English text (escaped) as detail.
- **Guard order.** `guard` runs the CLI's order unchanged: elevation first (an elevated process reads nothing), then the forbidden roots (fail closed), then Rerun's folder opened, never created (review S6 of P2-13). The CLI's elevated read commands (user decision E3) take the read-only parts `forbidden_roots` and `open_app` instead, each only the part it needs (amendment P5-1); `rerun-app` never calls them (source rule).
- **`Guarded` per job.** Every job builds its own `Guarded`: forbidden roots and the `AppDir` handle are fresh, since Rerun's folder can appear (a CLI run) or vanish between two clicks. Nothing of it is kept for the session.
- **Plan, shown, store, apply.** `plan` reads only and stores nothing; the app stores a plan only when it is applied (S6: looking at fixes never creates Rerun's folder), the CLI's `plan` stores at once as today. `Previewed` owns the `PlanBytes`, so what is stored and applied is exactly the bytes whose preview was built. The CLI path is `load_stored` → render → `shown` → ask → `apply`; the app path is `plan` → render → `shown` → click → `apply`.
- **Revert, rebind and forget have a preview too.** `*_preview` runs every check of the operation read only (`revert_check`, `rebind_check`, `verify`) and returns the fates per op, the X12 lines, the prompt state and the cleanup question. `RevertShown`, `RebindShown` and `ForgetShown` carry the transaction and a SHA-256 digest of the fates that were shown; the operation observes again under the lock and returns `Changed` (nothing written, show the preview again) when the fates differ. The closing-line logic of the CLI moves into `revert`.
- **Proof types are a naming convention, not a guarantee.** `shown()` is a free function: nothing can prove that a caller rendered the preview, so `Previewed` and `*Shown` do not make rule 5 a type rule. They make "this preview → exactly these bytes, this observation" the convenient and the only API path: there is no `apply` that takes a hash alone, no `Previewed` without `shown`, no `revert` without a preview. rustdoc `compile_fail` doctests pin that (no `trybuild`, no new dependency). Rule 5 itself rests on the renderers (the CLI's golden tests, the app's view-model tests) and on the core's re-checks under the lock.
- **`fetch`** becomes public with P5-5b (`pkg::download::fetch_with`, crate-private today, gains progress and cancellation). A cancel takes effect at the next read, up to 30 s (WinHTTP's receive timeout); a cancelled fetch keeps nothing in the cache (ADR 0025, the temp file is deleted).
- **The executable hash.** A Steam update during an app session must not let a plan for the old build apply. `flow::plan` hashes the executables again on every call (no session cache for planning) or the matched hash goes into the plan; decided in P5-2a (ADR 0020 amendment).

### The CLI becomes a renderer
- `rerun-cli` keeps `messages`, `out`, `confirm`, the `Exit` mapping and the flags (`--dry-run`, `--yes`, `--rebind`); its command modules call `flow` and render. Exit codes and output stay exactly as ADR 0016 and its amendments fix them.
- Acceptance of the extraction: every existing CLI test passes unchanged (the golden output is the parity test). Since both sides use `flow` afterwards, a parity test written later would have no bite: before the rebuild (P5-1) a golden plan of a fake world (bytes and hash) is frozen, and P5-2a must still produce it.
- The CLI stays English (its own catalogue, `messages`).

### `rerun-app` (planned)
```rust
// worker.rs: one thread for the session; owns WinSystem and WinHttp; one job at a time
pub enum Job { Library, Game(u32), Plan { app_id: u32, picks: Vec<Pick> }, Apply(Previewed),
               RevertPreview(TxnId), Revert(RevertShown), RebindPreview(TxnId), Rebind(RebindShown),
               ForgetPreview(TxnId), Forget(ForgetShown), Fetch(PackageNeed), Status, System,
               IndexImport { index: PathBuf, sig: PathBuf }, Settings(SettingsChange) }
pub enum Event { Row(GameRowVm), LibraryDone(LibraryVm), Game(GameVm), Preview(PreviewVm),
                 WaitingForUac, Progress(ProgressVm), Result(ResultVm), Status(StatusVm), Failed(ErrorVm) }
pub trait Wake: Send + 'static { fn wake(&self); }  // how the framework learns that an event is waiting
pub struct Worker { /* job and event channels, cancel and busy flags */ }
impl Worker { pub fn start(owner: PromptOwner, wake: Box<dyn Wake>) -> Self; pub fn send(&self, j: Job);
              pub fn poll(&self) -> Option<Event>; pub fn busy_writing(&self) -> bool; pub fn cancel(&self); }

// vm.rs: pure; flow results + Lang → view models
pub fn game_vm(v: &GameView, sel: &SelectionState, lang: Lang) -> GameVm;
pub fn preview_vm(p: &Planned, lang: Lang) -> PreviewVm;
pub fn revert_vm(r: &RevertPreview, lang: Lang) -> RevertVm;

// text.rs: the typed catalogue
pub enum Lang { En, De }
pub enum Msg<'a> { HeroNoTopo, HeroFixesAvailable { problems: u16, fixes: u16 }, /* … */ }
pub fn t(lang: Lang, m: &Msg<'_>) -> Cow<'static, str>; // one exhaustive match per language

// theme.rs: framework-free tokens; ui maps them
pub enum ThemeId { Mythen, Nacht, Kontrast }
pub enum Accent { Stein, Stahl, Sand }                  // ignored by Mythen
pub enum Density { Normal, Kompakt }
pub fn tokens(t: ThemeId, a: Accent, d: Density, high_contrast_os: bool) -> Tokens;

// settings.rs: <AppDir>\app\settings.json
pub struct Settings { pub format: u32, pub lang: Option<Lang>, pub theme: ThemeId, pub accent: Accent,
                      pub density: Density, pub view: LibView, pub group: bool, pub images: bool,
                      pub first_run_seen: bool, pub window: Option<WindowRect> }
```

- **Worker.** One thread for the whole session owns `WinSystem` and `WinHttp`; jobs run one at a time in the order sent, so the app never runs two core operations at once and never holds the journal lock across a user's think time. The UI thread never touches the system. A scan and Topo hashing run there, rows are streamed. Per session the worker keeps the read facts of each game (cleared by "scan again"); nothing is cached on disk.
- **View models are framework-free.** `vm` turns `flow` results into plain structs with every string already localized; the `ui` module only lays them out. View models are tested without a window, in en and de.
- **i18n: an own typed catalogue, no Fluent.** Every message is an enum variant with typed parameters; one exhaustive `match` per language makes a missing translation a compile error. Tests: no empty text, placeholder parity, the copy rules of `docs/07-ui.md` (no `!`, no superlatives, German with "du" and "ss"). The default language is Windows' display language if it is German, else English. This closes ADR 0016's open point "Localisation" for the app (it named Fluent).
- **Theme tokens.** Colours, radii, spacing, row height and fonts as values; the first themes are Mythen (default), Nacht and Kontrast (user decision U8 a), Windows' high contrast is followed automatically, Mica and Acrylic only if the framework offers them without own `unsafe`. Every text/background pair of every theme has a contrast of at least 4.5:1 (test).
- **Settings.** `<AppDir>\app\settings.json`, format 1, read bounded with `deny_unknown_fields`; a broken or oversized file means the defaults, never an error dialog. It needs a new `AppSub` and a public write path in `policy::root` (both crate-private today). It is written only on a real change: opening and closing the app never creates Rerun's folder (S6). It is Rerun's own state like the index store and the package cache, not a change to the system, so it is not journaled. Rerun's data folder is fixed at `<LocalAppData>\Rerun` (user decision U6 a); the app only shows it.
- **Untrusted text (ADR 0016).** View models carry untrusted fields (Steam names, paths, error details) only as `escape::Shown`; `rerun-app` never calls `as_raw_str` (source rule, as for the CLI). The UI isolates the direction of untrusted text (ADR 0016: the escape does not replace bidi isolation); the means is the framework's (ADR 0026).
- **The UAC owner.** A core change (win32-systems): `WinSystem::with_prompt_owner(PromptOwner)` (a raw window handle) makes the app window the owner of the helper's consent dialog; without it the console window as today. The framework must expose its window handle (an ADR 0026 criterion).
- **Opening links and folders.** One wrapper in `sys::win` for "report a problem", source links and "open in Explorer": only `https` URLs of the signed index that pass `policy::url`, Explorer only for Rerun's folder; a ban-list entry and a `clippy` exception there (security review in P5-5a).
- **Process hardening** as for every shipped executable: `restrict_dll_search` is the first statement, `/DEPENDENTLOADFLAG:0x800`, an `asInvoker` manifest with `PerMonitorV2`; the release binary is checked for neither the index test key nor `index-test` (a `test-key` feature as in the CLI, never shipped).
- **Accessibility** is a requirement on the UI layer that ADR 0026 must meet: every control with name and role through UI Automation, full keyboard use, state always as symbol and word, motion only when Windows allows it, text size following Windows scaling.

### The core rules the app keeps
1. **Nothing in the background** (ADR 0003). The worker lives exactly as long as the window; no tray, no autostart, no second process. Closing the window while `busy_writing` is refused with "Rerun finishes the running operation first"; a download is cancelled. A crash during an apply is the journal's case (ADR 0019): the next start shows the open transaction.
2. **Every change reversible.** The app writes only through `flow::apply`, `revert`, `rebind` and `forget`, i.e. through `exec` and the journal. The unit of revert is the transaction (user decision U1 a): a card lists every fix in it and says before the click that changing one of them later means reverting the whole transaction, launch profile included.
3. **The GUI is never elevated** (rule 6). An elevated or undeterminable process gets one blocking page ("Rerun runs as administrator. Start it normally.") and reads nothing; E3's exception for reading commands is the CLI's only. Admin parts go the CLI's way (`exec::apply` → `exec::helper` → `elevate::client::start`); the app never starts anything elevated itself.
4. **Preview before apply and before revert** (rule 5): the app reaches `apply` only with a `Previewed`, and `revert`, `rebind`, `forget` only with their `*Shown`; a change between preview and click is `Changed` and shows the preview again.
5. **Settings written only on a real change**; opening, browsing and closing write nothing and create no folder.

### One fix across issues (user decision U2 a)
- The fix identity is the variant ID. `flow::game` groups by it: one `Fix` per ID with one `Solved` per issue that names it. Evidence (`status`, `sources`, `tradeoffs`) stays per issue; a refusal is per issue (`when = no` refuses that issue only) and per variant (anti-cheat, a package, an admin-only folder).
- **Loader rule** (`catalog::check::topo`, `Rules::Source` and `Release`): the same variant ID in several issues of one Topo must have identical `steps` and `kind`; otherwise the Topo does not load. There is no converse rule (different IDs may have equal steps). No format or schema change: the YAML keeps its duplicate, the loader catches drift (ADR 0024 amendment and `docs/02-topo-format.md` with P5-4).
- **No dedupe in the engine or the helper** until a shared fix holds a `firewall_rule` or a CPU step: the engine plans a doubled package once already, and the existing chain refuses a doubled helper op (fail closed).

## Alternatives
- **`flow` as its own crate:** a boundary with two users that already share `rerun-core`; it would make every flow type a cross-crate API without gaining isolation. Revisit only if a third front end appears.
- **The app re-implements the flows:** the CLI and the app would diverge on the guard order, the revert gates and S6, the paths the core rules depend on.
- **The app calls `rerun.exe` with `--json`:** a second process per click, a versioned output format with no other consumer (ADR 0016), and the preview would cross a process boundary as text.
- **Proof types as a rule-5 guarantee (sealed tokens):** impossible without the core seeing the screen; claiming it would overstate the protection. **`trybuild`** for the compile-fail checks: a new dependency for what `compile_fail` doctests do.
- **`Guarded` per session:** stale forbidden roots and a stale `AppDir` handle after a CLI run created or removed Rerun's folder.
- **An async runtime or a thread pool:** the core is synchronous and the journal admits one writer; one worker thread gives the same responsiveness without a dependency and without two operations racing.
- **View models in the framework's types:** untestable without a window and tied to the framework of ADR 0026.
- **Fluent for i18n:** a dependency and run-time lookups; a missing German string shows only at run time. Two languages with typed parameters fit a `match`.
- **Store the plan when the preview is built:** every look at a fix would create Rerun's folder and leave plan files (against S6).
- **One fix across issues by identical steps (no rule),** or **a `fixes:` section in the format:** the first lets two copies drift unnoticed, the second changes schema, loader, engine, workbench, helper derivation and every Topo (user decision U2 a against both).

## Consequences
- `rerun-core` gains `flow` (P5-1 read side, P5-2a plan/store/apply, P5-2b revert/rebind/forget, P5-5b `fetch`), a public settings write path with a new `AppSub` (P5-10) and `WinSystem::with_prompt_owner` (P5-5c, ADR 0023 amendment). The CLI's command modules shrink to rendering; its tests stay as they are.
- `rerun-app` is created in P5-3, after ADR 0026 and this ADR are accepted; `app/` is removed then. New source rules: `rerun-app` names neither `flow::forbidden_roots`, `flow::open_app`, `ForbiddenRoots::resolve` nor `AppDir::open` (a `Guarded` comes only from `guard`), nor `as_raw_str`, and no framework outside `ui`; `rerun-helper` never names `flow`.
- Tests: `flow` against the fake world (the guard order: elevated means nothing read; AC1 shows EaglePatch once with two `Solved`; a Steam update between preview and apply is refused; a state change between revert preview and click is `Changed` with nothing written); the frozen golden plan; `compile_fail` doctests; view models in en and de without a window; worker order, cancellation, closing while writing, waiting for UAC (fake elevation); theme contrast; the loader rule fixtures; hardening checks on the built `rerun-app.exe`. Details in `docs/09-testing.md` with the steps.
- Docs with the steps: `docs/01-architecture.md` (workspace, `flow`, the frontend section), `docs/07-ui.md`, `docs/08-roadmap.md` (phase 5), `docs/02-topo-format.md` (fix identity), `docs/06-security.md` (the GUI process, the settings file, links), `docs/09-testing.md`; ADR 0016 (the GUI display), ADR 0020 (the executable hash), ADR 0023 (the prompt owner), ADR 0024 (the loader rule) amended; ADR 0001 superseded by ADR 0026.

## Open points
- The executable hash: rehash in `flow::plan` or record it in the plan (P5-2a, ADR 0020 amendment).
- ADR 0026 must show that the framework exposes its window handle, runs with the System32-only DLL search and `/DEPENDENTLOADFLAG:0x800`, starts its window in under 1 s, runs without a GPU (WARP) and is read by Narrator. A framework that fails one of these is out.
- The size limit of the settings file is fixed with P5-10.
- The CLI and the app at once: the journal lock keeps them apart; the app reloads its views after every write and when "Applied" gains focus, and a held lock is the message "another Rerun operation is running".
- Which core errors get their own typed refusal beyond the list above follows from the view-model tests; the rest stays generic with the English detail.

## Amendment P5-1 (2026-11-11): the read side as built

The read side of `flow` exists (P5-1); where it differs from the sketch above, this holds:

- **No `guard_read`.** The CLI's read commands each need a different part of the guards today (`scan` the forbidden roots without Rerun's folder, `status` and `index show` Rerun's folder without the forbidden roots, none of them the elevation check); one `guard_read` would have changed their behaviour on errors. They take the read-only parts `forbidden_roots(sys, install)` and `open_app(sys)`, documented as skipping E3. `Guarded` has private fields with getters (`env`, `fr`, `app`, `into_app`): only `guard` builds one. The planned source rule of `rerun-app`: it names neither `flow::forbidden_roots`/`flow::open_app` nor `ForbiddenRoots::resolve`/`AppDir::open`, and builds no `Guarded` but through `guard`.
- **Signatures.** `library(sys, fr, app_ids, hashes, on: &mut dyn FnMut(LibraryEvent) -> ControlFlow<B>) -> Result<LibraryFacts, B>` (the caller may stop the stream, e.g. a closed output; `LibraryFacts` = counts and the missing app IDs); `status(sys, &AppDir) -> Result<StatusView, JournalError>`; `index_state(Option<&AppDir>) -> IndexState` with `Current(Box<Catalog>)` and `Refused(StoreError)`.
- **`game`.** `GameView = { app_id, lookup: Lookup<Box<MatchView>> }` (`Lookup`: no index, no Topo, or the Topos read: retired ones aside, then no match, several, or one `MatchView` = the owned report, what was read, the fixes). `GameRow`, `TopoMatch`, `live`, `last_launch` and `warnings` follow in P5-3. `with_topo` (the same lookup with a closure on the one match) is public as a transition, for the CLI's `--pick`, until `flow::plan` (P5-2a).
- **`Fix`.** Variant and issue IDs as `String`; `packages` and `needs_helper` follow (P5-5); `refused` and the warned kinds are per variant: since P5-4 the loader makes every copy of an ID identical in `kind` and `steps` (ADR 0024 amendment P5-4), and the engine assesses a variant by its steps only, so the first copy speaks for the fix (the fail-closed merge of P5-1 is gone).
- **Untrusted text.** `flow` returns Topo and Steam text as the core holds it; it reaches the app's view models only as `Shown`: the escape happens in the view-model mapping, not in `flow` (as the CLI escapes in its renderers).

## Amendment P5-2a (2026-11-12): the write side of a plan as built

`flow::write` holds the write side of a plan (P5-2a); where it differs from the sketch above, this holds:

- **Signatures.** `plan(g, app_id, picks: &[Pick]) -> Result<Lookup<Picked>, GameRefusal>` (the lookup of `game`; on the one Topo that matches `Picked { topo, index, planned: Result<Planned, PlanRefusal> }`, `PlanRefusal` = the user data folder, the engine or the encoding); `plan_steps(g, &StepFile) -> Result<(Planned, Vec<StepKind>), StepsRefusal>` (the step file read by the caller; the step-file path moved too, so no public constructor of a `Planned` from raw bytes exists); `shown(Planned) -> Previewed`; `store(&mut Guarded, &Previewed) -> Result<PlanHash, StoreRefusal>` (`Empty`, `NoAppDir`, `AppDir`, `AppDirMoved`, `Store`; the folder it creates stays in the `Guarded`); `load_stored(g, &PlanHash) -> Result<Planned, LoadRefusal>`; `check(g, &Previewed) -> Result<usize, Refusal>`; `apply(g, Previewed) -> Result<Outcome, ApplyError>`. `with_topo` and `with_game` are `pub(crate)` and `Guarded::into_app` is gone (review of P5-2a; `store` keeps the folder in the `Guarded`): no caller outside `flow`.
- **`Planned` is read through getters** (`preview()`, `shadows()`, `warnings()`, `hash()`, `ops()`; review of P5-2a): its fields are private, so a caller cannot swap the preview it shows for the preview of other bytes.
- **`Solved.tradeoffs`** (review of P5-2a, rule 5): each issue's copy of a fix carries its own `tradeoffs` (the loader of P5-4 keeps them per issue), so the app shows every side effect of a fix before the apply.
- **`index_import(_bytes)` is not in P5-2a:** the import of a signed index through `flow` moves to the slice that ships the embedded index (P5-13, user decision U5) or the index import of the settings (P5-10), whichever comes first; `rerun index import` keeps its own path until then.
- **`Planned`** holds the bytes privately with `preview`, `shadows` (VirtualStore, P3-7) and the engine's `warnings`, all decoded from those bytes (`preview_with_shadows`, the rules of the apply); `Previewed` owns the bytes, the path of Rerun's folder planned with and the op count. Neither can be built outside `flow` (private fields; `compile_fail` doctests: no `Previewed` literal, no `apply` with a plan hash).
- **`check` and `apply` run on the stored plan** of the `Previewed`'s hash (`exec` loads it by that hash and accepts it only if it hashes to it): `store` (or `load_stored`) comes first; without Rerun's folder they are `Refusal::Plan(NotFound)`, nothing written. `apply` does not store on its own: the order plan → shown → store → check → apply is the caller's, so a store refusal is never mixed into `ApplyError`.
- **Left in the CLI:** reading the step file (`read_input`, `StepFile::parse`), the launch view and the prompt lines of the preview (`preview::launch_view`, `helper_lines`, `prompt_lines`); they move with P5-5a when the app shows them.
- **One change of order:** `rerun plan <steps.json>` now runs `flow::guard` (Rerun's folder opened) before it reads the step file; only a run where both fail reports the folder instead of the step file.

## Amendment P5-3b (2026-11-12): the session and the order of jobs as built

Measured on the developer machine with the release-speed test-key build (profile `dev-release`, real `WinSystem`, 40 games in two Steam libraries): a library scan takes 4.5 s (the folder walk and PE parse of each game, about 110 ms per game), a game page 35 to 85 ms (of which hashing the executables 25 to 50 ms), the applied and system pages 16 ms each. The slowness the user felt was mostly the scan in front of every other job (a click on a game or a page waited up to 4.5 s) and the debug build of the first check script; the rest is repeated work.

- **Order.** Jobs still run one at a time on the one worker thread, in the order sent, with one exception: a library scan hands the jobs that already wait the thread between two games (after the row's game folder is closed, `run_in`'s `waiting`), so a click is answered within one game's scan plus its own job. A second `Library` job during a scan stops it (no summary) and runs next. Each nested job builds its own `Guarded`. The scan announces itself with `Event::LibraryStarted`; the window clears the rows of an earlier scan on it (a rescan during a scan used to list games twice).
- **Session** (`worker::Session`, memory only, never on disk; the thread's lifetime): `flow::GameCache` keeps the hashed `ExeCheck`s per app and Topo, valid while the index `seq`, the game folder's identity, the live patches and every `match.exes` file's `Metadata` (length, file ID, attributes, link count) are the same; the anti-cheat listing is read fresh each time. The layer reports no timestamps (`Metadata`), so a file changed in place with the same length and file ID shows its old facts until the next rescan; `flow::plan` and the apply never take a cache and read the files fresh, so the preview and the hash the apply checks are not affected. The system page is kept too (until a rescan). The applied page is **not** kept: another process may apply or revert while the window is open, so every visit reads the journal (16 ms); the window only skips setting a page that equals the one it holds (no flash). The cache key holds the index's SHA-256, not its `seq` (a re-import with the same `seq` invalidates).
- **Open point before P5-5:** `Metadata` has no timestamps, so a patcher that changes an executable in place with the same length keeps the stale facts of the display until the next rescan. Either add `ChangeTime` (`FileBasicInformation`) to `Metadata`, or drop a cache entry when a fresh plan yields different `ExeCheck`s. Not implemented in P5-3b.
- **`flow::game_cached(g, app_id, Option<&mut GameCache>)`** next to `game`; `topo::read_game_with` is split into `read_exes_with` (the hashes) and `read_anti_cheat`.
- **The window** shows the game page at once from the library row (`vm::game_loading`: the title, the row's status as the hero line, its second line, the Steam app fact; the reading text holds the place of the problems and fixes, with room reserved) and sets the worker's page over it; the applied and system pages are set only if they differ from what the window holds (no flash, no rebuilt models on a switch back).
- **Trace.** The test-key build writes timing lines (`[ms since start] worker: game 15100 took 31.0 ms`, `ui: game 15100 clicked` and `shown`) to standard error (`trace.rs`, compiled only with the feature `test-key`); the shipped build has none.

## Amendment P5-2b (2026-11-12): revert, rebind and forget as built

`flow` holds revert, rebind and forget (`flow/revert.rs`); `rerun revert` (`--dry-run`, `--yes`, `--rebind`) and `rerun forget` render them, with every CLI test and golden line unchanged. Where it differs from the sketch above, this holds:

- **Signatures.** `revert_preview(g, &TxnId) -> Result<(RevertPreview, RevertShown), RevertGate>`, `revert(g, RevertShown) -> Result<RevertOutcome, ActError>`; `rebind_preview(g, &TxnId) -> Result<(RebindView, RebindShown), RevertGate>` (`RebindView`: `exec::RebindPreview` keeps its name), `rebind(g, RebindShown) -> Result<RevertOutcome, ActError>`; `forget_preview(g, &TxnId) -> Result<(ForgetPreview, ForgetShown), RevertGate>`, `forget(g, ForgetShown) -> Result<(), ActError>`. `ActError` = `Changed` (nothing written, show the preview again) or `Exec(ExecError)`; the CLI's error notes after a record (`MayHaveClosed`, `BoundNow`, …) stay its own.
- **`RevertGate`** = `NoAppDir`, `NotFound`, `Journal` (unreadable), `Forgotten`, `Closed(Closing)`, `Empty` (an empty transaction without a readable head), `Blocked` (damaged or unreadable), `Refused(Refusal)` (`revert_check`, `rebind_check`, `verify`), `Failed(ExecError)`. Forget takes `Forgotten` and `Closed` as its gates and previews a damaged transaction. A transaction bound already is `Refused(Refusal::Rebind(AlreadyBound))` from `rebind_preview`; the caller reverts it as it is through `revert_preview`.
- **The previews.** `RevertPreview { status, verified, empty, launch_option, prompt, ask }`: the transaction (`TxnStatus`, its id included) and the observation instead of a separate list of fates; `launch_option: Option<LaunchOption { id, fate: ProfileFate }>` is X12 (the fate logic moved from the CLI; `preview::Fate` is now an alias of `flow::ProfileFate`, the texts stay in the CLI); `prompt` is the administrator prompt state while a firewall rule of the head is still there; `ask: RevertAsk` = `Nothing`, `Cleanup(CleanupAsk { n, in_use })` (P2-15) or `Revert { ops }`. `ForgetPreview { status, verified: Option<Result<Verified, ExecError>>, launch_option, revert_would: Option<RevertWould> }` (review S7: a revert would finish it cleanly). `RevertOutcome { report, end: RevertEnd, launch_option }`: the closing-line decision (`Closed`, `Halted`, `InUse(n)`, `Kept`, `Foreign`) and the fate after the revert are `flow`'s; the CLI maps `RevertEnd` to its line and exit code. `fate_before`, `fate_after`, `fate_forget`, `revert_end` and `holding` are public for the renderers' tests.
- **The tokens** carry the transaction and two SHA-256 digests over the `Debug` form of what was shown: the transaction as the journal holds it (`TxnStatus`) and the observation (`Verified`, or for forget why there is none). `Debug` holds every field and is the same for the same state; a digest of a value that cannot be shown would be no stronger. `RebindShown` also carries the binding (`RebindTo`, compared by `exec` as before); `RevertShown` and `RebindShown` carry the launch-profile facts of the shown transaction, since a closed transaction's head is not read again for the fate after the revert.
- **Where it compares.** `exec` gains crate-private `revert_seen`, `revert_rebound_seen` and `forget_seen` (the public `revert`, `revert_rebound` and `forget` call them with "always the same") and `verify_in` (`verify` without the read-side hold, for a caller that holds the lock). Right after the lock is taken, before anything is read for the operation or written (forget: before its helper sweep), `flow` reads the transaction again and, for revert and forget, observes again (`verify_in`); a rebind compares the transaction there and its own observation with the new binding after every check, before its record. A difference is the new core refusal `Refusal::Changed { txn }` ("transaction … changed since its preview; nothing was done; look at it again before you go on"), which `flow` returns as `ActError::Changed` and the CLI prints like any refusal (exit 3) — the only new CLI behaviour, and only in that race. Another process that reverted or forgot meanwhile is `Changed` too (its records changed the status).
- **Cost and rest risk.** A revert observes twice (the preview and under the lock; the hashes of the touched files again). A change by another program after the comparison, while the revert runs, is met by `exec` as before: each op is observed again before it acts, the report marks an op "changed since the preview", and foreign state is left (ADR 0020).
- **Tests.** `flow/revert_tests.rs` FR1 to FR6 (`docs/09-testing.md`); `compile_fail` doctests: no `RevertShown` literal, no `flow::revert` with a transaction ID.
