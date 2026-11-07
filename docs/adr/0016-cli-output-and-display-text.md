# ADR 0016 · CLI output and display of untrusted text

**Status:** accepted · 2026-11-05 · extends ADR 0008, ADR 0012, ADR 0014, ADR 0015 (closes its sanitizer open point)

## Context
Phase 1 step 16 gives `rerun` its first commands: `rerun system` (the system profile, ADR 0015) and `rerun scan` (Steam games and their executables, ADR 0012, ADR 0014). The phase 1 acceptance (`docs/08-roadmap.md`) is read off their output on the developer machine (step 17).

Almost everything they print is untrusted: app names, library labels and paths come from user-writable Steam files and registry values, install folders and executable names from the game folder, adapter names from the driver, the GPU table's `source` texts from data. A name holding ESC, a bidi override, U+2028 or tag characters can rewrite the terminal (cursor moves, forged or hidden lines, window title), reorder or hide text. The core keeps such text raw (`RawText`, ADR 0012) and escapes only error targets (`sys::error::shown_target`); ADR 0011, 0012, 0014 and 0015 left the display to "the output layers (CLI step 16)".

Further findings:
- `clap` 4.6.7 with its default `color` feature writes through `anstream`'s `AutoStream`, which on Windows switches on `ENABLE_VIRTUAL_TERMINAL_PROCESSING` with `SetConsoleMode` on stdout and stderr, and reads `NO_COLOR`, `CLICOLOR`, `TERM` and `CI` (checked in the sources of `clap_builder` 4.6.7 and `anstyle-query` 1.1.5). Console modes and the code page belong to the console, which the parent shell shares; they outlive `rerun`.
- From step 16 `rerun.exe` links all of `WinSystem`, so its static imports become those the test binary `crates/rerun-core/tests/win_gpu_restricted.rs` already pins (`CORE_IMPORTS`), more than the one `SHIPPED_IMPORTS` list grants both shipped binaries (ADR 0008).
- `Dir::open_read` shares read only (ADR 0007): a game file held open by a scan blocks a writer, i.e. a Steam update.
- An `appmanifest_*.acf` holds account data (`LastOwner`, a SteamID).

## Decision

### Commands
- `rerun system` and `rerun scan [APP_ID…] [--hashes]`; nothing else in phase 1.
- Order in `main`: `restrict_dll_search()` stays the first statement (ADR 0008); then clap parses. `--help`, `--version` and usage errors end there, before any registry or file system access. `WinSystem::new()` comes after parsing.

```rust
// rerun-cli (binary crate)
#[derive(Parser)]
struct Cli { #[command(subcommand)] command: Command }

#[derive(Subcommand)]
enum Command {
    /// The system profile: GPU, CPU topology, OS build and the facts Topo conditions see.
    System,
    /// Steam games with their main executable, architecture and graphics API.
    Scan {
        /// Only these Steam app IDs.
        app_ids: Vec<u32>,
        /// Also compute SHA-1 and SHA-256 of the game executables (slow).
        #[arg(long)]
        hashes: bool,
    },
}

enum Exit { Report = 0, Fatal = 1, Usage = 2 }

fn system(sys: &dyn System, out: &mut Out<impl Write>, err: &mut Out<impl Write>) -> Exit;
fn scan(sys: &dyn System, install_dir: &Path, app_ids: &[u32], hashes: bool,
        out: &mut Out<impl Write>, err: &mut Out<impl Write>) -> Exit;
```

`main` builds `WinSystem` and the install folder and calls these; tests call them with `FakeSystem` and in-memory writers. Rendering is pure: `system::render(&SystemProfile, …) -> Vec<Message<'_>>` and `scan::render_game(&SteamApp, &GameExes, …) -> Vec<Message<'_>>` (and the like) take values with public fields and return messages.

### `rerun system`
`GpuArchTable::builtin()`, then `rerun_core::hw::read(&sys, builtin.ok())`. Four blocks:
- **GPU:** every hardware adapter (ADR 0015) with its name, VRAM, `integrated`, and its architecture or `unknown (0xVVVV:0xDDDD not in the table)`; the conditions adapter (`primary()`) is marked; with more than one hardware adapter a note says that conditions use the first in DXGI order and that a game's GPU preference may choose another. "Could not read" (`gpu` is `Err`, with the error's source and kind), "no hardware adapter" and an unknown device are three different lines; a built-in table that fails validation makes every architecture unavailable, with its own line.
- **CPU:** the topology in the form the phase 1 acceptance names, readable without arithmetic: a summary line (`2 L3 groups x 8 cores x 2 threads` on the 5950X) and one line per L3 group with its cores and threads; the efficiency classes and whether the CPU counts as hybrid.
- **OS:** `build.UBR`; the build alone when `UBR` is absent.
- **Conditions:** the five `when` keys with their facts (`Known`, `Unavailable`, `NoAdapter`, `Unknown`, ADR 0015).

### `rerun scan`
1. Rerun's install folder is the parent of `current_exe()`; `ForbiddenRoots::resolve(&sys, install_dir)` fails closed (exit 1, no report).
2. `detect::steam::scan(&sys, &fr)`.
3. Positional app IDs filter the result of `steam::scan` (no name filter). A requested ID that no library holds gets its own "not found" line; the exit code stays 0.
4. Per app, in library and app ID order: an `Installed` app is opened with `SteamLibrary::open_game` and scanned with `scan_game` (name hint: the install folder; `hashes` from the flag), printed as soon as it is done, and its `GameDir` dropped before the next app. The streamed per-game output is the progress indicator; the output holds no timings. Apps in state `UpdatePending` or `NotInstalled` are listed with their state and never opened or hashed: `open_read` shares read only and would block Steam's update.
5. Every issue of the Steam scan and of each game is one line with its location and kind, never file content. At the end a summary of counts and the line `Roles and APIs are hints from names and imports, not verdicts.`

Per game: `GameExes::main` as `One` (the executable), `Tied` (every tied executable, said to be a tie, nothing picked) or `None` with a reason derived from the candidates (no executable found, no game executable among them, every game executable failed to open or parse). The version is only the numbers of the fixed part (`FixedFileInfo`); no `RawText` (version strings, …) is shown in phase 1. Hashes in uppercase hex.

`--hashes` is opt-in; before the scan it writes to stderr: `warning: --hashes reads every game executable in full; can take minutes on a cold cache`.

### Output
- Human-readable text only, explicitly **not a stable interface**. `--json` comes only with a consumer, and then with a format version.
- English only in phase 1. Every user-facing string lives in one module `messages`: enum variants (or functions) with named parameters; counts are parameters, so Fluent plurals can follow; no sentence is assembled by concatenating messages. clap's help texts come from doc comments outside `messages`; accepted for phase 1.
- Static text is ASCII only. No colours, no `NO_COLOR` handling, no terminal width detection, no column alignment over untrusted strings.
- Untrusted fields enter a message only as `escape::Shown<'_>`, which only `rerun_core::escape` can create.
- The writer `Out` writes each line with `writeln!` and handles its result: `BrokenPipe` (a pipe closed early) ends the output silently with exit 0; any other write error is fatal (exit 1). Last-resort net: `Out::line` checks every line for control characters before writing it. It must never hide a missing field escape: in `cfg(test)` a hit panics, and the end-to-end tests assert it never fired (their expected lines carry each field's own escape); in a release build a hit line is escaped as a whole.

```rust
// rerun-cli
struct Out<W: Write> { w: W }
enum OutError { Closed, Io(std::io::ErrorKind) } // Closed = BrokenPipe
impl<W: Write> Out<W> { fn line(&mut self, m: &Message<'_>) -> Result<(), OutError>; }
enum Message<'a> { /* e.g. */ Adapter { name: Shown<'a>, vram_mb: u64, /* … */ }, /* … */ }
```

### Display of untrusted text: `rerun_core::escape`
One explicit table of code points (Unicode 16), no Unicode crate, two entry points.

**Base set** (escaped by both):
- `Cc` (control characters);
- every `Cf` (format) character, supplementary planes included (bidi controls, U+200B to U+200F, U+2060 to U+2064, U+FEFF, U+FFF9 to U+FFFB, U+110BD, U+13430 to U+1343F, U+1BCA0 to U+1BCA3, U+1D173 to U+1D17A, …);
- every `Default_Ignorable_Code_Point`: tags U+E0000 to U+E0FFF, variation selectors (U+180B to U+180D, U+180F, U+FE00 to U+FE0F, U+E0100 to U+E01EF), U+034F, the Hangul fillers (U+115F, U+1160, U+3164, U+FFA0), U+17B4, U+17B5, U+2065, U+FFF0 to U+FFF8;
- U+2028 and U+2029 (line and paragraph separator; ADR 0015 open point);
- supplementary private use (U+F0000 to U+FFFFD, U+100000 to U+10FFFD);
- noncharacters (U+FDD0 to U+FDEF and the last two code points of every plane).

**Entry points:**
- `escape::path`: the base set plus every character `path::is_deceptive` matches (special spaces, BMP private use, full-width ASCII, `¥`/`₩`, slash look-alikes). For `RelPath`, `RootPath` and `SysError` targets; `sys::error::shown_target` delegates to it.
- `escape::text`: the base set only. For app names, library labels, adapter names, the table's `source`, issue texts. Printable confusables are legitimate in names (a title in full-width letters stays readable); what matters for a path's identity does not matter for a label.

**Presentation:** a clean string is shown unchanged (borrowed, no allocation); otherwise the whole string is `{:?}`-quoted and every escapable character it still holds written as `\u{x}`. Idempotent. U+FFFD is kept (it is what `sys::win` already puts for broken adapter names).

```rust
pub mod escape {
    /// Text that went through `path` or `text`; the field is private, there is no other constructor.
    pub struct Shown<'a>(Cow<'a, str>);
    impl fmt::Display for Shown<'_> { /* writes the text */ }
    impl Shown<'_> { pub fn as_str(&self) -> &str; }
    pub fn path(s: &str) -> Shown<'_>;
    pub fn text(s: &str) -> Shown<'_>;
}
// sys::error, unchanged signature:
pub fn shown_target(target: String) -> String; // escape::path(&target), owned
```

`path::is_deceptive` itself is unchanged. The escape does not replace bidi isolation in the phase 5 app: strong right-to-left letters are no control characters and still reorder neighbouring UI text, so the app wraps untrusted text in `<bdi>` or `dir="auto"`.

### Exit codes
| Code | Meaning |
|---|---|
| 0 | report printed, also with partial failures (issues, a part of the profile unreadable, Steam not found, an unknown requested app ID), or the output ended by a closed pipe |
| 1 | fatal, no report: `restrict_dll_search`, `WinSystem::new`, `current_exe`, `ForbiddenRoots::resolve`, a write error other than `BrokenPipe` |
| 2 | usage error (clap) |

clap repeats the user's own arguments raw in usage errors; noted, not escaped (the user's own input). **Changed in P2-13 (security review N5):** usage errors are Rerun's own lines (`cli::usage_lines`: the kind in Rerun's words, the expected form from Rerun's own value parser, the value through `escape::text`, last on its line); only the help (also the one shown for a missing command) and the version stay clap's text, which holds no user input.

### Console
- No `SetConsoleOutputCP`, no `SetConsoleMode`: the code page and modes of a console are shared with the parent shell and outlive the process (the spirit of rule 2).
- `std` writes to a console with `WriteConsoleW` (Unicode whatever the code page) and plain UTF-8 bytes when redirected. Windows PowerShell 5.1 decodes piped output with its own encoding and may show mojibake for non-ASCII names; accepted.
- clap with `default-features = false` and the features `std`, `derive`, `help`, `usage`, `error-context`, `suggestions`, set in `[workspace.dependencies]`: no `color` (no `anstream`, no `SetConsoleMode`, no colour environment variables) and no `wrap_help` (no terminal width). The release binary contains no `SetConsoleMode`; clap's dependencies drop to `clap_builder`, `anstyle`, `clap_lex`, `strsim` and `clap_derive`.
- CI guard: the job fails if `cargo tree -p rerun-cli -e normal,features -i clap_builder` shows feature `"color"`. Risk it covers: feature unification once a phase 4 tool depends on clap with default features.

### Import allowlist per binary
The hardening policy takes the list as a parameter, `check_hardened(image, allowed)`. `LAUNCH_IMPORTS` (today's `SHIPPED_IMPORTS`, unchanged) for `rerun-launch.exe`; `CLI_IMPORTS` (today's `CORE_IMPORTS`, moved from `win_gpu_restricted.rs` into `tests/support/hardening.rs`, one list used by both tests) for `rerun.exe`. ADR 0008 amendment.

### Runs outside the usual setup
- Read-only, so no lock and no single-instance check. (Phase 2, amendment below: `apply`, `revert` and `forget` take the journal lock; `system`, `scan`, `plan` and `status` still do not.)
- Elevated with another administrator account (over-the-shoulder UAC): `HKCU` and the known folders are that account's, so Steam is "not found" for the interactive user. Documented, no workaround.
- `rerun.exe` on a network drive: `ForbiddenRoots::resolve` cannot resolve the forms of the install folder and fails closed; `rerun scan` exits 1. `rerun system` does not need it.

### Data kept out of the output
- The typed views extract allowlisted keys only (ADR 0011): `AppManifest` `appid`, `name`, `installdir`, `StateFlags`; `LibraryFolders` `path`, `label`. `LastOwner` and every other SteamID or account field is never extracted, so neither the output nor `{:?}` of a scan result can show it.
- Limits unchanged (ADR 0011): an `appmanifest_*.acf` at most 1 MiB, `libraryfolders.vdf` at most 4 MiB (user decision: the developer machine's file is 1,340 bytes, about 40 bytes per app; a 1 MiB cap gains nothing, since at most `max_bytes + 1` bytes are read and parsing is linear, and a file over the limit costs only the listed libraries, library 0 stays, with an issue). The 1 MB cap rule applies per manifest.

### Tests
Details in `docs/09-testing.md`, "CLI".
- Golden strings with `assert_eq!` (no snapshot crate); the pure render functions with directly built values.
- In-process end-to-end cases against `FakeSystem` (`rerun-core` with `fake` as a dev-dependency of `rerun-cli`): one or two games with images from the minimal PE writer, moved from `tests/support/hardening.rs` to `tests/support/pe_image.rs` (included with `#[path]`; `detect::pe::testfx` stays crate-private); malicious fixtures (an `installdir` with `..`, a manifest over 1 MiB, nesting over the limit, a missing required field, a name and a label with ESC, U+202E and tag characters, `LastOwner "76500000000000001"`). Expected: exit 0, the other games still listed, one issue line per problem with its location (escaped) and kind and never file content, the affected app not opened; the `LastOwner` value appears nowhere in stdout, stderr or `{:?}` of the scan results. The parser-level matrix stays in `rerun-core` (no duplication).
- Real Windows: `rerun system` runs in the normal test suite (CI shows "no hardware adapter"). `rerun scan` on the real machine is a local opt-in only: `#[ignore]` and `RERUN_SMOKE_REAL=1`, read-only, printing aggregate counts only (libraries, games, parse errors), no names, paths or SteamIDs, no snapshot files.

## Alternatives
- **`lexopt` or a hand-rolled parser:** smaller, but help, usage and suggestions written by hand for every later command; clap is already a dependency, and without default features it is four small crates plus the derive. **clap with `color`:** changes the console mode with `SetConsoleMode` and reads colour variables from the environment, for colours the output does not use.
- **`--json` now:** a format with no consumer would still be a promise; it comes with the app's or a script's need, versioned.
- **One sanitizer rule for everything:** either the strict rule, which quotes every name with full-width letters or `¥` as `\u{…}` soup, or the lax one, which lets confusables through in paths, where they matter for identity.
- **Replacing escapable characters with U+FFFD:** loses information, and replaced text is indistinguishable from a real U+FFFD and from other replaced characters.
- **Extending `is_deceptive`:** changes what `RelPath` accepts and with it `$defs/relPath` of both schemas (parity test, Topo format) for a display concern.
- **A non-zero exit code for partial failures:** any user process could turn every scan into a "failure" with one forged manifest; the output is not an interface for scripts, and the problems are in the report.
- **`SetConsoleOutputCP(65001)`:** changes the code page of the shared console for the parent shell, and a crash or kill skips the restore; `std` already writes Unicode to a console.
- **One import list for both shipped binaries:** would grant `rerun-launch.exe` `advapi32`, `combase` and `shell32` without review, against its minimal surface (ADR 0006).
- **Exposing `detect::pe::testfx` under the `fake` feature:** a PE writer in `rerun-core`'s public API for every crate that enables `fake`; a small writer in `tests/support` covers what the CLI tests need.
- **A snapshot crate (`insta`):** a new dependency and review files for a few dozen lines that `assert_eq!` pins as well.

## Consequences
- `rerun-cli` gets the modules `messages`, `out`, `system`, `scan`; `rerun-core` gets `escape`. No new dependency; clap loses its default features (the `anstream` family leaves `Cargo.lock`). `rerun-cli` gains `rerun-core` with `fake` as a dev-dependency; the shipped build never has it (the existing CI check).
- `shown_target` now escapes a superset (tags, variation selectors, U+2028/U+2029, noncharacters, supplementary private use); targets without such characters are unchanged, so existing errors and tests stay as they are.
- `tests/support/hardening.rs` holds `LAUNCH_IMPORTS` and `CLI_IMPORTS`, the PE writer moves to `tests/support/pe_image.rs`; ADR 0008 amendment.
- ADR 0014: phase 1 shows only the numeric fixed part of a version, the tie and none cases as above. ADR 0015: the sanitizer open point is closed here.
- CI: the clap colour guard; the phase 0 step `rerun --help` stays.
- Core rules: read-only and in-process (no background process, nothing to revert, no injection, no elevation); the console is left as found; apps Steam is updating are not touched.

## Open points
- **Fuzzing (decided: `cargo-fuzz` deferred):** `cargo-fuzz` needs nightly, which conflicts with the pinned `rust-toolchain.toml`, and the local Windows application control blocks freshly built or unsigned binaries (`cargo-fmt.exe` already fails with os error 4551), so a fuzz target cannot run on the developer machine. Revisit once that is resolved, and at the latest at audit A5 (supply chain and parsers). It would then be a `fuzz/` crate outside the workspace (own `[workspace]`, own `Cargo.lock`, the `libfuzzer-sys` dependency justified in its commit), run locally and time-boxed, not mandatory in CI. Meanwhile the stable regression guard is the in-tree harness: the xorshift loops plus the structural generators in `detect/vdf/structural.rs` (nesting, strings, entries and size at and over each limit, CRLF, BOM, stray CR, NUL, invalid UTF-8, unterminated tokens, structural mutations). Invariants: no panic, an error offset at most the input length, `Ok` results within the limits, `Display` and `Debug` of errors never contain input bytes, deterministic, `install_dir` either one classified segment or refused, no `LastOwner` or SteamID in the view (`docs/09-testing.md`). A round-trip property exists since the test-only writer; a production VDF writer is phase 3.
- **Step 17 acceptance run:** the user runs `rerun system` and `rerun scan` (release build) on the developer machine and spot-checks the API against PCGamingWiki. Only a summary with counts is recorded, as an amendment here; the output itself is never committed. Games modified on the developer machine (ZLUDA through a Steam launch option) are recorded as "not pristine", not as calibration cases. The cold and warm scan time and the cold hash rate are measured then; whether `Busy` needs a bounded retry (ADR 0012) is decided from that run.
- **Localisation:** German strings with Fluent when the app needs them (phase 5); clap's help texts then move into `messages` or stay English.
- **`--json`:** with the first consumer, versioned.
- **Unicode updates:** the table is pinned to Unicode 16; a new Unicode version is reviewed for new `Cf` and default-ignorable code points.
- **`AppState` guard in the core (after step 17):** `rerun scan` decides from a snapshot of `StateFlags`; an update that starts after the manifest was read still gets its game folder opened (read share only, for the length of one game scan). Moving the guard into `SteamLibrary::open_game` (re-reading the state) is decided together with the `Busy`/retry question from the step 17 run.
- **Issue texts with raw names:** issue lines that carry a raw entry or install folder name (an anomalous `steamapps` entry, an `installdir` that is no valid segment) go through the text rule as a whole, so printable confusables in those names stay visible as they are (the core already `{:?}`-quotes them). Accepted for phase 1.

## Amendment 2026-11-05: implementation (step 16)

- **Public API beyond the sketch:** `RawText::escaped()` (`escape::text` of the raw content; the output layers' only way to show raw text, so `rerun-cli` never calls `as_raw_str`, checked by a source rule test) and `Shown::into_owned()` (for text computed by the caller, such as an error message; a `Shown` keeps whether its input was escaped, which stays crate-internal). `hw` re-exports `CpuTopology` (already part of `SystemProfile`'s public API), so `rerun-cli` has no direct dependency on `rerun-proto`.
- **Last-resort net:** `Out::line` checks every line against the whole base set of `escape::text`, not only control characters; a hit panics in tests and is written escaped as a whole in a build.
- **Format choices:** untrusted text always stands last on its line (a name cannot pose as a marker such as "(conditions adapter)"); the version is `file_version` of the fixed part; the CPU summary is `G groups x C cores x T threads` when uniform, otherwise the totals with "(groups of different sizes)" or "(threads per core differ)", and "last-level cache groups" when the groups' cache levels differ; skipped or failed hashes go through the text rule (a failure may name a file); x86 executables show whether they are large address aware; hardware adapters are numbered from 0 in DXGI order (`adapter 0 (conditions adapter)`); an empty or whitespace-only library label is no line (step 17: Steam writes empty labels); what else a game shows: ADR 0014 amendment "what `rerun scan` shows".
- **Release binary:** CI builds the release `rerun.exe` before the tests and checks it like the release shim (`RERUN_RELEASE_CLI_EXE`): `CLI_IMPORTS`, `DependentLoadFlags`, and no console state API named in the image.
- **Localisation leftover:** the `Display` texts of core types that `rerun-cli` prints (`ApiReport`, `HashOutcome`, `AppState` in issues, Steam and exe issue texts, profile and table errors) are English sentences outside `messages`. Accepted for phase 1; they move behind message keys with the localisation (open point "Localisation").

## Amendment 2026-11-05: step 17 acceptance run

Run by the user on the developer machine (Ryzen 9 5950X, Radeon RX 9070 XT, Windows 11 build 26300), release build, read-only. Only counts and verdicts are recorded here; the output itself is not kept.

- **`rerun system`:** topology `2 L3 groups x 8 cores x 2 threads (16 cores, 32 threads)`, 32 MiB per group, one efficiency class (not hybrid); conditions adapter `0x1002:0x7550`, `rdna4`, not integrated, about 16 GiB VRAM (DXGI reports 16191 MiB); the Basic Render Driver is not counted; build `26300` with UBR. The five `when` facts match. Phase 1 topology criterion met.
- **`rerun scan` (warm file cache):** 4.06 s; 2 libraries, 33 apps: 29 installed, 4 with an update pending (listed, not opened; the user confirmed in Steam that these updates were being downloaded, so the `StateFlags` mapping holds); main executable 27 found, 1 tie, 1 without (the Steamworks redistributables, correct); 1 issue (a walk that hit the 128-directory limit; the main executable was still found); no escaped line, no control character.
- **PCGamingWiki spot check (17 games):** architecture 16 correct, 1 not checkable (no PCGamingWiki data), 0 wrong. API (static imports only): 9 correct, 3 correct but incomplete (a game that also offers D3D10/11 shows `d3d9`; unused extra imports such as `ddraw` or `opengl` next to the real API), 4 renderers loaded at run time shown as unknown (correct by design, ADR 0014), 1 not checkable, 0 wrong. Large address awareness cannot be checked against PCGamingWiki (no data on any of the 17 pages). Phase 1 scan criterion met.
- **Found and fixed during the run:** an empty library label printed as a line; adapters numbered from 1 instead of 0 (both `aa12d6c`); single-player and multiplayer executables that differ only by an `sp`/`mp` token now tie instead of one being picked (ADR 0014 amendment, `6ca6a96`).
- **Known limits confirmed:** when only the multiplayer part of a game is installed, Steam still lists the single-player app with the same install folder, and its main executable is the multiplayer one, because nothing else is on disk (correct for what is on disk; the per-app choice comes with Topos, phase 4). Games whose folders the user modified (ZLUDA through a Steam launch option) are not pristine and are no calibration cases.
- **Not measured:** the cold scan time and the cold hash rate (need a reboot); open. The `Busy`/retry question (ADR 0012) and the `AppState` guard in the core stay open: no `Busy` occurred in this run.

## Amendment 2026-11-05: phase 2 commands
- Phase 2 adds `plan`, `apply`, `revert`, `status` and `forget` (ADR 0020). `apply`, `revert` and `forget` hold the journal lock (`<LocalAppData>\Rerun\journal\lock`, share 0, ADR 0019) for their whole run; a second one gets `Busy`. `system`, `scan`, `plan` and `status` take no lock (`status` reads immutable journal files and shows an unclosed transaction as "open (in progress or interrupted)"). This replaces "read-only, so no lock" for the phase 2 commands; `system` and `scan` stay read-only.
- The output rules above apply unchanged: the preview of a plan and every `status` line show untrusted fields only as `escape::Shown` (condition S9). Exit codes of the new commands are fixed with their step (ADR 0020, open points).

## Amendment (P2-10b, 2026-11-06; security review S2): old registry data in the preview
- **Exception:** the preview of a plan (and, as lower-case hex, the stored plan `<AppDir>\plans\<hash>.json` and the journal head) shows the old data of a registry value that a `registry_set` step replaces, up to 1 KiB (`OLD_INLINE`). Everywhere else (scan issues, `status`, errors) registry content stays out of output, as above.
- **Why:** core rule 5 (preview before apply) asks that the user sees the value Rerun overwrites, not only its hash; a 1 KiB limit keeps a plan within its op budget and covers the settings values Topos replace. Larger and non-text old values are shown by type, length and SHA-256 only.
- **How:** the type and numbers are built by Rerun; string data goes through `escape::text` as a `Shown`, last on its line with nothing after it (`RegShown { kind, text }`, review S3), so a `"` or control character in it cannot pose as preview text.
- **Bound:** the preview shows only values a Topo step replaces, never other values of the key. A Topo review must not let a step replace a value that may hold a secret (a token, a password, a licence key): such a value would be shown in the preview and kept in the stored plan and the journal (user-readable `LocalAppData`).

## Amendment (P2-13, 2026-11-07): phase 2 commands

Plan `P2-13` with the user decisions E1 to E7 and the senior-dev conditions S1 to S8. Replaces the open "exit codes are fixed with their step" above.

### Commands
- `rerun plan <steps.json> [--dry-run]`: reads the step file (`docs/02-topo-format.md`, "Phase 2 step file"), shows the preview of exactly the bytes it stores (`plan::preview_stored` of the encoded plan), stores them as `<AppDir>\plans\<hash>.json` and prints `apply with: rerun apply <hash>`. A plan without ops is not stored. `--dry-run` creates nothing, not even Rerun's folder (review S6: the planners take `PlanCtx::app` as an `Option`; Rerun's folder is created only right before the plan is stored). No lock.
- `rerun apply <hash> [--dry-run] [--yes]`: shows the stored plan again, from the bytes that are applied, then runs every check of the apply without writing (`exec::check`: the same `preflight` chain the apply runs under the lock, review S1), asks, and applies (`exec::apply` loads the same bytes by hash and runs every check again under the lock). A plan the checks refuse is not asked about. `--dry-run` stops after the checks: no journal folder, no lock file, no record (user decision E2 a); an existing `journal\lock` is held read side while it checks, so an apply in progress makes it `JournalBusy` like the apply itself (review S2). It holds short read guards on the game files, as the apply does.
- `rerun revert <txn> [--dry-run] [--yes]`: first runs every check of the revert without writing (`exec::revert_check`: the revert's own chain, review S-a of the code review), so neither the preview, the dry run nor the question offers a revert that is then refused; then shows the transaction (its state and the roots of its head) and what a revert does now (`exec::verify`, newest op first: undone, nothing to do, Rerun's part set back, or left as it is because someone else changed it, with each INI key's state, the backup of an op left as found, a `.old` that holds a file as it was before a step of Rerun, and where the revert would halt), asks, reverts (`exec::revert`), and reports per op what it observed, marking an op that observed otherwise than the preview showed ("changed since the preview"). Already closed: exit 0; forgotten: exit 3; damaged or unreadable: exit 3 with the one text of `Refusal::Blocked` ("transaction T is damaged; rerun status shows what it left; only rerun forget T closes it"), also when a damaged later transaction with a usable head shares objects (it blocks every apply and revert on them, never others); an empty transaction: without a readable head exit 0, nothing to revert; with one, a line that the revert only closes it, and no question. A game folder that is another folder now (`IdentityMismatch`, a moved library or a reinstall) names forget, since a rebind is not supported yet (user decision E5 a; P2-14). `--dry-run` writes nothing and holds an existing lock file read side while it observes (review S2).
- `rerun status [--all]`: the journal only (`exec::status`: no lock, no game folder, nothing observed). Every transaction that is not closed as a block: its state, the roots of its head, every op newest first with its recorded state, its backup (`op-NNNN.bin` with its length, or "kept in the journal record") and its pending cleanups (a `.old` left next to a target), and the next step (`rerun revert <txn>`, or `rerun forget <txn>` for a damaged one or one with changes left as found). A forgotten transaction (by its record or a marker) is one line with where its backups stay, also without `--all` (review S8); closed and empty ones are counted, listed with `--all`, and shown anyway when they left a `.old`. A count line ends the report, and a note says that `revert --dry-run` and `forget` show what is on disk now. Runs elevated too. Exit 0 with a report, 1 only when the journal cannot be read.
- `rerun forget <txn> [--yes]`: shows the transaction with every op, every backup and every pending cleanup, what is on disk now (`verify`; if it cannot observe, that line instead) with every `.old` that holds a file as it was before a step of Rerun (never called the original; the backup is), then three fixed lines (forget changes nothing in the game folder or the registry; changes still in place stay and Rerun will not revert them; backups and files Rerun left are not deleted), "all N changes stay" for an applied one, and, when nothing is foreign and nothing halts, that `rerun revert <txn>` finishes it cleanly instead (review S7). Asks, then `exec::forget` (one record, one marker, or nothing). Already forgotten: exit 0; closed: exit 3.
- Registry data stays out of `status`, `revert` and `forget`: they show a transaction's head through `plan::preview_head`, which gives every old value, and the new value of an `add tokens` op, by type, length and SHA-256 only (review S3; the exception of the P2-10b amendment covers the plan preview only).
- Transactions are always named; there is no "last". A plan hash and a transaction name are parsed by clap (64 lower-case hex digits; 8 digits, `-`, 16 lower-case hex digits): a malformed one is a usage error before any system access.

### Confirmation (user decision E1 a, sharpened by the senior-dev review)
The preview goes to stdout, then the question (`Apply these 8 changes? [y/N]`) to stderr, followed by a space and flushed, no console mode changed. It is asked only when stdin and stdout are both consoles (`IsTerminal`): a preview piped away was not seen. Otherwise `--yes` is required (exit 2). The answer is one line of at most 256 bytes; `y` or `yes` (ASCII, any case, surrounding whitespace ignored) is yes, anything else, a longer line and the end of input are no (exit 3, "nothing done"). Right before the question the console's pending input is discarded (`sys::win::discard_console_input`, `FlushConsoleInputBuffer`; security review N4), so keystrokes typed ahead or pasted with the command never answer it; no console mode or code page changes.

### Elevated (user decision E3)
Elevated, or when elevation cannot be determined (fail closed), only `system`, `scan` and `status` run. `plan` (also with `--dry-run`), every dry run and every writing command exit 3 with the message that Rerun changes nothing then and that an administrator account always runs elevated with UAC turned off. The guard is in the core as well: `exec::apply`, `exec::check`, `exec::revert` and `exec::forget` refuse an elevated process for every plan, before the first record (`exec::standard_user`), not only plans with registry ops. Why: an elevated planner would check `user_writable` against the administrator's linked token (ADR 0007) and an apply would write under `Program Files` past the phase 3 helper; the journal and the plans would land in the profile of the administrator account (over-the-shoulder UAC). The phase 3 helper never reads the journal and does not use these functions (ADR 0019, `docs/06-security.md`).

### Exit codes
Only additive changes: scripts may rely on them.

| Code | Meaning | Cases |
|---|---|---|
| 0 | done, or a report | plan stored or shown (`--dry-run`), nothing to do; apply applied or nothing to do; `apply --dry-run` and `revert --dry-run` without objection (also with ops left as found or a halt: a report); revert closed, already closed, or nothing to revert; forget done or already forgotten; `status` (also with open or damaged transactions); `system`, `scan` |
| 1 | fatal, no report | the DLL search path, `WinSystem::new`, `current_exe`, `ForbiddenRoots::resolve`, Rerun's folder cannot be opened, the journal cannot be read (`status`), a write error other than a closed pipe before the change |
| 2 | usage | clap, a malformed plan hash or transaction name, no console without `--yes` |
| 3 | nothing changed | every `Refusal` (the game runs or cannot be checked, `JournalBusy`, Steam updating, gone or its manifest unreadable, `Mismatch`, `Blocked`, `Interrupted`, `Elevated`, `NeedsHelper`, `MainExe`, `Registry`, `Root`, `Plan`, `Later`, `Forgotten`, `Observe`), a step file or planner error, a transaction not found, closed (forget) or damaged (revert), every revert error before the run's first record (review S4), every forget error before its record or marker, the user said no, the preview could not be written (closed pipe before the change) |
| 4 | rolled back | the apply failed and was rolled back completely (`Closed { RolledBack }`, everything as before) |
| 5 | open, needs attention | the apply failed and its rollback did not finish (`LeftOpen`); a revert halted (a root that cannot run file ops), left ops as found (only forget closes it), or failed after its first record of the run (the transaction stays open; `rerun status` shows it, a revert goes on from there); a closing entry (a revert's `Closed`, forget's record or marker) that reached the journal although its flush failed (`ExecError::Unconfirmed`: "may have been closed", `rerun status` shows it) |

One function per error kind maps the codes (`exit_for_apply`, `exit_for_exec`); the `#[non_exhaustive]` catch-all counts as 5, since an unknown error may come after the first change. Every refusal has the same code (user decision E6 a); its text says whether to try again later.

### A closed pipe (deviation from "Output" above for the writing commands)
Before the change, a write of the preview that fails with `BrokenPipe` ends the command with nothing changed and exit 3 (core rule 5: a preview that did not arrive does not count); any other write error before the change is exit 1. After the change the report ends silently and the exit code of the operation stays (another write error is named on stderr).

### Output
Unchanged rules: English only, every string in `messages` (the phase 2 lines in `messages::txn`), untrusted text only as `escape::Shown` and last on its line, an INI key's old and new value on lines of their own; no `--json` (the app calls the core directly). The `Display` texts of `Refusal` and `PlanError` stay the accepted localisation leftover (amendment of step 16). Failures go to stderr as `rerun: <error>`, a hint on a line of its own.

### Ctrl+C
No console control handler: Ctrl+C during an apply or a revert ends the process like a crash, which the journal is built for (ADR 0019); the transaction is open, `rerun status` shows it and `rerun revert <txn>` finishes it (`docs/04-launch-methods.md`).

## Amendment (P2-14, 2026-11-07; plan `P2-14`, user decision E-R5)
- **`rerun revert <txn> --rebind [--dry-run]`**: after the checks of `revert` (closed, forgotten, damaged as before), `exec::rebind_check` is the preview (rule 5): the transaction and its roots; `rebind of root <i>:` the folder bound now with its identity and library and why it does not open; the folder Steam lists now with its identity and library; every folder the plan created there, "found there and not provably Rerun's (removed only if empty)" or "missing there"; `what the revert does there:` per op as `verify` shows it, with the INI keys; the note that registry changes are reverted where Rerun made them (a compatibility-layer value under the old program path; a value under the new program path is not touched); the note that the binding is permanent. Every path through `escape::path`. Below `what the revert does there:` a line names the folder `root <i>` means there (review N2); the registry note only where the head has registry ops; the halt hint is not given for an app installed in another folder of its library (no rebind binds that).
- **Only at a console (E-R5):** `--rebind --yes` is a usage error (clap, exit 2); without a console exit 2 ("a rebind is only confirmed at a console"); the question `Bind transaction <txn> to this folder and revert these <n> ops? [y/N]`, no: exit 3. `--dry-run` shows the preview and writes nothing (exit 0).
- **Exit codes:** every `RebindRefusal` (`NotNeeded` included) and every refusal before the record exit 3; after the record as a revert (0 closed, 5 open); a rebind whose record may not be on disk (`ExecError::RebindUnconfirmed`): exit 5 with "may be bound to the new folder"; any other error after the record: exit 5 with "bound to the new folder now; rerun revert <txn> goes on there", or for an uncertain closing (`Unconfirmed`) "bound to the new folder and may have been closed" (P2-14b review S3, N3). A transaction bound already (`AlreadyBound`) prints `already bound to: <folder>` and runs as a plain revert (its question).
- **Hints:** a refused revert at a folder that is another folder now names `rerun revert <txn> --rebind` for a folder Steam moved or reinstalled and `forget` for a folder the user chose; a revert that halts at a Steam root that is gone (also in the preview) adds `if Steam moved or reinstalled the game: rerun revert <txn> --rebind shows the folder Steam lists now`. `status` shows each binding of an open transaction as `root <i> rebound (identity <id>): <folder>` (journal only). Replaces "a rebind is not supported yet" of the P2-13 amendment.
- Tests: `src/tests.rs` C-RB1 (apply, the library moved, the halt with the hint, `--rebind --dry-run` writes nothing, `--rebind` binds and closes), C-RB2 (not needed 3, no 3 without a record, no console 2, `--rebind --yes` a conflict), C-RB6 (a reinstall: the hint names `--rebind`; a crash right after the record: the status line; `--rebind` again: "already bound", one question, reverted), C-RB7 (a failed rebind: "may be bound" or "bound now", exit 5).

## Amendment (P2-15, 2026-11-07; user decisions E-C1 to E-C4, senior-dev B1 and S3)
- **`status`:** a transaction whose every op is reverted but whose journal still names a `.old` of Rerun's (`TxnLine::CleanupPending`) has the state line `everything reverted, only cleanup pending`, its ops with their `pending cleanup: <path>` lines, and the hint `a file Rerun left is still there; rerun revert <txn> deletes it or says why it stays (close the game and any window showing its folder first)` (the journal does not say whether the file is in use or kept, so the journal-only texts are neutral; review S2). A transaction closed `Reverted` or `RolledBack` shows no cleanup line (it closes only once nothing of Rerun's is left); a forgotten one shows `may remain (pending cleanup): <path>` from its records.
- **`revert --dry-run` and the preview before the question** (rule 5): after the ops, one line per pending `.old` from `Verified::cleanup`: `will delete Rerun's copy (known content, SHA-256 <hex>): <path>`, `in use, stays for now (Rerun's copy; the transaction stays open): <path>`, `kept: the file next to it changed since the revert, so Rerun's copy stays (delete it yourself, or forget the transaction): <path>`, `not Rerun's file, or it cannot be checked as Rerun's; left as it is: <path>`; a file already gone has no line. The question of a revert that only cleans up is `Everything is reverted. Delete the file Rerun left? [y/N]` (`the <n> files`), counting the copies `verify` sees in use too (a process may hold one with delete sharing, so the delete can still succeed: `(it is in use now and may stay)`, `(one is …)`, `(<k> are …)`; review S1); with nothing to delete there is no question.
- **The report:** per pending `.old` `deleted Rerun's copy: <path>` or why it stays (the lines above), a `.old` it reports is not repeated as `left:`; the last line `transaction <txn> is reverted; <n> file(s) Rerun replaced is/are still in use and stay(s) for now; close the game and any window showing its folder, then run rerun revert <txn> again` (or, for a file kept next to a changed one, `… delete it yourself and run rerun revert <txn>, or rerun forget <txn>`).
- **A rollback with a `.old` left** (`ApplyError::CleanupPending`, senior-dev B1): `the apply failed and was rolled back, but a file Rerun left is still there: transaction <txn> stays open until it is deleted`, the cause, one line per file (the preview's lines), and by the reason `close the game and any window showing its folder, then run: rerun revert <txn>` or `a file next to Rerun's copy changed since, so the copy stays; delete it yourself and run rerun revert <txn>, or rerun forget <txn>`. A rollback that closes (`ApplyError::RolledBack`) names what its cleanup deleted or found not Rerun's (E-C4, review S1).
- **Stacking:** an apply on the objects of such a transaction, or the revert of an earlier one on them, is refused (exit 3) with the core's text `transaction <txn> is reverted, but a file Rerun left is still there; run rerun revert <txn>, it deletes the file or says why it stays (close the game and any window showing its folder first)`.
- **`forget`** of such a transaction says `Everything is reverted; only the files listed as pending cleanup stay, and Rerun will not delete them.` instead of `Changes still in place stay, …` (senior-dev S3), and the hint after `verify` follows what it sees: the in-use one while a file is in use, the kept one for a copy next to a changed file.
- **A full journal** (review N5): a revert refused because the journal has no room for another `RevertIntent` adds `the journal of transaction <txn> has no room for another revert attempt; only rerun forget <txn> closes it (backups stay)`.
- **Exit codes:** a revert that leaves a `.old` of Rerun's (in use or kept) exits 5, like any transaction left open; a rollback with one (`ApplyError::CleanupPending`) exits 5, not 4 (it is not closed); a revert that only cleans up and fails after its deletion is never 3 (the deletion is a change, senior-dev B2).
- Every path is shown through `escape::path` (a path from the journal cannot hold a control or bidi character, `RelPath`; the line escapes whatever it gets).
- Tests: `src/tests.rs` C-CL1 (a revert while the restore's `.old` is mapped: exit 5 and its text, the `status` lines, C-CL3 an apply on the same file refused with its text, forget's text, `--dry-run` names the deletion with the SHA-256, the question, the deletion, closed and identical; a rollback with a mapped `.old`: exit 5, its text, a later revert closes), `src/txn/tests.rs` C-CL2 (golden preview, report and status lines for every kind; ESC and U+202E escaped).
