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

clap repeats the user's own arguments raw in usage errors; noted, not escaped (the user's own input).

### Console
- No `SetConsoleOutputCP`, no `SetConsoleMode`: the code page and modes of a console are shared with the parent shell and outlive the process (the spirit of rule 2).
- `std` writes to a console with `WriteConsoleW` (Unicode whatever the code page) and plain UTF-8 bytes when redirected. Windows PowerShell 5.1 decodes piped output with its own encoding and may show mojibake for non-ASCII names; accepted.
- clap with `default-features = false` and the features `std`, `derive`, `help`, `usage`, `error-context`, `suggestions`, set in `[workspace.dependencies]`: no `color` (no `anstream`, no `SetConsoleMode`, no colour environment variables) and no `wrap_help` (no terminal width). The release binary contains no `SetConsoleMode`; clap's dependencies drop to `clap_builder`, `anstyle`, `clap_lex`, `strsim` and `clap_derive`.
- CI guard: the job fails if `cargo tree -p rerun-cli -e normal,features -i clap_builder` shows feature `"color"`. Risk it covers: feature unification once a phase 4 tool depends on clap with default features.

### Import allowlist per binary
The hardening policy takes the list as a parameter, `check_hardened(image, allowed)`. `LAUNCH_IMPORTS` (today's `SHIPPED_IMPORTS`, unchanged) for `rerun-launch.exe`; `CLI_IMPORTS` (today's `CORE_IMPORTS`, moved from `win_gpu_restricted.rs` into `tests/support/hardening.rs`, one list used by both tests) for `rerun.exe`. ADR 0008 amendment.

### Runs outside the usual setup
- Read-only, so no lock and no single-instance check.
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
- **Fuzzing (separate commit after step 16, after a spike):** `cargo-fuzz` needs nightly (conflicts with the pinned `rust-toolchain.toml`), and its MSVC/ASan limits on Windows are unverified. It would be a `fuzz/` crate outside the workspace (own `[workspace]`, own `Cargo.lock`, the `libfuzzer-sys` dependency justified in its commit), run locally and time-boxed, not mandatory in CI. The stable CI regression stays the in-tree xorshift harness, extended with structural generators (nesting just under and over the limit, long strings, many entries, CRLF and BOM). Invariants: no panic, an error offset at most the input length, `Ok` results within the limits, `Display` and `Debug` of errors never contain input bytes, deterministic, `install_dir` either one classified segment or refused. A round-trip property only once a VDF writer exists (phase 3).
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
