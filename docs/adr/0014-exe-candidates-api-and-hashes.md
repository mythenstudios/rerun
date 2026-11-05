# ADR 0014 · Executable candidates, graphics API and hashes

**Status:** accepted · 2026-11-05 · extends ADR 0007, ADR 0012, ADR 0013

## Context
Phase 1 step 14 turns one opened game folder (`GameDir`, ADR 0007) into the facts `rerun scan` shows (step 16) and later phases match Topos against: which executables the folder holds, which of them is the game, its architecture, its graphics API, and (only with `--hashes`) its SHA-1 and SHA-256. Step 13 (ADR 0013) parses one given file; step 14 decides which files.

Findings of the read-only dumps on the developer machine (ADR 0013 amendment):
- 9 of 33 game folders have no executable at the top level; the binaries lie in `Binaries\Win64`, `bin`, `x64` and similar subfolders.
- Many side executables: crash handlers (`UnityCrashHandler64.exe`, `crash_reporter.exe`, `createdump.exe`), installers and redistributables (`UbisoftConnectInstaller.exe`), anti-cheat (`*_BE.exe`, `pbsvc.exe`), launchers (a .NET `FFLauncher.exe`, `PlayGTAV.exe`, `REDprelauncher.exe`, `launcher.exe`), helpers (`BF3WebHelper.exe`).
- Unity games import only `UnityPlayer.dll`; the renderer lives in that DLL. Packed or DRM-wrapped executables show stub imports.
- Graphics imports seen: `d3d9`, `dxgi`, `d3d12`, `OPENGL32`, `d3dx9_*`; duplicate descriptors (several `KERNEL32.dll`) occur.
- `RelPath` refuses 8.3 short names (`~` followed by a digit).

The Topo format (`docs/02-topo-format.md`) knows `api: ddraw | d3d8 | d3d9 | d3d10 | d3d11 | opengl` (Topo and package schema alike) and matches executables by path and `sha1`/`sha256` in uppercase hex. Detection sees more than that enum (`d3d12`, `vulkan-1`, Glide, `dxgi` alone).

Everything read here is untrusted (ADR 0013, scenario 13 of `docs/06-security.md`).

## Decision

### User decisions (2026-11-05)
1. **API vocabulary:** the schemas do not change now. `GraphicsApi` knows `d3d12`, `vulkan` and `glide` with `topo_name() == None`; these spellings are reserved for an additive extension of `$defs/api` when the first Topo or package needs them (phase 4 at the latest), before the first release.
2. **Several Direct3D versions statically imported:** the highest wins, with the visible basis `HighestD3d` (shown as `d3d11 (also d3d9)`).
3. **Engine DLLs** (`UnityPlayer.dll`, `Core.dll` with `Engine.dll`) are not parsed in step 14; the verdict is `RendererInDll(engine)`.
4. **`--hashes` scope:** only `Game` candidates that parsed, at most 8 files, 2 GiB per file, 4 GiB per game; SHA-1 and SHA-256 in one pass; every candidate not hashed shows `Skipped(reason)`.
5. **Walk limits:** depth 3, 128 listed directories, 20,000 entries, 64 parsed executables; at a limit the partial result is kept with `complete == false` and one issue.

The numbers, the role table, the API table and the skip list are **provisional** until the developer-machine dump (`dump_exe_candidates`, see Consequences) has run; it is recorded as an amendment here, and the tables are tuned in a follow-up commit.

### Layers
- New module `detect::exe`, store-agnostic: it takes a `GameDir` (Steam today, manual and other stores later) and never a bare `Dir`. Submodules: `walk` (bounded listing of the game folder), `api` (pure mapping of DLL names to a verdict), `role` (pure name rules), `rank` (pure ordering), `hash` (streaming SHA-1/SHA-256 over a reader), `issue` (`ExeIssue`), `scan` (orchestration). No new `sys` method, no `unsafe`, no recursion.
- `scan_game(&GameDir, &Options) -> GameExes` never fails as a whole (like `steam::scan`, ADR 0012): every problem is an `ExeIssue` or stays on its candidate, and the scan goes on. `Options { name_hint: Option<RelPath>, hashes: bool, limits: ExeLimits }`; `ExeLimits` holds the walk limits, the parser limits (`pe: pe::Limits`) and the hash limits (`hash: HashLimits`), `ExeLimits::DEFAULT` the shipped values.
- `inspect_exe(&GameDir, &RelPath, &pe::Limits, Option<&HashLimits>) -> Result<ExeFacts, ExeError>` is the per-file pipeline (open through `pe::open_game_exe`, `Pe::info`, the API verdict, optionally the hashes on the same handle via `Pe::into_inner`). `scan_game` uses it for every candidate; Topo matching (phase 4) uses it for the paths named in `match.exes`, so a Topo never depends on the walk or its limits.
- The result owns no handle and borrows nothing (`GameExes: 'static`), so step 16 can drop the `GameDir` right after the scan of a game.
- Issues are a type of their own (`ExeIssue { at: Option<RelPath>, kind: ExeIssueKind }`, `at: None` is the game folder itself), not ADR 0012's `Issue`: its `Location` is Steam-specific, and an exe issue is always relative to one game, which the caller names. Same rules as ADR 0012: no file content, raw names only escaped (`{:?}`), `RelPath`s as they are; `Display` is `<path or "game folder">: <kind>`.

### Walk
Breadth-first from the game folder, one level after the other, every listing sorted by the folded name (`RelPath` order, the raw name as tie-break) before it is used, so the result and the limits do not depend on the listing order of the file system.
- Each directory to list is opened relative to the game handle (`GameDir::dir().open_dir`, never through a reparse point, ADR 0007), asked for `info().case_sensitive` and listed through that same handle (`read_dir(None)`). A case-sensitive directory is one `CaseSensitiveDir` issue and none of its entries is used (two names could fold to one `RelPath`); the game folder itself is checked the same way (through `info()` at walk time, not the `RootInfo` of opening). A directory that fails to open, to report its info or to list is one `Sys` issue; the walk goes on.
- Every entry name goes through `policy::path::classify`; an anomaly (`game.exe.`, `CON.exe`, `DATA~1`, a bidi override, invalid UTF-16, a path over 240 characters) is an `Anomaly` issue when it would have mattered (a directory to enter, a reparse point, or a name ending in `.exe`) and is never opened.
- **Directories** are entered when they are plain directories (`EntryKind::Dir`, not restricted), not deeper than `max_depth`, and not in the skip list. A reparse point (junction, symlink, unknown tag; `EntryKind::Reparse` does not tell a directory from a file, so every one is reported) or a restricted directory is a `NotFollowed` issue and is never entered. A directory beyond `max_depth` is counted (`WalkStats::depth_cut`), not reported per entry.
- **Skip list** (whole segment, ASCII case-insensitive, at every depth): `_CommonRedist`, `CommonRedist`, `__Installer`, `Installer`, `Installers`, `Redist`, `Redistributables`, `DirectX`, `DXSETUP`, `vcredist`, `dotNetFx`, `Support`, `EasyAntiCheat`, `BattlEye`. Skipped directories are not entered and are listed in `WalkStats::skipped_dirs` (never hidden). The list is data in `walk`.
- **Candidates** are plain files (`EntryKind::File`, also with an allowlisted data tag, not restricted) whose name ends in `.exe` (ASCII case-insensitive). A reparse point or a restricted entry named `*.exe` is a `NotFollowed` issue. `.com`, `.bat` and other files are not candidates.
- **Depth:** the game folder is level 0; an executable's depth is the level of the folder that holds it, so `Game\Binaries\Win64\Game-Win64-Shipping.exe` has depth 3.
- **Limits** (`ExeLimits::DEFAULT`; a value of exactly the limit is accepted):

| Limit | Value | Reason |
|---|---|---|
| `max_depth` | 3 directory levels below the game folder | `Game\Binaries\Win64\Game-Win64-Shipping.exe` (Unreal 4/5) is level 3; `Binaries\Win64`, `bin\x64`, `System` are level 1 or 2 |
| `max_dirs` | 128 listed directories (the game folder counts) | breadth-first reaches every level-1 and most level-2 folders of real games first |
| `max_entries` | 20,000 entries across all listings | `sys::win` opens every listed entry attribute-only (ADR 0012), about 10 to 20 µs each: at most about 0.4 s per game |
| `max_exes` | 64 candidates opened and parsed | real folders hold 1 to 15; at most 64 MiB read by the parser (ADR 0013 budget) |

  Before each further directory is listed, the walk stops if `max_dirs` directories were listed or at least `max_entries` entries were seen (the listing that crossed the limit is used); the result keeps what was found, `WalkStats::complete` is `false` and one `WalkLimit` issue names the limit. A walk that reaches a limit exactly with nothing left to list is complete. More than `max_exes` candidates: the first 64 in walk order are parsed, one `TooManyExes { found, max }` issue reports the count, and the others are not in the list. Partial results are acceptable here, unlike ADR 0012's manifests, because the walk only feeds display and suggestions; matching opens Topo paths directly (`inspect_exe`).
- Known limit (as ADR 0012): `Dir::read_dir` collects a whole directory before any limit applies; a phase 2 bounded `read_dir` would bound the single listing too.

### Roles
`Role` from the file stem (the name without its `.exe`) by a fixed rule table (ASCII case-insensitive; a non-ASCII stem never matches a rule), first matching group in this order, then from PE facts:
- `CrashReporter`: stem `createdump`, `crashpad_handler`, `crashreportclient`, `unitycrashhandler32`, `unitycrashhandler64`, `bssndrpt`, `bssndrpt64`, or containing `crash`.
- `AntiCheat`: stem `start_protected_game`, `pbsvc`, `pnkbstra`, `pnkbstrb`, starting with `beservice` or `easyanticheat`, or ending in `_be` or `_eac`.
- `Installer`: containing `setup`, `install`, `redist`, starting with `vc_redist`, `vcredist`, `dxsetup`, `dotnetfx`, `physx`, `oalinst`, or `unins` followed only by one or more digits.
- `Launcher`: containing `launcher` (also `prelauncher`).
- `Helper`: containing `webhelper`, `browsersubprocess`, `cefprocess`, `qtwebengineprocess`; ending in `_server`, `-server`, `dedicatedserver`; containing `config`, `settings`, `editor`.
- Otherwise `Game`.
- A name rule does not apply when the stem matches the install folder hint (similarity of at least 1, see "Ranking"), so `CrashBandicoot.exe` in `Crash Bandicoot` stays `Game`. (To check with the dump: this also keeps `Fallout4Launcher.exe` in `Fallout 4` a `Game`; ranking still puts `Fallout4.exe` first by similarity.)
- PE facts override the name: the DLL flag is `NotAnApp`; a `Legacy` error (DOS, NE, LE/LX) is `Legacy(format)`; a candidate that failed to open or parse keeps its name role and its error.
Roles are hints. Every candidate stays in the list with its role; nothing is dropped by role.

### Ranking
Candidates are sorted by, in this order: role (`Game` first; `Launcher`; `Helper`; `CrashReporter`, `AntiCheat`, `Installer`; `NotAnApp`, `Legacy`; failed last), API strength (`One` with basis `Only` 5, `HighestD3d` 4, `DelayOnly`/`Helper` 3, `Several` 3, `RendererInDll`/`Managed`/`DxgiOnly` 2, `None` 0), GUI subsystem before console, similarity to the install folder hint (2: equal, 1: one is a prefix of the other with at least 4 characters, 0; both reduced to lowercase ASCII letters and digits), depth (shallower first), then the path. `GameExes::main` is `One(index)` when exactly one `Game` candidate has the best key (everything but the path), `Tied(indices)` when several share it (Assassin's Creed ships a DX9 and a DX10 executable; both are game executables), and `None` without a `Game` candidate that parsed. Detection never promotes a launcher to the main executable.

### Graphics API
`api::classify(&[DllName], &[DllName], managed) -> ApiReport`, pure, on the static and the delay imports. DLL names compare ASCII case-insensitively and exactly (no substring), duplicates count once.

| DLL | Meaning |
|---|---|
| `ddraw.dll` | core `ddraw` (also Direct3D 7 and older) |
| `d3d8.dll` | core `d3d8` |
| `d3d9.dll` | core `d3d9` |
| `d3d10.dll`, `d3d10_1.dll` | core `d3d10` |
| `d3d11.dll` | core `d3d11` |
| `d3d12.dll` | core `d3d12` |
| `opengl32.dll` | core `opengl` |
| `vulkan-1.dll` | core `vulkan` |
| `glide.dll`, `glide2x.dll`, `glide3x.dll` | core `glide` |
| `d3dx9_NN.dll` (two digits) | helper `d3d9` |
| `d3dx10.dll`, `d3dx10_NN.dll` | helper `d3d10` |
| `d3dx11_NN.dll` | helper `d3d11` |
| `d3drm.dll`, `d3dim.dll`, `d3dim700.dll` | helper `ddraw` |
| `glu32.dll` | helper `opengl` |
| `dxgi.dll` | `dxgi` flag only (shared by `d3d10`, `d3d11`, `d3d12`) |
| `UnityPlayer.dll`; `Core.dll` together with `Engine.dll` | engine: renderer in a DLL (Unity; Unreal Engine 1/2), from either table |
| `d3dcompiler_NN.dll` and everything else | ignored |

Verdict, first rule that applies:
1. Static core imports present: one API is `One { api, basis: Only }`; only Direct3D family APIs (`ddraw` < `d3d8` < `d3d9` < `d3d10` < `d3d11` < `d3d12`) is `One { highest, basis: HighestD3d }` (many Direct3D 10/11 games import `d3d9.dll` for the `D3DPERF_*` markers only; `ddraw` next to `d3d8`/`d3d9` is common); anything mixing families (`opengl`, `vulkan`, `glide` with each other or with Direct3D) is `Several(set)`.
2. Else delay core imports, by the same rule, with basis `DelayOnly` (`Several` stays `Several`).
3. Else helper imports of both tables, by the same rule, with basis `Helper` (`d3dx9_43.dll` alone is `d3d9`, the device is created through `LoadLibrary`).
4. Else `dxgi.dll` in either table: `DxgiOnly` (the Direct3D version is loaded at runtime; never guessed).
5. Else an engine import: `RendererInDll(engine)`. Engine DLLs are not parsed: they hold several renderers (Unity: Direct3D 11 and 12, Vulkan; Unreal 2 `D3DDrv`/`OpenGLDrv`), the one in use is chosen by a configuration file.
6. Else managed (.NET): `Managed`. Else `None` (packed or DRM stubs, renderers loaded with `LoadLibrary`, e.g. Source).

`ApiReport` keeps the verdict and the evidence (core and helper sets and the `dxgi` flag per table, the engine), so output can show `d3d11 (also d3d9)`.

Topo vocabulary: `GraphicsApi` has `ddraw`, `d3d8`, `d3d9`, `d3d10`, `d3d11`, `d3d12`, `opengl`, `vulkan`, `glide` (`GraphicsApi::as_str`); `GraphicsApi::topo_name()` gives the Topo `api` value or `None` for `d3d12`, `vulkan` and `glide`. A parity test checks `topo_name` against `$defs/api` of both schemas. The schemas do not change in step 14 (user decision 1).

### Hashes
- Only with `--hashes` (`Options::hashes`); without it nothing beyond the parser's reads is read, and the hashes of every parsed candidate are `NotRequested`. Hashes are part of `ExeFacts`; a candidate that failed to open or parse has no hashes, its error is shown instead.
- Computed by `inspect_exe` on the very handle that was parsed (`Pe::into_inner`, seek to 0, no second open): `open_read` shares read only (ADR 0007), so no writer can change the file between parse and hash; a writer already open makes the open `Busy`.
- In `scan_game`, the selection needs the ranking, and the ranking needs every candidate parsed. So the first pass parses every candidate without hashes (one handle at a time); after ranking, the selected candidates are inspected again by `inspect_exe` with hashes, again one handle at a time for parse and hash. If the facts of the second inspection differ from the first (the file was replaced in between), the hash is `Failed(Changed)` and the first facts stay; if the second inspection fails, the hash is `Failed(Inspect(error))`. So a hash always belongs to the facts shown next to it. Re-parsing at most 8 files costs at most 8 MiB of reads, nothing next to the hashing.
- Streaming: one buffer of 256 KiB (`HashLimits::chunk_bytes`), each chunk fed to SHA-1 and SHA-256 in one pass; `Interrupted` retried as in the parser (16 times per read); the length is the number of bytes read, never asked from metadata.
- Bounds (`HashLimits::DEFAULT`): at most 2 GiB per file (`Skipped(TooLarge)` after reading at most the limit plus one chunk; the largest shipping executables seen are below 1 GiB); in `scan_game` only `Game` candidates that parsed, in rank order, at most 8 files and 4 GiB per game. The length the walk's listing reported decides only whether a file can still fit the remaining game budget (skipped without reading it); while hashing, the remaining budget caps the read, so a listing that understates the length costs at most the remaining budget plus one chunk. Others are `HashOutcome::Skipped(reason)` (`NotGame`, `TooManyFiles`, `GameBudget`, `TooLarge`), visible per candidate. No wall-clock timer in the core (deterministic tests); about 1 to 2 s per GiB on the developer machine, to be confirmed by the dump.
- Output in uppercase hex (Topo format). SHA-1 is an identity hint for Topo and package matching (`supports_exe_sha1`), never authorization: the elevated helper (phase 3) and `laa_patch` check SHA-256 only.
- Dependency: `sha1` 0.11 (RustCrypto `hashes`, MIT OR Apache-2.0, the same project and `digest` 0.11 stack as `sha2` 0.11, already a dependency of `rerun-core` for snapshots; the only new crate in `Cargo.lock`, `default-features = false`, uses SHA-NI through the shared `cpufeatures`; MSRV 1.85). Checked in the commit: `cargo tree -d` shows no second `digest`, `cargo deny check` passes.

### Errors and anomalies
- Reading failures (`SysError` of a listing, `PeReadError::Open`, `Io` while hashing) are no property of the file; format problems (anomalous names, `PeReadError::Parse`, `Legacy`) are. Both are shown, neither stops the scan. Walk problems are `ExeIssue`s; per-file problems stay on their candidate (`facts: Err`, or `HashOutcome::Failed` in its facts).
- `ExeIssueKind`: `Sys(SysError)`, `Anomaly(Anomaly)`, `CaseSensitiveDir`, `NotFollowed { kind, restricted }`, `WalkLimit { limit, max }`, `TooManyExes { found, max }`.
- `ExeError` wraps `PeReadError` (it names the file, never content).

## Alternatives
- **Top-level `*.exe` only:** misses 9 of 33 games on the developer machine.
- **Unbounded or deep walk:** modded games (`Data\meshes\…`) hold hundreds of thousands of files; every listed entry costs an attribute-only open.
- **Refusing the whole list at a limit** (ADR 0012 style): the walk is a hint, matching does not depend on it; a refused list would show nothing for large games.
- **Hiding side executables:** a wrong rule would hide the game; roles rank, they never drop.
- **Parsing engine DLLs (`UnityPlayer.dll`, `D3DDrv.dll`):** they list every renderer they can use, not the one in use; the answer would look precise and be a guess.
- **`Several` for every mix of Direct3D versions:** most Direct3D 10/11 games would be ambiguous because of `D3DPERF_*` imports from `d3d9.dll`; function names (phase 6) can refine `HighestD3d` later.
- **Extending the schema `api` enum now:** no Topo or package needs it yet; reserved spellings keep the later change additive.
- **`sha1_smol`** (no dependencies, BSD-3-Clause): slower, no SHA-NI, a second hashing stack next to `sha2`. **Windows CNG (`BCryptHash`):** `unsafe` and a new `sys` part for something pure Rust does.
- **Hashing after ranking with all handles held open:** up to 64 files locked against writers (a Steam update) for seconds; the second inspection keeps one handle open at a time.
- **Hashing in walk order during the first pass:** the per-game budget would go to whatever comes first in the walk (a level-0 tool before the level-3 game) instead of the best-ranked game executables.
- **Reusing ADR 0012's `Issue`:** couples the store-agnostic exe scan to Steam locations.

## Consequences
- `rerun scan` (step 16): per app `lib.open_game(fr, app_id)`, then `detect::exe::scan_game(&game, &Options { name_hint: Some(app.install_dir.clone()), hashes, limits: ExeLimits::DEFAULT })`; it prints the main executable (or the tied ones) with machine, API (`ApiReport`'s `Display`, built from `GraphicsApi::as_str` and the evidence), LAA for x86, then side candidates, walk stats and issues. Version strings stay `RawText` until the CLI sanitizes them.
- `docs/06-security.md` scenario 13 gets the walk and hash bounds and the list of what is read; `docs/09-testing.md` a section "Executable candidates".
- The `api` mapping, the role table and the skip list are heuristics with names in them; the developer-machine dump (`dump_exe_candidates` in `crates/rerun-core/tests/pe_system.rs`, `#[ignore]`, Windows only, read-only, never in CI, output never committed, names escaped, version strings only as their length, hashes only with `RERUN_DUMP_HASHES=1`) validates them and is recorded as an amendment here; the tables are tuned in a follow-up commit.
- Games with an 8.3-like folder or file name (`~` followed by a digit) are reported as anomalies and not scanned below that name.
