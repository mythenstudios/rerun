# 01 · Architecture

## Workspace

```
rerun_/
├─ crates/
│  ├─ rerun-core/      Library: detection, Topo engine, primitives, Journal, system layer
│  ├─ rerun-proto/     Small shared types (CPU topology and its pure Windows-record parser; from Phase 3 launch profile, CPU rule), no dependencies, serde only via feature
│  ├─ rerun-cli/       Binary `rerun` (scan, plan, apply, revert, status, topo validate)
│  ├─ rerun-launch/    Binary `rerun-launch.exe` – launch shim, only windows-sys + rerun-proto
│  ├─ rerun-cpu/       cdylib `rerun-cpu.asi` – inproc CPU fix, x86 + x64
│  └─ rerun-workbench/ Curator tool: query PCGamingWiki, generate Topo draft
├─ app/                Tauri 2 + Svelte 5 + TypeScript (Vite); `app/src-tauri` joins the Cargo workspace only in Phase 5
├─ topos/              Game recipes (YAML)
├─ packages/           Upstream tools (YAML)
├─ schema/             JSON Schema for Topo and package
├─ tests/fixtures/     CPU topologies, path parity cases, valid/invalid schema fixtures
└─ docs/
```

Dependencies always point to `rerun-core` or `rerun-proto`, never back.

## rerun-core: modules

| Module | Purpose |
|---|---|
| `detect` | Steam (libraryfolders.vdf, appmanifest_*.acf), GOG (registry), Ubisoft Connect, Epic, manual. PE parsing (architecture, imports → graphics API, LAA flag, version info), hashes. `detect::pe` (ADR 0013): own bounded parser over `Read + Seek`, no memory mapping and no whole-file read; `Pe::parse` reads the header region once (at most 64 KiB) and recognises DOS, NE and LE/LX executables as `Legacy`; `Headers` (machine, PE32/PE32+, characteristics with Large Address Aware and DLL, subsystem, DLL characteristics, image base, CLR header present); `imports`/`delay_imports`: DLL names only (`DllName`: 1 to 255 bytes of printable ASCII, compared ASCII case-insensitively), at most 1,024 per table, VC6 delay descriptors with virtual addresses; `dependent_load_flags` from the load config; `version_info`: the `RT_VERSION` branch at fixed depth (ID 1 else the lowest, language neutral, then en-US, then the lowest) and a tolerant VS_VERSIONINFO parser (explicit loop over four levels, the fixed part and six strings of one string table as `RawText`); `info` returns all of it, a broken version resource kept as an error next to the headers and imports; `open_game_exe(&GameDir, &RelPath, &Limits)` is the only reader for product code (handle-relative `Dir::open_read`, ADR 0007; the length is never asked for; `PeReadError` names the file, `into_inner` hands the handle back for hashing); every read is a bounded range read charged to a total budget per file (1 MiB); errors carry a kind and a file offset, never file content. `detect::vdf`: pure bounded parser for Valve KeyValues text (quoted subset only, limits for bytes, depth, entries and string length, explicit stack, no recursion) and `read_store_file`, the only reader, handle-relative to a `StoreDir` with at most `max_bytes + 1` bytes; `detect::steam::files`: typed views `LibraryFolders` (current and pre-2021 format) and `AppManifest`, untrusted text as `RawText` (`detect::text`, shared by every detector; no `Display`, `Debug` shows only the length) for `policy::root` (ADR 0011, ADR 0012). `detect::steam::scan(&dyn System, &ForbiddenRoots) -> SteamScan` (ADR 0012): never fails as a whole, every problem an `Issue` with a location; Steam root from `HKCU` `SteamPath`, then `HKLM` `InstallPath` (32-bit, then native view) through `Registry::get` only, every candidate through `StoreDir::open`, a disagreeing one reported and not scanned; library list from `steamapps\libraryfolders.vdf` (`config\libraryfolders.vdf` only on `NotFound`, never merged, at most 256), libraries de-duplicated by `RootId`; `steamapps` listed relative to each library, `appmanifest_<id>.acf` plain files only (at most 16,384, counted first), `appid` equal to `<id>`, `installdir` classified; `StateFlags` → `AppState`; duplicate app IDs kept and reported; game folders only through `SteamLibrary::open_game` (`StoreDir::game`). |
| `hw` | System profile: GPU (DXGI: vendor ID, device ID → generation, driver), CPU topology (see `03-cpu-topology.md`), OS build, monitor. |
| `topo` | Load, check signature, validate schema, evaluate `when` conditions against the system profile. |
| `pkg` | Packages: download (allowed hosts only), SHA256, extraction (Zip Slip safe), cache. |
| `prim` | Primitives (see below). |
| `plan` | Build a `Plan` (list of `Change`) from Topo + selection + profile. Detect conflicts (DLL slots, dependencies). Plan hash. |
| `journal` | SQLite (rusqlite) at `%LOCALAPPDATA%\Rerun\journal.db`. Write-ahead: entry before every change. Backups at `%LOCALAPPDATA%\Rerun\backups\<game>\`. |
| `elevate` | Parts of a plan that need admin go as JSON to `rerun.exe --elevated-apply` (ShellExecute `runas`). The helper re-validates, executes, exits. |
| `sys` | Traits `Fs` (only `open_dir`) and `Dir` (all file operations relative to an open root, ADR 0007), `Registry`, `Topology`, `KnownFolders` (via `GetSystemWindowsDirectoryW`, the raw `HKLM` `ProfileList` values and `SHGetKnownFolderPath` with the process token, never environment variables; ADR 0009), `Gpu` (DXGI adapters, raw IDs) (Phase 1), `Firewall`, `Process` (Phase 3), bundled in `System` (`&dyn System`). `sys::win` = real (from Phase 1, read-only in Phase 1: `nt` is the only module with NT/Win32 file calls and `NtCreateFile` through two wrappers, `token` the `AccessCheck` for `user_writable`, `shell` the only `SHGetKnownFolderPath`/`GetSystemWindowsDirectoryW` calls, `reg` the only registry calls (`RegOpenCurrentUser`, `RegOpenKeyExW`, `RegEnumKeyExW`, `RegQueryInfoKeyW`; values with `NtQueryValueKey`/`NtEnumerateValueKey`), `unsafe` only in these four; `status`/`name`/`reparse` pure, `fs` = `WinFs`/`WinDir`, `known_folders` = `WinKnownFolders`, `registry` = `WinRegistry` (read-only, input rules, limits, retries), `cpu`/`topology` = `WinTopology` (ADR 0010), `loader` the only `SetDefaultDllDirectories`/`LoadLibraryExW`/`GetProcAddress` (System32 only), `dxgi` a hand-written DXGI binding on `windows-sys` types and `gpu` = `WinGpu` (ADR 0008 amendment); `unsafe` also in `cpu`, `loader` and `dxgi`; `system` = `WinSystem`, the real `System` of all of them (`WinSystem::new() -> SysResult<Self>`, opens the current user's registry root; `rerun-cli` does not use it yet)), `sys::fake` = tests, `sys::snapshot` = state comparison, `sys::contract` = contract tests for both. No `Steam` trait: Steam is logic in `detect`. Bindings: ADR 0008. See ADR 0004. |
| `policy` | Rules above `sys`: `policy::path` (`RelPath`, `RootPath`, `classify` for names read from disk), `policy::root` (the only way to open a game or store folder: `StoreDir` by absolute path, `GameDir` handle-relative from its store or manually added, `ForbiddenRoots` resolved fail-closed from `KnownFolders`, lexical and canonical check, no volume or network roots, `RootId` re-checked at apply and revert; ADR 0007 and its amendment), from Phase 3 `policy::registry` (allowlist). Applies identically to the fake, the real system and the elevated helper. |

## Primitives

Every primitive implements:

```rust
pub trait Primitive {
    type Spec: DeserializeOwned;            // fields from the Topo
    fn plan(&self, spec: &Self::Spec, ctx: &Ctx) -> Result<Vec<Change>>;
    fn apply(&self, change: &Change, sys: &dyn System, j: &mut Journal) -> Result<()>;
    fn verify(&self, change: &Change, sys: &dyn System) -> Result<Verified>;
    fn revert(&self, entry: &JournalEntry, sys: &dyn System) -> Result<Reverted>;
}
```

| Primitive | Effect | Admin |
|---|---|---|
| `compat_layer` | `HKCU\…\AppCompatFlags\Layers` (mode, DISABLEDXMAXIMIZEDWINDOWEDMODE, HIGHDPIAWARE, 16BITCOLOR …) | no |
| `priority` | `IFEO\<exe>\PerfOptions\CpuPriorityClass` | yes |
| `firewall_rule` | Outbound block for the exe only (INetFwPolicy2) | yes |
| `file_install` | Files from a package into the game folder, occupy slots, backups | no* |
| `ini_set` | Set individual values in INI/CFG | no* |
| `registry_set` | Values under allowed game keys | depends on hive |
| `launch_option` | Steam launch option (localconfig.vdf, only while Steam is closed) | no |
| `launch_method` | `direct` / `watch` / `hold` / `ifeo` / `inproc` + CPU rule (see `04`) | ifeo: yes |
| `laa_patch` | Large Address Aware flag in the exe, with backup; not for DRM-protected exes | no* |
| `steam_input` | Hint/link: enable Steam Input per game | no |

\* unless the game is located under `Program Files` → then via the helper.

## Data flow

```
detect ─► hw ─► topo(when) ─► plan ─► [preview UI/CLI] ─► apply ─► journal
                                                     └► elevate (admin parts only)
start: Steam %command% / IFEO ─► rerun-launch ─► read profile ─► method ─► check ─► exit
revert: journal ─► hash check ─► restore backups ─► restore registry/firewall/IFEO/launch option ─► folder comparison
```

## rerun-launch

- Reads the launch profile of the target exe from `%LOCALAPPDATA%\Rerun\profiles\<hash>.json` (written on apply).
- Knows no Topos, no network, no registry except reading the profile.
- Target: < 1 MB, < 50 ms startup time, exits immediately (direct/watch) or together with the game (hold/ifeo).
- DLL hardening like every shipped executable (ADR 0008 amendment 2026-11-05): linked with `/DEPENDENTLOADFLAG:0x800` (`build.rs`), and the first statement of `main` restricts the DLL search path to System32 (`src/dll.rs`, its own copy of the one `SetDefaultDllDirectories` call), failing closed. `rerun` does the same through `rerun_core::sys::win::restrict_dll_search`.

## rerun-cpu (inproc)

- Loaded via Ultimate ASI Loader (`scripts/rerun-cpu.asi`) or as a proxy DLL.
- Sets affinity/CPU Sets from inside, hooks `SetProcessAffinityMask`, reports a smaller core count if needed (`GetSystemInfo`, `GetNativeSystemInfo`, possibly `GetLogicalProcessorInformation`).
- Configuration from `rerun-cpu.ini` next to it. Builds for x86 and x64.
- Cargo produces `rerun_cpu.dll`; the build step copies it to `dist/<arch>/rerun-cpu.asi` (ADR 0006). Static CRT, `panic = "abort"`.

## Frontend (app/)

- Tauri 2, Svelte 5, TypeScript, Vite. No UI library.
- Commands: `scan`, `game_detail`, `plan`, `apply(plan_hash)`, `revert(entry_ids)`, `status`, `system_profile`.
- The frontend holds no system state. It displays plans, the core executes.

## Network

Only two destinations: the signed Topo index (GitHub Releases of `mythenstudios/rerun-topos`) and package downloads from the hosts in `packages/`. No telemetry. Feedback = pre-filled GitHub issue in the browser.
