# 08 · Roadmap

Every phase ends with green tests and updated docs. The next phase starts only when the acceptance criteria are met.

## Phase 0 – Foundation
- Cargo workspace with all crates (empty), `rustfmt.toml`, `clippy.toml`, `deny.toml`
- GitHub Actions on `windows-latest`: fmt, clippy `-D warnings`, test, `cargo deny`; build x64 + i686 for `rerun-cpu`
- `sys` traits + `sys::fake` skeleton
- `schema/topo.schema.json`, `schema/package.schema.json` (first version)

**Acceptance:** CI green, `cargo run -p rerun-cli -- --help` works.

## Phase 1 – Detection
- Steam: `libraryfolders.vdf`, `appmanifest_*.acf` → games with path
- PE parser: x86/x64, imports → graphics API (ddraw, d3d8, d3d9, d3d10, d3d11, opengl32), LAA flag, version info; SHA1/SHA256
- `hw`: GPU via DXGI, CPU topology, OS build
- CLI: `rerun scan`, `rerun system`

**Acceptance:** `rerun scan` correctly lists the Steam games on the developer machine with API and architecture. The topology of the 5950X is detected as 2 L3 groups × 8 cores × 2 threads.

## Phase 2 – Primitives + Journal + revert
- Journal (SQLite, write-ahead), backups
- Primitives: `compat_layer`, `file_install` (local test file), `ini_set`, `registry_set`
- `plan`, preview output, plan hash
- CLI: `rerun plan <id> --dry-run`, `apply`, `revert`, `status`

**Acceptance:** Round-trip tests of all primitives green against `sys::fake`; crash and tampering tests green; manual test in Windows Sandbox.

## Phase 3 – Launching with CPU rules
- `rerun-launch`: `direct` (Job Object), `watch`, post-launch check
- CPU rule selection against all fixtures
- Primitive `launch_option` (Steam closed) and `launch_method`
- Elevated helper + primitives `priority`, `firewall_rule`

**Acceptance:** A Steam game launches via `rerun-launch` with 8 threads on one CCD, the check reports `ok`. A Ubisoft game via Steam with `watch` as well. The elevated helper (ADR 0008, H2, security review of step 10): its `System` has no GPU (a separate type, or a GPU part that returns `Unsupported` without touching DXGI); the helper binary never links `sys::win::loader`'s DLL loading or `sys::win::dxgi`, checked by an import allowlist test on the built helper like `tests/support/pe_min.rs`; and a source rule test refuses `WinGpu` and `WinSystem` in the helper's sources.

## Phase 4 – Topos and packages
- Package download (allowed hosts, SHA256, Zip Slip safe), DLL slots, reference counting
- Topo engine with `when`, variants, conflicts
- Signed index (Ed25519)
- 20 Topos, at least 5 of them `verified` on the developer machine
- `rerun-workbench`: PCGW query → draft

**Acceptance:** Install and revert of DXVK, dgVoodoo 2, Ultimate ASI Loader + EaglePatch leave a bit-identical game folder.

## Phase 5 – App
- Tauri app: Library, Game detail (3 tabs), Log, First launch
- i18n en/de
- Code signing, portable build

**Acceptance:** All flows from the mockup work against the real core.

## Phase 6 – Expansion
- `hold`, `ifeo`, `inproc` (`rerun-cpu.asi`, x86/x64), `shim_single`
- GOG, Epic, Ubisoft Connect detection
- Heuristic for games without a Topo (import table → wrapper suggestion)
- Separate repo `mythenstudios/rerun-topos` with PR templates and CI validation
