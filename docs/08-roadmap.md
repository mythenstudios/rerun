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
- PE parser: x86/x64, imports → graphics API (ddraw, d3d8, d3d9, d3d10, d3d11, opengl32), LAA flag, version info; SHA1/SHA256. Finding on the developer machine (ADR 0013 amendment): 9 of 33 game folders have their executables only in subfolders (`Binaries\Win64`), so the exe candidates are searched below the top level too (bounded); exe candidates, roles, ranking, graphics API (also `d3d12`, `vulkan`, `glide`, reserved for the schemas) and `--hashes` in ADR 0014
- `hw`: GPU via DXGI, CPU topology, OS build → system profile for the five `when` keys of `02-topo-format.md` (`gpu.vendor`, `gpu.arch`, `cpu.threads`, `cpu.hybrid`, `os.build`), evaluated against the first hardware adapter in DXGI order (software adapters skipped); VRAM and `integrated` in the profile for `rerun system` only. The GPU architecture table `data/gpu-arch.yaml` with its schema, every identifier declared and one sourced entry (developer machine's RX 9070 XT); test entries are synthetic; `unknown` never matches (ADR 0015). Further GPU `when` keys are scheduled in `03b-gpu-display.md` ("Open decisions")
- CLI: `rerun system` (profile, the topology in the form of the acceptance below) and `rerun scan [APP_ID…] [--hashes]` (Steam games with main executable, architecture and API, streamed per game); human-readable text only, not a stable interface, every untrusted field escaped (ADR 0016)

**Acceptance:** `rerun scan` correctly lists the Steam games on the developer machine with API and architecture. The topology of the 5950X is detected as 2 L3 groups × 8 cores × 2 threads (as `rerun system` prints it). Run by the user (step 17); only a summary with counts is recorded (ADR 0016 amendment). **Accepted 2026-11-05** (ADR 0016 amendment "step 17 acceptance run"; audit A1 passed with conditions for the phase 2 plan).

## Phase 2 – Primitives + Journal + revert
- File write side (`DirWrite`, `FileGuard`, ADR 0017) and registry write side with `policy::registry` (`HKCU` only, ADR 0018); write contracts against the fake and `sys::win` (under `target/`, private app hives)
- Journal: file-based under `AppDir` (`<LocalAppData>\Rerun\journal`, immutable records, write-ahead, backups, flushes before the closing record, lock, LIFO revert; ADR 0019)
- Plans and op kinds (ADR 0020): primitives `file_install` (local package files under `AppDir`, test fixtures only), `registry_set`, `compat_layer`, `ini_set`; preview output, plan hash; apply and revert only with the game closed (`users()`), refused while Steam updates the game; a foreign change is never overwritten (`forget`)
- CLI: `rerun plan <steps.json> [--dry-run]` (JSON step file until the Topo engine), `apply [--dry-run] [--yes]`, `revert [--dry-run] [--yes]`, `status [--all]`, `forget [--yes]` (P2-13); the rebind of a transaction whose game folder moved (`revert --rebind`, P2-14, before audit A3)
- Moved out: `gpu_preference` and `UserData` roots to phase 4, the VirtualStore warning to phase 3

**Acceptance:** Round-trip tests of all primitives green against `sys::fake`; crash (every intermediate state), power-loss and tampering tests green; write contracts green against `sys::win`; the sandbox run (`scripts/sandbox-test.wsb`, real `HKCU`, a game folder fixture) green in Windows Sandbox; audits A2 (after `file_install`) and A3 passed.

## Phase 3 – Launching with CPU rules
- `rerun-launch`: `direct` (Job Object), `watch`, post-launch check
- CPU rule selection against all fixtures
- Primitive `launch_option` (Steam closed) and `launch_method`
- Elevated helper + primitives `priority`, `firewall_rule`
- `verify` warns about UAC VirtualStore shadow copies of managed files (moved from phase 2)

**Acceptance:** A Steam game launches via `rerun-launch` with 8 threads on one CCD, the check reports `ok`. A Ubisoft game via Steam with `watch` as well. The elevated helper (ADR 0008, H2, security review of step 10): its `System` has no GPU (a separate type, or a GPU part that returns `Unsupported` without touching DXGI); the helper binary never links `sys::win::loader`'s DLL loading or `sys::win::dxgi`, checked by an import allowlist test on the built helper with `tests/support/hardening.rs` (`detect::pe`, ADR 0013); and a source rule test refuses `WinGpu` and `WinSystem` in the helper's sources.

## Phase 4 – Topos and packages
- Package download (allowed hosts, SHA256, Zip Slip safe), DLL slots, reference counting
- Topo engine with `when`, variants, conflicts
- Primitive `gpu_preference` with the `when` keys `gpu.hybrid` and `gpu.integrated`; `UserData` roots (`Documents`, `My Games`) with their own allowlist (both moved from phase 2, user decisions D6 and D8)
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
