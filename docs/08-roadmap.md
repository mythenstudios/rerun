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
- CLI: `rerun plan <steps.json> [--dry-run]` (JSON step file until the Topo engine), `apply [--dry-run] [--yes]`, `revert [--dry-run] [--yes]`, `status [--all]`, `forget [--yes]` (P2-13); the rebind of a transaction whose Steam game folder moved or was reinstalled (`revert --rebind [--dry-run]`, done in P2-14: the core in P2-14a, the Steam scan and the CLI in P2-14b; before audit A3)
- A2 leftovers before A3 (P2-15): a `.old` a process still maps keeps its transaction open until a later revert deletes it with its known hash (`RevertDone.old_left` by sequence index, `status` names exactly those, a rollback alike); the record budget of a repeated `RevertIntent`; nested roots in one plan refused; the full list of what a revert does not restore in the preview; the test combinations of A2 (faults × cuts of `C:` and `D:`, multi-op plans, stacked transactions, nested probes) and the cleanup axis
- Moved out: `gpu_preference` and `UserData` roots to phase 4, the VirtualStore warning to phase 3

**Acceptance:** Round-trip tests of all primitives green against `sys::fake`; crash (every intermediate state), power-loss and tampering tests green; write contracts green against `sys::win`; the sandbox run (`scripts/sandbox-test.wsb`, real `HKCU`, a game folder fixture) green in Windows Sandbox; audits A2 (after `file_install`) and A3 passed.

## Phase 3 – Launching with CPU rules
- `rerun-launch`: `direct` (Job Object), `watch`, post-launch check
- CPU rule selection against all fixtures
- Primitive `launch_method` (the launch profile, incl. `priority`; the Steam launch option is copied by the user, the revert preview names the option to remove)
- Preconditions from `compat_layer` (P2-11b, ADR 0018 amendment P2-11b): `rerun-launch` and the IFEO launcher start the game by exactly the path of its `Layers` value name (`docs/04-launch-methods.md`); the `HKLM` "all users" layer of the same executable (written by the compatibility tab, an `HKLM` `~ DPIUNAWARE` next to Rerun's `HKCU` `HIGHDPIAWARE`: how they combine is not measured) is read (read only) in the planner, a group conflict is refused (done in P3-6, ADR 0018 amendment P3-6: both views, fail closed, the preview names the value)
- `verify` warns about UAC VirtualStore shadow copies of managed files (moved from phase 2); done in P3-7: the preview of `plan` and `apply` and `verify` (`revert`, `forget`) warn for a root below `Program Files`, `Program Files (x86)` or `ProgramData` (ADR 0007 amendment P3-7)

**Acceptance:** A Steam game launches via `rerun-launch` with 8 threads on one CCD, the check reports `ok`. A Ubisoft game via Steam with `watch` as well. **Accepted 2026-11-09** ([DEV] Stronghold 2 with `direct` on 2026-11-08: `0x5555`, 8 threads on CCD 0 in a job, `applied`/`ok`/`hard:8:32`, revert closed; [DEV] AC Black Flag Resynced through Ubisoft Connect with `watch` on 2026-11-09: the game in a job with `0x5555`, the launcher chain untouched, `ok`, revert closed; docs/09; the CI sandbox suite green including `direct` and `watch`; `full-probes` green, run 42552362570 on `65c1dd8`; the acceptance review passed with conditions, met in this commit. Deferred: SB-L7 (a layer at a start with Steam's spelling of the path) and the real VirtualStore sandbox case to phase 4, the cold start of D2 before phase 5).

## Phase 4 – Topos and packages
- Signed index (Ed25519) and Topo engine first; then the elevated helper (moved from phase 3) with `firewall_rule` as its only operation in this phase; audit A4 on the helper design before any helper write code (passed with conditions on 2026-11-09, ADR 0023; slices 2a → 2b → 5a → 2c → 2d → 5b). Reverting a helper operation never depends on the current index or the current executable hash
- Package download (allowed hosts, SHA256, Zip Slip safe), DLL slots, reference counting
- Topo engine with `when`, variants, conflicts
- Topo loader requires `launch.start` for `direct`, `watch` and `auto`; re-evaluate E2 of P3-3 (reading Steam's `appinfo.vdf` to propose or check `start`, ADR 0022 amendment P3-3)
- Primitive `gpu_preference` with the `when` keys `gpu.hybrid` and `gpu.integrated`; `UserData` roots (`Documents`, `My Games`) with their own allowlist (both moved from phase 2, user decisions D6 and D8)
- Primitive `laa_patch` (the Large Address Aware flag of a 32-bit game executable from the Topo's `match`: backup, SHA-256 before and after, refused for DRM-protected builds, .NET and anti-cheat games; user-writable roots only in this phase)
- Anti-cheat detection in the scan: for such a game every plan (from a Topo or a step file) refuses packages, `laa_patch`, `firewall_rule`, `compat_layer` and the launch methods `watch`, `hold`, `ifeo`, `inproc`, and warns for the other steps; a signed Topo may release an anti-cheat that is verifiably dead (with a source; draft only until unlocked in P4-13 with the first PunkBuster Topo, ADR 0020 amendment P4-4). Non-goal in `00-vision.md` unchanged
- One package = one pinned version; another verified version of the same tool is its own package (e.g. `dxvk-1.10`), a Topo variant chooses it (no free version choice, rule 4)
- Shared package files are reference counted: a revert removes its own files, a file another open transaction still holds stays until the last one is reverted
- 20 Topos, at least 5 of them `verified` on the developer machine
- `rerun-workbench`: PCGW query → draft

**Acceptance:** Install and revert of DXVK, dgVoodoo 2, Ultimate ASI Loader + EaglePatch leave a bit-identical game folder.

**Acceptance (helper):** the elevated helper (ADR 0008, H2): its `System` has no GPU (a separate type, or a GPU part that returns `Unsupported` without touching DXGI); the helper binary never links `sys::win::loader`'s DLL loading or `sys::win::dxgi`, checked by an import allowlist test on the built helper with `tests/support/hardening.rs` (`detect::pe`, ADR 0013); and a source rule test refuses `WinGpu` and `WinSystem` in the helper's sources; a content test on the built helper finds neither `dxgi.dll` (ASCII or UTF-16) nor `CreateDXGIFactory1`, and a control binary that uses `WinGpu` must fail the same tests.

## Phase 5 – App
- Tauri app: Library, Game detail (3 tabs), Log, First launch
- Primitive `launch_option` (writes the Steam launch option, Steam closed; moved from phase 3)
- i18n en/de
- Code signing, portable build
- Before A6: every anti-cheat marker without a vendor source (`EasyAntiCheat`, `EasyAntiCheat_EOS`, `GameGuard`, `XIGNCODE`, `EAAntiCheat.GameServiceLauncher.exe`; `docs/05-sources-policy.md`) has one, or a dump of a real machine; the third-party link for `start_protected_game.exe` is replaced by Epic's own documentation once found
- Before A6: no release with an unsigned `rerun-helper.exe` (ADR 0023, audit A4 S12: before code signing its UAC prompt cannot be told apart from a malware prompt of the same name)

**Acceptance:** All flows from the mockup work against the real core.

## Phase 6 – Expansion
- `hold`, `ifeo`, `inproc` (`rerun-cpu.asi`, x86/x64), `shim_single`
- GOG, Epic, Ubisoft Connect detection, and game folders added by hand (matched by executable hash)
- Admin-only roots (retail installs under `Program Files`) through the helper, including replacing files there (`laa_patch`); needs a helper-owned backup store (moved from phase 4, user decision E1)
- Heuristic for games without a Topo (import table → wrapper suggestion)
- Separate repo `mythenstudios/rerun-topos` with PR templates and CI validation
