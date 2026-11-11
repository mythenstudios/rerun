# ADR 0026 · UI framework

**Status:** Accepted · 2026-11-11 (user decision) · supersedes ADR 0001 for the GUI (Tauri 2, Svelte 5); the Rust workspace and the CLI of ADR 0001 stand · the framework below the `ui` layer of ADR 0027 · phase 5, step P5-3

## Context
ADR 0027 puts a Rust-native app (`rerun-app`) over `rerun_core::flow` and keeps every framework type in one module, `rerun-app::ui`; worker, view models, the text catalogue, theme tokens and settings are framework-free. It left the framework to this ADR and named what the framework must show: its window handle (the owner of the UAC dialog), a process with the System32-only DLL search and `/DEPENDENTLOADFLAG:0x800`, a window in under 1 s, a run without a GPU, a tree Narrator reads. A framework that fails one of these is out.

Two throwaway spikes (not committed) built the same screens (the library list and a game page of `docs/07-ui.md`, the real Topos read through `rerun-core`'s model types, nothing written) on the developer machine (Windows 11 build 26300, Ryzen 9 5950X, Radeon RX 9070 XT), release profile of the workspace (fat LTO, one codegen unit, `panic = "abort"`, stripped):

| | GPUI (gpui-kit =0.9.1, pins gpui-pre =0.3.12) | Slint =1.18.1 |
|---|---|---|
| Upstream | gpui-pre is a snapshot of Zed's `gpui` republished by a single third-party maintainer; `gpui` on crates.io is stale (0.2.2, October 2025); gpui-kit breaks its API about monthly | the vendor's own crates; SemVer within 1.x, a minor release every 2 to 4 months |
| Crates (Windows tree) | 406 | 278 |
| Release binary | 12.6 to 13.3 MiB | 11.1 MiB (opt 3), 9.3 MiB (opt "s") |
| Working set | about 80 to 94 MB | 111 MB with femtovg (OpenGL, the default); 26 MB with the software renderer, pixel-identical; 0 CPU while idle |
| Without a GPU | D3D11, WARP as the last adapter | the software renderer needs no GPU at all |
| UI Automation (AccessKit) | active; the window buttons are missing from the tree | names and roles good, window buttons included; gaps listed under "Open points" |
| Window | not compared | frameless (`no-frame`) with `WindowMoveArea`; the Windows 11 snap layouts need a window subclass (about 60 lines, `unsafe`) |
| Licences outside `deny.toml`'s allow list | MPL-2.0 (bundled icon assets) | BSL-1.0 (`clipboard-win`, `error-code`); Slint's own expression `GPL-3.0-only OR LicenseRef-Slint-Royalty-free-2.0 OR LicenseRef-Slint-Software-3.0` (11 crates) |

Slint also embeds fonts with `import "…ttf"` in a `.slint` file (no install, no lookup at run time) and hands out the window handle through `raw-window-handle` 0.6 (the spike read the HWND that way). Build times (Slint): clean debug 79 s, incremental 3 to 4 s, clean release 182 to 186 s.

## Decision

### Slint, pinned
- `slint` and `slint-build` **=1.18.1**, pinned exactly like `ed25519-compact` and `miniz_oxide`: the framework decides how every screen and every untrusted string is drawn. An update is a commit of its own that repeats the spike's measures (size, crate count, the UI Automation dump, the licence list).
- Features: `default-features = false`; `std`, `compat-1-2`, `backend-winit`, `renderer-software`, `accessibility`, `raw-window-handle-06`; `renderer-femtovg` only if P5-3 keeps it (see "Open points"). No Qt, no Skia, no system tray (rule 1), no `unstable-*` feature. Whether Slint's locale support stays is open (Smart App Control, below).
- `slint-build` compiles the `.slint` files in `crates/rerun-app/build.rs`; no run-time interpreter, no `slint-interpreter`.

### Licence: Slint's GPL-3.0 option
- Rerun uses Slint under **GPL-3.0-only**, the GPL option of its licence expression. The Royalty-free License 2.0 was rejected: its attribution terms are obligations outside the GPL and sit badly with a GPL project that gains nothing from a proprietary option. The commercial licence was not considered.
- **Consequence, stated plainly:** Rerun's sources stay **GPL-3.0-or-later** (the workspace `license`, `README.md`). `rerun-app.exe` links Slint, which allows version 3 only, so the distributed `rerun-app.exe` is **effectively GPL-3.0-only**: it can be conveyed under GPL-3.0 and under no later version unless Slint offers one. `rerun.exe`, `rerun-launch.exe`, `rerun-helper.exe` and `rerun-cpu.asi` do not link Slint and stay GPL-3.0-or-later; a CI check keeps Slint out of their dependency trees.
- The app shows the Appropriate Legal Notices of GPL-3.0 (§ 0, § 5 d: copyright, no warranty, the licence and how to read it) and the third-party licences (Settings, P5-10).

### Where Slint lives (ADR 0027)
- Only `rerun-app::ui`, its `build.rs` and its `.slint` files name Slint (the source rule of ADR 0027). Nothing in `worker`, `vm`, `text`, `theme` or `settings` depends on it; a later switch replaces `ui` only.
- `Wake` (ADR 0027) is implemented in `ui` with `slint::invoke_from_event_loop`: the worker thread wakes the event loop, the UI thread polls the event and maps the view model into the structs generated from `.slint`. The worker never holds a Slint type.
- Text: every string reaches `ui` localized from `vm` and `text`; Slint's own translation (`@tr`, gettext) is not used.
- Theme: `theme::tokens` is copied into one `.slint` global at start and on a settings change; no colour or size literal in `.slint` outside that global.
- Fonts are embedded with `import`; their licences join the third-party list.
- Untrusted text (ADR 0016, ADR 0027): every untrusted field is drawn in its own `Text` element, never concatenated into a sentence with other text, so its direction cannot reorder its neighbours; the escape of ADR 0016 has already made bidi controls visible.

### The window
- Frameless with Rerun's own title bar (`docs/07-ui.md`): `no-frame` and `WindowMoveArea`; minimise, maximise and close are own buttons with names and roles.
- **Snap layouts** need a window subclass that answers `WM_NCHITTEST` with `HTMAXBUTTON` over the own maximise button. It lives in one module, `rerun-app::ui::chrome`, under the rules of `sys::win`: the only `unsafe` and the only `windows-sys` window calls of `rerun-app` (`#![allow(unsafe_code)]` with its reason, `// SAFETY:` on every block, the workspace's unsafe lints), reviewed by `win32-systems` and `security-reviewer`, pinned by a source rule. If the review finds it fragile, the fallback is the native title bar (snap layouts without `unsafe`, a deviation from the mockup).
- The HWND for `WinSystem::with_prompt_owner` (ADR 0027) is read in `ui::chrome` through `raw-window-handle`; no other module of `rerun-app` sees it.
- No Mica or Acrylic: Slint offers them only through winit's attributes behind an unstable feature (ADR 0027: only without own `unsafe` and without an unstable API).

### ADR 0027's criteria
| Criterion | State |
|---|---|
| Window handle | shown (spike, `raw-window-handle` 0.6) |
| System32-only DLL search, `/DEPENDENTLOADFLAG:0x800` | gate in P5-3: `restrict_dll_search` first in `main`, the DLLs the release `rerun-app.exe` loads measured as for `winhttp.dll` (with femtovg this includes `opengl32.dll` and the vendor's OpenGL driver) |
| Window in under 1 s | gate in P5-3, measured on the release build (not measured in the spike) |
| Without a GPU | met by the software renderer |
| Narrator | the UI Automation tree read (spike); a Narrator pass in P5-3 |

A gate that fails in P5-3 reopens this ADR before the app grows further.

### GPUI: the runner-up
GPUI drew well and falls back to WARP, but today it reaches crates.io only as a third party's snapshot with monthly breaking changes and a larger tree. It is re-evaluated **once Zed publishes regular `gpui` releases with a stable API**. A switch replaces `rerun-app::ui` and nothing else (ADR 0027).

## Alternatives
- **GPUI** (gpui-kit / gpui-pre): see above; supply chain and API churn, 406 crates, the window buttons missing from UI Automation, MPL-2.0 assets.
- **Slint under the Royalty-free License 2.0:** would keep the app binary at GPL-3.0-or-later in name, at the price of Slint's attribution terms next to the GPL; rejected by the user.
- **Tauri 2 + Svelte 5 (ADR 0001):** replaced by ADR 0027's Rust-native app: a WebView2 process tree, a second toolchain (npm) with its own supply chain, and an IPC boundary every view model would cross as JSON.
- **The native title bar from the start:** no `unsafe` in `rerun-app` at all, but not the window of `docs/07-ui.md`; kept as the fallback.

## Consequences
- ADR 0001 is superseded for the GUI. `app/` (the Tauri skeleton) is removed in P5-3, when `crates/rerun-app` is created, together with what refers to it: the `exclude` and its comment in `Cargo.toml`, `app/src-tauri` in the roots of `crates/rerun-core/tests/source_rules.rs`, the Tauri lines of `.gitignore`, the hardening loop of `.github/workflows/ci.yml` (`rerun-app` joins `rerun-cli` and `rerun-helper`).
- `deny.toml` changes in P5-3, when Slint enters the lock file, not before: `BSL-1.0` joins the allow list (GPL-compatible; `clipboard-win`, `error-code`), and one exception per Slint crate allows `GPL-3.0-only` (`slint`, `slint-build`, `slint-macros`, `i-slint-backend-selector`, `i-slint-backend-winit`, `i-slint-common`, `i-slint-compiler`, `i-slint-core`, `i-slint-core-macros`, `i-slint-renderer-software`, and `i-slint-renderer-femtovg` if kept), never `GPL-3.0-only` globally; the comment "prepared for later phases (Tauri, rustls ...)" goes. `README.md` gains the sentence on the app binary's licence.
- Tests with P5-3: source rules (Slint only in `ui`, `unsafe` and window calls only in `ui::chrome`, no `as_raw_str`); `cargo tree -e normal` of `rerun-cli`, `rerun-launch`, `rerun-helper` and `rerun-cpu` holds no `slint` or `i-slint-*` crate; the hardening checks on the release `rerun-app.exe` (imports, loaded DLLs, manifest, no index test key); the start time; a UI Automation dump in the sandbox suite (every interactive element named, with a role and keyboard-focusable).
- Docs: `docs/01-architecture.md` and `docs/08-roadmap.md` (phase 5) with this ADR; `docs/06-security.md` (the GUI process) and `docs/09-testing.md` with P5-3.

## Open points
- **Smart App Control and ICU.** On the developer machine Smart App Control blocked the build scripts of `icu_decimal_data` and `icu_locale_fallback_data` 2.4.0, which Slint's locale support pulls in. A parallel check builds without that feature (option b); if it holds, the feature stays off. A workaround on the machine never reaches the workspace (no `[patch]` of third-party crates).
- **Renderer.** Either the software renderer always, or femtovg (OpenGL) with the software renderer as the fallback. Recommended for evaluation: **software always**. The UI is static, the software renderer is pixel-identical at a quarter of the memory (26 MB against 111 MB), needs no GPU and loads no OpenGL driver into the process, and dropping femtovg drops its crates. To measure in P5-3: CPU while scrolling the library and resizing the window at 4K; the release profile (opt 3 or "s") is decided with it.
- **Accessibility gaps** of the spike, each with its mitigation, checked in P5-3:
  - no heading role: page titles carry the page name as the label of the main region, and switching a page moves focus there so Narrator reads it; an upstream request for a heading role;
  - the spike's toggles and radio buttons report "not keyboard-focusable" to UI Automation: P5-3 finds whether the markup (no focus scope) or the adapter causes it; full keyboard operation is tested either way;
  - rows outside the visible part of the list are missing from UI Automation: the list's label carries the number of games, keyboard navigation scrolls the focused row into view so Narrator reads it, and P5-3 finds whether clipping or virtualisation hides them;
  - Windows' text size setting, high contrast and "show animations" are read for `theme::tokens` (ADR 0027); where that read lives (`ui::chrome` or a read-only `sys` call) is decided with P5-3.
- **cargo-deny runs in CI only.** Smart App Control blocks the `cargo-deny` binary on the developer machine (os error 4551), so the licence check of the P5-3 commit is the CI job `deny`, before the push is considered done.
- **Third-party notices.** How the licence list shown in the app is generated without a new dependency (P5-10).

## Amendment P5-3 (2026-11-12): measured with the app

- **Renderer: software, always.** `ui::run` selects the winit backend with the software renderer; `renderer-femtovg` is not enabled, so no OpenGL crate is in the tree and no OpenGL or Direct3D DLL is loaded. Release build on the developer machine: the window is visible 40 to 70 ms after the process starts (five runs; gate 1 s), working set about 34 MB (13.5 MB private) with 39 games listed, no CPU while idle, about 0.42 s of CPU over 3.2 s of continuous resizing at about 2560 x 1400. Scrolling was not measured reliably (posted wheel messages are ignored by winit); a hand check follows. The release profile stays the workspace's (opt 3).
- **Gates.** `restrict_dll_search` is the first statement and the binary carries `/DEPENDENTLOADFLAG:0x800`, an embedded `asInvoker` manifest with per-monitor DPI awareness V2 and the import allowlist `APP_IMPORTS` (`tests/support/hardening.rs`). Every module the running release app loaded came from System32 (and comctl32 from WinSxS); none from the install folder. The renderer loads no OpenGL or Direct3D DLL; the system page loads `dxgi.dll` from System32 for the system profile, as `rerun system` does (`sys::win::loader`). The firewall DLLs of the first measurement came from the applied page's orphaned-rule read, which the review moved to P5-6 (the page reads the journal only).
- **Smart App Control and ICU.** Option b is not available: `i-slint-common` pulls the ICU4X data crates unconditionally (`icu_decimal/compiled_data` through `color-parsing` of the compiler), not behind a feature. The workspace stays unpatched; the developer machine builds with a local source replacement outside the repository (`.dev/sac-build`, `--config`), CI from crates.io.
- **Accessibility, first findings** (UI Automation dump of the release build): window buttons, navigation entries (tab items with the selected state), buttons, rows (list items with name, detail and status) and the switch are named, have roles and take the keyboard focus; Tab walks navigation, controls and rows, the focused row is scrolled into view (the gap "rows outside the visible part" is handled for keyboard users this way, the tree itself holds only the visible part). The page title takes the focus when a page opens. Open: the search field was not reached by Tab in the automated walk (to check by hand), the switch is reported as a button with a toggle state, a Narrator pass by the user.
