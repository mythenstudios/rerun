# 02 · Topo and package format (v1)

A **Topo** describes a game: how it is detected, which problems it has on which hardware, and which solutions exist. A **package** describes an upstream tool (DXVK, Special K, EaglePatch …) that Topos reference. The name comes from climbing: a topo is the route sketch for exactly one wall.

Both are YAML, are validated against `schema/topo.schema.json` or `schema/package.schema.json` (JSON Schema 2020-12) and are **purely declarative**. Validation and YAML rules: ADR 0005.

## General rules

- **YAML 1.2:** Booleans only `true`/`false`. `off`, `yes`, `on` are strings and therefore errors in bool fields. No merge keys, no duplicate keys; anchors/aliases are rejected entirely from Phase 4.
- **Unknown fields are errors** (`additionalProperties: false` everywhere).
- **File name = `id`**, e.g. `topos/assassins-creed-dc.yaml` has `id: assassins-creed-dc`. IDs: lowercase letters, digits, hyphens, at most 64 characters.
- **Hashes** in uppercase hex (`sha1`: 40, `sha256`: 64 characters).
- **`TODO`** is only allowed in: hashes (`sha1`, `sha256`), package `version`, `license`, `arch`, `source.release`, `assets[].url`, INI `section`/`key`, option `default`. If a file contains `TODO` anywhere, it must be `status: draft` (test). Unknown values are never invented.
- **Paths** (`match.exes[].path`, `files[].from/to`, `options.*.ini.file`) are relative to the game folder and must not leave it lexically:
  - no `..`/`.`, no drive, no leading separator, no UNC, no `:` (so also no Alternate Data Streams)
  - no characters `< > " | ? *` or control characters
  - no invisible or confusable Unicode characters (bidi control characters, zero-width, special spaces, fullwidth ASCII such as `．＼`, `¥`/`₩`, slash lookalikes)
  - no reserved device names (`CON`, `NUL`, `CONIN$`, `CLOCK$`, `COM1` …, also with extension)
  - no dot/space at the end of a segment, no space at the start of a segment
  - no `~` followed by a digit (8.3 short names; also blocks names like `Data~2024`)
  - at most 240 characters; `/` and `\` are both allowed

  Same rules as `rerun_core::policy::path::RelPath`. Comparisons are case-insensitive (`D3D9.dll` = `d3d9.dll`).
- **URLs:** always `https://`, host only from ASCII lowercase letters, digits and hyphens with a letter TLD. No port, no userinfo (`@` before the host), no IP literals, no backslash.

## Topo

```yaml
format: 1
id: assassins-creed-dc
title: "Assassin's Creed: Director's Cut Edition"
status: draft            # draft | active | needs-retest | retired
rev: 1
tested_on: [x64]         # x64 | arm64

match:
  steam_appid: 15100
  exes:                  # at least one; sha1 or sha256 required
    - { path: "AssassinsCreed_Dx9.exe",  sha1: "A9EA476E70F076709CCA59A802E26EC894432120", api: d3d9 }
    - { path: "AssassinsCreed_Dx10.exe", sha1: "601475FD5EFA02BBAE80D1C06DFA25A0A1E7FD2F", api: d3d10 }

launch:
  chain: [steam, upc]    # steam | upc | ea-app | rockstar | battlenet | epic | gog-galaxy
  method: auto           # auto | direct | watch | hold | ifeo | inproc
  fallback: inproc       # like method, without auto

issues:
  - id: controller
    title: "Modern controllers are not detected, no hotplug"
    when: {}             # empty = all systems
    variants:
      - id: steam-input
        status: unverified
        kind: fix
        steps: [{ steam_input: enable }]
      - id: eaglepatch
        status: reported
        kind: fix
        steps: [{ package: eaglepatch-ac1 }]
        tradeoffs: ["Old DInput controllers are no longer supported"]
        sources:
          - { type: repo, url: "https://github.com/Sergeanur/EaglePatch" }

tips:
  launch_options: []
  notes: []

links:
  pcgw: "Assassin's_Creed"   # page name, not a URL
```

### Fields

- `steam_appid` (in `match`, optional): the Steam app ID as an integer from 1 to 4294967295 (`u32`), the same range `detect::steam::files::AppManifest` accepts for `appid` in `appmanifest_<appid>.acf` (ADR 0011).
- `api` (in `match.exes`): `ddraw | d3d8 | d3d9 | d3d10 | d3d11 | opengl`. Detection also recognises `d3d12`, `vulkan` and `glide` (ADR 0014); these spellings are reserved for an additive extension of `$defs/api` in both schemas, made with the first Topo or package that needs them (phase 4 at the latest) and before the first release.
- `variants`: may be empty = "no known fix", a valid answer.
- `status` per variant: `verified` (tested ourselves, with hardware in the changelog), `reported` (several independent reports), `unverified` (single statement).
- `kind` (required): `fix` (game runs as intended) or `enhancement`.
- `when`: conditions against the system profile (ADR 0015). Several fields = AND. Only these fields:
  ```yaml
  when:
    gpu.vendor: amd                 # amd | nvidia | intel
    gpu.arch: [vega, rdna1, rdna2]  # identifiers declared in data/gpu-arch.yaml (archs)
    cpu.threads: { gt: 12 }         # gt | gte | lt | lte | eq; several in one object = AND (range)
    cpu.hybrid: true
    os.build: { gte: 22000 }
  ```
  - GPU keys use the **conditions adapter**: the first hardware adapter in DXGI order (software adapters and vendor `0x1414` skipped). A per-game adapter comes with `gpu_preference` (`03b-gpu-display.md`).
  - `gpu.vendor`: from the PCI vendor ID (`0x1002` amd, `0x10DE` nvidia, `0x8086` intel); any other vendor matches none.
  - `gpu.arch`: identifiers matching `^[a-z][a-z0-9_]{0,31}$`, never `unknown`, each declared in `archs` of `data/gpu-arch.yaml` (`03b-gpu-display.md`); from phase 4 the loader rejects an undeclared one. A device the table does not know matches no list.
  - `cpu.threads`: logical processors available system-wide (`CpuTopology::logical_count`, CPU Sets flagged `RealTime` or `Allocated` excluded, ADR 0010), not Rerun's process affinity. Above 64, a game that asks `GetSystemInfo` sees only its processor group.
  - `cpu.hybrid`: `true` when Windows reports more than one efficiency class.
  - `os.build`: `CurrentBuildNumber` of `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion` (e.g. 22000, the first Windows 11 build); the update revision (`UBR`) is never compared.
  - Evaluation (phase 4): each key is yes, no or unknown; a `when` is no if any key is no, else unknown if any key is unknown, else yes; an empty `when` is yes. A fact Rerun could not read is unknown; a variant whose `when` is unknown is never preselected or applied automatically. `when` selects suggestions and is never authorisation. Details: ADR 0015.
- `checks`: pure hints about runtimes outside the game folder. Rerun does not install them (game folder boundary), but shows a hint with a link. Values: `{ runtime: vcredist-x86 | vcredist-x64 | directx-jun2010 }`.
- `steps`: list of primitives. Each step is an object with **exactly one** key. Allowed in v1: `package: <package-id>`, `steam_input: enable`, `cpu: <CPU rule>`, `registry_set: <key and values>`, `compat_layer: <executable and tokens>`, `ini_set: <file and values>` (below). A `package` step is carried out by the `file_install` primitive: the package's files with their pinned hashes become `file_install` ops (ADR 0020); `file_install` itself is not a Topo step. Further primitives from `01-architecture.md` enter the schema only together with their spec and implementation; before that they are a validation error. Until the Topo engine exists (phase 4), `rerun plan` reads these step objects from a JSON step file (ADR 0020, user decision D7).
  - The `file_install` step object (phase 2 step file only, `deny_unknown_fields`): `{"file_install":{"package":"<package id>","version":"<version>","files":[{"from":"<path below the version folder>","to":"<path below the game folder>","sha256":"<64 lower-case hex digits>","config":false}]}}`. `package` and `version` follow the package rules below; `from` and `to` are relative paths (`RelPath`); `config` (default `false`) marks a file the user may edit: once it differs from what was installed, a revert leaves it (`Foreign`). Each `to` at most once and never below another `to`; missing folders are created one by one, a target with the same content is skipped, any other existing plain file is replaced (its backup goes into the journal), a hard-linked target is refused (ADR 0017, D1). New files get no read-only, hidden or system attribute.
  - The `registry_set` step (Topo step and step-file object alike, `deny_unknown_fields`; ADR 0018, ADR 0020 amendment P2-10b):
    ```yaml
    registry_set:
      key: 'HKCU\Software\<Vendor>\<Product>'   # optionally up to 4 more segments
      values:
        - { name: Windowed, dword: 1 }
        - { name: Lang, sz: en }
        - { name: Seed, qword: "18446744073709551615" }   # a decimal string
    ```
    `key` begins exactly with `HKCU\Software\` (`HKLM\…` needs the elevated helper of phase 3 and is refused in phase 2), then `<Vendor>\<Product>` and at most 4 more segments, each 1 to 64 printable ASCII characters without `\` and without a space at either end; `<Vendor>` is not on the deny list (`Microsoft`, `Classes`, `Policies`, `Wow6432Node`, `Clients`, `RegisteredApplications`, `AppDataLow`, `Valve`, `Rerun`, `Mythen Studios`, `Khronos`), compared case-insensitively by the loader and the planner (the schema checks only the form). 1 to 32 `values`, names unique (case-insensitive), each a `name` (0 to 128 printable ASCII characters without `\ / : %`; `""` is the default value) and exactly one of `dword` (0 to 4294967295), `qword` (a decimal string without sign or leading zero, `"0"` allowed) or `sz` (at most 1,024 printable ASCII characters without `\ / : %`: no paths, no variables; `null` is refused). `REG_BINARY` and the other types are not written. Missing keys from `<Vendor>` down are created one by one; a value that already holds the new value is skipped; any other old value (another type, a raw value, up to 1 MiB) is kept in the journal and restored exactly. The same value in two steps is refused; a plan with registry ops needs the game's main executable (to check that the game is closed); every registry op runs after every file op of the plan. A game that later fills a created key or changes a value (also by writing another type) is left as it is: the revert reports it and only `forget` closes the transaction.
  - The `compat_layer` step (Topo step and step-file object alike, `deny_unknown_fields`; ADR 0018 and ADR 0020, amendments P2-11):
    ```yaml
    compat_layer:
      exe: 'bin\game.exe'        # required, relative to the game folder
      layers: [<token>, <token>] # 1 to 8 tokens of the allowlist
    ```
    Compatibility-layer tokens for one executable of the game folder, in `HKCU\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers` (value name: the executable's canonical path, as the Compatibility tab of its Properties writes it). `exe` is a relative path to a plain `.exe` file below plain folders (no link or other reparse point on the way); the plan names it in the spelling stored on disk. `layers`: 1 to 8 unique tokens (`[A-Z0-9_]`, at most 40 characters), each on Rerun's token allowlist. **The allowlist is empty until the Windows Sandbox probes have fixed how Windows spells each token** (`docs/09-testing.md`, SB-L1 to SB-L3), so every `compat_layer` step is refused today; the list will name a source for every token, and only tokens the Compatibility tab itself writes are candidates. Elevation tokens (`RUNAS…`) are never added. Rerun never sets the value: it appends the tokens to whatever is there (every other token, `RUNASADMIN` included, stays as it is) and leaves out a token already present; a token of the same group as one already there (another operating-system mode, DPI, colour or resolution setting) is refused rather than replaced; a value in another form (another type, two spaces, a tab, non-ASCII, longer than 511 characters) is refused and left alone. Missing keys (`AppCompatFlags`, `Layers`) are created; they are shared with Windows, and a revert deletes them only when they are empty. A revert restores the old value exactly if nobody changed it since; otherwise it removes only the tokens Rerun added and keeps the rest, also when the user removed one of them (a value that holds one of Rerun's tokens twice, or in another case, is left and reported). A game folder reached through a link or by another name than its canonical path (a junctioned library, an 8.3 name) is refused until the Sandbox has shown which name Windows matches. Two `compat_layer` steps for one executable are refused; a plan with registry ops needs the game's main executable.
  - The `ini_set` step (Topo step and step-file object alike, `deny_unknown_fields`; ADR 0021, ADR 0020 amendment P2-12):
    ```yaml
    ini_set:
      file: 'cfg\game.ini'         # an existing .ini file, relative to the game folder
      values:                      # 1 to 8
        - { section: Display, key: Width, value: "1920" }
        - { section: Display, key: Fullscreen, value: "1" }
    ```
    Sets keys of one existing INI file of the game folder. `file`: a relative path ending in `.ini` (any case; not `desktop.ini`; no `.cfg` yet) to a plain file below plain folders, at most 1 MiB, not hard-linked, without the system attribute, no cloud placeholder; the plan names it in the spelling stored on disk. A missing file is refused (start the game once so it writes it, or ship it with a package; an `ini_set` and a package file for the same file in one plan are refused). The file is ANSI or UTF-8, with or without BOM, with CRLF or LF line endings; UTF-16 is refused until phase 4. `section` and `key`: `[A-Za-z0-9_. -]`, 1 to 64 characters, no space at either end, compared case-insensitively (the file's spelling stays); `value`: 1 to 128 printable ASCII characters, no space at either end, none of `\ / : % ; #` and no `..` (no paths, no environment references, nothing a game may read as a comment). Section and key unique per step (case-insensitive); one `ini_set` step per file. A value the file already holds is left out; an existing key gets only its value replaced (spaces around `=`, comments, order, line endings and every other byte stay); a missing key is inserted right after its section header; a missing section is appended at the end (refused in a file without any section header). Refused rather than guessed: a section or key that appears twice, a header of the section in another form (`[ Display ]`, text after `]`), a line starting with `[` without `]`, an old value that is not printable ASCII or longer than 128 characters, keys outside a section. The plan needs the game's main executable: it must be the program that writes the INI file when it exits (with a launcher, the game itself; `04-launch-methods.md`). A revert restores the file exactly if nobody changed it since; if the game rewrote it, only the keys that still hold Rerun's value are set back (a key the game or the user changed stays, and everything else in the file stays); a file deleted since stays deleted.
- `sources`: links directly to the guide, thread, repo or section, always `https://`, never just the home page. Types and patterns:
  - `repo`: `https://github.com|gitlab.com|codeberg.org/<owner>/<repo>[/…]`
  - `steam-guide`: `https://steamcommunity.com/sharedfiles/filedetails/?id=<n>`
  - `steam-thread`: `https://steamcommunity.com/app/<n>/discussions/<n>/<n>/` or `…/groups/<name>/discussions/<n>/<n>`
  - `pcgw`: `https://www.pcgamingwiki.com/wiki/<page>[#section]`
  - `official`: `https://<host>/<path>` (with path)
- `tips.launch_options`: individual game arguments that Rerun places **after** `%command%`, e.g. `-nointro`, `-dx9`, `+fps_max=60`. Pattern `^[-+][A-Za-z0-9_.=+-]+$`, at most 64 characters: no commands, no `%`, no quotes, no spaces. The part before `%command%` (e.g. `rerun-launch`) is generated by Rerun itself, never taken from the Topo. Escaping is applied when writing `localconfig.vdf`.
- `tips.notes`: list of `{ text, source? }`. Free text is never rendered as HTML in the UI.

### CPU rules (in `launch.cpu` or as a step)

```yaml
cpu:
  max_threads: 8          # 1–1024
  prefer: performance     # performance | any
  single_l3: true         # keep on one CCD/CCX
  prefer_l3: largest      # prefer the V-Cache CCD
  smt: false              # false = only one thread per core
  mode: hard              # hard (affinity) | soft (CPU Sets)
  report_cores: 8         # only in launch.cpu and only with method: inproc
```

Never concrete thread numbers in Topos. See `03-cpu-topology.md`. `shim_single` (`04-launch-methods.md`) enters the enum `method` only with Phase 6.

## Package

```yaml
format: 1
id: eaglepatch-ac1
name: EaglePatchAC1
status: draft             # draft | active | needs-retest | retired
tier: established         # official | established | community
source:
  repo: "https://github.com/Sergeanur/EaglePatch"
  release: "TODO"         # exact release URL
version: "TODO"
sha256: "TODO"            # computed ourselves
license: "TODO"           # SPDX expression, e.g. MIT, Zlib, "MIT OR Apache-2.0"
arch: [x86]               # always a list: x86 | x64
requires: [ultimate-asi-loader]
slots: []                 # occupied DLL names in the game folder
supports_exe_sha1:
  - "A9EA476E70F076709CCA59A802E26EC894432120"
files:
  - { from: "EaglePatchAC1.asi", to: "scripts/EaglePatchAC1.asi" }
  - { from: "EaglePatchAC1.ini", to: "scripts/EaglePatchAC1.ini", config: true }
options:
  ps3_controls: { ini: { file: "scripts/EaglePatchAC1.ini", section: "TODO", key: "TODO" }, default: false }
  shadows_4096: { ini: { file: "scripts/EaglePatchAC1.ini", section: "TODO", key: "TODO" }, default: true, kind: enhancement }
```

### Download

Exactly one of the two forms (except for `community`):

- **One download:** `source.release` + `sha256`.
- **Separate builds per architecture:** `assets: [{ arch, url, sha256 }]`, then without `source.release` and without top-level `sha256` (e.g. Ultimate ASI Loader).

**Provenance:** Every download URL must belong to the original, i.e. start with `<source.repo>/releases/download/` or be located on the host of `source.page`. A test checks this (`download_urls_belong_to_the_source`), and from Phase 4 the loader does too. The SHA256 secures integrity, not provenance.

With `tier: community` (see `05-sources-policy.md`), `source.page` (original page) is required and there is **no** direct download (`source.release` and `assets` forbidden). Rerun opens the page, the user downloads it themselves, Rerun then checks `sha256`.

### Fields

- `version`: `^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$`, without `..` (can safely appear in cache paths).
- `slots`: DLL file names that the package occupies in the game folder (`dinput8.dll`, `d3d9.dll`, `dxgi.dll` …), following the path rules (no `CON.dll`, no `X~1.dll`). Two packages with the same slot = conflict, unless one allows chainloading.
- `apis` + `slots_by_api`: for wrappers whose slots depend on the game's graphics API (DXVK).
- `requires`: shared dependencies are reference-counted. A package is removed only when nothing needs it anymore. Every referenced ID must exist as a package (test).
- `requires_gpu`: GPU prerequisites, v1: `[vulkan]`.
- `supports_exe_sha1`: exe versions the package is built for.
- `files[]`: `{ from, to, config?, arch?, api? }`. `arch`/`api` restrict an entry to specific architectures or APIs. Folders are derived from `to`.
- `options`: INI values that appear as toggles in the UI; `kind` as for variants. `section` and `key`: `^[A-Za-z0-9_. -]+$`. String `default`: no control characters (no CR/LF), no absolute paths, no `..`. Options are meant to be applied through `ini_set` (ADR 0021), whose rules are narrower: names of 1 to 64 characters without a space at either end, values of 1 to 128 printable ASCII characters without `\ / : % ; #`, an existing `.ini` file. The package schema is aligned with them when options are implemented (phase 4); until then an option outside them could not be applied.
- `config: true`: the file is meant to be modified by the user. A revert never overwrites or deletes a file whose content is no longer what Rerun wrote, whether `config` is set or not, and never asks: the change stays unresolved, its backup stays in the journal and `forget` closes it (user decision D10, ADR 0020). `config` is a hint for the preview and for `ini_set` options on that file.

## Signed index

`index.json` lists all Topos and packages with SHA256. `index.json.sig` = Ed25519 signature. The client checks the signature before parsing anything. The public key is built into the binary.
