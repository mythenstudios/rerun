# 02 · Topo and package format (v1)

A **Topo** describes a game: how it is detected, which problems it has on which hardware, and which solutions exist. A **package** describes an upstream tool (DXVK, Special K, EaglePatch …) that Topos reference. The name comes from climbing: a topo is the route sketch for exactly one wall.

Both are YAML, are validated against `schema/topo.schema.json` or `schema/package.schema.json` (JSON Schema 2020-12) and are **purely declarative**. Validation and YAML rules: ADR 0005.

## General rules

- **YAML 1.2:** Booleans only `true`/`false`. `off`, `yes`, `on` are strings and therefore errors in bool fields. No merge keys, no duplicate keys; anchors/aliases are rejected entirely from Phase 4.
- **Unknown fields are errors** (`additionalProperties: false` everywhere).
- **File name = `id`**, e.g. `topos/assassins-creed-dc.yaml` has `id: assassins-creed-dc`. IDs: lowercase letters, digits, hyphens, at most 64 characters.
- **Hashes** in uppercase hex (`sha1`: 40, `sha256`: 64 characters).
- **`TODO`** is only allowed in: hashes (`sha1`, `sha256`), package `version`, `license`, `arch`, `source.release`, `assets[].url`, INI `section`/`key`, option `default`, `launch.start`. If a file contains `TODO` anywhere, it must be `status: draft` (test). Unknown values are never invented.
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
  start: "TODO"          # Steam's launch entry, relative to the game folder (below); TODO only in a draft
  # priority: above_normal                   # normal | above_normal | high (below)

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

- `exes` (in `match`): 1 to 8 entries (each is hashed when the engine reads a game).
- `steam_appid` (in `match`, optional): the Steam app ID as an integer from 1 to 4294967295 (`u32`), the same range `detect::steam::files::AppManifest` accepts for `appid` in `appmanifest_<appid>.acf` (ADR 0011).
- `api` (in `match.exes`): `ddraw | d3d8 | d3d9 | d3d10 | d3d11 | opengl`. Detection also recognises `d3d12`, `vulkan` and `glide` (ADR 0014); these spellings are reserved for an additive extension of `$defs/api` in both schemas, made with the first Topo or package that needs them (phase 4 at the latest) and before the first release.
- `launch.start`: the program of **Steam's launch entry**, what Steam starts on Play (a launcher such as `FFLauncher.exe` may start the game itself), relative to the game folder, a `.exe`. `rerun-launch` applies a rule only when Steam's first argument is exactly this program (else `path_mismatch`, an unchanged start). Rerun does not read Steam's `appinfo.vdf` (ADR 0022 amendment P3-3, E2 a): find the entry in Steam's process tree while the game runs, or start it once through a profile and read `rerun status` (`path_mismatch` names the case); never guess, unknown is `TODO` with status `draft`. Required for `direct`, `watch` and `auto` by the Topo loader and the schema (P4-4; `TODO` only in a draft); the step `launch_method` of a step file names it itself (below).
- `launch.priority`: `normal`, `above_normal` or `high` (never realtime), set by `rerun-launch` at the start and checked about 5 s later. With `direct` only when `launch.start` is the game itself: a launcher does not pass a priority class on to the game it starts (ADR 0022 amendment P3-3); `watch` sets it on the game process it finds.
- `anti_cheat` (optional, P4-4): `{ dead: [<system>, …], source: <source> }`. Releases anti-cheat systems of this game that are verifiably dead (servers shut down, checks off), so the engine's anti-cheat rule (below) does not count them when it finds their markers. Systems: `easy-anti-cheat`, `battleye`, `punkbuster`, `gameguard`, `xigncode`, `ea-anticheat`; at least one, unique; `source` in the form of `sources` below, showing that the system is dead. Draft only until the field is reviewed (loader and schema; the signed index holds none yet).
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
- `steps`: list of primitives. Each step is an object with **exactly one** key. Allowed in v1: `package: <package-id>`, `steam_input: enable`, `cpu: <CPU rule>`, `registry_set: <key and values>`, `compat_layer: <executable and tokens>`, `ini_set: <file and values>`, `firewall_rule: <executable and direction>` (below; draft only until reviewed). A `package` step is carried out by the `file_install` primitive: the package's files with their pinned hashes become `file_install` ops (ADR 0020); `file_install` itself is not a Topo step. Further primitives from `01-architecture.md` enter the schema only together with their spec and implementation; before that they are a validation error. `rerun plan <app-id>` plans them from the signed index (the Topo engine, below); `rerun plan <steps.json>` still reads the same step objects from a local JSON step file (ADR 0020, user decision D7, L8).
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
    Compatibility-layer tokens for one executable of the game folder, in `HKCU\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers` (value name: the executable's canonical path, as the Compatibility tab of its Properties writes it). `exe` is a relative path to a plain `.exe` file below plain folders (no link or other reparse point on the way); the plan names it in the spelling stored on disk. `layers`: 1 to 8 unique tokens (`[A-Z0-9_]`, at most 40 characters), each on Rerun's token allowlist: the table in `docs/05-sources-policy.md`, "Reference data" (each token spelled as the Compatibility tab writes it, with its tab label and source; ADR 0018 amendment P2-11b). Never added: elevation tokens (`RUNAS…`), `REGISTERAPPRESTART` (Windows would start the program again by itself after a restart, core rule 1), operating-system modes (not yet: `WINXPSP3` makes a 32-bit game ask for administrator rights at every start, the others are not measured), and anything the tab was not seen to write. Of the tab's three DPI options only Application (`HIGHDPIAWARE`) can be added. Rerun never sets the value: it appends the tokens to whatever is there (every other token, `RUNASADMIN` included, stays as it is) and leaves out a token already present; a token of the same group as one already there (another operating-system mode, DPI, colour or resolution setting) is refused rather than replaced; a value in another form (another type, two spaces, a tab, non-ASCII, longer than 511 characters) is refused and left alone. Missing keys (`AppCompatFlags`, `Layers`) are created; they are shared with Windows, and a revert deletes them only when they are empty. A revert restores the old value exactly if nobody changed it since; otherwise it removes only the tokens Rerun added and keeps the rest, also when the user removed one of them (a value that holds one of Rerun's tokens twice, or in another case, is left and reported). A game folder reached through a link or by another name than its canonical path (a junctioned library, an 8.3 name) is refused: Windows applies a layer only when the game is started by exactly the path of the value name (SB-L2). An old value with a prefix joined to a word (`~X`) or a lone `~` or `$` after a word is refused as unusual. The "all users" value of the same executable (`HKLM\…\AppCompatFlags\Layers`, written by "Change settings for all users"; native and 32-bit view) is read, never written: a setting there of the same group as a token Rerun would add (e.g. `HKLM` `~ DPIUNAWARE` against `HIGHDPIAWARE`) is refused, as is such a value that cannot be read or is in another form; otherwise the preview names it (ADR 0018 amendment P3-6). Two `compat_layer` steps for one executable are refused; a plan with registry ops needs the game's main executable.
  - The `ini_set` step (Topo step and step-file object alike, `deny_unknown_fields`; ADR 0021, ADR 0020 amendment P2-12):
    ```yaml
    ini_set:
      file: 'cfg\game.ini'         # an existing .ini file, relative to the game folder
      values:                      # 1 to 8
        - { section: Display, key: Width, value: "1920" }
        - { section: Display, key: Fullscreen, value: "1" }
    ```
    Sets keys of one existing INI file of the game folder. `file`: a relative path ending in `.ini` (any case; not `desktop.ini`; no `.cfg` yet) to a plain file below plain folders, at most 1 MiB, not hard-linked, without the system attribute, no cloud placeholder; the plan names it in the spelling stored on disk. A missing file is refused (start the game once so it writes it, or ship it with a package; an `ini_set` and a package file for the same file in one plan are refused). The file is ANSI or UTF-8, with or without BOM, with CRLF or LF line endings; UTF-16 is refused until phase 4. `section` and `key`: `[A-Za-z0-9_. -]`, 1 to 64 characters, no space at either end, compared case-insensitively (the file's spelling stays); `value`: 1 to 128 printable ASCII characters, no space at either end, none of `\ / : % ; # [ ]` and no `..` (no paths, no environment references, nothing a game may read as a comment). Section and key unique per step (case-insensitive); one `ini_set` step per file. A value the file already holds is left out; an existing key gets only its value replaced (spaces around `=`, comments, order, line endings and every other byte stay); a missing key is inserted right after its section header; a missing section is appended at the end (refused in a file without any section header). Refused rather than guessed: a section or key that appears twice, a header of the section in another form (`[ Display ]`, text after `]`), a line starting with `[` without `]`, an old value that is not printable ASCII or longer than 128 characters, keys outside a section. The plan needs the game's main executable: it must be the program that writes the INI file when it exits (with a launcher, the game itself; `04-launch-methods.md`). A revert restores the file exactly if nobody changed it since; if the game rewrote it, only the keys that still hold Rerun's value are set back (a key the game or the user changed stays, and everything else in the file stays); a file deleted since stays deleted.
  - The `firewall_rule` step (Topo step only, `deny_unknown_fields`; ADR 0023 §6, P4-5a):
    ```yaml
    firewall_rule:
      exe: 'bin\game.exe'   # required: a path of match.exes
      direction: out        # required; only out (the game cannot connect) for now
    ```
    Rerun's own Windows Firewall block rule for one executable, added and removed by the elevated helper (ADR 0023; the helper re-derives it from the signed index). `exe` is a relative path ending in `.exe` that names an entry of `match.exes` in exactly its spelling (case included: the rule's program is derived from that entry) and that entry must carry a `sha256` (ADR 0024, "sha256 for elevated anchors": `sha1` alone never anchors anything elevated; `TODO` only in a draft). The rule has one form (`policy::firewall::rule`): name `Rerun - <topo-id> - <txn>-<op:03>`, group `Rerun`, action block, every profile, any protocol, the program the game folder's canonical path plus `exe` (no `%`, at most 243 characters), compared with what the firewall returns with ASCII case ignored, every other field at the firewall's default. Rerun never changes or removes any other rule, profile, default policy or the firewall's on/off state; a rule of that name that is not exactly Rerun's is `Foreign` and left alone. `direction` is required and only `out` is allowed for now (`in` may follow without a format break when a Topo needs it). The step was **draft only** until it was reviewed with the helper chain; since the [DEV] round trip through the real prompt and helper passed (P4-5b, 2026-11-10) it is reviewed (`FIREWALL_RULE_REVIEWED`), and a signed index may hold it like any other step (the schema no longer requires `status: draft` for it). Setting the constant back makes it draft only again. From P4-2d the engine plans it as a `firewall_rule` op after every other op of the plan (`{"firewall_rule":{"root":0,"program":"<exe>","direction":"out"}}`), built only from what the helper derives itself (`elevate::check_plan`: the executable there with its signed SHA-256, no anti-cheat, a drive that opens by identity; at most 8 rules, no executable twice); the apply starts the helper once, after every other change, and a revert removes the rules first. The anti-cheat rule refuses it (below).
- `sources`: links directly to the guide, thread, repo or section, always `https://`, never just the home page. Types and patterns:
  - `repo`: `https://github.com|gitlab.com|codeberg.org/<owner>/<repo>[/…]`
  - `steam-guide`: `https://steamcommunity.com/sharedfiles/filedetails/?id=<n>`
  - `steam-thread`: `https://steamcommunity.com/app/<n>/discussions/<n>/<n>/` or `…/groups/<name>/discussions/<n>/<n>`
  - `pcgw`: `https://www.pcgamingwiki.com/wiki/<page>[#section]`
  - `official`: `https://<host>/<path>` (with path)
- `tips.launch_options`: individual game arguments that Rerun places **after** `%command%`, e.g. `-nointro`, `-dx9`, `+fps_max=60`. Pattern `^[-+][A-Za-z0-9_.=+-]+$`, at most 64 characters: no commands, no `%`, no quotes, no spaces. The part before `%command%` (e.g. `rerun-launch`) is generated by Rerun itself, never taken from the Topo. Escaping is applied when writing `localconfig.vdf`.
- `tips.notes`: list of `{ text, source? }`. Free text is never rendered as HTML in the UI.

### The Topo engine (`rerun plan <app-id>`, P4-4)

ADR 0020 amendment P4-4. Reads only the current signed index, the game folder and the system profile; `appinfo.vdf` is never read.

- **Match:** the Topos naming the Steam app; every `match.exes` entry is hashed on the handle it was parsed on and matches with every hash it names (SHA-256, SHA-1). A Topo matches when one entry does; the first matching entry is the main executable. Retired Topos are listed and never chosen; exactly one of the others must match, otherwise nothing is offered. The signed index never holds two Topos that are not retired with the same app and an executable hash in common.
- **Report** (no `--pick`): every issue with its `when` here (yes, no, unknown), every variant with its status and kind, refused ones with the reason, anti-cheat warnings. Nothing is preselected, nothing stored.
- **Plan** (`--pick <issue>/<variant>`, repeated, one variant per issue): `when = no` is refused; `unknown` is planned only on this explicit pick, with a warning. `registry_set`, `compat_layer` and `ini_set` are planned as they are; a `cpu` step becomes the launch profile with the Topo's method, `launch.start` and `launch.priority` (one CPU rule per plan); `steam_input` is a hint; `package` follows in P4-7; `firewall_rule` steps become `firewall_rule` ops after every other op (P4-2d). The plan has the bytes of a step file with the same steps (and the rules), plus `source` (the SHA-256 of the signed index, the Topo ID and revision, the picks).
- **`launch.method: auto`:** `direct` when `launch.chain` is exactly `[steam]`, else `watch`; resolved at planning time and named in the output. `hold`, `ifeo`, `inproc` refuse a `cpu` step until their phase. `launch.cpu` is not planned yet (the report says "launch.cpu: not planned (pick a cpu step)").
- **Anti-cheat rule** (user decision E4): if the game folder, or the folder of a `match.exes` entry or of `launch.start`, holds a marker of an anti-cheat system (`docs/05-sources-policy.md`, "Reference data"; a marker that cannot be checked counts as found), the engine **refuses** `package`, `laa_patch`, `firewall_rule`, `compat_layer` and a CPU rule with `watch`, `hold`, `ifeo` or `inproc` (they open the protected process, sit in its start or run inside it), and **warns** for a CPU rule with `direct`, `ini_set`, `registry_set` and `gpu_preference`. Systems the Topo releases with `anti_cheat.dead` do not count. Non-goal unchanged (`00-vision.md`): this keeps Rerun away from protected games, it does not support them.
- **Every plan source:** the same rule holds for `rerun plan <steps.json>` (markers in the game folder and the folders of `main_exe` and of a `launch_method` start; `file_install` counts as `package`; nothing is released as dead). A marker the user may not open, or a named folder that is a link or cannot be asked, is counted and never released by `anti_cheat.dead`.

### Phase 2 step file (`rerun plan`)

`rerun plan <steps.json>` reads the steps from a JSON file (ADR 0020, user decision D7; P2-13). Since the Topo engine (P4-4) it is the local, unsigned input for tests, the Sandbox and experts (L8): a target of digits only is a Steam app ID for the engine, anything else a step file. Steps from a step file never reach the elevated helper (they carry no `PlanSource`); it is removed at the earliest before A6.

```json
{"format":1,"game":{"steam":440},"main_exe":"bin\\game.exe","steps":[
  {"ini_set":{"file":"game.ini","values":[{"section":"Display","key":"Width","value":"1920"}]}}]}
```

- `format`: `1`; read first, any other number is refused before anything else is parsed.
- `game`: exactly one of `{"steam": <app id>}` (the installed app found in exactly one Steam library; listed twice, updating or not installed is refused) or `{"folder": "<absolute path>"}` (a drive-letter folder, opened like a manually added game folder, never on the forbidden list).
- `main_exe`: required (user decision E4 a), a relative path to a plain file of the game folder: the program apply and revert ask `users()` about (`04-launch-methods.md`).
- `steps`: the step objects of this section (`file_install`, `registry_set`, `compat_layer`, `ini_set`, `launch_method`), in the order they are planned (the plan puts the launch profile first, then every other file op, then every registry op).

`launch_method` (P3-3c, ADR 0020 and ADR 0022 amendments P3-3), at most one per plan: the launch profile `rerun-launch` reads, written by `apply` to `<LocalAppData>\Rerun\profiles\<id>.profile` (nothing in the game folder, no administrator rights). Stronghold 2 (app 40960), whose Steam entry is a launcher:

```json
{"format":1,"game":{"steam":40960},"main_exe":"Stronghold2.exe","steps":[
  {"launch_method":{"method":"direct","start":"FFLauncher.exe","cpu":{"max_threads":8,"single_l3":true,"smt":false}}}]}
```

- `method`: `direct` (the rule on what Steam starts) or `watch` (P3-4: Steam's command starts unchanged, the rule goes on a new process of `main_exe` found after the start; `04-launch-methods.md`). `auto` is refused in a step file: the Topo engine resolves it (below).
- `start`: as `launch.start` above, relative; `main_exe` stays the game (the program apply and revert ask, D4). The profile's `target` (the program that gets the rule) is `start` for `direct` and `<game folder>\<main_exe>` for `watch`, in the spelling stored on disk; the step has no field for it. With `direct`, `start` and `main_exe` must both be x86 or x64 images and the profile says `x86` if either is i386; with `watch`, only `main_exe` is read (it must be an x86 or x64 `.exe`; `start` must be a plain `.exe`, its image is not read). A .NET "AnyCPU" image is i386 on disk and counts as x86, which limits the game to processors 0 to 31 of a group (ADR 0022 B6).
- `cpu`: a CPU rule (below); `priority`: as `launch.priority`. At least one of the two. With `direct` and `start` other than `main_exe` (a launcher) only a hard rule: `mode: soft` and `priority` are refused, they would reach the launcher only. With `watch` both are allowed (they land on the game), and `start` may be `main_exe` itself (a stub that starts the game again, e.g. through Ubisoft Connect; the preview says that a game that does not start itself again needs `direct`).
- Only for a Steam game in a library at its canonical path (not through a junction); the start and target paths are at most 259 characters each. The profile's ID comes from the Steam app ID, so the launch option stays valid across plans, also when the method changes (`direct` to `watch` replaces the same profile). The same rule planned again is "nothing to do"; another rule replaces Rerun's profile (a revert restores the earlier one). `watch_timeout_s` is always 120 (the search time of `watch`, fixed; unused by `direct`).
- The file is untrusted input: at most 1 MiB, UTF-8 without BOM, `deny_unknown_fields` at every level, read through `policy::root::read_input` (its folder by absolute path, read side only; the file one plain segment below it, never a link; not directly on a drive root, not on a network share). An error names its class, line and column, never the text.

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

Every field is optional, at least one is given (`cpu: {}` is refused). A missing field does not restrict: `max_threads` none, `prefer: any`, `single_l3: false`, `prefer_l3` none, `smt: true`, `mode: hard` (ADR 0022 amendment P3-3, F8). `report_cores` is refused outside `method: inproc` (phase 6). `mode: soft` sets the default CPU Sets of the started program only, a preference Windows may override, and never reaches programs it starts.

Never concrete thread numbers in Topos. See `03-cpu-topology.md`. `single_l3` keeps the game on the LLC with the most threads, which is not always the one with full-size cores: on CPUs with compact cores (Zen 5c next to Zen 5, Ryzen AI 300) it picks the larger Zen 5c cluster. For full-size cores (or the V-Cache CCD) write `prefer_l3: largest`. `shim_single` (`04-launch-methods.md`) enters the enum `method` only with Phase 6.

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
  - { from: "EaglePatchAC1.asi", to: "scripts/EaglePatchAC1.asi", sha256: "TODO" }
  - { from: "EaglePatchAC1.ini", to: "scripts/EaglePatchAC1.ini", sha256: "TODO", config: true }
options:
  ps3_controls: { ini: { file: "scripts/EaglePatchAC1.ini", section: "TODO", key: "TODO" }, default: false }
  shadows_4096: { ini: { file: "scripts/EaglePatchAC1.ini", section: "TODO", key: "TODO" }, default: true, kind: enhancement }
```

### Download

Exactly one of the two forms (except for `community`):

- **One download:** `source.release` + `sha256`.
- **Separate builds per architecture:** `assets: [{ arch, url, sha256 }]`, then without `source.release` and without top-level `sha256` (e.g. Ultimate ASI Loader).

**Provenance:** Every download URL must belong to the original, i.e. be exactly `<source.repo>/releases/download/<tag>/<file>` or be located on the host of `source.page`. A URL that names a release download (`/releases/download/`) has exactly that form, tag and file of `A-Z a-z 0-9 . _ + -`, neither `.` nor `..` (no `%`, `?`, `#`, no further `/`), and counts only for its own `source.repo`, never through the host of `source.page` (ADR 0024). A test checks this (`download_urls_belong_to_the_source`), and from Phase 4 the loader does too. The SHA256 secures integrity, not provenance.

With `tier: community` (see `05-sources-policy.md`), `source.page` (original page) is required and there is **no** direct download (`source.release` and `assets` forbidden). Rerun opens the page, the user downloads it themselves, Rerun then checks `sha256`.

### Fields

- `version`: `^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$`, without `..` (can safely appear in cache paths).
- `slots`: DLL file names that the package occupies in the game folder (`dinput8.dll`, `d3d9.dll`, `dxgi.dll` …), following the path rules (no `CON.dll`, no `X~1.dll`). Two packages with the same slot = conflict, unless one allows chainloading.
- `apis` + `slots_by_api`: for wrappers whose slots depend on the game's graphics API (DXVK).
- `requires`: shared dependencies are reference-counted. A package is removed only when nothing needs it anymore. Every referenced ID must exist as a package (test).
- `requires_gpu`: GPU prerequisites, v1: `[vulkan]`.
- `supports_exe_sha1`: exe versions the package is built for.
- `files[]`: `{ from, to, sha256, config?, arch?, api? }`. `sha256` (required, ADR 0024): the SHA-256 of the file as extracted, computed ourselves; `TODO` only in a draft. `arch`/`api` restrict an entry to specific architectures or APIs. Folders are derived from `to`. One package is one pinned version (user decision E2 a): another version of the same tool is another package (`dxvk-1-10`).
- `options`: INI values that appear as toggles in the UI; `kind` as for variants. `section` and `key`: `^[A-Za-z0-9_. -]+$`. String `default`: no control characters (no CR/LF), no absolute paths, no `..`. Options are meant to be applied through `ini_set` (ADR 0021), whose rules are narrower: names of 1 to 64 characters without a space at either end, values of 1 to 128 printable ASCII characters without `\ / : % ; # [ ]`, an existing `.ini` file. The package schema is aligned with them when options are implemented (phase 4); until then an option outside them could not be applied.
- `config: true`: the file is meant to be modified by the user. A revert never overwrites or deletes a file whose content is no longer what Rerun wrote, whether `config` is set or not, and never asks: the change stays unresolved, its backup stays in the journal and `forget` closes it (user decision D10, ADR 0020). `config` is a hint for the preview and for `ini_set` options on that file.

## Signed index

ADR 0024. One bundle `index.json` holds every released Topo and package; `index.json.sig` is its detached Ed25519 signature (exactly 64 raw bytes) over the raw bytes of `index.json`.

```json
{
  "format": 1,
  "seq": 12,
  "issued": "2026-11-09T12:00:00Z",
  "topos": [ { "format": 1, "id": "assassins-creed-dc", "...": "..." } ],
  "packages": [ { "format": 1, "id": "eaglepatch-ac1", "...": "..." } ]
}
```

- `seq`: from 1, raised for every published index. The client remembers the last one it accepted (`<LocalAppData>\Rerun\index\current.json`) and refuses a lower one (a rollback) and the same number with other bytes.
- `issued`: UTC, `YYYY-MM-DDTHH:MM:SSZ`.
- `topos`, `packages`: each entry in exactly the form of this document (the schemas `topo.schema.json`, `package.schema.json`; the bundle itself `index.schema.json`), sorted by `id`, no duplicates. Never `status: draft`, never `TODO` anywhere; every package a Topo step or a `requires` names is in the bundle.
- The client checks, in this order: size (at most 8 MiB), the signature against the public keys built into the binary (two slots: current and next, for rotation), and only then parses (`deny_unknown_fields`, `RelPath`, hashes) and checks the rules above. Every accepted index is kept by its SHA-256 below `<LocalAppData>\Rerun\index`, so a revert finds the index its transaction was applied with.
- Built from `topos/` and `packages/` by `rerun-workbench index build --seq <n> --issued <time> <out>` (drafts left out; the same files, `seq` and `issued` give the same bytes), signed offline by `rerun-workbench index sign <bundle> <private-key>`. Until phase 6 the user brings it in with `rerun index import <index.json> <index.json.sig>`; `rerun index show` names the current one.
