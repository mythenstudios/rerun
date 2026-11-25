# ADR 0032 · Game options with a choice (Topo `options`, launch profile format 3)

**Status:** Proposed · 2026-11-12, amendment P5-OE proposed 2026-11-25 (before A6, together with ADR 0029) · extends ADR 0020 (amendments P3-3, P4-4, P5-2a), ADR 0022 (D1, amendments P3-3, P4-13), ADR 0024, ADR 0027 · relates to ADR 0028 (`launch_option`, P5-7) · plan `P5-options` part B · phase 5, steps B1 and B2 after P5-7

## Context
Some games let the player choose something Rerun can set declaratively, which is not a problem and has no "fix": the graphics API above all. Assassin's Creed ships `AssassinsCreed_Dx9.exe` and `AssassinsCreed_Dx10.exe`; Steam starts `AssassinsCreed_Game.exe`, a detector that starts the DX10 build without asking (dev PC, P4-13 S1). Other games pick the API by an INI key or by a launch argument (`-dx9`), which the format so far only knows as a hint (`tips.launch_options`). The user wants a choice field on the game page: "automatic/unchanged", DX9, DX10.

The Topo format has issues with mutually exclusive variants, but an issue is a problem on this PC (`when`, evidence per variant, preselection of verified fixes, one fix per variant ID across issues, P5-4). A choice is none of that, and its default is "leave the game as it is".

Three effects are needed: (1) start another executable of the game than Steam's launch entry; (2) set INI keys (`ini_set`, ADR 0021); (3) pass fixed launch arguments. (1) needs `rerun-launch`: Steam's launch option `"<install>\rerun-launch.exe" --profile <id> %command%` (ADR 0022 D2) is the only declarative place between Steam and the game. ADR 0022 amendment P4-13 decided that the next profile extension is one new format with every key always present.

## Decision

### Format: a Topo section `options`
```yaml
options:                            # 0 to 8
  - id: graphics-api                # unique among the Topo's option and issue IDs
    title: "Graphics API"
    sources: [{ type: pcgw, url: "https://www.pcgamingwiki.com/wiki/Assassin%27s_Creed#…" }]
    values:                         # 1 to 8; "unchanged" is implicit and reserved
      - id: dx9
        title: "DirectX 9"
        status: unverified          # verified | reported | unverified, as variants
        steps: [{ start: "AssassinsCreed_Dx9.exe" }]
      - id: dx10
        title: "DirectX 10"
        status: unverified
        steps: [{ start: "AssassinsCreed_Dx10.exe" }]
```
- Every option has the implicit value `unchanged` (no steps, no op); it is the default and is never listed. Values are mutually exclusive by construction: one value per option per plan.
- Value steps, v1, at most 4 per value: `start: <exe>` (at most one), `launch_args: [<arg>, …]` (at most one, 1 to 8 arguments, each `^[-+][A-Za-z0-9_.=+-]+$`, at most 64 characters, as `tips.launch_options`), `ini_set` (ADR 0021, unchanged rules, also `root: user_data`). Nothing else: no package, no patch, no registry, no firewall, no CPU rule; an option never produces a helper op.
- `start` names a `match.exes` entry in exactly its spelling, with a `sha256` (the executable that will run is bound to a build, as for the elevated anchors of ADR 0024); the Topo needs `launch.start` (not `TODO`), `launch.chain: [steam]` and a method that resolves to `direct` (`auto` or `direct`): only then is Steam's own start the shim's to replace. `start` equal to `launch.start` is refused (nothing to change).
- `start` and `launch_args` stay option-only in v1: a fix that needs them waits for its first Topo.
- Loader (`Rules::Source` and `Release`): the ID rules, the reserved `unchanged`, the step rules above, `sources` at least one per option, and two values of one option never with identical steps.

### Launch profile format 3
- One new format, written for every profile from this version on (ADR 0022 P4-13: no third content-chosen format): format 2's keys always present (`cpu=none` allowed again, `cpu.exclude_first=none`) plus `run` (`none` or a canonical absolute drive path, the D1 path rules, ending in `.exe`) and `args` (`none` or the arguments joined by one space, each in the pattern above, at most 8 and 512 bytes). The reader takes formats 1, 2 and 3 as long as a revert can restore them.
- The planner (`prim::launch_method`): the step gains `run: Option<RelPath>` and `args: Vec<LaunchArg>`; a step needs at least one of `cpu`, `priority`, `run`, `args`. With `run`, the method must be `direct`, the profile's `target` is `run` (not `start`), `bitness` reads `start` and `run`, and the launcher restriction (F5: hard rule only, no priority) does not apply because the rule lands on the game itself.
- **The shim** (`rerun-launch`, M2 changed for this case only): when Steam's `argv[0]` equals `start` and the profile has `run`, `lpApplicationName` is `run` and `lpCommandLine` is `"<run>"` followed by the raw tail after `argv[0]`, byte for byte; `args` are appended to the command line after one space (they hold no quote, space or `%`). The job, CPU Sets, priority and the post-launch check apply to the program started. Everything else of D3 holds: no profile, an invalid one, `path_mismatch` or an elevated shim (M1) start Steam's command unchanged; a missing or unstartable `run` (`spawn_failed`) also falls back to Steam's command, unchanged, and records it (new result reason `run_failed:<code>`, additive). 740 with `run` uses `ShellExecuteExW` on `run` with the same parameters.
- Trust is unchanged (D2): the profile is user-writable and no privilege boundary for a non-elevated shim; whoever can write it can also write Steam's launch options. Budget: two keys and one string join; the < 50 ms and < 1 MB budgets hold (measured in [DEV] as for D2).

### Engine and plan
- **Picks:** `Selection` gains `choices: Vec<Choice { option, value }>` (at most one per option, `unchanged` is the absence); `PlanSource` gains `choices` (additive, omitted when empty, same form rules as picks, at most 8). The CLI takes `--set <option>=<value>` next to `--pick <issue>/<variant>`.
- **One profile per plan:** a value's `start` and `launch_args` join the one `launch_method` step of the plan with a picked `cpu` step (two `start` or two `launch_args` from different options are refused). Without a `cpu` step the engine makes a `launch_method` step with only `run`/`args` and the Topo's method and start.
- **The executable that runs:** with a `start` value, its `match.exes` entry is the plan's main executable (`PlanRoot.main_exe`, `main_sha256` of P5-2a): it is the process apply and revert ask (D4), and its architecture, `api` and SHA-1 are the ones a `package` step uses (P4-7) and `supports_exe_sha1` checks. A package not built for that build is refused with the option named.
- **Live profile (proposed: carry over):** today a later plan replaces the profile (a `ReplaceFile`, reverted newest first), so picking DX9 after an applied CPU fix would write a profile without the CPU rule and the game would crash again. The engine therefore reads the profile a live transaction holds (the file in `<AppDir>\profiles`, decoded bounded by `rerun-proto`; undecodable: refused) and carries over the part this plan does not set: the CPU rule and priority when no `cpu` step is picked, `run` and `args` when no choice sets them. The preview shows the whole new profile and names the transaction whose part is kept. Reverting the new transaction restores the old profile exactly; reverting the older one first is refused (`Later`, LIFO). Taking a choice back to `unchanged` is a revert of the transaction that set it (user decision U1 a). The alternatives (refuse while a profile is live; replace and warn) are user decision O3 of the plan. The app's choice field shows the value the live transaction set (`PlanSource.choices` of its head) and names that transaction.
- **Anti-cheat rule:** `start` and `launch_args` are warned like a CPU rule with `direct` (the shim only starts the game); `ini_set` as today.
- **Preview (rule 5):** the profile op shows `run` and `args` next to the rule ("Steam starts AssassinsCreed_Game.exe; rerun-launch starts AssassinsCreed_Dx9.exe instead"), and that the launch option is needed (paste fallback until P5-7, then `launch_option`). `ini_set` values as today.
- **Revert:** the profile is a journaled file op (exact); `ini_set` is X5 as today. No new row in "Exceptions to core rule 2"; X12 (the launch option) covers the option string as before and is revised by ADR 0028.

### Relation to `launch_option` (ADR 0028, P5-7)
The Steam launch option stays one constant string per game (`"<install>\rerun-launch.exe" --profile <id> %command%`), written once by `launch_option` or pasted. Every choice lives in the profile, a file in Rerun's own folder: changing an option never needs Steam closed and never edits `localconfig.vdf` again. `tips.launch_options` stay hints; a Topo that wants an argument applied uses an option value with `launch_args`.

### App
The game page shows a section "Options" above the fixes: one choice field per option (`Unchanged` first and preselected, then the values with their status), its sources, and, when a live transaction set a value, that value and the transaction. Picking a value changes the selection; the plan and preview are the usual ones (`flow::plan` with `choices`).

## Alternatives
- **Options as issues with variants:** no format change, but a choice would appear as a problem, need `when` and evidence, take part in fix preselection and the variant-ID rule, and "unchanged" would be "not picked". Rejected.
- **Arguments through `localconfig.vdf`** (after `%command%`, written by `launch_option`): Steam must be closed for every change and the option string changes with the choice; two places to revert. Rejected for the profile.
- **Steam launch option `"<game>\Dx9.exe" %command%`:** passes the detector's path to the game as an argument and puts a game path where only Rerun's prefix may stand (docs/02). Rejected.
- **A content-chosen format 3** (only when `run`/`args` are set): ADR 0022 P4-13 ruled that out.

## Consequences
- `catalog` (model, schema `options`, loader), `topo` (choices, the run executable, package checks, profile merge), `prim::launch_method` (run, args), `rerun-proto::profile` (format 3), `rerun-launch` (run, args, `run_failed`), `plan` (`PlanSource.choices`), `flow` (`Selection.choices`, the live value), `rerun-cli` (`--set`), `rerun-app` (choice field).
- Docs: `docs/02-topo-format.md` (`options`, steps `start`, `launch_args`), `docs/04-launch-methods.md` (the shim starts `run`), `docs/06-security.md` (the shim starting another program of the profile), `docs/07-ui.md`, `docs/09-testing.md`, ADR 0022 amendment (format 3, M2 exception).
- Reviews: win32-systems and security-reviewer on the shim change; senior-dev on the plan.

## Open points
- Whether Assassin's Creed runs when its DX9 or DX10 executable is started directly by the shim (overlay, playtime, the detector's role) is not measured; research (PCGW, Steam guides) and a [DEV] test before the values leave `unverified`.
- Plan finding: the engine's main executable is the *first* matching `match.exes` entry; for Assassin's Creed that is the DX9 build while the detector starts DX10, so today's D4 check asks the wrong process. Independent of options; to be fixed separately (ask every matched entry, or order the entries). *Closed by ADR 0020 amendment "Other executables" (2026-11-12): every matched executable is asked, and `assassins-creed-dc` lists Dx10 first.*

## Amendment P5-OE (2026-11-25, proposed)

Plan `P5-OE` (game options and Advanced in one plan, before A6). It folds in the conditions of the senior-dev review of 2026-11-12, the senior-dev plan review of 2026-11-25 (B1, S1 to S6, nits) and the user decisions of 2026-11-25, and fixes what Advanced (ADR 0029) shares with options. Where it differs from the decision above, this holds.

### Format and gates
- `options` is **entry format 1**: format 1 is frozen with the first release (ADR 0024 amendment "Forward compatibility" §4), not before. A private alpha build from before this change sets a Topo with `options` aside as `Unreadable`; no released client exists. Any option step kind or field added after A6 is entry format 2.
- `start` and `launch_args` in option values are **draft only** until the shim slice is reviewed (`catalog::check::OPTION_LAUNCH_REVIEWED`, like `LAA_PATCH_REVIEWED`); `ini_set` values are usable from the first slice. The floor functions walk `TopoOption`, `OptionValue` and `OptionStep` (all at 1).
- Loader additions: two options of one Topo never set the same INI file; a value with `launch_args` and without `start` is allowed only when `launch.start` names a `match.exes` entry (Steam starts the game itself), since otherwise the arguments would reach a launcher (for Assassin's Creed the detector).

### Launch profile format 3 (refines "Launch profile format 3" above)
- Keys in order: `method`, `start`, `target`, `bitness`, `priority`, `watch_timeout_s`, `cpu` (`none`/`rule`), the seven `cpu.*` keys when `rule` (`cpu.exclude_first` now `none`/`thread`/`core`), `run` (`none` or a path), `args` (`none` or the arguments). Written for every profile from this version on; formats 1 and 2 stay readable.
- **`run` (senior-dev condition 1, narrowed by the plan review of 2026-11-25, S2):** a path with the D1 rules, ending in `.exe`, not equal to `start`, and in **the same folder** as `start`: `run` and `start` are byte for byte equal up to and including the last `\` of each, and `run` has no further `\` (the planner builds both from the same game folder path, so no folding is needed in `rerun-proto`). The shim passes no `lpCurrentDirectory` (the child keeps Steam's, as today), which is the same folder Steam chose for `start`. A `run` below that folder needs its own decision on the working directory and is not part of format 3 v1. `run` requires `method=direct` and `target = run`.
- **Size (S3):** a format-3 profile with non-ASCII paths of 259 UTF-16 units each (`start`, `target` = `run`) and 512 bytes of `args` reaches about 3.3 KiB, above `plan::MAX_INLINE_BYTES` (2 KiB). Decision: raise `MAX_INLINE_BYTES` to 4 KiB before the format freeze, together with `MAX_OP_BYTES` (8 KiB today; a 4 KiB inline profile is 8 KiB of hex plus the op's JSON) to 12 KiB, after checking the journal's record limits (ADR 0019) that embed an op. If that check shows a limit that cannot move, the planner keeps 2 KiB and refuses a larger profile with a clear message ("the paths of this game are too long for a launch profile"), with a test. The shim reads up to 8 KiB either way.
- **`args`:** 1 to 8 arguments joined by one space, each `^[-+][A-Za-z0-9_.=+-]+$` and at most 64 characters, at most 512 bytes; requires `method=direct`. The pattern lives once, in `rerun_proto::profile::LaunchArg`; the catalogue reuses it.
- **Bitness with `run`:** the machine of `run` alone: with `run` the shim never starts `start` under the rule (a failed `run` falls back to Steam's command without any rule), so `start` is not part of the chain.

### The shim (refines "The shim" above; senior-dev condition 2)
- The M2 exception covers exactly two things: `lpApplicationName = run` when Steam's `argv[0]` equals `start` and the profile has `run`; and `args` appended (one space, then the arguments) to `lpCommandLine`. `lpCommandLine` with `run` is `"<run>"` followed by the raw tail after `argv[0]`, byte for byte. Nothing else of M2 changes; an elevated shim (M1), `path_mismatch` and every D3 fallback start Steam's command exactly as before, without `run` and without `args`.
- A `run` that cannot be started (`CreateProcessW` fails other than with 740) falls back to Steam's command unchanged, without the rule, and records `rule=skipped:run_failed:<code>`. 740 with `run` goes to `ShellExecuteExW` with `lpFile = run`, without the rule.
- The result file (format 1, additive as in P3-4) gains the optional line `run=yes` after `method` when the started program was `run`, so `rerun status` and the app word a start by the result alone ("rerun-launch started AssassinsCreed_Dx9.exe instead of AssassinsCreed_Game.exe"), and, for `path_mismatch` only, the optional line `steam_start=<file name>`: the last path component of Steam's `argv[0]` (D1 component rules, at most 255 UTF-16 units; never the folder). A reader treats it as untrusted: the app offers it as the start of a manual rule (ADR 0029, games without a Topo) only if it is a detected candidate of that game now.
- `docs/06-security.md` row 17 and the statement "the shim always starts Steam's own command, never `start`" are rewritten with the shim slice (plan review S4): with `run`, the shim starts `run` of the profile, never any other program.
- Budget measured in [DEV] as for D2 (< 50 ms to `CreateProcessW`, binary < 1 MB).

### Carry-over (refines "Live profile" above; senior-dev condition 3)
- **Source (plan review S6):** `exec::live_state` (in `exec`, read only, no lock) takes the **newest** transaction whose head holds a profile op for this game's profile ID, forgotten ones included (the holders of `flow::status` include them). If that newest holder is applied and live, its head's `Inline` bytes are the carried profile, decoded bounded by `rerun_proto::profile` (undecodable: refused); the file in `profiles` is read only to check that its SHA-256 equals the head's content, and another content (changed by someone) refuses the plan ("the launch profile changed since T…; undo or forget T… first"). If the newest holder is forgotten, or there is none, **nothing** is carried and an existing file is replaced as today (old state = the file's hash, restored by the revert); an older live holder below a forgotten one is never the source.
- **Parts:** the rule part (`method`, CPU rule, priority), `run`, `args`. Each part not set by this plan is carried. A plan that sets no part writes no profile op and leaves the live profile alone (an option of `ini_set` values only).
- **Conflicts:** a carried `watch` method with a new `run` or `args`, or a new `watch` rule part with a carried `run` or `args`, is refused (both need `direct`).
- **Every part is checked as if new (plan review S1):** the new profile is planned as a whole, so every rule of the planner and the engine holds for every part whatever its origin: the anti-cheat refusal of `run` and `args` also for carried ones, F5 for a carried rule part, the `run` folder rule, the bitness. Optionally `flow::game` checks the anti-cheat markers again for a live `run` and warns on the game page with the undo of its transaction.
- **Preview:** the whole new profile, each part with its source (a fix, an option value, "your own setting" (ADR 0029), "kept from transaction T…"), and the order of undo (newest first).
- The apply's old-state check of the `ReplaceFile` (the head's hash) closes the window between plan and apply: a profile changed or reverted meanwhile refuses the apply, nothing written.

### The executable that runs (refines "The executable that runs" above)
- **Effective main executable:** the entry of a chosen `start` value; else the `match.exes` entry whose path the carried `run` names (none matched: refused); else the first match. It is the plan's `main_exe`/`main_sha256`, the program D4 asks first, and the executable a `package` step is planned for (architecture, `api`, `supports_exe_sha1`). So a fix picked after an applied DX9 choice is planned for DX9.
- **Switching while packages are live (user decision E4 b, 2026-11-25):** a plan whose effective main executable differs (folded) from the `main_exe` recorded in the head of a live transaction of the game that installed package files (file ops with `ContentRef::Package`) or holds `compat_layer` ops is refused, naming that transaction ("undo T… first, then choose, then apply the fix again for the chosen executable"). No catalogue lookup. A precise check per package (`supports_exe_sha1`, architecture, API) may replace it later without a format change.
- **Undo order across the switch (plan review B1):** LIFO in `exec::stack::for_revert` is per object: a later transaction that shares no object does not hold an earlier one. A package installed for the executable a `run` chose shares no object with the profile. So `for_revert` gains one journal-only rule: the revert of a transaction whose profile op holds a profile with `run` (decoded from its head; undecodable counts as having one, fail closed) is `Later` while a later live transaction of the same game root has `main_exe` equal (folded) to that `run`'s entry and holds package or `compat_layer` ops. Taking DX9 back while a fix planned for DX9 is live is thereby refused until that fix is undone. The same holds for compatibility flags of Advanced (ADR 0029) on the executable a carried `run` made the main one. "Stacked" in the app and in this ADR means exactly the object LIFO plus this rule. Pinned by a round trip: T1 option (`run` Dx9) → T2 package for Dx9 → revert T1 refused `Later { T2 }` → revert T2, then T1 → snapshot identical to before T1.
- The bundle rule of ADR 0020 amendment "Other executables" (an API-dependent package on a Topo of two APIs) stays until a later amendment relaxes it for Topos with a `start` option per API.

### Anti-cheat (stricter than "Anti-cheat rule" above)
`start` and `launch_args` are **refused** with a marker found or unreadable, also when carried from a live profile: starting another executable than Steam's launch entry may skip the program that starts the anti-cheat system, and arguments change how a protected game starts. `ini_set` as today.

### Engine, plan, flow
- `PlanSource.picks` may be empty (0 to 32); `PlanSource.choices` (0 to 8, one per option, IDs of the Topo form, omitted when empty); a source with neither needs `Plan.manual` (ADR 0029).
- `flow::Selection { picks, choices, manual }` replaces the `picks` argument of `flow::plan`; the CLI takes `--set <option>=<value>`.
- `flow::MatchView` gains `options: Vec<OptionView>`: per option its values with status, sources, refusal (not matched here, anti-cheat, gate) and the live value with its transaction and whether it can be undone now (top of the stack). Choosing `unchanged` while a value is live is the undo of the transaction that set it (U1 a); while a newer transaction stacks on it, the field says so and offers nothing else.
- Switching from one value to another plans a new transaction on top (carry-over); undo goes newest first.

### Preview text (senior-dev condition 4)
A profile with `run` says: "Steam starts <start>; rerun-launch starts <run> instead. Whenever rerun-launch cannot use the profile (it is missing or invalid, Steam's path differs, Steam runs as administrator, or <run> cannot be started), it starts Steam's own command unchanged, without the rule: for Assassin's Creed the detector, which starts DirectX 10." The app's card of a CPU rule that a later option transaction stacks on says that the rule can be undone only after that option (docs/07).

### Consequences of this amendment
ADR 0022 amendment (format 3, the M2 exception, `run_failed`, `run=yes`, `steam_start`) and ADR 0020 amendment (`PlanSource` picks 0 to 32 and `choices`, `Plan.manual`, `MAX_INLINE_BYTES`/`MAX_OP_BYTES`, the `for_revert` rule of B1, which is also a line in the stacking section) with their slices; `docs/06-security.md` row 17 (the shim starts `run` of the profile); `docs/07-ui.md` (a CPU rule below an option). User decisions of 2026-11-25 (plan P5-OE): E1 a (Advanced without a Topo, its own last slice), E2 a, E3 a, E4 b, E5 a; the senior-dev plan review of 2026-11-25 released the plan with conditions B1, S1 to S6 and the nits, folded in above. This ADR becomes accepted with the slice O-2b as built.
