# ADR 0032 · Game options with a choice (Topo `options`, launch profile format 3)

**Status:** Proposed · 2026-11-12 · extends ADR 0020 (amendments P3-3, P4-4, P5-2a), ADR 0022 (D1, amendments P3-3, P4-13), ADR 0024, ADR 0027 · relates to ADR 0028 (`launch_option`, P5-7) · plan `P5-options` part B · phase 5, steps B1 and B2 after P5-7

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
- Plan finding: the engine's main executable is the *first* matching `match.exes` entry; for Assassin's Creed that is the DX9 build while the detector starts DX10, so today's D4 check asks the wrong process. Independent of options; to be fixed separately (ask every matched entry, or order the entries).
