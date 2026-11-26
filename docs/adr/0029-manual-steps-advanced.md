# ADR 0029 · Manual steps ("Advanced")

**Status:** Proposed · 2026-11-25 (user decisions E1 a, E2 a, E3 a, E4 b, E5 a and the senior-dev plan review of plan P5-OE folded in; accepted with its core slice as built) · extends ADR 0020 (amendments P4-4, P5-2a, "Other executables"), ADR 0022 (P3-3, P3-4, P4-13), ADR 0027 · shares the launch profile rules of ADR 0032 (amendment P5-OE) · plan `P5-OE` · before A6 (pulled forward by the user on 2026-11-25; was P5-8, moved to phase 6 by user decision U3 c)

## Context
Users want to choose a CPU rule for a game themselves ("Advanced"), not only pick a fix a Topo offers. Until now the only way is the phase 2 step file (`rerun plan <steps.json>`, ADR 0020 D7, L8): local, unsigned JSON with every step kind of the step-file language, paths included. The user decided on 2026-11-25 that the step file goes behind a test feature for the release, and that Advanced lands before A6 with a fixed scope: the declarative CPU rule fields with a live view of the selection on this PC, the launch method (`direct`, `watch`), the priority, and compatibility flags from the allowlist; never a firewall rule, a single-processor pick, a free `registry_set` or `ini_set`, a `laa_patch` or a helper op; the anti-cheat rule applies.

Core rule 4 ("Topos are purely declarative", downloads only from `packages/`, paths fenced, registry on allowed keys) governs what the signed index may make Rerun do. Manual steps are not Topo content: they are the user's own choice, made in the app or on the command line, for the game in front of them. They must still never be a back door around the fences rule 4 stands for.

Both Advanced and the game options (ADR 0032) write the one launch profile per game (ADR 0022 D2, one profile ID per Steam app), so they share one composition rule and one carry-over rule.

## Decision

### Scope: a closed allowlist, enforced by types
A manual selection is one value of `plan::Manual` (below). Its shape is the allowlist: there is no field, variant or string through which any other step kind, path or value could enter.
- **Launch:** `method` (`direct` or `watch`; never `auto`, `hold`, `ifeo`, `inproc`), an optional CPU rule (`CpuRuleSpec`: `max_threads` 1 to 1024, `prefer`, `single_l3`, `prefer_l3`, `smt`, `mode`, `exclude_first`; `report_cores` refused) and an optional priority (`normal`, `above_normal`, `high`). At least one of rule and priority. The planner rules of `launch_method` apply unchanged (F5: with `direct` and a launcher as `start`, only a hard rule; `watch` targets the main executable).
- **Compatibility flags:** 1 to 8 tokens of `policy::registry::layers::LAYER_TOKENS` (today `DISABLEDXMAXIMIZEDWINDOWEDMODE`, `HIGHDPIAWARE`), for the plan's main executable only. The allowlist is a planner rule (`Rules::Current`); a recorded head keeps decoding if the list shrinks later (audit S1, ADR 0018 open point P2-10b).
- **Executables (only for a game without a matched Topo, see below):** `main_exe` and `start`, each one of the game's detected main-executable candidates (`detect::exe`, the ranking of `rerun scan --hashes`); never a free path. `start` defaults to `main_exe`.
- **Never:** `package`/`file_install`, `ini_set`, `registry_set`, `gpu_preference`, `laa_patch`, `firewall_rule`, `steam_input`, game arguments, a `run` executable, single processors. Packages, `gpu_preference` and game arguments in Advanced are phase 6 (user scope of 2026-11-25); game arguments reach a game only through a Topo option value (`launch_args`, ADR 0032).

### Input: the app and the CLI, never a file
- The app's "Advanced" section on the game page (ADR 0027 amendment with the slice): every field is a choice, a checkbox or a bounded number; no text field.
- The CLI: `rerun plan <app-id> [--pick …] [--set …] [--method direct|watch] [--cpu <field>=<value>,…] [--priority normal|above_normal|high] [--layer <token>]… [--exe <candidate> [--start <candidate>]]`; parsed into `Manual` and checked by the same function as the app's input. No flag is mandatory: `--layer` alone is a manual selection of flags only; `--cpu` or `--priority` without `--method` take the Topo's resolved method (`direct` for a game without a Topo).
- **The step file** (L8) stays in the code behind the cargo feature `step-file`, built only for tests and the Sandbox scripts, never in a release build (user decision of 2026-11-25). `rerun plan <path>` in a release build says the step file is a test feature. The release workflow checks that the shipped `rerun.exe` was built without it.

### The plan records manual input: `Plan.manual`
- `Plan` gains `manual: Option<Manual>` (additive, omitted on the wire when absent; format 1 is unstable until A6, frozen with it). It records exactly what the user chose, for display ("your own setting") and for filling the Advanced form again; like `PlanSource` it is display and binding only: the ops are the truth, nothing in it authorises anything when read back.
- `Plan.source` (`PlanSource`) stays the binding to the signed index. A plan on a game with a matched Topo carries its `PlanSource` also when it holds only manual steps (`picks` and `choices` empty): it binds `launch.start`, `match` and the main executable's hash to the Topo they came from. Form rule: a source with no pick and no choice needs `manual`.
- **Main executable binding:** `Rules::Current` requires `main_sha256` and `other_exes` on the game root of every plan that has a `source` **or** `manual` (ADR 0020 amendments P5-2a, "Other executables"), so an apply refuses a game Steam updated since the preview, also without a Topo.
- **Never a helper op:** the elevated helper derives its ops only from the picks of a signed Topo (ADR 0023 §5, L8); `Manual` has no step kind that needs it.

### Combination with a Topo plan (one plan, one profile)
- Picks, option choices (ADR 0032) and `Manual` form one selection and one plan, one preview, one transaction (U1 a).
- The launch profile has three parts: the **rule part** (`method`, CPU rule, priority), `run` and `args`. A Topo fix with a `cpu` step and `Manual.launch` both set the rule part: one plan with both is refused ("your own CPU rule replaces the fix; pick one"). `run`/`args` come only from option values. A part this plan does not set is carried over from the live profile under the rules of ADR 0032 amendment P5-OE (the live transaction's head content, the file unchanged on disk, else refused).
- `Manual.launch.method = watch` with a `run` (chosen or carried) is refused (`run` needs `direct`).
- A manual compatibility flag and a Topo `compat_layer` step for the same executable in one plan are refused by the planner (two `compat_layer` steps for one executable), as today.
- `start` for a Topo game is the Topo's `launch.start`; `Manual` cannot change it.
- Flags go on the plan's effective main executable (ADR 0032 amendment P5-OE), which a carried `run` may have chosen. The revert of the option transaction that set that `run` is then `Later` while the flags' transaction is live (ADR 0032 amendment P5-OE, B1), and a plan that switches the executable while such flags are live is refused (E4 b).
- Every part of the new profile is checked as if new, whatever its origin (ADR 0032 amendment P5-OE, S1): a manual `watch` with a carried `run` is refused, the anti-cheat rule reaches carried parts.

### Games without a matched Topo (user decision E1 a, 2026-11-25; its own last slice)
- A Steam game with no Topo, or whose Topo does not match this build (`NoTopo`, `NoMatch`), can be given manual steps: the launch part and compatibility flags only, with `Manual.exe` naming `main_exe` and `start` from the detected candidates (checked again by `flow` when planning: a value that is not a candidate now is refused).
- `Manual.exe` is part of the plan format from the first core slice (so the format freezes with it); until the slice for games without a Topo lands, the planner refuses it (`NotYet`), and with a matched Topo it is always refused.
- The plan has no `source`; `manual` and `main_sha256` bind it. `other_exes` is `[]`.
- A wrong `start` (not Steam's launch entry) is harmless: the shim records `path_mismatch` and starts the game unchanged (ADR 0022 D3). Since ADR 0032 amendment P5-OE the result also carries `steam_start=<file name>` (the last component of Steam's `argv[0]`); the game page offers that name as the start only if it is a detected candidate of the game now (untrusted input, never a path). If it is not a candidate (a launcher outside the scan, another folder), the page says the rule did not apply and that Rerun cannot tell which program Steam starts; the user may pick another candidate or undo (the stated limit of this ADR).
- Without this, the release has no way at all to set a CPU rule for a game without a Topo (the step file is a test feature); with it, the user's original wish ("choose the CPU affinity myself") works for every Steam game.

### The anti-cheat rule
Unchanged and for every source (ADR 0020 amendment P4-4 follow-up 1): with a marker found (or unreadable), a CPU rule with `watch` and `compat_layer` are refused, a CPU rule with `direct` is warned. The markers are looked for in the game folder and the folders of the main executable and `start`.

### Preview and display (rule 5)
Every manual op is shown like a Topo op, labelled "your own setting" (not "fix of the Topo"); the launch profile is shown as a whole with the source of each part (a fix, an option value, your own setting, kept from transaction T). The Advanced section shows the selection of the rule on this PC live (`prim::launch_method::on_this_machine`, never part of the plan) while the user changes a field.

### Revert
Nothing new: the profile is a journaled file op (exact), compatibility flags are `compat_layer` ops (X3, X4 as today). No new row in "Exceptions to core rule 2". Undoing "your own setting" is the revert of its transaction (U1 a), newest first (LIFO) where it stacks.

### Relation to core rule 4
Rule 4 holds: Topos stay declarative and signed; manual steps are typed values of a closed set, planned by the same planners with the same fences (game folder, `HKCU` layers allowlist, Rerun's profiles folder), no path the user types, no download, no script, no helper. What a manual selection can do is a subset of what the user could do in the Compatibility tab of the executable's Properties and with a CPU affinity tool, with a preview and an exact undo.

## Alternatives
- **No Advanced, the step file in the release:** a JSON file of every step-file kind, paths included, as the expert input. Rejected: the largest unsigned input surface, and the user decided it goes behind a test feature.
- **Manual steps inside `PlanSource` (`PlanSource.manual`):** one field less, but `PlanSource` is the binding to signed data, and a game without a Topo has no source to put it in. Rejected in favour of `Plan.manual`.
- **Advanced only for games with a matched Topo** (scope of 2026-11-25 before plan P5-OE): smaller, but leaves most of a library without any CPU rule in the release. Not taken (user decision E1 a); the slice for games without a Topo comes last, so the Topo case does not wait for it.
- **Manual rule overrides a picked CPU fix silently:** refused instead; the app makes the two exclusive in the form.

## Consequences
- `plan` (`Manual`, `Plan.manual`, the form rules, the binding rule), `topo` (composition of the rule part), `flow` (`Selection.manual`, the Advanced view, the candidates of a game without a Topo), `prim::launch_method` (the live view of a rule spec), `rerun-cli` (flags), `rerun-app` (the Advanced section), `prim::step_file` behind the feature `step-file`.
- Docs: `docs/02-topo-format.md` (step file: test feature), `docs/04-launch-methods.md` (manual rules), `docs/06-security.md` (row 16 rewritten, a row for manual input), `docs/07-ui.md` (Advanced), `docs/09-testing.md`, ADR 0020 amendment (`Plan.manual`, the binding), ADR 0027 amendment.
- Reviews: senior-dev on the plan (rule 4 boundary, new plan field); security-reviewer and senior-dev on the core slice.

## Core slice E-1a as built (2026-11-26; games with a matched Topo; status stays Proposed until its review)
- **Types** (`plan::manual`): `Manual { launch: Option<ManualLaunch>, layers: Vec<TokenName>, exe: Option<ManualExe> }`, `ManualLaunch { method: Option<ManualMethod>, cpu: Option<CpuRuleSpec>, priority: Option<PrioritySpec> }`, `ManualMethod { Direct, Watch }`, `ManualExe { main_exe, start }` (`RelPath`). `Manual::check` is the one form check (CLI flags, engine, plan format; ADR 0020 amendment E-1a). **Deviation:** `method` is optional: absent means the Topo's resolved method (`direct` without a Topo, E-1b), so the plan records exactly what was chosen ("no flag is mandatory") and the ops carry the resolved method.
- **Engine** (`topo::plan`, `EngineSelection.manual`, `flow::Selection.manual`): the form first, `exe` refused with a Topo (`EngineError::ManualExe`); after the picks and the choices the launch part becomes the rule part of the one profile (`PartFrom::Manual`) and is composed with `run`/`args` of option values or of the live profile like a fix's rule part; a picked `cpu` step and an own launch part are refused (`ManualAndCpuFix`); own flags become one `compat_layer` step on the effective main executable, refused when a picked fix sets flags for the same executable (`ManualAndLayerFix`, a clear engine message instead of the planner's "two steps for one executable"); the anti-cheat rule per kind (`ManualAntiCheat`: refused for `watch` and flags, warned for `direct`). E4 b and B1 hold through the plan's `main_exe` unchanged. `Plan.manual` is the selection as given; `source` stays the binding to the Topo (its picks and choices may both be empty).
- **CLI** (E5 a): `rerun plan <app-id> [--method direct|watch] [--cpu <field>=<value>,…] [--priority normal|above_normal|high] [--layer <token>]… [--exe <path> [--start <path>]]`, each flag parsed by its own closed parser, then `Manual::check` before any system access (usage error). The output names the selection ("your own settings (Advanced, not checked by a Topo): …") and the profile part by part ("cpu rule and priority, from Advanced (your own setting, not checked)"). For a game without a matched Topo it says that own settings need one in this version (E-1b). Example: `rerun plan 8140 --cpu max_threads=8,smt=false --priority above_normal --dry-run`.
- **App:** only the origin text (`Msg::PvFromManual`) and the warning (`Msg::WarnManualAntiCheat`); the Advanced section with its live view (`AdvancedView`, `rule_view`, `allowed` of plan P5-OE) comes with the UI slice, on top of `prim::launch_method::on_this_machine`. **Deviation:** not built in E-1a.
- **Step file behind `step-file`:** `prim::StepFile`, `flow::plan_steps`, `PlanError::StepFile`, the CLI's `rerun plan <path>` and its message are compiled only with the cargo feature `step-file` (rerun-core, rerun-cli) or in the crate's own tests; `prim::GameRef` stays (the Steam lookup uses it). A release `rerun plan <path>` is a usage error naming the test feature. Checks: CI and `scripts/alpha-build.ps1` (`cargo tree -e normal,build`, the binary's text), `tests/hardening.rs`; the Sandbox's `rerun.exe` is built with the feature (ci.yml, `scripts/sandbox-launch.ps1`).
- **Tests:** `topo::manual_tests` M1 to M6 (allowlist bounds, wire form, binding, round trips of an own rule, own flags, own settings over a live `run`, with an option value, over a live CPU fix; refusals; anti-cheat), CLI C-TE20, hardening `only_a_step_file_build_reads_step_files`. No golden plan (the bytes of `manual` asserted in M1; the existing golden plans unchanged).

## Open points
- Whether a manual rule should be offered as a template from the Topo's verified CPU fix (prefill) is a UI detail of the app slice.
- Advanced beyond this scope (packages from the index with the slot check, `gpu_preference` on hybrid PCs, game arguments, single processors) stays phase 6.
