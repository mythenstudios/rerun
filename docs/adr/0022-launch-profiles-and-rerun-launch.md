# ADR 0022 · Launch profiles and rerun-launch

**Status:** accepted · 2026-11-08 · extends ADR 0006, ADR 0008, ADR 0010 · phase 3, step P3-1 (P3-1a: `rerun-proto`; P3-1b: the shim)

## Context
Phase 3 starts a Steam game through `rerun-launch.exe` with a CPU rule (`docs/04-launch-methods.md`, `docs/08-roadmap.md`). The shim depends on `windows-sys` and `rerun-proto` only (ADR 0006): everything it shares with `rerun-core` (the rule selection, the profile format) must live in `rerun-proto`, without serde. The selection has to run in the shim at every start, because CPU Set IDs are runtime values (ADR 0010). `docs/03-cpu-topology.md` left four points open: LP E-cores were "never for games" without a step that removes them, the group of step 1 was "group 0 (or the largest)", step 5 said "truncate to 32" for a 32-bit game, and the SMT example of the plan (4 cores × 2 threads) contradicted step 6 ("cores before SMT siblings"). For the shim itself the plan review (P3 plan, conditions B1–B4, B13; decisions D1–D3, D5) asked for decisions before P3-1b, among them two Win32 questions: how a hard mask reaches a group other than 0 (B4), and whether a 32-bit game is limited by a count or by indices (B6).

## Decision

### Shared code in `rerun-proto` (P3-1a)
- `cpu::rule`: `CpuRule { max_threads, prefer, single_l3, prefer_l3, smt, mode }`, `Bitness`, `select(&CpuTopology, &CpuRule, Bitness) -> Result<Selection, SelectError>`. `Selection { group, mask, cpu_set_ids, threads, of }`; `SelectError::Empty { after: SelectStep }` names the step that emptied the candidates, `Invalid` carries a `TopologyError` (`select` validates first). Pure, no dependency, no `unsafe`.
- `profile`: `LaunchProfile`, `ProfileId`, `encode`/`decode` (format 1, below). No serde: the shim reads it as is (ADR 0006).

### Selection (docs/03, "Selection algorithm")
1. **Group:** the group with the most logical processors, on a tie the lowest number (B6). Within it, LLCs whose `level` is below the highest level in the group drop out: LP E-cores keep their own L2 as last level beside an L3, so the level separates them where the efficiency class may not (Panther Lake). A machine whose LLCs share one level loses nothing. No rule field selects LP E-cores in phase 3.
2. **32-bit:** an x86 game keeps indices `< 32` only (B6, below). Before the class and L3 steps, so the L3 choice sees only what the game can address.
3. `prefer: performance` → highest efficiency class.
4. `prefer_l3: largest` → largest size, then most candidates, then lowest `llc`; `single_l3` → most candidates, then largest size, then lowest `llc`. Exactly one LLC with either flag; without them all LLCs stay.
5. `smt: false` → first thread of each core.
6. `max_threads: N` → first `N` of "first threads of all cores, then second threads …", by index (B5: the 5950X with `max_threads: 8, single_l3` is 8 cores × 1 thread on CCD 0, with or without SMT).
7. Empty → `Empty { after }`; only step 2 and `max_threads: 0` can empty a non-empty set.

`mode` (hard/soft) does not influence the selection.

### B6 · 32-bit games: indices below 32, not a count of 32
A WOW64 process holds affinity as pointer-sized values: `DWORD_PTR` in `SetProcessAffinityMask`/`GetProcessAffinityMask` and `KAFFINITY` (`ULONG_PTR`) in `GROUP_AFFINITY` are 32 bits wide in 32-bit code (Windows Data Types). A selection of 32 processors with any index ≥ 32 has bits the game cannot represent: `GetProcessAffinityMask` in the game cannot report them, and a game that reads its mask and sets it again (common in old engines, also the classic "single core" fixes) narrows or breaks its own affinity. Limiting the indices keeps the selection exactly representable in the game's own view; the count limit follows from it. The cost: on a group of more than 32 processors a 32-bit game never gets the processors at 32 and above, even if the best LLC sits there (Threadripper, Xeon; no consumer part with more than 32 threads per group is affected). The same rule applies in soft mode, so both modes agree. Manual check (docs/09, "32-bit game on a group with more than 32 logical processors"): only a measurement that shows bits above 31 to be harmless may relax this to a count.

### B4 · Hard limit: one `GROUP_AFFINITY` on the job, also for group 0
- The hard limit is set with `SetInformationJobObject(JobObjectGroupInformationEx)` and an array of exactly **one** `GROUP_AFFINITY { Mask, Group }`: "the affinity of the job for the processor groups to which the job is currently assigned" (`SetInformationJobObject`, `JOBOBJECTINFOCLASS`, Windows 8 and later). It names the group explicitly, so one code path serves group 0 and groups ≠ 0, and the single-group developer machine tests the same call a 128-thread machine uses.
- `JOB_OBJECT_LIMIT_AFFINITY` (`JOBOBJECT_BASIC_LIMIT_INFORMATION.Affinity`) is **never** set: it is a bare `KAFFINITY` without a group number, documented as "a subset of the system affinity mask obtained by calling `GetProcessAffinityMask`", i.e. of one (the primary) group, and on Windows 11 a process is no longer confined to one group by default ("Processor Groups": starting with Windows 11 and Windows Server 2022, process and thread affinities span all groups by default). Mixing both forms is undocumented.
- The child is born into the job: `CreateProcessW` with `EXTENDED_STARTUPINFO_PRESENT`, `CREATE_SUSPENDED` and `PROC_THREAD_ATTRIBUTE_JOB_LIST` (Windows 10 and later; no window between creation and `AssignProcessToJobObject`), plus `PROC_THREAD_ATTRIBUTE_GROUP_AFFINITY` with the same `GROUP_AFFINITY`, so the initial thread, and with it the process's primary group, is the selected group (`UpdateProcThreadAttribute`). Before `ResumeThread` the shim reads back the job's group affinity (`QueryInformationJobObject`) and the initial thread's (`GetThreadGroupAffinity`); any difference terminates the suspended child (it never ran) and starts Steam's command unchanged (D3). That the attribute fixes the primary group is an assumption checked by the multi-group case in docs/09 (a Hyper-V VM with `bcdedit /set groupsize 8`), before P3-1b counts as accepted on multi-group machines.
- Job flags (B4): `JOB_OBJECT_LIMIT_BREAKAWAY_OK` yes (a launcher child that asks for `CREATE_BREAKAWAY_FROM_JOB` may leave; refusing it would fail its start), `JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK` no (every child stays unless it asks), `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` off until measured: with it, Steam's "Stop" (which ends the shim) would end the game too, but so would a crash of the shim. The [DEV] measurement decides. Nested jobs (Steam or a launcher holding the shim in a job, Windows 8 and later): the parent's limits keep applying; if the nested job cannot take the limit, the shim starts unchanged (D3), Sandbox case R3.
- Soft mode: `SetProcessDefaultCpuSets(child, ids)` on the suspended child before `ResumeThread`. It applies to the launched process only, not to its children (plan nit); the preview says so.
- Priority (D6 a): the creation flag of `CreateProcessW` (`NORMAL_`, `ABOVE_NORMAL_`, `HIGH_PRIORITY_CLASS`; never realtime) for `direct`, `SetPriorityClass` on the target for `watch`.
- The setters (`SetInformationJobObject`, `UpdateProcThreadAttribute`, `SetProcessDefaultCpuSets`, `SetPriorityClass`) are banned in `clippy.toml` (ADR 0010) except in one wrapper module of `rerun-launch` (`#[allow(…, reason)]`); P3-1b amends ADR 0010 with its name. Handles (job, process, thread, attribute list) are RAII; the shim keeps the job handle open while it waits (B3).

### D1 · Profile format 1
- UTF-8 text, at most 8 KiB (`MAX_PROFILE_BYTES`), header `rerun-profile 1`, then `key=value` lines in a fixed order, each ending in LF: `method` (`direct`/`watch`), `start`, `target`, `bitness` (`x86`/`x64`), `priority` (`none`/`normal`/`above_normal`/`high`), `watch_timeout_s` (1–120), `cpu` (`none`/`rule`), and with `rule` the six lines `cpu.prefer`, `cpu.single_l3`, `cpu.prefer_l3`, `cpu.smt`, `cpu.mode`, `cpu.max_threads` (`none`/1–4096). Every key always present (explicit `none`), so the encoding is canonical: a file decodes to one profile and encodes back to the same bytes.
- Refused: more than 8 KiB (before parsing), not UTF-8, no final LF, CR, any control character, an empty line, another header or format, an unknown, repeated, misplaced or trailing key, a value outside its set, a number with a sign or leading zero, `direct` with `target != start`. Errors carry the line and the key, never content.
- `start` and `target` are canonical absolute drive paths: `X:\` and components, none empty, `.` or `..`, none ending in a space or a dot, none of `< > : " / | ? *`, at most 2,048 UTF-16 units; never `\\?\`, UNC or relative. `bitness` is the target's PE machine, read when planning.
- `encode` checks its output with `decode` and fails rather than write a file the shim would refuse (a deviation from the plan's infallible signature).
- `ProfileId`: 16 bytes, 32 lower-case hex digits in the file name and the launch option. How core derives it (folded canonical start path, or app ID + start path; plan nit) is decided with the planner in P3-3.
- Place: `<LocalAppData>\Rerun\profiles\<id>.profile` (docs/01). Written only by `apply` as a journaled file op (P3-3).

### D2 · How the shim finds its profile
The launch option is `"<install>\rerun-launch.exe" --profile <32 hex> %command%`. The folder comes from `SHGetKnownFolderPath(FOLDERID_LocalAppData)`, never from the environment. That adds `shell32.dll` to `LAUNCH_IMPORTS` (ADR 0008 import allowlist, reviewed in P3-1b). If a cold start measures 50 ms or more until `CreateProcessW` (release build, [DEV]), the option carries the full profile path instead and the shim checks only its form (`<drive>:\…\Rerun\profiles\<32 hex>.profile`).
The read is bounded (`MAX_PROFILE_BYTES + 1`) and refuses a reparse point at the file. The profile is user-writable by design: whoever can write it can also start the game with any affinity, so it is no privilege boundary (R7: an elevated Steam makes the shim elevated, it still starts only Steam's command and sets only affinity and priority).

### D3 · Fail closed for the rule, fail open for the start
Profile missing or invalid, Steam's first argument not equal to `start` (ordinal, case-insensitive; then `path_mismatch`), topology error, `Empty` selection, a job or verification failure: the shim starts Steam's command **unchanged**, without any limit, and records the outcome (D5). A rule is never applied to another path than the planned one. Without Rerun, Steam would have started exactly that command; an orphaned profile (revert while Steam was open) must not make a game unstartable. Exceptions, which start nothing: the DLL search restriction fails (ADR 0008, fail closed, B2), or the shim's own command line is unusable (B1).

### B1 · No console; the shim's own command line
- `#![windows_subsystem = "windows"]`: no console window flashes up at a game start. The shim reports through its exit code and the result file only; `crates/rerun-launch/tests/hardening.rs` checks the exit code instead of stderr (P3-1b).
- The command line is taken raw from `GetCommandLineW`: the shim's own first token (by the `CommandLineToArgvW` rule for argument 0), the literal `--profile`, one token, then Steam's command as the raw tail, never re-quoted from `argv`. A token that is not 32 lower-case hex digits counts as an invalid profile (D3: start the tail unchanged, no result file, since there is no ID). Without `--profile`, or with nothing after the token, there is no command to start: exit code 2, nothing started. If the game started, the shim's exit code is the game's (B3); before a start, 1 means the hardening failed and 2 an unusable command line.
- Steam's command is started with `lpApplicationName = profile.start` in the profile's spelling when it matches Steam's first argument, otherwise with `lpApplicationName = NULL` and the tail (unchanged start). Never a path from a handle, never `\\?\` (docs/04, layers start path). Handles are not inherited; environment and current directory are the shim's (Steam's).

### B2 · Elevation required (error 740)
If `CreateProcessW` fails with `ERROR_ELEVATION_REQUIRED`, the shim starts Steam's command with `ShellExecuteExW` (default verb, so Windows asks for consent per the game's manifest), without any rule, and records `elevation_required`. `ShellExecuteExW` is banned (ADR 0010); the exception is this one call in the wrapper module of `rerun-launch`, because `CreateProcessW` cannot raise a consent prompt and the game must still start (D3). Covered by a fake-OS test in P3-1b. It also needs `shell32.dll` (see D2).

### B3 · Lifetime
- `direct`: the shim waits for its direct child to exit and passes its exit code through, so Steam keeps tracking the game (risk R1: playtime, overlay, "Stop", cloud sync after the end). The post-launch check (P3-2) runs about 5 s after the start, while waiting. docs/04: "until the started process exits".
- `watch`: the shim lives at least as long as its direct child and at most until the target is found and checked; if the target never appears, it stops searching after `watch_timeout_s` (≤ 120 s) and writes `target_not_found` (≤ 130 s in all, plus the wait for the direct child).
- Rule 1 holds: never longer than the game, opt-in through the applied plan, the preview names the lifetime. A [DEV] measurement (overlay, Steam Input, cloud sync, a SteamStub game) may relax the wait, never extend it.

### D5 and B13 · Result file, not the journal
The journal has one writer under `journal\lock` (ADR 0019); a game start during an `apply` must neither block nor write records. The shim writes the outcome of the last start to `<LocalAppData>\Rerun\launch\<id>.result` (codec in `rerun-proto::launch`, P3-2): handle-relative below `launch`, a reparse point at `Rerun` or `launch` refused, temp file + rename in that folder, bounded. Core reads it as untrusted input. It is Rerun-owned state like the journal: revert and `forget` of the profile leave it. **B13:** a shim running elevated (`TokenElevation`, Steam started as administrator) writes no result file, so an elevated process never writes into a user-writable folder. This writer is new surface for the shim and goes to the security review with P3-2.

### Not decided here
D4 (`watch` target identity: path only, hash at plan time) and D6 (priority in the profile) are taken as decided in the plan; P3-4 records the `watch` details here. The result codec, `CheckOutcome` and `reset` without a culprit follow in P3-2.

## Sources (Microsoft Learn; the wording above is paraphrased)
- `SetInformationJobObject` and `JOBOBJECTINFOCLASS`: `JobObjectGroupInformationEx` (an array of `GROUP_AFFINITY`, Windows 8 and later). learn.microsoft.com/windows/win32/api/jobapi2/nf-jobapi2-setinformationjobobject
- `JOBOBJECT_BASIC_LIMIT_INFORMATION`: `Affinity` is a `ULONG_PTR` and a subset of the process affinity mask from `GetProcessAffinityMask`. learn.microsoft.com/windows/win32/api/winnt/ns-winnt-jobobject_basic_limit_information
- Processor Groups: affinity per group via `GROUP_AFFINITY`; Windows 11 / Server 2022 spread processes across groups by default. learn.microsoft.com/windows/win32/procthread/processor-groups
- `UpdateProcThreadAttribute`: `PROC_THREAD_ATTRIBUTE_JOB_LIST`, `PROC_THREAD_ATTRIBUTE_GROUP_AFFINITY`. learn.microsoft.com/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute
- Nested Jobs (Windows 8 and later). learn.microsoft.com/windows/win32/procthread/nested-jobs
- `GROUP_AFFINITY` (`KAFFINITY Mask`, `WORD Group`) and Windows Data Types (`DWORD_PTR`, `ULONG_PTR`: pointer width). learn.microsoft.com/windows/win32/api/winnt/ns-winnt-group_affinity, learn.microsoft.com/windows/win32/winprog/windows-data-types
- Testing several groups on a small machine: `bcdedit /set groupsize`. learn.microsoft.com/windows-hardware/drivers/devtest/boot-parameters-to-test-drivers-for-multiple-processor-group-support

## Alternatives
- **Basic-limit `Affinity` for group 0, `JobObjectGroupInformationEx` only for other groups:** two code paths, and the group-0 path relies on the primary group, which Windows 11 no longer pins.
- **`SetProcessAffinityMask` on the suspended child, no job:** one group only (the primary), the game may undo it, children are not covered.
- **32-bit: a count of 32 anywhere in the group:** more choice on large groups, but masks the game cannot represent (B6).
- **JSON profile with a hand-written parser, or serde in the shim:** a larger parser to bound and test (D1 b), or against ADR 0006 (D1 c).
- **Do not start on any error (D3 b):** an orphaned profile would block the game in Steam.
- **Results in the journal:** a second writer, or a start that blocks behind an `apply`.

## Consequences
- `rerun-proto` grows by `cpu::rule` and `profile` (no dependency). The fixtures planned in docs/03 exist now (datasheet or synthetic, assumptions in their README) with a reviewed selection snapshot.
- P3-1b: `rerun-launch` gets its `Os` trait (real and fake), the copy of the two topology calls (x64 only, `compile_error!` otherwise, ADR 0010), the wrapper module with the setter and `ShellExecuteExW` exceptions, `windows_subsystem`, and the reviewed `LAUNCH_IMPORTS` (`shell32.dll`); amendments to ADR 0008 and ADR 0010; docs/04 (lifetime, result file instead of journal, `reset` without culprit, start path rule) and docs/01 (exits immediately → lifetime) in the same commit.
- docs/03 states the selection precisely (group tie, LP-E rule, 32-bit indices, L3 ties only with `single_l3`/`prefer_l3`, B5).
