# 04 · Launch methods

## Problem

A Job Object only affects descendants of `rerun-launch`. Many games, however, are started by a launcher that runs outside of it:

```
steam.exe → rerun-launch → game.exe (stub) ─► exits, calls upc.exe
upc.exe (already running) → game.exe (real game)   ← inherits affinity from upc.exe
```

The same applies to EA App, Rockstar Launcher, Battle.net. In addition: games that set their affinity themselves, and launchers that start with breakaway.

## Methods

| Method | How | Lifetime | Admin | Risk |
|---|---|---|---|---|
| `direct` | Start game suspended, in a Job Object with limit (or with default CPU Sets), resume, wait for it | until the started process exits | no | none |
| `watch` | Start chain, wait for target exe (path; its hash is checked when planning), set affinity/CPU Sets, check, exit. Timeout 120 s | at least as long as the started process, at most until the target is found and checked (≤ 130 s if it never appears, plus the wait for the started process) | no | low |
| `hold` | like `watch`, stays until the game ends, sets affinity again if it was reset (check interval 2 s) | game duration | no | low, visible, opt-in |
| `ifeo` | `IFEO\<exe>\Debugger = rerun-launch`. Every start of the exe goes through us. Starts the real game (debugger flag, detach immediately), stays until the game ends, passes the exit code through | game duration | yes | AV/DRM may trigger; opt-in |
| `inproc` | `rerun-cpu.asi` in the game: sets affinity from inside, hooks `SetProcessAffinityMask`, reports a smaller core count | in the game | no | occupies slot; off-limits with anti-cheat |
| `shim_single` | Windows fix `SingleProcAffinity` via own SDB | permanent until revert | yes | only 1 core |

`auto` chooses based on `launch.chain` in the Topo: no third-party launchers → `direct`; known launchers → `watch`; the Topo can prescribe `hold`/`ifeo`/`inproc`.

## Post-launch check (required)

`rerun-launch` checks the actual affinity (and priority class) of the target process about 5 s after the start, while it waits, and writes the outcome of the last start to `<LocalAppData>\Rerun\launch\<id>.result` (ADR 0022 D5 and amendment P3-2), never to the journal: the journal has one writer, and a game start during an `apply` must neither block nor write records. Core reads the file as untrusted input; `rerun status` shows the last result per profile with its time (UTC), a file it cannot read as one line.

What is checked (rule applied, once, after waiting up to 5 s on the running game): hard limit – the job still holds exactly the selected group affinity and the game's process affinity equals it (or is a non-empty subset of it: `narrowed`); soft limit – the game's default CPU Sets are exactly the selected ones; priority – the game's priority class is the one set (not checked if the profile sets none).

- `ok` – "Affinity active · 8 of 32 threads · verified" (soft: the CPU Sets of the started process only)
- `narrowed` – hard limit: the job still holds the selection and the game limited itself to fewer of its threads (e.g. CPU 0); within the rule, not an error
- `reset` (`cpu`, `priority` or both) – changed after the start: the job holds something else, or the game's mask is empty or outside the job's (no culprit is named: the shim cannot tell who did it)
- `exited_early` – the started process ended within 5 s, before the check (it crashed, or it is a launcher stub that hands over to the real game as another process)
- `failed:<code>` – the check itself could not read the process
- `target_not_found` – `watch` only (P3-4): timeout, target exe never seen
- `rule_skipped` with a reason – the rule was not applied and the game started unchanged (below): `profile_missing`, `profile_unreadable`, `profile_reparse_point`, `profile_invalid`, `method_unsupported`, `path_mismatch`, `topology_unavailable`, `topology_invalid`, `selection_empty`, `spawn_failed`, `job_failed`, `read_back_failed`, `mismatch` (the read-back before the resume differed), `cpu_sets_failed`, `resume_failed`, `elevation_required`, … (the full list and the file format in ADR 0022 amendment P3-2)

The record is written once per start, before the shim waits for the game; with the rule applied that is after the check, so ending the shim (Steam's "Stop") within the first 5 s loses it. A failed write changes nothing else (a concurrent `rerun status` can make the replace fail; the old record stays). Nothing is written by an elevated shim (B13), for a token that is no profile ID, or when `<LocalAppData>\Rerun` does not exist; the folder `launch` is created if missing. The writer refuses a reparse point at `Rerun`, `launch` or the file. The file is Rerun's own state like the journal: revert and `forget` leave it, the next start replaces it.

The app shows this the next time it is opened. Failures become suggestions for the Topo (GitHub issue template).

## The main executable and the game-closed check

Apply and revert ask `users()` of every file a plan touches and of the game's **main executable** (user decision D4). A plan with registry ops or `ini_set` needs the main executable (user decisions E2 of P2-10b and E5 of P2-12): a registry value has no file to ask, and a running game holds no INI file open, it writes it when it exits, so asking the INI file itself proves nothing. The main executable must therefore be the process that writes the INI file on exit: with a launcher chain (above), the game, not the launcher or a stub that exits. Otherwise an apply or revert can run while the game is still running, and the game overwrites the change when it quits (a revert then finds `Drifted` or `Foreign`).

## Interrupting an apply or a revert

`rerun` installs no console control handler (P2-13): Ctrl+C, closing the console or a crash during `apply` or `revert` ends the process at once, which the journal is built for (ADR 0019). The transaction stays open; `rerun status` shows it and `rerun revert <txn>` finishes it from what is on disk. `apply` and `revert` refuse while the game (its main executable) runs, so start the game only after they have finished.

## Steam integration

Launch option `"<install>\rerun-launch.exe" --profile <id> %command%` (`<install>`: Rerun's install folder; `<id>`: 32 lower-case hex digits from the Steam app ID, the profile `<LocalAppData>\Rerun\profiles\<id>.profile`, ADR 0022 D2 and amendment P3-3). Written to `localconfig.vdf` only while Steam is closed, previous value to the Journal (phase 5). Until then (P3-3): `rerun plan` and `rerun apply` show the option to copy and where to paste it (the game > Properties > General > Launch options); existing launch options go after `%command%`, an option that already holds `%command%` (another wrapper) cannot be combined. Rerun does not change Steam's settings (ADR 0020 X12). The `revert` preview and report and the `forget` preview say what becomes of the profile: if the revert leaves no profile (a created one reverted), the user removes the option by hand, named literally; until then Steam keeps starting the game through `rerun-launch`, which finds no profile and starts it unchanged (`profile_missing`; `rerun status` says the option was still set). If the revert brings back a profile an earlier transaction wrote, that one keeps applying and the option stays. A profile that is not reverted (a halt before it, a profile someone changed, `forget`) keeps applying until the option is removed. Moving or deleting `rerun-launch.exe` breaks the start through Steam until the option is removed.

- **Start path.** The profile's `start` is the program of Steam's launch entry (Topo `launch.start`, step `launch_method.start`), which may be a launcher; then the game inherits a hard limit through the job, a soft limit or a priority class reaches only the launcher and is refused until `watch` (P3-4), and the post-launch check covers the launcher (`rerun status` says so). The preview shows the selection on this computer, the launcher case and the hints (more than one processor group, a 32-bit game on a group of more than 32 processors).
- **Steam updating.** The game-closed check and the app state hold for a plan whose only op is the profile too: a revert is refused while Steam reports the app as updating (`UpdatePending`), until Steam has finished.

## `rerun-launch direct` (phase 3, ADR 0022)

- **Command line.** Taken raw from `GetCommandLineW`: the shim's own name, `--profile`, one token, then Steam's command as the raw tail, passed to `CreateProcessW` unit for unit, never re-quoted. Steam's first argument (`argv[0]`, cut by the `CommandLineToArgvW` rule for argument 0) is always `lpApplicationName`, never `NULL`, so Windows never searches the current directory or `PATH`; it must be an absolute drive path (`X:\…`).
- **Path only.** The rule applies only if `argv[0]` equals the profile's `start` (ordinal, case-insensitive); the game is started by Steam's spelling of the path. Otherwise `path_mismatch`. No hash is checked at the start; the planner does not check one either in phase 3 (`launch_method` names the start by path, ADR 0022 amendment P3-3): the exe's hash is checked against the Topo's `match` when the Topo engine plans (phase 4).
- **Fail open for the start.** A missing, unreadable or invalid profile, another path, a topology or selection error, or any failure while setting and reading back the limit starts Steam's command unchanged (no job, no limit, no priority). Error 740 (`requireAdministrator`) starts it through `ShellExecuteExW` without a rule (`.exe` only). A shim that runs elevated (Steam as administrator, or UAC off) never reads the profile and starts the command unchanged.
- **Hard limit.** A Job Object with one `GROUP_AFFINITY` (`JobObjectGroupInformationEx`), the child created suspended inside it, the job and the initial thread read back, then resumed; a difference ends the suspended child and starts the command unchanged. **Soft limit.** `SetProcessDefaultCpuSets` on the suspended child (the started process only, not its children).
- **Lifetime.** The shim waits for the process it started and exits with its exit code, so Steam keeps tracking the game (playtime, overlay, "Stop"); the post-launch check and the result file (above) happen while it waits. Before a start: exit 1 (DLL hardening failed) or 2 (the shim's own command line is unusable: no `--profile`, nothing after it, or `argv[0]` not absolute); 3: the command could not be started. No console window.

## A game that Steam moved or reinstalled

After Steam moved a library (or the app into another library) or reinstalled the game, a revert halts at the game folder or is refused ("another folder now"). `rerun revert <txn> --rebind` (P2-14) shows the folder Steam lists for the app now (found by the Steam scan: exactly one library, every listed library readable), what the revert does there and that the registry changes are reverted where Rerun made them (a compatibility-layer value under the old program path; none is written under the new one), asks at a console, then binds the transaction to that folder for good and reverts it there. A folder the user chose is never rebound; `forget` closes such a transaction. The game must be closed in the new folder too, and its main executable must be there.

## Compatibility layers and the start path (phase 3 condition)

A compatibility layer (`compat_layer`, `AppCompatFlags\Layers`) applies only when Windows starts the program by exactly the path of the value name, the game's canonical path (SB-L2, ADR 0018 amendment P2-11b): a start through a junction, or through another spelling, gets no layer, silently. So `rerun-launch` and the IFEO launcher must start the game by that path as the plan names it: no `\\?\` prefix, no path taken from a handle, no junctioned library path. `rerun-launch` starts by Steam's `argv[0]` and applies a rule only if it equals the planned path case-insensitively (ADR 0022 M2); whether the layer then applies to Steam's spelling is Sandbox case SB-L7. 8.3 names are not measured. The Sandbox probes (`scripts/sandbox-probe-layers.ps1`) can check a start form before phase 3 relies on it.

## IFEO details

- Key: `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<exe-name>`, value `Debugger`. Applies to **all** exes with this name → additionally set `UseFilter` + `FilterFullPath` so that only the game's path is affected.
- Avoid recursion: create the game with `DEBUG_ONLY_THIS_PROCESS` (IFEO then does not apply), immediately `DebugActiveProcessStop`.
- Revert is guaranteed to remove the key, even if Rerun is uninstalled (uninstall notice + `rerun revert --all`).
