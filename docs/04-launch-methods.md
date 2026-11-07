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
| `direct` | Start game suspended, in a Job Object with limit, resume | ms | no | none |
| `watch` | Start chain, wait for target exe (path + hash), set affinity/CPU Sets, exit. Timeout 120 s | until game start | no | low |
| `hold` | like `watch`, stays until the game ends, sets affinity again if it was reset (check interval 2 s) | game duration | no | low, visible, opt-in |
| `ifeo` | `IFEO\<exe>\Debugger = rerun-launch`. Every start of the exe goes through us. Starts the real game (debugger flag, detach immediately), stays until the game ends, passes the exit code through | game duration | yes | AV/DRM may trigger; opt-in |
| `inproc` | `rerun-cpu.asi` in the game: sets affinity from inside, hooks `SetProcessAffinityMask`, reports a smaller core count | in the game | no | occupies slot; off-limits with anti-cheat |
| `shim_single` | Windows fix `SingleProcAffinity` via own SDB | permanent until revert | yes | only 1 core |

`auto` chooses based on `launch.chain` in the Topo: no third-party launchers → `direct`; known launchers → `watch`; the Topo can prescribe `hold`/`ifeo`/`inproc`.

## Post-launch check (required)

`rerun-launch` (or, with `direct`, a short follow-up run) checks the actual affinity of the target process a few seconds after the game starts and writes the result to the Journal:

- `ok` – "Affinity active · 8 of 32 threads · verified"
- `reset_by:<exe>` – "Reset by upc.exe · method hold/ifeo recommended"
- `target_not_found` – timeout, target exe never seen

The app shows this the next time it is opened. Failures become suggestions for the Topo (GitHub issue template).

## The main executable and the game-closed check

Apply and revert ask `users()` of every file a plan touches and of the game's **main executable** (user decision D4). A plan with registry ops or `ini_set` needs the main executable (user decisions E2 of P2-10b and E5 of P2-12): a registry value has no file to ask, and a running game holds no INI file open, it writes it when it exits, so asking the INI file itself proves nothing. The main executable must therefore be the process that writes the INI file on exit: with a launcher chain (above), the game, not the launcher or a stub that exits. Otherwise an apply or revert can run while the game is still running, and the game overwrites the change when it quits (a revert then finds `Drifted` or `Foreign`).

## Interrupting an apply or a revert

`rerun` installs no console control handler (P2-13): Ctrl+C, closing the console or a crash during `apply` or `revert` ends the process at once, which the journal is built for (ADR 0019). The transaction stays open; `rerun status` shows it and `rerun revert <txn>` finishes it from what is on disk. `apply` and `revert` refuse while the game (its main executable) runs, so start the game only after they have finished.

## Steam integration

Launch option `"<path>\rerun-launch.exe" %command%`. Written to `localconfig.vdf` only while Steam is closed, previous value to the Journal. Otherwise: copy + instructions.

## A game that Steam moved or reinstalled

After Steam moved a library (or the app into another library) or reinstalled the game, a revert halts at the game folder or is refused ("another folder now"). `rerun revert <txn> --rebind` (P2-14) shows the folder Steam lists for the app now (found by the Steam scan: exactly one library, every listed library readable), what the revert does there and that the registry changes are reverted where Rerun made them (a compatibility-layer value under the old program path; none is written under the new one), asks at a console, then binds the transaction to that folder for good and reverts it there. A folder the user chose is never rebound; `forget` closes such a transaction. The game must be closed in the new folder too, and its main executable must be there.

## Compatibility layers and the start path (phase 3 condition)

A compatibility layer (`compat_layer`, `AppCompatFlags\Layers`) applies only when Windows starts the program by exactly the path of the value name, the game's canonical path (SB-L2, ADR 0018 amendment P2-11b): a start through a junction, or through another spelling, gets no layer, silently. So `rerun-launch` and the IFEO launcher must start the game by that path as the plan names it: no `\\?\` prefix, no path taken from a handle, no junctioned library path. 8.3 names are not measured. The Sandbox probes (`scripts/sandbox-probe-layers.ps1`) can check a start form before phase 3 relies on it.

## IFEO details

- Key: `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<exe-name>`, value `Debugger`. Applies to **all** exes with this name → additionally set `UseFilter` + `FilterFullPath` so that only the game's path is affected.
- Avoid recursion: create the game with `DEBUG_ONLY_THIS_PROCESS` (IFEO then does not apply), immediately `DebugActiveProcessStop`.
- Revert is guaranteed to remove the key, even if Rerun is uninstalled (uninstall notice + `rerun revert --all`).
