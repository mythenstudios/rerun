# ADR 0028 · Steam launch option written by Rerun (`launch_option`)

**Status:** Proposed, deferred to phase 6 as an opt-in setting (copying stays the default; user 2026-11-24) · 2026-11-24 · extends ADR 0007, ADR 0011, ADR 0019, ADR 0020 (X12), ADR 0021, ADR 0022 (D2) · relates to ADR 0032 · plan P5-7 · accepted only after the [DEV] measurement of P5-7a and the user decisions E1 to E4

## Context
A launch profile (ADR 0022) only applies when Steam starts the game through `"<install>\rerun-launch.exe" --profile <id> %command%`. Until now the user pastes that launch option by hand and removes it by hand after a revert (ADR 0020 X12). Steam keeps launch options per account in `<Steam>\userdata\<account>\config\localconfig.vdf`, a Valve KeyValues text file that Steam holds in memory while it runs and writes back (at least) when it exits. The Steam folder is user-writable by default, so the file is untrusted input like `libraryfolders.vdf` (ADR 0011, docs/06 #12). It can be several MiB and holds personal data (friends, settings).

Open until measured (P5-7a): whether Steam rewrites the file on start, whether Steam Cloud (`sharedconfig.vdf`) carries launch options, how Steam escapes `"` and `\`, where it inserts `LaunchOptions`, what it changes on its own per session, whether it writes in place or by temp file and rename, and the real size and shape of the file.

## Decision (draft)
1. **When.** No Topo step. A plan gets one `LaunchOption` op exactly when it **creates** the launch profile of the game (`CreateFile` in `profiles`), placed after the profile op. A plan that replaces an existing profile gets none: the option belongs to the transaction that created the profile (or to the user who pasted it). The option string stays constant per game (ADR 0032); Topo arguments (`tips.launch_options`) are hints and never written.
2. **Root.** A new root kind `SteamConfig`: `userdata\<account>\config` opened handle-relative from the Steam root (`StoreDir`), no reparse point on the way, identity recorded and checked on every apply and revert, never rebound. Its write handle only for `exec` (`clippy.toml`). Fence: on this root only the op `LaunchOption`, only on `localconfig.vdf`, at most one per plan. A Steam folder the user cannot write is never written (no helper, rule 6).
3. **Account.** The one entry of `config\loginusers.vdf` with `MostRecent "1"` whose `userdata\<id>` exists (P5 U11 a). None, several or an unreadable file: no op, the copy fallback.
4. **Editor** (`policy::steam_option`, pure, the pattern of ADR 0021): only the string value `UserLocalConfigStore\Software\Valve\Steam\apps\<appid>\LaunchOptions` (keys compared ASCII case-insensitively) changes; every other byte stays. v1 inserts the key only into an existing app object. A duplicate key on the path, a value that is an object, any input the bounded grammar refuses: no op (copy fallback). The output of `set` is frozen (golden vectors), because recorded heads bind it. The editor and `parse` share one grammar core, an event walker with byte spans in `detect::vdf` (ADR 0011 amendment), with its own `Limits::LOCAL_CONFIG`.
5. **Value.** Empty or missing: Rerun's option. An existing option without `%command%`: Rerun's option, one space, the existing text. An existing option with `%command%` (another wrapper) or another Rerun option: refused with the reason. Exactly Rerun's option already there: no op.
6. **Steam must be closed.** "Running" means a process whose image is `<Steam root>\steam.exe`, through a new read-only `sys` capability `Processes::image_running` (the helper check of A4 S8, generalised); a process that cannot be asked counts as running (fail closed). Checked under the journal lock before the first change, again right before the op, and once more after the last write (a Steam started meanwhile is reported). Apply and revert are refused while Steam runs. Rerun never ends Steam.
7. **Revert** (the `IniValue` pattern): the file as written → the backup bytes back (exact); otherwise the value still Rerun's → `Drifted`, only the value is set back in the current content (the normal path, since Steam rewrites the file); the old value → `Before`; anything else per user decision E3. The head is bound to its backup (`set(backup) == new`), else `Blocked`.
8. **X12** applies only to transactions without a `LaunchOption` op (older ones, the copy fallback); new exception rows in ADR 0020 cover the semantic revert and a Steam started during the apply.

## Alternatives
- **Keep the copy step only.** Simple, but every user has to paste and later remove a string by hand, and a forgotten option keeps the shim in the start path (X12).
- **A tree-based VDF writer.** Rewrites the whole file in Rerun's format: no exact revert, and Steam's own layout changes would look like foreign changes.
- **Write while Steam runs.** Steam writes its in-memory copy back on exit and the change is lost.
- **Steam's own interfaces** (`steam://` URLs, the Steamworks API): none sets launch options.

## Consequences
- The first write outside game folders and Rerun's own folder into a file Steam owns; docs/06 gains a row.
- The user has to close Steam to apply or revert a plan with a launch profile (or chooses the copy fallback, E2).
- To be filled from P5-7a: limits, escape form, insertion point, Steam's own changes, cloud behaviour.
