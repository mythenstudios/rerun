# ADR 0020 · Plans, operations and primitives

**Status:** accepted (decided by the user) · 2026-11-05 · replaces the `Primitive` trait of `docs/01-architecture.md`; builds on ADR 0017, ADR 0018, ADR 0019

## Context
`docs/01-architecture.md` gave every primitive its own `plan`, `apply`, `verify` and `revert` over `&dyn System` (audit A1 nit: not over root types). The four phase 2 primitives (`file_install`, `registry_set`, `compat_layer`, `ini_set`) share a handful of effects: create a directory, create or replace a file, create a key, set a value. Each effect needs the same guard, intermediate phases, journal records, crash and power-loss tests (ADR 0017, ADR 0019); per primitive they would be written and tested four times. Phase 2 also needs an input before the Topo engine exists (phase 4), a plan hash that binds preview and apply, and rules for a revert that meets changed state.

## Decision

### Primitives are planners, effects are op kinds (user decision D9)
A primitive turns its spec into ops; `exec` applies, verifies and reverts op kinds. The round-trip test `apply → verify → revert → snapshot identical` stays mandatory **per primitive** (`docs/09-testing.md`); the crash, power-loss and tamper tests run per op kind.
```rust
// prim: durable spec types (serde, deny_unknown_fields) and one planner each
pub enum Step { FileInstall(FileInstallSpec), RegistrySet(RegistrySetSpec),
                CompatLayer(CompatLayerSpec), IniSet(IniSetSpec) }
pub struct PlanCtx<'a> { pub game: &'a GameDir<'a>, pub app: &'a AppDir<'a>,
                         pub sys: &'a dyn System, pub reg: &'a RegPolicy }  // reads only
pub fn plan(steps: &[Step], ctx: &PlanCtx<'_>) -> Result<Plan, PlanError>;

// plan
pub struct Plan { pub format: u32, pub roots: Vec<PlanRoot>, pub ops: Vec<Op> }   // format 1
pub struct PlanRoot { pub kind: RootKind, pub path: RootPath, pub id: RootId,
                      pub origin: PlanOrigin, pub main_exe: Option<RelPath> }
pub enum RootKind { Game }                    // `UserData` reserved (D6, phase 4)
pub enum PlanOrigin { Steam { store: RootPath, store_id: RootId, app_id: u32, installdir: RelPath },
                      Manual }
pub struct RootIx(pub u16);                   // index into `roots`, one per file op (condition S4)
pub enum Op {
    CreateDir   { root: RootIx, path: RelPath },
    CreateFile  { root: RootIx, path: RelPath, content: ContentRef, attrs: Attrs },
    ReplaceFile { root: RootIx, path: RelPath, old: FileState, content: ContentRef, attrs: Attrs },
    CreateKey   { slot: RegSlot, key: RegKey },
    SetValue    { slot: RegSlot, old: Option<RegValue>, new: RegValue },
    IniValue    { root: RootIx, path: RelPath, old_file: FileState, section: String, key: String,
                  old: Option<String>, new: String },
    TokenList   { slot: RegSlot, old: Option<RegValue>, add: Vec<String> },
}
pub struct FileState { pub sha256: [u8; 32], pub len: u64, pub attrs: Attrs }
pub enum ContentRef { Package { id: String, version: String, file: RelPath, sha256: [u8; 32], len: u64 } }
pub struct PlanHash(pub [u8; 32]);

// exec
pub enum Observed { Before, After, Drifted, Foreign }
// `fr`: roots are reopened through policy::root (StoreDir::open / game, GameDir::open_manual)
pub fn apply(sys: &dyn System, fr: &ForbiddenRoots, app: &AppDir<'_>, plan: &PlanHash) -> Result<TxnId, ApplyError>;
pub fn verify(sys: &dyn System, fr: &ForbiddenRoots, app: &AppDir<'_>, txn: &TxnId) -> Result<Vec<(usize, Observed)>, ExecError>;
pub fn revert(sys: &dyn System, fr: &ForbiddenRoots, app: &AppDir<'_>, txn: &TxnId, rebind: bool) -> Result<RevertReport, ExecError>;
pub fn forget(app: &AppDir<'_>, txn: &TxnId) -> Result<(), ExecError>;
```
- Ops whose old and new state are equal are not emitted (the same hash and attributes, the same value, a token already present). A plan without ops is "nothing to do" and starts no transaction.
- Every missing directory is its own `CreateDir`, every missing key its own `CreateKey` (ADR 0004). There is no delete op in phase 2: deleting is only ever a revert.
- `roots[]` with an index per op lets a plan span several roots and keeps room for `UserData` (D6) without a format change.
- An op that needs admin (an `HKLM` slot, a root the user cannot write) is marked `NeedsHelper` by the planner; phase 2 refuses such a plan, phase 3 sends that part to the helper. A non-elevated `AccessDenied` never escalates (ADR 0007).

### Plan hash
- `rerun plan` serialises the plan **once**; those bytes are the preview's source, are stored as `<AppDir>\plans\<hash>.json` and become `head.json` of the transaction (ADR 0019). `PlanHash` is SHA-256 over exactly these bytes. Nothing is serialised again for hashing.
- Head types use `BTreeMap` only, never `HashMap`; `RootId` (serial and file ID), every SHA-256 and every byte string (`REG_BINARY`, `Raw` data) are lower-case hex strings (no JSON number above 2^53); `format` is part of the hashed bytes.
- `apply` takes the hash the preview showed, reads the stored bytes (bounded), refuses unless their hash matches, then parses them as untrusted input. The hash binds what was previewed to what is applied and catches accidents; it is not a security boundary, the re-checks below are.

### Preview
Every op is shown before anything happens (core rule 5): root and path, key and value name, old and new value, content source and hash, attributes, and once per plan what a revert does not restore (ADR 0017, D3). Every untrusted field reaches output only as `escape::Shown` (condition S9; ADR 0016): `escape::path` for paths and value names, `escape::text` for values, INI sections and keys.

### Apply
In this order, all before `head.json` is written (ADR 0019): take the lock; check the hash; reopen every root through `policy::root` and `ensure_id`; for a Steam root re-read the app state, and refuse `UpdatePending` and `NotInstalled` (ADR 0012); **the game must be closed** (user decision D4): `users()` of every existing file-op target and of each root's main executable must be empty, else `Busy` with "<exe> is in use; close the game and try again later"; check stacking (ADR 0019); re-observe every op's old state (guard hash, value read) and refuse with `Mismatch` ("changed since the preview; plan again") on any difference. Then op by op (ADR 0019 write order), `verify` (every op must observe `After`), flushes, `Applied`. Any failure after the first change rolls back at once (ADR 0019, B-2). Revert checks D4 and the Steam state the same way.

### Observing and reverting
Each op kind observes its object on disk, never trusting a record alone:
- `Before`: as before the op. `After`: exactly as the op left it. `Drifted` (semantic ops only): the surrounding content changed, Rerun's own part is still exactly as it set it. `Foreign`: anything else.
- `After` is reverted, `Before` needs nothing, `Drifted` gets a semantic revert, `Foreign` is **never overwritten or deleted** (user decision D10, replacing "otherwise ask" in `docs/06-security.md` and `docs/02-topo-format.md`): the op stays unresolved, its backup stays in the journal, `status` names the backup's location, and `forget` closes the transaction after a preview.

| Op | `After` / revert |
|---|---|
| `CreateDir` | exists with the file ID from `Done`, empty / `remove_dir` by that ID; not empty or another ID: `Foreign` |
| `CreateFile` | content hash, one link / guard + `delete(expected)`; a user-edited file (a `config` file) is `Foreign` |
| `ReplaceFile` | new hash / guard + `replace(expected new, backup, old attributes)`; old hash is `Before` |
| `CreateKey` | exists, no values or subkeys / `delete_empty_key`; with content `Foreign` |
| `SetValue` | value equals `new` / set `old`, or delete it if there was none; equals `old`: `Before` |
| `IniValue` | file hash as written / restore the backup bytes; otherwise our key still has `new`: `Drifted`, set the key back to `old` (or remove it) in the current content and keep everything else; our key changed: `Foreign` |
| `TokenList` | value as written / restore `old`; otherwise our tokens still present: `Drifted`, remove only them (delete the value if nothing is left and there was none before); a token removed: `Foreign` |

For `ini_set` the semantic revert is the normal path, not an exception: games rewrite their INI files on every start, so `After` rarely holds by the time of a revert. The INI editor changes only the value span (line endings, encoding and every other byte kept), so a semantic revert of an unchanged file gives exactly the old bytes; the round-trip test pins that. A semantic revert writes through `FileGuard::replace` with the hash just observed as the expected one.

### Rebind (user decision D5)
After a moved Steam library or a reinstall, a revert meets `IdentityMismatch`. `rerun revert <txn> --rebind` binds the transaction to the new folder only if all hold: the recorded root cannot be opened any more; the Steam scan finds the app's install folder in exactly one library; every op of that root observes `Before` or `After` there (no `Foreign`); and the user confirms a preview showing the old and the new folder and identity. A `Rebind` record is written first. Manual roots are never rebound. Otherwise the transaction stays as it is and only `forget` closes it.

### Input until the Topo engine (user decision D7)
`rerun plan <steps.json>` reads a JSON step file: a throwaway envelope (`format: 1`, the game as a Steam app ID or a folder, `steps`) around **durable step objects**: each step is an object with exactly one key, deserialised into the spec types above with `deny_unknown_fields`. `registry_set`, `compat_layer` and `ini_set` are the Topo step objects of phase 4 and enter `schema/topo.schema.json` with their primitive (ADR 0005); `file_install` is what a Topo `package` step expands to (the package's files with their hashes) and is not a Topo step itself. The file is read through `policy::root` (its folder opened read-only by absolute path, the file a single segment), at most 1 MiB with a bounded read; every path field is parsed as `RelPath`, hashes follow `docs/02-topo-format.md`. No YAML at run time before phase 4.

### First primitive: `file_install` (user decision D11)
Sources are files below `<AppDir>\packages\<id>\<version>\` (`id` and `version` with the rules of `docs/02-topo-format.md`), each with a fixed SHA-256 in the step. In phase 2 only test fixtures are placed there (tests, the sandbox script); downloads, slots, `requires` and reference counting are phase 4. The planner emits `CreateDir` per missing parent, `CreateFile` for an absent target and `ReplaceFile` (old state from a guard) for an existing one; a source is opened sharing read only and is hashed while it is streamed into the temp file (ADR 0017). Audit A2 runs after this primitive.

### Moved
- `UserData` roots (`Documents`, `My Games`) to phase 4 (user decision D6: OneDrive placeholders and redirection need their own rules); the plan format already has `roots[]` with a kind.
- `gpu_preference` to phase 4 with `gpu.hybrid` and `gpu.integrated` (user decision D8; slot reserved, ADR 0018).
- The UAC VirtualStore warning (ADR 0007 "Open for Phase 2") to phase 3.

### CLI
`rerun plan <steps.json> [--dry-run]` (preview and `PlanHash`; without `--dry-run` the plan is stored), `rerun apply <plan-hash>`, `rerun revert <txn> [--rebind]`, `rerun status` (transactions with their state, unresolved ops, pending cleanups, backup locations), `rerun forget <txn>`. `apply`, `revert` and `forget` take the journal lock; `plan` and `status` do not. Output rules of ADR 0016.

## Alternatives
- **The per-primitive trait of `docs/01`:** four copies of the guard, phase, journal and crash logic; planners without a system are pure and cheap to test.
- **Hashing a re-serialised `Plan`:** serde output and map order are not stable across versions; a byte change would make an approved plan unappliable, or worse, a different plan hash the same.
- **Asking on revert** (the former "otherwise ask"): a dialog at revert time invites "overwrite" and destroys the user's or a mod manager's change; `forget` is explicit and keeps the backup until then.
- **Automatic rebind by app ID or name:** could attach a journal to a different folder.
- **YAML input in phase 2:** a run-time YAML parser before the loader rules of phase 4 exist (ADR 0005, ADR 0015 open point).
- **Restoring the INI backup whenever it matches, else refusing:** fails on nearly every game that rewrites its INI on start.

## Consequences
- `rerun-core` modules: `prim` (spec types and planners), `plan` (`Plan`, `Op`, `PlanHash`, storage), `exec` (apply, verify, revert, forget, `Observed`), `journal` (ADR 0019). `serde` with `derive` becomes a direct dependency of `rerun-core` (already in `Cargo.lock` through `serde_json` and `rerun-proto`), justified in its commit.
- `docs/01-architecture.md` (modules, primitives), `docs/02-topo-format.md` (`config: true`, `package`), `docs/03b-gpu-display.md` and `docs/08-roadmap.md` (`gpu_preference` in phase 4), `docs/06-security.md` (scenarios 6, 9, 10, 14) and `docs/09-testing.md` follow in the same commit.
- Core rules: rule 4 (no op kind runs code; content only from pinned hashes; roots and registry slots through policy), rule 5 (preview from the stored bytes), rule 2 (`Observed`, D10, LIFO), rule 6 (`NeedsHelper` refused in phase 2).

## Open points
- Exit codes of the new commands (refused before any change vs. rolled back vs. left open): fixed with the CLI step.
- The INI editor's accepted encodings and syntax (UTF-8, ANSI, UTF-16 with BOM; comments, duplicate keys, keys outside a section): P2-12, failing closed on anything ambiguous.
- `compat_layer` token list: P2-11 (ADR 0018).

## Amendment (P2-8, 2026-11-06; decided by the user after a senior-dev cross-check)

### Wire form of format 1 (`rerun-core::plan`)
- `{"format":1,"roots":[…],"ops":[…]}` exactly as `serde_json::to_vec` writes it: no whitespace, fields in declaration order, `deny_unknown_fields` everywhere, no maps. Enums are externally tagged in `snake_case` (`{"create_file":{…}}`; a unit variant is its name, `"origin":"manual"`). A SHA-256 is 64 lower-case hex digits, a `RootId` the string `<16 hex>-<32 hex>`, `Attrs` `{"readonly":…,"hidden":…,"system":…}`, paths are strings with `\` (`RelPath::parse` and `RootPath::new` again on read). Lengths are JSON numbers (at most 2 GiB).
- `ContentRef::Package` carries `config` (the step's `config: true`, shown by the preview), so the preview needs nothing but the plan.
- **One form:** `decode` checks `format` first (another value is `PlanError::Format`), parses strictly, and accepts the bytes only if re-encoding the result gives the same bytes; so `/`, a lower-case drive letter, whitespace or another field order is refused (`NotOneForm`), not normalised. Then the bounds of `encode`: at most 128 ops, 8 KiB per op serialised, 1 MiB per plan, 16 roots (no root listed twice, a Steam app ID ≥ 1), every `RootIx` inside `roots`, one op per object (root index and folded path), package ID and version by `docs/02-topo-format.md` and a valid segment, contents and old files at most 2 GiB, old files at most 4 GiB together, no `ReplaceFile` whose new hash equals the old one (ADR 0017 A2).
- `store` writes `plans\<hash>.json` with `create_new` and flushes `plans\`; the same bytes again are `Ok`, other bytes under the name are `HashMismatch`. `load` reads at most 1 MiB and refuses bytes that do not hash to the name.
- **Objects** (stacking, ADR 0019 B-2): `(RootId, folded path, created directory?)` per op; two overlap if equal, or if one is a directory an op creates and the other lies below it. Root identity, not the root index or app ID, so two Steam apps sharing one install folder overlap. Two different roots of which one lies inside the other (a manual root inside a Steam install folder) overlap as a whole, whatever the paths (fail closed, review S2).

### `file_install` and the planner context
`PlanCtx { game, app, steam_app, main_exe }` (no `sys`: the planner reads through the `GameDir` and `AppDir` handles; `RegPolicy` joins with P2-9). A Steam root needs its app ID, a manual one has none. Same content is no op whatever its attributes (senior-dev B1); new files get no R/H/S; refusals as in `docs/02-topo-format.md` and `prim::file_install`.
- **Name spelling (audit A2-B1; ADR 0017 D3: the case of a name is part of "exact").** The planner writes every existing segment of a target in its stored spelling (`Dir::stored_name`, `FileNameInformation` on an attribute-only handle, as the guard), whatever the step says: a replace names its target as the folder holds it. A segment the plan creates keeps the spelling of the first step that creates it; a new file keeps the step's. `exec` compares the guard's name (`FileGuard::name`) with the plan's last segment exactly (`RelPath::same_spelling`: `==` on a `RelPath` folds) in the old-state check and again on the apply's guard before backup and intent; another spelling is `Mismatch`. So the planned spelling is the one the file had when it was applied, and a recovery that renames `X.old` or `Yi.old` back in phase B renames onto it (before: onto the step's spelling, a silent snapshot difference at 4 of 217 crash points). A target found in another spelling after the apply (someone renamed it, case only) is not the planned object: the observation of a replace counts it as "other" in `S0` and every `Si`, so `verify` and the revert report it `Foreign` and leave it as the user named it (review S1); the restore checks the spelling on its own guard again (`Mismatch`). Existing ancestors are only opened, never renamed; their spelling in the plan is for the preview.

### `exec` (P2-8)
```rust
pub struct ExecCtx<'a> { pub sys: &'a dyn System, pub fr: &'a ForbiddenRoots, pub app: &'a AppDir<'a>, pub tag: InstanceTag }
pub enum Outcome { Nothing, Applied(TxnId) }
pub fn apply(cx: &ExecCtx, h: &PlanHash) -> Result<Outcome, ApplyError>;   // Refused | RolledBack | LeftOpen
pub fn verify(cx: &ExecCtx, t: &TxnId) -> Result<Vec<(u16, Observed)>, ExecError>; // read only, no lock
pub fn revert(cx: &ExecCtx, t: &TxnId) -> Result<RevertReport, ExecError>;  // also recovery; rebind with the CLI
pub fn forget(cx: &ExecCtx, t: &TxnId) -> Result<(), ExecError>;
```
- **Apply.** Nothing is written before `begin`: the stored plan (bounded, hash) is decoded; no ops is `Outcome::Nothing` (no lock, no transaction). Then the lock and the listing (stacking only there, below); every root reopened and checked by identity (a Steam root through its store, `app_manifest` with the plan's install folder and `Installed`, else `Refusal::Steam`); `!user_writable` is `NeedsHelper`; `users()` of every existing target and main executable (`Busy`); every created object still missing, every replaced file's guard holding exactly `old` (hash, length, R/H/S, one link), every source still hashing to its content (`Mismatch { op }`). Then `begin`; per op the order of ADR 0019, a replace checking the guard against `old` and asking `users()` on the guard again before backup and intent (senior-dev conditions 5 and 8); every op observed `After`; the touched game folders flushed (after every guard is dropped); `Applied`. A failure after `begin` runs the revert loop on the same writer and closes `RolledBack`; a failure between `begin` and the first intent leaves nothing to revert (closed `RolledBack`, or `Empty` if even that failed, which blocks nothing). A rollback that fails or meets a foreign op is `LeftOpen`.
- **Stacking on the listing** (only `list` sees a duplicate `seq`): a forgotten, closed or empty transaction blocks nothing; a `view` error, a damaged one without a usable head, a head whose hash differs from the listing's on its one `load` (condition 6) or that `decode` refuses (more than 128 ops included) is `Blocked` for every apply and for the revert of every earlier transaction; an open one, an applied one with any `RevertIntent` (condition 3) and a damaged one with a usable head have their head's objects open (`Interrupted` on overlap); an applied one is stackable. Revert is LIFO: a later open or applied transaction on an overlapping object is `Later`.
- **Revert = recovery = rollback**: the lock, the listing (the own entry must not be damaged), `resume`, `decode(w.head())` (the bytes read under the lock; refused: only `forget`), records that fit the head (an intent per existing op, temp names and backups by op kind, a replace's `BackupRef` equal to its `old`: else `Blocked`), LIFO, roots, Steam, `users()` of the intended targets; then newest op first: observe, `RevertIntent` (a temp name only when a restore starts, B2), act, flush the op's game folder (always, ADR 0019 amendment P2-8: a durable `RevertDone` must have a durable change and a durable undo of a failed sequence), `RevertDone`. With a restore, a `.old` holding `h0` is deleted only after the restore succeeded (review S1), so a damaged backup never costs the last copy of the old content. A foreign op gets `RevertIntent` and `RevertDone { Foreign }` and the lower ops are still reverted (**user decision D3, R1**); the transaction stays open, `RevertReport::closed` is `None`, only `forget` closes it. `verify` is the read-only preview of what a revert will meet (rule 5).
- **Observation** (every hash on a guard; a link count other than 1, other R/H/S, a restricted entry or a reparse point is "other"):
  - `CreateDir`: missing → `Before`; empty with `Done.file_id` → `After`, removed by that ID; otherwise `Foreign`. Without `Done` (**user decision D1**): the in-process rollback uses the call's result (an ID from `create_dir`; `AlreadyExists` from `create_dir` or `create_new` is foreign, never removed: condition 4); the recovery removes an empty directory by the ID it finds then, not empty is `Foreign`. `verify` counts a created folder holding only the targets of the plan's later ops as empty.
  - `CreateFile` (`X`): target missing → `Before`, `X` deleted; target `h1` → `After`, deleted with `h1` expected, `X` left; anything else `Foreign`, `X` deleted unless the target holds `h1`.
  - `ReplaceFile` (**senior-dev B2**): `S0 = (X, h0 → h1)` and one `Si = (Yi, h1 → h0)` per `RevertIntent` with a temp name. The newest `Si` whose `Yi` or `Yi.old` exists decides, else `S0`, by the table of ADR 0017 A3 for its direction: `S0` phase A or B → `Before` (B renames `X.old` back with `h0` expected), C or D → `After` (C deletes `X.old` with `h0` expected) and restore; `Si` phase A or B → `After` (B renames `Yi.old` back with `h1` expected) and a new restore, C or D → `Before`. A `X.old` holding `h0` next to a target holding `h0` after a restore was intended (or with `Done.old_left`) is the pending cleanup of step 8, not foreign. Once some `Si` decides, every earlier sequence completed (the ordered log of the folder's volume), so `X` and older `Yj` are no temp files of Rerun any more; a `.old` of them holding the expected hash is still cleaned up. Restore: `users()` on the guard, then `replace(h1, backup_reader(k), NewFile { Y, old R/H/S, sha256: BackupRef.sha256, max_len: BackupRef.len })`: the backup is checked while it is written, never before (TOCTOU). A step 8 that fails gets one more try on a fresh guard; still `Busy` (mapped) leaves `Y.old` as a pending cleanup named in the report (open point below).
- **Forget** (**user decision D2**): an empty, open or applied transaction (by the listing) is resumed and closed `Forgotten`; a damaged one, or one whose view is an error, gets the marker `journal\<txn>.forgotten` (ADR 0019 amendment). Backups stay.

### Open points (P2-8)
- A `.old` left mapped after a revert (`RevertDone.old_left`) is not cleaned up by a later run yet (cleaning up other transactions' `.old`, phase 5); the report names it.
- `main_exe` is `None` for a manual root without a chosen executable (then only the targets are asked); fixed with the CLI step.

## Amendment (P2-9, 2026-11-06; decided by the user after a senior-dev cross-check; conditions for P2-10)
- **Op form of registry slots (M2):** a registry op names a `RegSlot` whose executable is `{ root: RootIx, exe: RelPath }`, never a free-form path; `RegPolicy::check` builds the value name from `Plan::roots[root].path` (parsed again) on plan, apply and revert (ADR 0018 amendment P2-9).
- **6a, `CreateKey` without an identity proof (user decision a):** like D1 for directories: recovery deletes an **empty** key at the path of a `CreateKey` intent without `Done`; a key with values or subkeys is `Foreign`. P2-10 conditions: `Done` is written only for `create_key == true`; `false` (the key existed) is `Mismatch` and a rollback, never a delete (with a test); `verify` counts a key holding only later targets of the same plan as empty; the preview and `status` treat a game that fills the key or value later as the normal case (`Foreign`, then `forget`). Rest risk: `docs/06-security.md`, scenario 10.
- **6b, revert when a root does not open (user decision d, senior-dev):** the planner orders every registry op after every file op; `revert` opens roots lazily per op; a file op whose root does not open (for whatever reason) halts the revert **without a record**: the transaction stays open and resumable, and a rebind (D5) stays possible. Implemented in P2-10 (`exec`).
- **Op budget:** `SetValue { old }` cannot carry an old value of up to 1 MiB inside the 8 KiB op budget: the head holds `old: Option<ValueState { kind, len, sha256 }>` (small old values inline up to a limit), the bytes go to `Intent.before` or `op-NNNN.bin`; the preview shows kind, length and hash. `RegistryWrite::set(expected: Option<&RegValue>)` serves both (P2-10).
- **`create_key` errors (review S5):** after a failure past the create (its flags), the key may exist; `exec` treats an `Err` as "observe", never as foreign and never as "not created".
- **`RegWriter::delete_empty_key`** also deletes an empty key that existed before Rerun: `exec` deletes only keys it created itself (`Done` written after `create_key == true`), with a test.
- **Deserialising a `RegSlot`** (plan or journal) goes through `AsciiSeg::parse`, `AsciiName::parse` and `GameKey::new`, never through raw fields, so a manipulated journal cannot name a key the rules refuse.

## Amendment (P2-10a, 2026-11-06; decided by the user after a senior-dev cross-check)

### Dispatch by target (audit A2 should-item 3)
`Op::target() -> Target` replaces `Op::root()`/`Op::path()`: `Target::File { root, path, dir }` now, `Key` and `Value` with the registry op kinds (P2-10b). Every generic path matches on it: objects (`Object` is an enum by target, `root_path` always set) and "one op per object" in `plan`; in `exec` apply, observe, act, the record check, the game-closed check and the flushes (`Touched`: the game folders now, the hives with P2-10b; `flush_all` before `Applied`, `flush_for` the op's domain before each `RevertDone`). `exec::file` is the file domain behind it, unchanged; the revert loop stays one for every domain. The flush knobs of J6 are named by domain and place (`Flush::GameBeforeApplied`, `Flush::GameBeforeRevertDone`).

### Revert when a root does not open (user decisions 6b-d and E3)
An apply still needs every root open (`Roots::all`). A revert and `verify` open each root on its own (`Roots::each`) and sort it:
- **Open:** reopened and checked by identity. If the current user cannot write it (or its volume lacks POSIX semantics), its file ops cannot run; D4 still asks it (read access suffices).
- **Absent:** a manual folder whose path is not found; a Steam app without manifest, installed in another folder or not installed (the halt names which: `Refusal::SteamGone` or `Steam { NotInstalled }`). Extending E3's wording: a Steam library whose path is not found, and an app whose manifest says installed while its folder is not found. Only a `NotFound` of the open itself counts: `policy::root` reports a folder that changes while it is opened (`Dir::info` failing after the open, the `common` entry swapped) as `Busy` (review S-1). D4 does not ask an absent root, its file ops cannot run.
- **Undecided:** everything else (`UpdatePending`, a manifest that cannot be read now, `IdentityMismatch` (a rebind, D5, may bind it), busy (also the swap races above), access denied, a reparse point, forbidden). The revert is refused before any change.

D4 runs on the open roots (targets and `main_exe`; a missing `main_exe` is fine in a revert), and `Busy` refuses before any change. Then, newest op first, a file op whose root cannot run file ops **halts** the revert without a record (`Halt { op, root, why }`): `RevertReport { closed: None, halted: Some(..) }`, also at the first op (`Ok`, review N4). The transaction stays open and resumable, and a rebind stays possible. The halt is decided again on every run, so the revert goes on once the folder itself is back or the update has finished. A reinstall makes a new folder with a new identity: `IdentityMismatch`, undecided, refused until a rebind (D5). `verify` returns `Verified { ops, halted }`: newest op first; missing are the ops below the halt and the cleanly reverted ops of a root that cannot run file ops, while an op whose revert left it `Foreign` there is shown `Foreign` as recorded (security N-5). From P2-10b on, `check` refuses at encode and decode (the journal head is untrusted) any registry op before a file op, so a halt always comes after every registry op is reverted. The control K-R9 (every root opened eagerly, as before) fails H4.

### `verify` of a created directory (review S3)
`verify` observes newest op first, as a revert does, and hands each observation (`Seen`, with its actions) to the earlier ops. A created directory counts as gone what the later ops remove or never made: a target observed `After` or `Before`, and every temp name a later op deletes (`DeleteTmp`, review S-a). A later target observed `Foreign` stays, so the directories above it are `Foreign` too, as the revert will find them. Before, `verify` called them `After` (T2 changed accordingly), and called a folder holding only a later op's temp name `Foreign` while the revert closed it.

### The main executable and write access (user decision E2, review M1, S1; audit A2 should-item 8)
- A `main_exe` that is given must be a plain file of its root (not missing, not a folder, link or other reparse point, not restricted), checked by the planner (`PlanError::Step`) and again by the apply (`Refusal::MainExe`, before anything is written), since D4 would otherwise ask nothing about it. A revert tolerates a missing one. A file plan may still have none (its targets are asked; open point P2-8).
- Registry ops (P2-10b) need at least one root and a `main_exe` for every root: `check` refuses other plans on encode and decode, and the planner refuses a registry step without one. The hook is `Target::needs_main_exe` (false for files), so both rules apply as soon as the registry targets exist.
- Write access only for a root that file ops target (S1), in the planner and in the apply; D4 needs read access only, so a root without file ops may be read-only to the user.

### Checklist for P2-10b (from the P2-10a reviews)
- `check` refuses a registry op before a file op, on encode and decode (the head is untrusted; the planner's order alone is not the guarantee). **Done (P2-10b, `plan::check`, test P7).**
- S2: `writable()` (elevated) in the revert too, after `game_closed` and before `revert_loop`, for plans with registry ops. **Done (P2-10b, `exec::writable`, test R-T8).**
- N2: a `CompatLayers` slot is refused in `check` until P2-11. **Done (P2-10b, `plan::allowed`, test P7).**
- P-tests: a registry plan with `roots: []` and one without `main_exe` refused, also on decode. **Done (P2-10b, test P7).**
- `records_fit` compares `Before::Inline`/`Bin` exactly with the planned old value of a `SetValue`. **Done (P2-10b, `exec::reg::records_fit`, test R-T5).**
- **Open (from the P2-10b reviews, before A6):** S1, a tightened registry rule makes the head of an applied transaction undecodable (`Blocked`, unrevertable); recommended: decode heads for revert and stacking with a rule set frozen per format version, or without `check_new` (ADR 0018, open point P2-10b).

## Amendment (P2-10b, 2026-11-06; plan `P2-10` with the user decisions E1 to E3 and the senior-dev conditions)

### Registry op kinds in format 1
```rust
pub enum Op { /* file op kinds */
    CreateKey { slot: RegSlot, segs: u8 },   // the slot's key cut to `segs` segments below HKCU
    SetValue  { slot: RegSlot, old: Option<ValueState>, new: NewValue } }
pub enum NewValue { Dword(u32), Qword(u64), Sz(String) }   // {"dword":1} | {"qword":"<decimal>"} | {"sz":"…"}
pub struct ValueState { pub kind: u32, pub len: u32, pub sha256: [u8; 32], pub data: Option<Vec<u8>> }
pub const OLD_INLINE: usize = 1 << 10;      // `data` (hex) exactly when len <= OLD_INLINE: preview only
pub enum Target<'a> { File { .. }, Key { slot: &'a RegSlot, segs: u8 }, Value { slot: &'a RegSlot } }
pub(crate) enum Object { File { .. }, Key { key: RegKey, created: bool }, Value { key: RegKey, name: String } }
```
- A slot is written as `{"game_value":{"vendor":…,"product":…,"rest":[…],"name":…}}` (`compat_layers`/`gpu_preference` with `root` and `exe`) and read back through `AsciiSeg::parse`, `AsciiName::parse`, `GameKey::new` and `RelPath::parse` (ADR 0018 amendment P2-10b). `CreateKey` names its key by `segs` (`AllowedKey::cut`: below the anchor, at most the slot's key), so no key outside the slot can be expressed. `qword` is a decimal string (no JSON number above 2^53), without sign or leading zero.
- The old value of a `SetValue` is its type, length and SHA-256; its bytes ride along only up to 1 KiB, for the preview. The revert's source is always the journal (`Intent.before`, inline up to 16 KiB, else `op-NNNN.bin`). The worst case (the longest slot with a quote character, escaped to 2 bytes, in every segment and the name; 1 KiB of old data; a `REG_SZ` of 1,024 quote characters) is 5,345 bytes (review nit 6), inside the 8 KiB op budget (test P8).
- **`check` (encode and decode alike; the head is untrusted):** every slot passes `RegPolicy::check` with the plan's root paths (a `CompatLayers` slot is refused until P2-11, review N2; `GpuPreference` stays reserved), every new value `RegPolicy::check_new` (`PlanError::Registry`); every registry op comes after every file op (so a revert that halts at a file op has reverted every registry op, 6b-d); one op per key and per value (folded); `segs` within the slot; a `CreateKey` before every key and value below it; an old value with length at most 1 MiB, inline bytes exactly up to 1 KiB with the length and hash they claim, not equal to the new value, and absent in a key the plan creates; a plan with registry ops has at least one root and a `main_exe` for each (E2, review M1).
- **Objects:** a created key holds every key and value below it; a value is its key plus the folded name; a file and a registry object never overlap. `Object::of` fails closed: a slot the policy refuses is `Blocked`, never a missing object.
- **Preview:** the key (`HKCU\…`), the value name (`(default)` for `""`), the old value (numbers and strings decoded from the inline bytes, strings through `escape::text`; anything else by type, length and SHA-256; `missing`), a type change marked, the new value; once per plan with registry ops the note that a game filling the key or changing the value later (also with another type, review S4) is left as it is and closed with `forget`, and that a revert does not restore the last-write times of keys. This is the one place where old registry data reaches output (review N6; ADR 0016 output rules apply).

### `registry_set` (`prim::registry_set`)
- Step object (Topo step and step file alike, `deny_unknown_fields`; `docs/02-topo-format.md`, `schema/topo.schema.json`): `{"registry_set":{"key":"HKCU\\Software\\<Vendor>\\<Product>[\\…]","values":[{"name":…,"dword"|"qword"|"sz":…}]}}`. `key` begins exactly with `HKCU\Software\` (`HKLM\` and `HKEY_LOCAL_MACHINE` in any case are `NeedsHelper`); segments through `AsciiSeg::parse`, the key through `GameKey::new` (deny list, folded); 1 to 32 values with unique folded names (`AsciiName::parse`) and exactly one of `dword`, `qword` (decimal string, no leading zero), `sz` (`null` refused, review N5); every new value through `check_new`.
- `PlanCtx { game, app, steam_app, main_exe, reg }`: `reg` is a `RegReader` (`RegPolicy::reader`, the non-changing methods of the write side, so a link or volatile key on the way is refused, never followed). Per value: equal to the new value → omitted; otherwise `SetValue` with the old value's `ValueState` (another type, raw, more than 16 KiB included; over 1 MiB is `TooLarge`, refused). Missing keys (`missing_keys`, below the anchor) → one `CreateKey` each, top-down, once over all steps.
- The builder puts every registry op after every file op, whatever the order of the steps. Refused besides: the same value in two steps, a plan with registry ops and no `main_exe` (E2), more than 128 ops. No delete op.

### `exec` for registry ops (`exec::reg`)
- **Dispatch:** `Target::Key`/`Target::Value` go to `exec::reg` (apply, observe, act, `records_fit`); `Touched` holds the hives an apply wrote into, the `RegWriter` and the system. Registry ops never halt and need no root; D4 asks the main executable of every root (E2).
- **Apply**, before anything is written: every root open (`Roots::all`); for a plan with registry ops `RegWriter::writable()` (an elevated process: `Refusal::Elevated`, S2; with UAC off an administrator always gets it, the message says how to run as a standard user); D4; old state: a created key still missing (`Mismatch`), a value exactly its planned old state (`ValueState::is`; `Mismatch`), a link or volatile key on the way, a key deleted while opened, a value too large: `Refusal::Registry { op, source }`. Then per op: `CreateKey` intent → `create_key` → `true`: `Done` (hint `Created`); `false`: hint `Existed`, `Mismatch`, the rollback leaves the key (`Foreign`, 6a); an error: hint `Unknown`, the rollback observes. `SetValue`: read again (`Mismatch` before the intent), old bytes into the intent (`Inline` up to 16 KiB, else `backup_bytes`), `set(expected = the value read, new)`, `Done`; `Mismatch` or a policy refusal: hint `NotWritten` (nothing was written: `new` found there later is not Rerun's, `Foreign`, review N3). `verify` (every op `After`), the game folders, then `HKCU` flushed, `Applied`.
- **Revert**: after `game_closed`, `writable()` for a plan with registry ops (`Elevated` before the first record, S2). The location of every key and value is built again from the head (`RegPolicy::check` with the plan's roots). Observation (never a record alone; K1 trusts the records and fails R-T6):

| Op | Seen | Observed / act |
|---|---|---|
| `CreateKey` | missing | `Before` |
| | a link or volatile key on the way | `Foreign` |
| | empty, and `Done`, or hint `Created`/`Unknown`, or no proof in a recovery or `verify` (6a, rest risk scenario 10) | `After` / `delete_empty_key` (`NotEmpty` on the handle) |
| | empty with hint `Existed`; not empty (`verify`: except what later ops will remove, S3, after `counts()`, a key too large to list counts as not empty, S6) | `Foreign` |
| `SetValue` | exactly `new` and no hint `NotWritten` | `After` / `restore(expected new, old)`: the old bytes from `before_bytes` (hashed against the intent first) decoded with the head's type, or the value deleted if there was none |
| | the old value (missing for none) | `Before` |
| | anything else (another type, a `REG_SZ` without its NUL, a link or volatile key, too large) | `Foreign` (S4) |

- **Errors in a revert** (`restore`, `delete_empty_key`: `Busy`, `Mismatch`, `NotEmpty`; a swapped `.bin`: `BackupMismatch`) are `ExecError`s after the `RevertIntent`: the op stays open, the revert can be repeated. `HKCU` is flushed before every registry op's `RevertDone`, also when nothing changed.
- **E3 for registry ops (user decision b, narrow):** an undecided root (an update pending, another folder, busy, access denied) refuses the whole revert before any change, the registry ops included (R-H2/H3); an absent root or one the user cannot write halts at its newest file op after every registry op is reverted (R-H1). The draft's "H2/H3 halt" is superseded by E3.
- **Tests:** `exec/reg_tests.rs` (R-T1, R-T2, R-T3, R-T5 to R-T8, R-H, K1, K-R7, K-R9), `sys/win/tests/exec.rs` (R-T1, R-T6, R-T8, R-H1 on an app hive), `docs/09-testing.md`.
- **Crash and power-loss matrix (C7):** R-T3 (a failure and a crash after every file-system and registry call of apply and revert) and R-T4 (a power loss after every call × every cut of `C:`, `D:` and `HKCU`) for `RegNew`, `RegReplace`, `Mixed` and `Stacked`; J6 with 8 flush sites. The full product is 3,157 runs (about 40 s in a debug build; one test per kind, about 19 s wall clock), under the 60 s of S5, so no pairwise reduction is applied (`exec/reg_crash_tests.rs`).
- **`CreateKey` slot (review nit 8):** a `CreateKey` carries the whole slot of the first value that needs its key, including the value name and segments below the created key; only `segs` decides which key is created. The rest affects nothing but the plan hash.

## Amendment (P2-11, 2026-11-07; plan `P2-11` with the user decisions E1 to E8 and the senior-dev conditions)

### Rule sets of `decode` (user decision E4)
`plan::decode` takes a rule set: `Rules::Current` (planning, `encode`, apply) or `Rules::Recorded` (revert, `verify`, stacking: every location and form rule, no rule for new values). A rule tightened after an apply refuses only a new apply of the old plan (ADR 0018 amendment P2-11).

### `TokenList` in format 1 (user decisions E1 a, E4 with M1 and S6, E7)
```rust
pub enum Op { /* … */
    TokenList { slot: RegSlot, old: Option<ValueState>, add: Vec<TokenName>, new: String } }
// {"token_list":{"slot":{"compat_layers":{"root":0,"exe":"bin\\game.exe"}},"old":null,"add":["…"],"new":"…"}}
```
- A semantic op on a shared value (E1 a, replaces the sketch `TokenList { slot, old: Option<RegValue>, add: Vec<String> }` above): `add` are `TokenName`s (form `[A-Z0-9_]{1,40}` on the wire, ADR 0018 amendment P2-11) in byte order (M1: the plan hash does not depend on the allowlist's order or the order of the steps), `new` is carried (S6) so a revert never recomputes it with rules or prefixes that changed since.
- **`check`** (encode and decode, both rule sets): only on a `CompatLayers` slot, and a `CompatLayers` value is never the target of a `SetValue` (review N2 narrowed, not lifted: `check_new` keeps refusing it); `old` missing or a `REG_SZ` with its NUL in the strict grammar, at most 1 KiB and so inline, its bytes matching length and hash; 1 to 8 tokens, unique, in byte order, none already in `old` (folded); `new` in the grammar and not `old`; with an old value not in a key the plan creates; one op per value (folded name). `Rules::Current` adds `RegPolicy::check_tokens` (allowlist, elevation tokens, groups, length) and `new == layers::merge(old, add)`; Both rule sets also require the version-independent relation (security review S-1): with an old value `new` is exactly that value, one space and the tokens, without one `new` ends with a space and the tokens (the prefix is the current rules' business); otherwise a head whose old value and `Intent.before` were rewritten together could make the restore of `After` add a word. `Rules::Recorded` keeps the form and this relation only, so a token dropped from the allowlist or a changed prefix never blocks the revert of an applied transaction.
- **Op budget:** the executable path is a `RelPath` (at most 240 characters) and the values at most 1 KiB, so the worst case (P-L3: 240 characters outside the BMP, 4 bytes of UTF-8 each; an old value of 509 quote characters inline; one token, since a character of the old value costs 6 bytes in the op and one of a token 2) is 4,202 bytes, inside the 8 KiB budget; no `TokenList` can break it.
- **Objects (E7, M2):** a `CreateKey` of `AppCompatFlags` or `Layers` is only the key itself (`Object::Key { created: false }`): the keys hold the values of other programs and games, so two games below one created `Layers` key do not overlap. The value is its key and the folded executable path. Game keys keep "a created key holds everything below it".
- **Preview:** `add tokens HKCU\…\Layers @ <executable path>`, the tokens it adds, the old value (decoded, through `escape::text`, or `missing`) and the new one; once per plan `LAYERS_NOTE`: a revert removes only Rerun's tokens and keeps what was changed since, a value nobody changed is restored exactly, a token already there (also one an earlier Rerun transaction added) is not added again and the revert of that transaction removes it (review N3), a token the user adds that Rerun added too is removed by the revert, and the shared keys are deleted only when empty.

### `compat_layer` (`prim::compat_layer`; user decisions E3 a, E5 a; review N2, N3, S4)
- Step object (Topo step and step file alike, `deny_unknown_fields`; `docs/02-topo-format.md`, `schema/topo.schema.json`): `{"compat_layer":{"exe":"bin\\game.exe","layers":["…"]}}`. `exe` is required (no default to the main executable: the executable that needs a layer is often a launcher or a second binary), a `RelPath` to a plain `.exe` file (folded) below plain folders, not restricted, named in the plan in the stored spelling of every segment (A2-B1), so the value name is the canonical path; 1 to 8 `layers`, unique `TokenName`s on the add allowlist (empty until SB-L1/SB-L3, ADR 0018 amendment P2-11), sorted byte-wise in the op.
- The current value is read through `RegReader` (no link followed): missing → no old value; a `REG_SZ` in the strict grammar → the old value; anything else is refused ("unusual, Rerun leaves it alone"). A token already there is left out (all there: no op); in another case only it is refused (S4); a token of the same group as one already there is refused (E5 a), naming the Rerun transaction that added it if there is one (N2: the planner reads the journal listing and the recorded heads, read only, for the message), else pointing to the Compatibility tab. `RegPolicy::check_tokens` runs on the result. The missing keys below `CurrentVersion` become `CreateKey`s (top-down, once over all steps), then one `TokenList` with `new = layers::merge(old, add)`.
- **Path form (E3 a):** `GameDir::launch_path` (new, read only: the path a manual folder was opened by, or `<library as Steam names it>\steamapps\common\<installdir>`) must equal the canonical path (folded); otherwise the step is refused ("reached through a link") until SB-L2 has shown which value name Windows matches for a game started through a junction or an 8.3 name.
- Refused besides: a case-sensitive game folder or folder on the way, a link or volatile key on the way, two steps for one executable (folded), a plan without the main executable (E2 of P2-10). The builder puts the registry ops after every file op as before.

### `exec` for `TokenList` (`exec::reg`; user decisions E2 b, E6 b, E8; senior-dev conditions S2, S3, S5, N1)
- **Apply** as a `SetValue`: the old state re-observed before `begin` (`Mismatch`), read again before the intent, the old bytes inline in the intent (at most 1 KiB, never a `.bin`), then `RegWriter::add_tokens(expected = the value read, add)`: `policy` forms the new value, `exec` never writes a string to `Layers` itself (S5). A refused write (`Mismatch`, policy) is hint `NotWritten`. D4 asks the executable of every compatibility-layer op as well (it is not always the main executable).
- **Observation (replaces the `TokenList` row of the table above; first matching row wins):**

| # | Seen | Observed / act |
|---|---|---|
| 1 | a link or volatile key on the way, a value too large | `Foreign` |
| 2 | exactly `new` (a `REG_SZ`), no hint `NotWritten` | `After` / `restore(expected new, old)`: the old bytes from the journal (hashed first), or the value deleted if there was none |
| 3 | the old value (missing for none) | `Before` |
| 4 | anything else after a refused write in this run (`NotWritten`, N1) | `Foreign` |
| 5 | missing, while there was an old value (S3) | `Drifted`, nothing written |
| 6 | a `REG_SZ` in the grammar holding some of Rerun's tokens, each once and exactly (E2 b) | `Drifted` / `RegWriter::remove_tokens(expected = the value seen, add)`: those words removed, the rest in its order; deleted if only prefix words are left (S2) |
| 7 | a `REG_SZ` in the grammar holding none of them (E2 b) | `Drifted`, nothing written |
| 8 | another type, no NUL, outside the grammar or over 1 KiB, one of Rerun's tokens twice or in another case only (S4) | `Foreign` |

- **No `from`/`to` (E8):** the `RevertIntent` of a token list carries neither; the fields stay reserved for P2-12. A crash after `remove_tokens` and before `RevertDone` leaves a value without Rerun's tokens: the next run sees row 3, 5 or 7, never `Foreign`. `records_fit` keeps refusing `from`/`to` on every registry op and requires the old value inline, exactly the planned one.
- **Shared keys (E6 b, E7):** a `CreateKey` of `AppCompatFlags` or `Layers` that is empty is `After` and deleted as before; one that holds anything else, or existed when `create_key` ran, is `Drifted` and left, and the transaction closes (a game key keeps 6a: `Foreign`). `verify` counts a value of a later token list as gone only when its revert deletes it (`After` or `Before` without an old value, `Drifted` with only prefix words left, or missing), never one that stays.
- What a revert after a drift restores is "the current value minus Rerun's tokens", not the state before the first change: deliberate (D10 for a shared value), and the preview says so (`LAYERS_NOTE`). Indistinguishable and accepted: a token the user adds after the apply that Rerun added too is removed by the revert.
- **Accepted deviation from core rule 2 (review N-1, S-b):** the shared keys are one object each and hold no other object (E7), so two transactions below one created `Layers` do not overlap and may be reverted in any order. Reverted oldest first (R-L7: T1, then T2), T1 leaves the keys because T2's value is still there (E6 b), and T2 created none: `AppCompatFlags` and `Layers` stay, empty, for good. They are Windows keys that the compatibility tab creates as well; the preview says so (`LAYERS_NOTE`). Newest first, everything is as before.
- **Open points (P2-11):** after the user removes all of Rerun's tokens from a value Rerun created (no old value), a lone prefix (`~`) is left, observed `Drifted` (none of Rerun's tokens left) and left as it is (review N-c); whether the compatibility tab ever leaves such a value, and so whether a revert should delete it, goes onto the SB-L1 evaluation list. `PREFIX_NEW` and `PREFIX_WORDS` are fixed together with the token allowlist and the expectations of L1.
- **Tests:** `exec/layer_tests.rs` (R-L1 to R-L3, R-L6 to R-L8, D4, N2; controls K-L1, K-L2, K-L4), `sys/win/tests/exec.rs` (R-L1, R-L3 on an app hive), `exec/layer_crash_tests.rs` (R-L4 a failure and a crash after every call; R-L5 a power loss after every call at every cut of `C:` and `HKCU` for `LayersNew`, `LayersMerge`, `LayersDrift` and `LayersStacked`: 2,253 runs, about 18 s wall clock in a debug build, no reduction), `docs/09-testing.md`.

## Amendment (P2-12, 2026-11-07; plan `P2-12` with the user decisions 6c, E1 to E5 and the senior-dev conditions)

### `IniValue` in format 1 (user decision 6c; replaces the sketch `IniValue { …, section, key, old, new }` above)
```rust
pub enum Op { /* … */
    IniValue { root: RootIx, path: RelPath, old: FileState, new: FileHash, edits: Vec<IniEdit> } }
pub struct FileHash { pub sha256: [u8; 32], pub len: u64 }   // the new content; R/H/S = old.attrs
// {"ini_value":{"root":0,"path":"cfg\game.ini","old":{…},"new":{"sha256":"…","len":512},
//   "edits":[{"section":"Display","key":"Width","old":{"value":"1280"},"new":"1920"}]}}
```
- **One op per file** with its list of edits (6c): `IniEdit { section: IniName, key: IniName, old: Old::{Value(IniText), NoKey, NoSection}, new: IniText }` (ADR 0021; review nit: an enum instead of an option and a flag). The op is a file op (`Target::File`, the object is the file, so a `file_install` of the same file in another transaction stacks LIFO with it); `new` is carried (A2 should-item 5) so a revert never recomputes it with rules that changed since; `FileHash` is deliberately its own type, not `journal::Digest` of the same shape: the plan format does not borrow the journal's wire types (review nit).
- **`check`** (encode and decode, both rule sets): `policy::ini::path_ok` (the extension `.ini`, folded, not `desktop.ini`; review S4: no `.cfg` yet); `policy::ini::check_edits` (1 to 8 edits in canonical order, folded section then key, byte by byte, so the plan hash does not depend on the order of the step's values; unique; a section spelled one way and new or existing as a whole; every new value not empty and other than its old one); old and new content at most 1 MiB and different; one op per object as before; the old content counts toward the 4 GiB of backups. `Rules::Current` adds `IniText::check_new` for every new value (no `\ / : % ; #`, no `..`); `Rules::Recorded` keeps the form, the extension and the dialect: the extension and the dialect are location and form and hold in both rule sets, and a narrower dialect is a format change with a migration, never silent (ADR 0021).
- **The main executable (user decision E5 a):** `Op::needs_main_exe` replaces `Target::needs_main_exe` and holds for every registry op and every `IniValue`: a running game holds no INI file open, it writes it when it exits, so `users()` of the file itself proves nothing; D4 asks the main executable of every root. `docs/04-launch-methods.md` says which program that must be with a launcher.
- **Op budget:** the worst case (P-I5: a path of 240 characters outside the BMP, eight edits with 64-character names and 128-character old and new values of quotes) is under 7 KiB, inside the 8 KiB budget; no `IniValue` can break it.
- **Preview:** `edit ini <root>:<path>` with the new hash and length, the R/H/S (kept) and the old hash, length and R/H/S; per key `[section] key: old -> new` (old `missing` or `missing (new section)`), every name and value through `escape::text`. Once per plan `INI_NOTE`: a file nobody changed is restored exactly; one the game rewrote gets back only the keys that still hold Rerun's value, keys the game or the user changed and everything else stay; a key the game sets to Rerun's value is set back too; a file gone at the time of the revert stays gone (E2 a); the main executable must be the program that writes the file when it exits (E5). The encoding of the file is not part of the op and not shown.

### `ini_set` (`prim::ini_set`; user decisions E4 a, E5 a; review S4)
- Step object (Topo step and step file alike, `deny_unknown_fields`; `docs/02-topo-format.md`, `schema/topo.schema.json`): `{"ini_set":{"file":"cfg\\game.ini","values":[{"section":"Display","key":"Width","value":"1920"}]}}`; 1 to 8 values, unique by folded section and key, names `IniName`, values `IniText` (not empty) under `check_new`. The file is read once, bounded, through the game folder's read handle and in its stored spelling (A2-B1); a value it holds is left out, all held: no op. One `IniValue` per file with the edits in canonical order.
- Refused: a missing file (E4 a: start the game once or ship the file in a package), a folder, a link or reparse point on the way or as the file (a cloud placeholder included), restricted, hard-linked, the system attribute (S4), over 1 MiB, a case-sensitive folder, what `policy::ini` refuses, a new section in a file without any header (S4), two `ini_set` steps for one file, an `ini_set` and a `file_install` of one file in one plan (named, rather than "a second op on the same object"), a plan without the main executable (E5 a).

### `exec` for `IniValue` (`exec::ini`; user decisions E1 b, E2 a; senior-dev conditions M1, S2, S6)
- **Apply** as a `ReplaceFile`: the old state re-observed before `begin` and on the guard (planned spelling, hash, length, R/H/S, one link), `users()` on the guard and D4 with the main executable (E5 a); the bytes read from the guard must give exactly the planned new content through `policy::ini::edit` (`Mismatch` before the intent otherwise); backup, intent with `X`, the replace sequence with the edited bytes and the old R/H/S, `Done` with the file ID; a `Mismatch` of the replace is hint `NotWritten`. `exec` never forms INI text: every byte written comes from `edit`, `unedit` or the hashed backup. No new flush site (J6 stays 8).
- **Records:** `Intent { tmp: X, before: Bin(old) }`; a `RevertIntent` carries `from`/`to` only for a rewrite, with a temp name, `from != to`, both at most 1 MiB (`records_fit`, else `Blocked`); every other op kind keeps refusing them.
- **Binding of head and backup** (P2-11 S-1 carried over): before a revert and `verify`, every `IniValue` with an intent edits its backup (read whole, hashed against the intent, `BackupMismatch` otherwise) with the head's edits to exactly the head's new content, else `Blocked` and nothing written. The path is not bound (`docs/06-security.md`, row 14).
- **Observation, stage 1** (the generic table of ADR 0017 amendment P2-12 over `S0` and every `Si`; a rewrite's states compare content only). Besides the rows of A3: (M1) a target other than old and new next to `X.old` holding the old content is the cleanup of a completed apply the game rewrote since only with `Done` recorded **and** `X` gone (`X.old` deleted with the old hash expected, then stage 2); with `X` there (phase B after a power loss that kept `Done`, the game made a new file) or without `Done` it is `Foreign`: `X.old` may be the user's only copy. (S2) Only Rerun's own temp name and no `.old` next to another target: the temp name is deleted (A3) and stage 2 decides (never `Foreign` for that alone). Any other `.old` next to another target, a link, folder or reparse point at the target, another spelling: `Foreign`; a `.old` holding the file as it was before a step of Rerun is kept and named in the report (`Detail::Ini::previous`, S6: "your previous INI file").
- **Observation, stage 2** (replaces the `IniValue` row of the table above, and with it its "our key changed: `Foreign`", user decision E1 b; first matching row wins):

| # | Seen (after stage 1) | Observed / act |
|---|---|---|
| 2 | the `to` of a rewrite (its phase C or D) | `Drifted`, cleanup only |
| 3 | exactly `new` (content, length, the old R/H/S), no `NotWritten` | `After` / restore the backup (old R/H/S, expected `new`) |
| 4 | exactly `old` | `Before` |
| 5 | anything else after a refused write in this run (`NotWritten`) | `Foreign` |
| 6 | missing, no trace (E2 a) | `Drifted`, nothing written; the backup goes with the close |
| 7 | `unedit` refuses it (UTF-16, NUL, a lone CR, over 1 MiB, ambiguous at a target) | `Foreign` |
| 8 | some of Rerun's keys hold exactly Rerun's value (`New`) | `Drifted` / rewrite: `Semantic { from: seen, to: unedit(seen) }` in the `RevertIntent` with a temp name, then the replace sequence (expected `from`, the current R/H/S); a key someone changed or removed (`Changed`) stays and is named |
| 9 | none of them `New` | `Drifted`, nothing written |

  A rewrite found at its start (phase A, or B after the rename back) goes through rows 3 to 9 again with the content it started from (a fresh temp name; `to` is deterministic). Only row 3 restores the state before the first change; row 8 gives "the current file minus Rerun's keys" (D10): a key the game sets to Rerun's value is set back too (indistinguishable), and the preview says so (`INI_NOTE`). `verify` runs the same table read-only and reports the state of each key (`Verified::details`, `Detail::Ini`; review nit: a detail per op, not a field per op kind); the revert report carries the same (`OpReport::detail`).
- **Rewrite act:** on a guard of the target in the planned spelling (no placeholder), nobody using it (D4 on the guard), the bytes read must hash to `from` and `unedit` of them to `to`, else `Mismatch` and the op stays open (the `RevertIntent` is repeatable); a left `.old` gets one more delete with `from` expected, else it is a pending cleanup the report names. Every `.old` of earlier sequences is deleted only after the rewrite or restore succeeded.
- **Why `from`/`to` are recorded (rewritten after senior-dev S1):** a convergent variant (recompute `unedit` from whatever is found) would be possible. They are recorded so that every action on a `.old` expects a known hash (A2/S1), so that the `.old` of an earlier rewrite is cleaned up with its known hash once a later sequence decides, and so that the recovery never parses a `.old` and never needs the parser to agree with an earlier run. The control K-I1 (a rewrite recorded without them) shows what the recovery loses: a crash in phase B or C of the rewrite then reads that sequence as a restore (`h1` to `h0`), finds its `.old` with an unknown hash and leaves the file `Foreign` or missing.
- **Open points (P2-12):** UTF-16 and INI files below `Documents\My Games` with `UserData` (phase 4); a game folder under `Program Files` whose game reads its INI from the `VirtualStore` (the change has no effect; a warning with phase 3, ADR 0020 "Moved"); a revert after a crash in the middle of a rewrite, then a game start, then the revert: the traces next to a foreign file are `Foreign` (rare, `forget`; the `.old` is named); after a `Drifted` revert the backup is deleted with the close, so no copy of the old file stays (retention open, ADR 0019).
- **Tests:** `policy/ini/tests.rs` (dialect, I1, I2, golden vectors, random bytes), `plan/ini_tests.rs` (P-I1 to P-I6), `prim/ini_tests.rs` (T9-I), `exec/ini_tests.rs` (R-I1 to R-I3, R-I5 on constructed states, R-I6 to R-I8, S2/S6, D4; controls K-I2 to K-I5), `sys/win/tests/exec.rs` (R-I1, R-I3, R-I6 on NTFS), `exec/ini_crash_tests.rs` (R-I4 a failure and a crash after every call; R-I5 a power loss after every call at every cut of `C:` and `D:` for `IniEdit`, `IniDrift` and `IniStacked`: 1,509 runs, and the M1 matrix with the game running after every cut of the apply; about 9 s wall clock in a debug build, no reduction; K-I1, K-I5), `docs/09-testing.md`.
