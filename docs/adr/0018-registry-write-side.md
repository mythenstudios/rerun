# ADR 0018 · Registry write side and `policy::registry`

**Status:** accepted (decided by the user) · 2026-11-05 · amends ADR 0004 (registry allowlist now in phase 2) and ADR 0009 (write side), closes audit A1 B2 · amended 2026-11-06, P2-9 (see the amendment at the end; it takes precedence where the two differ)

## Context
Phase 2 ships `registry_set` and `compat_layer` (`docs/08-roadmap.md`), but ADR 0004, `docs/01-architecture.md` and `docs/06-security.md` placed the allowlist `policy::registry` in phase 3 (A1 B2, core rule 4). `RegKey` compares and hashes case-sensitively, while the registry folds names, so two spellings of one key would be two journal objects. Enumerated names are converted lossily (ADR 0009, open for phase 2). ADR 0009 follows registry links on reads and defers the write side.

Spike P2-1 (throwaway; observed on Windows 11 build 26300 in private app hives, standard user):
- `RegCreateKeyExW(parent, "L\Sub")` with a link key `L` tries to follow it (error 5 in an app hive, where links cannot be followed; nothing created). `REG_OPTION_OPEN_LINK` affects only the **last** segment: it opens `L` itself, `L\Sub2` still follows.
- A link is recognised on its own handle: `NtQueryKey(KeyFlagsInformation)` (12 bytes) has `REG_FLAG_LINK` (`0x2`; `0x1` = volatile) and needs `KEY_QUERY_VALUE`. `KeyNameInformation` (the kernel name) needs only `READ_CONTROL`. `REG_OPTION_CREATE_LINK` on an existing key is error 183.
- `RegFlushKey` works without admin, also with only `KEY_QUERY_VALUE`: about 3 µs on an unchanged hive, 0.9 ms after a change.
- Link following in the real `HKCU` cannot be tested in an app hive; it is a Windows Sandbox case.

## Decision

### Where the boundary is
`sys` executes, `policy::registry` decides (ADR 0004). The read trait `Registry` stays as it is (plus raw names, below); writes move to a trait only `policy::registry` can reach:
```rust
pub trait RegistryWrite: Registry {
    fn create_key(&self, k: &RegKey) -> SysResult<bool>;          // exactly one segment below an existing parent; true = new
    fn set(&self, k: &RegKey, name: &str, v: &RegValue) -> SysResult<()>;
    fn delete_value(&self, k: &RegKey, name: &str) -> SysResult<()>;
    fn delete_empty_key(&self, k: &RegKey) -> SysResult<()>;      // no values, no subkeys, else NotEmpty
    fn flush(&self, k: &RegKey) -> SysResult<()>;                 // RegFlushKey on the key's hive
}
// System::registry_write() -> &dyn RegistryWrite is a clippy.toml ban outside policy::registry,
// like Fs::open_dir outside policy::root.
```
Contract of every `RegistryWrite` method (fake and `sys::win`): a link key anywhere on the path is `ReparsePoint` and is never followed or changed; `Hive::LocalMachine` is `Unsupported` (the GUI never writes `HKLM`, core rule 6); a typed value without a canonical encoding is `Unsupported` (ADR 0009).

### `policy::registry`
```rust
pub struct RegPolicy;                                   // fixed rules, no state in phase 2
pub enum RegSlot {
    CompatLayers { exe: ExePath },                      // value name = canonical exe path
    GameValue { key: GameKey, name: AsciiName },        // HKCU\Software\<Vendor>\<Product>[\…]
    GpuPreference { exe: ExePath },                     // reserved (D8), refused until phase 4
}
pub struct AllowedKey { key: RegKey, anchor: usize }    // private; segments past `anchor` may be created
pub struct AllowedValue { key: AllowedKey, name: String, slot: RegSlot }
impl RegPolicy {
    pub fn check(&self, slot: &RegSlot) -> Result<AllowedValue, RegPolicyError>;
    pub fn check_new(&self, v: &AllowedValue, new: &RegValue) -> Result<(), RegPolicyError>;
}
pub struct RegWriter<'s> { /* &'s dyn RegistryWrite; built only by policy::registry */ }
impl RegWriter<'_> {
    pub fn get(&self, v: &AllowedValue) -> SysResult<Option<RegValue>>;
    pub fn missing_keys(&self, k: &AllowedKey) -> SysResult<Vec<RegKey>>; // each one a CreateKey op
    pub fn create_key(&self, k: &RegKey, of: &AllowedKey) -> SysResult<bool>;
    pub fn set(&self, v: &AllowedValue, new: &RegValue) -> SysResult<()>;  // then reads back
    pub fn delete_value(&self, v: &AllowedValue) -> SysResult<()>;
    pub fn delete_empty_key(&self, k: &RegKey, of: &AllowedKey) -> SysResult<()>;
    pub fn flush(&self, k: &AllowedKey) -> SysResult<()>;
}
```
- **`HKCU` only, native view only.** `HKCU\Software` is shared between the views (ADR 0009). An op on `HKLM` is `NeedsHelper` at plan time and refused in phase 2 (ADR 0020); the phase 3 helper never writes `HKCU` (ADR 0009).
- **`CompatLayers`:** key `HKCU\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers` (anchor `CurrentVersion`: `AppCompatFlags` and `Layers` may be created), value name the canonical path of an executable inside a `GameDir` as Windows writes it (`D:\Games\X\game.exe`, from the root's canonical path and a `RelPath`, without `\\?\`), type `REG_SZ`. Rerun adds or removes only tokens from an allowlist (compatibility modes, `DISABLEDXMAXIMIZEDWINDOWEDMODE`, `HIGHDPIAWARE`, `DPIUNAWARE`, colour and resolution modes, …; the exact list and the `~`/`$` prefixes are fixed with `compat_layer` in P2-11 after a sandbox check). `RUNASADMIN`, `RUNASHIGHEST` and every other elevation token are never written; tokens already present, also those, are kept as they are (`TokenList`, ADR 0020). Whether Windows matches the value through a junctioned library by the canonical or the launch path is checked in the sandbox (P2-11).
- **`GpuPreference`:** `HKCU\Software\Microsoft\DirectX\UserGpuPreferences` is reserved as a slot so the plan format needs no change; `check` refuses it with `Unsupported` until the primitive lands in phase 4 together with `gpu.hybrid` (user decision D8).
- **`GameValue`:** `HKCU\Software\<Vendor>\<Product>` plus at most 4 further segments, named in the step (later the reviewed Topo); anchor `Software`, so missing keys from `<Vendor>` down may be created. Key segments and value names are **printable ASCII only** (`0x20` to `0x7E`, no `\`, no leading or trailing space, segments 1 to 64 characters, value names 0 to 128, the empty name is the default value; condition S3), so folding, lookalikes and lossy names cannot occur on the write side. `<Vendor>` must not fold to a deny list: `Microsoft`, `Classes`, `Policies`, `Wow6432Node`, `Clients`, `RegisteredApplications`, `AppDataLow`, `Valve` (Steam's own keys, a detection source, ADR 0012), `Rerun`, `Mythen Studios`.
- **Types and limits of new values:** `CompatLayers` a `REG_SZ` of allowlisted tokens, at most 512 UTF-16 units; `GameValue` `REG_DWORD`, `REG_QWORD`, `REG_SZ` (printable, no control characters, at most 1,024 UTF-16 units) and `REG_BINARY` (at most 4,096 bytes). Never `REG_EXPAND_SZ`, `REG_MULTI_SZ`, `REG_LINK` or a `Raw` type. Old values are recorded exactly whatever they are (`Raw` included, up to `MAX_VALUE_BYTES`; ADR 0019 condition S1).
- **Folded keys.** `RegKey` keeps its spelling for display; `Eq`, `Hash` and `Ord` use hive, view and the folded path (the crate's 1:1 fold, as for file names). Value names are compared folded as well.
- **Raw names** (amended 2026-11-06, P2-5, user decision E1; replaces the `RegName` sketch). `values` and `subkeys` keep returning `String` names, converted with U+FFFD where the UTF-16 name has an unpaired surrogate. **Every key or value name that holds U+FFFD is an anomaly**, the same rule as `policy::path::classify` for file names: it is never addressed, opened, descended into or written, and `sys::snapshot` records it as `RegAnomaly` (`why: Lossy`; a value with the data `values` returned). A real U+FFFD in a name is therefore an anomaly as well; no game key is known to use one. Two names of one key that fold alike are `RegAnomaly` with `why: Collides`; a name that no key path or value name may hold (NUL; for a subkey also `\` or empty) is `RegAnomaly` with `why: Invalid` and never opened, so one hostile name does not abort a snapshot (P2-5 review). The name of a key of the scope itself comes from the caller, not from the registry, so a case change of that key is not seen (like the name of a root on the file side); its subkeys and values are compared with their case. Anomalies with the same name under one key are a multiset in the snapshot, none overwrites another (A1 should-item 5c, ADR 0009 open point). No `RegName` type: the lossy flag would only restate what U+FFFD already tells, and the write side never needs it (its names are printable ASCII, condition S3).
- **Snapshot walk limits (P2-5).** `sys::snapshot` walks at most 64 levels of subkeys below a scope key and 100,000 keys per snapshot; beyond either `TooLarge` with the limit, like every bound of `sys` (the registry read limits of ADR 0009 are `TooLarge` since P2-5 as well). The depth stops a cycle, the budget a fan-out.

### Implementation (`sys::win::reg`)
- **Segment-wise walk.** Every write opens from the `HKCU` handle (`RegOpenCurrentUser`, kernel name checked, ADR 0009) one segment at a time relative to the parent handle, each with `REG_OPTION_OPEN_LINK` and at least `KEY_QUERY_VALUE`, and refuses a handle whose `KeyFlags & 0x2` (`REG_FLAG_LINK`) is set (`ReparsePoint`). Since `REG_OPTION_OPEN_LINK` only protects the last segment, each segment is its own last segment. A missing segment is created with `RegCreateKeyExW` on the parent handle with that one segment and `REG_OPTION_OPEN_LINK`; its disposition gives `create_key`'s `bool`.
- **Kernel name as second check (condition S5).** Before a value is set or a key deleted, `KeyNameInformation` of the handle must equal `\REGISTRY\USER\<SID>\` plus the expected path, folded; otherwise `Busy` and nothing is written. The same check guards the app-hive fixture today (`docs/09-testing.md`).
- **Values** are written with `NtSetValueKey` on the walked handle (not `RegSetValueExW`, which reads past the caller's buffer for string types, ADR 0009) and read back; deleted with `NtDeleteValueKey`.
- **`delete_empty_key`** queries values and subkeys on the walked handle and deletes the key **by that handle** (`NtDeleteKey`, `DELETE` access). It is not atomic: a value written by another process between the check and the delete is deleted with the key. Accepted limit: only keys Rerun created are ever deleted, and only the same user can race it.
- **No compare-and-swap.** The registry has none. Apply reads the old value, journals it (ADR 0019), writes, reads back; a write by another process inside that window is lost. Accepted limit, same user, microseconds. A revert first checks that the value is still Rerun's (ADR 0020) and never overwrites a foreign one (D10).
- **Durability (B-1):** `RegFlushKey` on every changed key before the journal's closing record (ADR 0019).
- **Revert re-checks the location:** the walk, the link and kernel-name checks and `RegPolicy::check` run again on revert; the journal is untrusted input (ADR 0019).
- `clippy.toml`: the registry write calls stay bans outside `sys::win::reg`, and `RegFlushKey` joins them (the list text of ADR 0009 now names it; the entry itself comes with P2-9). `NtSetValueKey`, `NtDeleteValueKey`, `NtDeleteKey` and `NtQueryKey` stay bans outside `sys::win::reg`.

## Alternatives
- **Full-path `RegCreateKeyExW`/`RegOpenKeyExW`:** follow links in every segment but the last (observed).
- **Only the last segment with `REG_OPTION_OPEN_LINK`, as ADR 0009 sketched:** the same gap for the intermediate segments.
- **A hard-coded allowlist of game keys:** every game would need a Rerun release; the Topo names its keys and review approves them (`docs/06-security.md`). The deny list is the backstop, not the boundary.
- **An allowlist of vendors instead of a deny list:** the same release problem.
- **Transacted registry (KTM):** deprecated and banned (ADR 0009); it would not cover the files of the same plan anyway.
- **`RegSaveKey` backups:** needs `SeBackupPrivilege` and saves whole subtrees; one value is what changes.

## Consequences
- `sys::registry`: `RegistryWrite` (the write methods leave `Registry`), folded `RegKey` comparisons, `System::registry_write` (no `RegName`, see "Raw names"). P2-9 implements it; its review checks explicitly against A1 B2. `registry_write_contract` runs against the fake and, in private app hives under `target/`, against `sys::win` (other spelling, other type, `delete_empty_key` with a value, a link segment); `HKCU` link following runs in Windows Sandbox (`docs/09-testing.md`). The fake registry gets `fail_at` (condition S10).
- ADR 0004: `policy::registry` is phase 2. ADR 0009: the write side is this ADR. `docs/06-security.md`: the allowed areas for phase 2.
- Core rules: rule 4 (registry only on allowed keys) is enforced before `sys`; rule 6 (no `HKLM` from the GUI); rule 2 (old value recorded exactly, flushed, never overwritten when foreign).

## Open points
- **Security review:** the `GameValue` deny list is a blocklist. Any other `HKCU\Software\<Vendor>` key is writable by a Topo, including one another program reads as a plugin or start path; the defence is the type and content limits, review of every Topo key and the preview. The review decides whether that suffices or whether a key must also exist before Rerun may write it.
- The `compat_layer` token list, the `~`/`$` prefixes and the junction question: P2-11, in Windows Sandbox.
- `HKCU` link behaviour on the real hive (a link key planted by same-user malware): Windows Sandbox.
- **Link keys in the snapshot** (P2-5, senior-dev condition 4): reads follow links (ADR 0009), so `sys::snapshot` sees through a link key and has no entry for "this key is a link". A link replaced by a real key with the same content compares as identical. P2-9 gives the snapshot its own entry for a link key (from `KeyFlags`, the same query as the write side) and pins it; until then the depth and key limits only stop a cycle. Manual case in `docs/09-testing.md` (Windows Sandbox).

## Amendment (P2-9, 2026-11-06; decided by the user after a senior-dev cross-check)

- **Folded keys (A2 should-item 2):** `RegKey` implements `Eq`, `Hash` and `Ord` over hive, view and the folded path; `Display` keeps the spelling. Keys are built with `RegKey::new`/`join`; a struct literal skips their trimming and `check_key` refuses what it leaves.
- **Link keys in the snapshot (open point closed):** `Registry::link` (ADR 0009 amendment P2-9) on every key of the scope and every subkey; a link is `SnapEntry::RegLink { name, target }` and is not entered. A link replaced by a key with the same content is one difference (snapshot contract, fake and `sys::win`). The fake models link keys and follows them on reads (at most 16 levels, then `Other`); in an app hive Windows refuses to follow one, so link following stays a Windows Sandbox case.
- **`RegistryWrite` (replaces the sketch above):** `key_state` and `read` (both without following links), `create_key` (one segment, `true` = created by this call), `set(k, name, expected: Option<&RegValue>, new)` and `delete_value(k, name, expected)` (the expected old value is compared on the walked handle, else `Mismatch` and nothing is written; `set` reads back, `Busy` if the value is not `new`), `delete_empty_key`, `flush(hive)` (`RegFlushKey` flushes the whole hive anyway). Reached through `System::registry_write`, a `clippy.toml` ban outside `policy::registry`.
- **One sequence (`sys::seq::reg`, like ADR 0017 A1):** `sys::fake` and `sys::win` implement only `PrimHive` (`open_root`, `root_name`, `elevated`) and `PrimKey` (`open`/`create` of one segment with `REG_OPTION_OPEN_LINK`, `flags`, `kernel_name`, `query`, `counts`, `set_value`, `delete_value`, `delete` by handle, `flush`). Every segment is walked by itself and its flags checked; the kernel name is compared before every change, for `create_key` on the **parent** before the create (an existing link at the last segment is then caught by its flags). A failure after `set_value` leaves the old or the new value; the caller observes (like step 8 of a replace).
- **Conditions S1, S2, S4:** `RegView::Wow32` is `Unsupported` on the write side (the views of `HKCU` are one key; two views would be two objects). A changing method in an elevated process is `Unsupported` (fail closed; the GUI never runs elevated, the phase 3 helper never writes `HKCU`). A volatile key on the path (`KeyFlags` bit `0x1`) is `Unsupported`: its changes are never durable.
- **`sys::win` (P2-9):** `WinRegistry` implements the primitives in `sys::win::registry` over `sys::win::reg` (`RegOpenKeyExW`/`RegCreateKeyExW` of one segment with `REG_OPTION_OPEN_LINK`, `NtQueryKey` for name and flags, `NtSetValueKey`, `NtDeleteValueKey`, `NtDeleteKey`, `RegFlushKey`, now a `clippy.toml` ban). A walk starts from a new handle to the `RegOpenCurrentUser(KEY_READ)` root; every segment is opened relative to the previous handle with `KEY_QUERY_VALUE | READ_CONTROL` plus the one right it needs. `ERROR_KEY_DELETED`/`STATUS_KEY_DELETED` map to `Busy` (S3; reads too). Elevation comes from `TokenElevation` once in `WinRegistry::new`; a token that cannot be asked counts as elevated.
- **Observed (Windows 11 build 26300, app hive, standard user, 2026-11-06):** the write contract passes with no skip in about 6 ms; relative opens with write rights below a `KEY_READ` root work; overwriting a value in another spelling keeps the stored spelling (no B1 analogue needed); `RegRenameKey` moves the key under an open handle and the kernel-name check catches it (K-R2 bites on Windows too); volatile keys and link keys can be created in an app hive (links not followed). Still a Windows Sandbox case: the real `HKCU` (link following, `Software\Classes`, `RegFlushKey` on the real `RegOpenCurrentUser(KEY_READ)` handle; `docs/09-testing.md`).
- **`policy::registry` (P2-9, replaces the sketch above where they differ):** `RegSlot::CompatLayers { root: RootIx, exe: RelPath }` and `GpuPreference { root, exe }` (senior-dev M2: no free-form exe path in a slot); `RegPolicy::check(&slot, roots: &[RootPath])` builds the value name from the plan root's path, parsed again, plus the `RelPath` (at most 16,383 UTF-16 units), so the journal's copy of a slot is re-checked the same way. `check_new` refuses new `CompatLayers` values (`Unsupported`) until `compat_layer` (P2-11). `RegWriter` (built only by `RegPolicy::writer`, the one caller of `System::registry_write`): `state`, `get`, `missing_keys` (below the anchor, top-down), `create_key`/`delete_empty_key` only for the key or its keys below the anchor (`InvalidPath` otherwise), `set(v, expected, new)` with `check_new` applied again, `restore(v, expected, old)` that writes the old value back exactly without `check_new` (a raw or `REG_BINARY` old value included; `None` deletes), `flush`.
- **User decision G1 (closes the open point "Security review"):** the deny list plus a content rule: value names and string data (`REG_SZ`, `REG_EXPAND_SZ`, `REG_MULTI_SZ`, of which only `REG_SZ` is written) hold none of `\ / : %`, so no path and no environment variable; `Khronos` joins the deny list (`Vulkan\ImplicitLayers` would make every Vulkan program load a DLL; a native-messaging manifest path makes a browser start a program). Deliberately no limit beyond that: a command line without these characters (PuTTY's `ProxyTelnetCommand`) or a DWORD switch of another program is left to the review of every Topo key and to the preview (`docs/06-security.md`, row 6). The rules guard the Topos of phase 4 and are never loosened for one; paths later only through a slot of their own bound to a `GameDir`. Whether `Valve` narrows to `Valve\Steam` stays open.
- **`REG_BINARY` is not written** for a `GameValue` until a reviewed Topo needs it (user decision; resolves M1). Old values of any type are still recorded and restored exactly.
- **S6:** `RUNASADMIN`, `RUNASHIGHEST` and every other elevation token are never added by an apply; a revert restores the previous value exactly (also when it held one).

### Review follow-ups (P2-9)
- **G1 is ASCII (review M1):** new `REG_SZ` data of a `GameValue` is printable ASCII (`0x20` to `0x7E`), like value names. Unicode would let best-fit characters through (U+FF1A, U+FF3C, U+FF05, U+FF0F, U+2215 become `: \ % /` for a reader that uses the ANSI API) and bidi or format characters (U+202E, U+2028) pass a control-character check.
- **The rename window is accepted, not closed (review S3; corrects "location TOCTOU closed" of the P2-9 plan):** the kernel name is compared on the walked handle, and the write runs on that handle. Another program of the same user that renames the key in the microseconds between the comparison and `set_value`/`delete_value`/`create`/`NtDeleteKey` makes the write follow the handle into the moved key; the registry has no compare-and-swap. After `set_value` and `delete_value` the sequence compares the kernel name again and reports `Busy`, so the caller observes (for a create or a delete the outcome is observed by the caller as well).
- **Bans:** besides `System::registry_write`, the changing methods `RegistryWrite::{create_key, set, delete_value, delete_empty_key, flush}` are `clippy.toml` bans outside `policy::registry` (`RegWriter`), with a resolve check in `sys/win/bans.rs`; `WinRegistry` is no longer exported from the crate (only `WinSystem`).
- **UAC off (`EnableLUA=0`):** an administrator's token is always elevated, so the write side refuses every change for that account. The CLI and GUI step must say so in a clear message (with how to run Rerun as a standard user).

## Amendment (P2-10b, 2026-11-06)
- **Slots on the wire:** `RegSlot` serialises through a plain mirror (`{"game_value":{"vendor","product","rest","name"}}`, `{"compat_layers":{"root","exe"}}`, `{"gpu_preference":{…}}`, `deny_unknown_fields`) and deserialises only through `AsciiSeg::parse`, `AsciiName::parse`, `GameKey::new` and `RelPath::parse`, so a plan or journal head cannot name a key or value the rules refuse.
- **`AllowedKey::cut(segs)`:** the allowed key cut to its first `segs` segments, only below the anchor and at most the key itself; a `CreateKey` op names its key this way (ADR 0020 amendment P2-10b).
- **`RegReader`** (`RegPolicy::reader`): `state`, `get`, `missing_keys` of the write side, which follow no link; the planner's view of the registry. `RegWriter` holds one.
