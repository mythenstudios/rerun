# ADR 0024 · Signed index and catalogue

**Status:** accepted · 2026-11-09, amended the same day by the security review of P4-3 (retired and revoked keys, the test-key build guard, the key file DACL and OneDrive refusal, the release download form, the import floor check, the exact pin); amended 2026-11-10 by P4-14 (`draft`, the workbench's one online command); amended 2026-11-11 by P4-13 (the test-key `rerun.exe` and its own index state, `index sign-test`); amendment "Forward compatibility" accepted 2026-11-12 (user decision of 2026-11-12), slice FC-a built the same day, slice FC-b the same day · extends ADR 0005, ADR 0019 · phase 4, step P4-3

## Context
From phase 4 Topos and packages decide what Rerun plans, and later what the elevated helper may do (ADR 0007: "no exe hash, no elevated apply"). They come from a repository Rerun does not control at runtime, so they must reach the client as signed data that Rerun can tell from a forgery, a damaged copy and an old copy replayed. ADR 0005 named the typed serde structs the runtime authority from phase 4; until now only the JSON Schemas existed. The plan of phase 4 (user decisions E2, E5; conditions R1, R6) fixed the frame: one signed bundle, an Ed25519 key generated offline with a rotation slot, a test key only behind a feature, one pinned version per package, and the bytes of the index a transaction was applied with kept for its revert.

## Decision

### One bundle, signed over its raw bytes
- `index.json` holds every released Topo and every released package: `{ "format": 1, "seq": <n>, "issued": "YYYY-MM-DDTHH:MM:SSZ", "topos": [...], "packages": [...] }`, both lists sorted by `id` without duplicates (`schema/index.schema.json`; each entry in the language of `topo.schema.json` and `package.schema.json`).
- `index.json.sig` is the detached Ed25519 signature over the raw bytes of `index.json`: exactly 64 bytes, no encoding, no header. The key signs index bundles only.
- The client (`rerun_core::catalog`) works in a fixed order and skips nothing (*steps 3 and 4 per entry since the amendment "Forward compatibility": an entry that fails them is set aside, the envelope and the heads still refuse the whole index*): (1) at most `MAX_INDEX_BYTES` (8 MiB) and a signature of exactly 64 bytes, (2) the signature verified under one of the trusted keys, (3) only then the bytes parsed as UTF-8 JSON (`format` first, then `deny_unknown_fields` at every level, `RelPath` for every path, hashes as typed values), (4) the form rules of `catalog::check` with `Rules::Release` on every entry (no `status: draft`, no `TODO` anywhere), sorted IDs, every package a Topo or package names present. A `Catalog` can only be built from a `Verified`, and a `Verified` only by `verify`. A parse error names its class, line and column, never the text.

### Keys and rotation
- `catalog::key::RELEASE_KEYS` has two slots of raw 32-byte public keys: the current key and its successor. Rotation ships a binary that already trusts the next key, then the index is signed with it; one release later the old key moves from its slot to `RETIRED_KEYS`. `KeyId` = the first 8 bytes of SHA-256 over the public key, shown by `rerun index show` and the workbench.
- **Three lists, three uses (security review of P4-3, follow-up 1):** `trusted_keys()` (the release slots, with `test-key` the test key) is the only set that lets an index in (`import`, `current`). `RETIRED_KEYS` holds former release keys: they never admit a new index, but `store::by_hash` (the revert path, `revert_keys()` = trusted plus retired) still reads an index they signed, so a rotation never makes a transaction unrevertable (R1); `import` checks its floor the same way, so an index accepted before the rotation stays a valid floor. `REVOKED_KEYS` holds compromised keys: `verify` refuses a signature by one of them everywhere, `by_hash` included (`IndexError::Revoked`), whatever set the caller passes. A compromised key is never retired, only revoked; a revert whose index was signed by a revoked key fails, and the transaction is closed with `forget`.
- Both slots are empty until the user generates the release key offline (`rerun-workbench key generate <out-dir>`). With no key every index is refused with a clear message (`IndexError::NoKeys`).
- The private key is a 32-byte seed in a file of 64 hex digits, written only with `create_new` into an existing folder that is neither this repository, nor any Git working tree (a `.git` entry on the way up), nor a OneDrive folder (`OneDrive`, `OneDriveConsumer`, `OneDriveCommercial`, case-insensitive by whole segments: synced is not offline); `index sign` reads a key only from such a folder too. The empty key file gets a protected DACL with one ACE (full access for the current user, nothing inherited from the folder) before the key is written; the DACL is read back, and a file whose DACL could not be set is removed. It is never in the repository.
- The test key is published (its seed is in `catalog::key::test_key`). It is trusted only with the cargo feature `test-key`, which only dev-dependencies enable. Guards: `compile_error!` when `test-key` is on and debug assertions are off (the shipped `release` profile; the test profiles `dev`, `ci` and `dev-release` keep debug assertions, so the invariant is: never in the `release` profile, not "never in an optimised build"), a unit test (no release slot and no retired key holds a test key; without the feature the trusted set is exactly the release set), CI (`cargo tree -e normal,build` of `rerun-cli` enables neither `fake` nor `test-key`), and the release binary test (the release `rerun.exe` holds neither the test seed nor the test public key; the test build must hold them, so the check bites).

- **Amendment P4-13 (test-key `rerun.exe`, user decisions E-A and U1 a):** for the topo round trip on the developer machine (`docs/09-testing.md`, "Topo round trip on the developer machine") `rerun-cli` has its own feature `test-key` (= `rerun-core/test-key`, never default). Such a `rerun.exe` keeps its index state in `<AppDir>\index-test` (`policy::root::app::index_folder`, decided by `rerun-core`'s feature, so `import`, `current` and the revert path `store::by_hash` agree; the helper gets the folder by identity and needs no change), so a test-key index never raises the floor of the real `<AppDir>\index\current.json` and a release `rerun.exe` never sees an index the test key signed. Every other folder (`journal`, `plans`, `profiles`, `launch`, `cache`) is the real one, because `rerun-launch` reads the profile from the real `profiles`. Guards as for the helper: `compile_error!` in `rerun-cli` (besides the one in `rerun-core`) without debug assertions; `main` writes `rerun: TEST-KEY BUILD - …` as the first stderr line of every command (never `run`, so the in-process tests see the same output); the release binary test also looks for `index-test` (ASCII and UTF-16) and the banner. Drafts reach no index, a test-key index included: a test index is the normal `index build`, signed with `rerun-workbench index sign-test` (feature `test-key` of the workbench, which never ships): the same release rules as `index sign`, a draft or a `TODO` refused, the signature verified back under the test key and written only as a new file (`create_new`, never over an existing `.sig` or through a link). An open transaction of a test-key `rerun.exe` names an index only `index-test` holds; a release `rerun.exe` cannot revert it (only `forget`), so the round trip ends every case without an open transaction.

### Sequence and storage (`<AppDir>\index`)
- `<sha256>.json` and `<sha256>.sig`: every accepted index and its signature, named by the SHA-256 of the bytes, written with `create_new` (a damaged copy is replaced through `FileGuard::replace`). Rerun deletes none of them in phase 4.
- `current.json` = `{"format":1,"seq":<n>,"sha256":"<hex>"}`: the last accepted index. `import` refuses a lower `seq` (rollback) and the same `seq` with other bytes; the same bytes again are "already current". Before comparing, `import` checks the pointer and the index it names like `by_hash` (bounded, hash against name, signature, form, the pointer's `seq`); anything wrong there is `Damaged` and names `current.json` to remove (never a misleading rollback). Removing it is the user's decision and drops the floor. `lock` (share 0) is held by `import`. Order: index and signature, flush, then the pointer, flush; a crash leaves the old pointer.
- Everything there is user-writable (`docs/06-security.md` #14): `current` reads the pointer, the bytes bounded, checks their hash against the name, verifies the signature and parses again; a pointer that disagrees with its index is `Damaged`. The `seq` floor protects against an old index replayed from outside (a mirror, a download, a user tricked into importing it), not against a process of the user that rewrites `current.json`: such a process can change anything below `<AppDir>`, and the signature still binds every entry to the key.
- **Revert reads the index it was applied with (P4 condition R1):** `catalog::store::by_hash(app, sha256)` reads `<sha256>.json` by its hash with the signature check under `revert_keys()` (trusted and retired, never revoked) and without any `seq` floor. A plan built from a Topo (P4-4, `PlanSource`) names the hash; the helper (ADR 0023) gets those bytes and checks only the signature. A revert therefore never depends on the current index, its `seq` or a hash that changed since. *Corrected by the amendment "Forward compatibility" (§8): as built, no revert reads an index at all. The journal head holds the plan bytes, and the helper's remove request names no index (ADR 0023 §5). `store::by_hash` has no production caller (tests only). An index is read by its hash only on the add path: by the CLI's recheck before `begin` (`exec::helper::recheck`) and by the helper's `validate_add`, both through `store::load` under the trusted keys. Retired keys count only for `by_hash` and for the floor check of `import`.*

### Typed catalogue (ADR 0005, runtime authority)
- `catalog::model`: `Topo`, `Package`, `Index` and their parts, `deny_unknown_fields` everywhere, an optional field refuses an explicit `null`, a list with `minItems: 1` is an `Option<Vec<_>>`, maps are `BTreeMap`. The planners' step types are reused (`RegistrySetSpec`, `CompatLayerSpec`, `IniSetSpec`, `CpuRuleSpec`); their rules in force now (token allowlist, the INI value rule, the game folder) stay the planners'.
- `catalog::check`: the schema rules the types cannot carry (patterns of IDs, URLs per source type, licence, version, DLL names, lengths, unique items, the download forms), plus loader-only rules: unique issue IDs per Topo and variant IDs per issue, the registry vendor deny list and unique value names, the `qword` range, download provenance, `TODO` ⇒ `draft`. A download URL that names a release download is exactly `https://<forge>/<owner>/<repo>/releases/download/<tag>/<file>` (tag and file of `[A-Za-z0-9._+-]`, neither `.` nor `..`; so no `%`, `?`, `#` or further `/`; schema `$defs/downloadUrl`, loader `check::release_download`), and it counts only for its own `source.repo`, never through the host of `source.page`. Errors name a field by path; a map key that failed its rule is named by position (`options[2]`), never by its text. `Rules::Source` is a file of `topos/` or `packages/`; `Rules::Release` an entry of the index.
- Parity: the typed loader and the schemas run against the same fixtures (`tests/fixtures/schema/`, `crates/rerun-core/tests/catalog_parity.rs` next to `tests/schema.rs`): every valid fixture loads, every invalid one is refused.
- Packages (user decision E2 a): one package is one pinned version; another version is another package (`dxvk-1-10`). `files[].sha256` is required (`TODO` only in a draft): every file a package installs is anchored by its own hash.
- **sha256 for elevated anchors (P4 condition R6):** `match.exes[].sha256` stays optional in the format (old games are documented by SHA-1), but an executable that anchors an elevated op (the target of `firewall_rule`, P4-5; `laa_patch`) must carry a `sha256`; `sha1` alone never anchors anything elevated. The loader rule enters with the first such step: built with `firewall_rule` in P4-5a (`catalog::check`: the step names an entry of `match.exes`, in exactly its spelling (no case or Unicode folding), and that entry has a `sha256`; from P4-2d the rule's program is derived from that entry, never from the step's spelling; the step was draft only until reviewed, `FIREWALL_RULE_REVIEWED`, reviewed since P4-5b); `laa_patch` follows with its own step (P4-10). **Built (P4-10):** the same rule for `laa_patch` (`catalog::check::laa_patch`: an entry of `match.exes` in exactly its spelling with a `sha256`; draft only until reviewed, `LAA_PATCH_REVIEWED`, reviewed since P4-10).

### The workbench builds and signs, offline
- `rerun-workbench index build --seq <n> --issued <time> [--root <repo>] <out>`: every file of `topos/` and `packages/` loaded like the runtime loader (strict YAML without anchors or aliases, typed structs, `Rules::Source`, file name = ID); drafts left out; a released Topo that needs a package left out fails the build; the bytes are a function of the files, `seq` and `issued` only (sorted, typed, pretty JSON with a final newline) and must read back as the same index. `seq` and `issued` are arguments, never the clock: the same input gives the same bytes.
- `rerun-workbench index sign <bundle> <private-key>` signs only a bundle that passes the client's index rules, verifies its own signature and writes `<bundle>.sig`.
- `rerun-workbench` is a curator tool, never shipped: it uses `std::fs`, `serde-saphyr`, the signing half of `ed25519-compact` and `getrandom` (the key seed).
- **Amendment P4-14 (`draft`):** `rerun-workbench draft` is the workbench's only online command and stays apart from the key: it never reads a key file, and `index` and `key` stay offline. It asks `www.pcgamingwiki.com` through `sys::Http` (ADR 0025) at most twice (the app ID lookup's `Location`, never followed; one `action=parse` of the page's wikitext and sections), within fixed bounds (`docs/06-security.md` #28), and writes a Topo draft of facts and links only (`docs/02-topo-format.md`, "Drafts from PCGamingWiki"), loaded like a source file before it is printed or written. The facts come from a fixed list of template parameters of the page (anonymous Cargo queries are refused by the wiki, user decision D4 a), read by a bounded scanner with value whitelists: a template the wiki renames or restructures makes the draft fail, never a draft with wrong facts. `main` restricts the DLL search path first for every command (ADR 0008).
- **Amendment P5-4 (one variant ID, one fix; user decision U2 of plan P5):** Topo validation is this ADR's (`catalog::check::topo`, used by `index build` with `Rules::Source` and by every index check with `Rules::Release`), so the rule lives here. The same variant ID under several issues of one Topo is one fix: every copy has identical `kind` and `steps` (structural equality, order included). These two are what the fix *does*: the engine assesses and plans a variant by its steps alone (refusal, anti-cheat warnings, ops), and `kind` decides how the fix is shown; `status`, `sources` and `tradeoffs` are the evidence and wording of one issue and may differ. A differing copy is a `RuleError` at `issues[i].variants[j].steps` (or `.kind`) naming the variant and the issue of the first copy; `index build` prefixes the file (= the Topo ID), the index check `topo <id>`. No converse rule (two IDs with equal steps are allowed), no format or schema change (the schema cannot express it; a loader-only rule like unique IDs), no engine or helper dedupe: the engine already plans a package picked twice once, and a duplicate executable is refused by `elevate::derive`. With the rule, `flow::fixes` takes the refusal and warnings of the first copy (ADR 0027).

### Distribution until phase 6
- No network in this step. `rerun index import <index.json> <index.json.sig>` reads both files through `policy::root::read_input` (bounded, plain files), verifies and checks before Rerun's folder is created, then stores; `rerun index show` reads the current index back like an import. Elevated, `import` is refused (user decision E3); `show` only reads and also runs elevated, like `status`. A download (P4-6) and a bundled index (user decision E5) use the same `catalog::store::import`.

### Dependency
`ed25519-compact` 2.6 (MIT, Frank Denis, maintained, pure Rust, no dependencies without default features; about 5,000 lines of source plus precomputed tables): `rerun-core` uses it for verification only (`default-features = false`: no `random`, `pem`, `x25519`). `ed25519-dalek` would bring `curve25519-dalek` and a second `sha2` major version. Pinned exactly (`=2.6.1`): every binary that verifies (`rerun`, later the helper) must decide edge cases alike, so an update is a deliberate change with its own review. Its verification rejects a non-canonical `S` and is cofactored (it accepts when `[8](R' - R)` is the identity). Signature malleability does not matter here: an index is identified by the SHA-256 of its bytes, never by its signature, and a second valid signature over the same bytes changes nothing that is stored or compared (`import` replaces a differing stored `.sig` of the same bytes).

## Consequences
- A forged, damaged, truncated or foreign-signed index is refused before a byte of it is parsed; an old one cannot replace a newer one.
- Until the release key exists, every real index is refused: development and tests use the test key behind `test-key`.
- The Topo engine (P4-4) plans from a `Catalog` only, names the index hash in the plan, and the helper (P4-2, ADR 0023) checks the signature of exactly those bytes again.
- Stored indexes accumulate below `<AppDir>\index`; cleaning up old ones that no open transaction names is left for later (at most a few MiB each).
- The format of a package changed (`files[].sha256` required); `format` stays 1 because no index was ever published (ADR 0005).

## Amendment (2026-11-12): forward compatibility

**Status: accepted** (user decision of 2026-11-12; architect's design; the senior-dev cross-check of 2026-11-12 released it with conditions 1 to 10, folded into the text below). **FC-a built** (2026-11-12): `catalog::entries` (heads, classification, `check_bundle`), `check::topo_floor`/`package_floor` (`check/floor.rs`), `INDEX_FORMAT`/`ENTRY_FORMAT`, the workbench strict, the schemas, the frozen bundle `tests/fixtures/index/format-1.json`; FX1 to FX10 in `docs/09-testing.md`. Built as written, with three details: a head that does not parse is the new `IndexError::Head { list, pos, class, line, column }` (position within the entry); the envelope, `FormatOnly` and every head are read from a JSON object only (a serde struct alone also takes an array); the API rule of P5-5c (a package whose files depend on the graphics API on a Topo of two APIs) is a cross-entry rule of §3 4.2 like `supports_exe_sha1` (`Refused`). **FC-b built** (2026-11-12): `flow::Lookup::NoTopo` and `Read` carry `aside` (typed, no text); the CLI lines of §10 (`index import`/`show`, `plan <app-id>`, `--pick` and `package fetch` refused with exit 3, the reason escaped as a whole); `flow::need` answers a set-aside package as `Unobtainable` with the same words; the app shows the two states on the library row (group "No Topo, nothing offered") and as the game page's hero, the reasons behind "Show details", a note next to a usable Topo, and the count of set-aside entries in the status bar. The test labels of this amendment are FX1 to FX11 (FC1 to FC5 name the firewall crash matrices of `exec/fw_crash_tests.rs`). Resolves the A6 point of ADR 0022 amendment P4-13 ("after the first release an additive Topo field would break older clients on the whole index").

### Context
Steps 3 and 4 of "One bundle, signed over its raw bytes" refuse the whole index for anything this build does not read: an unknown field (`deny_unknown_fields`), an unknown step kind or enum value, an entry `format` other than 1, a broken rule in one entry. Before the first release this costs nothing, because no index has been published yet. After it, every additive change of the Topo or package language (a step kind, a field, a value, a gate such as `ANTI_CHEAT_RELEASE_REVIEWED` opened) would make every older Rerun refuse every new index and stay on the last one it accepted. User decision of 2026-11-12: an older client skips a Topo or package it does not understand (unknown fields, unknown step kinds, unknown enum values, a newer format number), shows it as "needs a newer Rerun", and keeps the rest of the index; the signature check stays over the whole index.

### Decision

#### 1. Two numbers, one boundary
- `INDEX_FORMAT` (the envelope's top-level `format`) and `ENTRY_FORMAT` (the highest entry `format` this build reads) become two constants, both 1. No wire change: the envelope and every entry carry `format` already, and every existing bundle keeps its bytes and its meaning.
- **The envelope stays strict.** Steps 1 and 2 (size, the Ed25519 signature over the raw bytes of the whole index, revoked keys) are unchanged and still come before any parsing. Then `format` is read **alone** (`FormatOnly`, as `from_verified` does today), before the strict envelope. A value other than `INDEX_FORMAT` refuses the whole index as `IndexError::Format`, worded "this index needs a newer version of Rerun". This way an envelope of format 2 that also adds a key says "needs newer" and not "unknown field". Only then is the envelope parsed with `deny_unknown_fields` (`format`, `seq`, `issued`, `topos`, `packages`). The envelope is never extended additively. Any change to it gets a new `INDEX_FORMAT` and its own ADR with a migration plan (for example, both bundles published side by side until older clients are gone).
- **The tolerance boundary is the entry**, meaning one element of `topos` or `packages`. Each entry is kept as its raw JSON text (`serde_json::value::RawValue`, the feature `raw_value` of the existing dependency, no new crate) and read in two stages (§2, §3).

#### 2. The frozen head
- Stage 1 reads the entry's **head** leniently, with one head struct per list:
  - `TopoHead`: `format` (u32), `id` (`Id`) and `match.steam_appid` (optional, 1 to 4294967295; `match` itself is optional, and its other keys are ignored).
  - `PackageHead`: `format` and `id` only. It has no `match`. A `match` key in a package entry is ignored by the head like any other key; stage 2 refuses it in a known format (`Unreadable`), and a set-aside package never carries a `steam_appid`.
- The head structs (with `TopoHead`'s inner `match`) are the only structs of the catalogue without `deny_unknown_fields`. They ignore every other key and authorise nothing: they name and sort the entry and link a set-aside Topo to its game for display.
- The heads belong to the envelope contract. These keys keep their name, type, range and meaning in every future entry format. A new format may add keys next to them but may never move, retype, widen or redefine them.
- If a head does not parse, the **whole index** is refused. This covers an entry that is not an object, a missing or malformed `format` or `id`, a duplicate key, and a `steam_appid` that is not a number from 1 to 4294967295. **`steam_appid: 0` refuses the index:** the key is frozen with its range, it was never valid in any format, and the workbench cannot produce it. Treating it as absent would let a broken head pass silently. The same holds for IDs that are not sorted and unique per list over all heads, known and set aside alike, so a set-aside entry can never shadow a known one.

#### 3. Known or set aside
Each entry goes through these steps in order:
1. `format > ENTRY_FORMAT`: **set aside as `Newer { format }`**. Nothing beyond the head is parsed.
2. Otherwise stage 2 parses the entry strictly into `Topo` or `Package`, exactly as before this amendment: **`deny_unknown_fields` at every level stays**, along with `RelPath`, typed hashes and closed enums. A known format is read only by the strict types. On failure the entry is **set aside as `Unreadable { class, line, column }`** (the position within the entry, never its text).
3. The rules of `catalog::check` with `Rules::Release` and the format rule of §5 (`floor <= format`). On failure the entry is **set aside as `Refused(RuleError)`**.
4. Cross-entry rules, in this order, over the entries that passed steps 1 to 3:
   1. **Packages.** A package whose `requires` names a set-aside package is set aside as `Package { id, newer }`. A package whose `requires` names a package the index does not hold at all is `Refused`. This is repeated until a pass sets nothing aside. Each pass removes at least one package or ends the loop, so there are at most as many passes as packages, and a `requires` cycle that contains a set-aside member ends with the whole cycle set aside.
   2. **Topos and their packages.** A Topo with a step that names a set-aside package is set aside as `Package { id, newer }`. A Topo that names a package the index does not hold at all, or breaks the `supports_exe_sha1` rule, is `Refused`.
   3. **Overlap, last.** The P4-4 follow-up 4 rule (two Topos that are not retired claim the same app and executable hash) runs over the Topos that are **still known after 4.1 and 4.2**. Both Topos of an overlapping pair are `Refused`, so the engine never has to choose. A Topo that was set aside earlier, for whatever reason, takes no part. This matches `Newer` and `Unreadable` entries, whose executables are never read, so a known Topo that overlaps a set-aside one stays known (the workbench forbids such pairs in the whole bundle, §6). Overlap only removes Topos, so nothing earlier has to run again.

A **known** entry has passed every rule the strict loader applied before this amendment, including the cross-entry rules. `Catalog::topo`, `package`, `topos` and `packages` return known entries only, so the engine, `flow`, the downloader and the helper see nothing else. A set-aside entry is kept as `Aside { kind, id, format, steam_appid, why }` for display only. It is never matched, planned, downloaded, extracted or derived.

**Why a broken entry of a known format is set aside rather than refusing the index (the security trade-off).** The signature is checked over all bytes before any of this, so only the holder of the key decides what an index contains. Tolerance therefore concerns our own content, never an attacker's. The strict parse is a correctness boundary per entry, and it stays exactly as strict for every entry that is used. Refusing the whole index for one bad entry would keep every user on an old index because of one of our own mistakes. The most likely such mistake is a new feature shipped without its format (§5), which would bring back exactly the failure this amendment removes. It would also mean that a rule tightened in a newer build (a gate set back to `false`, a grown deny list) withdraws the whole catalogue instead of the entries it hits. When entries are set aside instead, such a rule works as a kill switch per step kind. The loudness moves to where the mistake is made: the workbench refuses to build or sign an index with any set-aside entry (§6), and `index import` and `index show` name every set-aside entry with its reason (§10).

`AsideWhy::needs_newer()` is true for `Newer` and for `Package { newer: true }` (the package is itself `Newer`, or set aside for that reason). It is false for `Package { newer: false }`, for example a Topo whose package is `Unreadable` or `Refused`. Every reason other than "needs newer" is shown as "this version of Rerun cannot use it".

#### 4. What an entry format means and what needs a new one
- An entry's `format` is the lowest `ENTRY_FORMAT` a client needs to use the entry. Within one entry format nothing is ever loosened and nothing changes meaning.
- From the first release on (see below), a new entry format is needed for:
  - a new field anywhere in the entry, including the planners' step specs the model reuses;
  - a new step kind or a new enum value;
  - a wider limit or pattern (more `match.exes`, a longer text, a new URL form);
  - a gate (`*_REVIEWED`) opened;
  - any change of meaning of an existing key, which should be a new key instead.
- Formats are additive. One set of typed structs reads every format up to `ENTRY_FORMAT`, with the newer parts optional. ADR 0005's "a v2 gets its own schema files, the loader branches on `format`" therefore remains only for a non-additive format, which needs its own ADR.
- A **tightened** rule needs no new format. A newer build sets aside the entries it hits (`Refused`).
- Topos and packages share one counter (`ENTRY_FORMAT`). `docs/02-topo-format.md` gets a format history.
- **Format 1 is frozen with the first release** (A6), not with this amendment. Until then no index has been published, so every addition stays format 1 and needs no bump. This covers the content of ADR 0031 and ADR 0032, the `anti_cheat` release if `ANTI_CHEAT_RELEASE_REVIEWED` opens before A6, and any other step, field or value added before then.
- From the first release on, every addition in the list above is format 2 or later. The format history records which features format 1 holds as released.
- The floor functions (§5) exist from the start, with every feature at 1, so their structure is in place before the first bump.

#### 5. The floor: one function, checked at both ends
- `catalog::check::topo_floor(&Topo) -> Floor` and `package_floor(&Package) -> Floor`, where `Floor { format, at }` is the lowest format the entry's content needs and the field path of the first feature that needs it.
- **What the compiler forces.** The floor functions destructure every struct of the model without `..` and match every enum without `_`. That makes a new field, step kind or enum value a compile error until its format is decided. This holds for a nested type (the reused step specs `RegistrySetSpec`, `CompatLayerSpec`, `IniSetSpec`, `CpuRuleSpec`, `GpuPreferenceSpec`, `UserDataSpec`, `PrioritySpec`, `policy::firewall::Direction`, `AntiCheat`, and the model's own parts) **only if it has its own floor function that the entry's floor function reaches**. Under `-D warnings`, `dead_code` catches a floor function nothing calls. A type that is never walked is not covered, and the floor tests (FX3) walk every type.
- **What the compiler cannot force: review only.** The following go into the `new-primitive` checklist and need their line in the floor function by hand:
  - serde attributes that change what parses without changing a type: `default` added to a field that was required, `alias`, `rename`, `untagged` or `flatten` changes;
  - the `try_from = "String"` types, whose rules sit in a function and not in the type: `Id`, `RelPath`, `ArchIdText`, `Hex`, `TodoMark`;
  - `String` fields with a pattern, an allowlist or a limit in `catalog::check`, for example a longer title, a new source URL form, more `match.exes`, the registry `KEY_PREFIX` and vendor deny list, the INI name and value rules;
  - planner-only rules, which the loader does not run at all. The compatibility-layer token allowlist (`policy::registry::layers`) is checked only by the planner: at load, `check::compat_layer` only checks the form (1 to 8 unique tokens of `A-Z`, `0-9`, `_`, 1 to 40 characters). A token newly allowed would therefore load in an older client and be refused there at plan time instead of being set aside. Allowing it needs a floor line (the token set of each format). The same applies to every rule the model doc calls "the planners'";
  - gates (`*_REVIEWED`) and relaxed limits in general.
- `Rules::Source` and `Rules::Release` both require `1 <= format <= ENTRY_FORMAT` and `floor.format <= format`. Otherwise they report a `RuleError` at `at`, for example "uses gpu_preference.foo of entry format 2; set format: 2".
- A `format` above the floor is allowed: a deliberate bump hides an entry from older clients, for example after a change of meaning that should have been a new key.
- The curator writes `format` in the source file, and the bundle carries it unchanged. The build checks the number but never stamps it, so the bytes stay a function of the files and the pull request shows which Rerun a Topo needs.
- On the client the floor check is part of step 3 of §3. An entry whose content needs more than its `format` says is `Refused`, so a newer build treats a mislabelled entry the way an older build would (as unusable).

#### 6. The workbench
- `index build` refuses a source file below its floor or above the workbench's own `ENTRY_FORMAT` (the workbench can only build what it reads). It then reads its own bytes back through the client's classification, `catalog::check_bundle(bytes) -> Result<Vec<Aside>, IndexError>`, and refuses any set-aside entry. `check_bundle` checks the envelope, the heads and the rules of every entry without a signature and returns only the set-aside list, never a catalogue anything could be planned from. It replaces the workbench's use of `check_index`.
- `index sign` and `index sign-test` run the same check before signing.
- As a result, only a workbench at least as new as the newest entry format in an index can build or sign it. An older workbench fails on the newer files.
- `draft` writes `format: 1` (a draft holds facts and links only).

#### 7. Store, sequence, rollback: unchanged
- `seq`, the floor, the rollback rule and the same-`seq` rule belong to the envelope and do not look at entries. An index with set-aside entries is accepted and raises the floor like any other index: it is the newest one, and a later build reads the same bytes with fewer entries set aside.
- `current`, the floor check of `import`, `store::load` on the add path (§9) and `by_hash` (no production caller, see the correction in "Sequence and storage") classify with the same function. After a downgrade (a newer build imported an index with format-2 entries, an older build reads it), the stored index therefore loads with those entries set aside instead of being `Damaged`.

#### 8. Transactions and revert
- A revert never reads an index. The journal head holds the plan bytes (ADR 0019, ADR 0020), the helper's remove request names no index (ADR 0023 §5), and `store::by_hash` has no production caller. R1 therefore holds more strongly than "Sequence and storage" first said: a revert depends on no index at all. A transaction whose Topo is set aside in a later index (upgraded to a newer format, or refused by a newer build) is listed by `status` and reverted exactly as before. `PlanSource` stays display and binding only.
- A stored plan applied after its Topo was set aside stops at the CLI's recheck before `begin` (`exec::helper::recheck`, `Refusal::Mismatch`), with nothing changed.
- Not covered here: plan heads with op kinds a build does not know, which only a downgrade with open transactions can produce. They remain ADR 0020's concern (format 1 unstable until A6; the open point "a rule set frozen per format version").

#### 9. The elevated helper
- The helper reads the index by hash and classifies it with the same function. It acts only on a known Topo:
  - A request that names a set-aside Topo is `Reason::Topo`, with nothing written. This includes a Topo set aside only because one of its packages is set aside. The same holds for a known Topo with another `rev`.
  - The signature is still verified over all bytes, under the trusted keys and the revocation list and against `HELPER_MIN_SEQ`, before anything is parsed (`Reason::Index` otherwise).
- The helper is not weakened. Its derivation is unchanged, and a known Topo has passed every rule the strict loader applied, the cross-entry rules included, so nothing it acts on is less checked than before. A set-aside sibling gives no lever, because it is never derived from.
- The CLI's recheck uses the same function, so CLI and helper (one build, `BUILD_ID`) agree on what is set aside.
- Considered and not taken: a helper that refuses any index with a set-aside entry of a known format. A gate closed in one build would then block every elevated fix of every Topo.

#### 10. Display
- `rerun index import` and `rerun index show` print, after the index facts, up to two lines: "N entries need a newer version of Rerun: topo x, package y" and "N entries cannot be used by this version of Rerun: topo z (reason)". Exit codes are unchanged (an import that stored the index is 0).
- `flow::with_topo` and `flow::game`: `Lookup::NoTopo` and `Lookup::Read` carry the set-aside Topos of the app (`Catalog::aside_for(app_id)`, from the head's `steam_appid`). `rerun plan <app-id>` says "Topo x for this game needs a newer version of Rerun" (or "Topo x for this game cannot be used by this version of Rerun (reason)"); with no usable Topo left (only set-aside ones, or retired and set-aside ones) it first says "app N: index S has no Topo for this game that this version of Rerun can use: nothing is offered" ("the index" when the game folder was read). A `--pick` for an app whose only Topos are set aside is refused (exit 3).
- `rerun package fetch` of a set-aside package is refused with the same wording (exit 3). `flow::need` gives the same answer to the app.
- The app's library row and game page show "Needs a newer version of Rerun" / "Braucht eine neuere Rerun-Version" when the app has no usable Topo but a set-aside one with `needs_newer()`, and "Not supported by this version of Rerun" / "Von dieser Rerun-Version nicht unterstützt" for the other reasons. An app with a usable Topo shows that Topo, plus a hint on the game page when another Topo of the app is set aside (it may be the one for this build).
- IDs and reasons reach output through `escape`, like every text of the index.

### Types (signatures; no implementation)
```rust
// catalog
pub const INDEX_FORMAT: u32 = 1;   // the envelope; strict
pub const ENTRY_FORMAT: u32 = 1;   // the highest entry format this build reads (model::FORMAT today)

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum EntryKind { Topo, Package }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Aside {
    pub kind: EntryKind,
    pub id: Id,
    pub format: u32,
    pub steam_appid: Option<u32>,   // Topos only, from the head
    pub why: AsideWhy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AsideWhy {
    Newer { format: u32 },                                        // above ENTRY_FORMAT
    Unreadable { class: &'static str, line: usize, column: usize }, // known format, does not parse
    Refused(RuleError),                                           // known format, breaks a rule of this build
    Package { id: Id, newer: bool },                              // names a set-aside package
}
impl AsideWhy { pub fn needs_newer(&self) -> bool; }

impl Catalog {
    pub fn from_verified(v: &Verified<'_>) -> Result<Self, IndexError>; // unchanged signature, tolerant per entry
    pub fn aside(&self) -> &[Aside];                                    // sorted by kind, then ID
    pub fn aside_for(&self, app_id: u32) -> impl Iterator<Item = &Aside> + '_;
    pub fn aside_entry(&self, kind: EntryKind, id: &str) -> Option<&Aside>;
    // topo, package, topos, packages, index: known entries only (unchanged signatures)
}

/// The client's classification without a signature, for the workbench: the set-aside list only.
pub fn check_bundle(bytes: &[u8]) -> Result<Vec<Aside>, IndexError>;

// private: `format` alone first, then the strict envelope with raw entries, then the lenient heads
#[derive(Deserialize)]
struct FormatOnly { format: u32 }
#[derive(Deserialize)] #[serde(deny_unknown_fields)]
struct Envelope<'a> { format: u32, seq: u64, issued: String,
                      #[serde(borrow)] topos: Vec<&'a RawValue>,
                      #[serde(borrow)] packages: Vec<&'a RawValue> }
#[derive(Deserialize)]               // lenient: no deny_unknown_fields (heads only)
struct TopoHead { format: u32, id: Id,
                  #[serde(rename = "match", default)] matches: Option<TopoHeadMatch> }
#[derive(Deserialize)]               // lenient
struct TopoHeadMatch { #[serde(default)] steam_appid: Option<NonZeroU32> } // 0 refuses the index
#[derive(Deserialize)]               // lenient; no `match`
struct PackageHead { format: u32, id: Id }

// catalog::check
pub struct Floor { pub format: u32, pub at: &'static str }
pub fn topo_floor(t: &Topo) -> Floor;
pub fn package_floor(p: &Package) -> Floor;

// flow::game
pub enum Lookup<R> {
    NoIndex,
    NoTopo { seq: u64, aside: Vec<Aside> },
    Read { retired: Vec<Topo>, aside: Vec<Aside>, found: Found<R> },
}
```

### Alternatives
- **Strict for known formats, only `Newer` set aside** (a broken entry of a known format refuses the index): louder, but one of our mistakes or a tightened rule would freeze every client on its last index. Rejected (§3).
- **A `min_client` (a Rerun version) per entry** instead of the existing `format`: it ties content to release numbers instead of the language, and needs a second number next to `format`. Rejected; `format` is the language version.
- **The workbench stamps the floor into the bundle**: the bytes would no longer be a function of the files, and a pull request would not show which Rerun a Topo needs. Rejected in favour of a check at both ends.
- **Tolerance inside an entry** (skip only the unknown step, variant or field): this needs lenient parsing inside structures that are used, which means giving up `deny_unknown_fields` exactly where it matters. Rejected. A finer unit only for set-aside *packages* (refuse only the variants that install one, the rest of the Topo usable) can follow later without a format change.
- **A tolerant envelope**: rejected. The envelope is minimal and changes only through a new `INDEX_FORMAT`.
- **Fallback copies** (an upgraded Topo kept in its old format for older clients): the same ID twice is refused by the heads, and a copy under another ID is excluded by the overlap rule, because both claim the same build and both would be `Refused` in a newer client, and the workbench would not build them. It would need a version dimension in ID uniqueness and overlap. Not now; see the consequences.

### Consequences
- Older clients keep taking new indexes. What they cannot use is named, never silently dropped.
- An upgraded Topo (one that starts using a format-2 feature) is shown to older clients as "needs a newer version of Rerun" until they update; they lose its older revision. A fallback copy under another ID is excluded by the overlap rule (see Alternatives). Curators can delay such a bump.
- From the first release on, every additive language change raises `ENTRY_FORMAT` and needs a row in the format history, a line in the floor function, a test, and a `format` bump in the source files that use it. The compiler enforces this for fields, step kinds and values of the types the floor functions walk. Review enforces it for everything listed in §5 under "review only".
- `docs/02-topo-format.md` contradicts this in two places, which change in the implementing commit:
  - line 79: the reserved `api` values `d3d12`, `vulkan`, `glide` as an "additive extension". This is format 1 if done before A6, a new format after it.
  - line 144: `firewall_rule` `direction: in` "may follow without a format break". `in` is a new value of `policy::firewall::Direction`, so it is a new entry format after A6.
- Behaviour change: an index with a draft, a `TODO`, a missing package or two overlapping Topos is no longer refused as a whole. The affected entries are set aside, and the old strictness moves to the workbench, which refuses to build or sign such an index. The existing tests move to the set-aside expectations.
- The schemas: `topo.schema.json` and `package.schema.json` allow `format` from 1 to `ENTRY_FORMAT` (`const: 1` today, an `enum` from format 2); `index.schema.json` describes the current version's view (every entry in the current language) and states the head keys as frozen. Schema parity stays as it is.

### Tests (the slice is accepted by them)
- **FX1** (core, fake): an index signed with the test key holds one known Topo and one Topo of `format: 2` with an unknown field and an unknown step kind. The known Topo loads and is planned. The future one is `Newer { format: 2 }` with its `steam_appid`, `topo(id)` is `None`, and `aside_for(app)` lists it.
- **FX2**: a `format: 1` Topo with an unknown step kind, one with an unknown field, and one with an unknown enum value (`api: d3d12`) are each `Unreadable` with `needs_newer() == false`, and the other entries load. The same content with `format: 2` is `Newer`.
- **FX3**: a known entry that breaks a release rule (a draft, a `TODO`, a missing package, two overlapping Topos, `supports_exe_sha1`) is `Refused` (both overlapping Topos), and the rest loads. A floor above `format` is `Refused` (with a test-only floor override, since every floor is 1 today).
- **FX4** (packages):
  - A package of `format: 2`, and a Topo that names it: `Package { newer: true }`, `needs_newer()`.
  - A package that `requires` the `format: 2` package is set aside transitively.
  - A Topo on an `Unreadable` package: `Package { newer: false }`, `needs_newer() == false`.
  - A `requires` cycle with a set-aside member terminates, with the whole cycle set aside.
  - A package entry with a `match` key: ignored by `PackageHead`, `Unreadable` in format 1, `Newer` without a `steam_appid` in format 2.
- **FX4b** (overlap order): a known Topo that overlaps a `Newer`, `Unreadable` or package-set-aside Topo stays known. Two known Topos that overlap are both `Refused`.
- **FX5** (envelope stays strict):
  - Envelope `format: 2` together with an unknown top-level key gives `IndexError::Format(2)` ("needs newer"), not a parse error.
  - Each of the following refuses the whole index: an unknown top-level key with envelope format 1; an entry that is not an object; a head without `format` or `id`, or with a malformed one; `steam_appid: 0` in a Topo head; IDs unsorted or duplicated across a known and a set-aside entry.
- **FX6** (signature over all): one byte changed inside the set-aside entry gives `Signature`. A revoked key is still refused on every path.
- **FX7** (store): an import with set-aside entries raises the floor; rollback and same-`seq` refusals are unchanged; `current` and `by_hash` give the same set-aside list; a stored current index with `format: 2` entries loads instead of `Damaged` (the downgrade case).
- **FX8** (helper, two-process fake): a request naming a set-aside Topo is `Reason::Topo` with nothing written. A request naming a Topo set aside only because its package is set aside is also `Reason::Topo`. A known Topo in an index that also holds a future entry is `Done`. The CLI's recheck of a stored plan whose Topo is now set aside is `Refusal::Mismatch` before `begin`.
- **FX9** (revert): a Topo applied, then an index imported in which it is `format: 2`. `status` lists the transaction, and the revert restores the game folder identically (snapshot).
- **FX10** (workbench and parity):
  - `index build` refuses a source below its floor and one above `ENTRY_FORMAT` (as built: the workbench test covers format 0 and above `ENTRY_FORMAT`; the floor case goes through the same `Rules::Source` check and is FX3, since every floor is 1 today).
  - `build`, `sign` and `sign-test` refuse a bundle with any set-aside entry.
  - A frozen format-1 bundle (`tests/fixtures/index/`, signed with the test key, frozen at A6) loads with nothing set aside in every later build (backward compatibility).
  - A parity category for index fixtures with `format: 2` entries: the typed loader sets them aside, and `index.schema.json` accepts their heads.
- **FX11** (display): `index import` and `index show` lines; `plan <app-id>` for an app with only a set-aside Topo, and for one with a usable and a set-aside Topo; `package fetch` of a set-aside package (exit 3); the app's view models for both reasons in `en` and `de`.

### Slices
- **FC-a**, built **before** ADR 0031 and ADR 0032 are implemented, so that their additions already go through the floor functions. It covers the core classification, the store, the helper and the CLI recheck, the workbench, the schemas, and `docs/02-topo-format.md` (meaning of `format`, the format history, lines 79 and 144, the signed index section). It also brings the correction of this ADR's "Sequence and storage" and the other documents named in the consequences. Accepted by FX1 to FX10; code review by senior-dev and security-reviewer.
- **FC-b**: the display in the CLI and the app (`flow::Lookup`, the CLI lines, the app's states and texts in `en` and `de`). Accepted by FX11.
