# ADR 0031 · Data patches of a game executable (`exe_patch`)

**Status:** Proposed · 2026-11-12 · extends ADR 0013, ADR 0020 (amendments P4-10, P4-13, P5-2a), ADR 0024 · plan `P5-options` part A · phase 5, after P5-7 and before P5-13 (format additions land before the first release)

## Context
Assassin's Creed (app 15100) crashes at the Ubisoft intro because it contacts a shut-down Ubisoft service. The verified fix is EaglePatch (an ASI plugin). PCGamingWiki names a second, manual way: overwrite the host name `gconnect.ubi.com` in `AssassinsCreed_Dx9.exe` / `AssassinsCreed_Dx10.exe` with zero bytes, so the request fails at once on the machine (`topos/assassins-creed-dc.yaml`, `tips.notes`). The user wants Rerun to offer that as a reversible fix (plan P5, user request of 2026-11-12).

Rerun can already change an executable: `laa_patch` (ADR 0020 amendment P4-10) is one `ReplaceFile` with `ContentRef::Patch` (at most 8 single-byte edits on a file bound by its SHA-256), backed up in the journal and restored bit for bit; a live patch still matches the Topo (`exec::patched_now`, `ExeCheck::patched_by`); Smart App Control, a signature and a Steam per-user executable are warned (P4-13). What it cannot do: change a run of bytes (a 16-byte host name plus up to 4 checksum bytes is 20 edits), say *what* it changes in terms a reviewer can check, or keep a byte patch away from code, imports and protection wrappers by rule rather than by curation alone.

Core rules at stake: 4 (declarative, nothing runs), 7 (no No-CD executable, no DRM removal), 2 (exact revert), 5 (preview).

## Decision

### The Topo step
```yaml
exe_patch:
  exe: "AssassinsCreed_Dx10.exe"    # a path of match.exes, in exactly its spelling
  sha256: "576A…0129"               # the build these offsets belong to: a match.exes entry of exe
  section: ".rdata"                 # the section that holds every edit
  edits:                            # 1 to 8
    - { at: "0x00A1B2C0", text: "gconnect.ubi.com", to: zero }
```
- `at`: the file offset, `^0x[0-9A-F]{1,8}$`. `text`: the bytes found there, printable ASCII (`0x20`–`0x7E`), 4 to 64 characters. `to`: what replaces them; v1 only `zero` (every byte `0x00`). A replacement text (another host) is a later, separate decision: it would send the game's traffic to a third party (see "Not decided").
- Offsets, not a search pattern: the step is bound to one exact build by its SHA-256, so an offset is deterministic and the planner never searches (no ambiguity, no parser for patterns). Another build of the same path needs its own step with its own `sha256` and offsets; a Topo lists one step per build.
- Only from a signed Topo (the step file refuses it, as `laa_patch`). Draft only until reviewed (`EXE_PATCH_REVIEWED`), like every step that changes a system before its review.

### What may be changed (the mechanical fence)
The planner reads the image (`detect::pe`, ADR 0013) and refuses unless all hold:
1. The file is the Topo's build (SHA-256 streamed on the parsed handle), a plain file with one link, in a folder the user can write (E1 = 0 of P4-10), no game with anti-cheat (`ANTI_CHEAT_RULES`: refused).
2. An x86 or x64 executable image (not a DLL, no CLR header), without a section of a protection wrapper (`PROTECTED_SECTIONS` of `laa_patch`).
3. Every edit lies wholly inside the raw data of the named section, and that section is **not code**: neither `IMAGE_SCN_CNT_CODE` nor `IMAGE_SCN_MEM_EXECUTE`. No edit in the headers, the section table, the overlay (after the last section: the certificate table lives there) or a gap between sections.
4. No edit overlaps the file range of a data directory: export, import, resource, exception, base relocation, debug, TLS, load config, bound import, IAT, delay import, CLR. (On MSVC builds the IAT often sits in `.rdata`; strings next to it are fine, the table itself is not.)
5. The bytes at `at` are exactly `text`; the edits do not overlap each other.
6. At most 8 edits per step, 64 bytes each, 512 changed bytes per executable in one plan.

So an `exe_patch` changes text data only: never an instruction, a jump, an import, a check of the image, or anything the loader reads. `detect::pe` gains the section characteristics and the file ranges of the data directories (ADR 0013 amendment; both come from the header region it already reads and bounds-checks).

### Policy line (rule 7)
Rule 7 and `docs/05-sources-policy.md` exclude No-CD and cracked executables and DRM removal. An `exe_patch`:
- distributes no file: it changes bytes of the user's own copy, bound to the build the store delivered, and the revert restores it bit for bit;
- may only neutralise a request to a **shut-down online service that is not a licence check**: telemetry, news, statistics, a dead matchmaking or a dead "connect" service whose failure crashes or stalls the game. The Assassin's Creed host `gconnect.ubi.com` is such a case: the Steam edition runs without Ubisoft Connect (`launch.chain: [steam]`), the game runs offline (reproduced: offline the menu is reached), and the request only crashes it because the server is gone;
- is **never** used to skip a disc check, a serial or activation check, online DRM, an entitlement server or an anti-tamper check, also when that server is dead. Such a game gets the note "GOG or Steam version required" (docs/05), never a patch;
- a curator states the purpose in the variant (`tradeoffs` and a comment) and the review checks it against the line above. The mechanical fence (data only, protected images refused) is the floor; the line is curation, as for every Topo.

### Provenance
- The variant needs at least one source of type `pcgw`, `official`, `repo` or `steam-guide` that names the technique (the host to blank) for this game (loader).
- Offsets and texts are measured by us on the store's build of each listed SHA-256, never copied from a guide (`docs/05`, "Hash computed ourselves"). `rerun-workbench exe-strings <exe> --text <t>` (curator tool, never shipped) prints every occurrence with its offset, section and whether the fence above admits it, and the SHA-256 of the file. Unknown offsets are `TODO` (draft).

### One op per executable, with `laa_patch`
- `ContentRef::Patch` gains `runs` (additive, omitted when empty): `{"offset":<n>,"old":"<hex>","new":"<hex>"}`, 1 to 64 bytes each, at most 8 (`MAX_PATCH_RUNS`), sorted, not overlapping each other or the single-byte `edits`, inside the file, each a change. `plan::patch_check` (both rule sets) and `plan::Patched` (the planner's and `exec`'s reader) take them; the op budget holds (8 runs of 64 bytes are about 2.3 KiB). A head without `runs` keeps its bytes (every `laa_patch` transaction already applied).
- The engine merges every patch of one executable in one plan, `laa_patch` and `exe_patch` alike, into **one** `ReplaceFile`: one backup, one checksum computed over all changes (recomputed when the stored one is not 0, kept 0 otherwise, P4-10 question a). Internally `Step::LaaPatch` becomes `Step::ExePatch { exe, sha256, laa: bool, runs }`; the planners share one streaming core (`prim::exe_patch`).
- Across transactions nothing changes: a live patch of the executable refuses another (`patched_by`), so both are picked in one plan, or the first is reverted.
- An `exe_patch` and a `firewall_rule` of one executable in one plan are refused, with the order that works (as `laa_patch`, P4-10 review).

### Matching after the patch
`exec::patched_now` and `ExeCheck::patched_by` already work on any `ContentRef::Patch` of a live transaction, so a patched build still matches as the build it was patched from; it is never an elevated anchor. The report says "matches (as patched by Rerun)". P5-2a holds: the plan's `main_sha256` is the patched file's while the patch is live.

### Packages bound to a build
`supports_exe_sha1` says a package was built for exactly those bytes. A data patch changes them, so (fail closed):
- an `exe_patch` and a package whose `supports_exe_sha1` names that executable's SHA-1 are refused **in one plan**;
- a package with `supports_exe_sha1` is refused for an executable a live `exe_patch` changed (`patched_by` with `runs`), naming the transaction to revert;
- an `exe_patch` is refused while a live transaction holds a file of such a package (the engine reads the open transactions' heads, as `patched_now`), naming it.
A header-only patch (`laa_patch`, no `runs`) keeps today's rule (accepted in P4-10). For Assassin's Creed this makes the hex variant and EaglePatch alternatives, as the user asked.

### Preview, warnings, revert
- Preview (rule 5): `patch file <exe>` as today, plus per run `text "<escaped>" at 0x<offset> (<section>) -> zero bytes`, the checksum bytes as single edits, and `PATCH_NOTE` once.
- Warnings as `laa_patch` (P4-13): `SmartAppControl` while it is not off, the stronger `SteamPerUserExe` for a Valve stub, `SignedExe` for a certificate table. No refusal: the user decides, the way back is `rerun revert <txn>` (bit for bit). Measured: Smart App Control blocked a patched `mafia2.exe` (CEG) while it let an ASI DLL load (Assassin's Creed, 2026-11-11), so the preview says plainly that the package fix is the one that survives Smart App Control.
- Revert, crash, power loss, tamper: the `ReplaceFile` of ADR 0017/0019, unchanged. Steam's "Verify integrity" restoring the original is `Before`. **No new row** in "Exceptions to core rule 2".

## Alternatives
- **A search pattern within a section** (no offsets): survives a rebuild, but every build is bound by its hash anyway; a search adds a matcher, ambiguity (two occurrences) and a pattern language to review. Rejected.
- **Free byte edits** (hex in, hex out, anywhere): the general tool a crack needs. Rejected; the fence keeps it to text in data sections.
- **Raising `MAX_PATCH_EDITS`** instead of runs: 20 single-byte edits per host do not fit the 8 KiB op budget for more than a few strings and read badly in a preview.
- **Two ops on one executable** (one per primitive): two backups of one file, and the second patch's base is the first's result; "one op per object" refuses it today. Rejected for one merged op.
- **Hosts file** (`gconnect.ubi.com` to `0.0.0.0`, GOG forum): system-wide, needs admin and a new allowed system area. Out of scope.

## Consequences
- `catalog` (model, schema `exePatch`, loader rules: `exe`/`sha256` a `match.exes` pair, `(exe, sha256)` unique, section name form, `at` form, `text` form, the source rule), `prim::exe_patch` (planner, shared with `laa_patch`), `plan` (`runs`, `patch_check`, `Patched`, preview), `topo` (merge, warnings, the package rule), `detect::pe` (section characteristics, data directory ranges), `rerun-workbench exe-strings`.
- Docs: `docs/02-topo-format.md` (the step), `docs/05-sources-policy.md` (the policy line), `docs/06-security.md` (row "a byte patch used as a crack": the fence, curation, review), `docs/09-testing.md`, `docs/01-architecture.md` (primitive list).
- Tests (fake): planner refusals one per fence rule (code section, executable flag, header, overlay, each data directory, protected section, other bytes, other build, overlap, limits); round trip `apply → verify → revert → snapshot identical` with runs only and merged with `laa_patch`; crash and power-loss matrix of the replace (unchanged kind, one run added); `patch_check` on encode and both decodes (forged runs); matching after the patch; the three package rules; preview text. [SB]: patch a repository-built test image's string in `.rdata`, start it, revert, bit for bit. [DEV]: Assassin's Creed with Smart App Control on and off (whether the patched build starts, whether the intro passes), after research.
- Reviews: security-reviewer and senior-dev on the plan and on the code; A6 checks the policy line.

## Not decided here
- A replacement text (`to: { text: … }`, e.g. a community server such as OpenSpy): sends traffic to a third party; needs its own sources rule and a decision.
- UTF-16 strings (`encoding: utf16le`): additive when a Topo needs one.
- Whether the PCGW tip fixes the *intro crash* at all: the PCGW section cited is "Game regularly freezes for a few seconds"; the variant stays `unverified` until the [DEV] test.
