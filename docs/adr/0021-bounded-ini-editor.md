# ADR 0021 · Bounded INI editor

**Status:** accepted · 2026-11-07 · extends ADR 0004, ADR 0017, ADR 0020 · step P2-12

## Context
`ini_set` (ADR 0020) sets a few keys in an INI file of a game folder. The file is untrusted input: the game, a mod manager, a cloud sync or the user writes it, before and after Rerun. Games rewrite their INI files on every start, often with their own whitespace, order and line endings, and Windows' own reader (`GetPrivateProfileString`) accepts nearly anything. Rerun must change exactly its keys, show them before it does, and give back exactly the old bytes when nothing else changed (core rule 2, ADR 0020 round trip). Reformatting a file, guessing an encoding or picking one of two duplicate keys would each break that silently.

No crate offers a byte-preserving, bounded editor with a documented dialect (`rust-ini` and `configparser` parse into maps and write their own format). The grammar Rerun needs is small.

## Decision

### Layers
- `policy::ini` is **pure**: `scan(&[u8]) -> Doc`, `edit(old, &[IniEdit]) -> Vec<u8>`, `unedit(cur, &[IniEdit]) -> Unedit { bytes, keys }`, `check_edits`, `path_ok`. No I/O, no dependency beyond `std`, `serde` and `thiserror`, no `unsafe`. It sits in `policy` because it decides what may be written (as `policy::registry::layers` does for compatibility layers); `prim::ini_set` and `exec::ini` call it, never the other way round.
- Every byte `exec` writes into an INI file comes from `edit`, `unedit` or the hashed backup; `exec` never forms INI text itself.

### Dialect (fail closed at Rerun's targets, tolerant elsewhere)
- **Size:** at most 1 MiB (`MAX_INI_BYTES`), read bounded.
- **Encoding:** `EF BB BF` is a UTF-8 BOM, kept as a prefix. Anything else without a NUL byte is ASCII-compatible text (UTF-8 or an ANSI code page) handled byte by byte; the structure is ASCII only (`[ ] = ; #`, CR, LF, space, tab). Refused: a UTF-16 BOM (`FF FE`, `FE FF`; user decision E3 b: UTF-16 LE comes with `UserData` in phase 4), any NUL byte (BOM-less UTF-16, UTF-32, binary). With a DBCS code page a trail byte can equal `[` or `]`; that only affects non-ASCII section names, never Rerun's targets (ASCII names).
- **Lines:** CRLF and LF, mixed too; a CR without LF is refused. A file that ends with a line ending has no empty last line.
- **Kinds**, after optional spaces and tabs: blank; comment (`;` or `#`); header: `[` and a `]` later on the line, always a section boundary, its name the text up to the first `]` (senior-dev S3); key line (holds `=`: key = the trimmed text before the first `=`, value = the trimmed rest; no inline comments, quotes not interpreted, as `GetPrivateProfileString`); anything else an "other" line. A line starting with `[` without `]` is refused anywhere: section boundaries would be unclear.
- **Names** are compared ASCII case-insensitively, the file's spelling stays. Keys before the first header are allowed but never a target.
- **Refused at a target only:** its section twice; a header of its section that is not exactly `[Name]` (`[ Display ]`, or text after `]` other than spaces and a comment); its key twice in the section; an "other" line equal to its key; an old value that is not printable ASCII or is longer than 128 characters ("an unusual value, Rerun leaves it alone"; the planner only). The same anomalies elsewhere are tolerated.

### Names and values
- `IniName`: `[A-Za-z0-9_. -]`, 1 to 64, no space at either end. `IniText`: printable ASCII `0x20`–`0x7E`, 0 to 128 characters, no space at either end; serde only through the parsers (the form).
- `IniText::check_new` (a rule in force now, `plan::Rules::Current` only): none of `\ / : % ; #` and no `..`. Syntactic only: whether a value is sensible for a game is curation (`docs/06-security.md`, row 1).
- An edit list (`check_edits`, both rule sets): 1 to 8 edits, in canonical order (folded section, then folded key, byte by byte) without a folded duplicate; a section spelled one way, its edits all `NoSection` or none; every new value not empty (an empty value has no span to find again) and other than its old one.
- `IniEdit { section, key, old: Old::{Value, NoKey, NoSection}, new }` on the wire `{"section":"Display","key":"Width","old":{"value":"1280"},"new":"1920"}` (`"old":"no_key"`, `"old":"no_section"`).

### `edit` (the bytes are frozen)
- An existing key: only its trimmed value span is replaced (spaces around `=` stay); an empty old value's span is the end of the line's content.
- A new key of an existing section: the line `key=value` right after the header (inserted before the header's line ending, with that line ending in front of it).
- A new section: `[Section]` and its `key=value` lines after the content of the last line. Refused in a file without any header, an empty one included (senior-dev S4: such a file may be no INI at all).
- Inserted lines take the line ending of the line they follow; at the end of a file without one, the first line ending of the file; else CRLF. At one place, new keys of an existing section come before new sections; edits in canonical order. New lines are always `key=value` without spaces.
- Every edit's old state must be exactly what the file holds (`NotOld`).
- **Frozen (senior-dev M2):** for an accepted input the output of `edit` never changes. A recorded head binds it (`exec::ini::binds`, ADR 0019 amendment P2-12): the revert recomputes `edit(backup)` and requires the recorded new hash. A change of `edit` therefore needs a versioned `edit` kept for older heads; golden vectors (fixed inputs, fixed SHA-256) pin the output.

### `unedit`
Per edit by `KeyState`: `New` (the value is exactly Rerun's) puts the old value back into the span, or removes the line Rerun inserted with its own line ending (the last line without one takes the line ending of the line before it along); a section Rerun created whose lines the revert removes completely loses its header too (one someone else emptied keeps it). `Old` (the old value, or missing as it was) and `Changed` (another value, or missing although there was one: user decision E1 b) are left. The result is the input if no key is `New`.

### Properties (tests)
- **I1:** `unedit(edit(f)).bytes == f` and every key `New`, exhaustively over a small alphabet (line kinds × line endings × BOM × last line with or without a line ending × every edit set the planner could make); `edit` changes only value spans and inserts lines.
- **I2:** a change of someone else outside Rerun's targets stays: `unedit(g(edit(f))) == g(f)`.
- **S5:** random bytes (many of them `[ ] = ; CR LF`) never panic; whatever `edit` accepts comes back exactly; `unedit` changes no line but Rerun's.

### Narrowing is a format change
The dialect decides which recorded edits can be reverted. A narrower dialect (refusing more) in a later version would make applied transactions unrevertable: it is a format change with a migration, never silent. Widening (UTF-16 LE, inline comments) is additive.

## Consequences
- A file Rerun refuses is reported, never guessed; the planner names the reason. A revert meeting such a file (the game rewrote it as UTF-16, a duplicate of Rerun's key) finds it `Foreign`.
- Exactness rests on the line-based rebuild: untouched lines are copied byte for byte.
- Known limits: no sectionless targets, no inline comments, no more than 8 keys per file, no UTF-16 (phase 4), `Documents\My Games` only with `UserData` (phase 4).

## Alternatives considered
- **A map-based parser that writes its own format:** loses comments, order and line endings; no exact revert.
- **Guessing the encoding (ANSI vs UTF-8, BOM-less UTF-16):** a wrong guess corrupts the file; byte transparency needs no guess for ASCII targets.
- **Choosing the first of two duplicate keys** (as some readers do): the game may read the other; refusing is the only safe choice.
