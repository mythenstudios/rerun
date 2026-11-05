# ADR 0011 · Bounded VDF parser for Steam files

**Status:** accepted · 2026-11-05 · extends ADR 0004, ADR 0007

## Context
Phase 1 detects Steam games from two Valve KeyValues text files ("VDF"): `libraryfolders.vdf` (the libraries of a Steam installation) and `steamapps\appmanifest_<appid>.acf` (one installed app). Both live in folders the user can write (Steam grants `Users` full control on its folder, ADR 0007), so any process running as the user can plant or edit them. Their content is untrusted input: it decides which folders become `StoreDir` roots and which install folder names reach `StoreDir::game`.

Valve's own KeyValues reader accepts more than Steam writes: unquoted tokens, `//` comments, conditionals such as `[$WIN32]`, `#include`/`#base` directives that pull in other files, a wide escape table, duplicate keys. No crate on crates.io offers documented limits for size, depth and node count together with a small dependency footprint (`keyvalues-parser` builds on `pest`, `steamlocate` bundles the whole Steam discovery). The grammar Steam emits is small.

## Decision

### Layers
- `detect::vdf` is a **pure** parser: `parse(&[u8], &Limits) -> Result<Document, VdfError>`. No I/O, no dependency beyond `std` and `thiserror`, no `unsafe`. Single pass with an explicit stack, no recursion.
- `detect::vdf::read::read_store_file(&StoreDir, &RelPath, &Limits) -> Result<Document, VdfReadError>` (re-exported as `detect::vdf::read_store_file`) is the only reader: `Dir::open_read` relative to the store handle, then at most `max_bytes + 1` bytes through `Read::take`; the parser turns more than `max_bytes` into `TooLarge`. The file length from metadata is never trusted (it is not even asked for). Never by absolute path, never `Dir::read` (unbounded). The bounded read stays local to this module in Phase 1; a general `Dir::read_limited` in `sys` is a Phase 2 follow-up (journal backups and INI files need the same bound).
- `detect::steam::files` holds the typed views `LibraryFolders::from_vdf` and `AppManifest::from_vdf`: pure functions from a `Document`, strict about the fields they use, errors as `ViewError`. Finding the Steam root, opening libraries, listing manifests and opening game folders is step 12 (`detect::steam`), not part of this decision.

### Accepted grammar
```
document = BOM? ws* (pair ws*)* EOF
pair     = string ws* (string | object)
object   = "{" ws* (pair ws*)* "}"
string   = '"' (char | escape)* '"'
char     = any character except '"', '\', CR, LF
escape   = '\' ( '"' | '\' | 'n' | 't' )
ws       = ' ' | '\t' | '\r' | '\n' | comment
comment  = "//" (any character except LF)*
```
- Input: UTF-8 only. One leading UTF-8 BOM is skipped. A UTF-16 BOM (`FF FE` or `FE FF`), invalid UTF-8 and a NUL byte anywhere (also in a comment) are errors. CRLF and LF are both line ends.
- Strings: a raw CR or LF inside a string is an error (an unterminated string is reported at its opening quote, not at the end of the file); a raw tab and other characters are kept as they are. Escapes: exactly `\"`, `\\`, `\n`, `\t`; any other escape is `UnknownEscape` at the backslash (user decision 2026-11-05).
- Rejected with their own error kind, where a token is expected: `[` (`Conditional`), `#include`/`#base` in any ASCII case (`Directive`, never followed), any other printable ASCII character that is not `"`, `{` or `}` (`UnquotedToken`, user decision 2026-11-05; a lone `/` included). Other characters there (control characters, non-ASCII, `{` where a key is expected, `}` where a value is expected) are `UnexpectedChar`. A `}` without an open object is `UnbalancedBrace`, end of input inside an object or after a key `UnexpectedEnd`.
- Checks run in this order and the first failure is reported: size, UTF-16 BOM, UTF-8, NUL, then the grammar in file order.
- Keys are kept as written. Duplicate keys are kept, in file order. Lookups (`Object::get_all`, `Object::get_unique -> Result<Option<&Entry>, Duplicate>`) compare keys ASCII case-insensitively (Valve's `stricmp`); non-ASCII characters compare exactly. Every `Entry { key, value, offset }` carries the byte offset of its key's opening quote.

### Limits
`Limits { max_bytes, max_depth, max_entries, max_string }` with the constants `Limits::LIBRARY_FOLDERS` and `Limits::APP_MANIFEST`:

| Limit | `libraryfolders.vdf` | `appmanifest_*.acf` | Reason |
|---|---|---|---|
| input bytes (raw, BOM included) | 4 MiB | 1 MiB | an app line in `apps` is about 30 bytes, so 4 MiB is over 100,000 installed apps; a manifest is usually under 10 KiB, games with hundreds of DLC depots stay under 100 KiB |
| nesting depth (open objects) | 16 | 16 | Steam writes at most 3 to 4 levels |
| entries (pairs) in total | 200,000 | 20,000 | bounds memory to tens of MiB; one entry per installed app plus a few per library |
| string length (decoded, bytes; keys and values) | 8 KiB | 8 KiB | paths and names are far below; long paths (32,767 UTF-16 units) are not supported by Steam libraries |

A value of exactly the limit is accepted, one more is an error. There is no per-object limit: the total bounds every object, and every operation on the tree is linear. Depth is additionally capped at `HARD_MAX_DEPTH = 64` whatever the caller passes, because the derived `Drop`, `Clone`, `PartialEq` and `Debug` of the tree recurse; the parser itself never does, so depth is bounded by the limit and not by the thread's stack.

### Errors
`VdfError { kind, offset }` with the byte offset in the input as given (BOM included) and a `#[non_exhaustive] VdfErrorKind`: `TooLarge`, `Utf16Bom`, `InvalidUtf8`, `Nul`, `UnterminatedString`, `UnknownEscape`, `UnexpectedChar`, `UnquotedToken`, `Directive`, `Conditional`, `UnbalancedBrace`, `UnexpectedEnd`, `TooDeep`, `TooManyEntries`, `StringTooLong`. Line and column (1-based, column in characters, a leading BOM not counted) are computed from the input only when an error is reported (`VdfError::line_col`). Errors never contain file content: at most the offending character as `U+XXXX` and the limit that was hit. `VdfReadError` adds the `RelPath` of the file and the line and column.

### Typed views
- `LibraryFolders { libraries: Vec<Library { path, label: Option<String> }> }`: exactly one top-level pair named `libraryfolders`, an object. Each child whose key is all ASCII digits is a library: an object with exactly one `path` string (current format) or a string that is the path itself (format before 2021, user decision 2026-11-05: both are supported). An optional `label` (at most one, a string, kept as written, empty included). Other keys (`contentstatsid`, `TimeNextStatsReport`, …) and the `apps` child of a library are ignored. Any malformed library entry fails the whole file (user decision 2026-11-05). Paths stay raw strings; `policy::root` decides whether they become roots (step 12).
- `AppManifest { app_id: u32, name, install_dir, state_flags: u32 }`: exactly one top-level pair named `AppState`, an object with exactly one each of `appid`, `installdir`, `name` (required, user decision 2026-11-05) and `StateFlags`, all strings. `appid` is 1 to 10 ASCII digits, no sign, no whitespace, no leading zero, not 0, and fits `u32`; `StateFlags` the same, except that `0` is allowed. A missing, duplicated or wrongly typed required field fails the file. `installdir` stays raw; `StoreDir::game` classifies it.
- `ViewError` names the field and byte offsets only, never a value.

## Alternatives
- **A crate (`keyvalues-parser`, `vdf-reader`, `steamlocate`).** Rejected: new dependencies (`pest` and its generator), no documented limits, recursion depth tied to the input, and `steamlocate` reads by absolute path, which ADR 0007 forbids.
- **Lenient parsing like Valve's reader** (unquoted tokens, unknown escapes kept literally). Rejected: Steam rewrites both files in the quoted form, so leniency only helps hand-edited or forged files and makes the accepted language harder to test.
- **Per-entry tolerance in `libraryfolders.vdf`** (skip one bad library, keep the rest). Rejected for v1: the file is written by Steam in one piece; a malformed entry means it was edited, and failing the file is simpler to reason about. Only the availability of detection is lost, which a same-user attacker could take away by deleting the file anyway.
- **`Dir::read_limited` in `sys` now.** Deferred to Phase 2: Phase 1 has one bounded reader, and a trait method needs its own contract test against `sys::win`.

## Consequences
- A hand-edited file with comments still parses; one with unquoted tokens, `#include` or unknown escapes is reported with its position and yields no data.
- Step 12 owns Steam root discovery, the two locations of `libraryfolders.vdf`, the check that the file name `appmanifest_<appid>.acf` matches `appid`, de-duplication of libraries by `RootId` and the meaning of `StateFlags`.
- `name` can contain any character Steam can encode (including an escaped newline or a raw control character); output layers sanitize it for display (CLI in step 16, UI in phase 5).
- The parser is fuzzed with a deterministic xorshift loop and checked with a round trip against a test-only writer (`docs/09-testing.md`).
- Phase 2 follow-up: `Dir::read_limited` in `sys` with a contract test; `detect::vdf::read` then uses it.
