# ADR 0005 · YAML and schema validation

**Status:** accepted · 2026-11-04

## Context
Topos and packages are YAML (ADR 0002) and must be validated strictly, without editors, CI and runtime deciding differently. `serde_yaml` is discontinued, `serde_yml` has a RUSTSEC advisory.

## Decision
- **Two stages:** JSON Schema (Draft 2020-12) under `schema/` for curators, editors and CI. From Phase 4, typed serde structs with `deny_unknown_fields` and `RelPath` are the authority at runtime. Both run against the same fixtures (`tests/fixtures/schema/`).
- **YAML crate:** `serde-saphyr` (pure Rust, MIT/Apache, limits against alias bombs). Options: `strict_booleans` (only `true`/`false`; `off`/`yes` are strings), merge keys forbidden, duplicate keys forbidden.
- **Validator:** `jsonschema` (MIT, maintained) without default features, i.e. without HTTP/file resolution. Dev dependency only, the binaries remain unaffected.
- `format: 1` is a constant. A v2 gets its own schema files, the loader branches on `format`. *Amended by ADR 0024 amendment "Forward compatibility" (2026-11-12): Topos and packages carry an entry format (`ENTRY_FORMAT`) whose versions are additive and read by one set of typed structs; own schema files and a branch remain only for a non-additive format, with its own ADR.*
- Shared definitions (`relPath`, hashes, IDs, URLs) are identical in both schemas; a test checks this. A parity test checks `relPath` and `RelPath::parse` against `tests/fixtures/paths.json`. Regexes without lookaround (ECMA-262 and Rust regex).
- Hashes in uppercase hex. `TODO` only in selected fields; a Rust test checks "`TODO` anywhere ⇒ `status: draft`".

## Consequences
- New primitives extend `$defs/step` only together with their spec and implementation; before that they are a validation error.
- Anchors/aliases are forbidden entirely in the loader in Phase 4; the schema does not see them.
