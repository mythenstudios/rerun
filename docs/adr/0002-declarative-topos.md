# ADR 0002 · Topos are purely declarative

**Status:** accepted · 2026-11-04

## Context
The recipe database is to be maintained by a community. Every recipe runs on other people's machines, sometimes with admin rights.

## Decision
Topos and packages are YAML without executable content. They can only invoke built-in primitives with validated parameters. Downloads only from packages with a pinned hash. The index is signed.

## Alternatives
- **Scripts per game (like protonfixes in Python):** maximally flexible, but every script is an attack vector and hard to review.
- **Lua sandbox:** more flexible than YAML, but a sandbox has to be secured by ourselves; the review effort remains high.

## Consequences
- New capabilities need a new primitive in the code, not a new script.
- Topos are easy to review and can be validated automatically.
