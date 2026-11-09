# 00 · Vision

## Problem

Old PC games often run poorly or not at all on Windows 11. The solutions exist, but they are scattered: PCGamingWiki, Steam guides, forums, Process Lasso, batch files, hosts entries, DLL wrappers. Every game costs research, and in the end nobody remembers what they changed on their system.

## Product

Rerun detects installed games, knows from a curated database (Topos) which problems occur on **this** system, and applies the matching fixes: with preview, Journal and complete undo.

On Linux the principle has existed for a long time (protonfixes, Luxtorpeda). On Windows the layer that detects the game and knows what it needs is missing.

## Who it is for

- **Standard:** wants to play an old game, clicks "Apply", done.
- **Experienced:** wants to configure things themselves (affinity, compatibility mode, wrapper, launch method) and see what happens.
- **Curators:** maintain Topos via pull request.

## Principles

1. Lightweight: portable exe, nothing in the background.
2. Reversible: every change, at any time, even after a crash.
3. Transparent: preview before every change, log afterwards.
4. Honest: evidence status per fix, trade-offs are stated, "no known fix" is a valid answer.
5. Hardware-aware: fixes apply only if they match the user's GPU, CPU and OS.
6. Trustworthy: only original sources, pinned versions, verified hashes.

## Scope

- **Fixes:** the game runs as intended (launch, crashes, controllers, resolution, core count, online services). The core of Rerun.
- **Enhancements:** widescreen, shadows, draw distance, FPS limit. Per toggle.
- **Mods:** large overhauls, gameplay changes. Not in v1, at most as a link.

## Non-goals

- No mod manager, no launcher replacement, no game library with metadata maintenance.
- No anti-cheat games, no online games with ban risk. Rerun detects anti-cheat in a game folder (`rerun scan`, the Topo engine) only to stay away: for such a game it refuses file, firewall and compatibility-layer fixes and the `watch` launch method, and warns for the rest (P4-4, `02-topo-format.md`). A Topo can release a verifiably dead system (`anti_cheat.dead`).
- No cracks, no circumventing copy protection.
- No driver updates as a "fix" for old games.
- No ARM64 in v1 (the field `tested_on` does exist in the format, though).

## Name and brand

**Rerun** – by Mythen Studios. Logo: pixel play triangle with cursor (prompt look) on an 8×7 grid. Black and white according to the Mythen design system. See `07-ui.md`.
