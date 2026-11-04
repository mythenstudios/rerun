# ADR 0003 · No permanent background process

**Status:** accepted · 2026-11-04

## Context
Tools like Process Lasso run permanently in the background to enforce rules. This contradicts the goal of a lightweight tool that is used only when needed.

## Decision
Rerun has no service, no tray, no autostart. Persistent fixes work without a running process (files, registry, firewall). Runtime fixes are set by `rerun-launch` at game launch; it lives at most as long as the game (`hold`, `ifeo`) and only via opt-in.

## Consequences
- Games that start via launchers need `watch`/`hold`/`ifeo`/`inproc` (see `04-launch-methods.md`).
- The app's status bar permanently says "No background process".
