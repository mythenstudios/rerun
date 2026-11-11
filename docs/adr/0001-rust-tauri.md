# ADR 0001 · Rust core + Tauri GUI + separate CLI

**Superseded for the GUI by ADR 0026 (2026-11-11: Slint instead of Tauri 2 and Svelte 5); the Rust workspace and the CLI stand.**

**Status:** accepted · 2026-11-04

## Context
Rerun needs deep Win32 access, a tiny launch shim that sits in between on every game launch, a 32/64-bit plugin and a GUI. The developer comes from web development.

## Decision
Rust workspace (`windows`/`windows-sys`), Tauri 2 with Svelte 5 for the GUI, CLI as an equivalent interface.

## Alternatives
- **C#/.NET + WinUI/Avalonia:** best Win32 interop, Playnite plugins would be possible directly. But the shim would need the .NET runtime or AOT effort, and the 32-bit ASI plugin would not be possible in C#.
- **Electron:** too heavy, contradicts "lean".
- **Python:** distribution and virus scanner problems.

## Consequences
- Shim < 1 MB without a runtime, ASI plugin in the same workspace.
- GUI in the familiar web stack, WebView2 is present on Windows 11.
- Playnite integration later as a thin .NET plugin that calls the CLI.
