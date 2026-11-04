//! `rerun-cpu.asi` – inproc CPU fix (see `docs/03-cpu-topology.md`, phase 6).
//!
//! Phase 0: empty library, so the x86 and x64 builds run in CI from the start.
//! Later: `DllMain` and hooks behind `#[cfg(not(test))]`, no heavy work under the
//! loader lock, the logic (mask computation, INI) in pure, testable modules.
