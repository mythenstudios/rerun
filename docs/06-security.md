# 06 · Threat model

## What we protect

The user's system (files outside the game folder, registry, firewall, autostart) and the trust that Rerun only does what the preview shows.

## Attackers and scenarios

| # | Scenario | Countermeasure |
|---|---|---|
| 1 | Malicious Topo in the community repo | Purely declarative format, no execute primitive, launch options only as game arguments after `%command%`, INI values without line breaks/paths, download URLs bound to the original source, schema validation, review via PR, signed index |
| 2 | Compromised GitHub repo / index replaced | Ed25519 signature, key offline, public key in the binary |
| 3 | Upstream release replaced | Pinned SHA256 in the package, check before extraction |
| 4 | Path escape (`..`, absolute paths, junctions, ADS, UNC, `CON`, Unicode lookalikes) | `RelPath` and `RootPath` lexically strict; all file operations relative to a root handle opened by `policy::root`, never follow junctions or symlinks below the root, forbidden roots from known folders, never environment variables (Windows, Program Files itself, profile roots, other users' profiles, per-volume system folders; a root may neither lie in nor contain a protected folder; the list fails closed), no network or volume roots, a game folder from a store is opened handle-relative so a junction at game level is an anomaly, root identity re-checked before every apply and revert, hard links never changed in place, invalid names on disk reported and never touched (ADR 0007) |
| 5 | Zip Slip during extraction | Check every entry individually, never extract blindly |
| 6 | Registry abuse | Allowlist of keys, previous value to the Journal |
| 7 | TOCTOU between preview and elevation | The plan hash only catches accidents; the boundary is the helper's own re-validation: it treats the plan as untrusted, only writes into roots that only admins can write and that contain the topo's target exe with the signed hash, verifies index signature and package hashes itself, and opens its root by volume GUID path + file ID; root identity (volume serial + file ID) is checked on every apply and revert (ADR 0007). Helper process hardening: ADR 0008 |
| 8 | Wrong exe targeted (same name) | Identification via path + hash; IFEO with `FilterFullPath` |
| 9 | Revert deletes foreign/modified files | Delete only if the hash matches, otherwise ask |
| 10 | Crash in the middle of apply | Write-ahead Journal, revert also works with incomplete entries |
| 11 | Rerun itself perceived as malware | Code signing, no injection, IFEO opt-in only, transparent preview |

## Principles

- The GUI never runs elevated. Admin only in the helper, per apply, with a validated plan.
- Network only to the Topo index and package hosts from `packages/`. No telemetry.
- `unsafe` minimal, commented, encapsulated in `sys::win`, `rerun-launch` and `rerun-cpu`.
- Dependencies checked with `cargo deny` (licenses, advisories, crates.io only, no OpenSSL) in CI.
- **Policy boundary (ADR 0004):** `sys` executes, `policy` decides. Confinement (`policy::path::RelPath`) and the registry allowlist (from Phase 3 `policy::registry`) sit above `sys` and apply equally to the fake, the real system and the elevated helper.
- **No system access bypassing `sys`:** `clippy.toml` blocks `std::fs` write operations and `std::process::Command::new` (`disallowed_methods = deny`). Exceptions only with `#[allow(…, reason = "…")]` in `sys::win` and `rerun-launch`.
- **CI supply chain:** GitHub Actions pinned by commit SHA, `permissions: contents: read`, toolchain pinned in `rust-toolchain.toml`, `Cargo.lock` committed and `--locked`.

## Allowed registry areas (initial list)

- `HKCU\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers` (value = path of the game exe)
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<exe>` (only `PerfOptions\CpuPriorityClass`, `Debugger`, `UseFilter`, filter subkeys)
- Game-specific keys that are explicitly named in the Topo and approved in review
