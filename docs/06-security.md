# 06 · Threat model

## What we protect

The user's system (files outside the game folder, registry, firewall, autostart) and the trust that Rerun only does what the preview shows.

## Attackers and scenarios

| # | Scenario | Countermeasure |
|---|---|---|
| 1 | Malicious Topo in the community repo | Purely declarative format, no execute primitive, launch options only as game arguments after `%command%`, INI values without line breaks/paths, download URLs bound to the original source, schema validation, review via PR, signed index |
| 2 | Compromised GitHub repo / index replaced | Ed25519 signature, key offline, public key in the binary |
| 3 | Upstream release replaced | Pinned SHA256 in the package, check before extraction |
| 4 | Path escape (`..`, absolute paths, junctions, ADS, UNC, `CON`, Unicode lookalikes) | `RelPath` and `GameRoot` lexically strict (Phase 0); operations relative to a root handle, never follow junctions below the root (ADR 0007, to be decided before Phase 1) |
| 5 | Zip Slip during extraction | Check every entry individually, never extract blindly |
| 6 | Registry abuse | Allowlist of keys, previous value to the Journal |
| 7 | TOCTOU between preview and elevation | Plan hash; helper re-validates the plan and compares the hash |
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
