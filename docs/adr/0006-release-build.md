# ADR 0006 · Release build

**Status:** accepted · 2026-11-04

## Context
`rerun-cpu.asi` runs in old 32- and 64-bit game processes, `rerun-launch.exe` is started by Steam and should stay < 1 MB. Neither may depend on an installed VC++ Redistributable.

## Decision
- `+crt-static` for `x86_64-pc-windows-msvc` and `i686-pc-windows-msvc` (`.cargo/config.toml`).
- Release profile: `lto = "fat"`, `codegen-units = 1`, `panic = "abort"`, `debug = "line-tables-only"` (the PDB is not shipped); `opt-level = "s"` for `rerun-launch` and `rerun-cpu`.
- Cargo cannot change the extension: the artifact `rerun_cpu.dll` is copied to `dist/<arch>/rerun-cpu.asi` in the CI step. A packaging script follows with Phase 5/6.
- Toolchain pinned in `rust-toolchain.toml`, MSRV = pinned version. Updates deliberately via commit.

## Consequences
- A panic terminates the process immediately, including the GUI. This is acceptable because the Journal works write-ahead.
- CI checks the size and allowed dependencies of `rerun-launch`, always built with `-p` (otherwise feature unification pulls in `rerun-proto/serde`). The dependency check covers normal dependencies only (`cargo tree -e normal`): since ADR 0013 `rerun-core` is a dev-dependency of `rerun-launch` for its hardening test, which never reaches the shipped binary (the size build with `-p` does not build dev-dependencies). CI builds this release binary before the tests, and the hardening test checks it as well (`RERUN_RELEASE_LAUNCH_EXE`), since the test-profile binary is linked with the features of the test build.

## Amendment P5-13c (2026-11-24): the alpha packaging script
`scripts/alpha-build.ps1` (ADR 0030) is the packaging script for the unsigned alpha: the real `release` profile (never `dev-release`, never the feature `test-key`), one `cargo build -p` per shipped binary as in CI (`rerun-launch`, `rerun-cli`, `rerun-app`; no feature unification), `RERUN_BUILD_ID` = the commit (`<commit>-dirty` for a test payload from uncommitted sources), the hardening tests of those three crates run against exactly these binaries (`RERUN_RELEASE_*_EXE`), the `cargo tree` check for `rerun-core/fake` and `rerun-core/test-key`, then the payload folder `dist\rerun-<version>-<commit>\` with `payload.json` (every file, size, SHA-256), the portable zip of that folder and `SHA256SUMS.txt`, each checked back against the manifest. The signed index is built and signed only with `-Key <private release key>`, which only the developer passes (never an automated agent); the key ID must be one of `RELEASE_KEYS` and `seq` at least `HELPER_MIN_SEQ`. `-NoIndex` makes a test payload without an index. Locally the builds use `--config .dev\sac-build\sac.toml` (Smart App Control); output with `os error 4551` stops the script. Not shipped: `rerun-helper.exe` (no helper in the alpha), `rerun-cpu.asi` (phase 6), `rerun-workbench`. The version is `0.1.0-alpha.N` (`Cargo.toml`, user decision U9 a of P5-13). Code signing and the GitHub release pipeline stay at A6.

**Follow-up (security review of P5-13):** before the local source replacement is used, the script checks every vendored crate against its `.crate` archive in Cargo's registry cache (the archive's SHA-256 must be the checksum in `Cargo.lock`; the same files with the same SHA-256; allowed: the files `cargo vendor` itself leaves out, `.gitignore`, `.gitattributes`, `.git` and `.cargo-ok`, and the documented `icu_*_data` change of `make-vendor.sh`, build script with its known SHA-256 removed and `build = false`). Accepted risk: the vendor folder lives only on the developer machine and is trusted as far as that check reaches. `-NoSac` builds from crates.io directly (CI, a machine without `.dev`). The dirty check covers `.cargo` and `rust-toolchain.toml` too; `-Key` is resolved by PowerShell's provider path and never printed.
