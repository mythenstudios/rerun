//! Test program for the `laa_patch` case of the CI sandbox suite (docs/09-testing.md, P4-10).
//! Built from this file by `scripts/sandbox-launch.ps1` as a 32-bit image
//! (`--target i686-pc-windows-msvc`, linked with `/LARGEADDRESSAWARE:NO` so the flag is not set,
//! and `/RELEASE` so the image stores a checksum); nothing third-party is involved.
//!
//! It asks for 2.5 GiB of address space in two blocks (1.5 GiB and 1 GiB, reserved and
//! committed by the heap, never touched, so no memory is used). A 32-bit process without the
//! Large Address Aware flag has 2 GiB of user address space and cannot get both; with the flag,
//! on 64-bit Windows, it has 4 GiB and gets them. Exit 32: both blocks (the large address space);
//! 16: not both. Started before the patch it must say 16, after the patch 32, after the revert
//! 16 again.
//!
//! Std only, no `unsafe`, no imports of its own (the workspace's source rule allows no
//! hand-written FFI, `crates/rerun-core/tests/source_rules.rs`).

use std::process::ExitCode;

fn main() -> ExitCode {
    let mut low: Vec<u8> = Vec::new();
    let mut high: Vec<u8> = Vec::new();
    let first = low.try_reserve_exact(1536 << 20).is_ok();
    let second = first && high.try_reserve_exact(1024 << 20).is_ok();
    println!(
        "laa-stub: 1.5 GiB {} at {:#x}, 1 GiB {} at {:#x}",
        if first { "reserved" } else { "refused" },
        low.as_ptr().addr(),
        if second { "reserved" } else { "refused" },
        high.as_ptr().addr()
    );
    ExitCode::from(if second { 32 } else { 16 })
}
