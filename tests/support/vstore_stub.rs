//! Test program for the UAC VirtualStore case of the CI sandbox suite (docs/09-testing.md,
//! "VirtualStore, real case"). Built from this file by `scripts/sandbox-launch.ps1` as a 32-bit
//! image (`--target i686-pc-windows-msvc`); nothing third-party is involved.
//!
//! It appends one line to `settings.ini` next to its own executable. Started by a standard
//! user from a folder under `Program Files`, with no manifest in the image and UAC on, that
//! write is virtualized: it lands in `%LOCALAPPDATA%\VirtualStore\...` and succeeds. Without
//! virtualization the open is refused (exit 2). The image must carry no manifest (a
//! `requestedExecutionLevel` would switch virtualization off); the script checks that.
//!
//! Std only, no `unsafe`, no imports of its own.

use std::fs::OpenOptions;
use std::io::{Seek, SeekFrom, Write};
use std::process::ExitCode;

fn main() -> ExitCode {
    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => {
            println!("vstore-stub: no own path: {e}");
            return ExitCode::from(3);
        }
    };
    let Some(dir) = exe.parent() else {
        println!("vstore-stub: own path has no folder");
        return ExitCode::from(3);
    };
    let target = dir.join("settings.ini");
    let result = OpenOptions::new()
        .write(true)
        .open(&target)
        .and_then(|mut f| {
            f.seek(SeekFrom::End(0))?;
            f.write_all(b"\r\n; written by vstore-stub\r\n")
        });
    match result {
        Ok(()) => {
            println!("vstore-stub: wrote {}", target.display());
            ExitCode::SUCCESS
        }
        Err(e) => {
            println!(
                "vstore-stub: write to {} failed: {e} (os error {:?})",
                target.display(),
                e.raw_os_error()
            );
            ExitCode::from(2)
        }
    }
}
