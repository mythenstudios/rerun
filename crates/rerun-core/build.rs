//! Sets `RERUN_BUILD_ID` for `rerun_core::BUILD_ID` (ADR 0023 §2, A4 S9): the commit when the
//! release build or CI passes `RERUN_BUILD_ID` (checked: 7 to 64 characters of letters,
//! digits, `.` and `-`), otherwise `dev-<SHA-256 of the contract sources>`
//! (`src/build_contract.rs`), so a CLI and a helper copied by hand from different local builds
//! of the contract refuse each other.

#[path = "src/build_contract.rs"]
mod build_contract;

use sha2::{Digest, Sha256};

fn main() {
    println!("cargo::rerun-if-changed=build.rs");
    println!("cargo::rerun-if-changed=src/build_contract.rs");
    // The contract directories; `src/policy` as a whole, because `policy/firewall*` does not
    // exist before P4-5a (a missing path would rerun the script on every build). Any change
    // there recompiles this crate anyway.
    println!("cargo::rerun-if-changed=src/elevate");
    println!("cargo::rerun-if-changed=src/policy");
    println!("cargo::rerun-if-env-changed=RERUN_BUILD_ID");
    #[expect(
        clippy::disallowed_methods,
        reason = "build script: the release build passes the commit in a variable; not a path"
    )]
    let release = std::env::var("RERUN_BUILD_ID")
        .ok()
        .filter(|s| !s.is_empty());
    let id = match release {
        Some(id) if build_contract::valid_release_id(&id) => id,
        Some(id) => panic!(
            "RERUN_BUILD_ID must be 7 to 64 characters of ASCII letters, digits, '.' and '-', \
             got {} characters",
            id.len()
        ),
        None => {
            let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
            let mut h = Sha256::new();
            if let Err(e) = build_contract::feed_contract(&src, &mut |b| h.update(b)) {
                panic!("build ID: {e}");
            }
            let hex: String = h.finalize().iter().map(|b| format!("{b:02x}")).collect();
            format!("dev-{hex}")
        }
    };
    println!("cargo::rustc-env=RERUN_BUILD_ID={id}");
}
