//! Links `rerun-helper.exe` (ADR 0023 §2, ADR 0008 H2) with:
//! - `/DEPENDENTLOADFLAG:0x800`: the loader resolves the static imports from System32 only;
//! - an embedded manifest with `requestedExecutionLevel` `asInvoker`: elevation comes only
//!   from the `runas` verb of the CLI's start, never from the manifest or an installer
//!   heuristic, and a non-elevated start reaches the helper's own refusal.
//!
//! `tests/hardening.rs` checks the flag, the import table and the manifest of the built binary.

fn main() {
    println!("cargo::rerun-if-changed=build.rs");
    #[expect(
        clippy::disallowed_methods,
        reason = "build script: Cargo passes the target environment in a variable; not a path"
    )]
    let target_env = std::env::var("CARGO_CFG_TARGET_ENV");
    // link.exe (and lld-link) only; both are PE fields.
    if target_env.as_deref() == Ok("msvc") {
        println!("cargo::rustc-link-arg-bins=/DEPENDENTLOADFLAG:0x800");
        println!("cargo::rustc-link-arg-bins=/MANIFEST:EMBED");
        println!("cargo::rustc-link-arg-bins=/MANIFESTUAC:level='asInvoker' uiAccess='false'");
    }
}
