//! Links `rerun.exe` with `/DEPENDENTLOADFLAG:0x800` (ADR 0008, H2): the loader resolves the
//! static imports from System32 only, never from the (possibly user-writable) install folder.
//! `tests/hardening.rs` checks the flag and the import table of the built binary.

fn main() {
    println!("cargo::rerun-if-changed=build.rs");
    #[expect(
        clippy::disallowed_methods,
        reason = "build script: Cargo passes the target environment in a variable; not a path"
    )]
    let target_env = std::env::var("CARGO_CFG_TARGET_ENV");
    // link.exe (and lld-link) only; the flag is a Windows PE load config field.
    if target_env.as_deref() == Ok("msvc") {
        println!("cargo::rustc-link-arg-bins=/DEPENDENTLOADFLAG:0x800");
    }
}
