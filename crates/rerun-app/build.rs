//! Builds `rerun-app.exe` (ADR 0026, ADR 0027):
//! - compiles `ui/app.slint` with `slint-build` (no run-time interpreter); the images it names
//!   are embedded;
//! - links with `/DEPENDENTLOADFLAG:0x800` (ADR 0008, H2): the loader resolves the static imports
//!   from System32 only;
//! - embeds a manifest with `requestedExecutionLevel` `asInvoker` (the GUI is never elevated,
//!   rule 6) and the per-monitor DPI awareness V2 of `rerun-app.manifest`.
//!
//! `tests/hardening.rs` checks the flag, the import table and the manifest of the built binary.

fn main() {
    println!("cargo::rerun-if-changed=build.rs");
    println!("cargo::rerun-if-changed=rerun-app.manifest");
    let config = slint_build::CompilerConfiguration::new()
        .with_style("fluent-dark".into())
        .embed_resources(slint_build::EmbedResourcesKind::EmbedFiles);
    if let Err(e) = slint_build::compile_with_config("ui/app.slint", config) {
        panic!("ui/app.slint: {e}");
    }
    #[expect(
        clippy::disallowed_methods,
        reason = "build script: Cargo passes the target environment in a variable; not a path"
    )]
    let target_env = std::env::var("CARGO_CFG_TARGET_ENV");
    // link.exe (and lld-link) only; all three are PE fields.
    if target_env.as_deref() == Ok("msvc") {
        let manifest = concat!(env!("CARGO_MANIFEST_DIR"), "/rerun-app.manifest");
        println!("cargo::rustc-link-arg-bins=/DEPENDENTLOADFLAG:0x800");
        println!("cargo::rustc-link-arg-bins=/MANIFEST:EMBED");
        println!("cargo::rustc-link-arg-bins=/MANIFESTINPUT:{manifest}");
        println!("cargo::rustc-link-arg-bins=/MANIFESTUAC:level='asInvoker' uiAccess='false'");
    }
}
