//! Builds `rerun-app.exe` (ADR 0026, ADR 0027):
//! - compiles `ui/app.slint` with `slint-build` (no run-time interpreter); the images it names
//!   are embedded;
//! - links with `/DEPENDENTLOADFLAG:0x800` (ADR 0008, H2): the loader resolves the static imports
//!   from System32 only;
//! - embeds a manifest with `requestedExecutionLevel` `asInvoker` (the GUI is never elevated,
//!   rule 6) and the per-monitor DPI awareness V2 of `rerun-app.manifest`;
//! - embeds `assets/rerun.ico` (the brand icon, a copy of `brand/icon/rerun.ico`) as the first
//!   icon group (`RT_GROUP_ICON` 1, one `RT_ICON` per image), the icon Explorer, the Start-menu
//!   shortcut and the taskbar show. The `.res` file is written here from the `.ico` (one fixed
//!   record per resource, see [`icon_res`]) and handed to the linker, which converts it like
//!   one from `rc.exe`: no resource compiler, no build dependency.
//!
//! `tests/hardening.rs` checks the flag, the import table, the manifest and the icon of the
//! built binary.

fn main() {
    println!("cargo::rerun-if-changed=build.rs");
    println!("cargo::rerun-if-changed=rerun-app.manifest");
    println!("cargo::rerun-if-changed=assets/rerun.ico");
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
    // link.exe (and lld-link) only; all four are PE fields.
    if target_env.as_deref() == Ok("msvc") {
        let manifest = concat!(env!("CARGO_MANIFEST_DIR"), "/rerun-app.manifest");
        let ico = include_bytes!("assets/rerun.ico");
        let res = icon_res(ico).unwrap_or_else(|e| panic!("assets/rerun.ico: {e}"));
        #[expect(
            clippy::disallowed_methods,
            reason = "build script: Cargo names its output folder in a variable"
        )]
        let out = std::path::PathBuf::from(
            std::env::var_os("OUT_DIR").unwrap_or_else(|| panic!("OUT_DIR not set")),
        );
        let res_path = out.join("rerun-app-icon.res");
        #[expect(
            clippy::disallowed_methods,
            reason = "build script: writes its own output into Cargo's OUT_DIR"
        )]
        std::fs::write(&res_path, res).unwrap_or_else(|e| panic!("{}: {e}", res_path.display()));
        println!("cargo::rustc-link-arg-bins={}", res_path.display());
        println!("cargo::rustc-link-arg-bins=/DEPENDENTLOADFLAG:0x800");
        println!("cargo::rustc-link-arg-bins=/MANIFEST:EMBED");
        println!("cargo::rustc-link-arg-bins=/MANIFESTINPUT:{manifest}");
        println!("cargo::rustc-link-arg-bins=/MANIFESTUAC:level='asInvoker' uiAccess='false'");
    }
}

/// `RT_ICON` (`winuser.h`).
const RT_ICON: u16 = 3;
/// `RT_GROUP_ICON` (`winuser.h`).
const RT_GROUP_ICON: u16 = 14;
/// `LANG_NEUTRAL`, `SUBLANG_NEUTRAL`: the loader's first choice in every UI language.
const LANG_NEUTRAL: u16 = 0;
/// `MOVEABLE | DISCARDABLE`, the memory flags `rc.exe` gives an icon image.
const FLAGS_ICON: u16 = 0x1010;
/// `MOVEABLE | PURE | DISCARDABLE`, the memory flags `rc.exe` gives an icon group.
const FLAGS_GROUP: u16 = 0x1030;

fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(at..at + 2)?.try_into().ok()?))
}

fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

/// One record of a 32-bit `.res` file with a numeric type and a numeric name: `DataSize`,
/// `HeaderSize` (32), `TYPE` and `NAME` as `0xFFFF` + ID, `DataVersion`, `MemoryFlags`,
/// `LanguageId`, `Version`, `Characteristics`, then the data padded to 4 bytes.
fn push_record(res: &mut Vec<u8>, kind: u16, id: u16, flags: u16, data: &[u8]) {
    let Ok(size) = u32::try_from(data.len()) else {
        panic!("resource larger than 4 GiB");
    };
    res.extend_from_slice(&size.to_le_bytes());
    res.extend_from_slice(&32u32.to_le_bytes());
    for ordinal in [kind, id] {
        res.extend_from_slice(&0xFFFFu16.to_le_bytes());
        res.extend_from_slice(&ordinal.to_le_bytes());
    }
    res.extend_from_slice(&0u32.to_le_bytes());
    res.extend_from_slice(&flags.to_le_bytes());
    res.extend_from_slice(&LANG_NEUTRAL.to_le_bytes());
    res.extend_from_slice(&0u32.to_le_bytes());
    res.extend_from_slice(&0u32.to_le_bytes());
    res.extend_from_slice(data);
    res.resize(res.len().next_multiple_of(4), 0);
}

/// The `.res` file for the `.ico` file `ico`: the empty record every `.res` file starts with,
/// `RT_ICON` 1..=n with the images as stored, and `RT_GROUP_ICON` 1, the `ICONDIR` with
/// 14-byte entries whose last field is the `RT_ICON` ID instead of the file offset.
fn icon_res(ico: &[u8]) -> Result<Vec<u8>, String> {
    let bad = |what: &str| format!("not an icon file: {what}");
    if u16_at(ico, 0) != Some(0) || u16_at(ico, 2) != Some(1) {
        return Err(bad("ICONDIR header"));
    }
    let count = u16_at(ico, 4).ok_or_else(|| bad("truncated"))?;
    if count == 0 {
        return Err(bad("no image"));
    }
    let mut res = Vec::new();
    push_record(&mut res, 0, 0, 0, &[]);
    let mut group = ico[..6].to_vec();
    for i in 0..count {
        let at = 6 + 16 * usize::from(i);
        let entry = ico
            .get(at..at + 16)
            .ok_or_else(|| bad("truncated directory"))?;
        let size = u32_at(entry, 8).ok_or_else(|| bad("entry"))?;
        let offset = u32_at(entry, 12).ok_or_else(|| bad("entry"))?;
        let start = usize::try_from(offset).map_err(|_| bad("offset"))?;
        let end = start
            .checked_add(usize::try_from(size).map_err(|_| bad("size"))?)
            .ok_or_else(|| bad("size"))?;
        let image = ico
            .get(start..end)
            .ok_or_else(|| bad("image outside the file"))?;
        let id = i + 1;
        push_record(&mut res, RT_ICON, id, FLAGS_ICON, image);
        // Width, height, colours, reserved as stored; planes 1 where the file says 0 (PNG
        // images); bit count and size as stored; the RT_ICON ID.
        group.extend_from_slice(&entry[..4]);
        let planes = u16_at(entry, 4).ok_or_else(|| bad("entry"))?.max(1);
        group.extend_from_slice(&planes.to_le_bytes());
        group.extend_from_slice(&entry[6..12]);
        group.extend_from_slice(&id.to_le_bytes());
    }
    push_record(&mut res, RT_GROUP_ICON, 1, FLAGS_GROUP, &group);
    Ok(res)
}
