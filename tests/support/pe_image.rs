//! A minimal PE image writer for tests (ADR 0016, `docs/09-testing.md`): the teeth of the
//! hardening policy (`tests/support/hardening.rs`) and the game executables of the CLI tests.
//! Included with `#[path]`. Written out from `winnt.h` on purpose, independent of the layout
//! constants of `rerun_core::detect::pe` (whose own builder, `detect::pe::testfx`, stays
//! crate-private).

#![allow(
    dead_code,
    reason = "shared by several test crates (#[path]); each uses a part of it"
)]

/// `IMAGE_FILE_MACHINE_I386`.
pub const I386: u16 = 0x014C;
/// `IMAGE_FILE_MACHINE_AMD64`.
pub const AMD64: u16 = 0x8664;
/// `IMAGE_FILE_MACHINE_ARM64`.
pub const ARM64: u16 = 0xAA64;

fn put(b: &mut [u8], at: usize, v: &[u8]) {
    b[at..at + v.len()].copy_from_slice(v);
}

/// A minimal image for `machine`, PE32 for x86 and PE32+ otherwise (offsets from `winnt.h`,
/// written out here on purpose so the teeth do not depend on the parser's own layout): one
/// section `.rdata` at RVA 0x1000 (file offset 0x200, 0x200 bytes) holding the import table at
/// +0x00, the delay-import table at +0x80, the load config at +0x100 and the DLL names from
/// +0x180.
pub fn image_for(machine: u16, imports: &[&str], delayed: &[&str], load_flags: u16) -> Vec<u8> {
    const OPT: usize = 0x58;
    const RVA: u32 = 0x1000;
    const RAW: usize = 0x200;
    let pe32 = machine == I386;
    // Data directories at 96 (PE32) or 112 (PE32+) of the optional header (with 16 of them
    // 224 or 240 bytes); `DependentLoadFlags` at 0x36 or 0x4E of the load config.
    let (dirs, opt_size, flags_at): (usize, u16, usize) = if pe32 {
        (96, 224, 0x36)
    } else {
        (112, 240, 0x4E)
    };
    let mut b = vec![0u8; 0x400];
    put(&mut b, 0, b"MZ");
    put(&mut b, 0x3C, &0x40u32.to_le_bytes()); // e_lfanew
    put(&mut b, 0x40, b"PE\0\0");
    put(&mut b, 0x44, &machine.to_le_bytes()); // Machine
    put(&mut b, 0x46, &1u16.to_le_bytes()); // NumberOfSections
    put(&mut b, 0x54, &opt_size.to_le_bytes()); // SizeOfOptionalHeader
    put(&mut b, 0x56, &0x0022u16.to_le_bytes()); // Characteristics
    if pe32 {
        put(&mut b, OPT, &0x10Bu16.to_le_bytes()); // Magic: PE32
        put(&mut b, OPT + 28, &0x40_0000u32.to_le_bytes()); // ImageBase
        put(&mut b, OPT + 92, &16u32.to_le_bytes()); // NumberOfRvaAndSizes
    } else {
        put(&mut b, OPT, &0x20Bu16.to_le_bytes()); // Magic: PE32+
        put(&mut b, OPT + 24, &0x1_4000_0000u64.to_le_bytes()); // ImageBase
        put(&mut b, OPT + 108, &16u32.to_le_bytes()); // NumberOfRvaAndSizes
    }
    put(&mut b, OPT + 60, &0x200u32.to_le_bytes()); // SizeOfHeaders
    put(&mut b, OPT + 68, &3u16.to_le_bytes()); // Subsystem: console
    let dir = |b: &mut [u8], index: usize, rva: u32, size: u32| {
        put(b, OPT + dirs + 8 * index, &rva.to_le_bytes());
        put(b, OPT + dirs + 8 * index + 4, &size.to_le_bytes());
    };
    let section = OPT + usize::from(opt_size);
    put(&mut b, section, b".rdata\0\0");
    put(&mut b, section + 8, &0x200u32.to_le_bytes()); // VirtualSize
    put(&mut b, section + 12, &RVA.to_le_bytes()); // VirtualAddress
    put(&mut b, section + 16, &0x200u32.to_le_bytes()); // SizeOfRawData
    put(&mut b, section + 20, &0x200u32.to_le_bytes()); // PointerToRawData

    let mut name_at = 0x180;
    let mut name = |b: &mut [u8], s: &str| {
        let rva = RVA + u32::try_from(name_at).unwrap_or(u32::MAX);
        put(b, RAW + name_at, s.as_bytes());
        name_at += s.len() + 1;
        rva
    };
    if !imports.is_empty() {
        dir(&mut b, 1, RVA, 0x80);
        for (i, s) in imports.iter().enumerate() {
            let rva = name(&mut b, s);
            put(&mut b, RAW + 20 * i + 12, &rva.to_le_bytes()); // IMAGE_IMPORT_DESCRIPTOR::Name
        }
    }
    if !delayed.is_empty() {
        dir(&mut b, 13, RVA + 0x80, 0x80);
        for (i, s) in delayed.iter().enumerate() {
            let rva = name(&mut b, s);
            put(&mut b, RAW + 0x80 + 32 * i, &1u32.to_le_bytes()); // Attributes: RVA based
            put(&mut b, RAW + 0x80 + 32 * i + 4, &rva.to_le_bytes()); // DllNameRVA
        }
    }
    dir(&mut b, 10, RVA + 0x100, 0x80);
    put(&mut b, RAW + 0x100, &0x80u32.to_le_bytes()); // IMAGE_LOAD_CONFIG_DIRECTORY*::Size
    put(&mut b, RAW + 0x100 + flags_at, &load_flags.to_le_bytes());
    b
}

/// The native machine of the build (x64 in CI).
pub const NATIVE_MACHINE: u16 = if cfg!(target_arch = "aarch64") {
    ARM64
} else {
    AMD64
};

/// [`image_for`] the native machine.
pub fn image(imports: &[&str], delayed: &[&str], load_flags: u16) -> Vec<u8> {
    image_for(NATIVE_MACHINE, imports, delayed, load_flags)
}
