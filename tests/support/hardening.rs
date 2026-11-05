//! Test policy for the DLL hardening of the shipped executables (ADR 0008, H2; ADR 0013,
//! "Hardening tests"), included with `#[path]` by `crates/rerun-cli/tests/hardening.rs`,
//! `crates/rerun-launch/tests/hardening.rs` and `crates/rerun-core/tests/win_gpu_restricted.rs`.
//! The executables are read with `rerun_core::detect::pe` over a `std::fs::File` of the build
//! output; this file keeps only what is checked, plus a small PE32+ writer for its own teeth
//! test.

#![allow(
    dead_code,
    reason = "shared by several test crates (#[path]); each uses a part of it"
)]

use std::io::{Read, Seek};
use std::path::Path;

use rerun_core::detect::pe::{DllName, Limits, Pe};

/// `LOAD_LIBRARY_SEARCH_SYSTEM32`, the flag `/DEPENDENTLOADFLAG:0x800` sets.
pub const SEARCH_SYSTEM32: u16 = 0x800;

/// Whether a shipped executable must never import `dll` statically: graphics DLLs (they are not
/// KnownDLLs and must be loaded only on demand from System32, ADR 0008) and the dynamic CRT
/// (static CRT, ADR 0006).
pub fn forbidden_import(dll: &str) -> bool {
    let d = dll.to_ascii_lowercase();
    d == "dxgi.dll"
        || d == "dxcore.dll"
        || d.starts_with("d3d")
        || d.starts_with("vcruntime")
        || d.starts_with("msvcp")
        || d.starts_with("ucrtbase")
        || d.starts_with("api-ms-win-crt-")
}

/// The static imports a shipped executable may have: exact names, compared case-insensitively.
/// Found on 2026-11-05 for `rerun.exe` and `rerun-launch.exe` (debug and release, x64). A new
/// import fails the hardening tests: review it, then extend this list and ADR 0008 (amendment
/// 2026-11-05, DLL hardening).
pub const SHIPPED_IMPORTS: &[&str] = &[
    "kernel32.dll",
    "ntdll.dll",
    "api-ms-win-core-synch-l1-2-0.dll",
];

/// `imports` has no forbidden DLL and nothing outside `allowed` (exact, case-insensitive).
pub fn check_imports(imports: &[DllName], allowed: &[&str]) -> Result<(), String> {
    let all: Vec<&str> = imports.iter().map(DllName::as_str).collect();
    if let Some(bad) = all.iter().find(|d| forbidden_import(d)) {
        return Err(format!("forbidden static import {bad} (imports: {all:?})"));
    }
    let new: Vec<&str> = all
        .iter()
        .copied()
        .filter(|d| !allowed.iter().any(|a| a.eq_ignore_ascii_case(d)))
        .collect();
    if !new.is_empty() {
        return Err(format!(
            "static imports not in the allowlist: {new:?} (all: {all:?}); review them, then \
             update the allowlist in tests/support/hardening.rs and ADR 0008 (amendment \
             2026-11-05)"
        ));
    }
    Ok(())
}

/// Checks an executable (ADR 0008, H2): `DependentLoadFlags` is exactly System32, every static
/// import is in [`SHIPPED_IMPORTS`], no delay-load import. Returns the imported DLL names.
pub fn check_hardened<R: Read + Seek>(image: R) -> Result<Vec<DllName>, String> {
    let mut pe = Pe::parse(image, &Limits::DEFAULT).map_err(|e| e.to_string())?;
    let flags = pe.dependent_load_flags().map_err(|e| e.to_string())?;
    if flags != Some(SEARCH_SYSTEM32) {
        return Err(format!(
            "DependentLoadFlags is {flags:x?}, expected {SEARCH_SYSTEM32:#x} (System32 only)"
        ));
    }
    let imports = pe.imports().map_err(|e| e.to_string())?;
    check_imports(&imports, SHIPPED_IMPORTS)?;
    let delayed = pe.delay_imports().map_err(|e| e.to_string())?;
    if !delayed.is_empty() {
        return Err(format!("delay-load imports {delayed:?}"));
    }
    Ok(imports)
}

/// The static and delay-load imports of the executable at `path` (the test's own build
/// output).
pub fn imports_of(path: &Path) -> Result<(Vec<DllName>, Vec<DllName>), String> {
    let file = std::fs::File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut pe = Pe::parse(file, &Limits::DEFAULT).map_err(|e| e.to_string())?;
    let imports = pe.imports().map_err(|e| e.to_string())?;
    let delayed = pe.delay_imports().map_err(|e| e.to_string())?;
    Ok((imports, delayed))
}

/// [`check_hardened`] on the executable at `path`.
pub fn check_hardened_file(path: &Path) -> Result<Vec<DllName>, String> {
    let file = std::fs::File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    check_hardened(file)
}

/// The DLL names, comma-separated, for the test output.
pub fn joined(names: &[DllName]) -> String {
    names
        .iter()
        .map(DllName::as_str)
        .collect::<Vec<_>>()
        .join(", ")
}

// ---------- Teeth: a minimal PE32+ written here, independent of `detect::pe` ----------

/// A minimal x64 image (offsets from `winnt.h`, written out here on purpose so the teeth do
/// not depend on the parser's own layout): one section `.rdata` at RVA 0x1000 (file offset
/// 0x200, 0x200 bytes) holding the import table at +0x00, the delay-import table at +0x80, the
/// load config at +0x100 and the DLL names from +0x180.
fn image(imports: &[&str], delayed: &[&str], dependent_load_flags: u16) -> Vec<u8> {
    fn put(b: &mut [u8], at: usize, v: &[u8]) {
        b[at..at + v.len()].copy_from_slice(v);
    }
    const OPT: usize = 0x58;
    const RVA: u32 = 0x1000;
    const RAW: usize = 0x200;
    let mut b = vec![0u8; 0x400];
    put(&mut b, 0, b"MZ");
    put(&mut b, 0x3C, &0x40u32.to_le_bytes()); // e_lfanew
    put(&mut b, 0x40, b"PE\0\0");
    put(&mut b, 0x44, &0x8664u16.to_le_bytes()); // Machine: AMD64
    put(&mut b, 0x46, &1u16.to_le_bytes()); // NumberOfSections
    put(&mut b, 0x54, &240u16.to_le_bytes()); // SizeOfOptionalHeader: 112 + 16 x 8
    put(&mut b, 0x56, &0x0022u16.to_le_bytes()); // Characteristics
    put(&mut b, OPT, &0x20Bu16.to_le_bytes()); // Magic: PE32+
    put(&mut b, OPT + 24, &0x1_4000_0000u64.to_le_bytes()); // ImageBase
    put(&mut b, OPT + 60, &0x200u32.to_le_bytes()); // SizeOfHeaders
    put(&mut b, OPT + 68, &3u16.to_le_bytes()); // Subsystem: console
    put(&mut b, OPT + 108, &16u32.to_le_bytes()); // NumberOfRvaAndSizes
    let dir = |b: &mut [u8], index: usize, rva: u32, size: u32| {
        put(b, OPT + 112 + 8 * index, &rva.to_le_bytes());
        put(b, OPT + 116 + 8 * index, &size.to_le_bytes());
    };
    let section = OPT + 240;
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
    put(&mut b, RAW + 0x100, &0x80u32.to_le_bytes()); // IMAGE_LOAD_CONFIG_DIRECTORY64::Size
    put(
        &mut b,
        RAW + 0x100 + 0x4E,
        &dependent_load_flags.to_le_bytes(),
    );
    b
}

#[test]
fn hardening_checks_have_teeth() {
    use std::io::Cursor;
    let check = |imports: &[&str], delayed: &[&str], flags: u16| {
        check_hardened(Cursor::new(image(imports, delayed, flags)))
    };
    // The positive control: a hardened image passes, so the failures below are not about the
    // writer.
    let ok = check(&["KERNEL32.dll", "ntdll.dll"], &[], SEARCH_SYSTEM32).unwrap();
    assert_eq!(joined(&ok), "KERNEL32.dll, ntdll.dll");
    // A graphics import fails, also when it is allowlisted.
    let e = check(&["kernel32.dll", "d3d9.dll"], &[], SEARCH_SYSTEM32).unwrap_err();
    assert!(e.contains("forbidden static import d3d9.dll"), "{e}");
    let d3d9 = image(&["d3d9.dll"], &[], SEARCH_SYSTEM32);
    let mut pe = Pe::parse(Cursor::new(d3d9), &Limits::DEFAULT).unwrap();
    assert!(check_imports(&pe.imports().unwrap(), &["d3d9.dll"]).is_err());
    // An import outside the allowlist, a delay-load import, other or no flags fail.
    let e = check(&["kernel32.dll", "user32.dll"], &[], SEARCH_SYSTEM32).unwrap_err();
    assert!(e.contains("not in the allowlist"), "{e}");
    let e = check(&["kernel32.dll"], &["dxgi.dll"], SEARCH_SYSTEM32).unwrap_err();
    assert!(e.contains("delay-load imports"), "{e}");
    for flags in [0, 0x1000, SEARCH_SYSTEM32 | 0x200] {
        let e = check(&["kernel32.dll"], &[], flags).unwrap_err();
        assert!(e.contains("DependentLoadFlags"), "{e}");
    }
    // Malformed input is an error, never a panic.
    assert!(check_hardened(Cursor::new(b"MZ")).is_err());
    assert!(check_hardened(Cursor::new(b"")).is_err());

    assert!(forbidden_import("D3D11.dll") && forbidden_import("api-ms-win-crt-heap-l1-1-0.dll"));
    assert!(
        !forbidden_import("kernel32.dll") && !forbidden_import("api-ms-win-core-synch-l1-2-0.dll")
    );
}
