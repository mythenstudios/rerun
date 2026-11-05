//! Minimal, bounds-checked PE32+ reader for the DLL hardening tests of the shipped executables
//! (ADR 0008, H2; `crates/rerun-cli/tests/hardening.rs`, `crates/rerun-launch/tests/
//! hardening.rs`, included there with `#[path]`). It reads only what those tests check: the
//! import and delay-import DLL names and `IMAGE_LOAD_CONFIG_DIRECTORY64::DependentLoadFlags`.
//! Every read is a checked slice access; malformed input is an `Err`, never a panic. Step 13
//! replaces it with `rerun_core::detect::pe`.

#![allow(
    dead_code,
    reason = "shared by several test crates (#[path]); each uses a part of it"
)]

/// `IMAGE_NT_OPTIONAL_HDR64_MAGIC`.
const PE32_PLUS: u16 = 0x20B;
/// Data directory indices (winnt.h `IMAGE_DIRECTORY_ENTRY_*`).
const DIR_IMPORT: usize = 1;
const DIR_LOAD_CONFIG: usize = 10;
const DIR_DELAY_IMPORT: usize = 13;
/// Offset of `DependentLoadFlags` in `IMAGE_LOAD_CONFIG_DIRECTORY64` (winnt.h, SDK 10.0.26100:
/// eleven fields up to `ProcessHeapFlags` at 0x48, `CSDVersion` at 0x4C).
pub const DEPENDENT_LOAD_FLAGS: usize = 0x4E;
/// Upper bound for import descriptors and name lengths (no real binary comes close).
const MAX_ENTRIES: usize = 4096;
const MAX_NAME: usize = 256;

fn u16_at(d: &[u8], at: usize) -> Result<u16, String> {
    let b = d
        .get(at..at.checked_add(2).ok_or("offset overflow")?)
        .ok_or(format!("u16 at {at:#x} out of bounds"))?;
    Ok(u16::from_le_bytes([b[0], b[1]]))
}

fn u32_at(d: &[u8], at: usize) -> Result<u32, String> {
    let b = d
        .get(at..at.checked_add(4).ok_or("offset overflow")?)
        .ok_or(format!("u32 at {at:#x} out of bounds"))?;
    Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn us(v: u32) -> Result<usize, String> {
    usize::try_from(v).map_err(|e| e.to_string())
}

struct Section {
    va: u32,
    size: u32,
    raw_ptr: u32,
    raw_size: u32,
}

/// A parsed PE32+ image (headers only; the data stays borrowed).
pub struct Pe<'a> {
    data: &'a [u8],
    dirs: Vec<(u32, u32)>,
    sections: Vec<Section>,
}

impl<'a> Pe<'a> {
    /// Parses the DOS, NT and optional headers, the data directories and the section table.
    pub fn parse(data: &'a [u8]) -> Result<Self, String> {
        if data.get(..2) != Some(b"MZ") {
            return Err("no MZ header".into());
        }
        let nt = us(u32_at(data, 0x3C)?)?;
        if data.get(nt..nt.checked_add(4).ok_or("offset overflow")?) != Some(b"PE\0\0") {
            return Err("no PE signature".into());
        }
        let coff = nt + 4;
        let sections = usize::from(u16_at(data, coff + 2)?);
        let opt_size = usize::from(u16_at(data, coff + 16)?);
        let opt = coff + 20;
        let magic = u16_at(data, opt)?;
        if magic != PE32_PLUS {
            return Err(format!("optional header magic {magic:#x}, expected PE32+"));
        }
        let dir_count = us(u32_at(data, opt + 108)?)?.min(16);
        if 112 + dir_count * 8 > opt_size {
            return Err("data directories exceed the optional header".into());
        }
        let dirs = (0..dir_count)
            .map(|i| {
                Ok((
                    u32_at(data, opt + 112 + i * 8)?,
                    u32_at(data, opt + 116 + i * 8)?,
                ))
            })
            .collect::<Result<Vec<_>, String>>()?;
        let table = opt + opt_size;
        let sections = (0..sections)
            .map(|i| {
                let s = table + i * 40;
                Ok(Section {
                    size: u32_at(data, s + 8)?,
                    va: u32_at(data, s + 12)?,
                    raw_size: u32_at(data, s + 16)?,
                    raw_ptr: u32_at(data, s + 20)?,
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        Ok(Self {
            data,
            dirs,
            sections,
        })
    }

    /// File offset of `rva`, if a section maps it to file data.
    fn offset(&self, rva: u32) -> Result<usize, String> {
        let s = self
            .sections
            .iter()
            .find(|s| rva >= s.va && rva - s.va < s.size.max(s.raw_size))
            .ok_or(format!("rva {rva:#x} in no section"))?;
        let delta = rva - s.va;
        if delta >= s.raw_size {
            return Err(format!("rva {rva:#x} not backed by file data"));
        }
        let at = us(s.raw_ptr)?
            .checked_add(us(delta)?)
            .ok_or("offset overflow")?;
        if at >= self.data.len() {
            return Err(format!("rva {rva:#x} beyond the file"));
        }
        Ok(at)
    }

    fn dir(&self, i: usize) -> Option<(u32, u32)> {
        self.dirs.get(i).copied().filter(|&(rva, _)| rva != 0)
    }

    /// NUL-terminated ASCII name at `rva`.
    fn name(&self, rva: u32) -> Result<String, String> {
        let at = self.offset(rva)?;
        let tail = &self.data[at..];
        let len = tail
            .iter()
            .take(MAX_NAME)
            .position(|&b| b == 0)
            .ok_or(format!("name at {rva:#x} not terminated"))?;
        let name = &tail[..len];
        if !name.is_ascii() {
            return Err(format!("name at {rva:#x} is not ASCII"));
        }
        Ok(String::from_utf8_lossy(name).into_owned())
    }

    /// DLL names of a descriptor table: `stride` bytes per descriptor, the name RVA at
    /// `name_at`, terminated by an all-zero descriptor.
    fn names(&self, dir: usize, stride: usize, name_at: usize) -> Result<Vec<String>, String> {
        let Some((rva, _)) = self.dir(dir) else {
            return Ok(Vec::new());
        };
        let start = self.offset(rva)?;
        let mut out = Vec::new();
        for i in 0..MAX_ENTRIES {
            let d = start + i * stride;
            let raw = self
                .data
                .get(d..d + stride)
                .ok_or(format!("descriptor {i} out of bounds"))?;
            if raw.iter().all(|&b| b == 0) {
                return Ok(out);
            }
            out.push(self.name(u32_at(self.data, d + name_at)?)?);
        }
        Err("descriptor table not terminated".into())
    }

    /// DLL names of the import directory (`IMAGE_IMPORT_DESCRIPTOR`: 20 bytes, `Name` at 12).
    pub fn imports(&self) -> Result<Vec<String>, String> {
        self.names(DIR_IMPORT, 20, 12)
    }

    /// DLL names of the delay-import directory (`IMAGE_DELAYLOAD_DESCRIPTOR`: 32 bytes,
    /// `DllNameRVA` at 4).
    pub fn delay_imports(&self) -> Result<Vec<String>, String> {
        self.names(DIR_DELAY_IMPORT, 32, 4)
    }

    /// `DependentLoadFlags` of the load config directory; `None` without a load config or if
    /// its `Size` does not reach the field.
    pub fn dependent_load_flags(&self) -> Result<Option<u16>, String> {
        let Some((rva, _)) = self.dir(DIR_LOAD_CONFIG) else {
            return Ok(None);
        };
        let at = self.offset(rva)?;
        if us(u32_at(self.data, at)?)? < DEPENDENT_LOAD_FLAGS + 2 {
            return Ok(None);
        }
        u16_at(self.data, at + DEPENDENT_LOAD_FLAGS).map(Some)
    }
}

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
pub fn check_imports(imports: &[String], allowed: &[&str]) -> Result<(), String> {
    if let Some(bad) = imports.iter().find(|d| forbidden_import(d)) {
        return Err(format!(
            "forbidden static import {bad} (imports: {imports:?})"
        ));
    }
    let new: Vec<&String> = imports
        .iter()
        .filter(|d| !allowed.iter().any(|a| a.eq_ignore_ascii_case(d)))
        .collect();
    if !new.is_empty() {
        return Err(format!(
            "static imports not in the allowlist: {new:?} (all: {imports:?}); review them, then              update the allowlist in tests/support/pe_min.rs and ADR 0008 (amendment 2026-11-05)"
        ));
    }
    Ok(())
}

/// Checks a built executable (ADR 0008, H2): `DependentLoadFlags` is exactly System32, every
/// static import is in [`SHIPPED_IMPORTS`], no delay-load import. Returns the imported DLL
/// names.
pub fn check_hardened(image: &[u8]) -> Result<Vec<String>, String> {
    let pe = Pe::parse(image)?;
    let flags = pe.dependent_load_flags()?;
    if flags != Some(SEARCH_SYSTEM32) {
        return Err(format!(
            "DependentLoadFlags is {flags:x?}, expected {SEARCH_SYSTEM32:#x} (System32 only)"
        ));
    }
    let imports = pe.imports()?;
    check_imports(&imports, SHIPPED_IMPORTS)?;
    let delayed = pe.delay_imports()?;
    if !delayed.is_empty() {
        return Err(format!("delay-load imports {delayed:?}"));
    }
    Ok(imports)
}

#[test]
fn pe_min_refuses_malformed_input_without_panicking() {
    assert!(Pe::parse(b"").is_err());
    assert!(Pe::parse(b"MZ").is_err());
    let mut d = vec![0u8; 0x200];
    d[..2].copy_from_slice(b"MZ");
    d[0x3C..0x40].copy_from_slice(&0x40u32.to_le_bytes());
    d[0x40..0x44].copy_from_slice(b"PE\0\0");
    // A PE32 magic is refused; a truncated or huge e_lfanew is out of bounds.
    d[0x58..0x5A].copy_from_slice(&0x10Bu16.to_le_bytes());
    assert!(Pe::parse(&d).is_err());
    d[0x3C..0x40].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(Pe::parse(&d).is_err());
    assert!(forbidden_import("D3D11.dll") && forbidden_import("api-ms-win-crt-heap-l1-1-0.dll"));
    assert!(
        !forbidden_import("kernel32.dll") && !forbidden_import("api-ms-win-core-synch-l1-2-0.dll")
    );
    let names = |v: &[&str]| v.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
    assert!(check_imports(&names(&["KERNEL32.dll", "ntdll.dll"]), SHIPPED_IMPORTS).is_ok());
    assert!(check_imports(&names(&["kernel32.dll", "user32.dll"]), SHIPPED_IMPORTS).is_err());
    assert!(
        check_imports(
            &names(&["api-ms-win-core-file-l1-1-0.dll"]),
            SHIPPED_IMPORTS
        )
        .is_err()
    );
    assert!(check_imports(&names(&["dxgi.dll"]), &["dxgi.dll"]).is_err());
}
