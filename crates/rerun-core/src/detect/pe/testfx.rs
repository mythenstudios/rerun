//! Test-only builder for synthetic PE images (ADR 0013, `docs/09-testing.md`, "PE parser").
//! Every image, name and string is invented.
//!
//! Layout of a built image: DOS header, NT headers at `e_lfanew`, the section table, padding to
//! `SizeOfHeaders` (a multiple of 0x200); then one data section `.rdata` at RVA [`DATA_RVA`]
//! holding [`Builder::data`], then `extra_sections` empty sections without file data.

use super::layout as l;

/// RVA of the data section.
pub(super) const DATA_RVA: u32 = 0x1000;
/// File alignment of the built images.
pub(super) const FILE_ALIGN: usize = 0x200;

/// Writes `v` little-endian at `at`, growing `b` if needed.
pub(super) fn put(b: &mut Vec<u8>, at: usize, v: &[u8]) {
    if b.len() < at + v.len() {
        b.resize(at + v.len(), 0);
    }
    b[at..at + v.len()].copy_from_slice(v);
}

pub(super) fn put16(b: &mut Vec<u8>, at: usize, v: u16) {
    put(b, at, &v.to_le_bytes());
}

pub(super) fn put32(b: &mut Vec<u8>, at: usize, v: u32) {
    put(b, at, &v.to_le_bytes());
}

fn align(v: usize, to: usize) -> usize {
    v.div_ceil(to) * to
}

/// A synthetic image to build.
#[derive(Debug, Clone)]
pub(super) struct Builder {
    pub machine: u16,
    pub magic: u16,
    pub characteristics: u16,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub image_base: u64,
    pub e_lfanew: u32,
    /// `NumberOfRvaAndSizes`.
    pub rva_count: u32,
    /// `SizeOfOptionalHeader`; `None`: the fixed part plus `min(rva_count, 16)` directories.
    pub opt_size: Option<u16>,
    /// Empty sections after the data section (no file data).
    pub extra_sections: usize,
    /// Data directories `(index, rva, size)`, written in this order.
    pub dirs: Vec<(usize, u32, u32)>,
    /// Content of the data section.
    pub data: Vec<u8>,
}

/// A built image and where its parts are.
#[derive(Debug, Clone)]
pub(super) struct Image {
    pub bytes: Vec<u8>,
    /// File offset of the COFF file header.
    pub coff: usize,
    /// File offset of the optional header.
    pub opt: usize,
    /// File offset of the section table.
    pub table: usize,
    /// File offset of the data section.
    pub data: usize,
}

impl Builder {
    /// An x64 GUI executable (PE32+), nothing imported.
    pub fn x64() -> Self {
        Self {
            machine: l::MACHINE_AMD64,
            magic: l::OPTIONAL_MAGIC_PE32_PLUS,
            characteristics: 0x0022,
            subsystem: l::SUBSYSTEM_WINDOWS_GUI,
            dll_characteristics: 0x8160,
            image_base: 0x1_4000_0000,
            e_lfanew: 0x80,
            rva_count: 16,
            opt_size: None,
            extra_sections: 0,
            dirs: Vec::new(),
            data: Vec::new(),
        }
    }

    /// An x86 GUI executable (PE32), not Large Address Aware, nothing imported.
    pub fn x86() -> Self {
        Self {
            machine: l::MACHINE_I386,
            magic: l::OPTIONAL_MAGIC_PE32,
            characteristics: 0x0102,
            dll_characteristics: 0x8140,
            image_base: 0x40_0000,
            ..Self::x64()
        }
    }

    /// Size of the fixed part of the optional header for `magic`.
    pub fn fixed(&self) -> usize {
        if self.magic == l::OPTIONAL_MAGIC_PE32 {
            l::OPT32_DATA_DIRECTORY
        } else {
            l::OPT64_DATA_DIRECTORY
        }
    }

    pub fn build(&self) -> Image {
        let e = usize::try_from(self.e_lfanew).unwrap();
        let coff = e + 4;
        let opt = coff + l::FILE_HEADER_SIZE;
        let fixed = self.fixed();
        let dirs = usize::try_from(self.rva_count).unwrap().min(16);
        let opt_size = self.opt_size.map_or(fixed + dirs * 8, usize::from);
        let table = opt + opt_size;
        let sections = 1 + self.extra_sections;
        let headers_end = table + sections * l::SECTION_HEADER_SIZE;
        let size_of_headers = align(headers_end.max(l::DOS_HEADER_SIZE), FILE_ALIGN);
        let data_len = self.data.len().max(1);
        let raw_size = align(data_len, FILE_ALIGN);

        let mut b = vec![0u8; size_of_headers];
        put(&mut b, 0, l::DOS_SIGNATURE);
        put32(&mut b, l::DOS_E_LFANEW, self.e_lfanew);
        put(&mut b, e, l::NT_SIGNATURE);
        put16(&mut b, coff + l::FILE_MACHINE, self.machine);
        put16(
            &mut b,
            coff + l::FILE_NUMBER_OF_SECTIONS,
            u16::try_from(sections).unwrap(),
        );
        put16(
            &mut b,
            coff + l::FILE_SIZE_OF_OPTIONAL_HEADER,
            u16::try_from(opt_size).unwrap(),
        );
        put16(&mut b, coff + l::FILE_CHARACTERISTICS, self.characteristics);
        // The optional header fields are written only where `opt_size` leaves room, so a
        // too small header does not overwrite the section table.
        let opt_field = |b: &mut Vec<u8>, at: usize, v: &[u8]| {
            if at + v.len() <= opt_size {
                put(b, opt + at, v);
            }
        };
        opt_field(&mut b, l::OPT_MAGIC, &self.magic.to_le_bytes());
        if self.magic == l::OPTIONAL_MAGIC_PE32 {
            let base = u32::try_from(self.image_base).unwrap();
            opt_field(&mut b, l::OPT32_IMAGE_BASE, &base.to_le_bytes());
            opt_field(
                &mut b,
                l::OPT32_NUMBER_OF_RVA_AND_SIZES,
                &self.rva_count.to_le_bytes(),
            );
        } else {
            opt_field(&mut b, l::OPT64_IMAGE_BASE, &self.image_base.to_le_bytes());
            opt_field(
                &mut b,
                l::OPT64_NUMBER_OF_RVA_AND_SIZES,
                &self.rva_count.to_le_bytes(),
            );
        }
        let soh = u32::try_from(size_of_headers).unwrap();
        opt_field(&mut b, l::OPT_SIZE_OF_HEADERS, &soh.to_le_bytes());
        opt_field(&mut b, l::OPT_SUBSYSTEM, &self.subsystem.to_le_bytes());
        opt_field(
            &mut b,
            l::OPT_DLL_CHARACTERISTICS,
            &self.dll_characteristics.to_le_bytes(),
        );
        for &(index, rva, size) in &self.dirs {
            let at = fixed + index * l::DATA_DIRECTORY_SIZE;
            opt_field(&mut b, at, &rva.to_le_bytes());
            opt_field(&mut b, at + 4, &size.to_le_bytes());
        }

        // Section table: the data section, then empty ones far above it.
        let section = |b: &mut Vec<u8>, i: usize, name: &[u8], va: u32, vs: u32, rs, rp| {
            let s = table + i * l::SECTION_HEADER_SIZE;
            put(b, s, name);
            put32(b, s + l::SECTION_VIRTUAL_SIZE, vs);
            put32(b, s + l::SECTION_VIRTUAL_ADDRESS, va);
            put32(b, s + l::SECTION_SIZE_OF_RAW_DATA, rs);
            put32(b, s + l::SECTION_POINTER_TO_RAW_DATA, rp);
        };
        section(
            &mut b,
            0,
            b".rdata\0\0",
            DATA_RVA,
            u32::try_from(data_len).unwrap(),
            u32::try_from(raw_size).unwrap(),
            soh,
        );
        for i in 0..self.extra_sections {
            let va = 0x0100_0000 + u32::try_from(i).unwrap() * 0x1000;
            section(&mut b, i + 1, b".bss\0\0\0\0", va, 0x1000, 0, 0);
        }
        b.resize(size_of_headers + raw_size, 0);
        put(&mut b, size_of_headers, &self.data);
        Image {
            bytes: b,
            coff,
            opt,
            table,
            data: size_of_headers,
        }
    }
}

/// A plain DOS executable: `MZ`, a 64-byte header, `e_lfanew` 0, some code.
pub(super) fn dos_exe() -> Vec<u8> {
    let mut b = vec![0u8; 0x80];
    put(&mut b, 0, l::DOS_SIGNATURE);
    put(&mut b, 0x40, b"\xB4\x4C\xCD\x21");
    b
}

/// An `MZ` stub with a new-executable signature `sig` at `e_lfanew` 0x80.
pub(super) fn new_exe(sig: &[u8; 2]) -> Vec<u8> {
    let mut b = vec![0u8; 0x200];
    put(&mut b, 0, l::DOS_SIGNATURE);
    put32(&mut b, l::DOS_E_LFANEW, 0x80);
    put(&mut b, 0x80, sig);
    b
}
