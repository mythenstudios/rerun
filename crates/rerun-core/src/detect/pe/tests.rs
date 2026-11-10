//! Headers, section table, RVA mapping, reads and budget (ADR 0013). Every image is synthetic
//! (`testfx`).

use std::io::{self, Cursor, Read, Seek, SeekFrom};

use super::layout as l;
use super::testfx::{Builder, DATA_RVA, dos_exe, new_exe, put16, put32};
use super::{Headers, LegacyFormat, Limits, Machine, Pe, PeError, PeErrorKind, PeFormat};

fn parse(bytes: &[u8]) -> Result<Pe<Cursor<&[u8]>>, PeError> {
    Pe::parse(Cursor::new(bytes), &Limits::DEFAULT)
}

fn parse_with<'a>(bytes: &'a [u8], limits: &Limits) -> Result<Pe<Cursor<&'a [u8]>>, PeError> {
    Pe::parse(Cursor::new(bytes), limits)
}

fn err(bytes: &[u8]) -> (PeErrorKind, Option<u64>) {
    let e = parse(bytes).unwrap_err();
    (e.kind, e.offset)
}

fn headers(bytes: &[u8]) -> Headers {
    parse(bytes).unwrap().headers().clone()
}

fn off(at: usize) -> Option<u64> {
    Some(u64::try_from(at).unwrap())
}

// ---------- Headers ----------

#[test]
fn an_x64_executable_reports_its_headers() {
    let img = Builder::x64().build();
    let h = headers(&img.bytes);
    assert_eq!(
        h,
        Headers {
            machine: Machine::X64,
            format: PeFormat::Pe32Plus,
            characteristics: 0x0022,
            subsystem: l::SUBSYSTEM_WINDOWS_GUI,
            dll_characteristics: 0x8160,
            image_base: 0x1_4000_0000,
            size_of_headers: 0x200,
            section_count: 1,
            managed: false,
        }
    );
    assert!(h.large_address_aware());
    assert!(!h.is_dll());
}

#[test]
fn an_x86_executable_reports_its_headers() {
    let mut b = Builder::x86();
    b.subsystem = l::SUBSYSTEM_WINDOWS_CUI;
    let h = headers(&b.build().bytes);
    assert_eq!(h.machine, Machine::X86);
    assert_eq!(h.format, PeFormat::Pe32);
    assert_eq!(h.image_base, 0x40_0000);
    assert_eq!(h.subsystem, l::SUBSYSTEM_WINDOWS_CUI);
    assert!(!h.large_address_aware());
    b.characteristics |= l::FILE_LARGE_ADDRESS_AWARE | l::FILE_DLL;
    let h = headers(&b.build().bytes);
    assert!(h.large_address_aware() && h.is_dll());
}

#[test]
fn machines_and_formats() {
    let mut b = Builder::x64();
    b.machine = l::MACHINE_ARM64;
    assert_eq!(headers(&b.build().bytes).machine, Machine::Arm64);
    // Another machine is reported raw with either format.
    for magic in [l::OPTIONAL_MAGIC_PE32, l::OPTIONAL_MAGIC_PE32_PLUS] {
        let mut b = Builder::x64();
        b.machine = 0x01C4;
        b.magic = magic;
        b.image_base = 0x40_0000;
        assert_eq!(headers(&b.build().bytes).machine, Machine::Other(0x01C4));
    }
}

#[test]
fn a_machine_that_contradicts_the_format_is_refused() {
    for (machine, magic) in [
        (l::MACHINE_I386, l::OPTIONAL_MAGIC_PE32_PLUS),
        (l::MACHINE_AMD64, l::OPTIONAL_MAGIC_PE32),
        (l::MACHINE_ARM64, l::OPTIONAL_MAGIC_PE32),
    ] {
        let mut b = Builder::x64();
        b.machine = machine;
        b.magic = magic;
        b.image_base = 0x40_0000;
        let img = b.build();
        assert_eq!(
            err(&img.bytes),
            (PeErrorKind::MachineMismatch, off(img.coff))
        );
    }
}

#[test]
fn the_clr_directory_marks_a_managed_image() {
    let mut b = Builder::x86();
    b.dirs = vec![(l::DIR_COM_DESCRIPTOR, DATA_RVA, 0x48)];
    assert!(headers(&b.build().bytes).managed);
    // RVA or size 0 is not a CLR header.
    b.dirs = vec![(l::DIR_COM_DESCRIPTOR, DATA_RVA, 0)];
    assert!(!headers(&b.build().bytes).managed);
    b.dirs = vec![(l::DIR_COM_DESCRIPTOR, 0, 0x48)];
    assert!(!headers(&b.build().bytes).managed);
    // A directory beyond NumberOfRvaAndSizes is not read.
    b.dirs = vec![(l::DIR_COM_DESCRIPTOR, DATA_RVA, 0x48)];
    b.rva_count = 14;
    b.opt_size = Some(u16::try_from(b.fixed() + 16 * 8).unwrap());
    assert!(!headers(&b.build().bytes).managed);
}

// ---------- Not PE ----------

#[test]
fn files_without_mz_are_not_executables() {
    for bytes in [&b""[..], b"M", b"ZM\0\0", b"PE\0\0", b"mz"] {
        assert_eq!(err(bytes), (PeErrorKind::NotExecutable, Some(0)));
    }
    let mut img = Builder::x64().build().bytes;
    img[0] = b'Z';
    assert_eq!(err(&img), (PeErrorKind::NotExecutable, Some(0)));
}

#[test]
fn dos_ne_and_le_executables_are_legacy() {
    let dos = Some(u64::try_from(l::DOS_E_LFANEW).unwrap());
    assert_eq!(
        err(&dos_exe()),
        (PeErrorKind::Legacy(LegacyFormat::Dos), dos)
    );
    // Shorter than the DOS header: e_lfanew is not even there.
    assert_eq!(
        err(b"MZ\x90\0"),
        (PeErrorKind::Legacy(LegacyFormat::Dos), dos)
    );
    assert_eq!(
        err(&new_exe(b"NE")),
        (PeErrorKind::Legacy(LegacyFormat::Ne), Some(0x80))
    );
    for sig in [b"LE", b"LX"] {
        assert_eq!(
            err(&new_exe(sig)),
            (PeErrorKind::Legacy(LegacyFormat::Le), Some(0x80))
        );
    }
    // Anything else at e_lfanew, or an e_lfanew beyond the file, is DOS.
    for sig in [b"PX", b"ne", b"\0\0"] {
        assert_eq!(
            err(&new_exe(sig)),
            (PeErrorKind::Legacy(LegacyFormat::Dos), dos)
        );
    }
    let mut far = new_exe(b"NE");
    put32(&mut far, l::DOS_E_LFANEW, 0x1000);
    assert_eq!(err(&far), (PeErrorKind::Legacy(LegacyFormat::Dos), dos));
    put32(&mut far, l::DOS_E_LFANEW, u32::MAX);
    assert_eq!(err(&far), (PeErrorKind::Legacy(LegacyFormat::Dos), dos));
    // `PE\0` without the last NUL is not PE either.
    let mut pe3 = new_exe(b"PE");
    pe3[0x82] = 0;
    pe3[0x83] = 1;
    assert_eq!(err(&pe3), (PeErrorKind::Legacy(LegacyFormat::Dos), dos));
}

#[test]
fn an_e_lfanew_beyond_the_header_region_is_dos() {
    let mut b = Builder::x64();
    b.e_lfanew = 0x1_0000;
    let img = b.build();
    assert_eq!(
        err(&img.bytes),
        (PeErrorKind::Legacy(LegacyFormat::Dos), off(l::DOS_E_LFANEW))
    );
    // With a larger region it parses.
    let limits = Limits {
        max_header_bytes: 0x2_0000,
        ..Limits::DEFAULT
    };
    assert!(parse_with(&img.bytes, &limits).is_ok());
}

#[test]
fn overlapping_dos_and_nt_headers_are_accepted() {
    // Tiny images put the NT headers inside the DOS header (e_lfanew 4); the loader accepts it.
    let mut b = Builder::x86();
    b.e_lfanew = 4;
    let mut img = b.build().bytes;
    // The DOS header's e_lfanew lies inside the optional header now; keep it consistent.
    put32(&mut img, l::DOS_E_LFANEW, 4);
    let e = parse(&img);
    // Either it parses or it fails on a field the overlap clobbered, never a panic.
    if let Ok(pe) = e {
        assert_eq!(pe.headers().machine, Machine::X86);
    }
}

// ---------- Truncation and the header region ----------

#[test]
fn a_file_ending_inside_the_headers_is_truncated() {
    let img = Builder::x64().build();
    // Inside the COFF header, the optional header and the section table.
    for (cut, at) in [
        (img.coff + 10, img.coff),
        (img.opt + 1, img.opt),
        (img.opt + 40, img.opt),
        (img.table + 39, img.table),
    ] {
        assert_eq!(err(&img.bytes[..cut]), (PeErrorKind::Truncated, off(at)));
    }
    // The section table complete, the section data missing: the headers parse.
    assert!(parse(&img.bytes[..img.table + 40]).is_ok());
}

#[test]
fn the_header_region_limit_is_exact() {
    let mut b = Builder::x64();
    b.extra_sections = 3;
    let img = b.build();
    let end = img.table + 4 * l::SECTION_HEADER_SIZE;
    let at = Limits {
        max_header_bytes: end,
        ..Limits::DEFAULT
    };
    assert!(parse_with(&img.bytes, &at).is_ok());
    let over = Limits {
        max_header_bytes: end - 1,
        ..Limits::DEFAULT
    };
    assert_eq!(
        parse_with(&img.bytes, &over).unwrap_err(),
        PeError::at(PeErrorKind::HeadersOutOfRange, off(img.table).unwrap())
    );
    // An optional header reaching past the region.
    let small = Limits {
        max_header_bytes: img.opt + 100,
        ..Limits::DEFAULT
    };
    assert_eq!(
        parse_with(&img.bytes, &small).unwrap_err(),
        PeError::at(PeErrorKind::HeadersOutOfRange, off(img.opt).unwrap())
    );
}

#[test]
fn sections_up_to_the_limit_are_accepted() {
    let mut b = Builder::x64();
    b.extra_sections = 95;
    let h = headers(&b.build().bytes);
    assert_eq!(h.section_count, 96);
    b.extra_sections = 96;
    let img = b.build();
    assert_eq!(
        err(&img.bytes),
        (
            PeErrorKind::TooManySections,
            off(img.coff + l::FILE_NUMBER_OF_SECTIONS)
        )
    );
    let small = Limits {
        max_sections: 2,
        ..Limits::DEFAULT
    };
    b.extra_sections = 1;
    assert!(parse_with(&b.build().bytes, &small).is_ok());
    b.extra_sections = 2;
    assert_eq!(
        parse_with(&b.build().bytes, &small).unwrap_err().kind,
        PeErrorKind::TooManySections
    );
}

#[test]
fn zero_sections_are_accepted() {
    let img = Builder::x64().build();
    let mut bytes = img.bytes.clone();
    put16(&mut bytes, img.coff + l::FILE_NUMBER_OF_SECTIONS, 0);
    assert_eq!(headers(&bytes).section_count, 0);
}

// ---------- Optional header ----------

#[test]
fn an_unknown_optional_magic_is_refused() {
    for magic in [0x107u16, 0, 0x20C, 0x10A] {
        let mut b = Builder::x64();
        b.magic = magic;
        let img = b.build();
        assert_eq!(
            err(&img.bytes),
            (PeErrorKind::UnknownOptionalMagic, off(img.opt))
        );
    }
}

#[test]
fn the_optional_header_size_must_cover_its_fields() {
    let size_at = |img: &super::testfx::Image| off(img.coff + l::FILE_SIZE_OF_OPTIONAL_HEADER);
    for b in [Builder::x86(), Builder::x64()] {
        let fixed = b.fixed();
        // Fixed part plus every directory read: accepted at the size, refused one below.
        for (rva_count, dirs) in [(16, 16), (3, 3), (0, 0), (u32::MAX, 16), (17, 16)] {
            let mut c = b.clone();
            c.rva_count = rva_count;
            c.opt_size = Some(u16::try_from(fixed + dirs * 8).unwrap());
            assert!(parse(&c.build().bytes).is_ok(), "{rva_count}");
            if fixed + dirs * 8 > fixed {
                c.opt_size = Some(u16::try_from(fixed + dirs * 8 - 1).unwrap());
                let img = c.build();
                assert_eq!(
                    err(&img.bytes),
                    (PeErrorKind::BadOptionalHeaderSize, size_at(&img)),
                    "{rva_count}"
                );
            }
        }
        for size in [0u16, 1, u16::try_from(fixed - 1).unwrap()] {
            let mut c = b.clone();
            c.rva_count = 0;
            c.opt_size = Some(size);
            let img = c.build();
            let e = err(&img.bytes);
            assert_eq!(
                e,
                (PeErrorKind::BadOptionalHeaderSize, size_at(&img)),
                "{size}"
            );
        }
        // A larger optional header than needed is fine (the table follows it).
        let mut c = b.clone();
        c.opt_size = Some(u16::try_from(fixed + 16 * 8 + 64).unwrap());
        let img = c.build();
        assert_eq!(headers(&img.bytes).section_count, 1);
    }
}

// ---------- RVA mapping ----------

#[test]
fn rvas_map_through_the_sections_and_the_headers() {
    let mut b = Builder::x64();
    b.data = vec![0xAB; 0x300];
    b.extra_sections = 1;
    let img = b.build();
    let mut bytes = img.bytes.clone();
    let s0 = img.table;
    let s1 = img.table + l::SECTION_HEADER_SIZE;
    // Data section: VirtualSize 0x3000, raw 0x400 (two file-aligned blocks of 0x300 bytes).
    put32(&mut bytes, s0 + l::SECTION_VIRTUAL_SIZE, 0x3000);
    let pe = parse(&bytes).unwrap();
    let map = |rva| pe.layout.map(rva);
    let data = u64::try_from(img.data).unwrap();
    assert_eq!(map(DATA_RVA).unwrap().offset, data);
    assert_eq!(map(DATA_RVA).unwrap().available, 0x400);
    assert_eq!(map(DATA_RVA + 0x3FF).unwrap().offset, data + 0x3FF);
    assert_eq!(map(DATA_RVA + 0x3FF).unwrap().available, 1);
    assert_eq!(map(DATA_RVA + 0x400), Err(PeErrorKind::RvaNotBacked));
    assert_eq!(map(DATA_RVA + 0x2FFF), Err(PeErrorKind::RvaNotBacked));
    assert_eq!(map(DATA_RVA + 0x3000), Err(PeErrorKind::RvaNotMapped));
    // Below SizeOfHeaders an RVA is its own file offset.
    assert_eq!(map(0).unwrap().offset, 0);
    assert_eq!(map(0x1FF).unwrap().available, 1);
    assert_eq!(map(0x200), Err(PeErrorKind::RvaNotMapped));
    assert_eq!(map(u32::MAX), Err(PeErrorKind::RvaNotMapped));

    // VirtualSize 0: the extent is SizeOfRawData.
    put32(&mut bytes, s0 + l::SECTION_VIRTUAL_SIZE, 0);
    let pe = parse(&bytes).unwrap();
    assert_eq!(pe.layout.map(DATA_RVA + 0x3FF).unwrap().available, 1);
    assert_eq!(
        pe.layout.map(DATA_RVA + 0x400),
        Err(PeErrorKind::RvaNotMapped)
    );

    // VirtualSize smaller than the raw data: only the extent is backed.
    put32(&mut bytes, s0 + l::SECTION_VIRTUAL_SIZE, 0x10);
    let pe = parse(&bytes).unwrap();
    assert_eq!(pe.layout.map(DATA_RVA + 0xF).unwrap().available, 1);
    assert_eq!(
        pe.layout.map(DATA_RVA + 0x10),
        Err(PeErrorKind::RvaNotMapped)
    );

    // Overlapping sections: the first in table order wins.
    put32(&mut bytes, s0 + l::SECTION_VIRTUAL_SIZE, 0x300);
    put32(&mut bytes, s1 + l::SECTION_VIRTUAL_ADDRESS, DATA_RVA);
    put32(&mut bytes, s1 + l::SECTION_SIZE_OF_RAW_DATA, 0x200);
    put32(&mut bytes, s1 + l::SECTION_POINTER_TO_RAW_DATA, 0x0);
    let pe = parse(&bytes).unwrap();
    assert_eq!(pe.layout.map(DATA_RVA).unwrap().offset, data);
    // A section near u32::MAX does not overflow.
    put32(&mut bytes, s1 + l::SECTION_VIRTUAL_ADDRESS, u32::MAX - 4);
    put32(&mut bytes, s1 + l::SECTION_VIRTUAL_SIZE, u32::MAX);
    put32(&mut bytes, s1 + l::SECTION_POINTER_TO_RAW_DATA, u32::MAX);
    let pe = parse(&bytes).unwrap();
    let m = pe.layout.map(u32::MAX).unwrap();
    assert_eq!(m.offset, u64::from(u32::MAX) + 4);
    assert_eq!(m.clamp(usize::MAX), 0x200 - 4);
}

// ---------- Reads, budget, I/O errors ----------

/// A reader around a buffer that counts what is requested and fails or misbehaves on demand.
#[derive(Debug)]
struct Probe<'a> {
    inner: Cursor<&'a [u8]>,
    reads: u64,
    interrupts: u32,
    fail: Option<io::ErrorKind>,
    overclaim: bool,
}

impl<'a> Probe<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self {
            inner: Cursor::new(bytes),
            reads: 0,
            interrupts: 0,
            fail: None,
            overclaim: false,
        }
    }
}

impl Read for Probe<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.reads += 1;
        if self.interrupts > 0 {
            self.interrupts -= 1;
            return Err(io::Error::from(io::ErrorKind::Interrupted));
        }
        if let Some(kind) = self.fail {
            return Err(io::Error::new(kind, "SECRETMARKER from the device"));
        }
        // At most 7 bytes per call, so the read loop is exercised.
        let len = buf.len().min(7);
        let n = self.inner.read(&mut buf[..len])?;
        Ok(if self.overclaim && n > 0 {
            buf.len() + 100
        } else {
            n
        })
    }
}

impl Seek for Probe<'_> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.inner.seek(pos)
    }
}

#[test]
fn the_header_read_is_charged_with_its_requested_length() {
    let img = Builder::x64().build();
    let pe = parse(&img.bytes).unwrap();
    assert_eq!(
        pe.bytes_read(),
        u64::try_from(Limits::DEFAULT.max_header_bytes).unwrap()
    );
    // A budget of exactly the header region is enough, one byte less is not.
    let exact = Limits {
        max_read_bytes: 64 << 10,
        ..Limits::DEFAULT
    };
    assert!(parse_with(&img.bytes, &exact).is_ok());
    let short = Limits {
        max_read_bytes: (64 << 10) - 1,
        ..Limits::DEFAULT
    };
    assert_eq!(
        parse_with(&img.bytes, &short).unwrap_err(),
        PeError::at(PeErrorKind::ReadBudget, 0)
    );
}

#[test]
fn reads_go_through_short_reads_and_interrupts() {
    let img = Builder::x64().build();
    let mut probe = Probe::new(&img.bytes);
    probe.interrupts = 3;
    let pe = Pe::parse(&mut probe, &Limits::DEFAULT).unwrap();
    assert_eq!(pe.headers().machine, Machine::X64);
    assert!(probe.reads > 3);
    // Endless interrupts end as an error.
    let mut probe = Probe::new(&img.bytes);
    probe.interrupts = u32::MAX;
    assert_eq!(
        Pe::parse(&mut probe, &Limits::DEFAULT).unwrap_err(),
        PeError::at(PeErrorKind::Io(io::ErrorKind::Interrupted), 0)
    );
    assert_eq!(probe.reads, 17);
}

#[test]
fn a_reader_claiming_more_than_the_buffer_does_not_panic() {
    let img = Builder::x64().build();
    let mut probe = Probe::new(&img.bytes);
    probe.overclaim = true;
    // The first read fills 7 bytes but claims the whole buffer: the region is "full" and
    // mostly zero, so the result is an error or not, but never a panic.
    let _ = Pe::parse(&mut probe, &Limits::DEFAULT);
}

#[test]
fn io_errors_keep_only_their_kind() {
    let img = Builder::x64().build();
    let mut probe = Probe::new(&img.bytes);
    probe.fail = Some(io::ErrorKind::InvalidData);
    let e = Pe::parse(&mut probe, &Limits::DEFAULT).unwrap_err();
    assert_eq!(
        e,
        PeError::at(PeErrorKind::Io(io::ErrorKind::InvalidData), 0)
    );
    assert!(!format!("{e} / {e:?}").contains("SECRET"));
}

#[test]
fn the_reader_is_handed_back() {
    let img = Builder::x64().build();
    let pe = parse(&img.bytes).unwrap();
    let cursor = pe.into_inner();
    assert_eq!(cursor.get_ref().len(), img.bytes.len());
    // By `&mut`, the reader stays with the caller even after an error.
    let mut cursor = Cursor::new(&b"MZ"[..]);
    assert!(Pe::parse(&mut cursor, &Limits::DEFAULT).is_err());
    assert_eq!(cursor.get_ref().len(), 2);
}

#[test]
fn error_messages_name_kind_and_offset_only() {
    let img = Builder::x64().build();
    let mut bytes = img.bytes.clone();
    put16(&mut bytes, img.opt, 0x107);
    let e = parse(&bytes).unwrap_err();
    assert_eq!(
        e.to_string(),
        format!("unknown optional header magic at offset {:#x}", img.opt)
    );
    let e = PeError {
        kind: PeErrorKind::Legacy(LegacyFormat::Ne),
        offset: None,
    };
    assert_eq!(e.to_string(), "16-bit Windows (NE) executable, not PE");
}

// ---------- Fuzzing ----------

/// xorshift64*, deterministic.
pub(super) struct Rng(pub u64);

impl Rng {
    pub fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    pub fn below(&mut self, n: usize) -> usize {
        usize::try_from(self.next() % u64::try_from(n).unwrap()).unwrap()
    }
}

/// Values that hit edges when written over a header field.
const EDGES: &[u32] = &[
    0,
    1,
    2,
    0x10,
    0x7F,
    0x80,
    0xFF,
    0x1000,
    0xFFFF,
    0x7FFF_FFFF,
    u32::MAX,
];

/// One mutation of `bytes`: a byte flip, an edge value over a field, a cut or a duplicated
/// slice; most mutations aim at the header region.
pub(super) fn mutate(rng: &mut Rng, bytes: &mut Vec<u8>, hot: usize) {
    let len = bytes.len().max(1);
    let at = if rng.below(4) == 0 {
        rng.below(len)
    } else {
        rng.below(hot.min(len).max(1))
    };
    match rng.below(5) {
        0 => {
            if let Some(b) = bytes.get_mut(at) {
                *b ^= 1 << rng.below(8);
            }
        }
        1 | 2 => {
            let v = EDGES[rng.below(EDGES.len())].to_le_bytes();
            let n = [1, 2, 4][rng.below(3)];
            for (i, b) in v.iter().take(n).enumerate() {
                if let Some(t) = bytes.get_mut(at + i) {
                    *t = *b;
                }
            }
        }
        3 => bytes.truncate(at),
        _ => {
            let end = (at + rng.below(64)).min(bytes.len());
            let slice = bytes[at.min(end)..end].to_vec();
            let to = rng.below(len).min(bytes.len());
            bytes.splice(to..to, slice);
        }
    }
}

#[test]
fn mutated_headers_never_panic_and_stay_within_limits() {
    let seeds = [Builder::x64(), Builder::x86(), {
        let mut b = Builder::x64();
        b.extra_sections = 5;
        b.dirs = vec![(l::DIR_COM_DESCRIPTOR, DATA_RVA, 8)];
        b
    }];
    let small = Limits {
        max_header_bytes: 0x300,
        max_sections: 4,
        ..Limits::DEFAULT
    };
    let mut rng = Rng(0x5EED_0013_0000_0001);
    let (mut ok, mut failed) = (0, 0);
    for round in 0..20_000 {
        let seed = &seeds[round % seeds.len()];
        let img = seed.build();
        let mut bytes = img.bytes.clone();
        for _ in 0..1 + rng.below(4) {
            mutate(&mut rng, &mut bytes, img.table + 6 * l::SECTION_HEADER_SIZE);
        }
        let limits = if round % 4 == 0 {
            small
        } else {
            Limits::DEFAULT
        };
        match parse_with(&bytes, &limits) {
            Ok(pe) => {
                ok += 1;
                assert!(usize::from(pe.headers().section_count) <= limits.max_sections);
                assert!(pe.bytes_read() <= limits.max_read_bytes);
            }
            Err(e) => {
                failed += 1;
                // Offsets lie in the header region or the section table that follows the
                // optional header (`SizeOfOptionalHeader` is a `u16`).
                if let Some(at) = e.offset {
                    let bound = limits.max_header_bytes + 0x1_0000 + 20;
                    assert!(at <= u64::try_from(bound).unwrap(), "{e}");
                }
            }
        }
    }
    assert!(ok > 1000 && failed > 1000, "ok {ok}, failed {failed}");
}

// ---------- Image fields (P4-10) ----------

/// The offsets `laa_patch` edits, the stored checksum, the certificate table and the section
/// names, for both formats and an `e_lfanew` that is not the usual one.
#[test]
fn image_fields_name_the_offsets_and_names() {
    for (mut b, e) in [(Builder::x86(), 0x80u32), (Builder::x64(), 0xE8)] {
        b.e_lfanew = e;
        b.checksum = 0x0001_2345;
        b.extra_sections = 2;
        b.extra_names = vec![*b".bind\0\0\0"];
        b.dirs = vec![(l::DIR_SECURITY, 0x0000_0400, 0x30)];
        let img = b.build();
        let f = parse(&img.bytes).unwrap().image_fields();
        assert_eq!(f.characteristics_at, off(img.coff + 18).unwrap());
        assert_eq!(f.checksum_at, off(img.opt + 64).unwrap());
        assert_eq!(f.checksum, 0x0001_2345);
        assert_eq!(f.certificates, Some((0x400, 0x30)));
        assert_eq!(
            f.section_names,
            [*b".rdata\0\0", *b".bind\0\0\0", *b".bss\0\0\0\0"]
        );
        let at = usize::try_from(f.characteristics_at).unwrap();
        assert_eq!(
            u16::from_le_bytes([img.bytes[at], img.bytes[at + 1]]),
            b.characteristics
        );
    }
    // No certificate table: a directory entry with a zero size is none.
    let mut b = Builder::x86();
    b.dirs = vec![(l::DIR_SECURITY, 0x400, 0)];
    assert_eq!(
        parse(&b.build().bytes).unwrap().image_fields().certificates,
        None
    );
}
