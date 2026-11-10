//! The archive readers (ADR 0025 part 2) against hand-written archives: what they read, and the
//! zip-slip and damage corpus (docs/09-testing.md, "Package archives"). Every archive is built
//! here; nothing is downloaded.

use std::io::Read;

use super::testfx::{
    Descriptor, TarEntry, ZipEntry, gzip, put16, put32, tar, tar_gz, zip, zip_layout,
};
use super::{Archive, ArchiveError, EntryKind, Extraction, Format, Limits};
use crate::path::RelPath;

fn rel(s: &str) -> RelPath {
    RelPath::parse(s).unwrap()
}

fn open(b: &[u8], f: Format) -> Result<Archive<'_>, ArchiveError> {
    Archive::open(b, f, &Limits::DEFAULT)
}

/// The content of `name`, extracted.
fn read(a: &Archive<'_>, name: &str) -> Result<Vec<u8>, ArchiveError> {
    let i = a.find(&rel(name))?;
    let mut got = Vec::new();
    let r = a.extract::<std::io::Error>(&[i], &mut |_, r| {
        r.read_to_end(&mut got)?;
        Ok(())
    });
    match r {
        Ok(()) => Ok(got),
        Err(Extraction::Archive(e)) => Err(e),
        Err(Extraction::Sink(e)) => panic!("sink: {e}"),
    }
}

/// Every file of the archive, extracted.
fn read_every(a: &Archive<'_>) -> Result<Vec<(String, Vec<u8>)>, ArchiveError> {
    let files: Vec<String> = a
        .entries()
        .iter()
        .filter(|e| e.kind == EntryKind::File)
        .map(|e| e.name.as_str().to_owned())
        .collect();
    files
        .into_iter()
        .map(|n| read(a, &n).map(|c| (n, c)))
        .collect()
}

fn names(a: &Archive<'_>) -> Vec<(String, EntryKind, u64)> {
    a.entries()
        .iter()
        .map(|e| (e.name.as_str().to_owned(), e.kind, e.size))
        .collect()
}

// ---------- What is read ----------

#[test]
fn formats_come_from_the_file_name() {
    assert_eq!(Format::of_file_name("x.zip"), Some(Format::Zip));
    assert_eq!(Format::of_file_name("X.ZIP"), Some(Format::Zip));
    assert_eq!(
        Format::of_file_name("dxvk-2.7.1.tar.gz"),
        Some(Format::TarGz)
    );
    assert_eq!(Format::of_file_name("a.tgz"), Some(Format::TarGz));
    for n in [
        ".zip", "x.7z", "x.rar", "x.tar", "x.gz", "x.tar.xz", "x.dll", "zip", ".tar.gz",
    ] {
        assert_eq!(Format::of_file_name(n), None, "{n}");
    }
}

#[test]
fn a_zip_with_stored_deflated_and_described_entries_reads_back() {
    let big: Vec<u8> = (0..200_000u32)
        .flat_map(|i| (i % 251).to_le_bytes())
        .collect();
    let mut with_sig = ZipEntry::file("bin/b.dll", b"b content");
    with_sig.descriptor = Descriptor::WithSig;
    let mut no_sig = ZipEntry::stored("bin/c.dll", b"c content");
    no_sig.descriptor = Descriptor::NoSig;
    let mut utf8 = ZipEntry::file("Read\u{e9}.txt", b"utf-8 name");
    utf8.flags = 0x0800;
    let b = zip(&[
        ZipEntry::dir("bin/"),
        ZipEntry::stored("a.txt", b"stored"),
        ZipEntry::file("bin/big.dat", &big),
        with_sig,
        no_sig,
        utf8,
        ZipEntry::file("empty.txt", b""),
    ]);
    let a = open(&b, Format::Zip).unwrap();
    assert_eq!(
        names(&a),
        [
            ("bin".to_owned(), EntryKind::Dir, 0),
            ("a.txt".to_owned(), EntryKind::File, 6),
            (r"bin\big.dat".to_owned(), EntryKind::File, big.len() as u64),
            (r"bin\b.dll".to_owned(), EntryKind::File, 9),
            (r"bin\c.dll".to_owned(), EntryKind::File, 9),
            ("Read\u{e9}.txt".to_owned(), EntryKind::File, 10),
            ("empty.txt".to_owned(), EntryKind::File, 0),
        ]
    );
    assert_eq!(read(&a, "a.txt").unwrap(), b"stored");
    assert_eq!(read(&a, "bin/big.dat").unwrap(), big);
    assert_eq!(read(&a, r"bin\b.dll").unwrap(), b"b content");
    assert_eq!(read(&a, "bin/c.dll").unwrap(), b"c content");
    assert_eq!(read(&a, "Read\u{e9}.txt").unwrap(), b"utf-8 name");
    assert_eq!(read(&a, "empty.txt").unwrap(), b"");
    // A comment after the end record is fine.
    let l = zip_layout(
        &[ZipEntry::file("a.txt", b"x")],
        b"a comment PK\x05\x06 inside",
    );
    assert_eq!(
        read(&open(&l.bytes, Format::Zip).unwrap(), "a.txt").unwrap(),
        b"x"
    );
    // An empty archive.
    assert!(open(&zip(&[]), Format::Zip).unwrap().entries().is_empty());
}

#[test]
fn a_tar_gz_in_gnu_and_posix_form_reads_back() {
    let mut posix = TarEntry::file("deep.dll", b"posix with prefix");
    posix.gnu = false;
    posix.prefix = b"pkg/x64".to_vec();
    let mut plain = TarEntry::file("pkg/plain.txt", b"posix");
    plain.gnu = false;
    let big: Vec<u8> = (0..100_000u32)
        .flat_map(|i| (i % 13).to_le_bytes())
        .collect();
    let b = tar_gz(&[
        TarEntry::dir("./"),
        TarEntry::dir("./pkg/"),
        TarEntry::file("./pkg/x32/d3d9.dll", b"x32 d3d9"),
        TarEntry::file("pkg/big.bin", &big),
        posix,
        plain,
        TarEntry::file("pkg/empty", b""),
    ]);
    let a = open(&b, Format::TarGz).unwrap();
    assert_eq!(
        names(&a),
        [
            ("pkg".to_owned(), EntryKind::Dir, 0),
            (r"pkg\x32\d3d9.dll".to_owned(), EntryKind::File, 8),
            (r"pkg\big.bin".to_owned(), EntryKind::File, big.len() as u64),
            (r"pkg\x64\deep.dll".to_owned(), EntryKind::File, 17),
            (r"pkg\plain.txt".to_owned(), EntryKind::File, 5),
            (r"pkg\empty".to_owned(), EntryKind::File, 0),
        ]
    );
    assert_eq!(read(&a, "pkg/x32/d3d9.dll").unwrap(), b"x32 d3d9");
    assert_eq!(read(&a, "pkg/big.bin").unwrap(), big);
    assert_eq!(read(&a, "pkg/x64/deep.dll").unwrap(), b"posix with prefix");
    // Several entries in one pass, in archive order whatever the order asked.
    let ix: Vec<usize> = ["pkg/plain.txt", "pkg/x32/d3d9.dll"]
        .iter()
        .map(|n| a.find(&rel(n)).unwrap())
        .collect();
    let mut seen = Vec::new();
    a.extract::<std::io::Error>(&ix, &mut |e, r| {
        let mut v = Vec::new();
        r.read_to_end(&mut v)?;
        seen.push((e.name.as_str().to_owned(), v));
        Ok(())
    })
    .unwrap();
    assert_eq!(
        seen,
        [
            (r"pkg\x32\d3d9.dll".to_owned(), b"x32 d3d9".to_vec()),
            (r"pkg\plain.txt".to_owned(), b"posix".to_vec()),
        ]
    );
}

#[test]
fn names_match_exactly_and_folders_are_not_files() {
    let b = zip(&[ZipEntry::dir("x64/"), ZipEntry::file("x64/d3d9.dll", b"d")]);
    let a = open(&b, Format::Zip).unwrap();
    assert_eq!(
        a.find(&rel("x64/D3D9.dll")),
        Err(ArchiveError::NotFound {
            name: r"x64\D3D9.dll".to_owned(),
            other_case: true
        })
    );
    assert_eq!(
        a.find(&rel("x64/d3d8.dll")),
        Err(ArchiveError::NotFound {
            name: r"x64\d3d8.dll".to_owned(),
            other_case: false
        })
    );
    assert_eq!(
        a.find(&rel("x64")),
        Err(ArchiveError::Folder("x64".to_owned()))
    );
}

// ---------- The zip-slip corpus ----------

/// Names no archive may hold (each refused for the whole archive, extracted or not).
const BAD_NAMES: &[&str] = &[
    "../evil.dll",
    "a/../../evil.dll",
    "a/..",
    "./a.dll",
    "a/./b.dll",
    "a//b.dll",
    "/abs.dll",
    "//server/share/x.dll",
    "C:/Windows/x.dll",
    "C:x.dll",
    "a\\b.dll",
    "..\\evil.dll",
    "\\\\server\\share\\x.dll",
    "a/b\\..\\..\\c.dll",
    "x.dll:stream",
    "x.dll::$DATA",
    "CON",
    "aux.txt",
    "a/nul/b.dll",
    "COM1.dll",
    "LPT\u{b9}",
    "trailing.",
    "trailing ",
    " lead.dll",
    "PROGRA~1/x.dll",
    "a<b.dll",
    "a|b.dll",
    "a?b.dll",
    "a*b.dll",
    "a\"b.dll",
    "x\u{0}y.dll",
    "x\ny.dll",
    "a\u{2215}b.dll",
    "a\u{2044}b.dll",
    "a\u{ff0f}b.dll",
    "\u{ff0e}\u{ff0e}\u{ff3c}evil.dll",
    "\u{202e}lld.exe",
    "x\u{200b}.dll",
    "a\u{a5}b.dll",
    "",
];

#[test]
fn bad_names_refuse_a_zip() {
    for n in BAD_NAMES {
        let mut e = ZipEntry::file(n, b"x");
        e.flags = 0x0800;
        let b = zip(&[ZipEntry::file("ok.dll", b"ok"), e]);
        match open(&b, Format::Zip) {
            Err(ArchiveError::BadName { .. }) => {}
            other => panic!("{n:?}: {other:?}"),
        }
    }
    // A name that is not UTF-8, and a non-ASCII name without the UTF-8 flag.
    let mut e = ZipEntry::file("x", b"x");
    e.name = vec![b'a', 0xFF, b'.', b'd'];
    e.flags = 0x0800;
    assert!(matches!(
        open(&zip(&[e.clone()]), Format::Zip),
        Err(ArchiveError::BadName {
            why: "not UTF-8",
            ..
        })
    ));
    e.flags = 0;
    e.name = "caf\u{e9}.dll".as_bytes().to_vec();
    assert!(matches!(
        open(&zip(&[e]), Format::Zip),
        Err(ArchiveError::BadName { .. })
    ));
}

#[test]
fn bad_names_refuse_a_tar_gz() {
    for n in BAD_NAMES {
        // A tar name ends at its first NUL (`x y.dll` is `x` there).
        if n.len() > 100 || n.contains(' ') {
            continue;
        }
        // One leading `./` is dropped in a tar; `./a.dll` is fine there.
        if *n == "./a.dll" {
            continue;
        }
        let b = tar_gz(&[TarEntry::file("ok.dll", b"ok"), TarEntry::file(n, b"x")]);
        match open(&b, Format::TarGz) {
            Err(ArchiveError::BadName { .. }) => {}
            other => panic!("{n:?}: {other:?}"),
        }
    }
    let b = tar_gz(&[
        TarEntry::file("./a.dll", b"x"),
        TarEntry::file("././b.dll", b"x"),
    ]);
    assert!(matches!(
        open(&b, Format::TarGz),
        Err(ArchiveError::BadName { .. })
    ));
}

#[test]
fn duplicates_case_collisions_and_entries_below_files_are_refused() {
    let utf8 = |n: &str, d: &[u8]| {
        let mut e = ZipEntry::file(n, d);
        e.flags = 0x0800;
        e
    };
    let dup = |a: &str, b: &str| {
        let z = zip(&[utf8(a, b"1"), utf8(b, b"2")]);
        let t = tar_gz(&[TarEntry::file(a, b"1"), TarEntry::file(b, b"2")]);
        (z, t)
    };
    for (a, b) in [
        ("d3d9.dll", "d3d9.dll"),
        ("d3d9.dll", "D3D9.DLL"),
        ("x64/d3d9.dll", "X64/d3d9.dll"),
        ("\u{c4}.dll", "\u{e4}.dll"),
    ] {
        let (z, t) = dup(a, b);
        assert!(
            matches!(open(&z, Format::Zip), Err(ArchiveError::Duplicate(_))),
            "{a} {b}"
        );
        assert!(
            matches!(open(&t, Format::TarGz), Err(ArchiveError::Duplicate(_))),
            "{a} {b}"
        );
    }
    // A folder and a file of one name.
    let z = zip(&[ZipEntry::dir("x/"), ZipEntry::file("X", b"1")]);
    assert!(matches!(
        open(&z, Format::Zip),
        Err(ArchiveError::Duplicate(_))
    ));
    // An entry below a file (also when the file comes later).
    for entries in [
        vec![ZipEntry::file("a", b"1"), ZipEntry::file("a/b.dll", b"2")],
        vec![
            ZipEntry::file("A/b/c.dll", b"2"),
            ZipEntry::file("a/B", b"1"),
        ],
    ] {
        assert!(matches!(
            open(&zip(&entries), Format::Zip),
            Err(ArchiveError::BelowFile(_))
        ));
    }
    let t = tar_gz(&[TarEntry::file("a", b"1"), TarEntry::file("a/b", b"2")]);
    assert!(matches!(
        open(&t, Format::TarGz),
        Err(ArchiveError::BelowFile(_))
    ));
}

#[test]
fn links_devices_and_other_tar_types_are_refused() {
    for (kind, special) in [
        (b'1', true),
        (b'2', true),
        (b'3', true),
        (b'4', true),
        (b'6', true),
        (b'7', true),
        (b'L', false),
        (b'K', false),
        (b'x', false),
        (b'g', false),
        (b'S', false),
        (b'V', true),
        (b'M', true),
    ] {
        let t = tar_gz(&[
            TarEntry::file("a.dll", b"a"),
            TarEntry::typed("link.dll", kind),
        ]);
        let e = open(&t, Format::TarGz).unwrap_err();
        let ok = if special {
            matches!(e, ArchiveError::Special { .. })
        } else {
            matches!(e, ArchiveError::Unsupported(_))
        };
        assert!(ok, "type {}: {e:?}", kind as char);
    }
    // A zip entry with a Unix link mode, a FIFO mode, a Windows reparse attribute.
    for (made_by, attrs) in [
        (0x0314, 0o120_777u32 << 16),
        (0x0314, 0o010_644 << 16),
        (0x0014, 0x0400),
        (0x0A14, 0x0400 | 0x20),
    ] {
        let mut e = ZipEntry::file("link.dll", b"target.dll");
        e.made_by = made_by;
        e.attrs = attrs;
        assert!(
            matches!(
                open(&zip(&[e]), Format::Zip),
                Err(ArchiveError::Special { .. })
            ),
            "{made_by:#x} {attrs:#o}"
        );
    }
    // Unix regular files and folders are fine.
    let mut f = ZipEntry::file("a.dll", b"a");
    f.made_by = 0x0314;
    f.attrs = 0o100_644 << 16;
    let mut d = ZipEntry::dir("d/");
    d.made_by = 0x0314;
    d.attrs = 0o040_755 << 16;
    assert!(open(&zip(&[f, d]), Format::Zip).is_ok());
}

// ---------- Bombs and limits ----------

#[test]
fn compression_ratio_size_and_count_limits_hold() {
    let zeros = vec![0u8; 4 * 1024 * 1024];
    // Zip: 4 MiB of zeros deflate to a few KiB: over 100:1.
    let z = zip(&[ZipEntry::file("zeros.bin", &zeros)]);
    assert_eq!(
        open(&z, Format::Zip).unwrap_err(),
        ArchiveError::TooLarge("the compression ratio of an entry")
    );
    // Up to the floor any ratio is fine.
    let small = zip(&[ZipEntry::file("zeros.bin", &zeros[..1024 * 1024])]);
    assert!(open(&small, Format::Zip).is_ok());
    // tar.gz: the whole stream.
    let t = tar_gz(&[TarEntry::file("zeros.bin", &zeros)]);
    assert_eq!(
        open(&t, Format::TarGz).unwrap_err(),
        ArchiveError::TooLarge("the compression ratio of the archive")
    );
    // Smaller limits, each exactly at and one over.
    let three = zip(&[
        ZipEntry::file("a", b"12345"),
        ZipEntry::file("b", b"12345"),
        ZipEntry::stored("c", b"12345"),
    ]);
    let lim = |f: &dyn Fn(&mut Limits)| {
        let mut l = Limits::DEFAULT;
        f(&mut l);
        l
    };
    assert!(Archive::open(&three, Format::Zip, &lim(&|l| l.max_entries = 3)).is_ok());
    assert_eq!(
        Archive::open(&three, Format::Zip, &lim(&|l| l.max_entries = 2)).unwrap_err(),
        ArchiveError::TooLarge("the number of entries")
    );
    assert!(Archive::open(&three, Format::Zip, &lim(&|l| l.max_entry_bytes = 5)).is_ok());
    assert_eq!(
        Archive::open(&three, Format::Zip, &lim(&|l| l.max_entry_bytes = 4)).unwrap_err(),
        ArchiveError::TooLarge("the size of an entry")
    );
    assert!(Archive::open(&three, Format::Zip, &lim(&|l| l.max_total_bytes = 15)).is_ok());
    assert_eq!(
        Archive::open(&three, Format::Zip, &lim(&|l| l.max_total_bytes = 14)).unwrap_err(),
        ArchiveError::TooLarge("the total size of the entries")
    );
    assert!(Archive::open(&three, Format::Zip, &lim(&|l| l.max_name_bytes = 1)).is_ok());
    assert_eq!(
        Archive::open(&three, Format::Zip, &lim(&|l| l.max_name_bytes = 0)).unwrap_err(),
        ArchiveError::TooLarge("an entry name")
    );
    let len = three.len() as u64;
    assert!(Archive::open(&three, Format::Zip, &lim(&|l| l.max_archive_bytes = len)).is_ok());
    assert_eq!(
        Archive::open(
            &three,
            Format::Zip,
            &lim(&|l| l.max_archive_bytes = len - 1)
        )
        .unwrap_err(),
        ArchiveError::TooLarge("the archive's size")
    );
    let t = tar_gz(&[TarEntry::file("a", b"12345"), TarEntry::file("b", b"12345")]);
    assert!(Archive::open(&t, Format::TarGz, &lim(&|l| l.max_entries = 2)).is_ok());
    assert_eq!(
        Archive::open(&t, Format::TarGz, &lim(&|l| l.max_entries = 1)).unwrap_err(),
        ArchiveError::TooLarge("the number of entries")
    );
    assert_eq!(
        Archive::open(&t, Format::TarGz, &lim(&|l| l.max_entry_bytes = 4)).unwrap_err(),
        ArchiveError::TooLarge("the size of an entry")
    );
    // The tar stream is 10,240 bytes (GNU record padding).
    assert!(Archive::open(&t, Format::TarGz, &lim(&|l| l.max_total_bytes = 10_240)).is_ok());
    assert_eq!(
        Archive::open(&t, Format::TarGz, &lim(&|l| l.max_total_bytes = 10_239)).unwrap_err(),
        ArchiveError::TooLarge("the decompressed tar stream")
    );
}

#[test]
fn overlapping_zip_entries_are_refused() {
    // The second entry's local header and data lie inside the first entry's content (the
    // overlapping zip bomb): a copy of a real local header of `b.dll`, stored inside `a.bin`.
    let inner = zip_layout(&[ZipEntry::stored("b.dll", b"x")], b"");
    let chunk = inner.bytes[..inner.centrals[0]].to_vec();
    let l = zip_layout(
        &[
            ZipEntry::stored("a.bin", &chunk),
            ZipEntry::stored("b.dll", b"x"),
        ],
        b"",
    );
    let mut b = l.bytes.clone();
    let inside = l.locals[0] + 30 + "a.bin".len();
    put32(&mut b, l.centrals[1] + 42, u32::try_from(inside).unwrap());
    assert_eq!(open(&b, Format::Zip).unwrap_err(), ArchiveError::Overlap);
    // Two central entries for one local header.
    let l = zip_layout(
        &[ZipEntry::stored("b.dll", b"x"), ZipEntry::stored("c", b"y")],
        b"",
    );
    let mut b = l.bytes.clone();
    put32(&mut b, l.centrals[1] + 42, 0);
    let name = l.centrals[1] + 46;
    b[name] = b'b';
    assert!(open(&b, Format::Zip).is_err());
}

// ---------- Damage ----------

#[test]
fn a_wrong_crc_or_size_is_found_while_extracting() {
    let mut crc = ZipEntry::file("a.dll", b"content");
    crc.crc = Some(0x1234_5678);
    let a = zip(&[crc]);
    assert_eq!(
        read(&open(&a, Format::Zip).unwrap(), "a.dll"),
        Err(ArchiveError::Crc(r"a.dll".to_owned()))
    );
    let mut stored = ZipEntry::stored("a.dll", b"content");
    stored.crc = Some(0);
    let a = zip(&[stored]);
    assert_eq!(
        read(&open(&a, Format::Zip).unwrap(), "a.dll"),
        Err(ArchiveError::Crc(r"a.dll".to_owned()))
    );
    for size in [6, 8] {
        let mut e = ZipEntry::file("a.dll", b"content");
        e.size = Some(size);
        let a = zip(&[e]);
        assert_eq!(
            read(&open(&a, Format::Zip).unwrap(), "a.dll"),
            Err(ArchiveError::Size(r"a.dll".to_owned())),
            "{size}"
        );
    }
    // A tar entry whose size runs past the stream: the structure check finds it.
    let mut e = TarEntry::file("a.dll", b"content");
    e.size = Some(1_000_000);
    let t = gzip(&tar(&[e])[..1536]);
    assert!(matches!(
        open(&t, Format::TarGz),
        Err(ArchiveError::Truncated(_))
    ));
}

#[test]
fn data_descriptors_and_local_headers_must_agree_with_the_central_directory() {
    for d in [Descriptor::WithSig, Descriptor::NoSig] {
        let mut e = ZipEntry::file("a.dll", b"content");
        e.descriptor = d;
        e.descriptor_crc = Some(1);
        assert_eq!(
            open(&zip(&[e]), Format::Zip).unwrap_err(),
            ArchiveError::Corrupt("a data descriptor that differs from the central directory"),
            "{d:?}"
        );
    }
    let l = zip_layout(&[ZipEntry::file("a.dll", b"content")], b"");
    let differs = ArchiveError::Corrupt("a local header that differs from the central directory");
    // Another name, method, CRC, size in the local header.
    for (at, v) in [(30usize, b'b'), (8, 0), (14, 0xAA), (22, 0x01)] {
        let mut b = l.bytes.clone();
        b[l.locals[0] + at] ^= v.max(1);
        assert_eq!(open(&b, Format::Zip).unwrap_err(), differs, "byte {at}");
    }
    let mut b = l.bytes.clone();
    b[l.locals[0]] = b'X';
    assert_eq!(
        open(&b, Format::Zip).unwrap_err(),
        ArchiveError::Corrupt("a local header signature")
    );
}

#[test]
fn zip64_several_disks_encryption_and_other_methods_are_refused() {
    let l = zip_layout(&[ZipEntry::file("a.dll", b"content")], b"");
    let refused = |b: &[u8], want: ArchiveError| {
        assert_eq!(open(b, Format::Zip).unwrap_err(), want);
    };
    let zip64 = ArchiveError::Unsupported("zip64");
    // End record fields at their maximum.
    for (at, wide) in [(8usize, false), (10, false), (12, true), (16, true)] {
        let mut b = l.bytes.clone();
        if wide {
            put32(&mut b, l.eocd + at, u32::MAX);
        } else {
            put16(&mut b, l.eocd + at, u16::MAX);
        }
        refused(&b, zip64.clone());
    }
    // A zip64 locator before the end record.
    let mut b = l.bytes[..l.eocd].to_vec();
    b.extend_from_slice(&0x0706_4B50u32.to_le_bytes());
    b.extend_from_slice(&[0u8; 16]);
    let cd_size = u32::try_from(b.len() - l.centrals[0]).unwrap();
    b.extend_from_slice(&l.bytes[l.eocd..]);
    let at = b.len() - 22 + 12;
    put32(&mut b, at, cd_size);
    refused(&b, zip64.clone());
    // Central sizes or the local offset at their maximum.
    for at in [20usize, 24, 42] {
        let mut b = l.bytes.clone();
        put32(&mut b, l.centrals[0] + at, u32::MAX);
        refused(&b, zip64.clone());
    }
    // A zip64 extra field.
    let mut e = ZipEntry::file("a.dll", b"content");
    e.extra = vec![0x01, 0x00, 0x08, 0x00, 0, 0, 0, 0, 0, 0, 0, 0];
    refused(&zip(&[e]), zip64);
    // Several disks.
    for (at, central) in [(4usize, false), (6, false), (8, false), (34, true)] {
        let mut b = l.bytes.clone();
        if central {
            put16(&mut b, l.centrals[0] + at, 1);
        } else {
            put16(&mut b, l.eocd + at, if at == 8 { 0 } else { 1 });
        }
        refused(
            &b,
            ArchiveError::Unsupported("an archive over several disks"),
        );
    }
    // Encryption (each bit), another method, the Unicode path field, a malformed extra field.
    for bit in [0x0001u16, 0x0040, 0x2000] {
        let mut e = ZipEntry::file("a.dll", b"content");
        e.flags = bit;
        refused(&zip(&[e]), ArchiveError::Unsupported("encryption"));
    }
    let mut b = l.bytes.clone();
    put16(&mut b, l.centrals[0] + 10, 14);
    put16(&mut b, l.locals[0] + 8, 14);
    refused(
        &b,
        ArchiveError::Unsupported("a compression method other than stored or deflate"),
    );
    let mut e = ZipEntry::file("a.dll", b"content");
    e.extra = vec![0x75, 0x70, 0x05, 0x00, 1, 0, 0, 0, b'b'];
    refused(
        &zip(&[e]),
        ArchiveError::Unsupported("a second (Unicode) name for an entry"),
    );
    let mut e = ZipEntry::file("a.dll", b"content");
    e.extra = vec![0x0A, 0x00, 0x09, 0x00, 0];
    refused(&zip(&[e]), ArchiveError::Corrupt("an extra field"));
}

#[test]
fn data_around_a_zip_is_refused() {
    let b = zip(&[ZipEntry::file("a.dll", b"content")]);
    let mut after = b.clone();
    after.extend_from_slice(b"junk");
    assert_eq!(
        open(&after, Format::Zip).unwrap_err(),
        ArchiveError::NotFormat("zip")
    );
    let mut before = b"junk".to_vec();
    before.extend_from_slice(&b);
    assert_eq!(
        open(&before, Format::Zip).unwrap_err(),
        ArchiveError::Corrupt("the position of the central directory")
    );
    assert_eq!(
        open(b"", Format::Zip).unwrap_err(),
        ArchiveError::NotFormat("zip")
    );
    assert_eq!(
        open(&tar_gz(&[]), Format::Zip).unwrap_err(),
        ArchiveError::NotFormat("zip")
    );
    assert_eq!(
        open(&b, Format::TarGz).unwrap_err(),
        ArchiveError::NotFormat("tar.gz (gzip)")
    );
}

#[test]
fn a_tar_gz_is_checked_to_its_end() {
    let entries = [TarEntry::file("a.dll", b"content")];
    // Bytes after the gzip member, a second member.
    let mut b = tar_gz(&entries);
    b.push(0);
    assert_eq!(open(&b, Format::TarGz).unwrap_err(), ArchiveError::Trailing);
    let mut b = tar_gz(&entries);
    b.extend_from_slice(&gzip(b"more"));
    assert_eq!(open(&b, Format::TarGz).unwrap_err(), ArchiveError::Trailing);
    // Something after the end marker of the tar.
    let mut t = tar(&entries);
    let n = t.len();
    t[n - 1] = 1;
    assert_eq!(
        open(&gzip(&t), Format::TarGz).unwrap_err(),
        ArchiveError::Trailing
    );
    // No end marker.
    let t = tar(&entries);
    assert_eq!(
        open(&gzip(&t[..1024]), Format::TarGz).unwrap_err(),
        ArchiveError::Truncated("the end of the tar archive")
    );
    // The gzip CRC and length.
    let mut b = tar_gz(&entries);
    let n = b.len();
    b[n - 8] ^= 1;
    assert_eq!(
        open(&b, Format::TarGz).unwrap_err(),
        ArchiveError::Crc("the gzip stream".to_owned())
    );
    let mut b = tar_gz(&entries);
    let n = b.len();
    b[n - 4] ^= 1;
    assert_eq!(
        open(&b, Format::TarGz).unwrap_err(),
        ArchiveError::Corrupt("the gzip length")
    );
    // A header checksum, a version 7 header, a base-256 size.
    let mut e = TarEntry::file("a.dll", b"content");
    e.checksum = Some(1);
    assert_eq!(
        open(&tar_gz(&[e]), Format::TarGz).unwrap_err(),
        ArchiveError::Corrupt("a tar header checksum")
    );
    let mut t = tar(&entries);
    t[257..265].copy_from_slice(&[0; 8]);
    let sum: u64 = t[..512]
        .iter()
        .enumerate()
        .map(|(i, b)| {
            if (148..156).contains(&i) {
                32
            } else {
                u64::from(*b)
            }
        })
        .sum();
    t[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
    assert_eq!(
        open(&gzip(&t), Format::TarGz).unwrap_err(),
        ArchiveError::Unsupported("a tar format other than ustar or GNU")
    );
    let mut t = tar(&entries);
    t[124] = 0x80;
    fix_checksum(&mut t);
    assert_eq!(
        open(&gzip(&t), Format::TarGz).unwrap_err(),
        ArchiveError::Unsupported("a tar number in base-256")
    );
    // Reserved gzip flags.
    let mut b = tar_gz(&entries);
    b[3] = 0x20;
    assert_eq!(
        open(&b, Format::TarGz).unwrap_err(),
        ArchiveError::Corrupt("the gzip header flags")
    );
}

/// Sets the checksum of the first tar header to match its bytes.
fn fix_checksum(t: &mut [u8]) {
    let sum: u64 = t[..512]
        .iter()
        .enumerate()
        .map(|(i, b)| {
            if (148..156).contains(&i) {
                32
            } else {
                u64::from(*b)
            }
        })
        .sum();
    t[148..156].copy_from_slice(format!("{sum:06o}  ").as_bytes());
}

/// Every prefix of an archive is refused (and never panics).
fn every_prefix_is_refused(b: &[u8], f: Format) {
    for n in 0..b.len() {
        assert!(
            open(&b[..n], f).is_err(),
            "{f:?}: prefix of {n} bytes opened"
        );
    }
}

#[test]
fn truncated_archives_are_refused() {
    let z = zip(&[
        ZipEntry::dir("d/"),
        ZipEntry::file("d/a.dll", b"content a"),
        ZipEntry::stored("b.txt", b"content b"),
    ]);
    every_prefix_is_refused(&z, Format::Zip);
    let t = tar_gz(&[TarEntry::dir("d/"), TarEntry::file("d/a.dll", b"content a")]);
    every_prefix_is_refused(&t, Format::TarGz);
}

/// A changed byte anywhere: refused when opened or extracted, or (a byte nobody reads, such as
/// a time stamp) the same content. Never another content, never a panic.
fn every_flip_is_caught(b: &[u8], f: Format) {
    let good = read_every(&open(b, f).unwrap()).unwrap();
    for i in 0..b.len() {
        let mut x = b.to_vec();
        x[i] ^= 0x41;
        let Ok(a) = open(&x, f) else { continue };
        if let Ok(got) = read_every(&a) {
            assert_eq!(got, good, "{f:?}: byte {i} changed the content unnoticed");
        }
    }
}

#[test]
fn a_changed_byte_never_changes_content_unnoticed() {
    let mut d = ZipEntry::file("d/c.dll", b"described content");
    d.descriptor = Descriptor::WithSig;
    let z = zip(&[
        ZipEntry::file(
            "d/a.dll",
            b"deflated content, a little longer than the rest",
        ),
        ZipEntry::stored("b.txt", b"stored content"),
        d,
    ]);
    every_flip_is_caught(&z, Format::Zip);
    let t = tar_gz(&[
        TarEntry::dir("d/"),
        TarEntry::file("d/a.dll", b"content a"),
        TarEntry::file("b.txt", b"content b"),
    ]);
    every_flip_is_caught(&t, Format::TarGz);
}

#[test]
fn a_sink_that_stops_early_does_not_skip_the_checks() {
    let mut e = ZipEntry::file("a.dll", b"content");
    e.crc = Some(7);
    let b = zip(&[e]);
    let a = open(&b, Format::Zip).unwrap();
    let r = a.extract::<()>(&[0], &mut |_, _| Ok(()));
    assert!(matches!(r, Err(Extraction::Archive(ArchiveError::Crc(_)))));
    // The sink's own failure is reported as the sink's.
    let b = zip(&[ZipEntry::file("a.dll", b"content")]);
    let a = open(&b, Format::Zip).unwrap();
    let r = a.extract::<&str>(&[0], &mut |_, _| Err("full"));
    assert!(matches!(r, Err(Extraction::Sink("full"))));
}
