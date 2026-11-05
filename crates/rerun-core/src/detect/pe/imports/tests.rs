//! Import and delay-import DLL names, load config (ADR 0013). Every image is synthetic.

use std::collections::HashSet;
use std::io::Cursor;

use super::DllName;
use crate::detect::pe::layout as l;
use crate::detect::pe::testfx::{Builder, DATA_RVA, Image, dll_names, put32};
use crate::detect::pe::tests::{Rng, mutate};
use crate::detect::pe::{Limits, Pe, PeError, PeErrorKind};

fn pe(bytes: &[u8]) -> Pe<Cursor<&[u8]>> {
    Pe::parse(Cursor::new(bytes), &Limits::DEFAULT).unwrap()
}

fn pe_with<'a>(bytes: &'a [u8], limits: &Limits) -> Pe<Cursor<&'a [u8]>> {
    Pe::parse(Cursor::new(bytes), limits).unwrap()
}

fn strs(names: &[DllName]) -> Vec<&str> {
    names.iter().map(DllName::as_str).collect()
}

fn names(list: &[&str]) -> Vec<Vec<u8>> {
    list.iter().map(|s| s.as_bytes().to_vec()).collect()
}

fn off(at: usize) -> u64 {
    u64::try_from(at).unwrap()
}

/// Shrinks the data section's `VirtualSize` to `len` bytes.
fn shrink(img: &mut Image, len: usize) {
    put32(
        &mut img.bytes,
        img.table + l::SECTION_VIRTUAL_SIZE,
        u32::try_from(len).unwrap(),
    );
}

#[test]
fn import_and_delay_names_come_in_table_order_with_their_spelling() {
    for mut b in [Builder::x64(), Builder::x86()] {
        b.imports = Some(names(&[
            "KERNEL32.dll",
            "d3d9.dll",
            "USER32.DLL",
            "kernel32.dll",
        ]));
        b.delay = Some(vec![
            (b"dinput8.dll".to_vec(), true),
            (b"XInput1_3.dll".to_vec(), true),
        ]);
        let img = b.build();
        let mut pe = pe(&img.bytes);
        assert_eq!(
            strs(&pe.imports().unwrap()),
            ["KERNEL32.dll", "d3d9.dll", "USER32.DLL", "kernel32.dll"]
        );
        assert_eq!(
            strs(&pe.delay_imports().unwrap()),
            ["dinput8.dll", "XInput1_3.dll"]
        );
        // Repeatable on the same `Pe`.
        assert_eq!(pe.imports().unwrap().len(), 4);
    }
}

#[test]
fn no_directory_and_an_empty_table_have_no_names() {
    let mut b = Builder::x64();
    let img = b.build();
    let mut p = pe(&img.bytes);
    assert_eq!(p.imports(), Ok(vec![]));
    assert_eq!(p.delay_imports(), Ok(vec![]));
    assert_eq!(p.dependent_load_flags(), Ok(None));
    b.imports = Some(vec![]);
    b.delay = Some(vec![]);
    let img = b.build();
    let mut p = pe(&img.bytes);
    assert_eq!(p.imports(), Ok(vec![]));
    assert_eq!(p.delay_imports(), Ok(vec![]));
    // A directory beyond NumberOfRvaAndSizes is not read.
    b.imports = Some(names(&["a.dll"]));
    b.rva_count = 1;
    let img = b.build();
    let mut p = pe(&img.bytes);
    assert_eq!(p.imports(), Ok(vec![]));
}

#[test]
fn import_dlls_up_to_the_limit_are_read() {
    for (max, len) in [(Limits::DEFAULT.max_import_dlls, 12), (3, 12)] {
        let limits = Limits {
            max_import_dlls: max,
            ..Limits::DEFAULT
        };
        let mut b = Builder::x64();
        b.imports = Some(dll_names(max, len));
        b.delay = Some(dll_names(max, len).into_iter().map(|n| (n, true)).collect());
        let img = b.build();
        let mut p = pe_with(&img.bytes, &limits);
        assert_eq!(p.imports().unwrap().len(), max);
        assert_eq!(p.delay_imports().unwrap().len(), max);

        b.imports = Some(dll_names(max + 1, len));
        b.delay = Some(
            dll_names(max + 1, len)
                .into_iter()
                .map(|n| (n, true))
                .collect(),
        );
        let img = b.build();
        let mut p = pe_with(&img.bytes, &limits);
        assert_eq!(
            p.imports(),
            Err(PeError::at(
                PeErrorKind::TooManyImports,
                off(img.import_table.unwrap())
            ))
        );
        assert_eq!(
            p.delay_imports(),
            Err(PeError::at(
                PeErrorKind::TooManyImports,
                off(img.delay_table.unwrap())
            ))
        );
    }
}

#[test]
fn a_table_without_terminator_is_refused() {
    let mut b = Builder::x64();
    b.imports = Some(names(&["a.dll", "b.dll"]));
    let mut img = b.build();
    let table = img.import_table.unwrap();
    let end = table - img.data + 2 * l::IMPORT_DESCRIPTOR_SIZE;
    // The file-backed data ends right before the terminator.
    shrink(&mut img, end);
    assert_eq!(
        pe(&img.bytes).imports(),
        Err(PeError::at(PeErrorKind::ImportsNotTerminated, off(table)))
    );
    // In the middle of a descriptor.
    shrink(&mut img, end - 5);
    assert_eq!(
        pe(&img.bytes).imports(),
        Err(PeError::at(PeErrorKind::ImportsNotTerminated, off(table)))
    );
    // The file ends before the terminator.
    let img = b.build();
    let cut = &img.bytes[..table + 2 * l::IMPORT_DESCRIPTOR_SIZE + 3];
    assert_eq!(
        pe(cut).imports(),
        Err(PeError::at(PeErrorKind::Truncated, off(table)))
    );
}

#[test]
fn dll_names_must_be_printable_ascii_of_1_to_255_bytes() {
    let good: &[&[u8]] = &[b"a", b" spaced name.dll", b"~!@#$%^&()_+{}[];',.dll"];
    for name in good {
        let mut b = Builder::x64();
        b.imports = Some(vec![name.to_vec()]);
        assert_eq!(
            pe(&b.build().bytes).imports().unwrap()[0]
                .as_str()
                .as_bytes(),
            *name
        );
    }
    let mut b = Builder::x64();
    b.imports = Some(dll_names(1, 255));
    assert_eq!(
        pe(&b.build().bytes).imports().unwrap()[0].as_str().len(),
        255
    );

    let bad: Vec<Vec<u8>> = vec![
        b"".to_vec(),
        dll_names(1, 256).remove(0),
        b"tab\t.dll".to_vec(),
        b"\x01.dll".to_vec(),
        b"del\x7F.dll".to_vec(),
        "d\u{e4}.dll".as_bytes().to_vec(),
        "\u{202E}lld.exe".as_bytes().to_vec(),
        b"esc\x1b[31m.dll".to_vec(),
    ];
    for name in bad {
        let mut b = Builder::x64();
        b.imports = Some(vec![name.clone()]);
        let img = b.build();
        assert_eq!(
            pe(&img.bytes).imports(),
            Err(PeError::at(PeErrorKind::BadDllName, off(img.names[0]))),
            "{name:?}"
        );
    }
}

#[test]
fn a_dll_name_must_end_within_the_backed_data() {
    // The last bytes of the header region (below SizeOfHeaders, padding after the section
    // table): a name there has only these bytes left.
    let mut b = Builder::x64();
    b.imports = Some(names(&["a.dll"]));
    let img = b.build();
    let table = img.import_table.unwrap();
    let mut bytes = img.bytes.clone();
    put32(&mut bytes, table + l::IMPORT_NAME, 0x1FC);
    bytes[0x1FC..0x200].copy_from_slice(b"wxyz");
    assert_eq!(
        pe(&bytes).imports(),
        Err(PeError::at(PeErrorKind::BadDllName, 0x1FC))
    );
    bytes[0x1FF] = 0;
    assert_eq!(strs(&pe(&bytes).imports().unwrap()), ["wxy"]);
}

#[test]
fn unmapped_and_unbacked_rvas_name_the_field_that_holds_them() {
    let mut b = Builder::x64();
    b.imports = Some(names(&["a.dll"]));
    let img = b.build();
    let table = img.import_table.unwrap();
    // A name RVA in no section.
    let mut bytes = img.bytes.clone();
    put32(&mut bytes, table + l::IMPORT_NAME, 0x00F0_0000);
    assert_eq!(
        pe(&bytes).imports(),
        Err(PeError::at(PeErrorKind::RvaNotMapped, off(table)))
    );
    // A name RVA past the file-backed part of the data section (VirtualSize 0x2000).
    let mut bytes = img.bytes.clone();
    put32(&mut bytes, img.table + l::SECTION_VIRTUAL_SIZE, 0x2000);
    put32(&mut bytes, table + l::IMPORT_NAME, DATA_RVA + 0x1000);
    assert_eq!(
        pe(&bytes).imports(),
        Err(PeError::at(PeErrorKind::RvaNotBacked, off(table)))
    );
    // The directory RVA itself.
    let mut b = Builder::x64();
    b.dirs = vec![(l::DIR_IMPORT, 0x00F0_0000, 40)];
    let img = b.build();
    let entry = img.opt + l::OPT64_DATA_DIRECTORY + l::DIR_IMPORT * 8;
    assert_eq!(
        pe(&img.bytes).imports(),
        Err(PeError::at(PeErrorKind::RvaNotMapped, off(entry)))
    );
}

#[test]
fn vc6_delay_descriptors_hold_virtual_addresses() {
    let mut b = Builder::x86();
    b.delay = Some(vec![
        (b"old.dll".to_vec(), false),
        (b"new.dll".to_vec(), true),
    ]);
    let img = b.build();
    assert_eq!(
        strs(&pe(&img.bytes).delay_imports().unwrap()),
        ["old.dll", "new.dll"]
    );
    let table = img.delay_table.unwrap();
    // Below ImageBase, and far above it.
    for va in [0x1000, 0x3F_FFFF, u32::MAX] {
        let mut bytes = img.bytes.clone();
        put32(&mut bytes, table + l::DELAYLOAD_DLL_NAME_RVA, va);
        assert_eq!(
            pe(&bytes).delay_imports(),
            Err(PeError::at(PeErrorKind::RvaNotMapped, off(table))),
            "{va:#x}"
        );
    }
    // ImageBase itself is RVA 0, inside the headers: the bytes there are read as they are
    // (`MZ`, then NUL in the built image).
    let mut bytes = img.bytes.clone();
    put32(&mut bytes, table + l::DELAYLOAD_DLL_NAME_RVA, 0x40_0000);
    assert_eq!(
        strs(&pe(&bytes).delay_imports().unwrap()),
        ["MZ", "new.dll"]
    );
    // x64: ImageBase above 4 GiB, every 32-bit address is below it.
    let mut b = Builder::x64();
    b.delay = Some(vec![(b"old.dll".to_vec(), true)]);
    let img = b.build();
    let table = img.delay_table.unwrap();
    let mut bytes = img.bytes.clone();
    put32(&mut bytes, table + l::DELAYLOAD_ATTRIBUTES, 0);
    assert_eq!(
        pe(&bytes).delay_imports(),
        Err(PeError::at(PeErrorKind::RvaNotMapped, off(table)))
    );
}

#[test]
fn dependent_load_flags_in_both_formats() {
    for mut b in [Builder::x64(), Builder::x86()] {
        let field = if b.magic == l::OPTIONAL_MAGIC_PE32 {
            l::LOAD_CONFIG32_DEPENDENT_LOAD_FLAGS
        } else {
            l::LOAD_CONFIG64_DEPENDENT_LOAD_FLAGS
        };
        let want = u32::try_from(field + 2).unwrap();
        b.load_config = Some((0x140, 0x800));
        assert_eq!(pe(&b.build().bytes).dependent_load_flags(), Ok(Some(0x800)));
        // Size exactly reaching the field, and one byte short.
        b.load_config = Some((want, 0x800));
        assert_eq!(pe(&b.build().bytes).dependent_load_flags(), Ok(Some(0x800)));
        b.load_config = Some((want - 1, 0x800));
        assert_eq!(pe(&b.build().bytes).dependent_load_flags(), Ok(None));
        b.load_config = Some((0, 0x800));
        assert_eq!(pe(&b.build().bytes).dependent_load_flags(), Ok(None));
        // The backed data ends before the field.
        b.load_config = Some((0x140, 0x800));
        let mut img = b.build();
        let at = img.load_config.unwrap();
        let data = img.data;
        shrink(&mut img, at - data + field + 1);
        assert_eq!(
            pe(&img.bytes).dependent_load_flags(),
            Err(PeError::at(PeErrorKind::Truncated, off(at)))
        );
        shrink(&mut img, at - data + 3);
        assert_eq!(
            pe(&img.bytes).dependent_load_flags(),
            Err(PeError::at(PeErrorKind::Truncated, off(at)))
        );
    }
}

#[test]
fn dll_names_compare_and_hash_case_insensitively() {
    let a = DllName::new(b"KERNEL32.dll", 255).unwrap();
    let b = DllName::new(b"kernel32.DLL", 255).unwrap();
    assert_eq!(a, b);
    assert!(a.eq_ignore_ascii_case("Kernel32.Dll"));
    assert_eq!(a.to_string(), "KERNEL32.dll");
    assert_eq!(format!("{a:?}"), "DllName(\"KERNEL32.dll\")");
    let set: HashSet<DllName> = [a, b].into_iter().collect();
    assert_eq!(set.len(), 1);
    assert!(DllName::new(b"x", 0).is_none());
    // The Kelvin sign never passes (not ASCII), so it cannot fold to `k`.
    assert!(DllName::new("\u{212A}ernel32.dll".as_bytes(), 255).is_none());
}

#[test]
fn the_worst_case_of_every_import_limit_stays_within_the_budget() {
    let mut b = Builder::x64();
    b.imports = Some(dll_names(1024, 255));
    b.delay = Some(
        dll_names(1024, 255)
            .into_iter()
            .map(|n| (n, true))
            .collect(),
    );
    b.load_config = Some((0x140, 0x800));
    let img = b.build();
    let mut p = pe(&img.bytes);
    assert_eq!(p.imports().unwrap().len(), 1024);
    assert_eq!(p.delay_imports().unwrap().len(), 1024);
    assert_eq!(p.dependent_load_flags(), Ok(Some(0x800)));
    // Header region, both tables (clamped to the backed data), 2,048 names of 256 bytes, the
    // load config.
    assert!(p.bytes_read() <= Limits::DEFAULT.max_read_bytes);
    assert!(
        p.bytes_read() > 64 * 1024 + 2048 * 256,
        "{}",
        p.bytes_read()
    );
    // A small budget stops in the middle, with the offset of the read it refused.
    let limits = Limits {
        max_read_bytes: 70 * 1024,
        ..Limits::DEFAULT
    };
    let e = pe_with(&img.bytes, &limits).imports().unwrap_err();
    assert_eq!(e.kind, PeErrorKind::ReadBudget);
    assert!(e.offset.is_some());
}

#[test]
fn import_errors_never_show_names() {
    let mut b = Builder::x64();
    b.imports = Some(vec![b"SECRETMARKER\x07.dll".to_vec()]);
    let e = pe(&b.build().bytes).imports().unwrap_err();
    assert_eq!(e.kind, PeErrorKind::BadDllName);
    let shown = format!("{e} / {e:?}");
    assert!(!shown.contains("SECRET"), "{shown}");
}

#[test]
fn mutated_import_tables_never_panic_and_stay_within_limits() {
    let mut seeds = Vec::new();
    for mut b in [Builder::x64(), Builder::x86()] {
        let vc6 = b.magic == l::OPTIONAL_MAGIC_PE32;
        b.imports = Some(names(&["KERNEL32.dll", "d3d9.dll", "USER32.dll"]));
        b.delay = Some(vec![
            (b"dinput8.dll".to_vec(), true),
            (b"old.dll".to_vec(), !vc6),
        ]);
        b.load_config = Some((0x40, 0x800));
        seeds.push(b.build());
    }
    let small = Limits {
        max_import_dlls: 2,
        max_name_bytes: 9,
        max_read_bytes: 66 * 1024,
        ..Limits::DEFAULT
    };
    let mut rng = Rng(0x5EED_0013_0000_0004);
    let (mut ok, mut failed) = (0, 0);
    for round in 0..20_000 {
        let img = &seeds[round % seeds.len()];
        let mut bytes = img.bytes.clone();
        for _ in 0..1 + rng.below(4) {
            // Hot region: the data directories and the whole data section.
            let hot = bytes.len();
            mutate(&mut rng, &mut bytes, hot);
        }
        let limits = if round % 4 == 0 {
            small
        } else {
            Limits::DEFAULT
        };
        let Ok(mut p) = Pe::parse(Cursor::new(&bytes[..]), &limits) else {
            continue;
        };
        for r in [p.imports(), p.delay_imports()] {
            match r {
                Ok(list) => {
                    ok += 1;
                    assert!(list.len() <= limits.max_import_dlls);
                    for n in &list {
                        assert!(n.as_str().len() <= limits.max_name_bytes);
                        assert!(n.as_str().bytes().all(|b| (0x20..=0x7E).contains(&b)));
                    }
                }
                Err(_) => failed += 1,
            }
        }
        let _ = p.dependent_load_flags();
        assert!(p.bytes_read() <= limits.max_read_bytes);
    }
    assert!(ok > 1000 && failed > 1000, "ok {ok}, failed {failed}");
}
