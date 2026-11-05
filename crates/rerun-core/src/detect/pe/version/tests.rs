//! Version resource: the `RT_VERSION` branch and `VS_VERSIONINFO`, plus `Pe::info` (ADR 0013).
//! Every image and string is synthetic.

use std::io::Cursor;

use super::{StringTableId, VersionInfo, parse};
use crate::detect::pe::layout as l;
use crate::detect::pe::testfx::{
    Builder, Node, ResId, STRINGS, TREE_BLOB, TREE_ENTRY, TREE_LANGS, TREE_NAMES, Value, Vs,
    dll_names, fixed_info, put32, string_table, var_file_info, version_info, version_tree,
};
use crate::detect::pe::tests::{Rng, mutate};
use crate::detect::pe::{Limits, Pe, PeError, PeErrorKind};
use crate::detect::text::RawText;

fn blob(vs: &Vs) -> Result<VersionInfo, (PeErrorKind, usize)> {
    parse(&vs.encode(), &Limits::DEFAULT)
}

fn text(t: &Option<RawText>) -> Option<&str> {
    t.as_ref().map(RawText::as_raw_str)
}

fn description(v: &VersionInfo) -> Option<&str> {
    text(&v.strings.file_description)
}

fn standard() -> Vs {
    version_info(
        vec![string_table("040904b0", STRINGS)],
        Some((0x0409, 0x04B0)),
    )
}

fn through_pe(b: &Builder) -> Result<Option<VersionInfo>, PeError> {
    let img = b.build();
    Pe::parse(Cursor::new(&img.bytes[..]), &Limits::DEFAULT)
        .unwrap()
        .version_info()
}

fn with_version(vs: &Vs) -> Builder {
    Builder::x86().with_version(vs.encode())
}

fn off(at: usize) -> u64 {
    u64::try_from(at).unwrap()
}

/// A table `key` whose `FileDescription` is `desc`.
fn described(key: &str, desc: &str) -> Vs {
    string_table(key, &[("FileDescription", desc)])
}

// ---------- VS_VERSIONINFO ----------

#[test]
fn a_full_version_resource_is_read() {
    let v = blob(&standard()).unwrap();
    let f = v.fixed.unwrap();
    assert_eq!(f.file_version, [1, 2, 3, 4]);
    assert_eq!(f.product_version, [1, 2, 0, 0]);
    assert_eq!(
        (
            f.file_flags_mask,
            f.file_flags,
            f.file_os,
            f.file_type,
            f.file_subtype
        ),
        (0x3F, 0, 0x0004_0004, 1, 0)
    );
    assert_eq!(
        v.table,
        Some(StringTableId {
            language: 0x0409,
            codepage: 0x04B0
        })
    );
    let s = &v.strings;
    assert_eq!(text(&s.company_name), Some("Invented Games"));
    assert_eq!(text(&s.file_description), Some("Invented Game"));
    assert_eq!(text(&s.file_version), Some("1.2.3.4"));
    assert_eq!(text(&s.original_filename), Some("game.exe"));
    assert_eq!(text(&s.product_name), Some("Invented"));
    assert_eq!(text(&s.product_version), Some("1.2"));
    // Through the resource directory of an image as well.
    assert_eq!(through_pe(&with_version(&standard())), Ok(Some(v)));
}

#[test]
fn the_string_table_is_chosen_by_translation_then_en_us_then_first() {
    let tables = || {
        vec![
            described("040704e4", "de"),
            described("040904b0", "en"),
            described("0c0c04b0", "fr"),
        ]
    };
    let pick = |vs: Vs| description(&blob(&vs).unwrap()).map(str::to_owned);
    assert_eq!(
        pick(version_info(tables(), Some((0x0C0C, 0x04B0)))).as_deref(),
        Some("fr")
    );
    // A translation without its table, or none: the first 0x0409 table.
    assert_eq!(
        pick(version_info(tables(), Some((0x0411, 0x04B0)))).as_deref(),
        Some("en")
    );
    assert_eq!(pick(version_info(tables(), None)).as_deref(), Some("en"));
    // Codepage must match too.
    assert_eq!(
        pick(version_info(tables(), Some((0x0C0C, 0x04E4)))).as_deref(),
        Some("en")
    );
    // No 0x0409: the first.
    let others = vec![described("040704e4", "de"), described("0c0c04b0", "fr")];
    assert_eq!(pick(version_info(others, None)).as_deref(), Some("de"));
    // VarFileInfo before StringFileInfo.
    let vs = Vs::new(
        "VS_VERSION_INFO",
        Value::Bin(fixed_info([1, 0, 0, 0], [1, 0, 0, 0])),
        vec![
            var_file_info(0x0C0C, 0x04B0),
            Vs::new("StringFileInfo", Value::None, tables()),
        ],
    );
    assert_eq!(pick(vs).as_deref(), Some("fr"));
    // Hex digits in either case.
    let upper = version_info(vec![described("0C0C04B0", "FR")], Some((0x0C0C, 0x04B0)));
    let v = blob(&upper).unwrap();
    assert_eq!(v.table.unwrap().language, 0x0C0C);
    assert_eq!(description(&v), Some("FR"));
}

#[test]
fn kept_keys_compare_ascii_case_insensitively_and_the_first_wins() {
    let vs = version_info(
        vec![string_table(
            "040904b0",
            &[
                ("companyname", "first"),
                ("CompanyName", "second"),
                ("Comments", "skipped"),
                ("PRODUCTNAME", "upper"),
            ],
        )],
        None,
    );
    let v = blob(&vs).unwrap();
    assert_eq!(text(&v.strings.company_name), Some("first"));
    assert_eq!(text(&v.strings.product_name), Some("upper"));
    assert_eq!(v.strings.file_description, None);
}

#[test]
fn tables_with_other_keys_are_skipped() {
    for key in [
        "zz0904b0",
        "040904b",
        "040904b00",
        "",
        "Translation",
        "04 904b0",
    ] {
        let vs = version_info(
            vec![described(key, "bad"), described("040704e4", "good")],
            None,
        );
        let v = blob(&vs).unwrap();
        assert_eq!(description(&v), Some("good"), "{key:?}");
    }
    // Only such tables: no strings, no table.
    let v = blob(&version_info(vec![described("x", "bad")], None)).unwrap();
    assert_eq!(v.table, None);
    assert_eq!(v.strings, super::VersionStrings::default());
}

#[test]
fn string_value_lengths_of_old_toolchains_are_ignored() {
    let expected = blob(&standard()).unwrap();
    // wValueLength in bytes (Borland, Delphi), zero, and absurd.
    for fix in [|v: usize| v * 2, |_| 0, |_| 0xFFFF, |v: usize| v - 1] {
        let mut vs = standard();
        for table in &mut vs.children[0].children {
            for s in &mut table.children {
                if let Value::Text(t) = &s.value {
                    let units = t.encode_utf16().count() + 1;
                    s.value_len = Some(u16::try_from(fix(units)).unwrap());
                }
            }
        }
        assert_eq!(blob(&vs).unwrap(), expected);
    }
}

#[test]
fn a_string_without_nul_runs_to_the_end_of_its_block() {
    let units: Vec<u16> = "no-nul".encode_utf16().collect();
    let table = Vs::new(
        "040904b0",
        Value::None,
        vec![
            Vs::new("FileDescription", Value::Units(units), Vec::new()),
            Vs::string("ProductName", "after"),
        ],
    );
    let v = blob(&version_info(vec![table], None)).unwrap();
    assert_eq!(description(&v), Some("no-nul"));
    assert_eq!(text(&v.strings.product_name), Some("after"));
    // The resource data ends right after the last character: no trailing padding.
    let vs = version_info(
        vec![string_table("040904b0", &[("FileDescription", "odd!")])],
        None,
    );
    let mut bytes = vs.encode();
    assert_eq!(bytes.len() % 4, 2, "the fixture ends unaligned");
    assert_eq!(
        description(&parse(&bytes, &Limits::DEFAULT).unwrap()),
        Some("odd!")
    );
    // Cut inside the last value (its NUL and one character): the string is what is left.
    bytes.truncate(bytes.len() - 4);
    assert_eq!(
        description(&parse(&bytes, &Limits::DEFAULT).unwrap()),
        Some("odd")
    );
}

#[test]
fn lengths_beyond_the_parent_are_clamped() {
    let mut vs = standard();
    vs.length = Some(0xFFFF);
    vs.children[0].length = Some(0xFFF0);
    let v = blob(&vs).unwrap();
    assert_eq!(text(&v.strings.company_name), Some("Invented Games"));
}

#[test]
fn a_broken_fixed_part_is_none_and_the_strings_stay() {
    // Wrong signature.
    let mut vs = standard();
    let mut fixed = fixed_info([1, 2, 3, 4], [1, 2, 0, 0]);
    fixed[0] ^= 1;
    vs.value = Value::Bin(fixed);
    let v = blob(&vs).unwrap();
    assert_eq!(v.fixed, None);
    assert_eq!(text(&v.strings.file_version), Some("1.2.3.4"));
    // No fixed part at all.
    let mut vs = standard();
    vs.value = Value::None;
    let v = blob(&vs).unwrap();
    assert_eq!(v.fixed, None);
    assert_eq!(text(&v.strings.file_version), Some("1.2.3.4"));
    // A value of another length is not a VS_FIXEDFILEINFO.
    let mut vs = standard();
    vs.value = Value::Bin(vec![0xBD, 0x04, 0xEF, 0xFE, 0, 0, 0, 0]);
    let v = blob(&vs).unwrap();
    assert_eq!(v.fixed, None);
    assert_eq!(text(&v.strings.product_name), Some("Invented"));
    // wValueLength 52 but the block ends before the fixed part does.
    let mut vs = standard();
    vs.length = Some(40);
    assert_eq!(blob(&vs).unwrap(), VersionInfo::default());
}

#[test]
fn malformed_blocks_are_errors_with_their_position() {
    // Root key.
    let mut vs = standard();
    vs.key = "VS_VERSION_INFX".to_owned();
    assert_eq!(blob(&vs), Err((PeErrorKind::BadVersionBlock, 0)));
    let mut vs = standard();
    vs.key = "VS_VERSION_INFO2".to_owned();
    assert_eq!(blob(&vs), Err((PeErrorKind::BadVersionBlock, 0)));
    // ASCII case-insensitive, like every key.
    let mut vs = standard();
    vs.key = "vs_version_info".to_owned();
    assert!(blob(&vs).is_ok());
    // wLength below 6, and a key without NUL within the block.
    for length in [0, 5, 10] {
        let mut vs = standard();
        vs.length = Some(length);
        assert_eq!(
            blob(&vs),
            Err((PeErrorKind::BadVersionBlock, 0)),
            "{length}"
        );
    }
    assert_eq!(
        parse(&[], &Limits::DEFAULT),
        Err((PeErrorKind::BadVersionBlock, 0))
    );
    assert_eq!(
        parse(&[0x40], &Limits::DEFAULT),
        Err((PeErrorKind::BadVersionBlock, 0))
    );
    // A child with wLength 0: at the child's position.
    let mut vs = standard();
    vs.children[0].length = Some(0);
    let bytes = vs.encode();
    let child = find_key(&bytes, "StringFileInfo") - 6;
    assert_eq!(
        parse(&bytes, &Limits::DEFAULT),
        Err((PeErrorKind::BadVersionBlock, child))
    );
    // A string block with wLength 0.
    let mut vs = standard();
    vs.children[0].children[0].children[1].length = Some(3);
    let bytes = vs.encode();
    let at = find_key(&bytes, "FileDescription") - 6;
    assert_eq!(
        parse(&bytes, &Limits::DEFAULT),
        Err((PeErrorKind::BadVersionBlock, at))
    );
    // Blocks under keys that are not read are not looked into.
    let mut vs = standard();
    vs.children.push(Vs::new(
        "Unknown",
        Value::None,
        vec![{
            let mut b = Vs::string("x", "y");
            b.length = Some(1);
            b
        }],
    ));
    assert!(blob(&vs).is_ok());
}

/// Byte position of the UTF-16 key `key` in `bytes`.
fn find_key(bytes: &[u8], key: &str) -> usize {
    let needle: Vec<u8> = key.encode_utf16().flat_map(u16::to_le_bytes).collect();
    bytes
        .windows(needle.len())
        .position(|w| w == needle)
        .unwrap()
}

#[test]
fn kept_strings_up_to_the_limit_are_read() {
    let at_limit = "x".repeat(1024);
    let over = "x".repeat(1025);
    let vs = version_info(
        vec![string_table("040904b0", &[("ProductName", &at_limit)])],
        None,
    );
    assert_eq!(
        text(&blob(&vs).unwrap().strings.product_name).map(str::len),
        Some(1024)
    );
    let vs = version_info(
        vec![string_table("040904b0", &[("ProductName", &over)])],
        None,
    );
    let bytes = vs.encode();
    let at = find_key(&bytes, "ProductName") - 6;
    assert_eq!(
        parse(&bytes, &Limits::DEFAULT),
        Err((PeErrorKind::StringTooLong, at))
    );
    // A smaller limit.
    let small = Limits {
        max_version_string: 3,
        ..Limits::DEFAULT
    };
    let vs = version_info(
        vec![string_table("040904b0", &[("FileVersion", "1.0")])],
        None,
    );
    assert!(parse(&vs.encode(), &small).is_ok());
    let vs = version_info(
        vec![string_table("040904b0", &[("FileVersion", "1.0a")])],
        None,
    );
    assert_eq!(
        parse(&vs.encode(), &small).unwrap_err().0,
        PeErrorKind::StringTooLong
    );
    // Only kept keys of the chosen table count.
    let long = "x".repeat(5000);
    let vs = version_info(
        vec![
            string_table("040904b0", &[("Comments", &long), ("ProductName", "p")]),
            string_table("040704e4", &[("ProductName", &long)]),
        ],
        None,
    );
    assert_eq!(text(&blob(&vs).unwrap().strings.product_name), Some("p"));
}

#[test]
fn string_tables_up_to_the_limit_are_read() {
    let tables = |n: usize| {
        (0..n)
            .map(|i| described(&format!("{:04x}04b0", i + 1), "d"))
            .collect()
    };
    assert!(blob(&version_info(tables(64), None)).is_ok());
    let vs = version_info(tables(65), None);
    let bytes = vs.encode();
    let at = find_key(&bytes, "004104b0") - 6;
    assert_eq!(
        parse(&bytes, &Limits::DEFAULT),
        Err((PeErrorKind::TooManyStringTables, at))
    );
    // Tables with other keys count too.
    let mut many: Vec<Vs> = (0..64).map(|_| described("bad", "d")).collect();
    many.push(described("040904b0", "d"));
    assert_eq!(
        blob(&version_info(many, None)).unwrap_err().0,
        PeErrorKind::TooManyStringTables
    );
}

#[test]
fn strings_are_kept_raw_with_unpaired_surrogates_replaced() {
    let units = vec![0x0047, 0xD800, 0x0021, 0xDC00, 0];
    let table = Vs::new(
        "040904b0",
        Value::None,
        vec![
            Vs::new("FileDescription", Value::Units(units), Vec::new()),
            Vs::string("CompanyName", "Inv\u{2122} \u{1b}[31m\u{202E}"),
            Vs::string("ProductName", "\u{1F3AE} pair"),
        ],
    );
    let v = blob(&version_info(vec![table], None)).unwrap();
    assert_eq!(description(&v), Some("G\u{FFFD}!\u{FFFD}"));
    assert_eq!(
        text(&v.strings.company_name),
        Some("Inv\u{2122} \u{1b}[31m\u{202E}")
    );
    assert_eq!(text(&v.strings.product_name), Some("\u{1F3AE} pair"));
}

#[test]
fn debug_of_version_info_shows_no_strings() {
    let vs = version_info(
        vec![string_table(
            "040904b0",
            &[
                ("CompanyName", "SECRETMARKER"),
                ("Comments", "SECRETMARKER"),
            ],
        )],
        None,
    );
    let v = blob(&vs).unwrap();
    assert_eq!(text(&v.strings.company_name), Some("SECRETMARKER"));
    let shown = format!("{v:?} {v:#?}");
    assert!(!shown.contains("SECRET"), "{shown}");
}

// ---------- The RT_VERSION branch ----------

fn tree(b: &Builder, root: Vec<(ResId, Node)>) -> Result<Option<VersionInfo>, PeError> {
    let mut b = b.clone();
    b.resources = Some(root);
    through_pe(&b)
}

fn dir(entries: Vec<(ResId, Node)>) -> Node {
    Node::Dir(entries)
}

fn data(desc: &str) -> Node {
    Node::Data(version_info(vec![described("040904b0", desc)], None).encode())
}

fn rt_version(names: Vec<(ResId, Node)>) -> Vec<(ResId, Node)> {
    vec![(ResId::Id(l::RT_VERSION), dir(names))]
}

fn desc_of(r: Result<Option<VersionInfo>, PeError>) -> Option<String> {
    r.unwrap().and_then(|v| description(&v).map(str::to_owned))
}

#[test]
fn no_version_resource_is_none() {
    let b = Builder::x86();
    assert_eq!(through_pe(&b), Ok(None));
    assert_eq!(tree(&b, vec![]), Ok(None));
    // Only an icon.
    assert_eq!(
        tree(
            &b,
            vec![(ResId::Id(3), dir(vec![(ResId::Id(1), data("x"))]))]
        ),
        Ok(None)
    );
    // RT_VERSION as a name is not RT_VERSION.
    assert_eq!(
        tree(
            &b,
            vec![(ResId::Name, dir(vec![(ResId::Id(1), data("x"))]))]
        ),
        Ok(None)
    );
    // RT_VERSION without IDs, or an ID without languages.
    assert_eq!(tree(&b, rt_version(vec![])), Ok(None));
    assert_eq!(
        tree(&b, rt_version(vec![(ResId::Id(1), dir(vec![]))])),
        Ok(None)
    );
    assert_eq!(
        tree(&b, rt_version(vec![(ResId::Name, dir(vec![]))])),
        Ok(None)
    );
}

#[test]
fn the_id_is_1_else_the_lowest_and_names_are_skipped() {
    let b = Builder::x86();
    let lang = |d: &str| dir(vec![(ResId::Id(l::LANG_EN_US), data(d))]);
    let names = vec![
        (ResId::Id(3), lang("three")),
        (ResId::Id(1), lang("one")),
        (ResId::Id(2), lang("two")),
    ];
    assert_eq!(desc_of(tree(&b, rt_version(names))).as_deref(), Some("one"));
    let names = vec![(ResId::Id(5), lang("five")), (ResId::Id(3), lang("three"))];
    assert_eq!(
        desc_of(tree(&b, rt_version(names))).as_deref(),
        Some("three")
    );
    let names = vec![(ResId::Name, lang("named")), (ResId::Id(7), lang("seven"))];
    assert_eq!(
        desc_of(tree(&b, rt_version(names))).as_deref(),
        Some("seven")
    );
    // Equal IDs: the first.
    let names = vec![(ResId::Id(4), lang("a")), (ResId::Id(4), lang("b"))];
    assert_eq!(desc_of(tree(&b, rt_version(names))).as_deref(), Some("a"));
}

#[test]
fn the_language_is_neutral_else_en_us_else_the_lowest() {
    let b = Builder::x86();
    let pick = |langs: &[u16]| {
        let entries = langs
            .iter()
            .map(|&id| (ResId::Id(id), data(&format!("{id:04x}"))))
            .collect();
        desc_of(tree(&b, rt_version(vec![(ResId::Id(1), dir(entries))])))
    };
    assert_eq!(pick(&[0x0407, 0x0409, 0x0000]).as_deref(), Some("0000"));
    assert_eq!(pick(&[0x0407, 0x0409]).as_deref(), Some("0409"));
    assert_eq!(pick(&[0x0407, 0x0405, 0x0C0C]).as_deref(), Some("0405"));
}

#[test]
fn levels_of_the_wrong_kind_are_a_bad_tree() {
    let b = Builder::x86();
    let base = |b: &Builder, root: Vec<(ResId, Node)>| {
        let mut b = b.clone();
        b.resources = Some(root);
        b.build().rsrc.unwrap()
    };
    // RT_VERSION a data entry: at the root entry.
    let root = vec![(ResId::Id(l::RT_VERSION), data("x"))];
    let at = base(&b, root.clone()) + 16;
    assert_eq!(
        tree(&b, root),
        Err(PeError::at(PeErrorKind::BadResourceTree, off(at)))
    );
    // The ID a data entry, the language a directory.
    let root = rt_version(vec![(ResId::Id(1), data("x"))]);
    let at = base(&b, root.clone()) + TREE_NAMES + 16;
    assert_eq!(
        tree(&b, root),
        Err(PeError::at(PeErrorKind::BadResourceTree, off(at)))
    );
    let root = rt_version(vec![(
        ResId::Id(1),
        dir(vec![(ResId::Id(0x0409), dir(vec![]))]),
    )]);
    let at = base(&b, root.clone()) + TREE_LANGS + 16;
    assert_eq!(
        tree(&b, root),
        Err(PeError::at(PeErrorKind::BadResourceTree, off(at)))
    );
}

#[test]
fn resource_tables_up_to_the_limit_are_read() {
    let b = Builder::x86();
    let blob = standard().encode();
    let root = |n: usize| {
        let mut entries = version_tree(blob.clone());
        entries.extend((1..n).map(|i| {
            (
                ResId::Id(1000 + u16::try_from(i).unwrap()),
                Node::Data(Vec::new()),
            )
        }));
        entries
    };
    assert!(tree(&b, root(1024)).unwrap().is_some());
    let mut c = b.clone();
    c.resources = Some(root(1025));
    let img = c.build();
    assert_eq!(
        through_pe(&c),
        Err(PeError::at(
            PeErrorKind::TooManyResourceEntries,
            off(img.rsrc.unwrap())
        ))
    );
    // Named entries count too, at every level.
    let names = (0..1024)
        .map(|_| (ResId::Name, dir(vec![])))
        .chain([(ResId::Id(1), dir(vec![(ResId::Id(0), data("x"))]))])
        .collect();
    assert_eq!(
        tree(&b, rt_version(names)).unwrap_err().kind,
        PeErrorKind::TooManyResourceEntries
    );
}

#[test]
fn tables_and_entries_must_be_backed() {
    let b = with_version(&standard());
    let img = b.build();
    let rsrc = img.rsrc.unwrap();
    let parse_img = |bytes: &[u8]| {
        Pe::parse(Cursor::new(bytes), &Limits::DEFAULT)
            .unwrap()
            .version_info()
    };
    // The backed data ends inside the language table.
    let mut bytes = img.bytes.clone();
    let cut = rsrc - img.data + TREE_LANGS + 20;
    put32(
        &mut bytes,
        img.table + l::SECTION_VIRTUAL_SIZE,
        u32::try_from(cut).unwrap(),
    );
    assert_eq!(
        parse_img(&bytes),
        Err(PeError::at(
            PeErrorKind::Truncated,
            off(rsrc + TREE_LANGS + 16)
        ))
    );
    // A subdirectory offset pointing far away.
    let mut bytes = img.bytes.clone();
    put32(&mut bytes, rsrc + 20, 0x8000_0000 | 0x00F0_0000);
    assert_eq!(
        parse_img(&bytes),
        Err(PeError::at(PeErrorKind::RvaNotMapped, off(rsrc + 16)))
    );
    // An offset that overflows the RVA.
    let mut bytes = img.bytes.clone();
    put32(&mut bytes, rsrc + 20, 0xFFFF_FFFF);
    assert_eq!(
        parse_img(&bytes).unwrap_err().kind,
        PeErrorKind::RvaNotMapped
    );
    // The data RVA of the data entry in no section.
    let mut bytes = img.bytes.clone();
    put32(&mut bytes, rsrc + TREE_ENTRY, 0x00F0_0000);
    assert_eq!(
        parse_img(&bytes),
        Err(PeError::at(
            PeErrorKind::RvaNotMapped,
            off(rsrc + TREE_ENTRY)
        ))
    );
    // A size of 0 leaves nothing to parse; a huge size is clamped.
    let mut bytes = img.bytes.clone();
    put32(&mut bytes, rsrc + TREE_ENTRY + 4, 0);
    assert_eq!(
        parse_img(&bytes),
        Err(PeError::at(
            PeErrorKind::BadVersionBlock,
            off(rsrc + TREE_BLOB)
        ))
    );
    let mut bytes = img.bytes.clone();
    put32(&mut bytes, rsrc + TREE_ENTRY + 4, u32::MAX);
    assert!(parse_img(&bytes).unwrap().is_some());
    // An error inside the blob is reported at its file offset.
    let mut bytes = img.bytes.clone();
    bytes[rsrc + TREE_BLOB + 6] = b'X';
    assert_eq!(
        parse_img(&bytes),
        Err(PeError::at(
            PeErrorKind::BadVersionBlock,
            off(rsrc + TREE_BLOB)
        ))
    );
}

#[test]
fn only_max_version_bytes_are_read() {
    let mut vs = standard();
    // A root of about 60 KiB, then a limit below it: the root is clamped to what was read.
    vs.children[0].children[0]
        .children
        .push(Vs::string("Comments", &"c".repeat(30_000)));
    let b = with_version(&vs);
    let img = b.build();
    let limits = Limits {
        max_version_bytes: 4096,
        ..Limits::DEFAULT
    };
    let mut p = Pe::parse(Cursor::new(&img.bytes[..]), &limits).unwrap();
    let before = p.bytes_read();
    let v = p.version_info().unwrap().unwrap();
    // Three tables of one entry, the data entry, and 4,096 bytes of the blob.
    assert_eq!(p.bytes_read() - before, 3 * (16 + 8) + 16 + 4096);
    assert_eq!(text(&v.strings.company_name), Some("Invented Games"));
}

// ---------- Pe::info ----------

#[test]
fn info_keeps_headers_and_imports_when_the_version_is_broken() {
    let mut vs = standard();
    vs.key = "broken".to_owned();
    let mut b = with_version(&vs);
    b.imports = Some(vec![b"d3d9.dll".to_vec()]);
    let img = b.build();
    let mut p = Pe::parse(Cursor::new(&img.bytes[..]), &Limits::DEFAULT).unwrap();
    let info = p.info().unwrap();
    assert_eq!(info.imports[0].as_str(), "d3d9.dll");
    assert_eq!(info.delay_imports, vec![]);
    assert_eq!(
        info.version,
        Err(PeError::at(
            PeErrorKind::BadVersionBlock,
            off(img.rsrc.unwrap() + TREE_BLOB)
        ))
    );
    // A broken import table fails the whole call.
    let mut b = with_version(&standard());
    b.imports = Some(vec![b"bad\x01.dll".to_vec()]);
    let img = b.build();
    let mut p = Pe::parse(Cursor::new(&img.bytes[..]), &Limits::DEFAULT).unwrap();
    assert_eq!(p.info().unwrap_err().kind, PeErrorKind::BadDllName);
    // Without problems, everything.
    let mut b = with_version(&standard());
    b.imports = Some(vec![b"KERNEL32.dll".to_vec()]);
    b.delay = Some(vec![(b"d3d8.dll".to_vec(), false)]);
    let img = b.build();
    let mut p = Pe::parse(Cursor::new(&img.bytes[..]), &Limits::DEFAULT).unwrap();
    let info = p.info().unwrap();
    assert_eq!(info.headers.machine, crate::detect::pe::Machine::X86);
    assert_eq!(info.delay_imports[0].as_str(), "d3d8.dll");
    let shown = format!("{info:?}");
    assert!(info.version.unwrap().unwrap().fixed.is_some());
    assert!(!shown.contains("Invented"), "{shown}");
}

/// A cursor that fails every read starting at or after `from` (before the end of the file).
struct FailFrom<'a> {
    inner: Cursor<&'a [u8]>,
    from: u64,
}

impl std::io::Read for FailFrom<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let pos = self.inner.position();
        let len = u64::try_from(self.inner.get_ref().len()).unwrap();
        if pos >= self.from && pos < len {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "SECRETMARKER from the device",
            ));
        }
        self.inner.read(buf)
    }
}

impl std::io::Seek for FailFrom<'_> {
    fn seek(&mut self, to: std::io::SeekFrom) -> std::io::Result<u64> {
        self.inner.seek(to)
    }
}

#[test]
fn info_fails_on_reading_errors_in_the_version_part() {
    // An I/O error from the resource directory on is no property of the file: `info` fails,
    // `version_info` reports it as it is.
    let img = with_version(&standard()).build();
    let rsrc = off(img.rsrc.unwrap());
    let reader = FailFrom {
        inner: Cursor::new(&img.bytes[..]),
        from: rsrc,
    };
    let mut p = Pe::parse(reader, &Limits::DEFAULT).unwrap();
    let io = PeErrorKind::Io(std::io::ErrorKind::PermissionDenied);
    let e = p.info().unwrap_err();
    assert_eq!(e, PeError::at(io, rsrc));
    assert!(!format!("{e} / {e:?}").contains("SECRET"));
    assert_eq!(p.version_info().unwrap_err().kind, io);

    // The budget runs out inside the version part: the header region and the 16-byte root
    // table header fit, its entries do not.
    let header = u64::try_from(Limits::DEFAULT.max_header_bytes).unwrap();
    let limits = Limits {
        max_read_bytes: header + 16 + 7,
        ..Limits::DEFAULT
    };
    let mut p = Pe::parse(Cursor::new(&img.bytes[..]), &limits).unwrap();
    let e = p.info().unwrap_err();
    assert_eq!(e.kind, PeErrorKind::ReadBudget);
    assert_eq!(p.bytes_read(), header + 16);
    // With room for the three tables, the data entry and the blob, it is read again.
    let limits = Limits {
        max_read_bytes: header + 3 * (16 + 8) + 16 + 4096,
        ..Limits::DEFAULT
    };
    let mut p = Pe::parse(Cursor::new(&img.bytes[..]), &limits).unwrap();
    assert!(p.info().unwrap().version.unwrap().is_some());
}

#[test]
fn the_worst_case_of_every_limit_stays_within_the_budget() {
    let mut vs = standard();
    vs.children[0].children[0]
        .children
        .push(Vs::string("Comments", &"c".repeat(30_000)));
    let blob = vs.encode();
    let many = |first: (ResId, Node)| {
        let mut entries = vec![first];
        entries.extend((1..1024).map(|i| {
            (
                ResId::Id(2000 + u16::try_from(i).unwrap()),
                Node::Data(Vec::new()),
            )
        }));
        entries
    };
    let langs = many((ResId::Id(0), Node::Data(blob)));
    let names = many((ResId::Id(1), Node::Dir(langs)));
    let root = many((ResId::Id(l::RT_VERSION), Node::Dir(names)));
    let mut b = Builder::x64();
    b.extra_sections = 95;
    b.resources = Some(root);
    b.imports = Some(dll_names(1024, 255));
    b.delay = Some(
        dll_names(1024, 255)
            .into_iter()
            .map(|n| (n, true))
            .collect(),
    );
    b.load_config = Some((0x140, 0x800));
    let img = b.build();
    let mut p = Pe::parse(Cursor::new(&img.bytes[..]), &Limits::DEFAULT).unwrap();
    let info = p.info().unwrap();
    assert_eq!(p.dependent_load_flags(), Ok(Some(0x800)));
    assert_eq!(info.imports.len(), 1024);
    assert_eq!(info.delay_imports.len(), 1024);
    let v = info.version.unwrap().unwrap();
    assert_eq!(text(&v.strings.company_name), Some("Invented Games"));
    let read = p.bytes_read();
    assert!(read <= Limits::DEFAULT.max_read_bytes, "{read}");
    assert!(read > 600 * 1024, "{read}");
}

#[test]
fn mutated_version_resources_never_panic_and_stay_within_limits() {
    let mut seeds = Vec::new();
    let quirky = {
        let mut vs = version_info(
            vec![
                described("040704e4", "de"),
                string_table("040904b0", STRINGS),
            ],
            Some((0x0409, 0x04B0)),
        );
        vs.children[0].children[1].children[0].value_len = Some(30);
        vs
    };
    for vs in [standard(), quirky] {
        let mut b = with_version(&vs);
        b.imports = Some(vec![b"KERNEL32.dll".to_vec(), b"d3d9.dll".to_vec()]);
        seeds.push(b.build());
    }
    let small = Limits {
        max_resource_entries: 1,
        max_version_bytes: 200,
        max_version_string: 8,
        max_string_tables: 1,
        ..Limits::DEFAULT
    };
    let mut rng = Rng(0x5EED_0013_0000_0005);
    let (mut some, mut failed) = (0, 0);
    for round in 0..20_000 {
        let img = &seeds[round % seeds.len()];
        let mut bytes = img.bytes.clone();
        let rsrc = img.rsrc.unwrap();
        for _ in 0..1 + rng.below(4) {
            // Aim at the resource directory and the blob.
            let len = bytes.len();
            let mut tail = bytes.split_off(rsrc.min(len));
            mutate(&mut rng, &mut tail, 600);
            bytes.extend_from_slice(&tail);
        }
        let limits = if round % 4 == 0 {
            small
        } else {
            Limits::DEFAULT
        };
        let Ok(mut p) = Pe::parse(Cursor::new(&bytes[..]), &limits) else {
            continue;
        };
        match p.version_info() {
            Ok(Some(v)) => {
                some += 1;
                let s = &v.strings;
                for t in [
                    &s.company_name,
                    &s.file_description,
                    &s.file_version,
                    &s.original_filename,
                    &s.product_name,
                    &s.product_version,
                ]
                .into_iter()
                .flatten()
                {
                    assert!(t.as_raw_str().encode_utf16().count() <= limits.max_version_string);
                }
            }
            Ok(None) => {}
            Err(_) => failed += 1,
        }
        let _ = p.info();
        assert!(p.bytes_read() <= limits.max_read_bytes);
    }
    assert!(some > 1000 && failed > 1000, "some {some}, failed {failed}");
}
