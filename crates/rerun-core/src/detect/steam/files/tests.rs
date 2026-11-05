use super::{AppManifest, Expected, Library, LibraryFolders, ViewError};
use crate::detect::vdf::{Document, Limits, parse};

const LIB_CURRENT: &[u8] =
    include_bytes!("../../../../../../tests/fixtures/vdf/libraryfolders-current.vdf");
const LIB_LEGACY: &[u8] =
    include_bytes!("../../../../../../tests/fixtures/vdf/libraryfolders-legacy.vdf");
const LIB_COMMENTS: &[u8] =
    include_bytes!("../../../../../../tests/fixtures/vdf/libraryfolders-comments.vdf");
const ACF_MINIMAL: &[u8] =
    include_bytes!("../../../../../../tests/fixtures/vdf/appmanifest-minimal.acf");
const ACF_FULL: &[u8] = include_bytes!("../../../../../../tests/fixtures/vdf/appmanifest-full.acf");

fn doc(input: &[u8], limits: &Limits) -> Document {
    parse(input, limits).unwrap_or_else(|e| panic!("{e} in {:?}", String::from_utf8_lossy(input)))
}

fn libs(input: &str) -> Result<LibraryFolders, ViewError> {
    LibraryFolders::from_vdf(&doc(input.as_bytes(), &Limits::LIBRARY_FOLDERS))
}

fn manifest(input: &str) -> Result<AppManifest, ViewError> {
    AppManifest::from_vdf(&doc(input.as_bytes(), &Limits::APP_MANIFEST))
}

fn lib(path: &str, label: Option<&str>) -> Library {
    Library {
        path: path.to_owned(),
        label: label.map(str::to_owned),
    }
}

/// A manifest with the four required fields; `appid` and `StateFlags` as given.
fn app_state(appid: &str, flags: &str) -> String {
    format!(
        "\"AppState\"\n{{\n\t\"appid\"\t\t\"{appid}\"\n\t\"name\"\t\t\"N\"\n\t\"StateFlags\"\t\t\"{flags}\"\n\t\"installdir\"\t\t\"D\"\n}}\n"
    )
}

// ---------- libraryfolders.vdf ----------

#[test]
fn the_current_format_lists_every_library() {
    let lf = LibraryFolders::from_vdf(&doc(LIB_CURRENT, &Limits::LIBRARY_FOLDERS)).unwrap();
    assert_eq!(
        lf.libraries,
        [
            lib(r"C:\Fixture\Steam", Some("")),
            lib(r"D:\Fixture Library", Some("Fast SSD")),
            lib(r"E:\Spiele\Bibliothek Ä", Some("Ünterwegs")),
        ]
    );
}

#[test]
fn the_format_before_2021_is_supported() {
    let lf = LibraryFolders::from_vdf(&doc(LIB_LEGACY, &Limits::LIBRARY_FOLDERS)).unwrap();
    assert_eq!(
        lf.libraries,
        [
            lib(r"D:\Fixture Library", None),
            lib(r"E:\Other Fixture", None)
        ]
    );
}

#[test]
fn comments_do_not_change_the_view() {
    let lf = LibraryFolders::from_vdf(&doc(LIB_COMMENTS, &Limits::LIBRARY_FOLDERS)).unwrap();
    assert_eq!(
        lf.libraries,
        [lib(
            r"C:\Fixture\Steam",
            Some("Quote \" tab \t newline \n backslash \\ end")
        )]
    );
}

#[test]
fn both_formats_may_appear_in_one_file_and_order_and_duplicates_are_kept() {
    let lf = libs(r#""libraryfolders" { "1" "B:\\Old" "0" { "path" "A:\\New" } "1" "B:\\Old" }"#)
        .unwrap();
    assert_eq!(
        lf.libraries,
        [
            lib(r"B:\Old", None),
            lib(r"A:\New", None),
            lib(r"B:\Old", None)
        ]
    );
}

#[test]
fn non_numeric_keys_and_apps_are_ignored() {
    let lf = libs(
        r#""libraryfolders" {
            "contentstatsid" "-1"
            "TimeNextStatsReport" { "x" "y" }
            "+1" "ignored" " 1" "ignored" "1 " "ignored" "1a" "ignored" "" "ignored"
            "١" "arabic-indic digit, not ASCII"
            "0" { "path" "C:\\S" "apps" { "not" { "checked" "" } } "mounted" "1" }
        }"#,
    )
    .unwrap();
    assert_eq!(lf.libraries, [lib(r"C:\S", None)]);
    // Leading zeros are fine for library keys: they are only an index.
    let lf = libs(r#""libraryfolders" { "007" "C:\\S" }"#).unwrap();
    assert_eq!(lf.libraries, [lib(r"C:\S", None)]);
}

#[test]
fn keys_are_matched_ascii_case_insensitively() {
    let lf = libs(r#""LIBRARYFOLDERS" { "0" { "PATH" "C:\\S" "Label" "L" } }"#).unwrap();
    assert_eq!(lf.libraries, [lib(r"C:\S", Some("L"))]);
}

#[test]
fn an_empty_library_list_is_valid() {
    assert_eq!(libs(r#""libraryfolders" { }"#).unwrap().libraries, []);
}

#[test]
fn the_library_root_must_be_exactly_one_object() {
    let root = ViewError::Root {
        name: "libraryfolders",
    };
    for bad in [
        "",
        r#""other" { }"#,
        r#""libraryfolders" { } "libraryfolders" { }"#,
        r#""libraryfolders" { } "extra" "x""#,
        r#""extra" "x" "libraryfolders" { }"#,
    ] {
        assert_eq!(libs(bad), Err(root.clone()), "{bad}");
    }
    assert_eq!(
        libs(r#""libraryfolders" "x""#),
        Err(ViewError::WrongType {
            field: "libraryfolders",
            at: 0,
            expected: Expected::Obj
        })
    );
}

#[test]
fn a_malformed_library_fails_the_whole_file() {
    let good = r#""libraryfolders" { "0" { "path" "C:\\A" } "#;
    let cases: [(&str, ViewError); 5] = [
        (
            r#""1" { "label" "x" } }"#,
            ViewError::Missing {
                field: "path",
                at: 42,
            },
        ),
        (
            r#""1" { "path" "B" "Path" "C" } }"#,
            ViewError::Duplicate {
                field: "path",
                first: 48,
                second: 59,
            },
        ),
        (
            r#""1" { "path" { } } }"#,
            ViewError::WrongType {
                field: "path",
                at: 48,
                expected: Expected::Str,
            },
        ),
        (
            r#""1" { "path" "B" "label" { } } }"#,
            ViewError::WrongType {
                field: "label",
                at: 59,
                expected: Expected::Str,
            },
        ),
        (
            r#""1" { "path" "B" "label" "x" "LABEL" "y" } }"#,
            ViewError::Duplicate {
                field: "label",
                first: 59,
                second: 71,
            },
        ),
    ];
    for (tail, expected) in cases {
        let input = format!("{good}{tail}");
        assert_eq!(libs(&input), Err(expected), "{input}");
    }
}

#[test]
fn library_paths_stay_raw() {
    // Not this view's business: policy::root decides (step 12).
    for raw in [
        "",
        r"relative\\path",
        r"\\\\server\\share",
        r"C:\\Windows",
        r"..\\..",
    ] {
        let lf = libs(&format!(
            r#""libraryfolders" {{ "0" {{ "path" "{raw}" }} }}"#
        ))
        .unwrap();
        assert_eq!(lf.libraries.len(), 1, "{raw}");
    }
}

// ---------- appmanifest_<appid>.acf ----------

#[test]
fn the_manifest_fixtures_yield_their_fields() {
    let m = AppManifest::from_vdf(&doc(ACF_MINIMAL, &Limits::APP_MANIFEST)).unwrap();
    assert_eq!(
        m,
        AppManifest {
            app_id: 1_000_001,
            name: "Fixture Game".into(),
            install_dir: "Fixture Game".into(),
            state_flags: 4,
        }
    );
    let m = AppManifest::from_vdf(&doc(ACF_FULL, &Limits::APP_MANIFEST)).unwrap();
    assert_eq!(
        m,
        AppManifest {
            app_id: 1_000_003,
            name: "Fixture: The \"Quoted\" Edition".into(),
            install_dir: "Fixture Quoted Edition".into(),
            state_flags: 1026,
        }
    );
}

#[test]
fn app_ids_are_strict() {
    for good in ["1", "9", "10", "1000001", "4294967295"] {
        let m = manifest(&app_state(good, "4")).unwrap();
        assert_eq!(m.app_id.to_string(), good);
    }
    for bad in [
        "",
        "0",
        "00",
        "0123",
        "+1",
        "-1",
        " 1",
        "1 ",
        "\t1",
        "1\\n",
        "1_000",
        "1e3",
        "0x10",
        "4294967296",
        "9999999999",
        "12345678901",
        "00000000001",
        "１",
        "١",
    ] {
        let input = app_state(bad, "4");
        assert_eq!(
            manifest(&input),
            Err(ViewError::InvalidNumber {
                field: "appid",
                at: 14
            }),
            "{bad:?}"
        );
    }
}

#[test]
fn state_flags_are_strict_but_may_be_zero() {
    for (good, n) in [("0", 0), ("4", 4), ("1026", 1026), ("4294967295", u32::MAX)] {
        assert_eq!(manifest(&app_state("7", good)).unwrap().state_flags, n);
    }
    for bad in ["", "00", "04", "+4", " 4", "4294967296", "-0"] {
        assert!(
            matches!(
                manifest(&app_state("7", bad)),
                Err(ViewError::InvalidNumber {
                    field: "StateFlags",
                    ..
                })
            ),
            "{bad:?}"
        );
    }
}

#[test]
fn every_required_field_must_be_present_once_and_a_string() {
    let fields = [
        ("appid", "\"appid\" \"7\""),
        ("name", "\"name\" \"N\""),
        ("installdir", "\"installdir\" \"D\""),
        ("StateFlags", "\"StateFlags\" \"4\""),
    ];
    for (i, (field, _)) in fields.iter().enumerate() {
        let others: Vec<&str> = fields
            .iter()
            .enumerate()
            .filter(|&(j, _)| j != i)
            .map(|(_, (_, pair))| *pair)
            .collect();
        let rest = others.join(" ");

        let missing = format!("\"AppState\" {{ {rest} }}");
        assert_eq!(
            manifest(&missing),
            Err(ViewError::Missing { field, at: 0 }),
            "{missing}"
        );

        let wrong = format!("\"AppState\" {{ {rest} \"{field}\" {{ }} }}");
        assert!(
            matches!(manifest(&wrong), Err(ViewError::WrongType { field: f, expected: Expected::Str, .. }) if f == *field),
            "{wrong}"
        );

        let twice = format!(
            "\"AppState\" {{ {} {} }}",
            fields.map(|f| f.1).join(" "),
            fields[i].1
        );
        assert!(
            matches!(manifest(&twice), Err(ViewError::Duplicate { field: f, .. }) if f == *field),
            "{twice}"
        );
        // Also when the second spelling differs in case.
        let upper = format!(
            "\"AppState\" {{ {} {} }}",
            fields.map(|f| f.1).join(" "),
            fields[i].1.to_ascii_uppercase()
        );
        assert!(
            matches!(manifest(&upper), Err(ViewError::Duplicate { field: f, .. }) if f == *field),
            "{upper}"
        );
    }
}

#[test]
fn the_manifest_root_must_be_exactly_one_app_state_object() {
    let root = ViewError::Root { name: "AppState" };
    for bad in [
        String::new(),
        "\"Other\" { }".to_owned(),
        format!("{}{}", app_state("1", "4"), app_state("2", "4")),
        format!("{} \"extra\" \"x\"", app_state("1", "4")),
    ] {
        assert_eq!(manifest(&bad), Err(root.clone()), "{bad}");
    }
    assert_eq!(
        manifest("\"AppState\" \"x\""),
        Err(ViewError::WrongType {
            field: "AppState",
            at: 0,
            expected: Expected::Obj
        })
    );
    // Case-insensitive root and fields.
    let m = manifest(
        "\"appstate\" { \"APPID\" \"5\" \"Name\" \"n\" \"InstallDir\" \"d\" \"stateflags\" \"0\" }",
    )
    .unwrap();
    assert_eq!((m.app_id, m.state_flags), (5, 0));
}

#[test]
fn name_and_installdir_stay_raw() {
    let m = manifest(
        "\"AppState\" { \"appid\" \"5\" \"name\" \"a\\nb\\t\u{1b}[31m\" \"installdir\" \"..\\\\..\\\\Windows\" \"StateFlags\" \"4\" }",
    )
    .unwrap();
    assert_eq!(m.name, "a\nb\t\u{1b}[31m");
    assert_eq!(m.install_dir, r"..\..\Windows");
    let m = manifest(
        "\"AppState\" { \"appid\" \"5\" \"name\" \"\" \"installdir\" \"\" \"StateFlags\" \"4\" }",
    )
    .unwrap();
    assert_eq!((m.name.as_str(), m.install_dir.as_str()), ("", ""));
}

#[test]
fn view_errors_never_show_values() {
    const MARK: &str = "SECRETMARKER";
    let cases = [
        manifest(&app_state(MARK, "4")).unwrap_err(),
        manifest(&app_state("1", MARK)).unwrap_err(),
        manifest(&format!("\"{MARK}\" {{ }}")).unwrap_err(),
        manifest(&format!("\"AppState\" \"{MARK}\"")).unwrap_err(),
        libs(&format!(
            "\"libraryfolders\" {{ \"0\" {{ \"label\" \"{MARK}\" }} }}"
        ))
        .unwrap_err(),
        libs(&format!(
            "\"libraryfolders\" {{ \"0\" {{ \"path\" \"{MARK}\" \"path\" \"{MARK}\" }} }}"
        ))
        .unwrap_err(),
    ];
    for e in cases {
        let shown = format!("{e} / {e:?}");
        assert!(!shown.contains(MARK), "{shown}");
    }
}

// ---------- Fuzz: the views on mutated fixtures ----------

/// xorshift64*, so the loop is the same on every machine.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: usize) -> usize {
        usize::try_from(self.next() % u64::try_from(n).unwrap()).unwrap()
    }
}

#[test]
fn views_on_mutated_fixtures_never_panic() {
    const ROUNDS: usize = 20_000;
    const BYTES: &[u8] = b"\"{}\\0 a19\n";
    let fixtures: [&[u8]; 5] = [LIB_CURRENT, LIB_LEGACY, LIB_COMMENTS, ACF_MINIMAL, ACF_FULL];
    let mut rng = Rng(0x5DEE_CE66_D1CE_5EED);
    // Only the view matching the fixture counts: the other one always fails on `Root`,
    // which would satisfy "refused" without any mutation.
    let (mut ok, mut refused) = ([0usize; 2], [0usize; 2]);
    for _ in 0..ROUNDS {
        let pick = rng.below(fixtures.len());
        let view = usize::from(pick >= 3);
        let mut buf = fixtures[pick].to_vec();
        for _ in 0..=rng.below(2) {
            let at = rng.below(buf.len());
            match rng.below(3) {
                0 => buf[at] = BYTES[rng.below(BYTES.len())],
                1 => buf.insert(at, BYTES[rng.below(BYTES.len())]),
                _ => {
                    buf.remove(at);
                }
            }
        }
        let Ok(d) = parse(&buf, &Limits::LIBRARY_FOLDERS) else {
            continue;
        };
        let r = if view == 0 {
            LibraryFolders::from_vdf(&d).map(|_| ())
        } else {
            AppManifest::from_vdf(&d).map(|_| ())
        };
        match r {
            Ok(()) => ok[view] += 1,
            Err(e) => {
                assert!(!e.to_string().is_empty());
                refused[view] += 1;
            }
        }
    }
    assert!(
        ok.iter().chain(&refused).all(|&n| n > 0),
        "ok {ok:?}, refused {refused:?}"
    );
}
