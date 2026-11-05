use super::{
    CodePoint, Document, Entry, HARD_MAX_DEPTH, Limits, LineCol, Object, Value, VdfError,
    VdfErrorKind, parse,
};

const LIB_CURRENT: &[u8] =
    include_bytes!("../../../../../tests/fixtures/vdf/libraryfolders-current.vdf");
const LIB_LEGACY: &[u8] =
    include_bytes!("../../../../../tests/fixtures/vdf/libraryfolders-legacy.vdf");
const LIB_COMMENTS: &[u8] =
    include_bytes!("../../../../../tests/fixtures/vdf/libraryfolders-comments.vdf");
const ACF_MINIMAL: &[u8] =
    include_bytes!("../../../../../tests/fixtures/vdf/appmanifest-minimal.acf");
const ACF_FULL: &[u8] = include_bytes!("../../../../../tests/fixtures/vdf/appmanifest-full.acf");

pub(super) const FIXTURES: &[&[u8]] =
    &[LIB_CURRENT, LIB_LEGACY, LIB_COMMENTS, ACF_MINIMAL, ACF_FULL];

const L: Limits = Limits::LIBRARY_FOLDERS;

fn ok(input: &[u8]) -> Document {
    parse(input, &L).unwrap_or_else(|e| panic!("{e} in {:?}", String::from_utf8_lossy(input)))
}

fn err_with(input: &[u8], limits: &Limits) -> VdfError {
    match parse(input, limits) {
        Ok(doc) => panic!("parsed {doc:?} from {:?}", String::from_utf8_lossy(input)),
        Err(e) => e,
    }
}

fn err(input: &[u8]) -> (VdfErrorKind, usize) {
    let e = err_with(input, &L);
    (e.kind, e.offset)
}

fn ch(c: char) -> CodePoint {
    CodePoint(c)
}

fn str_of(e: &Entry) -> &str {
    e.value
        .as_str()
        .unwrap_or_else(|| panic!("{} is not a string", e.key))
}

fn obj_of(e: &Entry) -> &Object {
    e.value
        .as_object()
        .unwrap_or_else(|| panic!("{} is not an object", e.key))
}

fn only<'a>(o: &'a Object, key: &str) -> &'a Entry {
    o.get_unique(key)
        .unwrap_or_else(|d| panic!("{key}: {d}"))
        .unwrap_or_else(|| panic!("{key} missing"))
}

pub(super) fn small(
    max_bytes: usize,
    max_depth: usize,
    max_entries: usize,
    max_string: usize,
) -> Limits {
    Limits {
        max_bytes,
        max_depth,
        max_entries,
        max_string,
    }
}

// ---------- Accepted input ----------

#[test]
fn the_library_fixtures_parse() {
    let doc = ok(LIB_CURRENT);
    assert_eq!(doc.root().len(), 1);
    let lf = obj_of(only(doc.root(), "libraryfolders"));
    let keys: Vec<&str> = lf.entries().iter().map(|e| e.key.as_str()).collect();
    assert_eq!(keys, ["0", "1", "2"]);
    let two = obj_of(only(lf, "2"));
    assert_eq!(str_of(only(two, "path")), r"E:\Spiele\Bibliothek Ä");
    assert_eq!(str_of(only(two, "label")), "Ünterwegs");
    assert!(obj_of(only(two, "apps")).is_empty());
    let apps = obj_of(only(obj_of(only(lf, "0")), "apps"));
    assert_eq!(str_of(only(apps, "1000002")), "1048576");

    let legacy = ok(LIB_LEGACY);
    let lf = obj_of(only(legacy.root(), "libraryfolders"));
    assert_eq!(only(legacy.root(), "libraryfolders").key, "LibraryFolders");
    assert_eq!(str_of(only(lf, "1")), r"D:\Fixture Library");
    assert_eq!(str_of(only(lf, "contentstatsid")), "-3333333333333333333");
}

#[test]
fn comments_and_every_escape_are_accepted() {
    let doc = ok(LIB_COMMENTS);
    let lf = obj_of(only(doc.root(), "libraryfolders"));
    let zero = obj_of(only(lf, "0"));
    assert_eq!(str_of(only(zero, "path")), r"C:\Fixture\Steam");
    assert_eq!(
        str_of(only(zero, "label")),
        "Quote \" tab \t newline \n backslash \\ end"
    );
    assert!(obj_of(only(zero, "apps")).is_empty());
    assert_eq!(str_of(only(lf, "contentstatsid")), "-1");
}

#[test]
fn the_manifest_fixtures_parse() {
    let doc = ok(ACF_MINIMAL);
    let st = obj_of(only(doc.root(), "AppState"));
    assert_eq!(st.len(), 4);
    assert_eq!(str_of(only(st, "appid")), "1000001");

    let doc = ok(ACF_FULL);
    let st = obj_of(only(doc.root(), "appstate"));
    assert_eq!(str_of(only(st, "name")), "Fixture: The \"Quoted\" Edition");
    let depots = obj_of(only(st, "InstalledDepots"));
    assert_eq!(
        str_of(only(obj_of(only(depots, "1000005")), "dlcappid")),
        "1000006"
    );
}

#[test]
fn empty_and_whitespace_only_documents_are_empty() {
    for input in [
        &b""[..],
        b" \t\r\n",
        b"// only a comment",
        b"// a\n// b\n",
        b"\xEF\xBB\xBF",
        b"\xEF\xBB\xBF  // c",
    ] {
        assert!(ok(input).root().is_empty(), "{input:?}");
    }
}

#[test]
fn tokens_need_no_whitespace_between_them() {
    let doc = ok(br#""a""b""c"{"d""e"}"f"//x
"g""#);
    let keys: Vec<&str> = doc
        .root()
        .entries()
        .iter()
        .map(|e| e.key.as_str())
        .collect();
    assert_eq!(keys, ["a", "c", "f"]);
    assert_eq!(str_of(only(doc.root(), "f")), "g");
    assert_eq!(str_of(only(obj_of(only(doc.root(), "c")), "d")), "e");
}

#[test]
fn a_utf8_bom_is_skipped_but_offsets_count_it() {
    let doc = ok(b"\xEF\xBB\xBF\"a\" \"b\"");
    assert_eq!(doc.root().entries()[0].offset, 3);
    assert_eq!(str_of(only(doc.root(), "a")), "b");
    // Only one BOM: a second one is a character where a key is expected.
    assert_eq!(
        err(b"\xEF\xBB\xBF\xEF\xBB\xBF\"a\" \"b\""),
        (VdfErrorKind::UnexpectedChar { ch: ch('\u{FEFF}') }, 3)
    );
}

#[test]
fn crlf_and_lf_are_line_ends() {
    let crlf =
        b"\"libraryfolders\"\r\n{\r\n\t\"0\"\r\n\t{\r\n\t\t\"path\"\t\t\"C:\\\\X\"\r\n\t}\r\n}\r\n";
    let doc = ok(crlf);
    let lf = obj_of(only(doc.root(), "libraryfolders"));
    assert_eq!(str_of(only(obj_of(only(lf, "0")), "path")), r"C:\X");
    // A comment ends at LF; the CR before it belongs to the comment.
    let doc = ok(b"// c\r\n\"a\" \"b\"\r\n");
    assert_eq!(str_of(only(doc.root(), "a")), "b");
}

#[test]
fn raw_tabs_and_control_characters_in_strings_are_kept() {
    let doc = ok(b"\"k\" \"a\tb\x01c\x1b\x7f\"");
    assert_eq!(str_of(only(doc.root(), "k")), "a\tb\u{1}c\u{1b}\u{7f}");
}

#[test]
fn non_ascii_text_is_kept_exactly() {
    let doc = ok("\"Schlüssel\" \"Wert 日本 🎮\"".as_bytes());
    assert_eq!(str_of(only(doc.root(), "Schlüssel")), "Wert 日本 🎮");
}

#[test]
fn offsets_point_at_the_opening_quote_of_the_key() {
    let input = b"\"a\" { \"b\" \"c\" \"d\" { } }\n\"e\" \"f\"";
    let doc = ok(input);
    let a = only(doc.root(), "a");
    assert_eq!(a.offset, 0);
    let inner = obj_of(a);
    assert_eq!(only(inner, "b").offset, 6);
    assert_eq!(only(inner, "d").offset, 14);
    assert_eq!(only(doc.root(), "e").offset, 24);
}

// ---------- Duplicates, order, lookup ----------

#[test]
fn duplicates_and_order_are_preserved() {
    let doc = ok(br#""x" "1" "B" "2" "x" "3" "b" { } "X" "5""#);
    let keys: Vec<&str> = doc
        .root()
        .entries()
        .iter()
        .map(|e| e.key.as_str())
        .collect();
    assert_eq!(keys, ["x", "B", "x", "b", "X"]);
    let xs: Vec<&str> = doc.root().get_all("x").map(str_of).collect();
    assert_eq!(xs, ["1", "3", "5"]);
    assert_eq!(doc.root().get_all("b").count(), 2);
    let dup = doc.root().get_unique("X").unwrap_err();
    assert_eq!((dup.first, dup.second), (0, 16));
    assert_eq!(doc.root().get_unique("missing"), Ok(None));
}

#[test]
fn lookup_folds_ascii_only() {
    let doc = ok("\"Ä\" \"upper\" \"ä\" \"lower\" \"STATEFLAGS\" \"4\"".as_bytes());
    assert_eq!(str_of(only(doc.root(), "Ä")), "upper");
    assert_eq!(str_of(only(doc.root(), "ä")), "lower");
    assert_eq!(str_of(only(doc.root(), "StateFlags")), "4");
    // The Kelvin sign and the long s do not fold to ASCII.
    let doc = ok("\"\u{212A}\" \"kelvin\" \"\u{17F}\" \"long s\"".as_bytes());
    assert_eq!(doc.root().get_unique("k"), Ok(None));
    assert_eq!(doc.root().get_unique("s"), Ok(None));
}

// ---------- Errors with exact offsets ----------

#[test]
fn utf16_boms_are_refused() {
    assert_eq!(err(b"\xFF\xFE\"\0a\0\"\0"), (VdfErrorKind::Utf16Bom, 0));
    assert_eq!(err(b"\xFE\xFF\0\"\0a\0\""), (VdfErrorKind::Utf16Bom, 0));
    assert_eq!(err(b"\xFF\xFE"), (VdfErrorKind::Utf16Bom, 0));
}

#[test]
fn invalid_utf8_is_reported_at_the_first_bad_byte() {
    assert_eq!(err(b"\"a\xFF\" \"b\""), (VdfErrorKind::InvalidUtf8, 2));
    assert_eq!(err(b"\"k\" \"\xC3\""), (VdfErrorKind::InvalidUtf8, 5));
    // An encoded surrogate and an overlong form are invalid UTF-8.
    assert_eq!(err(b"\"\xED\xA0\x80\""), (VdfErrorKind::InvalidUtf8, 1));
    assert_eq!(err(b"\"\xC0\xA2\""), (VdfErrorKind::InvalidUtf8, 1));
    // Truncated BOM.
    assert_eq!(err(b"\xEF\xBB"), (VdfErrorKind::InvalidUtf8, 0));
}

#[test]
fn nul_is_refused_anywhere() {
    assert_eq!(err(b"\"a\0\" \"b\""), (VdfErrorKind::Nul, 2));
    assert_eq!(err(b"\"a\" \"b\" // c\0"), (VdfErrorKind::Nul, 12));
    assert_eq!(err(b"\0"), (VdfErrorKind::Nul, 0));
}

#[test]
fn unterminated_strings_are_reported_at_their_opening_quote() {
    use VdfErrorKind::UnterminatedString as U;
    assert_eq!(err(b"\"a\" \"bc"), (U, 4));
    assert_eq!(err(b"\"a\" \"b\nc\""), (U, 4));
    assert_eq!(err(b"\"a\" \"b\r\nc\""), (U, 4));
    assert_eq!(err(b"\"a\r\" \"b\""), (U, 0));
    assert_eq!(err(b"\"a"), (U, 0));
    assert_eq!(err(b"\""), (U, 0));
    assert_eq!(err(b"\"a\\"), (U, 0));
    assert_eq!(err(b"\"a\\\n\""), (U, 0));
    assert_eq!(err(b"\"a\\\r\n\""), (U, 0));
    // The classic hand-edit mistake: an unescaped backslash at the end of a path.
    assert_eq!(
        err(b"\"path\" \"D:\\Lib\\\"\n}"),
        (VdfErrorKind::UnknownEscape { ch: ch('L') }, 10)
    );
    assert_eq!(err(b"\"path\" \"D:\\\\Lib\\\"\n"), (U, 7));
}

#[test]
fn unknown_escapes_are_refused_at_the_backslash() {
    for (esc, c) in [
        ('r', 'r'),
        ('0', '0'),
        ('\'', '\''),
        ('u', 'u'),
        ('x', 'x'),
        ('a', 'a'),
        ('/', '/'),
        (' ', ' '),
        ('\t', '\t'),
        ('ä', 'ä'),
        ('🎮', '🎮'),
    ] {
        let input = format!("\"k\" \"ab\\{esc}c\"");
        assert_eq!(
            err(input.as_bytes()),
            (VdfErrorKind::UnknownEscape { ch: ch(c) }, 7),
            "{esc:?}"
        );
    }
    // In a key too.
    assert_eq!(
        err(b"\"\\q\" \"v\""),
        (VdfErrorKind::UnknownEscape { ch: ch('q') }, 1)
    );
}

#[test]
fn unexpected_characters() {
    use VdfErrorKind::UnexpectedChar as C;
    assert_eq!(err(b"{ }"), (C { ch: ch('{') }, 0));
    assert_eq!(err(b"\"a\" }"), (C { ch: ch('}') }, 4));
    assert_eq!(err(b"\"a\" { \"b\" } }"), (C { ch: ch('}') }, 10));
    assert_eq!(err(b"\"a\" \"b\" \x0B"), (C { ch: ch('\u{0B}') }, 8));
    assert_eq!(err(b"\x0C"), (C { ch: ch('\u{0C}') }, 0));
    assert_eq!(err(b"\"a\"\x01\"b\""), (C { ch: ch('\u{1}') }, 3));
    assert_eq!(err(b"\x7F"), (C { ch: ch('\u{7F}') }, 0));
    assert_eq!(err("\"a\" ä".as_bytes()), (C { ch: ch('ä') }, 4));
    assert_eq!(
        err("\u{A0}\"a\" \"b\"".as_bytes()),
        (C { ch: ch('\u{A0}') }, 0)
    );
    assert_eq!(
        err("\"a\"\u{2028}\"b\"".as_bytes()),
        (C { ch: ch('\u{2028}') }, 3)
    );
}

#[test]
fn unquoted_tokens_are_refused() {
    use VdfErrorKind::UnquotedToken as T;
    assert_eq!(err(b"key \"v\""), (T, 0));
    assert_eq!(err(b"\"k\" value"), (T, 4));
    assert_eq!(err(b"\"k\" 1"), (T, 4));
    assert_eq!(err(b"\"k\" \"v\" next"), (T, 8));
    assert_eq!(err(b"\"k\" { a \"b\" }"), (T, 6));
    assert_eq!(err(b"/ \"k\" \"v\""), (T, 0));
    assert_eq!(err(b"\"k\" \"v\"/"), (T, 7));
    assert_eq!(err(b"\"k\" \"v\" /*c*/"), (T, 8));
    assert_eq!(err(b"#other \"x\""), (T, 0));
    assert_eq!(err(b"#"), (T, 0));
    assert_eq!(err(b"$WIN32"), (T, 0));
}

#[test]
fn directives_are_refused_and_never_followed() {
    use VdfErrorKind::Directive as D;
    assert_eq!(err(b"#include \"other.vdf\""), (D, 0));
    assert_eq!(err(b"#base \"base.vdf\"\n\"a\" \"b\""), (D, 0));
    assert_eq!(err(b"#INCLUDE \"x\""), (D, 0));
    assert_eq!(err(b"#Base \"x\""), (D, 0));
    assert_eq!(err(b"\"a\" \"b\"\n#include \"x\""), (D, 8));
    assert_eq!(err(b"\"a\" {\n\t#base \"x\"\n}"), (D, 7));
    assert_eq!(err(b"\"a\" #include \"x\""), (D, 4));
}

#[test]
fn conditionals_are_refused() {
    use VdfErrorKind::Conditional as K;
    assert_eq!(err(b"\"k\" \"v\" [$WIN32]"), (K, 8));
    assert_eq!(err(b"\"k\" [$X360] { }"), (K, 4));
    assert_eq!(err(b"\"a\" { } [!$OSX]"), (K, 8));
    assert_eq!(err(b"[$WIN32]"), (K, 0));
}

#[test]
fn unbalanced_braces_and_early_ends() {
    assert_eq!(err(b"}"), (VdfErrorKind::UnbalancedBrace, 0));
    assert_eq!(err(b"\"a\" { } }"), (VdfErrorKind::UnbalancedBrace, 8));
    assert_eq!(err(b"\"a\" \"b\" }"), (VdfErrorKind::UnbalancedBrace, 8));
    assert_eq!(err(b"\"a\""), (VdfErrorKind::UnexpectedEnd, 3));
    assert_eq!(err(b"\"a\" // c"), (VdfErrorKind::UnexpectedEnd, 8));
    assert_eq!(err(b"\"a\" {"), (VdfErrorKind::UnexpectedEnd, 5));
    assert_eq!(
        err(b"\"a\" { \"b\" { } "),
        (VdfErrorKind::UnexpectedEnd, 14)
    );
    assert_eq!(err(b"\"a\" { \"b\""), (VdfErrorKind::UnexpectedEnd, 9));
}

#[test]
fn checks_run_in_the_documented_order() {
    // Size before everything.
    let tiny = small(2, 16, 10, 10);
    let e = err_with(b"\xFF\xFE\0", &tiny);
    assert_eq!((e.kind, e.offset), (VdfErrorKind::TooLarge { limit: 2 }, 2));
    // UTF-16 BOM before UTF-8 (FF is invalid UTF-8).
    assert_eq!(err(b"\xFF\xFE\xFF"), (VdfErrorKind::Utf16Bom, 0));
    // UTF-8 before NUL, even when the NUL comes first.
    assert_eq!(err(b"\0\"\xFF\""), (VdfErrorKind::InvalidUtf8, 2));
    // NUL before the grammar, even when the grammar error comes first.
    assert_eq!(err(b"} \0"), (VdfErrorKind::Nul, 2));
}

// ---------- Limits ----------

#[test]
fn the_size_limit_is_inclusive() {
    let input = b"\"a\" \"b\"";
    let at = small(input.len(), 16, 10, 10);
    assert!(parse(input, &at).is_ok());
    let below = small(input.len() - 1, 16, 10, 10);
    let e = err_with(input, &below);
    assert_eq!(
        (e.kind, e.offset),
        (
            VdfErrorKind::TooLarge {
                limit: input.len() - 1
            },
            input.len() - 1
        )
    );
    // The BOM counts.
    let bom = b"\xEF\xBB\xBF\"a\" \"b\"";
    assert!(parse(bom, &small(bom.len(), 16, 10, 10)).is_ok());
    assert!(parse(bom, &small(bom.len() - 1, 16, 10, 10)).is_err());
}

fn nested(depth: usize) -> String {
    let mut s = String::new();
    for _ in 0..depth {
        s.push_str("\"k\"{");
    }
    for _ in 0..depth {
        s.push('}');
    }
    s
}

#[test]
fn the_depth_limit_is_inclusive() {
    let at = nested(L.max_depth);
    let doc = ok(at.as_bytes());
    let mut o = doc.root();
    for _ in 0..L.max_depth {
        o = obj_of(only(o, "k"));
    }
    assert!(o.is_empty());

    let over = nested(L.max_depth + 1);
    assert_eq!(
        err(over.as_bytes()),
        (VdfErrorKind::TooDeep { limit: 16 }, 4 * 16 + 3)
    );
    let none = small(100, 0, 10, 10);
    assert!(parse(b"\"a\" \"b\"", &none).is_ok());
    let e = err_with(b"\"a\" {}", &none);
    assert_eq!((e.kind, e.offset), (VdfErrorKind::TooDeep { limit: 0 }, 4));
}

#[test]
fn the_depth_is_capped_whatever_the_caller_passes() {
    let huge = small(usize::MAX, usize::MAX, usize::MAX, usize::MAX);
    assert_eq!(huge.effective_depth(), HARD_MAX_DEPTH);
    assert!(parse(nested(HARD_MAX_DEPTH).as_bytes(), &huge).is_ok());
    let e = err_with(nested(HARD_MAX_DEPTH + 1).as_bytes(), &huge);
    assert_eq!(
        (e.kind, e.offset),
        (
            VdfErrorKind::TooDeep {
                limit: HARD_MAX_DEPTH
            },
            4 * HARD_MAX_DEPTH + 3
        )
    );
}

#[test]
fn a_million_open_braces_do_not_overflow_the_stack() {
    const N: usize = 1_000_000;
    // Balanced and unbalanced, with the shipped limit (the input fits in 4 MiB) and with
    // limits that would allow everything but the hard depth cap.
    let open = "\"k\"{".repeat(N);
    let balanced = format!("{open}{}", "}".repeat(N));
    let huge = small(usize::MAX, usize::MAX, usize::MAX, usize::MAX);
    assert!(open.len() <= L.max_bytes);
    for (input, limits, limit) in [
        (&open, &L, 16),
        (&open, &huge, HARD_MAX_DEPTH),
        (&balanced, &huge, HARD_MAX_DEPTH),
    ] {
        let e = err_with(input.as_bytes(), limits);
        assert_eq!(
            (e.kind, e.offset),
            (VdfErrorKind::TooDeep { limit }, 4 * limit + 3)
        );
    }
    // Raw braces without keys fail at the first one.
    let braces = "{".repeat(N);
    assert_eq!(
        err(braces.as_bytes()),
        (VdfErrorKind::UnexpectedChar { ch: ch('{') }, 0)
    );
}

#[test]
fn the_entry_limit_is_inclusive_and_counts_nested_pairs() {
    let limits = small(1000, 16, 3, 10);
    assert!(parse(br#""a" { "b" "1" "c" "2" }"#, &limits).is_ok());
    let e = err_with(br#""a" { "b" "1" "c" "2" } "d" "3""#, &limits);
    assert_eq!(
        (e.kind, e.offset),
        (VdfErrorKind::TooManyEntries { limit: 3 }, 24)
    );
    let e = err_with(br#""a" "1" "b" "2" "c" "3" "d" {}"#, &limits);
    assert_eq!(
        (e.kind, e.offset),
        (VdfErrorKind::TooManyEntries { limit: 3 }, 24)
    );
}

#[test]
fn the_shipped_entry_limits_hold() {
    for limits in [Limits::LIBRARY_FOLDERS, Limits::APP_MANIFEST] {
        let pair = "\"1\" \"2\"\n";
        let at = pair.repeat(limits.max_entries);
        assert!(at.len() <= limits.max_bytes);
        assert_eq!(
            parse(at.as_bytes(), &limits)
                .unwrap_or_else(|e| panic!("{e}"))
                .root()
                .len(),
            limits.max_entries
        );
        let over = pair.repeat(limits.max_entries + 1);
        let e = err_with(over.as_bytes(), &limits);
        assert_eq!(
            (e.kind, e.offset),
            (
                VdfErrorKind::TooManyEntries {
                    limit: limits.max_entries
                },
                pair.len() * limits.max_entries
            )
        );
    }
}

#[test]
fn the_string_limit_is_inclusive_and_counts_decoded_bytes() {
    let limits = small(1000, 16, 10, 4);
    for ok_input in [
        &br#""abcd" "wxyz""#[..],
        br#""a\nb\\" "\"\"\"\"""#,
        "\"äö\" \"€\"".as_bytes(), // 4 and 3 bytes
        br#""" """#,
    ] {
        assert!(
            parse(ok_input, &limits).is_ok(),
            "{:?}",
            String::from_utf8_lossy(ok_input)
        );
    }
    let too_long = VdfErrorKind::StringTooLong { limit: 4 };
    for (input, at) in [
        (&br#""abcde" "v""#[..], 0),
        (br#""k" "vwxyz""#, 4),
        (br#""k" "\\\\\\\\\\""#, 4),
        ("\"k\" \"äöü\"".as_bytes(), 4),
        // Also when the string never ends.
        (br#""k" "vwxyz"#, 4),
    ] {
        let e = err_with(input, &limits);
        assert_eq!((e.kind, e.offset), (too_long, at), "{input:?}");
    }
    // The shipped limit.
    let max = "x".repeat(L.max_string);
    assert!(parse(format!("\"{max}\" \"{max}\"").as_bytes(), &L).is_ok());
    let e = err_with(format!("\"k\" \"{max}x\"").as_bytes(), &L);
    assert_eq!(
        (e.kind, e.offset),
        (VdfErrorKind::StringTooLong { limit: 8192 }, 4)
    );
}

#[test]
fn the_shipped_limits_are_the_documented_ones() {
    assert_eq!(
        Limits::LIBRARY_FOLDERS,
        small(4 * 1024 * 1024, 16, 200_000, 8 * 1024)
    );
    assert_eq!(
        Limits::APP_MANIFEST,
        small(1024 * 1024, 16, 20_000, 8 * 1024)
    );
}

// ---------- Error reporting ----------

#[test]
fn line_and_column_are_computed_on_demand() {
    let lc = |input: &[u8]| {
        let e = err_with(input, &L);
        let LineCol { line, column } = e.line_col(input);
        (line, column)
    };
    assert_eq!(lc(b"x"), (1, 1));
    assert_eq!(lc(b"\"a\" \"b\"\n\"c\" x"), (2, 5));
    assert_eq!(lc(b"\"a\" \"b\"\r\n\"c\" x"), (2, 5));
    // Column in characters, the BOM not counted.
    assert_eq!(lc("\u{FEFF}\"ä€🎮\" x".as_bytes()), (1, 7));
    assert_eq!(lc("\"日本\" \"v\"\n\t\"ü\" ?".as_bytes()), (2, 6));
    // A lone CR is not a line end.
    assert_eq!(lc(b"\"a\" \"b\"\r\"c\" x"), (1, 13));
    // Invalid UTF-8 still yields a position.
    assert_eq!(lc(b"\"a\"\n\"\xFF\""), (2, 2));
    assert_eq!(LineCol::of(b"ab", 99), LineCol { line: 1, column: 3 });
    assert_eq!(
        LineCol::of(b"\xEF\xBB\xBF", 1),
        LineCol { line: 1, column: 1 }
    );
    assert_eq!(
        LineCol { line: 3, column: 7 }.to_string(),
        "line 3, column 7"
    );
}

#[test]
fn errors_never_show_file_content() {
    const MARK: &str = "SECRETMARKER";
    let cases = [
        format!("{MARK} \"v\""),
        format!("\"k\" {MARK}"),
        format!("\"{MARK}\" \"{MARK}"),
        format!("\"{MARK}\" \"{MARK}\n\""),
        format!("\"k\" \"{MARK}\\q{MARK}\""),
        format!("#include \"{MARK}\""),
        format!("#{MARK}"),
        format!("\"k\" [${MARK}]"),
        format!("\"{MARK}\" {{ \"{MARK}\" \"v\" }} }}"),
        format!("\"{MARK}\" {{ \"{MARK}\" \"v\""),
        format!("\"{MARK}\""),
        format!("\"k\" \"{MARK}\" \u{A0}{MARK}"),
        format!("\"k\" \"{MARK}\0\""),
        format!("\u{FEFF}\u{FEFF}{MARK}"),
        format!("\"k\" \"{}\"", MARK.repeat(1000)),
        format!("{}{MARK}", "\"k\"{".repeat(20)),
    ];
    for input in &cases {
        let e = err_with(input.as_bytes(), &L);
        let shown = format!("{e} / {e:?} / {}", e.line_col(input.as_bytes()));
        assert!(!shown.contains(MARK), "{shown}");
        assert!(!shown.contains("SECRET"), "{shown}");
    }
    let invalid = [b"\"k\" \"".as_slice(), MARK.as_bytes(), b"\xFF\""].concat();
    let e = err_with(&invalid, &L);
    assert!(!e.to_string().contains(MARK));
    let tiny = small(4, 16, 10, 10);
    let e = err_with(MARK.as_bytes(), &tiny);
    assert!(!e.to_string().contains(MARK));
}

#[test]
fn error_messages_name_kind_offset_and_code_point() {
    assert_eq!(
        err_with(b"\"k\" \"a\\x\"", &L).to_string(),
        "unknown escape: backslash followed by U+0078 at byte 6"
    );
    assert_eq!(
        err_with("\"k\" 🎮".as_bytes(), &L).to_string(),
        "unexpected character U+1F3AE at byte 4"
    );
    assert_eq!(
        err_with(nested(17).as_bytes(), &L).to_string(),
        "nesting deeper than 16 at byte 67"
    );
}

// ---------- Round trip with a test-only writer ----------

/// Writes `doc` in Steam's layout. Strings are escaped with the four supported escapes; a
/// raw CR cannot occur in a parsed string.
fn write(doc: &Document) -> String {
    fn quote(s: &str, out: &mut String) {
        out.push('"');
        for c in s.chars() {
            match c {
                '"' => out.push_str("\\\""),
                '\\' => out.push_str("\\\\"),
                '\n' => out.push_str("\\n"),
                '\t' => out.push_str("\\t"),
                c => out.push(c),
            }
        }
        out.push('"');
    }
    fn object(o: &Object, indent: usize, out: &mut String) {
        let tabs = "\t".repeat(indent);
        for e in o.entries() {
            out.push_str(&tabs);
            quote(&e.key, out);
            match &e.value {
                Value::Str(s) => {
                    out.push_str("\t\t");
                    quote(s, out);
                    out.push('\n');
                }
                Value::Obj(inner) => {
                    out.push('\n');
                    out.push_str(&tabs);
                    out.push_str("{\n");
                    object(inner, indent + 1, out);
                    out.push_str(&tabs);
                    out.push_str("}\n");
                }
            }
        }
    }
    let mut out = String::new();
    object(doc.root(), 0, &mut out);
    out
}

/// Parses `doc`'s written form and checks that it describes the same tree (the writer is
/// injective, so equal output means equal keys, values and structure; offsets differ). The
/// written form may be longer than the input (indentation, escapes), so only the byte limit
/// is lifted.
pub(super) fn assert_round_trip(doc: &Document, limits: &Limits) {
    let text = write(doc);
    let limits = Limits {
        max_bytes: usize::MAX,
        ..*limits
    };
    let again = parse(text.as_bytes(), &limits).unwrap_or_else(|e| panic!("{e} in {text:?}"));
    assert_eq!(write(&again), text);
}

#[test]
fn the_fixtures_round_trip() {
    for f in FIXTURES {
        assert_round_trip(&ok(f), &L);
    }
}

/// xorshift64*, so the loops are the same on every machine.
pub(super) struct Rng(pub(super) u64);

impl Rng {
    pub(super) fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    pub(super) fn below(&mut self, n: usize) -> usize {
        usize::try_from(self.next() % u64::try_from(n).unwrap()).unwrap()
    }

    pub(super) fn byte(&mut self) -> u8 {
        self.next().to_le_bytes()[0]
    }

    pub(super) fn pick<T: Copy>(&mut self, items: &[T]) -> T {
        items[self.below(items.len())]
    }
}

/// Characters a generated string draws from: every escape, raw tab, structure, comment
/// starters, non-ASCII, control characters. Never CR (no escape for it) and never NUL.
const STRING_CHARS: &[char] = &[
    'a', 'Z', '0', ' ', '"', '\\', '\n', '\t', '{', '}', '/', '#', '[', 'ä', '€', '🎮', '\u{1}',
    '\u{7f}', '\u{feff}',
];

fn random_string(rng: &mut Rng, max: usize) -> String {
    (0..rng.below(max + 1))
        .map(|_| rng.pick(STRING_CHARS))
        .collect()
}

fn random_object(rng: &mut Rng, depth: usize, budget: &mut usize) -> Object {
    let mut entries = Vec::new();
    while *budget > 0 && rng.below(4) != 0 {
        *budget -= 1;
        let key = random_string(rng, 6);
        let value = if depth > 0 && rng.below(3) == 0 {
            Value::Obj(random_object(rng, depth - 1, budget))
        } else {
            Value::Str(random_string(rng, 12))
        };
        entries.push(Entry {
            key,
            value,
            offset: 0,
        });
    }
    Object { entries }
}

#[test]
fn generated_documents_round_trip() {
    let mut rng = Rng(0x0123_4567_89AB_CDEF);
    for _ in 0..2_000 {
        let mut budget = 60;
        let doc = Document {
            root: random_object(&mut rng, 5, &mut budget),
        };
        assert_round_trip(&doc, &L);
    }
}

/// Walks the tree without recursion and checks every limit.
pub(super) fn assert_within(doc: &Document, limits: &Limits) {
    let mut stack = vec![(doc.root(), 0usize)];
    let mut entries = 0;
    while let Some((o, depth)) = stack.pop() {
        assert!(depth <= limits.effective_depth());
        for e in o.entries() {
            entries += 1;
            assert!(e.key.len() <= limits.max_string);
            match &e.value {
                Value::Str(s) => assert!(s.len() <= limits.max_string),
                Value::Obj(inner) => stack.push((inner, depth + 1)),
            }
        }
    }
    assert!(entries <= limits.max_entries);
}

/// Bytes that matter to the grammar.
const INTERESTING: &[u8] = &[
    b'"', b'{', b'}', b'\\', b'/', b'\n', b'\r', b'\t', b' ', b'#', b'[', b'n', b'a', 0, 0xEF,
    0xFF, 0xC3,
];

/// Limits small enough that the fuzz loops hit them.
const FUZZ: Limits = Limits {
    max_bytes: 4096,
    max_depth: 4,
    max_entries: 64,
    max_string: 48,
};

/// Parses `input` and checks the result: a document stays within the limits and round-trips,
/// an error lies within the input. `None` = parsed.
fn check_outcome(input: &[u8], limits: &Limits) -> Option<VdfErrorKind> {
    match parse(input, limits) {
        Ok(doc) => {
            assert_within(&doc, limits);
            assert_round_trip(&doc, limits);
            None
        }
        Err(e) => {
            assert!(e.offset <= input.len(), "{e} beyond {}", input.len());
            assert!(!e.to_string().is_empty());
            let lc = e.line_col(input);
            assert!(lc.line >= 1 && lc.column >= 1);
            Some(e.kind)
        }
    }
}

#[test]
fn mutated_fixtures_never_panic() {
    const ROUNDS: usize = 20_000;
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    let (mut parsed, mut by_limit) = (0, 0);
    for round in 0..ROUNDS {
        let mut buf = rng.pick(FIXTURES).to_vec();
        for _ in 0..=rng.below(3) {
            if buf.is_empty() {
                break;
            }
            match rng.below(6) {
                0 => {
                    let at = rng.below(buf.len());
                    buf[at] = rng.byte();
                }
                1 => {
                    let at = rng.below(buf.len());
                    buf[at] = rng.pick(INTERESTING);
                }
                2 => {
                    let at = rng.below(buf.len() + 1);
                    buf.insert(at, rng.pick(INTERESTING));
                }
                3 => {
                    let at = rng.below(buf.len());
                    buf.remove(at);
                }
                4 => {
                    let at = rng.below(buf.len() + 1);
                    buf.truncate(at);
                }
                _ => {
                    let from = rng.below(buf.len());
                    let to = (from + rng.below(64)).min(buf.len());
                    let piece = buf[from..to].to_vec();
                    let at = rng.below(buf.len() + 1);
                    buf.splice(at..at, piece);
                }
            }
        }
        // Every fourth round runs against small limits.
        let limits = if round % 4 == 0 { &FUZZ } else { &L };
        match check_outcome(&buf, limits) {
            None => parsed += 1,
            Some(
                VdfErrorKind::TooDeep { .. }
                | VdfErrorKind::TooManyEntries { .. }
                | VdfErrorKind::StringTooLong { .. }
                | VdfErrorKind::TooLarge { .. },
            ) => by_limit += 1,
            Some(_) => {}
        }
    }
    // Some mutations hit only string content; the loop must exercise both outcomes and
    // the limits.
    assert!(parsed > 0 && parsed < ROUNDS, "parsed {parsed}");
    assert!(by_limit > 0, "no limit was hit");
}

#[test]
fn random_bytes_never_panic() {
    let mut rng = Rng(0x2545_F491_4F6C_DD1D);
    for _ in 0..20_000 {
        let len = rng.below(300);
        let buf: Vec<u8> = (0..len)
            .map(|_| {
                if rng.below(2) == 0 {
                    rng.pick(INTERESTING)
                } else {
                    rng.byte()
                }
            })
            .collect();
        let _ = check_outcome(&buf, &FUZZ);
    }
}

#[test]
fn random_token_streams_hit_both_outcomes() {
    const ROUNDS: usize = 20_000;
    const TOKENS: &[&str] = &[
        "\"k\"",
        "\"v\"",
        "\"a\\\"b\"",
        "\"\\n\"",
        "{",
        "}",
        " ",
        "\t",
        "\n",
        "\r\n",
        "// c\n",
        "\"",
        "\\",
        "x",
        "#include",
        "[$W]",
        "\"\\q\"",
        "ä",
        "\u{feff}",
    ];
    let mut rng = Rng(0xDEAD_BEEF_CAFE_F00D);
    let mut parsed = 0;
    for _ in 0..ROUNDS {
        let mut s = String::new();
        for _ in 0..rng.below(24) {
            // Mostly well-formed pairs, sometimes a random token.
            match rng.below(5) {
                0 => s.push_str(rng.pick(TOKENS)),
                1 => s.push_str("\"k\" {"),
                2 => s.push('}'),
                _ => s.push_str("\"k\" \"v\" "),
            }
        }
        if check_outcome(s.as_bytes(), &FUZZ).is_none() {
            parsed += 1;
        }
    }
    assert!(parsed > 0 && parsed < ROUNDS, "parsed {parsed}");
}
