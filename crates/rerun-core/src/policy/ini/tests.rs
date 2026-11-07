//! I-tests of the INI editor (P2-12, ADR 0021): the dialect table, the positions of `edit`,
//! I1 exhaustively over a small alphabet, I2 (changes of someone else), the frozen output
//! (golden vectors, review M2), the grammar of names and values, and random bytes (review S5).

use sha2::{Digest, Sha256};

use super::{
    Encoding, Found, IniEdit, IniError, IniName, IniText, KeyState, Kind, Loc, MAX_INI_BYTES, Old,
    check_edits, edit, path_ok, scan, unedit,
};

fn n(s: &str) -> IniName {
    IniName::parse(s).unwrap()
}

fn t(s: &str) -> IniText {
    IniText::parse(s).unwrap()
}

fn val(v: &str) -> Old {
    Old::Value(t(v))
}

fn ed(section: &str, key: &str, old: Old, new: &str) -> IniEdit {
    IniEdit {
        section: n(section),
        key: n(key),
        old,
        new: t(new),
    }
}

/// What `get` finds for `[section] key`.
fn get(b: &[u8], section: &str, key: &str) -> Result<String, IniError> {
    let d = scan(b)?;
    Ok(match d.get(0, &n(section), &n(key))? {
        Found::NoSection => "no section".to_owned(),
        Found::NoKey => "no key".to_owned(),
        Found::Value(v) => format!("={v}"),
    })
}

#[test]
fn i_dialect_encodings_and_refusals() {
    assert_eq!(scan(b"a=1").unwrap().encoding, Encoding::Plain);
    assert_eq!(
        scan(b"\xEF\xBB\xBF[S]\r\na=1").unwrap().encoding,
        Encoding::Utf8Bom
    );
    assert_eq!(scan(b"").unwrap().lines.len(), 0);
    assert_eq!(scan(b"\xEF\xBB\xBF").unwrap().lines.len(), 0);
    // ANSI bytes are text (byte by byte), as is UTF-8.
    assert_eq!(
        get(b"[S]\r\nName=\xE9t\xE9", "S", "Name"),
        Err(IniError::Unusual { edit: 0 })
    );
    for (b, want) in [
        (&b"\xFF\xFE[\x00S\x00]\x00"[..], IniError::Utf16),
        (b"\xFE\xFF\x00[\x00S\x00]", IniError::Utf16),
        (b"\xFF\xFE\x00\x00", IniError::Utf16),
        (b"\x00\x00\xFE\xFF", IniError::Nul),
        (b"[\x00S\x00]\x00", IniError::Nul),
        (b"a=1\x00", IniError::Nul),
        (b"a=1\rb=2", IniError::LoneCr),
        (b"a=1\r", IniError::LoneCr),
        (b"a=1\r\r\n", IniError::LoneCr),
        (b"[S\r\na=1", IniError::Unclear),
        (b"x=1\n  [Other", IniError::Unclear),
    ] {
        assert_eq!(scan(b).map(|_| ()), Err(want), "{b:?}");
    }
    let big = vec![b'a'; MAX_INI_BYTES + 1];
    assert_eq!(scan(&big).map(|_| ()), Err(IniError::TooLarge));
    let max = vec![b'a'; MAX_INI_BYTES];
    assert!(scan(&max).is_ok());
}

#[test]
fn i_dialect_line_kinds() {
    let b = b"top=0\r\n\
              ; [S] Width=9\r\n\
              # Width=8\r\n\
              \t \r\n\
              [S] ; comment\r\n\
              Width = 1280 ; not a comment\r\n\
              Empty=\r\n\
              Quoted=\"a b\"\r\n\
              x\r\n\
              =nokey\n\
              [Other]junk\n\
              Width=5";
    let d = scan(b).unwrap();
    let kinds: Vec<&str> = d
        .lines
        .iter()
        .map(|l| match l.kind {
            Kind::Blank => "blank",
            Kind::Comment => "comment",
            Kind::Header { exact: true, .. } => "header",
            Kind::Header { exact: false, .. } => "header (not exact)",
            Kind::Key { .. } => "key",
            Kind::Other { .. } => "other",
        })
        .collect();
    assert_eq!(
        kinds,
        [
            "key",
            "comment",
            "comment",
            "blank",
            "header",
            "key",
            "key",
            "key",
            "other",
            "key",
            "header (not exact)",
            "key"
        ]
    );
    // No inline comments, no quotes interpreted; the key before the first header is no target.
    assert_eq!(get(b, "S", "Width"), Ok("=1280 ; not a comment".to_owned()));
    assert_eq!(get(b, "S", "Quoted"), Ok("=\"a b\"".to_owned()));
    assert_eq!(get(b, "S", "Empty"), Ok("=".to_owned()));
    assert_eq!(get(b, "S", "top"), Ok("no key".to_owned()));
    assert_eq!(get(b, "S", "Height"), Ok("no key".to_owned()));
    assert_eq!(get(b, "Missing", "Width"), Ok("no section".to_owned()));
    // Names folded, the file's spelling kept.
    assert_eq!(get(b, "s", "WIDTH"), Ok("=1280 ; not a comment".to_owned()));
    // `[Other]junk` is a boundary (S3), but no target.
    assert!(get(b, "S", "Width").is_ok());
    assert_eq!(
        get(b, "Other", "Width"),
        Err(IniError::Ambiguous { edit: 0 })
    );
    // A header with leading spaces is exact; spaces inside the brackets are not.
    assert_eq!(get(b"  [S]\nk=1", "S", "k"), Ok("=1".to_owned()));
}

#[test]
fn i_dialect_ambiguity_only_at_targets() {
    let amb = Err(IniError::Ambiguous { edit: 0 });
    for (what, b) in [
        ("section twice", &b"[S]\nk=1\n[s]\nj=2"[..]),
        ("spaces in the brackets", b"[ S ]\nk=1"),
        ("text after ]", b"[S] x\nk=1"),
        ("key twice", b"[S]\nk=1\nK = 2"),
        ("other line equal to the key", b"[S]\nk\nj=1"),
    ] {
        assert_eq!(get(b, "S", "k"), amb, "{what}");
    }
    // The same anomalies elsewhere are tolerated.
    let b = b"[A]\nk=1\nk=2\nk\n[ B ]\n[C] x\n[A2]\n[S]\nk=1\nj=2\n[D]\n[D]";
    assert_eq!(get(b, "S", "k"), Ok("=1".to_owned()));
    assert_eq!(get(b, "S", "j"), Ok("=2".to_owned()));
    // Unusual old values (the planner leaves them alone).
    let long = format!("[S]\nk={}", "x".repeat(129));
    assert_eq!(
        get(long.as_bytes(), "S", "k"),
        Err(IniError::Unusual { edit: 0 })
    );
    let ok = format!("[S]\nk={}", "x".repeat(128));
    assert!(get(ok.as_bytes(), "S", "k").is_ok());
    assert_eq!(
        get(b"[S]\nk=a\tb", "S", "k"),
        Err(IniError::Unusual { edit: 0 })
    );
    assert_eq!(
        get(b"[S]\nk=\x7f", "S", "k"),
        Err(IniError::Unusual { edit: 0 })
    );
}

#[test]
fn i_names_values_and_rules() {
    for ok in [
        "Display",
        "a",
        "Key.Name_1-2",
        "With Space",
        &"x".repeat(64),
    ] {
        assert!(IniName::parse(ok).is_ok(), "{ok}");
    }
    for bad in [
        "",
        " a",
        "a ",
        "a=b",
        "[a]",
        "a;b",
        "ä",
        "a\tb",
        &"x".repeat(65),
        "/Script/X",
    ] {
        assert_eq!(IniName::parse(bad), Err(IniError::Name), "{bad}");
    }
    for ok in [
        "",
        "1920",
        "a b",
        "x=y",
        "\"q\"",
        &"x".repeat(128),
        "~!@$^&*()",
    ] {
        assert!(IniText::parse(ok).is_ok(), "{ok}");
    }
    for bad in [" a", "a ", "a\tb", "ä", "\u{7f}", &"x".repeat(129)] {
        assert_eq!(IniText::parse(bad), Err(IniError::Text), "{bad}");
    }
    for ok in ["1920", "a b", "1.5", "true", "x=y", "-1"] {
        assert!(t(ok).check_new().is_ok(), "{ok}");
    }
    for bad in ["C:\\x", "a/b", "%TEMP%", "a;b", "#1", "..", "a..b", "x:1"] {
        assert!(t(bad).check_new().is_err(), "{bad}");
    }
    // Serde only through the parsers.
    assert!(serde_json::from_str::<IniName>("\" a\"").is_err());
    assert!(serde_json::from_str::<IniText>("\"a\\tb\"").is_err());
    let e = ed("Display", "Width", val("1280"), "1920");
    assert_eq!(
        serde_json::to_string(&e).unwrap(),
        r#"{"section":"Display","key":"Width","old":{"value":"1280"},"new":"1920"}"#
    );
    for (old, wire) in [
        (Old::NoKey, r#""no_key""#),
        (Old::NoSection, r#""no_section""#),
    ] {
        let e = ed("Display", "Width", old, "1920");
        let s = serde_json::to_string(&e).unwrap();
        assert!(s.contains(&format!(r#""old":{wire}"#)), "{s}");
        assert_eq!(serde_json::from_str::<IniEdit>(&s).unwrap(), e);
    }
    assert!(
        serde_json::from_str::<IniEdit>(
            r#"{"section":"S","key":"k","old":"no_key","new":"1","x":1}"#
        )
        .is_err()
    );
    // The extension.
    for (p, want) in [
        ("game.ini", true),
        (r"cfg\Game.INI", true),
        ("a.b.ini", true),
        ("desktop.ini", false),
        (r"x\Desktop.ini", false),
        ("game.cfg", false),
        (".ini", false),
        ("game.ini.bak", false),
        ("gameini", false),
    ] {
        assert_eq!(
            path_ok(&crate::path::RelPath::parse(p).unwrap()),
            want,
            "{p}"
        );
    }
}

#[test]
fn i_edit_lists() {
    let a = ed("A", "k", val("1"), "2");
    let b = ed("B", "k", Old::NoKey, "2");
    assert!(check_edits(&[a.clone(), b.clone()]).is_ok());
    for (what, list) in [
        ("empty", vec![]),
        ("unsorted", vec![b.clone(), a.clone()]),
        (
            "folded twice",
            vec![a.clone(), ed("a", "K", Old::NoKey, "3")],
        ),
        ("same value", vec![ed("A", "k", val("2"), "2")]),
        ("empty new", vec![ed("A", "k", val("2"), "")]),
        (
            "a section new and existing",
            vec![
                ed("A", "j", Old::NoSection, "1"),
                ed("A", "k", Old::NoKey, "1"),
            ],
        ),
        (
            "a section spelled two ways",
            vec![
                ed("A", "j", Old::NoSection, "1"),
                ed("a", "k", Old::NoSection, "1"),
            ],
        ),
        (
            "nine",
            (0..9)
                .map(|i| ed("A", &format!("k{i}"), Old::NoKey, "1"))
                .collect(),
        ),
    ] {
        assert!(
            matches!(check_edits(&list), Err(IniError::Edits(_))),
            "{what}"
        );
    }
}

/// `edit` and back with `unedit`, exactly.
fn round(f: &[u8], edits: &[IniEdit], want: &[u8]) {
    let got = edit(f, edits).unwrap();
    assert_eq!(
        String::from_utf8_lossy(&got),
        String::from_utf8_lossy(want),
        "edit of {:?}",
        String::from_utf8_lossy(f)
    );
    let back = unedit(&got, edits).unwrap();
    assert_eq!(
        back.bytes,
        f,
        "unedit of {:?}",
        String::from_utf8_lossy(&got)
    );
    assert!(back.keys.iter().all(|k| *k == KeyState::New));
}

#[test]
fn i_edit_positions() {
    // An existing key: only the value span; spaces around `=` stay.
    round(
        b"[Display]\r\nWidth = 1280 \r\nHeight=720\r\n",
        &[ed("Display", "Width", val("1280"), "1920")],
        b"[Display]\r\nWidth = 1920 \r\nHeight=720\r\n",
    );
    // An empty old value: at the end of the line's content.
    round(
        b"[S]\nk=  \nj=1",
        &[ed("S", "k", val(""), "5")],
        b"[S]\nk=  5\nj=1",
    );
    // A new key: right after the header, with the header's line ending.
    round(
        b"[S] ; c\r\nj=1\n",
        &[ed("S", "k", Old::NoKey, "5")],
        b"[S] ; c\r\nk=5\r\nj=1\n",
    );
    // A header at the end without a line ending: the first line ending of the file.
    round(
        b"a=1\n[S]",
        &[ed("S", "k", Old::NoKey, "5")],
        b"a=1\n[S]\nk=5",
    );
    // ... and CRLF if the file has none.
    round(b"[S]", &[ed("S", "k", Old::NoKey, "5")], b"[S]\r\nk=5");
    // A new section after the last line, with its line ending.
    round(
        b"[A]\r\na=1\r\n",
        &[ed("New", "k", Old::NoSection, "5")],
        b"[A]\r\na=1\r\n[New]\r\nk=5\r\n",
    );
    round(
        b"\xEF\xBB\xBF[A]\na=1",
        &[
            ed("B", "j", Old::NoSection, "2"),
            ed("B", "k", Old::NoSection, "1"),
            ed("C", "x", Old::NoSection, "3"),
        ],
        b"\xEF\xBB\xBF[A]\na=1\n[B]\nj=2\nk=1\n[C]\nx=3",
    );
    // New keys of an existing section at the last line come before a new section.
    round(
        b"[Z]\n",
        &[
            ed("A", "x", Old::NoSection, "1"),
            ed("Z", "k", Old::NoKey, "2"),
        ],
        b"[Z]\nk=2\n[A]\nx=1\n",
    );
    // Several keys at once, mixed line endings kept.
    round(
        b"[S]\r\nk=1\n[T]\nj = 2\r\n",
        &[
            ed("S", "a", Old::NoKey, "9"),
            ed("S", "k", val("1"), "10"),
            ed("T", "j", val("2"), "3"),
        ],
        b"[S]\r\na=9\r\nk=10\n[T]\nj = 3\r\n",
    );
    // Folded names: the file's spelling stays, a new section takes the step's.
    round(
        b"[display]\nWIDTH=1",
        &[ed("Display", "Width", val("1"), "2")],
        b"[display]\nWIDTH=2",
    );
}

#[test]
fn i_edit_refuses_what_is_not_the_old_state() {
    let f = b"[S]\nk=1\n";
    for (i, e) in [
        ed("S", "k", val("2"), "3"),
        ed("S", "k", Old::NoKey, "3"),
        ed("S", "k", Old::NoSection, "3"),
        ed("S", "j", val("1"), "3"),
        ed("T", "j", Old::NoKey, "3"),
        ed("S", "j", Old::NoSection, "3"),
    ]
    .into_iter()
    .enumerate()
    {
        assert_eq!(edit(f, &[e]), Err(IniError::NotOld { edit: 0 }), "{i}");
    }
    // A new section in a file without a header (S4), an empty one included.
    for f in [&b"a=1"[..], b"", b"\xEF\xBB\xBF"] {
        assert_eq!(
            edit(f, &[ed("S", "k", Old::NoSection, "1")]),
            Err(IniError::NoHeader)
        );
    }
    assert_eq!(
        edit(b"[S]\nk=1\nk=2", &[ed("S", "k", val("1"), "3")]),
        Err(IniError::Ambiguous { edit: 0 })
    );
    // Case matters for the old value (bytes).
    assert_eq!(
        edit(b"[S]\nk=True", &[ed("S", "k", val("true"), "0")]),
        Err(IniError::NotOld { edit: 0 })
    );
}

#[test]
fn i_unedit_key_states_and_drift() {
    let edits = [
        ed("S", "a", val("1"), "10"),
        ed("S", "b", Old::NoKey, "20"),
        ed("S", "c", val("3"), "30"),
        ed("T", "d", Old::NoSection, "40"),
    ];
    let f = b"[S]\r\na=1\r\nc=3\r\n";
    let e = edit(f, &edits).unwrap();
    assert_eq!(
        String::from_utf8(e.clone()).unwrap(),
        "[S]\r\nb=20\r\na=10\r\nc=30\r\n[T]\r\nd=40\r\n"
    );
    // The game changed `a`, removed `c` and `d`, added a key of its own: only `b` goes back.
    let g = b"[S]\r\nb=20\r\na=11\r\nmine=1\r\n[T]\r\n";
    let u = unedit(g, &edits).unwrap();
    assert_eq!(
        u.keys,
        [
            KeyState::Changed,
            KeyState::New,
            KeyState::Changed,
            KeyState::Old
        ]
    );
    // `[T]` was left empty by the game: it stays (documented).
    assert_eq!(u.bytes, b"[S]\r\na=11\r\nmine=1\r\n[T]\r\n");
    // Nothing of Rerun's left: the bytes as they are.
    let h = b"[S]\na=1\n";
    let u = unedit(h, &edits).unwrap();
    assert!(!u.writes());
    assert_eq!(u.bytes, h);
    // A duplicate of one of Rerun's keys is ambiguous (Foreign in exec).
    assert_eq!(
        unedit(b"[S]\nb=20\nb=20", &edits).map(|u| u.keys),
        Err(IniError::Ambiguous { edit: 1 })
    );
    // A section Rerun created with a key of the game: the header stays.
    let g = b"[S]\r\nb=20\r\na=10\r\nc=30\r\n[T]\r\nd=40\r\ngame=1\r\n";
    let u = unedit(g, &edits).unwrap();
    assert_eq!(u.bytes, b"[S]\r\na=1\r\nc=3\r\n[T]\r\ngame=1\r\n");
}

/// I2: someone changes lines outside Rerun's targets: `unedit(g(edit(f))) == g(f)`.
#[test]
fn i2_changes_of_someone_else_stay() {
    let f: &[u8] = b"; head\r\n[Video]\r\nWidth=1280\r\nGamma=1.0\r\n[Audio]\r\nVolume=5\r\n";
    let edits = [
        ed("Video", "Fullscreen", Old::NoKey, "1"),
        ed("Video", "Width", val("1280"), "1920"),
        ed("Zz", "k", Old::NoSection, "2"),
    ];
    let e = String::from_utf8(edit(f, &edits).unwrap()).unwrap();
    let f = String::from_utf8(f.to_vec()).unwrap();
    type G = fn(&str) -> String;
    let gs: [(&str, G); 6] = [
        ("a foreign value", |s| s.replace("Gamma=1.0", "Gamma=2.2")),
        ("a line inserted", |s| {
            s.replace("[Audio]\r\n", "[Audio]\r\nMusic=3\r\n")
        }),
        ("a line deleted", |s| s.replace("Gamma=1.0\r\n", "")),
        ("a comment inserted", |s| {
            s.replace("; head", "; head\r\n; more")
        }),
        ("LF in another section", |s| {
            s.replace("Volume=5\r\n", "Volume=5\n")
        }),
        ("a section added at the top", |s| {
            format!("[First]\r\na=1\r\n{s}")
        }),
    ];
    for (what, g) in gs {
        let u = unedit(g(&e).as_bytes(), &edits).unwrap();
        assert_eq!(String::from_utf8(u.bytes).unwrap(), g(&f), "{what}");
    }
}

/// The lines of `b` (content only), for the subsequence checks.
fn contents(b: &[u8]) -> Vec<Vec<u8>> {
    let d = scan(b).unwrap();
    d.lines
        .iter()
        .map(|l| b[l.start..l.content_end].to_vec())
        .collect()
}

/// `edit` changed only value spans and inserted lines: every line of `f` is in `e`, in
/// order, the same or a key line with only its value span changed.
fn only_spans_and_inserts(f: &[u8], e: &[u8]) -> bool {
    let (a, b) = (contents(f), contents(e));
    let same_key = |x: &[u8], y: &[u8]| {
        let (Some(i), Some(j)) = (
            x.iter().position(|c| *c == b'='),
            y.iter().position(|c| *c == b'='),
        ) else {
            return false;
        };
        x[..=i] == y[..=j]
    };
    let mut j = 0;
    for x in &a {
        loop {
            let Some(y) = b.get(j) else { return false };
            j += 1;
            if x == y || same_key(x, y) {
                break;
            }
        }
    }
    true
}

/// I1 exhaustively over a small alphabet: lines × line endings × BOM × last line with or
/// without a line ending × every set of edits the planner could make of the file.
#[test]
fn i1_unedit_of_edit_is_the_identity() {
    const LINES: &[&str] = &[
        "[Display]",
        "[Other] ; c",
        "Width=1280",
        " width = 640 ",
        "Depth=",
        "; Width=1",
        "",
        "x",
    ];
    let targets = [
        ("Display", "Width", "1920"),
        ("Display", "Depth", "32"),
        ("Other", "Width", "5"),
        ("New", "Key", "1"),
    ];
    let mut checked = 0usize;
    let mut kinds = [0usize; 3];
    let mut files = Vec::new();
    for len in 0..=3usize {
        let combos = LINES.len().pow(u32::try_from(len).unwrap());
        for c in 0..combos {
            let mut idx = Vec::new();
            let mut r = c;
            for _ in 0..len {
                idx.push(r % LINES.len());
                r /= LINES.len();
            }
            for eols in 0..(1usize << len) {
                for open_end in [false, true] {
                    for bom in [false, true] {
                        let mut f = Vec::new();
                        if bom {
                            f.extend_from_slice(b"\xEF\xBB\xBF");
                        }
                        for (k, i) in idx.iter().enumerate() {
                            f.extend_from_slice(LINES[*i].as_bytes());
                            if k + 1 < len || !open_end {
                                f.extend_from_slice(if eols >> k & 1 == 1 {
                                    b"\r\n"
                                } else {
                                    b"\n"
                                });
                            }
                        }
                        files.push(f);
                    }
                }
            }
        }
    }
    for f in &files {
        let Ok(d) = scan(f) else { continue };
        for set in 1..(1u32 << targets.len()) {
            let mut edits = Vec::new();
            let mut skip = false;
            for (i, (s, k, new)) in targets.iter().enumerate() {
                if set >> i & 1 == 0 {
                    continue;
                }
                let old = match d.get(0, &n(s), &n(k)) {
                    Ok(Found::Value(v)) if v == *new => continue,
                    Ok(Found::Value(v)) => val(v),
                    Ok(Found::NoKey) => Old::NoKey,
                    Ok(Found::NoSection) if d.has_header() => Old::NoSection,
                    _ => {
                        skip = true;
                        break;
                    }
                };
                edits.push(ed(s, k, old, new));
            }
            if skip || edits.is_empty() {
                continue;
            }
            edits.sort_by_key(super::IniEdit::order);
            let e = edit(f, &edits)
                .unwrap_or_else(|x| panic!("{x}: {:?} {edits:?}", String::from_utf8_lossy(f)));
            for x in &edits {
                kinds[match x.old {
                    Old::Value(_) => 0,
                    Old::NoKey => 1,
                    Old::NoSection => 2,
                }] += 1;
            }
            let u = unedit(&e, &edits).unwrap();
            assert_eq!(
                u.bytes,
                *f,
                "{:?} {edits:?} → {:?}",
                String::from_utf8_lossy(f),
                String::from_utf8_lossy(&e)
            );
            assert!(u.keys.iter().all(|k| *k == KeyState::New));
            assert!(
                only_spans_and_inserts(f, &e),
                "{:?}",
                String::from_utf8_lossy(f)
            );
            // The file as it was: nothing of Rerun's in it.
            let same = unedit(f, &edits).unwrap();
            assert_eq!(same.bytes, *f);
            assert!(same.keys.iter().all(|k| *k == KeyState::Old));
            checked += 1;
        }
    }
    assert!(checked > 10_000, "{checked}");
    assert!(kinds.iter().all(|k| *k > 1000), "{kinds:?}");
}

fn hex(b: &[u8]) -> String {
    crate::wire::hex32::to_string(&Sha256::digest(b).into())
}

/// M2: the bytes `edit` writes are frozen. A recorded head binds them (`exec::ini::binds`): a
/// change here makes every applied INI transaction unrevertable, so it needs a versioned
/// `edit` (ADR 0021). Inputs and their SHA-256 are fixed.
#[test]
fn i_m2_edit_output_is_frozen() {
    let edits = [
        ed("Audio", "Volume", val("5"), "7"),
        ed("Display", "Fullscreen", Old::NoKey, "1"),
        ed("Display", "Width", val(""), "1920"),
        ed("New Section", "Mode", Old::NoSection, "2"),
        ed("New Section", "Rate", Old::NoSection, "60"),
    ];
    let vectors: [(&[u8], &str); 4] = [
        (
            b"; game\r\n[Display]\r\nWidth=\r\nHeight=720\r\n[Audio]\r\nVolume = 5\r\n",
            "b0ade4f9bbcca0198a3e446b111de881a1ef03eb0faf4af6e0d88f94f1f8d029",
        ),
        (
            b"\xEF\xBB\xBF[display] ; v\nWIDTH=   \n[audio]\nvolume=5",
            "28e666aa13db36d6d294fc300f179897f4769f618868411fb2bf0a5f968ce2b9",
        ),
        (
            b"top=1\n  [Display]\r\nWidth=\n[Audio]\r\nVolume=5\r\n\r\n",
            "4bf607bc1b338095db10f37356bbebed1af9fda617bb20678ffc798a48d07c4c",
        ),
        (
            b"[Audio]\nVolume=5\n[Display]
Width=",
            "39caa1558c1964ab4cf796a98bfd1b99bbe40d1aea5957ad1a2b6965d3286f39",
        ),
    ];
    let mut got = Vec::new();
    for (f, _) in vectors {
        let e = match edit(f, &edits) {
            Ok(e) => e,
            Err(x) => panic!("{x}: {:?}", String::from_utf8_lossy(f)),
        };
        assert_eq!(unedit(&e, &edits).unwrap().bytes, f);
        got.push(hex(&e));
    }
    let want: Vec<String> = vectors.iter().map(|(_, h)| (*h).to_owned()).collect();
    assert_eq!(
        got,
        want,
        "{:?}",
        vectors.map(|(f, _)| String::from_utf8_lossy(&edit(f, &edits).unwrap()).into_owned())
    );
}

/// An independent reference for `unedit` (review S-2), assembled from the lines of `g`: every
/// line that is not Rerun's copied with its own line ending; a line holding exactly Rerun's
/// value either dropped (Rerun inserted it) or copied with only its value span replaced by the
/// old value; the header of a section Rerun created dropped when every line of the section is;
/// the documented exception: when the last line is dropped and has no line ending, the line
/// ending of the last line kept goes too. `None` where `unedit` must refuse.
fn reference(g: &[u8], edits: &[IniEdit]) -> Option<Vec<u8>> {
    let d = scan(g).ok()?;
    let n = d.lines.len();
    let mut dropped = vec![false; n];
    let mut replaced: Vec<Option<&[u8]>> = vec![None; n];
    let mut created = Vec::new();
    let mut any = false;
    for (i, e) in edits.iter().enumerate() {
        let loc = d.locate(u8::try_from(i).ok()?, &e.section, &e.key).ok()?;
        let Loc::Section {
            header,
            from,
            to,
            key,
        } = loc
        else {
            continue;
        };
        if e.old == Old::NoSection {
            created.push((header, from, to));
        }
        let Some(l) = key else { continue };
        let (s, t) = d.value(l);
        if &g[s..t] != e.new.as_str().as_bytes() {
            continue;
        }
        any = true;
        match &e.old {
            Old::Value(o) => replaced[l] = Some(o.as_str().as_bytes()),
            Old::NoKey | Old::NoSection => dropped[l] = true,
        }
    }
    if !any {
        return Some(g.to_vec());
    }
    for (h, f, t) in created {
        if t > f && dropped[f..t].iter().all(|x| *x) {
            dropped[h] = true;
        }
    }
    let mut out = Vec::new();
    if g.starts_with(b"\xEF\xBB\xBF") {
        out.extend_from_slice(b"\xEF\xBB\xBF");
    }
    let mut last_eol = 0;
    for (i, l) in d.lines.iter().enumerate() {
        if dropped[i] {
            continue;
        }
        let content = &g[l.start..l.content_end];
        match replaced[i] {
            Some(old) => {
                let (s, t) = d.value(i);
                out.extend_from_slice(&g[l.start..s]);
                out.extend_from_slice(old);
                out.extend_from_slice(&g[t..l.content_end]);
            }
            None => out.extend_from_slice(content),
        }
        out.extend_from_slice(&g[l.content_end..l.end]);
        last_eol = l.end - l.content_end;
    }
    let last = d.lines.last()?;
    if dropped[n - 1] && last.end == last.content_end {
        out.truncate(out.len() - last_eol);
    }
    (out.len() <= super::MAX_INI_BYTES).then_some(out)
}

/// xorshift64*, so the loops are the same on every machine.
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

/// S5: random bytes, many of them structure (`[ ] = ; CR LF`), never panic `scan`, `edit` or
/// `unedit`; whatever `edit` accepts comes back exactly (I1); `unedit` of the edited file,
/// changed at a random place, or of the random file itself equals [`reference`] (review S-2),
/// also with old and new values of unequal length.
#[test]
fn i_s5_random_bytes() {
    const ALPHABET: &[u8] = b"[]=;# \t\r\n\r\nkjSTkjST12\xEF\xBB\xBF\x00\xFF\xE9";
    let pool = [
        ed("S", "k", val("1"), "2"),
        ed("S", "j", Old::NoKey, "3"),
        ed("T", "k", Old::NoSection, "4"),
        ed("S", "k", Old::NoKey, "2"),
        ed("T", "k", val("2"), "4"),
        // Old and new values of unequal length (review S-2).
        ed("S", "k", val("1"), "22"),
        ed("T", "j", val("long value"), "x"),
        ed("S", "m", val("abc"), "z"),
    ];
    let mut rng = Rng(0x1d2c_3b4a_5968_7786);
    let mut stats = [0usize; 4];
    for _ in 0..60_000 {
        let len = rng.below(48);
        let mut f: Vec<u8> = (0..len)
            .map(|_| ALPHABET[rng.below(ALPHABET.len())])
            .collect();
        if rng.below(2) == 0 {
            f.splice(0..0, *b"[S]\n");
        }
        let mut edits: Vec<IniEdit> = Vec::new();
        for e in &pool {
            if rng.below(2) == 0 && !edits.iter().any(|x| x.order() == e.order()) {
                edits.push(e.clone());
            }
        }
        edits.sort_by_key(super::IniEdit::order);
        let _ = scan(&f).map(|d| (d.has_header(), d.get(0, &n("S"), &n("k"))));
        if check_edits(&edits).is_err() {
            continue;
        }
        // What `unedit` sees: the edited file, often changed by someone else at a random
        // place, or the random file itself.
        let g = match edit(&f, &edits) {
            Ok(e) => {
                stats[0] += 1;
                let u = unedit(&e, &edits).unwrap();
                assert_eq!(u.bytes, f, "{f:?} {edits:?}");
                assert!(u.keys.iter().all(|k| *k == KeyState::New));
                let mut g = e;
                if rng.below(3) > 0 {
                    let at = rng.below(g.len() + 1);
                    let chunk: Vec<u8> = (0..=rng.below(6))
                        .map(|_| ALPHABET[rng.below(ALPHABET.len())])
                        .collect();
                    g.splice(at..at, chunk);
                }
                g
            }
            Err(_) => {
                stats[1] += 1;
                f
            }
        };
        // S-2 (review): an independent reference for every result of `unedit`.
        let got = unedit(&g, &edits);
        let want = reference(&g, &edits);
        match (&got, &want) {
            (Ok(u), Some(w)) => {
                assert_eq!(
                    String::from_utf8_lossy(&u.bytes),
                    String::from_utf8_lossy(w),
                    "{g:?} {edits:?}"
                );
                stats[if u.writes() { 2 } else { 3 }] += 1;
            }
            (Err(_), None) => {}
            _ => panic!("{g:?} {edits:?}: unedit {got:?}, reference {want:?}"),
        }
    }
    assert!(stats.iter().all(|s| *s > 100), "{stats:?}");
}

/// The test knobs bite: K-I2 (line endings normalised) breaks I1, R-I8 (a forbidden
/// character) breaks `check_new` only.
#[test]
fn i_knobs_bite() {
    let f = b"[S]\r\nk=1\r\n";
    let edits = [ed("S", "k", val("1"), "2")];
    super::knob::normalise_eol(true);
    let e = edit(f, &edits);
    let back = e.as_ref().ok().and_then(|e| unedit(e, &edits).ok());
    super::knob::normalise_eol(false);
    assert_ne!(back.map(|u| u.bytes), Some(f.to_vec()));
    super::knob::forbid(Some('2'));
    let rule = t("2").check_new();
    super::knob::forbid(None);
    assert!(rule.is_err());
    assert!(t("2").check_new().is_ok());
}

/// S-1 (security review): `unedit` that would grow a file past 1 MiB (long old values put back
/// over a file the game filled up to the bound) is `TooLarge`, as is an `edit` past it.
#[test]
fn i_s1_results_are_bounded() {
    let long = "x".repeat(128);
    let edits = [ed("S", "k", val(&long), "1")];
    let applied = "[S]\nk=1\n;".to_owned();
    let mut g = applied.clone().into_bytes();
    g.resize(MAX_INI_BYTES - 10, b'p');
    assert!(scan(&g).is_ok());
    assert_eq!(
        unedit(&g, &edits).map(|u| u.bytes.len()),
        Err(IniError::TooLarge)
    );
    // Just inside the bound it is fine.
    let mut g = applied.into_bytes();
    g.resize(MAX_INI_BYTES - 127, b'p');
    assert_eq!(unedit(&g, &edits).map(|u| u.bytes.len()), Ok(MAX_INI_BYTES));
    // `edit` the other way round.
    let mut f = format!("[S]\nk={long}\n;").into_bytes();
    f.resize(MAX_INI_BYTES - 2, b'p');
    let grow = [ed("S", "j", Old::NoKey, "1")];
    assert_eq!(edit(&f, &grow), Err(IniError::TooLarge));
}

/// Nit 1 (security review): the lines of a scan are bounded (memory), so 1 MiB of line feeds
/// or of empty headers is `TooLarge`; 65,536 lines are scanned.
#[test]
fn i_the_number_of_lines_is_bounded() {
    let feeds = vec![b'\n'; MAX_INI_BYTES];
    assert_eq!(scan(&feeds).map(|_| ()), Err(IniError::TooLarge));
    let headers = b"[a]\n".repeat(MAX_INI_BYTES / 4);
    assert_eq!(scan(&headers).map(|_| ()), Err(IniError::TooLarge));
    let ok = vec![b'\n'; super::MAX_LINES];
    assert_eq!(scan(&ok).map(|d| d.lines.len()), Ok(super::MAX_LINES));
    let over = vec![b'\n'; super::MAX_LINES + 1];
    assert_eq!(scan(&over).map(|_| ()), Err(IniError::TooLarge));
}

/// Nit 5 (security review): brackets are refused in new values (rules in force now only).
#[test]
fn i_brackets_are_no_new_value() {
    for bad in ["[Display]", "a]", "[", "x[1]"] {
        assert!(t(bad).check_new().is_err(), "{bad}");
    }
}

/// M2 (senior-dev nit): the fallbacks for the line ending of inserted lines are frozen too: a
/// header as the last line without a line ending (the first line ending of the file), a file
/// without any line ending (CRLF), and a new section after a last line without one.
#[test]
fn i_m2_line_ending_fallbacks_are_frozen() {
    let vectors: [(&[u8], Vec<IniEdit>, &[u8]); 4] = [
        (
            b"a=1\n[S]",
            vec![ed("S", "k", Old::NoKey, "5")],
            b"a=1\n[S]\nk=5",
        ),
        (
            b"a=1\r\n[S]",
            vec![ed("S", "k", Old::NoKey, "5")],
            b"a=1\r\n[S]\r\nk=5",
        ),
        (b"[S]", vec![ed("S", "k", Old::NoKey, "5")], b"[S]\r\nk=5"),
        (
            b"[S]\nk=1",
            vec![ed("New", "a", Old::NoSection, "2")],
            b"[S]\nk=1\n[New]\na=2",
        ),
    ];
    for (f, edits, want) in vectors {
        let e = edit(f, &edits).unwrap();
        assert_eq!(
            String::from_utf8_lossy(&e),
            String::from_utf8_lossy(want),
            "{:?}",
            String::from_utf8_lossy(f)
        );
        assert_eq!(unedit(&e, &edits).unwrap().bytes, f);
    }
}
