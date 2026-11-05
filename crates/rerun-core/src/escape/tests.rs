//! Tests of the display escape (ADR 0016, `docs/09-testing.md`, "CLI").

use super::{BASE, in_base_set, in_path_set, path, text};
use crate::path::{RelPath, is_deceptive};

fn ch(cp: u32) -> char {
    char::from_u32(cp).unwrap_or_else(|| panic!("{cp:#x} is no scalar value"))
}

/// Every scalar value.
fn all_chars() -> impl Iterator<Item = char> {
    (0..=0x10_FFFFu32).filter_map(char::from_u32)
}

#[test]
fn the_table_is_sorted_and_without_overlaps() {
    for w in BASE.windows(2) {
        let [(s0, e0), (s1, e1)] = [w[0], w[1]];
        assert!(s0 <= e0 && s1 <= e1, "{w:x?}");
        assert!(e0 < s1, "overlap or unsorted: {w:x?}");
    }
    assert!(BASE.iter().all(|&(_, e)| e <= 0x10_FFFF));
}

#[test]
fn every_range_is_escaped_at_both_bounds_by_both_entry_points() {
    for &(start, end) in BASE {
        for cp in [start, end] {
            // Surrogates are no `char`; no range starts or ends in them.
            let c = ch(cp);
            assert!(in_base_set(c) && in_path_set(c), "{cp:#x}");
            let s = format!("a{c}b");
            assert!(text(&s).is_escaped(), "{cp:#x}");
            assert!(path(&s).is_escaped(), "{cp:#x}");
        }
    }
}

/// The code points just outside each range: `(code point, escaped by path)`. None is escaped
/// by `text`.
const NEIGHBOURS: &[(u32, bool)] = &[
    (0x0020, false),
    (0x007E, false),
    (0x00A0, true), // no-break space: deceptive
    (0x00AC, false),
    (0x00AE, false),
    (0x034E, false),
    (0x0350, false),
    (0x05FF, false),
    (0x0606, false),
    (0x061B, false),
    (0x061D, false),
    (0x06DC, false),
    (0x06DE, false),
    (0x070E, false),
    (0x0710, false),
    (0x088F, false),
    (0x0892, false),
    (0x08E1, false),
    (0x08E3, false),
    (0x115E, false),
    (0x1161, false),
    (0x17B3, false),
    (0x17B6, false),
    (0x180A, false),
    (0x1810, false),
    (0x200A, true), // hair space: deceptive
    (0x2010, false),
    (0x2027, false),
    (0x202F, true), // narrow no-break space: deceptive
    (0x205F, true), // medium mathematical space: deceptive
    (0x2070, false),
    (0x3163, false),
    (0x3165, false),
    (0xFDCF, false),
    (0xFDF0, false),
    (0xFDFF, false),
    (0xFE10, false),
    (0xFEFE, false),
    (0xFF00, false),
    (0xFF9F, false),
    (0xFFA1, false),
    (0xFFEF, false),
    (0xFFFC, false),
    (0xFFFD, false), // replacement character: kept
    (0x110BC, false),
    (0x110BE, false),
    (0x110CC, false),
    (0x110CE, false),
    (0x1342F, false),
    (0x13440, false),
    (0x1BC9F, false),
    (0x1BCA4, false),
    (0x1D172, false),
    (0x1D17B, false),
    (0xDFFFD, false),
    (0xE1000, false),
    (0xEFFFD, false),
];

#[test]
fn the_neighbours_of_every_range_are_kept_by_text() {
    for &(cp, by_path) in NEIGHBOURS {
        let c = ch(cp);
        let s = format!("a{c}b");
        assert!(!in_base_set(c), "{cp:#x}");
        assert!(!text(&s).is_escaped(), "{cp:#x}");
        assert_eq!(text(&s).as_str(), s);
        assert_eq!(path(&s).is_escaped(), by_path, "{cp:#x}");
    }
    // Every range has its neighbours in the list (or a neighbour that is itself escapable).
    for &(start, end) in BASE {
        for cp in [start.wrapping_sub(1), end + 1] {
            let Some(c) = char::from_u32(cp) else {
                continue;
            };
            if in_base_set(c) {
                continue;
            }
            assert!(
                NEIGHBOURS.iter().any(|&(n, _)| n == cp),
                "{cp:#x} missing in NEIGHBOURS"
            );
        }
    }
}

#[test]
fn noncharacters_of_every_plane_are_escaped() {
    for plane in 0..=0x10u32 {
        for low in [0xFFFE, 0xFFFF] {
            let c = ch(plane << 16 | low);
            assert!(in_base_set(c), "{c:?}");
        }
    }
    for cp in 0xFDD0..=0xFDEF {
        assert!(in_base_set(ch(cp)), "{cp:#x}");
    }
    // The code point before a plane's noncharacters is kept (outside private use).
    for plane in 0..=0xEu32 {
        let c = ch(plane << 16 | 0xFFFD);
        assert!(!in_base_set(c), "{c:?}");
    }
}

#[test]
fn the_sets_contain_what_they_promise() {
    let mut base = 0usize;
    for c in all_chars() {
        let b = in_base_set(c);
        base += usize::from(b);
        // Every control character is in the base set; path escapes everything text escapes
        // and everything is_deceptive matches.
        if c.is_control() {
            assert!(b, "{c:?}");
        }
        if b || is_deceptive(c) {
            assert!(in_path_set(c), "{c:?}");
        } else {
            assert!(!in_path_set(c), "{c:?}");
        }
    }
    // A sanity bound: private use A and B dominate (2 x 65,536), the rest is a few thousand.
    assert!((131_072..140_000).contains(&base), "{base}");
}

#[test]
fn terminal_and_layout_controls_are_escaped() {
    let cases: &[(&str, &str)] = &[
        // ANSI CSI (colour), OSC 8 (hyperlink), OSC 52 (clipboard), C1 CSI, BEL, CR, Tab.
        ("a\u{1b}[31mred", r#""a\u{1b}[31mred""#),
        (
            "\u{1b}]8;;http://x\u{1b}\\link",
            r#""\u{1b}]8;;http://x\u{1b}\\link""#,
        ),
        ("\u{1b}]52;c;SGk=\u{7}", r#""\u{1b}]52;c;SGk=\u{7}""#),
        ("x\u{9b}2Jy", r#""x\u{9b}2Jy""#),
        ("bell\u{7}", r#""bell\u{7}""#),
        ("over\rwrite", r#""over\rwrite""#),
        ("tab\there", r#""tab\there""#),
        ("new\nline", r#""new\nline""#),
        // Line and paragraph separator, zero width space, BOM.
        ("a\u{2028}b\u{2029}c", r#""a\u{2028}b\u{2029}c""#),
        ("zero\u{200B}width", r#""zero\u{200b}width""#),
        ("\u{FEFF}bom", r#""\u{feff}bom""#),
        // Bidi override, tag characters, supplementary private use, noncharacters.
        ("evil\u{202E}gpj.exe", r#""evil\u{202e}gpj.exe""#),
        (
            "flag\u{E0067}\u{E0062}\u{E007F}",
            r#""flag\u{e0067}\u{e0062}\u{e007f}""#,
        ),
        ("pua\u{F0000}\u{10FFFD}", r#""pua\u{f0000}\u{10fffd}""#),
        (
            "non\u{FDD0}\u{FFFE}\u{1FFFF}",
            r#""non\u{fdd0}\u{fffe}\u{1ffff}""#,
        ),
        // Variation selector, Hangul filler, soft hyphen.
        ("v\u{FE0F}\u{3164}\u{AD}", r#""v\u{fe0f}\u{3164}\u{ad}""#),
    ];
    for (raw, shown) in cases {
        assert_eq!(text(raw).as_str(), *shown, "text {raw:?}");
        assert_eq!(path(raw).as_str(), *shown, "path {raw:?}");
        assert!(text(raw).is_escaped());
    }
}

#[test]
fn confusables_stay_in_text_and_are_escaped_in_paths() {
    for (raw, as_path) in [
        (
            "Ｆｕｌｌ：ｗｉｄｔｈ",
            r#""\u{ff26}\u{ff55}\u{ff4c}\u{ff4c}\u{ff1a}\u{ff57}\u{ff49}\u{ff44}\u{ff54}\u{ff48}""#,
        ),
        ("C:\\Games\\a：b", r#""C:\\Games\\a\u{ff1a}b""#),
        ("¥100", r#""\u{a5}100""#),
        ("a\u{2215}b", r#""a\u{2215}b""#),
        ("no\u{A0}break", r#""no\u{a0}break""#),
        ("pua\u{E000}", r#""pua\u{e000}""#),
    ] {
        let t = text(raw);
        assert!(!t.is_escaped(), "{raw:?}");
        assert_eq!(t.as_str(), raw);
        assert_eq!(path(raw).as_str(), as_path, "{raw:?}");
    }
}

#[test]
fn clean_strings_are_borrowed_and_unchanged() {
    for s in [
        "",
        "Half-Life 2",
        r"C:\Program Files (x86)\Steam",
        "Straße ä",
        "日本語",
        "Ελληνικά",
        "broken \u{FFFD} name",
        "שלום", // strong right-to-left letters are no control characters
    ] {
        for shown in [text(s), path(s)] {
            assert!(!shown.is_escaped(), "{s:?}");
            assert_eq!(shown.as_str(), s);
            assert_eq!(shown.to_string(), s);
        }
    }
}

#[test]
fn every_valid_rel_path_fixture_is_unchanged_by_path() {
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("../../../../tests/fixtures/paths.json")).unwrap();
    let valid = fixture["valid"].as_array().unwrap();
    assert!(!valid.is_empty());
    for v in valid {
        let s = v.as_str().unwrap();
        assert!(RelPath::parse(s).is_ok(), "{s:?}");
        let shown = path(s);
        assert!(!shown.is_escaped(), "{s:?}");
        assert_eq!(shown.as_str(), s);
    }
}

/// xorshift64, fixed seed: reproducible.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }

    /// A scalar value: uniform over all of them, or ASCII, or one of the interesting ones.
    fn char(&mut self) -> char {
        const SPECIAL: &[char] = &[
            '\u{1b}',
            '\u{7}',
            '\r',
            '\n',
            '\t',
            '"',
            '\\',
            '\u{9b}',
            '\u{202E}',
            '\u{2028}',
            '\u{200B}',
            '\u{FEFF}',
            '\u{E0041}',
            '\u{F0000}',
            '\u{FFFE}',
            '\u{FFFD}',
            '\u{FF1A}',
            '\u{A5}',
            'ä',
            '日',
        ];
        match self.below(3) {
            0 => loop {
                let cp = u32::try_from(self.below(0x11_0000)).unwrap_or(0);
                if let Some(c) = char::from_u32(cp) {
                    break c;
                }
            },
            1 => ch(u32::try_from(0x20 + self.below(0x5F)).unwrap_or(0x20)),
            _ => {
                let i = usize::try_from(self.below(SPECIAL.len() as u64)).unwrap_or(0);
                SPECIAL[i]
            }
        }
    }
}

#[test]
fn random_strings_are_escaped_completely_and_idempotently() {
    let mut rng = Rng(0x5EED_0016_DEAD_BEEF);
    for _ in 0..20_000 {
        let len = rng.below(12);
        let s: String = (0..len).map(|_| rng.char()).collect();
        for (f, bad) in [
            (
                text as fn(&str) -> super::Shown<'_>,
                in_base_set as fn(char) -> bool,
            ),
            (path, in_path_set),
        ] {
            let once = f(&s);
            let clean = !s.chars().any(bad);
            assert_eq!(once.is_escaped(), !clean, "{s:?}");
            if clean {
                assert_eq!(once.as_str(), s);
            } else {
                let o = once.as_str();
                assert!(
                    o.starts_with('"') && o.ends_with('"') && o.len() >= 2,
                    "{o:?}"
                );
            }
            assert!(!once.as_str().chars().any(bad), "{s:?} -> {once:?}");
            let twice = f(once.as_str());
            assert!(!twice.is_escaped(), "{s:?}");
            assert_eq!(twice.as_str(), once.as_str());
        }
    }
}

#[test]
fn every_escapable_char_alone_is_escaped_without_a_trace() {
    for c in all_chars().filter(|c| in_path_set(*c)) {
        let s = c.to_string();
        let shown = path(&s);
        assert!(shown.is_escaped());
        assert!(!shown.as_str().chars().any(in_path_set), "{c:?}");
        if in_base_set(c) {
            assert!(!text(&s).as_str().chars().any(in_base_set), "{c:?}");
        }
    }
}
