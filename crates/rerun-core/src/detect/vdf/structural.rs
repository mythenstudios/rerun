//! Structural generators for the VDF harness (ADR 0016, open point "Fuzzing").
//!
//! The byte-level loops in `tests.rs` mutate fixtures blindly. These tests build documents
//! with a known shape (a model of the expected outcome) at, just under and just over every
//! limit, plus lexical oddities and structural mutations, and check the same invariants on
//! every input of every generator ([`check`]):
//!
//! - no panic; parsing twice gives equal results;
//! - an error offset is at most the input length, and `Display`, `Debug` and the line/column of
//!   an error never contain input bytes (a unique marker string is placed in the input);
//! - an `Ok` document stays within its limits, every entry offset points at an opening quote,
//!   and it round-trips through the test-only writer.
//!
//! Everything is deterministic (xorshift seeds, fixed iteration counts), stable Rust, no
//! dependency. The through-the-views part checks that `installdir` is either one classified
//! segment or refused, and that `AppManifest` never carries `LastOwner` or a SteamID.

use super::tests::{FIXTURES, Rng, assert_round_trip, assert_within, small};
use super::{Document, Entry, HARD_MAX_DEPTH, Limits, Value, VdfError, VdfErrorKind, parse};
use crate::detect::steam::files::{AppManifest, LibraryFolders};
use crate::path::classify;

/// Unique text that must never show up in an error.
const MARK: &str = "ZQ9MARKER9QZ";

const BOM: &str = "\u{FEFF}";

type Want = Option<(VdfErrorKind, usize)>;

// ---------- Invariants ----------

/// Walks the tree without recursion, in file order is not needed: `f(depth, entry)`.
fn walk(doc: &Document, mut f: impl FnMut(usize, &Entry)) {
    let mut stack = vec![(doc.root(), 1usize)];
    while let Some((o, depth)) = stack.pop() {
        for e in o.entries() {
            f(depth, e);
            if let Value::Obj(inner) = &e.value {
                stack.push((inner, depth + 1));
            }
        }
    }
}

fn entry_count(doc: &Document) -> usize {
    let mut n = 0;
    walk(doc, |_, _| n += 1);
    n
}

fn max_depth(doc: &Document) -> usize {
    let mut deepest = 0;
    walk(doc, |d, e| {
        if matches!(e.value, Value::Obj(_)) {
            deepest = deepest.max(d);
        }
    });
    deepest
}

/// The tree in file order without offsets, one line per string pair, object start and end.
fn shape(doc: &Document) -> Vec<String> {
    let mut out = Vec::new();
    let mut stack = vec![doc.root().entries().iter()];
    while let Some(it) = stack.last_mut() {
        match it.next() {
            None => {
                stack.pop();
                out.push("}".to_owned());
            }
            Some(e) => match &e.value {
                Value::Str(s) => out.push(format!("{:?}={:?}", e.key, s)),
                Value::Obj(o) => {
                    out.push(format!("{:?}{{", e.key));
                    stack.push(o.entries().iter());
                }
            },
        }
    }
    out
}

/// Parses `input` and checks every invariant. `label` names the case in a failure message
/// (the input itself may be megabytes).
fn check(label: &str, input: &[u8], limits: &Limits) -> Result<Document, VdfError> {
    let first = parse(input, limits);
    assert_eq!(first, parse(input, limits), "{label}: not deterministic");
    match &first {
        Ok(doc) => {
            assert!(
                input.len() <= limits.max_bytes,
                "{label}: accepted too much"
            );
            assert_within(doc, limits);
            walk(doc, |_, e| {
                assert_eq!(
                    input.get(e.offset),
                    Some(&b'"'),
                    "{label}: offset {} of {:?} is not a quote",
                    e.offset,
                    e.key.len()
                );
            });
            assert_round_trip(doc, limits);
        }
        Err(e) => {
            assert!(
                e.offset <= input.len(),
                "{label}: {e} beyond {}",
                input.len()
            );
            let lc = e.line_col(input);
            assert!(lc.line >= 1 && lc.column >= 1, "{label}: {lc}");
            let shown = format!("{e} | {e:?} | {lc} | {lc:?}");
            assert!(!shown.contains(MARK), "{label}: leaked content: {shown}");
            assert!(shown.len() < 200, "{label}: message too long: {shown}");
            // Characters are shown as U+XXXX only, so the text is plain ASCII whatever the input.
            assert!(shown.is_ascii(), "{label}: non-ASCII in {shown}");
        }
    }
    first
}

/// [`check`] plus the expected outcome: `None` = parses, `Some((kind, offset))` = that error.
fn expect(label: &str, input: &[u8], limits: &Limits, want: Want) -> Option<Document> {
    let got = check(label, input, limits);
    match (got, want) {
        (Ok(doc), None) => Some(doc),
        (Err(e), Some((kind, offset))) => {
            assert_eq!((e.kind, e.offset), (kind, offset), "{label}");
            None
        }
        (Ok(doc), Some(w)) => panic!(
            "{label}: parsed {} entries, wanted {w:?}",
            entry_count(&doc)
        ),
        (Err(e), None) => panic!("{label}: refused ({e}), wanted ok"),
    }
}

fn must_fail(label: &str, input: &[u8], limits: &Limits) -> VdfError {
    check(label, input, limits).expect_err(label)
}

// ---------- Builders ----------

/// Source text of `s`: quoted, with the four escapes.
fn quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
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
    out
}

/// A document under construction. Remembers where every key starts, so a test knows the
/// offset the parser must report.
struct Build {
    text: String,
    keys: Vec<usize>,
    open: usize,
    nl: &'static str,
}

/// Separators after a token: LF, CRLF, tab, nothing but a space, a lone CR, a comment that
/// contains quotes and braces.
const GAPS: &[&str] = &[
    "\n",
    "\r\n",
    "\t",
    " ",
    "\r",
    " // c \"q\" { }\n",
    " //\r\n",
];

impl Build {
    fn new(nl: &'static str) -> Self {
        Self {
            text: String::new(),
            keys: Vec::new(),
            open: 0,
            nl,
        }
    }

    fn pair(&mut self, key: &str, value: &str) {
        self.keys.push(self.text.len());
        self.text.push_str(&quote(key));
        self.text.push('\t');
        self.text.push_str(&quote(value));
        self.text.push_str(self.nl);
    }

    fn begin(&mut self, key: &str) {
        self.keys.push(self.text.len());
        self.text.push_str(&quote(key));
        self.text.push_str(self.nl);
        self.text.push('{');
        self.text.push_str(self.nl);
        self.open += 1;
    }

    fn end(&mut self) {
        self.text.push('}');
        self.text.push_str(self.nl);
        self.open -= 1;
    }

    fn finish(mut self) -> Self {
        while self.open > 0 {
            self.end();
        }
        self
    }
}

/// Characters of a random string: structure, escapes, non-ASCII, control characters. Never
/// CR (no escape for it) and never NUL.
const FULL_CHARS: &[char] = &[
    'a', 'Z', '0', ' ', '"', '\\', '\n', '\t', '{', '}', '/', '#', '[', 'ä', '€', '🎮', '\u{1}',
    '\u{7f}', '\u{feff}',
];

/// Characters that are never structure, never need an escape and never form a comment
/// starter: removing or adding a brace or quote in such a document always unbalances it.
const PLAIN_CHARS: &[char] = &[
    'a', 'Z', '0', ' ', '#', '[', 'ä', '€', '🎮', '\u{1}', '\u{7f}',
];

fn rand_str(rng: &mut Rng, max: usize, alphabet: &[char]) -> String {
    (0..rng.below(max + 1))
        .map(|_| rng.pick(alphabet))
        .collect()
}

/// `pairs` pairs (objects count as one) spread over objects up to `depth` deep.
fn random_doc(
    rng: &mut Rng,
    pairs: usize,
    depth: usize,
    nl: &'static str,
    alphabet: &[char],
) -> Build {
    let mut b = Build::new(nl);
    for i in 0..pairs {
        let key = if i == 0 {
            MARK.to_owned()
        } else {
            rand_str(rng, 6, alphabet)
        };
        if b.open < depth && rng.below(3) == 0 {
            b.begin(&key);
        } else {
            let value = rand_str(rng, 12, alphabet);
            b.pair(&key, &value);
        }
        if b.open > 0 && rng.below(4) == 0 {
            b.end();
        }
    }
    b.finish()
}

// ---------- Depth ----------

/// `depth` nested objects around one pair; the offset of every `{`.
fn nest(depth: usize, gap: &str) -> (String, Vec<usize>) {
    let mut s = String::new();
    let mut braces = Vec::new();
    for _ in 0..depth {
        s.push_str("\"k\"");
        s.push_str(gap);
        braces.push(s.len());
        s.push('{');
        s.push_str(gap);
    }
    s.push_str("\"leaf\" \"v\"");
    s.push_str(gap);
    for _ in 0..depth {
        s.push('}');
        s.push_str(gap);
    }
    (s, braces)
}

#[test]
fn nesting_at_and_over_the_depth_limit() {
    let configured = [
        0,
        1,
        2,
        3,
        16,
        63,
        HARD_MAX_DEPTH,
        HARD_MAX_DEPTH + 1,
        1000,
        usize::MAX,
    ];
    for cfg in configured {
        let limits = small(usize::MAX, cfg, usize::MAX, usize::MAX);
        let eff = cfg.min(HARD_MAX_DEPTH);
        assert_eq!(limits.effective_depth(), eff);
        let mut depths = vec![eff, eff + 1, HARD_MAX_DEPTH, HARD_MAX_DEPTH + 1];
        depths.extend(eff.checked_sub(1));
        depths.sort_unstable();
        depths.dedup();
        for depth in depths {
            for gap in GAPS {
                let (text, braces) = nest(depth, gap);
                let label = format!("depth {depth} limit {cfg} gap {gap:?}");
                let want =
                    (depth > eff).then(|| (VdfErrorKind::TooDeep { limit: eff }, braces[eff]));
                if let Some(doc) = expect(&label, text.as_bytes(), &limits, want) {
                    assert_eq!(max_depth(&doc), depth, "{label}");
                }
            }
        }
    }
}

#[test]
fn siblings_do_not_add_up_to_depth() {
    // Depth is the number of objects open at once, not the number of objects.
    let limits = small(usize::MAX, 1, usize::MAX, usize::MAX);
    let flat = "\"k\" { \"a\" \"b\" }\n".repeat(500);
    let doc = expect("siblings", flat.as_bytes(), &limits, None).expect("parsed");
    assert_eq!(doc.root().len(), 500);
    let over = format!("{flat}\"k\" {{ \"n\" {{ }} }}");
    must_fail("one more level", over.as_bytes(), &limits);
}

// ---------- Strings ----------

/// Source text and decoded byte length of the units a string is built from.
const UNITS: &[(&str, usize)] = &[
    ("x", 1),
    ("\\\"", 1),
    ("\\\\", 1),
    ("\\n", 1),
    ("\\t", 1),
    ("é", 2),
    ("€", 3),
    ("🎮", 4),
    (" ", 1),
    ("{", 1),
    ("//", 2),
    ("#", 1),
];

/// Source text of a string body that decodes to exactly `n` bytes.
fn body_of_len(rng: &mut Rng, n: usize) -> String {
    let mut body = String::new();
    let mut have = 0;
    while have < n {
        let (src, len) = rng.pick(UNITS);
        if have + len <= n {
            body.push_str(src);
            have += len;
        }
    }
    body
}

#[test]
fn strings_at_and_over_the_string_limit() {
    let mut rng = Rng(0x57A1_0001_D00D_F00D);
    let prefixes = ["", BOM, "// c\r\n", "\"p\" { \"\" \"\" }\n"];
    for s in [0usize, 1, 2, 3, 4, 5, 63, 64, 65, 255, 8192] {
        let limits = small(1 << 20, 16, 100, s);
        // Decoded length relative to the limit: under, at, over by one, straddling with a
        // multi-byte character.
        for delta in [-1isize, 0, 1, 2] {
            for round in 0..6 {
                let (body, decoded) = if delta == 2 && s >= 1 {
                    // Over the limit by a multi-byte character instead of by a plain byte.
                    let mut body = body_of_len(&mut rng, s - 1);
                    body.push('€');
                    (body, s + 2)
                } else {
                    let n = s.saturating_add_signed(delta);
                    (body_of_len(&mut rng, n), n)
                };
                for position in 0..3usize {
                    // A limit of 0 allows only empty strings: no "k", "v" or "p" around.
                    if position == 2 && s == 0 {
                        continue;
                    }
                    let prefix = prefixes[(round + position) % prefixes.len()];
                    let prefix = if s == 0 && prefix.contains('p') {
                        ""
                    } else {
                        prefix
                    };
                    let (text, quote_at) = match position {
                        0 => (format!("{prefix}\"{body}\" \"\""), prefix.len()),
                        1 => (format!("{prefix}\"\" \"{body}\""), prefix.len() + 3),
                        _ => (
                            format!("{prefix}\"k\" {{ \"{body}\" \"v\" }}"),
                            prefix.len() + 6,
                        ),
                    };
                    let label = format!("string {decoded} limit {s} position {position}");
                    let want = (decoded > s)
                        .then_some((VdfErrorKind::StringTooLong { limit: s }, quote_at));
                    if let Some(doc) = expect(&label, text.as_bytes(), &limits, want) {
                        let mut longest = 0;
                        walk(&doc, |_, e| {
                            longest = longest.max(e.key.len());
                            if let Value::Str(v) = &e.value {
                                longest = longest.max(v.len());
                            }
                        });
                        let others = usize::from(position == 2 || prefix.contains('p'));
                        assert_eq!(longest, decoded.max(others), "{label}");
                    }
                }
            }
        }
    }
}

#[test]
fn escapes_at_the_string_boundary() {
    let limits = small(1 << 10, 4, 10, 4);
    // (value source, error?) with a limit of 4 decoded bytes.
    let cases: &[(&str, bool)] = &[
        (r#"xxx\n"#, false),
        (r#"xxxx\n"#, true),
        (r#"xxx\""#, false),
        (r#"xxxx\""#, true),
        (r#"\\\\\\\\"#, false),
        (r#"\\\\\\\\\\"#, true),
        (r#"\t\t\t\t"#, false),
        (r#"\t\t\t\t\t"#, true),
        ("xx€", true),
        ("x€", false),
        ("xxx€", true),
        ("🎮", false),
        ("x🎮", true),
    ];
    for (src, over) in cases {
        let text = format!("\"k\" \"{src}\"");
        let want = over.then_some((VdfErrorKind::StringTooLong { limit: 4 }, 4));
        expect(src, text.as_bytes(), &limits, want);
    }
    // A string that never ends: too long once it is, unterminated before that.
    let long = [
        ("\"k\" \"xxxx", false),
        ("\"k\" \"xxxxx", true),
        ("\"k\" \"xxxx\n\"", false),
        ("\"k\" \"xxxxx\n\"", true),
        ("\"k\" \"xxxx\r", false),
        ("\"k\" \"xxxxx\r", true),
        ("\"k\" \"xxx\\n", false),
        ("\"k\" \"xxx\\nx", true),
    ];
    for (src, over) in long {
        let kind = if over {
            VdfErrorKind::StringTooLong { limit: 4 }
        } else {
            VdfErrorKind::UnterminatedString
        };
        expect(src, src.as_bytes(), &limits, Some((kind, 4)));
    }
    // An escape cut off by the end of the input or a line end.
    for src in ["\"k\" \"x\\", "\"k\" \"x\\\n\"", "\"k\" \"x\\\r\n\""] {
        expect(
            src,
            src.as_bytes(),
            &limits,
            Some((VdfErrorKind::UnterminatedString, 4)),
        );
    }
}

#[test]
fn unquoted_tokens_of_any_length_are_refused_alike() {
    for s in [1usize, 8, 9, 63, 64, 65] {
        let limits = small(1 << 20, 16, 100, s);
        for n in [s, s + 1, 2 * s] {
            let token = format!("{MARK}{}", "x".repeat(n));
            for (text, at) in [
                (format!("{token} \"v\""), 0),
                (format!("\"k\" {token}"), 4),
                (format!("\"k\" {{ {token} }}"), 6),
                (format!("\"k\" \"v\" // {token}\n{token}"), 12 + token.len()),
            ] {
                let e = must_fail(&format!("unquoted {n}/{s}"), text.as_bytes(), &limits);
                assert_eq!(
                    (e.kind, e.offset),
                    (VdfErrorKind::UnquotedToken, at),
                    "{n}/{s}"
                );
            }
        }
    }
    // A non-ASCII start is a code point, never the character.
    let e = must_fail(
        "unquoted non-ascii",
        format!("{MARK}é").as_bytes(),
        &Limits::APP_MANIFEST,
    );
    assert_eq!(e.kind, VdfErrorKind::UnquotedToken);
    let e = must_fail(
        "non-ascii",
        format!("é{MARK}").as_bytes(),
        &Limits::APP_MANIFEST,
    );
    assert!(matches!(e.kind, VdfErrorKind::UnexpectedChar { .. }));
}

// ---------- Entries ----------

#[test]
fn entries_at_and_over_the_entry_limit() {
    let mut rng = Rng(0x0E27_A1E5_0000_0001);
    for e_max in [1usize, 2, 3, 17, 255, 1000] {
        let limits = small(usize::MAX, 16, e_max, 64);
        for n in [e_max - 1, e_max, e_max + 1, e_max + 2] {
            for gap in GAPS {
                for depth in [0, 1, 4] {
                    let b = random_doc(&mut rng, n, depth, gap, FULL_CHARS);
                    // An object that is closed counts as one pair, whatever it holds.
                    assert_eq!(b.keys.len(), n);
                    let label = format!("{n} pairs, limit {e_max}, depth {depth}, gap {gap:?}");
                    let want = (n > e_max)
                        .then(|| (VdfErrorKind::TooManyEntries { limit: e_max }, b.keys[e_max]));
                    if let Some(doc) = expect(&label, b.text.as_bytes(), &limits, want) {
                        assert_eq!(entry_count(&doc), n, "{label}");
                        let mut offsets = Vec::new();
                        walk(&doc, |_, e| offsets.push(e.offset));
                        offsets.sort_unstable();
                        assert_eq!(offsets, b.keys, "{label}");
                    }
                }
            }
        }
    }
}

#[test]
fn the_shipped_entry_limits_at_the_edge_with_nesting() {
    for limits in [Limits::LIBRARY_FOLDERS, Limits::APP_MANIFEST] {
        // Objects and their children all count: one object plus N-1 children is N pairs.
        let children = |n: usize| format!("\"o\" {{ {} }}", "\"1\" \"2\" ".repeat(n));
        let at = children(limits.max_entries - 1);
        assert!(at.len() <= limits.max_bytes);
        expect("shipped at", at.as_bytes(), &limits, None);
        let over = children(limits.max_entries);
        let want = (
            VdfErrorKind::TooManyEntries {
                limit: limits.max_entries,
            },
            "\"o\" { ".len() + "\"1\" \"2\" ".len() * (limits.max_entries - 1),
        );
        expect("shipped over", over.as_bytes(), &limits, Some(want));
    }
}

// ---------- Bytes ----------

/// `doc` extended to exactly `total` bytes, with trailing spaces or a trailing comment.
fn pad_to(doc: &str, total: usize, comment: bool) -> String {
    let missing = total - doc.len();
    let mut s = doc.to_owned();
    if comment && missing >= 3 {
        s.push_str("//");
        s.push_str(&"c".repeat(missing - 2));
    } else {
        s.push_str(&" ".repeat(missing));
    }
    s
}

#[test]
fn input_size_at_and_over_the_byte_limit() {
    let base = "\"a\" \"b\"";
    for prefix in ["", BOM, "\r\n"] {
        let doc = format!("{prefix}{base}");
        for max in [doc.len(), doc.len() + 1, doc.len() + 2, 64, 1000, 4096] {
            let limits = small(max, 16, 100, 64);
            for comment in [false, true] {
                for size in [max.saturating_sub(1).max(doc.len()), max, max + 1, max + 2] {
                    let text = pad_to(&doc, size, comment);
                    assert_eq!(text.len(), size);
                    let want = (size > max).then_some((VdfErrorKind::TooLarge { limit: max }, max));
                    expect(
                        &format!("size {size} limit {max}"),
                        text.as_bytes(),
                        &limits,
                        want,
                    );
                }
            }
            // Over the limit, whatever else is wrong: size is checked first.
            for junk in [&b"\xFF"[..], b"\0", b"\xFF\xFE", b"}", MARK.as_bytes()] {
                let mut text = pad_to(&doc, max, false).into_bytes();
                text.truncate(max.saturating_sub(junk.len()));
                text.extend_from_slice(junk);
                text.push(b' ');
                let size = text.len();
                if size > max {
                    expect(
                        "junk over the limit",
                        &text,
                        &limits,
                        Some((VdfErrorKind::TooLarge { limit: max }, max)),
                    );
                }
            }
        }
    }
    // Nothing fits in nothing.
    let none = small(0, 16, 100, 64);
    expect("empty", b"", &none, None);
    expect(
        "one byte",
        b" ",
        &none,
        Some((VdfErrorKind::TooLarge { limit: 0 }, 0)),
    );
}

// ---------- Lexical oddities ----------

#[test]
fn line_ends_and_bom_do_not_change_the_tree() {
    let mut rng = Rng(0x11AE_0000_C0DE_0001);
    let limits = small(usize::MAX, 6, usize::MAX, 64);
    for round in 0..120 {
        let b = random_doc(&mut rng, 3 + round % 25, 4, "\n", FULL_CHARS);
        let lf = b.text.clone();
        let base = expect("lf", lf.as_bytes(), &limits, None).expect("parsed");
        let want = shape(&base);
        let mut offsets = Vec::new();
        walk(&base, |_, e| offsets.push(e.offset));
        offsets.sort_unstable();
        assert_eq!(offsets, b.keys, "round {round}");
        let variants = [
            lf.replace('\n', "\r\n"),
            lf.replace('\n', "\r"),
            lf.replace('\n', "\n\n\r\n"),
            format!("{BOM}{lf}"),
            format!("{BOM}{}", lf.replace('\n', "\r\n")),
        ];
        for (i, text) in variants.iter().enumerate() {
            let doc =
                expect(&format!("variant {i}"), text.as_bytes(), &limits, None).expect("parsed");
            assert_eq!(shape(&doc), want, "round {round} variant {i}");
        }
        // The BOM shifts every offset by exactly 3.
        let doc = parse(variants[3].as_bytes(), &limits).expect("bom");
        let mut shifted = Vec::new();
        walk(&doc, |_, e| shifted.push(e.offset));
        shifted.sort_unstable();
        assert_eq!(
            shifted,
            b.keys.iter().map(|k| k + 3).collect::<Vec<_>>(),
            "round {round}"
        );
    }
}

#[test]
fn stray_carriage_returns() {
    let l = Limits::LIBRARY_FOLDERS;
    // A CR between tokens is whitespace.
    expect("cr gap", b"\"a\"\r\"b\"\r\r\"c\" \r{\r}\r", &l, None);
    // A CR inside a string is an unterminated string at the opening quote.
    for (text, at) in [
        (&b"\"a\r\" \"b\""[..], 0),
        (b"\"a\" \"b\rc\"", 4),
        (b"\"a\" \"b\r", 4),
        (b"\"a\" \"b\\\r\"", 4),
    ] {
        expect(
            "cr in string",
            text,
            &l,
            Some((VdfErrorKind::UnterminatedString, at)),
        );
    }
    // A comment ends at LF only: a CR does not end it, so the rest of the line is comment.
    let doc = expect("cr in comment", b"// c\r\"a\" \"b\"", &l, None).expect("parsed");
    assert!(doc.root().is_empty());
    let doc = expect("crlf comment", b"// c\r\n\"a\" \"b\"", &l, None).expect("parsed");
    assert_eq!(doc.root().len(), 1);
    // A trailing lone CR after the last pair.
    expect("trailing cr", b"\"a\" \"b\"\r", &l, None);
    expect("cr in the middle of a pair", b"\"a\"\r\r\r\"b\"", &l, None);
}

#[test]
fn comments_everywhere_and_never_content() {
    let l = Limits::LIBRARY_FOLDERS;
    let comment = format!("// {MARK} \" {{ }} \\q [x] #include\n");
    let doc = format!(
        "{comment}\"a\" {comment}{{ {comment}\"b\" {comment}\"c\" {comment}}} {comment}\"d\" {comment}\"e\"{comment}"
    );
    let doc = expect("comments", doc.as_bytes(), &l, None).expect("parsed");
    assert_eq!(entry_count(&doc), 3);
    // A comment that ends the file without a line end; one that hides a CRLF-less rest.
    expect(
        "comment at eof",
        format!("\"a\" \"b\" // {MARK}").as_bytes(),
        &l,
        None,
    );
    // A single slash is not a comment.
    let e = must_fail(
        "single slash",
        format!("\"a\" \"b\" /{MARK}").as_bytes(),
        &l,
    );
    assert_eq!(e.kind, VdfErrorKind::UnquotedToken);
    let e = must_fail(
        "block comment",
        format!("/* {MARK} */ \"a\" \"b\"").as_bytes(),
        &l,
    );
    assert_eq!(e.kind, VdfErrorKind::UnquotedToken);
    // A comment cannot hide a NUL or invalid UTF-8.
    let e = must_fail("nul in comment", b"// a\0b\n", &l);
    assert_eq!((e.kind, e.offset), (VdfErrorKind::Nul, 4));
    let e = must_fail("invalid in comment", b"// a\xFFb\n", &l);
    assert_eq!((e.kind, e.offset), (VdfErrorKind::InvalidUtf8, 4));
    // Comments at the depth, entry and string boundary change nothing.
    let c = format!("// {MARK}\n");
    let text = format!("{c}\"a\" {c}{{ {c}\"b\" {c}{{ \"c\" {c}{{ \"d\" \"xyz\" }} }} }}{c}");
    let limits = small(usize::MAX, 3, 4, 3);
    expect("comments at the limits", text.as_bytes(), &limits, None).expect("parsed");
    let e = must_fail(
        "comments over depth",
        text.as_bytes(),
        &small(usize::MAX, 2, 4, 3),
    );
    assert_eq!(e.kind, VdfErrorKind::TooDeep { limit: 2 });
    let e = must_fail(
        "comments over entries",
        text.as_bytes(),
        &small(usize::MAX, 3, 3, 3),
    );
    assert_eq!(e.kind, VdfErrorKind::TooManyEntries { limit: 3 });
    let e = must_fail(
        "comments over string",
        text.as_bytes(),
        &small(usize::MAX, 3, 4, 2),
    );
    assert_eq!(e.kind, VdfErrorKind::StringTooLong { limit: 2 });
}

#[test]
fn nul_bytes_anywhere() {
    let mut rng = Rng(0x0000_BAD0_0000_0001);
    for round in 0..150 {
        let b = random_doc(
            &mut rng,
            2 + round % 20,
            3,
            GAPS[round % GAPS.len()],
            FULL_CHARS,
        );
        let text = b.text.into_bytes();
        for _ in 0..8 {
            let at = rng.below(text.len() + 1);
            let mut with = text.clone();
            with.insert(at, 0);
            // The text is valid UTF-8 and has no NUL of its own, so the first NUL is the
            // inserted one, unless the insert cut a multi-byte character (invalid UTF-8
            // comes first). Use the std oracle for that.
            let want = match std::str::from_utf8(&with) {
                Ok(_) => (VdfErrorKind::Nul, at),
                Err(e) => (VdfErrorKind::InvalidUtf8, e.valid_up_to()),
            };
            let got = must_fail("nul", &with, &Limits::LIBRARY_FOLDERS);
            assert_eq!((got.kind, got.offset), want, "round {round} at {at}");
        }
    }
}

#[test]
fn invalid_utf8_anywhere() {
    const BAD: &[&[u8]] = &[
        b"\xFF",
        b"\xC3",
        b"\x80",
        b"\xE2\x82",
        b"\xED\xA0\x80",
        b"\xC0\xAF",
        b"\xF4\x90\x80\x80",
        b"\xFE",
    ];
    let mut rng = Rng(0x0BAD_0F00_0000_0001);
    for round in 0..150 {
        let b = random_doc(
            &mut rng,
            2 + round % 20,
            3,
            GAPS[round % GAPS.len()],
            FULL_CHARS,
        );
        let text = b.text.into_bytes();
        for _ in 0..8 {
            let at = rng.below(text.len() + 1);
            let bad = rng.pick(BAD);
            let mut with = text[..at].to_vec();
            with.extend_from_slice(bad);
            with.extend_from_slice(&text[at..]);
            // A NUL before the bad byte does not change the report: UTF-8 is checked first.
            if rng.below(2) == 0 && at > 0 {
                with.insert(0, b'\n');
                with.insert(1, 0);
            }
            let got = check("invalid utf-8", &with, &Limits::LIBRARY_FOLDERS);
            if with.starts_with(b"\xFF\xFE") || with.starts_with(b"\xFE\xFF") {
                assert_eq!(got.expect_err("utf-16").kind, VdfErrorKind::Utf16Bom);
            } else if let Err(utf8) = std::str::from_utf8(&with) {
                let e = got.expect_err("invalid utf-8");
                assert_eq!(
                    (e.kind, e.offset),
                    (VdfErrorKind::InvalidUtf8, utf8.valid_up_to())
                );
            }
        }
    }
}

#[test]
fn every_prefix_of_a_valid_document_is_cut_off_cleanly() {
    let mut rng = Rng(0x09E1_F1C5_0000_0001);
    let mut docs: Vec<Vec<u8>> = FIXTURES.iter().map(|f| f.to_vec()).collect();
    for round in 0..6 {
        docs.push(
            random_doc(&mut rng, 8 + round, 3, "\r\n", FULL_CHARS)
                .text
                .into_bytes(),
        );
    }
    let mut cut = 0;
    for doc in &docs {
        check("full", doc, &Limits::LIBRARY_FOLDERS).expect("the whole document parses");
        for end in 0..doc.len() {
            let prefix = &doc[..end];
            match check("prefix", prefix, &Limits::LIBRARY_FOLDERS) {
                Ok(_) => {}
                Err(e) => {
                    // Cutting a valid document can only make it end early, never invent a
                    // directive, a conditional, a stray brace or a limit.
                    assert!(
                        matches!(
                            e.kind,
                            VdfErrorKind::UnterminatedString
                                | VdfErrorKind::UnexpectedEnd
                                | VdfErrorKind::UnquotedToken
                                | VdfErrorKind::InvalidUtf8
                        ),
                        "prefix {end}: {e}"
                    );
                    cut += 1;
                }
            }
        }
    }
    assert!(cut > 1000, "only {cut} prefixes were refused");
}

#[test]
fn an_unbalanced_brace_or_quote_is_never_accepted() {
    let mut rng = Rng(0xBA1A_0000_0000_0001);
    let l = Limits::LIBRARY_FOLDERS;
    let mut tried = 0;
    for round in 0..10 {
        // No comments, no escapes, no structure inside strings: every `{`, `}` and `"` of the
        // text is structure, so dropping or adding one cannot give a valid document.
        let b = random_doc(&mut rng, 6 + round, 3, "\n", PLAIN_CHARS);
        let text = b.text.into_bytes();
        expect("base", &text, &l, None).expect("parsed");
        for (i, &c) in text.iter().enumerate() {
            if matches!(c, b'{' | b'}' | b'"') {
                let mut without = text.clone();
                without.remove(i);
                must_fail("removed", &without, &l);
                tried += 1;
            }
        }
        // A quote anywhere makes the count odd; a brace only counts outside a string.
        let mut quotes = 0;
        for i in 0..=text.len() {
            let outside = quotes % 2 == 0;
            for c in *b"{}\"" {
                if c == b'"' || outside {
                    let mut with = text.clone();
                    with.insert(i, c);
                    must_fail("inserted", &with, &l);
                    tried += 1;
                }
            }
            if text.get(i) == Some(&b'"') {
                quotes += 1;
            }
        }
    }
    assert!(tried > 3000, "{tried}");
}

// ---------- Random structural mixes ----------

/// One structural edit: insert, remove or swap a brace, quote or backslash, or duplicate or
/// drop a whole line.
fn mutate(rng: &mut Rng, buf: &mut Vec<u8>) {
    const STRUCT: &[u8] = b"{}\"\\\n\r/";
    let positions: Vec<usize> = buf
        .iter()
        .enumerate()
        .filter(|(_, b)| STRUCT.contains(b))
        .map(|(i, _)| i)
        .collect();
    match rng.below(6) {
        0 => {
            let at = rng.below(buf.len() + 1);
            buf.insert(at, rng.pick(STRUCT));
        }
        1 if !positions.is_empty() => {
            buf.remove(rng.pick(&positions));
        }
        2 if !positions.is_empty() => {
            let at = rng.pick(&positions);
            buf[at] = rng.pick(STRUCT);
        }
        3 if positions.len() > 1 => {
            let (a, b) = (rng.pick(&positions), rng.pick(&positions));
            buf.swap(a, b);
        }
        4 if !buf.is_empty() => {
            // Duplicate a line.
            let from = rng.below(buf.len());
            let start = buf[..from]
                .iter()
                .rposition(|&b| b == b'\n')
                .map_or(0, |p| p + 1);
            let end = buf[from..]
                .iter()
                .position(|&b| b == b'\n')
                .map_or(buf.len(), |p| from + p + 1);
            let line = buf[start..end].to_vec();
            buf.splice(start..start, line);
        }
        _ if !buf.is_empty() => {
            // Drop a line.
            let from = rng.below(buf.len());
            let start = buf[..from]
                .iter()
                .rposition(|&b| b == b'\n')
                .map_or(0, |p| p + 1);
            let end = buf[from..]
                .iter()
                .position(|&b| b == b'\n')
                .map_or(buf.len(), |p| from + p + 1);
            buf.drain(start..end);
        }
        _ => {}
    }
}

#[test]
fn random_structural_mixes() {
    const ROUNDS: usize = 6_000;
    let limit_sets = [
        Limits::LIBRARY_FOLDERS,
        small(2048, 4, 40, 24),
        small(512, 2, 12, 8),
        small(usize::MAX, usize::MAX, usize::MAX, usize::MAX),
    ];
    let mut rng = Rng(0x5712_0C70_0000_0001);
    let (mut parsed, mut refused, mut by_limit) = (0, 0, 0);
    for round in 0..ROUNDS {
        let pairs = 2 + rng.below(30);
        let gap = GAPS[rng.below(GAPS.len())];
        let b = random_doc(&mut rng, pairs, 5, gap, FULL_CHARS);
        let mut buf = b.text.into_bytes();
        if rng.below(4) == 0 {
            buf.splice(0..0, BOM.bytes());
        }
        // A third of the rounds stay valid, the rest take one to three edits.
        if rng.below(3) != 0 {
            for _ in 0..=rng.below(3) {
                mutate(&mut rng, &mut buf);
            }
        }
        let limits = &limit_sets[round % limit_sets.len()];
        match check(&format!("mix {round}"), &buf, limits) {
            Ok(_) => parsed += 1,
            Err(e) => {
                refused += 1;
                if matches!(
                    e.kind,
                    VdfErrorKind::TooDeep { .. }
                        | VdfErrorKind::TooManyEntries { .. }
                        | VdfErrorKind::StringTooLong { .. }
                        | VdfErrorKind::TooLarge { .. }
                ) {
                    by_limit += 1;
                }
            }
        }
    }
    assert!(parsed > ROUNDS / 10, "parsed {parsed}");
    assert!(refused > ROUNDS / 10, "refused {refused}");
    assert!(by_limit > 100, "limits hit {by_limit}");
}

// ---------- Through the views ----------

/// What `classify` accepted must be one plain segment, equal to the input.
fn assert_segment(raw: &str, label: &str) -> bool {
    match classify(raw, false) {
        Ok(seg) => {
            let s = seg.as_str();
            assert_eq!(s, raw, "{label}: changed");
            assert!(!s.contains(['\\', '/', ':']), "{label}: separator in {s:?}");
            assert!(!matches!(s, "" | "." | ".."), "{label}: {s:?}");
            assert_eq!(seg.segments().count(), 1, "{label}");
            true
        }
        Err(_) => false,
    }
}

fn acf(install_dir: &str) -> String {
    format!(
        "\"AppState\"\n{{\n\t\"appid\"\t\t\"1000001\"\n\t\"name\"\t\t\"{MARK}\"\n\t\"StateFlags\"\t\t\"4\"\n\t\"LastOwner\"\t\t\"76500000000000001\"\n\t\"installdir\"\t\t{}\n}}\n",
        quote(install_dir)
    )
}

fn manifest_of(text: &str) -> Option<AppManifest> {
    let doc = check("acf", text.as_bytes(), &Limits::APP_MANIFEST).ok()?;
    AppManifest::from_vdf(&doc).ok()
}

/// Neither the view nor its text form carries the owner or the name.
fn assert_no_owner(m: &AppManifest) {
    let shown = format!("{m:?} {m:#?}");
    for needle in [
        "LastOwner",
        "lastowner",
        "SteamID",
        "76500000000000001",
        MARK,
    ] {
        assert!(!shown.contains(needle), "{needle} in {shown}");
    }
}

#[test]
fn installdir_is_one_classified_segment_or_refused() {
    let good = [
        "Game",
        "Half-Life 2",
        "Ünïcode Spiel",
        "a.b",
        "x_y",
        "Game (2004)",
    ];
    let bad = [
        "",
        ".",
        "..",
        "..\\..\\Windows",
        "../x",
        "a\\b",
        "a/b",
        "C:\\Windows",
        "C:",
        "C:x",
        "\\\\?\\C:\\",
        "\\\\server\\share",
        "\\x",
        "/x",
        "x:stream",
        "x::$DATA",
        "CON",
        "nul.txt",
        "COM1",
        "x ",
        "x.",
        "PROGRA~1",
        "bad\u{FFFD}name",
        &"x".repeat(300),
    ];
    for name in good {
        let m = manifest_of(&acf(name)).expect("view");
        assert_no_owner(&m);
        assert!(assert_segment(m.install_dir.as_raw_str(), name), "{name}");
    }
    for name in bad {
        let m = manifest_of(&acf(name)).expect("view accepts any string; policy decides");
        assert_no_owner(&m);
        assert!(
            !assert_segment(m.install_dir.as_raw_str(), name),
            "{name:?}"
        );
    }
}

#[test]
fn views_on_generated_installdirs_and_structural_mutations() {
    const ROUNDS: usize = 6_000;
    const DIR_CHARS: &[char] = &[
        'a', 'B', '1', ' ', '.', '\\', '/', ':', '~', '"', 'é', '\u{FFFD}', '\u{202E}', '$',
    ];
    let mut rng = Rng(0x71E5_0000_0000_0001);
    let (mut accepted, mut refused, mut views_ok, mut views_refused) = (0, 0, 0, 0);
    let fixtures: Vec<&[u8]> = FIXTURES.to_vec();
    for round in 0..ROUNDS {
        let mut buf = if round % 2 == 0 {
            acf(&rand_str(&mut rng, 8, DIR_CHARS)).into_bytes()
        } else {
            fixtures[rng.below(fixtures.len())].to_vec()
        };
        for _ in 0..rng.below(3) {
            mutate(&mut rng, &mut buf);
        }
        let Ok(doc) = check("view input", &buf, &Limits::APP_MANIFEST) else {
            continue;
        };
        match AppManifest::from_vdf(&doc) {
            Ok(m) => {
                views_ok += 1;
                assert_no_owner(&m);
                if assert_segment(m.install_dir.as_raw_str(), "generated") {
                    accepted += 1;
                } else {
                    refused += 1;
                }
            }
            Err(e) => {
                views_refused += 1;
                let shown = format!("{e} {e:?}");
                assert!(
                    !shown.contains(MARK) && !shown.contains("76500000000000001"),
                    "{shown}"
                );
            }
        }
        match LibraryFolders::from_vdf(&doc) {
            Ok(lf) => {
                let shown = format!("{lf:?} {lf:#?}");
                assert!(!shown.contains(MARK), "{shown}");
            }
            Err(e) => assert!(!format!("{e} {e:?}").contains(MARK)),
        }
    }
    assert!(
        accepted > 20 && refused > 20,
        "accepted {accepted}, refused {refused}"
    );
    assert!(
        views_ok > 20 && views_refused > 20,
        "{views_ok} / {views_refused}"
    );
}

#[test]
fn the_manifest_view_has_exactly_four_fields() {
    // Guards against a field for the owner being added: the Debug output names every field.
    let m = manifest_of(&acf("Game")).expect("view");
    let shown = format!("{m:?}");
    let fields = shown.matches(": ").count();
    assert_eq!(fields, 4, "{shown}");
    for name in ["app_id", "name", "install_dir", "state_flags"] {
        assert!(shown.contains(name), "{shown}");
    }
}
