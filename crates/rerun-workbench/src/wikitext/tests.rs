//! The wikitext scanner (P4-14, D4 a) on invented wikitext, hostile input included: deep
//! nesting, huge and duplicate parameters, `}}` and `|` inside comments, links and `<nowiki>`,
//! unclosed constructs, Unicode look-alikes of names and keys. Never a panic, never a value
//! taken from the wrong place.

use super::*;

const T: Wanted = Wanted {
    template: "API",
    keys: &["direct3d versions", "windows 32-bit exe"],
};

fn one(text: &str) -> Result<Found, ScanError> {
    read(text, &[T]).map(|mut v| v.remove(0))
}

fn vals(text: &str) -> Vec<Option<String>> {
    one(text).unwrap().unwrap()
}

#[test]
fn reads_named_parameters_of_top_level_templates() {
    let v = vals("x\n{{API\n|direct3d versions = 9, 10 \n|windows 32-bit exe=true\n|other=1}}\n");
    assert_eq!(v, [Some("9, 10".into()), Some("true".into())]);
    // Name forms: `_` for a space, the first letter's case, white space around.
    assert_eq!(
        vals("{{ aPI |direct3d versions=9}}")[0].as_deref(),
        Some("9")
    );
    assert!(one("{{ api\n|direct3d versions=9}}").unwrap().is_none());
    assert!(one("{{ API_x }}").unwrap().is_none());
    let w = Wanted {
        template: "Infobox game",
        keys: &["steam appid"],
    };
    let r = read("{{Infobox_game|steam appid=7}}", &[w]).unwrap();
    assert_eq!(r[0].as_ref().unwrap()[0].as_deref(), Some("7"));
    // Absent template, absent key.
    assert_eq!(one("{{Video|fov=true}}").unwrap(), None);
    assert_eq!(vals("{{API}}"), [None, None]);
}

#[test]
fn nested_templates_links_and_positional_parameters_do_not_split() {
    let v = vals(
        "{{API|{{x|direct3d versions=12}}|[[a|direct3d versions=11]]|direct3d versions = {{tag|a=b}} 9 [[l|m]]|positional}}",
    );
    assert_eq!(v[0].as_deref(), Some("{{tag|a=b}} 9 [[l|m]]"));
    // A nested API is not the page's API.
    assert_eq!(one("{{Outer|{{API|direct3d versions=9}}}}").unwrap(), None);
    // `=` in the name segment is part of the name, not a parameter.
    assert_eq!(one("{{API=|direct3d versions=9}}"), Ok(None));
}

#[test]
fn comments_and_nowiki_hide_what_they_hold() {
    // `}}` and `|` inside a comment do not end or split the template; the comment goes.
    let v = vals(
        "{{API|direct3d versions=9<!-- }} |windows 32-bit exe=true -->|windows 32-bit exe=false}}",
    );
    assert_eq!(v, [Some("9".into()), Some("false".into())]);
    // A <nowiki> element becomes one opaque character, its braces count for nothing.
    let v = vals("{{API|direct3d versions=<nowiki>}}|windows 32-bit exe=true</nowiki>}}");
    assert_eq!(v[0].as_deref(), Some("\u{FFFD}"));
    assert_eq!(v[1], None);
    let v = vals("{{API|direct3d versions=<NoWiki />9|windows 32-bit exe=<pre class=x>{{</PRE>}}");
    assert_eq!(v[0].as_deref(), Some("\u{FFFD}9"));
    assert_eq!(v[1].as_deref(), Some("\u{FFFD}"));
    // Not a tag: `<prefix>` and a `<nowiki` without `>` within the bound are text.
    assert_eq!(
        vals("{{API|direct3d versions=<prefix>}}")[0].as_deref(),
        Some("<prefix>")
    );
    // Unclosed: an error, never "to the end".
    assert_eq!(one("{{API|a=<!-- x}}"), Err(ScanError::UnclosedComment));
    assert_eq!(one("{{API|a=<nowiki>x}}"), Err(ScanError::UnclosedTag));
    assert_eq!(one("<pre>{{API}}"), Err(ScanError::UnclosedTag));
}

#[test]
fn unclosed_and_stray_braces() {
    assert_eq!(
        one("{{API|direct3d versions=9"),
        Err(ScanError::UnclosedTemplate)
    );
    assert_eq!(one("{{API|x={{y}}"), Err(ScanError::UnclosedTemplate));
    // Stray closers at the top level are text; a link left open at its template's end is an
    // error (it would hide the template's `|` and `=`, review 1a).
    assert_eq!(
        one("}} ]] {{API|direct3d versions=[[a|b}}"),
        Err(ScanError::UnclosedLink)
    );
    assert_eq!(
        one("{{API|direct3d versions=12|x=[[|direct3d versions=9}}"),
        Err(ScanError::UnclosedLink)
    );
    assert_eq!(
        vals("}} ]] {{API|direct3d versions=[[a|b]] 9}}")[0].as_deref(),
        Some("[[a|b]] 9")
    );
    assert_eq!(
        vals("{{API|direct3d versions=9]]}}")[0].as_deref(),
        Some("9]]")
    );
    // Triple braces: no error; such a value is never whitelisted anyway.
    assert!(one("{{API|direct3d versions={{{1|9}}}}}").is_ok());
}

#[test]
fn bounds_are_errors() {
    let deep = format!(
        "{}{}",
        "{{".repeat(MAX_DEPTH + 1),
        "}}".repeat(MAX_DEPTH + 1)
    );
    assert_eq!(one(&deep), Err(ScanError::TooDeep));
    let ok = format!("{}{}", "{{".repeat(MAX_DEPTH), "}}".repeat(MAX_DEPTH));
    assert_eq!(one(&ok), Ok(None));
    let links = format!("{{{{API|{}", "[[".repeat(MAX_DEPTH));
    assert_eq!(one(&links), Err(ScanError::TooDeep));
    // 10 000 nested openers: an error, no stack overflow.
    assert_eq!(one(&"{{".repeat(10_000)), Err(ScanError::TooDeep));
    let many = format!("{{{{API{}}}}}", "|x".repeat(MAX_SEGMENTS));
    assert_eq!(one(&many), Err(ScanError::TooManyParams));
    let fine = format!("{{{{API{}}}}}", "|x".repeat(MAX_SEGMENTS - 1));
    assert!(one(&fine).is_ok());
    assert_eq!(
        one(&"{{a}}".repeat(MAX_TEMPLATES + 1)),
        Err(ScanError::TooManyTemplates)
    );
    let long = format!(
        "{{{{API|direct3d versions={}}}}}",
        "9".repeat(MAX_VALUE + 1)
    );
    assert_eq!(
        one(&long),
        Err(ScanError::ValueTooLong("API", "direct3d versions"))
    );
    // A long value of a key that is not read is fine (notes are long).
    let notes = format!("{{{{API|direct3d notes={}}}}}", "n".repeat(100_000));
    assert_eq!(vals(&notes), [None, None]);
}

#[test]
fn duplicates_are_errors() {
    assert_eq!(
        one("{{API|direct3d versions=9|direct3d versions=10}}"),
        Err(ScanError::DuplicateParam("API", "direct3d versions"))
    );
    assert_eq!(
        one("{{API|direct3d versions=9}}{{ API }}"),
        Err(ScanError::DuplicateTemplate("API"))
    );
    // Not read, not counted.
    assert!(one("{{API|x=1|x=2}}").is_ok());
}

#[test]
fn unicode_look_alikes_never_match() {
    for text in [
        "{{A\u{200B}PI|direct3d versions=9}}",
        "{{\u{FF21}PI|direct3d versions=9}}",
        "{{API\u{00A0}|direct3d versions=9}}",
    ] {
        assert_eq!(one(text), Ok(None), "{text:?}");
    }
    for text in [
        "{{API|direct3d\u{00A0}versions=9}}",
        "{{API|direct3d versions\u{200B}=9}}",
        "{{API|\u{FEFF}direct3d versions=9}}",
        "{{API|direct3d versions\u{FF1D}9}}",
    ] {
        assert_eq!(vals(text), [None, None], "{text:?}");
    }
    // Multi-byte text around delimiters keeps char boundaries.
    let v = vals(
        "\u{00E9}{{API|direct3d versions=\u{00E9}9\u{1F600}|windows 32-bit exe=\u{202E}true}}",
    );
    assert_eq!(v[0].as_deref(), Some("\u{00E9}9\u{1F600}"));
    assert_eq!(v[1].as_deref(), Some("\u{202E}true"));
}

#[test]
fn every_prefix_and_garbage_never_panics() {
    let text = "a{{API|direct3d versions=9 <!-- c --> [[l|x]] <nowiki>}}</nowiki>|windows 32-bit exe=true}}\u{00E9}{{Video|fov=hackable}}";
    for end in 0..=text.len() {
        if let Some(p) = text.get(..end) {
            let _ = one(p);
        }
    }
    let mut seed = 0x9E37_79B9_7F4A_7C15u64;
    let alphabet = [
        "{{",
        "}}",
        "[[",
        "]]",
        "|",
        "=",
        "<!--",
        "-->",
        "<nowiki>",
        "</nowiki>",
        "API",
        "direct3d versions",
        "x",
        "\u{00E9}",
        "<pre/>",
    ];
    for _ in 0..2000 {
        let mut s = String::new();
        for _ in 0..24 {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            s.push_str(alphabet[usize::try_from(seed % alphabet.len() as u64).unwrap()]);
        }
        let _ = one(&s);
    }
}

#[test]
fn ref_and_other_opaque_elements_hide_what_they_hold() {
    // A `|` inside a <ref> does not split the template (review 1b).
    assert_eq!(
        vals("{{API|x=<ref>|direct3d versions=12|</ref>}}"),
        [None, None]
    );
    for text in [
        "{{API|x=<REF name=\"a\">|direct3d versions=12|</Ref>}}",
        "{{API|x=<syntaxhighlight lang=x>|direct3d versions=12|</syntaxhighlight>}}",
        "{{API|x=<source>|direct3d versions=12|</source>}}",
        "{{API|x=<math>|direct3d versions=12|</math>}}",
    ] {
        assert_eq!(vals(text), [None, None], "{text}");
    }
    // Self-closing: one opaque character, the rest is read.
    let v = vals("{{API|direct3d versions=9<ref name=\"a\" />|windows 32-bit exe=true}}");
    assert_eq!(v, [Some("9\u{FFFD}".into()), Some("true".into())]);
    // `<references/>` is no <ref>.
    assert_eq!(
        vals("{{API|direct3d versions=<references/>}}")[0].as_deref(),
        Some("<references/>")
    );
    // Unclosed, or an opening tag without its `>` within the bound: an error, never text.
    assert_eq!(
        one("{{API|x=<ref>|direct3d versions=12}}"),
        Err(ScanError::UnclosedTag)
    );
    let open = format!(
        "{{{{API|x=<ref {}|direct3d versions=12}}}}",
        "a".repeat(300)
    );
    assert_eq!(one(&open), Err(ScanError::UnclosedTag));
    assert_eq!(one("x <ref "), Err(ScanError::UnclosedTag));
    // `<ref` at the very end opens nothing: text.
    assert_eq!(one("x <ref"), Ok(None));
    // Transclusion tags anywhere: an error.
    for text in [
        "<includeonly>{{API|direct3d versions=12}}</includeonly>",
        "x <ONLYINCLUDE>",
        "{{API|direct3d versions=9}}<includeonly/>",
    ] {
        assert_eq!(one(text), Err(ScanError::Transclusion), "{text}");
    }
    // Inside a comment it is gone with the comment.
    assert!(one("<!-- <includeonly> -->{{API}}").is_ok());
}

#[test]
fn a_template_prefix_names_the_same_template() {
    assert_eq!(
        one("{{Template:API|direct3d versions=12}}{{API|direct3d versions=9}}"),
        Err(ScanError::DuplicateTemplate("API"))
    );
    for text in [
        "{{template:API|direct3d versions=9}}",
        "{{ TEMPLATE : API |direct3d versions=9}}",
        "{{Template_:_API|direct3d versions=9}}",
    ] {
        assert_eq!(vals(text)[0].as_deref(), Some("9"), "{text}");
    }
    // Only the prefix: `Templates:API`, `Template API` and `Template:Video` are other names.
    for text in [
        "{{Templates:API|direct3d versions=9}}",
        "{{Template API|direct3d versions=9}}",
        "{{Template:Video|direct3d versions=9}}",
    ] {
        assert_eq!(one(text), Ok(None), "{text}");
    }
}
