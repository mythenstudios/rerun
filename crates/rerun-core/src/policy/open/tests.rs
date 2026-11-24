//! OL1: the grammar of what Rerun hands to the shell (ADR 0027 amendment P5-10a).

use super::*;

const PCGW: &str = "https://www.pcgamingwiki.com/wiki/Assassin%27s_Creed#Controller_support";

#[test]
fn ol1_index_urls_of_the_form_pass_unchanged() {
    for u in [
        "https://github.com/ThirteenAG/WidescreenFixesPack",
        "https://github.com/ThirteenAG/WidescreenFixesPack/",
        "https://www.pcgamingwiki.com/wiki/Invented_Game",
        PCGW,
        "https://steamcommunity.com/app/15100/discussions/0/1234567890/",
        "https://steamcommunity.com/sharedfiles/filedetails/?id=123456",
        "https://example.org/a(b)c;d=e,f+g!h*i'j$k&l~m@n:o[p]",
        "https://example.org",
    ] {
        assert_eq!(admit(u).as_deref(), Ok(u), "{u}");
        assert!(openable(u), "{u}");
        assert_eq!(OpenUrl::from_index(u).unwrap().as_str(), u);
    }
}

#[test]
fn ol1_non_ascii_is_percent_encoded() {
    // A PCGW page with an accented title and a fragment.
    assert_eq!(
        admit("https://www.pcgamingwiki.com/wiki/Pok\u{e9}mon#Vid\u{e9}o").as_deref(),
        Ok("https://www.pcgamingwiki.com/wiki/Pok%C3%A9mon#Vid%C3%A9o")
    );
    assert_eq!(
        admit("https://example.org/\u{65e5}\u{672c}").as_deref(),
        Ok("https://example.org/%E6%97%A5%E6%9C%AC")
    );
    // A four-byte character.
    assert_eq!(
        admit("https://example.org/\u{1F600}").as_deref(),
        Ok("https://example.org/%F0%9F%98%80")
    );
}

#[test]
fn ol1_everything_else_is_refused() {
    let long_path = format!("https://example.org/{}", "a".repeat(MAX_OPEN_URL));
    for u in [
        // Other schemes and forms.
        "http://example.org/",
        "HTTPS://example.org/",
        "file:///C:/Windows/System32/calc.exe",
        "file://server/share",
        "javascript:alert(1)",
        "ms-settings:privacy",
        "search-ms:query=x",
        "mailto:a@example.org",
        r"\\server\share\x.exe",
        r"C:\Windows\notepad.exe",
        "https:example.org",
        "https:/example.org",
        "https://",
        " https://example.org/",
        // Hosts.
        "https://1.2.3.4/",
        "https://[::1]/",
        "https://example.org:443/",
        "https://example.org:8080/x",
        "https://user@example.org/",
        "https://user:pw@example.org/",
        "https://Example.org/",
        "https://EXAMPLE.ORG/",
        "https://localhost/",
        "https://example.org./",
        "https://-x.example.org/",
        "https://exa_mple.org/",
        "https://b\u{fc}cher.example/",
        "https://xn--bcher-kva.example\u{2e}/",
        "https://example.org?x=1",
        "https://example.org#x",
        "https://example.org\\x",
        // Characters a command line or a shell treats specially.
        "https://example.org/a\"b",
        "https://example.org/a\" --x",
        "https://example.org/a<b",
        "https://example.org/a>b",
        "https://example.org/a^b",
        "https://example.org/a`b",
        "https://example.org/a{b",
        "https://example.org/a|b",
        "https://example.org/a}b",
        "https://example.org/a\\b",
        "https://example.org/a b",
        "https://example.org/a\tb",
        "https://example.org/a\nb",
        "https://example.org/a\rb",
        "https://example.org/a\0b",
        "https://example.org/a\u{7f}b",
        // Bidi, invisible and confusable characters are refused, not encoded.
        "https://example.org/a\u{202e}b",
        "https://example.org/a\u{2066}b",
        "https://example.org/a\u{200b}b",
        "https://example.org/a\u{feff}b",
        "https://example.org/a\u{a0}b",
        "https://example.org/a\u{2215}b",
        "https://example.org/a\u{ff0f}b",
        // A bad escape, a second fragment.
        "https://example.org/a%",
        "https://example.org/a%2",
        "https://example.org/a%zz",
        "https://example.org/a#b#c",
    ] {
        assert_eq!(admit(u), Err(OpenRefusal::Form), "{u:?}");
        assert!(!openable(u), "{u:?}");
        assert!(OpenUrl::from_index(u).is_err(), "{u:?}");
    }
    assert_eq!(admit(&long_path), Err(OpenRefusal::TooLong));
    // The limit counts the encoded bytes.
    let base = "https://example.org/";
    let fits = format!("{base}{}", "a".repeat(MAX_OPEN_URL - base.len()));
    assert_eq!(admit(&fits).map(|s| s.len()), Ok(MAX_OPEN_URL));
    let encoded = format!("{base}{}\u{e9}", "a".repeat(MAX_OPEN_URL - base.len() - 5));
    assert_eq!(admit(&encoded), Err(OpenRefusal::TooLong));
}

#[test]
fn ol1_rerun_s_own_links_pass_the_grammar() {
    for l in [
        OwnLink::Repository,
        OwnLink::SourceOfThisBuild,
        OwnLink::NewIssue,
    ] {
        let u = OpenUrl::own(l);
        assert_eq!(admit(u.as_str()).as_deref(), Ok(u.as_str()), "{l:?}");
        assert!(u.as_str().starts_with(RERUN_REPO), "{l:?}");
    }
    assert_eq!(OpenUrl::own(OwnLink::Repository).as_str(), RERUN_REPO);
    assert_eq!(
        OpenUrl::own(OwnLink::NewIssue).as_str(),
        "https://github.com/mythenstudios/rerun/issues/new"
    );
    // The source of this build: the commit, if the build ID names one; else the repository.
    let commit = "0123456789abcdef0123456789abcdef01234567";
    assert_eq!(
        OpenUrl::own_for(OwnLink::SourceOfThisBuild, &format!("0.1.0+{commit}")).as_str(),
        format!("{RERUN_REPO}/tree/{commit}")
    );
    assert_eq!(
        OpenUrl::own_for(OwnLink::SourceOfThisBuild, "0.1.0+abc1234").as_str(),
        format!("{RERUN_REPO}/tree/abc1234")
    );
    for id in [
        "0.1.0+dev-0123456789abcdef",
        "0.1.0+ABC1234",
        "0.1.0+abc123",
        "0.1.0+v0.1.0",
        "0.1.0",
        &format!("0.1.0+{commit}0"),
    ] {
        assert_eq!(
            OpenUrl::own_for(OwnLink::SourceOfThisBuild, id).as_str(),
            RERUN_REPO,
            "{id}"
        );
    }
}

/// Decodes `%XX` (the test's own decoder).
fn decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            out.push(u8::from_str_radix(&s[i + 1..i + 3], 16).unwrap());
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).unwrap()
}

#[test]
fn ol1_the_issue_url_encodes_title_and_body_exactly() {
    let title = "Problem with Steam app 220";
    let body = "What happened:\n\n- a & b = c?\n- 100% #1 \"x\" <y> +z";
    let u = OpenUrl::issue(title, body).unwrap();
    let s = u.as_str();
    let q = s
        .strip_prefix("https://github.com/mythenstudios/rerun/issues/new?title=")
        .unwrap();
    let (t, b) = q.split_once("&body=").unwrap();
    assert_eq!(decode(t), title);
    assert_eq!(decode(b), body);
    // Nothing but unreserved characters and escapes in the values.
    assert!(
        q.bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"-._~%&=".contains(&c))
    );
    // Too long: refused, never cut.
    assert_eq!(
        OpenUrl::issue(title, &" ".repeat(MAX_OPEN_URL / 3)),
        Err(OpenRefusal::TooLong)
    );
}
