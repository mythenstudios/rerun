//! PCGamingWiki side of `draft` (P4-14) against `FakeHttp` and synthetic replies only (D3 b):
//! T1 the queries, T3 hostile replies, T4 every prefix and seeded byte changes of the fixtures.

use std::time::Duration;

use rerun_core::sys::fake::{FakeHttp, FakeReply};

use super::*;

pub(crate) const RACER: &[u8] =
    include_bytes!("../../../../tests/fixtures/pcgw/invented-racer-2.json");
pub(crate) const QUEST: &[u8] =
    include_bytes!("../../../../tests/fixtures/pcgw/invented-quest.json");

pub(crate) const RACER_URL: &str = "https://www.pcgamingwiki.com/w/api.php?action=parse&format=json&formatversion=2&prop=wikitext%7Csections&page=Invented_Racer_2";
pub(crate) const RACER_LOOKUP: &str = "https://www.pcgamingwiki.com/api/appid.php?appid=1234560";

fn page(s: &str) -> PageName {
    PageName::parse(s).unwrap()
}

fn client(h: &FakeHttp) -> Client<'_> {
    Client::new(h, Duration::ZERO, Duration::from_secs(60))
}

fn racer() -> PageName {
    page("Invented Racer 2")
}

/// The facts of the racer with `reply` scripted.
fn facts_with(reply: FakeReply) -> (Result<(GameFacts, Fixes), PcgwError>, Vec<String>) {
    let h = FakeHttp::default();
    h.reply(RACER_URL, reply);
    let r = client(&h).facts(&racer());
    (r, h.requests())
}

// ---------- T1 ----------

#[test]
fn t1_queries_are_built_and_encoded_here() {
    assert_eq!(appid_path(15), "/api/appid.php?appid=15");
    assert_eq!(format!("https://{HOST}{}", parse_path(&racer())), RACER_URL);
    assert_eq!(
        parse_path(&page("A'b & c+d%e_f\u{00E9}")),
        "/w/api.php?action=parse&format=json&formatversion=2&prop=wikitext%7Csections&page=A%27b_%26_c%2Bd%25e_f%C3%A9"
    );
    for p in [page("x y"), page("Invented: \u{00C9}dition (2) 100%")] {
        assert!(rerun_core::sys::http::check_request(HOST, &parse_path(&p)).is_ok());
    }
    // Space and `_` forms are one page, runs are joined.
    assert_eq!(page("a__b  c_"), page("a b c"));
    assert_eq!(page("a b").wiki(), "a_b");
    assert_eq!(
        page("A'b (c)").url(),
        "https://www.pcgamingwiki.com/wiki/A'b_(c)"
    );
}

#[test]
fn t1_bad_input_is_refused_before_any_request() {
    for bad in [
        "",
        "_ _",
        "a\"b",
        "a\\b",
        "a#b",
        "a<b",
        "a>b",
        "a[b",
        "a]b",
        "a{b",
        "a}b",
        "a|b",
        "a\nb",
        "a\tb",
        "a\u{0}b",
        "a\u{202E}b",
        "a\u{200B}b",
        "a\u{FEFF}b",
        "a\u{00A0}b",
        "a\u{2028}b",
        "a\u{FFFD}b",
    ] {
        assert!(
            matches!(PageName::parse(bad), Err(PcgwError::Input(_))),
            "{bad:?}"
        );
    }
    assert!(PageName::parse(&"a".repeat(MAX_PAGE)).is_ok());
    assert!(PageName::parse(&"a".repeat(MAX_PAGE + 1)).is_err());
    assert!(PageName::parse(&"\u{00E9}".repeat(128)).is_err());
}

#[test]
fn t1_the_lookup_reads_only_the_location() {
    let h = FakeHttp::default();
    let mut r = FakeReply::redirect(302, "https://www.pcgamingwiki.com/wiki/Invented_Racer_2");
    r.body = b"never read".to_vec();
    h.reply(RACER_LOOKUP, r);
    assert_eq!(
        client(&h).page(&Target::SteamApp(1_234_560)).unwrap(),
        racer()
    );
    assert_eq!(h.requests(), [RACER_LOOKUP]);
    // A page target asks nothing.
    let h = FakeHttp::default();
    assert_eq!(client(&h).page(&Target::Page(racer())).unwrap(), racer());
    assert!(h.requests().is_empty());
}

#[test]
fn t1_the_location_must_be_a_page_of_the_wiki() {
    assert_eq!(
        page_of_location("https://www.pcgamingwiki.com/wiki/A%27b_%C3%A9").unwrap(),
        page("A'b \u{00E9}")
    );
    for bad in [
        "https://www.pcgamingwiki.com/wiki/",
        "http://www.pcgamingwiki.com/wiki/A",
        "https://pcgamingwiki.com/wiki/A",
        "https://www.pcgamingwiki.com.evil.example/wiki/A",
        "https://www.pcgamingwiki.com/w/index.php?title=A",
        "https://www.pcgamingwiki.com/wiki/A?x=1",
        "https://www.pcgamingwiki.com/wiki/A#b",
        "https://www.pcgamingwiki.com/wiki/A%22b",
        "https://www.pcgamingwiki.com/wiki/A%0Ab",
        "https://www.pcgamingwiki.com/wiki/A%E2%80%AEb",
        "https://www.pcgamingwiki.com/wiki/A%FF",
        "https://www.pcgamingwiki.com/wiki/A%2",
        "https://www.pcgamingwiki.com/wiki/A%zz",
        "/wiki/A",
    ] {
        assert!(page_of_location(bad).is_err(), "{bad}");
    }
    let long = format!(
        "https://www.pcgamingwiki.com/wiki/{}",
        "%41".repeat(MAX_PAGE + 1)
    );
    assert!(page_of_location(&long).is_err());
}

#[test]
fn t1_lookup_statuses() {
    for (reply, want) in [
        (FakeReply::ok(b"<html>"), "no such page"),
        (FakeReply::status(404), "no such page"),
        (FakeReply::status(429), "status 429"),
        (
            FakeReply::redirect(302, "https://evil.example/wiki/A"),
            "did not name a page",
        ),
        (
            FakeReply {
                location: None,
                ..FakeReply::status(302)
            },
            "did not name a page",
        ),
        (FakeReply::fail(12029), "pcgamingwiki"),
    ] {
        let h = FakeHttp::default();
        h.reply(RACER_LOOKUP, reply);
        let e = client(&h).page(&Target::SteamApp(1_234_560)).unwrap_err();
        assert!(e.to_string().contains(want), "{e} / {want}");
        assert_eq!(
            h.requests(),
            [RACER_LOOKUP],
            "one request, nothing followed"
        );
    }
}

// ---------- parsing the fixtures ----------

#[test]
fn the_racer_facts() {
    let (f, x) = parse_page(RACER, &racer()).unwrap();
    assert_eq!(f.page, racer());
    assert_eq!(f.steam, [1_234_560]);
    assert_eq!(
        f.api,
        Some(ApiFacts {
            d3d: vec![9],
            ..ApiFacts::default()
        })
    );
    assert_eq!(f.bits, (Some(true), Some(false)));
    // `120 fps` is hackable only inside <nowiki>: not counted.
    assert_eq!(
        f.hackable,
        [("field of view", "Video"), ("60 FPS", "Video")]
    );
    assert!(f.missing.is_empty());
    let a = |v: &[Anchor]| v.iter().map(|a| a.as_str().to_owned()).collect::<Vec<_>>();
    assert_eq!(a(&x.essential), ["Skip_intro_videos"]);
    assert_eq!(a(&x.fixed), ["Crash_on_start", "Stutter_with_many_cores"]);
    assert_eq!(a(&x.unresolved), ["Audio_desync"]);
}

#[test]
fn the_quest_facts() {
    let q = page("Invented Quest: Gold Edition");
    let (f, x) = parse_page(QUEST, &q).unwrap();
    assert_eq!(f.steam, [2_345_670, 2_345_671]);
    let api = f.api.unwrap();
    assert_eq!(api.d3d, [9, 10]);
    assert!(api.opengl && !api.ddraw && !api.vulkan);
    assert_eq!(f.bits, (Some(true), None));
    assert_eq!(f.missing, ["Video", "Input"]);
    assert_eq!(x.fixed[0].as_str(), ".22modern.22_GPUs_and_%C3%A9");
    // The first letter's case is MediaWiki's to choose.
    assert!(parse_page(QUEST, &page("invented Quest: Gold Edition")).is_ok());
    assert!(parse_page(QUEST, &page("Invented quest: Gold Edition")).is_err());
}

#[test]
fn version_items() {
    for (v, want) in [
        ("9.0c, 10, 10.1", vec![9, 10]),
        ("11, 9", vec![9, 11]),
        ("true", vec![]),
        ("12, 7, 5", vec![5, 7, 12]),
        ("9.0cc, 9..1, .9, 999, x9, 9x", vec![]),
        ("", vec![]),
    ] {
        assert_eq!(d3d(v).unwrap(), want, "{v}");
    }
    assert!(listed("1.1, 2.0").unwrap() && listed("true").unwrap());
    assert!(!listed("false").unwrap() && !listed("").unwrap() && !listed("n/a").unwrap());
    assert_eq!(steam_ids("1, 2, 1").unwrap(), [1, 2]);
    for bad in ["0", "x", "4294967296", "\u{FF11}", "1 2", "-1", "+1"] {
        assert!(steam_ids(bad).is_err(), "{bad}");
    }
    let many = vec!["1"; MAX_ITEMS + 1].join(",");
    assert!(steam_ids(&many).is_err() && d3d(&many).is_err());
}

// ---------- T3 ----------

fn with_wikitext(wt: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "parse": { "title": "Invented Racer 2", "pageid": 1, "sections": [], "wikitext": wt }
    }))
    .unwrap()
}

#[test]
fn t3_status_redirect_and_size() {
    let mut big = FakeReply::ok(b"{}");
    big.length = Some(MAX_REPLY as u64 + 1);
    let mut long = FakeReply::ok(&vec![b' '; MAX_REPLY + 1]);
    long.length = None;
    let mut cut = FakeReply::ok(RACER);
    cut.cut_after = Some(100);
    for (reply, want) in [
        (
            FakeReply::redirect(301, "https://www.pcgamingwiki.com/wiki/X"),
            "redirect (301)",
        ),
        (
            FakeReply {
                body: b"<!DOCTYPE html><title>Just a moment...</title>".to_vec(),
                ..FakeReply::status(403)
            },
            "rate limit or Cloudflare",
        ),
        (FakeReply::status(429), "status 429"),
        (FakeReply::status(503), "try later"),
        (FakeReply::status(500), "status 500"),
        (big, "larger than"),
        (long, "larger than"),
        (cut, "pcgamingwiki"),
        (
            FakeReply::ok(b"<!DOCTYPE html><title>Just a moment...</title>"),
            "not JSON",
        ),
        (FakeReply::ok(b""), "not JSON"),
    ] {
        let (r, req) = facts_with(reply);
        let e = r.unwrap_err().to_string();
        assert!(e.contains(want), "{e} / {want}");
        assert_eq!(req, [RACER_URL], "one request, nothing followed");
    }
}

#[test]
fn t3_hostile_json() {
    let deep = format!("{{\"parse\":{}{}}}", "[".repeat(10_000), "]".repeat(10_000));
    let mut bad_utf8 = RACER.to_vec();
    let at = bad_utf8.windows(7).position(|w| w == b"Invente").unwrap();
    bad_utf8[at] = 0xFF;
    for (body, want) in [
        (deep.into_bytes(), "not a MediaWiki reply"),
        (bad_utf8, "not a MediaWiki reply"),
        (RACER[..RACER.len() / 2].to_vec(), "not a MediaWiki reply"),
        (
            b"{\"parse\":{\"title\":1}}".to_vec(),
            "not a MediaWiki reply",
        ),
        (b"{\"batchcomplete\":true}".to_vec(), "no parse result"),
        (
            b"{\"error\":{\"code\":\"bad\\u001b[31m\",\"info\":\"x\"}}".to_vec(),
            "unknown code",
        ),
        (
            br#"{"error":{"code":"ratelimited","info":"IGNORED TEXT"}}"#.to_vec(),
            "error ratelimited",
        ),
        (
            br#"{"error":{"code":"missingtitle"}}"#.to_vec(),
            "no such page",
        ),
        (
            br#"{"parse":{"title":"Other Game","sections":[],"wikitext":""}}"#.to_vec(),
            "another page",
        ),
        (
            br#"{"parse":{"title":"Invented Racer 2\u202e","sections":[],"wikitext":""}}"#.to_vec(),
            "another form",
        ),
        (
            br#"{"parse":{"title":"Invented Racer 2\nX","sections":[],"wikitext":""}}"#.to_vec(),
            "another form",
        ),
        (with_wikitext("#REDIRECT [[Elsewhere]]"), "redirect"),
        (with_wikitext("no infobox here"), "no {{Infobox game}}"),
        (
            with_wikitext("{{Infobox_game|steam appid=12x}}"),
            "not an app ID",
        ),
        (with_wikitext("{{Infobox game|steam appid=1"), "not closed"),
        (
            with_wikitext(&format!(
                "{{{{Infobox game|steam appid={}}}}}",
                "1".repeat(5000)
            )),
            "longer than",
        ),
        (
            with_wikitext("{{Infobox game|steam appid=1|steam appid=2}}"),
            "twice",
        ),
        (with_wikitext("{{Infobox game}}{{Infobox game}}"), "twice"),
        (with_wikitext(&"{{".repeat(10_000)), "deeper"),
    ] {
        let e = parse_page(&body, &racer()).unwrap_err().to_string();
        assert!(e.contains(want), "{e} / {want}");
        assert!(!e.contains("IGNORED") && !e.contains('\u{1b}'), "{e}");
    }
}

#[test]
fn t3_hostile_sections() {
    let s = |level: &str, anchor: &str| serde_json::json!({ "level": level, "anchor": anchor, "line": "x" });
    let reply = |sections: Vec<serde_json::Value>| {
        serde_json::to_vec(&serde_json::json!({
            "parse": { "title": "Invented Racer 2", "sections": sections, "wikitext": "{{Infobox game}}" }
        }))
        .unwrap()
    };
    for (sections, want) in [
        (vec![s("7", "a")], "level"),
        (vec![s("2 ", "a")], "level"),
        (vec![s("2", "")], "anchor"),
        (vec![s("2", &"a".repeat(MAX_ANCHOR + 1))], "anchor"),
        (vec![s("2", "a\u{202E}b")], "anchor"),
        (vec![s("2", "a\nb")], "anchor"),
        (vec![s("2", "a"); MAX_SECTIONS + 1], "sections"),
    ] {
        let e = parse_page(&reply(sections), &racer())
            .unwrap_err()
            .to_string();
        assert!(e.contains(want), "{e} / {want}");
    }
    // Spaces, `#` and non-ASCII in an anchor are encoded.
    let (_, x) = parse_page(
        &reply(vec![s("2", "Issues_fixed"), s("3", "a b#c\u{00E9}")]),
        &racer(),
    )
    .unwrap();
    assert_eq!(x.fixed[0].as_str(), "a%20b%23c%C3%A9");
}

#[test]
fn t3_budget_and_deadline() {
    let h = FakeHttp::default();
    h.reply(RACER_URL, FakeReply::ok(RACER));
    let mut c = client(&h);
    c.facts(&racer()).unwrap();
    c.facts(&racer()).unwrap();
    assert!(matches!(c.facts(&racer()), Err(PcgwError::Budget)));
    assert_eq!(h.requests().len(), MAX_REQUESTS);
    // The spacing would pass the deadline: refused before the second request.
    let h = FakeHttp::default();
    h.reply(RACER_URL, FakeReply::ok(RACER));
    let mut c = Client::new(&h, Duration::from_secs(3600), Duration::from_secs(60));
    c.facts(&racer()).unwrap();
    assert!(matches!(c.facts(&racer()), Err(PcgwError::Deadline)));
    assert_eq!(h.requests().len(), 1);
}

// ---------- T4 ----------

#[test]
fn t4_every_prefix_and_seeded_changes_never_panic() {
    let q = page("Invented Quest: Gold Edition");
    for (body, asked) in [(RACER, racer()), (QUEST, q)] {
        for end in 0..body.len() {
            let _ = parse_page(&body[..end], &asked);
        }
        let mut seed = 0x2545_F491_4F6C_DD1Du64;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for _ in 0..2000 {
            let mut b = body.to_vec();
            for _ in 0..1 + next() % 4 {
                let at = usize::try_from(next() % b.len() as u64).unwrap();
                b[at] = b"{}[]|=<>!-\"\\ax9\n"[usize::try_from(next() % 16).unwrap()];
            }
            if let Ok((f, x)) = parse_page(&b, &asked) {
                // Whatever parses still holds only checked values.
                assert!(f.steam.iter().all(|n| *n >= 1));
                for a in x.essential.iter().chain(&x.fixed).chain(&x.unresolved) {
                    assert!(
                        a.as_str()
                            .bytes()
                            .all(|c| c.is_ascii_graphic() && c != b'#')
                    );
                }
            }
        }
    }
}
