//! The settings format (P5-10b): the canonical encoding round-trips; every broken input is the
//! defaults and may be replaced; a newer format or an unusable place is the defaults for the
//! session only.

use rerun_core::flow::{Seen, SettingsRead, Unusable};

use super::{FORMAT, LangChoice, LibView, Settings, Writable, decode, encode};
use crate::theme::ThemeChoice;

fn bytes(b: &[u8]) -> SettingsRead {
    SettingsRead::Bytes {
        bytes: b.to_vec(),
        seen: Seen::Hash([7; 32]),
    }
}

fn defaults(w: Writable) -> (Settings, Writable) {
    (Settings::default(), w)
}

#[test]
fn the_canonical_encoding_round_trips() {
    let d = Settings::default();
    assert_eq!(
        String::from_utf8(encode(&d)).unwrap(),
        "{\"format\":1,\"language\":\"windows\",\"theme\":\"mythen\",\"library\":\"list\",\
         \"grouped\":true,\"intro_seen\":false}\n"
    );
    let all = [
        Settings::default(),
        Settings {
            language: LangChoice::De,
            library: LibView::Compact,
            grouped: false,
            intro_seen: true,
            ..Settings::default()
        },
        Settings {
            language: LangChoice::En,
            theme: ThemeChoice::Mythen,
            ..Settings::default()
        },
    ];
    for s in all {
        let b = encode(&s);
        assert!(b.len() < 512, "{}", b.len());
        assert_eq!(b.iter().filter(|c| **c == b'\n').count(), 1);
        assert!(b.is_ascii());
        assert_eq!(decode(&bytes(&b)), (s, Writable::Yes));
    }
    // A format field other than 1 is written as 1.
    let odd = Settings {
        format: 9,
        ..Settings::default()
    };
    assert!(
        String::from_utf8(encode(&odd))
            .unwrap()
            .starts_with("{\"format\":1,")
    );
}

#[test]
fn missing_fields_are_their_defaults() {
    assert_eq!(decode(&bytes(b"{\"format\":1}")), defaults(Writable::Yes));
    let (s, w) = decode(&bytes(b" {\"intro_seen\":true,\"format\":1}\r\n"));
    assert_eq!(w, Writable::Yes);
    assert!(s.intro_seen);
    assert!(s.grouped);
    assert_eq!(s.format, FORMAT);
}

#[test]
fn st4_a_broken_file_is_the_defaults_and_may_be_replaced() {
    let broken: [&[u8]; 16] = [
        b"",
        b"   ",
        b"null",
        b"[]",
        b"1",
        b"{",
        b"{}",
        b"{\"format\":0}",
        b"{\"format\":-1}",
        b"{\"format\":1.5}",
        b"{\"format\":\"1\"}",
        b"{\"format\":1,\"theme\":\"pink\"}",
        b"{\"format\":1,\"grouped\":\"yes\"}",
        b"{\"format\":1,\"font\":\"C:\\\\Windows\\\\evil.ttf\"}",
        b"{\"format\":1,\"format\":1}",
        b"\xef\xbb\xbf{\"format\":1}",
    ];
    for b in broken {
        assert_eq!(
            decode(&bytes(b)),
            defaults(Writable::Yes),
            "{}",
            String::from_utf8_lossy(b)
        );
    }
    // UTF-16 with a byte order mark.
    let utf16: Vec<u8> = "\u{feff}{\"format\":1,\"grouped\":false}"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    assert_eq!(decode(&bytes(&utf16)), defaults(Writable::Yes));
    assert_eq!(decode(&SettingsRead::Absent), defaults(Writable::Yes));
}

#[test]
fn st5_st6_a_newer_format_or_an_unusable_place_is_the_defaults_for_the_session() {
    // A newer Rerun's file, also with fields this build does not know.
    for b in [
        &b"{\"format\":2}"[..],
        b"{\"format\":2,\"accent\":\"stein\",\"grouped\":false}",
        b"{\"format\":4294967295}",
        b"{\"format\":4294967296}",
        b"{\"format\":18446744073709551615}",
        b"{\"format\":18446744073709551616}",
        b"{\"format\":1e30}",
    ] {
        assert_eq!(
            decode(&bytes(b)),
            defaults(Writable::SessionOnly),
            "{}",
            String::from_utf8_lossy(b)
        );
    }
    for why in [
        Unusable::Link,
        Unusable::NotAFile,
        Unusable::TooLarge,
        Unusable::Io(rerun_core::sys::SysErrorKind::AccessDenied),
    ] {
        let r = SettingsRead::Unusable {
            why,
            seen: Seen::Unknown,
        };
        assert_eq!(decode(&r), defaults(Writable::SessionOnly));
    }
}
