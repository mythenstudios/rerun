//! The third-party notices (P5-10e): `assets/THIRD-PARTY-NOTICES.txt`, generated and checked by
//! `tests/notices.rs`, embedded here and shown under Settings > About Rerun > Third-party
//! licences. Read only when that dialog opens. Framework free.

/// The file as committed.
pub const TEXT: &str = include_str!("../assets/THIRD-PARTY-NOTICES.txt");

/// The line before an entry and the line between its heading and its text (`tests/notices.rs`).
const ENTRY: &str =
    "================================================================================";
const BODY: &str =
    "--------------------------------------------------------------------------------";

/// One entry: who ships the text (Rerun, a font, or crates with version and licence), and the
/// licence text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notice {
    /// One or more lines.
    pub heading: String,
    /// The licence text.
    pub text: String,
}

/// The preamble (what the file is, its paragraphs unwrapped) and the entries of `text`, in its order.
pub fn parse(text: &str) -> (String, Vec<Notice>) {
    let text = text.replace("\r\n", "\n");
    let entry = format!("\n{ENTRY}\n");
    let body = format!("\n{BODY}\n");
    let mut parts = text.split(&entry);
    // The preamble's paragraphs as running text (the window wraps them itself).
    let preamble = parts
        .next()
        .unwrap_or_default()
        .trim()
        .split("\n\n")
        .map(|p| p.split('\n').collect::<Vec<_>>().join(" "))
        .collect::<Vec<_>>()
        .join("\n\n");
    let notices = parts
        .filter_map(|e| {
            let (h, t) = e.split_once(&body)?;
            Some(Notice {
                heading: h.trim().to_owned(),
                text: t.trim_end().to_owned(),
            })
        })
        .collect();
    (preamble, notices)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_embedded_notices_parse_into_entries() {
        let (preamble, notices) = parse(TEXT);
        assert!(preamble.starts_with("THIRD-PARTY NOTICES\n\nRerun by Mythen Studios is free"));
        assert!(preamble.contains("version 3 or (at your option)"));
        assert!(notices.len() > 10);
        assert!(notices[0].heading.starts_with("Rerun (GPL-3.0-or-later"));
        assert!(notices[0].text.contains("GNU GENERAL PUBLIC LICENSE"));
        assert!(
            notices
                .iter()
                .any(|n| n.heading.starts_with("Font IBM Plex Sans")
                    && n.text.contains("SIL OPEN FONT LICENSE"))
        );
        assert!(
            notices
                .iter()
                .any(|n| n.heading.contains("OR LicenseRef-Slint-Royalty-free-2.0"))
        );
        assert!(
            notices
                .iter()
                .all(|n| !n.heading.is_empty() && !n.text.is_empty())
        );
    }

    #[test]
    fn parse_takes_crlf_and_skips_a_broken_entry() {
        let t = format!(
            "Pre\r\n{ENTRY}\r\na 1 (MIT)\r\nb 2 (MIT)\r\n{BODY}\r\nText\r\n\r\n{ENTRY}\r\nno body line\r\n"
        );
        let (pre, n) = parse(&t);
        assert_eq!(pre, "Pre");
        assert_eq!(
            n,
            [Notice {
                heading: "a 1 (MIT)\nb 2 (MIT)".to_owned(),
                text: "Text".to_owned(),
            }]
        );
    }
}
