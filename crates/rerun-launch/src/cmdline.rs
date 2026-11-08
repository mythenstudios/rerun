//! The shim's own command line (ADR 0022, B1 and M2), taken raw from `GetCommandLineW`:
//!
//! ```text
//! <own argv[0]> --profile <token> <Steam's command, the raw tail>
//! ```
//!
//! Argument 0 is cut by the `CommandLineToArgvW` rule for argument 0 (a leading `"` runs to the
//! next `"`, otherwise up to the first space or tab), the shim's own and Steam's alike. Nothing
//! is ever re-quoted: Steam's command is passed on as the raw tail, unit for unit.

/// UTF-16 space.
const SPACE: u16 = b' ' as u16;
/// UTF-16 tab.
const TAB: u16 = b'\t' as u16;
/// UTF-16 double quote.
const QUOTE: u16 = b'"' as u16;
/// The literal option before the profile token.
const PROFILE: &[u16] = &[
    b'-' as u16,
    b'-' as u16,
    b'p' as u16,
    b'r' as u16,
    b'o' as u16,
    b'f' as u16,
    b'i' as u16,
    b'l' as u16,
    b'e' as u16,
];

/// Why the shim's own command line is unusable (exit code 2, nothing started).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Usage {
    /// The first argument is not `--profile`.
    NoProfileOption,
    /// Nothing after `--profile`.
    NoProfileToken,
    /// Nothing after the profile token: no command to start.
    NoCommand,
    /// Steam's first argument is not an absolute drive path (`X:\…`).
    NotAbsolute,
}

impl std::fmt::Display for Usage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::NoProfileOption => "the first argument is not --profile",
            Self::NoProfileToken => "no profile after --profile",
            Self::NoCommand => "no command after the profile",
            Self::NotAbsolute => "the command does not start with an absolute drive path",
        })
    }
}

/// The parts of a usable command line, borrowed from it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Command<'a> {
    /// The token after `--profile` (a profile ID if it is 32 lower-case hex digits).
    pub(crate) token: &'a [u16],
    /// Steam's command: everything after the token and the blanks that follow it, unchanged
    /// (trailing blanks included). `lpCommandLine` of `CreateProcessW`.
    pub(crate) tail: &'a [u16],
    /// Steam's first argument without quotes: `lpApplicationName`, always (M2).
    pub(crate) app: &'a [u16],
    /// The tail after `app` (and its closing quote) and the blanks that follow it, or `None`
    /// if nothing is left: `lpParameters` of the `ShellExecuteExW` fallback (B2).
    pub(crate) parameters: Option<&'a [u16]>,
}

fn is_blank(u: u16) -> bool {
    u == SPACE || u == TAB
}

fn skip_blanks(s: &[u16]) -> &[u16] {
    let n = s.iter().take_while(|&&u| is_blank(u)).count();
    &s[n..]
}

/// Argument 0 by the `CommandLineToArgvW` rule: `(argument without quotes, rest after it)`.
/// The rest starts right after the closing quote or at the blank that ended the argument.
pub(crate) fn split_argv0(s: &[u16]) -> (&[u16], &[u16]) {
    if let Some((&QUOTE, inner)) = s.split_first() {
        match inner.iter().position(|&u| u == QUOTE) {
            Some(end) => (&inner[..end], &inner[end + 1..]),
            None => (inner, &[]),
        }
    } else {
        let end = s.iter().position(|&u| is_blank(u)).unwrap_or(s.len());
        (&s[..end], &s[end..])
    }
}

/// `X:\` followed by anything, and no `"` anywhere: an absolute drive path (not relative,
/// not UNC, not `\\?\`, not drive-relative like `C:game.exe`).
pub(crate) fn is_absolute_drive_path(p: &[u16]) -> bool {
    let drive =
        matches!(p.first(), Some(&u) if u8::try_from(u).is_ok_and(|b| b.is_ascii_alphabetic()));
    drive
        && p.get(1) == Some(&(b':' as u16))
        && p.get(2) == Some(&(b'\\' as u16))
        && !p.contains(&QUOTE)
}

/// Splits the shim's own command line.
pub(crate) fn parse(line: &[u16]) -> Result<Command<'_>, Usage> {
    let (_own, rest) = split_argv0(line);
    let rest = skip_blanks(rest);
    let rest = rest.strip_prefix(PROFILE).ok_or(Usage::NoProfileOption)?;
    // `--profile` must be a whole argument: a blank follows it.
    if !rest.first().is_some_and(|&u| is_blank(u)) {
        return Err(if rest.is_empty() {
            Usage::NoProfileToken
        } else {
            Usage::NoProfileOption
        });
    }
    let rest = skip_blanks(rest);
    let end = rest.iter().position(|&u| is_blank(u)).unwrap_or(rest.len());
    let (token, rest) = rest.split_at(end);
    if token.is_empty() {
        return Err(Usage::NoProfileToken);
    }
    let tail = skip_blanks(rest);
    if tail.is_empty() {
        return Err(Usage::NoCommand);
    }
    let (app, after) = split_argv0(tail);
    if !is_absolute_drive_path(app) {
        return Err(Usage::NotAbsolute);
    }
    let parameters = Some(skip_blanks(after)).filter(|p| !p.is_empty());
    Ok(Command {
        token,
        tail,
        app,
        parameters,
    })
}

/// The path ends in `.exe`, ASCII case-insensitively (B2: only an exe goes to
/// `ShellExecuteExW`).
pub(crate) fn ends_with_exe(p: &[u16]) -> bool {
    let Some(ext) = p.len().checked_sub(4).map(|i| &p[i..]) else {
        return false;
    };
    let lower: Vec<u16> = ext
        .iter()
        .map(|&u| match u8::try_from(u) {
            Ok(b) => u16::from(b.to_ascii_lowercase()),
            Err(_) => u,
        })
        .collect();
    lower == [b'.' as u16, b'e' as u16, b'x' as u16, b'e' as u16]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn w(s: &str) -> Vec<u16> {
        s.encode_utf16().collect()
    }

    fn s(u: &[u16]) -> String {
        String::from_utf16(u).unwrap()
    }

    const OWN: &str =
        r#""C:\Program Files\Rerun\rerun-launch.exe" --profile 0123456789abcdef0123456789abcdef "#;

    fn parsed(tail: &str) -> (String, String, String, Option<String>) {
        let line = w(&format!("{OWN}{tail}"));
        let c = parse(&line).unwrap();
        (s(c.token), s(c.tail), s(c.app), c.parameters.map(s))
    }

    #[test]
    fn quoted_path_with_arguments() {
        let (token, tail, app, params) = parsed(r#""C:\Games\My Game\game.exe" -window -x "a b""#);
        assert_eq!(token, "0123456789abcdef0123456789abcdef");
        assert_eq!(tail, r#""C:\Games\My Game\game.exe" -window -x "a b""#);
        assert_eq!(app, r"C:\Games\My Game\game.exe");
        assert_eq!(params.as_deref(), Some(r#"-window -x "a b""#));
    }

    #[test]
    fn unquoted_path_without_spaces() {
        let (_, tail, app, params) = parsed(r"C:\Games\Game\game.exe -dx9");
        assert_eq!(tail, r"C:\Games\Game\game.exe -dx9");
        assert_eq!(app, r"C:\Games\Game\game.exe");
        assert_eq!(params.as_deref(), Some("-dx9"));
    }

    #[test]
    fn unquoted_path_with_spaces_ends_at_the_first_space() {
        // argv[0] is "C:\Program": absolute, but not the game (and never resolved piece by
        // piece, M2); the tail is still byte-identical.
        let (_, tail, app, params) = parsed(r"C:\Program Files\Game\game.exe -x");
        assert_eq!(tail, r"C:\Program Files\Game\game.exe -x");
        assert_eq!(app, r"C:\Program");
        assert_eq!(params.as_deref(), Some(r"Files\Game\game.exe -x"));
    }

    #[test]
    fn quotes_and_percent_in_arguments_and_trailing_blanks_stay() {
        let t = "\"C:\\G\\game.exe\" +set \"name\" \"%USERNAME%\" 100% \t ";
        let (_, tail, app, params) = parsed(t);
        assert_eq!(tail, t);
        assert_eq!(app, r"C:\G\game.exe");
        assert_eq!(
            params.as_deref(),
            Some("+set \"name\" \"%USERNAME%\" 100% \t ")
        );
    }

    #[test]
    fn no_parameters_after_the_program() {
        assert_eq!(parsed(r#""C:\G\game.exe""#).3, None);
        assert_eq!(parsed(r#""C:\G\game.exe"   "#).3, None);
        assert_eq!(parsed(r"C:\G\game.exe").3, None);
        assert_eq!(parsed(r#""C:\G\game.exe"   "#).1, r#""C:\G\game.exe"   "#);
    }

    #[test]
    fn a_quote_right_after_the_closing_quote_starts_the_parameters() {
        let (_, _, app, params) = parsed(r#""C:\G\game.exe"-x"#);
        assert_eq!(app, r"C:\G\game.exe");
        assert_eq!(params.as_deref(), Some("-x"));
    }

    #[test]
    fn unclosed_quote_runs_to_the_end() {
        let (_, tail, app, params) = parsed(r#""C:\G\game.exe -x"#);
        assert_eq!(tail, r#""C:\G\game.exe -x"#);
        assert_eq!(app, r"C:\G\game.exe -x");
        assert_eq!(params, None);
    }

    #[test]
    fn own_argv0_unquoted_and_tabs_between_arguments() {
        let line = w("rerun-launch.exe\t--profile\t\tabc\t\"C:\\G\\g.exe\"");
        let c = parse(&line).unwrap();
        assert_eq!(s(c.token), "abc");
        assert_eq!(s(c.tail), "\"C:\\G\\g.exe\"");
    }

    #[test]
    fn steam_argv0_not_an_absolute_drive_path() {
        for tail in [
            "game.exe -x",
            r"Games\game.exe",
            r"\Games\game.exe",
            r"C:game.exe",
            r"C:/Games/game.exe",
            r"\\server\share\game.exe",
            r"\\?\C:\Games\game.exe",
            r#""""#,
            r#""" C:\G\game.exe"#,
            r#"C:\a"b c"\game.exe"#,
            r"1:\game.exe",
        ] {
            let line = w(&format!("{OWN}{tail}"));
            assert_eq!(parse(&line), Err(Usage::NotAbsolute), "{tail}");
        }
    }

    #[test]
    fn unusable_own_command_lines() {
        let cases = [
            ("rerun-launch.exe", Usage::NoProfileOption),
            ("rerun-launch.exe C:\\G\\game.exe", Usage::NoProfileOption),
            (
                "rerun-launch.exe --profiles x C:\\G\\g.exe",
                Usage::NoProfileOption,
            ),
            (
                "rerun-launch.exe --PROFILE x C:\\G\\g.exe",
                Usage::NoProfileOption,
            ),
            ("rerun-launch.exe --profile", Usage::NoProfileToken),
            ("rerun-launch.exe --profile   ", Usage::NoProfileToken),
            ("rerun-launch.exe --profile abc", Usage::NoCommand),
            ("rerun-launch.exe --profile abc \t ", Usage::NoCommand),
            ("", Usage::NoProfileOption),
            ("\"C:\\R\\rerun-launch.exe", Usage::NoProfileOption),
        ];
        for (line, want) in cases {
            assert_eq!(parse(&w(line)), Err(want), "{line}");
        }
    }

    #[test]
    fn exe_suffix() {
        assert!(ends_with_exe(&w(r"C:\G\game.exe")));
        assert!(ends_with_exe(&w(r"C:\G\GAME.ExE")));
        assert!(!ends_with_exe(&w(r"C:\G\game.bat")));
        assert!(!ends_with_exe(&w(r"C:\G\game.exe ")));
        assert!(!ends_with_exe(&w(r"C:\G\game.exe.lnk")));
        assert!(!ends_with_exe(&w("exe")));
        assert!(!ends_with_exe(&w("")));
    }
}
