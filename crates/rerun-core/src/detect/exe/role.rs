//! Roles of executables from their names and PE facts (ADR 0014, "Roles"). Pure.
//!
//! The rule table is a heuristic with names in it, provisional until the developer-machine
//! dump (ADR 0014). Roles are hints: every candidate stays in the list with its role.

use std::fmt;

use super::ExeError;
use crate::detect::pe::{LegacyFormat, PeErrorKind, PeReadError};
use crate::path::RelPath;

/// What an executable is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Role {
    /// The game (no rule matched).
    Game,
    /// A launcher (`*launch*`); never promoted to the main executable.
    Launcher,
    /// A helper: web helper, server, configuration tool, editor, shader compiler, overlay,
    /// injector, activation tool.
    Helper,
    /// A crash reporter or dump writer.
    CrashReporter,
    /// An anti-cheat service or launcher.
    AntiCheat,
    /// An installer, uninstaller, updater, patcher or redistributable.
    Installer,
    /// A DLL with an `.exe` name (`IMAGE_FILE_DLL`).
    NotAnApp,
    /// A DOS, 16-bit Windows or linear executable: not runnable as it is on 64-bit Windows.
    Legacy(LegacyFormat),
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Game => f.write_str("game"),
            Self::Launcher => f.write_str("launcher"),
            Self::Helper => f.write_str("helper"),
            Self::CrashReporter => f.write_str("crash reporter"),
            Self::AntiCheat => f.write_str("anti-cheat"),
            Self::Installer => f.write_str("installer"),
            Self::NotAnApp => f.write_str("DLL, not an application"),
            Self::Legacy(format) => write!(f, "{format} executable"),
        }
    }
}

/// How a rule token matches the lowercased stem.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum How {
    Exact,
    Prefix,
    Suffix,
    Contains,
    /// The token followed only by one or more ASCII digits (`unins000`, Inno Setup).
    Digits,
}

/// The rule table (ADR 0014, "Roles"), in group order: the first rule that matches and is
/// not suspended by the install folder hint decides. Category tokens only, no game names.
/// Provisional; tuned with the developer-machine dump (ADR 0014 amendment).
const RULES: &[(Role, How, &str)] = &[
    (Role::CrashReporter, How::Exact, "createdump"),
    (Role::CrashReporter, How::Exact, "crashpad_handler"),
    (Role::CrashReporter, How::Exact, "crashreportclient"),
    (Role::CrashReporter, How::Exact, "unitycrashhandler32"),
    (Role::CrashReporter, How::Exact, "unitycrashhandler64"),
    (Role::CrashReporter, How::Exact, "bssndrpt"),
    (Role::CrashReporter, How::Exact, "bssndrpt64"),
    (Role::CrashReporter, How::Contains, "crash"),
    (Role::CrashReporter, How::Contains, "bugsplat"),
    (Role::AntiCheat, How::Exact, "start_protected_game"),
    (Role::AntiCheat, How::Prefix, "pbsvc"),
    (Role::AntiCheat, How::Prefix, "pnkbstr"),
    (Role::AntiCheat, How::Prefix, "beservice"),
    (Role::AntiCheat, How::Prefix, "easyanticheat"),
    (Role::AntiCheat, How::Suffix, "_be"),
    (Role::AntiCheat, How::Suffix, "_eac"),
    (Role::Installer, How::Contains, "setup"),
    (Role::Installer, How::Contains, "install"),
    (Role::Installer, How::Contains, "redist"),
    (Role::Installer, How::Contains, "patch"),
    (Role::Installer, How::Contains, "update"),
    (Role::Installer, How::Prefix, "vc_redist"),
    (Role::Installer, How::Prefix, "vcredist"),
    (Role::Installer, How::Prefix, "dxsetup"),
    (Role::Installer, How::Prefix, "dotnetfx"),
    (Role::Installer, How::Prefix, "physx"),
    (Role::Installer, How::Prefix, "oalinst"),
    (Role::Installer, How::Digits, "unins"),
    (Role::Launcher, How::Contains, "launch"),
    (Role::Helper, How::Contains, "webhelper"),
    (Role::Helper, How::Contains, "browsersubprocess"),
    (Role::Helper, How::Contains, "cefprocess"),
    (Role::Helper, How::Contains, "qtwebengineprocess"),
    (Role::Helper, How::Contains, "config"),
    (Role::Helper, How::Contains, "settings"),
    (Role::Helper, How::Contains, "editor"),
    (Role::Helper, How::Contains, "compil"),
    (Role::Helper, How::Contains, "overlay"),
    (Role::Helper, How::Contains, "inject"),
    (Role::Helper, How::Contains, "activation"),
    (Role::Helper, How::Suffix, "server"),
];

fn matches(how: How, token: &str, s: &str) -> bool {
    match how {
        How::Exact => s == token,
        How::Prefix => s.starts_with(token),
        How::Suffix => s.ends_with(token),
        How::Contains => s.contains(token),
        How::Digits => s
            .strip_prefix(token)
            .is_some_and(|d| !d.is_empty() && d.bytes().all(|b| b.is_ascii_digit())),
    }
}

/// The file name without its `.exe` (ASCII case-insensitive); the name itself otherwise.
pub(super) fn stem(file_name: &str) -> &str {
    let b = file_name.as_bytes();
    match b.len().checked_sub(4) {
        Some(at) if b.get(at..).is_some_and(|e| e.eq_ignore_ascii_case(b".exe")) => {
            file_name.get(..at).unwrap_or(file_name)
        }
        _ => file_name,
    }
}

/// Lowercase ASCII letters and digits of `s`.
fn reduce(s: &str) -> String {
    s.chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

/// Similarity of an executable's stem and the install folder hint (ADR 0014, "Ranking"):
/// 2 equal, 1 one contains the other and the shorter has at least 4 characters (no
/// acronyms), else 0; both reduced to lowercase ASCII letters and digits first. Nothing left
/// after reducing is 0.
pub(crate) fn similarity(stem: &str, hint: &str) -> u8 {
    let (a, b) = (reduce(stem), reduce(hint));
    if a.is_empty() || b.is_empty() {
        return 0;
    }
    if a == b {
        return 2;
    }
    let (short, long) = if a.len() <= b.len() {
        (&a, &b)
    } else {
        (&b, &a)
    };
    u8::from(short.len() >= 4 && long.contains(short.as_str()))
}

/// The role by name rules alone (ASCII case-insensitive; ASCII tokens also match inside a
/// stem with non-ASCII characters). `hint` is the install folder: a rule is suspended when
/// its token (reduced to letters and digits) occurs in the reduced hint, so
/// `CrashBandicoot.exe` in `Crash Bandicoot` stays the game while `Fallout4Launcher.exe` in
/// `Fallout 4` is a launcher. The first rule that matches and is not suspended decides.
pub(crate) fn name_role(file_name: &str, hint: Option<&RelPath>) -> Role {
    let s = stem(file_name).to_ascii_lowercase();
    let hint = hint.map(|h| reduce(h.file_name())).unwrap_or_default();
    RULES
        .iter()
        .find(|(_, how, token)| matches(*how, token, &s) && !suspended(token, &hint))
        .map_or(Role::Game, |(role, _, _)| *role)
}

/// The token occurs in the reduced install folder hint.
fn suspended(token: &str, hint: &str) -> bool {
    let t = reduce(token);
    !t.is_empty() && hint.contains(t.as_str())
}

/// The role once the file was inspected: PE facts override the name (the DLL flag is
/// `NotAnApp`, a `Legacy` error is `Legacy`); a file that failed otherwise keeps its name role.
pub(super) fn with_facts(name: Role, facts: &Result<super::ExeFacts, ExeError>) -> Role {
    match facts {
        Ok(f) if f.info.headers.is_dll() => Role::NotAnApp,
        Ok(_) => name,
        Err(ExeError::Pe(PeReadError::Parse { error, .. })) => match error.kind {
            PeErrorKind::Legacy(format) => Role::Legacy(format),
            _ => name,
        },
        Err(_) => name,
    }
}

#[cfg(test)]
mod tests;
