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
    /// A launcher (`*launcher*`); never promoted to the main executable.
    Launcher,
    /// A helper: web helper, server, configuration tool, editor.
    Helper,
    /// A crash reporter or dump writer.
    CrashReporter,
    /// An anti-cheat service or launcher.
    AntiCheat,
    /// An installer, uninstaller or redistributable.
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

const CRASH_EXACT: &[&str] = &[
    "createdump",
    "crashpad_handler",
    "crashreportclient",
    "unitycrashhandler32",
    "unitycrashhandler64",
    "bssndrpt",
    "bssndrpt64",
];
const ANTI_CHEAT_EXACT: &[&str] = &["start_protected_game", "pbsvc", "pnkbstra", "pnkbstrb"];
const ANTI_CHEAT_PREFIX: &[&str] = &["beservice", "easyanticheat"];
const ANTI_CHEAT_SUFFIX: &[&str] = &["_be", "_eac"];
const INSTALLER_CONTAINS: &[&str] = &["setup", "install", "redist"];
const INSTALLER_PREFIX: &[&str] = &[
    "vc_redist",
    "vcredist",
    "dxsetup",
    "dotnetfx",
    "physx",
    "oalinst",
];
const HELPER_CONTAINS: &[&str] = &[
    "webhelper",
    "browsersubprocess",
    "cefprocess",
    "qtwebengineprocess",
    "config",
    "settings",
    "editor",
];
const HELPER_SUFFIX: &[&str] = &["_server", "-server", "dedicatedserver"];

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
/// 2 equal, 1 one is a prefix of the other with at least 4 characters, else 0; both reduced
/// to lowercase ASCII letters and digits first. Nothing left after reducing is 0.
pub fn similarity(stem: &str, hint: &str) -> u8 {
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
    u8::from(short.len() >= 4 && long.starts_with(short.as_str()))
}

/// The role by name rules alone. `hint` is the install folder: a stem similar to it (at
/// least 1) suspends every rule (`CrashBandicoot.exe` in `Crash Bandicoot` is the game).
pub fn name_role(file_name: &str, hint: Option<&RelPath>) -> Role {
    let stem = stem(file_name);
    if !stem.is_ascii() || hint.is_some_and(|h| similarity(stem, h.file_name()) >= 1) {
        return Role::Game;
    }
    let s = stem.to_ascii_lowercase();
    let s = s.as_str();
    let contains = |list: &[&str]| list.iter().any(|w| s.contains(w));
    let starts = |list: &[&str]| list.iter().any(|w| s.starts_with(w));
    let ends = |list: &[&str]| list.iter().any(|w| s.ends_with(w));
    if CRASH_EXACT.contains(&s) || s.contains("crash") {
        Role::CrashReporter
    } else if ANTI_CHEAT_EXACT.contains(&s) || starts(ANTI_CHEAT_PREFIX) || ends(ANTI_CHEAT_SUFFIX)
    {
        Role::AntiCheat
    } else if contains(INSTALLER_CONTAINS) || starts(INSTALLER_PREFIX) || is_uninstaller(s) {
        Role::Installer
    } else if s.contains("launcher") {
        Role::Launcher
    } else if contains(HELPER_CONTAINS) || ends(HELPER_SUFFIX) {
        Role::Helper
    } else {
        Role::Game
    }
}

/// `unins` followed only by one or more digits (`unins000`, Inno Setup).
fn is_uninstaller(s: &str) -> bool {
    s.strip_prefix("unins")
        .is_some_and(|d| !d.is_empty() && d.bytes().all(|b| b.is_ascii_digit()))
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
