//! The Steam root from the registry (ADR 0012).
//!
//! Candidates in order ([`RootSource::ALL`]): `HKCU\Software\Valve\Steam` `SteamPath`, then
//! `HKLM\SOFTWARE\Valve\Steam` `InstallPath` in the 32-bit view (never spelled
//! `WOW6432Node`, ADR 0009), then the same in the native view. Every present candidate is
//! opened with [`StoreDir::open`]; the first that opens is the root, a later one that opens a
//! different folder is reported ([`IssueKind::RootsDisagree`]) and never scanned.
//!
//! Only [`Registry::get`] is used. A value is never expanded.

use std::fmt;
use std::path::Path;

use super::issue::{BadValue, Issue, IssueKind, Location};
use crate::detect::text::RawText;
use crate::policy::root::{ForbiddenRoots, StoreDir};
use crate::sys::registry::{Hive, RegKey, RegValue, RegView, reg_type};
use crate::sys::{Registry, SysErrorKind, System};

/// A registry candidate for the Steam root.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RootSource {
    /// `HKCU\Software\Valve\Steam` `SteamPath`, rewritten by the client on every start.
    CurrentUser,
    /// `HKLM\SOFTWARE\Valve\Steam` `InstallPath` in the 32-bit view (the installer's).
    Machine32,
    /// `HKLM\SOFTWARE\Valve\Steam` `InstallPath` in the native view.
    MachineNative,
}

impl RootSource {
    /// All candidates, in the order they are tried.
    pub const ALL: [Self; 3] = [Self::CurrentUser, Self::Machine32, Self::MachineNative];

    /// The key.
    pub fn key(self) -> RegKey {
        match self {
            Self::CurrentUser => {
                RegKey::new(Hive::CurrentUser, RegView::Native, r"Software\Valve\Steam")
            }
            Self::Machine32 => {
                RegKey::new(Hive::LocalMachine, RegView::Wow32, r"SOFTWARE\Valve\Steam")
            }
            Self::MachineNative => {
                RegKey::new(Hive::LocalMachine, RegView::Native, r"SOFTWARE\Valve\Steam")
            }
        }
    }

    /// The value name.
    pub fn value_name(self) -> &'static str {
        match self {
            Self::CurrentUser => "SteamPath",
            Self::Machine32 | Self::MachineNative => "InstallPath",
        }
    }
}

impl fmt::Display for RootSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::CurrentUser => r"HKCU\Software\Valve\Steam SteamPath",
            Self::Machine32 => r"HKLM\SOFTWARE\Valve\Steam InstallPath (32-bit view)",
            Self::MachineNative => r"HKLM\SOFTWARE\Valve\Steam InstallPath (native view)",
        })
    }
}

/// The text of a raw `REG_SZ`/`REG_EXPAND_SZ` (one that [`RegValue::decode`] kept as `Raw`):
/// even length, valid UTF-16LE, no NUL except any number of trailing ones (ADR 0009 leaves
/// this tolerance to detection).
fn tolerant_utf16(data: &[u8]) -> Option<String> {
    let (units, rest) = data.as_chunks::<2>();
    if !rest.is_empty() {
        return None;
    }
    let units: Vec<u16> = units.iter().map(|c| u16::from_le_bytes(*c)).collect();
    let end = units.iter().rposition(|u| *u != 0).map_or(0, |i| i + 1);
    let body = &units[..end];
    if body.contains(&0) {
        return None;
    }
    String::from_utf16(body).ok()
}

/// The path text of a candidate value: a string, `REG_EXPAND_SZ` only without `%`.
pub(super) fn text_of(value: &RegValue) -> Result<String, BadValue> {
    let (text, expandable) = match value {
        RegValue::String(s) => (s.clone(), false),
        RegValue::ExpandString(s) => (s.clone(), true),
        RegValue::Raw(raw)
            if raw.kind() == reg_type::REG_SZ || raw.kind() == reg_type::REG_EXPAND_SZ =>
        {
            let text = tolerant_utf16(raw.data()).ok_or(BadValue::InvalidString)?;
            (text, raw.kind() == reg_type::REG_EXPAND_SZ)
        }
        other => {
            let kind = other.encode().map_or(reg_type::REG_NONE, |(k, _)| k);
            return Err(BadValue::NotAString { kind });
        }
    };
    if text.is_empty() {
        return Err(BadValue::Empty);
    }
    if expandable && text.contains('%') {
        return Err(BadValue::Unexpanded);
    }
    Ok(text)
}

/// The value of one candidate. A missing key or value is `Ok(None)`.
pub(super) fn read_candidate(
    reg: &dyn Registry,
    source: RootSource,
) -> Result<Option<RawText>, IssueKind> {
    match reg.get(&source.key(), source.value_name()) {
        Ok(None) => Ok(None),
        Err(e) if e.kind == SysErrorKind::NotFound => Ok(None),
        Err(e) => Err(IssueKind::Sys(e)),
        Ok(Some(value)) => text_of(&value)
            .map(|t| Some(RawText::new(t)))
            .map_err(IssueKind::RegistryValue),
    }
}

/// The Steam root: the first candidate that opens, with its source. Every other present
/// candidate is opened as well and reported in `issues` if it fails or opens a different
/// folder. `None`: Steam is not installed (or every candidate was refused, see `issues`).
pub fn find_root<'s>(
    sys: &'s dyn System,
    fr: &ForbiddenRoots,
    issues: &mut Vec<Issue>,
) -> Option<(RootSource, StoreDir<'s>)> {
    let mut found: Option<(RootSource, StoreDir<'s>)> = None;
    for source in RootSource::ALL {
        let at = Location::Registry(source);
        let text = match read_candidate(sys.registry(), source) {
            Ok(Some(text)) => text,
            Ok(None) => continue,
            Err(kind) => {
                issues.push(Issue { at, kind });
                continue;
            }
        };
        let store = match StoreDir::open(sys, fr, Path::new(text.as_raw_str())) {
            Ok(store) => store,
            Err(e) => {
                issues.push(Issue {
                    at,
                    kind: IssueKind::Root(Box::new(e)),
                });
                continue;
            }
        };
        match &found {
            None => found = Some((source, store)),
            Some((winner, root)) => {
                if root.id() != store.id() {
                    issues.push(Issue {
                        at,
                        kind: IssueKind::RootsDisagree {
                            winner: *winner,
                            root: root.path().clone(),
                            other: store.path().clone(),
                        },
                    });
                }
            }
        }
    }
    found
}

#[cfg(test)]
mod tests;
