//! Typed views of Steam's two VDF files (ADR 0011). Pure functions from a parsed
//! [`Document`], strict about the fields they use and silent about the rest.
//!
//! - [`LibraryFolders`]: exactly one top-level object `libraryfolders`. Each child whose key
//!   is all ASCII digits is a library, in one of two formats: an object with exactly one
//!   `path` string and at most one `label` string (current), or a string that is the path
//!   itself (before 2021). Other keys and a library's `apps` are ignored. One malformed
//!   library fails the whole file.
//! - [`AppManifest`]: exactly one top-level object `AppState` with exactly one each of
//!   `appid`, `installdir`, `name` and `StateFlags`, all strings; the numbers strict (see
//!   [`AppManifest`]).
//!
//! Key lookups are ASCII case-insensitive (Valve's `stricmp`). Paths, labels, names and install
//! folder names stay raw ([`RawText`], ADR 0012): `policy::root` (`StoreDir::open`,
//! `StoreDir::game`) decides about paths, output layers sanitize names. Errors name fields and
//! byte offsets only, never values.

use crate::detect::text::RawText;
use crate::detect::vdf::{Document, Entry, Object, Value};

/// The libraries listed in `libraryfolders.vdf`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LibraryFolders {
    /// Libraries in file order (duplicates kept; step 12 de-duplicates by root identity).
    pub libraries: Vec<Library>,
}

/// One library.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Library {
    /// Path as written (decoded), unchecked. Not a root until `policy::root` accepts it.
    pub path: RawText,
    /// Label as written, if present (Steam writes `""` for none).
    pub label: Option<RawText>,
}

/// The fields Rerun uses from `appmanifest_<appid>.acf`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppManifest {
    /// `appid`: 1 to 10 ASCII digits, no sign, no whitespace, no leading zero, not 0, fits
    /// `u32`.
    pub app_id: u32,
    /// `name` as written. May contain any character; output layers sanitize it.
    pub name: RawText,
    /// `installdir` as written, unchecked; `detect::steam` classifies it.
    pub install_dir: RawText,
    /// `StateFlags`: like `appid`, but `0` is allowed. Its meaning: `detect::steam::state`.
    pub state_flags: u32,
}

/// What a value must be.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Expected {
    /// A string.
    Str,
    /// An object.
    Obj,
}

impl std::fmt::Display for Expected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Str => "a string",
            Self::Obj => "an object",
        })
    }
}

/// The document does not have the expected shape. Never contains values from the file.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ViewError {
    /// The document is not exactly one top-level pair with this name.
    #[error("expected exactly one top-level \"{name}\"")]
    Root {
        /// The expected name.
        name: &'static str,
    },
    /// A required field is missing.
    #[error("\"{field}\" missing in the object at byte {at}")]
    Missing {
        /// The field.
        field: &'static str,
        /// Offset of the object's key.
        at: usize,
    },
    /// A field that must be unique appears more than once.
    #[error("\"{field}\" appears more than once (bytes {first} and {second})")]
    Duplicate {
        /// The field.
        field: &'static str,
        /// Offset of the first occurrence.
        first: usize,
        /// Offset of the second occurrence.
        second: usize,
    },
    /// A field has the wrong type.
    #[error("\"{field}\" at byte {at} must be {expected}")]
    WrongType {
        /// The field.
        field: &'static str,
        /// Offset of the field.
        at: usize,
        /// What it must be.
        expected: Expected,
    },
    /// A numeric field is not a valid number.
    #[error("\"{field}\" at byte {at} is not a valid number")]
    InvalidNumber {
        /// The field.
        field: &'static str,
        /// Offset of the field.
        at: usize,
    },
}

const LIBRARY_FOLDERS: &str = "libraryfolders";
const APP_STATE: &str = "AppState";

/// The single top-level object `name` and the offset of its key.
fn root<'d>(doc: &'d Document, name: &'static str) -> Result<(&'d Object, usize), ViewError> {
    match doc.root().entries() {
        [only] if only.key.eq_ignore_ascii_case(name) => match &only.value {
            Value::Obj(obj) => Ok((obj, only.offset)),
            Value::Str(_) => Err(ViewError::WrongType {
                field: name,
                at: only.offset,
                expected: Expected::Obj,
            }),
        },
        _ => Err(ViewError::Root { name }),
    }
}

/// The at most one string `field` of `obj`, with the offset of its key.
fn unique_str<'o>(
    obj: &'o Object,
    field: &'static str,
) -> Result<Option<(&'o str, usize)>, ViewError> {
    let entry = obj.get_unique(field).map_err(|d| ViewError::Duplicate {
        field,
        first: d.first,
        second: d.second,
    })?;
    match entry {
        None => Ok(None),
        Some(Entry {
            value: Value::Str(s),
            offset,
            ..
        }) => Ok(Some((s, *offset))),
        Some(e) => Err(ViewError::WrongType {
            field,
            at: e.offset,
            expected: Expected::Str,
        }),
    }
}

/// The exactly one string `field` of `obj`, whose own key is at `at`.
fn required_str<'o>(
    obj: &'o Object,
    field: &'static str,
    at: usize,
) -> Result<(&'o str, usize), ViewError> {
    unique_str(obj, field)?.ok_or(ViewError::Missing { field, at })
}

/// A strict decimal `u32`: 1 to 10 ASCII digits, no sign or whitespace, no leading zero
/// (`0` itself only if `zero_ok`).
pub(super) fn decimal_u32(s: &str, zero_ok: bool) -> Option<u32> {
    let digits = s.as_bytes();
    if digits.is_empty() || digits.len() > 10 || !digits.iter().all(u8::is_ascii_digit) {
        return None;
    }
    if digits.starts_with(b"0") && (digits.len() > 1 || !zero_ok) {
        return None;
    }
    s.parse::<u64>().ok().and_then(|n| u32::try_from(n).ok())
}

fn number(obj: &Object, field: &'static str, at: usize, zero_ok: bool) -> Result<u32, ViewError> {
    let (s, field_at) = required_str(obj, field, at)?;
    decimal_u32(s, zero_ok).ok_or(ViewError::InvalidNumber {
        field,
        at: field_at,
    })
}

impl LibraryFolders {
    /// The libraries of a parsed `libraryfolders.vdf` (both formats).
    pub fn from_vdf(doc: &Document) -> Result<Self, ViewError> {
        let (folders, _) = root(doc, LIBRARY_FOLDERS)?;
        let mut libraries = Vec::new();
        for entry in folders.entries() {
            if entry.key.is_empty() || !entry.key.bytes().all(|b| b.is_ascii_digit()) {
                continue;
            }
            libraries.push(match &entry.value {
                // Before 2021: `"1" "D:\\Lib"`.
                Value::Str(path) => Library {
                    path: RawText::new(path.as_str()),
                    label: None,
                },
                Value::Obj(lib) => Library {
                    path: RawText::new(required_str(lib, "path", entry.offset)?.0),
                    label: unique_str(lib, "label")?.map(|(s, _)| RawText::new(s)),
                },
            });
        }
        Ok(Self { libraries })
    }
}

impl AppManifest {
    /// The fields of a parsed `appmanifest_<appid>.acf`.
    pub fn from_vdf(doc: &Document) -> Result<Self, ViewError> {
        let (st, at) = root(doc, APP_STATE)?;
        Ok(Self {
            app_id: number(st, "appid", at, false)?,
            name: RawText::new(required_str(st, "name", at)?.0),
            install_dir: RawText::new(required_str(st, "installdir", at)?.0),
            state_flags: number(st, "StateFlags", at, true)?,
        })
    }
}

#[cfg(test)]
mod tests;
