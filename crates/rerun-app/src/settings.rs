//! The app's settings (P5-10b, ADR 0027 amendment P5-10), framework-free: the typed form of
//! `<AppDir>\app\settings.json`, its canonical encoding, and the session's memory of what the file
//! held ([`Memo`]). The core moves the bytes (`flow::read_settings`, `flow::write_settings`).
//!
//! Format 1, one JSON object of at most `flow::SETTINGS_MAX` bytes, unknown fields refused:
//!
//! | Field        | Values                           | Default     |
//! |--------------|----------------------------------|-------------|
//! | `format`     | `1`                              | (required)  |
//! | `language`   | `"windows"`, `"en"`, `"de"`      | `"windows"` |
//! | `theme`      | `"mythen"`, `"nacht"`            | `"mythen"`  |
//! | `library`    | `"list"`, `"compact"`            | `"list"`    |
//! | `grouped`    | `true`, `false`                  | `true`      |
//! | `intro_seen` | `true`, `false`                  | `false`     |
//!
//! Only closed enums and booleans: never a path, a font or a URL, so nothing in the file can make
//! the app or Slint read anything else (security review S1 of P5-3). A missing field is its
//! default. The language and the library view (P5-10d) apply at once; a language change is saved
//! like any other.
//!
//! Reading ([`decode`]): anything wrong in a file of at most the bound (not JSON, not an object,
//! an unknown field, a wrong type, UTF-16, `format` 0) means the defaults and is replaced by the
//! next change; a file over the bound, a link or a folder in the file's place, or a `format` above
//! 1 of any size (a newer Rerun's file) means the defaults **for the session only**: that file is
//! never written over ([`Writable::SessionOnly`]).
//!
//! Writing ([`Memo::save`]): only a real change against what was read or last written (the
//! defaults without a file are no change), through `flow::write_settings` with the hash that was
//! read; if another Rerun wrote meanwhile it is read once more and the last writer wins.

use rerun_core::flow::{self, Guarded, Seen, SettingsError, SettingsRead};
use serde::{Deserialize, Serialize};

use crate::text::Lang;
use crate::theme::ThemeChoice;

/// The format this build reads and writes.
pub const FORMAT: u32 = 1;

/// The app's language.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LangChoice {
    /// Windows' display language: German for a German locale, else English (the default).
    #[default]
    Windows,
    /// English.
    En,
    /// German.
    De,
}

impl LangChoice {
    /// Its place in Settings > Appearance (0 like Windows, 1 English, 2 German).
    pub fn index(self) -> i32 {
        match self {
            Self::Windows => 0,
            Self::En => 1,
            Self::De => 2,
        }
    }

    /// The choice at a place of the list (an unknown place: the default).
    pub fn from_index(i: i32) -> Self {
        match i {
            1 => Self::En,
            2 => Self::De,
            _ => Self::Windows,
        }
    }

    /// The language to speak: the choice, or `windows` (Windows' display language) for
    /// [`Self::Windows`].
    pub fn resolve(self, windows: Lang) -> Lang {
        match self {
            Self::Windows => windows,
            Self::En => Lang::En,
            Self::De => Lang::De,
        }
    }
}

/// How the library lists the games.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LibView {
    /// One row per game with its details (the default).
    #[default]
    List,
    /// One short line per game.
    Compact,
}

impl LibView {
    /// Its place in the library bar and in Settings (0 list, 1 compact).
    pub fn index(self) -> i32 {
        match self {
            Self::List => 0,
            Self::Compact => 1,
        }
    }

    /// The view at a place of the list (an unknown place: the default).
    pub fn from_index(i: i32) -> Self {
        if i == 1 { Self::Compact } else { Self::List }
    }
}

const fn yes() -> bool {
    true
}

/// The settings (module docs).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    /// The format, [`FORMAT`].
    pub format: u32,
    /// The language.
    #[serde(default)]
    pub language: LangChoice,
    /// The theme (Windows' high contrast wins over it).
    #[serde(default)]
    pub theme: ThemeChoice,
    /// The library view.
    #[serde(default)]
    pub library: LibView,
    /// The library grouped by status.
    #[serde(default = "yes")]
    pub grouped: bool,
    /// The first-start card was dismissed ("Got it").
    #[serde(default)]
    pub intro_seen: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            format: FORMAT,
            language: LangChoice::default(),
            theme: ThemeChoice::default(),
            library: LibView::default(),
            grouped: true,
            intro_seen: false,
        }
    }
}

/// Whether the settings may be written this session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Writable {
    /// A change is written.
    Yes,
    /// A change holds for the session only: a newer Rerun's file, a file over the bound, or a
    /// link or a folder in its place, is never written over.
    SessionOnly,
}

/// The settings `r` holds, and whether a change may be written (module docs). Never fails.
pub fn decode(r: &SettingsRead) -> (Settings, Writable) {
    let bytes = match r {
        SettingsRead::Absent => return (Settings::default(), Writable::Yes),
        // Too large, a link, a folder: never written over.
        SettingsRead::Unusable { .. } => return (Settings::default(), Writable::SessionOnly),
        SettingsRead::Bytes { bytes, .. } => bytes,
    };
    /// Only the format, as any JSON number, every other field ignored: a newer format may have
    /// others, and its number may be of any size.
    #[derive(Deserialize)]
    struct Probe {
        format: serde_json::Number,
    }
    let Ok(p) = serde_json::from_slice::<Probe>(bytes) else {
        return (Settings::default(), Writable::Yes);
    };
    let newer = match p.format.as_u64() {
        Some(n) => n > u64::from(FORMAT),
        // Beyond `u64` (read as a float): a whole number above 1 is a newer format too.
        None => p
            .format
            .as_f64()
            .is_some_and(|f| f.is_finite() && f > 1.0 && f.fract() == 0.0),
    };
    if newer {
        return (Settings::default(), Writable::SessionOnly);
    }
    if p.format.as_u64() != Some(u64::from(FORMAT)) {
        return (Settings::default(), Writable::Yes);
    }
    match serde_json::from_slice::<Settings>(bytes) {
        Ok(s) => (s, Writable::Yes),
        Err(_) => (Settings::default(), Writable::Yes),
    }
}

/// The canonical bytes of `s`: compact JSON, every field in a fixed order, one line and `\n`.
pub fn encode(s: &Settings) -> Vec<u8> {
    let canonical = Settings {
        format: FORMAT,
        ..s.clone()
    };
    // Enums and booleans only: serialising cannot fail.
    let mut out = serde_json::to_vec(&canonical).unwrap_or_default();
    out.push(b'\n');
    out
}

/// What the session knows about the file: the settings in force, what the file held at the last
/// read or write, and whether a change may be written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Memo {
    /// The settings in force (as read, or as last written).
    pub settings: Settings,
    seen: Seen,
    writable: Writable,
}

impl Default for Memo {
    /// The defaults, as if there were no file.
    fn default() -> Self {
        Self {
            settings: Settings::default(),
            seen: Seen::Absent,
            writable: Writable::Yes,
        }
    }
}

/// What [`Memo::save`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Saved {
    /// The same as the settings in force: nothing written.
    Unchanged,
    /// Written.
    Written,
    /// Not written: the change holds for the session only.
    SessionOnly,
    /// Not written (the core's reason); the next change tries again.
    Failed(SettingsError),
}

impl Saved {
    /// A word for the [DEV] timing trace.
    pub fn word(&self) -> &'static str {
        match self {
            Self::Unchanged => "unchanged",
            Self::Written => "written",
            Self::SessionOnly => "for this session only",
            Self::Failed(SettingsError::Changed) => "not written: changed twice",
            Self::Failed(_) => "not written",
        }
    }
}

impl Memo {
    /// The settings file through `g` (creates nothing).
    pub fn load(g: &Guarded<'_>) -> Self {
        let r = flow::read_settings(g);
        let (settings, writable) = decode(&r);
        Self {
            settings,
            seen: r.seen(),
            writable,
        }
    }

    /// The defaults for a session that cannot read the file (a guard stopped it): nothing is
    /// written.
    pub fn session_only() -> Self {
        Self {
            writable: Writable::SessionOnly,
            seen: Seen::Unknown,
            ..Self::default()
        }
    }

    /// Whether a change is written.
    #[cfg(test)]
    pub fn writable(&self) -> Writable {
        self.writable
    }

    /// Writes `new` if it differs from the settings in force (module docs). The settings in force
    /// become `new` unless the write failed.
    pub fn save(&mut self, g: &mut Guarded<'_>, new: &Settings) -> Saved {
        if *new == self.settings {
            return Saved::Unchanged;
        }
        if self.writable == Writable::SessionOnly {
            self.settings = new.clone();
            return Saved::SessionOnly;
        }
        let bytes = encode(new);
        let r = match flow::write_settings(g, &bytes, &self.seen) {
            Err(SettingsError::Changed) => {
                // Another Rerun wrote meanwhile: read once more; the last writer wins, unless the
                // file is now one this build never writes over.
                let again = flow::read_settings(g);
                if decode(&again).1 == Writable::SessionOnly {
                    self.writable = Writable::SessionOnly;
                    self.seen = Seen::Unknown;
                    self.settings = new.clone();
                    return Saved::SessionOnly;
                }
                flow::write_settings(g, &bytes, &again.seen())
            }
            r => r,
        };
        match r {
            Ok(seen) => {
                self.seen = seen;
                self.settings = new.clone();
                Saved::Written
            }
            Err(e) => Saved::Failed(e),
        }
    }
}

/// The settings at the start of the app, before the window (`main`): through the guard, so an
/// elevated or blocked start reads nothing and writes nothing this session.
pub fn at_start(env: flow::Env<'_>) -> Memo {
    match flow::guard(env) {
        Ok(g) => Memo::load(&g),
        Err(_) => Memo::session_only(),
    }
}

#[cfg(test)]
mod tests;
