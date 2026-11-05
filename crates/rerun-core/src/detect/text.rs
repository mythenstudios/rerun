//! [`RawText`]: untrusted text from files and the registry (ADR 0012): Steam's files, registry
//! values and, since ADR 0013, version strings of executables.

use std::fmt;

/// Text exactly as read from an untrusted source (a path, label, name or install folder from
/// a Steam file, a registry value, a version string of an executable), unchecked.
///
/// Deliberately without `Display`, `Deref`, `AsRef<str>`, `AsRef<Path>` and `From`: the content
/// is reached only through [`RawText::as_raw_str`], so a raw path never reaches a `Path` API
/// and raw text never reaches an output without a visible call. `Debug` shows only the length,
/// so `{:?}` of a view or a scan result never prints file content.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct RawText(String);

impl RawText {
    /// Wraps text read from an untrusted source.
    pub fn new(text: impl Into<String>) -> Self {
        Self(text.into())
    }

    /// The raw content. Check it (`RootPath`, `classify`) before using it as a path, and
    /// sanitize it before showing it.
    pub fn as_raw_str(&self) -> &str {
        &self.0
    }

    /// Length in bytes (UTF-8).
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// `true` for the empty string.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for RawText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RawText({} bytes)", self.0.len())
    }
}

#[cfg(test)]
mod tests {
    use super::RawText;

    #[test]
    fn debug_shows_only_the_length() {
        let t = RawText::new("secret \u{1b}[31m name");
        assert_eq!(format!("{t:?}"), "RawText(17 bytes)");
        assert_eq!(format!("{:?}", Some(&t)), "Some(RawText(17 bytes))");
        assert_eq!(format!("{t:#?}"), "RawText(17 bytes)");
        assert_eq!(t.as_raw_str(), "secret \u{1b}[31m name");
        assert_eq!(t.len(), 17);
        assert!(!t.is_empty());
        assert!(RawText::new("").is_empty());
    }
}
