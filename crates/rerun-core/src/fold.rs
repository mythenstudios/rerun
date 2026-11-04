//! Name folding for case-insensitive comparisons, the way Windows does it.
//!
//! NTFS compares character by character via the upcase table (`$UpCase`), so always 1:1.
//! Therefore a character is only replaced if `to_uppercase` yields exactly **one** character:
//! `ß` stays `ß` (not `SS`), `ﬁ` stays `ﬁ`. Otherwise `Straße` and `STRASSE` would collapse,
//! which are two different files on NTFS. Remaining deviations from the NTFS table are
//! uncovered by the contract tests against `sys::win`.

/// Folds a name (file, directory, key, value) for comparisons.
pub(crate) fn fold(s: &str) -> String {
    s.chars()
        .map(|c| {
            let mut up = c.to_uppercase();
            match (up.next(), up.next()) {
                (Some(u), None) => u,
                _ => c,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::fold;

    #[test]
    fn folds_one_to_one_only() {
        assert_eq!(fold("d3d9.dll"), "D3D9.DLL");
        assert_eq!(fold("Über"), "ÜBER");
        assert_eq!(fold("Straße"), "STRAßE");
        assert_ne!(fold("Straße"), fold("STRASSE"));
        assert_eq!(fold("ﬁle"), "ﬁLE");
    }
}
