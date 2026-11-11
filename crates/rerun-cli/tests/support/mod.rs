//! Shared by the tests that run the built `rerun.exe`: the banner of a test-key build (ADR 0024
//! amendment P4-13). With `--all-features` (CI) the binary is built with the feature `test-key`
//! and writes the banner as the first stderr line of every command.

/// A copy of `messages::TEST_KEY_BANNER` (bound by `tests::the_banner_copies_agree` of the crate).
pub const BANNER: &str = "rerun: TEST-KEY BUILD - trusts the published index test key; index state in index-test; never for real use";

/// Stderr of the built binary without the banner line, which a test-key build must write first
/// and any other build must not write at all.
pub fn without_banner(stderr: &[u8]) -> String {
    let text = String::from_utf8_lossy(stderr).into_owned();
    let line = format!("{BANNER}\n");
    if cfg!(feature = "test-key") {
        match text.strip_prefix(&line) {
            Some(rest) => rest.to_owned(),
            None => panic!("a test-key build writes the banner first:\n{text}"),
        }
    } else {
        assert!(!text.contains("TEST-KEY"), "{text}");
        text
    }
}
