//! The release byte check of the index test key (ADR 0024; ADR 0023 §2, audit A4 S3), included
//! with `#[path]` by `crates/rerun-cli/tests/hardening.rs` and
//! `crates/rerun-helper/tests/hardening.rs`. Needs `rerun-core` with the feature `test-key`
//! (a dev-dependency of both crates).

/// Whether `image` holds the published test key of the signed index (ADR 0024): its seed as
/// hex text or its public key bytes.
pub fn holds_test_key(image: &[u8]) -> bool {
    use rerun_core::catalog::key::test_key;
    let seed = test_key::SEED_HEX.as_bytes();
    let public = test_key::public();
    let found = |needle: &[u8]| image.windows(needle.len()).any(|w| w == needle);
    found(seed) || found(public.bytes())
}
