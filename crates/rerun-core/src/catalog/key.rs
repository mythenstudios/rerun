//! The public keys the signed index is checked against (ADR 0024).
//!
//! Two slots are compiled in ([`RELEASE_KEYS`]): the current key and the next one, so a key
//! can be rotated by shipping a binary that already trusts its successor. Both slots are empty
//! until the release key is generated offline (`rerun-workbench key generate`); a build without
//! a key refuses every index ([`super::IndexError::NoKeys`]).
//!
//! The test key ([`test_key`], feature `test-key`) is published: its seed is in this file. It
//! is trusted only with the feature, which only dev-dependencies enable; CI checks that no
//! shipped crate enables it, and a test checks that no release slot holds it.

use sha2::{Digest, Sha256};

/// The release key slots: `[current, next]` as raw Ed25519 public keys (32 bytes each).
/// `None` is an empty slot.
pub const RELEASE_KEYS: [Option<[u8; 32]>; 2] = [None, None];

/// An Ed25519 public key the index may be signed with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicKey([u8; 32]);

impl PublicKey {
    /// The key from its 32 raw bytes.
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The raw bytes.
    pub fn bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Its [`KeyId`].
    pub fn id(&self) -> KeyId {
        let h: [u8; 32] = Sha256::digest(self.0).into();
        let mut id = [0u8; 8];
        id.copy_from_slice(&h[..8]);
        KeyId(id)
    }

    /// Whether `sig` is a valid Ed25519 signature of `msg` by this key. A key that is not a
    /// valid curve point verifies nothing.
    pub(crate) fn verifies(&self, msg: &[u8], sig: &[u8; 64]) -> bool {
        let pk = ed25519_compact::PublicKey::new(self.0);
        let sig = ed25519_compact::Signature::new(*sig);
        pk.verify(msg, &sig).is_ok()
    }
}

/// The first 8 bytes of SHA-256 over a public key: names a key in messages and records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KeyId(pub [u8; 8]);

impl std::fmt::Display for KeyId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

/// The keys of [`RELEASE_KEYS`] that are set.
pub fn release_keys() -> Vec<PublicKey> {
    RELEASE_KEYS
        .iter()
        .flatten()
        .map(|k| PublicKey(*k))
        .collect()
}

/// The keys this build trusts: the release keys, and with the feature `test-key` the test key.
pub fn trusted_keys() -> Vec<PublicKey> {
    #[allow(unused_mut, reason = "only the feature test-key adds a key")]
    let mut keys = release_keys();
    #[cfg(feature = "test-key")]
    keys.push(test_key::public());
    keys
}

/// The published test key (feature `test-key`, and this crate's own tests). Never trusted by a
/// release build.
#[cfg(any(test, feature = "test-key"))]
pub mod test_key {
    use super::PublicKey;

    /// The seed of the test key as 64 lower-case hex digits: SHA-256 of
    /// `rerun index test key 1 (published; never trusted by a release build)`.
    pub const SEED_HEX: &str = "2fa4131b313b655ec5bd06b18938c03c2f4ba202dc389abb381dd867100aba05";

    /// The seed of a second key that no build trusts (a foreign signer in tests): SHA-256 of
    /// `rerun index foreign test key (trusted by nothing)`.
    pub const FOREIGN_SEED_HEX: &str =
        "a7f280b1192bb0dffac987cd5f37e6281e84fb7382bf1e01a554a6f837c4b2e0";

    fn pair(seed_hex: &str) -> ed25519_compact::KeyPair {
        match crate::wire::hex32::from_str(seed_hex) {
            Some(seed) => ed25519_compact::KeyPair::from_seed(ed25519_compact::Seed::new(seed)),
            None => unreachable!("the test seeds are 64 lower-case hex digits"),
        }
    }

    /// The test key's public key.
    pub fn public() -> PublicKey {
        PublicKey(*pair(SEED_HEX).pk)
    }

    /// The foreign key's public key.
    pub fn foreign_public() -> PublicKey {
        PublicKey(*pair(FOREIGN_SEED_HEX).pk)
    }

    /// Signs `msg` with the test key (deterministic).
    pub fn sign(msg: &[u8]) -> [u8; 64] {
        *pair(SEED_HEX).sk.sign(msg, None)
    }

    /// Signs `msg` with the foreign key.
    pub fn sign_foreign(msg: &[u8]) -> [u8; 64] {
        *pair(FOREIGN_SEED_HEX).sk.sign(msg, None)
    }
}

#[cfg(test)]
mod tests {
    use super::{RELEASE_KEYS, release_keys, test_key, trusted_keys};

    /// ADR 0024: no release slot ever holds a published test key, and without the feature the
    /// trusted set is exactly the release set.
    #[test]
    fn release_key_set_has_no_test_key() {
        for k in [test_key::public(), test_key::foreign_public()] {
            assert!(
                !RELEASE_KEYS.iter().flatten().any(|r| r == k.bytes()),
                "a release slot holds a test key"
            );
        }
        let trusted = trusted_keys();
        if cfg!(feature = "test-key") {
            assert!(trusted.contains(&test_key::public()));
        } else {
            assert_eq!(trusted, release_keys());
        }
        assert!(!trusted.contains(&test_key::foreign_public()));
    }

    #[test]
    fn key_id_is_the_first_8_bytes_of_sha256() {
        let k = test_key::public();
        let id = k.id().to_string();
        assert_eq!(id.len(), 16);
        let full = crate::wire::hex32::to_string(&{
            use sha2::Digest;
            sha2::Sha256::digest(k.bytes()).into()
        });
        assert!(full.starts_with(&id));
    }
}
