//! The signed index and the typed catalogue (ADR 0024, ADR 0005).
//!
//! One bundle `index.json` holds every released Topo and package; `index.json.sig` is its
//! detached Ed25519 signature (64 raw bytes). Order, nothing skipped:
//!
//! 1. [`verify`]: at most [`MAX_INDEX_BYTES`], a signature of exactly 64 bytes, valid for the
//!    raw bytes under one of the trusted keys ([`key::trusted_keys`]). Nothing is parsed before.
//! 2. [`Catalog::from_verified`]: the envelope strict (`format` alone first, then
//!    `deny_unknown_fields`), each entry's frozen head lenient (IDs sorted and unique over all
//!    heads), then each entry known or set aside ([`Aside`], ADR 0024 amendment "Forward
//!    compatibility"): a newer entry format, a known format that does not parse into the strict
//!    types (`deny_unknown_fields` at every level, `RelPath`, hashes), one that breaks a rule of
//!    [`check`] with [`Rules::Release`] (no draft, no `TODO`, the floor), or the cross-entry rules
//!    (a missing or set-aside package, two Topos claiming one build). Only known entries are
//!    ever returned by [`Catalog::topo`] and the like.
//! 3. [`store`]: the rollback rule against the last accepted `seq` under
//!    `<AppDir>\index`, and the bytes kept by hash so a later revert can find the index a
//!    transaction was applied with (P4 condition R1).
//!
//! A [`Catalog`] exists only from a [`Verified`], and a [`Verified`] only from [`verify`].

pub mod check;
mod entries;
pub mod key;
pub mod model;
pub mod store;

use std::collections::BTreeMap;

use sha2::{Digest, Sha256};

pub use check::{RuleError, Rules};
pub use entries::{Aside, AsideWhy, EntryKind, check_bundle};
pub use key::{KeyId, PublicKey, trusted_keys};
pub use model::{ENTRY_FORMAT, Index, Package, Topo};

/// Most bytes of `index.json` (8 MiB).
pub const MAX_INDEX_BYTES: usize = 8 << 20;
/// The length of `index.json.sig`: one raw Ed25519 signature.
pub const SIG_BYTES: usize = 64;
/// The format of the envelope (the index's top-level `format`): strict, never extended
/// additively; another value refuses the whole index (ADR 0024 amendment "Forward
/// compatibility" §1). The entries' own counter is [`ENTRY_FORMAT`].
pub const INDEX_FORMAT: u32 = 1;

/// Why an index is refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IndexError {
    /// This build trusts no key yet (both release slots empty).
    #[error("this build of Rerun trusts no index key yet: every index is refused")]
    NoKeys,
    /// More than [`MAX_INDEX_BYTES`].
    #[error("the index is larger than {limit} bytes")]
    TooLarge {
        /// The limit.
        limit: usize,
    },
    /// The signature is not 64 bytes, or no trusted key made it for these bytes.
    #[error("the signature does not match the index (wrong, damaged or from an unknown key)")]
    Signature,
    /// The signature is valid, but by a key on `key::REVOKED_KEYS` (compromised).
    #[error("the index is signed with the revoked key {0}: refused")]
    Revoked(KeyId),
    /// Not UTF-8 JSON of the index form (position only, never the text).
    #[error("the signed index is not a valid index ({class} at line {line}, column {column})")]
    Parse {
        /// `syntax`, `data` (a field of the wrong form), `eof`.
        class: &'static str,
        /// 1-based line.
        line: usize,
        /// 1-based column.
        column: usize,
    },
    /// Another envelope `format`.
    #[error(
        "this index needs a newer version of Rerun (index format {0}; this build reads format {INDEX_FORMAT})"
    )]
    Format(u32),
    /// An entry whose frozen head (`format`, `id`, a Topo's `match.steam_appid`) does not parse:
    /// the whole index is refused (position only, never the text).
    #[error(
        "entry {pos} of {list} in the signed index has no valid head ({class} at line {line}, column {column} of the entry)"
    )]
    Head {
        /// `topos` or `packages`.
        list: &'static str,
        /// 0-based position in the list.
        pos: usize,
        /// `syntax`, `data`, `eof`.
        class: &'static str,
        /// 1-based line within the entry.
        line: usize,
        /// 1-based column.
        column: usize,
    },
    /// A broken rule of the envelope (`seq`, `issued`, IDs sorted and unique over the heads).
    #[error("the signed index breaks a rule: {0}")]
    Rule(String),
}

/// Bytes whose signature checked out: the only input of [`Catalog::from_verified`].
#[derive(Debug, Clone, Copy)]
pub struct Verified<'a> {
    bytes: &'a [u8],
    key: KeyId,
    sha256: [u8; 32],
}

impl<'a> Verified<'a> {
    /// The signed bytes.
    pub fn bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// The key that signed them.
    pub fn key(&self) -> KeyId {
        self.key
    }

    /// SHA-256 of the bytes.
    pub fn sha256(&self) -> &[u8; 32] {
        &self.sha256
    }
}

/// Checks the size and the signature of `index` (module docs, step 1). `keys` empty is
/// [`IndexError::NoKeys`]; a signature by a key on `key::REVOKED_KEYS` is
/// [`IndexError::Revoked`], whatever `keys` holds.
pub fn verify<'a>(
    index: &'a [u8],
    sig: &[u8],
    keys: &[PublicKey],
) -> Result<Verified<'a>, IndexError> {
    verify_with(index, sig, keys, key::REVOKED_KEYS)
}

/// [`verify`] against an explicit revocation list (tests).
pub(crate) fn verify_with<'a>(
    index: &'a [u8],
    sig: &[u8],
    keys: &[PublicKey],
    revoked: &[[u8; 32]],
) -> Result<Verified<'a>, IndexError> {
    if keys.is_empty() {
        return Err(IndexError::NoKeys);
    }
    if index.len() > MAX_INDEX_BYTES {
        return Err(IndexError::TooLarge {
            limit: MAX_INDEX_BYTES,
        });
    }
    let sig: &[u8; SIG_BYTES] = sig.try_into().map_err(|_| IndexError::Signature)?;
    let key = keys
        .iter()
        .find(|k| k.verifies(index, sig))
        .ok_or(IndexError::Signature)?;
    if revoked.contains(key.bytes()) {
        return Err(IndexError::Revoked(key.id()));
    }
    Ok(Verified {
        bytes: index,
        key: key.id(),
        sha256: Sha256::digest(index).into(),
    })
}

/// The known Topos and packages of one verified index, by ID, and the entries set aside (ADR
/// 0024 amendment "Forward compatibility").
#[derive(Debug, Clone)]
pub struct Catalog {
    index: Index,
    aside: Vec<Aside>,
    key: KeyId,
    sha256: [u8; 32],
    topos: BTreeMap<String, usize>,
    packages: BTreeMap<String, usize>,
}

/// The class of a JSON error (position only, never the text).
pub(crate) fn parse_class(e: &serde_json::Error) -> &'static str {
    use serde_json::error::Category;
    match e.classify() {
        Category::Io => "io",
        Category::Syntax => "syntax",
        Category::Data => "data",
        Category::Eof => "eof",
    }
}

/// `YYYY-MM-DDTHH:MM:SSZ` with plausible ranges (no calendar check beyond them).
pub fn issued_ok(s: &str) -> bool {
    let b = s.as_bytes();
    let num = |r: std::ops::Range<usize>, lo: u32, hi: u32| {
        b.get(r.clone())
            .is_some_and(|d| d.iter().all(u8::is_ascii_digit))
            && s.get(r)
                .and_then(|d| d.parse::<u32>().ok())
                .is_some_and(|n| (lo..=hi).contains(&n))
    };
    b.len() == 20
        && b[4] == b'-'
        && b[7] == b'-'
        && b[10] == b'T'
        && b[13] == b':'
        && b[16] == b':'
        && b[19] == b'Z'
        && num(0..4, 2000, 9999)
        && num(5..7, 1, 12)
        && num(8..10, 1, 31)
        && num(11..13, 0, 23)
        && num(14..16, 0, 59)
        && num(17..19, 0, 59)
}

impl Catalog {
    /// Parses and classifies verified bytes (module docs, step 2): the envelope strict, each
    /// entry known or set aside.
    pub fn from_verified(v: &Verified<'_>) -> Result<Self, IndexError> {
        let entries::Classified { index, aside } = entries::classify(v.bytes)?;
        let topos = index
            .topos
            .iter()
            .enumerate()
            .map(|(i, t)| (t.id.as_str().to_owned(), i))
            .collect();
        let packages = index
            .packages
            .iter()
            .enumerate()
            .map(|(i, p)| (p.id.as_str().to_owned(), i))
            .collect();
        Ok(Self {
            index,
            aside,
            key: v.key,
            sha256: v.sha256,
            topos,
            packages,
        })
    }

    /// The index with its known entries only.
    pub fn index(&self) -> &Index {
        &self.index
    }

    /// Its sequence number.
    pub fn seq(&self) -> u64 {
        self.index.seq
    }

    /// When it was built.
    pub fn issued(&self) -> &str {
        &self.index.issued
    }

    /// The key that signed it.
    pub fn key(&self) -> KeyId {
        self.key
    }

    /// SHA-256 of its bytes (the name it is kept under).
    pub fn sha256(&self) -> &[u8; 32] {
        &self.sha256
    }

    /// Every known Topo, sorted by ID.
    pub fn topos(&self) -> &[Topo] {
        &self.index.topos
    }

    /// Every known package, sorted by ID.
    pub fn packages(&self) -> &[Package] {
        &self.index.packages
    }

    /// The known Topo `id` (never a set-aside one).
    pub fn topo(&self, id: &str) -> Option<&Topo> {
        self.topos.get(id).map(|i| &self.index.topos[*i])
    }

    /// The known package `id` (never a set-aside one).
    pub fn package(&self, id: &str) -> Option<&Package> {
        self.packages.get(id).map(|i| &self.index.packages[*i])
    }

    /// The entries set aside, sorted by kind, then ID (display only).
    pub fn aside(&self) -> &[Aside] {
        &self.aside
    }

    /// The set-aside Topos of a Steam app (from their heads).
    pub fn aside_for(&self, app_id: u32) -> impl Iterator<Item = &Aside> + '_ {
        self.aside
            .iter()
            .filter(move |a| a.kind == EntryKind::Topo && a.steam_appid == Some(app_id))
    }

    /// The set-aside entry `id` of a list.
    pub fn aside_entry(&self, kind: EntryKind, id: &str) -> Option<&Aside> {
        self.aside
            .iter()
            .find(|a| a.kind == kind && a.id.as_str() == id)
    }
}

#[cfg(test)]
mod tests;
