//! The signed index and the typed catalogue (ADR 0024, ADR 0005).
//!
//! One bundle `index.json` holds every released Topo and package; `index.json.sig` is its
//! detached Ed25519 signature (64 raw bytes). Order, nothing skipped:
//!
//! 1. [`verify`]: at most [`MAX_INDEX_BYTES`], a signature of exactly 64 bytes, valid for the
//!    raw bytes under one of the trusted keys ([`key::trusted_keys`]). Nothing is parsed before.
//! 2. [`Catalog::from_verified`]: the bytes as UTF-8 JSON into [`Index`] (`deny_unknown_fields`
//!    at every level, `RelPath`, hashes), then the form rules ([`check`], [`Rules::Release`]:
//!    no draft, no `TODO`), Topos and packages sorted by ID without duplicates, every package a
//!    Topo or package names present.
//! 3. [`store`]: the rollback rule against the last accepted `seq` under
//!    `<AppDir>\index`, and the bytes kept by hash so a later revert can find the index a
//!    transaction was applied with (P4 condition R1).
//!
//! A [`Catalog`] exists only from a [`Verified`], and a [`Verified`] only from [`verify`].

pub mod check;
pub mod key;
pub mod model;
pub mod store;

use std::collections::BTreeMap;

use sha2::{Digest, Sha256};

pub use check::{RuleError, Rules};
pub use key::{KeyId, PublicKey, trusted_keys};
pub use model::{FORMAT, Index, Package, Topo};

/// Most bytes of `index.json` (8 MiB).
pub const MAX_INDEX_BYTES: usize = 8 << 20;
/// The length of `index.json.sig`: one raw Ed25519 signature.
pub const SIG_BYTES: usize = 64;
/// The format of the index.
pub const INDEX_FORMAT: u32 = FORMAT;

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
    /// Another `format`.
    #[error("index format {0} is not supported (this build reads format 1)")]
    Format(u32),
    /// A broken rule of an entry or of the bundle.
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

/// The released Topos and packages of one verified index, by ID.
#[derive(Debug, Clone)]
pub struct Catalog {
    index: Index,
    key: KeyId,
    sha256: [u8; 32],
    topos: BTreeMap<String, usize>,
    packages: BTreeMap<String, usize>,
}

/// The `format` field alone, read before the rest.
#[derive(serde::Deserialize)]
struct FormatOnly {
    format: u32,
}

fn parse_error(e: &serde_json::Error) -> IndexError {
    use serde_json::error::Category;
    IndexError::Parse {
        class: match e.classify() {
            Category::Io => "io",
            Category::Syntax => "syntax",
            Category::Data => "data",
            Category::Eof => "eof",
        },
        line: e.line(),
        column: e.column(),
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
    /// Parses and checks verified bytes (module docs, step 2).
    pub fn from_verified(v: &Verified<'_>) -> Result<Self, IndexError> {
        let f: FormatOnly = serde_json::from_slice(v.bytes).map_err(|e| parse_error(&e))?;
        if f.format != INDEX_FORMAT {
            return Err(IndexError::Format(f.format));
        }
        let index: Index = serde_json::from_slice(v.bytes).map_err(|e| parse_error(&e))?;
        let (topos, packages) = check_index(&index)?;
        Ok(Self {
            index,
            key: v.key,
            sha256: v.sha256,
            topos,
            packages,
        })
    }

    /// The index.
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

    /// Every Topo, sorted by ID.
    pub fn topos(&self) -> &[Topo] {
        &self.index.topos
    }

    /// Every package, sorted by ID.
    pub fn packages(&self) -> &[Package] {
        &self.index.packages
    }

    /// The Topo `id`.
    pub fn topo(&self, id: &str) -> Option<&Topo> {
        self.topos.get(id).map(|i| &self.index.topos[*i])
    }

    /// The package `id`.
    pub fn package(&self, id: &str) -> Option<&Package> {
        self.packages.get(id).map(|i| &self.index.packages[*i])
    }
}

type Lookup = BTreeMap<String, usize>;

/// The bundle rules (module docs, step 2) on a parsed index. Also run by the workbench on
/// what it builds.
pub fn check_index(index: &Index) -> Result<(Lookup, Lookup), IndexError> {
    let rule = |what: String| IndexError::Rule(what);
    if index.format != INDEX_FORMAT {
        return Err(IndexError::Format(index.format));
    }
    if index.seq == 0 {
        return Err(rule("seq starts at 1".into()));
    }
    if !issued_ok(&index.issued) {
        return Err(rule("issued is not YYYY-MM-DDTHH:MM:SSZ".into()));
    }
    let sorted = |ids: Vec<&str>, what: &str| {
        if ids.windows(2).all(|w| w[0] < w[1]) {
            Ok(())
        } else {
            Err(rule(format!(
                "{what} are not sorted by ID without duplicates"
            )))
        }
    };
    sorted(index.topos.iter().map(|t| t.id.as_str()).collect(), "topos")?;
    sorted(
        index.packages.iter().map(|p| p.id.as_str()).collect(),
        "packages",
    )?;
    for t in &index.topos {
        check::topo(t, Rules::Release).map_err(|e| rule(format!("topo {}: {e}", t.id)))?;
    }
    for p in &index.packages {
        check::package(p, Rules::Release).map_err(|e| rule(format!("package {}: {e}", p.id)))?;
    }
    // P4-4 review follow-up 4: two Topos that are not retired never claim the same build (the
    // same app and an executable hash in common), so the engine finds at most one.
    let live: Vec<&Topo> = index
        .topos
        .iter()
        .filter(|t| t.status != model::Status::Retired)
        .collect();
    for (i, a) in live.iter().enumerate() {
        if let Some(b) = live[..i].iter().find(|b| check::overlap(a, b)) {
            return Err(rule(format!(
                "topos {} and {} claim the same app and executable hash",
                b.id, a.id
            )));
        }
    }
    let packages: Lookup = index
        .packages
        .iter()
        .enumerate()
        .map(|(i, p)| (p.id.as_str().to_owned(), i))
        .collect();
    for t in &index.topos {
        if let Some(id) = check::package_refs(t).find(|id| !packages.contains_key(id.as_str())) {
            return Err(rule(format!(
                "topo {}: package {id} is not in the index",
                t.id
            )));
        }
    }
    for p in &index.packages {
        if let Some(id) = p
            .requires
            .iter()
            .find(|id| !packages.contains_key(id.as_str()))
        {
            return Err(rule(format!(
                "package {}: requires {id}, which is not in the index",
                p.id
            )));
        }
    }
    let topos = index
        .topos
        .iter()
        .enumerate()
        .map(|(i, t)| (t.id.as_str().to_owned(), i))
        .collect();
    Ok((topos, packages))
}

#[cfg(test)]
mod tests;
