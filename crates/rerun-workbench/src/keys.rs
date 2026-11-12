//! The index key (ADR 0024): `key generate` and `index sign`.
//!
//! The private key is an Ed25519 seed, written as 64 lower-case hex digits and a newline to
//! `rerun-index.key`; the public key the same way to `rerun-index.pub`. Neither file is ever
//! written into a Git working tree, this repository or a OneDrive folder ([`outside_repo`]), and
//! `index sign` reads a private key only from outside those. The private key file gets an
//! owner-only protected DACL before the key is written (`acl`). The public key goes into
//! `RELEASE_KEYS` of `rerun_core::catalog::key` by hand (the printed line).

use std::path::{Path, PathBuf};

use ed25519_compact::{KeyPair, Seed};
use rerun_core::catalog::key::PublicKey;
use rerun_core::catalog::model::Index;
use rerun_core::catalog::verify;
use sha2::{Digest, Sha256};

/// The private key file.
pub const KEY_FILE: &str = "rerun-index.key";
/// The public key file.
pub const PUB_FILE: &str = "rerun-index.pub";

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex32(s: &str) -> Option<[u8; 32]> {
    let b = s.as_bytes();
    if b.len() != 64 {
        return None;
    }
    let digit = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    };
    let mut out = [0u8; 32];
    for (i, o) in out.iter_mut().enumerate() {
        *o = digit(b[2 * i])? << 4 | digit(b[2 * i + 1])?;
    }
    Some(out)
}

/// The repository this tool was built from.
fn this_repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..")
}

/// Refuses `dir` (an existing folder) when it is this repository or below it, or below any Git
/// working tree (a folder with a `.git` entry on the way up): a private key must never be
/// one `git add` away from a commit. Also refuses a OneDrive folder (synced is not offline).
pub fn outside_repo(dir: &Path) -> Result<PathBuf, String> {
    let canon = dir
        .canonicalize()
        .map_err(|e| format!("{}: {e}", dir.display()))?;
    if let Ok(repo) = this_repo().canonicalize()
        && canon.starts_with(&repo)
    {
        return Err(format!(
            "{} is inside the Rerun repository: a private key never goes there",
            dir.display()
        ));
    }
    if let Some(top) = canon.ancestors().find(|a| a.join(".git").exists()) {
        return Err(format!(
            "{} is inside the Git working tree {}: a private key never goes there",
            dir.display(),
            top.display()
        ));
    }
    if let Some(root) = synced_root(&canon, &onedrive_roots()) {
        return Err(format!(
            "{} is inside the OneDrive folder {root}: a synced folder is not offline storage",
            dir.display()
        ));
    }
    Ok(canon)
}

/// The OneDrive folders of this user (`OneDrive`, `OneDriveConsumer`, `OneDriveCommercial`).
fn onedrive_roots() -> Vec<String> {
    ["OneDrive", "OneDriveConsumer", "OneDriveCommercial"]
        .iter()
        .filter_map(std::env::var_os)
        .filter_map(|v| v.into_string().ok())
        .filter(|v| !v.trim().is_empty())
        .collect()
}

/// `path` without a `\\?\` prefix, `\` separated, lower case, no trailing separator.
fn plain(path: &str) -> String {
    let p = path.strip_prefix(r"\\?\").unwrap_or(path);
    p.replace('/', "\\").trim_end_matches('\\').to_lowercase()
}

/// The first of `roots` that `canon` is or lies below (case-insensitive, by whole segments).
fn synced_root(canon: &Path, roots: &[String]) -> Option<String> {
    let p = plain(&canon.to_string_lossy());
    roots
        .iter()
        .find(|r| {
            let r = plain(r);
            !r.is_empty() && (p == r || p.starts_with(&format!("{r}\\")))
        })
        .cloned()
}

/// A new key pair from 32 bytes of the OS random number generator.
pub fn generate() -> Result<KeyPair, String> {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).map_err(|e| format!("no random numbers: {e}"))?;
    Ok(KeyPair::from_seed(Seed::new(seed)))
}

/// The text of the private key file.
pub fn key_text(kp: &KeyPair) -> String {
    format!("{}\n", hex(kp.sk.seed().as_ref()))
}

/// The text of the public key file.
pub fn pub_text(kp: &KeyPair) -> String {
    format!("{}\n", hex(kp.pk.as_ref()))
}

/// The line for `RELEASE_KEYS`.
pub fn release_line(pk: &PublicKey) -> String {
    let bytes: Vec<String> = pk.bytes().iter().map(|b| format!("0x{b:02x}")).collect();
    format!("Some([{}])", bytes.join(", "))
}

/// Reads a private key file's text.
pub fn parse_key(text: &str) -> Result<KeyPair, String> {
    let seed = unhex32(text.trim_end_matches(['\r', '\n']))
        .ok_or("not a private key file (64 lower-case hex digits)")?;
    Ok(KeyPair::from_seed(Seed::new(seed)))
}

/// What `sign` signed.
#[derive(Debug)]
pub struct Signed {
    /// The signature (the bytes of `index.json.sig`).
    pub sig: [u8; 64],
    /// The bundle's `seq`.
    pub seq: u64,
    /// SHA-256 of the bundle, hex.
    pub sha256: String,
    /// The public key.
    pub key: PublicKey,
}

/// Signs `bundle` after checking it is a valid release index (nothing else is ever signed),
/// then verifies the signature like the client.
pub fn sign(bundle: &[u8], kp: &KeyPair) -> Result<Signed, String> {
    crate::bundle::refuse_aside(bundle)?;
    let index: Index = serde_json::from_slice(bundle).map_err(|e| format!("not an index: {e}"))?;
    let sig = *kp.sk.sign(bundle, None);
    let key = PublicKey::new(*kp.pk);
    verify(bundle, &sig, &[key]).map_err(|e| format!("own signature does not verify: {e}"))?;
    Ok(Signed {
        sig,
        seq: index.seq,
        sha256: hex(&Sha256::digest(bundle)),
        key,
    })
}

/// [`sign`] with the published test key (feature `test-key`, ADR 0024 amendment P4-13): the
/// same release rules, then the signature verified again under the test key alone.
#[cfg(feature = "test-key")]
pub fn sign_test(bundle: &[u8]) -> Result<Signed, String> {
    use rerun_core::catalog::key::test_key;
    let s = sign(bundle, &parse_key(test_key::SEED_HEX)?)?;
    verify(bundle, &s.sig, &[test_key::public()])
        .map_err(|e| format!("the test key's signature does not verify: {e}"))?;
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::{generate, key_text, outside_repo, parse_key, pub_text, release_line, sign};
    use rerun_core::catalog::key::PublicKey;

    #[test]
    fn the_repository_and_git_trees_are_refused_a_temp_folder_is_not() {
        let repo = super::this_repo();
        assert!(outside_repo(&repo).is_err());
        assert!(outside_repo(&repo.join("crates")).is_err());
        assert!(outside_repo(&std::env::temp_dir()).is_ok());
        assert!(outside_repo(&repo.join("no-such-folder")).is_err());
    }

    #[test]
    fn onedrive_folders_are_refused() {
        use super::synced_root;
        use std::path::Path;
        let roots = vec![
            r"C:\Users\P\OneDrive".to_owned(),
            r"D:\Sync\OneDrive - Firm\".to_owned(),
        ];
        let hit = |p: &str| synced_root(Path::new(p), &roots).is_some();
        assert!(hit(r"\\?\C:\Users\P\OneDrive"));
        assert!(hit(r"\\?\c:\users\p\onedrive\Keys"));
        assert!(hit(r"D:\Sync\OneDrive - Firm\x"));
        assert!(!hit(r"C:\Users\P\OneDriveOld\Keys"), "by whole segments");
        assert!(!hit(r"C:\Users\P\Keys"));
        assert!(synced_root(Path::new(r"C:\x"), &[String::new()]).is_none());
    }

    #[test]
    fn key_files_read_back() {
        let kp = generate().unwrap();
        let back = parse_key(&key_text(&kp)).unwrap();
        assert_eq!(*back.pk, *kp.pk);
        assert_eq!(pub_text(&kp).trim_end().len(), 64);
        assert!(parse_key("00").is_err());
        assert!(parse_key(&"A".repeat(64)).is_err(), "upper case");
        let line = release_line(&PublicKey::new([0xab; 32]));
        assert!(line.starts_with("Some([0xab, 0xab"));
        assert_ne!(*generate().unwrap().pk, *kp.pk, "two keys differ");
    }

    #[test]
    fn only_a_valid_index_is_signed() {
        let kp = generate().unwrap();
        assert!(sign(b"{}", &kp).is_err());
        let bundle =
            br#"{"format":1,"seq":1,"issued":"2026-11-09T00:00:00Z","topos":[],"packages":[]}"#;
        let s = sign(bundle, &kp).unwrap();
        assert_eq!(s.seq, 1);
        rerun_core::catalog::verify(bundle, &s.sig, &[s.key]).unwrap();
        let draft =
            br#"{"format":1,"seq":0,"issued":"2026-11-09T00:00:00Z","topos":[],"packages":[]}"#;
        assert!(sign(draft, &kp).is_err(), "seq 0");
    }

    /// FX10 (ADR 0024 amendment "Forward compatibility" §6): `index sign` refuses a bundle with
    /// any entry the client would set aside, whatever the reason.
    #[test]
    fn a_bundle_with_set_aside_entries_is_not_signed() {
        let kp = generate().unwrap();
        for (what, entry) in [
            (
                "newer",
                r#"{"format":2,"id":"future-game","match":{"steam_appid":7}}"#,
            ),
            ("unreadable", r#"{"format":1,"id":"broken-game"}"#),
        ] {
            let bundle = format!(
                r#"{{"format":1,"seq":1,"issued":"2026-11-12T00:00:00Z","topos":[{entry}],"packages":[]}}"#
            );
            let e = sign(bundle.as_bytes(), &kp).unwrap_err();
            assert!(
                e.contains("the client would set aside 1 entry"),
                "{what}: {e}"
            );
        }
    }

    /// One Topo in an index, with `status`.
    #[cfg(feature = "test-key")]
    fn with_topo(status: &str) -> Vec<u8> {
        // An invented hash.
        let sha = "AB".repeat(32);
        format!(
            r#"{{"format":1,"seq":7,"issued":"2026-11-11T00:00:00Z","topos":[{{"format":1,"id":"invented-game","title":"Invented Game","status":"{status}","rev":1,"match":{{"steam_appid":220,"exes":[{{"path":"game.exe","sha256":"{sha}","api":"d3d9"}}]}},"issues":[]}}],"packages":[]}}"#
        )
        .into_bytes()
    }

    /// ADR 0024 amendment P4-13: `index sign-test` signs only what `index sign` signs, and the
    /// signature is the published test key's (a test-key build trusts it, a release build not).
    #[cfg(feature = "test-key")]
    #[test]
    fn sign_test_uses_the_test_key_and_the_release_rules() {
        use rerun_core::catalog::key::test_key;
        let bundle = with_topo("active");
        let s = super::sign_test(&bundle).unwrap();
        assert_eq!(s.seq, 7);
        assert_eq!(s.key, test_key::public());
        assert_eq!(s.sig, test_key::sign(&bundle));
        rerun_core::catalog::verify(&bundle, &s.sig, &[test_key::public()]).unwrap();
        assert!(
            rerun_core::catalog::verify(&bundle, &s.sig, &[test_key::foreign_public()]).is_err()
        );
        // The release rules: a draft, a `TODO` and a malformed index are refused.
        let e = super::sign_test(&with_topo("draft")).unwrap_err();
        assert!(e.contains("draft"), "{e}");
        let todo = String::from_utf8(bundle.clone())
            .unwrap()
            .replace("Invented Game", "TODO");
        assert!(super::sign_test(todo.as_bytes()).is_err());
        assert!(super::sign_test(b"{}").is_err());
        // An entry the client would set aside (FX10): a newer entry format.
        let newer = String::from_utf8(bundle).unwrap().replacen(
            r#""topos":[{"format":1"#,
            r#""topos":[{"format":2"#,
            1,
        );
        let e = super::sign_test(newer.as_bytes()).unwrap_err();
        assert!(e.contains("needs a newer version of Rerun"), "{e}");
    }
}
