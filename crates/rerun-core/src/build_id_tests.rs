//! The build ID (ADR 0023 §2, A4 S9).

use std::path::Path;

use sha2::{Digest, Sha256};

use crate::build_contract::{feed, feed_contract, is_test_file, valid_release_id};
use crate::{BUILD_ID, VERSION};

/// A dev build's ID is the SHA-256 the build script computed over exactly the contract
/// sources as they are now; a release build's ID is a valid commit form.
#[test]
fn the_build_id_names_this_build() {
    let suffix = BUILD_ID
        .strip_prefix(VERSION)
        .and_then(|s| s.strip_prefix('+'))
        .unwrap_or_else(|| panic!("{BUILD_ID}"));
    let Some(hex) = suffix.strip_prefix("dev-") else {
        assert!(valid_release_id(suffix), "{BUILD_ID}");
        return;
    };
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut h = Sha256::new();
    let files = feed_contract(&src, &mut |b| h.update(b)).unwrap();
    let now: String = h.finalize().iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(
        hex, now,
        "the build script hashed other sources than {files:?}"
    );
    assert!(
        files.iter().any(|f| f == "elevate/exit.rs")
            && files.iter().all(|f| !f.contains('\\') && !is_test_file(f)),
        "{files:?}"
    );
}

/// The hash covers path and content, ignores `\r` and the order of the listing, and an empty
/// contract hashes to the empty input.
#[test]
fn the_contract_hash_has_teeth() {
    let hash = |files: &[(&str, &[u8])]| {
        let owned = files
            .iter()
            .map(|(p, c)| ((*p).to_owned(), c.to_vec()))
            .collect();
        let mut h = Sha256::new();
        let order = feed(owned, &mut |b| h.update(b));
        (h.finalize().to_vec(), order)
    };
    let (base, order) = hash(&[("elevate/mod.rs", b"a\nb\n"), ("elevate/exit.rs", b"c")]);
    assert_eq!(order, ["elevate/exit.rs", "elevate/mod.rs"]);
    // Listing order, CRLF and a leading BOM do not matter; a BOM elsewhere does.
    assert_eq!(
        hash(&[("elevate/exit.rs", b"c"), ("elevate/mod.rs", b"a\r\nb\r\n")]).0,
        base
    );
    assert_eq!(
        hash(&[
            ("elevate/mod.rs", b"\xEF\xBB\xBFa\nb\n"),
            ("elevate/exit.rs", b"c")
        ])
        .0,
        base
    );
    assert_ne!(
        hash(&[
            ("elevate/mod.rs", b"a\n\xEF\xBB\xBFb\n"),
            ("elevate/exit.rs", b"c")
        ])
        .0,
        base
    );
    // Content, a path, a moved boundary between two files, an added file do.
    for other in [
        hash(&[("elevate/mod.rs", b"a\nb\n"), ("elevate/exit.rs", b"d")]),
        hash(&[("elevate/mod.rs", b"a\nb\n"), ("elevate/exits.rs", b"c")]),
        hash(&[("elevate/mod.rs", b"a\nb\nc"), ("elevate/exit.rs", b"")]),
        hash(&[
            ("elevate/mod.rs", b"a\nb\n"),
            ("elevate/exit.rs", b"c"),
            ("policy/firewall.rs", b""),
        ]),
    ] {
        assert_ne!(other.0, base);
    }
    assert_eq!(hash(&[]).0, Sha256::digest(b"").to_vec());
}

#[test]
fn release_ids_are_checked() {
    for ok in ["3056472", "3056472a1b2c", "0.1.0-rc.1", &"a".repeat(64)] {
        assert!(valid_release_id(ok), "{ok}");
    }
    for bad in [
        "",
        "305647",
        "a b c d e",
        "3056472\n",
        "30564/2",
        "3056472+x",
        &"a".repeat(65),
    ] {
        assert!(!valid_release_id(bad), "{bad:?}");
    }
}

/// Test files are not contract (ADR 0023 §2): a test-only change keeps the build ID.
#[test]
fn test_files_are_not_contract() {
    for t in [
        "elevate/tests.rs",
        "elevate/exit_tests.rs",
        "policy/firewall/tests/rule.rs",
    ] {
        assert!(is_test_file(t), "{t}");
    }
    for c in [
        "elevate/mod.rs",
        "elevate/exit.rs",
        "policy/firewall.rs",
        "elevate/testsuite.rs",
    ] {
        assert!(!is_test_file(c), "{c}");
    }
}
