//! The contract sources of the build ID (ADR 0023 §2, A4 S9), shared by `build.rs` (which
//! computes the hash) and the test in `lib.rs` (which recomputes it from the sources).
//!
//! The contract between the CLI and the helper is what both derive from a request: the
//! request codec and the exit code (`src/elevate/`) and the firewall rule form
//! (`src/policy/firewall.rs` and `src/policy/firewall/`, from P4-5a). A local build's ID is
//! `dev-<SHA-256 over these files>`, so a CLI and a helper copied by hand from builds with
//! different contract sources refuse each other (`Refused(Build)`, P4-2c), while unrelated
//! changes keep them compatible.
//!
//! Test files are not part of the contract ([`is_test_file`]: `tests.rs`, `*_tests.rs`, anything
//! below a `tests` folder): they define nothing either binary derives, and a test-only change
//! must not make a hand-copied helper refuse the CLI.
//!
//! The hash: for every regular file below the contract paths, sorted by its `/`-separated path
//! relative to `src/`: the path's bytes, a NUL, the content's length as `u64` little-endian,
//! the content without a leading UTF-8 BOM and with every `\r` removed (a checkout with CRLF or
//! an editor's BOM gives the same ID). Missing paths contribute nothing; a link or any other
//! reparse point, or an entry that is neither a file nor a folder, fails the build.

use std::path::{Path, PathBuf};

/// The contract paths, relative to `src/` (a directory, or a file).
pub const CONTRACT_PATHS: &[&str] = &["elevate", "policy/firewall.rs", "policy/firewall"];

/// Whether `rel` (`/`-separated, relative to `src/`) is a test file, not contract.
pub fn is_test_file(rel: &str) -> bool {
    let mut segments = rel.split('/').rev();
    let name = segments.next().unwrap_or_default();
    name == "tests.rs" || name.ends_with("_tests.rs") || segments.any(|s| s == "tests")
}

/// Every regular file below `p` (or `p` itself), recursively. A link (or, on Windows, any
/// reparse point) or an entry that is neither a file nor a folder is an error: it is never
/// followed and never silently skipped.
fn files(p: &Path, out: &mut Vec<PathBuf>) -> Result<(), String> {
    #[expect(
        clippy::disallowed_methods,
        reason = "build ID: the crate's own sources, read at build time and in a test (A4 S9)"
    )]
    let meta = match std::fs::symlink_metadata(p) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(format!("{}: {e}", p.display())),
    };
    #[cfg(windows)]
    let reparse = {
        use std::os::windows::fs::MetadataExt;
        // FILE_ATTRIBUTE_REPARSE_POINT (winnt.h): symlinks, junctions and every other tag.
        meta.file_attributes() & 0x400 != 0
    };
    #[cfg(not(windows))]
    let reparse = false;
    if reparse || meta.file_type().is_symlink() {
        return Err(format!(
            "{}: a link in the contract sources of the build ID",
            p.display()
        ));
    }
    if meta.is_file() {
        out.push(p.to_path_buf());
    } else if !meta.is_dir() {
        return Err(format!(
            "{}: neither a file nor a folder in the contract sources",
            p.display()
        ));
    } else {
        #[expect(
            clippy::disallowed_methods,
            reason = "build ID: the crate's own sources, read at build time and in a test (A4 S9)"
        )]
        let entries = std::fs::read_dir(p).map_err(|e| format!("{}: {e}", p.display()))?;
        for e in entries {
            let e = e.map_err(|e| format!("{}: {e}", p.display()))?;
            files(&e.path(), out)?;
        }
    }
    Ok(())
}

/// Feeds the contract files below `src` to `update` (the caller's SHA-256) in the order of
/// the module docs. Returns the files hashed, relative to `src`, for the test's message.
pub fn feed_contract(src: &Path, update: &mut dyn FnMut(&[u8])) -> Result<Vec<String>, String> {
    let mut all = Vec::new();
    for p in CONTRACT_PATHS {
        files(&src.join(p), &mut all)?;
    }
    let named: Vec<(String, PathBuf)> = all
        .into_iter()
        .map(|f| {
            let rel = f
                .strip_prefix(src)
                .map_err(|e| format!("{}: {e}", f.display()))?
                .to_string_lossy()
                .replace('\\', "/");
            Ok((rel, f))
        })
        .filter(|r| r.as_ref().map_or(true, |(rel, _)| !is_test_file(rel)))
        .collect::<Result<_, String>>()?;
    let mut read = Vec::with_capacity(named.len());
    for (rel, f) in named {
        #[expect(
            clippy::disallowed_methods,
            reason = "build ID: the crate's own sources, read at build time and in a test (A4 S9)"
        )]
        let bytes = std::fs::read(&f).map_err(|e| format!("{}: {e}", f.display()))?;
        read.push((rel, bytes));
    }
    Ok(feed(read, update))
}

/// Feeds `(relative path, content)` pairs to `update` as the module docs say (sorted by path,
/// a leading UTF-8 BOM and every `\r` removed). Pure. Returns the paths in order.
pub fn feed(mut files: Vec<(String, Vec<u8>)>, update: &mut dyn FnMut(&[u8])) -> Vec<String> {
    files.sort();
    for (rel, bytes) in &files {
        let text = bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(bytes);
        let content: Vec<u8> = text.iter().copied().filter(|b| *b != b'\r').collect();
        update(rel.as_bytes());
        update(&[0]);
        update(&(content.len() as u64).to_le_bytes());
        update(&content);
    }
    files.into_iter().map(|(rel, _)| rel).collect()
}

/// `RERUN_BUILD_ID` as the release build sets it (the commit): 7 to 64 characters of ASCII
/// letters, digits, `.` and `-`.
pub fn valid_release_id(id: &str) -> bool {
    (7..=64).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
}
