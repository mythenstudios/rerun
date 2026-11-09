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
//! The hash: for every regular file below the contract paths, sorted by its `/`-separated path
//! relative to `src/`: the path's bytes, a NUL, the content's length as `u64` little-endian,
//! the content, with every `\r` removed (a checkout with CRLF gives the same ID). Missing paths
//! contribute nothing.

use std::path::{Path, PathBuf};

/// The contract paths, relative to `src/` (a directory, or a file).
pub const CONTRACT_PATHS: &[&str] = &["elevate", "policy/firewall.rs", "policy/firewall"];

/// Every regular file below `p` (or `p` itself), recursively; links are not followed.
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
    if meta.is_file() {
        out.push(p.to_path_buf());
    } else if meta.is_dir() {
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
/// `\r` removed). Pure. Returns the paths in order.
pub fn feed(mut files: Vec<(String, Vec<u8>)>, update: &mut dyn FnMut(&[u8])) -> Vec<String> {
    files.sort();
    for (rel, bytes) in &files {
        let content: Vec<u8> = bytes.iter().copied().filter(|b| *b != b'\r').collect();
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
