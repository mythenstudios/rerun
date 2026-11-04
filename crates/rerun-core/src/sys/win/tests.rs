//! Smoke test of the read-only `sys::win` file system on the developer's own volume.
//!
//! Everything happens in a fresh directory below the workspace `target/` folder, created and
//! removed with `std::fs` by the test itself (asserted to be inside `target/`). The full
//! contract against real Windows (TOCTOU races, junctions, WOF, 8.3 names) is `sys::contract`
//! in a later step.

#![allow(
    clippy::disallowed_methods,
    reason = "test fixture under target/: std::fs sets up and removes the directory, \
              Fs::open_dir opens it"
)]

use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

use super::WinFs;
use crate::path::RelPath;
use crate::sys::SysErrorKind;
use crate::sys::fs::{EntryKind, Fs};

/// A fresh directory below `<workspace>/target/win-fs-smoke`, removed on drop.
struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        static N: AtomicU32 = AtomicU32::new(0);
        let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
        let target = manifest.join("../../target");
        let base = target.join("win-fs-smoke");
        std::fs::create_dir_all(&base).unwrap();
        let target = std::fs::canonicalize(target).unwrap();
        let base = std::fs::canonicalize(base).unwrap();
        assert!(
            base.starts_with(&target),
            "{} not in {}",
            base.display(),
            target.display()
        );
        let dir = base.join(format!(
            "{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        assert!(dir.starts_with(&target));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).unwrap();
        Self(dir)
    }

    fn path(&self, rel: &str) -> PathBuf {
        self.0.join(rel)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn rel(s: &str) -> RelPath {
    RelPath::parse(s).unwrap()
}

fn kind_of<T>(r: Result<T, crate::sys::SysError>) -> SysErrorKind {
    match r {
        Ok(_) => panic!("expected an error"),
        Err(e) => e.kind,
    }
}

#[test]
fn read_only_walk_metadata_and_identity() {
    let fx = Fixture::new();
    std::fs::write(fx.path("a.txt"), b"hello").unwrap();
    std::fs::hard_link(fx.path("a.txt"), fx.path("link.txt")).unwrap();
    std::fs::create_dir(fx.path("Sub")).unwrap();
    std::fs::write(fx.path(r"Sub\b.bin"), [1u8, 2, 3]).unwrap();

    let fs = WinFs::new();
    let root = fs.open_dir(&fx.0).unwrap();
    let info = root.info().unwrap();
    assert_eq!(info.final_path, fx.0);
    assert!(!info.is_volume_root());
    let shown = info.final_path.to_str().unwrap().replace('/', "\\");
    assert!(
        shown.ends_with(&info.volume_path),
        "{shown} / {}",
        info.volume_path
    );
    assert!(info.volume_first_segment().is_some());
    assert!(info.user_writable, "the test created this directory");
    assert!(!info.case_sensitive);
    assert_ne!(info.file_id, 0);

    // Listing: raw names, kinds, hard link count shared by both names.
    let mut entries = root.read_dir(None).unwrap();
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(names, ["Sub", "a.txt", "link.txt"]);
    assert_eq!(entries[0].meta.kind, EntryKind::Dir);
    assert_eq!(
        (
            entries[1].meta.kind,
            entries[1].meta.len,
            entries[1].meta.links
        ),
        (EntryKind::File, 5, 2)
    );
    assert_eq!(entries[1].meta.file_id, entries[2].meta.file_id);

    // Metadata: case-insensitive, missing and below-a-file are None.
    let sub_meta = root.metadata(&rel("SUB")).unwrap().unwrap();
    assert_eq!(
        (sub_meta.kind, sub_meta.len, sub_meta.links),
        (EntryKind::Dir, 0, 1)
    );
    assert_eq!(root.metadata(&rel("missing")).unwrap(), None);
    assert_eq!(root.metadata(&rel(r"missing\x")).unwrap(), None);
    assert_eq!(root.metadata(&rel(r"a.txt\x")).unwrap(), None);
    assert_eq!(
        root.metadata(&rel(r"sub\B.BIN")).unwrap().map(|m| m.len),
        Some(3)
    );

    // Reads.
    assert_eq!(root.read(&rel("a.txt")).unwrap(), b"hello");
    assert_eq!(root.read(&rel(r"Sub\b.bin")).unwrap(), [1, 2, 3]);
    assert_eq!(
        kind_of(root.open_read(&rel("Sub"))),
        SysErrorKind::AccessDenied
    );
    assert_eq!(
        kind_of(root.open_read(&rel("nope"))),
        SysErrorKind::NotFound
    );

    // Relative opens and handle identity.
    let sub = root.open_dir(&rel("sub")).unwrap();
    let sub_info = sub.info().unwrap();
    assert_eq!(sub_info.file_id, sub_meta.file_id);
    assert_eq!(sub_info.volume_serial, info.volume_serial);
    assert_eq!(
        sub_info.final_path,
        fx.path("Sub"),
        "stored case is reported"
    );
    let sub_entries = sub.read_dir(None).unwrap();
    assert_eq!(sub_entries.len(), 1);
    assert_eq!(sub_entries[0].name, "b.bin");
    assert_eq!(root.read_dir(Some(&rel("Sub"))).unwrap(), sub_entries);
    assert_eq!(
        kind_of(root.open_dir(&rel("a.txt"))),
        SysErrorKind::InvalidPath
    );
    assert_eq!(
        kind_of(root.open_dir(&rel("missing"))),
        SysErrorKind::NotFound
    );
    assert_eq!(
        kind_of(root.open_dir(&rel(r"a.txt\x"))),
        SysErrorKind::InvalidPath
    );

    // Writes are refused in phase 1.
    let p = rel("new.txt");
    for r in [
        root.create_new(&p, b"x"),
        root.replace(&rel("a.txt"), b"x", "tmp"),
        root.create_dir(&p),
        root.remove_file(&rel("a.txt")),
        root.remove_dir(&rel("Sub")),
        root.rename(&rel("a.txt"), &p),
        root.set_readonly(&rel("a.txt"), true),
    ] {
        assert_eq!(kind_of(r), SysErrorKind::Unsupported);
    }
    assert_eq!(root.read(&rel("a.txt")).unwrap(), b"hello");
}

#[test]
fn absolute_open_input_rules() {
    let fx = Fixture::new();
    std::fs::write(fx.path("f"), b"").unwrap();
    let fs = WinFs::new();
    let s = fx.0.to_str().unwrap().to_owned();
    let plain = s.strip_prefix(r"\\?\").unwrap_or(&s).to_owned();
    // Plain drive path and forward slashes reach the same directory.
    let id = fs.open_dir(&fx.0).unwrap().info().unwrap().file_id;
    assert_eq!(
        fs.open_dir(Path::new(&plain))
            .unwrap()
            .info()
            .unwrap()
            .file_id,
        id
    );
    assert_eq!(
        fs.open_dir(Path::new(&plain.replace('\\', "/")))
            .unwrap()
            .info()
            .unwrap()
            .file_id,
        id
    );
    assert_eq!(
        kind_of(fs.open_dir(&fx.path("f"))),
        SysErrorKind::InvalidPath
    );
    assert_eq!(
        kind_of(fs.open_dir(&fx.path("missing"))),
        SysErrorKind::NotFound
    );
    assert_eq!(
        kind_of(fs.open_dir(&fx.path(r"missing\deeper"))),
        SysErrorKind::NotFound
    );
    for bad in [
        "relative".to_owned(),
        format!(r"{plain}\.."),
        format!(r"{plain}\.\x"),
        format!(r"{plain}\a?b"),
        r"\\localhost\c$".to_owned(),
    ] {
        assert_eq!(
            kind_of(fs.open_dir(Path::new(&bad))),
            SysErrorKind::InvalidPath,
            "{bad}"
        );
    }
}

#[test]
fn concurrent_writer_is_busy_and_rename_keeps_the_handle() {
    let fx = Fixture::new();
    std::fs::write(fx.path("w.log"), b"x").unwrap();
    std::fs::create_dir(fx.path("d")).unwrap();
    let fs = WinFs::new();
    let root = fs.open_dir(&fx.0).unwrap();

    // D10: open_read shares read only.
    let writer = std::fs::OpenOptions::new()
        .append(true)
        .open(fx.path("w.log"))
        .unwrap();
    assert_eq!(kind_of(root.open_read(&rel("w.log"))), SysErrorKind::Busy);
    // Attribute-only opens never conflict.
    assert_eq!(
        root.metadata(&rel("w.log")).unwrap().map(|m| m.len),
        Some(1)
    );
    drop(writer);
    let mut s = String::new();
    root.open_read(&rel("w.log"))
        .unwrap()
        .read_to_string(&mut s)
        .unwrap();
    assert_eq!(s, "x");

    // A Dir handle shares delete: its directory can be renamed and the handle follows.
    let d = root.open_dir(&rel("d")).unwrap();
    std::fs::rename(fx.path("d"), fx.path("e")).unwrap();
    assert_eq!(d.info().unwrap().final_path, fx.path("e"));

    // ... and deleted: the handle then reports NotFound.
    std::fs::remove_dir(fx.path("e")).unwrap();
    assert_eq!(kind_of(d.info()), SysErrorKind::NotFound);
    assert_eq!(kind_of(d.metadata(&rel("x"))), SysErrorKind::NotFound);
    assert_eq!(kind_of(d.read_dir(None)), SysErrorKind::NotFound);
}

/// Needs the symlink privilege or developer mode; skipped (with a note) otherwise.
#[test]
fn symlinks_are_never_followed_below_a_root() {
    let fx = Fixture::new();
    std::fs::create_dir(fx.path("real")).unwrap();
    std::fs::write(fx.path(r"real\x"), b"x").unwrap();
    if let Err(e) = std::os::windows::fs::symlink_dir("real", fx.path("link")) {
        eprintln!("skipped: cannot create a directory symlink ({e})");
        return;
    }
    let fs = WinFs::new();
    let root = fs.open_dir(&fx.0).unwrap();
    let m = root.metadata(&rel("link")).unwrap().unwrap();
    assert_eq!(m.kind, EntryKind::Reparse);
    let r = m.reparse.unwrap();
    assert_eq!(
        (r.tag, r.surrogate, r.target.as_deref()),
        (crate::sys::fs::tag::SYMLINK, true, Some("real"))
    );
    assert_eq!(
        kind_of(root.open_dir(&rel("link"))),
        SysErrorKind::ReparsePoint
    );
    assert_eq!(
        kind_of(root.open_read(&rel(r"link\x"))),
        SysErrorKind::ReparsePoint
    );
    assert_eq!(
        kind_of(root.metadata(&rel(r"link\x"))),
        SysErrorKind::ReparsePoint
    );
    let listed: Vec<_> = root
        .read_dir(None)
        .unwrap()
        .into_iter()
        .map(|e| (e.name, e.meta.kind))
        .collect();
    assert!(listed.contains(&("link".to_owned(), EntryKind::Reparse)));
    // Fs::open_dir follows it (above the root).
    let via = WinFs::new()
        .open_dir(&fx.path("link"))
        .unwrap()
        .info()
        .unwrap();
    assert_eq!(via.final_path, fx.path("real"));
}
