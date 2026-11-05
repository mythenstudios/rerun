use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use super::{VdfReadError, read_bounded, read_store_file};
use crate::detect::vdf::{Document, Limits, LineCol, VdfErrorKind};
use crate::path::RelPath;
use crate::policy::root::{ForbiddenRoots, StoreDir};
use crate::sys::fake::{FakeSystem, FakeSystemBuilder};
use crate::sys::fs::{DirEntry, Metadata, ReadSeek, RootInfo, tag};
use crate::sys::{Dir, SysError, SysErrorKind, SysResult};

const INSTALL: &str = r"C:\Users\Player\AppData\Local\Programs\Rerun";
const STORE: &str = r"D:\SteamLibrary";
const FILE: &str = r"steamapps\libraryfolders.vdf";
const DOC: &[u8] =
    b"\"libraryfolders\"\n{\n\t\"0\"\n\t{\n\t\t\"path\"\t\t\"D:\\\\SteamLibrary\"\n\t}\n}\n";

fn base() -> FakeSystemBuilder {
    FakeSystem::builder()
        .windows_layout()
        .dir(INSTALL)
        .dir(STORE)
}

fn rel(s: &str) -> RelPath {
    RelPath::parse(s).unwrap()
}

fn store_file(path: &str) -> String {
    format!(r"{STORE}\{path}")
}

fn read_with(sys: &FakeSystem, file: &str, limits: &Limits) -> Result<Document, VdfReadError> {
    let fr = ForbiddenRoots::resolve(sys, Path::new(INSTALL)).unwrap();
    let store = StoreDir::open(sys, &fr, Path::new(STORE)).unwrap();
    read_store_file(&store, &rel(file), limits)
}

fn read(sys: &FakeSystem) -> Result<Document, VdfReadError> {
    read_with(sys, FILE, &Limits::LIBRARY_FOLDERS)
}

fn read_kind(r: Result<Document, VdfReadError>) -> SysErrorKind {
    match r {
        Err(VdfReadError::Read { file, source }) => {
            assert_eq!(file, rel(FILE));
            source.kind
        }
        other => panic!("expected Read, got {other:?}"),
    }
}

/// `"k" "v"` padded with spaces to exactly `len` bytes.
fn padded(len: usize) -> Vec<u8> {
    let mut v = b"\"k\" \"v\"".to_vec();
    v.resize(len, b' ');
    v
}

#[test]
fn a_store_file_is_read_and_parsed() {
    let sys = base().file(store_file(FILE), DOC).build().unwrap();
    let doc = read(&sys).unwrap();
    let lf = doc.root().get_unique("libraryfolders").unwrap().unwrap();
    assert_eq!(lf.offset, 0);
}

#[test]
fn bom_and_crlf_on_disk_are_accepted() {
    let sys = base()
        .file(
            store_file(FILE),
            b"\xEF\xBB\xBF\"libraryfolders\"\r\n{\r\n}\r\n".to_vec(),
        )
        .build()
        .unwrap();
    assert_eq!(read(&sys).unwrap().root().len(), 1);
}

#[test]
fn a_file_at_the_limit_is_read_and_one_byte_more_is_too_large() {
    for limits in [Limits::LIBRARY_FOLDERS, Limits::APP_MANIFEST] {
        let at = base()
            .file(store_file(FILE), padded(limits.max_bytes))
            .build()
            .unwrap();
        assert_eq!(read_with(&at, FILE, &limits).unwrap().root().len(), 1);

        let over = base()
            .file(store_file(FILE), padded(limits.max_bytes + 1))
            .build()
            .unwrap();
        // Refused by the bounded read before the parser sees a byte.
        assert_eq!(
            read_kind(read_with(&over, FILE, &limits)),
            SysErrorKind::TooLarge
        );
    }
    let tiny = Limits {
        max_bytes: 7,
        ..Limits::APP_MANIFEST
    };
    let sys = base().file(store_file(FILE), padded(7)).build().unwrap();
    assert!(read_with(&sys, FILE, &tiny).is_ok());
    let sys = base().file(store_file(FILE), padded(8)).build().unwrap();
    let e = read_with(&sys, FILE, &tiny).unwrap_err();
    assert_eq!(
        e.to_string(),
        r"steamapps\libraryfolders.vdf: too large: steamapps\libraryfolders.vdf, more than 7 bytes"
    );
    assert_eq!(read_kind(Err(e)), SysErrorKind::TooLarge);
}

#[test]
fn a_missing_file_is_not_found() {
    let sys = base().dir(store_file("steamapps")).build().unwrap();
    assert_eq!(read_kind(read(&sys)), SysErrorKind::NotFound);
    let sys = base().build().unwrap();
    assert_eq!(read_kind(read(&sys)), SysErrorKind::NotFound);
}

#[test]
fn a_directory_is_refused() {
    let sys = base().dir(store_file(FILE)).build().unwrap();
    assert_eq!(read_kind(read(&sys)), SysErrorKind::AccessDenied);
}

#[test]
fn a_file_symlink_is_never_followed() {
    let sys = base()
        .file(r"D:\Elsewhere\libraryfolders.vdf", DOC)
        .file_symlink(store_file(FILE), r"D:\Elsewhere\libraryfolders.vdf")
        .build()
        .unwrap();
    assert_eq!(read_kind(read(&sys)), SysErrorKind::ReparsePoint);
}

#[test]
fn a_junction_at_steamapps_is_never_followed() {
    let sys = base()
        .file(r"D:\Elsewhere\libraryfolders.vdf", DOC)
        .junction(store_file("steamapps"), r"D:\Elsewhere")
        .build()
        .unwrap();
    assert_eq!(read_kind(read(&sys)), SysErrorKind::ReparsePoint);
}

#[test]
fn a_file_with_a_rejected_reparse_tag_is_refused() {
    let sys = base()
        .tagged_file(store_file(FILE), DOC, tag::APPEXECLINK)
        .build()
        .unwrap();
    assert_eq!(read_kind(read(&sys)), SysErrorKind::ReparsePoint);
    // An allowed data tag (WOF) reads like a plain file.
    let sys = base()
        .tagged_file(store_file(FILE), DOC, tag::WOF)
        .build()
        .unwrap();
    assert!(read(&sys).is_ok());
}

#[test]
fn a_restricted_file_or_folder_is_refused() {
    let sys = base()
        .file(store_file(FILE), DOC)
        .restricted(store_file(FILE))
        .build()
        .unwrap();
    assert_eq!(read_kind(read(&sys)), SysErrorKind::AccessDenied);
    let sys = base()
        .file(store_file(FILE), DOC)
        .restricted(store_file("steamapps"))
        .build()
        .unwrap();
    assert_eq!(read_kind(read(&sys)), SysErrorKind::AccessDenied);
}

#[test]
fn the_file_is_read_through_the_store_handle_not_its_path() {
    // The store is renamed after it was opened and a forged store takes its place: the
    // read still sees the original file.
    let sys = base().file(store_file(FILE), DOC).build().unwrap();
    let fr = ForbiddenRoots::resolve(&sys, Path::new(INSTALL)).unwrap();
    let store = StoreDir::open(&sys, &fr, Path::new(STORE)).unwrap();
    sys.rename_abs(STORE, r"D:\Moved").unwrap();
    sys.fake_fs()
        .put_file(Path::new(&store_file(FILE)), b"\"forged\" \"x\"")
        .unwrap();
    let doc = read_store_file(&store, &rel(FILE), &Limits::LIBRARY_FOLDERS).unwrap();
    assert!(doc.root().get_unique("libraryfolders").unwrap().is_some());
}

#[test]
fn parse_errors_name_the_file_and_position_but_not_the_content() {
    let sys = base()
        .file(
            store_file(FILE),
            b"\"libraryfolders\"\r\n{\r\n\t\"0\" SECRETMARKER\r\n}\r\n".to_vec(),
        )
        .build()
        .unwrap();
    let e = read(&sys).unwrap_err();
    match &e {
        VdfReadError::Parse { file, error, at } => {
            assert_eq!(file, &rel(FILE));
            assert_eq!(error.kind, VdfErrorKind::UnquotedToken);
            assert_eq!(*at, LineCol { line: 3, column: 6 });
        }
        other => panic!("expected Parse, got {other:?}"),
    }
    let shown = format!("{e} / {e:?}");
    assert_eq!(
        e.to_string(),
        r"steamapps\libraryfolders.vdf: unquoted token at byte 26 (line 3, column 6)"
    );
    assert!(!shown.contains("SECRET"), "{shown}");
}

// ---------- The bound itself, with handles that are not a file system ----------

/// A handle whose only file never ends and counts what was read. `read` (unbounded) panics.
#[derive(Debug, Default)]
struct EndlessDir {
    served: Arc<AtomicU64>,
    fail_after: Option<u64>,
}

struct Endless {
    served: Arc<AtomicU64>,
    fail_after: Option<u64>,
}

impl Read for Endless {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let so_far = self.served.load(Ordering::SeqCst);
        if self.fail_after.is_some_and(|n| so_far >= n) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "SECRETMARKER from the device",
            ));
        }
        // Valid VDF forever: `"k" "v"` pairs.
        let pattern = b"\"k\" \"v\" ";
        for (i, b) in buf.iter_mut().enumerate() {
            let at = usize::try_from(so_far).unwrap() + i;
            *b = pattern[at % pattern.len()];
        }
        self.served
            .fetch_add(u64::try_from(buf.len()).unwrap(), Ordering::SeqCst);
        Ok(buf.len())
    }
}

impl Seek for Endless {
    fn seek(&mut self, _: SeekFrom) -> io::Result<u64> {
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }
}

fn unsupported<T>() -> SysResult<T> {
    Err(SysError::new(SysErrorKind::Unsupported, "endless"))
}

impl Dir for EndlessDir {
    fn info(&self) -> SysResult<RootInfo> {
        unsupported()
    }
    fn open_dir(&self, _: &RelPath) -> SysResult<Box<dyn Dir + '_>> {
        unsupported()
    }
    fn metadata(&self, _: &RelPath) -> SysResult<Option<Metadata>> {
        panic!("the reader must not ask for metadata (the length is never trusted)")
    }
    fn open_read(&self, _: &RelPath) -> SysResult<Box<dyn ReadSeek + '_>> {
        Ok(Box::new(Endless {
            served: Arc::clone(&self.served),
            fail_after: self.fail_after,
        }))
    }
    fn read(&self, _: &RelPath) -> SysResult<Vec<u8>> {
        panic!("the unbounded Dir::read must never be used")
    }
    fn read_dir_limited(&self, _: Option<&RelPath>, _: usize) -> SysResult<Vec<DirEntry>> {
        unsupported()
    }
    fn users(&self, _: &RelPath) -> SysResult<Vec<u32>> {
        unsupported()
    }
}

#[test]
fn an_endless_file_is_cut_at_the_limit_plus_one() {
    for limits in [Limits::LIBRARY_FOLDERS, Limits::APP_MANIFEST] {
        let dir = EndlessDir::default();
        let r = read_bounded(&dir, &rel(FILE), &limits);
        assert_eq!(read_kind(r), SysErrorKind::TooLarge);
        // `Dir::read_limited` never asks the reader for more than the limit plus one byte.
        let served = dir.served.load(Ordering::SeqCst);
        assert_eq!(served, u64::try_from(limits.max_bytes).unwrap() + 1);
    }
}

#[test]
fn a_read_error_is_reported_without_its_message() {
    let dir = EndlessDir {
        fail_after: Some(10),
        ..EndlessDir::default()
    };
    let e = read_bounded(&dir, &rel(FILE), &Limits::APP_MANIFEST).unwrap_err();
    assert_eq!(
        e,
        VdfReadError::Read {
            file: rel(FILE),
            source: SysError::new(SysErrorKind::Other, FILE),
        }
    );
    assert!(!format!("{e} / {e:?}").contains("SECRET"));
}
