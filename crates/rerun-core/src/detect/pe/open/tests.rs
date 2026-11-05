//! `open_game_exe` against `sys::fake`, and the bound with handles that are not a file system
//! (ADR 0013, "Layers"). Every image and string is synthetic.

use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use super::{GameExe, PeReadError, open_bounded, open_game_exe};
use crate::detect::pe::testfx::{Builder, STRINGS, string_table, version_info};
use crate::detect::pe::{LegacyFormat, Limits, Machine, PeErrorKind};
use crate::detect::text::RawText;
use crate::path::RelPath;
use crate::policy::root::{ForbiddenRoots, GameDir};
use crate::sys::fake::{FakeSystem, FakeSystemBuilder};
use crate::sys::fs::{DirEntry, Metadata, ReadSeek, RootInfo, tag};
use crate::sys::{Dir, SysError, SysErrorKind, SysResult, shown_target};

const INSTALL: &str = r"C:\Users\Player\AppData\Local\Programs\Rerun";
const GAME: &str = r"D:\Games\Invented Game";
const EXE: &str = r"bin\game.exe";

fn base() -> FakeSystemBuilder {
    FakeSystem::builder()
        .windows_layout()
        .dir(INSTALL)
        .dir(GAME)
}

fn rel(s: &str) -> RelPath {
    RelPath::parse(s).unwrap()
}

fn game_file(path: &str) -> String {
    format!(r"{GAME}\{path}")
}

/// An x86 executable importing `d3d9.dll` with the usual version strings.
fn image() -> Vec<u8> {
    let mut b = Builder::x86().with_version(
        version_info(
            vec![string_table("040904b0", STRINGS)],
            Some((0x0409, 0x04B0)),
        )
        .encode(),
    );
    b.imports = Some(vec![b"KERNEL32.dll".to_vec(), b"d3d9.dll".to_vec()]);
    b.build().bytes
}

fn game(sys: &FakeSystem) -> GameDir<'_> {
    let fr = ForbiddenRoots::resolve(sys, Path::new(INSTALL)).unwrap();
    GameDir::open_manual(sys, &fr, Path::new(GAME)).unwrap()
}

fn open_kind(r: Result<GameExe<'_>, PeReadError>) -> SysErrorKind {
    match r {
        Err(PeReadError::Open { file, source }) => {
            assert_eq!(file, rel(EXE));
            source.kind
        }
        Err(other) => panic!("expected Open, got {other:?}"),
        Ok(_) => panic!("expected Open, got a parsed image"),
    }
}

fn exe_kind(sys: &FakeSystem) -> SysErrorKind {
    open_kind(open_game_exe(&game(sys), &rel(EXE), &Limits::DEFAULT))
}

#[test]
fn an_executable_is_opened_and_parsed_through_the_game_handle() {
    let sys = base().file(game_file(EXE), image()).build().unwrap();
    let game = game(&sys);
    let mut pe = open_game_exe(&game, &rel(EXE), &Limits::DEFAULT).unwrap();
    assert_eq!(pe.headers().machine, Machine::X86);
    let info = pe.info().unwrap();
    let names: Vec<&str> = info.imports.iter().map(|n| n.as_str()).collect();
    assert_eq!(names, ["KERNEL32.dll", "d3d9.dll"]);
    let version = info.version.unwrap().unwrap();
    assert_eq!(
        version
            .strings
            .file_description
            .as_ref()
            .map(RawText::as_raw_str),
        Some("Invented Game")
    );
    assert!(pe.bytes_read() <= Limits::DEFAULT.max_read_bytes);
}

#[test]
fn the_reader_is_handed_back_for_hashing() {
    let bytes = image();
    let sys = base().file(game_file(EXE), bytes.clone()).build().unwrap();
    let game = game(&sys);
    let pe = open_game_exe(&game, &rel(EXE), &Limits::DEFAULT).unwrap();
    let mut file = pe.into_inner();
    file.seek(SeekFrom::Start(0)).unwrap();
    let mut all = Vec::new();
    file.read_to_end(&mut all).unwrap();
    assert_eq!(all, bytes);
}

#[test]
fn the_file_is_read_through_the_game_handle_not_its_path() {
    // The game folder is renamed after it was opened and a forged one takes its place: the
    // read still sees the original executable.
    let sys = base().file(game_file(EXE), image()).build().unwrap();
    let game = game(&sys);
    sys.rename_abs(GAME, r"D:\Games\Moved").unwrap();
    sys.fake_fs()
        .put_file(Path::new(&game_file(EXE)), b"not an executable")
        .unwrap();
    let pe = open_game_exe(&game, &rel(EXE), &Limits::DEFAULT).unwrap();
    assert_eq!(pe.headers().machine, Machine::X86);
}

#[test]
fn a_missing_file_is_not_found() {
    let sys = base().dir(game_file("bin")).build().unwrap();
    assert_eq!(exe_kind(&sys), SysErrorKind::NotFound);
    let sys = base().build().unwrap();
    assert_eq!(exe_kind(&sys), SysErrorKind::NotFound);
}

#[test]
fn open_errors_name_the_file_once() {
    let sys = base().dir(game_file("bin")).build().unwrap();
    let Err(e) = open_game_exe(&game(&sys), &rel(EXE), &Limits::DEFAULT) else {
        panic!("expected an error");
    };
    let PeReadError::Open { source, .. } = &e else {
        panic!("expected Open, got {e:?}");
    };
    assert_eq!(e.to_string(), source.to_string());
    assert_eq!(e.to_string().matches("game.exe").count(), 1, "{e}");
}

#[test]
fn a_valid_rel_path_is_shown_as_it_is() {
    // `PeReadError::Parse` shows the `RelPath` unescaped: `RelPath` and `shown_target` must
    // refuse the same characters, so a valid path never needs escaping.
    for p in [
        EXE,
        r"Größe\Spiel.exe",
        r"日本語\ゲーム.exe",
        r"Game (1998)\bin\GAME.EXE",
        r"a b\c-d_e+f,g;h=i[j]k{l}m'n!o@p#q$r%s^t&u.exe",
    ] {
        let p = rel(p);
        assert_eq!(shown_target(p.to_string()), p.to_string(), "{p}");
    }
    // What `shown_target` would escape is no valid `RelPath`: bidi override, newline,
    // zero-width space, full-width solidus, division slash.
    for bad in ['\u{202E}', '\n', '\u{200B}', '\u{FF0F}', '\u{2215}'] {
        let raw = format!(r"bin\a{bad}b.exe");
        assert_ne!(shown_target(raw.clone()), raw);
        assert!(RelPath::parse(&raw).is_err(), "{raw:?}");
    }
}

#[test]
fn a_directory_is_refused() {
    let sys = base().dir(game_file(EXE)).build().unwrap();
    assert_eq!(exe_kind(&sys), SysErrorKind::AccessDenied);
}

#[test]
fn a_file_symlink_is_never_followed() {
    let sys = base()
        .file(r"D:\Elsewhere\game.exe", image())
        .file_symlink(game_file(EXE), r"D:\Elsewhere\game.exe")
        .build()
        .unwrap();
    assert_eq!(exe_kind(&sys), SysErrorKind::ReparsePoint);
}

#[test]
fn a_junction_on_the_way_is_never_followed() {
    let sys = base()
        .file(r"D:\Elsewhere\game.exe", image())
        .junction(game_file("bin"), r"D:\Elsewhere")
        .build()
        .unwrap();
    assert_eq!(exe_kind(&sys), SysErrorKind::ReparsePoint);
}

#[test]
fn a_file_with_a_rejected_reparse_tag_is_refused_and_wof_is_read() {
    for rejected in [tag::APPEXECLINK, tag::PROJFS] {
        let sys = base()
            .tagged_file(game_file(EXE), image(), rejected)
            .build()
            .unwrap();
        assert_eq!(exe_kind(&sys), SysErrorKind::ReparsePoint);
    }
    // An allowed data tag (WOF, e.g. CompactGUI) reads like a plain file.
    let sys = base()
        .tagged_file(game_file(EXE), image(), tag::WOF)
        .build()
        .unwrap();
    let game = game(&sys);
    let mut pe = open_game_exe(&game, &rel(EXE), &Limits::DEFAULT).unwrap();
    assert_eq!(pe.imports().unwrap().len(), 2);
}

#[test]
fn a_restricted_file_or_folder_is_refused() {
    let sys = base()
        .file(game_file(EXE), image())
        .restricted(game_file(EXE))
        .build()
        .unwrap();
    assert_eq!(exe_kind(&sys), SysErrorKind::AccessDenied);
    let sys = base()
        .file(game_file(EXE), image())
        .restricted(game_file("bin"))
        .build()
        .unwrap();
    assert_eq!(exe_kind(&sys), SysErrorKind::AccessDenied);
}

#[test]
fn parse_errors_name_the_file_and_the_offset_but_not_the_content() {
    let sys = base()
        .file(game_file(EXE), b"SECRETMARKER, not an executable".to_vec())
        .build()
        .unwrap();
    let game = game(&sys);
    let Err(e) = open_game_exe(&game, &rel(EXE), &Limits::DEFAULT) else {
        panic!("expected an error");
    };
    match &e {
        PeReadError::Parse { file, error } => {
            assert_eq!(file, &rel(EXE));
            assert_eq!(error.kind, PeErrorKind::NotExecutable);
        }
        other => panic!("expected Parse, got {other:?}"),
    }
    assert_eq!(
        e.to_string(),
        r"bin\game.exe: not an executable (no MZ signature) at offset 0x0"
    );
    assert!(!format!("{e} / {e:?}").contains("SECRET"));

    let mut dos = b"MZ".to_vec();
    dos.resize(0x40, 0);
    let sys = base().file(game_file(EXE), dos).build().unwrap();
    let game = self::game(&sys);
    assert!(matches!(
        open_game_exe(&game, &rel(EXE), &Limits::DEFAULT),
        Err(PeReadError::Parse { error, .. })
            if error.kind == PeErrorKind::Legacy(LegacyFormat::Dos)
    ));
}

// ---------- The bound itself, with handles that are not a file system ----------

/// A file that never ends: the built image, then zeros forever. It counts the bytes it
/// served; seeking from the end (asking for the length) panics.
struct Endless {
    image: Arc<Vec<u8>>,
    pos: u64,
    served: Arc<AtomicU64>,
    fail: bool,
}

impl Read for Endless {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.fail {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "SECRETMARKER from the device",
            ));
        }
        for (i, b) in buf.iter_mut().enumerate() {
            let at = usize::try_from(self.pos).unwrap() + i;
            *b = self.image.get(at).copied().unwrap_or(0);
        }
        let n = u64::try_from(buf.len()).unwrap();
        self.pos += n;
        self.served.fetch_add(n, Ordering::SeqCst);
        Ok(buf.len())
    }
}

impl Seek for Endless {
    fn seek(&mut self, to: SeekFrom) -> io::Result<u64> {
        match to {
            SeekFrom::Start(p) => self.pos = p,
            SeekFrom::Current(d) => self.pos = self.pos.checked_add_signed(d).unwrap(),
            SeekFrom::End(_) => panic!("the reader must not seek to the end (length)"),
        }
        Ok(self.pos)
    }
}

/// A handle whose only file is [`Endless`]. `metadata` and the unbounded `read` panic.
#[derive(Debug, Default)]
struct EndlessDir {
    image: Arc<Vec<u8>>,
    served: Arc<AtomicU64>,
    fail: bool,
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
            image: Arc::clone(&self.image),
            pos: 0,
            served: Arc::clone(&self.served),
            fail: self.fail,
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
fn an_endless_file_is_read_only_within_the_budget() {
    let dir = EndlessDir {
        image: Arc::new(image()),
        ..EndlessDir::default()
    };
    let mut pe = open_bounded(&dir, &rel(EXE), &Limits::DEFAULT).unwrap();
    // `parse` reads exactly the header region, nothing more.
    let header = u64::try_from(Limits::DEFAULT.max_header_bytes).unwrap();
    assert_eq!(dir.served.load(Ordering::SeqCst), header);
    let info = pe.info().unwrap();
    assert_eq!(info.imports.len(), 2);
    assert!(info.version.unwrap().is_some());
    // Every byte served was charged, and the budget holds.
    let served = dir.served.load(Ordering::SeqCst);
    assert!(served <= pe.bytes_read(), "{served} > {}", pe.bytes_read());
    assert!(pe.bytes_read() <= Limits::DEFAULT.max_read_bytes);
}

#[test]
fn a_small_budget_stops_an_endless_file() {
    let dir = EndlessDir {
        image: Arc::new(image()),
        ..EndlessDir::default()
    };
    let limits = Limits {
        max_read_bytes: u64::try_from(Limits::DEFAULT.max_header_bytes).unwrap() - 1,
        ..Limits::DEFAULT
    };
    assert!(matches!(
        open_bounded(&dir, &rel(EXE), &limits),
        Err(PeReadError::Parse { error, .. }) if error.kind == PeErrorKind::ReadBudget
    ));
    assert_eq!(dir.served.load(Ordering::SeqCst), 0);
}

#[test]
fn a_read_error_keeps_only_its_kind() {
    let dir = EndlessDir {
        fail: true,
        ..EndlessDir::default()
    };
    let Err(e) = open_bounded(&dir, &rel(EXE), &Limits::DEFAULT) else {
        panic!("expected an error");
    };
    assert!(matches!(
        &e,
        PeReadError::Parse { file, error }
            if *file == rel(EXE) && error.kind == PeErrorKind::Io(io::ErrorKind::InvalidData)
    ));
    assert!(!format!("{e} / {e:?}").contains("SECRET"));
}
