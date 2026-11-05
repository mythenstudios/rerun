//! The walk against `sys::fake` (ADR 0014, "Walk"). Every folder and file name is invented;
//! the files are not executables (the walk never reads them).

use std::path::Path;

use super::{SKIP_DIRS, Walk, walk, walk_dir};
use crate::detect::exe::{ExeIssue, ExeIssueKind, ExeLimits, LimitKind};
use crate::path::RelPath;
use crate::policy::root::{ForbiddenRoots, GameDir};
use crate::sys::fake::{FakeSystem, FakeSystemBuilder};
use crate::sys::fs::{DirEntry, EntryKind, Metadata, ReadSeek, RootInfo, tag};
use crate::sys::{Dir, SysError, SysErrorKind, SysResult};

const INSTALL: &str = r"C:\Users\Player\AppData\Local\Programs\Rerun";
const GAME: &str = r"D:\Games\Invented Game";

fn base() -> FakeSystemBuilder {
    FakeSystem::builder()
        .windows_layout()
        .dir(INSTALL)
        .dir(GAME)
}

fn at(path: &str) -> String {
    format!(r"{GAME}\{path}")
}

fn rel(s: &str) -> RelPath {
    RelPath::parse(s).unwrap()
}

fn game(sys: &FakeSystem) -> GameDir<'_> {
    let fr = ForbiddenRoots::resolve(sys, Path::new(INSTALL)).unwrap();
    GameDir::open_manual(sys, &fr, Path::new(GAME)).unwrap()
}

fn run(sys: &FakeSystem) -> Walk {
    walk(&game(sys), &ExeLimits::DEFAULT)
}

fn paths(w: &Walk) -> Vec<&str> {
    w.exes.iter().map(|e| e.path.as_str()).collect()
}

fn issue_at<'w>(w: &'w Walk, p: &str) -> &'w ExeIssueKind {
    let want = (!p.is_empty()).then(|| rel(p));
    &w.issues
        .iter()
        .find(|i| i.at == want)
        .unwrap_or_else(|| panic!("no issue at {p:?}: {:?}", w.issues))
        .kind
}

const MZ: &[u8] = b"MZ";

#[test]
fn executables_at_every_level_in_breadth_first_sorted_order() {
    let sys = base()
        .file(at("Zeta.exe"), MZ)
        .file(at("alpha.EXE"), b"MZ--")
        .file(at(r"Binaries\Win64\Game-Win64-Shipping.exe"), MZ)
        .file(at(r"bin\x64\tool.exe"), MZ)
        .file(at(r"bin\b.exe"), MZ)
        .file(at(r"Game\Binaries\Win64\Game-Win64-Shipping.exe"), MZ)
        .file(at("readme.txt"), MZ)
        .build()
        .unwrap();
    let w = run(&sys);
    assert_eq!(
        paths(&w),
        [
            "alpha.EXE",
            "Zeta.exe",
            r"bin\b.exe",
            r"bin\x64\tool.exe",
            r"Binaries\Win64\Game-Win64-Shipping.exe",
            r"Game\Binaries\Win64\Game-Win64-Shipping.exe",
        ]
    );
    let depths: Vec<usize> = w.exes.iter().map(|e| e.depth).collect();
    assert_eq!(depths, [0, 0, 1, 2, 2, 3]);
    assert_eq!(w.exes[0].listed_len, 4);
    assert!(w.stats.complete);
    assert!(w.issues.is_empty(), "{:?}", w.issues);
    // Folded order per level ("BIN" < "BINARIES" < "GAME"): the game folder, bin, Binaries,
    // Game, bin\x64, Binaries\Win64, Game\Binaries, Game\Binaries\Win64.
    assert_eq!(w.stats.listed_dirs, 8);
    assert_eq!(w.stats.exes_found, 6);
    assert_eq!(w.stats.depth_cut, 0);
}

#[test]
fn only_plain_files_ending_in_exe_are_candidates() {
    let sys = base()
        .file(at("a.ExE"), MZ)
        .file(at("b.com"), MZ)
        .file(at("c.bat"), MZ)
        .file(at("d.exe.bak"), MZ)
        .file(at("e.exex"), MZ)
        .file(at("exe"), MZ)
        .file(at(r"f.exe\inner.exe"), MZ)
        .build()
        .unwrap();
    let w = run(&sys);
    // A directory named `f.exe` is entered, never a candidate itself.
    assert_eq!(paths(&w), ["a.ExE", r"f.exe\inner.exe"]);
}

#[test]
fn depth_three_is_listed_and_level_four_is_counted() {
    let sys = base()
        .file(at(r"a\b\c\level3.exe"), MZ)
        .file(at(r"a\b\c\d\level4.exe"), MZ)
        .dir(at(r"a\b\c\e"))
        .build()
        .unwrap();
    let w = run(&sys);
    assert_eq!(paths(&w), [r"a\b\c\level3.exe"]);
    assert_eq!(w.stats.depth_cut, 2);
    assert!(w.stats.complete, "a depth cut is no limit of the walk");
    assert!(w.issues.is_empty(), "{:?}", w.issues);

    let limits = ExeLimits {
        max_depth: 0,
        ..ExeLimits::DEFAULT
    };
    let w = walk(&game(&sys), &limits);
    assert!(w.exes.is_empty());
    assert_eq!(w.stats.listed_dirs, 1);
    assert_eq!(w.stats.depth_cut, 1);
}

#[test]
fn skipped_folders_are_listed_and_never_entered() {
    let mut b = base().file(at("game.exe"), MZ);
    for (i, name) in SKIP_DIRS.iter().enumerate() {
        // Every other one in another case, and one level down as well.
        let name = if i % 2 == 0 {
            name.to_ascii_uppercase()
        } else {
            name.to_ascii_lowercase()
        };
        b = b
            .file(at(&format!(r"{name}\setup.exe")), MZ)
            .file(at(&format!(r"bin\{name}\x.exe")), MZ);
    }
    let sys = b.build().unwrap();
    let w = run(&sys);
    assert_eq!(paths(&w), ["game.exe"]);
    assert_eq!(w.stats.skipped_dirs.len(), 2 * SKIP_DIRS.len());
    for name in SKIP_DIRS {
        assert!(w.stats.skipped_dirs.contains(&rel(name)), "{name}");
        assert!(
            w.stats.skipped_dirs.contains(&rel(&format!(r"bin\{name}"))),
            "{name}"
        );
    }
    // Only the game folder and `bin` were listed.
    assert_eq!(w.stats.listed_dirs, 2);
    // Not a whole segment: entered.
    let sys = base().file(at(r"RedistX\a.exe"), MZ).build().unwrap();
    assert_eq!(paths(&run(&sys)), [r"RedistX\a.exe"]);
}

#[test]
fn reparse_points_and_restricted_entries_are_reported_and_never_followed() {
    let sys = base()
        .file(r"D:\Elsewhere\other.exe", MZ)
        .junction(at("junction"), r"D:\Elsewhere")
        .file_symlink(at("linked.exe"), r"D:\Elsewhere\other.exe")
        .tagged_dir(at("projected"), tag::PROJFS)
        .file(at(r"locked\inner.exe"), MZ)
        .restricted(at("locked"))
        .file(at("denied.exe"), MZ)
        .restricted(at("denied.exe"))
        .file(at("denied.txt"), MZ)
        .restricted(at("denied.txt"))
        .tagged_file(at("compressed.exe"), MZ, tag::WOF)
        .tagged_dir(at("cloud"), tag::CLOUD)
        .file(at(r"cloud\synced.exe"), MZ)
        .build()
        .unwrap();
    sys.fake_fs()
        .put_link(Path::new(&at("dirlink")), tag::SYMLINK, r"D:\Elsewhere")
        .unwrap();
    let w = run(&sys);
    assert_eq!(paths(&w), ["compressed.exe", r"cloud\synced.exe"]);
    let reparse = ExeIssueKind::NotFollowed {
        kind: EntryKind::Reparse,
        restricted: false,
    };
    for p in ["junction", "dirlink", "linked.exe", "projected"] {
        assert_eq!(issue_at(&w, p), &reparse, "{p}");
    }
    assert_eq!(
        issue_at(&w, "locked"),
        &ExeIssueKind::NotFollowed {
            kind: EntryKind::Dir,
            restricted: true
        }
    );
    assert_eq!(
        issue_at(&w, "denied.exe"),
        &ExeIssueKind::NotFollowed {
            kind: EntryKind::File,
            restricted: true
        }
    );
    // A restricted file that is no candidate is not worth an issue.
    assert!(!w.issues.iter().any(|i| i.at == Some(rel("denied.txt"))));
    assert_eq!(w.issues.len(), 6, "{:?}", w.issues);
    let shown: Vec<String> = w.issues.iter().map(ToString::to_string).collect();
    assert_eq!(shown[0], "denied.exe: restricted file; not followed");
    assert_eq!(
        shown[1],
        "dirlink: reparse point (junction, symlink or unknown tag); not followed"
    );
    assert_eq!(shown[4], "locked: restricted directory; not followed");
}

#[test]
fn case_sensitive_folders_are_not_used() {
    let sys = base()
        .file(at("game.exe"), MZ)
        .case_sensitive_dir(at("sensitive"))
        .file(at(r"sensitive\a.exe"), MZ)
        .file(at(r"sensitive\A.EXE"), MZ)
        .build()
        .unwrap();
    let w = run(&sys);
    assert_eq!(paths(&w), ["game.exe"]);
    assert_eq!(issue_at(&w, "sensitive"), &ExeIssueKind::CaseSensitiveDir);
    assert_eq!(w.issues.len(), 1);
    assert_eq!(
        w.stats.entries, 2,
        "the case-sensitive folder is not listed"
    );

    // The game folder itself, checked when the walk starts.
    let sys = base()
        .case_sensitive_dir(GAME)
        .file(at("game.exe"), MZ)
        .build()
        .unwrap();
    let w = run(&sys);
    assert!(w.exes.is_empty());
    assert_eq!(
        w.issues,
        [ExeIssue {
            at: None,
            kind: ExeIssueKind::CaseSensitiveDir
        }]
    );
    assert_eq!(
        w.issues[0].to_string(),
        "game folder: case-sensitive directory; its entries are not used"
    );
}

#[test]
fn anomalous_names_are_reported_where_they_matter_and_never_opened() {
    let long = "d".repeat(200);
    let sys = base()
        .raw_file(GAME, "game.exe.", MZ)
        .raw_file(GAME, "CON.exe", MZ)
        .raw_file(GAME, "evil\u{202E}exe.txt.exe", MZ)
        .raw_file(GAME, "bad\u{FFFD}.exe", MZ)
        .raw_file(GAME, "notes.txt.", MZ)
        .dir(at("DATA~1"))
        .file(at(r"DATA~1\hidden.exe"), MZ)
        .file(at(&format!(r"{long}\{}.exe", "e".repeat(45))), MZ)
        .file(at(&format!(r"{long}\short.exe")), MZ)
        .build()
        .unwrap();
    let w = run(&sys);
    assert_eq!(paths(&w), [format!(r"{long}\short.exe").as_str()]);
    let anomalies: Vec<(Option<&RelPath>, &str)> = w
        .issues
        .iter()
        .map(|i| match &i.kind {
            ExeIssueKind::Anomaly(a) => (i.at.as_ref(), a.name.as_str()),
            other => panic!("expected an anomaly, got {other:?}"),
        })
        .collect();
    let top: Vec<&str> = anomalies
        .iter()
        .filter(|(at, _)| at.is_none())
        .map(|(_, n)| *n)
        .collect();
    assert_eq!(
        top,
        [
            "bad\u{FFFD}.exe",
            "CON.exe",
            "DATA~1",
            "evil\u{202E}exe.txt.exe",
            "game.exe."
        ]
    );
    // The over-long path is reported below its folder; `notes.txt.` did not matter.
    assert_eq!(anomalies.len(), 6, "{anomalies:?}");
    assert_eq!(anomalies[5].0, Some(&rel(&long)));
    // Raw names appear escaped only.
    for i in &w.issues {
        let shown = i.to_string();
        assert!(!shown.contains('\u{202E}'), "{shown}");
    }
}

#[test]
fn the_result_does_not_depend_on_the_listing_order() {
    let sys = base()
        .file(at("b.exe"), MZ)
        .file(at("A.exe"), MZ)
        .file(at(r"z\y.exe"), MZ)
        .file(at(r"m\n.exe"), MZ)
        .file(at(r"m\k\l.exe"), MZ)
        .build()
        .unwrap();
    let g = game(&sys);
    let sorted = walk(&g, &ExeLimits::DEFAULT);
    let reversed = walk_dir(&Scripted::new(g.dir()), &ExeLimits::DEFAULT);
    assert_eq!(sorted, reversed);
    assert_eq!(
        paths(&sorted),
        ["A.exe", "b.exe", r"m\n.exe", r"z\y.exe", r"m\k\l.exe"]
    );
    // The limits cut at the same place, too.
    let limits = ExeLimits {
        max_dirs: 2,
        ..ExeLimits::DEFAULT
    };
    assert_eq!(
        walk(&g, &limits),
        walk_dir(&Scripted::new(g.dir()), &limits)
    );
}

#[test]
fn a_folder_that_fails_is_an_issue_and_the_walk_goes_on() {
    let sys = base()
        .file(at(r"a\one.exe"), MZ)
        .file(at(r"b\two.exe"), MZ)
        .build()
        .unwrap();
    let g = game(&sys);
    let mut dir = Scripted::new(g.dir());
    dir.fail = Some(rel("a"));
    let w = walk_dir(&dir, &ExeLimits::DEFAULT);
    assert_eq!(paths(&w), [r"b\two.exe"]);
    match issue_at(&w, "a") {
        ExeIssueKind::Sys(e) => assert_eq!(e.kind, SysErrorKind::NotFound),
        other => panic!("expected Sys, got {other:?}"),
    }
    assert!(w.stats.complete);
    assert_eq!(w.stats.listed_dirs, 3);
}

#[test]
fn two_names_that_fold_alike_make_a_folder_case_sensitive() {
    let sys = base()
        .file(at("game.exe"), MZ)
        .file(at(r"bin\a.exe"), MZ)
        .file(at(r"bin\b.exe"), MZ)
        .build()
        .unwrap();
    let g = game(&sys);
    let mut dir = Scripted::new(g.dir());
    dir.twin_at = Some(rel("bin"));
    let w = walk_dir(&dir, &ExeLimits::DEFAULT);
    assert_eq!(paths(&w), ["game.exe"]);
    assert_eq!(
        w.issues,
        [ExeIssue {
            at: Some(rel("bin")),
            kind: ExeIssueKind::CaseSensitiveDir
        }]
    );
}

/// Folders `d0` … `d{n-1}`, each holding one executable.
fn folders(n: usize) -> FakeSystem {
    (0..n)
        .fold(base(), |b, i| b.file(at(&format!(r"d{i:03}\x.exe")), MZ))
        .build()
        .unwrap()
}

#[test]
fn the_directory_limit_keeps_a_partial_result() {
    let sys = folders(4);
    // The game folder and its four folders: exactly five.
    let exact = ExeLimits {
        max_dirs: 5,
        ..ExeLimits::DEFAULT
    };
    let w = walk(&game(&sys), &exact);
    assert!(w.stats.complete);
    assert_eq!(w.exes.len(), 4);
    assert!(w.issues.is_empty());

    let over = ExeLimits {
        max_dirs: 4,
        ..ExeLimits::DEFAULT
    };
    let w = walk(&game(&sys), &over);
    assert!(!w.stats.complete);
    assert_eq!(paths(&w), [r"d000\x.exe", r"d001\x.exe", r"d002\x.exe"]);
    assert_eq!(
        w.issues,
        [ExeIssue {
            at: None,
            kind: ExeIssueKind::WalkLimit {
                limit: LimitKind::Dirs,
                max: 4
            }
        }]
    );
    assert_eq!(
        w.issues[0].to_string(),
        "game folder: walk stopped after 4 listed directories; the list of executables is \
         incomplete"
    );
}

#[test]
fn the_entry_limit_uses_the_listing_that_crossed_it() {
    let sys = folders(3);
    // 3 entries in the game folder, 1 in each folder: 6 in all.
    let exact = ExeLimits {
        max_entries: 6,
        ..ExeLimits::DEFAULT
    };
    let w = walk(&game(&sys), &exact);
    assert!(w.stats.complete);
    assert_eq!(w.stats.entries, 6);
    assert_eq!(w.exes.len(), 3);

    // Crossed by the game folder's listing (3 > 2): that listing is used, nothing else.
    let over = ExeLimits {
        max_entries: 2,
        ..ExeLimits::DEFAULT
    };
    let w = walk(&game(&sys), &over);
    assert!(!w.stats.complete);
    assert_eq!(w.stats.listed_dirs, 1);
    assert_eq!(w.stats.entries, 3);
    assert!(w.exes.is_empty());
    assert_eq!(
        w.issues[0].kind,
        ExeIssueKind::WalkLimit {
            limit: LimitKind::Entries,
            max: 2
        }
    );
    // Reached exactly with folders left: those are not listed.
    let reached = ExeLimits {
        max_entries: 4,
        ..ExeLimits::DEFAULT
    };
    let w = walk(&game(&sys), &reached);
    assert!(!w.stats.complete);
    assert_eq!(paths(&w), [r"d000\x.exe"]);
}

#[test]
fn more_executables_than_the_limit_keep_the_first_in_walk_order() {
    let sys = (0..5)
        .fold(base(), |b, i| b.file(at(&format!("g{i}.exe")), MZ))
        .build()
        .unwrap();
    let exact = ExeLimits {
        max_exes: 5,
        ..ExeLimits::DEFAULT
    };
    let w = walk(&game(&sys), &exact);
    assert_eq!(w.exes.len(), 5);
    assert!(w.issues.is_empty());
    let over = ExeLimits {
        max_exes: 3,
        ..ExeLimits::DEFAULT
    };
    let w = walk(&game(&sys), &over);
    assert_eq!(paths(&w), ["g0.exe", "g1.exe", "g2.exe"]);
    assert_eq!(w.stats.exes_found, 5);
    assert!(w.stats.complete, "the walk itself was complete");
    assert_eq!(
        w.issues,
        [ExeIssue {
            at: None,
            kind: ExeIssueKind::TooManyExes { found: 5, max: 3 }
        }]
    );
}

#[test]
fn the_shipped_limits() {
    let l = ExeLimits::DEFAULT;
    assert_eq!(
        (l.max_depth, l.max_dirs, l.max_entries, l.max_exes),
        (3, 128, 20_000, 64)
    );
    assert_eq!(l.pe, crate::detect::pe::Limits::DEFAULT);
}

// ---------- A handle that lists in reverse and can fail ----------

/// Delegates to a real handle, lists every folder in reverse order, fails `open_dir` of
/// `fail` with `NotFound`, and lists folder `twin_at` with an extra entry: its first entry
/// again under an upper-case name (as if the folder turned case-sensitive between `info` and
/// `read_dir`).
#[derive(Debug)]
struct Scripted<'a> {
    inner: &'a dyn Dir,
    owned: Option<Box<dyn Dir + 'a>>,
    fail: Option<RelPath>,
    twin_at: Option<RelPath>,
    twin: bool,
}

impl<'a> Scripted<'a> {
    fn new(inner: &'a dyn Dir) -> Self {
        Self {
            inner,
            owned: None,
            fail: None,
            twin_at: None,
            twin: false,
        }
    }

    fn dir(&self) -> &dyn Dir {
        self.owned.as_deref().unwrap_or(self.inner)
    }
}

impl Dir for Scripted<'_> {
    fn info(&self) -> SysResult<RootInfo> {
        self.dir().info()
    }
    fn open_dir(&self, p: &RelPath) -> SysResult<Box<dyn Dir + '_>> {
        if self.fail.as_ref() == Some(p) {
            return Err(SysError::new(SysErrorKind::NotFound, p.as_str()));
        }
        let sub = self.dir().open_dir(p)?;
        Ok(Box::new(Scripted {
            inner: self.dir(),
            owned: Some(sub),
            fail: None,
            twin_at: None,
            twin: self.twin_at.as_ref() == Some(p),
        }))
    }
    fn metadata(&self, p: &RelPath) -> SysResult<Option<Metadata>> {
        self.dir().metadata(p)
    }
    fn open_read(&self, p: &RelPath) -> SysResult<Box<dyn ReadSeek + '_>> {
        self.dir().open_read(p)
    }
    fn read_dir_limited(&self, p: Option<&RelPath>, max: usize) -> SysResult<Vec<DirEntry>> {
        let mut entries = self.dir().read_dir_limited(p, max)?;
        entries.reverse();
        if self.twin
            && let Some(first) = entries.first().cloned()
        {
            entries.push(DirEntry {
                name: first.name.to_uppercase(),
                ..first
            });
        }
        Ok(entries)
    }
    fn users(&self, p: &RelPath) -> SysResult<Vec<u32>> {
        self.dir().users(p)
    }
}
