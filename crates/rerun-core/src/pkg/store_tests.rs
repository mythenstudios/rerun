//! `pkg::store` against the fake (P5-8b-1): listing (PS1, store side), exactly what was shown
//! (PS5), tampering (PS6), a crash after every call (PS7, store side), the locks and a file in
//! use (PS8). The world: `exec::tests::base`, whose package `fix-pack\1.0.2` holds `d3d9.dll`,
//! `mods\x.dll` and `new.dll`. Every name and content is invented.

use std::path::Path;

use super::{
    CacheEntry, EmptyId, Listing, Removed, Shown, StoreError, StoreKeep, StoreSub, list, remove,
};
use crate::exec::tests::{base, finish};
use crate::policy::root::{AppDir, AppSub, Create};
use crate::sys::contract::{Access, Share};
use crate::sys::fake::{FakeSystem, Fault, Prim};
use crate::sys::fs::{Attrs, tag};
use crate::sys::snapshot::{Scope, SnapRoot, Snapshot, snapshot};
use crate::sys::{Fs, System};

pub(crate) const APP: &str = r"C:\Users\Player\AppData\Local\Rerun";
pub(crate) const PACKAGES: &str = r"C:\Users\Player\AppData\Local\Rerun\packages";
pub(crate) const CACHE: &str = r"C:\Users\Player\AppData\Local\Rerun\cache";
const VERSION: &str = r"C:\Users\Player\AppData\Local\Rerun\packages\fix-pack\1.0.2";
/// An archive name (64 hex digits) and a temp name of the cache.
const ARCHIVE: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
const TEMP: &str = ".rerun-00000000000000ab-0.tmp";

fn at(dir: &str, name: &str) -> String {
    format!(r"{dir}\{name}")
}

/// The base world, with an archive and a temp file in the cache, an empty `<id>` folder and the
/// lock files of both folders.
pub(crate) fn world() -> FakeSystem {
    let sys = finish(base());
    let fx = sys.fake_fs();
    fx.put_file(Path::new(&at(CACHE, ARCHIVE)), b"an archive")
        .unwrap();
    fx.put_file(Path::new(&at(CACHE, TEMP)), b"half").unwrap();
    fx.put_file(Path::new(&at(CACHE, "lock")), b"").unwrap();
    fx.put_file(Path::new(&at(PACKAGES, ".lock")), b"").unwrap();
    fx.mkdir_all(Path::new(&at(PACKAGES, "empty-pack")))
        .unwrap();
    fx.sync_all();
    sys
}

fn app(sys: &FakeSystem) -> AppDir<'_> {
    AppDir::open(sys, Create::Never).unwrap().unwrap()
}

pub(crate) fn listed(sys: &FakeSystem) -> Listing {
    list(&app(sys)).unwrap_or_else(|e| panic!("{e}"))
}

/// What "remove all unused" would show of a listing (no journal here): every package that may go,
/// every cache entry, every empty `<id>` folder.
pub(crate) fn all_of(l: &Listing) -> Vec<Shown> {
    let mut v: Vec<Shown> = l
        .packages
        .iter()
        .filter(|p| p.keep.is_none())
        .cloned()
        .map(Shown::Package)
        .collect();
    v.extend(l.cache.iter().cloned().map(Shown::Archive));
    v.extend(l.empty_ids.iter().cloned().map(Shown::EmptyId));
    v
}

fn rm(sys: &FakeSystem, shown: &[Shown]) -> Result<Removed, StoreError> {
    remove(sys, &app(sys), shown)
}

/// The names in `abs`, sorted (empty if it does not exist).
pub(crate) fn ls(sys: &FakeSystem, abs: &str) -> Vec<String> {
    #[expect(clippy::disallowed_methods, reason = "test: list a fixture folder")]
    let Ok(d) = sys.fake_fs().open_dir(Path::new(abs)) else {
        return Vec::new();
    };
    let mut v: Vec<String> = d
        .read_dir(None)
        .unwrap()
        .into_iter()
        .map(|e| e.name)
        .collect();
    v.sort();
    v
}

pub(crate) fn snap(sys: &FakeSystem, abs: &str) -> Snapshot {
    #[expect(clippy::disallowed_methods, reason = "test: snapshot a fixture folder")]
    let d = sys.fake_fs().open_dir(Path::new(abs)).unwrap();
    snapshot(
        sys.registry(),
        &Scope {
            dirs: vec![SnapRoot::new(&*d, abs.to_owned())],
            keys: Vec::new(),
        },
    )
    .unwrap()
}

/// The diff lines of `a` → `b` outside `packages` and `cache`.
pub(crate) fn outside_store(a: &Snapshot, b: &Snapshot) -> Vec<String> {
    a.diff(b)
        .into_iter()
        .filter(|l| {
            let u = l.to_uppercase();
            !u.contains("PACKAGES") && !u.contains("CACHE")
        })
        .collect()
}

fn writes(calls: &[Prim]) -> Vec<Prim> {
    calls
        .iter()
        .copied()
        .filter(|c| {
            matches!(
                c,
                Prim::CreateTmp
                    | Prim::CreateDir
                    | Prim::Rename
                    | Prim::Write
                    | Prim::OpenLock
                    | Prim::OpenFileDelete
                    | Prim::OpenDirDelete
                    | Prim::PosixDelete
            )
        })
        .collect()
}

#[test]
fn ps1_the_listing_reads_only_and_names_every_part() {
    let sys = world();
    sys.fake_fs().record_calls(true);
    let l = listed(&sys);
    let calls = sys.fake_fs().take_calls();
    sys.fake_fs().record_calls(false);
    assert!(!calls.is_empty(), "the record bites");
    assert_eq!(writes(&calls), [], "listing writes nothing");
    assert_eq!(l.packages.len(), 1, "{l:?}");
    let p = &l.packages[0];
    assert_eq!((p.id.as_str(), p.version.as_str()), ("fix-pack", "1.0.2"));
    assert_eq!(p.keep, None);
    assert_eq!(p.files(), 3);
    let mut rels: Vec<&str> = p.items.iter().map(|i| i.rel.as_str()).collect();
    rels.sort_unstable();
    assert_eq!(rels, ["d3d9.dll", "mods", r"mods\x.dll", "new.dll"]);
    assert_eq!(p.bytes(), 23 + 20 + 22);
    assert_eq!(p.temps, 0);
    let names: Vec<(&str, bool, u64)> = l
        .cache
        .iter()
        .map(|c| (c.name.as_str(), c.temp, c.len))
        .collect();
    assert_eq!(names.len(), 2);
    assert!(names.contains(&(ARCHIVE, false, 10)) && names.contains(&(TEMP, true, 4)));
    assert_eq!(
        l.empty_ids
            .iter()
            .map(|e| e.id.as_str())
            .collect::<Vec<_>>(),
        ["empty-pack"]
    );
    assert!(l.foreign.is_empty(), "{:?}", l.foreign);

    // No sub folder: nothing listed, nothing created.
    let sys = crate::prim::tests::builder().build().unwrap();
    drop(AppDir::open(&sys, Create::IfMissing).unwrap());
    let before = snap(&sys, APP);
    assert_eq!(listed(&sys), Listing::default());
    assert!(before == snap(&sys, APP));
}

#[test]
fn remove_takes_exactly_the_store_and_nothing_else() {
    let sys = world();
    let before = snap(&sys, APP);
    let l = listed(&sys);
    let r = rm(&sys, &all_of(&l)).unwrap();
    assert_eq!(r.packages, [("fix-pack".to_owned(), "1.0.2".to_owned())]);
    assert_eq!((r.archives, r.leftovers, r.gone), (1, 2, 0));
    assert_eq!(r.bytes, 65 + 10 + 4);
    assert!(r.stopped.is_empty(), "{r:?}");
    // Only the lock files are left.
    assert_eq!(ls(&sys, PACKAGES), [".lock"]);
    assert_eq!(ls(&sys, CACHE), ["lock"]);
    assert_eq!(
        outside_store(&before, &snap(&sys, APP)),
        Vec::<String>::new()
    );
    // A second run with the same list: everything is gone already, which is done.
    let r = rm(&sys, &all_of(&l)).unwrap();
    assert_eq!((r.gone, r.packages.len(), r.bytes), (4, 0, 0));
}

#[test]
fn remove_keeps_another_version_and_the_id_folder_with_it() {
    let sys = world();
    let other = at(PACKAGES, r"fix-pack\2.0\new.dll");
    sys.fake_fs().put_file(Path::new(&other), b"v2").unwrap();
    let l = listed(&sys);
    let one: Vec<Shown> = l
        .packages
        .iter()
        .filter(|p| p.version == "1.0.2")
        .cloned()
        .map(Shown::Package)
        .collect();
    let r = rm(&sys, &one).unwrap();
    assert_eq!(r.packages.len(), 1);
    assert_eq!(ls(&sys, &at(PACKAGES, "fix-pack")), ["2.0"]);
    assert_eq!(ls(&sys, &at(PACKAGES, r"fix-pack\2.0")), ["new.dll"]);
}

#[test]
fn ps5_what_differs_from_what_was_shown_is_changed_and_nothing_goes() {
    type Change = fn(&FakeSystem);
    let changes: [(&str, Change); 5] = [
        ("a new file in a shown folder", |s| {
            s.fake_fs()
                .put_file(Path::new(&at(VERSION, r"mods\y.dll")), b"y")
                .unwrap();
        }),
        ("another file under a shown name", |s| {
            let p = at(VERSION, "new.dll");
            s.fake_fs().remove_abs(Path::new(&p)).unwrap();
            s.fake_fs().put_file(Path::new(&p), b"another").unwrap();
        }),
        ("another archive under a shown name", |s| {
            let p = at(CACHE, ARCHIVE);
            s.fake_fs().remove_abs(Path::new(&p)).unwrap();
            s.fake_fs().put_file(Path::new(&p), b"an archive").unwrap();
        }),
        ("a shown empty folder that is not empty now", |s| {
            s.fake_fs()
                .put_file(Path::new(&at(PACKAGES, r"empty-pack\1.0\a.dll")), b"a")
                .unwrap();
        }),
        ("a shown package that stays now", |s| {
            s.fake_fs()
                .set_attrs(
                    Path::new(&at(VERSION, "new.dll")),
                    Attrs {
                        readonly: true,
                        ..Attrs::default()
                    },
                )
                .unwrap();
        }),
    ];
    for (what, change) in changes {
        let sys = world();
        let shown = all_of(&listed(&sys));
        change(&sys);
        let before = snap(&sys, APP);
        assert!(
            matches!(rm(&sys, &shown), Err(StoreError::Changed)),
            "{what}"
        );
        assert!(before == snap(&sys, APP), "{what}: nothing deleted");
    }

    // A shown file gone already is done; a package that came since is untouched.
    let sys = world();
    let shown = all_of(&listed(&sys));
    let fx = sys.fake_fs();
    fx.remove_abs(Path::new(&at(VERSION, "new.dll"))).unwrap();
    fx.remove_abs(Path::new(&at(CACHE, TEMP))).unwrap();
    fx.put_file(Path::new(&at(PACKAGES, r"late-pack\1.0\a.dll")), b"a")
        .unwrap();
    fx.put_file(Path::new(&at(CACHE, &ARCHIVE.replace('0', "f"))), b"late")
        .unwrap();
    let r = rm(&sys, &shown).unwrap();
    assert_eq!(r.gone, 1, "the temp file");
    assert_eq!(r.packages.len(), 1);
    assert_eq!(ls(&sys, PACKAGES), [".lock", "late-pack"]);
    assert_eq!(
        ls(&sys, CACHE),
        [ARCHIVE.replace('0', "f").as_str(), "lock"]
    );
}

/// The keep reason of `fix-pack\1.0.2` after `tamper`, and that the removal of every listed
/// part leaves it whole.
fn kept_whole(tamper: impl Fn(&FakeSystem)) -> Option<StoreKeep> {
    let sys = world();
    tamper(&sys);
    let l = listed(&sys);
    let keep = l.packages.iter().find(|p| p.id == "fix-pack")?.keep;
    let files = ls(&sys, VERSION);
    let r = rm(&sys, &all_of(&l)).unwrap();
    assert!(r.packages.is_empty(), "{r:?}");
    assert_eq!(ls(&sys, VERSION), files, "the package stays whole");
    keep
}

#[test]
fn ps6_links_attributes_names_and_too_many_entries_stay_with_their_reason() {
    let target = r"D:\Elsewhere";
    let ro = Attrs {
        readonly: true,
        ..Attrs::default()
    };
    // Inside a version folder: the package stays whole.
    let link = |name: &'static str, t: u32| {
        move |s: &FakeSystem| {
            s.fake_fs()
                .put_link(Path::new(&at(VERSION, name)), t, r"D:\Elsewhere")
                .unwrap();
        }
    };
    assert_eq!(
        kept_whole(link(r"mods\j", tag::MOUNT_POINT)),
        Some(StoreKeep::Reparse)
    );
    assert_eq!(
        kept_whole(link("f.dll", tag::SYMLINK)),
        Some(StoreKeep::Reparse)
    );
    assert_eq!(
        kept_whole(|s| s
            .fake_fs()
            .put_hardlink(
                Path::new(&at(VERSION, "new.dll")),
                Path::new(r"C:\Users\Player\copy.dll")
            )
            .unwrap()),
        Some(StoreKeep::Linked)
    );
    for attrs in [
        ro,
        Attrs {
            hidden: true,
            ..Attrs::default()
        },
        Attrs {
            system: true,
            ..Attrs::default()
        },
    ] {
        assert_eq!(
            kept_whole(|s| s
                .fake_fs()
                .set_attrs(Path::new(&at(VERSION, "mods")), attrs)
                .unwrap()),
            Some(StoreKeep::Attributes),
            "{attrs:?}"
        );
    }
    assert_eq!(
        kept_whole(|s| s
            .fake_fs()
            .put_raw_file(Path::new(VERSION), "bad.", b"x")
            .unwrap()),
        Some(StoreKeep::BadName)
    );
    assert_eq!(
        kept_whole(|s| {
            for i in 0..=super::MAX_ENTRIES {
                s.fake_fs()
                    .put_file(Path::new(&at(VERSION, &format!(r"many\{i}.bin"))), b"")
                    .unwrap();
            }
        }),
        Some(StoreKeep::TooMany)
    );
    assert_eq!(
        kept_whole(|s| {
            let deep = (0..=super::MAX_DEPTH)
                .map(|i| format!("d{i}"))
                .collect::<Vec<_>>()
                .join(r"\");
            s.fake_fs()
                .put_file(Path::new(&at(VERSION, &format!(r"{deep}\a.bin"))), b"")
                .unwrap();
        }),
        Some(StoreKeep::TooMany)
    );

    // At the top: foreign, never followed; the targets stay.
    let sys = world();
    let fx = sys.fake_fs();
    fx.put_file(Path::new(r"D:\Elsewhere\keep.dll"), b"keep")
        .unwrap();
    fx.put_link(
        Path::new(&at(PACKAGES, "linked-pack")),
        tag::MOUNT_POINT,
        target,
    )
    .unwrap();
    fx.put_link(
        Path::new(&at(PACKAGES, r"fix-pack\9.9")),
        tag::MOUNT_POINT,
        target,
    )
    .unwrap();
    fx.put_file(Path::new(&at(PACKAGES, "Bad_Name")), b"x")
        .unwrap();
    fx.put_file(Path::new(&at(PACKAGES, r"fix-pack\not..ok")), b"x")
        .unwrap();
    fx.put_file(Path::new(&at(CACHE, "notes.txt")), b"x")
        .unwrap();
    fx.put_link(
        Path::new(&at(CACHE, &ARCHIVE.replace('1', "2"))),
        tag::SYMLINK,
        target,
    )
    .unwrap();
    let l = listed(&sys);
    let mut foreign: Vec<(StoreSub, &str, StoreKeep)> = l
        .foreign
        .iter()
        .map(|f| (f.sub, f.name.as_str(), f.keep))
        .collect();
    foreign.sort_by_key(|f| f.1.to_owned());
    let swapped = ARCHIVE.replace('1', "2");
    let mut want = vec![
        (StoreSub::Packages, "Bad_Name", StoreKeep::BadName),
        (StoreSub::Packages, r"fix-pack\9.9", StoreKeep::Reparse),
        (StoreSub::Packages, r"fix-pack\not..ok", StoreKeep::BadName),
        (StoreSub::Packages, "linked-pack", StoreKeep::Reparse),
        (StoreSub::Cache, "notes.txt", StoreKeep::BadName),
        (StoreSub::Cache, swapped.as_str(), StoreKeep::Reparse),
    ];
    want.sort_by_key(|f| f.1.to_owned());
    assert_eq!(foreign, want);
    let r = rm(&sys, &all_of(&l)).unwrap();
    assert!(r.stopped.is_empty(), "{r:?}");
    assert_eq!(ls(&sys, r"D:\Elsewhere"), ["keep.dll"]);
    assert_eq!(
        ls(&sys, PACKAGES),
        [".lock", "Bad_Name", "fix-pack", "linked-pack"]
    );
    assert_eq!(ls(&sys, &at(PACKAGES, "fix-pack")), ["9.9", "not..ok"]);
    assert_eq!(ls(&sys, CACHE), [swapped.as_str(), "lock", "notes.txt"]);

    // `packages` or `cache` itself a junction: listed as foreign, never followed, and nothing is
    // removed through it.
    for (sub, name) in [(StoreSub::Packages, PACKAGES), (StoreSub::Cache, CACHE)] {
        let sys = world();
        sys.fake_fs()
            .put_file(Path::new(r"D:\Elsewhere\keep.dll"), b"keep")
            .unwrap();
        let shown = all_of(&listed(&sys));
        sys.fake_fs()
            .swap_with_junction(Path::new(name), target)
            .unwrap();
        let l = listed(&sys);
        assert!(
            l.foreign
                .iter()
                .any(|f| f.sub == sub && f.name.is_empty() && f.keep == StoreKeep::Reparse),
            "{:?}",
            l.foreign
        );
        assert!(matches!(rm(&sys, &shown), Err(StoreError::Changed)));
        assert_eq!(ls(&sys, r"D:\Elsewhere"), ["keep.dll"]);
    }
}

#[test]
fn ps8_a_held_lock_is_busy_and_a_file_in_use_stops_only_its_package() {
    for sub in [AppSub::Packages, AppSub::Cache] {
        let sys = world();
        let shown = all_of(&listed(&sys));
        let a = app(&sys);
        let dir = a.sub_write(sub, Create::Never).unwrap().unwrap();
        let name = if sub == AppSub::Packages {
            ".lock"
        } else {
            "lock"
        };
        let held = dir
            .lock(&crate::path::RelPath::from_segment(name).unwrap())
            .unwrap();
        let before = (ls(&sys, VERSION), ls(&sys, CACHE), ls(&sys, PACKAGES));
        assert!(matches!(rm(&sys, &shown), Err(StoreError::Busy)), "{sub:?}");
        drop(held);
        let after = (ls(&sys, VERSION), ls(&sys, CACHE), ls(&sys, PACKAGES));
        assert_eq!(before, after, "{sub:?}: nothing deleted");
    }

    // A scanner holds one file of `fix-pack` without share-delete: that package stops, the rest
    // goes; the next run finishes it.
    let sys = world();
    let fx = sys.fake_fs();
    fx.put_file(Path::new(&at(PACKAGES, r"other-pack\1.0\a.dll")), b"a")
        .unwrap();
    let shown = all_of(&listed(&sys));
    let held = fx
        .hold_open_as(
            4242,
            Path::new(&at(VERSION, r"mods\x.dll")),
            Access::READ,
            Share::RW,
        )
        .unwrap();
    let r = rm(&sys, &shown).unwrap();
    assert_eq!(r.packages, [("other-pack".to_owned(), "1.0".to_owned())]);
    assert_eq!(r.stopped, [("fix-pack@1.0.2".to_owned(), StoreKeep::Busy)]);
    assert_eq!(r.archives, 1);
    drop(held);
    let l = listed(&sys);
    let r = rm(&sys, &all_of(&l)).unwrap();
    assert_eq!(r.packages.len(), 1, "{r:?}");
    assert_eq!(ls(&sys, PACKAGES), [".lock"]);
}

/// The calls of a complete removal of everything in [`world`].
fn trace() -> Vec<Prim> {
    let sys = world();
    let shown = all_of(&listed(&sys));
    let a = app(&sys);
    let fx = sys.fake_fs();
    fx.clear_faults();
    fx.record_calls(true);
    remove(&sys, &a, &shown).unwrap();
    fx.record_calls(false);
    fx.take_calls()
}

#[test]
fn ps7_a_crash_after_any_call_leaves_a_consistent_store_and_the_next_run_finishes() {
    let calls = trace();
    assert!(calls.contains(&Prim::OpenFileDelete) && calls.contains(&Prim::OpenDirDelete));
    for i in 0..calls.len() {
        let sys = world();
        let shown = all_of(&listed(&sys));
        let a = app(&sys);
        let fx = sys.fake_fs();
        fx.clear_faults();
        let nth = calls[..=i].iter().filter(|c| **c == calls[i]).count();
        fx.fault(calls[i], nth, Fault::CrashAfter);
        let _ = remove(&sys, &a, &shown);
        assert!(fx.crashed(), "crash after call {i}");
        drop(a);
        sys.restart();
        // Consistent: the package is listed whole-or-partial and removable, or gone (an empty
        // `<id>` folder at most); nothing is foreign.
        let l = listed(&sys);
        assert!(l.foreign.is_empty(), "{i}: {:?}", l.foreign);
        assert!(l.packages.iter().all(|p| p.keep.is_none()), "{i}: {l:?}");
        let r = rm(&sys, &all_of(&l)).unwrap_or_else(|e| panic!("{i}: {e}"));
        assert!(r.stopped.is_empty(), "{i}: {r:?}");
        assert_eq!(ls(&sys, PACKAGES), [".lock"], "{i}");
        assert_eq!(ls(&sys, CACHE), ["lock"], "{i}");
    }
}

#[test]
fn ps10_an_elevated_process_removes_nothing() {
    let sys = world();
    let shown = all_of(&listed(&sys));
    sys.fake_registry().set_elevated(true);
    let a = app(&sys);
    let before = snap(&sys, APP);
    sys.fake_fs().record_calls(true);
    assert!(matches!(
        remove(&sys, &a, &shown),
        Err(StoreError::Elevated)
    ));
    assert_eq!(sys.fake_fs().take_calls(), [], "nothing read but the token");
    assert!(before == snap(&sys, APP));
}

/// `CacheEntry` and `EmptyId` compare by every field (what `remove` compares).
#[test]
fn shown_entries_compare_by_identity() {
    let c = CacheEntry {
        name: ARCHIVE.to_owned(),
        file_id: 1,
        len: 2,
        temp: false,
    };
    assert_ne!(
        c,
        CacheEntry {
            file_id: 3,
            ..c.clone()
        }
    );
    let e = EmptyId {
        id: "x".to_owned(),
        file_id: 1,
    };
    assert_ne!(
        e,
        EmptyId {
            file_id: 2,
            ..e.clone()
        }
    );
}
