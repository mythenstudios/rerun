//! The VirtualStore lookup (P3-7) against the fake: a copy found and named, roots outside the
//! three folders never looked up (no file-system call), links not followed, an unknown
//! `LocalAppData` a note.

use super::{Shadow, check_root};
use crate::escape;
use crate::path::{RelPath, RootPath};
use crate::sys::KnownFolder;
use crate::sys::fake::{FakeSystem, FakeSystemBuilder};

const VS: &str = r"C:\Users\Player\AppData\Local\VirtualStore";
const PF86_GAME: &str = r"C:\Program Files (x86)\G";

fn rel(s: &str) -> RelPath {
    RelPath::parse(s).unwrap()
}

fn root(s: &str) -> RootPath {
    RootPath::new(s).unwrap()
}

fn layout() -> FakeSystemBuilder {
    FakeSystem::builder()
        .windows_layout()
        .file(format!(r"{PF86_GAME}\settings.ini"), b"managed".to_vec())
        .file(format!(r"{PF86_GAME}\d3d9.dll"), b"managed".to_vec())
}

fn check(sys: &FakeSystem, at: &str, files: &[&str]) -> Vec<Shadow> {
    let files: Vec<RelPath> = files.iter().map(|f| rel(f)).collect();
    check_root(sys, 0, &root(at), &files)
}

fn copy(path: &str, file: &str) -> Shadow {
    Shadow::Copy {
        root: 0,
        file: rel(file),
        copy: escape::path(path).into_owned(),
    }
}

#[test]
fn a_copy_is_reported_with_its_full_path() {
    let sys = layout()
        .file(
            format!(r"{VS}\Program Files (x86)\G\settings.ini"),
            b"copy".to_vec(),
        )
        .build()
        .unwrap();
    let found = check(&sys, PF86_GAME, &["settings.ini", "d3d9.dll"]);
    let want = format!(r"{VS}\Program Files (x86)\G\settings.ini");
    assert_eq!(found, vec![copy(&want, "settings.ini")]);
    // The field is the `escape::path` form (a clean path is shown unchanged).
    let Shadow::Copy { copy: shown, .. } = &found[0] else {
        unreachable!()
    };
    assert_eq!(shown.as_str(), want);
}

#[test]
fn every_virtualized_folder_is_looked_up_and_files_below_folders_too() {
    for (base, below) in [
        (r"C:\Program Files", r"Program Files"),
        (r"C:\Program Files (x86)", r"Program Files (x86)"),
        (r"C:\ProgramData", "ProgramData"),
    ] {
        let sys = FakeSystem::builder()
            .windows_layout()
            .dir(format!(r"{base}\G"))
            .file(format!(r"{VS}\{below}\G\bin\x.cfg"), b"copy".to_vec())
            .build()
            .unwrap();
        let found = check(&sys, &format!(r"{base}\G"), &[r"bin\x.cfg"]);
        assert_eq!(
            found,
            vec![copy(&format!(r"{VS}\{below}\G\bin\x.cfg"), r"bin\x.cfg")],
            "{base}"
        );
    }
}

#[test]
fn no_copy_and_no_virtual_store_folder_say_nothing() {
    let sys = layout().build().unwrap();
    assert_eq!(check(&sys, PF86_GAME, &["settings.ini"]), Vec::new());
    // A folder of the file's name is no copy of it.
    let sys = layout()
        .dir(format!(r"{VS}\Program Files (x86)\G\settings.ini"))
        .build()
        .unwrap();
    assert_eq!(check(&sys, PF86_GAME, &["settings.ini"]), Vec::new());
}

#[test]
fn a_root_outside_the_three_folders_is_never_looked_up() {
    // A copy where a lookup for `D:\Games\G` would find one (if it ignored the drive).
    let sys = FakeSystem::builder()
        .windows_layout()
        .file(r"D:\Games\G\settings.ini", b"managed".to_vec())
        .file(format!(r"{VS}\Games\G\settings.ini"), b"copy".to_vec())
        .dir(r"C:\Program Files Extra\G")
        .file(
            format!(r"{VS}\Program Files Extra\G\settings.ini"),
            b"copy".to_vec(),
        )
        .build()
        .unwrap();
    let fx = sys.fake_fs();
    fx.record_calls(true);
    // `C:\Program Files Extra` shares a prefix with `C:\Program Files` but is not inside it.
    for at in [r"D:\Games\G", r"C:\Program Files Extra\G"] {
        assert_eq!(check(&sys, at, &["settings.ini"]), Vec::new(), "{at}");
    }
    assert_eq!(fx.take_calls(), Vec::new(), "no file-system call at all");
    // The record is live: a root inside a virtualized folder is looked up.
    let sys = layout().build().unwrap();
    sys.fake_fs().record_calls(true);
    check(&sys, PF86_GAME, &["settings.ini"]);
    assert!(!sys.fake_fs().take_calls().is_empty());
}

#[test]
fn a_junction_in_the_virtual_store_path_is_not_followed() {
    // `VirtualStore\Program Files (x86)` is a junction to a folder that holds a "copy".
    let sys = layout()
        .file(r"C:\Elsewhere\G\settings.ini", b"copy".to_vec())
        .dir(VS)
        .junction(format!(r"{VS}\Program Files (x86)"), r"C:\Elsewhere")
        .build()
        .unwrap();
    assert_eq!(
        check(&sys, PF86_GAME, &["settings.ini"]),
        vec![Shadow::Link {
            root: 0,
            at: escape::path(&format!(r"{VS}\Program Files (x86)\G")).into_owned(),
        }]
    );
}

#[test]
fn a_link_below_the_game_folder_copy_is_not_followed() {
    let sys = FakeSystem::builder()
        .windows_layout()
        .dir(PF86_GAME)
        .file(r"C:\Elsewhere\x.cfg", b"copy".to_vec())
        .dir(format!(r"{VS}\Program Files (x86)\G"))
        .junction(format!(r"{VS}\Program Files (x86)\G\bin"), r"C:\Elsewhere")
        .file_symlink(
            format!(r"{VS}\Program Files (x86)\G\top.cfg"),
            r"C:\Elsewhere\x.cfg",
        )
        .build()
        .unwrap();
    let link_at = |p: &str| Shadow::Link {
        root: 0,
        at: escape::path(&format!(r"{VS}\Program Files (x86)\G\{p}")).into_owned(),
    };
    assert_eq!(
        check(&sys, PF86_GAME, &[r"bin\x.cfg", "top.cfg"]),
        vec![link_at(r"bin\x.cfg"), link_at("top.cfg")]
    );
}

#[test]
fn an_unknown_local_app_data_is_a_note_not_a_failure() {
    let sys = layout()
        .file(
            format!(r"{VS}\Program Files (x86)\G\settings.ini"),
            b"copy".to_vec(),
        )
        .without_known_folder(KnownFolder::LocalAppData)
        .build()
        .unwrap();
    let found = check(&sys, PF86_GAME, &["settings.ini"]);
    let [Shadow::Unchecked { root: 0, why, .. }] = found.as_slice() else {
        panic!("{found:?}")
    };
    assert!(why.as_str().starts_with("LocalAppData is unknown"), "{why}");
}

/// Review nit: the raw `LocalAppData` value in a reason is shown as a path (`escape::path`),
/// apart from the text, so a deceptive character in it never reaches the console raw.
#[test]
fn a_path_in_the_reason_is_escaped_as_a_path() {
    let raw = "C:\\Users\\Player\\AppData\\Lo\u{202e}cal";
    let sys = layout()
        .known_folder(KnownFolder::LocalAppData, raw)
        .build()
        .unwrap();
    let found = check(&sys, PF86_GAME, &["settings.ini"]);
    let [Shadow::Unchecked { root: 0, why, at }] = found.as_slice() else {
        panic!("{found:?}")
    };
    assert_eq!(
        why.as_str(),
        "LocalAppData: invalid path: invisible or confusable character"
    );
    let at = at.as_ref().expect("the path is named");
    assert_eq!(at, &escape::path(raw).into_owned());
    assert!(at.as_str().contains(r"\u{202e}"), "{at}");
    assert!(!at.as_str().contains('\u{202e}'));
    assert!(!why.as_str().contains('\u{202e}'));
}

/// Review nit: a root whose `VirtualStore\<path without drive>` exceeds [`RelPath::MAX_LEN`]
/// cannot be looked up: a note, not "no copy".
#[test]
fn a_root_too_long_for_the_virtual_store_path_is_a_note() {
    // The root itself is valid (`MAX_LEN` characters below the drive); `VirtualStore\` makes the
    // looked-up path longer than a `RelPath` may be.
    let name = "g".repeat(RelPath::MAX_LEN - r"Program Files (x86)\".len());
    let at = format!(r"C:\Program Files (x86)\{name}");
    let sys = layout().dir(&at).build().unwrap();
    let found = check(&sys, &at, &["settings.ini"]);
    let [Shadow::Unchecked { root: 0, why, at }] = found.as_slice() else {
        panic!("{found:?}")
    };
    assert_eq!(why.as_str(), "invalid path: too long");
    assert!(
        at.as_ref()
            .is_some_and(|a| a.as_str().starts_with("VirtualStore\\"))
    );
}

/// Review nit: a file (not a folder) at a component of `VirtualStore\…` means no copy can
/// exist there (module docs), for the root part and for the part below the game folder alike:
/// nothing is reported, never a note in one place and silence in the other.
#[test]
fn a_file_on_the_way_means_no_copy_in_both_parts() {
    // Root part: `VirtualStore\Program Files (x86)` is a file.
    let sys = layout()
        .file(format!(r"{VS}\Program Files (x86)"), b"x".to_vec())
        .build()
        .unwrap();
    assert_eq!(check(&sys, PF86_GAME, &["settings.ini"]), Vec::new());
    // Root part, deeper: `VirtualStore\Program Files (x86)\G` is a file.
    let sys = layout()
        .file(format!(r"{VS}\Program Files (x86)\G"), b"x".to_vec())
        .build()
        .unwrap();
    assert_eq!(check(&sys, PF86_GAME, &["settings.ini"]), Vec::new());
    // Below the game folder: `…\G\bin` is a file, the managed file is `bin\x.cfg`.
    let sys = layout()
        .file(format!(r"{VS}\Program Files (x86)\G\bin"), b"x".to_vec())
        .build()
        .unwrap();
    assert_eq!(check(&sys, PF86_GAME, &[r"bin\x.cfg"]), Vec::new());
}

#[test]
fn a_local_app_data_that_cannot_be_opened_is_a_note() {
    let sys = layout()
        .known_folder(KnownFolder::LocalAppData, r"C:\Missing\Local")
        .build()
        .unwrap();
    let found = check(&sys, PF86_GAME, &["settings.ini"]);
    assert!(
        matches!(found.as_slice(), [Shadow::Unchecked { root: 0, .. }]),
        "{found:?}"
    );
}
