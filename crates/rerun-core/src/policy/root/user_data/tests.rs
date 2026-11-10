//! UD-P (P4-12): the user data root against the fake. The allowlist; the base from the known
//! folder (missing, a share, an 8.3 name, the profile itself, another user's or the `Public`
//! profile, a drive root, a junction at it); the folder below it handle-relative (a junction at
//! `My Games` or at the folder, case-sensitive); both cloud signals (a tag or attribute of the
//! base, a folder on the way or the folder; a registered sync root over the base, lexical and
//! canonical, or over the folder; `SyncRootManager` unreadable or too large; a foreign one); a
//! volume without POSIX semantics; a non-ASCII profile; the control K-U1 (the cloud checks off:
//! the cloud cases open).

use std::path::Path;

use super::super::{Forbidden, ForbiddenRoots, Protected, RootError, RootId};
use super::{
    CloudWhy, MAX_SYNC_PROVIDERS, SYNC_ROOT_MANAGER, UserBase, UserDataDir, UserDirError, knob,
    user_dir_ok,
};
use crate::path::{RelPath, RootPath};
use crate::sys::fake::{FakeSystem, FakeSystemBuilder};
use crate::sys::fs::{FsKind, tag};
use crate::sys::registry::{Hive, RegKey, RegValue, RegView};
use crate::sys::{KnownFolder, SysErrorKind};

const INSTALL: &str = r"C:\Users\Player\AppData\Local\Programs\Rerun";
const DOCS: &str = r"C:\Users\Player\Documents";
const SUB: &str = r"My Games\G";

fn rel(s: &str) -> RelPath {
    RelPath::parse(s).unwrap()
}

/// The Windows layout with `Documents\My Games\G`.
fn base() -> FakeSystemBuilder {
    FakeSystem::builder()
        .windows_layout()
        .dir(INSTALL)
        .dir(format!(r"{DOCS}\{SUB}"))
}

fn fr(sys: &FakeSystem) -> ForbiddenRoots {
    ForbiddenRoots::resolve(sys, Path::new(INSTALL)).unwrap()
}

fn open<'s>(sys: &'s FakeSystem, sub: &str) -> Result<UserDataDir<'s>, RootError> {
    UserDataDir::open(sys, &fr(sys), UserBase::Documents, &rel(sub))
}

/// The write handle, as `exec` gets it.
#[expect(
    clippy::disallowed_methods,
    reason = "test: the write side of a user data folder as exec sees it"
)]
fn write_side<'u>(u: &'u UserDataDir<'_>) -> crate::sys::SysResult<&'u dyn crate::sys::DirWrite> {
    u.dir_write()
}

fn sync_key(provider: &str) -> RegKey {
    RegKey::new(
        Hive::LocalMachine,
        RegView::Native,
        format!(r"{SYNC_ROOT_MANAGER}\{provider}\UserSyncRoots"),
    )
}

/// A registered sync root at `path`.
fn synced(b: FakeSystemBuilder, path: &str) -> FakeSystemBuilder {
    b.value(
        sync_key("OneDrive!S-1-5-21-1-2-3-1001!Personal"),
        "S-1-5-21-1-2-3-1001",
        RegValue::String(path.to_owned()),
    )
}

fn sys_kind(r: Result<UserDataDir<'_>, RootError>) -> SysErrorKind {
    match r {
        Err(RootError::Sys(e)) => e.kind,
        other => panic!("expected Sys, got {other:?}"),
    }
}

fn cloud(r: Result<UserDataDir<'_>, RootError>) -> CloudWhy {
    match r {
        Err(RootError::CloudSynced { why, .. }) => why,
        other => panic!("expected CloudSynced, got {other:?}"),
    }
}

#[test]
fn ud_p1_the_allowlist() {
    let d = UserBase::Documents;
    for ok in [
        r"My Games\Fallout3",
        "Fallout3",
        r"My Games\G\Saves",
        r"a\b\c\d",
        r"Rockstar Games\GTA IV",
    ] {
        assert_eq!(user_dir_ok(d, &rel(ok)), Ok(()), "{ok}");
    }
    for (bad, want) in [
        ("My Games", UserDirError::SharedContainer),
        ("my games", UserDirError::SharedContainer),
        (r"a\b\c\d\e", UserDirError::TooDeep),
    ] {
        assert_eq!(user_dir_ok(d, &rel(bad)), Err(want), "{bad}");
    }
    for bad in [
        "WindowsPowerShell",
        r"WindowsPowerShell\Modules",
        r"powershell\x",
        // Review M1: Rainmeter's skin INIs run commands.
        r"Rainmeter\Skins\x",
        "rainmeter",
    ] {
        assert!(
            matches!(user_dir_ok(d, &rel(bad)), Err(UserDirError::Denied(_))),
            "{bad}"
        );
    }
    // A replacement character is no plain name.
    assert!(matches!(
        user_dir_ok(d, &rel("G\u{FFFD}")),
        Err(UserDirError::Denied(_))
    ));
    // `open` checks it first, before anything is opened.
    let sys = base().build().unwrap();
    assert!(matches!(
        open(&sys, "My Games"),
        Err(RootError::UserDir {
            why: UserDirError::SharedContainer,
            ..
        })
    ));
}

#[test]
fn ud_p2_opens_the_folder_below_documents() {
    let sys = base().build().unwrap();
    let u = open(&sys, SUB).unwrap();
    assert_eq!(*u.path(), RootPath::new(format!(r"{DOCS}\{SUB}")).unwrap());
    assert_eq!(u.base(), UserBase::Documents);
    assert_eq!(u.sub().as_str(), SUB);
    assert!(u.ensure_id(u.id()).is_ok());
    let other = RootId {
        volume_serial: u.id().volume_serial,
        file_id: u.id().file_id + 1,
    };
    assert!(matches!(
        u.ensure_id(other),
        Err(RootError::IdentityMismatch { .. })
    ));
    assert!(write_side(&u).is_ok());
    // The spelling of the Topo stays the plan's `sub`; the path is the canonical one.
    let u = open(&sys, r"my games\g").unwrap();
    assert_eq!(u.sub().as_str(), r"my games\g");
    assert_eq!(u.path().to_string(), format!(r"{DOCS}\{SUB}"));
}

#[test]
fn ud_p3_a_missing_base_or_folder_is_not_found() {
    let sys = base().build().unwrap();
    // A missing folder names the canonical base (exec tells a moved Documents from it).
    match open(&sys, r"My Games\Other") {
        Err(RootError::UserDirMissing { base, sub }) => {
            assert_eq!(base.to_string(), DOCS);
            assert_eq!(sub.as_str(), r"My Games\Other");
        }
        other => panic!("{other:?}"),
    }
    let sys = base()
        .without_known_folder(KnownFolder::Documents)
        .build()
        .unwrap();
    assert_eq!(sys_kind(open(&sys, SUB)), SysErrorKind::NotFound);
    let sys = FakeSystem::builder()
        .known_folder(KnownFolder::Documents, r"D:\NoDocs")
        .windows_layout()
        .dir(INSTALL)
        .build()
        .unwrap();
    // `windows_layout` made `D:\NoDocs`, but not the folder below it.
    assert!(matches!(
        open(&sys, SUB),
        Err(RootError::UserDirMissing { .. })
    ));
}

#[test]
fn ud_p4_a_base_that_is_no_plain_own_folder_is_refused() {
    // A share, an 8.3 name, a drive root: lexically.
    for docs in [
        r"\\server\home\Player\Documents",
        r"C:\Users\PLAYER~1\Documents",
        r"D:\",
    ] {
        let sys = base()
            .known_folder(KnownFolder::Documents, docs)
            .build()
            .unwrap();
        assert!(
            matches!(open(&sys, SUB), Err(RootError::InvalidPath(_))),
            "{docs}: {:?}",
            open(&sys, SUB)
        );
    }
    // Documents is the profile itself, another user's or the Public one.
    for (docs, want) in [
        (
            r"C:\Users\Player",
            Forbidden::Is(Protected::Known(KnownFolder::Profile)),
        ),
        (r"C:\Users\Public\Documents", Forbidden::OtherUserProfile),
        (r"C:\Users\Other\Documents", Forbidden::OtherUserProfile),
    ] {
        let sys = base()
            .known_folder(KnownFolder::Documents, docs)
            .dir(format!(r"{docs}\{SUB}"))
            .build()
            .unwrap();
        match open(&sys, SUB) {
            Err(RootError::Forbidden { reason, .. }) => assert_eq!(reason, want, "{docs}"),
            other => panic!("{docs}: {other:?}"),
        }
    }
    // A junction at Documents into another profile: refused on its canonical path.
    let sys = base()
        .dir(format!(r"C:\Users\Other\Documents\{SUB}"))
        .junction(r"C:\Users\Player\Docs2", r"C:\Users\Other\Documents")
        .known_folder(KnownFolder::Documents, r"C:\Users\Player\Docs2")
        .build()
        .unwrap();
    match open(&sys, SUB) {
        Err(RootError::Forbidden { reason, path }) => {
            assert_eq!(reason, Forbidden::OtherUserProfile);
            assert_eq!(path.to_string(), r"C:\Users\Other\Documents");
        }
        other => panic!("{other:?}"),
    }
    // A volume folder.
    let sys = base()
        .known_folder(KnownFolder::Documents, r"D:\$Recycle.Bin\Docs")
        .build()
        .unwrap();
    assert!(matches!(
        open(&sys, SUB),
        Err(RootError::Forbidden {
            reason: Forbidden::VolumeFolder(_),
            ..
        })
    ));
}

#[test]
fn ud_p5_a_junction_at_documents_is_followed_one_below_is_refused() {
    // Documents moved to D: and linked back: the canonical path counts.
    let sys = base()
        .dir(format!(r"D:\Docs\{SUB}"))
        .junction(r"C:\Users\Player\MovedDocs", r"D:\Docs")
        .known_folder(KnownFolder::Documents, r"C:\Users\Player\MovedDocs")
        .build()
        .unwrap();
    let u = open(&sys, SUB).unwrap();
    assert_eq!(u.path().to_string(), format!(r"D:\Docs\{SUB}"));
    // A junction at `My Games`, at the folder: never followed.
    for (link, target) in [
        (format!(r"{DOCS}\My Games"), r"D:\Elsewhere"),
        (format!(r"{DOCS}\My Games\J"), r"D:\Elsewhere\J"),
    ] {
        let sys = FakeSystem::builder()
            .windows_layout()
            .dir(INSTALL)
            .dir(r"D:\Elsewhere\J")
            .dir(format!(r"{DOCS}\Other"))
            .junction(&link, target)
            .build()
            .unwrap();
        assert!(
            matches!(open(&sys, r"My Games\J"), Err(RootError::Reparse { .. })),
            "{link}: {:?}",
            open(&sys, r"My Games\J")
        );
    }
}

#[test]
fn ud_p6_a_cloud_tag_or_attribute_on_the_way_is_refused() {
    for (at, attr) in [
        (DOCS.to_owned(), false),
        (format!(r"{DOCS}\My Games"), false),
        (format!(r"{DOCS}\{SUB}"), false),
        (DOCS.to_owned(), true),
        (format!(r"{DOCS}\{SUB}"), true),
    ] {
        let sys = base().build().unwrap();
        if attr {
            sys.fake_fs().set_cloud_attrs(Path::new(&at), true).unwrap();
        } else {
            sys.fake_fs()
                .set_dir_tag(Path::new(&at), tag::CLOUD | 0x1000)
                .unwrap();
        }
        assert_eq!(
            cloud(open(&sys, SUB)),
            CloudWhy::Folder(RootPath::new(&at).unwrap()),
            "{at} attr {attr}"
        );
    }
}

#[test]
fn ud_p7_a_registered_sync_root_over_it_is_refused() {
    // Over Documents (lexical form), over the folder only, over the canonical form.
    for (sr, want) in [
        (r"C:\Users\Player", DOCS.to_owned()),
        (DOCS, DOCS.to_owned()),
        (
            r"C:\Users\Player\Documents\My Games",
            format!(r"{DOCS}\{SUB}"),
        ),
    ] {
        let sys = synced(base(), sr).build().unwrap();
        match open(&sys, SUB) {
            Err(RootError::CloudSynced { path, why }) => {
                assert_eq!(path.to_string(), want, "{sr}");
                assert_eq!(why, CloudWhy::SyncRoot(sr.to_owned()));
            }
            other => panic!("{sr}: {other:?}"),
        }
    }
    let moved = || {
        base()
            .dir(format!(r"D:\OneDrive\Documents\{SUB}"))
            .junction(r"C:\Users\Player\Docs2", r"D:\OneDrive\Documents")
            .known_folder(KnownFolder::Documents, r"C:\Users\Player\Docs2")
    };
    let sys = synced(moved(), r"D:\OneDrive").build().unwrap();
    assert_eq!(
        cloud(open(&sys, SUB)),
        CloudWhy::SyncRoot(r"D:\OneDrive".to_owned())
    );
    // The `\\?\` form a provider may write counts as well.
    let sys = synced(moved(), r"\\?\D:\OneDrive").build().unwrap();
    assert!(matches!(
        open(&sys, SUB),
        Err(RootError::CloudSynced { .. })
    ));
    // Review L1: a text on the drive that is no plain folder counts as the whole drive (the
    // drive root, an 8.3 name, a deceptive character, too long); a volume or device path and a
    // relative text as everywhere: all refuse (fail closed).
    let on_d = || {
        base()
            .known_folder(KnownFolder::Documents, r"D:\Documents")
            .dir(format!(r"D:\Documents\{SUB}"))
    };
    let long = format!(r"D:\{}", "x".repeat(300));
    for sr in [
        r"D:\",
        r"d:",
        r"D:\ONEDRI~1",
        "D:\\One\u{202E}Drive",
        long.as_str(),
        r"\\?\Volume{12345678-1234-1234-1234-123456789abc}\OneDrive",
        r"\\.\HarddiskVolume3\OneDrive",
        "OneDrive",
    ] {
        let sys = synced(on_d(), sr).build().unwrap();
        assert!(
            matches!(open(&sys, SUB), Err(RootError::CloudSynced { .. })),
            "{sr:?}: {:?}",
            open(&sys, SUB)
        );
    }
    // A text on another drive that is no plain folder: that drive only.
    let sys = synced(on_d(), r"E:\").build().unwrap();
    assert!(open(&sys, SUB).is_ok());
    // The displayed text is escaped.
    let sys = synced(on_d(), "D:\\One\u{202E}Drive").build().unwrap();
    match cloud(open(&sys, SUB)) {
        CloudWhy::SyncRoot(t) => assert!(!t.contains('\u{202E}'), "{t:?}"),
        other => panic!("{other:?}"),
    }
    // A sync root elsewhere, a value of another type, a share: no reason to refuse.
    let sys = synced(on_d(), r"\\?\UNC\server\share\OneDrive")
        .build()
        .unwrap();
    assert!(open(&sys, SUB).is_ok());
    let sys = synced(base(), r"C:\Users\Player\OneDrive")
        .value(
            sync_key("Dropbox!S-1-5-21-1-2-3-1001!x"),
            "a",
            RegValue::Dword(1),
        )
        .value(
            sync_key("Box!S-1-5-21-1-2-3-1001!x"),
            "b",
            RegValue::String(r"\\server\box".into()),
        )
        .key(RegKey::new(
            Hive::LocalMachine,
            RegView::Native,
            format!(r"{SYNC_ROOT_MANAGER}\NoRoots"),
        ))
        .build()
        .unwrap();
    assert!(open(&sys, SUB).is_ok());
    // Unreadable: refused (fail closed).
    let sys = base()
        .denied_key(RegKey::new(
            Hive::LocalMachine,
            RegView::Native,
            SYNC_ROOT_MANAGER,
        ))
        .build()
        .unwrap();
    assert_eq!(sys_kind(open(&sys, SUB)), SysErrorKind::AccessDenied);
    // More provider keys than the bound: refused.
    let mut b = base();
    for i in 0..=MAX_SYNC_PROVIDERS {
        b = b.key(RegKey::new(
            Hive::LocalMachine,
            RegView::Native,
            format!(r"{SYNC_ROOT_MANAGER}\P{i}"),
        ));
    }
    let sys = b.build().unwrap();
    assert_eq!(sys_kind(open(&sys, SUB)), SysErrorKind::TooLarge);
}

#[test]
fn ud_p8_case_sensitive_not_writable_and_without_posix_semantics() {
    for at in [
        DOCS.to_owned(),
        format!(r"{DOCS}\My Games"),
        format!(r"{DOCS}\{SUB}"),
    ] {
        // Case-sensitive while still empty, then filled.
        let sys = FakeSystem::builder()
            .windows_layout()
            .dir(INSTALL)
            .case_sensitive_dir(&at)
            .dir(format!(r"{DOCS}\{SUB}"))
            .build()
            .unwrap();
        assert!(
            matches!(open(&sys, SUB), Err(RootError::Anomaly(_))),
            "{at}: {:?}",
            open(&sys, SUB)
        );
    }
    let sys = base().build().unwrap();
    sys.fake_fs()
        .set_user_writable(Path::new(&format!(r"{DOCS}\{SUB}")), false)
        .unwrap();
    assert_eq!(sys_kind(open(&sys, SUB)), SysErrorKind::AccessDenied);
    // Documents on an exFAT drive: opened, but never written.
    let sys = base()
        .known_folder(KnownFolder::Documents, r"E:\Docs")
        .dir(format!(r"E:\Docs\{SUB}"))
        .build()
        .unwrap();
    sys.fake_fs().set_fs_kind('E', FsKind::ExFat);
    let u = open(&sys, SUB).unwrap();
    assert_eq!(
        write_side(&u).map(|_| ()).unwrap_err().kind,
        SysErrorKind::Unsupported
    );
}

#[test]
fn ud_p9_a_non_ascii_profile() {
    for name in ["J\u{fc}rgen", "Y\u{131}lmaz"] {
        let profile = format!(r"C:\Users\{name}");
        let sys = FakeSystem::builder()
            .known_folder(KnownFolder::Profile, &profile)
            .known_folder(
                KnownFolder::LocalAppData,
                format!(r"{profile}\AppData\Local"),
            )
            .known_folder(
                KnownFolder::RoamingAppData,
                format!(r"{profile}\AppData\Roaming"),
            )
            .known_folder(KnownFolder::Documents, format!(r"{profile}\Documents"))
            .windows_layout()
            .dir(format!(r"{profile}\Documents\{SUB}"))
            .dir(INSTALL)
            .build()
            .unwrap();
        let u = open(&sys, SUB).unwrap();
        assert_eq!(u.path().to_string(), format!(r"{profile}\Documents\{SUB}"));
        let again = open(&sys, SUB).unwrap();
        assert_eq!(again.id(), u.id());
    }
}

/// K-U1: with both cloud checks off, every cloud case of UD-P6 and UD-P7 opens: the checks
/// are what refuses them.
#[test]
fn k_u1_the_cloud_checks_off_let_the_cloud_cases_through() {
    struct Off;
    impl Drop for Off {
        fn drop(&mut self) {
            knob::uncheck_cloud(false);
        }
    }
    let _off = Off;
    knob::uncheck_cloud(true);
    let sys = base().build().unwrap();
    sys.fake_fs()
        .set_dir_tag(Path::new(DOCS), tag::CLOUD)
        .unwrap();
    sys.fake_fs()
        .set_cloud_attrs(Path::new(&format!(r"{DOCS}\{SUB}")), true)
        .unwrap();
    assert!(open(&sys, SUB).is_ok());
    let sys = synced(base(), r"C:\Users\Player").build().unwrap();
    assert!(open(&sys, SUB).is_ok());
}
