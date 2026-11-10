//! `admin_only`, `helper_image` and `dir_by_id` against the fake (ADR 0023 §2, A4 N1, S1).

use std::path::Path;

use super::{ADMIN_SIDS, NotAdminOnly, WRITE_MASK, admin_only, dir_by_id, helper_image};
use crate::path::RelPath;
use crate::policy::root::RootError;
use crate::sys::fake::{FAKE_USER_SID, FakeSd, FakeSystem};
use crate::sys::fs::{AceFact, EntryKind, FsKind, SdFacts, ace};
use crate::sys::{KnownFolder, SysErrorKind, System};

const PF: &str = r"C:\Program Files";
const DIR: &str = r"C:\Program Files\Rerun";
const EXE: &str = r"C:\Program Files\Rerun\rerun-helper.exe";
const USERS: &str = "S-1-5-32-545";

fn facts(owner: Option<&str>, dacl: Option<Vec<AceFact>>) -> SdFacts {
    SdFacts {
        kind: EntryKind::Dir,
        links: 1,
        owner: owner.map(str::to_owned),
        dacl,
        persistent_acls: true,
        nt_name: None,
    }
}

fn entry(ace_type: u8, flags: u8, mask: u32, sid: Option<&str>) -> AceFact {
    AceFact {
        ace_type,
        flags,
        mask,
        sid: sid.map(str::to_owned),
    }
}

#[test]
fn admin_only_rule() {
    let admin = Some("S-1-5-32-544");
    let full = 0x001F_01FF;
    // Every admin SID may own and write.
    for sid in ADMIN_SIDS {
        let f = facts(
            Some(sid),
            Some(vec![entry(ace::ALLOWED, 0, full, Some(sid))]),
        );
        assert_eq!(admin_only(&f), Ok(()));
    }
    // Read and execute for Users, a deny ACE, an inherit-only CREATOR OWNER and an
    // inherit-only callback ACE are fine; so is an empty DACL.
    let ok = facts(
        admin,
        Some(vec![
            entry(ace::ALLOWED, 0, 0x0012_00A9, Some(USERS)),
            entry(ace::DENIED, 0, full, Some(USERS)),
            entry(
                ace::ALLOWED,
                ace::INHERIT_ONLY | 0x3,
                0x1000_0000,
                Some("S-1-3-0"),
            ),
            entry(ace::ALLOWED_CALLBACK, ace::INHERIT_ONLY, full, Some(USERS)),
        ]),
    );
    assert_eq!(admin_only(&ok), Ok(()));
    assert_eq!(admin_only(&facts(admin, Some(vec![]))), Ok(()));
    // Each bit of the write mask alone makes a writer, any other bit does not.
    for bit in (0..32).map(|b| 1u32 << b) {
        let f = facts(admin, Some(vec![entry(ace::ALLOWED, 0, bit, Some(USERS))]));
        let expected = if bit & WRITE_MASK != 0 {
            Err(NotAdminOnly::Writer {
                sid: USERS.to_owned(),
                mask: bit,
            })
        } else {
            Ok(())
        };
        assert_eq!(admin_only(&f), expected, "{bit:#x}");
    }
    assert_eq!(WRITE_MASK.count_ones(), 10);
    // Owner, no owner, NULL DACL, no ACLs.
    assert_eq!(
        admin_only(&facts(Some(FAKE_USER_SID), Some(vec![]))),
        Err(NotAdminOnly::Owner(FAKE_USER_SID.to_owned()))
    );
    assert_eq!(
        admin_only(&facts(None, Some(vec![]))),
        Err(NotAdminOnly::NoOwner)
    );
    assert_eq!(admin_only(&facts(admin, None)), Err(NotAdminOnly::NullDacl));
    let mut no_acls = facts(admin, Some(vec![]));
    no_acls.persistent_acls = false;
    assert_eq!(admin_only(&no_acls), Err(NotAdminOnly::NoAcls));
    // Allow ACEs that cannot be judged fail closed, even for an admin SID.
    for t in [
        ace::ALLOWED_CALLBACK,
        ace::ALLOWED_OBJECT,
        ace::ALLOWED_CALLBACK_OBJECT,
        0x11,
        0x7F,
    ] {
        let f = facts(admin, Some(vec![entry(t, 0, 0x1, Some(ADMIN_SIDS[0]))]));
        assert_eq!(
            admin_only(&f),
            Err(NotAdminOnly::Unjudgeable { ace_type: t })
        );
    }
    let f = facts(admin, Some(vec![entry(ace::ALLOWED, 0, 0x1, None)]));
    assert!(matches!(
        admin_only(&f),
        Err(NotAdminOnly::Unjudgeable { .. })
    ));
    // The message names the SID (A4 N1).
    let f = facts(admin, Some(vec![entry(ace::ALLOWED, 0, 0x2, Some(USERS))]));
    assert!(admin_only(&f).unwrap_err().to_string().contains(USERS));
}

fn set_admin_only(sys: &FakeSystem, paths: &[&str]) {
    for p in paths {
        sys.fake_fs()
            .set_sd(Path::new(p), FakeSd::admin_only())
            .unwrap();
    }
}

/// `Program Files`, `Rerun` and the helper, all admin-only.
fn installed() -> FakeSystem {
    let sys = FakeSystem::builder()
        .file(EXE, b"MZ helper".to_vec())
        .build()
        .unwrap();
    set_admin_only(&sys, &[PF, DIR, EXE]);
    sys
}

fn reason<T: std::fmt::Debug>(r: Result<T, RootError>) -> (String, String) {
    match r {
        Err(RootError::HelperUnsafe { path, reason }) => (path.to_string(), reason),
        other => panic!("expected HelperUnsafe, got {other:?}"),
    }
}

#[test]
fn helper_image_accepts_an_admin_only_install() {
    let sys = installed();
    let image = helper_image(&sys).unwrap();
    assert_eq!(image.path.to_string(), EXE);
    // The NT name of the same object (the fake's device name for drive C:).
    assert!(
        image
            .nt_name
            .ends_with(r"\Program Files\Rerun\rerun-helper.exe"),
        "{}",
        image.nt_name
    );
    assert!(image.nt_name.starts_with(r"\Device\"), "{}", image.nt_name);
}

#[test]
fn helper_image_refuses_anything_a_user_could_change() {
    // Not installed: the folder, then the file.
    let sys = FakeSystem::builder().dir(PF).build().unwrap();
    set_admin_only(&sys, &[PF]);
    assert_eq!(
        reason(helper_image(&sys)),
        (DIR.to_owned(), "not installed".to_owned())
    );
    let sys = FakeSystem::builder().dir(DIR).build().unwrap();
    set_admin_only(&sys, &[PF, DIR]);
    assert_eq!(
        reason(helper_image(&sys)),
        (EXE.to_owned(), "not installed".to_owned())
    );

    // Each of the three objects owned by the user.
    for p in [PF, DIR, EXE] {
        let sys = installed();
        let user_owned = FakeSd {
            owner: Some(FAKE_USER_SID.to_owned()),
            dacl: Some(vec![]),
        };
        sys.fake_fs().set_sd(Path::new(p), user_owned).unwrap();
        let (at, why) = reason(helper_image(&sys));
        assert_eq!(at, p);
        assert!(why.contains(FAKE_USER_SID), "{why}");
    }
    // Users with delete-child on Program Files (A4 N1), with write on the folder and the file.
    for (p, mask) in [(PF, 0x40), (DIR, 0x2), (EXE, 0x4000_0000)] {
        let sys = installed();
        let mut sd = FakeSd::admin_only();
        if let Some(d) = sd.dacl.as_mut() {
            d.push(FakeSd::allow(USERS, mask));
        }
        sys.fake_fs().set_sd(Path::new(p), sd).unwrap();
        let (at, why) = reason(helper_image(&sys));
        assert_eq!(at, p);
        assert!(why.contains(USERS), "{why}");
    }
    // A NULL DACL on the file.
    let sys = installed();
    let null = FakeSd {
        owner: Some(ADMIN_SIDS[0].to_owned()),
        dacl: None,
    };
    sys.fake_fs().set_sd(Path::new(EXE), null).unwrap();
    assert!(reason(helper_image(&sys)).1.contains("NULL DACL"));
}

#[test]
fn helper_image_refuses_links_and_linked_files() {
    // `Rerun` is a junction to an admin-only folder elsewhere.
    let sys = FakeSystem::builder()
        .dir(PF)
        .file(r"C:\Elsewhere\rerun-helper.exe", b"MZ".to_vec())
        .junction(DIR, r"C:\Elsewhere")
        .build()
        .unwrap();
    set_admin_only(
        &sys,
        &[PF, DIR, r"C:\Elsewhere", r"C:\Elsewhere\rerun-helper.exe"],
    );
    let (at, why) = reason(helper_image(&sys));
    assert_eq!(at, DIR);
    assert!(why.contains("reparse"), "{why}");

    // The helper is a symbolic link.
    let sys = FakeSystem::builder()
        .dir(DIR)
        .file_symlink(EXE, r"C:\Elsewhere\x.exe")
        .build()
        .unwrap();
    set_admin_only(&sys, &[PF, DIR, EXE]);
    assert!(reason(helper_image(&sys)).1.contains("reparse"));

    // A second hard link (the content could be changed through the other name).
    let sys = installed();
    sys.fake_fs()
        .put_hardlink(Path::new(EXE), Path::new(r"C:\Users\Public\h.exe"))
        .unwrap();
    assert!(reason(helper_image(&sys)).1.contains("2 hard links"));

    // A folder named rerun-helper.exe.
    let sys = FakeSystem::builder().dir(EXE).build().unwrap();
    set_admin_only(&sys, &[PF, DIR, EXE]);
    assert!(reason(helper_image(&sys)).1.contains("not a file"));
}

#[test]
fn helper_image_needs_acls_and_the_known_folder() {
    let sys = installed();
    sys.fake_fs().set_fs_kind('C', FsKind::Fat);
    assert!(
        reason(helper_image(&sys))
            .1
            .contains("FILE_PERSISTENT_ACLS")
    );
    // No Program Files known folder: a system error, never a guess.
    let sys = FakeSystem::builder()
        .without_known_folder(KnownFolder::ProgramFiles)
        .build()
        .unwrap();
    assert!(matches!(helper_image(&sys), Err(RootError::Sys(_))));
}

fn kind<T>(r: Result<T, RootError>) -> SysErrorKind {
    match r {
        Err(RootError::Sys(e)) => e.kind,
        Err(e) => panic!("{e}"),
        Ok(_) => panic!("opened"),
    }
}

#[test]
fn dir_by_id_opens_only_plain_directories_of_that_volume() {
    let base = r"C:\Users\u\AppData\Local\Rerun";
    let sys = FakeSystem::builder()
        .dir(format!(r"{base}\elevate"))
        .file(format!(r"{base}\x.txt"), b"x".to_vec())
        .junction(format!(r"{base}\j"), r"C:\Windows")
        .dir(r"D:\Other")
        .build()
        .unwrap();
    #[expect(
        clippy::disallowed_methods,
        reason = "test: open the folders to learn their identity"
    )]
    let rerun = sys.fs().open_dir(Path::new(base)).unwrap();
    let rel = |s: &str| RelPath::parse(s).unwrap();
    let elevate = rerun.open_dir(&rel("elevate")).unwrap();
    let info = elevate.info().unwrap();
    let guid = info.volume_guid.unwrap();
    assert!(info.supports_open_by_id && info.persistent_acls);

    let d = dir_by_id(&sys, &guid, info.file_id).unwrap();
    assert_eq!(d.info().unwrap().final_path, info.final_path);
    // The object, not the name: after a rename it is still found.
    drop((d, elevate));
    sys.rename_abs(format!(r"{base}\elevate"), format!(r"{base}\moved"))
        .unwrap();
    let d = dir_by_id(&sys, &guid, info.file_id).unwrap();
    assert!(d.info().unwrap().final_path.ends_with("moved"));

    let file_id = rerun.metadata(&rel("x.txt")).unwrap().unwrap().file_id;
    let link_id = rerun.metadata(&rel("j")).unwrap().unwrap().file_id;
    assert_eq!(
        kind(dir_by_id(&sys, &guid, file_id)),
        SysErrorKind::InvalidPath
    );
    assert_eq!(
        kind(dir_by_id(&sys, &guid, link_id)),
        SysErrorKind::ReparsePoint
    );
    assert_eq!(
        kind(dir_by_id(&sys, &guid, 0xFFFF_FFFF)),
        SysErrorKind::NotFound
    );
    assert_eq!(
        kind(dir_by_id(&sys, &guid, u128::MAX)),
        SysErrorKind::NotFound
    );
    // The same ID on another volume names nothing.
    #[expect(
        clippy::disallowed_methods,
        reason = "test: the other volume's identity"
    )]
    let other = sys
        .fs()
        .open_dir(Path::new(r"D:\Other"))
        .unwrap()
        .info()
        .unwrap();
    let d_guid = other.volume_guid.unwrap();
    assert_ne!(d_guid, guid);
    assert_eq!(
        kind(dir_by_id(&sys, &d_guid, info.file_id)),
        SysErrorKind::NotFound
    );
    // exFAT cannot open by ID.
    sys.fake_fs().set_fs_kind('D', FsKind::ExFat);
    assert_eq!(
        kind(dir_by_id(&sys, &d_guid, other.file_id)),
        SysErrorKind::Unsupported
    );
}

/// Security N5 of P4-2c: a helper built with the published index test key is refused for a
/// release CLI and accepted by a test-key CLI; the seed the check looks for is exactly the test
/// key's (masked in the binary, so a release CLI never holds it).
#[test]
fn a_test_key_helper_is_refused_unless_the_cli_is_a_test_build() {
    use super::{check_test_key, holds_test_key};
    use crate::catalog::key::test_key;
    assert!(holds_test_key(test_key::SEED_HEX.as_bytes()));
    assert!(!holds_test_key(test_key::FOREIGN_SEED_HEX.as_bytes()));
    let sys = installed();
    let image = helper_image(&sys).unwrap();
    check_test_key(&sys, &image, false).unwrap();
    // The seed somewhere inside the image, as a test-key build holds it.
    let mut bytes = b"MZ helper ".to_vec();
    bytes.extend_from_slice(test_key::SEED_HEX.as_bytes());
    bytes.extend_from_slice(b" more");
    sys.fake_fs().remove_abs(Path::new(EXE)).unwrap();
    sys.fake_fs().put_file(Path::new(EXE), &bytes).unwrap();
    set_admin_only(&sys, &[EXE]);
    let image = helper_image(&sys).unwrap();
    let (path, why) = reason(check_test_key(&sys, &image, false));
    assert_eq!(path, EXE);
    assert!(why.contains("test key"), "{why}");
    check_test_key(&sys, &image, true).unwrap();
    // The product entry answers for this build.
    assert_eq!(
        super::helper_for_this_build(&sys).is_ok(),
        cfg!(feature = "test-key")
    );
}
