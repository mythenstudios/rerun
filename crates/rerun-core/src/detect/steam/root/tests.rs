use super::{RootSource, find_root, read_candidate, text_of};
use crate::detect::steam::issue::{BadValue, Issue, IssueKind, Location};
use crate::detect::steam::testfx::{SteamFixture, base, fr};
use crate::path::{PathError, RootPath};
use crate::policy::root::{Forbidden, RootError};
use crate::sys::fake::FakeSystem;
use crate::sys::registry::{RegValue, reg_type};
use crate::sys::{SysErrorKind, System};

use RootSource::{CurrentUser, Machine32, MachineNative};

const STEAM: &str = r"C:\Program Files (x86)\Steam";

fn rp(s: &str) -> RootPath {
    RootPath::new(s).unwrap()
}

/// The root (source and canonical path) and the issues.
fn run(sys: &FakeSystem) -> (Option<(RootSource, RootPath)>, Vec<Issue>) {
    let fr = fr(sys);
    let mut issues = Vec::new();
    let root = find_root(sys, &fr, &mut issues).map(|(s, store)| (s, store.path().clone()));
    (root, issues)
}

fn utf16(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

fn raw(kind: u32, data: &[u8]) -> RegValue {
    RegValue::decode(kind, data)
}

// ---------- Candidates ----------

#[test]
fn the_keys_and_values_are_exactly_the_three_candidates() {
    let shown: Vec<String> = RootSource::ALL
        .iter()
        .map(|s| format!("{} @ {}", s.key(), s.value_name()))
        .collect();
    assert_eq!(
        shown,
        [
            r"HKCU[native]\Software\Valve\Steam @ SteamPath",
            r"HKLM[wow32]\SOFTWARE\Valve\Steam @ InstallPath",
            r"HKLM[native]\SOFTWARE\Valve\Steam @ InstallPath",
        ]
    );
}

#[test]
fn hkcu_steam_path_with_forward_slashes_and_lower_case_is_the_root() {
    let sys = base()
        .dir(STEAM)
        .candidate_path(CurrentUser, "c:/program files (x86)/steam")
        .build()
        .unwrap();
    assert_eq!(run(&sys), (Some((CurrentUser, rp(STEAM))), vec![]));
}

#[test]
fn hklm_is_used_when_hkcu_is_absent() {
    let sys = base()
        .dir(STEAM)
        .candidate_path(Machine32, STEAM)
        .build()
        .unwrap();
    assert_eq!(run(&sys), (Some((Machine32, rp(STEAM))), vec![]));

    let sys = base()
        .dir(STEAM)
        .candidate_path(MachineNative, STEAM)
        .build()
        .unwrap();
    assert_eq!(run(&sys), (Some((MachineNative, rp(STEAM))), vec![]));
}

#[test]
fn the_32_bit_view_is_the_wow6432node_key() {
    // The installer of the 32-bit client writes the redirected key.
    let sys = base()
        .dir(STEAM)
        .value(
            crate::sys::registry::RegKey::new(
                crate::sys::registry::Hive::LocalMachine,
                crate::sys::registry::RegView::Native,
                r"SOFTWARE\WOW6432Node\Valve\Steam",
            ),
            "InstallPath",
            RegValue::String(STEAM.into()),
        )
        .build()
        .unwrap();
    assert_eq!(run(&sys), (Some((Machine32, rp(STEAM))), vec![]));
}

#[test]
fn no_candidate_is_no_root_and_no_issue() {
    let sys = base().build().unwrap();
    assert_eq!(run(&sys), (None, vec![]));
    // The key without the value, and the other value names, do not count either.
    let sys = base()
        .key(CurrentUser.key())
        .value(
            CurrentUser.key(),
            "InstallPath",
            RegValue::String(STEAM.into()),
        )
        .value(Machine32.key(), "SteamPath", RegValue::String(STEAM.into()))
        .dir(STEAM)
        .build()
        .unwrap();
    assert_eq!(run(&sys), (None, vec![]));
}

#[test]
fn candidates_that_agree_are_silent() {
    // Other spelling, and HKLM through a junction to the same folder.
    let sys = base()
        .dir(r"D:\Steam")
        .junction(r"C:\SteamLink", r"D:\Steam")
        .candidate_path(CurrentUser, "d:/steam/")
        .candidate_path(Machine32, r"D:\STEAM")
        .candidate_path(MachineNative, r"C:\SteamLink")
        .build()
        .unwrap();
    assert_eq!(run(&sys), (Some((CurrentUser, rp(r"D:\Steam"))), vec![]));
}

#[test]
fn hkcu_wins_and_a_disagreeing_hklm_is_reported_and_not_used() {
    let sys = base()
        .dir(r"D:\Steam")
        .dir(STEAM)
        .candidate_path(CurrentUser, "d:/steam")
        .candidate_path(Machine32, STEAM)
        .build()
        .unwrap();
    let (root, issues) = run(&sys);
    assert_eq!(root, Some((CurrentUser, rp(r"D:\Steam"))));
    assert_eq!(
        issues,
        [Issue {
            at: Location::Registry(Machine32),
            kind: IssueKind::RootsDisagree {
                winner: CurrentUser,
                root: rp(r"D:\Steam"),
                other: rp(STEAM),
            },
        }]
    );
    assert_eq!(
        issues[0].to_string(),
        r"HKLM\SOFTWARE\Valve\Steam InstallPath (32-bit view): opens C:\Program Files (x86)\Steam, not the Steam root D:\Steam (from HKCU\Software\Valve\Steam SteamPath); not scanned"
    );
}

fn root_err(issue: &Issue) -> &RootError {
    match &issue.kind {
        IssueKind::Root(e) => e.as_ref(),
        other => panic!("expected Root, got {other:?}"),
    }
}

#[test]
fn a_candidate_that_does_not_open_is_reported_and_the_next_is_tried() {
    // HKCU points to a folder that is gone (Steam moved), HKLM to the real one.
    let sys = base()
        .dir(STEAM)
        .candidate_path(CurrentUser, r"D:\Old\Steam")
        .candidate_path(Machine32, STEAM)
        .build()
        .unwrap();
    let (root, issues) = run(&sys);
    assert_eq!(root, Some((Machine32, rp(STEAM))));
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0].at, Location::Registry(CurrentUser));
    assert!(
        matches!(root_err(&issues[0]), RootError::Sys(e) if e.kind == SysErrorKind::NotFound),
        "{issues:?}"
    );
}

#[test]
fn a_stale_hklm_after_the_root_is_found_is_reported_too() {
    let sys = base()
        .dir(STEAM)
        .candidate_path(CurrentUser, STEAM)
        .candidate_path(Machine32, r"E:\Gone")
        .build()
        .unwrap();
    let (root, issues) = run(&sys);
    assert_eq!(root, Some((CurrentUser, rp(STEAM))));
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0].at, Location::Registry(Machine32));
}

#[test]
fn forbidden_network_and_volume_root_candidates_are_refused() {
    let sys = base()
        .mounted_volume(r"D:\Mounts\Steam")
        .dir(STEAM)
        .candidate_path(CurrentUser, r"C:\Windows")
        .candidate_path(Machine32, r"\\server\share\Steam")
        .candidate_path(MachineNative, r"D:\Mounts\Steam")
        .build()
        .unwrap();
    let (root, issues) = run(&sys);
    assert_eq!(root, None);
    assert_eq!(issues.len(), 3, "{issues:?}");
    assert!(matches!(
        root_err(&issues[0]),
        RootError::Forbidden {
            reason: Forbidden::Is(_),
            ..
        }
    ));
    assert!(matches!(
        root_err(&issues[1]),
        RootError::InvalidPath(PathError { .. })
    ));
    assert!(matches!(
        root_err(&issues[2]),
        RootError::Forbidden {
            reason: Forbidden::VolumeRoot,
            ..
        }
    ));
    // A bare drive root and a relative path never get as far as an open.
    for bad in [
        r"D:\",
        "Steam",
        r"..\Steam",
        r"\\?\C:\Steam",
        r"\\.\C:\Steam",
    ] {
        let sys = base().candidate_path(CurrentUser, bad).build().unwrap();
        let (root, issues) = run(&sys);
        assert_eq!(root, None, "{bad}");
        assert!(
            matches!(root_err(&issues[0]), RootError::InvalidPath(_)),
            "{bad}: {issues:?}"
        );
    }
}

#[test]
fn a_denied_key_is_an_issue_and_the_next_candidate_is_tried() {
    let sys = base()
        .dir(STEAM)
        .candidate_path(CurrentUser, r"D:\Elsewhere")
        .denied_key(CurrentUser.key())
        .candidate_path(Machine32, STEAM)
        .build()
        .unwrap();
    let (root, issues) = run(&sys);
    assert_eq!(root, Some((Machine32, rp(STEAM))));
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0].at, Location::Registry(CurrentUser));
    assert!(
        matches!(&issues[0].kind, IssueKind::Sys(e) if e.kind == SysErrorKind::AccessDenied),
        "{issues:?}"
    );
}

// ---------- Values ----------

#[test]
fn string_values() {
    let ok = |v: RegValue| text_of(&v);
    assert_eq!(ok(RegValue::String(STEAM.into())), Ok(STEAM.into()));
    assert_eq!(ok(RegValue::ExpandString(STEAM.into())), Ok(STEAM.into()));
    assert_eq!(ok(RegValue::String(String::new())), Err(BadValue::Empty));
    assert_eq!(
        ok(RegValue::ExpandString(String::new())),
        Err(BadValue::Empty)
    );
    assert_eq!(
        ok(RegValue::ExpandString(r"%ProgramFiles(x86)%\Steam".into())),
        Err(BadValue::Unexpanded)
    );
    // `%` in a plain REG_SZ is a legal folder name character.
    assert_eq!(
        ok(RegValue::String(r"D:\100%\Steam".into())),
        Ok(r"D:\100%\Steam".into())
    );
}

#[test]
fn other_types_are_not_strings() {
    for (v, kind) in [
        (RegValue::Dword(1), reg_type::REG_DWORD),
        (RegValue::Qword(1), reg_type::REG_QWORD),
        (RegValue::Binary(utf16(STEAM)), reg_type::REG_BINARY),
        (
            RegValue::MultiString(vec![STEAM.into()]),
            reg_type::REG_MULTI_SZ,
        ),
        (raw(reg_type::REG_NONE, &utf16(STEAM)), reg_type::REG_NONE),
        (raw(reg_type::REG_LINK, &utf16(STEAM)), reg_type::REG_LINK),
    ] {
        assert_eq!(text_of(&v), Err(BadValue::NotAString { kind }), "{v:?}");
    }
}

#[test]
fn raw_strings_are_read_tolerantly() {
    let mut nul2 = utf16(STEAM);
    nul2.extend([0, 0, 0, 0]);
    for (what, data) in [("no terminator", utf16(STEAM)), ("two NULs", nul2)] {
        for kind in [reg_type::REG_SZ, reg_type::REG_EXPAND_SZ] {
            let v = raw(kind, &data);
            assert!(matches!(v, RegValue::Raw(_)), "{what}");
            assert_eq!(text_of(&v), Ok(STEAM.into()), "{what} ({kind})");
        }
    }
    let mut inner = utf16(r"C:\A");
    inner.extend([0, 0]);
    inner.extend(utf16(r"\B"));
    let mut odd = utf16(STEAM);
    odd.push(0);
    let bad: [(&str, Vec<u8>); 4] = [
        ("NUL inside", inner),
        ("odd length", odd),
        (
            "lone surrogate",
            [0xD800_u16, 0x41]
                .iter()
                .flat_map(|u| u.to_le_bytes())
                .collect(),
        ),
        ("zero length", vec![]),
    ];
    for (what, data) in bad {
        let v = raw(reg_type::REG_SZ, &data);
        let expected = if data.is_empty() {
            BadValue::Empty
        } else {
            BadValue::InvalidString
        };
        assert_eq!(text_of(&v), Err(expected), "{what}");
    }
    // Only NULs: empty.
    assert_eq!(
        text_of(&raw(reg_type::REG_SZ, &[0, 0, 0, 0])),
        Err(BadValue::Empty)
    );
    // A tolerant expandable string with `%` is refused like a canonical one.
    assert_eq!(
        text_of(&raw(reg_type::REG_EXPAND_SZ, &utf16(r"%X%\Steam"))),
        Err(BadValue::Unexpanded)
    );
}

#[test]
fn a_bad_value_is_an_issue_without_the_value_and_nothing_is_opened() {
    const MARK: &str = "SECRETMARKER";
    let sys = base()
        .dir(STEAM)
        .candidate(
            CurrentUser,
            RegValue::ExpandString(format!(r"%{MARK}%\Steam")),
        )
        .candidate(Machine32, RegValue::Dword(7))
        .candidate_path(MachineNative, STEAM)
        .build()
        .unwrap();
    let (root, issues) = run(&sys);
    assert_eq!(root, Some((MachineNative, rp(STEAM))));
    assert_eq!(
        issues,
        [
            Issue {
                at: Location::Registry(CurrentUser),
                kind: IssueKind::RegistryValue(BadValue::Unexpanded),
            },
            Issue {
                at: Location::Registry(Machine32),
                kind: IssueKind::RegistryValue(BadValue::NotAString {
                    kind: reg_type::REG_DWORD
                }),
            },
        ]
    );
    for i in &issues {
        let shown = format!("{i} / {i:?}");
        assert!(!shown.contains(MARK), "{shown}");
    }
    assert_eq!(
        issues[1].to_string(),
        r"HKLM\SOFTWARE\Valve\Steam InstallPath (32-bit view): registry type 4, not a string"
    );
}

#[test]
fn read_candidate_hands_out_raw_text() {
    let sys = base().candidate_path(CurrentUser, STEAM).build().unwrap();
    let t = read_candidate(sys.registry(), CurrentUser)
        .unwrap()
        .unwrap();
    assert_eq!(t.as_raw_str(), STEAM);
    assert_eq!(format!("{t:?}"), "RawText(28 bytes)");
    assert_eq!(read_candidate(sys.registry(), Machine32), Ok(None));
}
