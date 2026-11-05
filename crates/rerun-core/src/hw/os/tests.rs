//! `hw::os` against the fake registry.

use super::*;
use crate::sys::SysErrorKind;
use crate::sys::System;
use crate::sys::fake::FakeSystem;
use crate::sys::registry::reg_type;

const SRC: ProfileSource = ProfileSource::CurrentBuildNumber;

fn read_with(value: RegValue) -> Result<OsBuild, ProfileError> {
    let sys = FakeSystem::builder()
        .value(current_version_key(), BUILD_VALUE, value)
        .build()
        .unwrap();
    read(sys.registry())
}

fn read_sz(s: &str) -> Result<OsBuild, ProfileError> {
    read_with(RegValue::String(s.to_owned()))
}

#[test]
fn builds_and_ubr_from_the_builder() {
    for (build, ubr) in [(26300, Some(1000)), (22631, Some(4890)), (20348, None)] {
        let sys = FakeSystem::builder().os_build(build, ubr).build().unwrap();
        assert_eq!(read(sys.registry()), Ok(OsBuild { build, ubr }));
    }
    let b = OsBuild {
        build: 26100,
        ubr: Some(4061),
    };
    assert_eq!(b.to_string(), "26100.4061");
    assert_eq!(OsBuild { ubr: None, ..b }.to_string(), "26100");
}

#[test]
fn build_number_parse_cases() {
    for (s, build) in [
        ("1", 1),
        ("20348", 20348),
        ("22000", 22000),
        ("26300", 26300),
        ("4294967295", u32::MAX),
    ] {
        assert_eq!(read_sz(s), Ok(OsBuild { build, ubr: None }), "{s:?}");
    }
    for s in [
        "",
        "0",
        "00",
        "022631",
        " 22631",
        "22631 ",
        "22631\t",
        "+22631",
        "-1",
        "22631.1",
        "22,631",
        "0x5867",
        "4294967296",
        "99999999999999999999",
        "\u{FF12}\u{FF12}\u{FF16}\u{FF13}\u{FF11}",
        "\u{0662}\u{0662}",
        "22631\u{200E}",
    ] {
        assert_eq!(read_sz(s), Err(ProfileError::Malformed(SRC)), "{s:?}");
    }
}

#[test]
fn other_value_types_are_malformed() {
    for v in [
        RegValue::Dword(22631),
        RegValue::Qword(22631),
        RegValue::ExpandString("22631".to_owned()),
        RegValue::MultiString(vec!["22631".to_owned()]),
        RegValue::Binary(b"22631".to_vec()),
        // REG_SZ bytes without the terminating NUL: Raw.
        RegValue::decode(reg_type::REG_SZ, &[b'2', 0, b'2', 0]),
        RegValue::decode(reg_type::REG_NONE, &[]),
    ] {
        assert_eq!(
            read_with(v.clone()),
            Err(ProfileError::Malformed(SRC)),
            "{v:?}"
        );
    }
}

#[test]
fn missing_value_key_and_denied_key() {
    // The key exists, the value does not.
    let sys = FakeSystem::builder()
        .key(current_version_key())
        .build()
        .unwrap();
    assert_eq!(read(sys.registry()), Err(ProfileError::Missing(SRC)));
    // No key at all: the system error is kept.
    let sys = FakeSystem::new();
    let e = read(sys.registry()).unwrap_err();
    assert!(
        matches!(&e, ProfileError::Sys(SRC, s) if s.kind == SysErrorKind::NotFound),
        "{e:?}"
    );
    // A key the user may not read.
    let sys = FakeSystem::builder()
        .os_build(26300, Some(1))
        .denied_key(current_version_key())
        .build()
        .unwrap();
    let e = read(sys.registry()).unwrap_err();
    assert!(
        matches!(&e, ProfileError::Sys(SRC, s) if s.kind == SysErrorKind::AccessDenied),
        "{e:?}"
    );
}

/// The native view: a value only in the 32-bit view (`WOW6432Node`) is not seen.
#[test]
fn only_the_native_view_counts() {
    let wow = RegKey::new(Hive::LocalMachine, RegView::Wow32, CURRENT_VERSION);
    let sys = FakeSystem::builder()
        .value(wow, BUILD_VALUE, RegValue::String("22631".to_owned()))
        .build()
        .unwrap();
    assert!(read(sys.registry()).is_err());
}

#[test]
fn ubr_never_fails_the_build() {
    let base = || {
        FakeSystem::builder().value(
            current_version_key(),
            BUILD_VALUE,
            RegValue::String("26300".to_owned()),
        )
    };
    for ubr in [
        RegValue::String("1000".to_owned()),
        RegValue::Qword(1000),
        RegValue::Binary(vec![0xE8, 3, 0, 0]),
        RegValue::decode(reg_type::REG_DWORD, &[1, 2, 3]),
    ] {
        let sys = base()
            .value(current_version_key(), UBR_VALUE, ubr)
            .build()
            .unwrap();
        assert_eq!(
            read(sys.registry()),
            Ok(OsBuild {
                build: 26300,
                ubr: None
            })
        );
    }
    let sys = base()
        .value(current_version_key(), UBR_VALUE, RegValue::Dword(0))
        .build()
        .unwrap();
    assert_eq!(read(sys.registry()).unwrap().ubr, Some(0));
}

/// Errors name the source and kind, never the stored text.
#[test]
fn errors_never_echo_the_value() {
    for s in ["SECRET", "22631 SECRET", "\u{202E}SECRET"] {
        let e = read_sz(s).unwrap_err();
        assert_eq!(e.to_string(), "CurrentBuildNumber: malformed");
        assert_eq!(e.origin(), SRC);
    }
    assert_eq!(
        ProfileError::Missing(SRC).to_string(),
        "CurrentBuildNumber: missing"
    );
    let e = read(FakeSystem::new().registry()).unwrap_err();
    assert!(e.to_string().starts_with("CurrentBuildNumber: "), "{e}");
}
