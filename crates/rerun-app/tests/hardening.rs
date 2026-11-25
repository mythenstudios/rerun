//! Hardening of `rerun-app.exe` (ADR 0008 H2, ADR 0026, ADR 0027): linked with
//! `/DEPENDENTLOADFLAG:0x800`, every static import in `APP_IMPORTS`, no graphics DLL and no
//! dynamic CRT imported statically, no delay-load import, the Windows subsystem and an
//! `asInvoker` manifest (never `requireAdministrator`, `highestAvailable` or
//! `uiAccess='true'`) with per-monitor DPI awareness V2; the release binary holds neither the
//! index test key nor the test-key build's index folder (`index-test`). The status bar's
//! test-key line is a catalogue message in every build, shown only with the feature. The first
//! icon group is `assets/rerun.ico`, image for image.
//!
//! The release binary is the one CI builds (`cargo build -p rerun-app --release`, without
//! dev-dependencies): its path comes from `RERUN_RELEASE_APP_EXE`; unset, the check is skipped
//! locally and fails on a GitHub-hosted runner.

#![cfg(windows)]
#![expect(clippy::disallowed_methods, reason = "test reads its own built binary")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test code: a failure should abort the test"
)]

use std::path::Path;

use rerun_core::detect::pe::{Limits, Pe};

#[path = "../../../tests/support/hardening.rs"]
mod hardening;

#[path = "../../../tests/support/test_key.rs"]
mod test_key;

/// `IMAGE_SUBSYSTEM_WINDOWS_GUI`: no console window.
const SUBSYSTEM_WINDOWS_GUI: u16 = 2;

/// Whether `image` holds `text` as ASCII or as UTF-16LE.
fn holds_text(image: &[u8], text: &str) -> bool {
    let ascii = text.as_bytes();
    let wide: Vec<u8> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let found = |needle: &[u8]| image.windows(needle.len()).any(|w| w == needle);
    found(ascii) || found(&wide)
}

/// Every check of the built app at `exe`; the imported DLLs for the output.
fn check_app(exe: &Path) -> String {
    let imports = hardening::check_hardened_file(exe, hardening::APP_IMPORTS)
        .unwrap_or_else(|e| panic!("{}: {e}", exe.display()));
    let image = std::fs::read(exe).unwrap();
    let pe = Pe::parse(std::fs::File::open(exe).unwrap(), &Limits::DEFAULT).unwrap();
    assert_eq!(pe.headers().subsystem, SUBSYSTEM_WINDOWS_GUI);
    let has = |s: &[u8]| image.windows(s.len()).any(|w| w == s);
    // link.exe merges `/MANIFESTUAC` into `rerun-app.manifest` and writes double quotes then.
    assert!(
        has(br#"level="asInvoker""#) || has(b"level='asInvoker'"),
        "{}: no asInvoker manifest",
        exe.display()
    );
    assert!(
        has(b"PerMonitorV2"),
        "{}: no per-monitor DPI awareness",
        exe.display()
    );
    for other in [
        &b"requireAdministrator"[..],
        b"highestAvailable",
        b"uiAccess='true'",
        br#"uiAccess="true""#,
    ] {
        assert!(
            !has(other),
            "{}: {}",
            exe.display(),
            String::from_utf8_lossy(other)
        );
    }
    check_icon(&image, exe);
    hardening::joined(&imports)
}

fn u16_at(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(b[at..at + 2].try_into().unwrap())
}

fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}

/// The resource tree of a PE32+ image, read just far enough for the icon check (test code over
/// the binary this build made; `rerun_core::detect::pe` reads only `RT_VERSION`).
struct Resources<'a> {
    image: &'a [u8],
    /// RVA and file offset of the resource directory.
    rva: u32,
    at: usize,
}

impl<'a> Resources<'a> {
    fn new(image: &'a [u8]) -> Self {
        let nt = u32_at(image, 0x3C) as usize;
        let sections = usize::from(u16_at(image, nt + 6));
        let opt = nt + 24;
        assert_eq!(u16_at(image, opt), 0x20B, "PE32+ expected");
        // `DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE]`.
        let rva = u32_at(image, opt + 112 + 2 * 8);
        assert_ne!(rva, 0, "no resource directory");
        let table = opt + usize::from(u16_at(image, nt + 20));
        let at = (0..sections)
            .map(|i| table + 40 * i)
            .find_map(|s| {
                let va = u32_at(image, s + 12);
                let size = u32_at(image, s + 16).max(u32_at(image, s + 8));
                (va..va + size)
                    .contains(&rva)
                    .then(|| (u32_at(image, s + 20) + rva - va) as usize)
            })
            .expect("resource directory outside every section");
        Self { image, rva, at }
    }

    /// The ID entries of the table at `offset` (relative to the directory): (ID, target).
    fn table(&self, offset: u32) -> Vec<(u16, u32)> {
        let t = self.at + offset as usize;
        let named = usize::from(u16_at(self.image, t + 12));
        let ids = usize::from(u16_at(self.image, t + 14));
        (named..named + ids)
            .map(|i| {
                let e = t + 16 + 8 * i;
                (u16_at(self.image, e), u32_at(self.image, e + 4))
            })
            .collect()
    }

    fn sub(&self, entries: &[(u16, u32)], id: u16) -> Option<u32> {
        let target = entries.iter().find(|e| e.0 == id)?.1;
        assert_ne!(target & 0x8000_0000, 0, "resource {id}: not a directory");
        Some(target & 0x7FFF_FFFF)
    }

    /// The data of resource `kind`/`id` in its only language.
    fn data(&self, kind: u16, id: u16) -> Option<&'a [u8]> {
        let names = self.sub(&self.table(0), kind)?;
        let langs = self.table(self.sub(&self.table(names), id)?);
        assert_eq!(
            langs.len(),
            1,
            "resource {kind}/{id}: one language expected"
        );
        let entry = self.at + langs[0].1 as usize;
        let data_rva = u32_at(self.image, entry);
        let size = u32_at(self.image, entry + 4) as usize;
        let start = self.at + (data_rva - self.rva) as usize;
        Some(&self.image[start..start + size])
    }
}

/// `RT_ICON`, `RT_GROUP_ICON` (`winuser.h`).
const RT_ICON: u16 = 3;
const RT_GROUP_ICON: u16 = 14;

/// The lowest icon group (the one Explorer and the shortcut take as index 0) is group 1 and
/// holds every image of `assets/rerun.ico`, byte for byte, with its size and bit count.
fn check_icon(image: &[u8], exe: &Path) {
    let ico = include_bytes!("../assets/rerun.ico");
    let res = Resources::new(image);
    let groups = res.table(
        res.sub(&res.table(0), RT_GROUP_ICON)
            .expect("no RT_GROUP_ICON"),
    );
    assert_eq!(
        groups.iter().map(|g| g.0).min(),
        Some(1),
        "{}: the first icon group is not 1",
        exe.display()
    );
    let group = res.data(RT_GROUP_ICON, 1).unwrap();
    assert_eq!(group[..6], ico[..6], "{}: icon group header", exe.display());
    let count = usize::from(u16_at(ico, 4));
    assert_eq!(group.len(), 6 + 14 * count);
    for i in 0..count {
        let (g, f) = (6 + 14 * i, 6 + 16 * i);
        assert_eq!(group[g..g + 4], ico[f..f + 4], "image {i}: size");
        assert_eq!(
            group[g + 6..g + 12],
            ico[f + 6..f + 12],
            "image {i}: bits, bytes"
        );
        let offset = u32_at(ico, f + 12) as usize;
        let len = u32_at(ico, f + 8) as usize;
        let icon = res
            .data(RT_ICON, u16_at(group, g + 12))
            .expect("RT_ICON missing");
        assert_eq!(
            icon,
            &ico[offset..offset + len],
            "{}: image {i}",
            exe.display()
        );
    }
}

#[test]
fn rerun_app_exe_is_hardened() {
    let exe = env!("CARGO_BIN_EXE_rerun-app");
    eprintln!("rerun-app.exe imports: {}", check_app(Path::new(exe)));
}

#[test]
fn release_rerun_app_exe_is_hardened_and_holds_no_test_key() {
    let Some(exe) = std::env::var_os("RERUN_RELEASE_APP_EXE") else {
        assert!(
            !hardening::on_github_hosted_runner(),
            "RERUN_RELEASE_APP_EXE is not set on a GitHub-hosted runner (ci.yml)"
        );
        eprintln!("RERUN_RELEASE_APP_EXE not set: release binary not checked");
        return;
    };
    let exe = Path::new(&exe);
    eprintln!("release rerun-app.exe imports: {}", check_app(exe));
    let image = std::fs::read(exe).unwrap();
    assert!(
        !test_key::holds_test_key(&image),
        "the release rerun-app.exe holds the index test key"
    );
    assert!(
        !holds_text(&image, "index-test"),
        "the release rerun-app.exe names the test-key index folder"
    );
}

/// The test-profile binary trusts the test key (rerun-core/test-key through the dev-dependency),
/// so the release checks above bite.
#[test]
fn the_test_build_holds_the_test_key() {
    let image = std::fs::read(env!("CARGO_BIN_EXE_rerun-app")).unwrap();
    assert!(test_key::holds_test_key(&image));
    assert!(holds_text(&image, "index-test"));
}
