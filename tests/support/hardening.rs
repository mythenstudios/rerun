//! Test policy for the DLL hardening of the shipped executables (ADR 0008, H2; ADR 0013,
//! "Hardening tests"), included with `#[path]` by `crates/rerun-cli/tests/hardening.rs`,
//! `crates/rerun-launch/tests/hardening.rs`, `crates/rerun-helper/tests/hardening.rs` and
//! `crates/rerun-core/tests/win_gpu_restricted.rs`.
//! The executables are read with `rerun_core::detect::pe` over a `std::fs::File` of the build
//! output; this file keeps only what is checked. Its teeth test writes its images with the
//! minimal PE writer in `tests/support/pe_image.rs` (independent of `detect::pe`), which the
//! CLI tests use as well.
//!
//! One allowlist per shipped binary (ADR 0008 amendment "import allowlist per binary", ADR
//! 0016): [`LAUNCH_IMPORTS`] for `rerun-launch.exe`, [`CLI_IMPORTS`] for `rerun.exe` (and for
//! the `WinSystem` test binary, so the two cannot drift apart), [`HELPER_IMPORTS`] for
//! `rerun-helper.exe` (ADR 0023), whose image must also pass [`check_helper_content`].

#![allow(
    dead_code,
    reason = "shared by several test crates (#[path]); each uses a part of it"
)]

use std::io::{Read, Seek};
use std::path::Path;

use rerun_core::detect::pe::{DllName, Limits, Machine, Pe, PeFormat};

#[path = "pe_image.rs"]
mod pe_image;

/// `LOAD_LIBRARY_SEARCH_SYSTEM32`, the flag `/DEPENDENTLOADFLAG:0x800` sets.
pub const SEARCH_SYSTEM32: u16 = 0x800;

/// The machine of the shipped executables: the native one of the build (x64 in CI), PE32+.
pub const NATIVE: Machine = if cfg!(target_arch = "aarch64") {
    Machine::Arm64
} else {
    Machine::X64
};

/// Whether a shipped executable must never import `dll` statically: graphics DLLs (they are not
/// KnownDLLs and must be loaded only on demand from System32, ADR 0008) and the dynamic CRT
/// (static CRT, ADR 0006).
pub fn forbidden_import(dll: &str) -> bool {
    let d = dll.to_ascii_lowercase();
    d == "dxgi.dll"
        || d == "dxcore.dll"
        || d.starts_with("d3d")
        || d.starts_with("vcruntime")
        || d.starts_with("msvcp")
        || d.starts_with("ucrtbase")
        || d.starts_with("api-ms-win-crt-")
}

/// The static imports `rerun-launch.exe` may have: exact names, compared case-insensitively.
/// Found on 2026-11-05 (debug and release, x64); extended by P3-1b (ADR 0022, reviewed there
/// and in ADR 0008): `advapi32.dll` for the token check of an elevated shim
/// (`OpenProcessToken`, `GetTokenInformation`, `CheckTokenMembership`, M1), `shell32.dll` for
/// `SHGetKnownFolderPath` (D2) and the `ShellExecuteExW` fallback (B2), `combase.dll` for
/// `CoTaskMemFree` (the known-folder string), `ole32.dll` for `CoInitializeEx`/`CoUninitialize`
/// around `ShellExecuteExW` (B2). All four are KnownDLLs on Windows 11 (checked on build 26300). A new import
/// fails the hardening test: review it, then extend this list and ADR 0008 (amendment
/// 2026-11-05, DLL hardening).
pub const LAUNCH_IMPORTS: &[&str] = &[
    "kernel32.dll",
    "ntdll.dll",
    "api-ms-win-core-synch-l1-2-0.dll",
    "advapi32.dll",
    "shell32.dll",
    "combase.dll",
    "ole32.dll",
];

/// The static imports `rerun.exe` may have, which links all of `WinSystem` from phase 1 step 16
/// (ADR 0016); also the list of `crates/rerun-core/tests/win_gpu_restricted.rs`, the test binary
/// that links every part of `WinSystem`. Found on 2026-11-05. `bcryptprimitives.dll` and
/// `userenv.dll` come from `std`, `advapi32.dll`, `combase.dll` and `shell32.dll` from
/// `windows-sys`. P4-2b (ADR 0023 §2, A4 N3): `ole32.dll` for `CoInitializeEx`/`CoUninitialize`
/// around the helper's `ShellExecuteExW` (`sys::win::elevation`), a KnownDLL like in
/// [`LAUNCH_IMPORTS`]. P4-5a (ADR 0023 §8 outcome A, ADR 0008 amendment P4-5a): `ole32.dll` also
/// for `CoCreateInstance` and `oleaut32.dll` (a KnownDLL) for `SysStringLen`, `SysFreeString`
/// and `VariantClear` of the firewall read (`sys::win::com`). P4-6 (ADR 0025, ADR 0008 amendment
/// P4-6): `winhttp.dll` for the package download (`sys::win::http`; not a KnownDLL, loaded from
/// System32 by `/DEPENDENTLOADFLAG:0x800`). A new import fails the tests: review it, then extend
/// this list and ADR 0008 (amendment "import allowlist per binary").
pub const CLI_IMPORTS: &[&str] = &[
    "kernel32.dll",
    "ntdll.dll",
    "api-ms-win-core-synch-l1-2-0.dll",
    "advapi32.dll",
    "combase.dll",
    "shell32.dll",
    "bcryptprimitives.dll",
    "userenv.dll",
    "ole32.dll",
    "oleaut32.dll",
    "winhttp.dll",
];

/// The static imports `rerun-helper.exe` may have (ADR 0023 §13, docs/08 "Acceptance
/// (helper)"). Found on 2026-11-09 with the P4-2a scaffold (`restrict_dll_search`, the token's
/// privileges and elevation): `advapi32.dll` for `OpenProcessToken`, `GetTokenInformation` and
/// `AdjustTokenPrivileges`. P4-2c (`WinHelperSystem`, reviewed): `shell32.dll` for
/// `SHGetKnownFolderPath` (`Program Files` for the own image check and the forbidden list),
/// `combase.dll` for `CoTaskMemFree` of its result (no COM is initialised or activated), and
/// `bcryptprimitives.dll` from `std` (`ProcessPrng`, the seed of the `HashMap`/`HashSet` of the
/// registry and file system reads), the same three as in [`CLI_IMPORTS`]. P4-5b (the firewall
/// COM, reviewed for the CLI in P4-5a): `ole32.dll` for `CoInitializeEx`, `CoUninitialize` and
/// `CoCreateInstance`, `oleaut32.dll` for `SysAllocStringLen`, `SysStringLen`, `SysFreeString`
/// and `VariantClear`. Never a graphics DLL ([`forbidden_import`]).
pub const HELPER_IMPORTS: &[&str] = &[
    "kernel32.dll",
    "ntdll.dll",
    "api-ms-win-core-synch-l1-2-0.dll",
    "advapi32.dll",
    "shell32.dll",
    "combase.dll",
    "bcryptprimitives.dll",
    "ole32.dll",
    "oleaut32.dll",
];

/// The run-time loaders `std` itself names in every binary: its backtrace support loads
/// `dbghelp.dll` with them (checked on 2026-11-09 in the release `rerun-launch.exe`, which does
/// not depend on `rerun-core`). Reviewed exception of the helper's loader check
/// ([`dynamic_loaders`]); the content check ([`dxgi_references`]) shows that nothing loads
/// DXGI through them.
pub const STD_LOADERS: &[&str] = &["LoadLibraryA", "LoadLibraryExW"];

/// Whether `image` contains `needle`, ASCII case-insensitive.
fn contains_ascii_ci(image: &[u8], needle: &[u8]) -> bool {
    image
        .windows(needle.len())
        .any(|w| w.eq_ignore_ascii_case(needle))
}

/// Whether `image` contains `needle` as UTF-16LE, ASCII case-insensitive.
fn contains_utf16_ci(image: &[u8], needle: &[u8]) -> bool {
    let n = needle.len() * 2;
    image.windows(n).any(|w| {
        w.as_chunks::<2>()
            .0
            .iter()
            .zip(needle)
            .all(|(c, b)| c[1] == 0 && c[0].eq_ignore_ascii_case(b))
    })
}

/// What in `image` names DXGI (docs/08 "Acceptance (helper)", B9): `dxgi.dll` as ASCII or
/// UTF-16LE (case-insensitive) and the entry point `CreateDXGIFactory1`. A byte search over the
/// whole file, so it finds an import, a `LoadLibrary` argument and a `GetProcAddress` name
/// alike. Empty for the helper; the `WinGpu` control binary must not be empty.
pub fn dxgi_references(image: &[u8]) -> Vec<&'static str> {
    let mut found = Vec::new();
    if contains_ascii_ci(image, b"dxgi.dll") {
        found.push("dxgi.dll (ASCII)");
    }
    if contains_utf16_ci(image, b"dxgi.dll") {
        found.push("dxgi.dll (UTF-16LE)");
    }
    if image
        .windows(b"CreateDXGIFactory1".len())
        .any(|w| w == b"CreateDXGIFactory1")
    {
        found.push("CreateDXGIFactory1");
    }
    found
}

/// Every run-time loader name in `image` (`LoadLibrary` followed by letters, and
/// `LoadPackagedLibrary`), sorted and unique: a byte search over the whole file (an import's
/// hint/name entry or a `GetProcAddress` string alike), so `detect::pe` needs no function-name
/// API (ADR 0013). The helper may name only [`STD_LOADERS`].
pub fn dynamic_loaders(image: &[u8]) -> Vec<String> {
    let mut found = Vec::new();
    for prefix in [&b"LoadLibrary"[..], b"LoadPackagedLibrary"] {
        for (i, w) in image.windows(prefix.len()).enumerate() {
            if w == prefix {
                let tail = image[i + prefix.len()..]
                    .iter()
                    .take_while(|b| b.is_ascii_alphabetic())
                    .count();
                let name = &image[i..i + prefix.len() + tail];
                found.push(String::from_utf8_lossy(name).into_owned());
            }
        }
    }
    found.sort();
    found.dedup();
    found
}

/// The helper's content rules on `image` (docs/08 "Acceptance (helper)"): no DXGI reference
/// and no run-time loader beyond [`STD_LOADERS`].
pub fn check_helper_content(image: &[u8]) -> Result<(), String> {
    let dxgi = dxgi_references(image);
    if !dxgi.is_empty() {
        return Err(format!("names DXGI: {dxgi:?}"));
    }
    let extra: Vec<String> = dynamic_loaders(image)
        .into_iter()
        .filter(|n| !STD_LOADERS.contains(&n.as_str()))
        .collect();
    if !extra.is_empty() {
        return Err(format!(
            "run-time loaders beyond std's {STD_LOADERS:?}: {extra:?}"
        ));
    }
    Ok(())
}

/// Console APIs that change state the parent shell shares (code page, modes; ADR 0016).
/// `rerun.exe` must not name them anywhere: neither as a static import (the hint/name table
/// holds the function name) nor as a string for `GetProcAddress`.
pub const CONSOLE_STATE_APIS: &[&str] = &["SetConsoleMode", "SetConsoleOutputCP", "SetConsoleCP"];

/// The [`CONSOLE_STATE_APIS`] whose name occurs in `image` (a byte search over the whole file,
/// so `detect::pe` needs no function-name API).
pub fn console_state_apis(image: &[u8]) -> Vec<&'static str> {
    CONSOLE_STATE_APIS
        .iter()
        .copied()
        .filter(|name| image.windows(name.len()).any(|w| w == name.as_bytes()))
        .collect()
}

/// `imports` has no forbidden DLL and nothing outside `allowed` (exact, case-insensitive).
pub fn check_imports(imports: &[DllName], allowed: &[&str]) -> Result<(), String> {
    let all: Vec<&str> = imports.iter().map(DllName::as_str).collect();
    if let Some(bad) = all.iter().find(|d| forbidden_import(d)) {
        return Err(format!("forbidden static import {bad} (imports: {all:?})"));
    }
    let new: Vec<&str> = all
        .iter()
        .copied()
        .filter(|d| !allowed.iter().any(|a| a.eq_ignore_ascii_case(d)))
        .collect();
    if !new.is_empty() {
        return Err(format!(
            "static imports not in the allowlist: {new:?} (all: {all:?}); review them, then \
             update the allowlist in tests/support/hardening.rs and ADR 0008 (amendment \
             2026-11-05)"
        ));
    }
    Ok(())
}

/// Checks an executable (ADR 0008, H2): PE32+ for the [`NATIVE`] machine, `DependentLoadFlags`
/// exactly System32, every static import in `allowed` (the list of that binary) and none
/// forbidden, no delay-load import. Returns the imported DLL names.
pub fn check_hardened<R: Read + Seek>(image: R, allowed: &[&str]) -> Result<Vec<DllName>, String> {
    let mut pe = Pe::parse(image, &Limits::DEFAULT).map_err(|e| e.to_string())?;
    let h = pe.headers();
    if h.format != PeFormat::Pe32Plus || h.machine != NATIVE {
        return Err(format!(
            "{:?} {:?}, expected PE32+ for {NATIVE:?}",
            h.machine, h.format
        ));
    }
    let flags = pe.dependent_load_flags().map_err(|e| e.to_string())?;
    if flags != Some(SEARCH_SYSTEM32) {
        return Err(format!(
            "DependentLoadFlags is {flags:x?}, expected {SEARCH_SYSTEM32:#x} (System32 only)"
        ));
    }
    let imports = pe.imports().map_err(|e| e.to_string())?;
    check_imports(&imports, allowed)?;
    let delayed = pe.delay_imports().map_err(|e| e.to_string())?;
    if !delayed.is_empty() {
        return Err(format!("delay-load imports {delayed:?}"));
    }
    Ok(imports)
}

/// The static and delay-load imports of the executable at `path` (the test's own build
/// output).
pub fn imports_of(path: &Path) -> Result<(Vec<DllName>, Vec<DllName>), String> {
    let file = std::fs::File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut pe = Pe::parse(file, &Limits::DEFAULT).map_err(|e| e.to_string())?;
    let imports = pe.imports().map_err(|e| e.to_string())?;
    let delayed = pe.delay_imports().map_err(|e| e.to_string())?;
    Ok((imports, delayed))
}

/// [`check_hardened`] on the executable at `path`.
pub fn check_hardened_file(path: &Path, allowed: &[&str]) -> Result<Vec<DllName>, String> {
    let file = std::fs::File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    check_hardened(file, allowed)
}

/// A GitHub-hosted runner (as the machine-wide fs fixtures decide it, `sys::win::testfx`): there
/// an unset release path is a CI configuration error, locally the check is skipped.
pub fn on_github_hosted_runner() -> bool {
    let is = |k: &str, v: &str| std::env::var(k).is_ok_and(|x| x == v);
    is("GITHUB_ACTIONS", "true") && is("RUNNER_ENVIRONMENT", "github-hosted")
}

/// The DLL names, comma-separated, for the test output.
pub fn joined(names: &[DllName]) -> String {
    names
        .iter()
        .map(DllName::as_str)
        .collect::<Vec<_>>()
        .join(", ")
}

#[test]
fn hardening_checks_have_teeth() {
    use std::io::Cursor;

    use pe_image::{AMD64, ARM64, I386, image, image_for};
    let check = |imports: &[&str], delayed: &[&str], flags: u16| {
        check_hardened(Cursor::new(image(imports, delayed, flags)), LAUNCH_IMPORTS)
    };
    // The positive control: a hardened image passes, so the failures below are not about the
    // writer.
    let ok = check(&["KERNEL32.dll", "ntdll.dll"], &[], SEARCH_SYSTEM32).unwrap();
    assert_eq!(joined(&ok), "KERNEL32.dll, ntdll.dll");
    // A graphics import fails, also when it is allowlisted.
    let e = check(&["kernel32.dll", "d3d9.dll"], &[], SEARCH_SYSTEM32).unwrap_err();
    assert!(e.contains("forbidden static import d3d9.dll"), "{e}");
    let d3d9 = image(&["d3d9.dll"], &[], SEARCH_SYSTEM32);
    let mut pe = Pe::parse(Cursor::new(d3d9), &Limits::DEFAULT).unwrap();
    assert!(check_imports(&pe.imports().unwrap(), &["d3d9.dll"]).is_err());
    // An import outside the allowlist, a delay-load import, other or no flags fail.
    let e = check(&["kernel32.dll", "user32.dll"], &[], SEARCH_SYSTEM32).unwrap_err();
    assert!(e.contains("not in the allowlist"), "{e}");
    let e = check(&["kernel32.dll"], &["dxgi.dll"], SEARCH_SYSTEM32).unwrap_err();
    assert!(e.contains("delay-load imports"), "{e}");
    for flags in [0, 0x1000, SEARCH_SYSTEM32 | 0x200] {
        let e = check(&["kernel32.dll"], &[], flags).unwrap_err();
        assert!(e.contains("DependentLoadFlags"), "{e}");
    }
    // A PE32 image and a PE32+ image for another machine fail, though hardened otherwise.
    let hardened_for = |machine| image_for(machine, &["kernel32.dll"], &[], SEARCH_SYSTEM32);
    let e = check_hardened(Cursor::new(hardened_for(I386)), LAUNCH_IMPORTS).unwrap_err();
    assert!(e.contains("expected PE32+"), "{e}");
    // ... and the PE32 image itself is well-formed: the parser reads its flags and imports.
    let mut pe32 = Pe::parse(Cursor::new(hardened_for(I386)), &Limits::DEFAULT).unwrap();
    assert_eq!(pe32.headers().format, PeFormat::Pe32);
    assert_eq!(pe32.dependent_load_flags(), Ok(Some(SEARCH_SYSTEM32)));
    assert_eq!(pe32.imports().unwrap().len(), 1);
    let other = if NATIVE == Machine::Arm64 {
        AMD64
    } else {
        ARM64
    };
    let e = check_hardened(Cursor::new(hardened_for(other)), LAUNCH_IMPORTS).unwrap_err();
    assert!(e.contains("expected PE32+"), "{e}");
    // Malformed input is an error, never a panic.
    assert!(check_hardened(Cursor::new(b"MZ"), LAUNCH_IMPORTS).is_err());
    assert!(check_hardened(Cursor::new(b""), CLI_IMPORTS).is_err());

    assert!(forbidden_import("D3D11.dll") && forbidden_import("api-ms-win-crt-heap-l1-1-0.dll"));
    assert!(
        !forbidden_import("kernel32.dll") && !forbidden_import("api-ms-win-core-synch-l1-2-0.dll")
    );
}

#[test]
fn the_console_api_check_has_teeth() {
    assert!(console_state_apis(b"MZ kernel32.dll\0GetStdHandle\0").is_empty());
    assert_eq!(
        console_state_apis(b"\0\0SetConsoleMode\0WriteConsoleW\0"),
        ["SetConsoleMode"]
    );
    assert_eq!(
        console_state_apis(b"SetConsoleOutputCP\0SetConsoleCP\0"),
        ["SetConsoleOutputCP", "SetConsoleCP"]
    );
    // SetConsoleCtrlHandler is no console state API.
    assert!(console_state_apis(b"SetConsoleCtrlHandler\0").is_empty());
}

#[test]
fn the_helper_content_checks_have_teeth() {
    let utf16 = |s: &str| -> Vec<u8> { s.encode_utf16().flat_map(u16::to_le_bytes).collect() };
    // Clean: std's two loaders, a DXGI-like name that is none.
    let clean = b"MZ\0LoadLibraryA\0LoadLibraryExW\0GetProcAddress\0dxgi_dll\0dxcore\0";
    assert_eq!(check_helper_content(clean), Ok(()));
    assert_eq!(dynamic_loaders(clean), ["LoadLibraryA", "LoadLibraryExW"]);
    // Each DXGI form alone fails, in any case.
    for bad in [
        b"\0dxgi.dll\0".to_vec(),
        b"\0DXGI.DLL\0".to_vec(),
        utf16("Dxgi.Dll"),
        b"\0CreateDXGIFactory1\0".to_vec(),
    ] {
        let e = check_helper_content(&bad).unwrap_err();
        assert!(e.contains("names DXGI"), "{e}");
    }
    assert_eq!(
        dxgi_references(
            &[
                b"dxgi.dll ".as_slice(),
                &utf16("DXGI.dll"),
                b"CreateDXGIFactory1"
            ]
            .concat()
        ),
        [
            "dxgi.dll (ASCII)",
            "dxgi.dll (UTF-16LE)",
            "CreateDXGIFactory1"
        ]
    );
    // A loader beyond std's fails.
    for bad in [
        &b"LoadLibraryW\0"[..],
        b"LoadLibraryExA",
        b"LoadPackagedLibrary\0",
    ] {
        let e = check_helper_content(bad).unwrap_err();
        assert!(e.contains("run-time loaders"), "{e}");
    }
    // The CLI's own imports beyond the helper's fail the helper's list (the COM DLLs joined it
    // with the firewall write side in P4-5b).
    {
        use pe_image::image;
        let img = image(&["kernel32.dll", "userenv.dll"], &[], SEARCH_SYSTEM32);
        let e = check_hardened(std::io::Cursor::new(img), HELPER_IMPORTS).unwrap_err();
        assert!(e.contains("not in the allowlist"), "{e}");
    }
    for dll in HELPER_IMPORTS {
        assert!(!forbidden_import(dll), "{dll}");
    }
}

#[test]
fn each_binary_has_its_own_allowlist() {
    use std::io::Cursor;

    use pe_image::image;
    let check = |imports: &[&str], allowed: &[&str]| {
        check_hardened(Cursor::new(image(imports, &[], SEARCH_SYSTEM32)), allowed)
    };
    // The CLI's own imports pass its list and fail the shim's: rerun-launch.exe never gets
    // them without a review (advapi32, combase and shell32 were reviewed for it in P3-1b).
    for dll in ["bcryptprimitives.dll", "userenv.dll"] {
        check(&["kernel32.dll", dll], CLI_IMPORTS).unwrap();
        let e = check(&["kernel32.dll", dll], LAUNCH_IMPORTS).unwrap_err();
        assert!(e.contains("not in the allowlist"), "{e}");
    }
    // COM: the shim (B2, around ShellExecuteExW), the CLI (the helper start, ADR 0023 N3, and
    // the firewall read) and, since P4-5b, the helper (the firewall write) import ole32.dll;
    // the shim has no oleaut32.dll (no BSTR, no VARIANT).
    check(&["kernel32.dll", "ole32.dll"], LAUNCH_IMPORTS).unwrap();
    check(&["kernel32.dll", "ole32.dll"], CLI_IMPORTS).unwrap();
    check(
        &["kernel32.dll", "ole32.dll", "oleaut32.dll"],
        HELPER_IMPORTS,
    )
    .unwrap();
    let e = check(&["kernel32.dll", "oleaut32.dll"], LAUNCH_IMPORTS).unwrap_err();
    assert!(e.contains("not in the allowlist"), "{e}");
    // An import outside both lists fails both, a forbidden one fails both.
    for allowed in [LAUNCH_IMPORTS, CLI_IMPORTS] {
        let e = check(&["kernel32.dll", "user32.dll"], allowed).unwrap_err();
        assert!(e.contains("not in the allowlist"), "{e}");
        let e = check(&["kernel32.dll", "dxgi.dll"], allowed).unwrap_err();
        assert!(e.contains("forbidden static import dxgi.dll"), "{e}");
    }
    // The shim's list is part of the CLI's; no list holds a forbidden name.
    for dll in LAUNCH_IMPORTS {
        assert!(CLI_IMPORTS.contains(dll), "{dll}");
    }
    for dll in LAUNCH_IMPORTS.iter().chain(CLI_IMPORTS) {
        assert!(!forbidden_import(dll), "{dll}");
    }
}
