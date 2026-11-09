//! [`WinKnownFolders`]: the real [`KnownFolders`] (ADR 0007, ADR 0009). No `unsafe`; the FFI
//! is in `shell`, registry reads go through [`Registry`].
//!
//! Sources, each pinned by `known_folders_ignore_the_environment` on real Windows:
//! - `Windows`: `GetSystemWindowsDirectoryW`.
//! - `ProgramData` and `UserProfiles`: the raw values
//!   `ProgramData` and `ProfilesDirectory` of `HKLM\SOFTWARE\Microsoft\Windows NT\
//!   CurrentVersion\ProfileList` (native view), with `%SystemDrive%` and `%SystemRoot%`
//!   expanded from `GetSystemWindowsDirectoryW` and any other variable refused. The shell
//!   (`SHGetKnownFolderPath`, also with a token) and `userenv` expand `%SystemDrive%` there from
//!   the process environment (found on Windows 11, 2026-11-04), so they are not asked.
//! - Every other folder: `SHGetKnownFolderPath` with its `FOLDERID_*` (see `shell`).
//!
//! Never from environment variables: `windir`, `ProgramFiles`, `USERPROFILE` and friends can
//! be set by any program of the user and are inherited by the elevated helper.
//!
//! Errors: a failed `SHGetKnownFolderPath` with `HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND)` or
//! `E_INVALIDARG` (the system has no such folder) is `NotFound`, every other `HRESULT` is
//! `Other`; the `HRESULT` is attached. A missing `ProfileList` value is `NotFound`, a value of
//! another type or with another variable `Unsupported`.

use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;

use windows_sys::Win32::Foundation::E_INVALIDARG;
use windows_sys::Win32::UI::Shell::{
    FOLDERID_LocalAppData, FOLDERID_Profile, FOLDERID_ProgramFiles, FOLDERID_ProgramFilesCommon,
    FOLDERID_ProgramFilesCommonX86, FOLDERID_ProgramFilesX86, FOLDERID_RoamingAppData,
};
use windows_sys::core::{GUID, HRESULT};

use super::shell;
use super::status::win32_error;
use crate::sys::registry::{Hive, RegKey, RegValue, RegView};
use crate::sys::{KnownFolder, KnownFolders, Registry, SysError, SysErrorKind, SysResult};

/// winerror.h `HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND)`.
const HRESULT_FILE_NOT_FOUND: HRESULT = 0x8007_0002_u32.cast_signed();
/// The key with the machine's profile folders.
const PROFILE_LIST: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList";

/// Where a known folder comes from.
#[derive(Clone, Copy)]
enum Source {
    /// `GetSystemWindowsDirectoryW`.
    SystemWindows,
    /// A raw value of [`PROFILE_LIST`], expanded against the Windows directory.
    ProfileList(&'static str),
    /// `SHGetKnownFolderPath`.
    Shell(GUID),
}

fn source(folder: KnownFolder) -> Source {
    match folder {
        KnownFolder::Windows => Source::SystemWindows,
        KnownFolder::ProgramData => Source::ProfileList("ProgramData"),
        KnownFolder::UserProfiles => Source::ProfileList("ProfilesDirectory"),
        KnownFolder::ProgramFiles => Source::Shell(FOLDERID_ProgramFiles),
        KnownFolder::ProgramFilesX86 => Source::Shell(FOLDERID_ProgramFilesX86),
        KnownFolder::ProgramFilesCommon => Source::Shell(FOLDERID_ProgramFilesCommon),
        KnownFolder::ProgramFilesCommonX86 => Source::Shell(FOLDERID_ProgramFilesCommonX86),
        KnownFolder::Profile => Source::Shell(FOLDERID_Profile),
        KnownFolder::LocalAppData => Source::Shell(FOLDERID_LocalAppData),
        KnownFolder::RoamingAppData => Source::Shell(FOLDERID_RoamingAppData),
    }
}

/// The real known folders. Every call asks the system; `registry` is used for the
/// machine-wide `HKLM` values only.
pub struct WinKnownFolders {
    registry: Arc<dyn Registry>,
}

impl fmt::Debug for WinKnownFolders {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WinKnownFolders").finish_non_exhaustive()
    }
}

impl WinKnownFolders {
    /// The real known folders; `registry` must be the real registry (its `HKLM`).
    pub fn new(registry: Arc<dyn Registry>) -> Self {
        Self { registry }
    }
}

impl KnownFolders for WinKnownFolders {
    fn get(&self, folder: KnownFolder) -> SysResult<PathBuf> {
        let target = format!("known folder {folder}");
        match source(folder) {
            Source::SystemWindows => windows_dir(&target).map(PathBuf::from),
            Source::ProfileList(name) => {
                let windows = windows_dir(&target)?;
                profile_list(&*self.registry, name, &windows, &target).map(PathBuf::from)
            }
            Source::Shell(id) => by_id(&id, &target),
        }
    }
}

/// The Windows directory as a string (expansion needs Unicode).
fn windows_dir(target: &str) -> SysResult<String> {
    shell::system_windows_directory()
        .map_err(|code| win32_error(code, target))?
        .into_string()
        .map_err(|_| SysError::new(SysErrorKind::Unsupported, target))
}

/// The value `name` of [`PROFILE_LIST`], expanded against `windows`.
fn profile_list(reg: &dyn Registry, name: &str, windows: &str, target: &str) -> SysResult<String> {
    let key = RegKey::new(Hive::LocalMachine, RegView::Native, PROFILE_LIST);
    let shown = format!("{target} ({key} @ {name})");
    let raw = match reg.get(&key, name)? {
        None => return Err(SysError::new(SysErrorKind::NotFound, shown)),
        Some(RegValue::ExpandString(s) | RegValue::String(s)) => s,
        Some(_) => return Err(SysError::new(SysErrorKind::Unsupported, shown)),
    };
    expand_machine(&raw, windows)
        .ok_or_else(|| SysError::new(SysErrorKind::Unsupported, format!("{shown}: {raw:?}")))
}

/// Expands `%SystemDrive%` (the drive of `windows`, `X:`) and `%SystemRoot%` (`windows`)
/// in `value`, case-insensitively. `None` for any other variable, an unpaired `%`, an empty
/// result or a Windows directory without a drive letter. Pure.
fn expand_machine(value: &str, windows: &str) -> Option<String> {
    let drive = windows.get(..2).filter(|d| {
        let b = d.as_bytes();
        b[0].is_ascii_alphabetic() && b[1] == b':'
    })?;
    let mut out = String::with_capacity(value.len() + windows.len());
    let mut rest = value;
    while let Some(start) = rest.find('%') {
        out.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        let end = after.find('%')?;
        let var = &after[..end];
        if var.eq_ignore_ascii_case("SystemDrive") {
            out.push_str(drive);
        } else if var.eq_ignore_ascii_case("SystemRoot") {
            out.push_str(windows);
        } else {
            return None;
        }
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    (!out.is_empty()).then_some(out)
}

fn by_id(id: &GUID, target: &str) -> SysResult<PathBuf> {
    shell::known_folder_path(id)
        .map(PathBuf::from)
        .map_err(|hr| hresult_error(hr, target))
}

/// Classifies a failed `SHGetKnownFolderPath` (pure).
fn kind_of_hresult(hr: HRESULT) -> SysErrorKind {
    if hr == HRESULT_FILE_NOT_FOUND || hr == E_INVALIDARG {
        SysErrorKind::NotFound
    } else {
        SysErrorKind::Other
    }
}

fn hresult_error(hr: HRESULT, target: &str) -> SysError {
    SysError::new(kind_of_hresult(hr), target).with_hresult(hr)
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::disallowed_methods,
        reason = "test: std::fs creates the decoy directories in the test root, Fs::open_dir \
                  opens each known folder read-only"
    )]

    use std::ffi::OsString;
    use std::io::Write as _;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;

    use windows_sys::Win32::UI::Shell::FOLDERID_ProgramData;
    use windows_sys::core::GUID;

    use super::{
        PROFILE_LIST, Source, WinKnownFolders, by_id, expand_machine, kind_of_hresult,
        profile_list, source,
    };
    use crate::path::RootPath;
    use crate::sys::fake::FakeRegistry;
    use crate::sys::fs::Fs;
    use crate::sys::registry::{Hive, RegKey, RegValue, RegView};
    use crate::sys::win::WinFs;
    use crate::sys::win::WinRegistry;
    use crate::sys::win::testfx::{TestRoot, note};
    use crate::sys::{KnownFolder, KnownFolders, SysErrorKind};

    /// Set (to `1`) only in the child process of `known_folders_ignore_the_environment`.
    const CHILD_MARKER: &str = "RERUN_KNOWN_FOLDERS_CHILD";
    /// Prefix of the child's result lines.
    const LINE: &str = "rerun-known-folder\t";
    /// Prefix of the child's control line.
    const CONTROL: &str = "rerun-known-folder-control\t";
    /// Full name of the child test, for `--exact`.
    const CHILD_TEST: &str = "sys::win::known_folders::tests::child_reports_known_folders";

    /// Every variable a careless implementation could take a known folder from (ADR 0009).
    const VARS: [&str; 17] = [
        "windir",
        "SystemRoot",
        "SystemDrive",
        "ProgramFiles",
        "ProgramFiles(x86)",
        "ProgramW6432",
        "CommonProgramFiles",
        "CommonProgramFiles(x86)",
        "CommonProgramW6432",
        "ProgramData",
        "ALLUSERSPROFILE",
        "PUBLIC",
        "USERPROFILE",
        "HOMEDRIVE",
        "HOMEPATH",
        "LOCALAPPDATA",
        "APPDATA",
    ];

    fn real() -> WinKnownFolders {
        WinKnownFolders::new(Arc::new(WinRegistry::new().unwrap()))
    }

    /// One line per folder: `<prefix><folder>\t<path or error, Debug-formatted>`. Debug keeps
    /// unpaired surrogates distinguishable, so equal lines mean equal paths.
    fn report() -> Vec<String> {
        let kf = real();
        KnownFolder::ALL
            .into_iter()
            .map(|f| {
                let r = match kf.get(f) {
                    Ok(p) => format!("{:?}", p.as_os_str()),
                    Err(e) => format!(
                        "error {} hresult {:?} win32 {:?}",
                        e.kind, e.hresult, e.win32
                    ),
                };
                format!("{LINE}{f}\t{r}")
            })
            .collect()
    }

    #[test]
    fn hresults_map_to_kinds() {
        let hr = |v: u32| v.cast_signed();
        assert_eq!(kind_of_hresult(hr(0x8007_0002)), SysErrorKind::NotFound);
        assert_eq!(kind_of_hresult(hr(0x8007_0057)), SysErrorKind::NotFound);
        assert_eq!(kind_of_hresult(hr(0x8007_0005)), SysErrorKind::Other);
        assert_eq!(kind_of_hresult(hr(0x8000_4005)), SysErrorKind::Other);
    }

    #[test]
    fn every_folder_has_its_source() {
        assert!(matches!(
            source(KnownFolder::Windows),
            Source::SystemWindows
        ));
        assert!(matches!(
            source(KnownFolder::ProgramData),
            Source::ProfileList("ProgramData")
        ));
        assert!(matches!(
            source(KnownFolder::UserProfiles),
            Source::ProfileList("ProfilesDirectory")
        ));
        let shell = KnownFolder::ALL
            .into_iter()
            .filter(|f| matches!(source(*f), Source::Shell(_)))
            .count();
        assert_eq!(shell, KnownFolder::ALL.len() - 3);
    }

    #[test]
    fn machine_values_expand_only_system_drive_and_root() {
        let w = r"D:\Windows";
        assert_eq!(
            expand_machine(r"%SystemDrive%\ProgramData", w).as_deref(),
            Some(r"D:\ProgramData")
        );
        assert_eq!(
            expand_machine(r"%systemdrive%\Users", w).as_deref(),
            Some(r"D:\Users")
        );
        assert_eq!(
            expand_machine(r"%SYSTEMROOT%\Profiles", w).as_deref(),
            Some(r"D:\Windows\Profiles")
        );
        assert_eq!(expand_machine(r"E:\Users", w).as_deref(), Some(r"E:\Users"));
        for bad in [
            r"%USERPROFILE%\x",
            r"%ProgramData%",
            r"%SystemDrive\x",
            r"x%",
            r"%%\x",
            "",
        ] {
            assert_eq!(expand_machine(bad, w), None, "{bad:?}");
        }
        assert_eq!(expand_machine(r"%SystemDrive%\x", r"\\srv\win"), None);
        assert_eq!(expand_machine(r"%SystemDrive%\x", "C"), None);
    }

    #[test]
    fn profile_list_values_are_read_raw_from_hklm() {
        let reg = FakeRegistry::default();
        let key = RegKey::new(Hive::LocalMachine, RegView::Native, PROFILE_LIST);
        let create_all = |k: &RegKey| {
            let mut path = String::new();
            for seg in k.path.split('\\') {
                if !path.is_empty() {
                    path.push('\\');
                }
                path.push_str(seg);
                reg.put_key(&RegKey::new(k.hive, k.view, &path)).unwrap();
            }
        };
        let set = |name: &str, v: RegValue| {
            create_all(&key);
            reg.put_value(&key, name, &v).unwrap();
        };
        let w = r"C:\Windows";
        let kind = |r: crate::sys::SysResult<String>| r.unwrap_err().kind;
        assert_eq!(
            kind(profile_list(&reg, "ProgramData", w, "t")),
            SysErrorKind::NotFound
        );
        set(
            "ProgramData",
            RegValue::ExpandString(r"%SystemDrive%\ProgramData".into()),
        );
        set("ProfilesDirectory", RegValue::String(r"E:\Users".into()));
        set("Bad", RegValue::Dword(1));
        set("Env", RegValue::ExpandString(r"%PUBLIC%\..".into()));
        assert_eq!(
            profile_list(&reg, "ProgramData", w, "t").unwrap(),
            r"C:\ProgramData"
        );
        assert_eq!(
            profile_list(&reg, "ProfilesDirectory", w, "t").unwrap(),
            r"E:\Users"
        );
        assert_eq!(
            kind(profile_list(&reg, "Bad", w, "t")),
            SysErrorKind::Unsupported
        );
        assert_eq!(
            kind(profile_list(&reg, "Env", w, "t")),
            SysErrorKind::Unsupported
        );
        // The WOW64 view is never consulted.
        let wow = RegKey::new(Hive::LocalMachine, RegView::Wow32, PROFILE_LIST);
        create_all(&wow);
        reg.put_value(&wow, "ProgramData", &RegValue::String(r"X:\Decoy".into()))
            .unwrap();
        assert_eq!(
            profile_list(&reg, "ProgramData", w, "t").unwrap(),
            r"C:\ProgramData"
        );
    }

    #[test]
    fn an_unknown_folder_id_is_not_found_with_its_hresult() {
        // Random, registered nowhere.
        let id = GUID::from_u128(0x5d1c_3f0e_8b7a_4c62_9e41_0a2b_6c8d_f317);
        let e = by_id(&id, "known folder test").unwrap_err();
        assert_eq!(e.kind, SysErrorKind::NotFound, "{e:?}");
        assert!(e.hresult.is_some_and(|hr| hr < 0), "{e:?}");
        assert_eq!(e.win32, None);
    }

    #[test]
    fn every_known_folder_resolves_and_opens() {
        let kf = real();
        let fs = WinFs::new();
        let mut seen: Vec<PathBuf> = Vec::new();
        for f in KnownFolder::ALL {
            let p = kf.get(f).unwrap_or_else(|e| panic!("{f}: {e:?}"));
            assert_eq!(kf.get(f).unwrap(), p, "{f} is stable across calls");
            let s = p.to_str().unwrap_or_else(|| panic!("{f}: not Unicode"));
            if s.starts_with(r"\\") {
                assert_eq!(f, KnownFolder::RoamingAppData, "{f} is a UNC path: {s}");
                assert!(
                    !s.starts_with(r"\\?\") && !s.starts_with(r"\\.\"),
                    "{f} is a device path: {s}"
                );
                note(&format!("{f} is redirected to {s}; not opened"));
                continue;
            }
            assert!(RootPath::new(&p).is_ok(), "{f} is not drive-absolute: {s}");
            assert!(
                !seen
                    .iter()
                    .any(|q| q.as_os_str().eq_ignore_ascii_case(p.as_os_str())),
                "{f} duplicates another folder: {s}"
            );
            let dir = fs
                .open_dir(&p)
                .unwrap_or_else(|e| panic!("open {f} ({s}): {e:?}"));
            let info = dir.info().unwrap_or_else(|e| panic!("info {f}: {e:?}"));
            assert!(
                RootPath::from_final_path(&info.final_path).is_ok(),
                "{f}: final path {} is not on a drive letter",
                info.final_path.display()
            );
            seen.push(p);
        }
    }

    /// Runs only as the child of [`known_folders_ignore_the_environment`] and prints the known
    /// folders it sees; a no-op in a normal test run.
    #[test]
    fn child_reports_known_folders() {
        #[expect(
            clippy::disallowed_methods,
            reason = "test gate: only the marker decides whether this is the child process"
        )]
        let child = std::env::var_os(CHILD_MARKER).is_some_and(|v| v == "1");
        if !child {
            return;
        }
        // Own lines: libtest prints "test … ... " without a newline before the output.
        let mut out = std::io::stdout().lock();
        writeln!(out).unwrap();
        for line in report() {
            writeln!(out, "{line}").unwrap();
        }
        // Control: the shell's own FOLDERID_ProgramData follows %SystemDrive% (the reason it
        // is not a source), so it shows that the decoy environment reached this process.
        let control = by_id(&FOLDERID_ProgramData, "control")
            .map(|p| format!("{:?}", p.as_os_str()))
            .unwrap_or_else(|e| format!("error {e:?}"));
        writeln!(out, "{CONTROL}{control}").unwrap();
    }

    /// ADR 0009: a child started with every path variable pointing into the test root reports
    /// exactly the parent's known folders.
    #[test]
    fn known_folders_ignore_the_environment() {
        let Some(root) = TestRoot::new("known-folders-env") else {
            return;
        };
        let env = root.work("env");
        let exe = std::env::current_exe().unwrap();
        #[expect(
            clippy::disallowed_methods,
            reason = "test: starts its own test binary as the child of this check"
        )]
        let mut cmd = std::process::Command::new(&exe);
        cmd.args([CHILD_TEST, "--exact", "--nocapture", "--test-threads=1"])
            .env(CHILD_MARKER, "1");
        // The child is a console program: no window from a test.
        std::os::windows::process::CommandExt::creation_flags(
            &mut cmd,
            windows_sys::Win32::System::Threading::CREATE_NO_WINDOW,
        );
        for var in VARS {
            cmd.env(var, decoy(&env, var));
        }
        let out = run_with_deadline(cmd, CHILD_DEADLINE);
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            out.status.success(),
            "child failed ({}):\n{stdout}\n{}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        );
        let child: Vec<&str> = stdout.lines().filter(|l| l.starts_with(LINE)).collect();
        assert_eq!(
            child.len(),
            KnownFolder::ALL.len(),
            "the child did not report every folder:\n{stdout}"
        );
        let decoys = env.to_string_lossy().to_lowercase().replace('\\', r"\\");
        let control = stdout
            .lines()
            .find_map(|l| l.strip_prefix(CONTROL))
            .unwrap_or_else(|| panic!("the child printed no control line:\n{stdout}"));
        assert!(
            control.to_lowercase().contains(&decoys),
            "the decoy environment did not reach the child, the check proves nothing (or \
             Windows no longer expands %SystemDrive% for FOLDERID_ProgramData from the \
             environment; then pick another control): {control}"
        );
        let mut differ = Vec::new();
        for (p, c) in report().iter().zip(&child) {
            assert!(!p.contains("\terror "), "parent: {p}");
            if p != c || c.to_lowercase().contains(&decoys) {
                differ.push(format!("parent {p}\n  child {c}"));
            }
        }
        assert!(
            differ.is_empty(),
            "known folders depend on the environment:\n{}",
            differ.join("\n")
        );
    }

    /// The child test must finish within this time; it is killed otherwise.
    const CHILD_DEADLINE: std::time::Duration = std::time::Duration::from_secs(60);

    /// Runs `cmd` with piped output (read on threads, so a full pipe cannot block the child);
    /// kills it and panics if it is not done within `deadline`.
    fn run_with_deadline(
        mut cmd: std::process::Command,
        deadline: std::time::Duration,
    ) -> std::process::Output {
        use std::io::Read as _;
        use std::process::Stdio;
        let mut child = cmd
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let drain = |r: Option<Box<dyn std::io::Read + Send>>| {
            std::thread::spawn(move || {
                let mut buf = Vec::new();
                if let Some(mut r) = r {
                    let _ = r.read_to_end(&mut buf);
                }
                buf
            })
        };
        let out = drain(child.stdout.take().map(|r| Box::new(r) as _));
        let err = drain(child.stderr.take().map(|r| Box::new(r) as _));
        let started = std::time::Instant::now();
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if started.elapsed() > deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("the child test did not finish within {deadline:?} and was killed");
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        };
        std::process::Output {
            status,
            stdout: out.join().unwrap(),
            stderr: err.join().unwrap(),
        }
    }

    /// A fresh directory for `var` below `env`. `HOMEDRIVE` and `HOMEPATH` combine to a
    /// directory there too (`HOMEPATH` is a rooted path without a drive).
    fn decoy(env: &Path, var: &str) -> OsString {
        if var == "HOMEPATH" {
            return OsString::from(r"\HOMEPATH");
        }
        let dir = env.join(var.replace(['(', ')'], "_"));
        std::fs::create_dir(&dir).unwrap();
        if var == "HOMEDRIVE" {
            std::fs::create_dir(dir.join("HOMEPATH")).unwrap();
        }
        dir.into_os_string()
    }
}
