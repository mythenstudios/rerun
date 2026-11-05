//! `detect::pe` on real executables of this machine (ADR 0013), read-only.
//!
//! - Smoke tests (in CI): `kernel32.dll`, `ntdll.dll` and `notepad.exe` of System32, and
//!   `kernel32.dll` of SysWOW64 if present, opened handle-relative below the Windows folder
//!   through `WinSystem`.
//! - Manual dumps (`#[ignore]`, user decision 6, never in CI, output never committed):
//!   `dump_system32_pe` parses every top-level `*.exe` and `*.dll` of System32 and SysWOW64 and
//!   prints a summary per outcome; `dump_game_exes` runs `steam::scan`, opens every game folder
//!   with `open_game` and parses each top-level `*.exe` through `open_game_exe`;
//!   `dump_exe_candidates` (ADR 0014) runs `detect::exe::scan_game` for every game folder and
//!   prints candidates, roles, API verdicts with their evidence, the main executable, walk
//!   statistics, issues and times, then a summary of the observed graphics import
//!   combinations (hashes only with `RERUN_DUMP_HASHES=1`). All write nothing, print names
//!   only escaped (`{:?}`) and version strings only as their length.
//!   Run by hand: `cargo test -p rerun-core --test pe_system dump_ -- --ignored --nocapture`
//!   (all), or name one dump instead of `dump_`.

#![cfg(windows)]
#![expect(
    clippy::disallowed_methods,
    reason = "test opens the Windows folder by absolute path (Fs::open_dir), read-only"
)]

use std::collections::BTreeMap;
use std::io::Write;

use rerun_core::detect::pe::{
    Limits, Machine, Pe, PeErrorKind, PeFormat, PeInfo, PeReadError, layout, open_game_exe,
};
use rerun_core::detect::text::RawText;
use rerun_core::path::RelPath;
use rerun_core::sys::fs::EntryKind;
use rerun_core::sys::win::WinSystem;
use rerun_core::sys::{Dir, KnownFolder, SysErrorKind, System};

/// Not captured by `cargo test` (like `dump_steam_scan`).
fn note(msg: &str) {
    let _ = writeln!(std::io::stderr(), "{msg}");
}

fn rel(s: &str) -> RelPath {
    RelPath::parse(s).unwrap_or_else(|e| panic!("{s}: {e}"))
}

/// The Windows folder, opened through the system layer.
fn windows(sys: &WinSystem) -> Box<dyn Dir + '_> {
    let path = sys
        .known_folders()
        .get(KnownFolder::Windows)
        .unwrap_or_else(|e| panic!("{e}"));
    sys.fs().open_dir(&path).unwrap_or_else(|e| panic!("{e}"))
}

fn info(dir: &dyn Dir, file: &str) -> PeInfo {
    let reader = dir.open_read(&rel(file)).unwrap_or_else(|e| panic!("{e}"));
    let mut pe = Pe::parse(reader, &Limits::DEFAULT).unwrap_or_else(|e| panic!("{file}: {e}"));
    let info = pe.info().unwrap_or_else(|e| panic!("{file}: {e}"));
    assert!(pe.bytes_read() <= Limits::DEFAULT.max_read_bytes);
    info
}

fn text(t: Option<&RawText>) -> &str {
    t.map_or("", RawText::as_raw_str)
}

/// The machine of this test binary (System32 holds native images).
fn native() -> Machine {
    if cfg!(target_arch = "aarch64") {
        Machine::Arm64
    } else {
        Machine::X64
    }
}

#[test]
fn system32_kernel32_and_ntdll() {
    let sys = WinSystem::new().unwrap();
    let win = windows(&sys);

    let k = info(&*win, r"System32\kernel32.dll");
    assert_eq!(k.headers.machine, native());
    assert_eq!(k.headers.format, PeFormat::Pe32Plus);
    assert!(k.headers.is_dll() && !k.headers.managed);
    assert!(
        k.imports
            .iter()
            .any(|d| d.eq_ignore_ascii_case("ntdll.dll")),
        "{:?}",
        k.imports
    );
    let v = k.version.unwrap().unwrap();
    let fixed = v.fixed.unwrap();
    assert!(fixed.file_version[0] >= 10, "{:?}", fixed.file_version);
    assert!(
        text(v.strings.original_filename.as_ref())
            .to_ascii_lowercase()
            .starts_with("kernel32"),
        "OriginalFilename of {} bytes",
        v.strings.original_filename.as_ref().map_or(0, RawText::len)
    );
    assert!(!text(v.strings.file_description.as_ref()).is_empty());
    assert!(!text(v.strings.product_version.as_ref()).is_empty());

    // ntdll imports nothing.
    let n = info(&*win, r"System32\ntdll.dll");
    assert_eq!(n.headers.machine, native());
    assert!(n.headers.is_dll());
    assert!(n.imports.is_empty(), "{:?}", n.imports);
    assert!(n.delay_imports.is_empty(), "{:?}", n.delay_imports);
    assert!(n.version.unwrap().is_some());
}

#[test]
fn system32_notepad() {
    let sys = WinSystem::new().unwrap();
    let win = windows(&sys);
    match win.open_read(&rel(r"System32\notepad.exe")) {
        Ok(_) => {}
        // Not every edition ships the inbox notepad.
        Err(e) if e.kind == SysErrorKind::NotFound => {
            note("System32\\notepad.exe: not present, skipped");
            return;
        }
        Err(e) => panic!("{e}"),
    }
    let n = info(&*win, r"System32\notepad.exe");
    assert_eq!(n.headers.machine, native());
    assert!(!n.headers.is_dll());
    assert_eq!(n.headers.subsystem, layout::SUBSYSTEM_WINDOWS_GUI);
    assert!(!n.imports.is_empty());
    assert!(n.version.unwrap().is_some());
}

#[test]
fn syswow64_kernel32() {
    let sys = WinSystem::new().unwrap();
    let win = windows(&sys);
    match win.open_read(&rel(r"SysWOW64\kernel32.dll")) {
        Ok(_) => {}
        Err(e) if e.kind == SysErrorKind::NotFound => {
            note("SysWOW64\\kernel32.dll: not present, skipped");
            return;
        }
        Err(e) => panic!("{e}"),
    }
    let k = info(&*win, r"SysWOW64\kernel32.dll");
    assert_eq!(k.headers.machine, Machine::X86);
    assert_eq!(k.headers.format, PeFormat::Pe32);
    assert!(k.headers.is_dll());
    assert!(
        k.imports
            .iter()
            .any(|d| d.eq_ignore_ascii_case("ntdll.dll")),
        "{:?}",
        k.imports
    );
    assert!(k.version.unwrap().unwrap().fixed.is_some());
}

// ---------- Manual dumps (read-only, never in CI) ----------

/// Top-level files of `dir` ending in one of `exts` (ASCII case-insensitive), as relative
/// paths; names that are no valid path segment are counted, not opened.
fn top_level(dir: &dyn Dir, sub: Option<&RelPath>, exts: &[&str]) -> (Vec<RelPath>, usize) {
    let entries = match dir.read_dir(sub) {
        Ok(e) => e,
        Err(e) => {
            note(&format!("listing failed: {e}"));
            return (Vec::new(), 0);
        }
    };
    let mut files = Vec::new();
    let mut skipped = 0;
    for e in entries {
        let lower = e.name.to_ascii_lowercase();
        if !exts.iter().any(|x| lower.ends_with(x)) {
            continue;
        }
        if e.meta.kind != EntryKind::File || e.meta.restricted {
            skipped += 1;
            continue;
        }
        let path = match sub {
            Some(s) => s.child(&e.name),
            None => RelPath::from_segment(&e.name),
        };
        match path {
            Ok(p) => files.push(p),
            Err(_) => skipped += 1,
        }
    }
    files.sort_by(|a, b| a.as_str().cmp(b.as_str()));
    (files, skipped)
}

fn machine(m: Machine) -> String {
    match m {
        Machine::X86 => "x86".to_owned(),
        Machine::X64 => "x64".to_owned(),
        Machine::Arm64 => "arm64".to_owned(),
        Machine::Other(raw) => format!("machine {raw:#06x}"),
    }
}

fn outcome(r: &Result<PeInfo, PeReadError>) -> String {
    match r {
        Ok(i) => {
            let version = match &i.version {
                Ok(Some(_)) => "version",
                Ok(None) => "no version",
                Err(_) => "version error",
            };
            format!("ok {} {version}", machine(i.headers.machine))
        }
        Err(PeReadError::Open { source, .. }) => format!("open: {:?}", source.kind),
        Err(PeReadError::Parse { error, .. }) => match error.kind {
            PeErrorKind::Legacy(f) => format!("legacy {f:?}"),
            k => format!("parse: {k:?}"),
        },
        Err(e) => format!("other: {e}"),
    }
}

/// The error without the file name (the dumps print names only escaped): the system layer
/// escapes its targets, parse errors carry no content.
fn detail(e: &PeReadError) -> String {
    match e {
        PeReadError::Open { source, .. } => source.to_string(),
        PeReadError::Parse { error, .. } => error.to_string(),
        _ => "unknown error".to_owned(),
    }
}

/// `info` of `file` below `dir`, and the bytes read for it.
fn read_info(dir: &dyn Dir, file: &RelPath) -> (Result<PeInfo, PeReadError>, u64) {
    let parse = |error| PeReadError::Parse {
        file: file.clone(),
        error,
    };
    let reader = match dir.open_read(file) {
        Ok(r) => r,
        Err(source) => {
            let e = PeReadError::Open {
                file: file.clone(),
                source,
            };
            return (Err(e), 0);
        }
    };
    match Pe::parse(reader, &Limits::DEFAULT) {
        Ok(mut pe) => {
            let info = pe.info().map_err(parse);
            (info, pe.bytes_read())
        }
        Err(error) => (Err(parse(error)), 0),
    }
}

/// Parses every top-level `*.exe` and `*.dll` of System32 and SysWOW64 and prints a summary
/// per outcome, the files with an error or a version error by name (escaped). Read-only.
/// Run by hand: `cargo test -p rerun-core --test pe_system dump_system32_pe -- --ignored
/// --nocapture`.
#[test]
#[ignore = "reads every executable of System32 and SysWOW64; run by hand, never in CI"]
fn dump_system32_pe() {
    let sys = WinSystem::new().unwrap_or_else(|e| panic!("{e}"));
    let win = windows(&sys);
    for folder in ["System32", "SysWOW64"] {
        let started = std::time::Instant::now();
        let sub = rel(folder);
        let (files, skipped) = top_level(&*win, Some(&sub), &[".exe", ".dll"]);
        let mut summary: BTreeMap<String, usize> = BTreeMap::new();
        let mut most = 0u64;
        for file in &files {
            let (r, read) = read_info(&*win, file);
            most = most.max(read);
            let o = outcome(&r);
            let why = match &r {
                Ok(i) => i.version.as_ref().err().map(ToString::to_string),
                Err(e) => Some(detail(e)),
            };
            if let Some(why) = why {
                note(&format!("  {:?}: {o} ({why})", file.as_str()));
            }
            *summary.entry(o).or_default() += 1;
        }
        note(&format!(
            "{folder}: {} files, {skipped} skipped (not a plain file or no valid name), \
             most bytes read for one file {most}, took {:?}",
            files.len(),
            started.elapsed()
        ));
        for (o, n) in &summary {
            note(&format!("  {n:6}  {o}"));
        }
    }
}

/// Runs `steam::scan`, opens every game folder with `open_game` and parses each top-level
/// `*.exe` through `open_game_exe`. Prints app IDs, exe names escaped, the facts, DLL names
/// (printable ASCII by construction) and version strings only as their length. Read-only.
/// Run by hand: `cargo test -p rerun-core --test pe_system dump_game_exes -- --ignored
/// --nocapture`.
#[test]
#[ignore = "reads this machine's Steam games; run by hand, never in CI"]
fn dump_game_exes() {
    use rerun_core::detect::steam::scan;
    use rerun_core::policy::root::ForbiddenRoots;

    let sys = WinSystem::new().unwrap_or_else(|e| panic!("{e}"));
    let exe = std::env::current_exe().unwrap_or_else(|e| panic!("current_exe: {e}"));
    let install = exe
        .parent()
        .unwrap_or_else(|| panic!("the test binary has no folder"));
    let fr = ForbiddenRoots::resolve(&sys, install).unwrap_or_else(|e| panic!("{e}"));
    let started = std::time::Instant::now();
    let s = scan(&sys, &fr);
    let mut summary: BTreeMap<String, usize> = BTreeMap::new();
    for lib in &s.libraries {
        for app in lib.apps() {
            let game = match lib.open_game(&fr, app.app_id) {
                Ok(g) => g,
                Err(e) => {
                    // As in `dump_steam_scan`: root errors escape raw names.
                    note(&format!("app {}: game folder: {e}", app.app_id));
                    continue;
                }
            };
            let (exes, skipped) = top_level(game.dir(), None, &[".exe"]);
            note(&format!(
                "app {} installdir {:?}: {} exe, {skipped} skipped",
                app.app_id,
                app.install_dir.as_str(),
                exes.len()
            ));
            for file in &exes {
                let r = open_game_exe(&game, file, &Limits::DEFAULT).and_then(|mut pe| {
                    pe.info().map_err(|error| PeReadError::Parse {
                        file: file.clone(),
                        error,
                    })
                });
                let o = outcome(&r);
                match &r {
                    Ok(i) => {
                        let h = &i.headers;
                        let names = |v: &[rerun_core::detect::pe::DllName]| {
                            v.iter()
                                .map(|d| d.as_str().to_owned())
                                .collect::<Vec<_>>()
                                .join(" ")
                        };
                        let version = match &i.version {
                            Ok(Some(v)) => format!(
                                "fixed {:?}, table {:?}, strings (bytes) company {} \
                                 description {} file {} original {} product {} \
                                 product version {}",
                                v.fixed.map(|f| f.file_version),
                                v.table,
                                v.strings.company_name.as_ref().map_or(0, RawText::len),
                                v.strings.file_description.as_ref().map_or(0, RawText::len),
                                v.strings.file_version.as_ref().map_or(0, RawText::len),
                                v.strings.original_filename.as_ref().map_or(0, RawText::len),
                                v.strings.product_name.as_ref().map_or(0, RawText::len),
                                v.strings.product_version.as_ref().map_or(0, RawText::len),
                            ),
                            Ok(None) => "no version resource".to_owned(),
                            Err(e) => format!("version: {e}"),
                        };
                        note(&format!(
                            "  {:?}: {} {:?} laa {} subsystem {} managed {}; imports [{}]; \
                             delay [{}]; {version}",
                            file.as_str(),
                            machine(h.machine),
                            h.format,
                            h.large_address_aware(),
                            h.subsystem,
                            h.managed,
                            names(&i.imports),
                            names(&i.delay_imports),
                        ));
                    }
                    Err(e) => note(&format!("  {:?}: {o} ({})", file.as_str(), detail(e))),
                }
                *summary.entry(o).or_default() += 1;
            }
        }
    }
    for issue in &s.issues {
        note(&format!("issue: {issue}"));
    }
    note(&format!(
        "games: {} libraries, took {:?}",
        s.libraries.len(),
        started.elapsed()
    ));
    for (o, n) in &summary {
        note(&format!("  {n:6}  {o}"));
    }
}

// ---------- Exe candidates (ADR 0014; read-only, never in CI) ----------

/// `RERUN_DUMP_HASHES=1` turns hashing on for `dump_exe_candidates`. A test gate, never a path.
#[expect(
    clippy::disallowed_methods,
    reason = "test gate for the manual dump, not a source of paths (ADR 0009)"
)]
fn dump_hashes() -> bool {
    std::env::var_os("RERUN_DUMP_HASHES").is_some_and(|v| v == "1")
}

/// Graphics-related DLL names (lowercase) of a table, for the summary of combinations: what
/// `detect::exe::api` maps and its near misses (`d3dcompiler_*`, `dxgi*`, engines).
fn graphics_dlls(dlls: &[rerun_core::detect::pe::DllName]) -> Vec<String> {
    const PREFIXES: &[&str] = &[
        "d3d",
        "dx",
        "ddraw",
        "opengl",
        "glu",
        "vulkan",
        "glide",
        "unityplayer",
    ];
    let mut out: Vec<String> = dlls
        .iter()
        .map(|d| d.as_str().to_ascii_lowercase())
        .filter(|n| {
            PREFIXES.iter().any(|p| n.starts_with(p)) || n == "core.dll" || n == "engine.dll"
        })
        .collect();
    out.sort();
    out.dedup();
    out
}

fn api_set(set: &rerun_core::detect::exe::ApiSet) -> String {
    set.iter().map(|a| a.as_str()).collect::<Vec<_>>().join(",")
}

/// Runs `steam::scan`, then `detect::exe::scan_game` for every game folder, and prints per
/// game the candidates (paths escaped) with role, depth, similarity, machine, subsystem, LAA,
/// CLR, the API verdict and its evidence, the DLL names (printable ASCII by construction),
/// version strings only as their length, the main executable, the walk statistics, the issues
/// and the time; then a summary of roles, verdicts and observed combinations of graphics
/// imports. Hashes only with `RERUN_DUMP_HASHES=1`. Read-only: writes nothing.
/// Run by hand: `cargo test -p rerun-core --test pe_system dump_exe_candidates -- --ignored
/// --nocapture`.
#[test]
#[ignore = "reads this machine's Steam games; run by hand, never in CI"]
fn dump_exe_candidates() {
    use rerun_core::detect::exe::{ExeIssueKind, HashOutcome, Main, Options, scan_game};
    use rerun_core::detect::steam::scan;
    use rerun_core::policy::root::ForbiddenRoots;

    let sys = WinSystem::new().unwrap_or_else(|e| panic!("{e}"));
    let exe = std::env::current_exe().unwrap_or_else(|e| panic!("current_exe: {e}"));
    let install = exe
        .parent()
        .unwrap_or_else(|| panic!("the test binary has no folder"));
    let fr = ForbiddenRoots::resolve(&sys, install).unwrap_or_else(|e| panic!("{e}"));
    let hashes = dump_hashes();
    let started = std::time::Instant::now();
    let s = scan(&sys, &fr);

    let mut games = 0usize;
    let mut candidates = 0usize;
    let mut mains: BTreeMap<&str, usize> = BTreeMap::new();
    let mut roles: BTreeMap<String, usize> = BTreeMap::new();
    let mut verdicts: BTreeMap<String, usize> = BTreeMap::new();
    let mut combos: BTreeMap<String, usize> = BTreeMap::new();
    let mut issue_kinds: BTreeMap<String, usize> = BTreeMap::new();
    let mut incomplete = 0usize;
    let mut hashed_bytes = 0u64;
    let mut most_dirs = 0usize;
    let mut most_entries = 0usize;
    let mut slowest = std::time::Duration::ZERO;

    for lib in &s.libraries {
        for app in lib.apps() {
            let game = match lib.open_game(&fr, app.app_id) {
                Ok(g) => g,
                Err(e) => {
                    // As in `dump_steam_scan`: root errors escape raw names.
                    note(&format!("app {}: game folder: {e}", app.app_id));
                    continue;
                }
            };
            games += 1;
            let options = Options {
                name_hint: Some(app.install_dir.clone()),
                hashes,
                ..Options::default()
            };
            let t = std::time::Instant::now();
            let r = scan_game(&game, &options);
            let took = t.elapsed();
            slowest = slowest.max(took);
            drop(game);

            let main = match &r.main {
                Main::One(i) => {
                    *mains.entry("one").or_default() += 1;
                    format!("{:?}", r.candidates[*i].path.as_str())
                }
                Main::Tied(v) => {
                    *mains.entry("tied").or_default() += 1;
                    let tied: Vec<String> = v
                        .iter()
                        .map(|i| format!("{:?}", r.candidates[*i].path.as_str()))
                        .collect();
                    format!("tied [{}]", tied.join(", "))
                }
                Main::None => {
                    *mains.entry("none").or_default() += 1;
                    "none".to_owned()
                }
            };
            let st = &r.stats;
            if !st.complete {
                incomplete += 1;
            }
            most_dirs = most_dirs.max(st.listed_dirs);
            most_entries = most_entries.max(st.entries);
            let skipped: Vec<String> = st
                .skipped_dirs
                .iter()
                .map(|p| format!("{:?}", p.as_str()))
                .collect();
            note(&format!(
                "app {} installdir {:?}: {} candidates, main {main}; walk complete {}, {} dirs, \
                 {} entries, {} exes found, {} depth cut, skipped [{}]; took {took:?}",
                app.app_id,
                app.install_dir.as_str(),
                r.candidates.len(),
                st.complete,
                st.listed_dirs,
                st.entries,
                st.exes_found,
                st.depth_cut,
                skipped.join(", "),
            ));
            candidates += r.candidates.len();
            for (i, c) in r.candidates.iter().enumerate() {
                *roles.entry(format!("{:?}", c.role)).or_default() += 1;
                let head = format!(
                    "  #{i} {:?}: {}, depth {}, similarity {}, listed {} bytes",
                    c.path.as_str(),
                    c.role,
                    c.depth,
                    c.similarity,
                    c.listed_len,
                );
                let f = match &c.facts {
                    Ok(f) => f,
                    Err(e) => {
                        *verdicts.entry("error".to_owned()).or_default() += 1;
                        let why = match e {
                            rerun_core::detect::exe::ExeError::Pe(pe) => detail(pe),
                            _ => "unknown error".to_owned(),
                        };
                        note(&format!("{head}; error: {why}"));
                        continue;
                    }
                };
                let h = &f.info.headers;
                let ev = &f.api.evidence;
                let verdict = format!("{:?}", f.api.verdict);
                let kind = verdict
                    .split([' ', '(', '{'])
                    .next()
                    .unwrap_or_default()
                    .to_owned();
                *verdicts.entry(kind).or_default() += 1;
                let names = |v: &[rerun_core::detect::pe::DllName]| {
                    v.iter()
                        .map(|d| d.as_str().to_owned())
                        .collect::<Vec<_>>()
                        .join(" ")
                };
                let combo = format!(
                    "{} | static [{}] | delay [{}]{}",
                    f.api,
                    graphics_dlls(&f.info.imports).join(" "),
                    graphics_dlls(&f.info.delay_imports).join(" "),
                    if h.managed { " | managed" } else { "" },
                );
                *combos.entry(combo).or_default() += 1;
                let version = match &f.info.version {
                    Ok(Some(v)) => format!(
                        "version fixed {:?}, strings (bytes) description {} product {} \
                         original {}",
                        v.fixed.map(|x| x.file_version),
                        v.strings.file_description.as_ref().map_or(0, RawText::len),
                        v.strings.product_name.as_ref().map_or(0, RawText::len),
                        v.strings.original_filename.as_ref().map_or(0, RawText::len),
                    ),
                    Ok(None) => "no version resource".to_owned(),
                    Err(e) => format!("version: {e}"),
                };
                let hash = match &f.hashes {
                    HashOutcome::NotRequested => String::new(),
                    HashOutcome::Done(d) => {
                        hashed_bytes += d.len;
                        format!("; {}", f.hashes)
                    }
                    other => format!("; hashes {other}"),
                };
                note(&format!(
                    "{head}; {} {:?} subsystem {} laa {} managed {}; api {} = {verdict} \
                     [static core {} helper {} dxgi {} | delay core {} helper {} dxgi {} | \
                     engine {:?}]; imports [{}]; delay [{}]; {version}; parser read {} \
                     bytes{hash}",
                    machine(h.machine),
                    h.format,
                    h.subsystem,
                    h.large_address_aware(),
                    h.managed,
                    f.api,
                    api_set(&ev.imports.core),
                    api_set(&ev.imports.helper),
                    ev.imports.dxgi,
                    api_set(&ev.delay.core),
                    api_set(&ev.delay.helper),
                    ev.delay.dxgi,
                    ev.engine,
                    names(&f.info.imports),
                    names(&f.info.delay_imports),
                    f.bytes_read,
                ));
            }
            for issue in &r.issues {
                let kind = match &issue.kind {
                    ExeIssueKind::Sys(_) => "sys",
                    ExeIssueKind::Anomaly(_) => "anomaly",
                    ExeIssueKind::CaseSensitiveDir => "case-sensitive dir",
                    ExeIssueKind::NotFollowed { .. } => "not followed",
                    ExeIssueKind::WalkLimit { .. } => "walk limit",
                    ExeIssueKind::TooManyExes { .. } => "too many exes",
                    _ => "other",
                };
                *issue_kinds.entry(kind.to_owned()).or_default() += 1;
                // Issues escape raw names and carry no file content (ADR 0014).
                note(&format!("  issue: {issue}"));
            }
        }
    }
    for issue in &s.issues {
        note(&format!("steam issue: {issue}"));
    }
    note(&format!(
        "summary: {games} games in {} libraries, {candidates} candidates, {incomplete} \
         incomplete walks, at most {most_dirs} dirs and {most_entries} entries in one game, \
         slowest game {slowest:?}, hashes {}, {hashed_bytes} bytes hashed; took {:?}",
        s.libraries.len(),
        if hashes { "on" } else { "off" },
        started.elapsed()
    ));
    note("main executables:");
    for (k, n) in &mains {
        note(&format!("  {n:6}  {k}"));
    }
    note("roles:");
    for (k, n) in &roles {
        note(&format!("  {n:6}  {k}"));
    }
    note("verdicts:");
    for (k, n) in &verdicts {
        note(&format!("  {n:6}  {k}"));
    }
    note("issues:");
    for (k, n) in &issue_kinds {
        note(&format!("  {n:6}  {k}"));
    }
    note("observed graphics import combinations (verdict | static | delay):");
    for (k, n) in &combos {
        note(&format!("  {n:6}  {k}"));
    }
}
