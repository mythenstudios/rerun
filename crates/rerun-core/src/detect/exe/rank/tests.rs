//! The rank key and the main executable (ADR 0014, "Ranking"). Pure; the facts are built by
//! hand.

use super::{Key, rank};
use crate::detect::exe::api::classify;
use crate::detect::exe::role::Role;
use crate::detect::exe::{Candidate, ExeError, ExeFacts, Main};
use crate::detect::pe::layout::{SUBSYSTEM_WINDOWS_CUI, SUBSYSTEM_WINDOWS_GUI};
use crate::detect::pe::{
    DllName, Headers, LegacyFormat, Machine, PeError, PeErrorKind, PeFormat, PeInfo, PeReadError,
};
use crate::path::RelPath;

fn rel(s: &str) -> RelPath {
    RelPath::parse(s).unwrap()
}

fn facts(imports: &[&str], subsystem: u16) -> ExeFacts {
    let imports: Vec<DllName> = imports.iter().map(|n| DllName::for_test(n)).collect();
    let api = classify(&imports, &[], false);
    ExeFacts {
        info: PeInfo {
            headers: Headers {
                machine: Machine::X64,
                format: PeFormat::Pe32Plus,
                characteristics: 0x0022,
                subsystem,
                dll_characteristics: 0,
                image_base: 0x1_4000_0000,
                size_of_headers: 0x400,
                section_count: 1,
                managed: false,
            },
            imports,
            delay_imports: Vec::new(),
            version: Ok(None),
        },
        api,
        bytes_read: 0,
    }
}

fn cand(path: &str, role: Role, facts: Result<ExeFacts, ExeError>) -> Candidate {
    Candidate {
        depth: path.matches('\\').count(),
        path: rel(path),
        listed_len: 0,
        similarity: 0,
        role,
        facts,
    }
}

fn game(path: &str, imports: &[&str]) -> Candidate {
    cand(path, Role::Game, Ok(facts(imports, SUBSYSTEM_WINDOWS_GUI)))
}

fn failed(path: &str, role: Role, kind: PeErrorKind) -> Candidate {
    let error = PeError { kind, offset: None };
    cand(
        path,
        role,
        Err(ExeError::Pe(PeReadError::Parse {
            file: rel(path),
            error,
        })),
    )
}

fn order(c: &[Candidate]) -> Vec<&str> {
    c.iter().map(|c| c.path.as_str()).collect()
}

#[test]
fn the_role_comes_first() {
    let mut c = vec![
        failed("broken.exe", Role::Game, PeErrorKind::NotExecutable),
        failed(
            "dos.exe",
            Role::Legacy(LegacyFormat::Dos),
            PeErrorKind::Legacy(LegacyFormat::Dos),
        ),
        cand(
            "dll.exe",
            Role::NotAnApp,
            Ok(facts(&["d3d9.dll"], SUBSYSTEM_WINDOWS_GUI)),
        ),
        cand(
            "setup.exe",
            Role::Installer,
            Ok(facts(&["d3d9.dll"], SUBSYSTEM_WINDOWS_GUI)),
        ),
        cand(
            "anti_be.exe",
            Role::AntiCheat,
            Ok(facts(&[], SUBSYSTEM_WINDOWS_GUI)),
        ),
        cand(
            "crash.exe",
            Role::CrashReporter,
            Ok(facts(&[], SUBSYSTEM_WINDOWS_GUI)),
        ),
        cand(
            "tool.exe",
            Role::Helper,
            Ok(facts(&["d3d11.dll"], SUBSYSTEM_WINDOWS_GUI)),
        ),
        cand(
            "launcher.exe",
            Role::Launcher,
            Ok(facts(&["d3d11.dll"], SUBSYSTEM_WINDOWS_GUI)),
        ),
        game(r"bin\x64\game.exe", &[]),
    ];
    let main = rank(&mut c);
    assert_eq!(
        order(&c),
        [
            r"bin\x64\game.exe",
            "launcher.exe",
            "tool.exe",
            // One group, then API strength (d3d9 first), then the path.
            "setup.exe",
            "anti_be.exe",
            "crash.exe",
            "dll.exe",
            "dos.exe",
            "broken.exe",
        ]
    );
    assert_eq!(main, Main::One(0));
}

#[test]
fn then_the_api_strength() {
    let mut c = vec![
        game("none.exe", &[]),
        game("dxgi.exe", &["dxgi.dll"]),
        game("helper.exe", &["d3dx9_43.dll"]),
        game("highest.exe", &["d3d9.dll", "d3d11.dll"]),
        game("only.exe", &["d3d9.dll"]),
    ];
    assert_eq!(rank(&mut c), Main::One(0));
    assert_eq!(
        order(&c),
        [
            "only.exe",
            "highest.exe",
            "helper.exe",
            "dxgi.exe",
            "none.exe"
        ]
    );
}

#[test]
fn then_gui_similarity_depth_and_path() {
    let console = |p: &str| {
        cand(
            p,
            Role::Game,
            Ok(facts(&["d3d9.dll"], SUBSYSTEM_WINDOWS_CUI)),
        )
    };
    let similar = |p: &str, s: u8| {
        let mut c = game(p, &["d3d9.dll"]);
        c.similarity = s;
        c
    };
    let mut c = vec![
        console("a_console.exe"),
        similar(r"deep\deeper\b.exe", 0),
        similar(r"deep\c.exe", 0),
        similar("z_prefix.exe", 1),
        similar("z_equal.exe", 2),
    ];
    assert_eq!(rank(&mut c), Main::One(0));
    assert_eq!(
        order(&c),
        [
            "z_equal.exe",
            "z_prefix.exe",
            r"deep\c.exe",
            r"deep\deeper\b.exe",
            "a_console.exe"
        ]
    );
}

#[test]
fn equal_keys_are_tied_in_path_order() {
    let mut c = vec![
        game("Invented_Dx10.exe", &["d3d10.dll"]),
        game("Invented_Dx9.exe", &["d3d9.dll"]),
        cand(
            "launcher.exe",
            Role::Launcher,
            Ok(facts(&["d3d9.dll"], SUBSYSTEM_WINDOWS_GUI)),
        ),
        game(r"bin\other.exe", &["d3d9.dll"]),
    ];
    assert_eq!(rank(&mut c), Main::Tied(vec![0, 1]));
    assert_eq!(
        order(&c),
        [
            "Invented_Dx10.exe",
            "Invented_Dx9.exe",
            r"bin\other.exe",
            "launcher.exe"
        ]
    );
}

#[test]
fn no_parsed_game_is_no_main_and_a_launcher_never_is() {
    let mut c = vec![
        cand(
            "launcher.exe",
            Role::Launcher,
            Ok(facts(&["d3d11.dll"], SUBSYSTEM_WINDOWS_GUI)),
        ),
        cand(
            "config.exe",
            Role::Helper,
            Ok(facts(&[], SUBSYSTEM_WINDOWS_GUI)),
        ),
    ];
    assert_eq!(rank(&mut c), Main::None);
    assert_eq!(order(&c), ["launcher.exe", "config.exe"]);

    let mut c = vec![
        failed("game.exe", Role::Game, PeErrorKind::Truncated),
        failed(
            "dos.exe",
            Role::Legacy(LegacyFormat::Dos),
            PeErrorKind::Legacy(LegacyFormat::Dos),
        ),
    ];
    assert_eq!(rank(&mut c), Main::None);
    assert_eq!(order(&c), ["dos.exe", "game.exe"]);

    let mut c: Vec<Candidate> = Vec::new();
    assert_eq!(rank(&mut c), Main::None);
}

#[test]
fn the_key_ignores_the_path() {
    let a = game("a.exe", &["d3d9.dll"]);
    let b = game("b.exe", &["d3d9.dll"]);
    assert_eq!(Key::of(&a), Key::of(&b));
    let open = cand(
        "c.exe",
        Role::Game,
        Err(ExeError::Pe(PeReadError::Open {
            file: rel("c.exe"),
            source: crate::sys::SysError::new(crate::sys::SysErrorKind::Busy, "c.exe"),
        })),
    );
    assert!(Key::of(&open) > Key::of(&a));
}
