//! Tests of `flow` against the fake system layer (P5-1). The CLI's tests run every read
//! command through `flow` with golden output (`rerun-cli`); `rerun-cli/src/flow_tests.rs` runs
//! `flow::game` on an index signed with the test key. Here:
//! - FG1 the guard order: an elevated process stops at the first gate and nothing is read; an
//!   unknown install folder stops before the forbidden roots; unresolvable forbidden roots stop
//!   before a Rerun folder that cannot be opened (control: that folder alone is
//!   `Gate::AppDir`); a passed guard never creates Rerun's folder.
//! - FF1 to FF3 the fixes of a report: one fix per variant ID with one `Solved` per issue that
//!   names it (`when` per issue), the refusal per variant kept, warned kinds merged once.
//! - FL1 the library without Steam: the Steam event, no library, the requested app IDs missing
//!   once each in the order asked; a `Break` stops the stream and is returned.
//! - FL2 (moved from `rerun-cli`) the counts: a failed game candidate is an issue whatever
//!   the main executable, a failed installer is not.
//! - FS1 the status of an empty Rerun folder: no transaction, no launch folder, no holder.

use std::ops::ControlFlow;
use std::path::{Path, PathBuf};

use crate::catalog::Topo;
use crate::detect::steam::RootSource;
use crate::policy::root::{AppDir, Create};
use crate::sys::KnownFolder;
use crate::sys::fake::{FakeHttp, FakeSystem};
use crate::topo::{AntiCheatState, LaunchProblem, Refusal, StepKind, Tri};

use super::{
    Env, Gate, IssueView, LibraryEvent, OwnedReport, VariantView, fixes, guard, library, open_app,
    status,
};

const INSTALL: &str = r"C:\Users\Player\AppData\Local\Programs\Rerun";
const RERUN: &str = r"C:\Users\Player\AppData\Local\Rerun";

fn sys() -> FakeSystem {
    FakeSystem::builder()
        .windows_layout()
        .dir(INSTALL)
        .build()
        .unwrap()
}

fn install() -> Result<PathBuf, String> {
    Ok(PathBuf::from(INSTALL))
}

#[test]
fn fg1_the_guard_order() {
    let http = FakeHttp::default();
    let s = sys();
    let ok = install();
    // Elevated: the first gate, nothing of the file system read.
    s.fake_registry().set_elevated(true);
    s.fake_fs().record_calls(true);
    let g = guard(Env {
        sys: &s,
        http: &http,
        install: &ok,
    });
    assert!(matches!(g, Err(Gate::Elevated(_))));
    let calls = s.fake_fs().take_calls();
    assert!(calls.is_empty(), "{calls:?}");
    s.fake_registry().set_elevated(false);
    // The install folder unknown: before the forbidden roots, nothing read.
    let unknown = Err("no current exe".to_owned());
    let g = guard(Env {
        sys: &s,
        http: &http,
        install: &unknown,
    });
    assert!(matches!(g, Err(Gate::InstallUnknown(e)) if e == "no current exe"));
    let calls = s.fake_fs().take_calls();
    assert!(calls.is_empty(), "{calls:?}");
    // Forbidden roots that do not resolve (the Windows folder unknown) while Rerun's folder
    // cannot be opened either (a file at its name): the forbidden roots come first.
    let bare = FakeSystem::builder()
        .windows_layout()
        .dir(INSTALL)
        .file(RERUN, b"not a folder".to_vec())
        .without_known_folder(KnownFolder::Windows)
        .build()
        .unwrap();
    let g = guard(Env {
        sys: &bare,
        http: &http,
        install: &ok,
    });
    assert!(matches!(g, Err(Gate::Forbidden(_))));
    // Control: in that world Rerun's folder alone is refused, so a swapped order would give
    // `Gate::AppDir`.
    assert!(matches!(open_app(&bare), Err(Gate::AppDir(_))));
    // Passed: Rerun's folder is opened only if it exists, never created.
    let g = guard(Env {
        sys: &s,
        http: &http,
        install: &ok,
    })
    .map_err(|_| "guard")
    .unwrap();
    // Control: a guard that passes reads (the record above bites).
    assert!(!s.fake_fs().take_calls().is_empty());
    s.fake_fs().record_calls(false);
    assert!(g.app().is_none());
    drop(g);
    assert!(AppDir::open(&s, Create::Never).unwrap().is_none());
    assert!(open_app(&s).unwrap().is_none());
}

/// A Topo in the shape of Assassin's Creed (invented IDs and steps): one variant ID under two
/// issues, and a second variant under the second issue.
fn topo() -> Topo {
    let step = r#"{"compat_layer":{"exe":"game.exe","layers":["HIGHDPIAWARE"]}}"#;
    let src = r#"{"type":"repo","url":"https://github.com/example/patch"}"#;
    serde_json::from_str(&format!(
        r#"{{"format":1,"id":"invented-game","title":"Invented Game","status":"active","rev":1,
"match":{{"steam_appid":220,"exes":[{{"path":"game.exe","sha256":"{h}","api":"d3d9"}}]}},
"issues":[
 {{"id":"controller","title":"Controllers","variants":[{{"id":"patch","status":"unverified","kind":"fix","steps":[{step}],"sources":[{src}]}}]}},
 {{"id":"online","title":"Online","when":{{"gpu.vendor":"nvidia"}},"variants":[
   {{"id":"patch","status":"verified","kind":"fix","steps":[{step}],"sources":[{src},{src}]}},
   {{"id":"limit","status":"verified","kind":"fix","steps":[{{"cpu":{{"max_threads":8}}}}]}}]}}
]}}"#,
        h = "0".repeat(64)
    ))
    .unwrap()
}

/// The report of [`topo`] with `refused`/`warned` per (issue, variant).
fn report(when: [Tri; 2], per: &[(usize, usize, Option<Refusal>, Vec<StepKind>)]) -> OwnedReport {
    let t = topo();
    let issues = t
        .issues
        .iter()
        .enumerate()
        .map(|(i, issue)| IssueView {
            issue: issue.clone(),
            when: when[i],
            variants: issue
                .variants
                .iter()
                .enumerate()
                .map(|(v, variant)| {
                    let (refused, warned) = per
                        .iter()
                        .find(|(pi, pv, ..)| (*pi, *pv) == (i, v))
                        .map_or((None, Vec::new()), |(_, _, r, w)| (*r, w.clone()));
                    VariantView {
                        variant: variant.clone(),
                        refused,
                        warned,
                    }
                })
                .collect(),
        })
        .collect();
    OwnedReport {
        topo: t,
        main_exe: None,
        launch: Err(LaunchProblem::NoMethod),
        anti_cheat: AntiCheatState::Clear,
        issues,
        several_gpus: false,
    }
}

#[test]
fn ff1_one_fix_per_variant_id() {
    let f = fixes(&report([Tri::Yes, Tri::No], &[]));
    let ids: Vec<&str> = f.iter().map(|f| f.variant.as_str()).collect();
    assert_eq!(ids, ["patch", "limit"]);
    let patch = &f[0];
    let solved: Vec<(&str, Tri, usize)> = patch
        .solves
        .iter()
        .map(|s| (s.issue.as_str(), s.when, s.sources.len()))
        .collect();
    // `when` and the evidence stay per issue.
    assert_eq!(
        solved,
        [("controller", Tri::Yes, 1), ("online", Tri::No, 2)]
    );
    assert_eq!(patch.refused, None);
    assert_eq!(f[1].solves.len(), 1);
}

#[test]
fn ff2_the_refusal_per_variant_is_kept_apart_from_when() {
    let ac = Some(Refusal::AntiCheat(StepKind::CompatLayer));
    let f = fixes(&report(
        [Tri::Yes, Tri::Yes],
        &[(0, 0, ac, Vec::new()), (1, 0, ac, Vec::new())],
    ));
    assert_eq!(f[0].refused, ac);
    assert!(f[0].solves.iter().all(|s| s.when == Tri::Yes));
    // The other variant of the second issue is not refused.
    assert_eq!(f[1].refused, None);
}

#[test]
fn ff3_a_drift_between_copies_refuses_and_merges_warnings() {
    let ac = Some(Refusal::AntiCheat(StepKind::CompatLayer));
    let f = fixes(&report(
        [Tri::Yes, Tri::Unknown],
        &[
            (0, 0, None, vec![StepKind::IniSet]),
            (1, 0, ac, vec![StepKind::IniSet, StepKind::RegistrySet]),
        ],
    ));
    assert_eq!(
        f[0].refused, ac,
        "fail closed: the first refusal of any copy"
    );
    assert_eq!(f[0].warned, [StepKind::IniSet, StepKind::RegistrySet]);
}

#[test]
fn fl1_the_library_without_steam() {
    let s = sys();
    let ok = install();
    let fr = super::forbidden_roots(&s, &ok).map_err(|_| "fr").unwrap();
    let mut seen = Vec::new();
    let facts = library::<()>(&s, &fr, &[7, 9, 7], false, &mut |ev| {
        seen.push(match ev {
            LibraryEvent::Steam(st) => format!("steam {:?}", st.root.map(RootSource::key)),
            LibraryEvent::Library { index, .. } => format!("library {index}"),
            LibraryEvent::Row { app, .. } => format!("app {}", app.app_id),
        });
        ControlFlow::Continue(())
    })
    .unwrap();
    assert_eq!(seen, ["steam None"]);
    assert_eq!(facts.missing, [7, 9]);
    assert_eq!(facts.counts.libraries, 0);
    assert_eq!(facts.counts.apps, 0);
    let stopped = library(&s, &fr, &[], false, &mut |_| ControlFlow::Break("closed"));
    assert_eq!(stopped, Err("closed"));
}

#[test]
fn fl2_a_failed_game_candidate_is_an_issue_whatever_the_main_executable() {
    use crate::detect::exe::{Candidate, ExeError, GameExes, Main, Role, WalkStats};
    use crate::detect::pe::{PeError, PeErrorKind, PeReadError};
    use crate::path::RelPath;
    let failed = |path: &str, role| Candidate {
        path: RelPath::parse(path).unwrap(),
        depth: 0,
        listed_len: 1 << 20,
        similarity: 0,
        role,
        facts: Err(ExeError::Pe(PeReadError::Parse {
            file: RelPath::parse(path).unwrap(),
            error: PeError {
                kind: PeErrorKind::Truncated,
                offset: Some(0x3c),
            },
        })),
    };
    let exes = GameExes {
        stats: WalkStats {
            complete: true,
            listed_dirs: 1,
            entries: 2,
            exes_found: 2,
            depth_cut: 0,
            skipped_dirs: Vec::new(),
        },
        candidates: vec![
            failed("game_dx12.exe", Role::Game),
            failed("setup.exe", Role::Installer),
        ],
        main: Main::One(0),
        issues: Vec::new(),
        anti_cheat: crate::detect::exe::AntiCheatScan::default(),
    };
    let mut counts = super::LibraryCounts::default();
    super::library::tally(&mut counts, &exes);
    // One main executable; the failed game candidate is an issue, the installer is not.
    assert_eq!((counts.one, counts.issues), (1, 1));
}

#[test]
fn fs1_the_status_of_an_empty_folder() {
    let s = sys();
    s.fake_fs().mkdir_all(Path::new(RERUN)).unwrap();
    s.fake_fs().sync_all();
    let app = open_app(&s).map_err(|_| "app").unwrap().unwrap();
    let v = status(&s, &app).unwrap();
    assert!(v.status.txns.is_empty());
    assert!(v.holders.is_empty());
    assert!(matches!(v.launch, Ok(None)));
}
