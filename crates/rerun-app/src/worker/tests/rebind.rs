//! The rebind dialog through the worker (P5-6c, ADR 0027 amendment P5-6c), in the fake world of
//! the write tests, with a Steam library that is moved to another volume after the apply.
//! - AB1 the undo of a moved game folder halts, its dialog says the game folder has changed and
//!   offers "Check new folder" (never confirmable itself); the rebind preview writes nothing
//!   (Rerun's folder and the new folder snapshots), names the old and the new folder, the fates
//!   there and that the binding is permanent; the confirm binds and undoes: the new folder is
//!   as it was before the apply, the transaction is closed, the history lists it as undone.
//! - AB2 the new folder changes between the preview and the click: `Changed`, nothing written,
//!   the preview again with a calm note; the click on that one completes.
//! - AB3 a confirm that carries an older nonce writes nothing and shows the current preview.
//! - AB4 (VB2) the registry note appears only for a change with registry ops, and every folder
//!   the dialog names is escaped text.
//! - AB5 a change that was not moved needs no rebind: the undo dialog has no second button, and
//!   a rebind preview of it is the plain refusal "every folder opens as recorded".

use std::path::Path;

use rerun_core::sys::System;
use rerun_core::sys::fake::FakeSystem;
use rerun_core::sys::fs::Fs;
use rerun_core::sys::snapshot::{Scope, SnapRoot, Snapshot, snapshot};

use super::write::{RERUN, Rig, applied_of, dialog_of, result_of};
use super::*;
use crate::vm::{DialogKind, Selection, Tone};

pub(super) const LIB_E: &str = r"E:\SteamLibrary";
pub(super) const GAME_E: &str = r"E:\SteamLibrary\steamapps\common\G";
const FILES: [&str; 3] = ["game.exe", "FFLauncher.exe", "game.ini"];

#[allow(clippy::disallowed_methods, reason = "test: copy a fixture tree")]
fn read(sys: &FakeSystem, abs: &str) -> Vec<u8> {
    use rerun_core::path::RelPath;
    let p = Path::new(abs);
    let d = sys.fake_fs().open_dir(p.parent().unwrap()).unwrap();
    d.read(&RelPath::parse(&p.file_name().unwrap().to_string_lossy()).unwrap())
        .unwrap()
}

#[allow(clippy::disallowed_methods, reason = "test: look at a fixture folder")]
fn is_gone(sys: &FakeSystem, abs: &str) -> bool {
    sys.fake_fs().open_dir(Path::new(abs)).is_err()
}

/// Steam's "move library" to another volume: the game's files copied (new file IDs), the old
/// ones removed, the manifest moved, the library list names the Steam folder, the old library
/// (it still holds the other apps) and the new one.
pub(super) fn move_library(sys: &FakeSystem, files: &[&str]) {
    let fx = sys.fake_fs();
    fx.mkdir_all(Path::new(GAME_E)).unwrap();
    for f in files {
        let data = read(sys, &format!(r"{G}\{f}"));
        fx.put_file(Path::new(&format!(r"{GAME_E}\{f}")), &data)
            .unwrap();
        fx.remove_abs(Path::new(&format!(r"{G}\{f}"))).unwrap();
    }
    fx.remove_abs(Path::new(G)).unwrap();
    let manifest = format!(r"{LIB}\steamapps\appmanifest_220.acf");
    let acf_text = read(sys, &manifest);
    fx.put_file(
        Path::new(&format!(r"{LIB_E}\steamapps\appmanifest_220.acf")),
        &acf_text,
    )
    .unwrap();
    fx.remove_abs(Path::new(&manifest)).unwrap();
    let vdf = format!(r"{STEAM}\steamapps\libraryfolders.vdf");
    fx.remove_abs(Path::new(&vdf)).unwrap();
    let mut out = String::from("\"libraryfolders\"\n{\n");
    for (i, p) in [STEAM, LIB, LIB_E].iter().enumerate() {
        out.push_str(&format!(
            "\t\"{i}\"\n\t{{\n\t\t\"path\"\t\t\"{}\"\n\t}}\n",
            p.replace('\\', r"\\")
        ));
    }
    out.push_str("}\n");
    fx.put_file(Path::new(&vdf), out.as_bytes()).unwrap();
    fx.sync_all();
}

fn snap_of(rig: &Rig, dir: &str) -> Snapshot {
    let fr =
        rerun_core::policy::root::ForbiddenRoots::resolve(&rig.sys, Path::new(INSTALL)).unwrap();
    let g = rerun_core::policy::root::GameDir::open_manual(&rig.sys, &fr, Path::new(dir)).unwrap();
    snapshot(
        System::registry(&rig.sys),
        &Scope {
            dirs: vec![SnapRoot::new(g.dir(), dir)],
            keys: Vec::new(),
        },
    )
    .unwrap()
}

/// Applies the preselection (the CPU limit with its launch profile, the INI edit) and moves the
/// library; returns the rig, the transaction, the new folder's `game.ini` before the undo and
/// the game's files as they were before the apply.
fn moved(nvidia: bool) -> (Rig, rerun_core::journal::TxnId, Vec<(String, Vec<u8>)>) {
    let mut rig = if nvidia {
        Rig::with_nvidia(Lang::En)
    } else {
        Rig::new(Lang::En)
    };
    let before: Vec<(String, Vec<u8>)> = FILES
        .iter()
        .map(|f| ((*f).to_owned(), read(&rig.sys, &format!(r"{G}\{f}"))))
        .collect();
    let page = rig.page();
    let picks = Selection::preselected(&page).picks(&page);
    let pv = rig.preview_of(picks);
    let ev = rig.run(Job::Apply { hash: pv.hash });
    let a = applied_of(&ev);
    assert_eq!(a.open, 1, "{ev:?}");
    let txn = a.cards[0].txn;
    move_library(&rig.sys, &FILES);
    (rig, txn, before)
}

fn dialog_notes(d: &crate::vm::DialogVm) -> Vec<&str> {
    d.notes.iter().map(String::as_str).collect()
}

fn detail_of<'a>(d: &'a crate::vm::DialogVm, label: &str) -> Option<&'a str> {
    d.details
        .iter()
        .find(|x| x.who.as_ref().is_some_and(|w| w.as_str() == label))
        .map(|x| x.what.as_str())
}

#[test]
fn ab1_a_moved_library_is_rebound_and_undone() {
    let (mut rig, txn, before) = moved(false);
    // Precondition: the game folder is gone where it was bound, and the new folder holds the
    // changed files (so that an undo there is visible).
    assert!(is_gone(&rig.sys, G));
    assert_eq!(
        read(&rig.sys, &format!(r"{GAME_E}\game.ini")),
        b"[Display]\r\nWidth=1920\r\n"
    );

    // The undo preview halts and says the game folder has changed; the second button asks for
    // the rebind preview. The dialog itself cannot undo anything.
    let ev = rig.run(Job::RevertPreview { txn });
    let d = dialog_of(&ev);
    assert_eq!(d.kind, DialogKind::Undo);
    assert_eq!(d.secondary.as_deref(), Some("Check new folder"));
    assert!(
        dialog_notes(d).contains(&"The game folder has changed"),
        "{:?}",
        d.notes
    );

    // The rebind preview writes nothing: not Rerun's folder, not the new folder.
    let (app_before, new_before) = (rig.snap_app(), snap_of(&rig, GAME_E));
    let ev = rig.run(Job::RebindPreview { txn });
    let d = dialog_of(&ev).clone();
    assert!(rig.snap_app() == app_before, "the preview writes nothing");
    assert!(snap_of(&rig, GAME_E) == new_before);
    assert_eq!((d.kind, d.can_confirm), (DialogKind::Rebind, true));
    assert_eq!(d.title, "Bind this change to the new folder?");
    assert_eq!(d.confirm, "Rebind and undo");
    assert_eq!(d.secondary, None);
    assert_eq!(detail_of(&d, "Recorded folder"), Some(G));
    assert_eq!(detail_of(&d, "Folder Steam lists now"), Some(GAME_E));
    assert_eq!(detail_of(&d, "Its library"), Some(LIB_E));
    assert_eq!(detail_of(&d, "Library"), Some(LIB));
    assert!(detail_of(&d, "Why it does not open").is_some());
    assert!(
        dialog_notes(&d).contains(
            &"The new binding is permanent: every later undo of this change uses the new folder."
        ),
        "{:?}",
        d.notes
    );
    assert!(
        dialog_notes(&d)
            .iter()
            .any(|n| n.starts_with("Only the folder bound now is undone"))
    );
    // No registry change in this plan: no registry note.
    assert!(
        !dialog_notes(&d)
            .iter()
            .any(|n| n.starts_with("Registry changes"))
    );
    // Every change has its fate in the new folder.
    assert!(
        !d.ops.is_empty() && d.ops.iter().all(|o| o.fate.is_some()),
        "{:?}",
        d.ops
    );
    // The launch option goes back by hand, as in an undo.
    assert!(d.launch.is_some());

    // The confirm binds and undoes: the new folder is as it was before the apply.
    let ev = rig.rebind(txn);
    let r = result_of(&ev);
    assert_eq!(
        (r.tone, r.notice.title.as_str()),
        (Tone::Done, "Undone"),
        "{r:?}"
    );
    assert_eq!(applied_of(&ev).open, 0);
    for (f, data) in &before {
        assert_eq!(
            &read(&rig.sys, &format!(r"{GAME_E}\{f}")),
            data,
            "{f} is as before the apply"
        );
    }
    // The launch profile in Rerun's folder is gone, the history lists it as undone.
    let ev = rig.run(Job::History);
    let Some(Event::History(h)) = ev.first() else {
        panic!("{ev:?}");
    };
    assert_eq!(h.groups.len(), 1);
    assert_eq!(h.groups[0].kind, vm::HistGroup::Reverted);
    assert_eq!(h.groups[0].entries[0].txn, txn);
    let _ = RERUN;
}

#[test]
fn ab2_a_folder_that_changes_after_the_preview_is_a_changed_preview_and_writes_nothing() {
    let (mut rig, txn, _) = moved(false);
    rig.run(Job::RevertPreview { txn });
    let ev = rig.run(Job::RebindPreview { txn });
    let first = dialog_of(&ev).clone();
    assert!(first.can_confirm && first.changed.is_none());
    // The game rewrites its INI in the new folder between the preview and the click.
    rig.sys
        .fake_fs()
        .put_file(
            Path::new(&format!(r"{GAME_E}\game.ini")),
            b"[Display]\r\nWidth=1920\r\nHeight=1080\r\n",
        )
        .unwrap();
    rig.sys.fake_fs().sync_all();
    let (app_before, new_before) = (rig.snap_app(), snap_of(&rig, GAME_E));
    let ev = rig.rebind(txn);
    // Not an undo: the preview again with a calm note, and nothing written.
    assert!(!ev.iter().any(|e| matches!(e, Event::Result(_))), "{ev:?}");
    let again = dialog_of(&ev);
    assert_eq!(again.kind, DialogKind::Rebind);
    assert_eq!(
        again.changed.as_deref(),
        Some(&*crate::text::t(Lang::En, crate::text::Msg::ChangedNote))
    );
    assert!(again.nonce != first.nonce);
    assert!(rig.snap_app() == app_before, "nothing was written");
    assert!(snap_of(&rig, GAME_E) == new_before);
    // The transaction is still open; the click on the new preview completes.
    assert_eq!(applied_of(&rig.run(Job::Status)).open, 1);
    let ev = rig.rebind(txn);
    assert_eq!(result_of(&ev).tone, Tone::Done, "{ev:?}");
}

#[test]
fn ab3_a_confirm_with_an_older_nonce_writes_nothing() {
    let (mut rig, txn, _) = moved(false);
    rig.run(Job::RevertPreview { txn });
    let ev = rig.run(Job::RebindPreview { txn });
    let nonce = dialog_of(&ev).nonce;
    let (app_before, new_before) = (rig.snap_app(), snap_of(&rig, GAME_E));
    // A second preview replaces the first (the window refreshed it); the old click arrives late.
    let ev = rig.run(Job::RebindPreview { txn });
    let fresh = dialog_of(&ev).nonce;
    assert!(fresh > nonce);
    let ev = rig.run(Job::Rebind { txn, nonce });
    assert!(!ev.iter().any(|e| matches!(e, Event::Result(_))), "{ev:?}");
    assert_eq!(dialog_of(&ev).kind, DialogKind::Rebind);
    assert!(rig.snap_app() == app_before, "nothing was written");
    assert!(snap_of(&rig, GAME_E) == new_before);
    // A click that was never previewed for this transaction writes nothing either.
    let ev = rig.run(Job::Rebind { txn, nonce: 9_999 });
    assert!(!ev.iter().any(|e| matches!(e, Event::Result(_))), "{ev:?}");
    assert!(rig.snap_app() == app_before);
    // Control: the nonce of the shown dialog does undo (the refusals above were the nonce).
    let now = dialog_of(&ev).nonce;
    let ev = rig.run(Job::Rebind { txn, nonce: now });
    assert_eq!(result_of(&ev).tone, Tone::Done, "{ev:?}");
}

#[test]
fn ab4_the_registry_note_is_there_only_with_registry_changes() {
    let plain = {
        let (mut rig, txn, _) = moved(false);
        rig.run(Job::RevertPreview { txn });
        let ev = rig.run(Job::RebindPreview { txn });
        dialog_of(&ev).ops.len()
    };
    let (mut rig, txn, _) = moved(true);
    rig.run(Job::RevertPreview { txn });
    let ev = rig.run(Job::RebindPreview { txn });
    let d = dialog_of(&ev);
    assert_eq!(d.kind, DialogKind::Rebind);
    // Precondition: the compatibility layer is in this plan (a registry change), not in the other.
    assert!(d.ops.len() > plain, "{} vs {plain}", d.ops.len());
    assert!(
        dialog_notes(d)
            .iter()
            .any(|n| n.starts_with("Registry changes are undone where Rerun made them")),
        "{:?}",
        d.notes
    );
    // The same in German, with the German words for the label of each folder.
    rig.lang = Lang::De;
    let ev = rig.run(Job::RebindPreview { txn });
    let d = dialog_of(&ev);
    assert_eq!(d.confirm, "Neu zuordnen und rückgängig machen");
    assert_eq!(detail_of(d, "Gespeicherter Ordner"), Some(G));
}

#[test]
fn ab5_a_folder_that_is_where_it_was_needs_no_rebind() {
    let mut rig = Rig::new(Lang::En);
    let pv = rig.preview();
    let ev = rig.run(Job::Apply { hash: pv.hash });
    let txn = applied_of(&ev).cards[0].txn;
    // Nothing moved: the undo dialog has no second button.
    let ev = rig.run(Job::RevertPreview { txn });
    let d = dialog_of(&ev);
    assert_eq!((d.secondary.as_deref(), d.kind), (None, DialogKind::Undo));
    // A rebind preview anyway is the plain refusal, in its own words; nothing is written.
    let app_before = rig.snap_app();
    let ev = rig.run(Job::RebindPreview { txn });
    let r = result_of(&ev);
    assert_eq!(
        r.notice.title,
        "Rerun cannot bind this change to a new folder"
    );
    assert!(
        r.notice
            .body
            .starts_with("Every folder of this change opens as recorded")
    );
    assert!(rig.snap_app() == app_before);
}
