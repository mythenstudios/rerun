//! The rebind dialog's refusals as view models (P5-6c, ADR 0027 amendment P5-6c).
//! - VB1 every `RebindRefusal` has its own words (one heading, one sentence each, the core's
//!   text as an escaped detail), in both languages; the ones that go away by themselves are
//!   calm; `Changed` is the stale message that refreshes; the generic message is never used for
//!   a known reason. The undo dialog of a changed game folder offers the second button and
//!   cannot be confirmed.
//! - VB2 (the rebind dialog's content) is in the worker tests: it needs a real rebind preview.

use std::collections::BTreeSet;

use rerun_core::escape;
use rerun_core::exec::{RebindRefusal, Refusal};
use rerun_core::journal::TxnId;

use crate::text::{Lang, Msg, t};
use crate::vm::{DialogKind, Tone, refusal, revert_refused_vm};

fn id() -> TxnId {
    "00000007-00000000000000ab".parse().unwrap()
}

fn inner() -> Box<Refusal> {
    Box::new(Refusal::Busy(escape::text("game.exe").into_owned()))
}

fn path() -> rerun_core::escape::Shown<'static> {
    escape::path(r"E:\SteamLibrary\steamapps\common\G").into_owned()
}

#[test]
fn vb1_every_rebind_refusal_has_its_own_words() {
    let all: Vec<(RebindRefusal, Msg, Tone)> = vec![
        (
            RebindRefusal::NotNeeded,
            Msg::RefRebindNotNeeded,
            Tone::Calm,
        ),
        (
            RebindRefusal::AlreadyBound {
                root: 0,
                path: path(),
            },
            Msg::RefRebindNotNeeded,
            Tone::Calm,
        ),
        (RebindRefusal::Manual, Msg::RefRebindManual, Tone::Attention),
        (
            RebindRefusal::NotApplied,
            Msg::RefRebindNotApplied,
            Tone::Attention,
        ),
        (
            RebindRefusal::Undecided(inner()),
            Msg::RefRebindUndecided,
            Tone::Calm,
        ),
        (
            RebindRefusal::MoreThanOne,
            Msg::RefRebindMoreThanOne,
            Tone::Attention,
        ),
        (
            RebindRefusal::NoCandidate,
            Msg::RefRebindNoCandidate,
            Tone::Attention,
        ),
        (
            RebindRefusal::Ambiguous(vec![path()]),
            Msg::RefRebindAmbiguous,
            Tone::Attention,
        ),
        (
            RebindRefusal::LibraryUnreadable(path()),
            Msg::RefRebindLibraryUnreadable,
            Tone::Calm,
        ),
        (
            RebindRefusal::UpdatePending,
            Msg::RefRebindUpdatePending,
            Tone::Calm,
        ),
        (
            RebindRefusal::OtherInstallDir,
            Msg::RefRebindOtherInstallDir,
            Tone::Attention,
        ),
        (
            RebindRefusal::Candidate(inner()),
            Msg::RefRebindCandidate,
            Tone::Attention,
        ),
        (
            RebindRefusal::SharedFolder,
            Msg::RefRebindSharedFolder,
            Tone::Attention,
        ),
        (
            RebindRefusal::Halts(inner()),
            Msg::RefRebindHalts,
            Tone::Attention,
        ),
        (
            RebindRefusal::NotWritable,
            Msg::RefRebindNotWritable,
            Tone::Attention,
        ),
        (
            RebindRefusal::Foreign { op: 1 },
            Msg::RefRebindForeign,
            Tone::Attention,
        ),
        (
            RebindRefusal::RevertPending { op: 1 },
            Msg::RefRebindRevertPending,
            Tone::Attention,
        ),
        (
            RebindRefusal::TooLarge,
            Msg::RefRebindNoRoom,
            Tone::Attention,
        ),
        (RebindRefusal::NoRoom, Msg::RefRebindNoRoom, Tone::Attention),
    ];
    for lang in Lang::ALL {
        let mut bodies = BTreeSet::new();
        for (x, body, tone) in &all {
            let msg = format!("{x}");
            let r = refusal(&Refusal::Rebind(clone(x)), lang);
            assert_eq!(r.notice.title, t(lang, Msg::RefRebindTitle), "{msg}");
            assert_eq!(r.notice.body, t(lang, *body), "{msg}");
            assert_eq!(r.tone, *tone, "{msg}");
            // The core's text is the one escaped detail; nothing refreshes the page.
            assert_eq!(r.notice.details.len(), 1, "{msg}");
            assert!(!r.refresh);
            bodies.insert(r.notice.body.clone());
        }
        // Every kind of reason says something of its own (`NotNeeded` and `AlreadyBound`, `TooLarge` and `NoRoom` share one).
        assert_eq!(bodies.len(), all.len() - 2, "{lang:?}");
        // A folder that changed since the preview is the calm stale message, which refreshes.
        let r = refusal(&Refusal::Rebind(RebindRefusal::Changed), lang);
        assert_eq!(r.notice.title, t(lang, Msg::RefStaleTitle));
        assert!(r.refresh && r.tone == Tone::Calm);
    }
}

fn clone(x: &RebindRefusal) -> RebindRefusal {
    match x {
        RebindRefusal::NotNeeded => RebindRefusal::NotNeeded,
        RebindRefusal::AlreadyBound { root, .. } => RebindRefusal::AlreadyBound {
            root: *root,
            path: path(),
        },
        RebindRefusal::Manual => RebindRefusal::Manual,
        RebindRefusal::NotApplied => RebindRefusal::NotApplied,
        RebindRefusal::Undecided(_) => RebindRefusal::Undecided(inner()),
        RebindRefusal::MoreThanOne => RebindRefusal::MoreThanOne,
        RebindRefusal::NoCandidate => RebindRefusal::NoCandidate,
        RebindRefusal::Ambiguous(_) => RebindRefusal::Ambiguous(vec![path()]),
        RebindRefusal::LibraryUnreadable(_) => RebindRefusal::LibraryUnreadable(path()),
        RebindRefusal::UpdatePending => RebindRefusal::UpdatePending,
        RebindRefusal::OtherInstallDir => RebindRefusal::OtherInstallDir,
        RebindRefusal::Candidate(_) => RebindRefusal::Candidate(inner()),
        RebindRefusal::SharedFolder => RebindRefusal::SharedFolder,
        RebindRefusal::Halts(_) => RebindRefusal::Halts(inner()),
        RebindRefusal::NotWritable => RebindRefusal::NotWritable,
        RebindRefusal::Foreign { op } => RebindRefusal::Foreign { op: *op },
        RebindRefusal::RevertPending { op } => RebindRefusal::RevertPending { op: *op },
        RebindRefusal::Changed => RebindRefusal::Changed,
        RebindRefusal::TooLarge => RebindRefusal::TooLarge,
        RebindRefusal::NoRoom => RebindRefusal::NoRoom,
        other => panic!("a refusal this test does not know: {other}"),
    }
}

#[test]
fn vb1_the_undo_dialog_of_a_changed_game_folder_offers_the_check_and_cannot_be_confirmed() {
    for lang in Lang::ALL {
        let d = revert_refused_vm(id(), &inner(), 9, true, lang);
        assert_eq!(d.kind, DialogKind::Undo);
        assert_eq!(d.secondary.as_deref(), Some(&*t(lang, Msg::RebindCheckBtn)));
        assert!(!d.can_confirm && d.ops.is_empty() && d.launch.is_none());
        assert_eq!(d.intro, t(lang, Msg::UndoFolderChanged));
        assert!(
            d.notes
                .contains(&t(lang, Msg::UndoFolderChangedBody).into_owned())
        );
        assert_eq!(d.changed.as_deref(), Some(&*t(lang, Msg::ChangedNote)));
        assert_eq!((d.nonce, d.txn), (9, id()));
        // The core's reason is a detail.
        assert_eq!(d.details.len(), 1);
    }
}

/// VB2 (the launch option part of the rebind dialog, shared with the undo dialog): every
/// `ProfileFate` says its own sentence; only "the previous profile is back" shows no option; the
/// one that goes says until when; an unknown install folder is a warning, not an option.
#[test]
fn vb2_every_profile_fate_has_its_sentence() {
    use rerun_core::exec::launch_result::ProfileId;
    use rerun_core::flow::{LaunchOption, ProfileFate};
    use std::path::PathBuf;
    let install: Result<PathBuf, String> = Ok(PathBuf::from(r"C:\Rerun"));
    let unknown: Result<PathBuf, String> = Err("unknown".to_owned());
    let fates = [
        (ProfileFate::Gone, Msg::LaunchFateGone, true, true),
        (ProfileFate::PreviousBack, Msg::LaunchFatePrev, false, false),
        (ProfileFate::Stays, Msg::LaunchFateStays, false, true),
        (ProfileFate::Left, Msg::LaunchFateLeft, false, true),
    ];
    for lang in Lang::ALL {
        let mut firsts = BTreeSet::new();
        for (fate, msg, until, option) in fates {
            let l = LaunchOption {
                id: ProfileId([7; 16]),
                fate,
            };
            let v = crate::vm::fate_launch(&l, &install, lang);
            assert_eq!(v.lines[0], t(lang, msg), "{fate:?}");
            assert_eq!(v.lines.len(), 1 + usize::from(until), "{fate:?}");
            assert_eq!(v.option.is_some(), option, "{fate:?}");
            assert!(v.problems.is_empty());
            firsts.insert(v.lines[0].clone());
            // Without a known install folder there is no option, only a warning.
            let v = crate::vm::fate_launch(&l, &unknown, lang);
            assert!(v.option.is_none());
            assert_eq!(v.problems.len(), 1, "{fate:?}");
        }
        assert_eq!(firsts.len(), fates.len(), "every fate says its own words");
    }
}
