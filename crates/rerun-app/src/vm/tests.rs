//! View-model tests that need no world (P5-5a): what a fix needs decides whether the app offers
//! it; the typed refusals come out calm, in both languages, with what to do and the core's
//! text only as an escaped detail.

use rerun_core::catalog::model::{Kind, Tier, VariantStatus};
use rerun_core::escape;
use rerun_core::exec::{ApplyError, Outcome, Refusal};
use rerun_core::flow::{Fix, NeedState, PackageNeed, Solved};
use rerun_core::journal::TxnId;
use rerun_core::topo::{StepKind, Tri};

use super::{Offer, Tone, apply_result, refusal};
use crate::text::{Lang, Msg, t};

fn fix(packages: &[&str], needs_helper: bool, refused: bool) -> Fix {
    Fix {
        variant: "p".to_owned(),
        kind: Kind::Fix,
        solves: vec![Solved {
            issue: "i".to_owned(),
            when: Tri::Yes,
            status: VariantStatus::Verified,
            sources: Vec::new(),
            tradeoffs: Vec::new(),
        }],
        refused: refused.then_some(rerun_core::topo::Refusal::AntiCheat(StepKind::Package)),
        warned: Vec::new(),
        packages: packages
            .iter()
            .map(|id| PackageNeed {
                id: (*id).to_owned(),
                name: (*id).to_owned(),
                version: "1.0".to_owned(),
                license: "MIT".to_owned(),
                tier: Tier::Established,
                repo: None,
                downloads: Vec::new(),
                state: NeedState::Missing,
            })
            .collect(),
        needs_helper,
    }
}

fn offer(f: &Fix, lang: Lang) -> (Offer, Option<String>) {
    let v = super::fix(f, &|id| escape::text(id).into_owned(), lang);
    (v.offer, v.note)
}

#[test]
fn vw1_only_a_fix_without_a_download_and_without_the_helper_is_selectable() {
    assert_eq!(
        offer(&fix(&[], false, false), Lang::En),
        (Offer::Selectable, None)
    );
    let (o, note) = offer(&fix(&["fix-pack"], false, false), Lang::En);
    assert_eq!(o, Offer::NeedsDownload);
    assert_eq!(note.as_deref(), Some(&*t(Lang::En, Msg::FixNeedsDownload)));
    let (o, note) = offer(&fix(&[], true, false), Lang::De);
    assert_eq!(o, Offer::NeedsHelper);
    assert_eq!(note.as_deref(), Some(&*t(Lang::De, Msg::FixNeedsHelper)));
    // The core's refusal wins over both: shown with its reason, nothing else to say.
    let (o, note) = offer(&fix(&["fix-pack"], true, true), Lang::En);
    assert_eq!((o, note), (Offer::Refused, None));
}

fn txn() -> TxnId {
    "00000007-00000000000000ab".parse().unwrap()
}

#[test]
fn vw2_a_refusal_is_calm_and_says_what_to_do() {
    for lang in Lang::ALL {
        let r = refusal(&Refusal::Busy(escape::text("game.exe").into_owned()), lang);
        assert_eq!(r.notice.title, t(lang, Msg::RefBusyTitle));
        assert_eq!(r.notice.body, t(lang, Msg::RefBusyBody));
        assert_eq!(r.tone, Tone::Attention);
        assert!(!r.refresh);
        // The core's own English text is the escaped detail, never part of a sentence.
        assert_eq!(r.notice.details.len(), 1);
        assert!(r.notice.details[0].what.as_str().contains("game.exe"));

        // Another change comes first: the transaction is named in the detail.
        let r = refusal(&Refusal::Later { txn: txn() }, lang);
        assert_eq!(r.notice.title, t(lang, Msg::RefOrderTitle));
        assert_eq!(
            r.notice.details[0].what.as_str(),
            "00000007-00000000000000ab"
        );

        // A game or a state that changed since the preview is no error: the page is read
        // again.
        for stale in [
            Refusal::GameChanged(escape::text("game.exe").into_owned()),
            Refusal::Mismatch { op: 2 },
            Refusal::Changed { txn: txn() },
        ] {
            let r = refusal(&stale, lang);
            assert_eq!(r.tone, Tone::Calm, "{stale}");
            assert_eq!(r.notice.title, t(lang, Msg::RefStaleTitle));
            assert!(r.refresh);
        }

        let r = refusal(&Refusal::JournalBusy, lang);
        assert_eq!(r.tone, Tone::Calm);
        assert_eq!(r.notice.title, t(lang, Msg::RefJournalBusyTitle));
        let r = refusal(&Refusal::NeedsHelper, lang);
        assert_eq!(r.notice.title, t(lang, Msg::RefAdminTitle));
        // Anything else is the generic message with the core's text.
        let r = refusal(&Refusal::Elevated, lang);
        assert_eq!(r.notice.title, t(lang, Msg::RefUnexpectedTitle));
        assert!(r.notice.details[0].what.as_str().contains("administrator"));
    }
}

#[test]
fn vw3_an_apply_that_did_nothing_or_was_rolled_back_says_so() {
    let r = apply_result(Ok(Outcome::Nothing), Lang::En);
    assert_eq!(
        (r.tone, r.notice.title.as_str()),
        (Tone::Calm, "Nothing to change")
    );
    let r = apply_result(Ok(Outcome::Applied(txn())), Lang::De);
    assert_eq!(
        (r.tone, r.notice.title.as_str()),
        (Tone::Done, "Angewendet")
    );
    let r = apply_result(
        Err(ApplyError::Refused(Refusal::Held { txn: txn() })),
        Lang::En,
    );
    assert_eq!(r.notice.title, "Another change comes first");
}

// ---------- table-driven: every warning, shadow and refusal says something calm ----------

use rerun_core::detect::steam::AppState;
use rerun_core::exec::SteamGone;
use rerun_core::hw::SacState;
use rerun_core::path::RelPath;
use rerun_core::policy::root::Shadow;
use rerun_core::topo::Warning;

fn rel(s: &str) -> RelPath {
    RelPath::parse(s).unwrap()
}

#[test]
fn vw4_every_warning_and_shadow_has_words_in_both_languages() {
    use rerun_core::catalog::model::GpuRequirement;
    let sac = |state| Warning::SmartAppControl { state };
    let w: Vec<(Warning, Msg, bool)> = vec![
        (Warning::NeedsRetest, Msg::WarnNeedsRetest, false),
        (
            Warning::WhenUnknown { issue: "i".into() },
            Msg::WarnWhenUnknown,
            true,
        ),
        (
            Warning::AntiCheat {
                issue: "i".into(),
                variant: "v".into(),
                step: StepKind::Package,
            },
            Msg::WarnAntiCheat,
            true,
        ),
        (
            Warning::SteamInput { issue: "i".into() },
            Msg::WarnSteamInput,
            true,
        ),
        (sac(SacState::Enforce), Msg::WarnSacOn, false),
        (sac(SacState::Evaluation), Msg::WarnSacEvaluation, false),
        (sac(SacState::Unknown), Msg::WarnSacUnknown, false),
        (
            Warning::SteamPerUserExe {
                exe: rel("game.exe"),
            },
            Msg::WarnSteamPerUser,
            true,
        ),
        (
            Warning::SignedExe {
                exe: rel("game.exe"),
            },
            Msg::WarnSignedExe,
            true,
        ),
        (
            Warning::GpuPreferenceSet {
                exe: rel("game.exe"),
                by: None,
            },
            Msg::WarnGpuSet,
            true,
        ),
        (
            Warning::RequiresGpu {
                package: "p".into(),
                needs: GpuRequirement::Vulkan,
            },
            Msg::WarnRequiresGpu,
            true,
        ),
    ];
    for lang in Lang::ALL {
        for (warning, msg, detail) in &w {
            let v = super::warning_vm(warning, lang).expect("says something");
            assert_eq!(v.text, t(lang, *msg).as_ref(), "{warning:?}");
            assert_eq!(v.detail.is_some(), *detail, "{warning:?}");
            assert_eq!(v.badge.word, t(lang, Msg::WarningWord));
        }
        assert!(super::warning_vm(&sac(SacState::Off), lang).is_none());
        let at = escape::path(r"C:\x").into_owned();
        let shadows = [
            (
                Shadow::Copy {
                    root: 0,
                    file: rel("a.ini"),
                    copy: at.clone(),
                },
                Msg::WarnVsCopy,
            ),
            (
                Shadow::Link {
                    root: 0,
                    at: at.clone(),
                },
                Msg::WarnVsLink,
            ),
            (
                Shadow::Unchecked {
                    root: 0,
                    why: escape::text("no").into_owned(),
                    at: None,
                },
                Msg::WarnVsUnchecked,
            ),
        ];
        for (s, m) in &shadows {
            let v = super::shadow_vm(s, lang);
            assert_eq!(v.text, t(lang, *m).as_ref());
            assert!(v.detail.is_some());
        }
    }
}

#[test]
fn vw5_every_refusal_has_its_message_and_keeps_or_refreshes_the_page() {
    let shown = |s: &str| escape::text(s).into_owned();
    // (refusal, title, the page is read again)
    let table: Vec<(Refusal, Msg, bool)> = vec![
        (Refusal::Busy(shown("g")), Msg::RefBusyTitle, false),
        (Refusal::Unchecked(shown("g")), Msg::RefBusyTitle, false),
        (Refusal::JournalBusy, Msg::RefJournalBusyTitle, false),
        (Refusal::Blocked { txn: txn() }, Msg::RefBlockedTitle, false),
        (
            Refusal::Interrupted { txn: txn() },
            Msg::RefOrderTitle,
            false,
        ),
        (Refusal::Later { txn: txn() }, Msg::RefOrderTitle, false),
        (Refusal::Held { txn: txn() }, Msg::RefOrderTitle, false),
        (
            Refusal::HeldChange { txn: txn() },
            Msg::RefOrderTitle,
            false,
        ),
        (
            Refusal::SlotTaken {
                txn: txn(),
                op: 1,
                path: shown("d.dll"),
                package: shown("p"),
            },
            Msg::RefSlotTitle,
            false,
        ),
        (
            Refusal::CleanupPending { txn: txn() },
            Msg::RefCleanupTitle,
            false,
        ),
        // Steam busy keeps the page and the selection: try again when Steam has finished.
        (
            Refusal::Steam {
                app_id: 1,
                state: AppState::UpdatePending,
            },
            Msg::RefSteamTitle,
            false,
        ),
        (
            Refusal::SteamGone {
                app_id: 1,
                gone: SteamGone::NoManifest,
            },
            Msg::RefSteamTitle,
            false,
        ),
        (
            Refusal::SteamManifest { app_id: 1 },
            Msg::RefSteamTitle,
            false,
        ),
        (Refusal::GameChanged(shown("g")), Msg::RefStaleTitle, true),
        (Refusal::Mismatch { op: 1 }, Msg::RefStaleTitle, true),
        (Refusal::MainExe(shown("g")), Msg::RefStaleTitle, true),
        (Refusal::Changed { txn: txn() }, Msg::RefStaleTitle, true),
        (Refusal::NeedsHelper, Msg::RefAdminTitle, false),
        (
            Refusal::Forgotten { txn: txn() },
            Msg::RefNothingTitle,
            true,
        ),
    ];
    for lang in Lang::ALL {
        for (r, title, refresh) in &table {
            let v = refusal(r, lang);
            assert_eq!(v.notice.title, t(lang, *title), "{r}");
            assert_eq!(v.refresh, *refresh, "{r}");
            assert!(!v.notice.body.is_empty() && !v.notice.details.is_empty());
        }
    }
}
