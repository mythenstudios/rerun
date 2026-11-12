//! View-model tests that need no world (P5-5a): what a fix needs decides whether the app offers
//! it; the typed refusals come out calm, in both languages, with what to do and the core's
//! text only as an escaped detail.

use rerun_core::catalog::model::{Kind, VariantStatus};
use rerun_core::escape;
use rerun_core::exec::{ApplyError, Outcome, Refusal};
use rerun_core::flow::{Fix, Solved};
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
        packages: packages.iter().map(|s| (*s).to_owned()).collect(),
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
