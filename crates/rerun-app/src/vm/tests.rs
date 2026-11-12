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
                page: None,
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

/// VD0 (P5-5b): a fix that needs a package is offered with a consent, never selectable before
/// it; one whose packages are in place is selectable; one with a package Rerun cannot download
/// is not offered at all.
#[test]
fn vd0_the_packages_decide_whether_a_fix_asks_first() {
    let with = |states: &[NeedState]| {
        let mut f = fix(&[], false, false);
        f.packages = states
            .iter()
            .enumerate()
            .map(|(i, s)| PackageNeed {
                id: format!("p{i}"),
                name: format!("P{i}"),
                version: "1.0".to_owned(),
                license: "MIT".to_owned(),
                tier: Tier::Established,
                repo: None,
                page: None,
                downloads: Vec::new(),
                state: s.clone(),
            })
            .collect();
        f
    };
    let missing = NeedState::Missing;
    let there = NeedState::Unpacked;
    let never = NeedState::Unobtainable("a community package".to_owned());
    for lang in Lang::ALL {
        assert_eq!(
            offer(&with(std::slice::from_ref(&there)), lang).0,
            Offer::Selectable
        );
        assert_eq!(
            offer(&with(&[there.clone(), missing.clone()]), lang).0,
            Offer::NeedsDownload
        );
        let (o, note) = offer(&with(&[missing.clone(), never.clone()]), lang);
        assert_eq!(o, Offer::NoPackage);
        assert_eq!(note.as_deref(), Some(&*t(lang, Msg::FixNoPackage)));
    }
    // A package that needs a download and a helper: the helper's lock wins (P5-5c).
    let mut f = with(&[missing]);
    f.needs_helper = true;
    assert_eq!(offer(&f, Lang::En).0, Offer::NeedsHelper);
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

// ---------- the download dialogs (P5-5b) ----------

use rerun_core::catalog::model::Arch;
use rerun_core::flow::{DownloadNeed, FetchError, FetchKind};
use rerun_core::pkg::download::FetchError as Dl;
use rerun_core::sys::{SysError, SysErrorKind};

use super::{
    DownloadStage, PackageState, Value, cancelled, closing, consent, failed, no_consent, progress,
};

fn dl(arch: Option<Arch>, url: &str, host: &str, sha: &str) -> DownloadNeed {
    DownloadNeed {
        arch,
        url: url.to_owned(),
        host: host.to_owned(),
        sha256: sha.to_owned(),
    }
}

/// Two packages: one with an asset per architecture (two URLs on one host), one whose name
/// carries a bidi override.
fn needs() -> Vec<PackageNeed> {
    vec![
        PackageNeed {
            id: "loader".to_owned(),
            name: "Ultimate ASI Loader".to_owned(),
            version: "9.8".to_owned(),
            license: "MIT".to_owned(),
            tier: Tier::Established,
            repo: Some("https://github.com/ThirteenAG/Ultimate-ASI-Loader".to_owned()),
            page: None,
            downloads: vec![
                dl(
                    Some(Arch::X86),
                    "https://github.com/o/r/releases/download/v9.8/x86.zip",
                    "github.com",
                    &"a".repeat(64),
                ),
                dl(
                    Some(Arch::X64),
                    "https://github.com/o/r/releases/download/v9.8/x64.zip",
                    "github.com",
                    &"b".repeat(64),
                ),
            ],
            state: NeedState::Missing,
        },
        PackageNeed {
            id: "evil".to_owned(),
            name: "Pack\u{202e}gnp".to_owned(),
            version: "1".to_owned(),
            license: "MIT".to_owned(),
            tier: Tier::Official,
            repo: None,
            page: Some("https://example.org/pack".to_owned()),
            downloads: vec![dl(
                None,
                "https://github.com/o/p/releases/download/v1/p.zip",
                "github.com",
                &"c".repeat(64),
            )],
            state: NeedState::Missing,
        },
    ]
}

fn label(lang: Lang, m: Msg) -> String {
    t(lang, m).into_owned()
}

/// VD1: the consent lists, per package, everything the index says (name and version, source,
/// every release URL, the host once, every SHA-256, the licence), that the size comes while it
/// downloads, and that the file is checked after; untrusted text stays escaped and `Shown`.
#[test]
fn vd1_the_consent_lists_what_the_index_says() {
    for lang in Lang::ALL {
        let d = consent(220, "fix-pack", &needs(), 7, lang);
        assert_eq!(d.stage, DownloadStage::Consent);
        assert_eq!(
            (d.nonce, d.app_id, d.variant.as_str()),
            (7, 220, "fix-pack")
        );
        assert_eq!(d.title, label(lang, Msg::DlConsentTitle));
        assert_eq!(d.confirm.as_deref(), Some(label(lang, Msg::DlBtn).as_str()));
        assert_eq!(d.cancel, label(lang, Msg::BtnCancel));
        assert!(!d.cancelling);
        assert_eq!(d.notes, [label(lang, Msg::DlChecked)]);
        assert_eq!(d.packages.len(), 2);
        let p = &d.packages[0];
        assert_eq!(p.target.as_str(), "Ultimate ASI Loader 9.8");
        let lines: Vec<(String, Vec<String>)> = p
            .lines
            .iter()
            .map(|l| {
                (
                    l.label.clone(),
                    l.values.iter().map(|v| v.as_str().to_owned()).collect(),
                )
            })
            .collect();
        let one = |m: Msg, v: &str| (label(lang, m), vec![v.to_owned()]);
        assert_eq!(
            lines,
            [
                one(
                    Msg::DlLblSource,
                    "https://github.com/ThirteenAG/Ultimate-ASI-Loader"
                ),
                (
                    label(lang, Msg::DlLblRelease),
                    vec![
                        "x86: https://github.com/o/r/releases/download/v9.8/x86.zip".to_owned(),
                        "x64: https://github.com/o/r/releases/download/v9.8/x64.zip".to_owned()
                    ]
                ),
                one(Msg::DlLblHost, "github.com"),
                (
                    label(lang, Msg::DlLblVia),
                    vec![
                        "objects.githubusercontent.com".to_owned(),
                        "release-assets.githubusercontent.com".to_owned()
                    ]
                ),
                (
                    label(lang, Msg::DlLblSha),
                    vec![
                        format!("x86: {}", "a".repeat(64)),
                        format!("x64: {}", "b".repeat(64))
                    ]
                ),
                one(Msg::DlLblLicence, "MIT"),
                one(Msg::DlLblSize, &label(lang, Msg::DlSizeLater)),
            ]
        );
        // Everything the index wrote is `Shown` (escaped); only Rerun's own sentence is `Text`.
        for l in &p.lines {
            for v in &l.values {
                let own = matches!(v, Value::Text(_));
                assert_eq!(own, l.label == label(lang, Msg::DlLblSize), "{}", l.label);
            }
        }
        // A bidi override in a name is escaped, not drawn.
        assert!(!d.packages[1].target.as_str().contains('\u{202e}'));
        assert!(d.packages[1].target.as_str().contains("Pack"));
        // The other package has no repository: its page is the source.
        let src = d.packages[1]
            .lines
            .iter()
            .find(|l| l.label == label(lang, Msg::DlLblSource))
            .expect("a source line");
        assert_eq!(src.values[0].as_str(), "https://example.org/pack");
    }
    // The two languages are different texts (a copied English line would pass the compiler).
    let en = consent(1, "x", &needs(), 1, Lang::En);
    let de = consent(1, "x", &needs(), 1, Lang::De);
    assert_ne!(en.title, de.title);
    assert_ne!(en.intro, de.intro);
    assert_eq!(de.confirm.as_deref(), Some("Herunterladen"));
    assert_eq!(de.cancel, "Abbrechen");
}

/// VD2: the progress dialog shows each package's state and, while a body is read, how far (of
/// how much when the server announced it); it has no confirm, and a cancel that is not confirmed
/// yet says so and waits.
#[test]
fn vd2_progress_shows_every_state() {
    let status = |d: &super::DownloadVm, i: usize, lang: Lang| -> (String, Option<String>) {
        let find = |m: Msg| {
            d.packages[i]
                .lines
                .iter()
                .find(|l| l.label == label(lang, m))
                .map(|l| l.values[0].as_str().to_owned())
        };
        (find(Msg::DlLblStatus).unwrap(), find(Msg::DlLblSize))
    };
    for lang in Lang::ALL {
        let states = [
            PackageState::Reading {
                read: 1_300_000,
                announced: Some(3_250_000),
            },
            PackageState::Waiting,
        ];
        let d = progress(220, "f", &needs(), &states, 9, false, lang);
        assert_eq!(d.stage, DownloadStage::Progress);
        assert!(d.confirm.is_none());
        assert_eq!(d.cancel, label(lang, Msg::DlBtnCancel));
        assert!(!d.cancelling);
        assert_eq!(d.title, label(lang, Msg::DlProgressTitle));
        let (word, size) = status(&d, 0, lang);
        assert_eq!(word, label(lang, Msg::DlStDownloading));
        let want = if lang == Lang::En {
            "1.2 MB of 3.1 MB"
        } else {
            "1,2 MB von 3,1 MB"
        };
        assert_eq!(size.as_deref(), Some(want));
        assert_eq!(status(&d, 1, lang), (label(lang, Msg::DlStWaiting), None));
        // No announced length: how far, and that none was announced.
        let d = progress(
            220,
            "f",
            &needs(),
            &[PackageState::Reading {
                read: 2048,
                announced: None,
            }],
            9,
            false,
            lang,
        );
        let size = status(&d, 0, lang).1.unwrap();
        assert!(size.starts_with("2 KB"), "{size}");
        // The other states, by their words.
        for (s, m) in [
            (PackageState::Cached, Msg::DlStCached),
            (PackageState::Unpacking, Msg::DlStUnpacking),
            (PackageState::Done, Msg::DlStDone),
            (PackageState::NotStarted, Msg::DlStNotStarted),
        ] {
            let d = progress(220, "f", &needs(), &[s], 9, false, lang);
            assert_eq!(status(&d, 0, lang), (label(lang, m), None));
        }
        // A cancel that is asked for and not confirmed yet.
        let d = progress(220, "f", &needs(), &states, 9, true, lang);
        assert!(d.cancelling);
        assert_eq!(d.cancel, label(lang, Msg::DlCancelling));
    }
}

/// VD3: a failure is the same list with the words for what went wrong, the core's text as an
/// escaped detail, and "Try again" unless trying again cannot help.
#[test]
fn vd3_a_failure_names_what_went_wrong() {
    let net = |code| {
        FetchError::Download(Dl::Network(
            SysError::new(SysErrorKind::Other, "https://github.com").with_win32(code),
        ))
    };
    let site = |f: fn(String) -> Dl| FetchError::Download(f("github.com".to_owned()));
    let cases: Vec<(FetchError, FetchKind, Msg, bool)> = vec![
        (net(12029), FetchKind::Offline, Msg::DlErrOffline, true),
        (net(12007), FetchKind::Offline, Msg::DlErrOffline, true),
        (net(12002), FetchKind::TimedOut, Msg::DlErrTimedOut, true),
        (
            net(12030),
            FetchKind::Interrupted,
            Msg::DlErrInterrupted,
            true,
        ),
        (
            site(|host| Dl::TimedOut { host, secs: 600 }),
            FetchKind::TimedOut,
            Msg::DlErrTimedOut,
            true,
        ),
        (
            site(|host| Dl::Status { host, status: 404 }),
            FetchKind::Status,
            Msg::DlErrStatus,
            false,
        ),
        (
            FetchError::Download(Dl::Mismatch {
                expected: "AB".to_owned(),
            }),
            FetchKind::WrongHash,
            Msg::DlErrHash,
            false,
        ),
        (
            site(|host| Dl::TooLarge { host, limit: 64 }),
            FetchKind::TooLarge,
            Msg::DlErrTooLarge,
            false,
        ),
        (
            site(|host| Dl::TooManyRedirects { host }),
            FetchKind::RedirectRefused,
            Msg::DlErrRedirect,
            false,
        ),
        (
            FetchError::Unpack(rerun_core::pkg::extract::ExtractError::Layout {
                id: "p".to_owned(),
                why: "x".to_owned(),
            }),
            FetchKind::ExtractionRefused,
            Msg::DlErrExtract,
            false,
        ),
        (
            FetchError::NoIndex,
            FetchKind::Changed,
            Msg::DlErrChanged,
            false,
        ),
        (
            FetchError::Changed { id: "p".to_owned() },
            FetchKind::Changed,
            Msg::DlErrChanged,
            false,
        ),
        (
            FetchError::Unobtainable {
                id: "p".to_owned(),
                why: "x".to_owned(),
            },
            FetchKind::Unobtainable,
            Msg::DlErrUnobtainable,
            false,
        ),
    ];
    for lang in Lang::ALL {
        for (e, kind, msg, retry) in &cases {
            assert_eq!(e.kind(), *kind, "{e:?}");
            let d = failed(220, "f", &needs(), &[PackageState::NotStarted], e, 11, lang);
            assert_eq!(d.stage, DownloadStage::Failed, "{e:?}");
            assert_eq!(d.nonce, 11);
            assert_eq!(d.title, label(lang, Msg::DlFailedTitle));
            assert_eq!(d.intro, label(lang, *msg), "{e:?}");
            assert_eq!(d.confirm.is_some(), *retry, "{e:?}");
            if *retry {
                assert_eq!(
                    d.confirm.as_deref(),
                    Some(label(lang, Msg::DlBtnRetry).as_str())
                );
            }
            // The core's English text is the escaped detail; the list is still shown.
            assert_eq!(d.details.len(), 1);
            assert!(!d.details[0].what.as_str().is_empty());
            assert_eq!(d.packages.len(), 2);
            assert!(!d.cancelling);
        }
    }
    // A failure text with a control character in it is escaped, never drawn raw.
    let e = FetchError::Unobtainable {
        id: "p".to_owned(),
        why: "evil\u{202e}x".to_owned(),
    };
    let d = failed(220, "f", &needs(), &[], &e, 1, Lang::En);
    assert!(!d.details[0].what.as_str().contains('\u{202e}'));
}

/// VD4: the notices around a download: a cancel keeps nothing, the window says it waits for the
/// download to stop, and a confirm of a list that was not shown downloaded nothing.
#[test]
fn vd4_the_notices_say_what_happened() {
    for lang in Lang::ALL {
        let c = cancelled(lang);
        assert_eq!(c.tone, Tone::Calm);
        assert_eq!(c.notice.title, label(lang, Msg::DlCancelledTitle));
        assert_eq!(c.notice.body, label(lang, Msg::DlCancelledBody));
        assert!(!c.refresh);
        let w = closing(lang);
        assert_eq!(w.tone, Tone::Attention);
        assert_eq!(w.notice.title, label(lang, Msg::DlClosingTitle));
        // The grace period is named.
        assert!(w.notice.body.contains("15"), "{}", w.notice.body);
        let n = no_consent(lang);
        assert_eq!(n.tone, Tone::Calm);
        assert_eq!(n.notice.title, label(lang, Msg::DlNoConsentTitle));
    }
}

/// VD5: closing the window: a write is finished first; a download is cancelled and the window
/// closes when it has stopped; with neither it closes.
#[test]
fn vd5_closing_waits_for_a_write_and_cancels_a_download() {
    use super::{Closing, closing_policy};
    assert_eq!(closing_policy(false, false), Closing::Close);
    assert_eq!(closing_policy(true, false), Closing::FinishWrite);
    assert_eq!(closing_policy(false, true), Closing::CancelDownload);
    // Both: the write comes first (it cannot be cancelled).
    assert_eq!(closing_policy(true, true), Closing::FinishWrite);
}

/// VD6: a package that failed says so, the ones behind it were not started.
#[test]
fn vd6_the_failed_package_says_failed() {
    for lang in Lang::ALL {
        let states = [PackageState::Done, PackageState::Failed];
        let e = FetchError::NoIndex;
        let d = failed(220, "f", &needs(), &states, &e, 3, lang);
        let word = |i: usize| {
            d.packages[i]
                .lines
                .iter()
                .find(|l| l.label == label(lang, Msg::DlLblStatus))
                .map(|l| l.values[0].as_str().to_owned())
                .unwrap()
        };
        assert_eq!(word(0), label(lang, Msg::DlStDone));
        assert_eq!(word(1), label(lang, Msg::DlStFailed));
    }
}
