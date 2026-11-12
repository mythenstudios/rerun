//! View models of the package download (P5-5b, ADR 0027 amendment P5-5b): the consent dialog
//! ("These files will be downloaded"), the progress dialog, the failure dialog with "Try again",
//! and the notices around them. Pure: typed `flow` values and a [`Lang`] in, plain structs with
//! every string localized out. Untrusted text (package names, URLs, hosts, licences, the core's
//! error texts) stays [`Shown`] and is drawn in its own element.
//!
//! Rule 5 for downloads: [`consent`] lists, per package, everything the index says about it (name,
//! version, source, release URL, host, SHA-256, licence) and that the file is checked after the
//! download; the size is the one thing not known before (the index has no size field), it
//! appears while the download runs.

use rerun_core::catalog::model::Arch;
use rerun_core::escape;
use rerun_core::flow::{DownloadNeed, FetchError, FetchKind, PackageNeed};

use super::{DetailVm, LineVm, Notice, OpVm, ResultVm, Tone, Value, shown_error};
use crate::text::{Lang, Msg, t};

fn tx(lang: Lang, m: Msg) -> String {
    t(lang, m).into_owned()
}

/// Which dialog.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DownloadStage {
    /// "These files will be downloaded": nothing was requested yet.
    Consent,
    /// The download runs (or its cancel is not confirmed yet).
    Progress,
    /// It failed; "Try again" asks for the same list again.
    Failed,
}

/// Where one package stands while a download runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackageState {
    /// Not started.
    Waiting,
    /// The body of one of its downloads is being read.
    Reading {
        /// Bytes read.
        read: u64,
        /// The announced `Content-Length`, if the server sent one.
        announced: Option<u64>,
    },
    /// In the cache already; hashed again.
    Cached,
    /// The named files are being unpacked.
    Unpacking,
    /// In place.
    Done,
    /// Not downloaded (a failure came first).
    NotStarted,
}

/// The consent, progress or failure dialog.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DownloadVm {
    /// Which.
    pub stage: DownloadStage,
    /// Identifies this dialog: a confirm carries it, the worker downloads only for the list it
    /// last showed.
    pub nonce: u64,
    /// The game page the fix is on.
    pub app_id: u32,
    /// The fix (its variant ID, the pick).
    pub variant: String,
    /// The title.
    pub title: String,
    /// Under the title.
    pub intro: String,
    /// One entry per package.
    pub packages: Vec<OpVm>,
    /// Notes under the list.
    pub notes: Vec<String>,
    /// The core's text for a failure (escaped).
    pub details: Vec<DetailVm>,
    /// The confirm button ("Download", "Try again"); none while it runs.
    pub confirm: Option<String>,
    /// The cancel button's label.
    pub cancel: String,
    /// A cancel was asked for and the worker has not confirmed it yet: the button waits.
    pub cancelling: bool,
}

/// The arch a download is for, as a prefix of its URL or hash.
fn with_arch(d: &DownloadNeed, text: &str) -> Value {
    let arch = d.arch.map(|a| match a {
        Arch::X86 => "x86",
        Arch::X64 => "x64",
    });
    Value::Shown(match arch {
        Some(a) => escape::text(&format!("{a}: {text}")).into_owned(),
        None => escape::text(text).into_owned(),
    })
}

fn line(label: String, values: Vec<Value>) -> LineVm {
    LineVm {
        label,
        values,
        mono: true,
    }
}

fn plain(label: String, text: String) -> LineVm {
    LineVm {
        label,
        values: vec![Value::Text(text)],
        mono: false,
    }
}

fn state_word(s: PackageState) -> Msg {
    match s {
        PackageState::Waiting => Msg::DlStWaiting,
        PackageState::Reading { .. } => Msg::DlStDownloading,
        PackageState::Cached => Msg::DlStCached,
        PackageState::Unpacking => Msg::DlStUnpacking,
        PackageState::Done => Msg::DlStDone,
        PackageState::NotStarted => Msg::DlStNotStarted,
    }
}

/// One package as a list entry: what the consent shows, and while it runs where it stands.
/// `state`: `None` in the consent dialog.
fn package_op(index: usize, n: &PackageNeed, state: Option<PackageState>, lang: Lang) -> OpVm {
    let mut lines = Vec::new();
    if let Some(repo) = &n.repo {
        lines.push(line(
            tx(lang, Msg::DlLblSource),
            vec![Value::Shown(escape::text(repo).into_owned())],
        ));
    }
    lines.push(line(
        tx(lang, Msg::DlLblRelease),
        n.downloads.iter().map(|d| with_arch(d, &d.url)).collect(),
    ));
    let mut hosts: Vec<&str> = Vec::new();
    for d in &n.downloads {
        if !hosts.contains(&d.host.as_str()) {
            hosts.push(&d.host);
        }
    }
    lines.push(line(
        tx(lang, Msg::DlLblHost),
        hosts
            .iter()
            .map(|h| Value::Shown(escape::text(h).into_owned()))
            .collect(),
    ));
    lines.push(line(
        tx(lang, Msg::DlLblSha),
        n.downloads
            .iter()
            .map(|d| with_arch(d, &d.sha256))
            .collect(),
    ));
    lines.push(line(
        tx(lang, Msg::DlLblLicence),
        // The licence is index text: escaped like the rest.
        vec![Value::Shown(escape::text(&n.license).into_owned())],
    ));
    match state {
        None => lines.push(plain(tx(lang, Msg::DlLblSize), tx(lang, Msg::DlSizeLater))),
        Some(s) => {
            if let PackageState::Reading { read, announced } = s {
                lines.push(plain(
                    tx(lang, Msg::DlLblSize),
                    tx(
                        lang,
                        Msg::DlSize {
                            read,
                            total: announced,
                        },
                    ),
                ));
            }
            lines.push(plain(tx(lang, Msg::DlLblStatus), tx(lang, state_word(s))));
        }
    }
    OpVm {
        index,
        action: tx(lang, Msg::DlPackage),
        target: escape::text(&format!("{} {}", n.name, n.version)).into_owned(),
        lines,
        undo: None,
        fate: None,
    }
}

fn packages(needs: &[PackageNeed], states: Option<&[PackageState]>, lang: Lang) -> Vec<OpVm> {
    needs
        .iter()
        .enumerate()
        .map(|(i, n)| {
            let s = states.map(|s| s.get(i).copied().unwrap_or(PackageState::Waiting));
            package_op(i, n, s, lang)
        })
        .collect()
}

/// The consent dialog: what would be downloaded, before a byte is requested (rule 5).
pub fn consent(
    app_id: u32,
    variant: &str,
    needs: &[PackageNeed],
    nonce: u64,
    lang: Lang,
) -> DownloadVm {
    DownloadVm {
        stage: DownloadStage::Consent,
        nonce,
        app_id,
        variant: variant.to_owned(),
        title: tx(lang, Msg::DlConsentTitle),
        intro: tx(lang, Msg::DlConsentIntro),
        packages: packages(needs, None, lang),
        notes: vec![tx(lang, Msg::DlChecked)],
        details: Vec::new(),
        confirm: Some(tx(lang, Msg::DlBtn)),
        cancel: tx(lang, Msg::BtnCancel),
        cancelling: false,
    }
}

/// The progress dialog; `cancelling`: a cancel was asked for.
pub fn progress(
    app_id: u32,
    variant: &str,
    needs: &[PackageNeed],
    states: &[PackageState],
    nonce: u64,
    cancelling: bool,
    lang: Lang,
) -> DownloadVm {
    DownloadVm {
        stage: DownloadStage::Progress,
        nonce,
        app_id,
        variant: variant.to_owned(),
        title: tx(lang, Msg::DlProgressTitle),
        intro: tx(lang, Msg::DlProgressIntro),
        packages: packages(needs, Some(states), lang),
        notes: vec![tx(lang, Msg::DlChecked)],
        details: Vec::new(),
        confirm: None,
        cancel: tx(
            lang,
            if cancelling {
                Msg::DlCancelling
            } else {
                Msg::DlBtnCancel
            },
        ),
        cancelling,
    }
}

/// The words for a failure of `kind`.
fn failure_msg(kind: FetchKind) -> Msg {
    match kind {
        FetchKind::Offline => Msg::DlErrOffline,
        FetchKind::TimedOut => Msg::DlErrTimedOut,
        FetchKind::Interrupted => Msg::DlErrInterrupted,
        FetchKind::RedirectRefused => Msg::DlErrRedirect,
        FetchKind::Status => Msg::DlErrStatus,
        FetchKind::WrongHash => Msg::DlErrHash,
        FetchKind::TooLarge => Msg::DlErrTooLarge,
        FetchKind::ExtractionRefused => Msg::DlErrExtract,
        FetchKind::Changed => Msg::DlErrChanged,
        FetchKind::Unobtainable => Msg::DlErrUnobtainable,
        // A cancel never reaches a failure dialog; the generic text is the safe answer.
        FetchKind::Cancelled | FetchKind::Other => Msg::DlErrOther,
    }
}

/// Whether "Try again" can help: not when the list no longer matches the index or the package
/// cannot be downloaded at all.
fn retryable(kind: FetchKind) -> bool {
    !matches!(kind, FetchKind::Changed | FetchKind::Unobtainable)
}

/// The failure dialog: the same list, what went wrong, and "Try again" (a new confirm of the
/// list that is shown).
pub fn failed(
    app_id: u32,
    variant: &str,
    needs: &[PackageNeed],
    states: &[PackageState],
    e: &FetchError,
    nonce: u64,
    lang: Lang,
) -> DownloadVm {
    let kind = e.kind();
    DownloadVm {
        stage: DownloadStage::Failed,
        nonce,
        app_id,
        variant: variant.to_owned(),
        title: tx(lang, Msg::DlFailedTitle),
        intro: tx(lang, failure_msg(kind)),
        packages: packages(needs, Some(states), lang),
        notes: Vec::new(),
        details: vec![DetailVm::of(shown_error(e))],
        confirm: retryable(kind).then(|| tx(lang, Msg::DlBtnRetry)),
        cancel: tx(lang, Msg::BtnDismiss),
        cancelling: false,
    }
}

/// What closing the window does (rule 1: nothing lives on after the window).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Closing {
    /// Nothing runs: the window closes.
    Close,
    /// A write runs: refused until it has finished (the journal covers a crash, but a close in
    /// the middle of an apply is not offered).
    FinishWrite,
    /// A download runs: it is cancelled, the window says so and closes by itself when the
    /// worker reports that the download has stopped, which keeps the cache clean.
    CancelDownload,
}

/// The decision for a close request, given what the worker is doing.
pub fn closing_policy(writing: bool, downloading: bool) -> Closing {
    if writing {
        Closing::FinishWrite
    } else if downloading {
        Closing::CancelDownload
    } else {
        Closing::Close
    }
}

fn notice(tone: Tone, lang: Lang, title: Msg, body: Msg) -> ResultVm {
    ResultVm {
        tone,
        notice: Notice {
            title: tx(lang, title),
            body: tx(lang, body),
            details: Vec::new(),
        },
        refresh: false,
    }
}

/// The banner after a cancel: nothing was kept.
pub fn cancelled(lang: Lang) -> ResultVm {
    notice(
        Tone::Calm,
        lang,
        Msg::DlCancelledTitle,
        Msg::DlCancelledBody,
    )
}

/// The window cannot close until the download has stopped.
pub fn closing(lang: Lang) -> ResultVm {
    notice(
        Tone::Attention,
        lang,
        Msg::DlClosingTitle,
        Msg::DlClosingBody,
    )
}

/// A confirm that matches no list that was shown: nothing was downloaded.
pub fn no_consent(lang: Lang) -> ResultVm {
    notice(
        Tone::Calm,
        lang,
        Msg::DlNoConsentTitle,
        Msg::DlNoConsentBody,
    )
}
