//! The download dialogs of the window (P5-5b, ADR 0027 amendment P5-5b): consent ("These files
//! will be downloaded"), progress, and failure with "Try again". They are drawn in the window's
//! one dialog (`DialogView`), so the focus trap, Esc, the title taking the focus and the focus
//! returning to the fix's checkbox work as for undo and forget.
//!
//! The window sends only what the user did: `DownloadAsk` when a fix that needs a package is
//! ticked, `Download { nonce }` for "Download" or "Try again" of the dialog it shows, and the
//! cancel flag for "Cancel". Whether a download may start, what it fetches and whether the list
//! still matches the index is the worker's and the core's (rule 5: nothing is downloaded for a
//! list the user did not see).

use super::write::op;
use super::*;
use crate::vm::{DownloadStage, DownloadVm};
use crate::worker::DownloadOutcome;

/// The download dialog that is open.
pub(super) struct DownloadState {
    stage: DownloadStage,
    nonce: u64,
    /// The fix (its variant ID).
    variant: String,
}

/// The one dialog's data for a download dialog.
pub(super) fn download_data(d: &DownloadVm) -> DialogData {
    DialogData {
        kind: 2,
        title: s(&d.title),
        intro: s(&d.intro),
        changed: SharedString::new(),
        ops: model(d.packages.iter().map(op).collect()),
        notes: model(d.notes.iter().map(s).collect()),
        details: model(d.details.iter().map(detail).collect()),
        has_launch: false,
        launch_heading: SharedString::new(),
        launch_lines: model(Vec::new()),
        launch_option: SharedString::new(),
        launch_problems: model(Vec::new()),
        confirm: d.confirm.as_deref().map(s).unwrap_or_default(),
        can_confirm: d.confirm.is_some(),
        blocked: SharedString::new(),
        no_confirm: d.confirm.is_none(),
        cancel_label: s(&d.cancel),
        cancel_disabled: d.cancelling,
        no_cancel: false,
    }
}

/// A fix that needs a package was ticked: asks the worker what it would download. Nothing is
/// selected and nothing is requested from the network.
pub(super) fn ask(ui: &AppWindow, st: &mut State, page: &GameVm, i: usize) {
    if st.download.is_some() || st.dialog.is_some() || ui.global::<Modal>().get_working() {
        return;
    }
    let (Some(app_id), Some(fix)) = (st.game, page.fixes.get(i)) else {
        return;
    };
    // The checkbox takes the focus back when the dialog closes.
    st.opener = i32::try_from(i).map_or(-1, |i| -2 - i);
    ui.global::<Modal>().set_return_to(-1);
    st.worker.send(Job::DownloadAsk {
        app_id,
        variant: fix.key.clone(),
    });
}

/// The worker's dialog (consent, progress or failure) replaces what the window shows.
pub(super) fn download_event(ui: &AppWindow, st: &mut State, d: &DownloadVm) {
    // A consent for a page the user has left (a slow answer) is not shown.
    if d.stage == DownloadStage::Consent && st.game != Some(d.app_id) {
        return;
    }
    st.download = Some(DownloadState {
        stage: d.stage,
        nonce: d.nonce,
        variant: d.variant.clone(),
    });
    ui.set_dialog(download_data(d));
    if !ui.get_dialog_open() {
        ui.set_dialog_open(true);
        let m = ui.global::<Modal>();
        m.set_working(false);
        m.set_open(true);
    }
}

/// "Download" or "Try again": the download of exactly the list the dialog shows.
pub(super) fn confirm(ui: &AppWindow, st: &mut State) {
    let lang = st.lang;
    let Some(d) = st.download.as_mut() else {
        return;
    };
    if !matches!(d.stage, DownloadStage::Consent | DownloadStage::Failed) {
        return;
    }
    d.stage = DownloadStage::Progress;
    let nonce = d.nonce;
    // At once: the buttons of a running download, without waiting for the worker's first report.
    let mut data = ui.get_dialog();
    data.no_confirm = true;
    data.cancel_label = tr(lang, Msg::DlBtnCancel);
    data.cancel_disabled = false;
    ui.set_dialog(data);
    st.worker.send(Job::Download { nonce });
}

/// "Cancel" or Esc: closes a consent or failure dialog (nothing was requested), asks a running
/// download to stop.
pub(super) fn dismiss(ui: &AppWindow, st: &mut State) {
    match st.download.as_ref().map(|d| d.stage) {
        Some(DownloadStage::Progress) => cancel(ui, st),
        Some(_) => close(ui, st),
        None => {}
    }
}

/// Asks the running download to stop; the dialog says so until the worker confirms (it may take
/// up to 30 s, WinHTTP's receive timeout).
pub(super) fn cancel(ui: &AppWindow, st: &mut State) {
    st.worker.cancel_download();
    if st.download.is_some() {
        let mut data = ui.get_dialog();
        data.cancel_label = tr(st.lang, Msg::DlCancelling);
        data.cancel_disabled = true;
        ui.set_dialog(data);
    }
}

/// Whether a download is running as far as the window knows (its progress dialog is open).
pub(super) fn running(st: &State) -> bool {
    st.download
        .as_ref()
        .is_some_and(|d| d.stage == DownloadStage::Progress)
}

/// Closes the dialog; the opener takes the focus back.
fn close(ui: &AppWindow, st: &mut State) {
    ui.set_dialog_open(false);
    let m = ui.global::<Modal>();
    m.set_open(false);
    m.set_working(false);
    m.set_return_to(st.opener);
    st.download = None;
}

/// A download ended. Returns whether the window was asked to close meanwhile (it closes now).
pub(super) fn download_ended(ui: &AppWindow, st: &mut State, outcome: DownloadOutcome) -> bool {
    match outcome {
        DownloadOutcome::Done => {
            // The fresh page came before this: the fix is selectable now and the user asked for
            // it, so it is ticked and the usual preview follows.
            let variant = st.download.as_ref().map(|d| d.variant.clone());
            close(ui, st);
            if let (Some(key), Some(page)) = (variant, st.page.clone())
                && let Some(i) = page
                    .fixes
                    .iter()
                    .position(|f| f.key == key && f.offer == crate::vm::Offer::Selectable)
                && !st.selection.contains(&key)
            {
                st.selection.toggle(&page, i);
                super::write::show_selection(ui, st);
                plan_selection(ui, st);
            }
        }
        DownloadOutcome::Cancelled => close(ui, st),
        // The failure dialog was sent before this and stays.
        DownloadOutcome::Failed => {}
        // A confirm that matched no shown list, or a job that stopped before it began: nothing
        // runs, so no dialog stays.
        DownloadOutcome::Refused => close(ui, st),
    }
    std::mem::take(&mut st.close_after_download)
}
