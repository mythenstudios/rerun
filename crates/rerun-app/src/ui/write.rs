//! The write side of the window (P5-5a, ADR 0027): selecting fixes, the preview, apply, undo and
//! forget as the user sees them. Handlers turn clicks into worker jobs and draw the answers; the
//! plans and the journal are the core's (`flow`), the hash of the plan travels with "Apply" and
//! the core checks it again (rule 5). Moved out of `ui.rs` unchanged (P5-5 preparation).

use super::*;

// ---------- selecting, previewing, applying, undoing (P5-5a) ----------

fn value_str(v: &Value) -> SharedString {
    s(v.as_str())
}

fn line(l: &vm::LineVm) -> LineData {
    LineData {
        label: s(&l.label),
        values: model(l.values.iter().map(value_str).collect()),
        mono: l.mono,
    }
}

pub(super) fn op(o: &OpVm) -> OpData {
    let (fate_sym, fate_word) = match &o.fate {
        Some((b, word)) => (s(b.sym.glyph()), s(word)),
        None => (SharedString::new(), SharedString::new()),
    };
    OpData {
        index: i32::try_from(o.index).unwrap_or(i32::MAX),
        action: s(&o.action),
        target: shown(&o.target),
        lines: model(o.lines.iter().map(line).collect()),
        undo: o.undo.as_deref().map(s).unwrap_or_default(),
        fate_sym,
        fate_word,
    }
}

fn warn(w: &WarnVm) -> WarnData {
    WarnData {
        sym: s(w.badge.sym.glyph()),
        word: s(&w.badge.word),
        text: s(&w.text),
        detail: w.detail.as_ref().map(shown).unwrap_or_default(),
    }
}

fn launch(l: &LaunchVm) -> LaunchData {
    LaunchData {
        heading: s(&l.heading),
        lines: model(l.lines.iter().map(s).collect()),
        intro: s(&l.intro),
        option: l.option.as_ref().map(shown).unwrap_or_default(),
        notes: model(l.notes.iter().map(s).collect()),
        problems: model(l.problems.iter().map(warn).collect()),
        copy: s(&l.copy),
        copied: s(&l.copied),
    }
}

/// The preview panel without a preview: `state` 0 nothing selected, 1 being made.
pub(super) fn preview_none(state: i32) -> PreviewData {
    PreviewData {
        state,
        ..PreviewData::default()
    }
}

/// The preview panel with a refusal (state 3).
pub(super) fn preview_refused(r: &ResultVm) -> PreviewData {
    PreviewData {
        state: 3,
        refused: notice(&r.notice),
        ..PreviewData::default()
    }
}

/// The preview of a plan, drawn; `ready` only once the worker confirmed it was handed over
/// (module docs: "Apply" waits for it).
pub(super) fn preview_data(p: &PreviewVm, ready: bool) -> PreviewData {
    PreviewData {
        state: 2,
        hash: s(&p.hash),
        summary: s(&p.summary),
        folder: p.folder.as_ref().map(shown).unwrap_or_default(),
        ops: model(p.ops.iter().map(op).collect()),
        warnings: model(p.warnings.iter().map(warn).collect()),
        notes: model(p.notes.iter().map(s).collect()),
        has_launch: p.launch.is_some(),
        launch: p.launch.as_ref().map(launch).unwrap_or_default(),
        admin: s(&p.admin),
        admin_notes: model(p.admin_notes.iter().map(s).collect()),
        undo: s(&p.undo),
        can_apply: p.can_apply,
        nothing: p.nothing.as_deref().map(s).unwrap_or_default(),
        ready,
        ..PreviewData::default()
    }
}

pub(super) fn card(c: &TxnCardVm) -> CardData {
    CardData {
        id: s(&c.id),
        game: c.game.as_ref().map(value_str).unwrap_or_default(),
        state: badge(&c.state),
        problem: c.problem.as_deref().map(s).unwrap_or_default(),
        ops: model(c.ops.iter().map(op).collect()),
        note: s(&c.note),
        can_undo: c.can_undo,
        can_forget: c.can_forget,
    }
}

pub(super) fn dialog_data(d: &DialogVm) -> DialogData {
    let (heading, lines, option, problems) = match &d.launch {
        Some(l) => (
            l.heading.as_str(),
            l.lines.iter().map(s).collect(),
            l.option.as_ref().map(shown).unwrap_or_default(),
            l.problems.iter().map(warn).collect(),
        ),
        None => ("", Vec::new(), SharedString::new(), Vec::new()),
    };
    DialogData {
        kind: i32::from(d.kind == DialogKind::Forget),
        title: s(&d.title),
        intro: s(&d.intro),
        changed: d.changed.as_deref().map(s).unwrap_or_default(),
        ops: model(d.ops.iter().map(op).collect()),
        notes: model(d.notes.iter().map(s).collect()),
        details: model(d.details.iter().map(detail).collect()),
        has_launch: d.launch.is_some(),
        launch_heading: s(heading),
        launch_lines: model(lines),
        launch_option: option,
        launch_problems: model(problems),
        confirm: s(&d.confirm),
        can_confirm: d.can_confirm,
        blocked: d.blocked.as_deref().map(s).unwrap_or_default(),
        no_confirm: false,
        cancel_label: SharedString::new(),
        cancel_disabled: false,
        no_cancel: false,
    }
}

/// The wait for the UAC dialog in the window's one dialog: no button at all (P5-5c).
pub(super) fn uac_data(u: &vm::UacVm) -> DialogData {
    DialogData {
        kind: 3,
        title: s(&u.title),
        intro: s(&u.body),
        notes: model(u.notes.iter().map(s).collect()),
        no_confirm: true,
        no_cancel: true,
        cancel_disabled: true,
        ..DialogData::default()
    }
}

/// The worker waits for the UAC dialog: the window shows it as a modal that cannot be dismissed
/// (Esc and the buttons do nothing; closing the window is refused, a write runs), replacing an
/// undo dialog whose confirm started it. The result closes it.
pub(super) fn uac_wait(ui: &AppWindow, st: &mut State, u: &vm::UacVm) {
    // Opened by "Apply" (no dialog open): the focus goes to the result's banner afterwards, not
    // to the opener of an earlier dialog.
    if st.dialog.is_none() {
        st.opener = -1;
    }
    st.uac = true;
    ui.set_dialog(uac_data(u));
    ui.set_dialog_open(true);
    let m = ui.global::<Modal>();
    m.set_open(true);
    m.set_working(true);
}

fn banner(r: &ResultVm) -> BannerData {
    use crate::text::Sym;
    BannerData {
        tone: match r.tone {
            Tone::Done => 0,
            Tone::Calm => 1,
            Tone::Attention => 2,
        },
        sym: s(match r.tone {
            Tone::Done => Sym::Applied.glyph(),
            Tone::Calm => Sym::None.glyph(),
            Tone::Attention => Sym::Attention.glyph(),
        }),
        title: s(&r.notice.title),
        body: s(&r.notice.body),
        details: model(r.notice.details.iter().map(detail).collect()),
    }
}

/// Marks the selected fixes on the page the window holds (the rows are updated in place, so the
/// focused control stays).
pub(super) fn show_selection(ui: &AppWindow, st: &State) {
    let Some(page) = &st.page else {
        return;
    };
    let rows = ui.get_game().fixes;
    for (i, on) in st.selection.flags(page).into_iter().enumerate() {
        if let Some(mut row) = rows.row_data(i)
            && row.selected != on
        {
            row.selected = on;
            rows.set_row_data(i, row);
        }
    }
}

/// Asks the worker for the preview of the selection (or clears it when nothing is selected).
pub(super) fn plan_selection(ui: &AppWindow, st: &mut State) {
    let (Some(app_id), Some(page)) = (st.game, st.page.as_ref()) else {
        return;
    };
    let picks = st.selection.picks(page);
    st.preview_hash = None;
    ui.set_preview(preview_none(i32::from(!picks.is_empty())));
    st.worker.send(Job::Plan { app_id, picks });
}

/// Shows an outcome calmly above the page.
pub(super) fn show_result(ui: &AppWindow, r: &ResultVm) {
    ui.set_banner(banner(r));
    ui.set_banner_shown(true);
}

pub(super) fn close_dialog(ui: &AppWindow, st: &mut State) {
    ui.set_dialog_open(false);
    let m = ui.global::<Modal>();
    m.set_open(false);
    m.set_working(false);
    // The opener of the dialog takes the focus back.
    m.set_return_to(st.opener);
    st.dialog = None;
    st.uac = false;
}

/// How long a close waits for a cancelled download to stop before the window closes anyway.
const CLOSE_GRACE: Duration = Duration::from_secs(15);

/// The window's close: refused while a write runs (rule 1: the journal covers a crash, but a
/// close in the middle of an apply is not something to offer). A download is different: it is
/// cancelled, and the window closes by itself when the worker reports that it has stopped
/// (up to WinHTTP's 30 s receive timeout), so nothing outlives the window and the cache keeps
/// nothing of it (P5-5b).
fn close_window(ui: &AppWindow, st: &mut State) -> CloseRequestResponse {
    // A download that the window no longer shows (its end is on the way) does not hold the
    // window: it would wait for an event that already came.
    let downloading = st.worker.downloading() && download::running(st);
    match vm::closing_policy(st.worker.busy_writing(), downloading) {
        vm::Closing::Close => CloseRequestResponse::HideWindow,
        vm::Closing::FinishWrite => {
            show_result(ui, &vm::closing_blocked(st.lang));
            CloseRequestResponse::KeepWindowShown
        }
        vm::Closing::CancelDownload => {
            st.close_after_download = true;
            download::cancel(ui, st);
            show_result(ui, &vm::closing(st.lang));
            // A cancel takes effect at the next read; a request that hangs (WinHTTP's phases
            // are 30 s each) must not keep the window forever: after the grace period it
            // closes anyway (rule 1: the process ends). A leftover temporary file is removed by
            // the next fetch (`sweep`).
            let weak = ui.as_weak();
            slint::Timer::single_shot(CLOSE_GRACE, move || {
                if let Some(ui) = weak.upgrade() {
                    let _ = ui.hide();
                }
            });
            CloseRequestResponse::KeepWindowShown
        }
    }
}

pub(super) fn write_callbacks(ui: &AppWindow, state: &Rc<RefCell<State>>) {
    // A fix is ticked: the selection rules are `vm::Selection`'s, the window only asks.
    let weak = ui.as_weak();
    let st = state.clone();
    ui.on_fix_toggled(move |i| {
        let Some(ui) = weak.upgrade() else {
            return;
        };
        let mut st = st.borrow_mut();
        let (Some(page), Ok(i)) = (st.page.clone(), usize::try_from(i)) else {
            return;
        };
        // A fix that needs a download: the consent dialog first (nothing is selected, nothing
        // is downloaded until the user agrees there).
        if page
            .fixes
            .get(i)
            .is_some_and(|f| f.offer == vm::Offer::NeedsDownload)
        {
            download::ask(&ui, &mut st, &page, i);
            return;
        }
        st.selection.toggle(&page, i);
        show_selection(&ui, &st);
        plan_selection(&ui, &mut st);
    });

    // "Apply" carries the plan hash of the preview it belongs to; the worker applies only the
    // plan it shows under that hash, and the core checks the hash again.
    let weak = ui.as_weak();
    let st = state.clone();
    ui.on_apply(move |hash| {
        let Some(ui) = weak.upgrade() else {
            return;
        };
        let st = st.borrow();
        // One apply at a time, and only for a preview the worker confirmed: a key repeat or an
        // accessibility action on a disabled button sends nothing.
        let p = ui.get_preview();
        if ui.global::<Modal>().get_working() || !p.ready || !p.can_apply || p.hash != hash {
            return;
        }
        ui.global::<Modal>().set_working(true);
        let mut p = p;
        p.ready = false;
        ui.set_preview(p);
        st.worker.send(Job::Apply {
            hash: hash.to_string(),
        });
    });

    let weak = ui.as_weak();
    let st = state.clone();
    ui.on_card_undo(move |i| card_action(&weak, &st, i, false));
    let weak = ui.as_weak();
    let st = state.clone();
    ui.on_card_forget(move |i| card_action(&weak, &st, i, true));

    let weak = ui.as_weak();
    let st = state.clone();
    ui.on_dialog_confirm(move || {
        let Some(ui) = weak.upgrade() else {
            return;
        };
        let mut st = st.borrow_mut();
        // The wait for Windows has no confirm.
        if st.uac {
            return;
        }
        // The download dialogs share the window's dialog; their confirm is the download's.
        if st.download.is_some() {
            download::confirm(&ui, &mut st);
            return;
        }
        let Some((kind, txn, nonce)) = st.dialog else {
            return;
        };
        // Nothing while a write is in flight, nothing for a dialog that cannot be confirmed; the
        // worker also refuses a confirm that does not carry the shown dialog's nonce.
        if ui.global::<Modal>().get_working() || !ui.get_dialog().can_confirm {
            return;
        }
        ui.global::<Modal>().set_working(true);
        st.worker.send(match kind {
            DialogKind::Undo => Job::Revert { txn, nonce },
            DialogKind::Forget => Job::Forget { txn, nonce },
        });
    });

    let weak = ui.as_weak();
    let st = state.clone();
    ui.on_dialog_cancel(move || {
        if let Some(ui) = weak.upgrade() {
            let mut st = st.borrow_mut();
            // The wait for Windows cannot be dismissed: the result closes it.
            if st.uac {
                return;
            }
            if st.download.is_some() {
                download::dismiss(&ui, &mut st);
            } else {
                close_dialog(&ui, &mut st);
            }
        }
    });

    let weak = ui.as_weak();
    ui.on_banner_dismiss(move || {
        if let Some(ui) = weak.upgrade() {
            ui.set_banner_shown(false);
        }
    });

    let weak = ui.as_weak();
    let st = state.clone();
    ui.on_request_close(move || {
        let Some(ui) = weak.upgrade() else {
            return;
        };
        if matches!(
            close_window(&ui, &mut st.borrow_mut()),
            CloseRequestResponse::HideWindow
        ) {
            let _ = ui.hide();
        }
    });

    // Alt+F4 and the system menu take the same way.
    let weak = ui.as_weak();
    let st = state.clone();
    ui.window()
        .on_close_requested(move || match weak.upgrade() {
            Some(ui) => close_window(&ui, &mut st.borrow_mut()),
            None => CloseRequestResponse::HideWindow,
        });
}

/// A card's "Undo" or "Close without undoing": the preview first (rule 5).
fn card_action(weak: &slint::Weak<AppWindow>, st: &Rc<RefCell<State>>, i: i32, forget: bool) {
    let Some(ui) = weak.upgrade() else {
        return;
    };
    let mut st = st.borrow_mut();
    let Ok(i) = usize::try_from(i) else {
        return;
    };
    let cards = if ui.get_page() == 1 {
        &st.applied_cards
    } else {
        &st.game_cards
    };
    let Some(txn) = cards.get(i).map(|c| c.txn) else {
        return;
    };
    st.opener = i32::try_from(i * 2 + usize::from(forget)).unwrap_or(-1);
    ui.global::<Modal>().set_return_to(-1);
    st.worker.send(if forget {
        Job::ForgetPreview { txn }
    } else {
        Job::RevertPreview { txn }
    });
}
