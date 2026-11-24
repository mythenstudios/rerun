//! Links, "report a problem" and Rerun's folder in the window (P5-10a, ADR 0027 amendment
//! P5-10a). A click never hands a string to the worker: a source link is named by the fix, the
//! issue and the source's position on the page the window shows, the report by its dialog's
//! nonce, the folder by nothing at all. The core looks everything up again.

use std::cell::RefCell;
use std::rc::Rc;

use rerun_core::flow::LinkRef;
use slint::ComponentHandle;

use super::generated::{AppWindow, DataFolderData, Modal};
use super::{State, s, shown};
use crate::vm::DataVm;
use crate::worker::Job;

/// The focus target of "Report a problem..." when its dialog closes (`take-focus: Modal.return-to
/// == -1002` in `app.slint`).
pub(super) const REPORT_OPENER: i32 = -1002;

/// Settings > Data for the window.
pub(super) fn data_data(d: &DataVm) -> DataFolderData {
    DataFolderData {
        path: d.path.as_ref().map(shown).unwrap_or_default(),
        exists: d.exists,
        note: d.note.as_deref().map(s).unwrap_or_default(),
        detail: d.detail.as_ref().map(shown).unwrap_or_default(),
    }
}

/// Another dialog, a download or the wait for Windows holds the window.
fn busy(ui: &AppWindow, st: &State) -> bool {
    st.uac || st.download.is_some() || st.dialog.is_some() || ui.global::<Modal>().get_working()
}

/// The reference of source `si` of the issue `sj` of fix `fi` on the page the window shows.
fn link_of(st: &State, fi: i32, sj: i32, si: i32) -> Option<LinkRef> {
    let page = st.page.as_ref()?;
    let fix = page.fixes.get(usize::try_from(fi).ok()?)?;
    let sj = usize::try_from(sj).ok()?;
    let source = usize::try_from(si).ok()?;
    // Only a source the page offers an open button for.
    if !*fix.solves.get(sj)?.can_open.get(source)? {
        return None;
    }
    Some(LinkRef {
        app_id: page.app_id,
        topo: page.topo.clone()?,
        issue: fix.issues.get(sj)?.0.clone(),
        variant: fix.key.clone(),
        source,
    })
}

pub(super) fn open_callbacks(ui: &AppWindow, state: &Rc<RefCell<State>>) {
    let weak = ui.as_weak();
    let st = state.clone();
    ui.on_source_open(move |fi, sj, si| {
        let Some(ui) = weak.upgrade() else {
            return;
        };
        let st = st.borrow();
        if busy(&ui, &st) {
            return;
        }
        if let Some(r) = link_of(&st, fi, sj, si) {
            st.worker.send(Job::OpenSource(r));
        }
    });

    let weak = ui.as_weak();
    let st = state.clone();
    ui.on_report(move || {
        let Some(ui) = weak.upgrade() else {
            return;
        };
        let mut st = st.borrow_mut();
        let Some(app_id) = st.game else {
            return;
        };
        if busy(&ui, &st) {
            return;
        }
        // The button takes the focus back when the dialog closes.
        st.opener = REPORT_OPENER;
        ui.global::<Modal>().set_return_to(-1);
        st.worker.send(Job::ReportAsk { app_id });
    });

    let weak = ui.as_weak();
    let st = state.clone();
    ui.on_open_data_folder(move || {
        let Some(ui) = weak.upgrade() else {
            return;
        };
        let st = st.borrow();
        if busy(&ui, &st) {
            return;
        }
        st.worker.send(Job::OpenDataFolder);
    });
}
