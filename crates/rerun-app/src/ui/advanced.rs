//! The Advanced section of the game page in the window (ADR 0029, plan P5-OE "UI"): draws what
//! `vm::AdvancedVm` says and sends what the user did. The rules (what a field means, which one is
//! locked and why, what the form asks the worker to plan) are `vm::Form`'s; what the rule selects
//! on this PC is the core's, asked of the worker (`Job::Readout`) and shown as it answers. The
//! window computes nothing of it.
//!
//! The section is updated in place (rows of the models are set, never replaced), so the control
//! the user is on keeps the keyboard focus while the form redraws.

use super::generated::{AdvChoiceData, AdvGroupData, AdvSwitchData, AdvancedData};
use super::write::parts;
use super::*;
use crate::vm::{AdvancedRender, Field, GroupRender, ReadoutVm, SwitchRender};
use rerun_core::prim::CpuRuleSpec;

fn switch(r: &SwitchRender) -> AdvSwitchData {
    AdvSwitchData {
        label: s(&r.label),
        desc: s(&r.desc),
        checked: r.checked,
        enabled: r.enabled,
        has_note: r.note.is_some(),
        note: r.note.as_ref().map(parts).unwrap_or_default(),
    }
}

fn choices(r: &GroupRender) -> Vec<AdvChoiceData> {
    r.choices
        .iter()
        .map(|c| AdvChoiceData {
            name: s(&c.name),
            label: shown(&c.label),
            checked: c.checked,
            enabled: c.enabled,
        })
        .collect()
}

/// Sets the rows of `old` that differ and keeps the model (so the elements stay); a model of
/// another length is replaced.
fn sync_rows<T: Clone + PartialEq + 'static>(old: &ModelRc<T>, new: Vec<T>) -> ModelRc<T> {
    if old.row_count() == new.len() {
        for (i, n) in new.into_iter().enumerate() {
            if old.row_data(i).as_ref() != Some(&n) {
                old.set_row_data(i, n);
            }
        }
        old.clone()
    } else {
        model(new)
    }
}

fn group(old: &AdvGroupData, r: &GroupRender) -> AdvGroupData {
    AdvGroupData {
        label: s(&r.label),
        choices: sync_rows(&old.choices, choices(r)),
        has_note: r.note.is_some(),
        note: r.note.as_ref().map(parts).unwrap_or_default(),
    }
}

/// The section as the window shows it: `old` is the data it has (its models are kept),
/// `readout` what the rule selects on this PC (or a local word), `undo_card` the card of the
/// change a cleared form would mean taking back (-1: none).
pub(super) fn data(
    old: &AdvancedData,
    r: &AdvancedRender,
    readout: Option<&ReadoutVm>,
    undo_card: i32,
) -> AdvancedData {
    let start = r.start.as_ref();
    AdvancedData {
        available: r.available,
        name: s(&r.name),
        title: s(&r.title),
        intro: s(&r.intro),
        active: r.active.as_deref().map(s).unwrap_or_default(),
        unavailable: r.unavailable.as_deref().map(s).unwrap_or_default(),
        cpu_heading: s(&r.cpu_heading),
        has_launch_note: r.launch_note.is_some(),
        launch_note: r.launch_note.as_ref().map(parts).unwrap_or_default(),
        threads_label: s(&r.threads.label),
        threads_value: s(&r.threads.value),
        threads_less: s(&r.threads.less),
        threads_more: s(&r.threads.more),
        threads_less_on: r.threads.less_on,
        threads_more_on: r.threads.more_on,
        smt: switch(&r.smt),
        l3: switch(&r.l3),
        has_prefer: r.prefer.is_some(),
        prefer: r
            .prefer
            .as_ref()
            .map(|g| group(&old.prefer, g))
            .unwrap_or_default(),
        exclude: group(&old.exclude, &r.exclude),
        mode: group(&old.mode, &r.mode),
        method: group(&old.method, &r.method),
        priority: group(&old.priority, &r.priority),
        flags_label: s(&r.flags_label),
        flags: sync_rows(&old.flags, r.flags.iter().map(switch).collect()),
        has_flags_note: r.flags_note.is_some(),
        flags_note: r.flags_note.as_ref().map(parts).unwrap_or_default(),
        has_start: start.is_some(),
        start: start.map(|g| group(&old.start, g)).unwrap_or_default(),
        start_desc: s(&r.start_desc),
        has_problem: r.problem.is_some(),
        problem: r.problem.as_ref().map(parts).unwrap_or_default(),
        replaces: r.replaces.as_deref().map(s).unwrap_or_default(),
        undo_hint: r
            .undo_hint
            .as_ref()
            .map(|(h, _, _)| s(h))
            .unwrap_or_default(),
        undo_label: r
            .undo_hint
            .as_ref()
            .map(|(_, b, _)| s(b))
            .unwrap_or_default(),
        undo_card,
        read_title: s(&r.read_title),
        readout: readout.map(|x| s(&x.line)).unwrap_or_default(),
        readout_detail: readout
            .and_then(|x| x.detail.as_ref())
            .map(shown)
            .unwrap_or_default(),
        readout_note: readout
            .and_then(|x| x.note.as_deref())
            .map(s)
            .unwrap_or_default(),
    }
}

/// What the readout shows now: the worker's answer for the current rule, else the local word
/// (no rule, or a fix's rule instead), else nothing yet.
fn readout_now(st: &State, page: &GameVm) -> Option<ReadoutVm> {
    match st.selection.readout_rule(page) {
        Some((rule, _)) => st
            .readout
            .as_ref()
            .filter(|(r, _)| *r == rule)
            .map(|(_, v)| v.clone()),
        None => st.selection.readout_local(page),
    }
}

/// Draws the section for the current selection and asks the worker what the rule selects when the
/// rule changed. Called after every change of the selection.
pub(super) fn refresh(ui: &AppWindow, st: &mut State) {
    let Some(page) = st.page.clone() else {
        return;
    };
    match st.selection.readout_rule(&page) {
        Some((rule, bitness)) => {
            if st.readout.as_ref().map(|(r, _)| *r) != Some(rule) && st.readout_asked != Some(rule)
            {
                st.readout_asked = Some(rule);
                st.worker.send(Job::Readout { rule, bitness });
            }
        }
        None => {
            st.readout = None;
            st.readout_asked = None;
        }
    }
    show(ui, st);
}

/// Draws the section from the state (no job).
pub(super) fn show(ui: &AppWindow, st: &State) {
    let Some(page) = &st.page else {
        return;
    };
    let render = st.selection.advanced(page);
    let readout = readout_now(st, page);
    let undo = render.undo_hint.as_ref().map(|(_, _, t)| *t);
    let mut g = ui.get_game();
    g.advanced = data(
        &g.advanced,
        &render,
        readout.as_ref(),
        super::write::undo_card(page, undo),
    );
    ui.set_game(g);
}

/// The answer of the worker: kept only for the rule the section asks about now.
pub(super) fn answered(ui: &AppWindow, st: &mut State, rule: CpuRuleSpec, v: ReadoutVm) {
    if st.readout_asked == Some(rule) {
        st.readout_asked = None;
    }
    st.readout = Some((rule, v));
    show(ui, st);
}

/// A click on a field of the section: the rules are `vm::Form`'s, the window only asks; the one
/// selection is planned again.
pub(super) fn edited(ui: &AppWindow, st: &mut State, field: i32, value: i32) {
    let (Some(page), Some(f)) = (st.page.clone(), Field::from_ui(field, value)) else {
        return;
    };
    st.selection.edit(&page, f);
    super::write::show_selection(ui, st);
    super::write::plan_selection(ui, st);
}
