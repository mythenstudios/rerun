//! The options of a game (ADR 0032, plan P5-OE "UI"): the section "Options" above the problems
//! and fixes, the choice the user makes per option, what a live value looks like, and the parts
//! of the launch profile the preview shows with their origin. Pure: typed `flow` values and a
//! [`Lang`] in, plain structs with every string localized out. Nothing here changes a system;
//! the choices join the fix picks in one `flow::Selection` and one preview (rule 5).
//!
//! Rules of the section, all from the core's data:
//! - every option starts with the choice "Unchanged" (what the user has now; the implicit
//!   `unchanged` of the Topo format, never sent as a [`Choice`]);
//! - a value a live transaction chose is shown as active, with that change's number, and is the
//!   checked choice until the user picks another one;
//! - "Unchanged" while a value is live means undoing that change: the page explains and offers the
//!   change's undo; it never plans a revert by itself;
//! - a refused value stays visible, disabled, with the reason (anti-cheat, the program it starts
//!   is not here, another change holds files for another program, the launch profile problem).

use std::collections::BTreeMap;

use rerun_core::catalog::model::OptionStep;
use rerun_core::escape::{self, Shown};
use rerun_core::exec::{LiveError, LiveState};
use rerun_core::flow::OptionView;
use rerun_core::journal::TxnId;
use rerun_core::plan::Choice;
use rerun_core::topo::{LaunchParts, PartFrom, ValueRefusal};

use super::write::{TextLine, source_text};
use super::{Badge, status_badge};
use crate::text::{Lang, Msg, t};

fn tx(lang: Lang, m: Msg) -> String {
    t(lang, m).into_owned()
}

/// The options section.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct OptionsVm {
    /// The heading.
    pub title: String,
    /// What the section is.
    pub intro: String,
    /// The game cannot be planned for now (the journal's state), shown above the options.
    pub notice: Option<LiveNoticeVm>,
    /// The options, in the Topo's order.
    pub options: Vec<OptionVm>,
}

/// A game-level notice: the journal's state forbids every plan of the game (a [`LiveError`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveNoticeVm {
    /// The heading.
    pub title: String,
    /// What is wrong and what to do.
    pub body: String,
    /// The change it is about: its card has the undo.
    pub txn: Option<TxnId>,
    /// The button that opens that change's undo.
    pub undo_button: Option<String>,
    /// The journal's own text (escaped), for an unreadable journal.
    pub detail: Option<Shown<'static>>,
}

/// One option.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OptionVm {
    /// The option ID as the Topo spells it (the choice names it; never drawn as text of its own).
    pub key: String,
    /// What is chosen (Topo text, escaped).
    pub title: Shown<'static>,
    /// Where the values come from: type and link (escaped).
    pub sources: Vec<Shown<'static>>,
    /// Five or more choices: a list, one under the other, instead of a row.
    pub list: bool,
    /// "Unchanged" first, then the values in the Topo's order.
    pub choices: Vec<ChoiceVm>,
    /// A value of this option is live.
    pub live: Option<LiveVm>,
}

/// The value of an option that a live change set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveVm {
    /// The value ID.
    pub value: String,
    /// The change.
    pub txn: TxnId,
    /// "Active: <value> (change No. 3)", the value as its own element.
    pub line: TextLine,
    /// What "Unchanged" would mean now: undoing that change.
    pub undo_hint: String,
    /// The button that opens that change's undo.
    pub undo_button: String,
}

/// One choice of an option.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChoiceVm {
    /// The value ID; empty for "Unchanged".
    pub key: String,
    /// What the button says (Topo text, escaped; "Unchanged" for the first).
    pub label: Shown<'static>,
    /// The accessible name: "<option>: <value>".
    pub name: String,
    /// How well the value is tested; none for "Unchanged".
    pub status: Option<Badge>,
    /// What to know: what "Unchanged" means, why a value is not offered, a warning.
    pub note: Option<String>,
    /// It can be chosen.
    pub enabled: bool,
}

impl ChoiceVm {
    /// The choice is "Unchanged".
    pub fn is_unchanged(&self) -> bool {
        self.key.is_empty()
    }
}

fn live_notice(e: &LiveError, lang: Lang) -> LiveNoticeVm {
    let (m, txn, detail) = match e {
        LiveError::Journal(s) => (
            Msg::OptLiveJournal,
            None,
            Some(escape::text(s).into_owned()),
        ),
        LiveError::Interrupted { txn } => {
            (Msg::OptLiveInterrupted { n: txn.seq() }, Some(*txn), None)
        }
        LiveError::Unreadable { txn } => {
            (Msg::OptLiveUnreadable { n: txn.seq() }, Some(*txn), None)
        }
        LiveError::Changed { txn } => (Msg::OptLiveChanged { n: txn.seq() }, Some(*txn), None),
    };
    LiveNoticeVm {
        title: tx(lang, Msg::OptLiveTitle),
        body: tx(lang, m),
        txn,
        undo_button: txn.map(|t| tx(lang, Msg::OptUndoBtn { n: t.seq() })),
        detail,
    }
}

/// The options section of a game: `views` are the engine's options, `live` what the journal
/// says is live for the game, `topo` the ID of the Topo that matched (a live choice of another
/// Topo is not this page's).
pub fn options(
    views: &[OptionView],
    live: &Result<LiveState, LiveError>,
    topo: &str,
    lang: Lang,
) -> OptionsVm {
    let state = live.as_ref().ok();
    let options = views
        .iter()
        .map(|v| {
            let opt = &v.option;
            let live_choice = state.and_then(|s| {
                s.choices
                    .iter()
                    .find(|c| c.topo == topo && c.option == opt.id.as_str())
            });
            let title = escape::text(&opt.title).into_owned();
            let mut choices = vec![ChoiceVm {
                key: String::new(),
                name: format!("{}: {}", opt.title, tx(lang, Msg::OptUnchanged)),
                label: escape::text(&tx(lang, Msg::OptUnchanged)).into_owned(),
                status: None,
                note: Some(tx(lang, Msg::OptUnchangedDesc)),
                enabled: true,
            }];
            let mut live_vm = None;
            for val in &v.values {
                let id = val.value.id.as_str();
                // The program the value starts: another one than a live change's package files
                // or flags were planned for refuses it (user decision E4 b).
                let exe_switch = state.and_then(|s| {
                    val.value.steps.iter().find_map(|st| match st {
                        OptionStep::Start(run) => {
                            s.exes.iter().find(|e| e.exe != *run).map(|e| e.txn)
                        }
                        _ => None,
                    })
                });
                let (reason, enabled) = match (&val.refused, exe_switch, live.as_ref().err()) {
                    (_, _, Some(_)) => (Some(tx(lang, Msg::OptNotOfferedLive)), false),
                    (Some(ValueRefusal::AntiCheat(_)), _, _) => {
                        (Some(tx(lang, Msg::OptNotOfferedAntiCheat)), false)
                    }
                    (Some(ValueRefusal::NotMatched), _, _) => {
                        (Some(tx(lang, Msg::OptNotOfferedNotMatched)), false)
                    }
                    (None, Some(txn), None) => (
                        Some(tx(lang, Msg::OptNotOfferedExeSwitch { n: txn.seq() })),
                        false,
                    ),
                    (None, None, None) => (
                        (!val.warned.is_empty()).then(|| tx(lang, Msg::OptWarned)),
                        true,
                    ),
                };
                if let Some(c) = live_choice.filter(|c| c.value == id) {
                    live_vm = Some(LiveVm {
                        value: id.to_owned(),
                        txn: c.txn,
                        line: TextLine::named(
                            format!("{} ", tx(lang, Msg::OptActive)),
                            escape::text(&val.value.title).into_owned(),
                            format!(" {}", tx(lang, Msg::OptActiveChange { n: c.txn.seq() })),
                        ),
                        undo_hint: tx(lang, Msg::OptUndoHint { n: c.txn.seq() }),
                        undo_button: tx(lang, Msg::OptUndoBtn { n: c.txn.seq() }),
                    });
                }
                choices.push(ChoiceVm {
                    key: id.to_owned(),
                    name: format!("{}: {}", opt.title, val.value.title),
                    label: escape::text(&val.value.title).into_owned(),
                    status: Some(status_badge(val.value.status, lang)),
                    note: reason,
                    enabled,
                });
            }
            OptionVm {
                key: opt.id.as_str().to_owned(),
                title,
                sources: opt
                    .sources
                    .iter()
                    .map(|s| source_text(s.kind, &s.url, lang))
                    .collect(),
                list: choices.len() > 5,
                choices,
                live: live_vm,
            }
        })
        .collect();
    OptionsVm {
        title: tx(lang, Msg::OptionsTitle),
        intro: tx(lang, Msg::OptionsIntro),
        notice: live.as_ref().err().map(|e| live_notice(e, lang)),
        options,
    }
}

// ---------- the choices of the user ----------

/// The choices the user made on a game page, by option ID: the value that is to be applied. An
/// option that is not here keeps what it has (its live value, or "Unchanged"). Part of
/// [`super::Selection`]; the rules are pure and tested without a window.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Choices {
    values: BTreeMap<String, String>,
    /// The option whose "Unchanged" was chosen while a value is live: the page explains.
    hint: Option<usize>,
}

impl Choices {
    /// Nothing is chosen.
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// The option whose "Unchanged" needs the explanation.
    pub fn hint(&self) -> Option<usize> {
        self.hint
    }

    /// Forgets the explanation (any other click).
    pub fn clear_hint(&mut self) {
        self.hint = None;
    }

    /// Per option of `o`, the index of the choice that is checked: the chosen value, else the
    /// live value, else "Unchanged".
    pub fn checked(&self, o: &OptionsVm) -> Vec<usize> {
        o.options
            .iter()
            .map(|opt| {
                let want = self
                    .values
                    .get(&opt.key)
                    .map(String::as_str)
                    .or(opt.live.as_ref().map(|l| l.value.as_str()));
                want.and_then(|w| opt.choices.iter().position(|c| c.key == w))
                    .unwrap_or(0)
            })
            .collect()
    }

    /// The click on choice `choice` of option `option`.
    /// - A value that is not offered: nothing happens.
    /// - A value: it is chosen; the live value itself needs no choice (it is what is there).
    /// - "Unchanged" with a live value: the chosen value is dropped and the page explains
    ///   that this means undoing the change (it plans nothing); without one, the choice is
    ///   dropped.
    pub fn choose(&mut self, o: &OptionsVm, option: usize, choice: usize) {
        self.hint = None;
        let Some(opt) = o.options.get(option) else {
            return;
        };
        let Some(c) = opt.choices.get(choice) else {
            return;
        };
        if c.is_unchanged() {
            self.values.remove(&opt.key);
            if opt.live.is_some() {
                self.hint = Some(option);
            }
        } else if c.enabled {
            if opt.live.as_ref().is_some_and(|l| l.value == c.key) {
                self.values.remove(&opt.key);
            } else {
                self.values.insert(opt.key.clone(), c.key.clone());
            }
        }
    }

    /// Keeps what is still offered on a new page of the same game (after a write or a refresh);
    /// drops the rest.
    pub fn keep(&mut self, o: &OptionsVm) {
        self.values.retain(|k, v| {
            o.options.iter().any(|opt| {
                opt.key == *k
                    && opt
                        .choices
                        .iter()
                        .any(|c| c.key == *v && c.enabled && !c.is_unchanged())
                    && opt.live.as_ref().is_none_or(|l| l.value != *v)
            })
        });
        if self
            .hint
            .is_some_and(|i| o.options.get(i).is_none_or(|x| x.live.is_none()))
        {
            self.hint = None;
        }
    }

    /// The choices to plan, in the order of the page's options.
    pub fn to_plan(&self, o: &OptionsVm) -> Vec<Choice> {
        o.options
            .iter()
            .filter_map(|opt| {
                self.values.get(&opt.key).map(|v| Choice {
                    option: opt.key.clone(),
                    value: v.clone(),
                })
            })
            .collect()
    }
}

// ---------- the parts of the launch profile ----------

/// One part of the launch profile in the preview, with where it comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartVm {
    /// What the part is.
    pub label: String,
    /// The program or the arguments (escaped, its own element).
    pub detail: Option<Shown<'static>>,
    /// Where it comes from, in Rerun's words.
    pub from: String,
    /// The fix or option it comes from (an ID of the signed index, its own element).
    pub from_name: Option<Shown<'static>>,
}

/// The launch profile part by part, and what every fallback of the starter does (ADR 0022 D3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartsVm {
    /// The heading.
    pub heading: String,
    /// The parts the plan sets, with their origins.
    pub parts: Vec<PartVm>,
    /// "If the Rerun starter cannot use the profile ... it starts Steam's own command unchanged
    /// ...:" and the command's program as its own element.
    pub fallback: TextLine,
}

fn from_of(f: &PartFrom, lang: Lang) -> (String, Option<Shown<'static>>) {
    match f {
        PartFrom::Fix(p) => (
            tx(lang, Msg::PvFromFix),
            Some(escape::text(&p.variant).into_owned()),
        ),
        PartFrom::Option(c) => (
            tx(lang, Msg::PvFromOption),
            Some(escape::text(&format!("{} = {}", c.option, c.value)).into_owned()),
        ),
        PartFrom::Kept(txn) => (tx(lang, Msg::PvFromKept { n: txn.seq() }), None),
    }
}

/// The parts of the plan's launch profile (`flow::Planned::parts`), each with its origin.
pub fn parts_vm(p: &LaunchParts, lang: Lang) -> PartsVm {
    let mut parts = Vec::new();
    if let Some(f) = &p.rule {
        let (from, from_name) = from_of(f, lang);
        parts.push(PartVm {
            label: tx(lang, Msg::PvPartRule),
            detail: None,
            from,
            from_name,
        });
    }
    if let Some((exe, f)) = &p.run {
        let (from, from_name) = from_of(f, lang);
        parts.push(PartVm {
            label: tx(lang, Msg::PvPartRun),
            detail: Some(escape::path(exe.as_str()).into_owned()),
            from,
            from_name,
        });
    }
    if let Some((args, f)) = &p.args {
        let (from, from_name) = from_of(f, lang);
        parts.push(PartVm {
            label: tx(lang, Msg::PvPartArgs),
            // The arguments hold only `- + _ . =`, letters and digits (`LaunchArg`).
            detail: Some(escape::text(&args.join(" ")).into_owned()),
            from,
            from_name,
        });
    }
    PartsVm {
        heading: tx(lang, Msg::PvPartsHeading),
        parts,
        fallback: TextLine::named(
            format!(
                "{} ",
                tx(
                    lang,
                    Msg::PvFallback {
                        run: p.run.is_some(),
                        rule: p.rule.is_some(),
                        args: p.args.is_some(),
                    }
                )
            ),
            escape::path(p.start.as_str()).into_owned(),
            "",
        ),
    }
}
