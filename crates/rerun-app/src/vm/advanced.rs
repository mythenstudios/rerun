//! The "Advanced" section of the game page (ADR 0029, plan P5-OE "UI"): the user's own CPU rule,
//! launch method, priority and compatibility flags, collapsed at the foot of the page, below the
//! fixes and above the shared preview. Pure: typed `flow` values and a [`Lang`] in, plain structs
//! with every string localized out. Nothing here changes a system; the form is turned into one
//! [`Manual`] that joins the picks and the option values in one `flow::Selection`, one preview
//! and one Apply (rule 5), and the engine checks it again.
//!
//! The rules of the section, all from the core's data:
//! - the form's own check is [`Manual::check`] (what Rerun refuses is said inline before any
//!   plan: a method alone, a rule that limits nothing); the launcher case is the core's
//!   `prim::allowed`; the live readout of what the rule selects on this PC is the core's
//!   `flow::rule_view`, asked of the worker and shown as it answers (nothing is computed here);
//! - the live own settings (`AdvancedView::live`) fill the form: the launch part is shown and may
//!   be replaced (the preview warns), live flags are shown checked and cannot be unchecked (they
//!   are taken back by undoing their change);
//! - the launch part is exclusive with a chosen fix that sets a CPU rule, the flags with a chosen
//!   fix that sets flags for the same program, and both are locked with the reason while the
//!   anti-cheat rule applies; a locked part stays as it is in the form, is not part of the plan
//!   and comes back when the fix is unticked;
//! - what the launcher case or a kept `run` forbids (a soft rule, a priority, the method
//!   `watch`) is disabled with the reason, and dropped from the form when it becomes forbidden.

use std::collections::BTreeSet;

use rerun_core::escape::{self, Shown};
use rerun_core::flow::{AdvancedStart, AdvancedView, Bitness};
use rerun_core::journal::TxnId;
use rerun_core::path::RelPath;
use rerun_core::plan::{Manual, ManualError, ManualLaunch, ManualMethod};
use rerun_core::policy::registry::TokenName;
use rerun_core::prim::{
    CpuRuleSpec, ExcludeFirstSpec, MachineView, MachineWhy, ModeSpec, PreferL3Spec, PreferSpec,
    PrioritySpec, allowed,
};

use super::write::TextLine;
use crate::text::{Lang, Msg, t};

fn tx(lang: Lang, m: Msg) -> String {
    t(lang, m).into_owned()
}

/// The Advanced section of a game page: what the core said (`None`: no matched Topo, no section)
/// and the language its words are in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdvancedVm {
    /// The core's view of the section.
    pub view: Option<AdvancedView>,
    /// The page's language.
    pub lang: Lang,
}

impl Default for AdvancedVm {
    fn default() -> Self {
        Self {
            view: None,
            lang: Lang::En,
        }
    }
}

// ---------- the form ----------

/// The fields of the form, by what a click on them means (the window sends a number pair, see
/// [`Field::from_ui`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Field {
    /// The thread limit one step down.
    ThreadsLess,
    /// The thread limit one step up (the last step is no limit).
    ThreadsMore,
    /// SMT on or off.
    Smt(bool),
    /// One cache group on or off.
    SingleL3(bool),
    /// Which cores to prefer: 0 any, 1 performance.
    Prefer(usize),
    /// What to leave out first: 0 nothing, 1 CPU 0, 2 core 0.
    Exclude(usize),
    /// 0 hard, 1 soft.
    Mode(usize),
    /// 0 like the Topo, 1 direct, 2 watch.
    Method(usize),
    /// 0 unchanged, 1 normal, 2 above normal, 3 high.
    Priority(usize),
    /// The flag at this position of the allowlist, flipped.
    Flag(usize),
    /// The program Steam starts, at this position of the choices.
    Start(usize),
}

impl Field {
    /// A callback of the window: `field` and `value` as `ui/advanced.slint` documents them.
    pub fn from_ui(field: i32, value: i32) -> Option<Self> {
        let i = usize::try_from(value).ok();
        Some(match field {
            0 => Self::ThreadsLess,
            1 => Self::ThreadsMore,
            2 => Self::Smt(value != 0),
            3 => Self::SingleL3(value != 0),
            4 => Self::Prefer(i?),
            5 => Self::Exclude(i?),
            6 => Self::Mode(i?),
            7 => Self::Method(i?),
            8 => Self::Priority(i?),
            9 => Self::Flag(i?),
            10 => Self::Start(i?),
            _ => return None,
        })
    }
}

/// What the selected fixes mean for the section: the first selected fix that sets a CPU rule, and
/// the first one that sets flags for the page's main program (their variant IDs).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FixSel {
    /// A selected fix sets the CPU rule.
    pub cpu: Option<String>,
    /// A selected fix sets compatibility flags for the main program.
    pub layer: Option<String>,
}

/// Why a part of the form cannot be set now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LockWhy {
    /// A chosen fix sets the CPU rule (its ID).
    CpuFix(String),
    /// A chosen fix sets flags for the same program (its ID).
    LayerFix(String),
    /// The anti-cheat rule applies.
    AntiCheat,
    /// Steam starts a launcher: a soft rule and a priority would reach only it.
    Launcher,
    /// A live option value starts another program: `watch` does not work with it.
    Run,
    /// The Topo's launch method has no own launch settings.
    Unavailable,
}

/// The locks of the form (module docs), from the core's pure rules.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Locks {
    /// The whole launch part (CPU rule, method, priority).
    pub launch: Option<LockWhy>,
    /// The compatibility flags.
    pub flags: Option<LockWhy>,
    /// The method `watch`.
    pub watch: Option<LockWhy>,
    /// The soft mode.
    pub soft: Option<LockWhy>,
    /// A priority.
    pub priority: Option<LockWhy>,
}

/// What the user typed into the section, and what they changed from what is live (module docs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Form {
    /// The user changed a field since the form was filled from the live state.
    touched: bool,
    max_threads: Option<u16>,
    smt: bool,
    single_l3: bool,
    prefer_perf: bool,
    /// Carried from a live rule (the form has no control for it).
    prefer_l3: Option<PreferL3Spec>,
    exclude: Option<ExcludeFirstSpec>,
    soft: bool,
    method: Option<ManualMethod>,
    priority: Option<PrioritySpec>,
    start: Option<RelPath>,
    /// Flags chosen now (a flag that is live is not in here).
    flags: BTreeSet<String>,
}

impl Default for Form {
    fn default() -> Self {
        Self {
            touched: false,
            max_threads: None,
            smt: true,
            single_l3: false,
            prefer_perf: false,
            prefer_l3: None,
            exclude: None,
            soft: false,
            method: None,
            priority: None,
            start: None,
            flags: BTreeSet::new(),
        }
    }
}

/// What the form asks the worker to plan: the own settings, or what is wrong with them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Input {
    /// The settings to plan (`None`: nothing to plan, or a problem).
    pub manual: Option<Manual>,
    /// What Rerun refuses about the form, said inline before any plan.
    pub problem: Option<Problem>,
    /// The form was cleared although a launch part is live: that means undoing its change.
    pub clearing: Option<TxnId>,
}

/// A problem of the form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Problem {
    /// A launch part without a rule or a priority.
    NoRule,
    /// The CPU rule limits nothing.
    NoRestriction,
    /// The program Steam starts is not chosen.
    NeedsStart,
    /// Another refusal of the form's check (the core's text).
    Other(String),
}

impl Form {
    /// The form filled from what is live (a new page of the game).
    pub fn prefilled(a: &AdvancedVm) -> Self {
        let Some(v) = &a.view else {
            return Self::default();
        };
        let mut f = Self::default();
        let Some(live) = &v.live else {
            return f;
        };
        if let Some(l) = &live.manual.launch {
            f.method = l.method;
            f.priority = l.priority;
            f.start = l.start.clone();
            if let Some(c) = &l.cpu {
                f.max_threads = c.max_threads;
                f.smt = c.smt.unwrap_or(true);
                f.single_l3 = c.single_l3.unwrap_or(false);
                f.prefer_perf = c.prefer == Some(PreferSpec::Performance);
                f.prefer_l3 = c.prefer_l3;
                f.exclude = c.exclude_first;
                f.soft = c.mode == Some(ModeSpec::Soft);
            }
        }
        f
    }

    /// Keeps what the user typed on a new page of the same game (after a refresh); a form nobody
    /// touched shows what is live now (after a write: the new live state).
    pub fn keep(&mut self, a: &AdvancedVm) {
        let Some(v) = &a.view else {
            *self = Self::default();
            return;
        };
        if !self.touched {
            *self = Self::prefilled(a);
            return;
        }
        if let AdvancedStart::Choose(list) = &v.start {
            if self.start.as_ref().is_some_and(|s| !list.contains(s)) {
                self.start = None;
            }
        } else {
            self.start = None;
        }
        let live: Vec<&str> = v
            .live
            .iter()
            .flat_map(|l| l.flags.iter().map(|(t, _)| t.as_str()))
            .collect();
        self.flags
            .retain(|f| v.tokens.contains(&f.as_str()) && !live.contains(&f.as_str()));
    }

    /// The CPU rule the fields describe (`None`: no field limits anything or is set).
    pub fn cpu(&self) -> Option<CpuRuleSpec> {
        let set = self.max_threads.is_some()
            || !self.smt
            || self.single_l3
            || self.prefer_perf
            || self.prefer_l3.is_some()
            || self.exclude.is_some()
            || self.soft;
        set.then(|| CpuRuleSpec {
            max_threads: self.max_threads,
            prefer: self.prefer_perf.then_some(PreferSpec::Performance),
            single_l3: self.single_l3.then_some(true),
            prefer_l3: self.prefer_l3,
            smt: (!self.smt).then_some(false),
            mode: self.soft.then_some(ModeSpec::Soft),
            exclude_first: self.exclude,
            report_cores: None,
        })
    }

    fn launch_part(&self, v: &AdvancedView) -> Option<ManualLaunch> {
        let cpu = self.cpu();
        if cpu.is_none() && self.priority.is_none() && self.method.is_none() {
            return None;
        }
        Some(ManualLaunch {
            method: self.method,
            start: match v.start {
                AdvancedStart::Choose(_) => self.start.clone(),
                _ => None,
            },
            cpu,
            priority: self.priority,
        })
    }

    fn method_now(&self, v: &AdvancedView) -> ManualMethod {
        self.method.unwrap_or(v.default_method)
    }

    /// The locks (module docs) for `fixes` selected.
    pub fn locks(&self, v: &AdvancedView, fixes: &FixSel) -> Locks {
        let mut l = Locks::default();
        if matches!(v.start, AdvancedStart::Unavailable(_)) {
            l.launch = Some(LockWhy::Unavailable);
        } else if let Some(f) = &fixes.cpu {
            l.launch = Some(LockWhy::CpuFix(f.clone()));
        }
        if v.anti_cheat {
            l.flags = Some(LockWhy::AntiCheat);
            l.watch = Some(LockWhy::AntiCheat);
        } else if let Some(f) = &fixes.layer {
            l.flags = Some(LockWhy::LayerFix(f.clone()));
        }
        if l.watch.is_none() && v.kept_run {
            l.watch = Some(LockWhy::Run);
        }
        let start_known = !matches!(v.start, AdvancedStart::Choose(_)) || self.start.is_some();
        if start_known {
            let ok = allowed(
                self.method_now(v),
                v.started_is_main(self.start.as_ref()),
                v.kept_run,
            );
            if !ok.soft {
                l.soft = Some(LockWhy::Launcher);
            }
            if !ok.priority {
                l.priority = Some(LockWhy::Launcher);
            }
        }
        l
    }

    /// Drops what has become forbidden: the method `watch` under a lock, a soft rule or a priority
    /// the launcher case no longer allows.
    fn normalize(&mut self, v: &AdvancedView, fixes: &FixSel) {
        let l = self.locks(v, fixes);
        if l.watch.is_some() && self.method == Some(ManualMethod::Watch) {
            self.method = None;
        }
        let l = self.locks(v, fixes);
        if l.soft.is_some() {
            self.soft = false;
        }
        if l.priority.is_some() {
            self.priority = None;
        }
    }

    /// The click on `field`: nothing when the field is locked or does not exist.
    pub fn edit(&mut self, a: &AdvancedVm, fixes: &FixSel, field: Field) {
        let Some(v) = &a.view else {
            return;
        };
        let l = self.locks(v, fixes);
        let launch_free = l.launch.is_none();
        let live_flags = |t: &str| {
            v.live
                .as_ref()
                .is_some_and(|x| x.flags.iter().any(|(f, _)| f.as_str() == t))
        };
        let before = self.clone();
        match field {
            Field::ThreadsLess if launch_free => {
                self.max_threads = match self.max_threads {
                    None => v.steps.last().copied(),
                    Some(n) => v.steps.iter().rev().find(|s| **s < n).copied().or(Some(n)),
                };
            }
            Field::ThreadsMore if launch_free => {
                self.max_threads = self
                    .max_threads
                    .and_then(|n| v.steps.iter().find(|s| **s > n).copied());
            }
            Field::Smt(on) if launch_free => self.smt = on,
            Field::SingleL3(on) if launch_free => self.single_l3 = on,
            Field::Prefer(i) if launch_free && (v.hybrid || self.prefer_perf) => {
                self.prefer_perf = i == 1;
            }
            Field::Exclude(i) if launch_free && i < 3 => {
                self.exclude = match i {
                    1 => Some(ExcludeFirstSpec::Thread),
                    2 => Some(ExcludeFirstSpec::Core),
                    _ => None,
                };
            }
            Field::Mode(i) if launch_free && (i == 0 || l.soft.is_none()) && i < 2 => {
                self.soft = i == 1;
            }
            Field::Method(i) if launch_free && i < 3 && (i != 2 || l.watch.is_none()) => {
                self.method = match i {
                    1 => Some(ManualMethod::Direct),
                    2 => Some(ManualMethod::Watch),
                    _ => None,
                };
            }
            Field::Priority(i) if launch_free && i < 4 && (i == 0 || l.priority.is_none()) => {
                self.priority = match i {
                    1 => Some(PrioritySpec::Normal),
                    2 => Some(PrioritySpec::AboveNormal),
                    3 => Some(PrioritySpec::High),
                    _ => None,
                };
            }
            Field::Flag(i) if l.flags.is_none() => {
                if let Some(tok) = v.tokens.get(i).copied()
                    && !live_flags(tok)
                    && !self.flags.remove(tok)
                {
                    self.flags.insert(tok.to_owned());
                }
            }
            Field::Start(i) if launch_free => {
                if let AdvancedStart::Choose(list) = &v.start {
                    self.start = list.get(i).cloned();
                }
            }
            _ => {}
        }
        self.normalize(v, fixes);
        if *self != before {
            self.touched = true;
        }
    }

    /// The settings to plan, or what stands in the way (module docs): the launch part only when
    /// it differs from what is live and is not locked, the flags that are not live yet and not
    /// locked.
    pub fn input(&self, a: &AdvancedVm, fixes: &FixSel) -> Input {
        let none = Input {
            manual: None,
            problem: None,
            clearing: None,
        };
        let Some(v) = &a.view else {
            return none;
        };
        let l = self.locks(v, fixes);
        let live_launch = Self::prefilled(a).launch_part(v);
        let now = self.launch_part(v);
        let launch = if l.launch.is_none() && now != live_launch {
            now.clone()
        } else {
            None
        };
        let clearing = (l.launch.is_none() && now.is_none())
            .then(|| v.live.as_ref().and_then(|x| x.launch_txn))
            .flatten();
        let layers: Vec<TokenName> = if l.flags.is_none() {
            v.tokens
                .iter()
                .filter(|t| self.flags.contains(**t))
                .filter_map(|t| TokenName::parse(t).ok())
                .collect()
        } else {
            Vec::new()
        };
        if launch.is_none() && layers.is_empty() {
            return Input { clearing, ..none };
        }
        let m = Manual {
            launch,
            layers,
            exe: None,
        };
        match m.check() {
            Ok(())
                if matches!(v.start, AdvancedStart::Choose(_))
                    && m.launch.is_some()
                    && self.start.is_none() =>
            {
                Input {
                    problem: Some(Problem::NeedsStart),
                    ..none
                }
            }
            Ok(()) => Input {
                manual: Some(m),
                ..none
            },
            Err(e) => Input {
                problem: Some(match e {
                    ManualError::NoRule => Problem::NoRule,
                    ManualError::NoRestriction => Problem::NoRestriction,
                    other => Problem::Other(other.to_string()),
                }),
                ..none
            },
        }
    }

    /// What the live readout asks the worker: the rule and the program's bitness (`None`: no
    /// rule to show, or the launch part is locked).
    pub fn readout_rule(&self, a: &AdvancedVm, fixes: &FixSel) -> Option<(CpuRuleSpec, Bitness)> {
        let v = a.view.as_ref()?;
        if self.locks(v, fixes).launch.is_some() {
            return None;
        }
        self.cpu().map(|c| (c, v.bitness))
    }
}

/// Whether the worker takes `m` with `picks` on page `g`: the locks of the section hold in the
/// worker too, whatever a caller sends (the core checks the plan again).
pub fn manual_offered(g: &super::GameVm, picks: &[rerun_core::plan::Pick], m: &Manual) -> bool {
    let Some(v) = &g.advanced.view else {
        return false;
    };
    let picked = || {
        g.fixes
            .iter()
            .filter(|f| picks.iter().any(|p| p.variant == f.key))
    };
    if m.exe.is_some() || m.check().is_err() {
        return false;
    }
    if let Some(l) = &m.launch {
        let watch = l.method == Some(ManualMethod::Watch);
        if matches!(v.start, AdvancedStart::Unavailable(_))
            || picked().any(|f| f.sets_rule)
            || (watch && (v.anti_cheat || v.kept_run))
        {
            return false;
        }
    }
    if !m.layers.is_empty()
        && (v.anti_cheat
            || picked().any(|f| f.layer_exes.iter().any(|e| v.is_main(e)))
            || m.layers.iter().any(|t| !v.tokens.contains(&t.as_str())))
    {
        return false;
    }
    true
}

// ---------- the section as it is drawn ----------

/// One choice of a group of the section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChoiceRender {
    /// The accessible name, "<group>: <value>".
    pub name: String,
    /// What the button says (a path of the game is escaped).
    pub label: Shown<'static>,
    /// It is the checked one.
    pub checked: bool,
    /// It can be chosen.
    pub enabled: bool,
}

/// A group of radio-style choices.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupRender {
    /// The group's name (a radio group for a screen reader).
    pub label: String,
    /// The choices.
    pub choices: Vec<ChoiceRender>,
    /// Why the group cannot be set, or what to know.
    pub note: Option<TextLine>,
}

/// A switch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwitchRender {
    /// The accessible name and the label.
    pub label: String,
    /// What it does (the accessible description).
    pub desc: String,
    /// It is on.
    pub checked: bool,
    /// It can be switched.
    pub enabled: bool,
    /// Why it cannot (or that it is live).
    pub note: Option<TextLine>,
}

/// The thread limit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThreadsRender {
    /// The accessible name of the group.
    pub label: String,
    /// "No limit" or "8 threads".
    pub value: String,
    /// The names of the two buttons.
    pub less: String,
    /// The more button's name.
    pub more: String,
    /// The buttons can be used.
    pub less_on: bool,
    /// The more button can be used.
    pub more_on: bool,
}

/// The whole section as it is drawn now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdvancedRender {
    /// The section is shown (a matched Topo).
    pub available: bool,
    /// The accessible name of the button that opens it.
    pub name: String,
    /// The heading.
    pub title: String,
    /// What the section is.
    pub intro: String,
    /// "Active: own rule (change No. 5)".
    pub active: Option<String>,
    /// The Topo's launch has no own launch settings.
    pub unavailable: Option<String>,
    /// The CPU rule's heading.
    pub cpu_heading: String,
    /// Why the whole launch part is locked.
    pub launch_note: Option<TextLine>,
    /// The thread limit.
    pub threads: ThreadsRender,
    /// SMT.
    pub smt: SwitchRender,
    /// One cache group.
    pub l3: SwitchRender,
    /// Prefer performance cores: only on a PC that has them.
    pub prefer: Option<GroupRender>,
    /// What to leave out first.
    pub exclude: GroupRender,
    /// Hard or soft.
    pub mode: GroupRender,
    /// The launch method.
    pub method: GroupRender,
    /// The priority.
    pub priority: GroupRender,
    /// The heading of the flags.
    pub flags_label: String,
    /// The flags.
    pub flags: Vec<SwitchRender>,
    /// Why the flags are locked.
    pub flags_note: Option<TextLine>,
    /// The program Steam starts (a Topo that names none).
    pub start: Option<GroupRender>,
    /// Why the program is asked.
    pub start_desc: String,
    /// What is wrong with the form.
    pub problem: Option<TextLine>,
    /// The own rule replaces the rule of a live change.
    pub replaces: Option<String>,
    /// The form was cleared although a launch part is live: what that means, with the button.
    pub undo_hint: Option<(String, String, TxnId)>,
    /// The readout's heading.
    pub read_title: String,
}

fn lock_note(why: &LockWhy, lang: Lang) -> TextLine {
    match why {
        LockWhy::CpuFix(id) => TextLine::named(
            format!("{} ", tx(lang, Msg::AdvLockCpuFix)),
            escape::text(id).into_owned(),
            "",
        ),
        LockWhy::LayerFix(id) => TextLine::named(
            format!("{} ", tx(lang, Msg::AdvLockLayerFix)),
            escape::text(id).into_owned(),
            "",
        ),
        LockWhy::AntiCheat => TextLine::text(tx(lang, Msg::AdvLockAntiCheat)),
        LockWhy::Launcher => TextLine::text(tx(lang, Msg::AdvLockLauncher)),
        LockWhy::Run => TextLine::text(tx(lang, Msg::AdvLockRun)),
        LockWhy::Unavailable => TextLine::text(tx(lang, Msg::AdvUnavailable)),
    }
}

fn group(
    lang: Lang,
    label: Msg,
    items: Vec<(String, bool, bool)>,
    note: Option<TextLine>,
) -> GroupRender {
    let label = tx(lang, label);
    GroupRender {
        choices: items
            .into_iter()
            .map(|(value, checked, enabled)| ChoiceRender {
                name: format!("{label}: {value}"),
                label: escape::text(&value).into_owned(),
                checked,
                enabled,
            })
            .collect(),
        label,
        note,
    }
}

/// The label and the description of a compatibility flag; a token this version has no words for
/// shows as itself (escaped).
fn flag_words(token: &str, lang: Lang) -> (String, String) {
    match token {
        "DISABLEDXMAXIMIZEDWINDOWEDMODE" => (tx(lang, Msg::AdvFlagFso), token.to_owned()),
        "HIGHDPIAWARE" => (tx(lang, Msg::AdvFlagDpi), token.to_owned()),
        other => (
            escape::text(other).to_string(),
            escape::text(other).to_string(),
        ),
    }
}

impl AdvancedVm {
    /// The section as it is drawn for `form` with `fixes` selected.
    pub fn render(&self, form: &Form, fixes: &FixSel) -> AdvancedRender {
        let lang = self.lang;
        let Some(v) = &self.view else {
            return AdvancedRender::empty(lang);
        };
        let l = form.locks(v, fixes);
        let launch_free = l.launch.is_none();
        let input = form.input(self, fixes);
        let live_flag = |t: &str| {
            v.live
                .as_ref()
                .and_then(|x| x.flags.iter().find(|(f, _)| f.as_str() == t))
                .map(|(_, txn)| *txn)
        };
        let threads = {
            let less_on = launch_free
                && match form.max_threads {
                    None => !v.steps.is_empty(),
                    Some(n) => v.steps.iter().any(|s| *s < n),
                };
            ThreadsRender {
                label: tx(lang, Msg::AdvThreads),
                value: match form.max_threads {
                    None => tx(lang, Msg::AdvThreadsNone),
                    Some(n) => tx(lang, Msg::AdvThreadsValue { n: u32::from(n) }),
                },
                less: tx(lang, Msg::AdvThreadsLess),
                more: tx(lang, Msg::AdvThreadsMore),
                less_on,
                more_on: launch_free && form.max_threads.is_some(),
            }
        };
        let switch = |label: Msg, desc: Msg, checked: bool| SwitchRender {
            label: tx(lang, label),
            desc: tx(lang, desc),
            checked,
            enabled: launch_free,
            note: None,
        };
        let prefer = (v.hybrid || form.prefer_perf).then(|| {
            group(
                lang,
                Msg::AdvPrefer,
                vec![
                    (tx(lang, Msg::AdvPreferAny), !form.prefer_perf, launch_free),
                    (tx(lang, Msg::AdvPreferPerf), form.prefer_perf, launch_free),
                ],
                None,
            )
        });
        let exclude = group(
            lang,
            Msg::AdvExclude,
            vec![
                (
                    tx(lang, Msg::AdvExcludeNone),
                    form.exclude.is_none(),
                    launch_free,
                ),
                (
                    tx(lang, Msg::AdvExcludeThread),
                    form.exclude == Some(ExcludeFirstSpec::Thread),
                    launch_free,
                ),
                (
                    tx(lang, Msg::AdvExcludeCore),
                    form.exclude == Some(ExcludeFirstSpec::Core),
                    launch_free,
                ),
            ],
            None,
        );
        let mode = group(
            lang,
            Msg::AdvMode,
            vec![
                (tx(lang, Msg::AdvModeHard), !form.soft, launch_free),
                (
                    tx(lang, Msg::AdvModeSoft),
                    form.soft,
                    launch_free && l.soft.is_none(),
                ),
            ],
            l.soft
                .as_ref()
                .filter(|_| launch_free)
                .map(|w| lock_note(w, lang)),
        );
        let method = group(
            lang,
            Msg::AdvMethod,
            vec![
                (
                    tx(
                        lang,
                        Msg::AdvMethodTopo {
                            watch: v.default_method == ManualMethod::Watch,
                        },
                    ),
                    form.method.is_none(),
                    launch_free,
                ),
                (
                    tx(lang, Msg::AdvMethodDirect),
                    form.method == Some(ManualMethod::Direct),
                    launch_free,
                ),
                (
                    tx(lang, Msg::AdvMethodWatch),
                    form.method == Some(ManualMethod::Watch),
                    launch_free && l.watch.is_none(),
                ),
            ],
            l.watch
                .as_ref()
                .filter(|_| launch_free)
                .map(|w| lock_note(w, lang)),
        );
        let prio = |p: Option<PrioritySpec>| form.priority == p;
        let priority = group(
            lang,
            Msg::AdvPriority,
            vec![
                (tx(lang, Msg::AdvPrioNone), prio(None), launch_free),
                (
                    tx(lang, Msg::AdvPrioNormal),
                    prio(Some(PrioritySpec::Normal)),
                    launch_free && l.priority.is_none(),
                ),
                (
                    tx(lang, Msg::AdvPrioAbove),
                    prio(Some(PrioritySpec::AboveNormal)),
                    launch_free && l.priority.is_none(),
                ),
                (
                    tx(lang, Msg::AdvPrioHigh),
                    prio(Some(PrioritySpec::High)),
                    launch_free && l.priority.is_none(),
                ),
            ],
            l.priority
                .as_ref()
                .filter(|_| launch_free)
                .map(|w| lock_note(w, lang)),
        );
        let flags = v
            .tokens
            .iter()
            .map(|tok| {
                let (label, desc) = flag_words(tok, lang);
                let live = live_flag(tok);
                SwitchRender {
                    label,
                    desc,
                    checked: live.is_some() || form.flags.contains(*tok),
                    enabled: l.flags.is_none() && live.is_none(),
                    note: live
                        .map(|txn| TextLine::text(tx(lang, Msg::AdvFlagActive { n: txn.seq() }))),
                }
            })
            .collect();
        let start = match &v.start {
            AdvancedStart::Choose(list) => Some(group(
                lang,
                Msg::AdvStart,
                list.iter()
                    .map(|p| {
                        // The path is the untrusted part: its own element, never in a sentence.
                        (
                            escape::path(p.as_str()).to_string(),
                            form.start.as_ref() == Some(p),
                            launch_free,
                        )
                    })
                    .collect(),
                None,
            )),
            _ => None,
        };
        AdvancedRender {
            available: true,
            name: tx(lang, Msg::AdvName),
            title: tx(lang, Msg::AdvTitle),
            intro: tx(lang, Msg::AdvIntro),
            active: v.live.as_ref().map(|x| {
                tx(
                    lang,
                    Msg::AdvActive {
                        n: x.launch_txn.unwrap_or(x.txn).seq(),
                    },
                )
            }),
            unavailable: matches!(v.start, AdvancedStart::Unavailable(_))
                .then(|| tx(lang, Msg::AdvUnavailable)),
            cpu_heading: tx(lang, Msg::AdvCpuHeading),
            launch_note: l
                .launch
                .as_ref()
                .filter(|w| **w != LockWhy::Unavailable)
                .map(|w| lock_note(w, lang)),
            threads,
            smt: switch(Msg::AdvSmt, Msg::AdvSmtDesc, form.smt),
            l3: switch(Msg::AdvL3, Msg::AdvL3Desc, form.single_l3),
            prefer,
            exclude,
            mode,
            method,
            priority,
            flags_label: tx(lang, Msg::AdvFlags),
            flags,
            flags_note: l.flags.as_ref().map(|w| lock_note(w, lang)),
            start,
            start_desc: tx(lang, Msg::AdvStartDesc),
            problem: input.problem.as_ref().map(|p| problem_line(p, lang)),
            replaces: input
                .manual
                .as_ref()
                .filter(|m| m.launch.is_some())
                .and(v.rule_txn)
                .map(|txn| tx(lang, Msg::AdvReplaces { n: txn.seq() })),
            undo_hint: input.clearing.map(|txn| {
                (
                    tx(lang, Msg::AdvUndoHint { n: txn.seq() }),
                    tx(lang, Msg::OptUndoBtn { n: txn.seq() }),
                    txn,
                )
            }),
            read_title: tx(lang, Msg::AdvReadTitle),
        }
    }

    /// The first thing the readout says when no rule is asked of the worker: nothing limited, or
    /// the launch part is a chosen fix's.
    pub fn readout_local(&self, form: &Form, fixes: &FixSel) -> Option<ReadoutVm> {
        let v = self.view.as_ref()?;
        let l = form.locks(v, fixes);
        let m = if l.launch.is_some() {
            Msg::AdvReadLocked
        } else if form.cpu().is_none() {
            Msg::AdvReadNoRule
        } else {
            return None;
        };
        Some(ReadoutVm {
            line: tx(self.lang, m),
            detail: None,
            note: None,
        })
    }
}

fn problem_line(p: &Problem, lang: Lang) -> TextLine {
    match p {
        Problem::NoRule => TextLine::text(tx(lang, Msg::AdvErrNoRule)),
        Problem::NoRestriction => TextLine::text(tx(lang, Msg::AdvErrNoRestriction)),
        Problem::NeedsStart => TextLine::text(tx(lang, Msg::AdvNeedsStart)),
        Problem::Other(s) => TextLine::named(
            format!("{} ", tx(lang, Msg::AdvErrOther)),
            escape::text(s).into_owned(),
            "",
        ),
    }
}

impl AdvancedRender {
    fn empty(lang: Lang) -> Self {
        let g = |label: Msg| GroupRender {
            label: tx(lang, label),
            choices: Vec::new(),
            note: None,
        };
        let sw = |label: Msg| SwitchRender {
            label: tx(lang, label),
            desc: String::new(),
            checked: false,
            enabled: false,
            note: None,
        };
        Self {
            available: false,
            name: tx(lang, Msg::AdvName),
            title: tx(lang, Msg::AdvTitle),
            intro: String::new(),
            active: None,
            unavailable: None,
            cpu_heading: String::new(),
            launch_note: None,
            threads: ThreadsRender {
                label: tx(lang, Msg::AdvThreads),
                value: String::new(),
                less: String::new(),
                more: String::new(),
                less_on: false,
                more_on: false,
            },
            smt: sw(Msg::AdvSmt),
            l3: sw(Msg::AdvL3),
            prefer: None,
            exclude: g(Msg::AdvExclude),
            mode: g(Msg::AdvMode),
            method: g(Msg::AdvMethod),
            priority: g(Msg::AdvPriority),
            flags_label: String::new(),
            flags: Vec::new(),
            flags_note: None,
            start: None,
            start_desc: String::new(),
            problem: None,
            replaces: None,
            undo_hint: None,
            read_title: String::new(),
        }
    }
}

// ---------- the live readout ----------

/// What the rule selects on this PC, in words (the core's `MachineView`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadoutVm {
    /// "8 of 32 logical processors: cache group 0 (L3, 32 MB), cores 0-7, without SMT".
    pub line: String,
    /// The core's reason (escaped), when the processors cannot be read.
    pub detail: Option<Shown<'static>>,
    /// A 32-bit program on a large group, the processor group of a PC with several.
    pub note: Option<String>,
}

/// The core numbers as ranges: `0, 1, 2, 3, 8` as "0\u{2013}3, 8".
fn ranges(cores: &[u32]) -> String {
    let mut out: Vec<String> = Vec::new();
    let mut i = 0;
    while i < cores.len() {
        let mut j = i;
        while j + 1 < cores.len() && cores[j + 1] == cores[j] + 1 {
            j += 1;
        }
        out.push(if j > i + 1 {
            format!("{}\u{2013}{}", cores[i], cores[j])
        } else if j == i + 1 {
            format!("{}, {}", cores[i], cores[j])
        } else {
            cores[i].to_string()
        });
        i = j + 1;
    }
    out.join(", ")
}

/// The core's selection as a sentence (module docs).
pub fn readout(v: &MachineView, lang: Lang) -> ReadoutVm {
    match &v.selection {
        Ok(s) => {
            let mut parts = Vec::new();
            if let Some((n, level, bytes)) = s.llc {
                parts.push(tx(
                    lang,
                    Msg::AdvReadCache {
                        n,
                        level: u32::from(level),
                        mb: bytes >> 20,
                    },
                ));
            }
            parts.push(format!(
                "{} {}",
                tx(
                    lang,
                    Msg::AdvReadCores {
                        one: s.cores.len() == 1
                    }
                ),
                ranges(&s.cores)
            ));
            parts.push(tx(
                lang,
                Msg::AdvReadSmt {
                    on: usize::from(s.threads) > s.cores.len(),
                },
            ));
            if v.groups > 1 {
                parts.push(tx(
                    lang,
                    Msg::AdvReadGroup {
                        n: u32::from(s.group),
                    },
                ));
            }
            let head = tx(
                lang,
                Msg::AdvReadSel {
                    threads: u32::from(s.threads),
                    of: u32::from(s.of),
                },
            );
            ReadoutVm {
                line: format!("{head}: {}", parts.join(", ")),
                detail: None,
                note: v.x86_capped.then(|| tx(lang, Msg::AdvReadCap)),
            }
        }
        Err(MachineWhy::NoRule) => ReadoutVm {
            line: tx(lang, Msg::AdvReadNoRule),
            detail: None,
            note: None,
        },
        Err(MachineWhy::Empty { .. }) => ReadoutVm {
            line: tx(lang, Msg::AdvReadEmpty),
            detail: None,
            note: None,
        },
        Err(MachineWhy::Topology(why)) => ReadoutVm {
            line: tx(lang, Msg::AdvReadTopology),
            detail: Some(escape::text(why).into_owned()),
            note: None,
        },
    }
}

// ---------- own settings as facts ----------

/// The own settings of a change as a card shows them: a heading and one line per part.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnVm {
    /// "Your own settings (Advanced, not checked)".
    pub title: String,
    /// "up to 8 threads, SMT off, priority above normal", "2 compatibility flags".
    pub lines: Vec<String>,
}

/// The own settings the head of a change recorded (`Plan::manual`), for its card and its history
/// entry; `None` for a change without any.
pub fn own_settings(m: Option<&Manual>, lang: Lang) -> Option<OwnVm> {
    let lines = manual_lines(m?, lang);
    (!lines.is_empty()).then(|| OwnVm {
        title: tx(lang, Msg::AdvSumTitle),
        lines,
    })
}

/// The own settings of a transaction in words, one entry per part (History cards, the card on the
/// game page): "up to 8 threads, SMT off", "priority above normal", "2 compatibility flags".
/// Rerun's words and numbers only.
pub fn manual_lines(m: &Manual, lang: Lang) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(l) = &m.launch {
        let mut p = Vec::new();
        if let Some(c) = &l.cpu {
            if let Some(n) = c.max_threads {
                p.push(tx(lang, Msg::AdvSumThreads { n: u32::from(n) }));
            }
            if c.smt == Some(false) {
                p.push(tx(lang, Msg::AdvSumNoSmt));
            }
            if c.single_l3 == Some(true) {
                p.push(tx(lang, Msg::AdvSumL3));
            }
            if c.prefer == Some(PreferSpec::Performance) {
                p.push(tx(lang, Msg::AdvSumPerf));
            }
            if let Some(e) = c.exclude_first {
                p.push(tx(
                    lang,
                    Msg::AdvSumExclude {
                        core: e == ExcludeFirstSpec::Core,
                    },
                ));
            }
            if c.mode == Some(ModeSpec::Soft) {
                p.push(tx(lang, Msg::AdvSumSoft));
            }
        }
        if let Some(pr) = l.priority {
            let word = match pr {
                PrioritySpec::Normal => Msg::AdvPrioNormal,
                PrioritySpec::AboveNormal => Msg::AdvPrioAbove,
                PrioritySpec::High => Msg::AdvPrioHigh,
            };
            p.push(format!(
                "{} {}",
                tx(lang, Msg::AdvSumPriority),
                tx(lang, word).to_lowercase()
            ));
        }
        if let Some(me) = l.method {
            p.push(tx(
                lang,
                Msg::AdvSumMethod {
                    watch: me == ManualMethod::Watch,
                },
            ));
        }
        if !p.is_empty() {
            out.push(p.join(", "));
        }
    }
    if !m.layers.is_empty() {
        out.push(tx(
            lang,
            Msg::AdvSumFlags {
                n: u32::try_from(m.layers.len()).unwrap_or(u32::MAX),
            },
        ));
    }
    out
}
