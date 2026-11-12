//! View models of the write side (P5-5a, ADR 0027 amendment P5-5a): the fix selection, the
//! preview of a plan, the applied cards, the undo and forget dialogs, and the results and
//! refusals as calm notices. Pure: typed `flow` values and a [`Lang`] in, plain structs with
//! every string localized out. Untrusted text (paths, keys, Topo texts, the core's error texts)
//! stays [`Shown`] and is drawn in its own element.
//!
//! Rule 5: [`preview_vm`] shows every file, registry value, INI key, launch profile and
//! firewall rule of the plan, what undo does with each, the warnings and the launch option the
//! user pastes; [`revert_vm`] and [`forget_vm`] show what the operation meets before the click.
//!
//! The elevated helper (P5-5c, ADR 0023 amendment P5-5c): [`HelperState`] says whether a run
//! that needs it could start it now; the preview and the undo dialog name the UAC prompt Windows
//! will show ([`admin_lines`]), [`uac_wait`] is the modal while the worker waits for it, and the
//! results name the transaction's state after a declined prompt or an unconfirmed helper.

use std::collections::{BTreeSet, HashMap};
use std::path::PathBuf;

use rerun_core::catalog::model::{SourceType, VariantStatus};
use rerun_core::elevate::{PromptKind, PromptState};
use rerun_core::escape::{self, Shown};
use rerun_core::exec::{
    self, ApplyError, ExecError, HelperFailure, Outcome, Refusal, TxnLine, TxnStatus,
};
use rerun_core::flow::{
    self, ActError, ForgetPreview, LaunchOption, LaunchView, OptionText, PlanRefusal, Planned,
    ProfileFate, RevertAsk, RevertEnd, RevertGate, RevertOutcome, RevertPreview, RevertWould,
    StoreRefusal,
};
use rerun_core::hw::SacState;
use rerun_core::journal::{Observed, TxnId};
use rerun_core::plan::Pick;
use rerun_core::plan::{self, IniOldShown, PreviewOp, ProfilePreview, RegShown, RootKind};
use rerun_core::policy::root::Shadow;
use rerun_core::prim::MachineWhy;
use rerun_core::topo::{Tri, Warning};

use super::{Badge, DetailVm, FixVm, GameVm, Notice, Offer, Value, shown_error};
use crate::text::{Lang, Msg, Sym, t};

/// The names of the games the library listed (escaped), for the cards.
pub type Names = HashMap<u32, Shown<'static>>;

fn tx(lang: Lang, m: Msg) -> String {
    t(lang, m).into_owned()
}

// ---------- the selection ----------

/// The fixes the user selected on a game page, by variant ID (module docs of `vm`).
///
/// The rules, pure and tested without a window:
/// - only a fix that can be applied here is selectable ([`Offer::Selectable`]);
/// - the preselection is every selectable fix that is `verified` for a problem that affects
///   this PC, no two of them in conflict;
/// - fixes that solve a problem in common (a problem has alternatives, never two at once) are
///   mutually exclusive: selecting one deselects the others;
/// - a fix that solves several problems is selected once and picked for the one problem it is
///   attributed to ([`FixVm::pick_issue`]).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Selection {
    ids: BTreeSet<String>,
}

impl Selection {
    /// The preselection of `g`: `verified` fixes for a problem that affects this PC, nothing
    /// else (user decision of plan P5 §2.4).
    pub fn preselected(g: &GameVm) -> Self {
        let mut ids = BTreeSet::new();
        let mut chosen: Vec<usize> = Vec::new();
        for (i, f) in g.fixes.iter().enumerate() {
            if f.preselect && f.conflicts.iter().all(|c| !chosen.contains(c)) {
                chosen.push(i);
                ids.insert(f.key.clone());
            }
        }
        Self { ids }
    }

    /// Whether the fix with variant ID `key` is selected.
    pub fn contains(&self, key: &str) -> bool {
        self.ids.contains(key)
    }

    /// Toggles fix `i` of `g`: a fix that cannot be applied here is left alone; selecting one
    /// deselects the fixes it is exclusive with.
    pub fn toggle(&mut self, g: &GameVm, i: usize) {
        let Some(f) = g.fixes.get(i) else {
            return;
        };
        if f.offer != Offer::Selectable {
            return;
        }
        if self.ids.remove(&f.key) {
            return;
        }
        for c in &f.conflicts {
            if let Some(other) = g.fixes.get(*c) {
                self.ids.remove(&other.key);
            }
        }
        self.ids.insert(f.key.clone());
    }

    /// Keeps what is still selectable on a new page of the same game (after a write or a
    /// refresh); drops the rest.
    pub fn keep(&mut self, g: &GameVm) {
        self.ids.retain(|k| {
            g.fixes
                .iter()
                .any(|f| f.key == *k && f.offer == Offer::Selectable)
        });
    }

    /// Per fix of `g`, whether it is selected.
    pub fn flags(&self, g: &GameVm) -> Vec<bool> {
        g.fixes.iter().map(|f| self.ids.contains(&f.key)).collect()
    }

    /// The picks to plan: each selected fix once, for the problem it is attributed to.
    pub fn picks(&self, g: &GameVm) -> Vec<Pick> {
        g.fixes
            .iter()
            .filter(|f| self.ids.contains(&f.key))
            .map(|f| Pick {
                issue: f.pick_issue.clone(),
                variant: f.key.clone(),
            })
            .collect()
    }
}

/// The attribution, the conflicts and the preselection of `fixes` (called once by the page
/// builder, [`super::game`]).
pub(super) fn link(fixes: &mut [FixVm]) {
    // The problem a fix is picked for: one that affects this PC, else one that may, else the
    // first it solves (the engine takes a problem once).
    for f in fixes.iter_mut() {
        let rank = |w: Tri| match w {
            Tri::Yes => 0,
            Tri::Unknown => 1,
            Tri::No => 2,
        };
        f.pick_issue = f
            .issues
            .iter()
            .min_by_key(|(_, w)| rank(*w))
            .map(|(i, _)| i.clone())
            .unwrap_or_default();
    }
    // Two fixes are exclusive if they share a problem that is not "does not affect this PC", or
    // are picked for the same one.
    let n = fixes.len();
    let conflicts: Vec<Vec<usize>> = (0..n)
        .map(|i| {
            (0..n)
                .filter(|j| {
                    *j != i
                        && (fixes[i].pick_issue == fixes[*j].pick_issue
                            || fixes[i].issues.iter().any(|(a, w)| {
                                *w != Tri::No && fixes[*j].issues.iter().any(|(b, _)| a == b)
                            }))
                })
                .collect()
        })
        .collect();
    for (i, c) in conflicts.into_iter().enumerate() {
        fixes[i].exclusive = c.iter().map(|j| fixes[*j].id.clone()).collect();
        fixes[i].conflicts = c;
    }
    // A fix that needs the elevated helper is never preselected: an administrator change is the
    // user's own choice (P5-5c).
    for f in fixes.iter_mut() {
        f.preselect = f.offer == Offer::Selectable && f.solves_verified_here && !f.needs_helper;
    }
}

// ---------- the elevated helper (P5-5c) ----------

/// Whether a run that needs the elevated helper could start it now (`flow::helper`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HelperState {
    /// It is installed safely and Windows allows an elevation: the prompt the user will meet.
    Ready(PromptState),
    /// Not installed, not admin-only, or a test-key helper for a release build.
    Missing,
    /// Windows grants no elevation (`Denied`, `UacOff`; or this process is elevated).
    NoElevation,
}

/// The [`HelperState`] of `flow::helper`'s answer.
pub fn helper_state(r: &Result<PromptState, Refusal>) -> HelperState {
    match r {
        Ok(s) => HelperState::Ready(*s),
        Err(Refusal::NoElevation(_) | Refusal::Elevated) => HelperState::NoElevation,
        Err(_) => HelperState::Missing,
    }
}

/// What the preview says about administrator rights for a prompt state, and the notes under it:
/// which dialog Windows shows, whether it is on the secure desktop, whether only signed programs
/// are elevated (ADR 0023 §10).
pub fn admin_lines(s: &PromptState, lang: Lang) -> (String, Vec<String>) {
    let mut notes = Vec::new();
    let admin = if s.has_dialog() {
        notes.push(tx(
            lang,
            if s.kind == PromptKind::Credentials {
                Msg::AdminCredentials
            } else {
                Msg::AdminConsent
            },
        ));
        if s.secure_desktop == Some(false) {
            notes.push(tx(lang, Msg::AdminNotSecure));
        }
        tx(lang, Msg::PreviewAdminYes)
    } else {
        // `NoPrompt`, and `Unknown` ("unreadable = no dialog", ADR 0023 §10).
        tx(lang, Msg::PreviewAdminNoDialog)
    };
    if s.signed_only {
        notes.push(tx(lang, Msg::AdminSignedOnly));
    }
    (admin, notes)
}

/// The modal while the worker waits for the UAC dialog (it cannot be dismissed: the window waits
/// for Windows, and the helper's run decides what happened).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UacVm {
    /// "Waiting for Windows (UAC) ...".
    pub title: String,
    /// What to do.
    pub body: String,
    /// The dialog's kind and where it appears.
    pub notes: Vec<String>,
}

/// The wait for the dialog of `s` (only shown when Windows shows one).
pub fn uac_wait(s: &PromptState, lang: Lang) -> UacVm {
    let mut notes = Vec::new();
    if s.kind == PromptKind::Credentials {
        notes.push(tx(lang, Msg::AdminCredentials));
    }
    if s.secure_desktop == Some(false) {
        notes.push(tx(lang, Msg::AdminNotSecure));
    }
    notes.push(tx(lang, Msg::UacWaitHidden));
    UacVm {
        title: tx(lang, Msg::UacWaitTitle),
        body: tx(lang, Msg::UacWaitBody),
        notes,
    }
}

/// Whether a solved problem is verified and affects this PC.
pub(super) fn verified_here(when: Tri, status: VariantStatus) -> bool {
    when == Tri::Yes && status == VariantStatus::Verified
}

/// A source for display: its type and link as one escaped text.
pub(super) fn source_text(kind: SourceType, url: &str, lang: Lang) -> Shown<'static> {
    let word = tx(
        lang,
        match kind {
            SourceType::Repo => Msg::SourceRepo,
            SourceType::SteamGuide => Msg::SourceSteamGuide,
            SourceType::SteamThread => Msg::SourceSteamThread,
            SourceType::Pcgw => Msg::SourcePcgw,
            SourceType::Official => Msg::SourceOfficial,
        },
    );
    // The type word is Rerun's own, the link is index text: the whole line goes through the
    // text rule once.
    escape::text(&format!("{word}: {url}")).into_owned()
}

// ---------- the parts of a plan ----------

/// One labelled line of an op; each value is drawn in its own element.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LineVm {
    /// The label (Rerun's text; may be empty).
    pub label: String,
    /// The values.
    pub values: Vec<Value>,
    /// Set in the monospaced font.
    pub mono: bool,
}

fn line(label: String, values: Vec<Value>) -> LineVm {
    LineVm {
        label,
        values,
        mono: true,
    }
}

/// One op of a plan or of a transaction's head, with what undo does with it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpVm {
    /// The index in the plan (the number undo names).
    pub index: usize,
    /// What it does.
    pub action: String,
    /// The path below its root, or the registry key (escaped).
    pub target: Shown<'static>,
    /// The details.
    pub lines: Vec<LineVm>,
    /// What undo does with it.
    pub undo: Option<String>,
    /// What undo would meet now (an undo dialog only).
    pub fate: Option<(Badge, String)>,
}

/// The action's word and what undo does with it.
fn action_of(action: &str) -> (Msg, Option<Msg>) {
    match action {
        "create folder" => (Msg::ActCreateFolder, Some(Msg::UndoRemoves)),
        "create file" => (Msg::ActCreateFile, Some(Msg::UndoRemoves)),
        "create key" => (Msg::ActCreateKey, Some(Msg::UndoRemoves)),
        "replace file" => (Msg::ActReplaceFile, Some(Msg::UndoRestoresFile)),
        a if a == plan::PATCH_ACTION => (Msg::ActPatchFile, Some(Msg::UndoRestoresFile)),
        "set value" => (Msg::ActSetValue, Some(Msg::UndoRestoresValue)),
        a if a == plan::GPU_PREF_ACTION => (Msg::ActGpuPref, Some(Msg::UndoRestoresValue)),
        "add tokens" => (Msg::ActAddTokens, Some(Msg::UndoRemovesTokens)),
        "edit ini" => (Msg::ActEditIni, Some(Msg::UndoSetsKeys)),
        "block in firewall" => (Msg::ActFirewall, Some(Msg::UndoRemovesRule)),
        a if a == plan::HOLD_ACTION => (Msg::ActHold, Some(Msg::UndoKeepsShared)),
        _ => (Msg::ActOther, None),
    }
}

fn content(sha: &str, len: u64, lang: Lang) -> Vec<Value> {
    vec![Value::Text(format!(
        "{sha} \u{00B7} {}",
        t(lang, Msg::Bytes { n: len })
    ))]
}

fn reg_values(v: &RegShown) -> Vec<Value> {
    let mut out = vec![Value::Text(v.kind.clone())];
    if let Some(text) = &v.text {
        out.push(Value::Shown(text.clone()));
    }
    out
}

/// One op as the preview or a head shows it.
pub fn op_vm(o: &PreviewOp, lang: Lang) -> OpVm {
    let (action, undo) = action_of(o.action);
    let mut lines: Vec<LineVm> = Vec::new();
    if let Some(name) = &o.name {
        lines.push(line(
            tx(lang, Msg::LblValue),
            vec![Value::Shown(name.clone())],
        ));
    }
    if o.profile.is_none()
        && let Some(source) = &o.source
    {
        lines.push(line(
            tx(lang, Msg::LblFrom),
            vec![Value::Shown(source.clone())],
        ));
    }
    if o.held {
        lines.push(LineVm {
            label: String::new(),
            values: vec![Value::Text(tx(lang, Msg::HeldLine))],
            mono: false,
        });
        if let Some((sha, len)) = &o.content {
            lines.push(line(tx(lang, Msg::LblNew), content(sha, *len, lang)));
        }
    } else if let Some((sha, len)) = &o.content {
        lines.push(line(tx(lang, Msg::LblNew), content(sha, *len, lang)));
    }
    if let Some((sha, len, _)) = &o.old {
        lines.push(line(tx(lang, Msg::LblOld), content(sha, *len, lang)));
    }
    for e in &o.patch {
        lines.push(line(
            tx(lang, Msg::LblPatch),
            vec![Value::Text(tx(
                lang,
                Msg::PatchByte {
                    offset: e.offset,
                    old: e.old,
                    new: e.new,
                },
            ))],
        ));
    }
    if let Some(tokens) = &o.tokens {
        lines.push(line(
            tx(lang, Msg::LblAdds),
            vec![Value::Text(tokens.clone())],
        ));
    }
    if let Some(v) = &o.old_value {
        lines.push(line(tx(lang, Msg::LblValueNow), reg_values(v)));
    }
    if let Some(v) = &o.new_value {
        lines.push(line(tx(lang, Msg::LblValueNew), reg_values(v)));
    }
    for k in &o.ini {
        lines.push(line(
            tx(lang, Msg::LblIniKey),
            vec![Value::Shown(k.section.clone()), Value::Shown(k.key.clone())],
        ));
        lines.push(line(
            tx(lang, Msg::LblValueNow),
            vec![match &k.old {
                IniOldShown::Value(v) => Value::Shown(v.clone()),
                IniOldShown::Missing => Value::Text(tx(lang, Msg::IniMissing)),
                IniOldShown::NewSection => Value::Text(tx(lang, Msg::IniNewSection)),
            }],
        ));
        lines.push(line(
            tx(lang, Msg::LblValueNew),
            vec![Value::Shown(k.new.clone())],
        ));
    }
    match &o.profile {
        Some(ProfilePreview::Decoded(s)) => {
            lines.push(line(
                tx(lang, Msg::LblProfile),
                vec![Value::Text(format!("{} \u{00B7} {}", s.method, s.bitness))],
            ));
            if let Some(w) = &s.cpu {
                // The rule in the words of docs/02: technical, the same in every language.
                lines.push(line(
                    tx(lang, Msg::LblCpuRule),
                    vec![Value::Text(w.clone())],
                ));
            }
            if let Some(class) = s.priority {
                lines.push(line(
                    tx(lang, Msg::LblPriority),
                    vec![Value::Text(class.to_owned())],
                ));
            }
            lines.push(line(
                tx(lang, Msg::LblStart),
                vec![Value::Shown(s.start.clone())],
            ));
            if s.decoded.method == rerun_core::prim::launch_method::ProfileMethod::Watch {
                lines.push(line(
                    tx(lang, Msg::LblTarget),
                    vec![Value::Shown(s.target.clone())],
                ));
            }
        }
        Some(ProfilePreview::Unreadable(why)) => lines.push(line(
            tx(lang, Msg::LblProfile),
            vec![Value::Shown(escape::text(why).into_owned())],
        )),
        None => {}
    }
    if let Some(r) = &o.firewall {
        lines.push(line(
            tx(lang, Msg::LblValue),
            vec![
                Value::Shown(r.name.clone()),
                Value::Shown(r.program.clone()),
            ],
        ));
    }
    OpVm {
        index: o.index,
        action: tx(lang, action),
        target: o.path.clone(),
        lines,
        undo: undo.map(|m| tx(lang, m)),
        fate: None,
    }
}

/// A warning: the glyph and the word, the sentence, and the detail the sentence is about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WarnVm {
    /// Glyph and word, always together.
    pub badge: Badge,
    /// The sentence.
    pub text: String,
    /// What it is about (a path or an ID, escaped).
    pub detail: Option<Shown<'static>>,
}

fn warn(lang: Lang, m: Msg, detail: Option<Shown<'static>>) -> WarnVm {
    WarnVm {
        badge: Badge {
            sym: Sym::Attention,
            word: tx(lang, Msg::WarningWord),
            quiet: false,
        },
        text: tx(lang, m),
        detail,
    }
}

fn warnings_of(p: &Planned, lang: Lang) -> Vec<WarnVm> {
    p.warnings()
        .iter()
        .filter_map(|w| warning_vm(w, lang))
        .chain(p.shadows().iter().map(|s| shadow_vm(s, lang)))
        .collect()
}

/// An engine warning as a message; `None` for one that says nothing (Smart App Control off).
pub fn warning_vm(w: &Warning, lang: Lang) -> Option<WarnVm> {
    let id = |s: &str| Some(escape::text(s).into_owned());
    let path = |s: &str| Some(escape::path(s).into_owned());
    Some(match w {
        Warning::NeedsRetest => warn(lang, Msg::WarnNeedsRetest, None),
        Warning::WhenUnknown { issue } => warn(lang, Msg::WarnWhenUnknown, id(issue)),
        Warning::AntiCheat { variant, .. } => warn(lang, Msg::WarnAntiCheat, id(variant)),
        Warning::SteamInput { issue } => warn(lang, Msg::WarnSteamInput, id(issue)),
        Warning::SmartAppControl { state } => {
            let m = match state {
                SacState::Off => return None,
                SacState::Enforce => Msg::WarnSacOn,
                SacState::Evaluation => Msg::WarnSacEvaluation,
                SacState::Unknown => Msg::WarnSacUnknown,
            };
            warn(lang, m, None)
        }
        Warning::SteamPerUserExe { exe } => warn(lang, Msg::WarnSteamPerUser, path(exe.as_str())),
        Warning::SignedExe { exe } => warn(lang, Msg::WarnSignedExe, path(exe.as_str())),
        Warning::GpuPreferenceSet { exe, .. } => warn(lang, Msg::WarnGpuSet, path(exe.as_str())),
        Warning::RequiresGpu { package, .. } => warn(lang, Msg::WarnRequiresGpu, id(package)),
    })
}

/// A VirtualStore finding as a message.
pub fn shadow_vm(s: &Shadow, lang: Lang) -> WarnVm {
    match s {
        Shadow::Copy { copy, .. } => warn(lang, Msg::WarnVsCopy, Some(copy.clone())),
        Shadow::Link { at, .. } => warn(lang, Msg::WarnVsLink, Some(at.clone())),
        Shadow::Unchecked { why, at, .. } => warn(
            lang,
            Msg::WarnVsUnchecked,
            Some(at.clone().unwrap_or_else(|| why.clone())),
        ),
    }
}
/// The notes a preview says once (the core's constants, as flags, in the app's words).
fn notes_of(p: &plan::Preview, lang: Lang) -> Vec<String> {
    let mut out = vec![tx(lang, Msg::NoteNotRestored)];

    let mut add = |on: bool, m: Msg| {
        if on {
            out.push(tx(lang, m));
        }
    };
    add(p.registry.is_some(), Msg::NoteRegistry);
    add(p.layers.is_some(), Msg::NoteLayers);
    add(p.ini.is_some(), Msg::NoteIni);
    add(
        p.profiles.is_some_and(|n| n != plan::PROFILE_WATCH_NOTE),
        Msg::NoteProfile,
    );
    add(
        p.profiles == Some(plan::PROFILE_WATCH_NOTE),
        Msg::NoteProfileWatch,
    );
    add(p.firewall.is_some(), Msg::NoteFirewall);
    add(p.held.is_some(), Msg::NoteHold);
    add(p.patched.is_some(), Msg::NotePatch);
    add(p.gpu_pref.is_some(), Msg::NoteGpuPref);
    add(p.user_data.is_some(), Msg::NoteUserData);
    out
}

/// The Steam launch option a plan with a launch profile brings (P3-3d): what it does on this PC
/// and the text the user pastes into Steam.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchVm {
    /// The heading.
    pub heading: String,
    /// What the profile does on this PC.
    pub lines: Vec<String>,
    /// The launch option to paste (escaped); `None`: why not is in `problems`.
    pub option: Option<Shown<'static>>,
    /// Said above the option.
    pub intro: String,
    /// Said under it.
    pub notes: Vec<String>,
    /// Why the option cannot be offered, or would not work.
    pub problems: Vec<WarnVm>,
    /// The copy button's label.
    pub copy: String,
    /// What the copy button says afterwards.
    pub copied: String,
}

fn launch_vm(v: &LaunchView, lang: Lang) -> LaunchVm {
    let mut lines = Vec::new();
    match &v.machine.selection {
        Ok(s) => lines.push(tx(
            lang,
            Msg::LaunchCpu {
                threads: s.threads,
                of: s.of,
            },
        )),
        Err(MachineWhy::NoRule) => lines.push(tx(lang, Msg::LaunchCpuNone)),
        Err(_) => lines.push(tx(lang, Msg::LaunchCpuUnknown)),
    }
    let mut problems = Vec::new();
    let option = match &v.option {
        OptionText::Shown(o) => Some(o.clone()),
        OptionText::InstallUnknown => {
            problems.push(warn(lang, Msg::LaunchInstallUnknown, None));
            None
        }
        OptionText::NotShowable => {
            problems.push(warn(lang, Msg::LaunchNotShowable, None));
            None
        }
    };
    match &v.shim {
        Some((path, Ok(false))) => {
            problems.push(warn(lang, Msg::LaunchShimMissing, Some(path.clone())))
        }
        Some((_, Err(why))) => {
            problems.push(warn(lang, Msg::LaunchShimUnchecked, Some(why.clone())))
        }
        Some((_, Ok(true))) | None => {}
    }
    LaunchVm {
        heading: tx(lang, Msg::LaunchHeading),
        lines,
        option,
        intro: tx(lang, Msg::LaunchOptionIntro),
        notes: vec![
            tx(lang, Msg::LaunchOptionCombine),
            tx(lang, Msg::LaunchOptionByHand),
            tx(lang, Msg::LaunchShimStays),
        ],
        problems,
        copy: tx(lang, Msg::LaunchCopy),
        copied: tx(lang, Msg::LaunchCopied),
    }
}

// ---------- the preview ----------

/// The preview of a plan (rule 5): everything Rerun would change, before anything is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreviewVm {
    /// The plan hash (hex): the "Apply" button carries it, the core checks it again.
    pub hash: String,
    /// "N changes".
    pub summary: String,
    /// The game folder (escaped).
    pub folder: Option<Shown<'static>>,
    /// The ops, in order.
    pub ops: Vec<OpVm>,
    /// The warnings.
    pub warnings: Vec<WarnVm>,
    /// The notes of the plan.
    pub notes: Vec<String>,
    /// The launch option, if the plan writes a launch profile.
    pub launch: Option<LaunchVm>,
    /// "Administrator rights: not needed", or that Windows asks (P5-5c).
    pub admin: String,
    /// What Windows asks when the helper starts: the dialog, where it appears.
    pub admin_notes: Vec<String>,
    /// What undo does with the plan as a whole.
    pub undo: String,
    /// There is something to apply.
    pub can_apply: bool,
    /// Said instead of the ops when the plan changes nothing.
    pub nothing: Option<String>,
}

/// The preview of `p` (the plan's own decode of its bytes) with the launch view of this PC.
/// `prompt`: the UAC prompt state when the plan has firewall rules and the helper is ready
/// (`flow::helper`); a plan with rules and no prompt state cannot be applied.
pub fn preview_vm(
    p: &Planned,
    launch: Option<&LaunchView>,
    prompt: Option<&PromptState>,
    lang: Lang,
) -> PreviewVm {
    let pv = p.preview();
    let n = pv.ops.len();
    let helper = pv.firewall.is_some();
    let (admin, admin_notes) = match (helper, prompt) {
        (false, _) => (tx(lang, Msg::PreviewAdminNo), Vec::new()),
        (true, Some(s)) => admin_lines(s, lang),
        (true, None) => (
            tx(lang, Msg::PreviewAdminYes),
            vec![tx(lang, Msg::FixNeedsHelper)],
        ),
    };
    PreviewVm {
        hash: p.hash().to_string(),
        summary: tx(lang, Msg::PreviewChanges { n }),
        folder: pv
            .roots
            .iter()
            .find(|r| r.kind == RootKind::Game)
            .map(|r| r.path.clone()),
        ops: pv.ops.iter().map(|o| op_vm(o, lang)).collect(),
        warnings: warnings_of(p, lang),
        notes: notes_of(pv, lang),
        launch: launch.map(|v| launch_vm(v, lang)),
        admin,
        admin_notes,
        undo: tx(
            lang,
            Msg::PreviewUndo {
                profile: flow::profile_of(pv).is_some(),
            },
        ),
        can_apply: n > 0 && (!helper || prompt.is_some()),
        nothing: (n == 0).then(|| tx(lang, Msg::ResNothingBody)),
    }
}

// ---------- notices: refusals and results ----------

/// How a result is drawn: nothing is an error in the app's sense; a refusal that only asks the
/// user to look again is calm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tone {
    /// It worked.
    Done,
    /// Nothing happened, or look again: no warning glyph.
    Calm,
    /// Needs the user's attention.
    Attention,
}

/// The outcome of a job that may have written: a notice and what the window refreshes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResultVm {
    /// How it is drawn.
    pub tone: Tone,
    /// The words.
    pub notice: Notice,
    /// The page the job was about is read again (the game changed, or a write happened).
    pub refresh: bool,
}

fn result(tone: Tone, lang: Lang, title: Msg, body: Msg, refresh: bool) -> ResultVm {
    ResultVm {
        tone,
        notice: Notice {
            title: tx(lang, title),
            body: tx(lang, body),
            details: Vec::new(),
        },
        refresh,
    }
}

fn with_detail(mut r: ResultVm, detail: Shown<'static>) -> ResultVm {
    r.notice.details.push(DetailVm::of(detail));
    r
}

/// The typed refusals the user meets often, as calm messages with what to do; every other
/// refusal is the generic message with the core's English text as the detail (ADR 0027).
pub fn refusal(r: &Refusal, lang: Lang) -> ResultVm {
    use Msg::*;
    let txn = |t: &TxnId| DetailVm::of(escape::text(&t.to_string()).into_owned());
    let calm = |tone, a, b, refresh| result(tone, lang, a, b, refresh);
    let mut out = match r {
        Refusal::Busy(_) | Refusal::Unchecked(_) => {
            calm(Tone::Attention, RefBusyTitle, RefBusyBody, false)
        }
        Refusal::JournalBusy => calm(Tone::Calm, RefJournalBusyTitle, RefJournalBusyBody, false),
        Refusal::Blocked { .. } => calm(Tone::Attention, RefBlockedTitle, RefBlockedBody, false),
        Refusal::Interrupted { .. }
        | Refusal::Later { .. }
        | Refusal::Held { .. }
        | Refusal::HeldChange { .. } => calm(Tone::Attention, RefOrderTitle, RefOrderBody, false),
        Refusal::SlotTaken { .. } => calm(Tone::Attention, RefSlotTitle, RefSlotBody, false),
        Refusal::CleanupPending { .. } => {
            calm(Tone::Attention, RefCleanupTitle, RefCleanupBody, false)
        }
        Refusal::Steam { .. } | Refusal::SteamGone { .. } | Refusal::SteamManifest { .. } => {
            calm(Tone::Calm, RefSteamTitle, RefSteamBody, false)
        }
        // The game or the state changed since the preview (ADR 0020 amendment P5-2a): not an
        // error, the page is read again.
        Refusal::GameChanged(_)
        | Refusal::Mismatch { .. }
        | Refusal::MainExe(_)
        | Refusal::Changed { .. } => calm(Tone::Calm, RefStaleTitle, RefStaleBody, true),
        Refusal::NeedsHelper => calm(Tone::Attention, RefAdminTitle, RefAdminBody, false),
        // The helper (P5-5c), each before any prompt: not installed safely, no elevation here,
        // a helper of an earlier run still busy. Rules that no longer match the signed Topo
        // mean the game changed: the page is read again.
        Refusal::HelperUnsafe(_) => calm(Tone::Attention, RefHelperTitle, RefHelperBody, false),
        Refusal::NoElevation(_) => calm(
            Tone::Attention,
            RefNoElevationTitle,
            RefNoElevationBody,
            false,
        ),
        Refusal::Helper(HelperFailure::Busy(_)) => calm(
            Tone::Attention,
            RefHelperBusyTitle,
            RefHelperBusyBody,
            false,
        ),
        Refusal::HelperPlan(_) => calm(Tone::Calm, RefStaleTitle, RefStaleBody, true),
        Refusal::Forgotten { .. } => calm(Tone::Calm, RefNothingTitle, RefNothingBody, true),
        _ => calm(
            Tone::Attention,
            RefUnexpectedTitle,
            RefUnexpectedBody,
            false,
        ),
    };
    match r {
        Refusal::Interrupted { txn: x }
        | Refusal::Later { txn: x }
        | Refusal::Held { txn: x }
        | Refusal::HeldChange { txn: x }
        | Refusal::Blocked { txn: x }
        | Refusal::SlotTaken { txn: x, .. }
        | Refusal::CleanupPending { txn: x } => out.notice.details.push(txn(x)),
        _ => out.notice.details.push(DetailVm::of(shown_error(r))),
    }
    out
}

/// Why a plan was not made.
pub fn plan_refusal(e: &PlanRefusal, lang: Lang) -> ResultVm {
    with_detail(
        result(
            Tone::Attention,
            lang,
            Msg::RefPlanTitle,
            Msg::RefPlanBody,
            false,
        ),
        shown_error(e),
    )
}

/// The page could not be read for planning (the index, the game folder, the engine).
pub fn game_refusal(e: &flow::GameRefusal, lang: Lang) -> ResultVm {
    use flow::{GameOpen, GameRefusal};
    match e {
        GameRefusal::Index(e) => with_detail(plan_failed(lang), shown_error(e)),
        GameRefusal::Engine(e) => with_detail(plan_failed(lang), shown_error(e)),
        GameRefusal::Game(GameOpen::Folder(e)) => with_detail(plan_failed(lang), shown_error(e)),
        // Steam is updating the game, or it is gone: the page says so; nothing to plan.
        GameRefusal::Game(GameOpen::Steam { .. }) => result(
            Tone::Calm,
            lang,
            Msg::RefSteamTitle,
            Msg::RefSteamBody,
            true,
        ),
    }
}

fn plan_failed(lang: Lang) -> ResultVm {
    result(
        Tone::Attention,
        lang,
        Msg::RefPlanTitle,
        Msg::RefPlanBody,
        true,
    )
}

/// What an undo leaves for the user to do in Steam: the launch option to remove by hand (X12).
pub fn add_launch_option(
    r: &mut ResultVm,
    l: &LaunchOption,
    install: &Result<PathBuf, String>,
    lang: Lang,
) {
    if l.fate == ProfileFate::PreviousBack {
        return;
    }
    if let OptionText::Shown(o) = flow::option_text(install, l.id) {
        r.notice.body = format!("{} {}", r.notice.body, t(lang, Msg::LaunchOptionByHand));
        r.notice.details.push(DetailVm::of(o));
    }
}

/// The Topo no longer matches or the fixes changed since the page was read.
pub fn stale(lang: Lang) -> ResultVm {
    result(
        Tone::Calm,
        lang,
        Msg::RefStaleTitle,
        Msg::RefStaleBody,
        true,
    )
}

/// A pick the app cannot apply here (a download not agreed to, a helper that cannot run, a
/// refused fix): nothing is planned.
pub fn not_available(lang: Lang) -> ResultVm {
    result(
        Tone::Calm,
        lang,
        Msg::RefUnavailableTitle,
        Msg::RefUnavailableBody,
        false,
    )
}

/// An apply without the preview the click names.
pub fn no_preview(lang: Lang) -> ResultVm {
    result(
        Tone::Calm,
        lang,
        Msg::RefNoPreviewTitle,
        Msg::RefNoPreviewBody,
        false,
    )
}

/// Why a plan was not stored.
pub fn store_refusal(e: &StoreRefusal, lang: Lang) -> ResultVm {
    match e {
        // Rerun's folder is another one than the plan was made with: plan again.
        StoreRefusal::AppDirMoved => stale(lang),
        StoreRefusal::AppDir(e) => with_detail(unexpected(lang), shown_error(e)),
        StoreRefusal::Store(e) => with_detail(unexpected(lang), shown_error(e)),
        StoreRefusal::Empty | StoreRefusal::NoAppDir => unexpected(lang),
    }
}

fn unexpected(lang: Lang) -> ResultVm {
    result(
        Tone::Attention,
        lang,
        Msg::RefUnexpectedTitle,
        Msg::RefUnexpectedBody,
        false,
    )
}

/// The closing of the window while a write runs.
pub fn closing_blocked(lang: Lang) -> ResultVm {
    result(
        Tone::Attention,
        lang,
        Msg::ResClosingTitle,
        Msg::ResClosingBody,
        false,
    )
}

/// The outcome of `check` + `apply`.
pub fn apply_result(r: Result<Outcome, ApplyError>, lang: Lang) -> ResultVm {
    match r {
        Ok(Outcome::Nothing) => result(
            Tone::Calm,
            lang,
            Msg::ResNothingTitle,
            Msg::ResNothingBody,
            true,
        ),
        Ok(Outcome::Applied(t)) => with_detail(
            result(
                Tone::Done,
                lang,
                Msg::ResAppliedTitle,
                Msg::ResAppliedBody,
                true,
            ),
            escape::text(&t.to_string()).into_owned(),
        ),
        Err(ApplyError::Refused(r)) => refusal(&r, lang),
        // Closed, nothing different now: a declined UAC prompt (P5-5c), a helper that refused
        // or did not start, or any other failure the rollback undid.
        Err(ApplyError::RolledBack { txn, cause, .. }) => {
            let (title, body) = match &*cause {
                ExecError::Helper(HelperFailure::Declined) => {
                    (Msg::ResDeclinedTitle, Msg::ResDeclinedBody)
                }
                ExecError::Helper(_) => (Msg::ResHelperNotDoneTitle, Msg::ResHelperNotDoneBody),
                _ => (Msg::ResRolledBackTitle, Msg::ResRolledBackBody),
            };
            let mut r = with_detail(
                result(Tone::Calm, lang, title, body, true),
                shown_error(&*cause),
            );
            r.notice.details.push(txn_detail(&txn));
            r
        }
        // Open: each state in its own words (ADR 0023 §9), with the transaction to look for.
        Err(ApplyError::CleanupPending { txn, cause, .. }) => {
            open_result(Msg::ResCleanupOpenBody, &txn, &[&*cause], lang)
        }
        Err(ApplyError::HelperOpen { txn, cause }) => {
            open_result(Msg::ResHelperOpenBody, &txn, &[&*cause], lang)
        }
        Err(ApplyError::LeftOpen {
            txn,
            cause,
            rollback,
        }) => open_result(Msg::ResOpenBody, &txn, &[&*cause, &*rollback], lang),
        Err(e) => with_detail(
            result(
                Tone::Attention,
                lang,
                Msg::RefUnexpectedTitle,
                Msg::RefUnexpectedBody,
                true,
            ),
            shown_error(&e),
        ),
    }
}

fn txn_detail(t: &TxnId) -> DetailVm {
    DetailVm::of(escape::text(&t.to_string()).into_owned())
}

/// An apply that left its transaction open: the state's words, the causes, the transaction.
fn open_result(body: Msg, txn: &TxnId, causes: &[&ExecError], lang: Lang) -> ResultVm {
    let mut r = result(Tone::Attention, lang, Msg::ResOpenTitle, body, true);
    for c in causes {
        r.notice.details.push(DetailVm::of(shown_error(*c)));
    }
    r.notice.details.push(txn_detail(txn));
    r
}

fn exec_error(e: &ExecError, lang: Lang) -> ResultVm {
    match e {
        ExecError::Refused(r) => refusal(r, lang),
        ExecError::Foreign { .. } => with_detail(
            result(
                Tone::Attention,
                lang,
                Msg::ResForeignTitle,
                Msg::ResForeignBody,
                true,
            ),
            shown_error(e),
        ),
        ExecError::Unconfirmed(_) => with_detail(
            result(
                Tone::Attention,
                lang,
                Msg::ResUnconfirmedTitle,
                Msg::ResUnconfirmedBody,
                true,
            ),
            shown_error(e),
        ),
        e => with_detail(
            result(
                Tone::Attention,
                lang,
                Msg::RefUnexpectedTitle,
                Msg::RefUnexpectedBody,
                true,
            ),
            shown_error(e),
        ),
    }
}

/// An undo, a rebind or a forget that did not go through. `Changed` is not an error: the
/// caller shows the preview again with [`Msg::ChangedNote`].
pub fn act_error(e: &ActError, lang: Lang) -> ResultVm {
    match e {
        ActError::Changed => result(
            Tone::Calm,
            lang,
            Msg::ResChangedTitle,
            Msg::ChangedNote,
            true,
        ),
        ActError::Exec(e) => exec_error(e, lang),
    }
}

/// How an undo ended. An undo that stopped at the helper (a declined UAC prompt, a helper that
/// did not finish) says so; nothing below it was undone (ADR 0023 §9: the batch first).
pub fn revert_result(o: &RevertOutcome, lang: Lang) -> ResultVm {
    let helper_halt = o
        .report
        .halted
        .as_ref()
        .filter(|h| matches!(*h.why, Refusal::Helper(_)));
    if let Some(h) = helper_halt {
        let declined = matches!(*h.why, Refusal::Helper(HelperFailure::Declined));
        let r = if declined {
            result(
                Tone::Calm,
                lang,
                Msg::ResUndoDeclinedTitle,
                Msg::ResUndoDeclinedBody,
                true,
            )
        } else {
            result(
                Tone::Attention,
                lang,
                Msg::ResHaltedTitle,
                Msg::ResHaltedBody,
                true,
            )
        };
        let mut r = with_detail(r, shown_error(&*h.why));
        r.notice.details.push(txn_detail(&o.report.txn));
        return r;
    }
    let (tone, a, b) = match o.end {
        RevertEnd::Closed => (Tone::Done, Msg::ResRevertedTitle, Msg::ResRevertedBody),
        RevertEnd::Halted => (Tone::Attention, Msg::ResHaltedTitle, Msg::ResHaltedBody),
        RevertEnd::InUse(_) => (Tone::Attention, Msg::ResInUseTitle, Msg::ResInUseBody),
        RevertEnd::Kept => (Tone::Attention, Msg::ResKeptTitle, Msg::ResKeptBody),
        RevertEnd::Foreign => (Tone::Attention, Msg::ResForeignTitle, Msg::ResForeignBody),
    };
    result(tone, lang, a, b, true)
}

/// A forget that went through.
pub fn forget_result(lang: Lang) -> ResultVm {
    result(
        Tone::Done,
        lang,
        Msg::ResForgottenTitle,
        Msg::ResForgottenBody,
        true,
    )
}

/// Why a preview of an undo or a forget is not offered.
pub fn gate(g: &RevertGate, lang: Lang) -> ResultVm {
    match g {
        RevertGate::NoAppDir
        | RevertGate::NotFound(_)
        | RevertGate::Forgotten
        | RevertGate::Closed(_)
        | RevertGate::Empty => result(
            Tone::Calm,
            lang,
            Msg::RefNothingTitle,
            Msg::RefNothingBody,
            true,
        ),
        RevertGate::Blocked => result(
            Tone::Attention,
            lang,
            Msg::RefBlockedTitle,
            Msg::RefBlockedBody,
            true,
        ),
        RevertGate::Refused(r) => refusal(r, lang),
        RevertGate::Journal(e) => with_detail(
            result(
                Tone::Attention,
                lang,
                Msg::RefUnexpectedTitle,
                Msg::RefUnexpectedBody,
                false,
            ),
            shown_error(e),
        ),
        RevertGate::Failed(e) => exec_error(e, lang),
    }
}

// ---------- applied cards ----------

/// One transaction of the journal as a card (user decision U1: the card lists everything in
/// it and says before the click that undo takes all of it back together).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxnCardVm {
    /// The transaction (for the jobs; never drawn as text of its own).
    pub txn: TxnId,
    /// Its ID as text.
    pub id: String,
    /// The Steam app, if its head names one.
    pub app_id: Option<u32>,
    /// The game: its name (escaped) or "Steam app N".
    pub game: Option<Value>,
    /// State glyph and word.
    pub state: Badge,
    /// What is wrong, if something is.
    pub problem: Option<String>,
    /// Everything in it.
    pub ops: Vec<OpVm>,
    /// Says what undo takes back together.
    pub note: String,
    /// "Undo" is offered.
    pub can_undo: bool,
    /// "Close without undoing" is offered.
    pub can_forget: bool,
}

fn head_ops(st: &TxnStatus, lang: Lang) -> Vec<OpVm> {
    flow::head(st)
        .map(|p| p.ops.iter().map(|o| op_vm(o, lang)).collect())
        .unwrap_or_default()
}

/// Whether a transaction's head writes a launch profile.
fn st_has_profile(st: &TxnStatus) -> bool {
    flow::head(st).is_some_and(|p| flow::profile_of(p).is_some())
}

/// The Steam app a transaction's head names.
pub fn app_of(st: &TxnStatus) -> Option<u32> {
    flow::head(st)?
        .roots
        .iter()
        .find_map(|r| r.steam.as_ref().map(|(a, _)| *a))
}

/// The card of an open transaction; `None` for a settled one (closed, forgotten, empty).
pub fn card(st: &TxnStatus, names: &Names, lang: Lang) -> Option<TxnCardVm> {
    if st.is_settled() {
        return None;
    }
    let state = |sym, m| Badge {
        sym,
        word: tx(lang, m),
        quiet: false,
    };
    let foreign = flow::left_foreign(st);
    let (state, problem, can_undo) = match &st.state {
        TxnLine::Applied if foreign => (
            state(Sym::Attention, Msg::StateForeign),
            Some(Msg::ProblemForeign),
            true,
        ),
        TxnLine::Applied => (state(Sym::Applied, Msg::StateApplied), None, true),
        TxnLine::Open => (
            state(Sym::Attention, Msg::StateInterrupted),
            Some(Msg::ProblemInterrupted),
            true,
        ),
        TxnLine::CleanupPending => (
            state(Sym::Attention, Msg::StateCleanup),
            Some(Msg::ProblemCleanup),
            true,
        ),
        TxnLine::Damaged(_) => (
            state(Sym::Attention, Msg::StateDamaged),
            Some(Msg::ProblemDamaged),
            false,
        ),
        TxnLine::Unreadable(_) => (
            state(Sym::Attention, Msg::StateUnreadable),
            Some(Msg::ProblemUnreadable),
            false,
        ),
        TxnLine::Empty | TxnLine::Closed(_) => return None,
    };
    let app_id = app_of(st);
    let game = app_id.map(|a| match names.get(&a) {
        Some(n) if !n.as_str().is_empty() => Value::Shown(n.clone()),
        _ => Value::Text(tx(lang, Msg::UnnamedGame { app_id: a })),
    });
    let ops = head_ops(st, lang);
    Some(TxnCardVm {
        txn: st.id,
        id: st.id.to_string(),
        app_id,
        game,
        state,
        problem: problem.map(|m| tx(lang, m)),
        note: if ops.is_empty() {
            tx(lang, Msg::CardNoOps)
        } else {
            tx(
                lang,
                Msg::CardNote {
                    n: ops.len(),
                    profile: st_has_profile(st),
                },
            )
        },
        ops,
        can_undo,
        can_forget: true,
    })
}

/// The cards of every open transaction, oldest first.
pub fn cards(status: &exec::Status, names: &Names, lang: Lang) -> Vec<TxnCardVm> {
    status
        .txns
        .iter()
        .filter_map(|st| card(st, names, lang))
        .collect()
}

// ---------- the undo and forget dialogs ----------

/// Which dialog.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DialogKind {
    /// "Undo this change?"
    Undo,
    /// "Close this change without undoing it?"
    Forget,
}

/// What becomes of the launch profile and the option the user set in Steam (X12).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchFateVm {
    /// The heading.
    pub heading: String,
    /// The sentences.
    pub lines: Vec<String>,
    /// The launch option to remove by hand (escaped).
    pub option: Option<Shown<'static>>,
    /// Why no option is shown.
    pub problems: Vec<WarnVm>,
}

/// An undo or forget dialog: what the operation meets, before the click (rule 5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DialogVm {
    /// Which.
    pub kind: DialogKind,
    /// Identifies this dialog: a confirm carries it, the worker writes only for the dialog it
    /// last showed.
    pub nonce: u64,
    /// The transaction.
    pub txn: TxnId,
    /// The question.
    pub title: String,
    /// Under the question.
    pub intro: String,
    /// "The preview was updated ...": the state changed since the last preview.
    pub changed: Option<String>,
    /// What it meets, per op, newest first.
    pub ops: Vec<OpVm>,
    /// Notes (the game must be closed, the cleanup, where it would stop).
    pub notes: Vec<String>,
    /// The core's text where undo would stop (escaped).
    pub details: Vec<DetailVm>,
    /// The launch option after it.
    pub launch: Option<LaunchFateVm>,
    /// The confirm button.
    pub confirm: String,
    /// The confirm button works.
    pub can_confirm: bool,
    /// Why it does not.
    pub blocked: Option<String>,
}

fn fate_of(o: Option<Observed>, lang: Lang) -> (Badge, String) {
    let (sym, m, quiet) = match o {
        Some(Observed::Before) => (Sym::Open, Msg::FateBefore, true),
        Some(Observed::After) => (Sym::Applied, Msg::FateAfter, false),
        Some(Observed::Drifted) => (Sym::Unknown, Msg::FateDrifted, false),
        Some(Observed::Foreign) => (Sym::Attention, Msg::FateForeign, false),
        Some(Observed::Kept) => (Sym::NotHere, Msg::FateKept, true),
        None => (Sym::None, Msg::FateNotReached, true),
    };
    let word = tx(lang, m);
    (
        Badge {
            sym,
            word: word.clone(),
            quiet,
        },
        word,
    )
}

fn fate_ops(st: &TxnStatus, v: &exec::Verified, lang: Lang) -> Vec<OpVm> {
    let Some(head) = flow::head(st) else {
        return Vec::new();
    };
    // Newest op first, as the revert goes.
    let mut out: Vec<OpVm> = head
        .ops
        .iter()
        .map(|o| {
            let seen = v
                .ops
                .iter()
                .find(|(i, _)| usize::from(*i) == o.index)
                .map(|(_, s)| *s);
            let mut vm = op_vm(o, lang);
            vm.fate = Some(fate_of(seen, lang));
            vm
        })
        .collect();
    out.reverse();
    out
}

fn fate_launch(l: &LaunchOption, install: &Result<PathBuf, String>, lang: Lang) -> LaunchFateVm {
    let (m, until) = match l.fate {
        ProfileFate::Gone => (Msg::LaunchFateGone, true),
        ProfileFate::PreviousBack => (Msg::LaunchFatePrev, false),
        ProfileFate::Stays => (Msg::LaunchFateStays, false),
        ProfileFate::Left => (Msg::LaunchFateLeft, false),
    };
    let mut lines = vec![tx(lang, m)];
    let mut problems = Vec::new();
    let option = match flow::option_text(install, l.id) {
        OptionText::Shown(o) => Some(o),
        OptionText::InstallUnknown => {
            problems.push(warn(lang, Msg::LaunchInstallUnknown, None));
            None
        }
        OptionText::NotShowable => {
            problems.push(warn(lang, Msg::LaunchNotShowable, None));
            None
        }
    };
    if until {
        lines.push(tx(lang, Msg::LaunchUntilRemoved));
    }
    LaunchFateVm {
        heading: tx(lang, Msg::UndoAfter),
        // Left and Gone say it before the option, Prev says it without one.
        option: if l.fate == ProfileFate::PreviousBack {
            None
        } else {
            option
        },
        lines,
        problems,
    }
}

/// The undo dialog for a revert preview. `changed`: the state differs from the preview shown
/// before (the dialog opens again with a calm note). `helper`: whether the helper could run now,
/// read by the worker only when the undo needs it (`p.prompt`); without a ready helper such an
/// undo cannot be confirmed and says why.
pub fn revert_vm(
    p: &RevertPreview,
    install: &Result<PathBuf, String>,
    changed: bool,
    nonce: u64,
    helper: Option<&HelperState>,
    lang: Lang,
) -> DialogVm {
    let mut notes = vec![tx(lang, Msg::UndoCloseGame)];
    let mut details = Vec::new();
    if p.empty {
        notes.push(tx(lang, Msg::UndoEmpty));
    }
    if let RevertAsk::Cleanup(c) = p.ask {
        notes.push(tx(
            lang,
            Msg::UndoCleanup {
                n: c.n,
                in_use: c.in_use,
            },
        ));
    }
    if let Some(h) = &p.verified.halted {
        notes.push(tx(lang, Msg::UndoHalt { op: h.op }));
        details.push(DetailVm::of(shown_error(&*h.why)));
    }
    let blocked = prompt_block(p.prompt.as_ref(), helper, lang);
    if p.prompt.is_some()
        && let Some(HelperState::Ready(s)) = helper
    {
        let (admin, more) = admin_lines(s, lang);
        notes.push(admin);
        notes.extend(more);
    }
    DialogVm {
        kind: DialogKind::Undo,
        nonce,
        txn: p.status.id,
        title: tx(lang, Msg::UndoTitle),
        intro: tx(lang, Msg::UndoIntro),
        changed: changed.then(|| tx(lang, Msg::ChangedNote)),
        ops: fate_ops(&p.status, &p.verified, lang),
        notes,
        details,
        launch: p
            .launch_option
            .as_ref()
            .map(|l| fate_launch(l, install, lang)),
        confirm: tx(lang, Msg::UndoBtn),
        can_confirm: blocked.is_none(),
        blocked,
    }
}

/// Why an undo that needs the administrator prompt cannot be confirmed (`None`: it can, or it
/// needs no prompt).
fn prompt_block(
    p: Option<&PromptState>,
    helper: Option<&HelperState>,
    lang: Lang,
) -> Option<String> {
    p?;
    match helper {
        Some(HelperState::Ready(_)) => None,
        Some(HelperState::NoElevation) => Some(tx(lang, Msg::UndoNoElevation)),
        Some(HelperState::Missing) | None => Some(tx(lang, Msg::UndoPrompt)),
    }
}

/// The forget dialog for a forget preview.
pub fn forget_vm(
    p: &ForgetPreview,
    install: &Result<PathBuf, String>,
    changed: bool,
    nonce: u64,
    lang: Lang,
) -> DialogVm {
    let mut notes = Vec::new();
    if p.revert_would.is_some_and(|w| {
        matches!(
            w,
            RevertWould::BeClean | RevertWould::KeepCopy | RevertWould::CleanUp
        )
    }) {
        notes.push(tx(lang, Msg::ForgetWould));
    }
    let ops = match &p.verified {
        Some(Ok(v)) => {
            notes.push(tx(lang, Msg::ForgetNow));
            fate_ops(&p.status, v, lang)
        }
        _ => head_ops(&p.status, lang),
    };
    let details = match &p.verified {
        Some(Err(e)) => vec![DetailVm::of(shown_error(e))],
        _ => Vec::new(),
    };
    DialogVm {
        kind: DialogKind::Forget,
        nonce,
        txn: p.status.id,
        title: tx(lang, Msg::ForgetTitle),
        intro: tx(lang, Msg::ForgetIntro),
        changed: changed.then(|| tx(lang, Msg::ChangedNote)),
        ops,
        notes,
        details,
        launch: p
            .launch_option
            .as_ref()
            .map(|l| fate_launch(l, install, lang)),
        confirm: tx(lang, Msg::BtnForget),
        can_confirm: true,
        blocked: None,
    }
}
