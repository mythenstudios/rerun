//! The one renderer of a plan's preview (P2-13): `plan`, `apply`, and the roots and ops of a
//! transaction in `status`, `revert` and `forget`. Pure: a [`Preview`] in, one message per
//! line out. Every untrusted field arrives escaped from the core (`escape::Shown`) and stands
//! last on its line; an INI key's old and new value each get their own line. Registry text
//! appears only where the core put it: the preview of a stored plan (a recorded head comes
//! masked, `plan::preview_head`).

use std::path::PathBuf;

use rerun_core::escape::{self, Shown};
use rerun_core::exec::launch_result::ProfileId;
use rerun_core::plan::{Preview, PreviewOp, ProfilePreview, ProfileShown, RootKind};
use rerun_core::policy::root::{Shadow, file_present};
use rerun_core::prim::launch_method::{ProfileMethod as Method, RuleMode};
use rerun_core::prim::{MachineView, MachineWhy, SHIM, on_this_machine, steam_option_text};
use rerun_core::sys::System;

use rerun_core::elevate::{PromptKind, PromptState};

use crate::messages::{At, HelperMsg, Message, OpRef, ProfileMsg, TxnMsg, ranges};

fn m(t: TxnMsg<'_>) -> Message<'_> {
    Message::Txn(t)
}

/// What and where op `o` acts.
pub fn op_ref(o: &PreviewOp) -> OpRef<'_> {
    OpRef {
        action: o.action,
        at: match o.root {
            Some(root) => At::File {
                root,
                path: o.path.clone(),
            },
            None => At::Reg {
                key: o.path.clone(),
            },
        },
    }
}

/// The op with index `k` of `p`, as [`op_ref`].
pub fn op_at(p: Option<&Preview>, k: u16) -> Option<OpRef<'_>> {
    p.and_then(|p| p.ops.get(usize::from(k))).map(op_ref)
}

/// The roots of `p`.
pub fn roots(p: &Preview) -> Vec<Message<'_>> {
    let mut out = Vec::new();
    for r in &p.roots {
        out.push(m(TxnMsg::Root {
            index: r.index,
            path: r.path.clone(),
        }));
        if let Some((app_id, library)) = &r.steam {
            out.push(m(TxnMsg::RootSteam {
                app_id: *app_id,
                library: library.clone(),
            }));
        }
        if let Some(path) = &r.main_exe {
            out.push(m(TxnMsg::RootMainExe { path: path.clone() }));
        }
        if r.kind == RootKind::Profiles {
            out.push(Message::Profile(ProfileMsg::ProfilesRoot));
        }
    }
    out
}

/// One op with everything the preview knows about it.
pub fn op(o: &PreviewOp) -> Vec<Message<'_>> {
    let mut out = vec![m(TxnMsg::Op {
        index: o.index,
        op: op_ref(o),
    })];
    if let Some(name) = &o.name {
        out.push(m(TxnMsg::ValueName { name: name.clone() }));
    }
    if o.profile.is_some() {
        // Not a package: the plan carries the bytes (P3-3).
        out.push(Message::Profile(ProfileMsg::InlineSource));
    } else if let Some(source) = &o.source {
        out.push(m(TxnMsg::Source {
            source: source.clone(),
        }));
    }
    if let (true, Some((sha256, len))) = (o.held, &o.content) {
        out.push(m(TxnMsg::HeldContent { sha256, len: *len }));
    } else if let Some((sha256, len)) = &o.content {
        out.push(m(TxnMsg::NewContent {
            sha256,
            len: *len,
            attrs: o.attrs.as_deref(),
        }));
    }
    if let Some((sha256, len, attrs)) = &o.old {
        out.push(m(TxnMsg::OldContent {
            sha256,
            len: *len,
            attrs,
        }));
    }
    for e in &o.patch {
        out.push(m(TxnMsg::PatchByte(e)));
    }
    if let Some(t) = &o.tokens {
        out.push(m(TxnMsg::Tokens { tokens: tokens(t) }));
    }
    for (view, value) in &o.machine {
        out.push(m(TxnMsg::MachineValue { view, value }));
    }
    if let Some(v) = &o.old_value {
        out.push(m(TxnMsg::OldValue(v)));
    }
    if let Some(v) = &o.new_value {
        out.push(m(TxnMsg::NewValue(v)));
    }
    if o.type_change {
        out.push(m(TxnMsg::TypeChange));
    }
    for k in &o.ini {
        out.push(m(TxnMsg::IniKey {
            section: k.section.clone(),
            key: k.key.clone(),
        }));
        out.push(m(TxnMsg::IniOld(&k.old)));
        out.push(m(TxnMsg::IniNew {
            value: k.new.clone(),
        }));
    }
    if o.config {
        out.push(m(TxnMsg::Config));
    }
    match &o.profile {
        Some(ProfilePreview::Decoded(s)) => {
            out.push(Message::Profile(ProfileMsg::Profile {
                id: &s.id,
                method: s.method,
                bitness: s.bitness,
            }));
            if let Some(w) = &s.cpu {
                out.push(Message::Profile(ProfileMsg::Rule { words: w }));
            }
            if let Some(class) = s.priority {
                out.push(Message::Profile(ProfileMsg::Priority { class }));
            }
            out.push(Message::Profile(ProfileMsg::Start {
                path: s.start.clone(),
            }));
            if s.decoded.method == Method::Watch {
                out.push(Message::Profile(ProfileMsg::Target {
                    path: s.target.clone(),
                }));
            }
        }
        Some(ProfilePreview::Unreadable(why)) => {
            out.push(Message::Profile(ProfileMsg::Unreadable {
                why: escape::text(why),
            }));
        }
        None => {}
    }
    if let Some(r) = &o.firewall {
        out.push(Message::Helper(HelperMsg::Rule {
            direction: r.direction,
            group: r.group,
            name: r.name.clone(),
        }));
        out.push(Message::Helper(HelperMsg::Program {
            program: r.program.clone(),
        }));
    }
    out
}

/// The administrator prompt a plan with firewall rules brings on this machine (P4-2d; ADR 0023
/// §10, A4 N7): announced before the confirmation, so the user knows whether Windows asks again.
/// Nothing for a plan without them.
pub fn prompt_lines(sys: &dyn System, p: &Preview) -> Vec<Message<'static>> {
    if p.firewall.is_none() {
        return Vec::new();
    }
    let s = rerun_core::elevate::prompt::read(sys);
    prompt_lines_of(&s)
}

/// At `plan` (ADR 0023 §2): the helper's pre-check as a warning, never an error, and the prompt
/// lines; nothing for a plan without firewall rules.
pub fn helper_lines(sys: &dyn System, p: &Preview) -> Vec<Message<'static>> {
    if p.firewall.is_none() {
        return Vec::new();
    }
    let mut out = Vec::new();
    if let Err(e) = rerun_core::policy::root::helper_for_this_build(sys) {
        out.push(Message::Helper(HelperMsg::NotInstalled {
            error: escape::text(&e.to_string()).into_owned(),
        }));
    }
    out.extend(prompt_lines(sys, p));
    out
}

/// [`prompt_lines`] for a prompt state (pure).
pub fn prompt_lines_of(s: &PromptState) -> Vec<Message<'static>> {
    let mut out = Vec::new();
    if s.has_dialog() {
        out.push(Message::Helper(HelperMsg::PromptDialog {
            credentials: s.kind == PromptKind::Credentials,
        }));
        if s.secure_desktop == Some(false) {
            out.push(Message::Helper(HelperMsg::PromptNotSecure));
        }
    } else if matches!(s.kind, PromptKind::NoPrompt | PromptKind::Unknown) {
        out.push(Message::Helper(HelperMsg::NoDialog));
    }
    if s.signed_only {
        out.push(Message::Helper(HelperMsg::SignedOnly));
    }
    out
}

/// The tokens of an `add tokens` op (their grammar is `[A-Z0-9_]`; escaped all the same: the
/// preview field is a plain string).
fn tokens(t: &str) -> Shown<'_> {
    escape::text(t)
}

/// The whole preview: roots, ops, notes.
pub fn render(p: &Preview) -> Vec<Message<'_>> {
    let mut out = roots(p);
    for o in &p.ops {
        out.extend(op(o));
    }
    out.push(m(TxnMsg::Note(p.not_restored)));
    for note in [
        p.registry, p.layers, p.ini, p.profiles, p.firewall, p.held, p.patched,
    ]
    .into_iter()
    .flatten()
    {
        out.push(m(TxnMsg::Note(note)));
    }
    out
}

/// The lines of the UAC VirtualStore lookup (P3-7): after the notes of a preview, in the part of
/// `verify` that says what is on disk now.
pub fn shadow_lines(s: &[Shadow]) -> Vec<Message<'_>> {
    s.iter()
        .map(|x| {
            m(match x {
                Shadow::Copy { root, copy, .. } => TxnMsg::VirtualStoreCopy {
                    root: *root,
                    copy: copy.clone(),
                },
                Shadow::Link { root, at } => TxnMsg::VirtualStoreLink {
                    root: *root,
                    at: at.clone(),
                },
                Shadow::Unchecked { root, why, at } => TxnMsg::VirtualStoreUnchecked {
                    root: *root,
                    why: why.clone(),
                    at: at.clone(),
                },
            })
        })
        .collect()
}

/// The launch profile a preview writes, decoded (a stored plan: `Rules::Current` decodes it).
pub fn profile_of(p: &Preview) -> Option<&ProfileShown> {
    p.ops.iter().find_map(|o| match &o.profile {
        Some(ProfilePreview::Decoded(s)) => Some(&**s),
        _ => None,
    })
}

/// The profile ID of the launch profile op of `p` (from its file name; also for a profile that
/// does not decode).
pub fn profile_id_of(p: &Preview) -> Option<ProfileId> {
    p.ops.iter().find_map(|o| {
        o.profile.as_ref()?;
        ProfileId::from_hex(o.path.as_str().strip_suffix(".profile")?)
    })
}

/// The launch option for a front end: shown, or why not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OptionText {
    /// The option, as it is.
    Shown(Shown<'static>),
    /// Rerun's install folder is unknown.
    InstallUnknown,
    /// The install folder's path cannot be shown as it is.
    NotShowable,
}

/// The launch option of profile `id` with Rerun's install folder `install`.
pub fn option_text(install: &Result<PathBuf, String>, id: ProfileId) -> OptionText {
    match install {
        Err(_) => OptionText::InstallUnknown,
        Ok(dir) => steam_option_text(dir, id).map_or(OptionText::NotShowable, OptionText::Shown),
    }
}

/// The line of an option that cannot be shown.
fn option_missing(o: &OptionText) -> Option<Message<'static>> {
    match o {
        OptionText::Shown(_) => None,
        OptionText::InstallUnknown => Some(Message::Profile(ProfileMsg::InstallUnknown)),
        OptionText::NotShowable => Some(Message::Profile(ProfileMsg::OptionNotShowable)),
    }
}

/// What the preview of a launch profile shows beyond the plan (P3-3d): the selection on this
/// computer now, the launch option and whether the shim is there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchView {
    /// The rule on this computer.
    pub machine: MachineView,
    /// The launch option.
    pub option: OptionText,
    /// `rerun-launch.exe` in the install folder: its path and whether it is a plain file, or
    /// why that could not be checked (`None`: the install folder is unknown).
    pub shim: Option<(Shown<'static>, Result<bool, Shown<'static>>)>,
}

impl LaunchView {
    /// The option can be pasted and the shim is there (review L3: only then "paste it now").
    pub fn ready(&self) -> bool {
        matches!(self.option, OptionText::Shown(_)) && matches!(self.shim, Some((_, Ok(true))))
    }
}

/// The [`LaunchView`] of `p`, if it writes a launch profile.
pub fn launch_view(
    sys: &dyn System,
    install: &Result<PathBuf, String>,
    p: &Preview,
) -> Option<LaunchView> {
    let s = profile_of(p)?;
    let id = ProfileId::from_hex(&s.id)?;
    let machine = on_this_machine(sys.topology().read(), &s.decoded);
    let shim = install.as_ref().ok().map(|dir| {
        (
            escape::path(&dir.join(SHIM).display().to_string()).into_owned(),
            // The error names a path (ADR 0016: `escape::path`).
            file_present(sys, dir, SHIM).map_err(|e| escape::path(&e.to_string()).into_owned()),
        )
    });
    Some(LaunchView {
        machine,
        option: option_text(install, id),
        shim,
    })
}

/// The lines of a [`LaunchView`] (plan `P3-3` §5): the selection, the hints, the launch option.
pub fn launch_lines<'a>(p: &'a Preview, v: &'a LaunchView) -> Vec<Message<'a>> {
    let pm = Message::Profile;
    let mut out = vec![pm(ProfileMsg::MachineHeading)];
    let mut hard = false;
    let shown = profile_of(p);
    let watch = shown.is_some_and(|s| s.decoded.method == Method::Watch);
    match &v.machine.selection {
        Ok(s) => {
            hard = s.mode == RuleMode::Hard;
            out.push(pm(ProfileMsg::Selection {
                threads: s.threads,
                of: s.of,
                group: s.group,
                mask: s.mask,
                cores: ranges(&s.cores),
                llc: s.llc,
            }));
            out.push(pm(if watch {
                ProfileMsg::WatchMode { mode: s.mode }
            } else {
                ProfileMsg::Mode { mode: s.mode }
            }));
        }
        Err(MachineWhy::NoRule) => out.push(pm(ProfileMsg::MachineNoRule)),
        Err(MachineWhy::Topology(why)) => out.push(pm(ProfileMsg::MachineUnknown {
            why: escape::text(why),
        })),
        Err(MachineWhy::Empty { after }) => {
            out.push(pm(ProfileMsg::MachineEmpty { after: *after }));
        }
    }
    if v.machine.groups > 1 && hard {
        out.push(pm(ProfileMsg::MultiGroup));
    }
    if v.machine.x86_capped {
        out.push(pm(ProfileMsg::X86Capped));
    }
    if let Some(s) = shown {
        if s.launcher {
            out.push(pm(ProfileMsg::LauncherStarts {
                start: s.start.clone(),
            }));
            if let Some(main) = p.roots.first().and_then(|r| r.main_exe.clone()) {
                out.push(pm(ProfileMsg::LauncherGame { main }));
            }
        }
        if s.stub {
            out.push(pm(ProfileMsg::WatchStub));
        }
        if let Some(class) = s.priority {
            out.push(pm(if watch {
                ProfileMsg::WatchPriorityNote { class }
            } else {
                ProfileMsg::PriorityNote { class }
            }));
        }
        if watch {
            out.push(pm(ProfileMsg::WatchLeftAlone));
        }
    }
    out.push(pm(ProfileMsg::OptionHeading));
    match &v.option {
        OptionText::Shown(o) => out.push(pm(ProfileMsg::Option { option: o.clone() })),
        other => out.extend(option_missing(other)),
    }
    match &v.shim {
        Some((path, Ok(false))) => out.push(pm(ProfileMsg::ShimMissing { path: path.clone() })),
        Some((_, Err(why))) => out.push(pm(ProfileMsg::ShimUnchecked { why: why.clone() })),
        Some((_, Ok(true))) | None => {}
    }
    out.push(pm(ProfileMsg::OptionWhere));
    out.push(pm(ProfileMsg::OptionByHand));
    out.push(pm(ProfileMsg::OptionCombine));
    out.push(pm(ProfileMsg::OptionShimStays));
    out
}

/// What becomes of a transaction's launch profile (X12, review M1/B1): the text depends on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fate {
    /// No profile at the name any more (a created profile reverted, or `profiles` gone): the
    /// shim finds none, the option should go.
    Gone,
    /// A replaced profile reverted: the profile from before is back and applies.
    PreviousBack,
    /// The profile stays and applies (not reverted, changed by someone else, a halt before it,
    /// `forget`).
    Stays,
    /// An earlier run left it as found (changed by someone else); whether it is still there is
    /// not known now (its folder may be gone: `verify` shows such an op as recorded).
    Left,
}

/// X12 (revert, `forget`): the launch option Rerun does not change, by what becomes of the
/// profile; `after_revert`: said before a revert ("once the revert completes").
pub fn x12_lines(
    install: &Result<PathBuf, String>,
    id: ProfileId,
    fate: Fate,
    after_revert: bool,
) -> Vec<Message<'static>> {
    let pm = Message::Profile;
    let mut out = Vec::new();
    if after_revert {
        out.push(pm(ProfileMsg::AfterRevert));
    }
    let option = option_text(install, id);
    match fate {
        Fate::Gone => {
            match option {
                OptionText::Shown(option) => out.push(pm(ProfileMsg::OptionRemove { option })),
                other => out.extend(option_missing(&other)),
            }
            out.push(pm(ProfileMsg::OptionAny { id }));
            out.push(pm(ProfileMsg::OptionUntilRemoved));
        }
        Fate::PreviousBack => out.push(pm(ProfileMsg::ProfilePreviousBack { id })),
        Fate::Left => {
            out.push(pm(ProfileMsg::ProfileLeft { id }));
            match option {
                OptionText::Shown(option) => out.push(pm(ProfileMsg::OptionToStop { option })),
                other => out.extend(option_missing(&other)),
            }
            out.push(pm(ProfileMsg::OptionAny { id }));
        }
        Fate::Stays => {
            out.push(pm(ProfileMsg::ProfileStays { id }));
            match option {
                OptionText::Shown(option) => out.push(pm(ProfileMsg::OptionToStop { option })),
                other => out.extend(option_missing(&other)),
            }
            out.push(pm(ProfileMsg::OptionAny { id }));
        }
    }
    out
}

#[cfg(test)]
mod tests;
