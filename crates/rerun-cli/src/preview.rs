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
use rerun_core::policy::root::file_present;
use rerun_core::prim::launch_method::RuleMode;
use rerun_core::prim::{MachineView, MachineWhy, SHIM, launch_option, on_this_machine};
use rerun_core::sys::System;

use crate::messages::{At, Message, OpRef, ProfileMsg, TxnMsg, ranges};

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
    if let Some(source) = &o.source {
        out.push(m(TxnMsg::Source {
            source: source.clone(),
        }));
    }
    if let Some((sha256, len)) = &o.content {
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
    if let Some(t) = &o.tokens {
        out.push(m(TxnMsg::Tokens { tokens: tokens(t) }));
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
        }
        Some(ProfilePreview::Unreadable(why)) => {
            out.push(Message::Profile(ProfileMsg::Unreadable {
                why: escape::text(why),
            }));
        }
        None => {}
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
    for note in [p.registry, p.layers, p.ini, p.profiles]
        .into_iter()
        .flatten()
    {
        out.push(m(TxnMsg::Note(note)));
    }
    out
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

/// What the preview of a launch profile shows beyond the plan (P3-3d): the selection on this
/// computer now, the launch option and whether the shim is there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchView {
    /// The rule on this computer.
    pub machine: MachineView,
    /// The launch option (`None`: install folder unknown, or not showable as it is).
    pub option: Option<Shown<'static>>,
    /// `rerun-launch.exe` in the install folder: its path and whether it is a plain file
    /// (`None`: unknown).
    pub shim: Option<(Shown<'static>, bool)>,
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
    let (option, shim) = match install {
        Ok(dir) => (
            launch_option(dir, id),
            file_present(sys, dir, SHIM).ok().map(|ok| {
                (
                    escape::path(&dir.join(SHIM).display().to_string()).into_owned(),
                    ok,
                )
            }),
        ),
        Err(_) => (None, None),
    };
    Some(LaunchView {
        machine,
        option,
        shim,
    })
}

/// The lines of a [`LaunchView`] (plan `P3-3` §5): the selection, the hints, the launch option.
pub fn launch_lines<'a>(p: &'a Preview, v: &'a LaunchView) -> Vec<Message<'a>> {
    let pm = Message::Profile;
    let mut out = vec![pm(ProfileMsg::MachineHeading)];
    let mut hard = false;
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
            out.push(pm(ProfileMsg::Mode { mode: s.mode }));
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
    if let Some(s) = profile_of(p) {
        if s.launcher {
            out.push(pm(ProfileMsg::LauncherStarts {
                start: s.start.clone(),
            }));
            if let Some(main) = p.roots.first().and_then(|r| r.main_exe.clone()) {
                out.push(pm(ProfileMsg::LauncherGame { main }));
            }
        }
        if let Some(class) = s.priority {
            out.push(pm(ProfileMsg::PriorityNote { class }));
        }
    }
    out.push(pm(ProfileMsg::OptionHeading));
    match &v.option {
        Some(o) => out.push(pm(ProfileMsg::Option { option: o.clone() })),
        None => out.push(pm(ProfileMsg::OptionUnavailable)),
    }
    if let Some((path, false)) = &v.shim {
        out.push(pm(ProfileMsg::ShimMissing { path: path.clone() }));
    }
    out.push(pm(ProfileMsg::OptionWhere));
    out.push(pm(ProfileMsg::OptionByHand));
    out.push(pm(ProfileMsg::OptionCombine));
    out.push(pm(ProfileMsg::OptionShimStays));
    out
}

/// X12 (revert, `forget`): the launch option Rerun does not remove, as it would be built now,
/// and any option with the profile's ID.
pub fn option_stays(install: &Result<PathBuf, String>, id: ProfileId) -> Vec<Message<'static>> {
    let pm = Message::Profile;
    let mut out = Vec::new();
    match install.as_ref().ok().and_then(|d| launch_option(d, id)) {
        Some(option) => out.push(pm(ProfileMsg::OptionRemove { option })),
        None => out.push(pm(ProfileMsg::OptionUnavailable)),
    }
    out.push(pm(ProfileMsg::OptionAny { id }));
    out.push(pm(ProfileMsg::OptionUntilRemoved));
    out
}

#[cfg(test)]
mod tests;
