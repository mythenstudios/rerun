//! `rerun plan <app-id> [--pick <issue>/<variant>]… [--dry-run]` (P4-4): the Topo engine on the
//! current signed index.
//!
//! Order: the elevated guard, the forbidden roots, Rerun's folder without creating it, the
//! current index (`catalog::store::current`: signature and form checked again), the Topos that
//! name the app, the game folder (exactly one installed app in the Steam libraries, as for a
//! step file), per Topo the executables hashed on their parsed handles and the anti-cheat
//! markers, the system profile (`hw::read` with the built-in architecture table, the table
//! the Topo is checked against). Exactly one Topo must match.
//!
//! Without `--pick`: the report (issues, `when` here, variants and what the engine says);
//! nothing is stored, nothing created. With `--pick`: the engine's plan, then the same preview
//! and storage as a step file (`plan::show_and_store`), with the plan's origin and the
//! warnings before the preview. `appinfo.vdf` is never read (L9).
//!
//! The guards, the lookup, the report and the plan come from `rerun_core::flow` (`guard`,
//! `game`, `plan`, ADR 0027 and its amendment P5-2a); this module renders them.

use std::io::Write;

use rerun_core::catalog::Topo;
use rerun_core::catalog::model::{GpuRequirement, Kind, Status, VariantStatus};
use rerun_core::escape;
use rerun_core::flow::{self, Found, GameRefusal, Lookup, OwnedReport};
use rerun_core::plan::Pick;
use rerun_core::prim::MethodSpec;
use rerun_core::topo::{AntiCheatState, ExeState, GameFacts, Warning};

use crate::cli::Exit;
use crate::host::{Host, fail, gate, shown};
use crate::messages::{IndexMsg, Message, TopoMsg, TxnMsg};
use crate::out::Out;
use crate::plan::{game_open, show_and_store};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn status(s: Status) -> &'static str {
    match s {
        Status::Draft => "draft",
        Status::Active => "active",
        Status::NeedsRetest => "needs-retest",
        Status::Retired => "retired",
    }
}

fn method(m: MethodSpec) -> &'static str {
    match m {
        MethodSpec::Direct => "direct",
        MethodSpec::Watch => "watch",
        MethodSpec::Auto => "auto",
    }
}

fn exe_lines(g: &GameFacts) -> Vec<Message<'static>> {
    g.exes
        .iter()
        .map(|e| {
            let path = e.path.as_str();
            let (state, what) = match &e.state {
                ExeState::Match if e.patched_by.is_some() => (
                    "matches (as patched by Rerun's laa_patch)",
                    escape::path(path).into_owned(),
                ),
                ExeState::Match => ("matches", escape::path(path).into_owned()),
                ExeState::Mismatch => (
                    "has another content (no match)",
                    escape::path(path).into_owned(),
                ),
                ExeState::Missing => ("is missing", escape::path(path).into_owned()),
                ExeState::Unreadable(why) => (
                    "cannot be checked",
                    escape::text(&format!("{path}: {why}")).into_owned(),
                ),
            };
            Message::Topo(TopoMsg::Exe { state, what })
        })
        .collect()
}

fn list<T: std::fmt::Display>(v: &[T]) -> String {
    v.iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

/// The report's lines.
fn report_lines(r: &OwnedReport, g: &GameFacts) -> Vec<Message<'static>> {
    let t = &r.topo;
    let mut m = vec![Message::Topo(TopoMsg::Heading {
        id: t.id.to_string(),
        rev: t.rev,
        status: status(t.status),
        title: escape::text(&t.title).into_owned(),
    })];
    m.extend(exe_lines(g));
    m.push(Message::Topo(match &r.launch {
        Ok(lp) => TopoMsg::Launch {
            method: method(lp.method),
            auto: lp.auto,
            start: escape::path(lp.start.as_str()).into_owned(),
        },
        Err(p) => TopoMsg::LaunchProblem { why: p.to_string() },
    }));
    if t.launch.as_ref().is_some_and(|l| l.cpu.is_some()) {
        m.push(Message::Topo(TopoMsg::LaunchCpuNotPlanned));
    }
    match &r.anti_cheat {
        AntiCheatState::Clear => {}
        AntiCheatState::Enforced {
            systems,
            unreadable,
        } => m.push(Message::Topo(TopoMsg::AntiCheat {
            systems: list(systems),
            unreadable: *unreadable,
        })),
        AntiCheatState::Released { systems } => {
            m.push(Message::Topo(TopoMsg::AntiCheatReleased {
                systems: list(systems),
            }));
        }
    }
    if r.several_gpus {
        m.push(Message::Topo(TopoMsg::SeveralGpus));
    }
    for i in &r.issues {
        m.push(Message::Topo(TopoMsg::Issue {
            id: i.issue.id.to_string(),
            applies: i.when.as_str(),
            title: escape::text(&i.issue.title).into_owned(),
        }));
        if i.variants.is_empty() {
            m.push(Message::Topo(TopoMsg::NoKnownFix));
        }
        for v in &i.variants {
            let mut notes = Vec::new();
            if let Some(why) = &v.refused {
                notes.push(why.to_string());
            }
            if !v.warned.is_empty() {
                let kinds: Vec<&str> = v.warned.iter().map(|k| k.as_str()).collect();
                notes.push(format!("warning: anti-cheat found ({})", kinds.join(", ")));
            }
            m.push(Message::Topo(TopoMsg::Variant {
                pick: format!("{}/{}", i.issue.id, v.variant.id),
                status: match v.variant.status {
                    VariantStatus::Verified => "verified",
                    VariantStatus::Reported => "reported",
                    VariantStatus::Unverified => "unverified",
                },
                kind: match v.variant.kind {
                    Kind::Fix => "fix",
                    Kind::Enhancement => "enhancement",
                },
                note: (!notes.is_empty()).then(|| notes.join("; ")),
            }));
        }
    }
    m
}

fn warning_text(w: &Warning) -> String {
    match w {
        Warning::NeedsRetest => "warning: this Topo is marked to be tested again".to_owned(),
        Warning::WhenUnknown { issue } => format!(
            "warning: issue {issue}: a condition could not be checked on this system; planned \
             because you picked it"
        ),
        Warning::AntiCheat {
            issue,
            variant,
            step,
        } => format!(
            "warning: {issue}/{variant}: anti-cheat found; {} is planned, at your own risk",
            step.as_str()
        ),
        Warning::SteamInput { issue } => format!(
            "hint: issue {issue}: turn on Steam Input for this game in Steam (Rerun changes \
             nothing)"
        ),
        Warning::RequiresGpu { package, needs } => format!(
            "warning: package {package} needs {}; Rerun does not check it, the game may not \
             start without it",
            match needs {
                GpuRequirement::Vulkan => "a Vulkan driver for the graphics card",
            }
        ),
        Warning::SmartAppControl { state } => format!(
            "warning: Smart App Control {}decides per file whether the patched executable may \
             run. If the game then does not start (error 0x11c7 / 4551, \"An Application \
             Control policy has blocked this file\"), undo it with rerun revert <txn>, which \
             restores the original file bit for bit",
            match state {
                rerun_core::hw::SacState::Enforce => "is on and ",
                rerun_core::hw::SacState::Evaluation => {
                    "is in evaluation mode; once Windows turns it on, it "
                }
                _ => "is in a state Rerun cannot read; if it is on, it ",
            }
        ),
        Warning::SteamPerUserExe { exe } => format!(
            "warning: {} carries a Valve header: Steam likely built it for your account, so a \
             patched copy is a file no one else has. Smart App Control does not know it and is \
             likely to block it sooner or later, even if the game starts now; rerun revert \
             <txn> then restores the original file bit for bit",
            rerun_core::escape::path(exe.as_str())
        ),
        Warning::GpuPreferenceSet { exe, by } => match by {
            Some(t) => format!(
                "hint: the graphics preference of {} is High performance already, set by Rerun \
                 transaction {t}; nothing to do (reverting that transaction takes it back)",
                rerun_core::escape::path(exe.as_str())
            ),
            None => format!(
                "hint: the graphics preference of {} is High performance already; nothing to do",
                rerun_core::escape::path(exe.as_str())
            ),
        },
        Warning::SignedExe { exe } => format!(
            "warning: {} is digitally signed; the patch makes the signature invalid (the revert \
             restores it)",
            rerun_core::escape::path(exe.as_str())
        ),
    }
}

/// A Topo heading.
fn heading(t: &Topo) -> Message<'static> {
    Message::Topo(TopoMsg::Heading {
        id: t.id.to_string(),
        rev: t.rev,
        status: status(t.status),
        title: escape::text(&t.title).into_owned(),
    })
}

/// The retired Topos of the app, listed before anything else.
fn retired_lines(retired: &[Topo]) -> Vec<Message<'static>> {
    retired
        .iter()
        .map(|t| {
            Message::Topo(TopoMsg::Retired {
                id: t.id.to_string(),
                rev: t.rev,
                title: escape::text(&t.title).into_owned(),
            })
        })
        .collect()
}

/// The lines of the retired Topos and what one Topo gave; a lookup that found no single Topo
/// is written to stdout here and ends with `exit`.
fn one<R, W: Write, E: Write>(
    lookup: Lookup<R>,
    app_id: u32,
    exit: Exit,
    out: &mut Out<W>,
    err: &mut Out<E>,
) -> Result<(Vec<Message<'static>>, R), Exit> {
    let (retired, found) = match lookup {
        Lookup::NoIndex => {
            let _ = out.line(&Message::Topo(TopoMsg::NoIndex));
            return Err(exit);
        }
        Lookup::NoTopo { seq } => {
            let _ = out.line(&Message::Topo(TopoMsg::NoTopo { app_id, seq }));
            return Err(exit);
        }
        Lookup::Read { retired, found } => (retired, found),
    };
    let mut lead = retired_lines(&retired);
    match found {
        Found::One(r) => return Ok((lead, r)),
        Found::NoMatch(live) => {
            for (t, g) in &live {
                lead.push(heading(t));
                lead.extend(exe_lines(g));
            }
            lead.push(Message::Topo(TopoMsg::NoMatch));
        }
        Found::Several(ids) => lead.push(Message::Topo(TopoMsg::Several {
            ids: ids.join(", "),
        })),
    }
    Err(print(out, err, &lead, exit))
}

/// `lines` on stdout, then `exit`; a write error other than a closed pipe is fatal.
fn print<W: Write, E: Write>(
    out: &mut Out<W>,
    err: &mut Out<E>,
    lines: &[Message<'_>],
    exit: Exit,
) -> Exit {
    out.lines(lines)
        .and_then(|()| out.flush())
        .map_or_else(|e| crate::out::failed(err, e), |()| exit)
}

/// A lookup that stopped, on stderr: exit 3.
fn refusal<W: Write, E: Write>(out: &mut Out<W>, err: &mut Out<E>, r: GameRefusal) -> Exit {
    match r {
        GameRefusal::Index(e) => {
            let _ = err.line(&Message::Index(IndexMsg::Refused { error: shown(&e) }));
            Exit::Refused
        }
        GameRefusal::Game(e) => game_open(err, e),
        GameRefusal::Engine(e) => failed(out, err, &[], &e.to_string()),
    }
}

/// The engine or a planner refused: `lines` on stdout, the reason on stderr, exit 3.
fn failed<W: Write, E: Write>(
    out: &mut Out<W>,
    err: &mut Out<E>,
    lines: &[Message<'_>],
    why: &str,
) -> Exit {
    let _ = out.lines(lines).and_then(|()| out.flush());
    fail(
        err,
        TxnMsg::PlanFailed {
            error: escape::text(why).into_owned(),
        },
        Exit::Refused,
    )
}

/// `rerun plan <app-id>` (module docs).
pub fn plan<W: Write, E: Write>(
    host: &Host<'_>,
    app_id: u32,
    picks: &[Pick],
    dry_run: bool,
    out: &mut Out<W>,
    err: &mut Out<E>,
) -> Exit {
    match run(host, app_id, picks, dry_run, out, err) {
        Ok(e) | Err(e) => e,
    }
}

fn run<W: Write, E: Write>(
    host: &Host<'_>,
    app_id: u32,
    picks: &[Pick],
    dry_run: bool,
    out: &mut Out<W>,
    err: &mut Out<E>,
) -> Result<Exit, Exit> {
    let g = flow::guard(host.env()).map_err(|x| gate(err, x))?;
    if picks.is_empty() {
        // The report: nothing is stored, nothing created.
        let v = flow::game(&g, app_id).map_err(|r| refusal(out, err, r))?;
        let (mut m, mv) = match one(v.lookup, app_id, Exit::Report, out, err) {
            Ok(x) => x,
            Err(exit) => return Ok(exit),
        };
        m.extend(report_lines(&mv.report, &mv.read));
        m.push(Message::Blank);
        m.push(Message::Topo(TopoMsg::PickHint));
        return Ok(print(out, err, &m, Exit::Report));
    }
    let lookup = flow::plan(&g, app_id, picks).map_err(|r| refusal(out, err, r))?;
    let (lead, picked) = match one(lookup, app_id, Exit::Refused, out, err) {
        Ok(x) => x,
        Err(exit) => return Ok(exit),
    };
    let t = &picked.topo;
    let mut before = vec![heading(t)];
    match picked.planned {
        // The lines of the retired Topos are not shown with a refusal.
        Err(e) => Err(failed(out, err, &before, &e.to_string())),
        Ok(p) => {
            before.push(Message::Topo(TopoMsg::Source {
                id: t.id.to_string(),
                rev: t.rev,
                index: hex(&picked.index),
            }));
            before.extend(p.warnings.iter().map(|w| {
                Message::Topo(TopoMsg::Warning {
                    text: warning_text(w),
                })
            }));
            before.push(Message::Blank);
            let mut all = lead;
            all.extend(before);
            show_and_store(host, g, p, &all, dry_run, out, err)
        }
    }
}

#[cfg(test)]
mod warning_tests {
    use rerun_core::hw::SacState;
    use rerun_core::path::RelPath;
    use rerun_core::topo::Warning;

    use super::warning_text;

    /// P4-13: every Smart App Control warning names the block and the way back; the Valve
    /// header warning names the executable and the way back.
    #[test]
    fn smart_app_control_warnings_name_the_way_back() {
        let back = "rerun revert <txn>, which restores the original file bit for bit";
        for (state, lead) in [
            (
                SacState::Enforce,
                "Smart App Control is on and decides per file",
            ),
            (
                SacState::Evaluation,
                "is in evaluation mode; once Windows turns it on",
            ),
            (SacState::Unknown, "a state Rerun cannot read; if it is on"),
        ] {
            let t = warning_text(&Warning::SmartAppControl { state });
            assert!(t.starts_with("warning: "), "{t}");
            assert!(t.contains(lead), "{t}");
            assert!(t.contains("0x11c7 / 4551"), "{t}");
            assert!(t.contains(back), "{t}");
        }
        let t = warning_text(&Warning::SteamPerUserExe {
            exe: RelPath::parse(r"pc\mafia2.exe").unwrap(),
        });
        assert!(t.contains(r"pc\mafia2.exe carries a Valve header"), "{t}");
        assert!(t.contains("likely to block it sooner or later"), "{t}");
        assert!(t.contains("restores the original file bit for bit"), "{t}");
    }
}
