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

use std::io::Write;

use rerun_core::catalog::model::{GpuRequirement, Kind, Status, VariantStatus};
use rerun_core::catalog::{store, trusted_keys};
use rerun_core::escape;
use rerun_core::hw::{self, GpuArchTable};
use rerun_core::plan::{Pick, PlanBytes, Preview};
use rerun_core::policy::registry::RegPolicy;
use rerun_core::policy::root::{AppDir, Create, Shadow, UserDataDir, preview_with_shadows};
use rerun_core::prim::{GameRef, MethodSpec, PlanCtx};
use rerun_core::topo::{
    self, AntiCheatState, ExeState, Facts, GameFacts, Report, Selection, Warning,
};

use crate::cli::Exit;
use crate::host::{Host, fail, forbidden, shown, standard_user};
use crate::messages::{IndexMsg, Message, TopoMsg, TxnMsg};
use crate::out::Out;
use crate::plan::{Stored, show_and_store, with_game};

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
fn report_lines(r: &Report<'_>, g: &GameFacts) -> Vec<Message<'static>> {
    let t = r.topo;
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

/// What happened in the game folder.
enum Outcome {
    Report(Vec<Message<'static>>, Exit),
    Planned {
        before: Vec<Message<'static>>,
        bytes: PlanBytes,
        view: Box<Preview>,
        shadows: Vec<Shadow>,
    },
    Failed(Vec<Message<'static>>, String),
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
    let sys = host.sys;
    standard_user(sys, err)?;
    let fr = forbidden(host, err)?;
    let refused = if picks.is_empty() {
        Exit::Report
    } else {
        Exit::Refused
    };
    let app = AppDir::open(sys, Create::Never)
        .map_err(|e| fail(err, TxnMsg::AppDir { error: shown(&e) }, Exit::Fatal))?;
    let Some(dir) = app.as_ref() else {
        let _ = out.line(&Message::Topo(TopoMsg::NoIndex));
        return Ok(refused);
    };
    let catalog = match store::current(dir, &trusted_keys()) {
        Ok(Some(c)) => c,
        Ok(None) => {
            let _ = out.line(&Message::Topo(TopoMsg::NoIndex));
            return Ok(refused);
        }
        Err(e) => {
            let _ = err.line(&Message::Index(IndexMsg::Refused { error: shown(&e) }));
            return Err(Exit::Refused);
        }
    };
    let topos = topo::topos_for(&catalog, app_id);
    if topos.is_empty() {
        let _ = out.line(&Message::Topo(TopoMsg::NoTopo {
            app_id,
            seq: catalog.seq(),
        }));
        return Ok(refused);
    }
    let app_path = AppDir::path_of(sys).ok();
    let table = GpuArchTable::builtin().ok();
    let profile = hw::read(sys, table);
    let index = *catalog.sha256();
    let outcome = with_game(sys, &fr, &GameRef::Steam(app_id), err, |game, steam_app| {
        // P4-10 (R5): an executable a live laa_patch changed still counts as its build.
        let patched = rerun_core::exec::patched_now(dir, game.id());
        let read: Vec<(&rerun_core::catalog::Topo, GameFacts)> = topos
            .iter()
            .map(|t| (*t, topo::read_game_with(game, t, &patched)))
            .collect();
        // Review follow-up 4: retired Topos are listed, never chosen.
        let (retired, selection) = topo::select(read);
        let mut lead: Vec<Message<'static>> = retired
            .iter()
            .map(|t| {
                Message::Topo(TopoMsg::Retired {
                    id: t.id.to_string(),
                    rev: t.rev,
                    title: escape::text(&t.title).into_owned(),
                })
            })
            .collect();
        let (t, g) = match selection {
            Selection::One(t, g) => (t, g),
            Selection::NoMatch(live) => {
                for (t, g) in &live {
                    lead.push(Message::Topo(TopoMsg::Heading {
                        id: t.id.to_string(),
                        rev: t.rev,
                        status: status(t.status),
                        title: escape::text(&t.title).into_owned(),
                    }));
                    lead.extend(exe_lines(g));
                }
                lead.push(Message::Topo(TopoMsg::NoMatch));
                return Outcome::Report(lead, refused);
            }
            Selection::Several(several) => {
                let ids: Vec<String> = several.iter().map(|t| t.id.to_string()).collect();
                lead.push(Message::Topo(TopoMsg::Several {
                    ids: ids.join(", "),
                }));
                return Outcome::Report(lead, refused);
            }
        };
        let g = &g;
        let facts = Facts {
            profile: &profile,
            table,
            game: g,
            packages: catalog.packages(),
        };
        if picks.is_empty() {
            return match topo::report(t, &facts) {
                Ok(r) => {
                    let mut m = lead;
                    m.extend(report_lines(&r, g));
                    m.push(Message::Blank);
                    m.push(Message::Topo(TopoMsg::PickHint));
                    Outcome::Report(m, Exit::Report)
                }
                Err(e) => Outcome::Failed(Vec::new(), e.to_string()),
            };
        }
        let heading = vec![Message::Topo(TopoMsg::Heading {
            id: t.id.to_string(),
            rev: t.rev,
            status: status(t.status),
            title: escape::text(&t.title).into_owned(),
        })];
        // P4-12: the game's folder below Documents only if a picked step sets a file there.
        let user_data = match &t.user_data {
            Some(u) if topo::needs_user_data(t, picks, &profile) => {
                match UserDataDir::open(sys, &fr, u.base(), u.sub()) {
                    Ok(d) => Some(d),
                    Err(e) => return Outcome::Failed(heading, e.to_string()),
                }
            }
            _ => None,
        };
        let ctx = PlanCtx {
            game,
            app: app.as_ref(),
            steam_app,
            main_exe: None,
            reg: RegPolicy.reader(sys),
            app_path: app_path.as_ref(),
            user_data: user_data.as_ref(),
        };
        let tp = match topo::plan(&index, t, &facts, picks, &ctx) {
            Ok(tp) => tp,
            Err(e) => return Outcome::Failed(heading, e.to_string()),
        };
        let encoded = tp.plan.encode().and_then(|b| {
            let (v, sh) = preview_with_shadows(sys, &b)?;
            Ok((b, v, sh))
        });
        match encoded {
            Ok((bytes, view, shadows)) => {
                let mut before = lead;
                before.extend(heading);
                before.push(Message::Topo(TopoMsg::Source {
                    id: t.id.to_string(),
                    rev: t.rev,
                    index: hex(&index),
                }));
                before.extend(tp.warnings.iter().map(|w| {
                    Message::Topo(TopoMsg::Warning {
                        text: warning_text(w),
                    })
                }));
                before.push(Message::Blank);
                Outcome::Planned {
                    before,
                    bytes,
                    view: Box::new(view),
                    shadows,
                }
            }
            Err(e) => Outcome::Failed(heading, e.to_string()),
        }
    })?;
    match outcome {
        Outcome::Report(lines, exit) => Ok(out
            .lines(&lines)
            .and_then(|()| out.flush())
            .map_or_else(|e| crate::out::failed(err, e), |()| exit)),
        Outcome::Failed(lines, why) => {
            let _ = out.lines(&lines).and_then(|()| out.flush());
            Err(fail(
                err,
                TxnMsg::PlanFailed {
                    error: escape::text(&why).into_owned(),
                },
                Exit::Refused,
            ))
        }
        Outcome::Planned {
            before,
            bytes,
            view,
            shadows,
        } => show_and_store(
            host,
            Stored {
                app,
                app_path,
                bytes,
                view: *view,
                shadows,
            },
            &before,
            dry_run,
            out,
            err,
        ),
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
