//! The lines of `rerun plan <app-id>` (P4-4): the Topo engine's report and the warnings of a
//! Topo plan. IDs, numbers and kinds are Rerun's own text or of the ID form the signed index
//! checked; titles, paths and errors come as [`Shown`] and stand last.

use std::fmt;

use rerun_core::escape::Shown;

/// One line about a Topo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TopoMsg<'a> {
    /// No signed index has been imported.
    NoIndex,
    /// The index has no Topo for this app.
    NoTopo {
        /// The app.
        app_id: u32,
        /// The index.
        seq: u64,
    },
    /// The index has Topos for this app, but this build sets every one aside.
    NoUsableTopo {
        /// The app.
        app_id: u32,
        /// The index, when the lookup names it (not after the game folder was read).
        seq: Option<u64>,
    },
    /// A Topo of the app this build sets aside (ADR 0024 amendment "Forward compatibility"
    /// §10): never planned.
    Aside {
        /// Its ID.
        id: Shown<'a>,
        /// A newer Rerun can use it.
        newer: bool,
        /// Why this version cannot use it (`None` when `newer`).
        why: Option<Shown<'a>>,
    },
    /// The Topo's heading.
    Heading {
        /// Its ID.
        id: String,
        /// Its revision.
        rev: u32,
        /// `active`, `needs-retest`, `retired`.
        status: &'static str,
        /// Its title.
        title: Shown<'a>,
    },
    /// One executable of `match.exes`.
    Exe {
        /// `matches`, `different content (no match)`, `missing`, `cannot be read`.
        state: &'static str,
        /// The path (and the reason).
        what: Shown<'a>,
    },
    /// No executable matched: nothing is offered.
    NoMatch,
    /// A retired Topo of the app: listed, never chosen.
    Retired {
        /// Its ID.
        id: String,
        /// Its revision.
        rev: u32,
        /// Its title.
        title: Shown<'a>,
    },
    /// `launch.cpu` is shown, not planned (ADR 0020 amendment P4-4).
    LaunchCpuNotPlanned,
    /// Several hardware adapters and a GPU condition (P4-11, E-G2 d).
    SeveralGpus,
    /// Several Topos match this installation.
    Several {
        /// Their IDs.
        ids: String,
    },
    /// The launch as resolved.
    Launch {
        /// `direct` or `watch`.
        method: &'static str,
        /// It was `auto`.
        auto: bool,
        /// Steam's launch entry.
        start: Shown<'a>,
    },
    /// The launch cannot carry a CPU rule.
    LaunchProblem {
        /// Why (Rerun's text).
        why: String,
    },
    /// Anti-cheat found: the rule applies.
    AntiCheat {
        /// The systems, comma-separated.
        systems: String,
        /// A marker could not be checked.
        unreadable: bool,
    },
    /// Anti-cheat found, released as dead by the Topo.
    AntiCheatReleased {
        /// The systems.
        systems: String,
    },
    /// One issue.
    Issue {
        /// Its ID.
        id: String,
        /// `yes`, `no`, `unknown`.
        applies: &'static str,
        /// Its title.
        title: Shown<'a>,
    },
    /// An issue without a variant.
    NoKnownFix,
    /// One variant.
    Variant {
        /// `<issue>/<variant>`.
        pick: String,
        /// `verified`, `reported`, `unverified`.
        status: &'static str,
        /// `fix`, `enhancement`.
        kind: &'static str,
        /// What the engine says (Rerun's text), if anything.
        note: Option<String>,
    },
    /// How to plan.
    PickHint,
    /// One game option (ADR 0032).
    Option {
        /// Its ID.
        id: String,
        /// Its title.
        title: Shown<'a>,
    },
    /// One value of an option.
    OptionValue {
        /// `<option>=<value>`.
        set: String,
        /// `verified`, `reported`, `unverified`.
        status: &'static str,
        /// Its title.
        title: Shown<'a>,
        /// What the engine says (Rerun's text), if anything.
        note: Option<String>,
    },
    /// How to set an option.
    SetHint,
    /// The option values a plan sets.
    Choices {
        /// `<option>=<value>`, comma-separated.
        set: String,
    },
    /// The user's own settings a plan sets ("Advanced", ADR 0029).
    Manual {
        /// Rerun's words for each setting (fields and values of a closed set), comma-separated.
        set: String,
    },
    /// Advanced for a game without a matched Topo comes later (ADR 0029, slice E-1b).
    ManualNeedsTopo,
    /// The plan's origin.
    Source {
        /// The Topo.
        id: String,
        /// Its revision.
        rev: u32,
        /// The index's SHA-256.
        index: String,
    },
    /// A warning or hint of the plan (Rerun's text).
    Warning {
        /// The text.
        text: String,
    },
    /// The heading of the launch profile's parts (ADR 0032 amendment P5-OE).
    ProfileParts,
    /// One part of the launch profile and where it comes from (Rerun's words; a path last).
    ProfilePart {
        /// The part (`cpu rule`, `run`, `args <arguments>`; Rerun's text and arguments of the
        /// `LaunchArg` pattern).
        part: String,
        /// Where it comes from (Rerun's text: a fix, an option value, a transaction; IDs of the
        /// signed index).
        from: String,
        /// The executable of `run` (relative to the game folder).
        path: Option<Shown<'a>>,
    },
    /// What every fallback of `rerun-launch` starts (ADR 0022 D3): Steam's own command.
    ProfileFallback {
        /// The profile has `run`.
        run: bool,
        /// The profile has a CPU rule or a priority class.
        rule: bool,
        /// The profile has `args`.
        args: bool,
        /// Steam's launch entry (relative to the game folder).
        start: Shown<'a>,
    },
}

impl fmt::Display for TopoMsg<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoIndex => f.write_str(
                "no signed index has been imported yet; import one with rerun index import",
            ),
            Self::NoTopo { app_id, seq } => {
                write!(f, "app {app_id}: index {seq} has no Topo for this game")
            }
            Self::NoUsableTopo { app_id, seq } => {
                match seq {
                    Some(seq) => write!(f, "app {app_id}: index {seq} has ")?,
                    None => write!(f, "app {app_id}: the index has ")?,
                }
                f.write_str(
                    "no Topo for this game that this version of Rerun can use: nothing is offered",
                )
            }
            Self::Aside { id, newer: true, .. } => {
                write!(f, "Topo {id} for this game needs a newer version of Rerun")
            }
            Self::Aside {
                id,
                newer: false,
                why,
            } => {
                write!(
                    f,
                    "Topo {id} for this game cannot be used by this version of Rerun"
                )?;
                match why {
                    Some(w) => write!(f, " ({w})"),
                    None => Ok(()),
                }
            }
            Self::Heading {
                id,
                rev,
                status,
                title,
            } => write!(f, "Topo {id} rev {rev} ({status}): {title}"),
            Self::Exe { state, what } => write!(f, "  executable {state}: {what}"),
            Self::NoMatch => f.write_str(
                "  no executable of this installation matches the Topo's hashes: nothing is offered",
            ),
            Self::Retired { id, rev, title } => {
                write!(f, "Topo {id} rev {rev} is retired and offers nothing: {title}")
            }
            Self::LaunchCpuNotPlanned => {
                f.write_str("  launch.cpu: not planned (pick a cpu step)")
            }
            Self::SeveralGpus => f.write_str(
                "  note: this PC has several graphics adapters; GPU conditions are checked on \
                 each of them and are unknown where your GPUs differ",
            ),
            Self::Several { ids } => write!(
                f,
                "several Topos match this installation ({ids}): refused, nothing is offered"
            ),
            Self::Launch {
                method,
                auto,
                start,
            } => {
                let from = if *auto { " (auto)" } else { "" };
                write!(f, "  launch: {method}{from}, Steam starts {start}")
            }
            Self::LaunchProblem { why } => write!(f, "  launch: {why}"),
            Self::AntiCheat {
                systems,
                unreadable,
            } => {
                let what = if systems.is_empty() {
                    "a marker that cannot be checked"
                } else {
                    systems.as_str()
                };
                let also = if *unreadable && !systems.is_empty() {
                    " (and a marker that cannot be checked)"
                } else {
                    ""
                };
                write!(
                    f,
                    "  anti-cheat: {what}{also}: no package, laa_patch, firewall_rule, \
                     compat_layer or watch for this game; other fixes with a warning"
                )
            }
            Self::AntiCheatReleased { systems } => write!(
                f,
                "  anti-cheat: {systems} found, released as dead by the Topo"
            ),
            Self::Issue { id, applies, title } => {
                write!(f, "  issue {id} (applies here: {applies}): {title}")
            }
            Self::NoKnownFix => f.write_str("    no known fix"),
            Self::Variant {
                pick,
                status,
                kind,
                note,
            } => {
                write!(f, "    {pick}: {status} {kind}")?;
                match note {
                    Some(n) => write!(f, "; {n}"),
                    None => Ok(()),
                }
            }
            Self::PickHint => f.write_str(
                "plan with --pick <issue>/<variant> (one per issue); a variant whose conditions \
                 are unknown here is planned only when picked",
            ),
            Self::Option { id, title } => {
                write!(f, "  option {id} (unchanged unless set): {title}")
            }
            Self::OptionValue {
                set,
                status,
                title,
                note,
            } => {
                write!(f, "    {set}: {status}")?;
                if let Some(n) = note {
                    write!(f, "; {n}")?;
                }
                write!(f, ": {title}")
            }
            Self::SetHint => f.write_str(
                "set an option with --set <option>=<value> (one value per option); an option \
                 left out stays as it is",
            ),
            Self::Choices { set } => write!(f, "options set: {set}"),
            Self::Manual { set } => write!(
                f,
                "your own settings (Advanced, not checked by a Topo): {set}"
            ),
            Self::ManualNeedsTopo => f.write_str(
                "your own settings (--method, --cpu, --priority, --layer) need a game with a \
                 matched Topo in this version; for a game without one they come later",
            ),
            Self::Source { id, rev, index } => {
                write!(f, "from Topo {id} rev {rev} of the signed index {index}")
            }
            Self::Warning { text } => write!(f, "{text}"),
            Self::ProfileParts => f.write_str("the launch profile, part by part:"),
            Self::ProfilePart { part, from, path } => match path {
                Some(p) => write!(f, "  {part}, {from}: {p}"),
                None => write!(f, "  {part}, {from}"),
            },
            Self::ProfileFallback {
                run,
                rule,
                args,
                start,
            } => {
                // O-2b review N1: said from the parts the profile has.
                let without: Vec<&str> = [(*rule, "the rule"), (*args, "the arguments")]
                    .into_iter()
                    .filter_map(|(on, w)| on.then_some(w))
                    .collect();
                write!(
                    f,
                    "  whenever rerun-launch cannot use the profile (it is missing or invalid, \
                     Steam's path differs, Steam runs as administrator{}), it starts Steam's \
                     own command unchanged",
                    if *run { ", or run cannot be started" } else { "" }
                )?;
                if !without.is_empty() {
                    write!(f, ", without {}", without.join(" and "))?;
                }
                write!(f, ": {start}")
            }
        }
    }
}
