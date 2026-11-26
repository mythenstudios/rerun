//! The command line (ADR 0016 and its phase 2 amendment). clap's help texts come from the doc
//! comments here (UI base strings, English); every other user-facing string lives in
//! `messages`.

use std::path::PathBuf;

use clap::{Parser, Subcommand};

use rerun_core::escape;

use rerun_core::catalog::model::Id;
use rerun_core::journal::TxnId;
use rerun_core::path::RelPath;
use rerun_core::plan::{Choice, Manual, ManualExe, ManualLaunch, ManualMethod, Pick, PlanHash};
use rerun_core::policy::registry::TokenName;
use rerun_core::prim::{
    CpuRuleSpec, ExcludeFirstSpec, MAX_THREADS, ModeSpec, PreferL3Spec, PreferSpec, PrioritySpec,
};

use crate::messages::Message;

/// Rerun by Mythen Studios – detects old PC games and applies (and cleanly removes)
/// the compatibility fixes they need.
#[derive(Debug, Parser)]
// No `about` key: clap uses the doc comment (UI base string) instead of the package
// description from Cargo.toml.
#[command(name = "rerun", bin_name = "rerun", version)]
pub struct Cli {
    /// The command.
    #[command(subcommand)]
    pub command: Command,
}

/// The commands of phases 1 and 2.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// The system profile: GPU, CPU topology, OS build and the facts Topo conditions see.
    System,
    /// Steam games with their main executable, architecture and graphics API.
    Scan {
        /// Only these Steam app IDs.
        app_ids: Vec<u32>,
        /// Also compute SHA-1 and SHA-256 of the game executables (slow).
        #[arg(long)]
        hashes: bool,
    },
    /// Plans fixes, game options and your own settings from the signed index for a Steam app
    /// and shows every change; stores the plan for apply. Without --pick, --set and your own
    /// settings, an app ID gives a report only.
    Plan {
        /// A Steam app ID (digits only); in a test build also a step file (JSON, at most 1 MiB).
        target: PathBuf,
        /// A variant to plan, as <issue>/<variant>; repeat for several issues (app ID only).
        #[arg(long = "pick", value_parser = pick)]
        picks: Vec<Pick>,
        /// A game option to set, as <option>=<value>; repeat for several options (app ID only).
        /// An option left out stays unchanged.
        #[arg(long = "set", value_parser = choice)]
        choices: Vec<Choice>,
        /// Your own launch method: direct or watch (default: the Topo's).
        #[arg(long, value_parser = method_arg)]
        method: Option<ManualMethod>,
        /// Your own CPU rule as <field>=<value>,...: max_threads=1..1024, smt=true|false,
        /// single_l3=true|false, prefer=performance|any, prefer_l3=largest,
        /// exclude_first=thread|core, mode=hard|soft.
        #[arg(long, value_parser = cpu_arg)]
        cpu: Option<CpuRuleSpec>,
        /// Your own priority: normal, above_normal or high.
        #[arg(long, value_parser = priority_arg)]
        priority: Option<PrioritySpec>,
        /// A compatibility flag for the game's executable: DISABLEDXMAXIMIZEDWINDOWEDMODE
        /// (disable fullscreen optimisations) or HIGHDPIAWARE (DPI scaling by the application);
        /// repeat for both.
        #[arg(long = "layer", value_parser = layer_arg)]
        layers: Vec<TokenName>,
        /// The game's executable, for a game without a matched Topo (a later version).
        #[arg(long, value_parser = rel_arg)]
        exe: Option<RelPath>,
        /// Steam's launch entry, for a game without a matched Topo (a later version; default:
        /// --exe).
        #[arg(long, requires = "exe", value_parser = rel_arg)]
        start: Option<RelPath>,
        /// Show the plan only; store nothing.
        #[arg(long)]
        dry_run: bool,
    },
    /// Applies a stored plan after showing it again.
    Apply {
        /// The plan hash `rerun plan` printed.
        #[arg(value_parser = plan_hash)]
        hash: PlanHash,
        /// Run every check, change nothing.
        #[arg(long)]
        dry_run: bool,
        /// Do not ask before applying (needed when not run from a console).
        #[arg(long)]
        yes: bool,
    },
    /// Reverts a transaction after showing what the revert does now.
    Revert {
        /// The transaction `rerun apply` printed.
        #[arg(value_parser = txn_id)]
        txn: TxnId,
        /// Show what the revert would do, change nothing.
        #[arg(long)]
        dry_run: bool,
        /// Do not ask before reverting (needed when not run from a console).
        #[arg(long)]
        yes: bool,
        /// Bind the transaction to the folder Steam lists now for the game, after a preview, then
        /// revert it there (only at a console; not with --yes).
        #[arg(long, conflicts_with = "yes")]
        rebind: bool,
    },
    /// Transactions with their state, backups and pending cleanups.
    Status {
        /// Also list every closed transaction.
        #[arg(long)]
        all: bool,
    },
    /// Closes a transaction without reverting it; changes nothing on disk.
    Forget {
        /// The transaction.
        #[arg(value_parser = txn_id)]
        txn: TxnId,
        /// Do not ask before forgetting (needed when not run from a console).
        #[arg(long)]
        yes: bool,
    },
    /// The history of transactions.
    History {
        /// What to do with it.
        #[command(subcommand)]
        command: HistoryCommand,
    },
    /// The signed Topo index.
    Index {
        /// What to do with it.
        #[command(subcommand)]
        command: IndexCommand,
    },
    /// Packages of the signed index.
    Package {
        /// What to do with them.
        #[command(subcommand)]
        command: PackageCommand,
    },
    /// Whether Rerun can be removed: exit 0 when no change is open, 5 when transactions are
    /// still open (listed). Also warns about games Steam may still start through
    /// rerun-launch.exe. Reads only.
    UninstallCheck,
}

/// `rerun history` (P5-6d-1b).
#[derive(Debug, Subcommand)]
pub enum HistoryCommand {
    /// Lists the entries and launch results that can be removed and those that stay, then
    /// removes them. Changes no game folder, registry value or firewall rule.
    Clear {
        /// Show the list only, change nothing.
        #[arg(long)]
        dry_run: bool,
        /// Do not ask before removing (needed when not run from a console).
        #[arg(long)]
        yes: bool,
    },
}

/// `rerun package`.
#[derive(Debug, Subcommand)]
pub enum PackageCommand {
    /// Downloads a package of the current index into Rerun's cache and checks its SHA-256
    /// (nothing is kept unless it matches), then unpacks the files the package names, each
    /// with its own SHA-256, into Rerun's packages folder.
    Fetch {
        /// The package as <id>@<version>, exactly as the index names it.
        #[arg(value_parser = package_spec)]
        package: PackageSpec,
    },
    /// Lists Rerun's package store: each package with its version, size, files and archives,
    /// and the transactions that use it.
    List,
    /// Removes one package and its archives from Rerun's store after listing every file; a
    /// package a transaction uses stays. Changes no game folder, registry value or firewall rule.
    Remove {
        /// The package as <id>@<version>, as `rerun package list` shows it.
        #[arg(value_parser = package_spec)]
        package: PackageSpec,
        /// Show the list only, change nothing.
        #[arg(long)]
        dry_run: bool,
        /// Do not ask before removing (needed when not run from a console).
        #[arg(long)]
        yes: bool,
    },
    /// Removes every package no transaction uses, archives without a package and leftovers of
    /// interrupted runs, after listing them.
    Prune {
        /// Show the list only, change nothing.
        #[arg(long)]
        dry_run: bool,
        /// Do not ask before removing (needed when not run from a console).
        #[arg(long)]
        yes: bool,
    },
}

/// A package as `<id>@<version>`, checked before any system access.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageSpec {
    /// The package ID.
    pub id: Id,
    /// The version (the rule of `version` in docs/02).
    pub version: String,
}

/// `<id>@<version>`: an ID of the Topo form and a version of the package form.
fn package_spec(s: &str) -> Result<PackageSpec, String> {
    let bad = || {
        "not <id>@<version> (an ID of a-z, 0-9 and single hyphens; a version of A-Z a-z 0-9 . _ + -)"
            .to_owned()
    };
    let (id, version) = s.split_once('@').ok_or_else(bad)?;
    match Id::parse(id) {
        Some(id) if rerun_core::catalog::check::version(version) => Ok(PackageSpec {
            id,
            version: version.to_owned(),
        }),
        _ => Err(bad()),
    }
}

/// `rerun index`.
#[derive(Debug, Subcommand)]
pub enum IndexCommand {
    /// Checks a signed index and its signature and makes it the current index (never an older
    /// one).
    Import {
        /// The index (index.json, at most 8 MiB).
        index: PathBuf,
        /// Its signature (index.json.sig, 64 bytes).
        sig: PathBuf,
    },
    /// The current index: number, date, entries, key.
    Show,
}

/// A pick `<issue>/<variant>`: two IDs of the Topo form, checked before any system access.
fn pick(s: &str) -> Result<Pick, String> {
    let bad = || "not <issue>/<variant> (IDs of a-z, 0-9 and single hyphens)".to_owned();
    let (issue, variant) = s.split_once('/').ok_or_else(bad)?;
    match (Id::parse(issue), Id::parse(variant)) {
        (Some(i), Some(v)) => Ok(Pick {
            issue: i.to_string(),
            variant: v.to_string(),
        }),
        _ => Err(bad()),
    }
}

/// A choice `<option>=<value>` (ADR 0032): two IDs of the Topo form, checked before any system
/// access; `unchanged` is the absence of `--set`, never a value.
fn choice(s: &str) -> Result<Choice, String> {
    let bad = || "not <option>=<value> (IDs of a-z, 0-9 and single hyphens)".to_owned();
    let (option, value) = s.split_once('=').ok_or_else(bad)?;
    match (Id::parse(option), Id::parse(value)) {
        (Some(_), Some(v)) if v.as_str() == rerun_core::catalog::model::UNCHANGED => Err(
            "unchanged is the default: leave out --set for this option (to take a value back, \
             revert the transaction that set it)"
                .to_owned(),
        ),
        (Some(o), Some(v)) => Ok(Choice {
            option: o.to_string(),
            value: v.to_string(),
        }),
        _ => Err(bad()),
    }
}

/// `--method`: `direct` or `watch` (ADR 0029: never `auto`, `hold`, `ifeo`, `inproc`).
fn method_arg(s: &str) -> Result<ManualMethod, String> {
    match s {
        "direct" => Ok(ManualMethod::Direct),
        "watch" => Ok(ManualMethod::Watch),
        _ => Err("not a launch method (direct or watch)".to_owned()),
    }
}

/// `--priority`: `normal`, `above_normal` or `high`.
fn priority_arg(s: &str) -> Result<PrioritySpec, String> {
    match s {
        "normal" => Ok(PrioritySpec::Normal),
        "above_normal" => Ok(PrioritySpec::AboveNormal),
        "high" => Ok(PrioritySpec::High),
        _ => Err("not a priority (normal, above_normal or high)".to_owned()),
    }
}

/// `--cpu <field>=<value>,...`: the fields of a CPU rule (docs/02), each once; never
/// `report_cores`. The rule as a whole is checked by `Manual::check`.
pub(crate) fn cpu_arg(s: &str) -> Result<CpuRuleSpec, String> {
    let bad = || {
        "not <field>=<value>,... of max_threads, smt, single_l3, prefer, prefer_l3, \
         exclude_first, mode"
            .to_owned()
    };
    let flag = |v: &str| match v {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err("smt and single_l3 are true or false".to_owned()),
    };
    let mut r = CpuRuleSpec::default();
    let mut seen: Vec<&str> = Vec::new();
    for item in s.split(',') {
        let (k, v) = item.split_once('=').ok_or_else(bad)?;
        if seen.contains(&k) {
            return Err("a field is named twice".to_owned());
        }
        match k {
            "max_threads" => {
                let n: u16 = v
                    .parse()
                    .ok()
                    .filter(|n| (1..=MAX_THREADS).contains(n))
                    .ok_or_else(|| "max_threads is 1 to 1024".to_owned())?;
                r.max_threads = Some(n);
            }
            "smt" => r.smt = Some(flag(v)?),
            "single_l3" => r.single_l3 = Some(flag(v)?),
            "prefer" => {
                r.prefer = Some(match v {
                    "performance" => PreferSpec::Performance,
                    "any" => PreferSpec::Any,
                    _ => return Err("prefer is performance or any".to_owned()),
                });
            }
            "prefer_l3" => {
                r.prefer_l3 = Some(match v {
                    "largest" => PreferL3Spec::Largest,
                    _ => return Err("prefer_l3 is largest".to_owned()),
                });
            }
            "exclude_first" => {
                r.exclude_first = Some(match v {
                    "thread" => ExcludeFirstSpec::Thread,
                    "core" => ExcludeFirstSpec::Core,
                    _ => return Err("exclude_first is thread or core".to_owned()),
                });
            }
            "mode" => {
                r.mode = Some(match v {
                    "hard" => ModeSpec::Hard,
                    "soft" => ModeSpec::Soft,
                    _ => return Err("mode is hard or soft".to_owned()),
                });
            }
            _ => return Err(bad()),
        }
        seen.push(k);
    }
    Ok(r)
}

/// `--layer`: a token of the form `[A-Z0-9_]` (the allowlist is `Manual::check`'s).
fn layer_arg(s: &str) -> Result<TokenName, String> {
    TokenName::parse(s).map_err(|_| "not a compatibility flag (A-Z, 0-9 and _)".to_owned())
}

/// `--exe`, `--start`: a path below the game folder.
fn rel_arg(s: &str) -> Result<RelPath, String> {
    RelPath::parse(s).map_err(|_| "not a path below the game folder".to_owned())
}

/// The flags of the user's own settings of `rerun plan` (ADR 0029).
#[derive(Debug, Default)]
pub struct ManualFlags {
    /// `--method`.
    pub method: Option<ManualMethod>,
    /// `--cpu`.
    pub cpu: Option<CpuRuleSpec>,
    /// `--priority`.
    pub priority: Option<PrioritySpec>,
    /// `--layer`.
    pub layers: Vec<TokenName>,
    /// `--exe`.
    pub exe: Option<RelPath>,
    /// `--start`.
    pub start: Option<RelPath>,
}

impl ManualFlags {
    /// The user's own settings, `None` when no flag of them is given. No flag is mandatory:
    /// `--layer` alone is a selection of flags only. Checked by `Manual::check` afterwards (the
    /// app's input is checked by the same function).
    pub fn manual(self) -> Option<Manual> {
        let launch = (self.method.is_some() || self.cpu.is_some() || self.priority.is_some())
            .then_some(ManualLaunch {
                method: self.method,
                cpu: self.cpu,
                priority: self.priority,
            });
        let exe = self.exe.map(|main_exe| ManualExe {
            start: self.start.unwrap_or_else(|| main_exe.clone()),
            main_exe,
        });
        (launch.is_some() || !self.layers.is_empty() || exe.is_some()).then_some(Manual {
            launch,
            layers: self.layers,
            exe,
        })
    }
}

/// The target of `rerun plan` is digits only: always meant as a Steam app ID.
pub fn digits_only(target: &std::path::Path) -> bool {
    target
        .to_str()
        .is_some_and(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
}

/// The target of `rerun plan` as a Steam app ID (1 to 4294967295), if it is digits only.
pub fn app_id(target: &std::path::Path) -> Option<u32> {
    if !digits_only(target) {
        return None;
    }
    target.to_str()?.parse().ok().filter(|n| *n > 0)
}

/// A plan hash: exactly 64 lower-case hex digits, checked before any system access.
fn plan_hash(s: &str) -> Result<PlanHash, String> {
    s.parse()
        .map_err(|_| "not a plan hash (64 lower-case hex digits)".to_owned())
}

/// A transaction name: 8 digits, `-`, 16 lower-case hex digits.
fn txn_id(s: &str) -> Result<TxnId, String> {
    s.parse()
        .map_err(|_| "not a transaction name (8 digits, '-', 16 lower-case hex digits)".to_owned())
}

/// The lines of a usage error (security review N5): Rerun's words for the kind, the expected
/// form from Rerun's own value parsers, and the value the user gave through `escape::text`,
/// last on its line. clap's own rendering would repeat the arguments raw.
pub fn usage_lines(e: &clap::Error) -> Vec<Message<'static>> {
    use clap::error::{ContextKind, ContextValue, ErrorKind};
    let what = match e.kind() {
        ErrorKind::InvalidValue | ErrorKind::ValueValidation => "invalid value",
        ErrorKind::UnknownArgument => "unknown argument",
        ErrorKind::InvalidSubcommand => "unknown command",
        ErrorKind::MissingRequiredArgument => "a required argument is missing",
        ErrorKind::MissingSubcommand => "a command is missing",
        ErrorKind::TooManyValues | ErrorKind::TooFewValues | ErrorKind::WrongNumberOfValues => {
            "wrong number of values"
        }
        ErrorKind::ArgumentConflict => "arguments that cannot be used together",
        _ => "invalid command line",
    };
    let value = [
        ContextKind::InvalidValue,
        ContextKind::InvalidArg,
        ContextKind::InvalidSubcommand,
    ]
    .into_iter()
    .find_map(|k| match e.get(k) {
        Some(ContextValue::String(s)) => Some(s.clone()),
        Some(ContextValue::Strings(v)) => Some(v.join(" ")),
        _ => None,
    });
    let why = match e.kind() {
        ErrorKind::ValueValidation => std::error::Error::source(e).map(ToString::to_string),
        _ => None,
    };
    vec![
        Message::Usage {
            what,
            why: why.map(|w| escape::text(&w).into_owned()),
            value: value.map(|v| escape::text(&v).into_owned()),
        },
        Message::UsageHelp,
    ]
}

/// Exit codes (ADR 0016 and its phase 2 amendment). Only additive changes: scripts may rely
/// on them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exit {
    /// Done, or a report was printed (also with partial failures, open transactions, or the
    /// output ended by a closed pipe after the change).
    Report = 0,
    /// Fatal, no report.
    Fatal = 1,
    /// Usage error (clap, a malformed hash or transaction, no console without `--yes`).
    Usage = 2,
    /// Nothing was changed: refused, declined, or the preview could not be written.
    Refused = 3,
    /// The apply failed and was rolled back completely.
    RolledBack = 4,
    /// A transaction stays open and needs attention.
    Open = 5,
}

impl From<Exit> for std::process::ExitCode {
    fn from(e: Exit) -> Self {
        Self::from(e as u8)
    }
}

#[cfg(test)]
mod tests {
    use clap::{CommandFactory, Parser};

    use super::{Cli, Command};

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn usage_errors_are_rerun_s_lines_with_the_value_escaped() {
        let text = |args: &[&str]| {
            let e = Cli::try_parse_from(args).unwrap_err();
            let mut out = crate::out::Out::new(Vec::new());
            out.lines(&super::usage_lines(&e)).unwrap();
            String::from_utf8(out.into_inner()).unwrap()
        };
        assert_eq!(
            text(&["rerun", "apply", "abc"]),
            "rerun: invalid value (not a plan hash (64 lower-case hex digits)): abc\n\
             rerun --help lists the commands, rerun <command> --help their arguments\n"
        );
        let evil = text(&["rerun", "scan", "x\u{1b}[2J"]);
        assert!(
            evil.starts_with(
                "rerun: invalid value (invalid digit found in string): \"x\\u{1b}[2J\"\n"
            ),
            "{evil}"
        );
        assert!(text(&["rerun", "nope"]).starts_with("rerun: unknown command: nope\n"));
    }

    #[test]
    fn hashes_and_transactions_are_checked_by_form() {
        let h = "a".repeat(64);
        assert!(matches!(
            Cli::try_parse_from(["rerun", "apply", &h, "--yes"]).map(|c| c.command),
            Ok(Command::Apply {
                yes: true,
                dry_run: false,
                ..
            })
        ));
        for bad in [&"A".repeat(64), &"a".repeat(63), "x", ""] {
            let e = Cli::try_parse_from(["rerun", "apply", bad]).unwrap_err();
            assert!(e.use_stderr(), "{bad}");
        }
        assert!(Cli::try_parse_from(["rerun", "revert", "00000001-00000000000000ab"]).is_ok());
        for bad in ["abc", "1-00000000000000ab", "00000001-00000000000000AB"] {
            assert!(
                Cli::try_parse_from(["rerun", "revert", bad]).is_err(),
                "{bad}"
            );
            assert!(
                Cli::try_parse_from(["rerun", "forget", bad]).is_err(),
                "{bad}"
            );
        }
    }
}
