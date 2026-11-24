//! Opening links and Rerun's folder (ADR 0027 amendment P5-10a): the one way from a front end
//! to the user's shell. `policy::open` decides what may be opened, [`Shell`] executes, this
//! module connects them. A front end never hands over a string: it names a source of the current
//! index ([`LinkRef`]), asks for the report ([`report`]) and opens exactly its URL, or asks for
//! Rerun's folder ([`open_data_folder`]).
//!
//! - [`source_url`]: a source URL of a variant of the **current** signed index, looked up by the
//!   Topo, issue, variant and position; another index, a missing source or no index opens
//!   nothing.
//! - [`report`]: the title and text of a new issue in Rerun's repository, from facts Rerun
//!   determines itself only: its build ID, the Windows build, the Steam app ID, the Topos the
//!   index has for the app (ID, revision, status) and the index's `seq`, the variant IDs of the
//!   game's open changes (from their heads), per graphics adapter its vendor and architecture
//!   from the table, the CPU's logical processors, cores and L3 groups, and how the last start
//!   went (fixed words). Never a Steam name, a path, an account or an adapter name. Lists are
//!   cut ("and N more") until the URL fits `policy::open::MAX_OPEN_URL`; the text is printable
//!   ASCII and `\n`. The front end shows exactly this text before it opens [`Report::url`].
//! - [`data_folder`]: the path of Rerun's folder and whether it exists (nothing is created);
//!   [`open_data_folder`] shows it in Explorer only if it exists, from the `AppDir` the guard
//!   opened.

use crate::catalog::model::Status;
use crate::exec::launch_result::{Check, Outcome};
use crate::hw::{self, ArchFact, GpuArchTable, GpuVendor, VendorFact};
use crate::path::RootPath;
use crate::policy::open::{OpenFolder, OpenRefusal, OpenUrl};
use crate::policy::root::{AppDir, RootError};
use crate::sys::{Shell, SysError};

use super::{Guarded, Heads, IndexState, head, index_state, journal, launch_lines, launch_of};

/// A source of a variant of the current index, by position (what a front end's link names).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkRef {
    /// The Steam app the game page is about.
    pub app_id: u32,
    /// The Topo ID.
    pub topo: String,
    /// The issue ID.
    pub issue: String,
    /// The variant ID.
    pub variant: String,
    /// The source's position in the variant's `sources`.
    pub source: usize,
}

/// The URL `r` names in the current signed index (module docs).
pub fn source_url(g: &Guarded<'_>, r: &LinkRef) -> Result<OpenUrl, OpenRefusal> {
    let IndexState::Current(c) = index_state(g.app()) else {
        return Err(OpenRefusal::NoIndex);
    };
    let url = c
        .topo(&r.topo)
        .filter(|t| t.matches.steam_appid == Some(r.app_id))
        .and_then(|t| t.issues.iter().find(|i| i.id.as_str() == r.issue))
        .and_then(|i| i.variants.iter().find(|v| v.id.as_str() == r.variant))
        .and_then(|v| v.sources.get(r.source))
        .ok_or(OpenRefusal::NotInIndex)?;
    OpenUrl::from_index(&url.url)
}

/// The prefilled issue of "report a problem" (module docs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    /// The issue's title (printable ASCII).
    pub title: String,
    /// The issue's text (printable ASCII and `\n`).
    pub body: String,
    url: OpenUrl,
}

impl Report {
    /// The new issue with exactly [`Self::title`] and [`Self::body`].
    pub fn url(&self) -> &OpenUrl {
        &self.url
    }
}

/// Most open changes, adapters and Topos named one by one.
const MAX_VARIANTS: usize = 8;
const MAX_GPUS: usize = 4;
const MAX_TOPOS: usize = 4;

/// The facts of a report, gathered once.
struct Facts {
    os: String,
    index: String,
    topos: Vec<String>,
    variants: Vec<String>,
    gpus: Vec<String>,
    cpu: String,
    last_start: String,
}

/// `items` joined by `, `, at most `n` of them and "and K more" for the rest; `none` for none.
fn listed(items: &[String], n: usize, none: &str) -> String {
    if items.is_empty() {
        return none.to_owned();
    }
    let shown = items.len().min(n);
    if shown == 0 {
        return format!("{} (not listed)", items.len());
    }
    let mut s = items[..shown].join(", ");
    if items.len() > shown {
        s.push_str(&format!(" and {} more", items.len() - shown));
    }
    s
}

/// The text of a report with at most `n` entries per list.
fn body(app_id: u32, f: &Facts, n: [usize; 3]) -> String {
    let [topos, variants, gpus] = n;
    format!(
        "What happened:\n\n\nWhat did you expect:\n\n\n\
         ---\n\
         Facts Rerun added (nothing else is sent):\n\
         - Rerun: {build}\n\
         - Windows build: {os}\n\
         - Steam app: {app_id}\n\
         - Index: {index}\n\
         - Topos: {topos}\n\
         - Open changes: {variants}\n\
         - Graphics: {gpus}\n\
         - CPU: {cpu}\n\
         - Last start: {last}\n",
        build = crate::BUILD_ID,
        os = f.os,
        index = f.index,
        topos = listed(&f.topos, topos, "none"),
        variants = listed(&f.variants, variants, "none"),
        gpus = listed(&f.gpus, gpus, "none found"),
        cpu = f.cpu,
        last = f.last_start,
    )
}

/// Keeps only printable ASCII and `\n` (every fact is Rerun's own already; a guard against a
/// future fact that is not).
fn ascii(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c == '\n' || c.is_ascii_graphic() || c == ' ' {
                c
            } else {
                '?'
            }
        })
        .collect()
}

fn status_word(s: Status) -> &'static str {
    match s {
        Status::Draft => "draft",
        Status::Active => "active",
        Status::NeedsRetest => "needs retest",
        Status::Retired => "retired",
    }
}

fn vendor_word(v: &VendorFact) -> String {
    match v {
        VendorFact::Unavailable => "unreadable".to_owned(),
        VendorFact::NoAdapter => "no adapter".to_owned(),
        VendorFact::Known(GpuVendor::Amd) => "AMD".to_owned(),
        VendorFact::Known(GpuVendor::Nvidia) => "NVIDIA".to_owned(),
        VendorFact::Known(GpuVendor::Intel) => "Intel".to_owned(),
        VendorFact::Known(GpuVendor::Other(id)) => format!("vendor 0x{id:04X}"),
    }
}

fn arch_word(a: &ArchFact) -> String {
    match a {
        ArchFact::Known(id) => id.as_str().to_owned(),
        ArchFact::Unknown => "architecture not in the table".to_owned(),
        ArchFact::Unavailable | ArchFact::NoAdapter => "architecture unknown".to_owned(),
    }
}

fn check_word(c: &Check) -> &'static str {
    match c {
        Check::Ok => "ok",
        Check::Narrowed => "narrowed by the game",
        Check::Reset { .. } => "changed after the start",
        Check::ExitedEarly => "the process ended early",
        Check::Failed { .. } => "failed",
    }
}

/// The facts of a report for `app_id` (module docs).
fn facts(g: &Guarded<'_>, app_id: u32) -> Facts {
    let sys = g.env().sys;
    let profile = hw::read(sys, GpuArchTable::builtin().ok());
    let os = profile
        .os
        .as_ref()
        .map_or_else(|_| "unreadable".to_owned(), ToString::to_string);
    let cpu = profile.cpu.as_ref().map_or_else(
        |_| "unreadable".to_owned(),
        |c| {
            format!(
                "{} logical, {} cores, {} L3 groups",
                c.logical_count(),
                c.core_count(),
                c.llc_count()
            )
        },
    );
    let gpus = profile
        .gpu_facts()
        .iter()
        .filter(|f| !matches!(f.vendor, VendorFact::NoAdapter))
        .map(|f| format!("{} {}", vendor_word(&f.vendor), arch_word(&f.arch)))
        .collect();
    let (index, topos) = match index_state(g.app()) {
        IndexState::None => ("none".to_owned(), Vec::new()),
        IndexState::Refused(_) => ("refused".to_owned(), Vec::new()),
        IndexState::Current(c) => (
            format!("seq {}", c.seq()),
            c.topos()
                .iter()
                .filter(|t| t.matches.steam_appid == Some(app_id))
                .map(|t| format!("{} rev {} ({})", t.id, t.rev, status_word(t.status)))
                .collect(),
        ),
    };
    let mut variants: Vec<String> = Vec::new();
    let mut last_start = "none recorded".to_owned();
    if let Some(app) = g.app() {
        match journal(app, Heads::Open) {
            Err(_) => variants.push("journal unreadable".to_owned()),
            Ok(j) => {
                for st in j.status.txns.iter().filter(|st| !st.is_settled()) {
                    let Some(p) = head(st) else { continue };
                    let ours = p
                        .roots
                        .iter()
                        .any(|r| r.steam.as_ref().is_some_and(|(a, _)| *a == app_id));
                    if ours {
                        for v in &p.variants {
                            if !variants.contains(v) {
                                variants.push(v.clone());
                            }
                        }
                    }
                }
                if let Ok(Some(r)) = &j.launch {
                    let lines = launch_lines(r, &j.holders);
                    if let Some(l) = launch_of(&lines, app_id) {
                        last_start = match &l.result {
                            Err(_) => "result unreadable".to_owned(),
                            Ok(res) => match &res.outcome {
                                Outcome::Applied { check, .. } => {
                                    format!("rule applied, check {}", check_word(check))
                                }
                                Outcome::Skipped { reason, .. } => {
                                    format!("rule not applied ({})", reason.name())
                                }
                            },
                        };
                    }
                }
            }
        }
    }
    Facts {
        os,
        index,
        topos,
        variants,
        gpus,
        cpu,
        last_start,
    }
}

/// The report for `app_id` (module docs): the lists cut until the URL fits.
pub fn report(g: &Guarded<'_>, app_id: u32) -> Result<Report, OpenRefusal> {
    report_of(app_id, &facts(g, app_id))
}

/// The report of `f`: the longest list loses an entry until the URL fits.
fn report_of(app_id: u32, f: &Facts) -> Result<Report, OpenRefusal> {
    let title = format!("Problem with Steam app {app_id}");
    // Each list's cap, never above its length (a cut must shorten the text).
    let mut n = [
        MAX_TOPOS.min(f.topos.len()),
        MAX_VARIANTS.min(f.variants.len()),
        MAX_GPUS.min(f.gpus.len()),
    ];
    loop {
        let body = ascii(&body(app_id, f, n));
        match OpenUrl::issue(&title, &body) {
            Ok(url) => return Ok(Report { title, body, url }),
            Err(OpenRefusal::TooLong) if n.iter().any(|k| *k > 0) => {
                // The list with the most entries shown loses one first.
                if let Some(k) = n.iter_mut().max() {
                    *k -= 1;
                }
            }
            Err(e) => return Err(e),
        }
    }
}

/// Rerun's folder: its path, and whether it exists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataFolder {
    /// The canonical path (of the open folder, or where it would be).
    pub path: RootPath,
    /// It exists (the guard opened it).
    pub exists: bool,
}

/// Rerun's folder (nothing is created).
pub fn data_folder(g: &Guarded<'_>) -> Result<DataFolder, RootError> {
    match g.app() {
        Some(app) => Ok(DataFolder {
            path: app.path().clone(),
            exists: true,
        }),
        None => Ok(DataFolder {
            path: AppDir::path_of(g.env().sys)?,
            exists: false,
        }),
    }
}

/// Why a link or the folder was not opened.
#[derive(Debug, thiserror::Error)]
pub enum OpenError {
    /// Rerun does not open it.
    #[error(transparent)]
    Refused(OpenRefusal),
    /// The shell failed.
    #[error(transparent)]
    Shell(SysError),
}

/// Hands `u` to the user's browser.
pub fn open_url(shell: &dyn Shell, u: &OpenUrl) -> Result<(), OpenError> {
    shell.open_url(u).map_err(OpenError::Shell)
}

/// Shows Rerun's folder in Explorer, only if it exists (never created).
pub fn open_data_folder(g: &Guarded<'_>, shell: &dyn Shell) -> Result<(), OpenError> {
    let app = g.app().ok_or(OpenError::Refused(OpenRefusal::NoAppDir))?;
    shell
        .open_folder(&OpenFolder::app_dir(app))
        .map_err(OpenError::Shell)
}

// The tests import a signed index, which needs the published test key (`test-key`, as for
// `packages_tests.rs`; the workspace run has it).
#[cfg(test)]
#[cfg(feature = "test-key")]
#[path = "open_tests.rs"]
mod tests;
