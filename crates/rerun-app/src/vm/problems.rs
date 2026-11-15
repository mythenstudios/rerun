//! Problem states (P5-6b, ADR 0027 amendment P5-6b): the calm band on every page that says how
//! many changes need the user, what an undo reports per change, and the firewall rules no change
//! owns. Display only: nothing here acts, and the band never starts a recovery by itself (ADR
//! 0019, rules 1 and 5).

use rerun_core::escape::{self, Shown};
use rerun_core::exec::{Backup, OldSeen, OrphanRule, OrphansError, RevertReport};
use rerun_core::journal::{Observed, TxnId};

use super::{AppliedVm, DetailVm, OpVm, shown_error};
use crate::text::{Lang, Msg, t};

fn tx(lang: Lang, m: Msg) -> String {
    t(lang, m).into_owned()
}

// ---------- the band ----------

/// The band above every page: how many changes need the user. It names the transactions it is
/// about, so a dismissal holds only for those (a new problem shows it again).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttentionVm {
    /// How many changes.
    pub count: usize,
    /// "N changes need you".
    pub title: String,
    /// What Rerun does and does not do.
    pub body: String,
    /// The button to the Applied page.
    pub action: String,
    /// The transactions it counts.
    pub txns: Vec<TxnId>,
}

/// The band for the Applied page's cards: only a card with a problem counts (interrupted,
/// undo interrupted, cleanup pending, needs you, damaged, unreadable); an applied card alone
/// never does. `None`: nothing needs the user.
pub fn attention(a: &AppliedVm, lang: Lang) -> Option<AttentionVm> {
    let txns: Vec<TxnId> = a
        .cards
        .iter()
        .filter(|c| c.problem.is_some())
        .map(|c| c.txn)
        .collect();
    if txns.is_empty() {
        return None;
    }
    let count = txns.len();
    Some(AttentionVm {
        count,
        title: tx(lang, Msg::AttentionTitle { count }),
        body: tx(lang, Msg::AttentionBody),
        action: tx(lang, Msg::AttentionView),
        txns,
    })
}

/// Whether the band is shown given what the user dismissed this session: any counted
/// transaction that was not dismissed shows it.
pub fn attention_shown(a: &AttentionVm, dismissed: &[TxnId]) -> bool {
    a.txns.iter().any(|t| !dismissed.contains(t))
}

// ---------- the report of an undo ----------

fn own(lang: Lang, m: Msg) -> Shown<'static> {
    escape::text(&tx(lang, m)).into_owned()
}

fn target_of(ops: &[OpVm], op: u16) -> Shown<'static> {
    ops.iter()
        .find(|o| o.index == usize::from(op))
        .map(|o| o.target.clone())
        .unwrap_or_else(|| escape::text("").into_owned())
}

/// What an undo did beyond closing, per change, in Rerun's words with the target of the change
/// (`ops`: the transaction's ops as its head lists them): a change where only Rerun's part was
/// set back, one someone else changed (left as found, where the old state stays), one left to a
/// later change, every `.old` that is still in use, kept or not Rerun's, and launch profiles set
/// back in another folder. Nothing for a change that went back as expected.
pub fn report_details(rep: &RevertReport, ops: &[OpVm], lang: Lang) -> Vec<DetailVm> {
    let mut out = Vec::new();
    let mut add = |who: Shown<'static>, what: Shown<'static>| {
        out.push(DetailVm {
            who: Some(who),
            what,
        });
    };
    for o in &rep.ops {
        let target = || target_of(ops, o.op);
        match o.observed {
            Observed::Before | Observed::After => {}
            Observed::Drifted => add(own(lang, Msg::ReportDrifted), target()),
            Observed::Kept => add(own(lang, Msg::ReportKept), target()),
            Observed::Foreign => {
                add(own(lang, Msg::ReportForeign), target());
                match &o.backup {
                    Some(Backup::Bin { path, .. }) => {
                        add(own(lang, Msg::HistoryBackupsIn), path.clone());
                    }
                    Some(Backup::Inline) => add(
                        own(lang, Msg::ReportForeignInline),
                        escape::text("").into_owned(),
                    ),
                    None => {}
                }
            }
        }
    }
    for p in &rep.cleanup {
        let m = match p.seen {
            OldSeen::InUse => Msg::ReportOldInUse,
            OldSeen::Kept => Msg::ReportOldKept,
            OldSeen::Foreign => Msg::ReportOldForeign,
            OldSeen::Gone | OldSeen::Ours | OldSeen::Deleted => continue,
        };
        add(own(lang, m), escape::path(p.path.as_str()).into_owned());
    }
    if let Some(pm) = &rep.profiles_moved {
        add(own(lang, Msg::ReportProfilesMoved), pm.now.clone());
    }
    out
}

// ---------- orphaned firewall rules ----------

/// One rule no change of this account owns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrphanRuleVm {
    /// Its name (escaped).
    pub name: Shown<'static>,
    /// Its program (escaped).
    pub program: Shown<'static>,
}

/// The System page's section "Firewall rules of Rerun without a change". Shown only when there
/// are rules, or when they cannot be listed.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct OrphansVm {
    /// The section is shown.
    pub shown: bool,
    /// Its heading.
    pub title: String,
    /// What the rules are and how to remove them (Rerun never removes them without admin).
    pub hint: String,
    /// The label of a rule's program.
    pub program_label: String,
    /// The rules.
    pub rules: Vec<OrphanRuleVm>,
    /// Why there is no list.
    pub note: Option<String>,
    /// The core's text for it (escaped).
    pub detail: Option<Shown<'static>>,
}

/// The section from the firewall read; `None`: Rerun's folder does not exist, so no change of
/// this account can own a rule and nothing is read.
pub fn orphans(r: Option<&Result<Vec<OrphanRule>, OrphansError>>, lang: Lang) -> OrphansVm {
    let base = || OrphansVm {
        title: tx(lang, Msg::OrphansTitle),
        hint: tx(lang, Msg::OrphansHint),
        program_label: tx(lang, Msg::OrphansProgram),
        ..OrphansVm::default()
    };
    match r {
        None => OrphansVm::default(),
        Some(Ok(v)) if v.is_empty() => OrphansVm::default(),
        Some(Ok(v)) => OrphansVm {
            shown: true,
            rules: v
                .iter()
                .map(|r| OrphanRuleVm {
                    name: r.name.clone(),
                    program: r.program.clone(),
                })
                .collect(),
            ..base()
        },
        Some(Err(e)) => OrphansVm {
            shown: true,
            note: Some(tx(
                lang,
                if matches!(e, OrphansError::Journal(_)) {
                    Msg::OrphansNoJournal
                } else {
                    Msg::OrphansUnreadable
                },
            )),
            detail: Some(shown_error(e)),
            ..base()
        },
    }
}
