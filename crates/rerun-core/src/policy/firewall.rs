//! Rerun's own firewall rules (ADR 0023 §5, §6; A4 S6, S11, N6; P4-5a): the one rule form that
//! planner, preview, helper and observation share, and the observation of planned rules.
//!
//! **The form** ([`rule`]): name `Rerun - <topo-id> - <txn>-<op:03>` ([`RuleName`], ASCII, R10),
//! group [`GROUP`], description `Added by Rerun for <topo-id>; removed by rerun revert <txn>`,
//! the direction of the Topo step (today only `out`), action block, all profiles, any protocol,
//! enabled, program = a [`Program`], every other field at the firewall's default ([`rest`]).
//!
//! **The program** (A4 S6 a, b): the path as the request or the journal head spells it, never
//! the spelling a handle reports; compared with ASCII case ignored with what the firewall returns, so a
//! case-only rename between plan and apply does not make Rerun's rule `Foreign`. A `%` is
//! refused (the firewall expands environment variables in `ApplicationName`; built-in rules use
//! `%SystemRoot%`), as is U+FFFD (what `sys` reads for text that is no valid UTF-16). At most
//! [`MAX_PROGRAM_CHARS`]: a drive and a [`RelPath`]. The firewall's own limit is measured with
//! the write contract (P4-5b); this bound stays below `MAX_PATH`.
//!
//! **Observation** ([`observe_all`], A4 S11): one enumeration for any number of planned rules.
//! A rule whose name equals a planned name **folded** counts as that name (until the P4-5b
//! write contract shows how `INetFwRules::Remove` compares names, A4 S6 c, the wider match is
//! the safe one): none is [`Observed::Before`]; exactly one with the exact name and every fact
//! equal is [`Observed::After`]; anything else (two or more, another group, a fact changed,
//! disabled) is [`Observed::Foreign`] and never touched (ADR 0020 D10).
//!
//! **Orphans** (ADR 0023 §6, A4 N6): [`rerun_rules`] selects every rule of group `Rerun` or of
//! Rerun's name form in one enumeration, [`orphans`] keeps those no open transaction of this
//! account names. The firewall is machine-wide, so the list includes the Rerun rules of other
//! Windows accounts on the PC; the wording says so (ADR 0023 §6).

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::catalog::model::Id;
use crate::fold::fold;
use crate::journal::TxnId;
use crate::path::{RelPath, RootPath};
use crate::sys::firewall::{
    ACTION_BLOCK, DIR_OUT, FwRest, FwRule, FwRule3, PROFILES_ALL, PROTOCOL_ANY,
};
use crate::sys::{Firewall, SysResult};

/// The group (`Grouping`) of every Rerun rule.
pub const GROUP: &str = "Rerun";
/// The start of every Rerun rule name.
pub const NAME_PREFIX: &str = "Rerun - ";
/// The longest program path: a drive (`X:\`) and a [`RelPath`].
pub const MAX_PROGRAM_CHARS: usize = 3 + RelPath::MAX_LEN;

/// The direction a `firewall_rule` step blocks. Only `out` for now (lead decision after the
/// P4-5a review): `in` can be added without a format break when a Topo needs it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    /// Outbound (the game cannot connect).
    Out,
}

impl Direction {
    /// `NET_FW_RULE_DIRECTION`.
    pub fn raw(self) -> i32 {
        match self {
            Self::Out => DIR_OUT,
        }
    }

    /// The word of the format.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Out => "out",
        }
    }
}

/// A Rerun rule name: `Rerun - <topo-id> - <txn>-<op:03>`. One written form; [`Self::parse`]
/// accepts only that form.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RuleName {
    name: String,
    topo: Id,
    txn: TxnId,
    op: u16,
}

impl RuleName {
    /// The name of op `op` of transaction `txn` for `topo`.
    pub fn derive(topo: &Id, txn: &TxnId, op: u16) -> Self {
        Self {
            name: format!("{NAME_PREFIX}{} - {txn}-{op:03}", topo.as_str()),
            topo: topo.clone(),
            txn: *txn,
            op,
        }
    }

    /// Exactly the form [`Self::derive`] writes; `None` otherwise.
    pub fn parse(s: &str) -> Option<Self> {
        let rest = s.strip_prefix(NAME_PREFIX)?;
        let (topo, tail) = rest.split_once(" - ")?;
        let (txn, op) = tail.rsplit_once('-')?;
        if !op.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let n = Self::derive(
            &Id::parse(topo)?,
            &TxnId::from_str(txn).ok()?,
            op.parse().ok()?,
        );
        (n.name == s).then_some(n)
    }

    /// The name.
    pub fn as_str(&self) -> &str {
        &self.name
    }

    /// The Topo.
    pub fn topo(&self) -> &Id {
        &self.topo
    }

    /// The transaction.
    pub fn txn(&self) -> TxnId {
        self.txn
    }

    /// The op index in the plan.
    pub fn op(&self) -> u16 {
        self.op
    }
}

impl fmt::Display for RuleName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.name)
    }
}

/// Why a path cannot be the program of a Rerun rule.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProgramError {
    /// A `%` (the firewall would expand it, A4 S6 b).
    #[error("the program path holds a '%', which the firewall would expand: {0}")]
    Percent(String),
    /// Longer than [`MAX_PROGRAM_CHARS`].
    #[error("the program path is longer than {MAX_PROGRAM_CHARS} characters: {0}")]
    TooLong(String),
    /// Not `X:\` (upper-case drive) and a relative path in its one written form, or a U+FFFD.
    #[error("the program path is not a drive path in Rerun's form: {0}")]
    Form(String),
    /// Not an `.exe`.
    #[error("the program is not an .exe: {0}")]
    NotExe(String),
}

/// The program of a Rerun rule (module docs, A4 S6 a, b).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Program(String);

impl Program {
    /// The executable `exe` of the game folder `root`, spelled as the plan spells both.
    ///
    /// # Errors
    /// See [`Self::parse`].
    pub fn new(root: &RootPath, exe: &RelPath) -> Result<Self, ProgramError> {
        Self::parse(&format!("{root}\\{}", exe.as_str()))
    }

    /// A program path as recorded (the request, the journal head).
    ///
    /// # Errors
    /// [`ProgramError`].
    pub fn parse(s: &str) -> Result<Self, ProgramError> {
        let shown = || crate::escape::path(s).to_string();
        if s.contains('%') {
            return Err(ProgramError::Percent(shown()));
        }
        if s.chars().count() > MAX_PROGRAM_CHARS {
            return Err(ProgramError::TooLong(shown()));
        }
        let b = s.as_bytes();
        let drive = b.len() > 3 && b[0].is_ascii_uppercase() && b[1] == b':' && b[2] == b'\\';
        let rest = s.get(3..).unwrap_or_default();
        let one_form = RelPath::parse(rest).is_ok_and(|r| r.as_str() == rest);
        if !drive || !one_form || s.contains('\u{FFFD}') {
            return Err(ProgramError::Form(shown()));
        }
        if !fold(s).ends_with(".EXE") {
            return Err(ProgramError::NotExe(shown()));
        }
        Ok(Self(s.to_owned()))
    }

    /// The path.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// `other` names this program: equal with ASCII case ignored (A4 S6 a; no Unicode folding,
    /// which would equate names NTFS keeps apart, e.g. U+0131 and `I`).
    pub fn names(&self, other: &str) -> bool {
        self.0.eq_ignore_ascii_case(other)
    }
}

/// The fields a Rerun rule leaves at the firewall's default (A4 S6 d), as `sys` reads them back:
/// both address lists `*`, interface types `All`, everything else empty, zero or off. Taken
/// from a fresh `HNetCfg.FWRule` object (`a_fresh_rule_object_has_the_default_rest` in
/// `sys::win::firewall`); that an added rule reads back the same is the P4-5b write contract.
pub fn rest() -> FwRest {
    FwRest {
        local_addresses: "*".to_owned(),
        remote_addresses: "*".to_owned(),
        interface_types: "All".to_owned(),
        edge_options: Some(0),
        v3: Some(FwRule3::default()),
        ..FwRest::default()
    }
}

/// Rerun's rule for op `op` of transaction `txn` of `topo` (module docs).
pub fn rule(topo: &Id, txn: &TxnId, op: u16, program: &Program, direction: Direction) -> FwRule {
    FwRule {
        name: RuleName::derive(topo, txn, op).name,
        description: format!(
            "Added by Rerun for {}; removed by rerun revert {txn}",
            topo.as_str()
        ),
        grouping: GROUP.to_owned(),
        program: program.as_str().to_owned(),
        direction: direction.raw(),
        action: ACTION_BLOCK,
        profiles: PROFILES_ALL,
        protocol: PROTOCOL_ANY,
        enabled: true,
        rest: rest(),
    }
}

/// What the firewall holds for a planned rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Observed {
    /// No rule of that name.
    Before,
    /// Exactly one, Rerun's, every fact as planned.
    After,
    /// Anything else: never touched.
    Foreign,
}

/// `found` is exactly `expected`: the exact name, the program with ASCII case ignored, every
/// other fact equal.
fn is_ours(expected: &FwRule, found: &FwRule) -> bool {
    found.name == expected.name
        && found.program.eq_ignore_ascii_case(&expected.program)
        && FwRule {
            program: String::new(),
            ..found.clone()
        } == FwRule {
            program: String::new(),
            ..expected.clone()
        }
}

/// Classifies `expected` against the rules of one selection.
fn classify(expected: &FwRule, rules: &[FwRule]) -> Observed {
    let name = fold(&expected.name);
    let mut same = rules.iter().filter(|r| fold(&r.name) == name);
    match (same.next(), same.next()) {
        (None, _) => Observed::Before,
        (Some(r), None) if is_ours(expected, r) => Observed::After,
        _ => Observed::Foreign,
    }
}

/// Observes every rule of `expected` in **one** enumeration (A4 S11); none for an empty list.
///
/// # Errors
/// The error of [`Firewall::select`].
pub fn observe_all(fw: &dyn Firewall, expected: &[FwRule]) -> SysResult<Vec<Observed>> {
    if expected.is_empty() {
        return Ok(Vec::new());
    }
    let names: Vec<String> = expected.iter().map(|r| fold(&r.name)).collect();
    let sel = fw.select(&|n, _| names.contains(&fold(n)))?;
    Ok(expected.iter().map(|e| classify(e, &sel.rules)).collect())
}

/// [`observe_all`] for one rule.
///
/// # Errors
/// The error of [`Firewall::select`].
pub fn observe(fw: &dyn Firewall, expected: &FwRule) -> SysResult<Observed> {
    let mut v = observe_all(fw, std::slice::from_ref(expected))?;
    Ok(v.pop().unwrap_or(Observed::Before))
}

/// Every rule of group `Rerun` (folded) or of Rerun's name form, in one enumeration.
///
/// # Errors
/// The error of [`Firewall::select`].
pub fn rerun_rules(fw: &dyn Firewall) -> SysResult<Vec<FwRule>> {
    let group = fold(GROUP);
    Ok(fw
        .select(&|n, g| fold(g) == group || RuleName::parse(n).is_some())?
        .rules)
}

/// The rules of `rules` that no name of `owned` (the planned rules of this account's open
/// transactions) names, compared folded (ADR 0023 §6, A4 N6).
pub fn orphans<'r>(rules: &'r [FwRule], owned: &[RuleName]) -> Vec<&'r FwRule> {
    let owned: Vec<String> = owned.iter().map(|n| fold(n.as_str())).collect();
    rules
        .iter()
        .filter(|r| !owned.contains(&fold(&r.name)))
        .collect()
}

#[cfg(test)]
mod tests;
