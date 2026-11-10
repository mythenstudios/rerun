//! Windows Firewall, read side (ADR 0023 §6, §8 outcome A, §12; P4-5a).
//!
//! A standard user can read the rule collection (measured, docs/09 "Firewall read as a
//! standard user", A4 S5), so the CLI observes rules itself. [`Firewall::select`] is **one**
//! enumeration of the whole collection (A4 S11): `keep` sees each rule's name and grouping and
//! decides whether its full facts are read. Callers that need several rules (a batch, the
//! orphan listing) select them in one call; `policy::firewall` never enumerates per op.
//!
//! `sys` is "dumb and honest" (ADR 0004): the facts are what the firewall returns, without
//! interpretation. A `NULL` string is the empty string; text that is not valid UTF-16 is
//! converted lossily (U+FFFD), which `policy::firewall` never produces in a rule of its own.
//! Direction, action, profiles and protocol stay raw numbers; the constants below name the
//! values Rerun uses (`netfw.h`, pinned against `windows-sys` by a test in `sys::win`).
//!
//! The write side ([`FirewallWrite`]: add, remove; P4-2d with the fake, P4-5b on Windows) is
//! reached only by the elevated helper through `policy::firewall`.

use super::SysResult;

/// `NET_FW_RULE_DIR_IN`.
pub const DIR_IN: i32 = 1;
/// `NET_FW_RULE_DIR_OUT`.
pub const DIR_OUT: i32 = 2;
/// `NET_FW_ACTION_BLOCK`.
pub const ACTION_BLOCK: i32 = 0;
/// `NET_FW_ACTION_ALLOW`.
pub const ACTION_ALLOW: i32 = 1;
/// `NET_FW_PROFILE2_ALL`.
pub const PROFILES_ALL: i32 = 0x7FFF_FFFF;
/// `NET_FW_IP_PROTOCOL_ANY`.
pub const PROTOCOL_ANY: i32 = 256;

/// More rules than this in one enumeration is `TooLarge`, never a truncated list (a machine can
/// hold 10^4 to 10^5 rules, ADR 0023 §6).
pub const MAX_RULES: usize = 200_000;
/// Longest text of one rule field in UTF-16 units; a longer one is `TooLarge`.
pub const MAX_TEXT_UTF16: usize = 1 << 20;

/// The facts of one rule (`INetFwRule`, `INetFwRule2`, `INetFwRule3`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FwRule {
    /// `Name`.
    pub name: String,
    /// `Description`.
    pub description: String,
    /// `Grouping`.
    pub grouping: String,
    /// `ApplicationName`: the program path as stored (built-in rules use `%SystemRoot%`).
    pub program: String,
    /// `Direction` (`NET_FW_RULE_DIRECTION`).
    pub direction: i32,
    /// `Action` (`NET_FW_ACTION`).
    pub action: i32,
    /// `Profiles` (bit mask of `NET_FW_PROFILE_TYPE2`).
    pub profiles: i32,
    /// `Protocol` (IANA number, 256 = any).
    pub protocol: i32,
    /// `Enabled`.
    pub enabled: bool,
    /// Every other field (A4 S6 d).
    pub rest: FwRest,
}

/// The fields of a rule beyond those [`policy::firewall`](crate::policy::firewall) sets: a rule
/// of Rerun's form leaves each at the firewall's default.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FwRest {
    /// `ServiceName`.
    pub service: String,
    /// `LocalPorts`.
    pub local_ports: String,
    /// `RemotePorts`.
    pub remote_ports: String,
    /// `LocalAddresses`.
    pub local_addresses: String,
    /// `RemoteAddresses`.
    pub remote_addresses: String,
    /// `IcmpTypesAndCodes`.
    pub icmp_types: String,
    /// `InterfaceTypes`.
    pub interface_types: String,
    /// `Interfaces` is set (a `VARIANT` other than `VT_EMPTY`); the list itself is not read.
    pub interfaces: bool,
    /// `EdgeTraversal`.
    pub edge_traversal: bool,
    /// `INetFwRule2::EdgeTraversalOptions`; `None` if the rule has no `INetFwRule2`.
    pub edge_options: Option<i32>,
    /// The `INetFwRule3` fields; `None` if the rule has no `INetFwRule3`.
    pub v3: Option<FwRule3>,
}

/// `INetFwRule3`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FwRule3 {
    /// `LocalAppPackageId`.
    pub package_id: String,
    /// `LocalUserOwner`.
    pub user_owner: String,
    /// `LocalUserAuthorizedList`.
    pub local_users: String,
    /// `RemoteUserAuthorizedList`.
    pub remote_users: String,
    /// `RemoteMachineAuthorizedList`.
    pub remote_machines: String,
    /// `SecureFlags`.
    pub secure_flags: i32,
}

/// The result of one enumeration.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FwSelection {
    /// Every rule enumerated.
    pub total: usize,
    /// The full facts of the rules `keep` chose, in enumeration order.
    pub rules: Vec<FwRule>,
}

/// The firewall's rules, read side (ADR 0023 §12).
pub trait Firewall: Send + Sync {
    /// One enumeration of every rule; `keep(name, grouping)` decides per rule whether its full
    /// facts are read and returned.
    ///
    /// # Errors
    /// The firewall cannot be read (COM, the firewall service), more than [`MAX_RULES`] rules
    /// or a field longer than [`MAX_TEXT_UTF16`] (`TooLarge`), the process environment does not
    /// name the Windows folder (A4 S10, `sys::win`).
    fn select(&self, keep: &dyn Fn(&str, &str) -> bool) -> SysResult<FwSelection>;
}

/// The firewall's write side (ADR 0023 §6, §12): the elevated helper's alone, reached only
/// through `policy::firewall` (`HelperSystem::firewall_write`). The fake's rules as data
/// (P4-2d), the real one `sys::win::WinFirewallWrite` (`INetFwRules::Add`, `Remove`; P4-5b).
pub trait FirewallWrite: Send + Sync {
    /// Adds `rule` (`INetFwRules::Add`).
    ///
    /// # Errors
    /// The firewall refuses the rule or cannot be reached.
    fn add(&self, rule: &FwRule) -> SysResult<()>;

    /// Removes **every** rule of the name `name` (`INetFwRules::Remove`; the design assumes
    /// the worst, ADR 0023 §6, R10: the caller counts first).
    ///
    /// # Errors
    /// The firewall refuses or cannot be reached.
    fn remove_named(&self, name: &str) -> SysResult<()>;
}

#[cfg(test)]
mod tests {
    use super::{Firewall, FirewallWrite};

    #[test]
    fn firewall_is_an_object_safe_send_sync_trait() {
        fn assert_send_sync<T: ?Sized + Send + Sync>() {}
        assert_send_sync::<dyn Firewall>();
        assert_send_sync::<dyn FirewallWrite>();
    }
}
