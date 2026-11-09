//! Is there a click boundary? The UAC prompt state of this machine and this token (ADR 0023
//! §10, condition R11, A4 N7).
//!
//! [`read`] gathers the facts read-only: from `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\
//! Policies\System` (native view, through [`crate::sys::Registry`]) `EnableLUA`,
//! `ConsentPromptBehaviorAdmin`, `ConsentPromptBehaviorUser`, `PromptOnSecureDesktop` and
//! `ValidateAdminCodeSignatures`, and the token kind from [`crate::sys::Elevation`]. A value
//! that is missing, of another type than `REG_DWORD` or unreadable is `None`. [`decide`] is
//! pure:
//!
//! | token | values | state |
//! |---|---|---|
//! | unreadable | | `Unknown` |
//! | elevated | | `Elevated` (the CLI refuses anyway, P2-13 E3) |
//! | not elevated | `EnableLUA` 0 | `UacOff` |
//! | not elevated | `EnableLUA` not exactly 1 | `Unknown` |
//! | filtered admin | `ConsentPromptBehaviorAdmin` 0 / 1, 3 / 2, 4, 5 / else | `NoPrompt` / `Credentials` / `Consent` / `Unknown` |
//! | standard user | `ConsentPromptBehaviorUser` 0 / anything else, also missing | `Denied` / `Credentials` (N7) |
//!
//! Only `Consent` and `Credentials` have a dialog ([`PromptState::has_dialog`]); `Unknown` is
//! treated as no dialog ("unreadable = no dialog", §10): the boundary is never assumed. The
//! secure desktop is always on for admin values 1 and 2 and user value 1, else as
//! `PromptOnSecureDesktop` says (`None` when unreadable; Windows' default is on). With
//! `ValidateAdminCodeSignatures = 1` Windows elevates only signed images: the unsigned helper
//! of phase 4 then fails to start, which the preview names (`signed_only`, N7).

use crate::sys::registry::{Hive, RegKey, RegValue, RegView};
use crate::sys::{System, TokenKind};

/// The policy key all values are read from.
pub const POLICY_KEY: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";

/// The facts [`decide`] works on (module docs). `None` = missing, not a DWORD or unreadable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PromptFacts {
    /// The token kind.
    pub token: Option<TokenKind>,
    /// `EnableLUA`.
    pub enable_lua: Option<u32>,
    /// `ConsentPromptBehaviorAdmin`.
    pub admin: Option<u32>,
    /// `ConsentPromptBehaviorUser`.
    pub user: Option<u32>,
    /// `PromptOnSecureDesktop`.
    pub secure_desktop: Option<u32>,
    /// `ValidateAdminCodeSignatures`.
    pub validate_signatures: Option<u32>,
}

/// What Windows does when the CLI starts the helper (module docs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PromptKind {
    /// A consent dialog (yes/no) for an administrator.
    Consent,
    /// A credentials dialog (an administrator's password).
    Credentials,
    /// An administrator is elevated without a dialog: the preview confirmation is the only
    /// boundary.
    NoPrompt,
    /// Standard users are denied elevation (`ConsentPromptBehaviorUser = 0`): refused before
    /// the lock.
    Denied,
    /// UAC is off (`EnableLUA = 0`): refused before the lock.
    UacOff,
    /// The process is already elevated: the CLI refuses before this matters.
    Elevated,
    /// Something could not be read or has an unknown value: treated as no dialog.
    Unknown,
}

/// The prompt state with its details.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PromptState {
    /// What happens.
    pub kind: PromptKind,
    /// For a dialog: on the secure desktop (`None` = unknown). `PromptOnSecureDesktop = 0`
    /// puts it on the user's desktop, where other processes of the user can reach it (N7).
    pub secure_desktop: Option<bool>,
    /// `ValidateAdminCodeSignatures = 1`: only signed images elevate (N7).
    pub signed_only: bool,
}

impl PromptState {
    /// A dialog the user answers is the click boundary.
    pub fn has_dialog(&self) -> bool {
        matches!(self.kind, PromptKind::Consent | PromptKind::Credentials)
    }
}

/// The pure decision of the module docs.
pub fn decide(f: &PromptFacts) -> PromptState {
    let signed_only = f.validate_signatures == Some(1);
    let state = |kind, secure_desktop| PromptState {
        kind,
        secure_desktop,
        signed_only,
    };
    let configured = match f.secure_desktop {
        Some(0) => Some(false),
        Some(1) => Some(true),
        _ => None,
    };
    let token = match f.token {
        None => return state(PromptKind::Unknown, None),
        Some(TokenKind::Elevated) => return state(PromptKind::Elevated, None),
        Some(t) => t,
    };
    match f.enable_lua {
        Some(0) => return state(PromptKind::UacOff, None),
        Some(1) => {}
        _ => return state(PromptKind::Unknown, None),
    }
    match token {
        TokenKind::Filtered => match f.admin {
            Some(0) => state(PromptKind::NoPrompt, None),
            Some(1) => state(PromptKind::Credentials, Some(true)),
            Some(2) => state(PromptKind::Consent, Some(true)),
            Some(3) => state(PromptKind::Credentials, configured),
            Some(4 | 5) => state(PromptKind::Consent, configured),
            _ => state(PromptKind::Unknown, None),
        },
        TokenKind::Standard | TokenKind::Elevated => match f.user {
            Some(0) => state(PromptKind::Denied, None),
            Some(1) => state(PromptKind::Credentials, Some(true)),
            _ => state(PromptKind::Credentials, configured),
        },
    }
}

/// The facts of this machine and process (module docs); never fails, an unreadable fact is
/// `None`.
pub fn facts(sys: &dyn System) -> PromptFacts {
    let key = RegKey::new(Hive::LocalMachine, RegView::Native, POLICY_KEY);
    let dword = |name: &str| match sys.registry().get(&key, name) {
        Ok(Some(RegValue::Dword(v))) => Some(v),
        _ => None,
    };
    PromptFacts {
        token: sys.elevation().token_kind().ok(),
        enable_lua: dword("EnableLUA"),
        admin: dword("ConsentPromptBehaviorAdmin"),
        user: dword("ConsentPromptBehaviorUser"),
        secure_desktop: dword("PromptOnSecureDesktop"),
        validate_signatures: dword("ValidateAdminCodeSignatures"),
    }
}

/// [`decide`] on [`facts`].
pub fn read(sys: &dyn System) -> PromptState {
    decide(&facts(sys))
}
