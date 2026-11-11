//! The state of Smart App Control (P4-10, `laa_patch`; user decision of 2026-11-10 after the
//! [DEV] measurement, a warning instead of a refusal since P4-13): `HKLM\SYSTEM\CurrentControlSet\Control\CI\Policy`
//! `VerifiedAndReputablePolicyState` in the native view, read through the read-only
//! [`Registry::get`] (ADR 0009). Microsoft documents the values 0 (off), 1 (on, enforcing) and 2
//! (evaluation) ("Test App Signatures with Smart App Control"). The value is absent where Smart
//! App Control does not exist (Windows 10, early Windows 11): off, also when the key is missing.
//! Any other value or type, or another failed read, is [`SacState::Unknown`]. Display and a
//! planning warning only, never authorisation.

use crate::sys::registry::{Hive, RegKey, RegValue, RegView, Registry};

/// The key below `HKLM`.
pub(crate) const CI_POLICY: &str = r"SYSTEM\CurrentControlSet\Control\CI\Policy";
/// The value (`REG_DWORD`).
pub(crate) const STATE_VALUE: &str = "VerifiedAndReputablePolicyState";

/// Smart App Control as read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SacState {
    /// Off, or not present on this Windows.
    Off,
    /// On: it blocks files without a cloud verdict and without a valid signature.
    Enforce,
    /// Evaluation: it blocks nothing now, but Windows may switch it on later.
    Evaluation,
    /// The value could not be read or has no documented meaning.
    Unknown,
}

/// Reads the state.
pub(crate) fn read(registry: &dyn Registry) -> SacState {
    let key = RegKey::new(Hive::LocalMachine, RegView::Native, CI_POLICY);
    match registry.get(&key, STATE_VALUE) {
        Ok(None) => SacState::Off,
        Err(e) if e.kind == crate::sys::SysErrorKind::NotFound => SacState::Off,
        Ok(Some(RegValue::Dword(0))) => SacState::Off,
        Ok(Some(RegValue::Dword(1))) => SacState::Enforce,
        Ok(Some(RegValue::Dword(2))) => SacState::Evaluation,
        Ok(Some(_)) | Err(_) => SacState::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::{CI_POLICY, STATE_VALUE, SacState, read};
    use crate::sys::System;
    use crate::sys::fake::FakeSystem;
    use crate::sys::registry::{Hive, RegKey, RegValue, RegView};

    fn with(v: Option<RegValue>) -> SacState {
        let key = RegKey::new(Hive::LocalMachine, RegView::Native, CI_POLICY);
        let mut b = FakeSystem::builder().key(key.clone());
        if let Some(v) = v {
            b = b.value(key, STATE_VALUE, v);
        }
        read(b.build().unwrap().registry())
    }

    #[test]
    fn every_documented_value_and_the_rest() {
        assert_eq!(with(None), SacState::Off);
        assert_eq!(
            read(FakeSystem::builder().build().unwrap().registry()),
            SacState::Off
        );
        assert_eq!(with(Some(RegValue::Dword(0))), SacState::Off);
        assert_eq!(with(Some(RegValue::Dword(1))), SacState::Enforce);
        assert_eq!(with(Some(RegValue::Dword(2))), SacState::Evaluation);
        assert_eq!(with(Some(RegValue::Dword(3))), SacState::Unknown);
        assert_eq!(
            with(Some(RegValue::String("1".to_owned()))),
            SacState::Unknown
        );
    }
}
