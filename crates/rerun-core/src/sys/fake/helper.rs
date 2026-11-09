//! Fake helper token (ADR 0023 §12, §14): elevated or not, each call can fail, and the calls
//! are recorded in order, so tests of `elevate::serve` see the fixed order of §3.

use std::sync::Mutex;

use crate::sys::{HelperToken, SysError, SysErrorKind, SysResult};

/// A call to [`FakeHelperToken`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenCall {
    /// [`HelperToken::drop_privileges`].
    DropPrivileges,
    /// [`HelperToken::is_elevated`].
    IsElevated,
}

/// [`HelperToken`] of a fake process: `elevated` as given; [`Self::fail`] makes one call fail
/// with `AccessDenied` from then on.
#[derive(Debug, Default)]
pub struct FakeHelperToken {
    elevated: bool,
    fail: Vec<TokenCall>,
    calls: Mutex<Vec<TokenCall>>,
}

impl FakeHelperToken {
    /// A token that is elevated (or not).
    #[must_use]
    pub fn new(elevated: bool) -> Self {
        Self {
            elevated,
            ..Self::default()
        }
    }

    /// `call` fails with `AccessDenied` from now on.
    #[must_use]
    pub fn fail(mut self, call: TokenCall) -> Self {
        self.fail.push(call);
        self
    }

    /// The calls so far, in order.
    pub fn calls(&self) -> Vec<TokenCall> {
        self.calls
            .lock()
            .map_or_else(|p| p.into_inner().clone(), |c| c.clone())
    }

    fn call(&self, call: TokenCall) -> SysResult<()> {
        match self.calls.lock() {
            Ok(mut c) => c.push(call),
            Err(p) => p.into_inner().push(call),
        }
        if self.fail.contains(&call) {
            return Err(SysError::new(
                SysErrorKind::AccessDenied,
                "fake helper token",
            ));
        }
        Ok(())
    }
}

impl HelperToken for FakeHelperToken {
    fn drop_privileges(&self) -> SysResult<()> {
        self.call(TokenCall::DropPrivileges)
    }

    fn is_elevated(&self) -> SysResult<bool> {
        self.call(TokenCall::IsElevated).map(|()| self.elevated)
    }
}
