//! The elevated helper's own token (ADR 0023 §3, §12).
//!
//! [`HelperToken`] is what `elevate::serve` asks about its own process before it reads
//! anything: drop every privilege it does not need (§3 step 2) and check that it runs elevated
//! (§3 step 3). The real one is `sys::win::WinHelperToken`, the fake one
//! `sys::fake::FakeHelperToken`. Only the helper uses it; the CLI and the GUI never drop
//! privileges (they never have any worth dropping, core rule 6).
//!
//! P4-2a has these two calls only; `own_image` (§3 step 4, the helper's image check) follows
//! with `sd_facts` and `open_by_id` in P4-2b, and the trait becomes part of `HelperSystem` in
//! P4-2c (§11, §15).

use super::SysResult;

/// The helper's own process token (ADR 0023 §3, §12).
pub trait HelperToken: Send + Sync {
    /// Removes every privilege of the process token except `SeChangeNotifyPrivilege`
    /// (`SE_PRIVILEGE_REMOVED`, so none can be enabled again), then reads the token back:
    /// any privilege left besides that one is an error (fail closed).
    ///
    /// # Errors
    /// The token cannot be opened, adjusted or read back, or a privilege is still there.
    fn drop_privileges(&self) -> SysResult<()>;

    /// Whether the process token is elevated (`TokenElevation`).
    ///
    /// # Errors
    /// The token cannot be read.
    fn is_elevated(&self) -> SysResult<bool>;
}

#[cfg(test)]
mod tests {
    use super::HelperToken;

    #[test]
    fn helper_token_is_an_object_safe_send_sync_trait() {
        fn assert_send_sync<T: ?Sized + Send + Sync>() {}
        assert_send_sync::<dyn HelperToken>();
    }
}
