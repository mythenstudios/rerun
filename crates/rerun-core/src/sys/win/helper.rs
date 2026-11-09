//! `WinHelperToken`: the elevated helper's own token (ADR 0023 §3, §12), over `token`. No
//! `unsafe` here.
//!
//! P4-2a: `drop_privileges` and `is_elevated`. The rest of the helper's system
//! (`WinHelperSystem`: file system read side with `open_by_id`, known folders, firewall, no GPU,
//! no topology, no registry) follows in P4-2b and P4-2c. Nothing here references `WinSystem`,
//! `WinGpu`, `dxgi` or `loader`'s DLL loading: the helper links only what it uses, which the
//! import and content tests of `crates/rerun-helper/tests/hardening.rs` check.

use super::status::kind_of_win32;
use super::token;
use crate::sys::{HelperToken, SysError, SysResult};

/// The real [`HelperToken`]: the token of the current process.
#[derive(Debug, Clone, Copy, Default)]
pub struct WinHelperToken;

fn err(op: &'static str, code: u32) -> SysError {
    SysError::new(kind_of_win32(code), op).with_win32(code)
}

impl HelperToken for WinHelperToken {
    fn drop_privileges(&self) -> SysResult<()> {
        token::drop_privileges().map_err(|c| err("drop privileges of the process token", c))
    }

    fn is_elevated(&self) -> SysResult<bool> {
        token::process_elevated().map_err(|c| err("TokenElevation of the process token", c))
    }
}
