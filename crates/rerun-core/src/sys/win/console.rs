//! The one console call of `rerun.exe` beyond what `std` does (P2-13, security review N4):
//! [`discard_console_input`] drops keystrokes typed ahead into the console's input buffer right
//! before `rerun` asks for a confirmation, so a `y` typed earlier (or pasted with the command)
//! never answers a question the user has not seen. It changes no console mode and no code page
//! (ADR 0016: the console is left as found; `SetConsoleMode` and friends stay banned).

#![allow(
    unsafe_code,
    reason = "FFI to GetStdHandle and FlushConsoleInputBuffer; every block has a SAFETY comment"
)]

use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
use windows_sys::Win32::System::Console::{
    FlushConsoleInputBuffer, GetStdHandle, STD_INPUT_HANDLE,
};

/// Discards the pending input events of this process's console input buffer, best effort: no
/// console, a redirected stdin or a failing call changes nothing and is not reported (the
/// caller asks only when stdin is a console).
pub fn discard_console_input() {
    // SAFETY: GetStdHandle takes a constant and returns the process's standard input handle,
    // a pseudo-owned handle of the process that must not be closed; it is borrowed for the
    // next call only and never closed here (no ownership, so no RAII wrapper is needed).
    let h = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
    if h.is_null() || h == INVALID_HANDLE_VALUE {
        return;
    }
    // SAFETY: `h` is the standard input handle just returned (not null, not invalid); it stays
    // open for the life of the process. FlushConsoleInputBuffer only discards queued input
    // records and fails harmlessly (returns 0) if `h` is no console input handle.
    let _ = unsafe { FlushConsoleInputBuffer(h) };
}
