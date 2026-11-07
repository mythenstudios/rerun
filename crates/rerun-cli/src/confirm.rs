//! The confirmation before `apply`, `revert` and `forget` (P2-13, user decision E1 a): the
//! preview on stdout, then a question on stderr, answered with `y` or `yes` (ASCII, any case,
//! surrounding whitespace ignored); anything else, an empty line or the end of input is "no".
//! Asked only when stdin and stdout are both consoles (a preview piped away was not seen);
//! otherwise `--yes` is required. No console mode is changed (ADR 0016).

use std::io::{self, BufRead, IsTerminal, Read, Write};

use crate::messages::Message;
use crate::out::Out;

/// The most bytes of an answer line (with its line end); a longer line is "no".
const MAX_ANSWER: u64 = 256;

/// The answer to a question.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Answer {
    /// Go on.
    Yes,
    /// Do nothing.
    No,
    /// No console to ask: `--yes` is required.
    NoConsole,
}

/// Asks the user (the console in `main`, a fake in tests).
pub trait Confirm {
    /// Asks `q` and returns the answer.
    fn ask(&mut self, q: &Message<'_>) -> Answer;
}

/// `y` or `yes`, ASCII, any case, surrounding whitespace ignored.
pub fn is_yes(line: &[u8]) -> bool {
    let s = line.trim_ascii();
    s.eq_ignore_ascii_case(b"y") || s.eq_ignore_ascii_case(b"yes")
}

/// Reads one answer line of at most [`MAX_ANSWER`] bytes from `r`: a longer line, a read
/// error or the end of input is "no".
pub fn read_answer(r: impl Read) -> Answer {
    let mut line = Vec::new();
    let mut limited = io::BufReader::new(r.take(MAX_ANSWER + 1));
    match limited.read_until(b'\n', &mut line) {
        Ok(n) if n > 0 && u64::try_from(line.len()).is_ok_and(|l| l <= MAX_ANSWER) => {
            if is_yes(&line) {
                Answer::Yes
            } else {
                Answer::No
            }
        }
        _ => Answer::No,
    }
}

/// The real console: the question on stderr, the answer from stdin.
pub struct Console;

impl Confirm for Console {
    fn ask(&mut self, q: &Message<'_>) -> Answer {
        if !(io::stdin().is_terminal() && io::stdout().is_terminal()) {
            return Answer::NoConsole;
        }
        // Review N4: keystrokes typed ahead never answer a question not seen yet (no console
        // mode changes; `rerun` has read nothing from stdin before).
        #[cfg(windows)]
        rerun_core::sys::win::discard_console_input();
        let mut err = Out::new(io::stderr().lock());
        if err.prompt(q).is_err() {
            return Answer::No;
        }
        let _ = io::stderr().flush();
        read_answer(io::stdin().lock())
    }
}

#[cfg(test)]
mod tests;
