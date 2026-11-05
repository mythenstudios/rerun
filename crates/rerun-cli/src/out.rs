//! The line writer (ADR 0016): one `writeln!` per message, every result handled.
//!
//! A pipe closed early (`BrokenPipe`) ends the output silently with exit 0; any other write
//! error is fatal (exit 1). Last-resort net: every line is checked for escapable characters
//! (`escape::text`) before it is written. It must never hide a missing field escape: in
//! `cfg(test)` a hit panics, so every test that renders through `Out` proves that it never
//! fired; in a build a hit line is written escaped as a whole.

use std::io::{self, Write};

use rerun_core::escape;

use crate::cli::Exit;
use crate::messages::Message;

/// Why a line could not be written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutError {
    /// The reader went away (`BrokenPipe`): end silently.
    Closed,
    /// Any other write error: fatal.
    Io(io::ErrorKind),
}

impl From<io::Error> for OutError {
    fn from(e: io::Error) -> Self {
        match e.kind() {
            io::ErrorKind::BrokenPipe => Self::Closed,
            kind => Self::Io(kind),
        }
    }
}

/// A line writer over stdout, stderr or a buffer in tests.
#[derive(Debug)]
pub struct Out<W: Write> {
    w: W,
}

impl<W: Write> Out<W> {
    /// Wraps a writer.
    pub fn new(w: W) -> Self {
        Self { w }
    }

    /// Writes one message as one line.
    pub fn line(&mut self, m: &Message<'_>) -> Result<(), OutError> {
        let text = m.to_string();
        let shown = escape::text(&text);
        if shown.is_escaped() {
            net_hit(&text);
        }
        writeln!(self.w, "{shown}")?;
        Ok(())
    }

    /// Writes every message, stopping at the first error.
    pub fn lines(&mut self, ms: &[Message<'_>]) -> Result<(), OutError> {
        ms.iter().try_for_each(|m| self.line(m))
    }

    /// Flushes the writer.
    pub fn flush(&mut self) -> Result<(), OutError> {
        self.w.flush()?;
        Ok(())
    }

    /// The writer (tests read their buffer back).
    #[cfg(test)]
    pub fn into_inner(self) -> W {
        self.w
    }
}

/// The net fired: a field reached a message without its escape.
#[cfg(test)]
fn net_hit(text: &str) {
    panic!(
        "last-resort net: a line holds an escapable character, a field escape is missing: {}",
        escape::text(text)
    );
}

#[cfg(not(test))]
fn net_hit(_: &str) {}

/// The exit code for a failed write of the report: silent 0 for a closed pipe, otherwise the
/// error on `err` and 1.
pub fn failed<E: Write>(err: &mut Out<E>, e: OutError) -> Exit {
    match e {
        OutError::Closed => Exit::Report,
        OutError::Io(kind) => {
            // Nothing more to do if stderr fails as well.
            let _ = err.line(&Message::WriteFailed { kind });
            Exit::Fatal
        }
    }
}

#[cfg(test)]
pub mod tests;
