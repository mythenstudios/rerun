//! The line writer: write errors and the last-resort net.

use std::io::{self, Write};

use super::{Out, OutError, failed};
use crate::cli::Exit;
use crate::messages::{FactText, Message};

/// A writer that fails every write with `kind` after `ok` successful lines.
pub struct Failing {
    pub kind: io::ErrorKind,
    pub ok: usize,
    pub written: Vec<u8>,
}

impl Write for Failing {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.ok == 0 {
            return Err(io::Error::from(self.kind));
        }
        if buf.contains(&b'\n') {
            self.ok -= 1;
        }
        self.written.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn condition(n: u32) -> Message<'static> {
    Message::Condition {
        key: "cpu.threads",
        value: FactText::Number(n),
    }
}

#[test]
fn every_message_is_one_line() {
    let mut out = Out::new(Vec::new());
    out.lines(&[condition(1), Message::Blank, condition(2)])
        .unwrap();
    out.flush().unwrap();
    assert_eq!(
        String::from_utf8(out.into_inner()).unwrap(),
        "  cpu.threads: 1\n\n  cpu.threads: 2\n"
    );
}

#[test]
fn a_closed_pipe_ends_silently_with_exit_0() {
    let mut out = Out::new(Failing {
        kind: io::ErrorKind::BrokenPipe,
        ok: 1,
        written: Vec::new(),
    });
    let e = out
        .lines(&[condition(1), condition(2), condition(3)])
        .unwrap_err();
    assert_eq!(e, OutError::Closed);
    let mut err = Out::new(Vec::new());
    assert_eq!(failed(&mut err, e), Exit::Report);
    assert!(err.into_inner().is_empty());
    assert_eq!(out.into_inner().written, b"  cpu.threads: 1\n");
}

#[test]
fn any_other_write_error_is_fatal_and_reported_on_stderr() {
    for kind in [
        io::ErrorKind::PermissionDenied,
        io::ErrorKind::Other,
        io::ErrorKind::WriteZero,
    ] {
        let mut out = Out::new(Failing {
            kind,
            ok: 0,
            written: Vec::new(),
        });
        let e = out.line(&condition(1)).unwrap_err();
        assert_eq!(e, OutError::Io(kind));
        let mut err = Out::new(Vec::new());
        assert_eq!(failed(&mut err, e), Exit::Fatal);
        let err = String::from_utf8(err.into_inner()).unwrap();
        assert_eq!(err, format!("rerun: cannot write the output: {kind}\n"));
    }
}

#[test]
#[should_panic(expected = "last-resort net")]
fn the_net_panics_in_tests_on_a_raw_control_character() {
    // A static key is the only way to get raw text into a message without `Shown`; a field
    // escape missing elsewhere would look the same to the net.
    let mut out = Out::new(Vec::new());
    let _ = out.line(&Message::Condition {
        key: "gpu.vendor\u{1b}[2J",
        value: FactText::Bool(true),
    });
}

#[test]
#[should_panic(expected = "last-resort net")]
fn the_net_also_catches_bidi_and_line_separators() {
    let mut out = Out::new(Vec::new());
    let _ = out.line(&Message::Condition {
        key: "gpu\u{202E}\u{2028}",
        value: FactText::Bool(true),
    });
}
