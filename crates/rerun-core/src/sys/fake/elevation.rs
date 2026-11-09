//! Fake elevation (ADR 0023 §12, §14): a token kind as set, and scripted helper runs in
//! order. P4-2b scripts the outcomes directly; from P4-2c a run can call `elevate::serve`
//! in-process with a helper view of the same world.

use std::collections::VecDeque;
use std::sync::{Mutex, PoisonError};

use crate::path::RootPath;
use crate::sys::elevation::{Elevation, HelperRun, TokenKind, parameters};
use crate::sys::{SysError, SysErrorKind, SysResult};

/// A recorded [`Elevation::run_helper`] call: the image and the command line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunCall {
    /// The image as given.
    pub image: RootPath,
    /// The `lpParameters` the real one would pass.
    pub parameters: String,
}

/// [`Elevation`] of a fake process. The token kind defaults to [`TokenKind::Filtered`] (an
/// administrator in admin approval mode, the common case); runs come from a queue, and an
/// empty queue is `Unsupported` (a test that starts the helper without scripting it fails).
#[derive(Debug)]
pub struct FakeElevation {
    kind: Mutex<SysResult<TokenKind>>,
    runs: Mutex<VecDeque<SysResult<HelperRun>>>,
    calls: Mutex<Vec<RunCall>>,
}

impl Default for FakeElevation {
    fn default() -> Self {
        Self {
            kind: Mutex::new(Ok(TokenKind::Filtered)),
            runs: Mutex::new(VecDeque::new()),
            calls: Mutex::new(Vec::new()),
        }
    }
}

impl FakeElevation {
    /// The token kind (or its error) from now on.
    pub fn set_token_kind(&self, kind: SysResult<TokenKind>) {
        *self.kind.lock().unwrap_or_else(PoisonError::into_inner) = kind;
    }

    /// Queues the outcome of the next run.
    pub fn push_run(&self, run: SysResult<HelperRun>) {
        self.runs
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push_back(run);
    }

    /// The runs so far, in order (only those whose arguments were plain).
    pub fn calls(&self) -> Vec<RunCall> {
        self.calls
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

impl Elevation for FakeElevation {
    fn token_kind(&self) -> SysResult<TokenKind> {
        self.kind
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn run_helper(&self, image: &RootPath, args: &[&str]) -> SysResult<HelperRun> {
        let parameters = parameters(args)?;
        self.calls
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(RunCall {
                image: image.clone(),
                parameters,
            });
        self.runs
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .pop_front()
            .unwrap_or_else(|| {
                Err(SysError::new(
                    SysErrorKind::Unsupported,
                    format!("{image}: no scripted helper run"),
                ))
            })
    }
}
