//! Fake elevation (ADR 0023 §12, §14): a token kind as set, scripted helper runs in order, and
//! whether a helper process runs (A4 S8). The two-process tests of `elevate` put a transport of
//! their own in front of `elevate::serve` instead (`elevate::chain_tests`), so `sys` never calls
//! up into `elevate`.

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
/// empty queue is `Unsupported` (a test that starts the helper without scripting it fails). No
/// helper process runs unless [`Self::set_helper_running`] says so.
#[derive(Debug)]
pub struct FakeElevation {
    kind: Mutex<SysResult<TokenKind>>,
    runs: Mutex<VecDeque<SysResult<HelperRun>>>,
    calls: Mutex<Vec<RunCall>>,
    running: Mutex<SysResult<Vec<String>>>,
}

impl Default for FakeElevation {
    fn default() -> Self {
        Self {
            kind: Mutex::new(Ok(TokenKind::Filtered)),
            runs: Mutex::new(VecDeque::new()),
            calls: Mutex::new(Vec::new()),
            running: Mutex::new(Ok(Vec::new())),
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

    /// The NT names of the images that run from now on (or the error of the process list).
    pub fn set_helper_running(&self, images: SysResult<Vec<String>>) {
        *self.running.lock().unwrap_or_else(PoisonError::into_inner) = images;
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

    fn helper_running(&self, nt_name: &str) -> SysResult<bool> {
        let folded = crate::fold::fold(nt_name);
        self.running
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .map(|v| v.iter().any(|i| crate::fold::fold(i) == folded))
            .map_err(Clone::clone)
    }
}
