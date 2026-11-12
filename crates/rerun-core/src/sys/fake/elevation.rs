//! Fake elevation (ADR 0023 §12, §14): a token kind as set, scripted helper runs in order, and
//! whether a helper process runs (A4 S8). The owner of the UAC dialog
//! (`FakeSystem::with_prompt_owner`, the fake of `WinSystem::with_prompt_owner`, P5-5c) is
//! recorded with every run. The two-process tests of `elevate` put a transport of
//! their own in front of `elevate::serve` instead (`elevate::chain_tests`), so `sys` never calls
//! up into `elevate`.

use std::collections::VecDeque;
use std::sync::{Mutex, PoisonError};

use crate::path::RootPath;
use crate::sys::elevation::{
    Elevation, HelperLock, HelperPresence, HelperRun, PromptOwner, PromptOwnerSlot, TokenKind,
    parameters,
};
use crate::sys::{SysError, SysErrorKind, SysResult};

/// A recorded [`Elevation::run_helper`] call: the image, the command line and the dialog's
/// owner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunCall {
    /// The image as given.
    pub image: RootPath,
    /// The `lpParameters` the real one would pass.
    pub parameters: String,
    /// The window the UAC dialog would belong to (`None`: the console window, as for the CLI).
    pub owner: Option<PromptOwner>,
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
    unaskable: Mutex<bool>,
    lock: Mutex<SysResult<HelperLock>>,
    owner: Mutex<PromptOwnerSlot>,
}

impl Default for FakeElevation {
    fn default() -> Self {
        Self {
            kind: Mutex::new(Ok(TokenKind::Filtered)),
            runs: Mutex::new(VecDeque::new()),
            calls: Mutex::new(Vec::new()),
            running: Mutex::new(Ok(Vec::new())),
            unaskable: Mutex::new(false),
            lock: Mutex::new(Ok(HelperLock::Free)),
            owner: Mutex::new(PromptOwnerSlot::new()),
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

    /// A process of the helper's file name runs that cannot be asked (or none).
    pub fn set_helper_unaskable(&self, on: bool) {
        *self
            .unaskable
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = on;
    }

    /// The owner of the UAC dialog of every run from now on.
    pub fn set_prompt_owner(&self, owner: Option<PromptOwner>) {
        let slot = PromptOwnerSlot::new();
        if let Some(o) = owner {
            slot.set(o);
        }
        self.set_prompt_owner_slot(slot);
    }

    /// The owner of the UAC dialog is whatever `slot` holds when a run starts (the fake of
    /// `WinSystem::with_prompt_owner_slot`).
    pub fn set_prompt_owner_slot(&self, slot: PromptOwnerSlot) {
        *self.owner.lock().unwrap_or_else(PoisonError::into_inner) = slot;
    }

    /// The helper's instance lock from now on.
    pub fn set_helper_lock(&self, lock: SysResult<HelperLock>) {
        *self.lock.lock().unwrap_or_else(PoisonError::into_inner) = lock;
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
        let owner = self
            .owner
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get();
        self.calls
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(RunCall {
                image: image.clone(),
                parameters,
                owner,
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

    fn helper_running(&self, nt_name: &str) -> SysResult<HelperPresence> {
        let folded = crate::fold::fold(nt_name);
        let running = self
            .running
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .map(|v| v.iter().any(|i| crate::fold::fold(i) == folded))
            .map_err(Clone::clone)?;
        let unaskable = *self
            .unaskable
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        Ok(if running {
            HelperPresence::Running
        } else if unaskable {
            HelperPresence::Unaskable
        } else {
            HelperPresence::None
        })
    }

    fn helper_lock(&self) -> SysResult<HelperLock> {
        self.lock
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}
