//! Fake shell (ADR 0027 amendment P5-10a): records exactly what it was asked to open, in order,
//! and opens nothing. [`FakeShell::failing`] answers every request with an error instead (a
//! missing browser association); a failed request is not recorded.

use std::sync::{Mutex, PoisonError};

use crate::path::RootPath;
use crate::policy::open::{OpenFolder, OpenUrl};
use crate::sys::{Shell, SysError, SysErrorKind, SysResult};

/// One request the fake shell took.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Opened {
    /// A URL for the browser, exactly as handed over.
    Url(String),
    /// A folder for Explorer.
    Folder(RootPath),
}

/// The fake [`Shell`].
#[derive(Debug, Default)]
pub struct FakeShell {
    /// Every request taken, in order.
    pub opened: Mutex<Vec<Opened>>,
    /// Every request fails with this kind (nothing is recorded).
    fail: Option<SysErrorKind>,
}

impl FakeShell {
    /// A shell that takes every request.
    pub fn new() -> Self {
        Self::default()
    }

    /// A shell that refuses every request with `kind`.
    pub fn failing(kind: SysErrorKind) -> Self {
        Self {
            opened: Mutex::new(Vec::new()),
            fail: Some(kind),
        }
    }

    /// What was opened so far.
    pub fn taken(&self) -> Vec<Opened> {
        self.opened
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn take(&self, o: Opened) -> SysResult<()> {
        if let Some(kind) = self.fail {
            return Err(SysError::new(kind, "the fake shell refuses"));
        }
        self.opened
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(o);
        Ok(())
    }
}

impl Shell for FakeShell {
    fn open_url(&self, url: &OpenUrl) -> SysResult<()> {
        self.take(Opened::Url(url.as_str().to_owned()))
    }

    fn open_folder(&self, folder: &OpenFolder) -> SysResult<()> {
        self.take(Opened::Folder(folder.path().clone()))
    }
}
