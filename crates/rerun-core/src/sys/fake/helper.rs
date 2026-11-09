//! Fake helper token and the helper's view of a fake world (ADR 0023 §12, §14).
//!
//! [`FakeHelperToken`]: elevated or not, an own image as set, an instance lock that is free or
//! held by another helper; each call can fail, and the calls are recorded in order, so tests of
//! `elevate::serve` see the fixed order of §3.
//!
//! [`FakeHelperSystem`]: the helper's [`HelperSystem`] over the same [`FakeSystem`] the CLI side
//! uses (the two-process fake of §14): its file system and firewall read side, the world's known
//! folders or another account's (over-the-shoulder elevation, §4), and the refusing parts of
//! the real helper's system (no GPU, no topology, no registry, no elevation, §11).

use std::sync::Mutex;

use super::{FakeKnownFolders, FakeSystem};
use crate::sys::{
    Elevation, Firewall, Fs, Gpu, HelperSystem, HelperToken, InstanceLock, KnownFolders,
    NoElevation, NoGpu, NoRegistry, NoTopology, Registry, RegistryWrite, SysError, SysErrorKind,
    SysResult, System, Topology,
};

/// A call to [`FakeHelperToken`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenCall {
    /// [`HelperToken::drop_privileges`].
    DropPrivileges,
    /// [`HelperToken::is_elevated`].
    IsElevated,
    /// [`HelperToken::own_image`].
    OwnImage,
    /// [`HelperToken::instance_lock`].
    InstanceLock,
}

/// [`HelperToken`] of a fake process: `elevated` as given, the image [`Self::image`] (none:
/// `NotFound`), the instance lock free unless [`Self::busy`]; [`Self::fail`] makes one call fail
/// with `AccessDenied` from then on.
#[derive(Debug, Default)]
pub struct FakeHelperToken {
    elevated: bool,
    image: Option<String>,
    busy: bool,
    fail: Vec<TokenCall>,
    calls: Mutex<Vec<TokenCall>>,
}

impl FakeHelperToken {
    /// A token that is elevated (or not).
    #[must_use]
    pub fn new(elevated: bool) -> Self {
        Self {
            elevated,
            ..Self::default()
        }
    }

    /// The process runs the image of this NT name.
    #[must_use]
    pub fn image(mut self, nt_name: &str) -> Self {
        self.image = Some(nt_name.to_owned());
        self
    }

    /// Another helper holds the instance lock.
    #[must_use]
    pub fn busy(mut self) -> Self {
        self.busy = true;
        self
    }

    /// `call` fails with `AccessDenied` from now on.
    #[must_use]
    pub fn fail(mut self, call: TokenCall) -> Self {
        self.fail.push(call);
        self
    }

    /// The calls so far, in order.
    pub fn calls(&self) -> Vec<TokenCall> {
        self.calls
            .lock()
            .map_or_else(|p| p.into_inner().clone(), |c| c.clone())
    }

    fn call(&self, call: TokenCall) -> SysResult<()> {
        match self.calls.lock() {
            Ok(mut c) => c.push(call),
            Err(p) => p.into_inner().push(call),
        }
        if self.fail.contains(&call) {
            return Err(SysError::new(
                SysErrorKind::AccessDenied,
                "fake helper token",
            ));
        }
        Ok(())
    }
}

impl HelperToken for FakeHelperToken {
    fn drop_privileges(&self) -> SysResult<()> {
        self.call(TokenCall::DropPrivileges)
    }

    fn is_elevated(&self) -> SysResult<bool> {
        self.call(TokenCall::IsElevated).map(|()| self.elevated)
    }

    fn own_image(&self) -> SysResult<String> {
        self.call(TokenCall::OwnImage)?;
        self.image
            .clone()
            .ok_or_else(|| SysError::new(SysErrorKind::NotFound, "fake helper image"))
    }

    fn instance_lock(&self) -> SysResult<InstanceLock> {
        self.call(TokenCall::InstanceLock)?;
        if self.busy {
            return Err(SysError::new(
                SysErrorKind::Busy,
                "another helper holds the instance lock",
            ));
        }
        Ok(InstanceLock::new(Box::new(())))
    }
}

/// The helper's view of a fake world (module docs).
#[derive(Debug)]
pub struct FakeHelperSystem<'w> {
    world: &'w FakeSystem,
    token: FakeHelperToken,
    known_folders: Option<FakeKnownFolders>,
}

impl<'w> FakeHelperSystem<'w> {
    /// The helper with `token` in `world`, with the world's known folders.
    pub fn new(world: &'w FakeSystem, token: FakeHelperToken) -> Self {
        Self {
            world,
            token,
            known_folders: None,
        }
    }

    /// The known folders of another account (over-the-shoulder elevation, ADR 0023 §4).
    #[must_use]
    pub fn with_known_folders(mut self, kf: FakeKnownFolders) -> Self {
        self.known_folders = Some(kf);
        self
    }

    /// The token.
    pub fn fake_token(&self) -> &FakeHelperToken {
        &self.token
    }
}

impl System for FakeHelperSystem<'_> {
    fn fs(&self) -> &dyn Fs {
        self.world.fs()
    }
    fn registry(&self) -> &dyn Registry {
        &NoRegistry
    }
    fn registry_write(&self) -> &dyn RegistryWrite {
        &NoRegistry
    }
    fn topology(&self) -> &dyn Topology {
        &NoTopology
    }
    fn known_folders(&self) -> &dyn KnownFolders {
        match &self.known_folders {
            Some(kf) => kf,
            None => self.world.known_folders(),
        }
    }
    fn gpu(&self) -> &dyn Gpu {
        &NoGpu
    }
    fn firewall(&self) -> &dyn Firewall {
        self.world.firewall()
    }
    fn elevation(&self) -> &dyn Elevation {
        &NoElevation
    }
}

impl HelperSystem for FakeHelperSystem<'_> {
    fn token(&self) -> &dyn HelperToken {
        &self.token
    }
}
