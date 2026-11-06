//! The fault hub of one fake system (ADR 0019 amendment; P2-9, audit A2 should-item 1): the
//! file system and the registry of a [`FakeSystem`](super::FakeSystem) share it, so a test
//! counts, fails and crashes their calls in one sequence, and a crash blocks both.
//!
//! - The unit is a [`Prim`]: a write primitive or read-side call of the file system, or a
//!   registry primitive ([`Prim::Reg`]). Every call of Rerun is counted per unit; an armed
//!   [`Fault`] fails one occurrence or crashes after it.
//! - After a crash every call of Rerun fails (file system and registry, reads included) until
//!   a restart, which also makes every registry handle stale ([`FaultHub::epoch`]); registry
//!   changes survive a crash, they live in the hive, not in the process.
//! - Fixture and attacker helpers are never counted, faulted or blocked, and neither is a
//!   call made from inside a step hook (it plays another program).
//! - Lock order: a component's own state, then the hub (the hub never calls out).

use std::cell::Cell;
use std::sync::{Mutex, MutexGuard, PoisonError};

use super::fs::FsOp;
use crate::sys::{SysError, SysErrorKind, SysResult};

/// A primitive call of the file system's write side (ADR 0017, A1) or of the registry write
/// side (ADR 0018, P2-9): the unit of the fake's hooks and faults.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Prim {
    /// `PrimDir::support` (case sensitivity, POSIX support; before every write).
    Support,
    /// `PrimDir::volume_name` (the guard's name re-check).
    VolumeName,
    /// `PrimDir::open_guard` (step 1).
    OpenGuard,
    /// `PrimDir::lookup` (attribute-only metadata of a child).
    Lookup,
    /// `PrimDir::create_tmp` (step 2).
    CreateTmp,
    /// `PrimDir::open_lock`.
    OpenLock,
    /// `PrimDir::create_dir`.
    CreateDir,
    /// `PrimDir::open_dir_delete`.
    OpenDirDelete,
    /// `PrimDir::rename` (steps 6 and 7, the undo, `rename_to`, `create_new`).
    Rename,
    /// `PrimDir::flush`.
    FlushDir,
    /// `PrimFile::state`.
    State,
    /// `PrimFile::name` (the guard's name re-check).
    Name,
    /// `PrimFile::read_at` (one chunk of the guard's hash or reader).
    ReadAt,
    /// `PrimFile::users`.
    Users,
    /// `PrimFile::write` (one chunk of step 3).
    Write,
    /// `PrimFile::set_attrs` (step 4).
    SetAttrs,
    /// `PrimFile::flush` (step 5).
    FlushFile,
    /// `PrimFile::posix_delete` (step 8, `delete`, `remove_dir`, the cleanup of `<tmp>`).
    PosixDelete,
    /// A read-side operation of a `Dir` handle or `Fs::open_dir` (`FsOp::OpenDir`): a fault
    /// unit only, its hooks are the walk steps.
    ReadSide(FsOp),
    /// A registry primitive of `sys::seq::reg`.
    Reg(RegPrim),
}

/// A registry primitive (`sys::seq::reg::{PrimHive, PrimKey}`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RegPrim {
    /// `PrimHive::open_root`.
    Root,
    /// `PrimKey::open` (one segment).
    Open,
    /// `PrimKey::create` (one segment).
    Create,
    /// `PrimKey::flags`.
    Flags,
    /// `PrimKey::kernel_name`.
    KernelName,
    /// `PrimKey::query`.
    Query,
    /// `PrimKey::counts`.
    Counts,
    /// `PrimKey::set_value`.
    SetValue,
    /// `PrimKey::delete_value`.
    DeleteValue,
    /// `PrimKey::delete`.
    Delete,
    /// `PrimKey::flush`.
    Flush,
}

/// What an armed fault does when its call comes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fault {
    /// The call fails with this kind before it acts.
    Fail(SysErrorKind),
    /// The call acts, then the process crashes (ADR 0019 amendment): this and every later
    /// call of Rerun fails with `Other` ("fake: process crashed"), so no rollback runs, until
    /// a restart. A read-side call crashes before it acts.
    CrashAfter,
}

#[derive(Debug, Default)]
struct Faults {
    /// Armed faults: call, its 1-based occurrence, what happens.
    armed: Vec<(Prim, usize, Fault)>,
    /// Calls seen since the faults were last cleared, per call.
    seen: Vec<(Prim, usize)>,
    fired: bool,
    record: bool,
    calls: Vec<Prim>,
    crashed: bool,
    /// Restarts so far: a registry handle of an earlier epoch is stale.
    epoch: u64,
}

/// The shared fault state (see the module docs).
#[derive(Debug, Default)]
pub(crate) struct FaultHub(Mutex<Faults>);

thread_local! {
    /// The current thread runs a step hook (another program).
    static IN_HOOK: Cell<bool> = const { Cell::new(false) };
}

/// The current thread runs a step hook, or stops.
pub(crate) fn set_in_hook(on: bool) {
    IN_HOOK.with(|h| h.set(on));
}

/// The error of every call after a crash.
pub(crate) fn crashed_err() -> SysError {
    SysError::new(SysErrorKind::Other, "fake: process crashed")
}

impl FaultHub {
    fn lock(&self) -> MutexGuard<'_, Faults> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Enters a call of Rerun: fails after a crash; counts it, records it, and applies an
    /// armed fault. `Ok(true)`: crash after the call acts. A call from inside a step hook is
    /// neither counted, recorded nor faulted; it still fails after a crash.
    pub(crate) fn enter(&self, call: Prim) -> SysResult<bool> {
        let mut f = self.lock();
        if f.crashed {
            return Err(crashed_err());
        }
        if IN_HOOK.with(Cell::get) {
            return Ok(false);
        }
        let n = match f.seen.iter_mut().find(|(c, _)| *c == call) {
            Some((_, n)) => {
                *n += 1;
                *n
            }
            None => {
                f.seen.push((call, 1));
                1
            }
        };
        if f.record {
            f.calls.push(call);
        }
        let Some(pos) = f.armed.iter().position(|(c, k, _)| *c == call && *k == n) else {
            return Ok(false);
        };
        let (_, _, fault) = f.armed.remove(pos);
        f.fired = true;
        match fault {
            Fault::Fail(kind) => Err(SysError::new(
                kind,
                format!("fake: injected fault at {call:?} #{n}"),
            )),
            Fault::CrashAfter => Ok(true),
        }
    }

    /// The process crashed and was not restarted yet.
    pub(crate) fn crashed(&self) -> bool {
        self.lock().crashed
    }

    /// The process crashes now.
    pub(crate) fn crash(&self) {
        self.lock().crashed = true;
    }

    /// Arms `fault` for the `nth` (1-based) call of `call`.
    pub(crate) fn arm(&self, call: Prim, nth: usize, fault: Fault) {
        self.lock().armed.push((call, nth, fault));
    }

    /// Disarms every fault and resets the call counts (not the crash flag).
    pub(crate) fn clear(&self) {
        let mut f = self.lock();
        f.armed.clear();
        f.seen.clear();
        f.fired = false;
    }

    /// An armed fault has fired since the last [`Self::clear`].
    pub(crate) fn fired(&self) -> bool {
        self.lock().fired
    }

    /// Records every call of Rerun from now on, or stops.
    pub(crate) fn record(&self, on: bool) {
        self.lock().record = on;
    }

    /// The calls recorded so far; clears the record.
    pub(crate) fn take_calls(&self) -> Vec<Prim> {
        std::mem::take(&mut self.lock().calls)
    }

    /// A restart (or the fresh process after a power loss): not crashed, no armed faults, no
    /// counts, a new epoch.
    pub(crate) fn restart(&self) {
        let mut f = self.lock();
        f.crashed = false;
        f.armed.clear();
        f.seen.clear();
        f.fired = false;
        f.epoch += 1;
    }

    /// The current epoch (see [`Self::restart`]).
    pub(crate) fn epoch(&self) -> u64 {
        self.lock().epoch
    }
}
