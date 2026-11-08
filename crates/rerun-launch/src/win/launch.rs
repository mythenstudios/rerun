//! The one wrapper module of the shim's banned process calls (ADR 0010 amendment, ADR 0022):
//! `CreateProcessW`, `SetInformationJobObject`, `UpdateProcThreadAttribute`,
//! `SetProcessDefaultCpuSets`, `GetThreadGroupAffinity`, `ShellExecuteExW` and
//! `CoInitializeEx` are called here and nowhere else in `rerun-launch`; so are the reads of
//! the post-launch check (P3-2): `GetProcessAffinityMask` and `GetProcessDefaultCpuSets`
//! (banned as topology sources, ADR 0010; here they read the shim's own child), the job's
//! group affinity, `GetPriorityClass` and a bounded wait that does not consume the child.
//!
//! The hard limit follows the order of ADR 0022 (B-2): [`spawn`] creates the job with its
//! limit flags (B4: `JOB_OBJECT_LIMIT_BREAKAWAY_OK` only) and the child suspended **inside**
//! it (`PROC_THREAD_ATTRIBUTE_JOB_LIST`); [`limit_job`] sets `JobObjectGroupInformationEx`;
//! [`read_back`] reads the job and the initial thread (a thread outside the selected group is
//! a difference, so the rule is never applied with another primary group); [`resume`] lets it
//! run. `PROC_THREAD_ATTRIBUTE_GROUP_AFFINITY` is not used: `CreateProcessW` refuses it
//! (ERROR_INVALID_PARAMETER, measured; ADR 0022 amendment P3-1b). `JOB_OBJECT_LIMIT_AFFINITY` is never
//! set. Every `GROUP_AFFINITY` passed has `Reserved` zeroed. Handles are `OwnedHandle`s in
//! [`Child`]; nothing is inherited.

use std::ffi::c_void;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::ptr;

use rerun_proto::profile::Priority;
use windows_sys::Win32::Foundation::{
    ERROR_INVALID_HANDLE, HANDLE, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::System::Com::{
    COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE, CoInitializeEx, CoUninitialize,
};
use windows_sys::Win32::System::JobObjects::{
    CreateJobObjectW, JOB_OBJECT_LIMIT_BREAKAWAY_OK, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JobObjectExtendedLimitInformation, JobObjectGroupInformationEx, QueryInformationJobObject,
    SetInformationJobObject,
};
use windows_sys::Win32::System::SystemInformation::GROUP_AFFINITY;
use windows_sys::Win32::System::Threading::{
    ABOVE_NORMAL_PRIORITY_CLASS, CREATE_SUSPENDED, CreateProcessW, DeleteProcThreadAttributeList,
    EXTENDED_STARTUPINFO_PRESENT, GetExitCodeProcess, GetPriorityClass, GetProcessAffinityMask,
    GetProcessDefaultCpuSets, GetThreadGroupAffinity, HIGH_PRIORITY_CLASS, INFINITE,
    InitializeProcThreadAttributeList, LPPROC_THREAD_ATTRIBUTE_LIST, NORMAL_PRIORITY_CLASS,
    PROC_THREAD_ATTRIBUTE_JOB_LIST, PROCESS_INFORMATION, ResumeThread, STARTUPINFOEXW,
    STARTUPINFOW, SetProcessDefaultCpuSets, TerminateProcess, UpdateProcThreadAttribute,
    WaitForSingleObject,
};
use windows_sys::Win32::UI::Shell::{
    SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW,
};

use super::last_error;
use crate::os::{GroupAffinity, ReadBack, Spawn, Terminated};

/// winuser.h `SW_SHOWNORMAL` (avoids the `Win32_UI_WindowsAndMessaging` feature).
const SW_SHOWNORMAL: i32 = 1;
/// Entries read back from the job: one is expected, more is a difference.
const READ_BACK_ENTRIES: usize = 4;

/// A started process: its handle, its initial thread (not for a `ShellExecuteExW` start) and
/// its job (hard limit only). All closed on drop; the job outlives the wait (B3).
#[derive(Debug)]
pub(crate) struct Child {
    process: OwnedHandle,
    thread: Option<OwnedHandle>,
    job: Option<OwnedHandle>,
}

/// Takes ownership of a handle a successful call returned; `None` for null.
///
/// # Safety
/// `raw` is null or a handle that the caller owns (just returned by a successful call) and
/// that nothing else closes.
unsafe fn own(raw: HANDLE) -> Option<OwnedHandle> {
    (!raw.is_null()).then(|| {
        // SAFETY: non-null, owned by the caller and closed by nothing else (the contract).
        unsafe { OwnedHandle::from_raw_handle(raw) }
    })
}

/// The Win32 error of a `WaitForSingleObject` result other than `WAIT_OBJECT_0`: the last
/// error for `WAIT_FAILED`, otherwise the result itself (`WAIT_TIMEOUT` = 258,
/// `WAIT_ABANDONED` = 128; neither is expected for a process handle without a timeout).
fn wait_error(r: u32) -> u32 {
    if r == WAIT_FAILED { last_error() } else { r }
}

/// `size_of::<T>()` as the `u32` length the APIs take (all such `T` are a few bytes).
fn len32<T>() -> u32 {
    u32::try_from(size_of::<T>()).unwrap_or(0)
}

fn to_raw(ga: GroupAffinity) -> Result<GROUP_AFFINITY, u32> {
    Ok(GROUP_AFFINITY {
        // A 32-bit KAFFINITY cannot hold a mask above bit 31 (run refuses that earlier).
        Mask: usize::try_from(ga.mask).map_err(|_| ERROR_INVALID_PARAMETER)?,
        Group: ga.group,
        Reserved: [0; 3],
    })
}

fn from_raw(ga: &GROUP_AFFINITY) -> GroupAffinity {
    GroupAffinity {
        group: ga.Group,
        mask: u64::try_from(ga.Mask).unwrap_or(0),
    }
}

/// winerror.h `ERROR_INVALID_PARAMETER`.
const ERROR_INVALID_PARAMETER: u32 = 87;

/// `SetInformationJobObject` with one fixed-size `T`.
fn set_job_info<T>(job: &OwnedHandle, class: i32, value: &T) -> Result<(), u32> {
    #[expect(
        clippy::disallowed_methods,
        reason = "rerun-launch's one SetInformationJobObject call site (ADR 0022, B4)"
    )]
    // SAFETY: `job` is a live job handle (JOB_OBJECT_ALL_ACCESS from CreateJobObjectW) kept
    // alive by the borrow; `value` points to a valid, initialized `T` of `len32::<T>()` bytes
    // that matches `class` (JOBOBJECT_EXTENDED_LIMIT_INFORMATION or one GROUP_AFFINITY), read
    // only during the call.
    let ok = unsafe {
        SetInformationJobObject(
            job.as_raw_handle(),
            class,
            ptr::from_ref(value).cast::<c_void>(),
            len32::<T>(),
        )
    };
    if ok == 0 {
        return Err(last_error());
    }
    Ok(())
}

/// Step 1 of B-2: a job whose only limit flag is `JOB_OBJECT_LIMIT_BREAKAWAY_OK` (B4;
/// `SILENT_BREAKAWAY_OK` no, `KILL_ON_JOB_CLOSE` off until measured).
fn create_job() -> Result<OwnedHandle, u32> {
    // SAFETY: null security attributes (default, not inheritable) and a null name (an
    // unnamed job) are documented inputs.
    let raw = unsafe { CreateJobObjectW(ptr::null(), ptr::null()) };
    // SAFETY: `raw` was just returned by CreateJobObjectW (null on failure); nothing else
    // owns it.
    let job = unsafe { own(raw) }.ok_or_else(last_error)?;
    let mut info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_BREAKAWAY_OK;
    set_job_info(&job, JobObjectExtendedLimitInformation, &info)?;
    Ok(job)
}

/// A process/thread attribute list, deleted on drop.
struct AttributeList {
    /// `u64` storage for the 8-byte alignment of the opaque list.
    buf: Vec<u64>,
}

impl AttributeList {
    fn new(count: u32) -> Result<Self, u32> {
        let mut size: usize = 0;
        // SAFETY: the documented size query: a null list and a valid `size` to write the
        // needed byte count to; it fails with ERROR_INSUFFICIENT_BUFFER by design.
        unsafe { InitializeProcThreadAttributeList(ptr::null_mut(), count, 0, &mut size) };
        if size == 0 {
            return Err(last_error());
        }
        let mut list = Self {
            buf: vec![0; size.div_ceil(8)],
        };
        // SAFETY: `list.ptr()` points to a writable, 8-aligned buffer of at least `size` bytes
        // (the size the query reported) that `list` owns; `size` is valid for a write.
        let ok = unsafe { InitializeProcThreadAttributeList(list.ptr(), count, 0, &mut size) };
        if ok == 0 {
            // Not initialized: nothing to delete.
            let code = last_error();
            list.buf = Vec::new();
            return Err(code);
        }
        Ok(list)
    }

    fn ptr(&mut self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
        self.buf.as_mut_ptr().cast()
    }

    /// Adds one attribute. The value must stay alive and unchanged until the list is
    /// dropped (`UpdateProcThreadAttribute` keeps the pointer).
    ///
    /// # Safety
    /// `value` points to `size` readable bytes of the type `attribute` documents and outlives
    /// every use of the list (the `CreateProcessW` call).
    unsafe fn update(
        &mut self,
        attribute: u32,
        value: *const c_void,
        size: usize,
    ) -> Result<(), u32> {
        let list = self.ptr();
        let attribute = usize::try_from(attribute).map_err(|_| ERROR_INVALID_PARAMETER)?;
        #[expect(
            clippy::disallowed_methods,
            reason = "rerun-launch's one UpdateProcThreadAttribute call site (ADR 0022, B-2)"
        )]
        // SAFETY: `list` is an initialized attribute list owned by `self`; `value` and `size`
        // describe a live value of the attribute's type (the caller's contract); flags 0 and
        // null previous-value/return-size pointers are documented.
        let ok = unsafe {
            UpdateProcThreadAttribute(
                list,
                0,
                attribute,
                value,
                size,
                ptr::null_mut(),
                ptr::null(),
            )
        };
        if ok == 0 {
            return Err(last_error());
        }
        Ok(())
    }
}

impl Drop for AttributeList {
    fn drop(&mut self) {
        if !self.buf.is_empty() {
            let list = self.ptr();
            // SAFETY: `list` was initialized by InitializeProcThreadAttributeList (an empty
            // buffer marks a failed initialization) and is deleted exactly once, here.
            unsafe { DeleteProcThreadAttributeList(list) };
        }
    }
}

fn priority_flag(p: Option<Priority>) -> u32 {
    match p {
        None => 0,
        Some(Priority::Normal) => NORMAL_PRIORITY_CLASS,
        Some(Priority::AboveNormal) => ABOVE_NORMAL_PRIORITY_CLASS,
        Some(Priority::High) => HIGH_PRIORITY_CLASS,
    }
}

fn with_nul(s: &[u16]) -> Vec<u16> {
    let mut v = Vec::with_capacity(s.len() + 1);
    v.extend_from_slice(s);
    v.push(0);
    v
}

/// `CreateProcessW(app, command_line)` (M2: `lpApplicationName` never null), no inherited
/// handles, the shim's environment and directory. With `spawn.in_job`: steps 1 and 2 of B-2.
pub(crate) fn spawn(app: &[u16], command_line: &[u16], spawn: &Spawn) -> Result<Child, u32> {
    let app = with_nul(app);
    let mut line = with_nul(command_line);
    let mut flags = priority_flag(spawn.priority);
    if spawn.suspended || spawn.in_job {
        flags |= CREATE_SUSPENDED;
    }
    // Declared before `list`, so they outlive it (drop order is reverse).
    let job = spawn.in_job.then(create_job).transpose()?;
    let jobs: [HANDLE; 1] = [job
        .as_ref()
        .map_or(ptr::null_mut(), AsRawHandle::as_raw_handle)];
    let mut list = None;
    let mut si = STARTUPINFOEXW::default();
    si.StartupInfo.cb = len32::<STARTUPINFOW>();
    if job.is_some() {
        // Only the job list: `PROC_THREAD_ATTRIBUTE_GROUP_AFFINITY` is a thread attribute that
        // `CreateProcessW` refuses with ERROR_INVALID_PARAMETER, alone or with the job list,
        // suspended or not (measured on Windows 11 build 26300, see ADR 0022 amendment P3-1b).
        let mut l = AttributeList::new(1)?;
        // SAFETY: `jobs` is an array of one live job handle, declared before `l` and alive
        // until after CreateProcessW; the attribute takes an array of HANDLE.
        unsafe {
            l.update(
                PROC_THREAD_ATTRIBUTE_JOB_LIST,
                jobs.as_ptr().cast(),
                size_of::<[HANDLE; 1]>(),
            )
        }?;
        si.StartupInfo.cb = len32::<STARTUPINFOEXW>();
        si.lpAttributeList = l.ptr();
        flags |= EXTENDED_STARTUPINFO_PRESENT;
        list = Some(l);
    }
    let mut pi = PROCESS_INFORMATION::default();
    #[expect(
        clippy::disallowed_methods,
        reason = "rerun-launch's one CreateProcessW call site (ADR 0022)"
    )]
    // SAFETY: `app` and `line` are NUL-terminated UTF-16 buffers owned by this function
    // (`line` writable, as the API may modify it); null security attributes, environment and
    // directory are documented (inherit the shim's); handles are not inherited. `si` is a
    // STARTUPINFOEXW whose `cb` matches the form in use (with EXTENDED_STARTUPINFO_PRESENT its
    // list is initialized and alive in `list`); `pi` is valid for a write.
    let ok = unsafe {
        CreateProcessW(
            app.as_ptr(),
            line.as_mut_ptr(),
            ptr::null(),
            ptr::null(),
            0,
            flags,
            ptr::null(),
            ptr::null(),
            ptr::from_ref(&si).cast::<STARTUPINFOW>(),
            &mut pi,
        )
    };
    if ok == 0 {
        return Err(last_error());
    }
    drop(list);
    // SAFETY: CreateProcessW succeeded, so both handles are new and owned by this function;
    // nothing else closes them.
    let thread = unsafe { own(pi.hThread) };
    // SAFETY: as above.
    let process = unsafe { own(pi.hProcess) }.ok_or(ERROR_INVALID_HANDLE)?;
    Ok(Child {
        process,
        thread,
        job,
    })
}

/// Step 3 of B-2: exactly one `GROUP_AFFINITY` on the job.
pub(crate) fn limit_job(child: &Child, affinity: GroupAffinity) -> Result<(), u32> {
    let job = child.job.as_ref().ok_or(ERROR_INVALID_HANDLE)?;
    let ga = to_raw(affinity)?;
    set_job_info(job, JobObjectGroupInformationEx, &ga)
}

/// Step 4 of B-2: the job's `JobObjectGroupInformationEx` and the initial thread's affinity.
pub(crate) fn read_back(child: &Child) -> Result<ReadBack, u32> {
    let job = job_affinity(child)?;
    let thread = child.thread.as_ref().ok_or(ERROR_INVALID_HANDLE)?;
    let mut ga = GROUP_AFFINITY::default();
    #[expect(
        clippy::disallowed_methods,
        reason = "rerun-launch's read-back of the suspended child's initial thread (ADR 0022, \
                  B-2), not a topology source"
    )]
    // SAFETY: `thread` is the live initial-thread handle from CreateProcessW
    // (THREAD_ALL_ACCESS); `ga` is valid for a write.
    let ok = unsafe { GetThreadGroupAffinity(thread.as_raw_handle(), &mut ga) };
    if ok == 0 {
        return Err(last_error());
    }
    Ok(ReadBack {
        job,
        thread: from_raw(&ga),
    })
}

/// The job's `JobObjectGroupInformationEx`, every entry (at most [`READ_BACK_ENTRIES`]; more
/// fails the call, which the callers treat as a difference). Step 4 of B-2 and the post-launch
/// check (P3-2).
pub(crate) fn job_affinity(child: &Child) -> Result<Vec<GroupAffinity>, u32> {
    let job = child.job.as_ref().ok_or(ERROR_INVALID_HANDLE)?;
    let mut entries = [GROUP_AFFINITY::default(); READ_BACK_ENTRIES];
    let mut returned: u32 = 0;
    let cap = u32::try_from(size_of::<[GROUP_AFFINITY; READ_BACK_ENTRIES]>())
        .map_err(|_| ERROR_INVALID_PARAMETER)?;
    // SAFETY: `job` is a live job handle (JOB_OBJECT_ALL_ACCESS); `entries` is a writable
    // array of `cap` bytes, alive for the call; `returned` is valid for a write.
    let ok = unsafe {
        QueryInformationJobObject(
            job.as_raw_handle(),
            JobObjectGroupInformationEx,
            entries.as_mut_ptr().cast(),
            cap,
            &mut returned,
        )
    };
    if ok == 0 {
        return Err(last_error());
    }
    let n = usize::try_from(returned).unwrap_or(usize::MAX) / size_of::<GROUP_AFFINITY>();
    let job = entries.get(..n).ok_or(ERROR_INVALID_PARAMETER)?;
    Ok(job.iter().map(from_raw).collect())
}

/// The post-launch check (P3-2): waits up to `ms` for the child to end, without consuming it.
pub(crate) fn wait_for(child: &Child, ms: u32) -> Result<bool, u32> {
    // SAFETY: `child.process` is a live process handle with SYNCHRONIZE (from CreateProcessW
    // or ShellExecuteExW), kept alive by the borrow.
    let r = unsafe { WaitForSingleObject(child.process.as_raw_handle(), ms) };
    match r {
        WAIT_OBJECT_0 => Ok(true),
        WAIT_TIMEOUT => Ok(false),
        r => Err(wait_error(r)),
    }
}

/// The post-launch check (P3-2): the process's affinity mask (of its primary group).
pub(crate) fn process_affinity(child: &Child) -> Result<u64, u32> {
    let mut process: usize = 0;
    let mut system: usize = 0;
    #[expect(
        clippy::disallowed_methods,
        reason = "rerun-launch's post-launch check of its own child's affinity (ADR 0022, P3-2), \
                  not a topology source"
    )]
    // SAFETY: `child.process` is a live process handle with PROCESS_QUERY_LIMITED_INFORMATION
    // (PROCESS_ALL_ACCESS from CreateProcessW); both outputs are valid for a write.
    let ok =
        unsafe { GetProcessAffinityMask(child.process.as_raw_handle(), &mut process, &mut system) };
    if ok == 0 {
        return Err(last_error());
    }
    u64::try_from(process).map_err(|_| ERROR_INVALID_PARAMETER)
}

/// Most CPU Set IDs the check reads (the topology's limit, ADR 0010).
const MAX_CPU_SET_IDS: u32 = 4096;
/// winerror.h `ERROR_INSUFFICIENT_BUFFER`.
const ERROR_INSUFFICIENT_BUFFER: u32 = 122;

/// The post-launch check (P3-2): the process's default CPU Sets; one retry with the size
/// Windows asks for, at most [`MAX_CPU_SET_IDS`].
pub(crate) fn cpu_sets(child: &Child) -> Result<Vec<u32>, u32> {
    let mut cap: u32 = 64;
    for _ in 0..2 {
        let mut ids = vec![0u32; usize::try_from(cap).map_err(|_| ERROR_INVALID_PARAMETER)?];
        let mut required: u32 = 0;
        #[expect(
            clippy::disallowed_methods,
            reason = "rerun-launch's post-launch check of the CPU Sets it set on its own child \
                      (ADR 0022, P3-2), not a topology source"
        )]
        // SAFETY: `child.process` is a live process handle with
        // PROCESS_QUERY_LIMITED_INFORMATION; `ids` is a writable array of `cap` u32 alive for
        // the call; `required` is valid for a write.
        let ok = unsafe {
            GetProcessDefaultCpuSets(
                child.process.as_raw_handle(),
                ids.as_mut_ptr(),
                cap,
                &mut required,
            )
        };
        if ok != 0 {
            ids.truncate(usize::try_from(required).map_err(|_| ERROR_INVALID_PARAMETER)?);
            return Ok(ids);
        }
        let code = last_error();
        if code != ERROR_INSUFFICIENT_BUFFER || required <= cap || required > MAX_CPU_SET_IDS {
            return Err(code);
        }
        cap = required;
    }
    Err(ERROR_INSUFFICIENT_BUFFER)
}

/// The post-launch check (P3-2, D6 addition): the process's priority class.
pub(crate) fn priority_class(child: &Child) -> Result<u32, u32> {
    // SAFETY: `child.process` is a live process handle with
    // PROCESS_QUERY_LIMITED_INFORMATION, kept alive by the borrow.
    let class = unsafe { GetPriorityClass(child.process.as_raw_handle()) };
    if class == 0 {
        return Err(last_error());
    }
    Ok(class)
}

/// Soft mode: `SetProcessDefaultCpuSets` on the suspended child.
pub(crate) fn set_cpu_sets(child: &Child, ids: &[u32]) -> Result<(), u32> {
    let count = u32::try_from(ids.len()).map_err(|_| ERROR_INVALID_PARAMETER)?;
    #[expect(
        clippy::disallowed_methods,
        reason = "rerun-launch's one SetProcessDefaultCpuSets call site (ADR 0022, soft mode)"
    )]
    // SAFETY: `child.process` is a live process handle (PROCESS_ALL_ACCESS from
    // CreateProcessW, which includes PROCESS_SET_LIMITED_INFORMATION); `ids` is a readable
    // array of `count` u32 IDs, alive for the call.
    let ok =
        unsafe { SetProcessDefaultCpuSets(child.process.as_raw_handle(), ids.as_ptr(), count) };
    if ok == 0 {
        return Err(last_error());
    }
    Ok(())
}

/// Step 5 of B-2: `ResumeThread` on the initial thread.
pub(crate) fn resume(child: &Child) -> Result<(), u32> {
    let thread = child.thread.as_ref().ok_or(ERROR_INVALID_HANDLE)?;
    // SAFETY: `thread` is the live initial-thread handle from CreateProcessW
    // (THREAD_SUSPEND_RESUME included).
    let previous = unsafe { ResumeThread(thread.as_raw_handle()) };
    if previous == u32::MAX {
        return Err(last_error());
    }
    Ok(())
}

/// How long [`terminate`] waits for the ended child.
const TERMINATE_WAIT_MS: u32 = 5_000;

/// Ends a suspended child that never ran and waits up to 5 s for it to end; the handles close
/// on return. Reported only: the unchanged start follows either way (D3).
pub(crate) fn terminate(child: Child) -> Terminated {
    let process = child.process.as_raw_handle();
    // SAFETY: `process` is a live process handle with PROCESS_TERMINATE (from CreateProcessW),
    // kept alive by `child` until this function returns.
    let ok = unsafe { TerminateProcess(process, 1) };
    if ok == 0 {
        return Terminated::Failed(last_error());
    }
    // SAFETY: as above, with SYNCHRONIZE.
    let r = unsafe { WaitForSingleObject(process, TERMINATE_WAIT_MS) };
    if r == WAIT_OBJECT_0 {
        Terminated::Ended
    } else {
        Terminated::NotConfirmed(wait_error(r))
    }
}

/// B3: waits for the child, then its exit code.
pub(crate) fn wait(child: Child) -> Result<u32, u32> {
    let process = child.process.as_raw_handle();
    // SAFETY: `process` is a live process handle with SYNCHRONIZE, kept alive by `child`
    // until this function returns.
    let r = unsafe { WaitForSingleObject(process, INFINITE) };
    if r != WAIT_OBJECT_0 {
        return Err(wait_error(r));
    }
    let mut code: u32 = 0;
    // SAFETY: `process` as above (PROCESS_QUERY_LIMITED_INFORMATION included); `code` is
    // valid for a write.
    let ok = unsafe { GetExitCodeProcess(process, &mut code) };
    if ok == 0 {
        return Err(last_error());
    }
    Ok(code)
}

/// COM for the one `ShellExecuteExW` call: uninitialised on drop if initialisation succeeded.
struct Com(bool);

impl Com {
    fn init() -> Self {
        let flags = (COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE).cast_unsigned();
        #[expect(
            clippy::disallowed_methods,
            reason = "rerun-launch's one CoInitializeEx call site, for ShellExecuteExW on the \
                      740 path only (ADR 0022, B2)"
        )]
        // SAFETY: the reserved pointer must be null; the flags are documented COINIT values.
        let hr = unsafe { CoInitializeEx(ptr::null(), flags) };
        Self(hr >= 0)
    }
}

impl Drop for Com {
    fn drop(&mut self) {
        if self.0 {
            // SAFETY: balances the successful CoInitializeEx of this thread, exactly once.
            unsafe { CoUninitialize() };
        }
    }
}

/// B2: `ShellExecuteExW` with the default verb, `file`, the raw `parameters`, no directory;
/// `SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC`; COM initialised around the call.
pub(crate) fn shell_execute(
    file: &[u16],
    parameters: Option<&[u16]>,
) -> Result<Option<Child>, u32> {
    let file = with_nul(file);
    let parameters = parameters.map(with_nul);
    let mut info = SHELLEXECUTEINFOW {
        cbSize: len32::<SHELLEXECUTEINFOW>(),
        fMask: SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC,
        lpFile: file.as_ptr(),
        lpParameters: parameters.as_ref().map_or(ptr::null(), |p| p.as_ptr()),
        nShow: SW_SHOWNORMAL,
        ..SHELLEXECUTEINFOW::default()
    };
    let com = Com::init();
    #[expect(
        clippy::disallowed_methods,
        reason = "rerun-launch's one ShellExecuteExW call site: the 740 fallback (ADR 0022, B2)"
    )]
    // SAFETY: `info` is a SHELLEXECUTEINFOW with a matching `cbSize`; `lpFile` and
    // `lpParameters` (or null) point to NUL-terminated buffers owned by this function and alive
    // for the call; `lpVerb` and `lpDirectory` are null (default verb, current directory).
    let ok = unsafe { ShellExecuteExW(&mut info) };
    let code = if ok == 0 { last_error() } else { 0 };
    drop(com);
    if ok == 0 {
        return Err(code);
    }
    // SAFETY: with SEE_MASK_NOCLOSEPROCESS a successful call hands over `hProcess` (or null)
    // to the caller; nothing else closes it.
    let process = unsafe { own(info.hProcess) };
    Ok(process.map(|process| Child {
        process,
        thread: None,
        job: None,
    }))
}

#[cfg(test)]
mod tests {
    //! Facts ADR 0022 amendment P3-1b relies on, measured on every Windows test run. Only
    //! `System32\cmd.exe` is started, suspended, and ended at once.

    use std::os::windows::ffi::OsStrExt;
    use std::path::PathBuf;

    use super::*;

    fn cmd_exe() -> Vec<u16> {
        #[expect(
            clippy::disallowed_methods,
            reason = "test: the Windows directory for a harmless system binary"
        )]
        let root = std::env::var_os("SystemRoot").unwrap();
        let p = PathBuf::from(root).join("System32").join("cmd.exe");
        p.as_os_str().encode_wide().collect()
    }

    /// `CreateProcessW` refuses `PROC_THREAD_ATTRIBUTE_GROUP_AFFINITY` with 87 (why B-2 sets the
    /// group through the job only). If a Windows version ever accepts it, this fails and the
    /// order can be revisited.
    #[test]
    fn create_process_with_group_affinity_attribute_fails_with_87() {
        let ga = GROUP_AFFINITY {
            Mask: 1,
            Group: 0,
            Reserved: [0; 3],
        };
        let mut list = AttributeList::new(1).unwrap();
        // SAFETY: `ga` is a GROUP_AFFINITY declared before `list` and alive until after
        // CreateProcessW.
        unsafe {
            list.update(
                windows_sys::Win32::System::Threading::PROC_THREAD_ATTRIBUTE_GROUP_AFFINITY,
                ptr::from_ref(&ga).cast(),
                size_of::<GROUP_AFFINITY>(),
            )
        }
        .unwrap();
        let mut si = STARTUPINFOEXW::default();
        si.StartupInfo.cb = len32::<STARTUPINFOEXW>();
        si.lpAttributeList = list.ptr();
        let app = with_nul(&cmd_exe());
        let mut line = app.clone();
        let mut pi = PROCESS_INFORMATION::default();
        #[expect(
            clippy::disallowed_methods,
            reason = "test: measures that CreateProcessW refuses the group affinity attribute"
        )]
        // SAFETY: as in `spawn`: NUL-terminated buffers owned here, null attributes,
        // environment and directory, an initialized list alive in `list`, `pi` writable.
        let ok = unsafe {
            CreateProcessW(
                app.as_ptr(),
                line.as_mut_ptr(),
                ptr::null(),
                ptr::null(),
                0,
                CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT,
                ptr::null(),
                ptr::null(),
                ptr::from_ref(&si).cast::<STARTUPINFOW>(),
                &mut pi,
            )
        };
        let code = last_error();
        if ok != 0 {
            // It started after all: end the never-resumed child before failing.
            // SAFETY: CreateProcessW succeeded; both handles are owned here.
            let thread = unsafe { own(pi.hThread) };
            // SAFETY: as above.
            let process = unsafe { own(pi.hProcess) }.unwrap();
            terminate(Child {
                process,
                thread,
                job: None,
            });
            panic!("CreateProcessW accepted PROC_THREAD_ATTRIBUTE_GROUP_AFFINITY");
        }
        assert_eq!(code, ERROR_INVALID_PARAMETER);
    }

    /// `JobObjectGroupInformationEx` can be set on a job that holds no process yet.
    #[test]
    fn group_information_on_an_empty_job_succeeds() {
        let job = create_job().unwrap();
        let ga = GROUP_AFFINITY {
            Mask: 1,
            Group: 0,
            Reserved: [0; 3],
        };
        set_job_info(&job, JobObjectGroupInformationEx, &ga).unwrap();
    }

    /// Soft mode has teeth: the suspended child reports exactly the CPU Set set on it.
    #[cfg(target_pointer_width = "64")]
    #[test]
    fn soft_limit_reads_back() {
        let topology = crate::win::cpu::topology().unwrap();
        let id = topology.cpus[0].cpu_set_id;
        let app = cmd_exe();
        let s = Spawn {
            in_job: false,
            suspended: true,
            priority: None,
        };
        let child = spawn(&app, &app, &s).unwrap();
        set_cpu_sets(&child, &[id]).unwrap();
        let mut ids = [0u32; 4];
        let mut n: u32 = 0;
        #[expect(
            clippy::disallowed_methods,
            reason = "test: reads back the CPU Sets the shim set on its own child"
        )]
        // SAFETY: `child.process` is a live process handle with query rights; `ids` is a
        // writable array of 4 u32 and `n` is valid for a write.
        let ok = unsafe {
            windows_sys::Win32::System::Threading::GetProcessDefaultCpuSets(
                child.process.as_raw_handle(),
                ids.as_mut_ptr(),
                4,
                &mut n,
            )
        };
        let code = last_error();
        // The check's own read agrees (P3-2).
        let read = cpu_sets(&child);
        assert_eq!(terminate(child), Terminated::Ended);
        assert_ne!(ok, 0, "GetProcessDefaultCpuSets failed: {code}");
        assert_eq!(&ids[..usize::try_from(n).unwrap()], [id]);
        assert_eq!(read, Ok(vec![id]));
    }

    /// The classes the check compares are the creation flags the shim sets.
    #[test]
    fn priority_classes_are_the_creation_flags() {
        use crate::os::priority_class as class;
        assert_eq!(class(Priority::Normal), NORMAL_PRIORITY_CLASS);
        assert_eq!(class(Priority::AboveNormal), ABOVE_NORMAL_PRIORITY_CLASS);
        assert_eq!(class(Priority::High), HIGH_PRIORITY_CLASS);
        for p in [Priority::Normal, Priority::AboveNormal, Priority::High] {
            assert_eq!(priority_flag(Some(p)), class(p));
        }
    }

    /// What the post-launch check reads (P3-2) on a suspended `cmd.exe` in its job with one
    /// processor: the job's one entry, the process's mask equal to it (the job narrows the
    /// process itself), the priority class of the creation flag, no default CPU Sets, and a
    /// bounded wait that times out without consuming the child.
    #[cfg(target_pointer_width = "64")]
    #[test]
    fn check_reads_on_a_limited_child() {
        let topology = crate::win::cpu::topology().unwrap();
        let cpu = &topology.cpus[0];
        let ga = GroupAffinity {
            group: cpu.group,
            mask: 1u64 << cpu.index,
        };
        let app = cmd_exe();
        let s = Spawn {
            in_job: true,
            suspended: true,
            priority: Some(Priority::High),
        };
        let child = spawn(&app, &app, &s).unwrap();
        let before = process_affinity(&child);
        let limited = limit_job(&child, ga);
        let job = job_affinity(&child);
        let mask = process_affinity(&child);
        let class = priority_class(&child);
        let sets = cpu_sets(&child);
        let waited = wait_for(&child, 0);
        assert_eq!(terminate(child), Terminated::Ended);
        limited.unwrap();
        assert_eq!(job, Ok(vec![ga]));
        assert_eq!(mask, Ok(ga.mask), "before the limit: {before:?}");
        assert_eq!(class, Ok(HIGH_PRIORITY_CLASS));
        assert_eq!(sets, Ok(vec![]));
        assert_eq!(waited, Ok(false));
    }

    /// `wait_for` sees a child that ended, and the later `wait` still gets its exit code.
    #[test]
    fn wait_for_sees_an_ended_child_and_wait_still_reads_its_code() {
        let app = cmd_exe();
        let mut line = vec![u16::from(b'"')];
        line.extend_from_slice(&app);
        line.extend("\" /c exit 5".encode_utf16());
        let child = spawn(&app, &line, &Spawn::UNCHANGED).unwrap();
        assert_eq!(wait_for(&child, 30_000), Ok(true));
        assert_eq!(wait(child), Ok(5));
    }
}
