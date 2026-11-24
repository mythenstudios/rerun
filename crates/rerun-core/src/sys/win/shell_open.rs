//! [`WinShell`]: the app's links and Rerun's folder handed to the user's shell (ADR 0027
//! amendment P5-10a, ADR 0008 amendment P5-10a). One of the two `ShellExecuteExW` call sites of
//! `rerun-core` (the other is `elevation`, the helper's start); COM around the call through
//! `elevation::Com` (apartment-threaded, `COINIT_DISABLE_OLE1DDE`), no `CoInitializeEx` of its
//! own.
//!
//! What it is given is already decided: an [`OpenUrl`] or an [`OpenFolder`], which only
//! `policy::open` builds. The call ([`Request::info`], a pure builder):
//! - verb `open`; the URL or the folder path as `lpFile` only; `lpParameters` and
//!   `lpDirectory` null (nothing is passed as arguments, no working directory);
//! - a link: `SEE_MASK_NOASYNC` only. Windows looks up the user's `https` handler; without one
//!   it shows its own "choose an app" dialog, owned by the app's window;
//! - a folder: also `SEE_MASK_CLASSNAME` with the class `Folder`, so the shell takes the path as
//!   a folder and Explorer navigates to it, whatever the path's own type: a file at that place
//!   would not be opened or run;
//! - never `SEE_MASK_NOCLOSEPROCESS`: no process handle comes back, nothing is waited for or
//!   kept; `SW_SHOWNORMAL`; the owner is the app's window (`PromptOwnerSlot`, as for the UAC
//!   dialog), read when the call is made.
//!
//! `ERROR_CANCELLED` (the user closed Windows' "choose an app" dialog) is no error: nothing was
//! opened, which is what the user chose. The call runs on the app's worker thread, never on the
//! UI thread (the shell may load its extensions into the process; `restrict_dll_search` holds).

#![allow(
    unsafe_code,
    reason = "FFI to shell32 for opening a link or Rerun's folder (P5-10a); every block has a \
              SAFETY comment"
)]

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::ptr;

use windows_sys::Win32::Foundation::HWND;
use windows_sys::Win32::UI::Shell::{
    SEE_MASK_CLASSNAME, SEE_MASK_NOASYNC, SHELLEXECUTEINFOW, ShellExecuteExW,
};

use super::elevation::{Com, ERROR_CANCELLED, owner_window};
use super::status::kind_of_win32;
use crate::policy::open::{OpenFolder, OpenUrl};
use crate::sys::{PromptOwnerSlot, Shell, SysError, SysResult};

/// winuser.h `SW_SHOWNORMAL` (avoids the `Win32_UI_WindowsAndMessaging` feature).
const SW_SHOWNORMAL: i32 = 1;
/// The verb of every call.
const VERB: &str = "open";
/// The class a folder is opened as.
const FOLDER_CLASS: &str = "Folder";

/// The real [`Shell`]: Windows' shell, owned by the window in its slot.
#[derive(Debug, Clone, Default)]
pub struct WinShell {
    owner: PromptOwnerSlot,
}

impl WinShell {
    /// Windows' dialogs of a call (a missing browser association) belong to the owner `slot`
    /// holds when the call is made (the app's window).
    pub fn new(owner: PromptOwnerSlot) -> Self {
        Self { owner }
    }
}

fn wide(s: &OsStr) -> Vec<u16> {
    s.encode_wide().chain([0]).collect()
}

/// One call's NUL-terminated strings and mask (module docs).
#[derive(Debug)]
struct Request {
    mask: u32,
    verb: Vec<u16>,
    file: Vec<u16>,
    class: Option<Vec<u16>>,
}

impl Request {
    /// A link for the user's `https` handler.
    fn url(url: &OpenUrl) -> Self {
        Self {
            mask: SEE_MASK_NOASYNC,
            verb: wide(OsStr::new(VERB)),
            file: wide(OsStr::new(url.as_str())),
            class: None,
        }
    }

    /// Rerun's folder for Explorer.
    fn folder(folder: &OpenFolder) -> Self {
        Self {
            mask: SEE_MASK_NOASYNC | SEE_MASK_CLASSNAME,
            verb: wide(OsStr::new(VERB)),
            file: wide(folder.path().path().as_os_str()),
            class: Some(wide(OsStr::new(FOLDER_CLASS))),
        }
    }

    /// The `SHELLEXECUTEINFOW` of the call, pointing into `self` (which must outlive it).
    fn info(&self, owner: HWND) -> SHELLEXECUTEINFOW {
        SHELLEXECUTEINFOW {
            cbSize: u32::try_from(size_of::<SHELLEXECUTEINFOW>()).unwrap_or(0),
            fMask: self.mask,
            hwnd: owner,
            lpVerb: self.verb.as_ptr(),
            lpFile: self.file.as_ptr(),
            lpParameters: ptr::null(),
            lpDirectory: ptr::null(),
            nShow: SW_SHOWNORMAL,
            lpClass: self.class.as_ref().map_or(ptr::null(), Vec::as_ptr),
            ..SHELLEXECUTEINFOW::default()
        }
    }
}

/// The last Win32 error of this thread (read right after a failed call).
fn last_error() -> u32 {
    std::io::Error::last_os_error()
        .raw_os_error()
        .map_or(0, i32::cast_unsigned)
}

impl WinShell {
    /// One `ShellExecuteExW` with `req`; `what` names it in an error.
    fn run(&self, req: &Request, what: &str) -> SysResult<()> {
        let mut info = req.info(owner_window(self.owner.get()));
        let com = Com::init();
        #[expect(
            clippy::disallowed_methods,
            reason = "one of rerun-core's two ShellExecuteExW call sites: a link or Rerun's folder \
                      for the user's shell (P5-10a; the other is elevation::start)"
        )]
        // SAFETY: `info` is a SHELLEXECUTEINFOW with a matching `cbSize`; `lpVerb`, `lpFile` and
        // `lpClass` (or null) point to NUL-terminated buffers owned by `req`, which outlives the
        // call; `lpParameters` and `lpDirectory` are null; `hwnd` is a window handle value (the
        // app's window, the console window or null), which Windows validates and never reads as
        // memory. Without SEE_MASK_NOCLOSEPROCESS no handle is returned to own.
        let ok = unsafe { ShellExecuteExW(&mut info) };
        let code = if ok == 0 { last_error() } else { 0 };
        drop(com);
        match (ok, code) {
            (0, ERROR_CANCELLED) => Ok(()),
            (0, c) => Err(SysError::new(kind_of_win32(c), what).with_win32(c)),
            _ => Ok(()),
        }
    }
}

impl Shell for WinShell {
    fn open_url(&self, url: &OpenUrl) -> SysResult<()> {
        self.run(&Request::url(url), "the default browser")
    }

    fn open_folder(&self, folder: &OpenFolder) -> SysResult<()> {
        self.run(&Request::folder(folder), "Explorer")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::open::OwnLink;
    use windows_sys::Win32::UI::Shell::{SEE_MASK_FLAG_NO_UI, SEE_MASK_NOCLOSEPROCESS};

    fn text(units: &[u16]) -> String {
        let (last, s) = units.split_last().unwrap();
        assert_eq!(*last, 0, "NUL-terminated");
        String::from_utf16(s).unwrap()
    }

    /// OL6: the call's fields, without calling the shell.
    #[test]
    fn ol6_a_link_is_the_file_and_nothing_else() {
        let url = OpenUrl::own(OwnLink::NewIssue);
        let req = Request::url(&url);
        let owner: HWND = ptr::without_provenance_mut(0x1234);
        let info = req.info(owner);
        assert_eq!(info.fMask, SEE_MASK_NOASYNC);
        assert_eq!(info.fMask & SEE_MASK_NOCLOSEPROCESS, 0);
        assert_eq!(info.fMask & SEE_MASK_FLAG_NO_UI, 0);
        assert_eq!(info.hwnd, owner);
        assert_eq!(info.lpVerb, req.verb.as_ptr());
        assert_eq!(text(&req.verb), "open");
        assert_eq!(info.lpFile, req.file.as_ptr());
        assert_eq!(text(&req.file), url.as_str());
        assert!(info.lpParameters.is_null());
        assert!(info.lpDirectory.is_null());
        assert!(info.lpClass.is_null());
        assert_eq!(info.nShow, SW_SHOWNORMAL);
        assert_eq!(info.cbSize as usize, size_of::<SHELLEXECUTEINFOW>());
    }

    #[test]
    fn ol6_a_folder_is_opened_as_the_folder_class() {
        let path = crate::path::RootPath::new(r"C:\Users\Player\AppData\Local\Rerun").unwrap();
        let folder = OpenFolder::for_test(path);
        let req = Request::folder(&folder);
        let info = req.info(ptr::null_mut());
        assert_eq!(info.fMask, SEE_MASK_NOASYNC | SEE_MASK_CLASSNAME);
        assert_eq!(text(&req.verb), "open");
        assert_eq!(text(&req.file), r"C:\Users\Player\AppData\Local\Rerun");
        let class = req.class.as_ref().unwrap();
        assert_eq!(info.lpClass, class.as_ptr());
        assert_eq!(text(class), "Folder");
        assert!(info.lpParameters.is_null());
        assert!(info.lpDirectory.is_null());
        assert_eq!(info.nShow, SW_SHOWNORMAL);
    }
}
