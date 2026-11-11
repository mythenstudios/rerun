//! The window chrome (ADR 0026): the only `unsafe` and the only `windows-sys` window calls of
//! `rerun-app`, under the rules of `sys::win` (every block one operation with a `// SAFETY:`
//! comment; source rule in `tests/source_rules.rs`).
//!
//! - The snap layouts of Windows 11 appear only for a window that answers `WM_NCHITTEST` with
//!   `HTMAXBUTTON` over its maximise button. Rerun's window is frameless with its own title bar
//!   (`docs/07-ui.md`), so a window subclass answers it over Rerun's own maximise button and
//!   turns the non-client mouse messages there into a hover state and a click.
//! - The Windows display language picks the app's language (ADR 0027).
//!
//! The window handle is read through `raw-window-handle` here and nowhere else. The subclass
//! state lives in thread-locals of the UI thread, the only thread the window procedure runs on.

#![allow(
    unsafe_code,
    reason = "the window subclass and two Win32 reads (ADR 0026: ui::chrome is the one place)"
)]

/// What the subclass tells the window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Chrome {
    /// The pointer is over the maximise button (`true`) or left it.
    Hover(bool),
    /// The maximise button was clicked.
    ToggleMaximized,
}

#[cfg(windows)]
pub use win::{install, ui_language};

#[cfg(not(windows))]
/// The Windows display language; English elsewhere.
pub fn ui_language() -> u16 {
    0x0409
}

#[cfg(not(windows))]
/// No subclass outside Windows.
pub fn install(
    _window: &slint::Window,
    _title_h: f32,
    _caption_w: f32,
    _on: Box<dyn Fn(Chrome)>,
) -> bool {
    false
}

#[cfg(windows)]
mod win {
    use std::cell::{Cell, RefCell};

    use raw_window_handle::{HasWindowHandle, RawWindowHandle};
    use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, POINT, RECT, WPARAM};
    use windows_sys::Win32::Globalization::GetUserDefaultUILanguage;
    use windows_sys::Win32::Graphics::Gdi::ScreenToClient;
    use windows_sys::Win32::UI::HiDpi::GetDpiForWindow;
    use windows_sys::Win32::UI::Input::KeyboardAndMouse::{
        TME_LEAVE, TME_NONCLIENT, TRACKMOUSEEVENT, TrackMouseEvent,
    };
    use windows_sys::Win32::UI::Shell::{DefSubclassProc, RemoveWindowSubclass, SetWindowSubclass};
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        GetClientRect, HTMAXBUTTON, WM_NCDESTROY, WM_NCHITTEST, WM_NCLBUTTONDOWN, WM_NCLBUTTONUP,
        WM_NCMOUSELEAVE, WM_NCMOUSEMOVE,
    };

    use super::Chrome;

    /// The subclass ID (one subclass per window).
    const SUBCLASS_ID: usize = 1;

    /// Where the window learns about hover and clicks.
    type OnChrome = Option<Box<dyn Fn(Chrome)>>;

    thread_local! {
        /// Where the window learns about hover and clicks.
        static ON: RefCell<OnChrome> = const { RefCell::new(None) };
        /// The title bar height and the window button width, in logical pixels.
        static GEOMETRY: Cell<(f64, f64)> = const { Cell::new((0.0, 0.0)) };
    }

    /// The Windows display language (`LANGID`) of the user.
    pub fn ui_language() -> u16 {
        // SAFETY: no arguments, no pointers; returns a value.
        unsafe { GetUserDefaultUILanguage() }
    }

    /// The window handle of `window`, once the native window exists.
    fn hwnd_of(window: &slint::Window) -> Option<HWND> {
        let handle = window.window_handle();
        let raw = handle.window_handle().ok()?.as_raw();
        match raw {
            RawWindowHandle::Win32(w) => Some(w.hwnd.get() as HWND),
            _ => None,
        }
    }

    /// Installs the snap-layout subclass on `window`'s native window: `title_h` and `caption_w`
    /// are the title bar height and the window button width (logical pixels; the maximise
    /// button is the second from the right). `false` if the native window does not exist yet
    /// or the subclass could not be set.
    pub fn install(
        window: &slint::Window,
        title_h: f32,
        caption_w: f32,
        on: Box<dyn Fn(Chrome)>,
    ) -> bool {
        let Some(hwnd) = hwnd_of(window) else {
            return false;
        };
        GEOMETRY.with(|g| g.set((f64::from(title_h), f64::from(caption_w))));
        ON.with(|o| *o.borrow_mut() = Some(on));
        // SAFETY: `hwnd` is the live top-level window of this thread (Slint's own window, read
        // just now); `subclass` is a function that lives for the whole process.
        let ok = unsafe { SetWindowSubclass(hwnd, Some(subclass), SUBCLASS_ID, 0) };
        ok != 0
    }

    fn tell(c: Chrome) {
        ON.with(|o| {
            if let Some(f) = o.borrow().as_ref() {
                f(c);
            }
        });
    }

    /// The low and high signed words of `lparam` (screen coordinates of a non-client message).
    fn point_of(lparam: LPARAM) -> POINT {
        // The low word of `v` as a signed 16-bit value (GET_X_LPARAM, GET_Y_LPARAM).
        let word = |v: isize| {
            let [lo, hi, ..] = v.to_le_bytes();
            i32::from(i16::from_le_bytes([lo, hi]))
        };
        POINT {
            x: word(lparam),
            y: word(lparam >> 16),
        }
    }

    /// Whether the screen point in `lparam` is over Rerun's maximise button.
    fn over_max_button(hwnd: HWND, lparam: LPARAM) -> bool {
        let mut pt = point_of(lparam);
        let mut rc = RECT {
            left: 0,
            top: 0,
            right: 0,
            bottom: 0,
        };
        // SAFETY: `hwnd` is the window this procedure belongs to; `pt` is a valid, writable
        // POINT.
        if unsafe { ScreenToClient(hwnd, &mut pt) } == 0 {
            return false;
        }
        // SAFETY: as above; `rc` is a valid, writable RECT.
        if unsafe { GetClientRect(hwnd, &mut rc) } == 0 {
            return false;
        }
        // SAFETY: `hwnd` is a valid window; returns a value.
        let dpi = unsafe { GetDpiForWindow(hwnd) };
        let scale = f64::from(if dpi == 0 { 96 } else { dpi }) / 96.0;
        let (title_h, caption_w) = GEOMETRY.with(Cell::get);
        let right = f64::from(rc.right);
        let (x, y) = (f64::from(pt.x), f64::from(pt.y));
        y >= 0.0
            && y < title_h * scale
            && x >= right - 2.0 * caption_w * scale
            && x < right - caption_w * scale
    }

    /// Asks for `WM_NCMOUSELEAVE` once the pointer leaves the non-client area.
    fn track_leave(hwnd: HWND) {
        let mut tme = TRACKMOUSEEVENT {
            cbSize: u32::try_from(size_of::<TRACKMOUSEEVENT>()).unwrap_or(0),
            dwFlags: TME_LEAVE | TME_NONCLIENT,
            hwndTrack: hwnd,
            dwHoverTime: 0,
        };
        // SAFETY: `tme` is a valid, initialised TRACKMOUSEEVENT for this thread's own window.
        unsafe { TrackMouseEvent(&mut tme) };
    }

    /// The subclass procedure.
    ///
    /// # Safety
    /// Called by Windows (comctl32) with the arguments of a window message of `hwnd`.
    unsafe extern "system" fn subclass(
        hwnd: HWND,
        msg: u32,
        wparam: WPARAM,
        lparam: LPARAM,
        id: usize,
        _data: usize,
    ) -> LRESULT {
        let on_max = wparam == HTMAXBUTTON as usize;
        match msg {
            WM_NCHITTEST if over_max_button(hwnd, lparam) => return HTMAXBUTTON as LRESULT,
            WM_NCMOUSEMOVE if on_max => {
                track_leave(hwnd);
                tell(Chrome::Hover(true));
                return 0;
            }
            WM_NCMOUSEMOVE | WM_NCMOUSELEAVE => tell(Chrome::Hover(false)),
            WM_NCLBUTTONDOWN if on_max => return 0,
            WM_NCLBUTTONUP if on_max => {
                tell(Chrome::Hover(false));
                tell(Chrome::ToggleMaximized);
                return 0;
            }
            WM_NCDESTROY => {
                // SAFETY: removes this very subclass from its window before the window goes.
                unsafe { RemoveWindowSubclass(hwnd, Some(subclass), id) };
            }
            _ => {}
        }
        // SAFETY: forwards the message with its original arguments to the next procedure.
        unsafe { DefSubclassProc(hwnd, msg, wparam, lparam) }
    }
}
