//! The window chrome (ADR 0026): the only `unsafe` and the only `windows-sys` window calls of
//! `rerun-app`, under the rules of `sys::win` (every block one operation with a `// SAFETY:`
//! comment; source rule in `tests/source_rules.rs`).
//!
//! - The snap layouts of Windows 11 appear only for a window that answers `WM_NCHITTEST` with
//!   `HTMAXBUTTON` over its maximise button. Rerun's window is frameless with its own title bar
//!   (`docs/07-ui.md`), so a window subclass answers it over Rerun's own maximise button and
//!   turns the non-client mouse messages there into a hover state and a click.
//! - The same subclass makes sure a window drag always ends ([`SizeMove`]): winit refuses every
//!   move and resize after one that Windows never ran.
//! - The Windows display language picks the app's language (ADR 0027).
//! - Windows' high contrast (P5-10c, ADR 0026 amendment P5-10): [`high_contrast`] reads whether
//!   it is on (`SPI_GETHIGHCONTRAST`) and, if so, the five system colours the theme then uses
//!   (`GetSysColor`). The subclass tells the window when Windows' colours or settings change
//!   (`WM_SYSCOLORCHANGE`, `WM_SETTINGCHANGE`: [`Chrome::ColorsChanged`]), so switching high
//!   contrast on or off follows at once, without a hook of its own.
//! - An elevated start is told with a plain message box before any Slint object exists (`main`,
//!   security review S1 of P5-3).
//! - The owner of the UAC dialog (P5-5c, ADR 0023 amendment P5-5c): [`owner_of`] reads the
//!   window's handle value for the worker, which builds its system with it
//!   (`WinSystem::with_prompt_owner`), so the dialog of a helper start appears in front of this
//!   window. The value leaves this module as a plain number; no other module of `rerun-app`
//!   names a window handle type.
//!
//! The caption geometry is coupled to `ui/app.slint`: the three `CaptionButton`s are the last
//! elements of the title bar, each `Theme.caption-w` wide, the maximise button the second from
//! the right, the title bar `Theme.title-h` high, the window's `resize-border-width` at its
//! edges. `ui` passes those tokens here; a source rule checks the order of the three buttons.
//!
//! AccessKit's UI Automation adapter replaces the procedure of the same window with
//! `SetWindowLongPtrW`. A comctl32 subclass is independent of that: comctl32 keeps its own
//! procedure in the chain and calls the next one through `DefSubclassProc`, whichever was
//! installed later, so both see every message.
//!
//! The window handle is read through `raw-window-handle` here and nowhere else. The subclass
//! state lives in thread-locals of the UI thread, the only thread the window procedure runs on.

#![allow(
    unsafe_code,
    reason = "the window subclass, a message box, the display language and high contrast \
              (ADR 0026: ui::chrome is the one place)"
)]

use crate::theme::SysColors;

/// The caption geometry in logical pixels (see the module docs).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Geometry {
    /// The title bar's height.
    pub title_h: f32,
    /// One window button's width.
    pub caption_w: f32,
    /// The resize border at the window's edges (not while maximised).
    pub resize_border: f32,
}

/// What the subclass asks the window on every hit test.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct WindowState {
    /// Physical pixels per logical pixel, as Slint lays out.
    pub scale: f32,
    /// The window is maximised (no resize border).
    pub maximized: bool,
}

/// What the subclass tells the window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Chrome {
    /// The pointer is over the maximise button (`true`) or left it.
    Hover(bool),
    /// The maximise button was clicked.
    ToggleMaximized,
    /// Windows' colours or settings changed: high contrast may have been switched (the window
    /// reads [`high_contrast`] again).
    ColorsChanged,
}

/// Whether the client point `(x, y)` is over the maximise button of a client area `right`
/// pixels wide. Not on the top resize border of a window that is not maximised (review N3):
/// the border keeps resizing there.
pub fn hit_max_button(g: Geometry, state: WindowState, right: f64, x: f64, y: f64) -> bool {
    let scale = f64::from(state.scale);
    let top = if state.maximized {
        0.0
    } else {
        f64::from(g.resize_border) * scale
    };
    let caption = f64::from(g.caption_w) * scale;
    y >= top
        && y < f64::from(g.title_h) * scale
        && x >= right - 2.0 * caption
        && x < right - caption
}

/// Whether a move or resize the window asked Windows for ended without Windows' size-move loop.
///
/// Slint's `WindowMoveArea` and resize border start a drag through winit (`drag_window`,
/// `drag_resize_window`), which marks itself as dragging, posts `WM_NCLBUTTONDOWN` with the hit
/// test of the drag and refuses every further drag until `WM_EXITSIZEMOVE` arrives (winit
/// 0.30). Windows sends that only at the end of a size-move loop it entered
/// (`WM_ENTERSIZEMOVE`). When it enters none, a resize on the edge of a maximised window being
/// the known case, winit stays dragging for good: the window can no longer be moved or resized,
/// only minimised and restored through the taskbar. The subclass watches every such button
/// press: [`SizeMove::pressed`] before Windows handles it, [`SizeMove::entered`] on
/// `WM_ENTERSIZEMOVE`, and when [`SizeMove::handled`] says no loop ran (`DefWindowProc` runs
/// the loop before it returns), it tells winit the drag is over with a `WM_EXITSIZEMOVE` of its
/// own.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SizeMove {
    entered: bool,
}

impl SizeMove {
    /// The left button went down on the non-client area (not on the maximise button).
    pub fn pressed(&mut self) {
        self.entered = false;
    }

    /// Windows entered its size-move loop.
    pub fn entered(&mut self) {
        self.entered = true;
    }

    /// Windows has handled the press: `true` if it ran no size-move loop, so no
    /// `WM_EXITSIZEMOVE` came and one must be sent.
    pub fn handled(&mut self) -> bool {
        !std::mem::replace(&mut self.entered, false)
    }
}

#[cfg(windows)]
pub use win::{high_contrast, install, message_box, owner_of, ui_language};

#[cfg(all(windows, feature = "test-key"))]
pub use win::process_age_ms;

#[cfg(not(windows))]
/// The Windows display language; English elsewhere.
pub fn ui_language() -> u16 {
    0x0409
}

#[cfg(not(windows))]
/// No high contrast outside Windows.
pub fn high_contrast() -> Option<SysColors> {
    None
}

#[cfg(not(windows))]
/// No subclass outside Windows.
pub fn install(
    _window: &slint::Window,
    _geometry: Geometry,
    _state: Box<dyn Fn() -> WindowState>,
    _on: Box<dyn Fn(Chrome)>,
) -> bool {
    false
}

#[cfg(not(windows))]
/// No message box outside Windows.
pub fn message_box(_title: &str, _text: &str) {}

#[cfg(not(windows))]
/// No window handle outside Windows.
pub fn owner_of(_window: &slint::Window) -> Option<isize> {
    None
}

#[cfg(windows)]
mod win {
    use std::cell::{Cell, RefCell};

    use raw_window_handle::{HasWindowHandle, RawWindowHandle};
    use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, POINT, RECT, WPARAM};
    use windows_sys::Win32::Globalization::GetUserDefaultUILanguage;
    use windows_sys::Win32::Graphics::Gdi::{
        COLOR_GRAYTEXT, COLOR_HIGHLIGHT, COLOR_HIGHLIGHTTEXT, COLOR_WINDOW, COLOR_WINDOWTEXT,
        GetSysColor, SYS_COLOR_INDEX, ScreenToClient,
    };
    use windows_sys::Win32::UI::Accessibility::{HCF_HIGHCONTRASTON, HIGHCONTRASTW};
    use windows_sys::Win32::UI::HiDpi::GetDpiForWindow;
    use windows_sys::Win32::UI::Input::KeyboardAndMouse::{
        TME_LEAVE, TME_NONCLIENT, TRACKMOUSEEVENT, TrackMouseEvent,
    };
    use windows_sys::Win32::UI::Shell::{DefSubclassProc, RemoveWindowSubclass, SetWindowSubclass};
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        GetClientRect, HTMAXBUTTON, IDC_HAND, LoadCursorW, MB_ICONWARNING, MB_OK, MessageBoxW,
        SPI_GETHIGHCONTRAST, SetCursor, SystemParametersInfoW, WM_ENTERSIZEMOVE, WM_EXITSIZEMOVE,
        WM_NCDESTROY, WM_NCHITTEST, WM_NCLBUTTONDBLCLK, WM_NCLBUTTONDOWN, WM_NCLBUTTONUP,
        WM_NCMOUSELEAVE, WM_NCMOUSEMOVE, WM_SETCURSOR, WM_SETTINGCHANGE, WM_SYSCOLORCHANGE,
    };

    use super::{Chrome, Geometry, SizeMove, SysColors, WindowState, hit_max_button};
    use crate::theme::Rgb;

    /// The subclass ID (one subclass per window).
    const SUBCLASS_ID: usize = 1;

    /// Where the window learns about hover and clicks.
    type OnChrome = Option<Box<dyn Fn(Chrome)>>;
    /// Where the subclass asks for the window's scale and state.
    type StateOf = Option<Box<dyn Fn() -> WindowState>>;

    thread_local! {
        /// Where the window learns about hover and clicks.
        static ON: RefCell<OnChrome> = const { RefCell::new(None) };
        /// Where the subclass asks for the window's scale and state.
        static STATE: RefCell<StateOf> = const { RefCell::new(None) };
        /// The caption geometry.
        static GEOMETRY: Cell<Geometry> = const {
            Cell::new(Geometry { title_h: 0.0, caption_w: 0.0, resize_border: 0.0 })
        };
        /// The left button went down over the maximise button and has not come up or left it.
        static PRESSED: Cell<bool> = const { Cell::new(false) };
        /// Whether Windows entered its size-move loop for the last drag (see [`SizeMove`]).
        static SIZE_MOVE: Cell<SizeMove> = const { Cell::new(SizeMove { entered: false }) };
    }

    /// The Windows display language (`LANGID`) of the user.
    pub fn ui_language() -> u16 {
        // SAFETY: no arguments, no pointers; returns a value.
        unsafe { GetUserDefaultUILanguage() }
    }

    /// Windows' high contrast: `None` while it is off (or cannot be read: the theme stays),
    /// else the system colours the tokens take (`theme::tokens`).
    pub fn high_contrast() -> Option<SysColors> {
        let mut hc = HIGHCONTRASTW {
            cbSize: u32::try_from(size_of::<HIGHCONTRASTW>()).unwrap_or(0),
            dwFlags: 0,
            lpszDefaultScheme: std::ptr::null_mut(),
        };
        // SAFETY: `hc` is a valid, writable HIGHCONTRASTW whose `cbSize` is its size, the size
        // passed too; Windows fills it and sets `lpszDefaultScheme` to a buffer of its own, which
        // is never read here; no profile update (`fWinIni` 0).
        let ok = unsafe {
            SystemParametersInfoW(SPI_GETHIGHCONTRAST, hc.cbSize, (&raw mut hc).cast(), 0)
        };
        if ok == 0 || hc.dwFlags & HCF_HIGHCONTRASTON == 0 {
            return None;
        }
        Some(SysColors {
            window: sys_color(COLOR_WINDOW),
            window_text: sys_color(COLOR_WINDOWTEXT),
            highlight: sys_color(COLOR_HIGHLIGHT),
            highlight_text: sys_color(COLOR_HIGHLIGHTTEXT),
            gray_text: sys_color(COLOR_GRAYTEXT),
        })
    }

    /// One system colour (`0x00BBGGRR`).
    fn sys_color(index: SYS_COLOR_INDEX) -> Rgb {
        // SAFETY: no pointers; `index` is one of the documented `COLOR_*` constants; returns a
        // value.
        let bgr = unsafe { GetSysColor(index) };
        let [r, g, b, _] = bgr.to_le_bytes();
        Rgb(r, g, b)
    }

    /// Milliseconds since the operating system created this process (the [DEV] test-key app's
    /// timing trace only): what passed before `main` ran (loader, antivirus scan, Smart App
    /// Control check of a fresh binary).
    #[cfg(feature = "test-key")]
    pub fn process_age_ms() -> Option<f64> {
        use windows_sys::Win32::Foundation::FILETIME;
        use windows_sys::Win32::System::SystemInformation::GetSystemTimePreciseAsFileTime;
        use windows_sys::Win32::System::Threading::{GetCurrentProcess, GetProcessTimes};
        let zero = FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        };
        let (mut created, mut exited, mut kernel, mut user) = (zero, zero, zero, zero);
        // SAFETY: no arguments; returns the pseudo handle of this process (never closed).
        let this = unsafe { GetCurrentProcess() };
        // SAFETY: `this` is the pseudo handle; the four pointers are valid, writable
        // FILETIMEs for the call.
        let ok =
            unsafe { GetProcessTimes(this, &mut created, &mut exited, &mut kernel, &mut user) };
        if ok == 0 {
            return None;
        }
        let mut now = zero;
        // SAFETY: one valid, writable FILETIME for the call.
        unsafe { GetSystemTimePreciseAsFileTime(&mut now) };
        let ticks = |t: FILETIME| (u64::from(t.dwHighDateTime) << 32) | u64::from(t.dwLowDateTime);
        // FILETIME counts 100 ns.
        Some(ticks(now).saturating_sub(ticks(created)) as f64 / 10_000.0)
    }

    /// A modal message box without an owner (no window exists yet); `title` and `text` are
    /// Rerun's own texts.
    pub fn message_box(title: &str, text: &str) {
        let wide = |s: &str| -> Vec<u16> { s.encode_utf16().chain(Some(0)).collect() };
        let (title, text) = (wide(title), wide(text));
        // SAFETY: both are NUL-terminated UTF-16 buffers that live across the call; no owner.
        unsafe {
            MessageBoxW(
                std::ptr::null_mut(),
                text.as_ptr(),
                title.as_ptr(),
                MB_OK | MB_ICONWARNING,
            )
        };
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

    /// The raw handle value of `window`'s native window, once it exists: the owner of the UAC
    /// dialog of a helper start (module docs). A number, not a pointer: the system layer passes
    /// it to Windows unchanged, and Windows checks it.
    pub fn owner_of(window: &slint::Window) -> Option<isize> {
        let handle = window.window_handle();
        let raw = handle.window_handle().ok()?.as_raw();
        match raw {
            RawWindowHandle::Win32(w) => Some(w.hwnd.get()),
            _ => None,
        }
    }

    /// Installs the snap-layout subclass on `window`'s native window (`geometry`: the module
    /// docs; `state`: Slint's scale factor and the maximised state, asked on every hit test, so
    /// a DPI change or `SLINT_SCALE_FACTOR` cannot move the hit area away from the drawn button,
    /// review N1). `false` if the native window does not exist yet or the subclass failed.
    pub fn install(
        window: &slint::Window,
        geometry: Geometry,
        state: Box<dyn Fn() -> WindowState>,
        on: Box<dyn Fn(Chrome)>,
    ) -> bool {
        let Some(hwnd) = hwnd_of(window) else {
            return false;
        };
        GEOMETRY.with(|g| g.set(geometry));
        STATE.with(|s| *s.borrow_mut() = Some(state));
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
        let asked = STATE.with(|s| s.borrow().as_ref().map(|f| f()));
        let state = match asked {
            Some(s) => s,
            None => {
                // SAFETY: `hwnd` is a valid window; returns a value.
                let dpi = unsafe { GetDpiForWindow(hwnd) };
                WindowState {
                    scale: f32::from(u16::try_from(dpi).unwrap_or(96).max(96)) / 96.0,
                    maximized: false,
                }
            }
        };
        hit_max_button(
            GEOMETRY.with(Cell::get),
            state,
            f64::from(rc.right),
            f64::from(pt.x),
            f64::from(pt.y),
        )
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
            // The hand cursor of Rerun's other buttons (review N5); the hit-test code is the low
            // word of `lparam`.
            WM_SETCURSOR if lparam & 0xffff == HTMAXBUTTON as isize => {
                // SAFETY: a shared system cursor; no instance handle.
                let hand = unsafe { LoadCursorW(std::ptr::null_mut(), IDC_HAND) };
                // SAFETY: `hand` is a cursor handle (null would only hide the cursor).
                unsafe { SetCursor(hand) };
                return 1;
            }
            WM_NCMOUSEMOVE if on_max => {
                track_leave(hwnd);
                tell(Chrome::Hover(true));
                return 0;
            }
            WM_NCMOUSEMOVE | WM_NCMOUSELEAVE => {
                // A press that left the button never toggles (review M2).
                PRESSED.with(|p| p.set(false));
                tell(Chrome::Hover(false));
            }
            // A double click on the button is a press like any other, never the caption's own
            // maximise (review M1).
            WM_NCLBUTTONDOWN | WM_NCLBUTTONDBLCLK if on_max => {
                PRESSED.with(|p| p.set(true));
                return 0;
            }
            WM_NCLBUTTONUP if on_max => {
                tell(Chrome::Hover(false));
                if PRESSED.with(|p| p.replace(false)) {
                    tell(Chrome::ToggleMaximized);
                }
                return 0;
            }
            WM_NCLBUTTONUP => PRESSED.with(|p| p.set(false)),
            // The drag winit asked for (the window is frameless: every other non-client press
            // is one): Windows runs its size-move loop inside the next procedure, or none.
            WM_NCLBUTTONDOWN => {
                SIZE_MOVE.with(|c| {
                    let mut s = c.get();
                    s.pressed();
                    c.set(s);
                });
                // SAFETY: forwards the message with its original arguments to the next
                // procedure.
                let r = unsafe { DefSubclassProc(hwnd, msg, wparam, lparam) };
                let mut s = SIZE_MOVE.with(Cell::get);
                if s.handled() {
                    // SAFETY: the message Windows sends at the end of a size-move loop, with
                    // its own arguments (both 0), to the next procedure of this window.
                    unsafe { DefSubclassProc(hwnd, WM_EXITSIZEMOVE, 0, 0) };
                }
                SIZE_MOVE.with(|c| c.set(s));
                return r;
            }
            WM_ENTERSIZEMOVE => SIZE_MOVE.with(|c| {
                let mut s = c.get();
                s.entered();
                c.set(s);
            }),
            // Windows' colours or settings changed (high contrast on or off among them): the
            // window reads them again; the message goes on to the next procedure as well.
            WM_SYSCOLORCHANGE | WM_SETTINGCHANGE => tell(Chrome::ColorsChanged),
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

#[cfg(test)]
mod tests {
    use super::{Geometry, SizeMove, WindowState, hit_max_button};

    #[test]
    fn a_drag_without_a_size_move_loop_is_ended() {
        let mut s = SizeMove::default();
        // A move or resize Windows ran: its own WM_EXITSIZEMOVE ended it.
        s.pressed();
        s.entered();
        assert!(!s.handled());
        // A resize on the edge of a maximised window: no loop, so one is sent.
        s.pressed();
        assert!(s.handled());
        // A loop from before (a keyboard move through the system menu) does not count for the
        // next press.
        s.entered();
        s.pressed();
        assert!(s.handled());
        // Handled once: the state is clean for the next press.
        s.pressed();
        s.entered();
        assert!(!s.handled());
        assert_eq!(s, SizeMove::default());
    }

    const G: Geometry = Geometry {
        title_h: 40.0,
        caption_w: 46.0,
        resize_border: 6.0,
    };

    #[test]
    fn the_max_button_hit_test() {
        let at = |scale: f32, maximized, x, y| {
            let right = 1200.0 * f64::from(scale);
            hit_max_button(G, WindowState { scale, maximized }, right, x, y)
        };
        // 100 %: the button spans x 1108..1154, y 6..40; the resize border above it stays.
        assert!(at(1.0, false, 1110.0, 20.0));
        assert!(at(1.0, false, 1153.0, 39.0));
        assert!(!at(1.0, false, 1154.0, 20.0)); // the close button
        assert!(!at(1.0, false, 1107.0, 20.0)); // the minimise button
        assert!(!at(1.0, false, 1110.0, 3.0)); // the top resize border
        assert!(at(1.0, true, 1110.0, 3.0)); // maximised: no border
        assert!(!at(1.0, false, 1110.0, 40.0)); // below the title bar
        // 150 %: everything scales.
        assert!(at(1.5, false, 1662.0, 30.0));
        assert!(!at(1.5, false, 1662.0, 8.0));
        assert!(!at(1.5, false, 1731.0, 30.0));
    }
}
