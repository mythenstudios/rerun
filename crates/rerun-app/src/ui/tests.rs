//! Start-time guard (P5-5 preparation): the window with its six embedded fonts is created,
//! shown and drawn once, headless through Slint's software renderer (no winit window, no
//! system access beyond reading the installed fonts). It measured about 5 ms to the first frame
//! and about 25 ms with a library page of mixed scripts (Latin, CJK, Cyrillic, Hangul, symbols,
//! which also takes the system font fallback), in a `ci` build on the developer machine, with
//! or without the fonts within 12 ms of each other. The bound is generous (the user's report of
//! 1.6 s to the first window was never in this part): it catches a font registration or a
//! fallback that starts to scan the system fonts or to shape everything again.

use std::rc::Rc;
use std::time::{Duration, Instant};

use slint::ComponentHandle as _;
use slint::platform::software_renderer::{MinimalSoftwareWindow, RepaintBufferType, Rgb565Pixel};
use slint::platform::{Platform, WindowAdapter};

use super::{
    AppWindow, BadgeData, RowData, SectionData, ThemeId, model, set_strings, set_theme, theme,
};
use crate::text::Lang;

struct Headless(Rc<MinimalSoftwareWindow>);

impl Platform for Headless {
    fn create_window_adapter(&self) -> Result<Rc<dyn WindowAdapter>, slint::PlatformError> {
        Ok(self.0.clone())
    }
}

const WIDTH: u32 = 1280;
const HEIGHT: u32 = 800;

/// The library page with names of several scripts and every status symbol.
fn rows() -> Vec<RowData> {
    let names = [
        "Mafia II",
        "ゲーム 日本語",
        "Игра Кириллица",
        "Game™ ® – “quoted”",
        "한국어 게임",
        "Ünïcödé Ångström",
    ];
    let symbols = ["■", "□", "◆", "—"];
    (0..60usize)
        .map(|i| RowData {
            app_id: i32::try_from(i).unwrap_or(0),
            name: names[i % names.len()].into(),
            detail: "C:/Games/Alpha — 1.2 GB".into(),
            exe: "game.exe".into(),
            badge: BadgeData {
                sym: symbols[i % symbols.len()].into(),
                word: "applied".into(),
                quiet: false,
            },
        })
        .collect()
}

/// The only test that installs a Slint platform: the platform is one per process.
#[test]
fn the_window_draws_its_first_frames_fast() {
    let start = Instant::now();
    let window = MinimalSoftwareWindow::new(RepaintBufferType::NewBuffer);
    slint::platform::set_platform(Box::new(Headless(window.clone()))).unwrap();
    let ui = AppWindow::new().unwrap();
    let created = start.elapsed();
    set_theme(&ui, &theme::tokens(ThemeId::default()));
    set_strings(&ui, Lang::En);
    window.set_size(slint::PhysicalSize::new(WIDTH, HEIGHT));
    ui.show().unwrap();
    let mut buf = vec![Rgb565Pixel(0); (WIDTH * HEIGHT) as usize];
    let mut draw = || {
        let mut drawn = false;
        window.draw_if_needed(|r| {
            r.render(&mut buf, WIDTH as usize);
            drawn = true;
        });
        drawn
    };
    assert!(draw(), "the first frame is drawn");
    let first = start.elapsed();
    ui.set_sections(model(vec![SectionData {
        title: "Section".into(),
        rows: model(rows()),
    }]));
    assert!(draw(), "the page with rows is drawn");
    let with_rows = start.elapsed();
    eprintln!(
        "headless start: window created {created:?}, first frame {first:?}, with 60 rows {with_rows:?}"
    );
    assert!(created < Duration::from_millis(500), "{created:?}");
    assert!(first < Duration::from_millis(750), "{first:?}");
    assert!(with_rows < Duration::from_secs(1), "{with_rows:?}");
}
