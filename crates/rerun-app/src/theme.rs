//! Theme tokens (ADR 0027): colours, radii, spacing, the type scale and the fonts as plain
//! values, framework-free. `ui` copies them into the one `.slint` global (`Theme`) at start; no
//! colour literal lives in a `.slint` file outside that global (source rule).
//!
//! Two themes, both dark (`docs/07-ui.md`, user decision E1 a of P5-10): "Mythen" (the default:
//! strictly monochrome, fills instead of borders, hairlines, the inverted primary button) and
//! "Nacht" (the neutral dark greys of Windows 11, no accent, no transparency). Windows' high
//! contrast wins over both (P5-10c): [`tokens`] then takes every colour from the system colours
//! `ui::chrome` read ([`SysColors`]) and draws the edges of controls, since fills alone may look
//! alike there. There is no own contrast palette and no light theme.

/// An sRGB colour.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rgb(pub u8, pub u8, pub u8);

impl Rgb {
    /// The relative luminance (WCAG 2.x).
    #[cfg(test)]
    pub fn luminance(self) -> f64 {
        let lin = |c: u8| {
            let s = f64::from(c) / 255.0;
            if s <= 0.040_45 {
                s / 12.92
            } else {
                ((s + 0.055) / 1.055).powf(2.4)
            }
        };
        0.2126 * lin(self.0) + 0.7152 * lin(self.1) + 0.0722 * lin(self.2)
    }

    /// The `0xRRGGBB` value.
    #[cfg(test)]
    pub fn hex(self) -> u32 {
        (u32::from(self.0) << 16) | (u32::from(self.1) << 8) | u32::from(self.2)
    }
}

/// The contrast ratio of two colours (WCAG 2.x), from 1 to 21.
#[cfg(test)]
pub fn contrast(a: Rgb, b: Rgb) -> f64 {
    let (la, lb) = (a.luminance(), b.luminance());
    let (hi, lo) = if la >= lb { (la, lb) } else { (lb, la) };
    (hi + 0.05) / (lo + 0.05)
}

/// The themes, as the settings file names them (`settings`, P5-10b).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ThemeChoice {
    /// Black and white, fills instead of borders (the default).
    #[default]
    Mythen,
    /// The neutral dark greys of Windows 11.
    Nacht,
}

impl ThemeChoice {
    /// Every theme.
    #[cfg(test)]
    pub const ALL: [Self; 2] = [Self::Mythen, Self::Nacht];
}

/// Windows' system colours while high contrast is on (`GetSysColor`, read in `ui::chrome`): the
/// only colours [`tokens`] uses then.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SysColors {
    /// `COLOR_WINDOW`: every surface.
    pub window: Rgb,
    /// `COLOR_WINDOWTEXT`: text, lines, the primary button's fill.
    pub window_text: Rgb,
    /// `COLOR_HIGHLIGHT`: the close button under the pointer.
    pub highlight: Rgb,
    /// `COLOR_HIGHLIGHTTEXT`: its glyph.
    pub highlight_text: Rgb,
    /// `COLOR_GRAYTEXT`: disabled text and the status bar.
    pub gray_text: Rgb,
}

/// The values a theme fixes. Sizes are logical pixels.
#[derive(Debug, Clone, PartialEq)]
pub struct Tokens {
    /// The window ("Fels").
    pub bg: Rgb,
    /// A raised surface (cards, groups).
    pub raised: Rgb,
    /// A raised surface under the pointer, a selected navigation entry.
    pub raised2: Rgb,
    /// Secondary buttons.
    pub raised3: Rgb,
    /// A secondary button under the pointer.
    pub raised4: Rgb,
    /// Hairlines between rows and around the window.
    pub line_soft: Rgb,
    /// Borders of inputs and the preview.
    pub line: Rgb,
    /// Strong lines (the left rule of a callout, a dashed status).
    pub line_strong: Rgb,
    /// Body text.
    pub text: Rgb,
    /// Headings, emphasised text, the primary button's fill.
    pub strong: Rgb,
    /// Secondary text.
    pub muted: Rgb,
    /// Tertiary text (the status bar).
    pub faint: Rgb,
    /// Text on the primary button.
    pub on_strong: Rgb,
    /// The close button under the pointer.
    pub danger: Rgb,
    /// The glyph of the close button under the pointer.
    pub on_danger: Rgb,
    /// The width of the edge drawn around buttons, cards, badges and the selected navigation
    /// entry: 0 in the themes (fills carry the shape), a hairline in high contrast.
    pub edge: f32,
    /// Small radius (chips, inputs).
    pub radius_s: f32,
    /// Radius of cards and buttons.
    pub radius_m: f32,
    /// Spacing scale: 4, 8, 12, 16, 24, 32, 40, 56.
    pub space: [f32; 8],
    /// Type scale: caption, small, body, large, group heading, page title, hero title.
    pub font_size: [f32; 7],
    /// Height of a library row.
    pub row_h: f32,
    /// Height of the title bar.
    pub title_h: f32,
    /// Width of a window button.
    pub caption_w: f32,
    /// The resize border at the window's edges.
    pub resize_border: f32,
    /// Width of the navigation.
    pub nav_w: f32,
    /// The text font.
    pub font_sans: &'static str,
    /// The display font of page titles.
    pub font_display: &'static str,
    /// The monospaced font (IDs, hashes, the status bar).
    pub font_mono: &'static str,
    /// The symbol font of the status glyphs.
    pub font_symbol: &'static str,
    /// The icon font of the window buttons.
    pub font_icons: &'static str,
}

/// The tokens of `t`, or of Windows' high contrast when `hc` is given (it wins). Text, display
/// and mono fonts are embedded (`assets/fonts`, `ui` imports them); a glyph they lack falls back
/// to a system font. The symbol and icon fonts are Windows'.
pub fn tokens(t: ThemeChoice, hc: Option<&SysColors>) -> Tokens {
    let base = match t {
        ThemeChoice::Mythen => Tokens {
            bg: Rgb(0x0b, 0x0b, 0x0b),
            raised: Rgb(0x11, 0x11, 0x10),
            raised2: Rgb(0x16, 0x16, 0x15),
            raised3: Rgb(0x1f, 0x1f, 0x1e),
            raised4: Rgb(0x2a, 0x2a, 0x28),
            line_soft: Rgb(0x1a, 0x1a, 0x19),
            line: Rgb(0x2e, 0x2e, 0x2c),
            line_strong: Rgb(0x8a, 0x8a, 0x86),
            text: Rgb(0xe8, 0xe8, 0xe4),
            strong: Rgb(0xf7, 0xf7, 0xf5),
            muted: Rgb(0x9c, 0x9c, 0x98),
            faint: Rgb(0x8a, 0x8a, 0x86),
            on_strong: Rgb(0x0b, 0x0b, 0x0b),
            danger: Rgb(0xc4, 0x2b, 0x1c),
            on_danger: Rgb(0xf7, 0xf7, 0xf5),
            edge: 0.0,
            ..common()
        },
        // Windows 11 dark: the window #202020, cards #2b2b2b, controls a step lighter; white
        // text, grey secondary text; no accent (the primary button stays inverted, as in Mythen).
        ThemeChoice::Nacht => Tokens {
            bg: Rgb(0x20, 0x20, 0x20),
            raised: Rgb(0x2b, 0x2b, 0x2b),
            raised2: Rgb(0x32, 0x32, 0x32),
            raised3: Rgb(0x37, 0x37, 0x37),
            raised4: Rgb(0x3d, 0x3d, 0x3d),
            line_soft: Rgb(0x30, 0x30, 0x30),
            line: Rgb(0x45, 0x45, 0x45),
            line_strong: Rgb(0x9a, 0x9a, 0x9a),
            text: Rgb(0xe6, 0xe6, 0xe6),
            strong: Rgb(0xff, 0xff, 0xff),
            muted: Rgb(0xb8, 0xb8, 0xb8),
            faint: Rgb(0xa0, 0xa0, 0xa0),
            on_strong: Rgb(0x1c, 0x1c, 0x1c),
            danger: Rgb(0xc4, 0x2b, 0x1c),
            on_danger: Rgb(0xff, 0xff, 0xff),
            edge: 0.0,
            ..common()
        },
    };
    match hc {
        Some(c) => high_contrast(c, base),
        None => base,
    }
}

/// The sizes and fonts every theme shares (the colours are overwritten).
fn common() -> Tokens {
    let none = Rgb(0, 0, 0);
    Tokens {
        bg: none,
        raised: none,
        raised2: none,
        raised3: none,
        raised4: none,
        line_soft: none,
        line: none,
        line_strong: none,
        text: none,
        strong: none,
        muted: none,
        faint: none,
        on_strong: none,
        danger: none,
        on_danger: none,
        edge: 0.0,
        radius_s: 2.0,
        radius_m: 4.0,
        space: [4.0, 8.0, 12.0, 16.0, 24.0, 32.0, 40.0, 56.0],
        font_size: [11.0, 12.0, 14.0, 16.0, 15.0, 30.0, 34.0],
        row_h: 64.0,
        title_h: 40.0,
        caption_w: 46.0,
        resize_border: 6.0,
        nav_w: 264.0,
        font_sans: "IBM Plex Sans",
        font_display: "Archivo Expanded",
        font_mono: "IBM Plex Mono",
        font_symbol: "Segoe UI Symbol",
        font_icons: "Segoe Fluent Icons",
    }
}

/// Windows' high contrast: every colour from the system colours, every surface the window's, so
/// every text is the window text on the window (the pair Windows guarantees); shapes get an edge.
fn high_contrast(c: &SysColors, base: Tokens) -> Tokens {
    Tokens {
        bg: c.window,
        raised: c.window,
        raised2: c.window,
        raised3: c.window,
        raised4: c.window,
        line_soft: c.window,
        line: c.window_text,
        line_strong: c.window_text,
        text: c.window_text,
        strong: c.window_text,
        muted: c.window_text,
        faint: c.gray_text,
        on_strong: c.window,
        danger: c.highlight,
        on_danger: c.highlight_text,
        edge: 1.0,
        ..base
    }
}

/// Every text colour on every background it is drawn on (`ui/app.slint`), named for the test.
#[cfg(test)]
pub fn text_pairs(t: &Tokens) -> Vec<(String, Rgb, Rgb)> {
    let surfaces = [
        ("bg", t.bg),
        ("raised", t.raised),
        ("raised2", t.raised2),
        ("raised3", t.raised3),
        ("raised4", t.raised4),
        ("line-soft", t.line_soft),
    ];
    // Body, strong and muted text appear on every surface; the faint text only in the status
    // bar on the window's background.
    let mut out = Vec::new();
    for (fg_name, fg) in [("text", t.text), ("strong", t.strong), ("muted", t.muted)] {
        for (bg_name, bg) in surfaces {
            out.push((format!("{fg_name} on {bg_name}"), fg, bg));
        }
    }
    out.push(("faint on bg".to_owned(), t.faint, t.bg));
    out.push(("primary button text".to_owned(), t.on_strong, t.strong));
    out.push((
        "primary button text, hovered".to_owned(),
        t.on_strong,
        t.text,
    ));
    out.push((
        "window button glyph on danger".to_owned(),
        t.on_danger,
        t.danger,
    ));
    out
}

/// Every colour of `t`, named for the test.
#[cfg(test)]
pub fn colours(t: &Tokens) -> Vec<(&'static str, Rgb)> {
    vec![
        ("bg", t.bg),
        ("raised", t.raised),
        ("raised2", t.raised2),
        ("raised3", t.raised3),
        ("raised4", t.raised4),
        ("line-soft", t.line_soft),
        ("line", t.line),
        ("line-strong", t.line_strong),
        ("text", t.text),
        ("strong", t.strong),
        ("muted", t.muted),
        ("faint", t.faint),
        ("on-strong", t.on_strong),
        ("danger", t.danger),
        ("on-danger", t.on_danger),
    ]
}

#[cfg(test)]
mod tests;
