//! Theme tokens (ADR 0027): colours, radii, spacing, the type scale and the fonts as plain
//! values, framework-free. `ui` copies them into the one `.slint` global (`Theme`) at start; no
//! colour literal lives in a `.slint` file outside that global (source rule).
//!
//! P5-3 ships the theme "Mythen" only (`docs/07-ui.md`): strictly monochrome, fills instead of
//! borders, hairlines, the inverted primary button. Nacht and Kontrast follow with P5-10 (user
//! decision U8 a); the enum stays so the settings and `ui` need no change then.

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

/// The themes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ThemeId {
    /// Black and white, fills instead of borders (the default).
    #[default]
    Mythen,
}

impl ThemeId {
    /// Every theme.
    #[cfg(test)]
    pub const ALL: [Self; 1] = [Self::Mythen];
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

/// The tokens of `t`. System fonts only in P5-3 (embedding is an open point of P5-10).
pub fn tokens(t: ThemeId) -> Tokens {
    match t {
        ThemeId::Mythen => Tokens {
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
            radius_s: 2.0,
            radius_m: 4.0,
            space: [4.0, 8.0, 12.0, 16.0, 24.0, 32.0, 40.0, 56.0],
            font_size: [11.0, 12.0, 14.0, 16.0, 15.0, 30.0, 34.0],
            row_h: 64.0,
            title_h: 40.0,
            caption_w: 46.0,
            nav_w: 264.0,
            font_sans: "Segoe UI Variable Text",
            font_display: "Segoe UI Variable Display",
            font_mono: "Consolas",
            font_symbol: "Segoe UI Symbol",
            font_icons: "Segoe Fluent Icons",
        },
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
        t.strong,
        t.danger,
    ));
    out
}

#[cfg(test)]
mod tests;
