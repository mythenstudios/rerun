//! Theme tokens (ADR 0027, P5-10c):
//! - TH1 every text/background pair of every theme reaches 4.5:1;
//! - TH2 in Windows' high contrast every colour is one of the system colours (whatever the
//!   theme), the edges are drawn, and with Windows' own contrast themes every pair still reaches
//!   4.5:1;
//! - both themes stay dark.

use super::{Rgb, SysColors, ThemeChoice, Tokens, colours, contrast, text_pairs, tokens};

fn low_pairs(tk: &Tokens) -> Vec<String> {
    text_pairs(tk)
        .iter()
        .filter(|(_, fg, bg)| contrast(*fg, *bg) < 4.5)
        .map(|(n, fg, bg)| format!("{n}: {:.2}", contrast(*fg, *bg)))
        .collect()
}

#[test]
fn th1_every_text_pair_of_every_theme_reaches_4_5_to_1() {
    for t in ThemeChoice::ALL {
        let tk = tokens(t, None);
        assert!(text_pairs(&tk).len() > 18, "{t:?}");
        let low = low_pairs(&tk);
        assert!(low.is_empty(), "{t:?}: {low:?}");
        // No edges outside high contrast: the themes draw shapes with fills.
        assert!(tk.edge.abs() < f32::EPSILON, "{t:?}");
    }
}

#[test]
fn both_themes_are_dark_and_differ() {
    for t in ThemeChoice::ALL {
        let tk = tokens(t, None);
        for (n, c) in colours(&tk) {
            if ["bg", "raised", "raised2", "raised3", "raised4", "line-soft"].contains(&n) {
                assert!(c.luminance() < 0.05, "{t:?} {n} {:06x}", c.hex());
            }
        }
    }
    assert_ne!(
        tokens(ThemeChoice::Mythen, None).bg,
        tokens(ThemeChoice::Nacht, None).bg
    );
    // Nacht is Windows 11's dark window.
    assert_eq!(tokens(ThemeChoice::Nacht, None).bg.hex(), 0x0020_2020);
}

/// Windows' "Night sky" and "Desert" contrast themes (Windows 11), and five colours that are
/// all different from every token of the themes.
fn system_themes() -> [SysColors; 3] {
    [
        SysColors {
            window: Rgb(0x00, 0x00, 0x00),
            window_text: Rgb(0xff, 0xff, 0xff),
            highlight: Rgb(0x8e, 0xe3, 0xf0),
            highlight_text: Rgb(0x26, 0x3b, 0x50),
            gray_text: Rgb(0xa6, 0xa6, 0xa6),
        },
        SysColors {
            window: Rgb(0xff, 0xfa, 0xef),
            window_text: Rgb(0x3d, 0x3d, 0x3d),
            highlight: Rgb(0x90, 0x39, 0x09),
            highlight_text: Rgb(0xff, 0xf5, 0xe3),
            gray_text: Rgb(0x67, 0x67, 0x67),
        },
        SysColors {
            window: Rgb(0x01, 0x02, 0x03),
            window_text: Rgb(0xfe, 0xfd, 0xfc),
            highlight: Rgb(0x11, 0x22, 0x33),
            highlight_text: Rgb(0xee, 0xdd, 0xcc),
            gray_text: Rgb(0x99, 0x88, 0x77),
        },
    ]
}

#[test]
fn th2_high_contrast_uses_only_the_system_colours() {
    for t in ThemeChoice::ALL {
        for sys in system_themes() {
            let tk = tokens(t, Some(&sys));
            let allowed = [
                sys.window,
                sys.window_text,
                sys.highlight,
                sys.highlight_text,
                sys.gray_text,
            ];
            for (n, c) in colours(&tk) {
                assert!(allowed.contains(&c), "{t:?} {n} {:06x}", c.hex());
            }
            assert!(tk.edge > 0.0, "{t:?}");
            // Every surface is the window, every text the window text (the pair Windows
            // guarantees), whatever the theme was.
            assert_eq!(tk.bg, sys.window);
            assert_eq!(tk.raised3, sys.window);
            assert_eq!(tk.text, sys.window_text);
            assert_eq!(tk.muted, sys.window_text);
            // Sizes and fonts are the theme's.
            assert_eq!(tk.row_h, tokens(t, None).row_h);
            assert_eq!(tk.font_sans, tokens(t, None).font_sans);
        }
        // Windows' own contrast themes keep every pair readable.
        for sys in &system_themes()[..2] {
            let low = low_pairs(&tokens(t, Some(sys)));
            assert!(low.is_empty(), "{t:?} {sys:?}: {low:?}");
        }
    }
}

#[test]
fn the_contrast_formula_has_teeth() {
    let black = Rgb(0, 0, 0);
    let white = Rgb(255, 255, 255);
    assert!((contrast(black, white) - 21.0).abs() < 1e-9);
    assert!((contrast(white, black) - 21.0).abs() < 1e-9);
    assert!((contrast(white, white) - 1.0).abs() < 1e-9);
    // WCAG's own example: #777777 on white is just under 4.5:1.
    let grey = contrast(Rgb(0x77, 0x77, 0x77), white);
    assert!(grey > 4.47 && grey < 4.5, "{grey}");
    // The disabled grey of the mockup (#6b6b68 on #1f1f1e) would fail: the test bites.
    assert!(contrast(Rgb(0x6b, 0x6b, 0x68), Rgb(0x1f, 0x1f, 0x1e)) < 4.5);
    assert_eq!(Rgb(0x0b, 0x1c, 0xf7).hex(), 0x000b_1cf7);
}
