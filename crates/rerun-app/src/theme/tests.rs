//! Theme tokens (ADR 0027): every text/background pair of every theme reaches 4.5:1.

use super::{Rgb, ThemeId, contrast, text_pairs, tokens};

#[test]
fn every_text_pair_of_every_theme_reaches_4_5_to_1() {
    for t in ThemeId::ALL {
        let tk = tokens(t);
        let pairs = text_pairs(&tk);
        assert!(pairs.len() > 18, "{t:?}");
        let low: Vec<String> = pairs
            .iter()
            .filter(|(_, fg, bg)| contrast(*fg, *bg) < 4.5)
            .map(|(n, fg, bg)| format!("{n}: {:.2}", contrast(*fg, *bg)))
            .collect();
        assert!(low.is_empty(), "{t:?}: {low:?}");
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
