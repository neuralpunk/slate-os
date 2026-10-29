// SPDX-License-Identifier: MIT OR Apache-2.0

//! Graphite, the desktop theme of docs/design/WM_STYLE.md §2 (Strata, ADR 0037):
//! warm near-black surfaces, chalk rationed for focus and selection, and
//! the high-contrast variant of §10.

use alloc::vec::Vec;

use crate::color::Color;
use crate::math::round;
use crate::paint::Painter;
use crate::shadow::BoxShadow;
use crate::ui::Area;

/// A semantic colour (docs/design/STRATA_COLORS.md): the colour itself for text,
/// icons and thin strokes; its tint (14% of it in `window`) for badges,
/// banners and highlighted rows; its border (35%) to outline a tint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Accent {
    pub text: Color,
    pub tint: Color,
    pub border: Color,
}

impl Accent {
    pub(crate) const fn new(text: u32, tint: u32, border: u32) -> Accent {
        Accent { text: Color::rgb(text), tint: Color::rgb(tint), border: Color::rgb(border) }
    }
}

/// The semantic colours, by meaning (STRATA_COLORS.md's palette and
/// rules: meaning only, never decoration, never colour alone).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Accents {
    /// Errors, destructive actions.
    pub clay: Accent,
    /// Warnings, pending states.
    pub ochre: Accent,
    /// Success, verified.
    pub sage: Accent,
    /// The Linux domain's marker.
    pub moss: Accent,
    /// Information, links.
    pub steel: Accent,
    /// A personal accent.
    pub heather: Accent,
}

/// A theme's geometry (ADR 0167): the title bar's height (its groove
/// included), the frames' corner radius, the top bar's height, the
/// focused frame's halo (a solid ring outside the outline; 0 for none),
/// the frames' shadows and the title's type.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Shape {
    pub title_h: f32,
    pub frame_r: f32,
    pub bar_h: f32,
    pub halo: f32,
    pub shadow_focused: [BoxShadow; 2],
    pub shadow_unfocused: BoxShadow,
    /// The window's name: its size, semibold (else medium), tracking.
    pub title_size: f32,
    pub title_semibold: bool,
    pub title_tracking: f32,
}

impl Shape {
    /// Graphite's (Atelier, ADR 0124): a contact shadow and a lifting one
    /// focused, a quieter one unfocused.
    pub const GRAPHITE: Shape = Shape {
        title_h: 36.0,
        frame_r: 12.0,
        bar_h: 32.0,
        halo: 0.0,
        shadow_focused: [
            BoxShadow { dx: 0.0, dy: 2.0, blur: 6.0, spread: 0.0, color: Color::rgb(0).with_alpha(89) },
            BoxShadow { dx: 0.0, dy: 32.0, blur: 72.0, spread: -28.0, color: Color::rgb(0).with_alpha(191) },
        ],
        shadow_unfocused: BoxShadow {
            dx: 0.0,
            dy: 8.0,
            blur: 24.0,
            spread: -8.0,
            color: Color::rgb(0).with_alpha(128),
        },
        title_size: 12.5,
        title_semibold: false,
        title_tracking: -0.005,
    };

    /// The light variant's: graphite's, with lighter shadows.
    pub const DAY: Shape = Shape {
        shadow_focused: [
            BoxShadow { dx: 0.0, dy: 2.0, blur: 6.0, spread: 0.0, color: Color::rgb(0).with_alpha(20) },
            BoxShadow { dx: 0.0, dy: 32.0, blur: 64.0, spread: -28.0, color: Color::rgb(0).with_alpha(77) },
        ],
        shadow_unfocused: BoxShadow {
            dx: 0.0,
            dy: 8.0,
            blur: 24.0,
            spread: -10.0,
            color: Color::rgb(0).with_alpha(46),
        },
        ..Shape::GRAPHITE
    };
}

/// Graphite's tokens.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Palette {
    // Surfaces, darkest to lightest.
    pub desktop: Color,
    pub well: Color,
    pub window: Color,
    pub overlay: Color,
    pub line_current: Color,
    pub header: Color,
    pub divider: Color,
    pub raised: Color,
    pub active_ws: Color,
    pub border: Color,
    pub border_strong: Color,
    // Text and marks, brightest to dimmest.
    pub chalk: Color,
    pub focus: Color,
    pub text_1: Color,
    pub text_2: Color,
    pub text_3: Color,
    pub text_4: Color,
    pub muted: Color,
    pub inactive: Color,
    pub decor: Color,
    /// The border of unfocused windows.
    pub unfocused: Color,
    // Inverted selection (§5).
    pub selected_tile: Color,
    pub selected_meta: Color,
    pub selected_tag: Color,
    /// A selected list row inside apps (§7).
    pub list_selected: Color,
    /// The focused password field's border (§6).
    pub field_focus: Color,
    // The wallpaper's contour lines, top to bottom (§2, §8).
    pub contour_top: Color,
    pub contour_bottom: Color,
    /// The dim layers behind the launcher and system dialogs.
    pub dim_launcher: Color,
    pub dim_dialog: Color,
    // The title bar (Atelier, ADR 0124): a tone off the content, a 1 px
    // groove under it, a 1 px rim of light along its top while focused
    // (transparent where there is none).
    pub titlebar: Color,
    pub titlebar_unfocused: Color,
    pub titlebar_groove: Color,
    pub titlebar_rim: Color,
    /// The focused bar's path and buttons.
    pub titlebar_path: Color,
    pub titlebar_button: Color,
    /// Lineation's lines (ADR 0124): the fine ones and every ninth.
    pub lineation_fine: Color,
    pub lineation_accent: Color,
    /// Colour with meaning (STRATA_COLORS.md).
    pub accents: Accents,
    // The theme's own colour (ADR 0167): chalk in graphite and Light.
    /// Selection, the active workspace, charts and folders.
    pub accent: Color,
    /// Text and icons on an `accent` fill.
    pub accent_on: Color,
    /// A quiet selected fill.
    pub accent_soft: Color,
    /// The accent dark enough for strokes and icons on light surfaces.
    pub accent_ink: Color,
    // The title bar's inks (ADR 0167): the name focused and not, the
    // app's glyph, the path and buttons unfocused, and a button's hover
    // fill.
    pub title_text: Color,
    pub title_text_unfocused: Color,
    pub title_glyph: Color,
    pub title_button_unfocused: Color,
    pub title_hover: Color,
    // The top bar (ADR 0167): its fill (transparent: the wallpaper shows
    // through), its text, the brightest text (an open menu's label), the
    // focused window's name, minimised windows, what is off (no link, an
    // empty workspace), the fill under an open menu or the focused
    // window, the clock and the logo; and how workspaces are shown.
    pub topbar_fill: Color,
    pub topbar_text: Color,
    pub topbar_strong: Color,
    pub topbar_focus_text: Color,
    pub topbar_muted: Color,
    pub topbar_dim: Color,
    pub topbar_raised: Color,
    pub topbar_clock: Color,
    pub topbar_logo: Color,
    pub workspaces: Workspaces,
    /// The terminal's 16 colours that go with this palette.
    pub ansi: &'static [Color; 16],
    /// The focused frame's halo (ADR 0167), when the shape has one.
    pub focus_halo: Color,
    /// Frames take their app's own accent (Sediment's strata, ADR 0167).
    pub app_accents: bool,
    /// The top bar's date, before the clock (transparent: none, the clock
    /// shows the day itself).
    pub topbar_date: Color,
    pub shape: Shape,
    // The apps' accents (ADR 0167): folders in Files' list, the chosen
    // place's icon, System Monitor's chart line and fill, its meters and
    // their track.
    pub folder: Color,
    pub place_icon: Color,
    pub chart: Color,
    pub chart_fill: Color,
    pub meter: Color,
    pub meter_track: Color,
}

/// How the top bar shows workspaces (ADR 0167).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Workspaces {
    /// Numbered cells, the active one raised, with a mark under the
    /// number: long for the active workspace, short for a used one.
    Marks,
    /// Numbered cells, the active one filled with the accent; a short
    /// mark under a used one (Copper Noir).
    Filled,
    /// A pill per workspace in its colour, the active one larger with its
    /// number (Sediment).
    Pills([Color; 4]),
}

impl Palette {
    pub const GRAPHITE: Palette = Palette {
        desktop: Color::rgb(0x121211),
        well: Color::rgb(0x161615),
        window: Color::rgb(0x1A1A19),
        overlay: Color::rgb(0x1C1C1B),
        line_current: Color::rgb(0x20201F),
        header: Color::rgb(0x222221),
        divider: Color::rgb(0x232322),
        raised: Color::rgb(0x262625),
        active_ws: Color::rgb(0x2A2A28),
        border: Color::rgb(0x333331),
        border_strong: Color::rgb(0x3A3A38),
        chalk: Color::rgb(0xE3E1DC),
        focus: Color::rgb(0xA9A7A2),
        text_1: Color::rgb(0xC9C7C2),
        text_2: Color::rgb(0xBEBCB7),
        text_3: Color::rgb(0xA3A29F),
        text_4: Color::rgb(0x9B9994),
        muted: Color::rgb(0x85837E),
        inactive: Color::rgb(0x75736F),
        decor: Color::rgb(0x5F5D59),
        unfocused: Color::rgb(0x262625),
        selected_tile: Color::rgb(0xCBC9C4),
        selected_meta: Color::rgb(0x3D3C3A),
        selected_tag: Color::rgb(0x8A8884),
        list_selected: Color::rgb(0xD9D7D2),
        field_focus: Color::rgb(0xBEBCB7),
        contour_top: Color::rgb(0x2A2927),
        contour_bottom: Color::rgb(0x171716),
        // rgba(10,10,9,0.66) and rgba(10,10,9,0.72).
        dim_launcher: Color::rgb(0x0A0A09).with_alpha(168),
        dim_dialog: Color::rgb(0x0A0A09).with_alpha(184),
        // `header`, `overlay`, `desktop`; white at 5%.
        titlebar: Color::rgb(0x222221),
        titlebar_unfocused: Color::rgb(0x1C1C1B),
        titlebar_groove: Color::rgb(0x121211),
        titlebar_rim: Color::rgb(0xFFFFFF).with_alpha(13),
        titlebar_path: Color::rgb(0x9B9994),
        titlebar_button: Color::rgb(0x9B9994),
        // `contour_bottom`, and a grey between it and `contour_top`.
        lineation_fine: Color::rgb(0x171716),
        lineation_accent: Color::rgb(0x1F1E1D),
        // STRATA_COLORS.md §1, Graphite.
        accents: Accents {
            clay: Accent::new(0xD0907E, 0x332B27, 0x5A433C),
            ochre: Accent::new(0xCFB07A, 0x332F27, 0x594E3B),
            sage: Accent::new(0xA4B38C, 0x2D2F29, 0x4A5041),
            moss: Accent::new(0x8FB2A4, 0x2A2F2C, 0x434F4A),
            steel: Accent::new(0x93A7BA, 0x2B2E30, 0x444B51),
            heather: Accent::new(0xB49DB3, 0x302C2F, 0x50484F),
        },
        // `chalk`, `window`, `raised`, `chalk`.
        accent: Color::rgb(0xE3E1DC),
        accent_on: Color::rgb(0x1A1A19),
        accent_soft: Color::rgb(0x262625),
        accent_ink: Color::rgb(0xE3E1DC),
        // `chalk`, `text_4`, `text_3`, `inactive`, `raised`.
        title_text: Color::rgb(0xE3E1DC),
        title_text_unfocused: Color::rgb(0x9B9994),
        title_glyph: Color::rgb(0xA3A29F),
        title_button_unfocused: Color::rgb(0x75736F),
        title_hover: Color::rgb(0x262625),
        // `desktop`, `text_3`, `chalk`, `text_1`, `muted`, `decor`,
        // `active_ws`, `text_1`, `chalk`.
        topbar_fill: Color::rgb(0x121211),
        topbar_text: Color::rgb(0xA3A29F),
        topbar_strong: Color::rgb(0xE3E1DC),
        topbar_focus_text: Color::rgb(0xC9C7C2),
        topbar_muted: Color::rgb(0x85837E),
        topbar_dim: Color::rgb(0x5F5D59),
        topbar_raised: Color::rgb(0x2A2A28),
        topbar_clock: Color::rgb(0xC9C7C2),
        topbar_logo: Color::rgb(0xE3E1DC),
        workspaces: Workspaces::Marks,
        ansi: &ANSI,
        focus_halo: Color::TRANSPARENT,
        app_accents: false,
        topbar_date: Color::TRANSPARENT,
        shape: Shape::GRAPHITE,
        // `text_3`, `chalk`, `text_1`, chalk at 11%, `text_3`, `well`.
        folder: Color::rgb(0xA3A29F),
        place_icon: Color::rgb(0xE3E1DC),
        chart: Color::rgb(0xC9C7C2),
        chart_fill: Color::rgb(0xE3E1DC).with_alpha(28),
        meter: Color::rgb(0xA3A29F),
        meter_track: Color::rgb(0x161615),
    };

    /// High contrast (§10): the focus outline in chalk, unfocused borders
    /// stronger, the dimmest readable text lifted.
    pub const HIGH_CONTRAST: Palette = Palette {
        focus: Color::rgb(0xE3E1DC),
        unfocused: Color::rgb(0x3A3A38),
        muted: Color::rgb(0xA3A29F),
        titlebar_rim: Color::TRANSPARENT,
        titlebar_path: Color::rgb(0xA3A29F),
        titlebar_button: Color::rgb(0xE3E1DC),
        topbar_muted: Color::rgb(0xA3A29F),
        ..Palette::GRAPHITE
    };

    /// The light variant (§9): the installer's colours (INSTALLER_STYLE.md
    /// §2): `desktop` #DCDBDB, `window` #F3F2F2, ink #0B0B0B as chalk, and
    /// the rest of the scale turned over with the same roles. `muted` is
    /// #5E5E5E, the lightest grey the installer allows for text.
    pub const DAY: Palette = Palette {
        desktop: Color::rgb(0xDCDBDB),
        well: Color::rgb(0xE8E7E7),
        window: Color::rgb(0xF3F2F2),
        overlay: Color::rgb(0xF6F5F5),
        line_current: Color::rgb(0xEAE9E9),
        header: Color::rgb(0xEEEDED),
        divider: Color::rgb(0xDEDDDD),
        raised: Color::rgb(0xE6E5E5),
        active_ws: Color::rgb(0xDAD9D9),
        border: Color::rgb(0xCFCECE),
        border_strong: Color::rgb(0xB9B8B8),
        chalk: Color::rgb(0x0B0B0B),
        focus: Color::rgb(0x404040),
        text_1: Color::rgb(0x1E1E1E),
        text_2: Color::rgb(0x2A2A2A),
        text_3: Color::rgb(0x404040),
        text_4: Color::rgb(0x4A4A4A),
        muted: Color::rgb(0x5E5E5E),
        inactive: Color::rgb(0x8C8B8B),
        decor: Color::rgb(0xA9A8A8),
        unfocused: Color::rgb(0xD4D3D3),
        selected_tile: Color::rgb(0x2A2A2A),
        selected_meta: Color::rgb(0xD9D8D8),
        selected_tag: Color::rgb(0xA6A6A6),
        list_selected: Color::rgb(0x0B0B0B),
        field_focus: Color::rgb(0x0B0B0B),
        contour_top: Color::rgb(0xC9C8C8),
        contour_bottom: Color::rgb(0xD7D6D6),
        // Lighter dims than graphite's, over a light desktop.
        dim_launcher: Color::rgb(0x0B0B0B).with_alpha(84),
        dim_dialog: Color::rgb(0x0B0B0B).with_alpha(102),
        // One tone deeper than the content: `line_current`, `header`,
        // `border`; white at 90%.
        titlebar: Color::rgb(0xEAE9E9),
        titlebar_unfocused: Color::rgb(0xEEEDED),
        titlebar_groove: Color::rgb(0xCFCECE),
        titlebar_rim: Color::rgb(0xFFFFFF).with_alpha(230),
        titlebar_path: Color::rgb(0x4A4A4A),
        titlebar_button: Color::rgb(0x4A4A4A),
        // `contour_bottom` and `border`.
        lineation_fine: Color::rgb(0xD7D6D6),
        lineation_accent: Color::rgb(0xCFCECE),
        // STRATA_COLORS.md §2, Limestone.
        accents: Accents {
            clay: Accent::new(0x8E4433, 0xE9E1DF, 0xD3BAB5),
            ochre: Accent::new(0x715820, 0xE6E3DD, 0xC9C1AF),
            sage: Accent::new(0x4E5D37, 0xE3E3DF, 0xBEC2B6),
            moss: Accent::new(0x3B5F52, 0xE1E3E2, 0xB8C3BF),
            steel: Accent::new(0x435D74, 0xE1E3E5, 0xBBC2CA),
            heather: Accent::new(0x6A4F6C, 0xE5E2E5, 0xC7BEC7),
        },
        // As graphite's: `chalk`, `window`, `raised`, `chalk`; `chalk`,
        // `text_4`, `text_3`, `inactive`, `raised`; `desktop`, `text_3`,
        // `chalk`, `text_1`, `muted`, `decor`, `active_ws`, `text_1`,
        // `chalk`.
        accent: Color::rgb(0x0B0B0B),
        accent_on: Color::rgb(0xF3F2F2),
        accent_soft: Color::rgb(0xE6E5E5),
        accent_ink: Color::rgb(0x0B0B0B),
        title_text: Color::rgb(0x0B0B0B),
        title_text_unfocused: Color::rgb(0x4A4A4A),
        title_glyph: Color::rgb(0x404040),
        title_button_unfocused: Color::rgb(0x8C8B8B),
        title_hover: Color::rgb(0xE6E5E5),
        topbar_fill: Color::rgb(0xDCDBDB),
        topbar_text: Color::rgb(0x404040),
        topbar_strong: Color::rgb(0x0B0B0B),
        topbar_focus_text: Color::rgb(0x1E1E1E),
        topbar_muted: Color::rgb(0x5E5E5E),
        topbar_dim: Color::rgb(0xA9A8A8),
        topbar_raised: Color::rgb(0xDAD9D9),
        topbar_clock: Color::rgb(0x1E1E1E),
        topbar_logo: Color::rgb(0x0B0B0B),
        workspaces: Workspaces::Marks,
        ansi: &ANSI_DAY,
        focus_halo: Color::TRANSPARENT,
        app_accents: false,
        topbar_date: Color::TRANSPARENT,
        shape: Shape::DAY,
        // As graphite's: `text_3`, `chalk`, `text_1`, chalk at 11%,
        // `text_3`, `well`.
        folder: Color::rgb(0x404040),
        place_icon: Color::rgb(0x0B0B0B),
        chart: Color::rgb(0x1E1E1E),
        chart_fill: Color::rgb(0x0B0B0B).with_alpha(28),
        meter: Color::rgb(0x404040),
        meter_track: Color::rgb(0xE8E7E7),
    };

    /// The light variant in high contrast: as [`Palette::HIGH_CONTRAST`].
    pub const DAY_HIGH_CONTRAST: Palette = Palette {
        focus: Color::rgb(0x0B0B0B),
        unfocused: Color::rgb(0xB9B8B8),
        muted: Color::rgb(0x404040),
        titlebar_groove: Color::rgb(0xB9B8B8),
        titlebar_rim: Color::TRANSPARENT,
        titlebar_path: Color::rgb(0x404040),
        titlebar_button: Color::rgb(0x0B0B0B),
        topbar_muted: Color::rgb(0x404040),
        ..Palette::DAY
    };

    /// The palette for the light variant and high contrast chosen.
    pub const fn pick(light: bool, high_contrast: bool) -> Palette {
        match (light, high_contrast) {
            (false, false) => Palette::GRAPHITE,
            (false, true) => Palette::HIGH_CONTRAST,
            (true, false) => Palette::DAY,
            (true, true) => Palette::DAY_HIGH_CONTRAST,
        }
    }

    /// Whether this is a light variant: its ink darker than its desktop.
    pub const fn light(&self) -> bool {
        (self.chalk.0 & 0xFF) < (self.desktop.0 & 0xFF)
    }
}

/// The terminal's 16 colours (§7): normal 0-7, then bright 8-15 (black,
/// red, green, yellow, blue, magenta, cyan, white).
pub const ANSI: [Color; 16] = [
    Color::rgb(0x2A2A28),
    Color::rgb(0xC98E86),
    Color::rgb(0xA9B89A),
    Color::rgb(0xCDB98C),
    Color::rgb(0x93A6B8),
    Color::rgb(0xB39BB0),
    Color::rgb(0x94B5B0),
    Color::rgb(0xBEBCB7),
    Color::rgb(0x5F5D59),
    Color::rgb(0xDDA8A0),
    Color::rgb(0xC1CEB3),
    Color::rgb(0xDFCDA6),
    Color::rgb(0xAFC0D0),
    Color::rgb(0xC9B4C6),
    Color::rgb(0xB0CBC6),
    Color::rgb(0xE3E1DC),
];

/// The terminal's 16 colours in the light variant (§9): the same roles
/// turned over, as for the rest of the scale. Black is the pale grey
/// next to `window` and bright black `decor`; white is `text-2` and
/// bright white the ink; the six hues are graphite's, darker and a little
/// stronger, the normal ones at 5:1 on `window` and the bright ones,
/// nearer the ink, at 7.5:1.
pub const ANSI_DAY: [Color; 16] = [
    Color::rgb(0xDEDDDD),
    Color::rgb(0xAB493C),
    Color::rgb(0x5A6E47),
    Color::rgb(0x7E642B),
    Color::rgb(0x4E6A85),
    Color::rgb(0x815C7C),
    Color::rgb(0x466F69),
    Color::rgb(0x2A2A2A),
    Color::rgb(0xA9A8A8),
    Color::rgb(0x80372D),
    Color::rgb(0x445235),
    Color::rgb(0x5E4B20),
    Color::rgb(0x3B4F63),
    Color::rgb(0x61445D),
    Color::rgb(0x35534F),
    Color::rgb(0x0B0B0B),
];

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// WCAG 2.x contrast ratio (relative luminance of sRGB).
    pub(crate) fn contrast(a: Color, b: Color) -> f64 {
        let lum = |c: Color| {
            let ch = |sh: u32| {
                let v = f64::from((c.0 >> sh) & 0xFF) / 255.0;
                if v <= 0.040_45 { v / 12.92 } else { std::primitive::f64::powf((v + 0.055) / 1.055, 2.4) }
            };
            0.2126 * ch(16) + 0.7152 * ch(8) + 0.0722 * ch(0)
        };
        let (x, y) = (lum(a), lum(b));
        (x.max(y) + 0.05) / (x.min(y) + 0.05)
    }

    #[test]
    fn readable_text_meets_aa() {
        // §10: everything a person must read is at least 4.5:1 on `window`.
        for (name, p) in [
            ("graphite", Palette::GRAPHITE),
            ("high contrast", Palette::HIGH_CONTRAST),
            ("day", Palette::DAY),
            ("day, high contrast", Palette::DAY_HIGH_CONTRAST),
            ("copper noir", Palette::COPPER_NOIR),
            ("sediment", Palette::SEDIMENT),
            ("sediment's terminal", Palette::SEDIMENT_TERMINAL),
        ] {
            for (token, c) in [
                ("chalk", p.chalk),
                ("text_1", p.text_1),
                ("text_3", p.text_3),
                ("text_4", p.text_4),
                ("muted", p.muted),
            ] {
                let r = contrast(c, p.window);
                assert!(r >= 4.5, "{name}: {token} is {r:.2}:1");
            }
            assert!(contrast(p.selected_meta, p.selected_tile) >= 4.5, "{name}: selected rows");
            // Apps draw selected rows' text in `window` on `list_selected`.
            assert!(contrast(p.window, p.list_selected) >= 4.5, "{name}: selected list rows");
            let bar = if p.topbar_fill.alpha() == 0 { p.desktop } else { p.topbar_fill };
            // The title bar (ADR 0124): the name, path and buttons on the
            // focused bar, the name on the unfocused one.
            for (what, fg, bg) in [
                ("title", p.title_text, p.titlebar),
                ("path", p.titlebar_path, p.titlebar),
                ("buttons", p.titlebar_button, p.titlebar),
                ("unfocused title", p.title_text_unfocused, p.titlebar_unfocused),
                // The top bar (ADR 0167), over its fill or the desktop.
                ("top bar", p.topbar_text, bar),
                ("clock", p.topbar_clock, bar),
                ("focused window", p.topbar_focus_text, bar),
            ] {
                let r = contrast(fg, bg);
                assert!(r >= 4.5, "{name}: {what} is {r:.2}:1");
            }
            // STRATA_COLORS.md: each accent on `window` and on its own tint.
            let a = p.accents;
            for (accent, x) in [
                ("clay", a.clay),
                ("ochre", a.ochre),
                ("sage", a.sage),
                ("moss", a.moss),
                ("steel", a.steel),
                ("heather", a.heather),
            ] {
                assert!(contrast(x.text, p.window) >= 4.5, "{name}: {accent} on window");
                assert!(contrast(x.text, x.tint) >= 4.5, "{name}: {accent} on its tint");
            }
        }
    }

    #[test]
    fn terminal_colours_are_readable() {
        // The hues and white, normal and bright, on each variant's window.
        for (name, set, window) in
            [("graphite", &ANSI, Palette::GRAPHITE.window), ("day", &ANSI_DAY, Palette::DAY.window)]
        {
            for i in (1..8).chain(9..16) {
                let r = contrast(set[i], window);
                assert!(r >= 4.5, "{name}: colour {i} is {r:.2}:1");
            }
        }
        assert!(contrast(ANSI_DAY[9], Palette::DAY.window) > contrast(ANSI_DAY[1], Palette::DAY.window));
    }
}

/// `a` to `b` by `t` (0 to 1), per channel.
pub fn mix(a: Color, b: Color, t: f32) -> Color {
    let ch = |s: u32| {
        let (x, y) = ((a.0 >> s) & 0xFF, (b.0 >> s) & 0xFF);
        (round(x as f32 + (y as f32 - x as f32) * t) as u32) << s
    };
    Color::rgb(ch(16) | ch(8) | ch(0))
}

/// The wallpaper (§8): `desktop`, with seven gently curving contour lines
/// across the lower 40% of the screen, fading downwards.
pub fn wallpaper(p: &mut Painter<'_>, pal: &Palette, area: Area) {
    let (x0, w, h) = (area.x, area.w, area.h);
    p.fill(area, 0.0, pal.desktop);
    let lines = 7;
    let top = area.y + h * 0.6;
    let step = h * 0.4 / lines as f32;
    let saved = p.clip(area);
    for i in 0..lines {
        let base = top + step * (i as f32 + 0.4);
        let c = mix(pal.contour_top, pal.contour_bottom, i as f32 / (lines - 1) as f32);
        let phase = i as f32 * 0.9;
        let points: Vec<(f32, f32)> = (0..=48)
            .map(|k| {
                let x = w * k as f32 / 48.0;
                let u = x / w * core::f32::consts::TAU;
                let y = base + 9.0 * crate::icon::sin(u * 0.8 + phase) + 4.0 * crate::icon::sin(u * 1.9 + phase * 1.7);
                (x0 + x, y)
            })
            .collect();
        p.polyline(&points, 1.0, c);
    }
    p.unclip(saved);
}
