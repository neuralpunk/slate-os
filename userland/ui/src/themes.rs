// SPDX-License-Identifier: MIT OR Apache-2.0

//! Strata's themes (ADR 0167): graphite and its light variant (WM_STYLE
//! §2, §9), and the two themes in colour of
//! docs/design/STRATA_THEMES_COPPER_SEDIMENT.md: Copper Noir (dark, graphite
//! warmed with one copper accent) and Sediment (light, cream over sand,
//! with a dark top bar and a dark terminal). Each is a [`Palette`]; high
//! contrast falls back to graphite's or Light's (the handoff, §4).

use crate::color::Color;
use crate::graphite::{Accent, Accents, Palette, Serif, Shape, Workspaces};
use crate::shadow::BoxShadow;

/// A theme, as a person chooses it in Settings.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Theme {
    #[default]
    Graphite,
    Light,
    CopperNoir,
    Sediment,
}

impl Theme {
    pub const ALL: [Theme; 4] = [Theme::Graphite, Theme::Light, Theme::CopperNoir, Theme::Sediment];

    /// Its name in the settings file (`theme=`).
    pub fn key(self) -> &'static str {
        match self {
            Theme::Graphite => "graphite",
            Theme::Light => "light",
            Theme::CopperNoir => "copper-noir",
            Theme::Sediment => "sediment",
        }
    }

    /// Its name as Settings shows it.
    pub fn name(self) -> &'static str {
        match self {
            Theme::Graphite => "Graphite",
            Theme::Light => "Light",
            Theme::CopperNoir => "Copper Noir",
            Theme::Sediment => "Sediment",
        }
    }

    pub fn from_key(k: &str) -> Option<Theme> {
        Theme::ALL.into_iter().find(|t| t.key() == k)
    }

    /// The wallpaper it brings (the person can choose another): Dunes,
    /// the default, for graphite and Light; each new theme its own.
    pub fn wallpaper(self) -> crate::wallpaper::Design {
        use crate::wallpaper::Design;
        match self {
            Theme::Graphite | Theme::Light => Design::default(),
            Theme::CopperNoir => Design::CopperGlow,
            Theme::Sediment => Design::Sediment,
        }
    }

    /// Whether it is a light theme.
    pub const fn light(self) -> bool {
        matches!(self, Theme::Light | Theme::Sediment)
    }

    /// Its palette; with high contrast, graphite's or Light's high
    /// contrast (the new themes have none of their own yet).
    pub const fn palette(self, high_contrast: bool) -> Palette {
        match (self, high_contrast) {
            (_, true) => Palette::pick(self.light(), true),
            (Theme::Graphite, false) => Palette::GRAPHITE,
            (Theme::Light, false) => Palette::DAY,
            (Theme::CopperNoir, false) => Palette::COPPER_NOIR,
            (Theme::Sediment, false) => Palette::SEDIMENT,
        }
    }

    /// The terminal's palette: the theme's, except Sediment's terminal,
    /// which stays dark inside the light theme (the handoff, §3.6).
    pub const fn terminal(self, high_contrast: bool) -> Palette {
        match (self, high_contrast) {
            (Theme::Sediment, false) => Palette::SEDIMENT_TERMINAL,
            _ => self.palette(high_contrast),
        }
    }
}

impl Shape {
    /// Copper Noir's frames (the handoff, §2.3): a 38 px title bar, a 34 px
    /// top bar, a 4 px halo, deeper shadows.
    pub const COPPER_NOIR: Shape = Shape {
        title_h: 38.0,
        frame_r: 12.0,
        bar_h: 34.0,
        halo: 4.0,
        shadow_focused: [
            BoxShadow { dx: 0.0, dy: 2.0, blur: 6.0, spread: 0.0, color: Color::rgb(0).with_alpha(102) },
            BoxShadow { dx: 0.0, dy: 40.0, blur: 80.0, spread: -30.0, color: Color::rgb(0).with_alpha(204) },
        ],
        shadow_unfocused: BoxShadow {
            dx: 0.0,
            dy: 10.0,
            blur: 30.0,
            spread: -10.0,
            color: Color::rgb(0).with_alpha(153),
        },
        title_size: 13.0,
        title_semibold: false,
        title_tracking: -0.005,
        title_serif: None,
        // Instrument Serif Italic 17 px (the handoff's §2.4).
        date_serif: Some((Serif::InstrumentItalic, 17.0)),
    };

    /// Sediment's (the handoff, §3.3): a 40 px title bar with the name in
    /// Host Grotesk 600 13.5 (Fraunces' fallback), radius 14, a 36 px top
    /// bar, a 3 px halo, warm brown shadows.
    pub const SEDIMENT: Shape = Shape {
        title_h: 40.0,
        frame_r: 14.0,
        bar_h: 36.0,
        halo: 3.0,
        shadow_focused: [
            BoxShadow { dx: 0.0, dy: 2.0, blur: 6.0, spread: 0.0, color: Color::rgb(0x3C2814).with_alpha(31) },
            BoxShadow { dx: 0.0, dy: 36.0, blur: 70.0, spread: -30.0, color: Color::rgb(0x3C2814).with_alpha(128) },
        ],
        shadow_unfocused: BoxShadow {
            dx: 0.0,
            dy: 14.0,
            blur: 34.0,
            spread: -16.0,
            color: Color::rgb(0x3C2814).with_alpha(89),
        },
        title_size: 13.5,
        title_semibold: true,
        title_tracking: -0.01,
        // Fraunces 600 at 15 px, its date Fraunces Italic 14 px (§3.3, §3.4).
        title_serif: Some((Serif::Fraunces, 15.0)),
        date_serif: Some((Serif::FrauncesItalic, 14.0)),
    };
}

/// An app's own accent in Sediment (the handoff, §1): `fill` for large
/// areas and dark surfaces, `ink` for strokes and icons on light ones.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AppAccent {
    pub fill: Color,
    pub ink: Color,
}

/// The five stratum colours an app may take as its accent in Sediment
/// (the handoff's §1 and §6.1: chosen from the wallpaper's bands, so no
/// app brings a hue of its own). An app's entry says which with
/// `accent=` (ADR 0167's addendum).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stratum {
    Ochre,
    Terracotta,
    Sage,
    Olive,
    Slate,
}

impl Stratum {
    pub const ALL: [Stratum; 5] = [Stratum::Ochre, Stratum::Terracotta, Stratum::Sage, Stratum::Olive, Stratum::Slate];

    /// The word in an app's entry (`accent=ochre`).
    pub fn parse(word: &str) -> Option<Stratum> {
        Stratum::ALL.into_iter().find(|s| s.word().eq_ignore_ascii_case(word.trim()))
    }

    pub fn word(self) -> &'static str {
        match self {
            Stratum::Ochre => "ochre",
            Stratum::Terracotta => "terracotta",
            Stratum::Sage => "sage",
            Stratum::Olive => "olive",
            Stratum::Slate => "slate",
        }
    }

    /// Its tones: the band's colour to fill, and an ink darkened to 3:1
    /// on Sediment's title bar and desktop (the handoff's three, then
    /// sage and slate solved the same way; slate's fill is the lighter
    /// one the handoff solved for its workspace pill).
    pub fn accent(self) -> AppAccent {
        let (fill, ink) = match self {
            Stratum::Ochre => (0xD9A441, 0x9C6B16),
            Stratum::Terracotta => (0xB5643C, 0xA5562F),
            Stratum::Sage => (0x8A9A6B, 0x6D7954),
            Stratum::Olive => (0x6E7A5A, 0x5E6A4A),
            Stratum::Slate => (0x7A8494, 0x4B5563),
        };
        AppAccent { fill: Color::rgb(fill), ink: Color::rgb(ink) }
    }
}

/// An app's accent: the stratum its entry declares where the theme has
/// app accents (Sediment); the palette's accent for apps that declare
/// none, and in other themes.
pub fn app_accent(pal: &Palette, stratum: Option<Stratum>) -> AppAccent {
    match stratum.filter(|_| pal.app_accents) {
        Some(s) => s.accent(),
        None => AppAccent { fill: pal.accent, ink: pal.accent_ink },
    }
}

impl Palette {
    /// Copper Noir (the handoff, §2.2): graphite's surfaces a few points
    /// towards brown, copper rationed for the focused outline, the active
    /// workspace, selection, the focused title bar's glyph and the clock.
    /// Tokens the handoff doesn't name are graphite's, warmed the same
    /// way.
    pub const COPPER_NOIR: Palette = Palette {
        desktop: Color::rgb(0x121211),
        well: Color::rgb(0x161514),
        window: Color::rgb(0x1A1918),
        overlay: Color::rgb(0x1D1B19),
        line_current: Color::rgb(0x211E1C),
        header: Color::rgb(0x23201D),
        divider: Color::rgb(0x2A2725),
        raised: Color::rgb(0x2C2621),
        active_ws: Color::rgb(0x302B27),
        border: Color::rgb(0x38332F),
        border_strong: Color::rgb(0x403A35),
        chalk: Color::rgb(0xE9E3DA),
        // The focused outline: copper at 75% over the desktop.
        focus: Color::rgb(0xA57553),
        text_1: Color::rgb(0xD6CFC5),
        text_2: Color::rgb(0xC9C2B8),
        text_3: Color::rgb(0xB8B0A6),
        text_4: Color::rgb(0xA49C92),
        muted: Color::rgb(0x8E877E),
        inactive: Color::rgb(0x77706A),
        decor: Color::rgb(0x5F5A54),
        unfocused: Color::rgb(0x2A2725),
        // Selection is copper with dark text.
        selected_tile: Color::rgb(0xD39466),
        selected_meta: Color::rgb(0x2E1F15),
        selected_tag: Color::rgb(0x7A5232),
        list_selected: Color::rgb(0xD39466),
        field_focus: Color::rgb(0xD39466),
        contour_top: Color::rgb(0x2C2925),
        contour_bottom: Color::rgb(0x181715),
        dim_launcher: Color::rgb(0x0A0A09).with_alpha(168),
        dim_dialog: Color::rgb(0x0A0A09).with_alpha(184),
        titlebar: Color::rgb(0x23201D),
        titlebar_unfocused: Color::rgb(0x1D1B19),
        titlebar_groove: Color::rgb(0x121211),
        // #FFD6B4 at 8% over the bar, solved.
        titlebar_rim: Color::rgb(0x352F29),
        titlebar_path: Color::rgb(0x8E877E),
        titlebar_button: Color::rgb(0xB8B0A6),
        lineation_fine: Color::rgb(0x181715),
        lineation_accent: Color::rgb(0x201E1B),
        // Graphite's, with copper as the personal accent (its tint 14%
        // and its border 35% in `window`, as STRATA_COLORS.md makes them).
        accents: Accents {
            clay: Accent::new(0xD0907E, 0x332B27, 0x5A433C),
            ochre: Accent::new(0xCFB07A, 0x332F27, 0x594E3B),
            sage: Accent::new(0xA4B38C, 0x2D2F29, 0x4A5041),
            moss: Accent::new(0x8FB2A4, 0x2A2F2C, 0x434F4A),
            steel: Accent::new(0x93A7BA, 0x2B2E30, 0x444B51),
            heather: Accent::new(0xD39466, 0x342A23, 0x5B4433),
        },
        accent: Color::rgb(0xD39466),
        accent_on: Color::rgb(0x1A1310),
        accent_soft: Color::rgb(0x2C2621),
        accent_ink: Color::rgb(0xD39466),
        title_text: Color::rgb(0xF1EBE2),
        title_text_unfocused: Color::rgb(0x8E877E),
        title_glyph: Color::rgb(0xD39466),
        // The mockup's #5F5A54 was 2.5:1 (the handoff, §2.9).
        title_button_unfocused: Color::rgb(0x77706A),
        title_hover: Color::rgb(0x2C2621),
        // No fill: the bar is drawn over the wallpaper.
        topbar_fill: Color::TRANSPARENT,
        topbar_text: Color::rgb(0xB8B0A6),
        topbar_strong: Color::rgb(0xF1EBE2),
        topbar_focus_text: Color::rgb(0xF1EBE2),
        // The other workspaces' numbers (the mockup's #6E675F was 3.4:1).
        topbar_muted: Color::rgb(0x857E75),
        topbar_dim: Color::rgb(0x5F5A54),
        topbar_raised: Color::rgb(0x2A2623),
        topbar_clock: Color::rgb(0xE0A97E),
        topbar_logo: Color::rgb(0xD39466),
        workspaces: Workspaces::Filled,
        ansi: &ANSI_COPPER,
        // Copper at 8% over the desktop.
        focus_halo: Color::rgb(0x211C18),
        app_accents: false,
        topbar_date: Color::rgb(0xF1EBE2),
        shape: Shape::COPPER_NOIR,
        // The handoff's §2.6: copper for folders, the chosen place's
        // icon, the chart (its fill at 14%) and the meters, on `line`.
        folder: Color::rgb(0xD39466),
        place_icon: Color::rgb(0xD39466),
        chart: Color::rgb(0xD39466),
        chart_fill: Color::rgb(0xD39466).with_alpha(36),
        meter: Color::rgb(0xD39466),
        meter_track: Color::rgb(0x2A2725),
    };

    /// Sediment (the handoff, §3.2): paper-cream windows over a sand sky,
    /// terracotta for selection, a dark ink top bar. Tokens the handoff
    /// doesn't name follow Light's roles in Sediment's browns.
    pub const SEDIMENT: Palette = Palette {
        // The sky's middle tone (the wallpaper draws the gradient).
        desktop: Color::rgb(0xEAD9C2),
        well: Color::rgb(0xF3EADC),
        window: Color::rgb(0xFBF6EE),
        overlay: Color::rgb(0xFDF9F3),
        line_current: Color::rgb(0xF1E6D6),
        header: Color::rgb(0xF6EEE2),
        divider: Color::rgb(0xE6D9C6),
        raised: Color::rgb(0xEADFCF),
        active_ws: Color::rgb(0xE2D3BD),
        border: Color::rgb(0xDCCBB2),
        border_strong: Color::rgb(0xC9B79C),
        chalk: Color::rgb(0x2B2622),
        focus: Color::rgb(0xA5562F),
        text_1: Color::rgb(0x342E29),
        text_2: Color::rgb(0x4A423B),
        text_3: Color::rgb(0x5A5047),
        text_4: Color::rgb(0x6A5E52),
        // The mockup's #7A6E62 was 4.0:1 on the bar (the handoff, §3.9).
        muted: Color::rgb(0x716558),
        inactive: Color::rgb(0x9E9080),
        decor: Color::rgb(0xB8A993),
        unfocused: Color::rgb(0xDCCBB2),
        // Selection: terracotta's ink with cream text (5.0:1).
        selected_tile: Color::rgb(0xA5562F),
        selected_meta: Color::rgb(0xFFF8EF),
        selected_tag: Color::rgb(0xD9A58A),
        list_selected: Color::rgb(0xA5562F),
        field_focus: Color::rgb(0xA5562F),
        contour_top: Color::rgb(0xD6C1A2),
        contour_bottom: Color::rgb(0xE2D0B6),
        dim_launcher: Color::rgb(0x2B2622).with_alpha(84),
        dim_dialog: Color::rgb(0x2B2622).with_alpha(102),
        titlebar: Color::rgb(0xF1E6D6),
        titlebar_unfocused: Color::rgb(0xF6EEE2),
        titlebar_groove: Color::rgb(0xDCCBB2),
        titlebar_rim: Color::TRANSPARENT,
        titlebar_path: Color::rgb(0x716558),
        titlebar_button: Color::rgb(0x6A5E52),
        lineation_fine: Color::rgb(0xE2D0B6),
        lineation_accent: Color::rgb(0xD6C1A2),
        // The handoff's §3.2, with terracotta's ink as the personal accent.
        accents: Accents {
            clay: Accent::new(0xA3452F, 0xF4E4DC, 0xDDBFB2),
            ochre: Accent::new(0x82600F, 0xF3E8D6, 0xDCCAA6),
            sage: Accent::new(0x56713A, 0xE9EDDD, 0xC6D0B0),
            moss: Accent::new(0x3F6355, 0xE3ECE6, 0xBCCFC4),
            steel: Accent::new(0x4B6A8A, 0xE6EBEF, 0xC0CCD8),
            heather: Accent::new(0x9A4F2A, 0xF4E6DA, 0xE0C2AE),
        },
        accent: Color::rgb(0xB5643C),
        accent_on: Color::rgb(0xFFF8EF),
        accent_soft: Color::rgb(0xEFE0CB),
        accent_ink: Color::rgb(0xA5562F),
        title_text: Color::rgb(0x2B2622),
        // The mockup's #8F8273 was 3.3:1.
        title_text_unfocused: Color::rgb(0x74685C),
        title_glyph: Color::rgb(0xA5562F),
        title_button_unfocused: Color::rgb(0x9E9080),
        title_hover: Color::rgb(0xEADFCF),
        topbar_fill: Color::rgb(0x2B2622),
        topbar_text: Color::rgb(0xE9DCC8),
        topbar_strong: Color::rgb(0xFFF8EF),
        topbar_focus_text: Color::rgb(0xFFF8EF),
        topbar_muted: Color::rgb(0xA89A88),
        topbar_dim: Color::rgb(0x7A6E62),
        topbar_raised: Color::rgb(0x433A33),
        topbar_clock: Color::rgb(0xF3C98B),
        topbar_logo: Color::rgb(0xE9DCC8),
        // Ochre, terracotta, sage, and a slate lifted to 4:1 on the bar.
        workspaces: Workspaces::Pills([
            Color::rgb(0xD9A441),
            Color::rgb(0xB5643C),
            Color::rgb(0x8A9A6B),
            Color::rgb(0x7A8494),
        ]),
        ansi: &ANSI_SEDIMENT,
        // The app's ink at 15% (see `app_accent`).
        focus_halo: Color::rgb(0xA5562F).with_alpha(38),
        app_accents: true,
        topbar_date: Color::rgb(0xE9DCC8),
        shape: Shape::SEDIMENT,
        // The handoff's §3.6: terracotta folders (4.0:1, an icon), the
        // chosen place's icon in ink, System Monitor's olive chart (its
        // fill at 18%), sage meters on the `track` tone.
        folder: Color::rgb(0xB5643C),
        place_icon: Color::rgb(0x2B2622),
        chart: Color::rgb(0x6E7A5A),
        chart_fill: Color::rgb(0x6E7A5A).with_alpha(46),
        meter: Color::rgb(0x8A9A6B),
        meter_track: Color::rgb(0xEADFCF),
    };

    /// Sediment's terminal (the handoff, §3.6): dark `#2B2622` inside the
    /// light theme, its text `#D9CBB7`, commands `#F3E9DC`, ochre for the
    /// cursor; the surfaces around it are Copper Noir's roles in
    /// Sediment's browns.
    pub const SEDIMENT_TERMINAL: Palette = Palette {
        desktop: Color::rgb(0x221E1B),
        well: Color::rgb(0x26221E),
        window: Color::rgb(0x2B2622),
        overlay: Color::rgb(0x302A26),
        line_current: Color::rgb(0x332D28),
        header: Color::rgb(0x36302A),
        divider: Color::rgb(0x3A332D),
        raised: Color::rgb(0x3D3630),
        active_ws: Color::rgb(0x443C35),
        border: Color::rgb(0x4A4139),
        border_strong: Color::rgb(0x564C43),
        chalk: Color::rgb(0xF3E9DC),
        focus: Color::rgb(0xD9A441),
        text_1: Color::rgb(0xE6D9C6),
        text_2: Color::rgb(0xD9CBB7),
        text_3: Color::rgb(0xC4B6A2),
        text_4: Color::rgb(0xB3A591),
        muted: Color::rgb(0xA89A88),
        inactive: Color::rgb(0x8A7D6E),
        decor: Color::rgb(0x6E6359),
        unfocused: Color::rgb(0x3A332D),
        selected_tile: Color::rgb(0xD9A441),
        selected_meta: Color::rgb(0x2B2622),
        selected_tag: Color::rgb(0x8F6A28),
        list_selected: Color::rgb(0xD9A441),
        field_focus: Color::rgb(0xD9A441),
        accent: Color::rgb(0xD9A441),
        accent_on: Color::rgb(0x2B2622),
        accent_soft: Color::rgb(0x3D3630),
        accent_ink: Color::rgb(0xD9A441),
        title_glyph: Color::rgb(0xD9A441),
        ansi: &ANSI_SEDIMENT,
        ..Palette::COPPER_NOIR
    };
}

/// Copper Noir's terminal colours (the handoff, §2.6): graphite's,
/// warmed.
pub const ANSI_COPPER: [Color; 16] = [
    Color::rgb(0x2A2725),
    Color::rgb(0xC98E86),
    Color::rgb(0xA9B89A),
    Color::rgb(0xE0B472),
    Color::rgb(0x93A7BA),
    Color::rgb(0xB39BB0),
    Color::rgb(0x94B5B0),
    Color::rgb(0xC9C2B8),
    Color::rgb(0x5F5A54),
    Color::rgb(0xDDA8A0),
    Color::rgb(0xC1CEB3),
    Color::rgb(0xEBC891),
    Color::rgb(0xAFC0D0),
    Color::rgb(0xC9B4C6),
    Color::rgb(0xB0CBC6),
    Color::rgb(0xE9E3DA),
];

/// Sediment's terminal colours (the handoff, §3.6), for its dark
/// terminal.
pub const ANSI_SEDIMENT: [Color; 16] = [
    Color::rgb(0x3A332D),
    Color::rgb(0xE0937A),
    Color::rgb(0xB7C98F),
    Color::rgb(0xE8B86A),
    Color::rgb(0xA9C0D8),
    Color::rgb(0xC9A0BE),
    Color::rgb(0x9CC4B8),
    Color::rgb(0xD9CBB7),
    Color::rgb(0x6E6359),
    Color::rgb(0xEEB09C),
    Color::rgb(0xCCDAA9),
    Color::rgb(0xF3C98B),
    Color::rgb(0xC3D4E6),
    Color::rgb(0xDBBBD2),
    Color::rgb(0xB8D7CD),
    Color::rgb(0xF3E9DC),
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graphite::tests::contrast;

    #[test]
    fn keys() {
        for t in Theme::ALL {
            assert_eq!(Theme::from_key(t.key()), Some(t));
            assert_eq!(t.light(), t.palette(false).light(), "{t:?}");
        }
        assert_eq!(Theme::from_key("paisley"), None);
        // High contrast falls back to graphite's or Light's.
        assert_eq!(Theme::CopperNoir.palette(true), Palette::HIGH_CONTRAST);
        assert_eq!(Theme::Sediment.palette(true), Palette::DAY_HIGH_CONTRAST);
        assert_eq!(Theme::Sediment.terminal(true), Palette::DAY_HIGH_CONTRAST);
        assert_eq!(Theme::Graphite.palette(false), Palette::GRAPHITE);
    }

    /// The ratios the handoff measured (§2.8, §3.8), from the tokens.
    #[test]
    fn handoff_ratios() {
        let (c, s) = (Palette::COPPER_NOIR, Palette::SEDIMENT);
        for (what, fg, bg, min) in [
            ("copper: focused title", c.title_text, c.titlebar, 4.5),
            ("copper: unfocused title", c.title_text_unfocused, c.titlebar_unfocused, 4.5),
            ("copper: path", c.titlebar_path, c.titlebar, 4.5),
            ("copper: buttons", c.titlebar_button, c.titlebar, 4.5),
            ("copper: unfocused buttons", c.title_button_unfocused, c.titlebar_unfocused, 3.0),
            ("copper: glyph", c.title_glyph, c.titlebar, 3.0),
            ("copper: selected", c.accent_on, c.accent, 4.5),
            ("copper: outline", c.focus, c.desktop, 3.0),
            ("copper: top bar", c.topbar_text, c.desktop, 4.5),
            ("copper: workspaces", c.topbar_muted, c.desktop, 4.5),
            ("copper: clock", c.topbar_clock, c.desktop, 4.5),
            ("copper: muted on the sidebar", c.muted, c.well, 4.5),
            ("sediment: focused title", s.title_text, s.titlebar, 4.5),
            ("sediment: unfocused title", s.title_text_unfocused, s.titlebar_unfocused, 4.5),
            ("sediment: path", s.titlebar_path, s.titlebar, 4.5),
            ("sediment: buttons", s.titlebar_button, s.titlebar, 4.5),
            ("sediment: glyph", s.title_glyph, s.titlebar, 3.0),
            ("sediment: selected", s.accent_on, s.accent_ink, 4.5),
            ("sediment: muted on the sidebar", s.muted, s.well, 4.5),
            ("sediment: top bar", s.topbar_text, s.topbar_fill, 4.5),
            ("sediment: top bar, muted", s.topbar_muted, s.topbar_fill, 4.5),
            ("sediment: clock", s.topbar_clock, s.topbar_fill, 4.5),
            ("sediment: warning on its tint", s.accents.ochre.text, s.accents.ochre.tint, 4.5),
        ] {
            let r = contrast(fg, bg);
            assert!(r >= min, "{what} is {r:.2}:1");
        }
        // The workspace pills on Sediment's bar: UI, 3:1.
        let Workspaces::Pills(pills) = s.workspaces else { panic!("sediment has pills") };
        for (i, pill) in pills.iter().enumerate() {
            let r = contrast(*pill, s.topbar_fill);
            assert!(r >= 3.0, "pill {i} is {r:.2}:1");
        }
        // The apps' inks on the title bar and the desktop (UI, 3:1).
        for st in Stratum::ALL.map(Some).into_iter().chain([None]) {
            let ink = app_accent(&s, st).ink;
            assert!(contrast(ink, s.titlebar) >= 3.0, "{st:?} on the title bar");
            assert!(contrast(ink, s.desktop) >= 3.0, "{st:?} on the desktop");
        }
        // The fills on the terminal's dark ground (its cursor).
        for st in Stratum::ALL {
            assert!(contrast(st.accent().fill, Palette::SEDIMENT_TERMINAL.window) >= 3.0, "{st:?} on the terminal");
        }
        assert_eq!(app_accent(&c, Some(Stratum::Ochre)).ink, c.accent_ink);
        assert_eq!(Stratum::parse("Terracotta"), Some(Stratum::Terracotta));
        assert_eq!(Stratum::parse("purple"), None);
        // Each semantic colour on Sediment's sidebar too.
        let a = s.accents;
        for x in [a.clay, a.ochre, a.sage, a.moss, a.steel] {
            assert!(contrast(x.text, s.well) >= 4.5, "{:06x} on the sidebar", x.text.0 & 0xFF_FFFF);
        }
    }

    #[test]
    fn terminal_colours_are_readable() {
        for (name, pal) in [("copper", Palette::COPPER_NOIR), ("sediment", Palette::SEDIMENT_TERMINAL)] {
            for i in (1..8).chain(9..16) {
                let r = contrast(pal.ansi[i], pal.window);
                assert!(r >= 4.5, "{name}: colour {i} is {r:.2}:1");
            }
            assert!(contrast(pal.muted, pal.window) >= 4.5, "{name}: muted");
        }
    }
}
