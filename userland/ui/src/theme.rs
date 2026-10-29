// SPDX-License-Identifier: MIT OR Apache-2.0

//! The design tokens of docs/design/INSTALLER_STYLE.md §2, and the high-contrast
//! variant §7 describes (borders and text become pure ink).

use crate::color::Color;
use crate::text::Face;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Theme {
    pub desktop: Color,
    pub window: Color,
    pub sidebar: Color,
    pub hairline: Color,
    pub border: Color,
    pub border_row: Color,
    pub hover_fill: Color,
    pub ink: Color,
    pub ink_hover: Color,
    pub text_2: Color,
    pub text_3: Color,
    pub on_ink: Color,
    pub on_ink_muted: Color,
    /// The text field's hover border (§4, "Text field").
    pub field_hover: Color,
}

impl Theme {
    pub const LIGHT: Theme = Theme {
        desktop: Color::rgb(0xDCDBDB),
        window: Color::rgb(0xF3F2F2),
        sidebar: Color::rgb(0xEEEDED),
        hairline: Color::rgb(0xDEDDDD),
        border: Color::rgb(0xCFCECE),
        border_row: Color::rgb(0xD4D3D3),
        hover_fill: Color::rgb(0xE6E5E5),
        ink: Color::rgb(0x0B0B0B),
        ink_hover: Color::rgb(0x2A2A2A),
        text_2: Color::rgb(0x404040),
        text_3: Color::rgb(0x5E5E5E),
        on_ink: Color::rgb(0xF3F2F2),
        on_ink_muted: Color::rgb(0xA6A6A6),
        field_hover: Color::rgb(0xA9A8A8),
    };

    /// High contrast: borders and text in ink.
    pub const HIGH_CONTRAST: Theme = Theme {
        hairline: Color::rgb(0x0B0B0B),
        border: Color::rgb(0x0B0B0B),
        border_row: Color::rgb(0x0B0B0B),
        text_2: Color::rgb(0x0B0B0B),
        text_3: Color::rgb(0x0B0B0B),
        on_ink_muted: Color::rgb(0xF3F2F2),
        field_hover: Color::rgb(0x0B0B0B),
        ..Theme::LIGHT
    };
}

/// The installer's typefaces (§2, "Typography").
#[derive(Debug)]
pub struct Fonts<'a> {
    pub regular: Face<'a>,
    pub medium: Face<'a>,
    pub semibold: Face<'a>,
    pub extrabold: Face<'a>,
    pub mono: Face<'a>,
}

impl<'a> Fonts<'a> {
    /// From the five font files: Host Grotesk 400, 500, 600, 800 and DM
    /// Mono 400.
    pub fn new(files: [&'a [u8]; 5]) -> Option<Fonts<'a>> {
        Some(Fonts {
            regular: Face::new(files[0], 1)?,
            medium: Face::new(files[1], 2)?,
            semibold: Face::new(files[2], 3)?,
            extrabold: Face::new(files[3], 4)?,
            mono: Face::new(files[4], 5)?,
        })
    }
}
