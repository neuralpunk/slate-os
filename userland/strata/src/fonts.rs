// SPDX-License-Identifier: MIT OR Apache-2.0

//! Strata's typefaces (docs/design/WM_STYLE.md §2): Host Grotesk 400, 500 and 600
//! for the interface, DM Mono 400 and 500 for data.

use slate_ui::text::Face;

/// The font files, in the order [`Fonts::new`] takes them.
pub const FILES: [&str; 5] =
    ["HostGrotesk-400.ttf", "HostGrotesk-500.ttf", "HostGrotesk-600.ttf", "DMMono-Regular.ttf", "DMMono-Medium.ttf"];

#[derive(Debug)]
pub struct Fonts<'a> {
    pub regular: Face<'a>,
    pub medium: Face<'a>,
    pub semibold: Face<'a>,
    pub mono: Face<'a>,
    pub mono_medium: Face<'a>,
}

impl<'a> Fonts<'a> {
    pub fn new(files: [&'a [u8]; 5]) -> Option<Fonts<'a>> {
        Some(Fonts {
            regular: Face::new(files[0], 1)?,
            medium: Face::new(files[1], 2)?,
            semibold: Face::new(files[2], 3)?,
            mono: Face::new(files[3], 4)?,
            mono_medium: Face::new(files[4], 5)?,
        })
    }
}
