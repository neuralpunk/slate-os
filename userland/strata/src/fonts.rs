// SPDX-License-Identifier: MIT OR Apache-2.0

//! Strata's typefaces (docs/design/WM_STYLE.md §2): Host Grotesk 400, 500 and 600
//! for the interface, DM Mono 400 and 500 for data; and the themes in
//! colour's display serifs, when they are installed (ADR 0175).

use slate_ui::graphite::Serif;

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
    /// Instrument Serif Italic, Fraunces 600 and Fraunces Italic, when
    /// their files are there ([`SERIF_FILES`]).
    pub serifs: Option<[Face<'a>; 3]>,
}

/// The serifs' files, in [`Serif`]'s order (ADR 0175).
pub const SERIF_FILES: [&str; 3] = ["InstrumentSerif-Italic.ttf", "Fraunces-600.ttf", "Fraunces-Italic-400.ttf"];

impl<'a> Fonts<'a> {
    pub fn new(files: [&'a [u8]; 5]) -> Option<Fonts<'a>> {
        Some(Fonts {
            regular: Face::new(files[0], 1)?,
            medium: Face::new(files[1], 2)?,
            semibold: Face::new(files[2], 3)?,
            mono: Face::new(files[3], 4)?,
            mono_medium: Face::new(files[4], 5)?,
            serifs: None,
        })
    }

    /// With the serifs from `files` ([`SERIF_FILES`]' order); without
    /// them if one is damaged. (Faces 8 to 10: the glyph cache's keys;
    /// the terminal's italics are 6 and 7.)
    pub fn with_serifs(mut self, files: [&'a [u8]; 3]) -> Fonts<'a> {
        let faces = (|| Some([Face::new(files[0], 8)?, Face::new(files[1], 9)?, Face::new(files[2], 10)?]))();
        self.serifs = faces;
        self
    }

    /// Serif `s`, if it is installed.
    pub fn serif(&self, s: Serif) -> Option<&Face<'a>> {
        let i = match s {
            Serif::InstrumentItalic => 0,
            Serif::Fraunces => 1,
            Serif::FrauncesItalic => 2,
        };
        self.serifs.as_ref().map(|f| &f[i])
    }
}
