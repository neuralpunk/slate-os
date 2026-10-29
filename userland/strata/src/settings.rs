// SPDX-License-Identifier: MIT OR Apache-2.0

//! A person's desktop settings (ADR 0039): the theme (graphite, its
//! light variant of WM_STYLE §9, Copper Noir or Sediment, ADR 0167), high
//! contrast (§10), dimming unfocused windows (§4),
//! reduced motion (§2) and locking the screen after a while without use
//! (ADR 0102) and the wallpaper (ADR 0110), in
//! `~/.config/strata/settings` as `key=value` lines. The Settings app
//! writes the file; Strata and its apps read it, Strata again whenever it
//! changes.

use alloc::string::String;
use alloc::vec::Vec;

use slate_rt::{fs, lossy};
use slate_ui::graphite::Palette;
use slate_ui::themes::Theme;
use slate_ui::wallpaper::Design;

/// The settings.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Settings {
    pub theme: Theme,
    pub high_contrast: bool,
    pub dim: bool,
    pub reduced_motion: bool,
    /// Lock the screen after this many seconds without input (0: never).
    pub lock: u32,
    pub wallpaper: Design,
    /// The person's own picture is the wallpaper (`wallpaper=picture`;
    /// [`crate::faces::wallpaper`]), else `wallpaper`'s design.
    pub picture: bool,
}

/// The idle times Settings offers (seconds; 0 is never).
pub const LOCK_CHOICES: [u32; 5] = [0, 60, 300, 900, 1800];

/// "5 minutes", "never".
pub fn lock_text(secs: u32) -> alloc::string::String {
    match secs {
        0 => alloc::string::String::from("never"),
        s if s % 60 == 0 && s / 60 == 1 => alloc::string::String::from("1 minute"),
        s if s % 60 == 0 => alloc::format!("{} minutes", s / 60),
        s => alloc::format!("{s} seconds"),
    }
}

impl Settings {
    /// Settings from the file's text; `base` gives what it doesn't say.
    pub fn parse(text: &str, base: Settings) -> Settings {
        let mut s = base;
        for line in text.lines() {
            let Some((k, v)) = line.split_once('=') else { continue };
            let (k, v) = (k.trim(), v.trim());
            match k {
                "theme" => s.theme = Theme::from_key(v).unwrap_or(s.theme),
                "contrast" => s.high_contrast = v == "high",
                "dim" => s.dim = v == "on",
                "motion" => s.reduced_motion = v == "reduced",
                "lock" => s.lock = v.parse().unwrap_or(s.lock),
                "wallpaper" if v == "picture" => s.picture = true,
                "wallpaper" => {
                    s.picture = false;
                    s.wallpaper = Design::from_key(v).unwrap_or(s.wallpaper);
                }
                // The design under a picture, for when it goes.
                "design" => s.wallpaper = Design::from_key(v).unwrap_or(s.wallpaper),
                _ => {}
            }
        }
        s
    }

    /// The file's text.
    pub fn render(&self) -> String {
        alloc::format!(
            "# Strata's settings (ADR 0039); the Settings app writes this file.\ntheme={}\ncontrast={}\ndim={}\nmotion={}\nlock={}\ndesign={}\nwallpaper={}\n",
            self.theme.key(),
            if self.high_contrast { "high" } else { "normal" },
            if self.dim { "on" } else { "off" },
            if self.reduced_motion { "reduced" } else { "full" },
            self.lock,
            self.wallpaper.key(),
            if self.picture { "picture" } else { self.wallpaper.key() },
        )
    }

    pub fn palette(&self) -> Palette {
        self.theme.palette(self.high_contrast)
    }

    /// Whether the theme is a light one.
    pub fn light(&self) -> bool {
        self.theme.light()
    }

    /// The system's defaults: high contrast from `slate.contrast=high` on
    /// the kernel command line, reduced motion from /etc/slate/motion, the
    /// idle lock from /etc/slate/lock (seconds; 5 minutes without it).
    pub fn system() -> Settings {
        Settings {
            high_contrast: crate::session::cmdline_word("slate.contrast=").as_deref() == Some("high"),
            reduced_motion: fs::read_file(b"/etc/slate/motion").is_ok_and(|t| lossy(&t).trim() == "reduced"),
            lock: fs::read_file(b"/etc/slate/lock").ok().and_then(|t| lossy(&t).trim().parse().ok()).unwrap_or(300),
            ..Settings::default()
        }
    }

    /// This person's settings.
    pub fn load() -> Settings {
        let base = Settings::system();
        match path().and_then(|p| fs::read_file(&p).ok()) {
            Some(t) => Settings::parse(&lossy(&t), base),
            None => base,
        }
    }

    /// Write them (the directory made if need be; a new file put in place
    /// whole, so that a reader never sees half).
    pub fn save(&self) -> Result<(), String> {
        let p = path().ok_or("HOME is not set")?;
        let home = slate_rt::env::var(b"HOME").unwrap_or_default();
        for d in [fs::join(&home, b".config"), fs::join(&home, b".config/strata")] {
            let _ = fs::mkdir(&d, 0o755);
        }
        let mut tmp = p.clone();
        tmp.extend_from_slice(b".new");
        fs::write_file(&tmp, self.render().as_bytes(), 0o644).map_err(|e| alloc::format!("{e}"))?;
        fs::rename(&tmp, &p).map_err(|e| alloc::format!("{e}"))
    }
}

/// `~/.config/strata/settings`.
pub fn path() -> Option<Vec<u8>> {
    let home = slate_rt::env::var(b"HOME").filter(|h| !h.is_empty())?;
    Some(fs::join(&home, b".config/strata/settings"))
}

/// The settings file's modification time, to notice changes.
pub fn stamp() -> Option<(i64, i64)> {
    let st = fs::stat(&path()?).ok()?;
    Some((st.mtime, st.mtime_nsec))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let s = Settings {
            theme: Theme::Light,
            high_contrast: false,
            dim: true,
            reduced_motion: true,
            lock: 900,
            wallpaper: Design::Orbits,
            picture: false,
        };
        assert_eq!(Settings::parse(&s.render(), Settings::default()), s);
        // A picture keeps the design under it.
        let pic = Settings { picture: true, ..s };
        assert_eq!(Settings::parse(&pic.render(), Settings::default()), pic);
        // What the file leaves out comes from the system's defaults.
        let base = Settings { high_contrast: true, ..Settings::default() };
        assert_eq!(Settings::parse("dim=on\nnonsense\n", base), Settings { dim: true, ..base });
        assert_eq!(Settings::parse("contrast=normal", base).high_contrast, false);
        // An unknown wallpaper keeps what was there.
        assert_eq!(Settings::parse("wallpaper=paisley", base).wallpaper, Design::Dunes);
        assert_eq!(s.palette(), Palette::DAY);
        // The themes by name (ADR 0167); an unknown one keeps what was there.
        for t in Theme::ALL {
            let with = Settings { theme: t, ..s };
            assert_eq!(Settings::parse(&with.render(), Settings::default()).theme, t);
        }
        assert_eq!(Settings::parse("theme=copper-noir", Settings::default()).palette(), Palette::COPPER_NOIR);
        assert_eq!(Settings::parse("theme=sediment\ncontrast=high", base).palette(), Palette::DAY_HIGH_CONTRAST);
        assert_eq!(Settings::parse("theme=paisley", s).theme, Theme::Light);
    }
}
