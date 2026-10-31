// SPDX-License-Identifier: MIT OR Apache-2.0

//! A person's desktop settings (ADR 0039): the theme (graphite, its
//! light variant of WM_STYLE §9, Copper Noir or Sediment, ADR 0167), high
//! contrast (§10), dimming unfocused windows (§4),
//! reduced motion (§2) and locking the screen after a while without use
//! (ADR 0102) and the wallpaper (ADR 0110), notifications, the pointer,
//! Night Light, text and cursor sizes and power (ADR 0186), in
//! `~/.config/strata/settings` as `key=value` lines. The Settings app
//! writes the file; Strata and its apps read it, Strata again whenever it
//! changes.

use alloc::string::String;
use alloc::vec::Vec;

use slate_rt::{fs, lossy};
use slate_ui::graphite::Palette;
use slate_ui::themes::Theme;
use slate_ui::wallpaper::Design;

/// Night Light (ADR 0186).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Night {
    #[default]
    Off,
    On,
    /// From `night_from` to `night_to`.
    Scheduled,
}

/// The settings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
    /// Do Not Disturb: no notification banners but urgent ones
    /// (`notifications=quiet`; ADR 0186).
    pub quiet: bool,
    /// The pointer's speed, -2 to 2 (`pointer=`).
    pub pointer: i8,
    /// Natural scrolling (`scroll=natural`).
    pub natural: bool,
    /// The mouse's buttons swapped (`buttons=left-handed`).
    pub left_handed: bool,
    /// Tapping a touchpad clicks (`tap=on`).
    pub tap: bool,
    pub night: Night,
    /// Night Light's hours, minutes after midnight (`night_hours=20:00-07:00`).
    pub night_from: u16,
    pub night_to: u16,
    /// How warm, 1 to 5 (`warmth=`).
    pub warmth: u8,
    /// Text size and the pointer's size, in percent (`text=`, `cursor=`).
    pub text: u8,
    pub cursor: u8,
    /// Turn the screen off after this many seconds without input (0:
    /// never; `blank=`).
    pub blank: u32,
    /// The battery's percentage in the top bar (`battery_percent=`).
    pub battery_percent: bool,
}

impl Default for Settings {
    fn default() -> Settings {
        Settings {
            theme: Theme::default(),
            high_contrast: false,
            dim: false,
            reduced_motion: false,
            lock: 0,
            wallpaper: Design::default(),
            picture: false,
            quiet: false,
            pointer: 0,
            natural: false,
            left_handed: false,
            tap: true,
            night: Night::Off,
            night_from: 20 * 60,
            night_to: 7 * 60,
            warmth: 3,
            text: 100,
            cursor: 100,
            blank: 600,
            battery_percent: true,
        }
    }
}

/// The text sizes Settings offers (percent), and the pointer's.
pub const TEXT_SIZES: [u8; 3] = [100, 125, 150];
pub const CURSOR_SIZES: [u8; 3] = [100, 150, 200];
/// When the screen may turn off (seconds; 0 is never).
pub const BLANK_CHOICES: [u32; 6] = [0, 60, 300, 600, 900, 1800];
/// Night Light's schedules (from, to; minutes after midnight).
pub const NIGHT_HOURS: [(u16, u16); 4] = [(19 * 60, 7 * 60), (20 * 60, 7 * 60), (21 * 60, 6 * 60), (22 * 60, 7 * 60)];

/// "20:00" for 1200.
pub fn hhmm(m: u16) -> String {
    alloc::format!("{:02}:{:02}", m / 60 % 24, m % 60)
}

/// 1200 for "20:00".
fn minutes(t: &str) -> Option<u16> {
    let (h, m) = t.split_once(':')?;
    let (h, m): (u16, u16) = (h.trim().parse().ok()?, m.trim().parse().ok()?);
    (h < 24 && m < 60).then_some(h * 60 + m)
}

impl Settings {
    /// Whether Night Light is on at `minute` (after midnight).
    pub fn night_now(&self, minute: u16) -> bool {
        match self.night {
            Night::Off => false,
            Night::On => true,
            Night::Scheduled if self.night_from <= self.night_to => (self.night_from..self.night_to).contains(&minute),
            Night::Scheduled => minute >= self.night_from || minute < self.night_to,
        }
    }
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
                "notifications" => s.quiet = v == "quiet",
                "pointer" => s.pointer = v.parse::<i8>().map_or(s.pointer, |p| p.clamp(-2, 2)),
                "scroll" => s.natural = v == "natural",
                "buttons" => s.left_handed = v == "left-handed",
                "tap" => s.tap = v == "on",
                "night" => {
                    s.night = match v {
                        "on" => Night::On,
                        "scheduled" => Night::Scheduled,
                        _ => Night::Off,
                    }
                }
                "night_hours" => {
                    if let Some((a, b)) = v.split_once('-').and_then(|(a, b)| Some((minutes(a)?, minutes(b)?))) {
                        (s.night_from, s.night_to) = (a, b);
                    }
                }
                "warmth" => s.warmth = v.parse::<u8>().map_or(s.warmth, |w| w.clamp(1, 5)),
                "text" => s.text = v.parse::<u8>().map_or(s.text, |t| t.clamp(50, 200)),
                "cursor" => s.cursor = v.parse::<u8>().map_or(s.cursor, |c| c.clamp(50, 250)),
                "blank" => s.blank = v.parse().unwrap_or(s.blank),
                "battery_percent" => s.battery_percent = v != "off",
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
            "# Strata's settings (ADR 0039); the Settings app writes this file.\ntheme={}\ncontrast={}\ndim={}\nmotion={}\nlock={}\ndesign={}\nwallpaper={}\nnotifications={}\n{}",
            self.theme.key(),
            if self.high_contrast { "high" } else { "normal" },
            if self.dim { "on" } else { "off" },
            if self.reduced_motion { "reduced" } else { "full" },
            self.lock,
            self.wallpaper.key(),
            if self.picture { "picture" } else { self.wallpaper.key() },
            if self.quiet { "quiet" } else { "shown" },
            self.render_more(),
        )
    }

    /// The pointer, Night Light, sizes and power lines (ADR 0186).
    fn render_more(&self) -> String {
        let night = match self.night {
            Night::Off => "off",
            Night::On => "on",
            Night::Scheduled => "scheduled",
        };
        alloc::format!(
            "pointer={}\nscroll={}\nbuttons={}\ntap={}\nnight={night}\nnight_hours={}-{}\nwarmth={}\ntext={}\ncursor={}\nblank={}\nbattery_percent={}\n",
            self.pointer,
            if self.natural { "natural" } else { "traditional" },
            if self.left_handed { "left-handed" } else { "right-handed" },
            if self.tap { "on" } else { "off" },
            hhmm(self.night_from),
            hhmm(self.night_to),
            self.warmth,
            self.text,
            self.cursor,
            self.blank,
            if self.battery_percent { "on" } else { "off" },
        )
    }

    pub fn palette(&self) -> Palette {
        self.theme.palette(self.high_contrast)
    }

    /// Whether the desktop looks different with `o` (its theme, contrast,
    /// wallpaper or dimming): the change cross-fades (ADR 0186).
    pub fn looks_different(&self, o: &Settings) -> bool {
        (self.theme, self.high_contrast, self.dim, self.wallpaper, self.picture)
            != (o.theme, o.high_contrast, o.dim, o.wallpaper, o.picture)
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
            quiet: true,
            pointer: -1,
            natural: true,
            left_handed: true,
            tap: false,
            night: Night::Scheduled,
            night_from: 21 * 60,
            night_to: 6 * 60,
            warmth: 5,
            text: 125,
            cursor: 150,
            blank: 300,
            battery_percent: false,
        };
        assert_eq!(Settings::parse(&s.render(), Settings::default()), s);
        // Night Light's hours across midnight.
        assert!(s.night_now(22 * 60) && s.night_now(60) && !s.night_now(12 * 60));
        let day = Settings { night_from: 9 * 60, night_to: 17 * 60, ..s };
        assert!(day.night_now(10 * 60) && !day.night_now(20 * 60));
        assert!(!Settings::default().night_now(22 * 60));
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
