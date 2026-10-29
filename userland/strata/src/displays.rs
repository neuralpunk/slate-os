// SPDX-License-Identifier: MIT OR Apache-2.0

//! The displays' arrangement (ADR 0170): what the person chose in
//! Settings › Displays, kept in `~/.config/strata/displays`, and what
//! Strata found connected, written to `~/.cache/strata/displays-now` for
//! Settings to show. Positions are in logical pixels; one scale serves
//! every display.
//!
//! ```text
//! scale=2
//! Virtual-1 on 0,0 1280x800@60 primary
//! Virtual-2 on 1280,0 auto
//! DP-1 off
//! ```

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use slate_display::kms::screens::{Screens, Want};
use slate_rt::fs;

/// One display as chosen.
#[derive(Clone, Debug, PartialEq)]
pub struct Choice {
    pub name: String,
    pub on: bool,
    /// Its top left corner, logical pixels.
    pub x: i32,
    pub y: i32,
    /// Width, height, refresh; None for the display's own mode.
    pub mode: Option<(u32, u32, u32)>,
    pub primary: bool,
}

/// The arrangement: a scale (None: chosen by the primary display's size)
/// and the displays the person placed.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Arrangement {
    pub scale: Option<f32>,
    pub displays: Vec<Choice>,
}

/// `WxH@HZ`.
fn mode(s: &str) -> Option<(u32, u32, u32)> {
    let (size, hz) = s.split_once('@').unwrap_or((s, "0"));
    let (w, h) = size.split_once('x')?;
    Some((w.parse().ok()?, h.parse().ok()?, hz.parse().ok()?))
}

fn mode_text(m: (u32, u32, u32)) -> String {
    format!("{}x{}@{}", m.0, m.1, m.2)
}

impl Arrangement {
    pub fn parse(text: &str) -> Arrangement {
        let mut a = Arrangement::default();
        for line in text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')) {
            if let Some(v) = line.strip_prefix("scale=") {
                a.scale = v.parse::<f32>().ok().filter(|s| (1.0..=4.0).contains(s));
                continue;
            }
            let mut w = line.split_whitespace();
            let (Some(name), Some(state)) = (w.next(), w.next()) else { continue };
            let mut c = Choice { name: name.into(), on: state == "on", x: 0, y: 0, mode: None, primary: false };
            for f in w {
                if f == "primary" {
                    c.primary = true;
                } else if let Some((x, y)) = f.split_once(',') {
                    c.x = x.parse().unwrap_or(0);
                    c.y = y.parse().unwrap_or(0);
                } else if f != "auto" {
                    c.mode = mode(f);
                }
            }
            a.displays.push(c);
        }
        a
    }

    pub fn render(&self) -> String {
        let mut s = match self.scale {
            Some(k) => format!("scale={k}\n"),
            None => "scale=auto\n".to_string(),
        };
        for c in &self.displays {
            if !c.on {
                s += &format!("{} off\n", c.name);
                continue;
            }
            let m = c.mode.map_or("auto".to_string(), mode_text);
            s += &format!("{} on {},{} {m}{}\n", c.name, c.x, c.y, if c.primary { " primary" } else { "" });
        }
        s
    }

    /// The scale: the person's, else by the primary display's size.
    pub fn scale_for(&self, w: u32, h: u32) -> f32 {
        self.scale.unwrap_or_else(|| crate::session::scale_for(w as i32, h as i32))
    }

    /// What slate-display is asked for (logical pixels).
    pub fn wants(&self) -> Vec<Want> {
        self.displays
            .iter()
            .map(|c| Want { name: c.name.clone(), on: c.on, x: c.x, y: c.y, mode: c.mode, primary: c.primary })
            .collect()
    }

    /// This person's arrangement (none: every display side by side).
    pub fn load() -> Arrangement {
        path(b".config/strata/displays")
            .and_then(|p| fs::read_file(&p).ok())
            .map_or_else(Arrangement::default, |t| Arrangement::parse(&String::from_utf8_lossy(&t)))
    }

    pub fn save(&self) -> Result<(), String> {
        save(b".config", b".config/strata/displays", &self.render())
    }
}

fn path(rel: &[u8]) -> Option<Vec<u8>> {
    let home = slate_rt::env::var(b"HOME").filter(|h| !h.is_empty())?;
    Some(fs::join(&home, rel))
}

/// Write `text` to `~/REL` whole (a new file renamed into place), making
/// `~/TOP/strata` first.
fn save(top: &[u8], rel: &[u8], text: &str) -> Result<(), String> {
    let p = path(rel).ok_or("HOME is not set")?;
    let home = slate_rt::env::var(b"HOME").unwrap_or_default();
    let dir = fs::join(&home, top);
    for d in [dir.clone(), fs::join(&dir, b"strata")] {
        let _ = fs::mkdir(&d, 0o755);
    }
    let mut tmp = p.clone();
    tmp.extend_from_slice(b".new");
    fs::write_file(&tmp, text.as_bytes(), 0o644).map_err(|e| format!("{e}"))?;
    fs::rename(&tmp, &p).map_err(|e| format!("{e}"))
}

/// A display Strata found: its name, whether it is lit, where (logical
/// pixels) and in which mode, its modes (the display's own first).
#[derive(Clone, Debug, PartialEq)]
pub struct Found {
    pub name: String,
    pub lit: bool,
    pub x: i32,
    pub y: i32,
    pub mode: (u32, u32, u32),
    pub primary: bool,
    pub modes: Vec<(u32, u32, u32)>,
}

/// What is connected now, and the scale in use (`auto`: chosen by the
/// primary display's size, not by the person).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Now {
    pub scale: f32,
    pub auto: bool,
    pub displays: Vec<Found>,
}

/// Where a display is beside the primary one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side {
    Right,
    Left,
    Above,
    Below,
}

impl Side {
    pub const ALL: [Side; 4] = [Side::Right, Side::Left, Side::Above, Side::Below];

    pub fn words(self) -> &'static str {
        match self {
            Side::Right => "right of the primary",
            Side::Left => "left of the primary",
            Side::Above => "above the primary",
            Side::Below => "below the primary",
        }
    }
}

/// The scales Settings offers, after automatic.
pub const SCALES: [f32; 3] = [1.0, 1.5, 2.0];

impl Now {
    /// From the screens lit, with the primary display's corner at (0, 0)
    /// (`auto`: the scale wasn't the person's choice).
    pub fn of(s: &Screens, auto: bool) -> Now {
        let scale = s.scale;
        let (px, py) = s.outputs.first().map_or((0, 0), |o| (o.x, o.y));
        let displays = s
            .heads
            .iter()
            .map(|h| {
                let lit = s.outputs.iter().position(|o| o.name == h.name);
                let mut modes: Vec<(u32, u32, u32)> = Vec::new();
                let own = h.preferred();
                for m in core::iter::once(&h.modes[own]).chain(h.modes.iter()) {
                    let t = (m.width, m.height, m.refresh);
                    if !modes.contains(&t) {
                        modes.push(t);
                    }
                }
                let (x, y, mode) = match lit.map(|i| &s.outputs[i]) {
                    Some(o) => (
                        ((o.x - px) as f32 / scale) as i32,
                        ((o.y - py) as f32 / scale) as i32,
                        (o.mode.width, o.mode.height, o.mode.refresh),
                    ),
                    None => (0, 0, modes[0]),
                };
                Found { name: h.name.clone(), lit: lit.is_some(), x, y, mode, primary: lit == Some(0), modes }
            })
            .collect();
        Now { scale, auto, displays }
    }

    pub fn render(&self) -> String {
        let mut s = format!("scale {}{}\n", self.scale, if self.auto { " auto" } else { "" });
        for d in &self.displays {
            s += &format!(
                "{} {} {},{} {}{} modes",
                d.name,
                if d.lit { "lit" } else { "dark" },
                d.x,
                d.y,
                mode_text(d.mode),
                if d.primary { " primary" } else { "" }
            );
            for m in &d.modes {
                s += " ";
                s += &mode_text(*m);
            }
            s += "\n";
        }
        s
    }

    pub fn parse(text: &str) -> Now {
        let mut n = Now { scale: 1.0, auto: false, displays: Vec::new() };
        for line in text.lines() {
            if let Some(v) = line.strip_prefix("scale ") {
                let mut w = v.split_whitespace();
                n.scale = w.next().and_then(|v| v.parse().ok()).unwrap_or(1.0);
                n.auto = w.next() == Some("auto");
                continue;
            }
            let mut w = line.split_whitespace();
            let (Some(name), Some(state), Some(at), Some(m)) = (w.next(), w.next(), w.next(), w.next()) else {
                continue;
            };
            let (x, y) = at.split_once(',').unwrap_or(("0", "0"));
            let mut d = Found {
                name: name.into(),
                lit: state == "lit",
                x: x.parse().unwrap_or(0),
                y: y.parse().unwrap_or(0),
                mode: mode(m).unwrap_or((0, 0, 0)),
                primary: false,
                modes: Vec::new(),
            };
            let mut in_modes = false;
            for f in w {
                match f {
                    "primary" => d.primary = true,
                    "modes" => in_modes = true,
                    m if in_modes => d.modes.extend(mode(m)),
                    _ => {}
                }
            }
            n.displays.push(d);
        }
        n
    }

    /// Strata's report, for Settings.
    pub fn load() -> Now {
        path(b".cache/strata/displays-now")
            .and_then(|p| fs::read_file(&p).ok())
            .map_or_else(Now::default, |t| Now::parse(&String::from_utf8_lossy(&t)))
    }

    pub fn save(&self) -> Result<(), String> {
        save(b".cache", b".cache/strata/displays-now", &self.render())
    }

    /// The arrangement that keeps everything as it is now.
    pub fn arrangement(&self) -> Arrangement {
        Arrangement {
            scale: (!self.auto).then_some(self.scale),
            displays: self
                .displays
                .iter()
                .map(|d| Choice {
                    name: d.name.clone(),
                    on: d.lit,
                    x: d.x,
                    y: d.y,
                    mode: Some(d.mode),
                    primary: d.primary,
                })
                .collect(),
        }
    }
}

impl Now {
    fn find(&self, name: &str) -> Option<usize> {
        self.displays.iter().position(|d| d.name == name)
    }

    fn primary(&self) -> Option<usize> {
        self.displays.iter().position(|d| d.primary && d.lit).or_else(|| self.displays.iter().position(|d| d.lit))
    }

    /// A display's logical size in its mode.
    fn size(&self, i: usize) -> (i32, i32) {
        let m = self.displays[i].mode;
        ((m.0 as f32 / self.scale) as i32, (m.1 as f32 / self.scale) as i32)
    }

    /// The display's sizes, the display's own first; and the next one
    /// after the current.
    pub fn next_size(&mut self, name: &str) {
        let Some(i) = self.find(name) else { return };
        let d = &self.displays[i];
        let mut sizes: Vec<(u32, u32)> = Vec::new();
        for m in &d.modes {
            if !sizes.contains(&(m.0, m.1)) {
                sizes.push((m.0, m.1));
            }
        }
        let at = sizes.iter().position(|&s| s == (d.mode.0, d.mode.1)).unwrap_or(0);
        let Some(&(w, h)) = sizes.get((at + 1) % sizes.len().max(1)) else { return };
        // That size's first mode (the fastest the display lists first).
        if let Some(&m) = d.modes.iter().find(|m| (m.0, m.1) == (w, h)) {
            self.displays[i].mode = m;
            self.replace_others();
        }
    }

    /// The display's next refresh rate at its size.
    pub fn next_rate(&mut self, name: &str) {
        let Some(i) = self.find(name) else { return };
        let d = &self.displays[i];
        let rates: Vec<(u32, u32, u32)> =
            d.modes.iter().copied().filter(|m| (m.0, m.1) == (d.mode.0, d.mode.1)).collect();
        let at = rates.iter().position(|&m| m == d.mode).unwrap_or(0);
        if let Some(&m) = rates.get((at + 1) % rates.len().max(1)) {
            self.displays[i].mode = m;
        }
    }

    /// Where display `name` is beside the primary (None: it is the
    /// primary, or off).
    pub fn side(&self, name: &str) -> Option<Side> {
        let (i, p) = (self.find(name)?, self.primary()?);
        if i == p || !self.displays[i].lit {
            return None;
        }
        let (d, q) = (&self.displays[i], &self.displays[p]);
        let (pw, ph) = self.size(p);
        Some(if d.x >= q.x + pw {
            Side::Right
        } else if d.x + self.size(i).0 <= q.x {
            Side::Left
        } else if d.y + self.size(i).1 <= q.y {
            Side::Above
        } else if d.y >= q.y + ph {
            Side::Below
        } else {
            Side::Right
        })
    }

    /// Put display `name` on `side` of the primary, edge to edge, aligned
    /// to its top (beside) or its left (above, below).
    pub fn place(&mut self, name: &str, side: Side) {
        let (Some(i), Some(p)) = (self.find(name), self.primary()) else { return };
        if i == p {
            return;
        }
        let ((pw, ph), (w, h)) = (self.size(p), self.size(i));
        let (px, py) = (self.displays[p].x, self.displays[p].y);
        (self.displays[i].x, self.displays[i].y) = match side {
            Side::Right => (px + pw, py),
            Side::Left => (px - w, py),
            Side::Above => (px, py - h),
            Side::Below => (px, py + ph),
        };
    }

    /// The next side for display `name`.
    pub fn next_side(&mut self, name: &str) {
        if let Some(s) = self.side(name) {
            let at = Side::ALL.iter().position(|&x| x == s).unwrap_or(0);
            self.place(name, Side::ALL[(at + 1) % Side::ALL.len()]);
        }
    }

    /// Every display beside the primary placed again on its side (after a
    /// size or the scale changed).
    fn replace_others(&mut self) {
        let sides: Vec<(String, Side)> =
            self.displays.iter().filter_map(|d| self.side(&d.name).map(|s| (d.name.clone(), s))).collect();
        for (n, s) in sides {
            self.place(&n, s);
        }
    }

    /// Display `name` primary: its corner (0, 0), the others where they
    /// were around it.
    pub fn make_primary(&mut self, name: &str) {
        let Some(i) = self.find(name) else { return };
        if !self.displays[i].lit {
            return;
        }
        let (x0, y0) = (self.displays[i].x, self.displays[i].y);
        for (k, d) in self.displays.iter_mut().enumerate() {
            d.primary = k == i;
            d.x -= x0;
            d.y -= y0;
        }
    }

    /// Turn display `name` on (on the primary's right) or off; the last
    /// lit display stays on. Whether it changed.
    pub fn toggle(&mut self, name: &str) -> bool {
        let Some(i) = self.find(name) else { return false };
        let lit = self.displays.iter().filter(|d| d.lit).count();
        if self.displays[i].lit {
            if lit <= 1 {
                return false;
            }
            let was_primary = self.displays[i].primary;
            self.displays[i].lit = false;
            self.displays[i].primary = false;
            if was_primary && let Some(other) = self.displays.iter().find(|d| d.lit).map(|d| d.name.clone()) {
                self.make_primary(&other);
            }
        } else {
            self.displays[i].lit = true;
            self.place(name, Side::Right);
        }
        true
    }

    /// The next scale: automatic, then [`SCALES`].
    pub fn next_scale(&mut self, auto_scale: f32) {
        let at = if self.auto { None } else { SCALES.iter().position(|&k| k == self.scale) };
        match at {
            None => (self.auto, self.scale) = (false, SCALES[0]),
            Some(k) if k + 1 < SCALES.len() => self.scale = SCALES[k + 1],
            Some(_) => (self.auto, self.scale) = (true, auto_scale),
        }
        self.replace_others();
    }

    /// What the scale row says.
    pub fn scale_words(&self) -> String {
        let k = if self.scale == (self.scale as i32) as f32 {
            format!("{}×", self.scale)
        } else {
            format!("{:.1}×", self.scale)
        };
        if self.auto { format!("automatic ({k})") } else { k }
    }
}

/// Where the displays file lives, to watch it (the settings' directory).
pub fn arrangement_path() -> Option<Vec<u8>> {
    path(b".config/strata/displays")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_file_round_trips() {
        let text = "scale=2\nVirtual-1 on 0,0 1280x800@60 primary\nVirtual-2 on 640,-40 auto\nDP-1 off\n";
        let a = Arrangement::parse(text);
        assert_eq!(a.scale, Some(2.0));
        assert_eq!(a.displays.len(), 3);
        assert_eq!(a.displays[0].mode, Some((1280, 800, 60)));
        assert!(a.displays[0].primary && !a.displays[1].primary);
        assert_eq!((a.displays[1].x, a.displays[1].y, a.displays[1].mode), (640, -40, None));
        assert!(!a.displays[2].on);
        assert_eq!(a.render(), text);
        assert_eq!(Arrangement::parse(&a.render()), a);
        let w = a.wants();
        assert_eq!((w[1].x, w[1].y), (640, -40));
        // Nonsense is skipped; an absurd scale is auto.
        let b = Arrangement::parse("scale=40\nlonely\n# a comment\n");
        assert_eq!(b, Arrangement::default());
    }

    #[test]
    fn what_strata_found() {
        let n = Now {
            scale: 1.0,
            auto: false,
            displays: alloc::vec![
                Found {
                    name: "Virtual-1".into(),
                    lit: true,
                    x: 0,
                    y: 0,
                    mode: (1280, 800, 60),
                    primary: true,
                    modes: alloc::vec![(1280, 800, 60), (1024, 768, 60)],
                },
                Found {
                    name: "Virtual-2".into(),
                    lit: false,
                    x: 0,
                    y: 0,
                    mode: (800, 600, 60),
                    primary: false,
                    modes: alloc::vec![(800, 600, 60)],
                },
            ],
        };
        assert_eq!(Now::parse(&n.render()), n);
        let a = n.arrangement();
        assert_eq!(a.render(), "scale=1\nVirtual-1 on 0,0 1280x800@60 primary\nVirtual-2 off\n");
        let auto = Now { auto: true, ..n.clone() };
        assert_eq!(Now::parse(&auto.render()), auto);
        assert_eq!(auto.arrangement().scale, None);
    }

    fn two() -> Now {
        let d = |name: &str, x: i32, mode, primary, modes: &[(u32, u32, u32)]| Found {
            name: name.into(),
            lit: true,
            x,
            y: 0,
            mode,
            primary,
            modes: modes.to_vec(),
        };
        Now {
            scale: 1.0,
            auto: true,
            displays: alloc::vec![
                d("DP-1", 0, (1920, 1080, 144), true, &[(1920, 1080, 144), (1920, 1080, 60), (1280, 720, 60)]),
                d("HDMI-A-1", 1920, (1280, 1024, 60), false, &[(1280, 1024, 60), (1024, 768, 60)]),
            ],
        }
    }

    #[test]
    fn editing_the_arrangement() {
        let mut n = two();
        assert_eq!(n.side("HDMI-A-1"), Some(Side::Right));
        assert_eq!(n.side("DP-1"), None);
        // Sides in turn: left, above, below, right again.
        n.next_side("HDMI-A-1");
        assert_eq!((n.displays[1].x, n.displays[1].y, n.side("HDMI-A-1")), (-1280, 0, Some(Side::Left)));
        n.next_side("HDMI-A-1");
        assert_eq!((n.displays[1].x, n.displays[1].y), (0, -1024));
        n.next_side("HDMI-A-1");
        assert_eq!((n.displays[1].x, n.displays[1].y), (0, 1080));
        n.next_side("HDMI-A-1");
        assert_eq!(n.side("HDMI-A-1"), Some(Side::Right));
        // Rates at a size, then the next size (the others stay beside it).
        n.next_rate("DP-1");
        assert_eq!(n.displays[0].mode, (1920, 1080, 60));
        n.next_size("DP-1");
        assert_eq!(n.displays[0].mode, (1280, 720, 60));
        assert_eq!(n.displays[1].x, 1280);
        // The scale: automatic, 1, 1.5, 2, automatic; displays re-placed.
        n.next_scale(1.0);
        assert_eq!((n.auto, n.scale), (false, 1.0));
        n.next_scale(1.0);
        assert_eq!((n.scale, n.displays[1].x, n.scale_words()), (1.5, 853, "1.5×".to_string()));
        n.next_scale(1.0);
        n.next_scale(1.0);
        assert_eq!(n.scale_words(), "automatic (1×)");
        // Primary elsewhere: the corner moves with it.
        let mut n = two();
        n.make_primary("HDMI-A-1");
        assert_eq!((n.displays[0].x, n.displays[1].x, n.displays[1].primary), (-1920, 0, true));
        assert_eq!(n.side("DP-1"), Some(Side::Left));
        // Off and on again; the last one stays on.
        let mut n = two();
        assert!(n.toggle("DP-1"));
        assert!(n.displays[1].primary && n.displays[1].x == 0);
        assert!(!n.toggle("HDMI-A-1"));
        assert!(n.toggle("DP-1"));
        assert_eq!((n.displays[0].lit, n.side("DP-1")), (true, Some(Side::Right)));
        assert_eq!(
            n.arrangement().render(),
            "scale=auto\nDP-1 on 1280,0 1920x1080@144\nHDMI-A-1 on 0,0 1280x1024@60 primary\n"
        );
    }
}
