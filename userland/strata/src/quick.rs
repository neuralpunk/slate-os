// SPDX-License-Identifier: MIT OR Apache-2.0

//! Quick settings (ADR 0186): the menu that hangs from the top bar's
//! status icons at the right, as the Applications menu hangs at the left.
//! The volume (a mute button and a slider, the default card's playback
//! volume through `slate_sound::mixer`), tiles for the network, Bluetooth
//! and the dark style and Do Not Disturb, the battery, the latest
//! notifications, and buttons to Settings, the lock screen and the power
//! dialog. Also the pop-up the volume and brightness
//! keys show ([`Osd`]).

use alloc::string::String;
use alloc::vec::Vec;

use slate_sound::mixer::Volume;
use slate_ui::graphite::Palette;
use slate_ui::icon::Icon;
use slate_ui::paint::Painter;
use slate_ui::ui::Area;

use slate_ui::graphite::mix;

use crate::draw;
use crate::fonts::Fonts;

/// The menu's width, and its distance from the screen's right edge.
pub const WIDTH: f32 = 340.0;
const EDGE: f32 = 6.0;
const PAD: f32 = 14.0;
const ROW_H: f32 = 36.0;
const TILE_H: f32 = 56.0;
const RADIUS: f32 = 14.0;

/// A tile: what it shows and does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tile {
    /// Opens Settings › Network.
    Network,
    /// Opens Settings › Bluetooth.
    Bluetooth,
    /// Switches between the theme and its light or dark partner.
    Dark,
    /// Do Not Disturb on or off.
    Quiet,
}

/// What the menu shows now.
#[derive(Clone, Debug, PartialEq)]
pub struct Quick {
    /// The default card's volume; None without a card.
    pub volume: Option<Volume>,
    pub dark: bool,
    pub network: Option<bool>,
    pub battery: Option<u8>,
    /// Do Not Disturb.
    pub quiet: bool,
    /// The newest notifications, newest first.
    pub notes: Vec<crate::notes::Listed>,
    /// The slider is being dragged.
    pub dragging: bool,
}

/// How many notifications the menu lists.
pub const LISTED: usize = 4;
const NOTE_H: f32 = 40.0;

/// What a click or a key in it asks for.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Outcome {
    Close,
    /// Set the volume to this level (0 to 1).
    Volume(f32),
    /// Mute or unmute.
    Mute,
    /// The dark style on or off.
    Dark,
    /// Do Not Disturb on or off.
    Quiet,
    /// The notifications cleared.
    ClearNotes,
    /// Open Settings at this section (its key).
    Settings(&'static str),
    Lock,
    Power,
}

/// Where its controls were drawn.
#[derive(Clone, Debug, Default)]
pub struct Hits {
    pub area: Area,
    pub mute: Option<Area>,
    pub slider: Option<Area>,
    pub tiles: Vec<(Tile, Area)>,
    /// "Clear", when there are notifications.
    pub clear: Option<Area>,
    pub settings: Area,
    pub lock: Area,
    pub power: Area,
}

impl Hits {
    /// Every control, for the pointer's hand.
    pub fn controls(&self) -> Vec<Area> {
        let mut v: Vec<Area> = self.tiles.iter().map(|t| t.1).collect();
        v.extend(self.mute);
        v.extend(self.slider);
        v.extend(self.clear);
        v.extend([self.settings, self.lock, self.power]);
        v
    }
}

impl Quick {
    /// The level the slider gives at x.
    pub fn level_at(hits: &Hits, x: f32) -> Option<f32> {
        let s = hits.slider?;
        Some(((x - s.x) / s.w).clamp(0.0, 1.0))
    }

    /// A press at (x, y).
    pub fn press(&mut self, hits: &Hits, x: f32, y: f32) -> Option<Outcome> {
        if !hits.area.contains(x, y) {
            return Some(Outcome::Close);
        }
        if hits.slider.is_some_and(|s| s.grow(6.0).contains(x, y)) && self.volume.is_some() {
            self.dragging = true;
            return Quick::level_at(hits, x).map(Outcome::Volume);
        }
        if hits.mute.is_some_and(|a| a.contains(x, y)) && self.volume.is_some() {
            return Some(Outcome::Mute);
        }
        if let Some((t, _)) = hits.tiles.iter().find(|(_, a)| a.contains(x, y)) {
            return Some(match t {
                Tile::Network => Outcome::Settings("network"),
                Tile::Bluetooth => Outcome::Settings("bluetooth"),
                Tile::Dark => Outcome::Dark,
                Tile::Quiet => Outcome::Quiet,
            });
        }
        if hits.clear.is_some_and(|a| a.contains(x, y)) {
            return Some(Outcome::ClearNotes);
        }
        if hits.settings.contains(x, y) {
            return Some(Outcome::Settings(""));
        }
        if hits.lock.contains(x, y) {
            return Some(Outcome::Lock);
        }
        hits.power.contains(x, y).then_some(Outcome::Power)
    }

    /// A key: Esc closes, left and right move the volume a step, M mutes.
    pub fn key(&self, code: u16) -> Option<Outcome> {
        use slate_display::input::{KEY_ESC, KEY_LEFT, KEY_RIGHT};
        const KEY_M: u16 = 50;
        let level = self.volume.map(|v| v.level);
        match code {
            KEY_ESC => Some(Outcome::Close),
            KEY_LEFT => level.map(|l| Outcome::Volume((l - 0.05).max(0.0))),
            KEY_RIGHT => level.map(|l| Outcome::Volume((l + 0.05).min(1.0))),
            KEY_M => level.map(|_| Outcome::Mute),
            _ => None,
        }
    }
}

/// The menu's surface on a screen `w` wide under a top bar `bar_h` tall.
pub fn area(q: &Quick, w: f32, bar_h: f32) -> Area {
    let battery = if q.battery.is_some() { 28.0 } else { 0.0 };
    let notes = 24.0 + 6.0 + if q.notes.is_empty() { 24.0 } else { NOTE_H * q.notes.len().min(LISTED) as f32 };
    let h = PAD + ROW_H + PAD + 2.0 * TILE_H + 10.0 + battery + PAD + 1.0 + PAD + notes + PAD + 1.0 + PAD + ROW_H + PAD;
    Area::new(w - EDGE - WIDTH, bar_h + 2.0, WIDTH, h)
}

/// A round button with an icon.
fn round(p: &mut Painter<'_>, pal: &Palette, a: Area, icon: Icon) {
    p.fill(a, a.h / 2.0, pal.raised);
    p.icon(icon, a.x + (a.w - 16.0) / 2.0, a.y + (a.h - 16.0) / 2.0, 16.0, pal.text_1);
}

/// Draw the menu (under a top bar on a screen `w` wide).
pub fn draw(p: &mut Painter<'_>, pal: &Palette, f: &Fonts<'_>, q: &Quick, w: f32) -> Hits {
    let a = area(q, w, pal.shape.bar_h);
    let mut hits = Hits { area: a, ..Hits::default() };
    p.shadow_under(a, RADIUS, &draw::MENU);
    p.fill(a, RADIUS, pal.overlay);
    draw::rim(p, pal, a, RADIUS);
    let (x, inner) = (a.x + PAD, a.w - 2.0 * PAD);
    let mut y = a.y + PAD;
    // The volume: the mute button, the slider, the level.
    let label = p.style(&f.regular, 12.5, pal.text_3);
    match q.volume {
        Some(v) => {
            let mute = Area::new(x, y, ROW_H, ROW_H);
            round(p, pal, mute, if v.muted { Icon::SpeakerMuted } else { Icon::Speaker });
            let pct = slate_sound::mixer::words(&v);
            let tw = 48.0;
            let track = Area::new(mute.right() + 12.0, y + ROW_H / 2.0 - 2.0, inner - ROW_H - 12.0 - tw - 8.0, 4.0);
            p.fill(track, 2.0, pal.well);
            let ink = if v.muted { pal.muted } else { pal.chalk };
            p.fill(Area::new(track.x, track.y, track.w * v.level, 4.0), 2.0, ink);
            let kx = track.x + track.w * v.level;
            p.fill(Area::new(kx - 8.0, track.y - 6.0, 16.0, 16.0), 8.0, ink);
            p.border(Area::new(kx - 8.0, track.y - 6.0, 16.0, 16.0), 8.0, 1.0, pal.overlay);
            let sw = p.measure(&label, &pct);
            p.line(&label, a.right() - PAD - sw, y, ROW_H, &pct);
            hits.mute = Some(mute);
            hits.slider = Some(track);
        }
        None => {
            p.icon(Icon::SpeakerMuted, x + 10.0, y + 10.0, 16.0, pal.muted);
            p.line(&label, x + ROW_H + 12.0, y, ROW_H, "No sound card");
        }
    }
    y += ROW_H + PAD;
    // The tiles, two to a row.
    let tw = (inner - 10.0) / 2.0;
    let net = match q.network {
        Some(true) => "Connected",
        Some(false) => "No connection",
        None => "Settings",
    };
    let tiles = [
        (Tile::Network, Icon::Wifi, "Network", net, q.network == Some(true)),
        (Tile::Bluetooth, Icon::Bluetooth, "Bluetooth", "Settings", false),
        (Tile::Dark, Icon::Moon, "Dark style", if q.dark { "On" } else { "Off" }, q.dark),
        (
            Tile::Quiet,
            if q.quiet { Icon::BellOff } else { Icon::Bell },
            "Do Not Disturb",
            if q.quiet { "On" } else { "Off" },
            q.quiet,
        ),
    ];
    for (i, (tile, icon, title, sub, on)) in tiles.into_iter().enumerate() {
        let t = Area::new(x + (i % 2) as f32 * (tw + 10.0), y + (i / 2) as f32 * (TILE_H + 10.0), tw, TILE_H);
        let fill = if on { mix(pal.raised, pal.chalk, 0.16) } else { pal.raised };
        p.fill(t, 10.0, fill);
        let ink = if on { pal.chalk } else { pal.text_1 };
        p.icon(icon, t.x + 12.0, t.y + (TILE_H - 18.0) / 2.0, 18.0, ink);
        let st = p.style(&f.medium, 13.0, ink);
        p.line(&st, t.x + 40.0, t.y + 9.0, 20.0, title);
        let sst = p.style(&f.regular, 11.5, pal.muted);
        p.line(&sst, t.x + 40.0, t.y + 28.0, 18.0, sub);
        hits.tiles.push((tile, t));
    }
    y += 2.0 * TILE_H + 10.0;
    if let Some(level) = q.battery {
        let (dx, dy) = p.to_device(x + 2.0, y + 8.0);
        slate_ui::icon::battery(p.canvas, dx, dy, 16.0 * p.scale, level, pal.text_1);
        p.line(&label, x + 26.0, y + 4.0, 20.0, &alloc::format!("Battery {level}%"));
        y += 28.0;
    }
    y += PAD;
    p.fill(Area::new(x, y, inner, 1.0), 0.0, pal.divider);
    y += 1.0 + PAD;
    // The latest notifications, and "Clear".
    let head = p.style(&f.medium, 12.5, pal.text_2);
    p.line(&head, x, y, 24.0, "Notifications");
    if !q.notes.is_empty() {
        let cst = p.style(&f.regular, 12.5, pal.text_3);
        let cw = p.measure(&cst, "Clear") + 20.0;
        let clear = Area::new(a.right() - PAD - cw, y, cw, 24.0);
        p.fill(clear, 6.0, pal.raised);
        p.line(&cst, clear.x + 10.0, clear.y, 24.0, "Clear");
        hits.clear = Some(clear);
    }
    y += 24.0 + 6.0;
    if q.notes.is_empty() {
        p.line(&label, x, y, 24.0, "No notifications");
        y += 24.0;
    }
    for n in q.notes.iter().take(LISTED) {
        let st = p.style(&f.regular, 13.0, pal.text_1);
        let summary = draw::truncate_end(p, &st, &n.summary, inner);
        p.line(&st, x, y + 2.0, 18.0, &summary);
        let small = p.style(&f.regular, 11.5, pal.muted);
        p.line(&small, x, y + 21.0, 16.0, &alloc::format!("{} · {}", n.app, n.clock));
        y += NOTE_H;
    }
    y += PAD;
    p.fill(Area::new(x, y, inner, 1.0), 0.0, pal.divider);
    y += 1.0 + PAD;
    // Settings at the left; lock and power at the right.
    hits.settings = Area::new(x, y, ROW_H, ROW_H);
    hits.power = Area::new(a.right() - PAD - ROW_H, y, ROW_H, ROW_H);
    hits.lock = Area::new(hits.power.x - 10.0 - ROW_H, y, ROW_H, ROW_H);
    round(p, pal, hits.settings, Icon::Sliders);
    round(p, pal, hits.lock, Icon::Lock);
    round(p, pal, hits.power, Icon::Power);
    hits
}

/// What the volume and brightness keys show for a moment: an icon, a
/// level (None: just words), and words.
#[derive(Clone, Debug, PartialEq)]
pub struct Osd {
    pub icon: Icon,
    pub level: Option<f32>,
    pub text: String,
    /// When it was shown (ms).
    pub since: i64,
}

/// How long the pop-up shows, fading in and out.
pub const OSD_MS: i64 = 1600;
const OSD_IN: i64 = 100;
const OSD_OUT: i64 = 250;

impl Osd {
    /// Its opacity at `now`; None once gone.
    pub fn opacity(&self, now: i64, reduced: bool) -> Option<f32> {
        let t = now - self.since;
        if !(0..OSD_MS).contains(&t) {
            return None;
        }
        if reduced {
            return Some(1.0);
        }
        Some(if t < OSD_IN {
            t as f32 / OSD_IN as f32
        } else if t > OSD_MS - OSD_OUT {
            (OSD_MS - t) as f32 / OSD_OUT as f32
        } else {
            1.0
        })
    }
}

/// The pop-up's surface, low in the middle of a `w` × `h` screen.
pub fn osd_area(w: f32, h: f32) -> Area {
    Area::new(slate_ui::math::round((w - 300.0) / 2.0), h - 140.0, 300.0, 56.0)
}

/// Draw the pop-up at `opacity`.
pub fn draw_osd(p: &mut Painter<'_>, pal: &Palette, f: &Fonts<'_>, o: &Osd, opacity: f32, w: f32, h: f32) {
    let a = osd_area(w, h);
    let k = opacity.clamp(0.0, 1.0);
    p.fill(a, 28.0, pal.overlay.faded(k));
    p.border(a, 28.0, 1.0, pal.border.faded(k));
    p.icon(o.icon, a.x + 22.0, a.y + 17.0, 22.0, pal.chalk.faded(k));
    let st = p.style(&f.regular, 12.5, pal.text_1.faded(k));
    match o.level {
        Some(l) => {
            let track = Area::new(a.x + 60.0, a.y + 26.0, a.w - 60.0 - 64.0, 4.0);
            p.fill(track, 2.0, pal.well.faded(k));
            p.fill(Area::new(track.x, track.y, track.w * l.clamp(0.0, 1.0), 4.0), 2.0, pal.chalk.faded(k));
            let tw = p.measure(&st, &o.text);
            p.line(&st, a.right() - 22.0 - tw, a.y, a.h, &o.text);
        }
        None => {
            p.line(&st, a.x + 60.0, a.y, a.h, &o.text);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn q() -> Quick {
        Quick {
            volume: Some(Volume { card: 0, level: 0.5, muted: false }),
            dark: true,
            network: Some(true),
            battery: None,
            quiet: false,
            notes: alloc::vec::Vec::new(),
            dragging: false,
        }
    }

    #[test]
    fn presses() {
        let mut q = q();
        let a = area(&q, 1280.0, 32.0);
        assert!(a.right() <= 1280.0 - EDGE + 0.01 && a.y > 32.0);
        let hits = Hits {
            area: a,
            mute: Some(Area::new(a.x + 14.0, a.y + 14.0, 36.0, 36.0)),
            slider: Some(Area::new(a.x + 62.0, a.y + 30.0, 200.0, 4.0)),
            tiles: alloc::vec![(Tile::Dark, Area::new(a.x + 14.0, a.y + 70.0, 150.0, 56.0))],
            ..Hits::default()
        };
        assert_eq!(q.press(&hits, 10.0, 10.0), Some(Outcome::Close));
        assert_eq!(q.press(&hits, a.x + 20.0, a.y + 20.0), Some(Outcome::Mute));
        assert_eq!(q.press(&hits, a.x + 62.0 + 150.0, a.y + 32.0), Some(Outcome::Volume(0.75)));
        assert!(q.dragging);
        assert_eq!(q.press(&hits, a.x + 20.0, a.y + 80.0), Some(Outcome::Dark));
        assert_eq!(Quick::level_at(&hits, a.x), Some(0.0));
        assert_eq!(q.key(1), Some(Outcome::Close));
        assert_eq!(q.key(106), Some(Outcome::Volume(0.55)));
        q.volume = None;
        assert_eq!(q.key(106), None);
    }

    #[test]
    fn the_popup_fades() {
        let o = Osd { icon: Icon::Speaker, level: Some(0.4), text: String::from("40%"), since: 1000 };
        assert_eq!(o.opacity(999, false), None);
        assert!(o.opacity(1050, false).is_some_and(|v| v > 0.0 && v < 1.0));
        assert_eq!(o.opacity(1500, false), Some(1.0));
        assert!(o.opacity(1000 + OSD_MS - 50, false).is_some_and(|v| v < 1.0));
        assert_eq!(o.opacity(1000 + OSD_MS, false), None);
        assert_eq!(o.opacity(1050, true), Some(1.0));
    }
}
