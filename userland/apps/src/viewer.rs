// SPDX-License-Identifier: MIT OR Apache-2.0

//! Image Viewer (ADR 0105), `image-viewer [FILE]`: one picture at a time
//! from a folder, read by Slate's own decoders (`libs/image`: PNG, JPEG,
//! GIF, BMP).
//!
//! It opens the file given (or the first picture in ~/Pictures, else
//! the home folder) and shows it whole, never larger than it is.
//!
//! Keys:
//! - left and right (or Page Up and Down, space) go through the
//!   folder's pictures, Home and End to its first and last;
//! - `+` and `-` (or the wheel) zoom, `0` fits it again, `1` shows it at
//!   its own size; zoomed in, the arrows move around it;
//! - `r` turns it clockwise, shift + `r` back.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use slate_display::input::{
    KEY_DOWN, KEY_END, KEY_HOME, KEY_LEFT, KEY_PAGEDOWN, KEY_PAGEUP, KEY_RIGHT, KEY_SPACE, KEY_UP,
};
use slate_image::Image;
use slate_strata::fonts::Fonts;
use slate_strata_client::mods::{ALT, CTRL, LOGO, SHIFT};
use slate_ui::graphite::Palette;
use slate_ui::paint::Painter;
use slate_ui::ui::Area;
use slate_ui::{Color, Rect};

use crate::kit::{self, App, Effect, Hints, Now};

/// The extensions read, lower case.
pub const EXTENSIONS: [&str; 5] = ["png", "jpg", "jpeg", "gif", "bmp"];

/// The largest file read (MiB): a picture bigger than this is refused
/// before it is read.
const MAX_FILE: u64 = 128 << 20;

const ZOOMS: [f32; 12] = [0.1, 0.25, 0.33, 0.5, 0.67, 1.0, 1.5, 2.0, 3.0, 4.0, 6.0, 8.0];

pub fn is_image(name: &str) -> bool {
    name.rsplit_once('.').is_some_and(|(_, e)| EXTENSIONS.iter().any(|x| x.eq_ignore_ascii_case(e)))
}

/// A picture read: its pixels, what it was, and its file's size.
#[derive(Debug)]
pub struct Loaded {
    pub image: Image,
    pub format: &'static str,
    pub bytes: usize,
}

#[derive(Debug, Default)]
pub struct Viewer {
    pub folder: String,
    /// The folder's pictures, by name.
    pub files: Vec<String>,
    pub index: usize,
    pub current: Option<Result<Loaded, String>>,
    /// The zoom (1.0: its own size), or None to fit the window.
    pub zoom: Option<f32>,
    /// Quarter turns clockwise.
    pub turns: u32,
    /// Where the view's centre is, as a fraction of the picture (zoomed in).
    pub centre: (f32, f32),
    /// Loading: 1 asked (the next frame says so), 2 to read now.
    loading: u8,
    /// The picture as last drawn, scaled: (index, turns, w, h).
    cache: Option<((usize, u32, u32, u32), Image)>,
    /// The fitting zoom, from the last frame.
    fit: f32,
}

/// Read and decode `path`.
pub fn load(path: &str) -> Result<Loaded, String> {
    let st = slate_rt::fs::stat(path.as_bytes()).map_err(|e| alloc::format!("{e}"))?;
    if st.size as u64 > MAX_FILE {
        return Err(String::from("It is too large to open."));
    }
    let data = slate_rt::fs::read_file(path.as_bytes()).map_err(|e| alloc::format!("{e}"))?;
    let format = slate_image::format(&data).map(|f| f.name()).ok_or("It is not a picture Slate can read.")?;
    let image = slate_image::decode(&data).map_err(|e| {
        String::from(match e {
            slate_image::Error::Unsupported => "Its kind of compression is not one Slate reads yet.",
            slate_image::Error::TooLarge => "It is too large to open.",
            slate_image::Error::Truncated => "The file ends too early: it may be damaged.",
            _ => "The file is damaged.",
        })
    })?;
    Ok(Loaded { image, format, bytes: data.len() })
}

/// The pictures in `folder`, by name.
pub fn pictures(folder: &str) -> Vec<String> {
    let mut v: Vec<String> = slate_rt::fs::read_dir(folder.as_bytes())
        .map(|es| es.iter().map(|e| String::from(slate_rt::lossy(&e.name))).filter(|n| is_image(n)).collect())
        .unwrap_or_default();
    v.sort_by_key(|a| a.to_lowercase());
    v
}

impl Viewer {
    /// Open `path` (a picture) among its folder's pictures.
    pub fn open(path: &str) -> Viewer {
        let (folder, name) =
            path.rsplit_once('/').map_or((".", path), |(d, n)| (if d.is_empty() { "/" } else { d }, n));
        let files = pictures(folder);
        let index = files.iter().position(|f| f == name).unwrap_or(0);
        Viewer { folder: String::from(folder), files, index, loading: 1, ..Viewer::default() }
    }

    /// The first picture in `folder`, if it has any.
    pub fn browse(folder: &str) -> Viewer {
        let files = pictures(folder);
        let loading = u8::from(!files.is_empty());
        Viewer { folder: String::from(folder), files, loading, ..Viewer::default() }
    }

    pub fn path(&self) -> Option<String> {
        self.files.get(self.index).map(|f| alloc::format!("{}/{f}", self.folder.trim_end_matches('/')))
    }

    fn go(&mut self, i: usize) -> Effect {
        if i == self.index || i >= self.files.len() {
            return Effect::None;
        }
        self.index = i;
        self.zoom = None;
        self.turns = 0;
        self.centre = (0.5, 0.5);
        self.loading = 1;
        self.cache = None;
        Effect::Redraw
    }

    fn zoom_by(&mut self, step: i32) -> Effect {
        let now = self.zoom.unwrap_or(self.fit);
        let next = if step > 0 {
            ZOOMS.iter().copied().find(|z| *z > now + 0.001)
        } else {
            ZOOMS.iter().rev().copied().find(|z| *z < now - 0.001)
        };
        match next {
            Some(z) => {
                self.zoom = if z <= self.fit && step < 0 { None } else { Some(z) };
                Effect::Redraw
            }
            None => Effect::None,
        }
    }

    fn pan(&mut self, dx: f32, dy: f32) -> Effect {
        if self.zoom.is_none() {
            return Effect::None;
        }
        self.centre = ((self.centre.0 + dx).clamp(0.0, 1.0), (self.centre.1 + dy).clamp(0.0, 1.0));
        Effect::Redraw
    }

    fn info(&self, l: &Loaded) -> String {
        let (w, h) = (l.image.width, l.image.height);
        alloc::format!("{w} × {h} · {} · {}", l.format, crate::help::size(l.bytes as u64))
    }
}

/// Grey squares under a transparent picture.
fn checker(p: &mut Painter<'_>, r: Rect, a: Color, b: Color) {
    let s = 8;
    let mut y = r.y;
    while y < r.bottom() {
        let mut x = r.x;
        while x < r.right() {
            let odd = ((x - r.x) / s + (y - r.y) / s) % 2 == 1;
            p.canvas.fill_rect(Rect::new(x, y, s.min(r.right() - x), s.min(r.bottom() - y)), if odd { a } else { b });
            x += s;
        }
        y += s;
    }
}

impl App for Viewer {
    /// A picture dropped on the window is shown, among its folder's
    /// (ADR 0156's addendum); anything else is said not to be one.
    fn dropped(&mut self, _x: f32, _y: f32, paths: &[String], _copy: bool) -> Effect {
        let name = |p: &str| String::from(p.rsplit('/').next().unwrap_or(p));
        match paths.iter().find(|p| is_image(&name(p))) {
            Some(p) => {
                crate::trace!("viewer: {} dropped", name(p));
                *self = Viewer::open(p);
            }
            None => {
                let Some(p) = paths.first() else { return Effect::None };
                self.current = Some(Err(alloc::format!("{} isn't a picture this viewer shows.", name(p))));
                self.cache = None;
            }
        }
        Effect::Redraw
    }

    fn draw(&mut self, p: &mut Painter<'_>, pal: &Palette, f: &Fonts<'_>, a: Area) {
        p.fill(a, 0.0, pal.desktop);
        let bar_h = 40.0;
        let view = Area::new(a.x, a.y, a.w, a.h - bar_h);
        let bar = Area::new(a.x, a.y + a.h - bar_h, a.w, bar_h);
        p.fill(bar, 0.0, pal.window);
        p.fill(Area::new(bar.x, bar.y, bar.w, 1.0), 0.0, pal.divider);
        let name = p.style(&f.medium, 13.0, pal.text_1);
        let meta = p.style(&f.mono, 11.5, pal.muted);
        let quiet = p.style(&f.regular, 14.0, pal.muted);
        let centre_text = |p: &mut Painter<'_>, s: &str, style: &slate_ui::text::Style<'_, '_>| {
            let w = p.measure(style, s);
            p.line(style, view.x + (view.w - w) / 2.0, view.y + view.h / 2.0 - 10.0, 20.0, s);
        };
        if self.files.is_empty() {
            centre_text(p, "No pictures here. Open one from Files.", &quiet);
            return;
        }
        let file = &self.files[self.index];
        let mut x = bar.x + 16.0;
        x += p.line(&name, x, bar.y + 10.0, 20.0, file) + 14.0;
        let count = alloc::format!("{} / {}", self.index + 1, self.files.len());
        let cw = p.measure(&meta, &count);
        p.line(&meta, bar.x + bar.w - 16.0 - cw, bar.y + 11.0, 18.0, &count);
        if self.loading > 0 {
            centre_text(p, "Opening…", &quiet);
            return;
        }
        let Some(cur) = &self.current else { return };
        let l = match cur {
            Ok(l) => l,
            Err(e) => {
                centre_text(p, &alloc::format!("Can't show {file}. {e}"), &quiet);
                return;
            }
        };
        let info = self.info(l);
        p.line(&meta, x, bar.y + 11.0, 18.0, &info);
        // The picture's size turned, the fitting zoom, and the size shown
        // (device pixels).
        let (iw, ih) =
            if self.turns % 2 == 1 { (l.image.height, l.image.width) } else { (l.image.width, l.image.height) };
        let dv = p.device(&view);
        let margin = 16.0 * p.scale;
        let fit = ((dv.w as f32 - 2.0 * margin) / iw as f32).min((dv.h as f32 - 2.0 * margin) / ih as f32).min(1.0);
        self.fit = fit.max(0.01);
        let z = self.zoom.unwrap_or(self.fit);
        let (sw, sh) = (((iw as f32 * z) as u32).max(1), ((ih as f32 * z) as u32).max(1));
        let key = (self.index, self.turns, sw, sh);
        if self.cache.as_ref().is_none_or(|(k, _)| *k != key) {
            let turned = l.image.rotate(self.turns);
            self.cache = Some((key, turned.scaled(sw, sh)));
        }
        let Some((_, shown)) = &self.cache else { return };
        // Where it goes: centred when it fits, else around the view's
        // centre point.
        let place = |view_len: i32, len: u32, c: f32| -> i32 {
            if (len as i32) <= view_len {
                (view_len - len as i32) / 2
            } else {
                (view_len as f32 / 2.0 - c * len as f32).clamp((view_len - len as i32) as f32, 0.0) as i32
            }
        };
        let ox = dv.x + place(dv.w, sw, self.centre.0);
        let oy = dv.y + place(dv.h, sh, self.centre.1);
        let clip = p.clip(view);
        let r = Rect::new(ox, oy, sw as i32, sh as i32);
        if l.image.has_alpha() {
            checker(p, r.intersect(&dv), pal.raised, pal.well);
        }
        p.canvas.draw_image(ox, oy, sw as i32, sh as i32, &shown.pixels);
        p.unclip(clip);
        let zoom = alloc::format!("{:.0}%", z * 100.0);
        let zw = p.measure(&meta, &zoom);
        p.line(&meta, bar.x + bar.w - 32.0 - cw - zw, bar.y + 11.0, 18.0, &zoom);
    }

    fn key(&mut self, code: u16, ch: Option<char>, mods: u8) -> Effect {
        if mods & (CTRL | ALT | LOGO) != 0 {
            return Effect::None;
        }
        let zoomed = self.zoom.is_some_and(|z| z > self.fit);
        match (code, ch) {
            (KEY_LEFT, _) if zoomed => self.pan(-0.1, 0.0),
            (KEY_RIGHT, _) if zoomed => self.pan(0.1, 0.0),
            (KEY_UP, _) if zoomed => self.pan(0.0, -0.1),
            (KEY_DOWN, _) if zoomed => self.pan(0.0, 0.1),
            (KEY_LEFT | KEY_PAGEUP, _) => self.go(self.index.saturating_sub(1)),
            (KEY_RIGHT | KEY_PAGEDOWN | KEY_SPACE, _) => self.go(self.index + 1),
            (KEY_HOME, _) => self.go(0),
            (KEY_END, _) => self.go(self.files.len().saturating_sub(1)),
            (_, Some('+' | '=')) => self.zoom_by(1),
            (_, Some('-')) => self.zoom_by(-1),
            (_, Some('0')) => {
                self.zoom = None;
                Effect::Redraw
            }
            (_, Some('1')) => {
                self.zoom = Some(1.0);
                self.centre = (0.5, 0.5);
                Effect::Redraw
            }
            (_, Some('r' | 'R')) => {
                self.turns = (self.turns + if mods & SHIFT != 0 { 3 } else { 1 }) % 4;
                Effect::Redraw
            }
            _ => Effect::None,
        }
    }

    fn scroll(&mut self, lines: i32) -> Effect {
        self.zoom_by(-lines.signum())
    }

    fn tick(&mut self, _now: Now) -> bool {
        match self.loading {
            1 => {
                self.loading = 2;
                false
            }
            2 => {
                self.loading = 0;
                self.current = self.path().map(|p| load(&p));
                match &self.current {
                    Some(Ok(l)) => crate::trace!(
                        "image-viewer: {} {}x{} {}",
                        self.files[self.index],
                        l.image.width,
                        l.image.height,
                        l.format
                    ),
                    Some(Err(e)) => crate::trace!("image-viewer: {}: {e}", self.files[self.index]),
                    None => {}
                }
                true
            }
            _ => false,
        }
    }

    fn wake(&self, _now: Now) -> Option<i64> {
        (self.loading > 0).then_some(0)
    }
}

pub fn main() -> i32 {
    let arg = slate_rt::env::args().get(1).map(|a| String::from(slate_rt::lossy(a)));
    let home = slate_rt::env::var(b"HOME").map(|h| String::from(slate_rt::lossy(&h))).unwrap_or_else(|| "/".into());
    let mut v = match arg {
        Some(path) => Viewer::open(&path),
        None => {
            let pictures = alloc::format!("{home}/Pictures");
            let v = Viewer::browse(&pictures);
            if v.files.is_empty() { Viewer::browse(&home) } else { v }
        }
    };
    let shown = v.folder.replacen(&home, "~", 1).to_string();
    kit::run("image-viewer", "images", Some(&shown), Hints { min: (360, 280), size: (900, 640) }, &mut v)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixtures() -> String {
        alloc::format!("{}/../../libs/image/tests/fixtures", env!("CARGO_MANIFEST_DIR"))
    }

    #[test]
    fn dropped_pictures() {
        let mut v = Viewer::browse("/nonexistent");
        v.dropped(0.0, 0.0, &[String::from("/x/notes.txt"), alloc::format!("{}/photo420.jpg", fixtures())], false);
        assert_eq!(v.files[v.index], "photo420.jpg");
        v.dropped(0.0, 0.0, &[String::from("/x/notes.txt")], false);
        assert!(matches!(&v.current, Some(Err(e)) if e == "notes.txt isn't a picture this viewer shows."));
    }

    #[test]
    fn a_folder_of_pictures() {
        let mut v = Viewer::open(&alloc::format!("{}/photo420.jpg", fixtures()));
        assert!(v.files.len() > 20 && v.files[v.index] == "photo420.jpg");
        assert!(v.files.iter().all(|f| is_image(f)));
        v.tick(Now::default());
        v.tick(Now::default());
        let l = v.current.as_ref().unwrap().as_ref().unwrap();
        assert_eq!((l.image.width, l.image.height, l.format), (61, 45, "JPEG"));
        // Next, and back; zoom steps from the fitting size.
        let i = v.index;
        assert_eq!(v.key(KEY_RIGHT, None, 0), Effect::Redraw);
        assert_eq!((v.index, v.loading), (i + 1, 1));
        v.key(KEY_LEFT, None, 0);
        assert_eq!(v.index, i);
        v.fit = 0.4;
        v.key(0, Some('+'), 0);
        assert_eq!(v.zoom, Some(0.5));
        v.key(0, Some('-'), 0);
        assert_eq!(v.zoom, None, "back below the fit: fit again");
        v.key(0, Some('r'), SHIFT);
        assert_eq!(v.turns, 3);
        assert!(load("/nonexistent.png").is_err());
        assert!(!is_image("notes.txt") && is_image("IMG_0001.JPG"));
    }
}
